/*
 * node_device_udev.c: node device enumeration - libudev implementation
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <gio/gio.h>
#include <libudev.h>
#include <pciaccess.h>
#ifdef __linux__
# include <scsi/scsi.h>
#endif

#include "node_device_conf.h"
#include "node_device_event.h"
#include "node_device_driver.h"
#include "node_device_udev.h"
#include "virerror.h"
#include "driver.h"
#include "virlog.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virfile.h"
#include "virccw.h"
#include "virpci.h"
#include "virpidfile.h"
#include "virstring.h"
#include "virnetdev.h"
#include "virmdev.h"
#include "virutil.h"

#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("node_device.node_device_udev");

#ifndef TYPE_RAID
# define TYPE_RAID 12
#endif

#define DMI_DEVPATH "/sys/devices/virtual/dmi/id"

typedef struct _udevEventData udevEventData;
struct _udevEventData {
    virObjectLockable parent;

    struct udev_monitor *udev_monitor;
    int watch;

    /* Thread data */
    virThread *th;
    virCond threadCond;
    bool threadQuit;
    bool dataReady;

    /* init thread */
    virThread *initThread;

    GList *mdevctlMonitors;
    virMutex mdevctlLock;
    int mdevctlTimeout;
};

static virClass *udevEventDataClass;

static void
udevEventDataDispose(void *obj)
{
    struct udev *udev = NULL;
    udevEventData *priv = obj;

    if (priv->watch != -1)
        virEventRemoveHandle(priv->watch);

    if (!priv->udev_monitor)
        return;

    udev = udev_monitor_get_udev(priv->udev_monitor);
    udev_monitor_unref(priv->udev_monitor);
    udev_unref(udev);

    VIR_WITH_MUTEX_LOCK_GUARD(&priv->mdevctlLock) {
        g_list_free_full(priv->mdevctlMonitors, g_object_unref);
    }
    virMutexDestroy(&priv->mdevctlLock);

    virCondDestroy(&priv->threadCond);
}


static int
udevEventDataOnceInit(void)
{
    if (!VIR_CLASS_NEW(udevEventData, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(udevEventData);

static udevEventData *
udevEventDataNew(void)
{
    udevEventData *ret = NULL;

    if (udevEventDataInitialize() < 0)
        return NULL;

    if (!(ret = virObjectLockableNew(udevEventDataClass)))
        return NULL;

    if (virCondInit(&ret->threadCond) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    if (virMutexInit(&ret->mdevctlLock) < 0) {
        virObjectUnref(ret);
        return NULL;
    }

    ret->watch = -1;
    return ret;
}


static bool
udevHasDeviceProperty(struct udev_device *dev,
                      const char *key)
{
    if (udev_device_get_property_value(dev, key))
        return true;

    return false;
}


static const char *
udevGetDeviceProperty(struct udev_device *udev_device,
                      const char *property_key)
{
    const char *ret = NULL;

    ret = udev_device_get_property_value(udev_device, property_key);

    VIR_DEBUG("Found property key '%s' value '%s' for device with sysname '%s' errno='%s'",
              property_key, NULLSTR(ret), udev_device_get_sysname(udev_device),
              ret ? "" : g_strerror(errno));

    return ret;
}


static void
udevGetStringProperty(struct udev_device *udev_device,
                      const char *property_key,
                      char **value)
{
    *value = g_strdup(udevGetDeviceProperty(udev_device, property_key));
}


static int
udevGetIntProperty(struct udev_device *udev_device,
                   const char *property_key,
                   int *value,
                   int base)
{
    const char *str = NULL;

    str = udevGetDeviceProperty(udev_device, property_key);
    if (!str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing udev property '%1$s' on '%2$s'"),
                       property_key, udev_device_get_sysname(udev_device));
        return -1;
    }

    if (virStrToLong_i(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse int '%1$s' from udev property '%2$s' on '%3$s'"),
                       str, property_key, udev_device_get_sysname(udev_device));
        return -1;
    }
    return 0;
}


static int
udevGetUintProperty(struct udev_device *udev_device,
                    const char *property_key,
                    unsigned int *value,
                    int base)
{
    const char *str = NULL;

    str = udevGetDeviceProperty(udev_device, property_key);
    if (!str) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing udev property '%1$s' on '%2$s'"),
                       property_key, udev_device_get_sysname(udev_device));
        return -1;
    }

    if (virStrToLong_ui(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse uint '%1$s' from udev property '%2$s' on '%3$s'"),
                       str, property_key, udev_device_get_sysname(udev_device));
        return -1;
    }
    return 0;
}


static const char *
udevGetDeviceSysfsAttr(struct udev_device *udev_device,
                       const char *attr_name)
{
    const char *ret = NULL;

    ret = udev_device_get_sysattr_value(udev_device, attr_name);

    VIR_DEBUG("Found sysfs attribute '%s' value '%s' "
              "for device with sysname '%s'",
              attr_name, NULLSTR(ret),
              udev_device_get_sysname(udev_device));
    return ret;
}


static int
udevGetStringSysfsAttr(struct udev_device *udev_device,
                       const char *attr_name,
                       char **value)
{
    *value = g_strdup(udevGetDeviceSysfsAttr(udev_device, attr_name));

    virStringStripControlChars(*value);

    if (*value != NULL && (STREQ(*value, "")))
        VIR_FREE(*value);

    return 0;
}


static int
udevGetIntSysfsAttr(struct udev_device *udev_device,
                    const char *attr_name,
                    int *value,
                    int base)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_i(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%1$s' to int"), str);
        return -1;
    }

    return 0;
}


static int
udevGetUintSysfsAttr(struct udev_device *udev_device,
                     const char *attr_name,
                     unsigned int *value,
                     int base)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_ui(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%1$s' to unsigned int"), str);
        return -1;
    }

    return 0;
}


static int
udevGetUint64SysfsAttr(struct udev_device *udev_device,
                       const char *attr_name,
                       unsigned long long *value)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_ull(str, NULL, 0, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%1$s' to unsigned long long"), str);
        return -1;
    }

    return 0;
}


static void
udevGenerateDeviceName(struct udev_device *device,
                       virNodeDeviceDef *def,
                       const char *s)
{
    nodeDeviceGenerateName(def,
                           udev_device_get_subsystem(device),
                           udev_device_get_sysname(device), s);
}

static virMutex pciaccessMutex = VIR_MUTEX_INITIALIZER;

static int
udevTranslatePCIIds(unsigned int vendor,
                    unsigned int product,
                    char **vendor_string,
                    char **product_string)
{
    struct pci_id_match m;
    const char *vendor_name = NULL, *device_name = NULL;

    m.vendor_id = vendor;
    m.device_id = product;
    m.subvendor_id = PCI_MATCH_ANY;
    m.subdevice_id = PCI_MATCH_ANY;
    m.device_class = 0;
    m.device_class_mask = 0;
    m.match_data = 0;

    /* pci_get_strings returns void and unfortunately is not thread safe. */
    VIR_WITH_MUTEX_LOCK_GUARD(&pciaccessMutex) {
        pci_get_strings(&m, &device_name, &vendor_name, NULL, NULL);
    }

    *vendor_string = g_strdup(vendor_name);
    *product_string = g_strdup(device_name);

    return 0;
}


static int
udevProcessPCI(struct udev_device *device,
               virNodeDeviceDef *def)
{
    virNodeDevCapPCIDev *pci_dev = &def->caps->data.pci_dev;
    virPCIEDeviceInfo *pci_express = NULL;
    virPCIDevice *pciDev = NULL;
    virPCIDeviceAddress devAddr = { 0 };
    int ret = -1;
    char *p;
    bool privileged = false;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        privileged = driver->privileged;
    }

    pci_dev->klass = -1;
    if (udevGetIntProperty(device, "PCI_CLASS", &pci_dev->klass, 16) < 0)
        goto cleanup;

    if ((p = strrchr(def->sysfs_path, '/')) == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->domain) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->bus) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->slot) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->function) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the PCI address from sysfs path: '%1$s'"),
                       def->sysfs_path);
        goto cleanup;
    }

    if (udevGetUintSysfsAttr(device, "vendor", &pci_dev->vendor, 16) < 0)
        goto cleanup;

    if (udevGetUintSysfsAttr(device, "device", &pci_dev->product, 16) < 0)
        goto cleanup;

    if (udevTranslatePCIIds(pci_dev->vendor,
                            pci_dev->product,
                            &pci_dev->vendor_name,
                            &pci_dev->product_name) != 0) {
        goto cleanup;
    }

    udevGenerateDeviceName(device, def, NULL);

    /* The default value is -1, because it can't be 0
     * as zero is valid node number. */
    pci_dev->numa_node = -1;
    if (udevGetIntSysfsAttr(device, "numa_node",
                            &pci_dev->numa_node, 10) < 0)
        goto cleanup;

    if (virNodeDeviceGetPCIDynamicCaps(def->sysfs_path, pci_dev) < 0)
        goto cleanup;

    devAddr.domain = pci_dev->domain;
    devAddr.bus = pci_dev->bus;
    devAddr.slot = pci_dev->slot;
    devAddr.function = pci_dev->function;

    if (!(pciDev = virPCIDeviceNew(&devAddr)))
        goto cleanup;

    /* We need to be root to read PCI device configs */
    if (privileged) {
        if (virPCIGetHeaderType(pciDev, &pci_dev->hdrType) < 0)
            goto cleanup;

        if (virPCIDeviceIsPCIExpress(pciDev) > 0) {
            pci_express = g_new0(virPCIEDeviceInfo, 1);

            if (virPCIDeviceHasPCIExpressLink(pciDev) > 0) {
                pci_express->link_cap = g_new0(virPCIELink, 1);
                pci_express->link_sta = g_new0(virPCIELink, 1);

                if (virPCIDeviceGetLinkCapSta(pciDev,
                                              &pci_express->link_cap->port,
                                              &pci_express->link_cap->speed,
                                              &pci_express->link_cap->width,
                                              &pci_express->link_sta->speed,
                                              &pci_express->link_sta->width) < 0)
                    goto cleanup;

                pci_express->link_sta->port = -1; /* PCIe can't negotiate port. Yet :) */
            }
            pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCIE;
            pci_dev->pci_express = g_steal_pointer(&pci_express);
        }
    }

    ret = 0;

 cleanup:
    virPCIDeviceFree(pciDev);
    virPCIEDeviceInfoFree(pci_express);
    return ret;
}


static int
udevProcessMdevParent(struct udev_device *device,
                      virNodeDeviceDef *def)
{
    virNodeDevCapMdevParent *mdev_parent = &def->caps->data.mdev_parent;

    udevGenerateDeviceName(device, def, NULL);

    if (virMediatedDeviceParentGetAddress(def->sysfs_path, &mdev_parent->address) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find address for mdev parent device '%1$s'"),
                       def->name);
        return -1;
    }

    if (virNodeDeviceGetMdevParentDynamicCaps(def->sysfs_path, mdev_parent) < 0)
        return -1;

    return 0;
}


static int
drmGetMinorType(int minor)
{
    int type = minor >> 6;

    if (minor < 0)
        return -1;

    switch (type) {
    case VIR_NODE_DEV_DRM_PRIMARY:
    case VIR_NODE_DEV_DRM_CONTROL:
    case VIR_NODE_DEV_DRM_RENDER:
        return type;
    default:
        return -1;
    }
}


static int
udevProcessDRMDevice(struct udev_device *device,
                     virNodeDeviceDef *def)
{
    virNodeDevCapDRM *drm = &def->caps->data.drm;
    int minor;

    udevGenerateDeviceName(device, def, NULL);

    if (udevGetIntProperty(device, "MINOR", &minor, 10) < 0)
        return -1;

    if ((minor = drmGetMinorType(minor)) == -1)
        return -1;

    drm->type = minor;

    return 0;
}


static int
udevProcessUSBDevice(struct udev_device *device,
                     virNodeDeviceDef *def)
{
    virNodeDevCapUSBDev *usb_dev = &def->caps->data.usb_dev;

    if (udevGetUintProperty(device, "BUSNUM", &usb_dev->bus, 10) < 0)
        return -1;
    if (udevGetUintProperty(device, "DEVNUM", &usb_dev->device, 10) < 0)
        return -1;
    if (udevGetUintProperty(device, "ID_VENDOR_ID", &usb_dev->vendor, 16) < 0)
        return -1;

    udevGetStringProperty(device,
                          "ID_VENDOR_FROM_DATABASE",
                          &usb_dev->vendor_name);

    if (!usb_dev->vendor_name &&
        udevGetStringSysfsAttr(device, "manufacturer",
                               &usb_dev->vendor_name) < 0)
        return -1;

    if (udevGetUintProperty(device, "ID_MODEL_ID", &usb_dev->product, 16) < 0)
        return -1;

    udevGetStringProperty(device,
                          "ID_MODEL_FROM_DATABASE",
                          &usb_dev->product_name);

    if (!usb_dev->product_name &&
        udevGetStringSysfsAttr(device, "product",
                               &usb_dev->product_name) < 0)
        return -1;

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessUSBInterface(struct udev_device *device,
                        virNodeDeviceDef *def)
{
    virNodeDevCapUSBIf *usb_if = &def->caps->data.usb_if;

    if (udevGetUintSysfsAttr(device, "bInterfaceNumber",
                             &usb_if->number, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceClass",
                             &usb_if->klass, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceSubClass",
                             &usb_if->subclass, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceProtocol",
                             &usb_if->protocol, 16) < 0)
        return -1;

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessNetworkInterface(struct udev_device *device,
                            virNodeDeviceDef *def)
{
    const char *devtype = udev_device_get_devtype(device);
    virNodeDevCapNet *net = &def->caps->data.net;

    if (devtype && STREQ(devtype, "wlan")) {
        net->subtype = VIR_NODE_DEV_CAP_NET_80211;
    } else {
        net->subtype = VIR_NODE_DEV_CAP_NET_80203;
    }

    udevGetStringProperty(device, "INTERFACE", &net->ifname);

    if (udevGetStringSysfsAttr(device, "address",
                               &net->address) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "addr_len", &net->address_len, 0) < 0)
        return -1;

    udevGenerateDeviceName(device, def, net->address);

    if (virNetDevGetLinkInfo(net->ifname, &net->lnk) < 0)
        return -1;

    if (virNetDevGetFeatures(net->ifname, &net->features) < 0)
        return -1;

    return 0;
}


static int
udevProcessSCSIHost(struct udev_device *device G_GNUC_UNUSED,
                    virNodeDeviceDef *def)
{
    virNodeDevCapSCSIHost *scsi_host = &def->caps->data.scsi_host;
    g_autofree char *filename = NULL;
    char *str;

    filename = g_path_get_basename(def->sysfs_path);

    if (!(str = STRSKIP(filename, "host")) ||
        virStrToLong_ui(str, NULL, 0, &scsi_host->host) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse SCSI host '%1$s'"),
                       filename);
        return -1;
    }

    virNodeDeviceGetSCSIHostCaps(&def->caps->data.scsi_host);

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessSCSITarget(struct udev_device *device,
                      virNodeDeviceDef *def)
{
    const char *sysname = NULL;
    virNodeDevCapSCSITarget *scsi_target = &def->caps->data.scsi_target;

    sysname = udev_device_get_sysname(device);

    scsi_target->name = g_strdup(sysname);

    virNodeDeviceGetSCSITargetCaps(def->sysfs_path, &def->caps->data.scsi_target);

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevGetSCSIType(virNodeDeviceDef *def G_GNUC_UNUSED,
                unsigned int type,
                char **typestring)
{
    int ret = 0;
    int foundtype = 1;

    *typestring = NULL;

#ifdef __linux__
    /* These values are Linux specific. */
    switch (type) {
    case TYPE_DISK:
        *typestring = g_strdup("disk");
        break;
    case TYPE_TAPE:
        *typestring = g_strdup("tape");
        break;
    case TYPE_PROCESSOR:
        *typestring = g_strdup("processor");
        break;
    case TYPE_WORM:
        *typestring = g_strdup("worm");
        break;
    case TYPE_ROM:
        *typestring = g_strdup("cdrom");
        break;
    case TYPE_SCANNER:
        *typestring = g_strdup("scanner");
        break;
    case TYPE_MOD:
        *typestring = g_strdup("mod");
        break;
    case TYPE_MEDIUM_CHANGER:
        *typestring = g_strdup("changer");
        break;
    case TYPE_ENCLOSURE:
        *typestring = g_strdup("enclosure");
        break;
    case TYPE_RAID:
        *typestring = g_strdup("raid");
        break;
    case TYPE_NO_LUN:
    default:
        foundtype = 0;
        break;
    }
#else
    /* Implement me. */
    foundtype = 0;
#endif

    if (*typestring == NULL) {
        if (foundtype == 1) {
            ret = -1;
        } else {
            VIR_DEBUG("Failed to find SCSI device type %d for %s",
                      type, def->sysfs_path);
        }
    }

    return ret;
}


static int
udevProcessSCSIDevice(struct udev_device *device G_GNUC_UNUSED,
                      virNodeDeviceDef *def)
{
    int ret = -1;
    unsigned int tmp = 0;
    virNodeDevCapSCSI *scsi = &def->caps->data.scsi;
    g_autofree char *filename = NULL;
    char *p = NULL;

    filename = g_path_get_basename(def->sysfs_path);

    if (virStrToLong_ui(filename, &p, 10, &scsi->host) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->bus) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->target) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->lun) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the SCSI address from filename: '%1$s'"),
                       filename);
        return -1;
    }

    if (udev_device_get_sysattr_value(device, "type")) {
        if (udevGetUintSysfsAttr(device, "type", &tmp, 0) < 0)
            goto cleanup;

        if (udevGetSCSIType(def, tmp, &scsi->type) < 0)
            goto cleanup;
    }

    udevGenerateDeviceName(device, def, NULL);

    ret = 0;

 cleanup:
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to process SCSI device with sysfs path '%1$s'"),
                       def->sysfs_path);
    }
    return ret;
}


static int
udevProcessDisk(struct udev_device *device,
                virNodeDeviceDef *def)
{
    virNodeDevCapStorage *storage = &def->caps->data.storage;

    if (udevGetUint64SysfsAttr(device, "size", &storage->num_blocks) < 0)
        return -1;

    if (udevGetUint64SysfsAttr(device, "queue/logical_block_size",
                               &storage->logical_block_size) < 0)
        return -1;

    storage->size = storage->num_blocks * storage->logical_block_size;

    return 0;
}


static int
udevProcessRemoveableMedia(struct udev_device *device,
                           virNodeDeviceDef *def,
                           int has_media)
{
    virNodeDevCapStorage *storage = &def->caps->data.storage;
    int is_removable = 0;

    if (udevGetIntSysfsAttr(device, "removable", &is_removable, 0) < 0)
        return -1;
    if (is_removable == 1)
        def->caps->data.storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;

    if (!has_media)
        return 0;

    def->caps->data.storage.flags |=
        VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

    udevGetStringProperty(device, "ID_FS_LABEL", &storage->media_label);

    if (udevGetUint64SysfsAttr(device, "size",
                               &storage->num_blocks) < 0)
        return -1;

    if (udevGetUint64SysfsAttr(device, "queue/logical_block_size",
                               &storage->logical_block_size) < 0)
        return -1;

    /* XXX This calculation is wrong for the qemu virtual cdrom
     * which reports the size in 512 byte blocks, but the logical
     * block size as 2048.  I don't have a physical cdrom on a
     * devel system to see how they behave. */
    def->caps->data.storage.removable_media_size =
        def->caps->data.storage.num_blocks *
        def->caps->data.storage.logical_block_size;

    return 0;
}


static int
udevProcessCDROM(struct udev_device *device,
                 virNodeDeviceDef *def)
{
    int has_media = 0;

    /* NB: the drive_type string provided by udev is different from
     * that provided by HAL; now it's "cd" instead of "cdrom" We
     * change it to cdrom to preserve compatibility with earlier
     * versions of libvirt.  */
    VIR_FREE(def->caps->data.storage.drive_type);
    def->caps->data.storage.drive_type = g_strdup("cdrom");

    if (udevHasDeviceProperty(device, "ID_CDROM_MEDIA") &&
        udevGetIntProperty(device, "ID_CDROM_MEDIA", &has_media, 0) < 0)
        return -1;

    return udevProcessRemoveableMedia(device, def, has_media);
}


static int
udevProcessFloppy(struct udev_device *device,
                  virNodeDeviceDef *def)
{
    int has_media = 0;

    if (udevHasDeviceProperty(device, "ID_FS_LABEL")) {
        /* Legacy floppy */
        has_media = 1;
    }

    return udevProcessRemoveableMedia(device, def, has_media);
}


static int
udevProcessSD(struct udev_device *device,
              virNodeDeviceDef *def)
{
    virNodeDevCapStorage *storage = &def->caps->data.storage;

    if (udevGetUint64SysfsAttr(device, "size",
                               &storage->num_blocks) < 0)
        return -1;

    if (udevGetUint64SysfsAttr(device, "queue/logical_block_size",
                               &storage->logical_block_size) < 0)
        return -1;

    storage->size = storage->num_blocks * storage->logical_block_size;

    return 0;
}


static int
udevProcessDASD(struct udev_device *device,
                virNodeDeviceDef *def)
{
    virNodeDevCapStorage *storage = &def->caps->data.storage;

    if (udevGetStringSysfsAttr(device, "device/uid", &storage->serial) < 0)
        return -1;

    return udevProcessDisk(device, def);
}


/* This function exists to deal with the case in which a driver does
 * not provide a device type in the usual place, but udev told us it's
 * a storage device, and we can make a good guess at what kind of
 * storage device it is from other information that is provided. */
static int
udevKludgeStorageType(virNodeDeviceDef *def)
{
    size_t i;
    const struct {
        const char *prefix;
        const char *subst;
    } fixups[] = {
        /* virtio disk */
        { "/dev/vd", "disk" },

        /* For Direct Access Storage Devices (DASDs) there are
         * currently no identifiers in udev besides ID_PATH. Since
         * ID_TYPE=disk does not exist on DASDs they fall through
         * the udevProcessStorage detection logic. */
        { "/dev/dasd", "dasd" },

        /* NVMe disk. While strictly speaking /dev/nvme is a
         * controller not a disk, this function is called if and
         * only if @def is of VIR_NODE_DEV_CAP_STORAGE type. */
        { "/dev/nvme", "disk" },
    };

    VIR_DEBUG("Could not find definitive storage type for device "
              "with sysfs path '%s', trying to guess it",
              def->sysfs_path);

    for (i = 0; i < G_N_ELEMENTS(fixups); i++) {
        if (STRPREFIX(def->caps->data.storage.block, fixups[i].prefix)) {
            def->caps->data.storage.drive_type = g_strdup(fixups[i].subst);
            VIR_DEBUG("Found storage type '%s' for device with sysfs path '%s'",
                      def->caps->data.storage.drive_type,
                      def->sysfs_path);
            return 0;
        }
    }

    VIR_DEBUG("Could not determine storage type "
              "for device with sysfs path '%s'", def->sysfs_path);
    return -1;
}


static int
udevProcessStorage(struct udev_device *device,
                   virNodeDeviceDef *def)
{
    virNodeDevCapStorage *storage = &def->caps->data.storage;
    int ret = -1;
    int rv;
    const char* devnode;

    devnode = udev_device_get_devnode(device);
    if (!devnode) {
        VIR_DEBUG("No devnode for '%s'", udev_device_get_devpath(device));
        goto cleanup;
    }

    storage->block = g_strdup(devnode);

    udevGetStringProperty(device, "ID_BUS", &storage->bus);
    udevGetStringProperty(device, "ID_SERIAL", &storage->serial);

    if (udevGetStringSysfsAttr(device, "device/vendor", &storage->vendor) < 0)
        goto cleanup;
    if (def->caps->data.storage.vendor)
        virTrimSpaces(def->caps->data.storage.vendor, NULL);

    if (udevGetStringSysfsAttr(device, "device/model", &storage->model) < 0)
        goto cleanup;
    if (def->caps->data.storage.model)
        virTrimSpaces(def->caps->data.storage.model, NULL);
    /* There is no equivalent of the hotpluggable property in libudev,
     * but storage is going toward a world in which hotpluggable is
     * expected, so I don't see a problem with not having a property
     * for it. */

    udevGetStringProperty(device, "ID_TYPE", &storage->drive_type);

    if (!storage->drive_type ||
        STREQ(def->caps->data.storage.drive_type, "generic")) {
        /* All floppy drives have the ID_DRIVE_FLOPPY prop. This is
         * needed since legacy floppies don't have a drive_type */
        if (udevHasDeviceProperty(device, "ID_DRIVE_FLOPPY"))
            storage->drive_type = g_strdup("floppy");
        else if (udevHasDeviceProperty(device, "ID_CDROM"))
            storage->drive_type = g_strdup("cd");
        else if (udevHasDeviceProperty(device, "ID_DRIVE_FLASH_SD"))
            storage->drive_type = g_strdup("sd");
        else if (udevKludgeStorageType(def) != 0)
            goto cleanup;
    }

    if (STREQ(def->caps->data.storage.drive_type, "cd") ||
        STREQ(def->caps->data.storage.drive_type, "cd/dvd")) {
        rv = udevProcessCDROM(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "disk")) {
        rv = udevProcessDisk(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "floppy")) {
        rv = udevProcessFloppy(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "sd")) {
        rv = udevProcessSD(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "dasd")) {
        rv = udevProcessDASD(device, def);
    } else {
        VIR_DEBUG("Unsupported storage type '%s'",
                  def->caps->data.storage.drive_type);
        goto cleanup;
    }

    if (rv < 0)
        goto cleanup;

    udevGenerateDeviceName(device, def, storage->serial);
    ret = 0;

 cleanup:
    VIR_DEBUG("Storage ret=%d", ret);
    return ret;
}


static int
udevProcessSCSIGeneric(struct udev_device *dev,
                       virNodeDeviceDef *def)
{
    udevGetStringProperty(dev, "DEVNAME", &def->caps->data.sg.path);

    if (!def->caps->data.sg.path)
        return -1;

    udevGenerateDeviceName(dev, def, NULL);

    return 0;
}


static int
udevProcessMediatedDevice(struct udev_device *dev,
                          virNodeDeviceDef *def)
{
    int iommugrp = -1;
    g_autofree char *linkpath = NULL;
    g_autofree char *canonicalpath = NULL;
    virNodeDevCapMdev *data = &def->caps->data.mdev;
    struct udev_device *parent_device = NULL;

    /* Because of a kernel uevent race, we might get the 'add' event prior to
     * the sysfs tree being ready, so any attempt to access any sysfs attribute
     * would result in ENOENT and us dropping the device, so let's work around
     * it by waiting for the attributes to become available.
     */

    linkpath = g_strdup_printf("%s/mdev_type", udev_device_get_syspath(dev));

    if (virFileWaitForExists(linkpath, 10, 100) < 0) {
        virReportSystemError(errno,
                             _("failed to wait for file '%1$s' to appear"),
                             linkpath);
        return -1;
    }

    if (virFileResolveLink(linkpath, &canonicalpath) < 0) {
        virReportSystemError(errno, _("failed to resolve '%1$s'"), linkpath);
        return -1;
    }

    data->type = g_path_get_basename(canonicalpath);

    data->uuid = g_strdup(udev_device_get_sysname(dev));
    if ((iommugrp = virMediatedDeviceGetIOMMUGroupNum(data->uuid)) < 0)
        return -1;

    /* lookup the address of parent device */
    parent_device = udev_device_get_parent(dev);
    if (parent_device) {
        const char *parent_sysfs_path = udev_device_get_syspath(parent_device);
        if (parent_sysfs_path)
            data->parent_addr = g_path_get_basename(parent_sysfs_path);
    }

    if (!data->parent_addr) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not get parent of '%1$s'"),
                       udev_device_get_syspath(dev));
        return -1;
    }

    udevGenerateDeviceName(dev, def, data->parent_addr);

    data->iommuGroupNumber = iommugrp;

    return 0;
}


static int
udevGetCCWAddress(const char *sysfs_path,
                  virNodeDevCapData *data)
{
    char *p;

    if ((p = strrchr(sysfs_path, '/')) == NULL ||
        virCCWDeviceAddressParseFromString(p + 1,
                                           &data->ccw_dev.cssid,
                                           &data->ccw_dev.ssid,
                                           &data->ccw_dev.devno) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the CCW address from sysfs path: '%1$s'"),
                       sysfs_path);
        return -1;
    }

    return 0;
}


static int
udevProcessCCW(struct udev_device *device,
               virNodeDeviceDef *def)
{
    int online = 0;

    /* process only online devices to keep the list sane */
    if (udevGetIntSysfsAttr(device, "online", &online, 0) < 0 || online != 1)
        return -1;

    if (udevGetCCWAddress(def->sysfs_path, &def->caps->data) < 0)
        return -1;

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessCSS(struct udev_device *device,
               virNodeDeviceDef *def)
{
    g_autofree char *dev_busid = NULL;

    /* only process IO subchannel and vfio-ccw devices to keep the list sane */
    if (!def->driver ||
        (STRNEQ(def->driver, "io_subchannel") &&
         STRNEQ(def->driver, "vfio_ccw")))
        return -1;

    if (udevGetCCWAddress(def->sysfs_path, &def->caps->data) < 0)
        return -1;

    udevGenerateDeviceName(device, def, NULL);

    /* process optional channel devices information */
    udevGetStringSysfsAttr(device, "dev_busid", &dev_busid);

    if (dev_busid != NULL && STRNEQ(dev_busid, "none"))
        def->caps->data.ccw_dev.channel_dev_addr = virCCWDeviceAddressFromString(dev_busid);

    if (virNodeDeviceGetCSSDynamicCaps(def->sysfs_path, &def->caps->data.ccw_dev) < 0)
        return -1;

    return 0;
}


static int
udevGetVDPACharDev(const char *sysfs_path,
                   virNodeDevCapData *data)
{
    struct dirent *entry;
    g_autoptr(DIR) dir = NULL;
    int direrr;

    if (virDirOpenIfExists(&dir, sysfs_path) <= 0)
        return -1;

    while ((direrr = virDirRead(dir, &entry, NULL)) > 0) {
        if (g_str_has_prefix(entry->d_name, "vhost-vdpa")) {
            g_autofree char *chardev = g_strdup_printf("/dev/%s", entry->d_name);

            if (!virFileExists(chardev)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("vDPA chardev path '%1$s' does not exist"),
                               chardev);
                return -1;
            }
            VIR_DEBUG("vDPA chardev is at '%s'", chardev);

            data->vdpa.chardev = g_steal_pointer(&chardev);
            break;
        }
    }
    if (direrr < 0)
        return -1;

    return 0;
}

static int
udevProcessVDPA(struct udev_device *device,
                virNodeDeviceDef *def)
{
    udevGenerateDeviceName(device, def, NULL);

    if (udevGetVDPACharDev(def->sysfs_path, &def->caps->data) < 0)
        return -1;

    return 0;
}


static int
udevProcessAPCard(struct udev_device *device,
                  virNodeDeviceDef *def)
{
    char *c;
    virNodeDevCapData *data = &def->caps->data;

    /* The sysfs path would be in the format /sys/bus/ap/devices/cardXX,
       where XX is the ap adapter id */
    if ((c = strrchr(def->sysfs_path, '/')) == NULL ||
        virStrToLong_ui(c + 1 + strlen("card"), NULL, 16,
                        &data->ap_card.ap_adapter) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the AP Card from sysfs path: '%1$s'"),
                       def->sysfs_path);
        return -1;
    }

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessAPQueue(struct udev_device *device,
                   virNodeDeviceDef *def)
{
    char *c;
    virNodeDevCapData *data = &def->caps->data;

    /* The sysfs path would be in the format /sys/bus/ap/devices
       /XX.YYYY, where XX is the ap adapter id and YYYY is the ap
       domain id  */
    if ((c = strrchr(def->sysfs_path, '/')) == NULL ||
        virStrToLong_ui(c + 1, &c, 16, &data->ap_queue.ap_adapter) < 0 ||
        virStrToLong_ui(c + 1, &c, 16, &data->ap_queue.ap_domain) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the AP Queue from sysfs path: '%1$s'"),
                       def->sysfs_path);
        return -1;
    }

    udevGenerateDeviceName(device, def, NULL);

    return 0;
}


static int
udevProcessAPMatrix(struct udev_device *device,
                    virNodeDeviceDef *def)
{
    /* Both udev_device_get_sysname and udev_device_get_subsystem return
     * "matrix" for an AP matrix device, so in order to prevent confusion in
     * naming, let's fallback to hardcoding the name.
     */
    virNodeDevCapData *data = &def->caps->data;

    data->ap_matrix.addr =  g_strdup(udev_device_get_sysname(device));
    def->name = g_strdup("ap_matrix");

    if (virNodeDeviceGetAPMatrixDynamicCaps(def->sysfs_path,
                                            &data->ap_matrix) < 0)
        return -1;

    return 0;
}


static int
udevGetDeviceNodes(struct udev_device *device,
                   virNodeDeviceDef *def)
{
    const char *devnode = NULL;
    struct udev_list_entry *list_entry = NULL;
    int n = 0;

    devnode = udev_device_get_devnode(device);

    def->devnode = g_strdup(devnode);

    udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device))
        n++;

    def->devlinks = g_new0(char *, n + 1);

    n = 0;
    udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
        def->devlinks[n++] = g_strdup(udev_list_entry_get_name(list_entry));
    }

    return 0;
}


static int
udevGetDeviceType(struct udev_device *device,
                  virNodeDevCapType *type)
{
    const char *devtype = NULL;
    char *subsystem = NULL;
    int ret = -1;

    devtype = udev_device_get_devtype(device);
    *type = 0;

    if (devtype) {
        if (STREQ(devtype, "usb_device"))
            *type = VIR_NODE_DEV_CAP_USB_DEV;
        else if (STREQ(devtype, "usb_interface"))
            *type = VIR_NODE_DEV_CAP_USB_INTERFACE;
        else if (STREQ(devtype, "scsi_host"))
            *type = VIR_NODE_DEV_CAP_SCSI_HOST;
        else if (STREQ(devtype, "scsi_target"))
            *type = VIR_NODE_DEV_CAP_SCSI_TARGET;
        else if (STREQ(devtype, "scsi_device"))
            *type = VIR_NODE_DEV_CAP_SCSI;
        else if (STREQ(devtype, "disk"))
            *type = VIR_NODE_DEV_CAP_STORAGE;
        else if (STREQ(devtype, "wlan"))
            *type = VIR_NODE_DEV_CAP_NET;
        else if (STREQ(devtype, "drm_minor"))
            *type = VIR_NODE_DEV_CAP_DRM;
        else if (STREQ(devtype, "ap_card"))
            *type = VIR_NODE_DEV_CAP_AP_CARD;
        else if (STREQ(devtype, "ap_queue"))
            *type = VIR_NODE_DEV_CAP_AP_QUEUE;
    } else {
        /* PCI devices don't set the DEVTYPE property. */
        if (udevHasDeviceProperty(device, "PCI_CLASS"))
            *type = VIR_NODE_DEV_CAP_PCI_DEV;

        /* Wired network interfaces don't set the DEVTYPE property,
         * USB devices also have an INTERFACE property, but they do
         * set DEVTYPE, so if devtype is NULL and the INTERFACE
         * property exists, we have a network device. */
        if (udevHasDeviceProperty(device, "INTERFACE"))
            *type = VIR_NODE_DEV_CAP_NET;

        /* The following devices do not set the DEVTYPE property, therefore
         * we need to rely on the SUBSYSTEM property */
        udevGetStringProperty(device, "SUBSYSTEM", &subsystem);

        if (STREQ_NULLABLE(subsystem, "scsi_generic"))
            *type = VIR_NODE_DEV_CAP_SCSI_GENERIC;
        else if (STREQ_NULLABLE(subsystem, "mdev"))
            *type = VIR_NODE_DEV_CAP_MDEV;
        else if (STREQ_NULLABLE(subsystem, "ccw"))
            *type = VIR_NODE_DEV_CAP_CCW_DEV;
        else if (STREQ_NULLABLE(subsystem, "css"))
            *type = VIR_NODE_DEV_CAP_CSS_DEV;
        else if (STREQ_NULLABLE(subsystem, "vdpa"))
            *type = VIR_NODE_DEV_CAP_VDPA;
        else if (STREQ_NULLABLE(subsystem, "matrix"))
            *type = VIR_NODE_DEV_CAP_AP_MATRIX;
        else if (STREQ_NULLABLE(subsystem, "mtty"))
            *type = VIR_NODE_DEV_CAP_MDEV_TYPES;

        VIR_FREE(subsystem);
    }

    if (!*type)
        VIR_DEBUG("Could not determine device type for device "
                  "with sysfs name '%s'",
                  udev_device_get_sysname(device));
    else
        ret = 0;

    return ret;
}


static int
udevGetDeviceDetails(struct udev_device *device,
                     virNodeDeviceDef *def)
{
    switch (def->caps->data.type) {
    case VIR_NODE_DEV_CAP_PCI_DEV:
        return udevProcessPCI(device, def);
    case VIR_NODE_DEV_CAP_USB_DEV:
        return udevProcessUSBDevice(device, def);
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        return udevProcessUSBInterface(device, def);
    case VIR_NODE_DEV_CAP_NET:
        return udevProcessNetworkInterface(device, def);
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        return udevProcessSCSIHost(device, def);
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        return udevProcessSCSITarget(device, def);
    case VIR_NODE_DEV_CAP_SCSI:
        return udevProcessSCSIDevice(device, def);
    case VIR_NODE_DEV_CAP_STORAGE:
        return udevProcessStorage(device, def);
    case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        return udevProcessSCSIGeneric(device, def);
    case VIR_NODE_DEV_CAP_DRM:
        return udevProcessDRMDevice(device, def);
    case VIR_NODE_DEV_CAP_MDEV:
        return udevProcessMediatedDevice(device, def);
    case VIR_NODE_DEV_CAP_CCW_DEV:
        return udevProcessCCW(device, def);
    case VIR_NODE_DEV_CAP_CSS_DEV:
        return udevProcessCSS(device, def);
    case VIR_NODE_DEV_CAP_VDPA:
        return udevProcessVDPA(device, def);
    case VIR_NODE_DEV_CAP_AP_CARD:
        return udevProcessAPCard(device, def);
    case VIR_NODE_DEV_CAP_AP_QUEUE:
        return udevProcessAPQueue(device, def);
    case VIR_NODE_DEV_CAP_AP_MATRIX:
        return udevProcessAPMatrix(device, def);
    case VIR_NODE_DEV_CAP_MDEV_TYPES:
        return udevProcessMdevParent(device, def);
    case VIR_NODE_DEV_CAP_VPD:
    case VIR_NODE_DEV_CAP_SYSTEM:
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
    case VIR_NODE_DEV_CAP_LAST:
        break;
    }

    return 0;
}


static void scheduleMdevctlUpdate(udevEventData *data, bool force);


static int
udevRemoveOneDeviceSysPath(const char *path)
{
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *def;
    virObjectEvent *event = NULL;

    if (!(obj = virNodeDeviceObjListFindBySysfsPath(driver->devs, path))) {
        VIR_DEBUG("Failed to find device to remove that has udev path '%s'",
                  path);
        return -1;
    }
    def = virNodeDeviceObjGetDef(obj);

    event = virNodeDeviceEventLifecycleNew(def->name,
                                           VIR_NODE_DEVICE_EVENT_DELETED,
                                           0);

    /* If the device is a mediated device that has been 'stopped', it may still
     * be defined by mdevctl and can therefore be started again. Don't drop it
     * from the list of node devices */
    if (virNodeDeviceObjIsPersistent(obj)) {
        VIR_FREE(def->sysfs_path);
        virNodeDeviceObjSetActive(obj, false);
    } else {
        VIR_DEBUG("Removing device '%s' with sysfs path '%s'",
                  def->name, path);
        virNodeDeviceObjListRemove(driver->devs, obj);
    }
    virNodeDeviceObjEndAPI(&obj);

    /* cannot check for mdev_types since they have already been removed */
    scheduleMdevctlUpdate(driver->privateData, false);

    virObjectEventStateQueue(driver->nodeDeviceEventState, event);
    return 0;
}


static int
udevRemoveOneDevice(struct udev_device *device)
{
    const char *path = udev_device_get_syspath(device);

    return udevRemoveOneDeviceSysPath(path);
}


static int
udevSetParent(struct udev_device *device,
              virNodeDeviceDef *def)
{
    struct udev_device *parent_device = NULL;
    const char *parent_sysfs_path = NULL;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *objdef;

    parent_device = device;
    do {

        parent_device = udev_device_get_parent(parent_device);
        if (parent_device == NULL)
            break;

        parent_sysfs_path = udev_device_get_syspath(parent_device);
        if (parent_sysfs_path == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get syspath for parent of '%1$s'"),
                           udev_device_get_syspath(parent_device));
            return -1;
        }

        if ((obj = virNodeDeviceObjListFindBySysfsPath(driver->devs,
                                                       parent_sysfs_path))) {
            objdef = virNodeDeviceObjGetDef(obj);
            def->parent = g_strdup(objdef->name);
            virNodeDeviceObjEndAPI(&obj);

            def->parent_sysfs_path = g_strdup(parent_sysfs_path);
        }

    } while (def->parent == NULL && parent_device != NULL);

    if (!def->parent)
        def->parent = g_strdup("computer");

    return 0;
}

static int
udevAddOneDevice(struct udev_device *device)
{
    virNodeDeviceDef *def = NULL;
    virNodeDeviceObj *obj = NULL;
    virNodeDeviceDef *objdef;
    virObjectEvent *event = NULL;
    bool new_device = true;
    int ret = -1;
    bool persistent = false;
    bool autostart = false;
    bool is_mdev;
    bool has_mdev_types = false;

    def = g_new0(virNodeDeviceDef, 1);

    def->sysfs_path = g_strdup(udev_device_get_syspath(device));

    udevGetStringProperty(device, "DRIVER", &def->driver);

    def->caps = g_new0(virNodeDevCapsDef, 1);

    if (udevGetDeviceType(device, &def->caps->data.type) != 0)
        goto cleanup;

    if (udevGetDeviceNodes(device, def) != 0)
        goto cleanup;

    if (udevGetDeviceDetails(device, def) != 0)
        goto cleanup;

    if (udevSetParent(device, def) != 0)
        goto cleanup;

    is_mdev = def->caps->data.type == VIR_NODE_DEV_CAP_MDEV;

    if ((obj = virNodeDeviceObjListFindByName(driver->devs, def->name))) {
        objdef = virNodeDeviceObjGetDef(obj);

        if (is_mdev)
            nodeDeviceDefCopyFromMdevctl(def, objdef);

        persistent = virNodeDeviceObjIsPersistent(obj);
        autostart = virNodeDeviceObjIsAutostart(obj);

        /* If the device was defined by mdevctl and was never instantiated, it
         * won't have a sysfs path. We need to emit a CREATED event... */
        new_device = (objdef->sysfs_path == NULL);

        virNodeDeviceObjEndAPI(&obj);
    }

    /* If this is a device change, the old definition will be freed
     * and the current definition will take its place. */
    if (!(obj = virNodeDeviceObjListAssignDef(driver->devs, def)))
        goto cleanup;
    virNodeDeviceObjSetPersistent(obj, persistent);
    virNodeDeviceObjSetAutostart(obj, autostart);
    objdef = virNodeDeviceObjGetDef(obj);

    if (new_device)
        event = virNodeDeviceEventLifecycleNew(objdef->name,
                                               VIR_NODE_DEVICE_EVENT_CREATED,
                                               0);
    else
        event = virNodeDeviceEventUpdateNew(objdef->name);

    virNodeDeviceObjSetActive(obj, true);
    has_mdev_types = virNodeDeviceObjHasCap(obj, VIR_NODE_DEV_CAP_MDEV_TYPES);
    virNodeDeviceObjEndAPI(&obj);

    if (has_mdev_types)
        scheduleMdevctlUpdate(driver->privateData, false);

    ret = 0;

 cleanup:
    virObjectEventStateQueue(driver->nodeDeviceEventState, event);

    if (ret != 0) {
        VIR_DEBUG("Discarding device %d %p %s", ret, def,
                  def ? NULLSTR(def->sysfs_path) : "");
        virNodeDeviceDefFree(def);
    }

    return ret;
}


static int
udevProcessDeviceListEntry(struct udev *udev,
                           struct udev_list_entry *list_entry)
{
    struct udev_device *device;
    const char *name = NULL;
    int ret = -1;

    name = udev_list_entry_get_name(list_entry);

    device = udev_device_new_from_syspath(udev, name);

    if (device != NULL) {
        if (udevAddOneDevice(device) != 0) {
            VIR_DEBUG("Failed to create node device for udev device '%s'",
                      name);
        }
        ret = 0;
    }

    udev_device_unref(device);

    return ret;
}


/* We do not care about every device (see udevGetDeviceType).
 * Do not bother enumerating over subsystems that do not
 * contain interesting devices.
 */
const char *subsystem_ignored[] = {
    "acpi", "tty", "vc", "i2c",
};

static int
udevEnumerateAddMatches(struct udev_enumerate *udev_enumerate)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(subsystem_ignored); i++) {
        const char *s = subsystem_ignored[i];
        if (udev_enumerate_add_nomatch_subsystem(udev_enumerate, s) < 0) {
            virReportSystemError(errno, "%s", _("failed to add subsystem filter"));
            return -1;
        }
    }
    return 0;
}


static int
udevEnumerateDevices(struct udev *udev)
{
    struct udev_enumerate *udev_enumerate = NULL;
    struct udev_list_entry *list_entry = NULL;
    int ret = -1;

    udev_enumerate = udev_enumerate_new(udev);
    if (udevEnumerateAddMatches(udev_enumerate) < 0)
        goto cleanup;

    if (udev_enumerate_scan_devices(udev_enumerate) < 0)
        VIR_WARN("udev scan devices failed");

    udev_list_entry_foreach(list_entry,
                            udev_enumerate_get_list_entry(udev_enumerate)) {

        udevProcessDeviceListEntry(udev, list_entry);
    }

    ret = 0;
 cleanup:
    udev_enumerate_unref(udev_enumerate);
    return ret;
}


static void
udevPCITranslateDeinit(void)
{
#if defined __s390__ || defined __s390x_
    /* Nothing was initialized, nothing needs to be cleaned up */
#else
    /* pci_system_cleanup returns void */
    pci_system_cleanup();
#endif
    return;
}


static int
nodeStateCleanup(void)
{
    udevEventData *priv = NULL;

    if (!driver)
        return -1;

    priv = driver->privateData;
    if (priv) {
        VIR_WITH_OBJECT_LOCK_GUARD(priv) {
            priv->threadQuit = true;
            virCondSignal(&priv->threadCond);
        }
        if (priv->initThread) {
            virThreadJoin(priv->initThread);
            g_clear_pointer(&priv->initThread, g_free);
        }
        if (priv->th) {
            virThreadJoin(priv->th);
            g_clear_pointer(&priv->th, g_free);
        }
    }

    virObjectUnref(priv);
    virObjectUnref(driver->nodeDeviceEventState);

    virNodeDeviceObjListFree(driver->devs);

    if (driver->lockFD != -1)
        virPidFileRelease(driver->stateDir, "driver", driver->lockFD);

    VIR_FREE(driver->stateDir);
    virCondDestroy(&driver->initCond);
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);

    udevPCITranslateDeinit();
    return 0;
}


static int
udevHandleOneDevice(struct udev_device *device)
{
    virNodeDevCapType dev_cap_type;
    const char *action = udev_device_get_action(device);

    VIR_DEBUG("udev action: '%s': %s", action, udev_device_get_syspath(device));

    if (STREQ(action, "add") || STREQ(action, "change")) {
        int ret = udevAddOneDevice(device);
        if (ret == 0 &&
            udevGetDeviceType(device, &dev_cap_type) == 0 &&
            dev_cap_type == VIR_NODE_DEV_CAP_MDEV)
            scheduleMdevctlUpdate(driver->privateData, false);
        return ret;
    }

    if (STREQ(action, "remove"))
        return udevRemoveOneDevice(device);

    if (STREQ(action, "move")) {
        const char *devpath_old = udevGetDeviceProperty(device, "DEVPATH_OLD");

        if (devpath_old) {
            g_autofree char *devpath_old_fixed = g_strdup_printf("/sys%s", devpath_old);

            udevRemoveOneDeviceSysPath(devpath_old_fixed);
        }

        return udevAddOneDevice(device);
    }

    return 0;
}


/* the caller must be holding the udevEventData object lock prior to calling
 * this function
 */
static bool
udevEventMonitorSanityCheck(udevEventData *priv,
                            int fd)
{
    int rc = -1;

    rc = udev_monitor_get_fd(priv->udev_monitor);
    if (fd != rc) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("File descriptor returned by udev %1$d does not match node device file descriptor %2$d"),
                       fd, rc);

        /* this is a non-recoverable error, let's remove the handle, so that we
         * don't get in here again because of some spurious behaviour and report
         * the same error multiple times
         */
        virEventRemoveHandle(priv->watch);
        priv->watch = -1;

        return false;
    }

    return true;
}


/**
 * udevEventHandleThread
 * @opaque: unused
 *
 * Thread to handle the udevEventHandleCallback processing when udev
 * tells us there's a device change for us (add, modify, delete, etc).
 *
 * Once notified there is data to be processed, the actual @device
 * data retrieval by libudev may be delayed due to how threads are
 * scheduled. In fact, the event loop could be scheduled earlier than
 * the handler thread, thus potentially emitting the very same event
 * the handler thread is currently trying to process, simply because
 * the data hadn't been retrieved from the socket.
 *
 * NB: Some older distros, such as CentOS 6, libudev opens sockets
 * without the NONBLOCK flag which might cause issues with event
 * based algorithm. Although the issue can be mitigated by resetting
 * priv->dataReady for each event found; however, the scheduler issues
 * would still come into play.
 */
static void
udevEventHandleThread(void *opaque G_GNUC_UNUSED)
{
    udevEventData *priv = driver->privateData;
    struct udev_device *device = NULL;

    /* continue rather than break from the loop on non-fatal errors */
    while (1) {
        VIR_WITH_OBJECT_LOCK_GUARD(priv) {
            while (!priv->dataReady && !priv->threadQuit) {
                if (virCondWait(&priv->threadCond, &priv->parent.lock)) {
                    virReportSystemError(errno, "%s",
                                         _("handler failed to wait on condition"));
                    return;
                }
            }

            if (priv->threadQuit)
                return;

            errno = 0;
            device = udev_monitor_receive_device(priv->udev_monitor);
        }

        if (!device) {
            if (errno == 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to receive device from udev monitor"));
                return;
            }

            /* POSIX allows both EAGAIN and EWOULDBLOCK to be used
             * interchangeably when the read would block or timeout was fired.
             * EINVAL might happen on too large udev entries, ignore those for
             * the robustness of udevEventHandleThread.
             */
            VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINVAL) {
            VIR_WARNINGS_RESET
                virReportSystemError(errno, "%s",
                                     _("failed to receive device from udev monitor"));
                return;
            }

            /* Trying to move the reset of the @priv->dataReady flag to
             * after the udev_monitor_receive_device wouldn't help much
             * due to event mgmt and scheduler timing. */
            VIR_WITH_OBJECT_LOCK_GUARD(priv) {
                priv->dataReady = false;
            }

            continue;
        }

        udevHandleOneDevice(device);
        udev_device_unref(device);

        /* Instead of waiting for the next event after processing @device
         * data, let's keep reading from the udev monitor and only wait
         * for the next event once either a EAGAIN or a EWOULDBLOCK error
         * is encountered. */
    }
}


static void
udevEventHandleCallback(int watch G_GNUC_UNUSED,
                        int fd,
                        int events G_GNUC_UNUSED,
                        void *data G_GNUC_UNUSED)
{
    udevEventData *priv = driver->privateData;
    VIR_LOCK_GUARD lock = virObjectLockGuard(priv);

    if (!udevEventMonitorSanityCheck(priv, fd))
        priv->threadQuit = true;
    else
        priv->dataReady = true;

    virCondSignal(&priv->threadCond);
}


/* DMI is intel-compatible specific */
#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
static void
udevGetDMIData(virNodeDevCapSystem *syscap)
{
    udevEventData *priv = driver->privateData;
    struct udev *udev = NULL;
    struct udev_device *device = NULL;
    virNodeDevCapSystemHardware *hardware = &syscap->hardware;
    virNodeDevCapSystemFirmware *firmware = &syscap->firmware;

    VIR_WITH_OBJECT_LOCK_GUARD(priv) {
        udev = udev_monitor_get_udev(priv->udev_monitor);

        device = udev_device_new_from_syspath(udev, DMI_DEVPATH);
        if (device == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get udev device for syspath '%1$s'"),
                           DMI_DEVPATH);
            return;
        }
    }

    if (udevGetStringSysfsAttr(device, "product_name",
                               &syscap->product_name) < 0)
        goto cleanup;
    if (udevGetStringSysfsAttr(device, "sys_vendor",
                               &hardware->vendor_name) < 0)
        goto cleanup;
    if (udevGetStringSysfsAttr(device, "product_version",
                               &hardware->version) < 0)
        goto cleanup;
    if (udevGetStringSysfsAttr(device, "product_serial",
                               &hardware->serial) < 0)
        goto cleanup;

    if (virGetHostUUID(hardware->uuid))
        goto cleanup;

    if (udevGetStringSysfsAttr(device, "bios_vendor",
                               &firmware->vendor_name) < 0)
        goto cleanup;
    if (udevGetStringSysfsAttr(device, "bios_version",
                               &firmware->version) < 0)
        goto cleanup;
    if (udevGetStringSysfsAttr(device, "bios_date",
                               &firmware->release_date) < 0)
        goto cleanup;

 cleanup:
    if (device != NULL)
        udev_device_unref(device);
    return;
}
#endif


static int
udevSetupSystemDev(void)
{
    virNodeDeviceDef *def = NULL;
    virNodeDeviceObj *obj = NULL;
    int ret = -1;

    def = g_new0(virNodeDeviceDef, 1);

    def->name = g_strdup("computer");
    def->caps = g_new0(virNodeDevCapsDef, 1);

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
    udevGetDMIData(&def->caps->data.system);
#endif

    if (!(obj = virNodeDeviceObjListAssignDef(driver->devs, def)))
        goto cleanup;

    virNodeDeviceObjSetActive(obj, true);
    virNodeDeviceObjSetAutostart(obj, true);
    virNodeDeviceObjSetPersistent(obj, true);

    virNodeDeviceObjEndAPI(&obj);

    ret = 0;

 cleanup:
    if (ret == -1)
        virNodeDeviceDefFree(def);

    return ret;
}


static void
nodeStateInitializeEnumerate(void *opaque)
{
    struct udev *udev = opaque;
    udevEventData *priv = driver->privateData;

    /* Populate with known devices */
    if (udevEnumerateDevices(udev) != 0)
        goto error;
    /* Load persistent mdevs (which might not be activated yet) and additional
     * information about active mediated devices from mdevctl */
    if (nodeDeviceUpdateMediatedDevices() != 0)
        goto error;

 cleanup:
    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        driver->initialized = true;
        virCondBroadcast(&driver->initCond);
    }

    return;

 error:
    VIR_WITH_OBJECT_LOCK_GUARD(priv) {
        ignore_value(virEventRemoveHandle(priv->watch));
        priv->watch = -1;
        priv->threadQuit = true;
        virCondSignal(&priv->threadCond);
    }

    goto cleanup;
}


static int
udevPCITranslateInit(bool privileged G_GNUC_UNUSED)
{
#if defined __s390__ || defined __s390x_
    /* On s390(x) system there is no PCI bus.
     * Therefore there is nothing to initialize here. */
#else
    int rc;

    if ((rc = pci_system_init()) != 0) {
        /* Ignore failure as non-root; udev is not as helpful in that
         * situation, but a non-privileged user won't benefit much
         * from udev in the first place.  */
        if (errno != ENOENT && (privileged  || errno != EACCES)) {
            virReportSystemError(rc, "%s",
                                 _("Failed to initialize libpciaccess"));
            return -1;
        }
    }
#endif
    return 0;
}


static void
mdevctlUpdateThreadFunc(void *opaque G_GNUC_UNUSED)
{
    udevEventData *priv = driver->privateData;
    VIR_LOCK_GUARD lock = virLockGuardLock(&priv->mdevctlLock);

    if (nodeDeviceUpdateMediatedDevices() < 0)
        VIR_WARN("mdevctl failed to update mediated devices");
}


static void
launchMdevctlUpdateThread(int timer G_GNUC_UNUSED, void *opaque)
{
    udevEventData *priv = opaque;
    virThread thread;

    if (priv->mdevctlTimeout > 0) {
        virEventRemoveTimeout(priv->mdevctlTimeout);
        priv->mdevctlTimeout = -1;
    }

    if (virThreadCreateFull(&thread, false, mdevctlUpdateThreadFunc,
                            "mdevctl-thread", false, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to create mdevctl thread"));
    }
}


static void
mdevctlEventHandleCallback(GFileMonitor *monitor G_GNUC_UNUSED,
                           GFile *file,
                           GFile *other_file G_GNUC_UNUSED,
                           GFileMonitorEvent event_type,
                           gpointer user_data);


/* Recursively monitors a directory and its subdirectories for file changes and
 * returns a GList of GFileMonitor objects */
static GList*
monitorFileRecursively(udevEventData *udev,
                       GFile *file)
{
    GList *monitors = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GFileEnumerator) children = NULL;
    GFileMonitor *mon;

    if (!(children = g_file_enumerate_children(file, "standard::*",
                                               G_FILE_QUERY_INFO_NONE, NULL, &error)))
        goto error;

    if (!(mon = g_file_monitor(file, G_FILE_MONITOR_NONE, NULL, &error)))
        goto error;

    g_signal_connect(mon, "changed",
                     G_CALLBACK(mdevctlEventHandleCallback), udev);

    monitors = g_list_append(monitors, mon);

    while (true) {
        GFileInfo *info = NULL;
        GFile *child = NULL;
        GList *child_monitors = NULL;

        if (!g_file_enumerator_iterate(children, &info, &child, NULL, &error))
            goto error;

        if (!info)
            break;

        if (g_file_query_file_type(child, G_FILE_QUERY_INFO_NONE, NULL) ==
            G_FILE_TYPE_DIRECTORY) {

            child_monitors = monitorFileRecursively(udev, child);
            if (child_monitors)
                monitors = g_list_concat(monitors, child_monitors);
        }
    }

    return monitors;

 error:
    g_list_free_full(monitors, g_object_unref);
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unable to monitor directory: %1$s"), error->message);
    g_clear_error(&error);
    return NULL;
}


static int
mdevctlEnableMonitor(udevEventData *priv)
{
    g_autoptr(GFile) mdevctlConfigDir = NULL;
    const char *mdevctlDir = "/etc/mdevctl.d";

    if (!virFileExists(mdevctlDir))
        return 0;

    mdevctlConfigDir = g_file_new_for_path(mdevctlDir);

    /* mdevctl may add notification events in the future:
     * https://github.com/mdevctl/mdevctl/issues/27. For now, fall back to
     * monitoring the mdevctl configuration directory for changes.
     * mdevctl configuration is stored in a directory tree within
     * /etc/mdevctl.d/. There is a directory for each parent device, which
     * contains a file defining each mediated device */
    VIR_WITH_MUTEX_LOCK_GUARD(&priv->mdevctlLock) {
        if (!(priv->mdevctlMonitors = monitorFileRecursively(priv, mdevctlConfigDir)))
            return -1;
    }

    return 0;
}


/* Schedules an mdevctl update for 100ms in the future, canceling any existing
 * timeout that may have been set. In this way, multiple update requests in
 * quick succession can be collapsed into a single update. if @force is true,
 * an update thread will be spawned immediately. */
static void
scheduleMdevctlUpdate(udevEventData *data,
                      bool force)
{
    if (!force) {
        if (data->mdevctlTimeout > 0)
            virEventRemoveTimeout(data->mdevctlTimeout);
        data->mdevctlTimeout = virEventAddTimeout(100, launchMdevctlUpdateThread,
                                                  data, NULL);
        return;
    }

    launchMdevctlUpdateThread(-1, data);
}


static void
mdevctlEventHandleCallback(GFileMonitor *monitor G_GNUC_UNUSED,
                           GFile *file,
                           GFile *other_file G_GNUC_UNUSED,
                           GFileMonitorEvent event_type,
                           gpointer user_data)
{
    udevEventData *priv = user_data;
    /* if a new directory appears, monitor that directory for changes */
    if (event_type == G_FILE_MONITOR_EVENT_CREATED) {
        GFileType file_type = g_file_query_file_type(file,
                                                     G_FILE_QUERY_INFO_NONE,
                                                     NULL);
        if (file_type == G_FILE_TYPE_DIRECTORY) {
            GList *newmonitors = monitorFileRecursively(priv, file);

            VIR_WITH_MUTEX_LOCK_GUARD(&priv->mdevctlLock) {
                priv->mdevctlMonitors = g_list_concat(priv->mdevctlMonitors,
                                                      newmonitors);
            }
        }
    }

    /* When mdevctl creates a device, it can result in multiple notify events
     * emitted for a single logical change (e.g. several CHANGED events, or a
     * CREATED and CHANGED event followed by CHANGES_DONE_HINT). To avoid
     * spawning a mdevctl thread multiple times for a single logical
     * configuration change, try to coalesce these changes by waiting for the
     * CHANGES_DONE_HINT event. As a fallback,  add a timeout to trigger the
     * signal if that event never comes */
    scheduleMdevctlUpdate(priv, (event_type == G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT));
}


static int
nodeStateInitialize(bool privileged,
                    const char *root,
                    bool monolithic G_GNUC_UNUSED,
                    virStateInhibitCallback callback G_GNUC_UNUSED,
                    void *opaque G_GNUC_UNUSED)
{
    udevEventData *priv = NULL;
    struct udev *udev = NULL;

    if (root != NULL) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Driver does not support embedded mode"));
        return -1;
    }

    driver = g_new0(virNodeDeviceDriverState, 1);

    driver->lockFD = -1;
    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }
    if (virCondInit(&driver->initCond) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize condition variable"));
        virMutexDestroy(&driver->lock);
        VIR_FREE(driver);
        return VIR_DRV_STATE_INIT_ERROR;
    }

    driver->privileged = privileged;

    if (privileged) {
        driver->stateDir = g_strdup_printf("%s/libvirt/nodedev", RUNSTATEDIR);
    } else {
        g_autofree char *rundir = NULL;

        rundir = virGetUserRuntimeDirectory();
        driver->stateDir = g_strdup_printf("%s/nodedev/run", rundir);
    }

    if (g_mkdir_with_parents(driver->stateDir, S_IRWXU) < 0) {
        virReportSystemError(errno, _("cannot create state directory '%1$s'"),
                             driver->stateDir);
        goto cleanup;
    }

    if ((driver->lockFD =
         virPidFileAcquire(driver->stateDir, "driver", getpid())) < 0)
        goto cleanup;

    if (!(driver->devs = virNodeDeviceObjListNew()) ||
        !(priv = udevEventDataNew()))
        goto cleanup;

    virObjectLock(priv);

    driver->privateData = priv;
    driver->nodeDeviceEventState = virObjectEventStateNew();

    driver->parserCallbacks.postParse = nodeDeviceDefPostParse;
    driver->parserCallbacks.validate = nodeDeviceDefValidate;

    if (udevPCITranslateInit(privileged) < 0)
        goto unlock;

    udev = udev_new();
    if (!udev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create udev context"));
        goto unlock;
    }

    priv->udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
    if (!priv->udev_monitor) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("udev_monitor_new_from_netlink returned NULL"));
        goto unlock;
    }

    udev_monitor_enable_receiving(priv->udev_monitor);

    /* mimic udevd's behaviour and override the systems rmem_max limit in case
     * there's a significant number of device 'add' events
     */
    if (geteuid() == 0)
        udev_monitor_set_receive_buffer_size(priv->udev_monitor,
                                             128 * 1024 * 1024);

    priv->th = g_new0(virThread, 1);
    if (virThreadCreateFull(priv->th, true, udevEventHandleThread,
                            "udev-event", false, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to create udev handler thread"));
        g_clear_pointer(&priv->th, g_free);
        goto unlock;
    }

    /* We register the monitor with the event callback so we are
     * notified by udev of device changes before we enumerate existing
     * devices because libvirt will simply recreate the device if we
     * try to register it twice, i.e., if the device appears between
     * the time we register the callback and the time we begin
     * enumeration.  The alternative is to register the callback after
     * we enumerate, in which case we will fail to create any devices
     * that appear while the enumeration is taking place.  */
    priv->watch = virEventAddHandle(udev_monitor_get_fd(priv->udev_monitor),
                                    VIR_EVENT_HANDLE_READABLE,
                                    udevEventHandleCallback, NULL, NULL);
    if (priv->watch == -1)
        goto unlock;

    if (mdevctlEnableMonitor(priv) < 0)
        goto unlock;

    virObjectUnlock(priv);

    /* Create a fictional 'computer' device to root the device tree. */
    if (udevSetupSystemDev() != 0)
        goto cleanup;

    priv->initThread = g_new0(virThread, 1);
    if (virThreadCreateFull(priv->initThread, true, nodeStateInitializeEnumerate,
                            "nodedev-init", false, udev) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to create udev enumerate thread"));
        g_clear_pointer(&priv->initThread, g_free);
        goto cleanup;
    }

    return VIR_DRV_STATE_INIT_COMPLETE;

 cleanup:
    nodeStateCleanup();
    return VIR_DRV_STATE_INIT_ERROR;

 unlock:
    virObjectUnlock(priv);
    goto cleanup;
}


static int
nodeStateReload(void)
{
    return 0;
}


static virNodeDeviceDriver udevNodeDeviceDriver = {
    .name = "udev",
    .nodeNumOfDevices = nodeNumOfDevices, /* 0.7.3 */
    .nodeListDevices = nodeListDevices, /* 0.7.3 */
    .connectListAllNodeDevices = nodeConnectListAllNodeDevices, /* 0.10.2 */
    .connectNodeDeviceEventRegisterAny = nodeConnectNodeDeviceEventRegisterAny, /* 2.2.0 */
    .connectNodeDeviceEventDeregisterAny = nodeConnectNodeDeviceEventDeregisterAny, /* 2.2.0 */
    .nodeDeviceLookupByName = nodeDeviceLookupByName, /* 0.7.3 */
    .nodeDeviceLookupSCSIHostByWWN = nodeDeviceLookupSCSIHostByWWN, /* 1.0.2 */
    .nodeDeviceGetXMLDesc = nodeDeviceGetXMLDesc, /* 0.7.3 */
    .nodeDeviceGetParent = nodeDeviceGetParent, /* 0.7.3 */
    .nodeDeviceNumOfCaps = nodeDeviceNumOfCaps, /* 0.7.3 */
    .nodeDeviceListCaps = nodeDeviceListCaps, /* 0.7.3 */
    .nodeDeviceCreateXML = nodeDeviceCreateXML, /* 0.7.3 */
    .nodeDeviceDestroy = nodeDeviceDestroy, /* 0.7.3 */
    .nodeDeviceDefineXML = nodeDeviceDefineXML, /* 7.3.0 */
    .nodeDeviceUndefine = nodeDeviceUndefine, /* 7.3.0 */
    .nodeDeviceCreate = nodeDeviceCreate, /* 7.3.0 */
    .nodeDeviceSetAutostart = nodeDeviceSetAutostart, /* 7.8.0 */
    .nodeDeviceGetAutostart = nodeDeviceGetAutostart, /* 7.8.0 */
    .nodeDeviceIsPersistent = nodeDeviceIsPersistent, /* 7.8.0 */
    .nodeDeviceIsActive = nodeDeviceIsActive, /* 7.8.0 */
};


static virHypervisorDriver udevHypervisorDriver = {
    .name = "nodedev",
    .connectOpen = nodeConnectOpen, /* 4.1.0 */
    .connectClose = nodeConnectClose, /* 4.1.0 */
    .connectIsEncrypted = nodeConnectIsEncrypted, /* 4.1.0 */
    .connectIsSecure = nodeConnectIsSecure, /* 4.1.0 */
    .connectIsAlive = nodeConnectIsAlive, /* 4.1.0 */
};


static virConnectDriver udevConnectDriver = {
    .localOnly = true,
    .uriSchemes = (const char *[]){ "nodedev", NULL },
    .hypervisorDriver = &udevHypervisorDriver,
    .nodeDeviceDriver = &udevNodeDeviceDriver,
};


static virStateDriver udevStateDriver = {
    .name = "udev",
    .stateInitialize = nodeStateInitialize, /* 0.7.3 */
    .stateCleanup = nodeStateCleanup, /* 0.7.3 */
    .stateReload = nodeStateReload, /* 0.7.3 */
};


int
udevNodeRegister(void)
{
    VIR_DEBUG("Registering udev node device backend");

    if (virRegisterConnectDriver(&udevConnectDriver, false) < 0)
        return -1;
    if (virSetSharedNodeDeviceDriver(&udevNodeDeviceDriver) < 0)
        return -1;

    return virRegisterStateDriver(&udevStateDriver);
}
