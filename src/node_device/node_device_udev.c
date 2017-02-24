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
 *
 * Author: Dave Allan <dallan@redhat.com>
 */

#include <config.h>
#include <libudev.h>
#include <pciaccess.h>
#include <scsi/scsi.h>
#include <c-ctype.h>

#include "dirname.h"
#include "node_device_conf.h"
#include "node_device_event.h"
#include "node_device_driver.h"
#include "node_device_linux_sysfs.h"
#include "node_device_udev.h"
#include "virerror.h"
#include "driver.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virfile.h"
#include "virpci.h"
#include "virstring.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("node_device.node_device_udev");

#ifndef TYPE_RAID
# define TYPE_RAID 12
#endif

struct _udevPrivate {
    struct udev_monitor *udev_monitor;
    int watch;
    bool privileged;
};


static bool
udevHasDeviceProperty(struct udev_device *dev,
                      const char *key)
{
    if (udev_device_get_property_value(dev, key))
        return true;

    return false;
}


static const char *udevGetDeviceProperty(struct udev_device *udev_device,
                                         const char *property_key)
{
    const char *ret = NULL;

    ret = udev_device_get_property_value(udev_device, property_key);

    VIR_DEBUG("Found property key '%s' value '%s' for device with sysname '%s'",
              property_key, NULLSTR(ret), udev_device_get_sysname(udev_device));

    return ret;
}


static int udevGetStringProperty(struct udev_device *udev_device,
                                 const char *property_key,
                                 char **value)
{
    if (VIR_STRDUP(*value,
                   udevGetDeviceProperty(udev_device, property_key)) < 0)
        return -1;

    return 0;
}


static int udevGetIntProperty(struct udev_device *udev_device,
                              const char *property_key,
                              int *value,
                              int base)
{
    const char *str = NULL;

    str = udevGetDeviceProperty(udev_device, property_key);

    if (str && virStrToLong_i(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%s' to int"), str);
        return -1;
    }
    return 0;
}


static int udevGetUintProperty(struct udev_device *udev_device,
                               const char *property_key,
                               unsigned int *value,
                               int base)
{
    const char *str = NULL;

    str = udevGetDeviceProperty(udev_device, property_key);

    if (str && virStrToLong_ui(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%s' to int"), str);
        return -1;
    }
    return 0;
}


static const char *udevGetDeviceSysfsAttr(struct udev_device *udev_device,
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


static int udevGetStringSysfsAttr(struct udev_device *udev_device,
                                  const char *attr_name,
                                  char **value)
{
    if (VIR_STRDUP(*value, udevGetDeviceSysfsAttr(udev_device, attr_name)) < 0)
        return -1;

    virStringStripControlChars(*value);

    if (*value != NULL && (STREQ(*value, "")))
        VIR_FREE(*value);

    return 0;
}


static int udevGetIntSysfsAttr(struct udev_device *udev_device,
                               const char *attr_name,
                               int *value,
                               int base)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_i(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%s' to int"), str);
        return -1;
    }

    return 0;
}


static int udevGetUintSysfsAttr(struct udev_device *udev_device,
                                const char *attr_name,
                                unsigned int *value,
                                int base)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_ui(str, NULL, base, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%s' to unsigned int"), str);
        return -1;
    }

    return 0;
}


static int udevGetUint64SysfsAttr(struct udev_device *udev_device,
                                  const char *attr_name,
                                  unsigned long long *value)
{
    const char *str = NULL;

    str = udevGetDeviceSysfsAttr(udev_device, attr_name);

    if (str && virStrToLong_ull(str, NULL, 0, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to convert '%s' to unsigned long long"), str);
        return -1;
    }

    return 0;
}


static int udevGenerateDeviceName(struct udev_device *device,
                                  virNodeDeviceDefPtr def,
                                  const char *s)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s_%s",
                      udev_device_get_subsystem(device),
                      udev_device_get_sysname(device));

    if (s != NULL)
        virBufferAsprintf(&buf, "_%s", s);

    if (virBufferCheckError(&buf) < 0)
        return -1;

    def->name = virBufferContentAndReset(&buf);

    for (i = 0; i < strlen(def->name); i++) {
        if (!(c_isalnum(*(def->name + i))))
            *(def->name + i) = '_';
    }

    return 0;
}

#if HAVE_UDEV_LOGGING
typedef void (*udevLogFunctionPtr)(struct udev *udev,
                                   int priority,
                                   const char *file,
                                   int line,
                                   const char *fn,
                                   const char *format,
                                   va_list args);

static void
ATTRIBUTE_FMT_PRINTF(6, 0)
udevLogFunction(struct udev *udev ATTRIBUTE_UNUSED,
                int priority,
                const char *file,
                int line,
                const char *fn,
                const char *fmt,
                va_list args)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *format = NULL;

    virBufferAdd(&buf, fmt, -1);
    virBufferTrim(&buf, "\n", -1);

    format = virBufferContentAndReset(&buf);

    virLogVMessage(&virLogSelf,
                   virLogPriorityFromSyslog(priority),
                   file, line, fn, NULL, format ? format : fmt, args);

    VIR_FREE(format);
}
#endif


static int udevTranslatePCIIds(unsigned int vendor,
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

    /* pci_get_strings returns void */
    pci_get_strings(&m,
                    &device_name,
                    &vendor_name,
                    NULL,
                    NULL);

    if (VIR_STRDUP(*vendor_string, vendor_name) < 0 ||
        VIR_STRDUP(*product_string, device_name) < 0)
        return -1;

    return 0;
}


static int udevProcessPCI(struct udev_device *device,
                          virNodeDeviceDefPtr def)
{
    const char *syspath = NULL;
    virNodeDevCapPCIDevPtr pci_dev = &def->caps->data.pci_dev;
    virPCIEDeviceInfoPtr pci_express = NULL;
    virPCIDevicePtr pciDev = NULL;
    udevPrivate *priv = driver->privateData;
    int ret = -1;
    char *p;

    syspath = udev_device_get_syspath(device);

    if (udevGetUintProperty(device, "PCI_CLASS", &pci_dev->class, 16) < 0)
        goto cleanup;

    if ((p = strrchr(syspath, '/')) == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->domain) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->bus) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->slot) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 16, &pci_dev->function) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the PCI address from sysfs path: '%s'"),
                       syspath);
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

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        goto cleanup;

    /* The default value is -1, because it can't be 0
     * as zero is valid node number. */
    pci_dev->numa_node = -1;
    if (udevGetIntSysfsAttr(device, "numa_node",
                            &pci_dev->numa_node, 10) < 0)
        goto cleanup;

    if (nodeDeviceSysfsGetPCIRelatedDevCaps(syspath,
                                            &def->caps->data.pci_dev) < 0)
        goto cleanup;

    if (!(pciDev = virPCIDeviceNew(pci_dev->domain,
                                   pci_dev->bus,
                                   pci_dev->slot,
                                   pci_dev->function)))
        goto cleanup;

    /* We need to be root to read PCI device configs */
    if (priv->privileged) {
        if (virPCIGetHeaderType(pciDev, &pci_dev->hdrType) < 0)
            goto cleanup;

        if (virPCIDeviceIsPCIExpress(pciDev) > 0) {
            if (VIR_ALLOC(pci_express) < 0)
                goto cleanup;

            if (virPCIDeviceHasPCIExpressLink(pciDev) > 0) {
                if (VIR_ALLOC(pci_express->link_cap) < 0 ||
                    VIR_ALLOC(pci_express->link_sta) < 0)
                    goto cleanup;

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
            pci_dev->pci_express = pci_express;
            pci_express = NULL;
        }
    }

    ret = 0;

 cleanup:
    virPCIDeviceFree(pciDev);
    virPCIEDeviceInfoFree(pci_express);
    return ret;
}

static int drmGetMinorType(int minor)
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

static int udevProcessDRMDevice(struct udev_device *device,
                                virNodeDeviceDefPtr def)
{
    virNodeDevCapDRMPtr drm = &def->caps->data.drm;
    int minor;

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        return -1;

    if (udevGetIntProperty(device, "MINOR", &minor, 10) < 0)
        return -1;

    if ((minor = drmGetMinorType(minor)) == -1)
        return -1;

    drm->type = minor;

    return 0;
}

static int udevProcessUSBDevice(struct udev_device *device,
                                virNodeDeviceDefPtr def)
{
    virNodeDevCapUSBDevPtr usb_dev = &def->caps->data.usb_dev;

    if (udevGetUintProperty(device, "BUSNUM", &usb_dev->bus, 10) < 0)
        return -1;
    if (udevGetUintProperty(device, "DEVNUM", &usb_dev->device, 10) < 0)
        return -1;
    if (udevGetUintProperty(device, "ID_VENDOR_ID", &usb_dev->vendor, 16) < 0)
        return -1;

    if (udevGetStringProperty(device,
                              "ID_VENDOR_FROM_DATABASE",
                              &usb_dev->vendor_name) < 0)
        return -1;

    if (!usb_dev->vendor_name &&
        udevGetStringSysfsAttr(device, "manufacturer",
                               &usb_dev->vendor_name) < 0)
        return -1;

    if (udevGetUintProperty(device, "ID_MODEL_ID", &usb_dev->product, 16) < 0)
        return -1;

    if (udevGetStringProperty(device,
                              "ID_MODEL_FROM_DATABASE",
                              &usb_dev->product_name) < 0)
        return -1;

    if (!usb_dev->product_name &&
        udevGetStringSysfsAttr(device, "product",
                               &usb_dev->product_name) < 0)
        return -1;

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        return -1;

    return 0;
}


static int udevProcessUSBInterface(struct udev_device *device,
                                   virNodeDeviceDefPtr def)
{
    virNodeDevCapUSBIfPtr usb_if = &def->caps->data.usb_if;

    if (udevGetUintSysfsAttr(device, "bInterfaceNumber",
                             &usb_if->number, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceClass",
                             &usb_if->_class, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceSubClass",
                             &usb_if->subclass, 16) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "bInterfaceProtocol",
                             &usb_if->protocol, 16) < 0)
        return -1;

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        return -1;

    return 0;
}


static int udevProcessNetworkInterface(struct udev_device *device,
                                       virNodeDeviceDefPtr def)
{
    const char *devtype = udev_device_get_devtype(device);
    virNodeDevCapNetPtr net = &def->caps->data.net;

    if (devtype && STREQ(devtype, "wlan")) {
        net->subtype = VIR_NODE_DEV_CAP_NET_80211;
    } else {
        net->subtype = VIR_NODE_DEV_CAP_NET_80203;
    }

    if (udevGetStringProperty(device,
                              "INTERFACE",
                              &net->ifname) < 0)
        return -1;

    if (udevGetStringSysfsAttr(device, "address",
                               &net->address) < 0)
        return -1;

    if (udevGetUintSysfsAttr(device, "addr_len", &net->address_len, 0) < 0)
        return -1;

    if (udevGenerateDeviceName(device, def, net->address) != 0)
        return -1;

    if (virNetDevGetLinkInfo(net->ifname, &net->lnk) < 0)
        return -1;

    if (virNetDevGetFeatures(net->ifname, &net->features) < 0)
        return -1;

    return 0;
}


static int udevProcessSCSIHost(struct udev_device *device ATTRIBUTE_UNUSED,
                               virNodeDeviceDefPtr def)
{
    virNodeDevCapSCSIHostPtr scsi_host = &def->caps->data.scsi_host;
    char *filename = NULL;
    char *str;

    filename = last_component(def->sysfs_path);

    if (!(str = STRSKIP(filename, "host")) ||
        virStrToLong_ui(str, NULL, 0, &scsi_host->host) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse SCSI host '%s'"),
                       filename);
        return -1;
    }

    nodeDeviceSysfsGetSCSIHostCaps(&def->caps->data.scsi_host);

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        return -1;

    return 0;
}


static int udevProcessSCSITarget(struct udev_device *device ATTRIBUTE_UNUSED,
                                 virNodeDeviceDefPtr def)
{
    const char *sysname = NULL;
    virNodeDevCapSCSITargetPtr scsi_target = &def->caps->data.scsi_target;

    sysname = udev_device_get_sysname(device);

    if (VIR_STRDUP(scsi_target->name, sysname) < 0)
        return -1;

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        return -1;

    return 0;
}


static int udevGetSCSIType(virNodeDeviceDefPtr def ATTRIBUTE_UNUSED,
                           unsigned int type, char **typestring)
{
    int ret = 0;
    int foundtype = 1;

    *typestring = NULL;

    switch (type) {
    case TYPE_DISK:
        ignore_value(VIR_STRDUP(*typestring, "disk"));
        break;
    case TYPE_TAPE:
        ignore_value(VIR_STRDUP(*typestring, "tape"));
        break;
    case TYPE_PROCESSOR:
        ignore_value(VIR_STRDUP(*typestring, "processor"));
        break;
    case TYPE_WORM:
        ignore_value(VIR_STRDUP(*typestring, "worm"));
        break;
    case TYPE_ROM:
        ignore_value(VIR_STRDUP(*typestring, "cdrom"));
        break;
    case TYPE_SCANNER:
        ignore_value(VIR_STRDUP(*typestring, "scanner"));
        break;
    case TYPE_MOD:
        ignore_value(VIR_STRDUP(*typestring, "mod"));
        break;
    case TYPE_MEDIUM_CHANGER:
        ignore_value(VIR_STRDUP(*typestring, "changer"));
        break;
    case TYPE_ENCLOSURE:
        ignore_value(VIR_STRDUP(*typestring, "enclosure"));
        break;
    case TYPE_RAID:
        ignore_value(VIR_STRDUP(*typestring, "raid"));
        break;
    case TYPE_NO_LUN:
    default:
        foundtype = 0;
        break;
    }

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


static int udevProcessSCSIDevice(struct udev_device *device ATTRIBUTE_UNUSED,
                                 virNodeDeviceDefPtr def)
{
    int ret = -1;
    unsigned int tmp = 0;
    virNodeDevCapSCSIPtr scsi = &def->caps->data.scsi;
    char *filename = NULL, *p = NULL;

    filename = last_component(def->sysfs_path);

    if (virStrToLong_ui(filename, &p, 10, &scsi->host) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->bus) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->target) < 0 || p == NULL ||
        virStrToLong_ui(p + 1, &p, 10, &scsi->lun) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to parse the SCSI address from filename: '%s'"),
                       filename);
        return -1;
    }

    if (udev_device_get_sysattr_value(device, "type")) {
        if (udevGetUintSysfsAttr(device, "type", &tmp, 0) < 0)
            goto cleanup;

        if (udevGetSCSIType(def, tmp, &scsi->type) < 0)
            goto cleanup;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to process SCSI device with sysfs path '%s'"),
                       def->sysfs_path);
    }
    return ret;
}


static int udevProcessDisk(struct udev_device *device,
                           virNodeDeviceDefPtr def)
{
    virNodeDevCapStoragePtr storage = &def->caps->data.storage;

    if (udevGetUint64SysfsAttr(device, "size", &storage->num_blocks) < 0)
        return -1;

    if (udevGetUint64SysfsAttr(device, "queue/logical_block_size",
                               &storage->logical_block_size) < 0)
        return -1;

    storage->size = storage->num_blocks * storage->logical_block_size;

    return 0;
}


static int udevProcessRemoveableMedia(struct udev_device *device,
                                      virNodeDeviceDefPtr def,
                                      int has_media)
{
    virNodeDevCapStoragePtr storage = &def->caps->data.storage;
    int is_removable = 0;

    if (udevGetIntSysfsAttr(device, "removable", &is_removable, 0) < 0)
        return -1;
    if (is_removable == 1)
        def->caps->data.storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;

    if (!has_media)
        return 0;

    def->caps->data.storage.flags |=
        VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

    if (udevGetStringProperty(device, "ID_FS_LABEL",
                              &storage->media_label) < 0)
        return -1;

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

static int udevProcessCDROM(struct udev_device *device,
                            virNodeDeviceDefPtr def)
{
    int has_media = 0;

    /* NB: the drive_type string provided by udev is different from
     * that provided by HAL; now it's "cd" instead of "cdrom" We
     * change it to cdrom to preserve compatibility with earlier
     * versions of libvirt.  */
    VIR_FREE(def->caps->data.storage.drive_type);
    if (VIR_STRDUP(def->caps->data.storage.drive_type, "cdrom") < 0)
        return -1;

    if (udevHasDeviceProperty(device, "ID_CDROM_MEDIA") &&
        udevGetIntProperty(device, "ID_CDROM_MEDIA", &has_media, 0) < 0)
        return -1;

    return udevProcessRemoveableMedia(device, def, has_media);
}

static int udevProcessFloppy(struct udev_device *device,
                             virNodeDeviceDefPtr def)
{
    int has_media = 0;

    if (udevHasDeviceProperty(device, "ID_CDROM_MEDIA")) {
        /* USB floppy */
        if (udevGetIntProperty(device, "DKD_MEDIA_AVAILABLE", &has_media, 0) < 0)
            return -1;
    } else if (udevHasDeviceProperty(device, "ID_FS_LABEL")) {
        /* Legacy floppy */
        has_media = 1;
    }

    return udevProcessRemoveableMedia(device, def, has_media);
}


static int udevProcessSD(struct udev_device *device,
                         virNodeDeviceDefPtr def)
{
    virNodeDevCapStoragePtr storage = &def->caps->data.storage;

    if (udevGetUint64SysfsAttr(device, "size",
                               &storage->num_blocks) < 0)
        return -1;

    if (udevGetUint64SysfsAttr(device, "queue/logical_block_size",
                               &storage->logical_block_size) < 0)
        return -1;

    storage->size = storage->num_blocks * storage->logical_block_size;

    return 0;
}



/* This function exists to deal with the case in which a driver does
 * not provide a device type in the usual place, but udev told us it's
 * a storage device, and we can make a good guess at what kind of
 * storage device it is from other information that is provided. */
static int udevKludgeStorageType(virNodeDeviceDefPtr def)
{
    VIR_DEBUG("Could not find definitive storage type for device "
              "with sysfs path '%s', trying to guess it",
              def->sysfs_path);

    /* virtio disk */
    if (STRPREFIX(def->caps->data.storage.block, "/dev/vd") &&
        VIR_STRDUP(def->caps->data.storage.drive_type, "disk") > 0) {
        VIR_DEBUG("Found storage type '%s' for device "
                  "with sysfs path '%s'",
                  def->caps->data.storage.drive_type,
                  def->sysfs_path);
        return 0;
    }
    VIR_DEBUG("Could not determine storage type "
              "for device with sysfs path '%s'", def->sysfs_path);
    return -1;
}


static int udevProcessStorage(struct udev_device *device,
                              virNodeDeviceDefPtr def)
{
    virNodeDevCapStoragePtr storage = &def->caps->data.storage;
    int ret = -1;
    const char* devnode;

    devnode = udev_device_get_devnode(device);
    if (!devnode) {
        VIR_DEBUG("No devnode for '%s'", udev_device_get_devpath(device));
        goto cleanup;
    }

    if (VIR_STRDUP(storage->block, devnode) < 0)
        goto cleanup;

    if (udevGetStringProperty(device, "ID_BUS", &storage->bus) < 0)
        goto cleanup;
    if (udevGetStringProperty(device, "ID_SERIAL", &storage->serial) < 0)
        goto cleanup;

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

    if (udevGetStringProperty(device, "ID_TYPE", &storage->drive_type) < 0)
        goto cleanup;

    if (!storage->drive_type ||
        STREQ(def->caps->data.storage.drive_type, "generic")) {
        int val = 0;
        const char *str = NULL;

        /* All floppy drives have the ID_DRIVE_FLOPPY prop. This is
         * needed since legacy floppies don't have a drive_type */
        if (udevGetIntProperty(device, "ID_DRIVE_FLOPPY", &val, 0) < 0)
            goto cleanup;
        else if (val == 1)
            str = "floppy";

        if (!str) {
            if (udevGetIntProperty(device, "ID_CDROM", &val, 0) < 0)
                goto cleanup;
            else if (val == 1)
                str = "cd";
        }

        if (!str) {
            if (udevGetIntProperty(device, "ID_DRIVE_FLASH_SD", &val, 0) < 0)
                goto cleanup;
            if (val == 1)
                str = "sd";
        }

        if (str) {
            if (VIR_STRDUP(storage->drive_type, str) < 0)
                goto cleanup;
        } else {
            /* If udev doesn't have it, perhaps we can guess it. */
            if (udevKludgeStorageType(def) != 0)
                goto cleanup;
        }
    }

    if (STREQ(def->caps->data.storage.drive_type, "cd")) {
        ret = udevProcessCDROM(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "disk")) {
        ret = udevProcessDisk(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "floppy")) {
        ret = udevProcessFloppy(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "sd")) {
        ret = udevProcessSD(device, def);
    } else {
        VIR_DEBUG("Unsupported storage type '%s'",
                  def->caps->data.storage.drive_type);
        goto cleanup;
    }

    if (udevGenerateDeviceName(device, def, storage->serial) != 0)
        goto cleanup;

 cleanup:
    VIR_DEBUG("Storage ret=%d", ret);
    return ret;
}

static int
udevProcessSCSIGeneric(struct udev_device *dev,
                       virNodeDeviceDefPtr def)
{
    if (udevGetStringProperty(dev, "DEVNAME", &def->caps->data.sg.path) < 0 ||
        !def->caps->data.sg.path)
        return -1;

    if (udevGenerateDeviceName(dev, def, NULL) != 0)
        return -1;

    return 0;
}

static int
udevGetDeviceNodes(struct udev_device *device,
                   virNodeDeviceDefPtr def)
{
    const char *devnode = NULL;
    struct udev_list_entry *list_entry = NULL;
    int n = 0;

    devnode = udev_device_get_devnode(device);

    if (VIR_STRDUP(def->devnode, devnode) < 0)
        return -1;

    udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device))
        n++;

    if (VIR_ALLOC_N(def->devlinks, n + 1) < 0)
        return -1;

    n = 0;
    udev_list_entry_foreach(list_entry, udev_device_get_devlinks_list_entry(device)) {
        if (VIR_STRDUP(def->devlinks[n++], udev_list_entry_get_name(list_entry)) < 0)
            return -1;
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

        /* SCSI generic device doesn't set DEVTYPE property */
        if (udevGetStringProperty(device, "SUBSYSTEM", &subsystem) < 0)
            return -1;

        if (STREQ_NULLABLE(subsystem, "scsi_generic"))
            *type = VIR_NODE_DEV_CAP_SCSI_GENERIC;
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


static int udevGetDeviceDetails(struct udev_device *device,
                                virNodeDeviceDefPtr def)
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
    case VIR_NODE_DEV_CAP_SYSTEM:
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
    case VIR_NODE_DEV_CAP_LAST:
        break;
    }

    return 0;
}


static int udevRemoveOneDevice(struct udev_device *device)
{
    virNodeDeviceObjPtr dev = NULL;
    virObjectEventPtr event = NULL;
    const char *name = NULL;
    int ret = -1;

    name = udev_device_get_syspath(device);
    dev = virNodeDeviceObjFindBySysfsPath(&driver->devs, name);

    if (!dev) {
        VIR_DEBUG("Failed to find device to remove that has udev name '%s'",
                  name);
        goto cleanup;
    }

    event = virNodeDeviceEventLifecycleNew(dev->def->name,
                                           VIR_NODE_DEVICE_EVENT_DELETED,
                                           0);

    VIR_DEBUG("Removing device '%s' with sysfs path '%s'",
              dev->def->name, name);
    virNodeDeviceObjRemove(&driver->devs, &dev);

    ret = 0;
 cleanup:
    if (event)
        virObjectEventStateQueue(driver->nodeDeviceEventState, event);
    return ret;
}


static int udevSetParent(struct udev_device *device,
                         virNodeDeviceDefPtr def)
{
    struct udev_device *parent_device = NULL;
    const char *parent_sysfs_path = NULL;
    virNodeDeviceObjPtr dev = NULL;
    int ret = -1;

    parent_device = device;
    do {

        parent_device = udev_device_get_parent(parent_device);
        if (parent_device == NULL)
            break;

        parent_sysfs_path = udev_device_get_syspath(parent_device);
        if (parent_sysfs_path == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not get syspath for parent of '%s'"),
                           udev_device_get_syspath(parent_device));
            goto cleanup;
        }

        dev = virNodeDeviceObjFindBySysfsPath(&driver->devs,
                                              parent_sysfs_path);
        if (dev != NULL) {
            if (VIR_STRDUP(def->parent, dev->def->name) < 0) {
                virNodeDeviceObjUnlock(dev);
                goto cleanup;
            }
            virNodeDeviceObjUnlock(dev);

            if (VIR_STRDUP(def->parent_sysfs_path, parent_sysfs_path) < 0)
                goto cleanup;
        }

    } while (def->parent == NULL && parent_device != NULL);

    if (!def->parent && VIR_STRDUP(def->parent, "computer") < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int udevAddOneDevice(struct udev_device *device)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDeviceObjPtr dev = NULL;
    virObjectEventPtr event = NULL;
    bool new_device = true;
    int ret = -1;

    if (VIR_ALLOC(def) != 0)
        goto cleanup;

    if (VIR_STRDUP(def->sysfs_path, udev_device_get_syspath(device)) < 0)
        goto cleanup;

    if (udevGetStringProperty(device, "DRIVER", &def->driver) < 0)
        goto cleanup;

    if (VIR_ALLOC(def->caps) != 0)
        goto cleanup;

    if (udevGetDeviceType(device, &def->caps->data.type) != 0)
        goto cleanup;

    if (udevGetDeviceNodes(device, def) != 0)
        goto cleanup;

    if (udevGetDeviceDetails(device, def) != 0)
        goto cleanup;

    if (udevSetParent(device, def) != 0)
        goto cleanup;

    dev = virNodeDeviceObjFindByName(&driver->devs, def->name);
    if (dev) {
        virNodeDeviceObjUnlock(dev);
        new_device = false;
    }

    /* If this is a device change, the old definition will be freed
     * and the current definition will take its place. */
    dev = virNodeDeviceObjAssignDef(&driver->devs, def);
    if (dev == NULL)
        goto cleanup;

    if (new_device)
        event = virNodeDeviceEventLifecycleNew(dev->def->name,
                                               VIR_NODE_DEVICE_EVENT_CREATED,
                                               0);
    else
        event = virNodeDeviceEventUpdateNew(dev->def->name);

    virNodeDeviceObjUnlock(dev);

    ret = 0;

 cleanup:
    if (event)
        virObjectEventStateQueue(driver->nodeDeviceEventState, event);

    if (ret != 0) {
        VIR_DEBUG("Discarding device %d %p %s", ret, def,
                  def ? NULLSTR(def->sysfs_path) : "");
        virNodeDeviceDefFree(def);
    }

    return ret;
}


static int udevProcessDeviceListEntry(struct udev *udev,
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
const char *subsystem_blacklist[] = {
    "acpi", "tty", "vc", "i2c",
};

static int udevEnumerateAddMatches(struct udev_enumerate *udev_enumerate)
{
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(subsystem_blacklist); i++) {
        const char *s = subsystem_blacklist[i];
        if (udev_enumerate_add_nomatch_subsystem(udev_enumerate, s) < 0) {
            virReportSystemError(errno, "%s", _("failed to add susbsystem filter"));
            return -1;
        }
    }
    return 0;
}


static int udevEnumerateDevices(struct udev *udev)
{
    struct udev_enumerate *udev_enumerate = NULL;
    struct udev_list_entry *list_entry = NULL;
    int ret = -1;

    udev_enumerate = udev_enumerate_new(udev);
    if (udevEnumerateAddMatches(udev_enumerate) < 0)
        goto cleanup;

    ret = udev_enumerate_scan_devices(udev_enumerate);
    if (ret != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("udev scan devices returned %d"),
                       ret);
        goto cleanup;
    }

    udev_list_entry_foreach(list_entry,
                            udev_enumerate_get_list_entry(udev_enumerate)) {

        udevProcessDeviceListEntry(udev, list_entry);
    }

 cleanup:
    udev_enumerate_unref(udev_enumerate);
    return ret;
}


static void udevPCITranslateDeinit(void)
{
#if defined __s390__ || defined __s390x_
    /* Nothing was initialized, nothing needs to be cleaned up */
#else
    /* pci_system_cleanup returns void */
    pci_system_cleanup();
#endif
    return;
}


static int nodeStateCleanup(void)
{
    udevPrivate *priv = NULL;
    struct udev_monitor *udev_monitor = NULL;
    struct udev *udev = NULL;

    if (!driver)
        return -1;

    nodeDeviceLock();

    virObjectUnref(driver->nodeDeviceEventState);

    priv = driver->privateData;

    if (priv) {
        if (priv->watch != -1)
            virEventRemoveHandle(priv->watch);

        udev_monitor = DRV_STATE_UDEV_MONITOR(driver);

        if (udev_monitor != NULL) {
            udev = udev_monitor_get_udev(udev_monitor);
            udev_monitor_unref(udev_monitor);
        }
    }

    if (udev != NULL)
        udev_unref(udev);

    virNodeDeviceObjListFree(&driver->devs);
    nodeDeviceUnlock();
    virMutexDestroy(&driver->lock);
    VIR_FREE(driver);
    VIR_FREE(priv);

    udevPCITranslateDeinit();
    return 0;
}


static void udevEventHandleCallback(int watch ATTRIBUTE_UNUSED,
                                    int fd,
                                    int events ATTRIBUTE_UNUSED,
                                    void *data ATTRIBUTE_UNUSED)
{
    struct udev_device *device = NULL;
    struct udev_monitor *udev_monitor = DRV_STATE_UDEV_MONITOR(driver);
    const char *action = NULL;
    int udev_fd = -1;

    nodeDeviceLock();
    udev_fd = udev_monitor_get_fd(udev_monitor);
    if (fd != udev_fd) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("File descriptor returned by udev %d does not "
                         "match node device file descriptor %d"),
                       fd, udev_fd);
        goto cleanup;
    }

    device = udev_monitor_receive_device(udev_monitor);
    if (device == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("udev_monitor_receive_device returned NULL"));
        goto cleanup;
    }

    action = udev_device_get_action(device);
    VIR_DEBUG("udev action: '%s'", action);

    if (STREQ(action, "add") || STREQ(action, "change")) {
        udevAddOneDevice(device);
        goto cleanup;
    }

    if (STREQ(action, "remove")) {
        udevRemoveOneDevice(device);
        goto cleanup;
    }

 cleanup:
    udev_device_unref(device);
    nodeDeviceUnlock();
    return;
}


/* DMI is intel-compatible specific */
#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
static void
udevGetDMIData(virNodeDevCapSystemPtr syscap)
{
    struct udev *udev = NULL;
    struct udev_device *device = NULL;
    virNodeDevCapSystemHardwarePtr hardware = &syscap->hardware;
    virNodeDevCapSystemFirmwarePtr firmware = &syscap->firmware;

    udev = udev_monitor_get_udev(DRV_STATE_UDEV_MONITOR(driver));

    device = udev_device_new_from_syspath(udev, DMI_DEVPATH);
    if (device == NULL) {
        device = udev_device_new_from_syspath(udev, DMI_DEVPATH_FALLBACK);
        if (device == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get udev device for syspath '%s' or '%s'"),
                           DMI_DEVPATH, DMI_DEVPATH_FALLBACK);
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


static int udevSetupSystemDev(void)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDeviceObjPtr dev = NULL;
    int ret = -1;

    if (VIR_ALLOC(def) < 0)
        return -1;

    if (VIR_STRDUP(def->name, "computer") < 0)
        goto cleanup;

    if (VIR_ALLOC(def->caps) != 0)
        goto cleanup;

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
    udevGetDMIData(&def->caps->data.system);
#endif

    dev = virNodeDeviceObjAssignDef(&driver->devs, def);
    if (dev == NULL)
        goto cleanup;

    virNodeDeviceObjUnlock(dev);

    ret = 0;

 cleanup:
    if (ret == -1)
        virNodeDeviceDefFree(def);

    return ret;
}

static int udevPCITranslateInit(bool privileged ATTRIBUTE_UNUSED)
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

static int nodeStateInitialize(bool privileged,
                               virStateInhibitCallback callback ATTRIBUTE_UNUSED,
                               void *opaque ATTRIBUTE_UNUSED)
{
    udevPrivate *priv = NULL;
    struct udev *udev = NULL;
    int ret = -1;

    if (VIR_ALLOC(priv) < 0)
        return -1;

    priv->watch = -1;
    priv->privileged = privileged;

    if (VIR_ALLOC(driver) < 0) {
        VIR_FREE(priv);
        return -1;
    }

    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        VIR_FREE(priv);
        VIR_FREE(driver);
        return -1;
    }

    driver->privateData = priv;
    nodeDeviceLock();
    driver->nodeDeviceEventState = virObjectEventStateNew();

    if (udevPCITranslateInit(privileged) < 0)
        goto cleanup;

    udev = udev_new();
    if (!udev) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to create udev context"));
        goto cleanup;
    }
#if HAVE_UDEV_LOGGING
    /* cast to get rid of missing-format-attribute warning */
    udev_set_log_fn(udev, (udevLogFunctionPtr) udevLogFunction);
#endif

    priv->udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
    if (priv->udev_monitor == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("udev_monitor_new_from_netlink returned NULL"));
        goto cleanup;
    }

    udev_monitor_enable_receiving(priv->udev_monitor);

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
        goto cleanup;

    /* Create a fictional 'computer' device to root the device tree. */
    if (udevSetupSystemDev() != 0)
        goto cleanup;

    /* Populate with known devices */

    if (udevEnumerateDevices(udev) != 0)
        goto cleanup;

    ret = 0;

 cleanup:
    nodeDeviceUnlock();

    if (ret == -1)
        nodeStateCleanup();
    return ret;
}


static int nodeStateReload(void)
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
};

static virStateDriver udevStateDriver = {
    .name = "udev",
    .stateInitialize = nodeStateInitialize, /* 0.7.3 */
    .stateCleanup = nodeStateCleanup, /* 0.7.3 */
    .stateReload = nodeStateReload, /* 0.7.3 */
};

int udevNodeRegister(void)
{
    VIR_DEBUG("Registering udev node device backend");

    if (virSetSharedNodeDeviceDriver(&udevNodeDeviceDriver) < 0)
        return -1;

    return virRegisterStateDriver(&udevStateDriver);
}
