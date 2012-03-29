/*
 * node_device_udev.c: node device enumeration - libudev implementation
 *
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Dave Allan <dallan@redhat.com>
 */

#include <config.h>
#include <libudev.h>
#include <pciaccess.h>
#include <scsi/scsi.h>
#include <c-ctype.h>

#include "node_device_udev.h"
#include "virterror_internal.h"
#include "node_device_conf.h"
#include "node_device_driver.h"
#include "driver.h"
#include "datatypes.h"
#include "logging.h"
#include "memory.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "pci.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

#ifndef TYPE_RAID
# define TYPE_RAID 12
#endif

struct _udevPrivate {
    struct udev_monitor *udev_monitor;
    int watch;
};

static virDeviceMonitorStatePtr driverState = NULL;

static int udevStrToLong_ull(char const *s,
                             char **end_ptr,
                             int base,
                             unsigned long long *result)
{
    int ret = 0;

    ret = virStrToLong_ull(s, end_ptr, base, result);
    if (ret != 0) {
        VIR_ERROR(_("Failed to convert '%s' to unsigned long long"), s);
    } else {
        VIR_DEBUG("Converted '%s' to unsigned long %llu", s, *result);
    }

    return ret;
}


static int udevStrToLong_ui(char const *s,
                            char **end_ptr,
                            int base,
                            unsigned int *result)
{
    int ret = 0;

    ret = virStrToLong_ui(s, end_ptr, base, result);
    if (ret != 0) {
        VIR_ERROR(_("Failed to convert '%s' to unsigned int"), s);
    } else {
        VIR_DEBUG("Converted '%s' to unsigned int %u", s, *result);
    }

    return ret;
}

static int udevStrToLong_i(char const *s,
                           char **end_ptr,
                           int base,
                           int *result)
{
    int ret = 0;

    ret = virStrToLong_i(s, end_ptr, base, result);
    if (ret != 0) {
        VIR_ERROR(_("Failed to convert '%s' to int"), s);
    } else {
        VIR_DEBUG("Converted '%s' to int %u", s, *result);
    }

    return ret;
}


/* This function allocates memory from the heap for the property
 * value.  That memory must be later freed by some other code. */
static int udevGetDeviceProperty(struct udev_device *udev_device,
                                 const char *property_key,
                                 char **property_value)
{
    const char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    udev_value = udev_device_get_property_value(udev_device, property_key);
    if (udev_value == NULL) {
        VIR_DEBUG("udev reports device '%s' does not have property '%s'",
                  udev_device_get_sysname(udev_device), property_key);
        ret = PROPERTY_MISSING;
        goto out;
    }

    /* If this allocation is changed, the comment at the beginning
     * of the function must also be changed. */
    *property_value = strdup(udev_value);
    if (*property_value == NULL) {
        VIR_ERROR(_("Failed to allocate memory for property value for "
                    "property key '%s' on device with sysname '%s'"),
                  property_key, udev_device_get_sysname(udev_device));
        virReportOOMError();
        ret = PROPERTY_ERROR;
        goto out;
    }

    VIR_DEBUG("Found property key '%s' value '%s' "
              "for device with sysname '%s'",
              property_key, *property_value,
              udev_device_get_sysname(udev_device));

out:
    return ret;
}


static int udevGetStringProperty(struct udev_device *udev_device,
                                 const char *property_key,
                                 char **value)
{
    return udevGetDeviceProperty(udev_device, property_key, value);
}


static int udevGetIntProperty(struct udev_device *udev_device,
                              const char *property_key,
                              int *value,
                              int base)
{
    char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    ret = udevGetDeviceProperty(udev_device, property_key, &udev_value);

    if (ret == PROPERTY_FOUND) {
        if (udevStrToLong_i(udev_value, NULL, base, value) != 0) {
            ret = PROPERTY_ERROR;
        }
    }

    VIR_FREE(udev_value);
    return ret;
}


static int udevGetUintProperty(struct udev_device *udev_device,
                               const char *property_key,
                               unsigned int *value,
                               int base)
{
    char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    ret = udevGetDeviceProperty(udev_device, property_key, &udev_value);

    if (ret == PROPERTY_FOUND) {
        if (udevStrToLong_ui(udev_value, NULL, base, value) != 0) {
            ret = PROPERTY_ERROR;
        }
    }

    VIR_FREE(udev_value);
    return ret;
}


/* This function allocates memory from the heap for the property
 * value.  That memory must be later freed by some other code. */
static int udevGetDeviceSysfsAttr(struct udev_device *udev_device,
                                  const char *attr_name,
                                  char **attr_value)
{
    const char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    udev_value = udev_device_get_sysattr_value(udev_device, attr_name);
    if (udev_value == NULL) {
        VIR_DEBUG("udev reports device '%s' does not have sysfs attr '%s'",
                  udev_device_get_sysname(udev_device), attr_name);
        ret = PROPERTY_MISSING;
        goto out;
    }

    /* If this allocation is changed, the comment at the beginning
     * of the function must also be changed. */
    *attr_value = strdup(udev_value);
    if (*attr_value == NULL) {
        VIR_ERROR(_("Failed to allocate memory for sysfs attribute value for "
                    "sysfs attribute '%s' on device with sysname '%s'"),
                  attr_name, udev_device_get_sysname(udev_device));
        virReportOOMError();
        ret = PROPERTY_ERROR;
        goto out;
    }

    VIR_DEBUG("Found sysfs attribute '%s' value '%s' "
              "for device with sysname '%s'",
              attr_name, *attr_value,
              udev_device_get_sysname(udev_device));

out:
    return ret;
}


static int udevGetStringSysfsAttr(struct udev_device *udev_device,
                                  const char *attr_name,
                                  char **value)
{
    char *tmp = NULL;
    int ret = PROPERTY_MISSING;

    ret = udevGetDeviceSysfsAttr(udev_device, attr_name, &tmp);

    if (tmp != NULL && (STREQ(tmp, ""))) {
        VIR_FREE(tmp);
        tmp = NULL;
        ret = PROPERTY_MISSING;
    }

    *value = tmp;

    return ret;
}


static int udevGetIntSysfsAttr(struct udev_device *udev_device,
                               const char *attr_name,
                               int *value,
                               int base)
{
    char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    ret = udevGetDeviceSysfsAttr(udev_device, attr_name, &udev_value);

    if (ret == PROPERTY_FOUND) {
        if (udevStrToLong_i(udev_value, NULL, base, value) != 0) {
            ret = PROPERTY_ERROR;
        }
    }

    VIR_FREE(udev_value);
    return ret;
}


static int udevGetUintSysfsAttr(struct udev_device *udev_device,
                                const char *attr_name,
                                unsigned int *value,
                                int base)
{
    char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    ret = udevGetDeviceSysfsAttr(udev_device, attr_name, &udev_value);

    if (ret == PROPERTY_FOUND) {
        if (udevStrToLong_ui(udev_value, NULL, base, value) != 0) {
            ret = PROPERTY_ERROR;
        }
    }

    VIR_FREE(udev_value);
    return ret;
}


static int udevGetUint64SysfsAttr(struct udev_device *udev_device,
                                  const char *attr_name,
                                  unsigned long long *value)
{
    char *udev_value = NULL;
    int ret = PROPERTY_FOUND;

    ret = udevGetDeviceSysfsAttr(udev_device, attr_name, &udev_value);

    if (ret == PROPERTY_FOUND) {
        if (udevStrToLong_ull(udev_value, NULL, 0, value) != 0) {
            ret = PROPERTY_ERROR;
        }
    }

    VIR_FREE(udev_value);
    return ret;
}


static int udevGenerateDeviceName(struct udev_device *device,
                                  virNodeDeviceDefPtr def,
                                  const char *s)
{
    int ret = 0, i = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s_%s",
                      udev_device_get_subsystem(device),
                      udev_device_get_sysname(device));

    if (s != NULL) {
        virBufferAsprintf(&buf, "_%s", s);
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        VIR_ERROR(_("Buffer error when generating device name for device "
                    "with sysname '%s'"), udev_device_get_sysname(device));
        ret = -1;
    }

    def->name = virBufferContentAndReset(&buf);

    for (i = 0; i < strlen(def->name) ; i++) {
        if (!(c_isalnum(*(def->name + i)))) {
            *(def->name + i) = '_';
        }
    }

    return ret;
}


static void udevLogFunction(struct udev *udev ATTRIBUTE_UNUSED,
                            int priority ATTRIBUTE_UNUSED,
                            const char *file,
                            int line,
                            const char *fn,
                            const char *fmt,
                            va_list args)
{
    VIR_ERROR_INT(file, fn, line, fmt, args);
}


static int udevTranslatePCIIds(unsigned int vendor,
                               unsigned int product,
                               char **vendor_string,
                               char **product_string)
{
    int ret = -1;
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

    if (vendor_name != NULL) {
        *vendor_string = strdup(vendor_name);
        if (*vendor_string == NULL) {
            virReportOOMError();
            goto out;
        }
    }

    if (device_name != NULL) {
        *product_string = strdup(device_name);
        if (*product_string == NULL) {
            virReportOOMError();
            goto out;
        }
    }

    ret = 0;

out:
    return ret;
}


static int udevProcessPCI(struct udev_device *device,
                          virNodeDeviceDefPtr def)
{
    const char *syspath = NULL;
    union _virNodeDevCapData *data = &def->caps->data;
    int ret = -1;
    char *p;

    syspath = udev_device_get_syspath(device);

    if (udevGetUintProperty(device,
                            "PCI_CLASS",
                            &data->pci_dev.class,
                            16) == PROPERTY_ERROR) {
        goto out;
    }

    p = strrchr(syspath, '/');

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         16,
                                         &data->pci_dev.domain) == -1)) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         16,
                                         &data->pci_dev.bus) == -1)) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         16,
                                         &data->pci_dev.slot) == -1)) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         16,
                                         &data->pci_dev.function) == -1)) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "vendor",
                             &data->pci_dev.vendor,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "device",
                             &data->pci_dev.product,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevTranslatePCIIds(data->pci_dev.vendor,
                            data->pci_dev.product,
                            &data->pci_dev.vendor_name,
                            &data->pci_dev.product_name) != 0) {
        goto out;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    if (!pciGetPhysicalFunction(syspath, &data->pci_dev.physical_function))
        data->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    if (!pciGetVirtualFunctions(syspath, &data->pci_dev.virtual_functions,
        &data->pci_dev.num_virtual_functions) ||
        data->pci_dev.num_virtual_functions > 0)
        data->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;

    ret = 0;

out:
    return ret;
}


static int udevProcessUSBDevice(struct udev_device *device,
                                virNodeDeviceDefPtr def)
{
    union _virNodeDevCapData *data = &def->caps->data;
    int ret = -1;

    if (udevGetUintProperty(device,
                            "BUSNUM",
                            &data->usb_dev.bus,
                            10) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintProperty(device,
                            "DEVNUM",
                            &data->usb_dev.device,
                            10) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintProperty(device,
                            "ID_VENDOR_ID",
                            &data->usb_dev.vendor,
                            16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetStringSysfsAttr(device,
                              "manufacturer",
                              &data->usb_dev.vendor_name) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintProperty(device,
                            "ID_MODEL_ID",
                            &data->usb_dev.product,
                            16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetStringSysfsAttr(device,
                              "product",
                              &data->usb_dev.product_name) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevProcessUSBInterface(struct udev_device *device,
                                   virNodeDeviceDefPtr def)
{
    int ret = -1;
    union _virNodeDevCapData *data = &def->caps->data;

    if (udevGetUintSysfsAttr(device,
                             "bInterfaceNumber",
                             &data->usb_if.number,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "bInterfaceClass",
                             &data->usb_if._class,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "bInterfaceSubClass",
                             &data->usb_if.subclass,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "bInterfaceProtocol",
                             &data->usb_if.protocol,
                             16) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevProcessNetworkInterface(struct udev_device *device,
                                       virNodeDeviceDefPtr def)
{
    int ret = -1;
    const char *devtype = udev_device_get_devtype(device);
    union _virNodeDevCapData *data = &def->caps->data;

    if (devtype && STREQ(devtype, "wlan")) {
        data->net.subtype = VIR_NODE_DEV_CAP_NET_80211;
    } else {
        data->net.subtype = VIR_NODE_DEV_CAP_NET_80203;
    }

    if (udevGetStringProperty(device,
                              "INTERFACE",
                              &data->net.ifname) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetStringSysfsAttr(device,
                               "address",
                               &data->net.address) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUintSysfsAttr(device,
                             "addr_len",
                             &data->net.address_len,
                             0) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGenerateDeviceName(device, def, data->net.address) != 0) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevProcessSCSIHost(struct udev_device *device ATTRIBUTE_UNUSED,
                               virNodeDeviceDefPtr def)
{
    int ret = -1;
    union _virNodeDevCapData *data = &def->caps->data;
    char *filename = NULL;

    filename = basename(def->sysfs_path);

    if (!STRPREFIX(filename, "host")) {
        VIR_ERROR(_("SCSI host found, but its udev name '%s' does "
                    "not begin with 'host'"), filename);
        goto out;
    }

    if (udevStrToLong_ui(filename + strlen("host"),
                         NULL,
                         0,
                         &data->scsi_host.host) == -1) {
        goto out;
    }

    check_fc_host(&def->caps->data);
    check_vport_capable(&def->caps->data);

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevProcessSCSITarget(struct udev_device *device ATTRIBUTE_UNUSED,
                                 virNodeDeviceDefPtr def)
{
    int ret = -1;
    const char *sysname = NULL;
    union _virNodeDevCapData *data = &def->caps->data;

    sysname = udev_device_get_sysname(device);

    data->scsi_target.name = strdup(sysname);
    if (data->scsi_target.name == NULL) {
        virReportOOMError();
        goto out;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevGetSCSIType(virNodeDeviceDefPtr def ATTRIBUTE_UNUSED,
                           unsigned int type, char **typestring)
{
    int ret = 0;
    int foundtype = 1;

    *typestring = NULL;

    switch (type) {
    case TYPE_DISK:
        *typestring = strdup("disk");
        break;
    case TYPE_TAPE:
        *typestring = strdup("tape");
        break;
    case TYPE_PROCESSOR:
        *typestring = strdup("processor");
        break;
    case TYPE_WORM:
        *typestring = strdup("worm");
        break;
    case TYPE_ROM:
        *typestring = strdup("cdrom");
        break;
    case TYPE_SCANNER:
        *typestring = strdup("scanner");
        break;
    case TYPE_MOD:
        *typestring = strdup("mod");
        break;
    case TYPE_MEDIUM_CHANGER:
        *typestring = strdup("changer");
        break;
    case TYPE_ENCLOSURE:
        *typestring = strdup("enclosure");
        break;
    case TYPE_RAID:
        *typestring = strdup("raid");
        break;
    case TYPE_NO_LUN:
    default:
        foundtype = 0;
        break;
    }

    if (*typestring == NULL) {
        if (foundtype == 1) {
            ret = -1;
            virReportOOMError();
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
    union _virNodeDevCapData *data = &def->caps->data;
    char *filename = NULL, *p = NULL;

    filename = basename(def->sysfs_path);

    if (udevStrToLong_ui(filename, &p, 10, &data->scsi.host) == -1) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         10,
                                         &data->scsi.bus) == -1)) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         10,
                                         &data->scsi.target) == -1)) {
        goto out;
    }

    if ((p == NULL) || (udevStrToLong_ui(p+1,
                                         &p,
                                         10,
                                         &data->scsi.lun) == -1)) {
        goto out;
    }

    switch (udevGetUintSysfsAttr(device, "type", &tmp, 0)) {
    case PROPERTY_FOUND:
        if (udevGetSCSIType(def, tmp, &data->scsi.type) == -1) {
            goto out;
        }
        break;
    case PROPERTY_MISSING:
        break; /* No type is not an error */
    case PROPERTY_ERROR:
    default:
        goto out;
        break;
    }

    if (udevGenerateDeviceName(device, def, NULL) != 0) {
        goto out;
    }

    ret = 0;

out:
    if (ret != 0) {
        VIR_ERROR(_("Failed to process SCSI device with sysfs path '%s'"),
                  def->sysfs_path);
    }
    return ret;
}


static int udevProcessDisk(struct udev_device *device,
                           virNodeDeviceDefPtr def)
{
    union _virNodeDevCapData *data = &def->caps->data;
    int ret = 0;

    if (udevGetUint64SysfsAttr(device,
                               "size",
                               &data->storage.num_blocks) == PROPERTY_ERROR) {
        goto out;
    }

    if (udevGetUint64SysfsAttr(device,
                               "queue/logical_block_size",
                               &data->storage.logical_block_size)
        == PROPERTY_ERROR) {
        goto out;
    }

    data->storage.size = data->storage.num_blocks *
        data->storage.logical_block_size;

out:
    return ret;
}


static int udevProcessRemoveableMedia(struct udev_device *device,
                                      virNodeDeviceDefPtr def,
                                      int has_media)
{
    union _virNodeDevCapData *data = &def->caps->data;
    int tmp_int = 0, ret = 0;

    if ((udevGetIntSysfsAttr(device, "removable", &tmp_int, 0) == PROPERTY_FOUND) &&
        (tmp_int == 1)) {
        def->caps->data.storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;
    }

    if (has_media) {

        def->caps->data.storage.flags |=
            VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

        if (udevGetStringProperty(device, "ID_FS_LABEL",
                                  &data->storage.media_label) == PROPERTY_ERROR) {
            goto out;
        }

        if (udevGetUint64SysfsAttr(device,
                                   "size",
                                   &data->storage.num_blocks) == PROPERTY_ERROR) {
            goto out;
        }

        if (udevGetUint64SysfsAttr(device,
                                   "queue/logical_block_size",
                                   &data->storage.logical_block_size) == PROPERTY_ERROR) {
            goto out;
        }

        /* XXX This calculation is wrong for the qemu virtual cdrom
         * which reports the size in 512 byte blocks, but the logical
         * block size as 2048.  I don't have a physical cdrom on a
         * devel system to see how they behave. */
        def->caps->data.storage.removable_media_size =
            def->caps->data.storage.num_blocks *
            def->caps->data.storage.logical_block_size;
    }

out:
    return ret;
}

static int udevProcessCDROM(struct udev_device *device,
                            virNodeDeviceDefPtr def)
{
    int ret = -1;
    int tmp_int = 0;
    int has_media = 0;

    /* NB: the drive_type string provided by udev is different from
     * that provided by HAL; now it's "cd" instead of "cdrom" We
     * change it to cdrom to preserve compatibility with earlier
     * versions of libvirt.  */
    VIR_FREE(def->caps->data.storage.drive_type);
    def->caps->data.storage.drive_type = strdup("cdrom");
    if (def->caps->data.storage.drive_type == NULL) {
        virReportOOMError();
        goto out;
    }

    if ((udevGetIntProperty(device, "ID_CDROM_MEDIA",
                            &tmp_int, 0) == PROPERTY_FOUND))
        has_media = tmp_int;

    ret = udevProcessRemoveableMedia(device, def, has_media);
out:
    return ret;
}

static int udevProcessFloppy(struct udev_device *device,
                             virNodeDeviceDefPtr def)
{
    int tmp_int = 0;
    int has_media = 0;
    char *tmp_str = NULL;

    if ((udevGetIntProperty(device, "DKD_MEDIA_AVAILABLE",
                            &tmp_int, 0) == PROPERTY_FOUND))
        /* USB floppy */
        has_media = tmp_int;
    else if (udevGetStringProperty(device, "ID_FS_LABEL",
                                   &tmp_str) == PROPERTY_FOUND) {
        /* Legacy floppy */
        has_media = 1;
        VIR_FREE(tmp_str);
    }

    return udevProcessRemoveableMedia(device, def, has_media);
}

/* This function exists to deal with the case in which a driver does
 * not provide a device type in the usual place, but udev told us it's
 * a storage device, and we can make a good guess at what kind of
 * storage device it is from other information that is provided. */
static int udevKludgeStorageType(virNodeDeviceDefPtr def)
{
    int ret = -1;

    VIR_DEBUG("Could not find definitive storage type for device "
              "with sysfs path '%s', trying to guess it",
              def->sysfs_path);

    if (STRPREFIX(def->caps->data.storage.block, "/dev/vd")) {
        /* virtio disk */
        def->caps->data.storage.drive_type = strdup("disk");
        if (def->caps->data.storage.drive_type != NULL) {
            ret = 0;
        }
    }

    if (ret != 0) {
        VIR_DEBUG("Could not determine storage type for device "
                  "with sysfs path '%s'", def->sysfs_path);
    } else {
        VIR_DEBUG("Found storage type '%s' for device "
                  "with sysfs path '%s'",
                  def->caps->data.storage.drive_type,
                  def->sysfs_path);
    }

    return ret;
}


static void udevStripSpaces(char *s)
{
    if (s == NULL) {
        return;
    }

    while (virFileStripSuffix(s, " ")) {
        /* do nothing */
        ;
    }

    return;
}


static int udevProcessStorage(struct udev_device *device,
                              virNodeDeviceDefPtr def)
{
    union _virNodeDevCapData *data = &def->caps->data;
    int ret = -1;
    const char* devnode;

    devnode = udev_device_get_devnode(device);
    if(!devnode) {
        VIR_DEBUG("No devnode for '%s'", udev_device_get_devpath(device));
        goto out;
    }
    data->storage.block = strdup(devnode);

    if (udevGetStringProperty(device,
                              "ID_BUS",
                              &data->storage.bus) == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringProperty(device,
                              "ID_SERIAL",
                              &data->storage.serial) == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "device/vendor",
                               &data->storage.vendor) == PROPERTY_ERROR) {
        goto out;
    }
    udevStripSpaces(def->caps->data.storage.vendor);
    if (udevGetStringSysfsAttr(device,
                               "device/model",
                               &data->storage.model) == PROPERTY_ERROR) {
        goto out;
    }
    udevStripSpaces(def->caps->data.storage.model);
    /* There is no equivalent of the hotpluggable property in libudev,
     * but storage is going toward a world in which hotpluggable is
     * expected, so I don't see a problem with not having a property
     * for it. */

    if (udevGetStringProperty(device,
                              "ID_TYPE",
                              &data->storage.drive_type) != PROPERTY_FOUND) {
        int tmp_int = 0;

        /* All floppy drives have the ID_DRIVE_FLOPPY prop. This is
         * needed since legacy floppies don't have a drive_type */
        if ((udevGetIntProperty(device, "ID_DRIVE_FLOPPY",
                                &tmp_int, 0) == PROPERTY_FOUND) &&
            (tmp_int == 1)) {

            data->storage.drive_type = strdup("floppy");
            if (!data->storage.drive_type)
                goto out;
        } else {

            /* If udev doesn't have it, perhaps we can guess it. */
            if (udevKludgeStorageType(def) != 0) {
                goto out;
            }
        }
    }

    if (STREQ(def->caps->data.storage.drive_type, "cd")) {
        ret = udevProcessCDROM(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "disk")) {
        ret = udevProcessDisk(device, def);
    } else if (STREQ(def->caps->data.storage.drive_type, "floppy")) {
        ret = udevProcessFloppy(device, def);
    } else {
        VIR_DEBUG("Unsupported storage type '%s'",
                  def->caps->data.storage.drive_type);
        goto out;
    }

    if (udevGenerateDeviceName(device, def, data->storage.serial) != 0) {
        goto out;
    }

out:
    return ret;
}


static int udevGetDeviceType(struct udev_device *device,
                             enum virNodeDevCapType *type)
{
    const char *devtype = NULL;
    char *tmp_string = NULL;
    unsigned int tmp = 0;
    int ret = 0;

    devtype = udev_device_get_devtype(device);
    VIR_DEBUG("Found device type '%s' for device '%s'",
              NULLSTR(devtype), udev_device_get_sysname(device));

    if (devtype != NULL && STREQ(devtype, "usb_device")) {
        *type = VIR_NODE_DEV_CAP_USB_DEV;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "usb_interface")) {
        *type = VIR_NODE_DEV_CAP_USB_INTERFACE;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "scsi_host")) {
        *type = VIR_NODE_DEV_CAP_SCSI_HOST;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "scsi_target")) {
        *type = VIR_NODE_DEV_CAP_SCSI_TARGET;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "scsi_device")) {
        *type = VIR_NODE_DEV_CAP_SCSI;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "disk")) {
        *type = VIR_NODE_DEV_CAP_STORAGE;
        goto out;
    }

    if (devtype != NULL && STREQ(devtype, "wlan")) {
        *type = VIR_NODE_DEV_CAP_NET;
        goto out;
    }

    if (udevGetUintProperty(device, "PCI_CLASS", &tmp, 16) == PROPERTY_FOUND) {
        *type = VIR_NODE_DEV_CAP_PCI_DEV;
        goto out;
    }

    /* It does not appear that wired network interfaces set the
     * DEVTYPE property.  USB devices also have an INTERFACE property,
     * but they do set DEVTYPE, so if devtype is NULL and the
     * INTERFACE property exists, we have a network device. */
    if (devtype == NULL &&
        udevGetStringProperty(device,
                              "INTERFACE",
                              &tmp_string) == PROPERTY_FOUND) {
        VIR_FREE(tmp_string);
        *type = VIR_NODE_DEV_CAP_NET;
        goto out;
    }

    VIR_DEBUG("Could not determine device type for device "
              "with sysfs path '%s'",
              udev_device_get_sysname(device));
    ret = -1;

out:
    return ret;
}


static int udevGetDeviceDetails(struct udev_device *device,
                                virNodeDeviceDefPtr def)
{
    int ret = 0;

    switch (def->caps->type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        /* There's no libudev equivalent of system, so ignore it. */
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        ret = udevProcessPCI(device, def);
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        ret = udevProcessUSBDevice(device, def);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        ret = udevProcessUSBInterface(device, def);
        break;
    case VIR_NODE_DEV_CAP_NET:
        ret = udevProcessNetworkInterface(device, def);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        ret = udevProcessSCSIHost(device, def);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        ret = udevProcessSCSITarget(device, def);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        ret = udevProcessSCSIDevice(device, def);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        ret = udevProcessStorage(device, def);
        break;
    default:
        VIR_ERROR(_("Unknown device type %d"), def->caps->type);
        ret = -1;
        break;
    }

    return ret;
}


static int udevRemoveOneDevice(struct udev_device *device)
{
    virNodeDeviceObjPtr dev = NULL;
    const char *name = NULL;
    int ret = 0;

    name = udev_device_get_syspath(device);
    dev = virNodeDeviceFindBySysfsPath(&driverState->devs, name);

    if (dev != NULL) {
        VIR_DEBUG("Removing device '%s' with sysfs path '%s'",
                  dev->def->name, name);
        virNodeDeviceObjRemove(&driverState->devs, dev);
    } else {
        VIR_DEBUG("Failed to find device to remove that has udev name '%s'",
                  name);
        ret = -1;
    }

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
        if (parent_device == NULL) {
            break;
        }

        parent_sysfs_path = udev_device_get_syspath(parent_device);
        if (parent_sysfs_path == NULL) {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("Could not get syspath for parent of '%s'"),
                                     udev_device_get_syspath(parent_device));
            goto out;
        }

        dev = virNodeDeviceFindBySysfsPath(&driverState->devs,
                                           parent_sysfs_path);
        if (dev != NULL) {
            def->parent = strdup(dev->def->name);
            virNodeDeviceObjUnlock(dev);

            if (def->parent == NULL) {
                virReportOOMError();
                goto out;
            }

            def->parent_sysfs_path = strdup(parent_sysfs_path);
            if (def->parent_sysfs_path == NULL) {
                virReportOOMError();
                goto out;
            }

        }

    } while (def->parent == NULL && parent_device != NULL);

    if (def->parent == NULL) {
        def->parent = strdup("computer");
    }

    if (def->parent == NULL) {
        virReportOOMError();
        goto out;
    }

    ret = 0;

out:
    return ret;
}


static int udevAddOneDevice(struct udev_device *device)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDeviceObjPtr dev = NULL;
    int ret = -1;

    if (VIR_ALLOC(def) != 0) {
        virReportOOMError();
        goto out;
    }

    def->sysfs_path = strdup(udev_device_get_syspath(device));
    if (udevGetStringProperty(device,
                              "DRIVER",
                              &def->driver) == PROPERTY_ERROR) {
        goto out;
    }

    if (VIR_ALLOC(def->caps) != 0) {
        virReportOOMError();
        goto out;
    }

    if (udevGetDeviceType(device, &def->caps->type) != 0) {
        goto out;
    }

    if (udevGetDeviceDetails(device, def) != 0) {
        goto out;
    }

    if (udevSetParent(device, def) != 0) {
        goto out;
    }

    /* If this is a device change, the old definition will be freed
     * and the current definition will take its place. */
    dev = virNodeDeviceAssignDef(&driverState->devs, def);

    if (dev == NULL) {
        VIR_ERROR(_("Failed to create device for '%s'"), def->name);
        goto out;
    }

    virNodeDeviceObjUnlock(dev);

    ret = 0;

out:
    if (ret != 0) {
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


static int udevEnumerateDevices(struct udev *udev)
{
    struct udev_enumerate *udev_enumerate = NULL;
    struct udev_list_entry *list_entry = NULL;
    int ret = 0;

    udev_enumerate = udev_enumerate_new(udev);

    ret = udev_enumerate_scan_devices(udev_enumerate);
    if (0 != ret) {
        VIR_ERROR(_("udev scan devices returned %d"), ret);
        goto out;
    }

    udev_list_entry_foreach(list_entry,
                            udev_enumerate_get_list_entry(udev_enumerate)) {

        udevProcessDeviceListEntry(udev, list_entry);
    }

out:
    udev_enumerate_unref(udev_enumerate);
    return ret;
}


static int udevDeviceMonitorShutdown(void)
{
    int ret = 0;

    udevPrivate *priv = NULL;
    struct udev_monitor *udev_monitor = NULL;
    struct udev *udev = NULL;

    if (driverState) {
        nodeDeviceLock(driverState);

        priv = driverState->privateData;

        if (priv->watch != -1)
            virEventRemoveHandle(priv->watch);

        udev_monitor = DRV_STATE_UDEV_MONITOR(driverState);

        if (udev_monitor != NULL) {
            udev = udev_monitor_get_udev(udev_monitor);
            udev_monitor_unref(udev_monitor);
        }

        if (udev != NULL) {
            udev_unref(udev);
        }

        virNodeDeviceObjListFree(&driverState->devs);
        nodeDeviceUnlock(driverState);
        virMutexDestroy(&driverState->lock);
        VIR_FREE(driverState);
        VIR_FREE(priv);
    } else {
        ret = -1;
    }

#if defined __s390__ || defined __s390x_
    /* Nothing was initialized, nothing needs to be cleaned up */
#else
    /* pci_system_cleanup returns void */
    pci_system_cleanup();
#endif

    return ret;
}


static void udevEventHandleCallback(int watch ATTRIBUTE_UNUSED,
                                    int fd,
                                    int events ATTRIBUTE_UNUSED,
                                    void *data ATTRIBUTE_UNUSED)
{
    struct udev_device *device = NULL;
    struct udev_monitor *udev_monitor = DRV_STATE_UDEV_MONITOR(driverState);
    const char *action = NULL;
    int udev_fd = -1;

    nodeDeviceLock(driverState);
    udev_fd = udev_monitor_get_fd(udev_monitor);
    if (fd != udev_fd) {
        VIR_ERROR(_("File descriptor returned by udev %d does not "
                    "match node device file descriptor %d"), fd, udev_fd);
        goto out;
    }

    device = udev_monitor_receive_device(udev_monitor);
    if (device == NULL) {
        VIR_ERROR(_("udev_monitor_receive_device returned NULL"));
        goto out;
    }

    action = udev_device_get_action(device);
    VIR_DEBUG("udev action: '%s'", action);

    if (STREQ(action, "add") || STREQ(action, "change")) {
        udevAddOneDevice(device);
        goto out;
    }

    if (STREQ(action, "remove")) {
        udevRemoveOneDevice(device);
        goto out;
    }

out:
    udev_device_unref(device);
    nodeDeviceUnlock(driverState);
    return;
}


/* DMI is intel-compatible specific */
#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
static void
udevGetDMIData(union _virNodeDevCapData *data)
{
    struct udev *udev = NULL;
    struct udev_device *device = NULL;
    char *tmp = NULL;

    udev = udev_monitor_get_udev(DRV_STATE_UDEV_MONITOR(driverState));

    device = udev_device_new_from_syspath(udev, DMI_DEVPATH);
    if (device == NULL) {
        device = udev_device_new_from_syspath(udev, DMI_DEVPATH_FALLBACK);
        if (device == NULL) {
            VIR_ERROR(_("Failed to get udev device for syspath '%s' or '%s'"),
                      DMI_DEVPATH, DMI_DEVPATH_FALLBACK);
            goto out;
        }
    }

    if (udevGetStringSysfsAttr(device,
                               "product_name",
                               &data->system.product_name) == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "sys_vendor",
                               &data->system.hardware.vendor_name)
        == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "product_version",
                               &data->system.hardware.version)
        == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "product_serial",
                               &data->system.hardware.serial)
        == PROPERTY_ERROR) {
        goto out;
    }

    if (virGetHostUUID(data->system.hardware.uuid))
        goto out;

    if (udevGetStringSysfsAttr(device,
                               "bios_vendor",
                               &data->system.firmware.vendor_name)
        == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "bios_version",
                               &data->system.firmware.version)
        == PROPERTY_ERROR) {
        goto out;
    }
    if (udevGetStringSysfsAttr(device,
                               "bios_date",
                               &data->system.firmware.release_date)
        == PROPERTY_ERROR) {
        goto out;
    }

out:
    VIR_FREE(tmp);
    if (device != NULL) {
        udev_device_unref(device);
    }
    return;
}
#endif


static int udevSetupSystemDev(void)
{
    virNodeDeviceDefPtr def = NULL;
    virNodeDeviceObjPtr dev = NULL;
    int ret = -1;

    if (VIR_ALLOC(def) != 0) {
        virReportOOMError();
        goto out;
    }

    def->name = strdup("computer");
    if (def->name == NULL) {
        virReportOOMError();
        goto out;
    }

    if (VIR_ALLOC(def->caps) != 0) {
        virReportOOMError();
        goto out;
    }

#if defined(__x86_64__) || defined(__i386__) || defined(__amd64__)
    udevGetDMIData(&def->caps->data);
#endif

    dev = virNodeDeviceAssignDef(&driverState->devs, def);
    if (dev == NULL) {
        VIR_ERROR(_("Failed to create device for '%s'"), def->name);
        goto out;
    }

    virNodeDeviceObjUnlock(dev);

    ret = 0;

out:
    if (ret == -1) {
        virNodeDeviceDefFree(def);
    }

    return ret;
}

static int udevDeviceMonitorStartup(int privileged)
{
    udevPrivate *priv = NULL;
    struct udev *udev = NULL;
    int ret = 0;

#if defined __s390__ || defined __s390x_
    /* On s390(x) system there is no PCI bus.
     * Therefore there is nothing to initialize here. */
#else
    int pciret;

    if ((pciret = pci_system_init()) != 0) {
        /* Ignore failure as non-root; udev is not as helpful in that
         * situation, but a non-privileged user won't benefit much
         * from udev in the first place.  */
        if (errno != ENOENT && (privileged  || errno != EACCES)) {
            char ebuf[256];
            VIR_ERROR(_("Failed to initialize libpciaccess: %s"),
                      virStrerror(pciret, ebuf, sizeof(ebuf)));
            ret = -1;
            goto out;
        }
    }
#endif

    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        ret = -1;
        goto out;
    }

    priv->watch = -1;

    if (VIR_ALLOC(driverState) < 0) {
        virReportOOMError();
        VIR_FREE(priv);
        ret = -1;
        goto out;
    }

    if (virMutexInit(&driverState->lock) < 0) {
        VIR_ERROR(_("Failed to initialize mutex for driverState"));
        VIR_FREE(priv);
        VIR_FREE(driverState);
        ret = -1;
        goto out;
    }

    nodeDeviceLock(driverState);

    /*
     * http://www.kernel.org/pub/linux/utils/kernel/hotplug/libudev/libudev-udev.html#udev-new
     *
     * indicates no return value other than success, so we don't check
     * its return value.
     */
    udev = udev_new();
    udev_set_log_fn(udev, udevLogFunction);

    priv->udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
    if (priv->udev_monitor == NULL) {
        VIR_FREE(priv);
        VIR_ERROR(_("udev_monitor_new_from_netlink returned NULL"));
        ret = -1;
        goto out_unlock;
    }

    udev_monitor_enable_receiving(priv->udev_monitor);

    /* udev can be retrieved from udev_monitor */
    driverState->privateData = priv;

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
    if (priv->watch == -1) {
        ret = -1;
        goto out_unlock;
    }

    /* Create a fictional 'computer' device to root the device tree. */
    if (udevSetupSystemDev() != 0) {
        ret = -1;
        goto out_unlock;
    }

    /* Populate with known devices */

    if (udevEnumerateDevices(udev) != 0) {
        ret = -1;
        goto out_unlock;
    }

out_unlock:
    nodeDeviceUnlock(driverState);

out:
    if (ret == -1) {
        udevDeviceMonitorShutdown();
    }
    return ret;
}


static int udevDeviceMonitorReload(void)
{
    return 0;
}


static int udevDeviceMonitorActive(void)
{
    /* Always ready to deal with a shutdown */
    return 0;
}


static virDrvOpenStatus udevNodeDrvOpen(virConnectPtr conn,
                                        virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                                        unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (driverState == NULL) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->devMonPrivateData = driverState;

    return VIR_DRV_OPEN_SUCCESS;
}

static int udevNodeDrvClose(virConnectPtr conn)
{
    conn->devMonPrivateData = NULL;
    return 0;
}

static virDeviceMonitor udevDeviceMonitor = {
    .name = "udevDeviceMonitor",
    .open = udevNodeDrvOpen, /* 0.7.3 */
    .close = udevNodeDrvClose, /* 0.7.3 */
    .numOfDevices = nodeNumOfDevices, /* 0.7.3 */
    .listDevices = nodeListDevices, /* 0.7.3 */
    .deviceLookupByName = nodeDeviceLookupByName, /* 0.7.3 */
    .deviceGetXMLDesc = nodeDeviceGetXMLDesc, /* 0.7.3 */
    .deviceGetParent = nodeDeviceGetParent, /* 0.7.3 */
    .deviceNumOfCaps = nodeDeviceNumOfCaps, /* 0.7.3 */
    .deviceListCaps = nodeDeviceListCaps, /* 0.7.3 */
    .deviceCreateXML = nodeDeviceCreateXML, /* 0.7.3 */
    .deviceDestroy = nodeDeviceDestroy, /* 0.7.3 */
};

static virStateDriver udevStateDriver = {
    .name = "udev",
    .initialize = udevDeviceMonitorStartup, /* 0.7.3 */
    .cleanup = udevDeviceMonitorShutdown, /* 0.7.3 */
    .reload = udevDeviceMonitorReload, /* 0.7.3 */
    .active = udevDeviceMonitorActive, /* 0.7.3 */
};

int udevNodeRegister(void)
{
    VIR_DEBUG("Registering udev node device backend");

    if (virRegisterDeviceMonitor(&udevDeviceMonitor) < 0) {
        return -1;
    }

    return virRegisterStateDriver(&udevStateDriver);
}
