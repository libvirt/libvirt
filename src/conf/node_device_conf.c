/*
 * node_device_conf.c: config handling for node devices
 *
 * Copyright (C) 2008 Virtual Iron Software, Inc.
 * Copyright (C) 2008 David F. Lively
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
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#include <config.h>

#include <unistd.h>
#include <errno.h>

#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"

#include "node_device_conf.h"
#include "memory.h"
#include "xml.h"
#include "util.h"
#include "buf.h"
#include "uuid.h"
#include "pci.h"
#include "virrandom.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_ENUM_IMPL(virNodeDevCap, VIR_NODE_DEV_CAP_LAST,
              "system",
              "pci",
              "usb_device",
              "usb",
              "net",
              "scsi_host",
              "scsi_target",
              "scsi",
              "storage")

VIR_ENUM_IMPL(virNodeDevNetCap, VIR_NODE_DEV_CAP_NET_LAST,
              "80203",
              "80211")

VIR_ENUM_IMPL(virNodeDevHBACap, VIR_NODE_DEV_CAP_HBA_LAST,
              "fc_host",
              "vport_ops")


static int
virNodeDevCapsDefParseString(const char *xpath,
                             xmlXPathContextPtr ctxt,
                             char **string)
{
    char *s;

    if (!(s = virXPathString(xpath, ctxt)))
        return -1;

    *string = s;
    return 0;
}

int virNodeDeviceHasCap(const virNodeDeviceObjPtr dev, const char *cap)
{
    virNodeDevCapsDefPtr caps = dev->def->caps;
    while (caps) {
        if (STREQ(cap, virNodeDevCapTypeToString(caps->type)))
            return 1;
        caps = caps->next;
    }
    return 0;
}


virNodeDeviceObjPtr
virNodeDeviceFindBySysfsPath(const virNodeDeviceObjListPtr devs,
                             const char *sysfs_path)
{
    unsigned int i;

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(devs->objs[i]);
        if ((devs->objs[i]->def->sysfs_path != NULL) &&
            (STREQ(devs->objs[i]->def->sysfs_path, sysfs_path))) {
            return devs->objs[i];
        }
        virNodeDeviceObjUnlock(devs->objs[i]);
    }

    return NULL;
}


virNodeDeviceObjPtr virNodeDeviceFindByName(const virNodeDeviceObjListPtr devs,
                                            const char *name)
{
    unsigned int i;

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(devs->objs[i]);
        if (STREQ(devs->objs[i]->def->name, name))
            return devs->objs[i];
        virNodeDeviceObjUnlock(devs->objs[i]);
    }

    return NULL;
}


void virNodeDeviceDefFree(virNodeDeviceDefPtr def)
{
    virNodeDevCapsDefPtr caps;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->parent);
    VIR_FREE(def->driver);
    VIR_FREE(def->sysfs_path);
    VIR_FREE(def->parent_sysfs_path);

    caps = def->caps;
    while (caps) {
        virNodeDevCapsDefPtr next = caps->next;
        virNodeDevCapsDefFree(caps);
        caps = next;
    }

    VIR_FREE(def);
}

void virNodeDeviceObjFree(virNodeDeviceObjPtr dev)
{
    if (!dev)
        return;

    virNodeDeviceDefFree(dev->def);
    if (dev->privateFree)
        (*dev->privateFree)(dev->privateData);

    virMutexDestroy(&dev->lock);

    VIR_FREE(dev);
}

void virNodeDeviceObjListFree(virNodeDeviceObjListPtr devs)
{
    unsigned int i;
    for (i = 0 ; i < devs->count ; i++)
        virNodeDeviceObjFree(devs->objs[i]);
    VIR_FREE(devs->objs);
    devs->count = 0;
}

virNodeDeviceObjPtr virNodeDeviceAssignDef(virNodeDeviceObjListPtr devs,
                                           const virNodeDeviceDefPtr def)
{
    virNodeDeviceObjPtr device;

    if ((device = virNodeDeviceFindByName(devs, def->name))) {
        virNodeDeviceDefFree(device->def);
        device->def = def;
        return device;
    }

    if (VIR_ALLOC(device) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&device->lock) < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("cannot initialize mutex"));
        VIR_FREE(device);
        return NULL;
    }
    virNodeDeviceObjLock(device);
    device->def = def;

    if (VIR_REALLOC_N(devs->objs, devs->count+1) < 0) {
        device->def = NULL;
        virNodeDeviceObjUnlock(device);
        virNodeDeviceObjFree(device);
        virReportOOMError();
        return NULL;
    }
    devs->objs[devs->count++] = device;

    return device;

}

void virNodeDeviceObjRemove(virNodeDeviceObjListPtr devs,
                            const virNodeDeviceObjPtr dev)
{
    unsigned int i;

    virNodeDeviceObjUnlock(dev);

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(dev);
        if (devs->objs[i] == dev) {
            virNodeDeviceObjUnlock(dev);
            virNodeDeviceObjFree(devs->objs[i]);

            if (i < (devs->count - 1))
                memmove(devs->objs + i, devs->objs + i + 1,
                        sizeof(*(devs->objs)) * (devs->count - (i + 1)));

            if (VIR_REALLOC_N(devs->objs, devs->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            devs->count--;

            break;
        }
        virNodeDeviceObjUnlock(dev);
    }
}

char *virNodeDeviceDefFormat(const virNodeDeviceDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNodeDevCapsDefPtr caps;
    unsigned int i = 0;

    virBufferAddLit(&buf, "<device>\n");
    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);
    if (def->parent) {
        virBufferEscapeString(&buf, "  <parent>%s</parent>\n", def->parent);
    }
    if (def->driver) {
        virBufferAddLit(&buf, "  <driver>\n");
        virBufferEscapeString(&buf, "    <name>%s</name>\n", def->driver);
        virBufferAddLit(&buf, "  </driver>\n");
    }

    for (caps = def->caps; caps; caps = caps->next) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        union _virNodeDevCapData *data = &caps->data;

        virBufferAsprintf(&buf, "  <capability type='%s'>\n",
                          virNodeDevCapTypeToString(caps->type));
        switch (caps->type) {
        case VIR_NODE_DEV_CAP_SYSTEM:
            if (data->system.product_name)
                virBufferEscapeString(&buf, "    <product>%s</product>\n",
                                      data->system.product_name);
            virBufferAddLit(&buf, "    <hardware>\n");
            if (data->system.hardware.vendor_name)
                virBufferEscapeString(&buf, "      <vendor>%s</vendor>\n",
                                      data->system.hardware.vendor_name);
            if (data->system.hardware.version)
                virBufferEscapeString(&buf, "      <version>%s</version>\n",
                                      data->system.hardware.version);
            if (data->system.hardware.serial)
                virBufferEscapeString(&buf, "      <serial>%s</serial>\n",
                                      data->system.hardware.serial);
            virUUIDFormat(data->system.hardware.uuid, uuidstr);
            virBufferAsprintf(&buf, "      <uuid>%s</uuid>\n", uuidstr);
            virBufferAddLit(&buf, "    </hardware>\n");
            virBufferAddLit(&buf, "    <firmware>\n");
            if (data->system.firmware.vendor_name)
                virBufferEscapeString(&buf, "      <vendor>%s</vendor>\n",
                                      data->system.firmware.vendor_name);
            if (data->system.firmware.version)
                virBufferEscapeString(&buf, "      <version>%s</version>\n",
                                      data->system.firmware.version);
            if (data->system.firmware.release_date)
                virBufferEscapeString(&buf,
                                      "      <release_date>%s</release_date>\n",
                                      data->system.firmware.release_date);
            virBufferAddLit(&buf, "    </firmware>\n");
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
            virBufferAsprintf(&buf, "    <domain>%d</domain>\n",
                              data->pci_dev.domain);
            virBufferAsprintf(&buf, "    <bus>%d</bus>\n", data->pci_dev.bus);
            virBufferAsprintf(&buf, "    <slot>%d</slot>\n",
                              data->pci_dev.slot);
            virBufferAsprintf(&buf, "    <function>%d</function>\n",
                              data->pci_dev.function);
            virBufferAsprintf(&buf, "    <product id='0x%04x'",
                                  data->pci_dev.product);
            if (data->pci_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->pci_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferAsprintf(&buf, "    <vendor id='0x%04x'",
                                  data->pci_dev.vendor);
            if (data->pci_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->pci_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION) {
                virBufferAddLit(&buf, "    <capability type='phys_function'>\n");
                virBufferAsprintf(&buf,
                                  "      <address domain='0x%.4x' bus='0x%.2x' "
                                  "slot='0x%.2x' function='0x%.1x'/>\n",
                                  data->pci_dev.physical_function->domain,
                                  data->pci_dev.physical_function->bus,
                                  data->pci_dev.physical_function->slot,
                                  data->pci_dev.physical_function->function);
                virBufferAddLit(&buf, "    </capability>\n");
            }
            if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION) {
                virBufferAddLit(&buf, "    <capability type='virt_functions'>\n");
                for (i = 0 ; i < data->pci_dev.num_virtual_functions ; i++) {
                    virBufferAsprintf(&buf,
                                      "      <address domain='0x%.4x' bus='0x%.2x' "
                                      "slot='0x%.2x' function='0x%.1x'/>\n",
                                      data->pci_dev.virtual_functions[i]->domain,
                                      data->pci_dev.virtual_functions[i]->bus,
                                      data->pci_dev.virtual_functions[i]->slot,
                                      data->pci_dev.virtual_functions[i]->function);
                }
                virBufferAddLit(&buf, "    </capability>\n");
            }
            break;
        case VIR_NODE_DEV_CAP_USB_DEV:
            virBufferAsprintf(&buf, "    <bus>%d</bus>\n", data->usb_dev.bus);
            virBufferAsprintf(&buf, "    <device>%d</device>\n",
                              data->usb_dev.device);
            virBufferAsprintf(&buf, "    <product id='0x%04x'",
                                  data->usb_dev.product);
            if (data->usb_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->usb_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferAsprintf(&buf, "    <vendor id='0x%04x'",
                                  data->usb_dev.vendor);
            if (data->usb_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->usb_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            break;
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
            virBufferAsprintf(&buf, "    <number>%d</number>\n",
                              data->usb_if.number);
            virBufferAsprintf(&buf, "    <class>%d</class>\n",
                              data->usb_if._class);
            virBufferAsprintf(&buf, "    <subclass>%d</subclass>\n",
                              data->usb_if.subclass);
            virBufferAsprintf(&buf, "    <protocol>%d</protocol>\n",
                              data->usb_if.protocol);
            if (data->usb_if.description)
                virBufferEscapeString(&buf,
                                  "    <description>%s</description>\n",
                                  data->usb_if.description);
            break;
        case VIR_NODE_DEV_CAP_NET:
            virBufferEscapeString(&buf, "    <interface>%s</interface>\n",
                              data->net.ifname);
            if (data->net.address)
                virBufferEscapeString(&buf, "    <address>%s</address>\n",
                                  data->net.address);
            if (data->net.subtype != VIR_NODE_DEV_CAP_NET_LAST) {
                const char *subtyp =
                    virNodeDevNetCapTypeToString(data->net.subtype);
                virBufferEscapeString(&buf, "    <capability type='%s'/>\n",
                                      subtyp);
            }
            break;
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            virBufferAsprintf(&buf, "    <host>%d</host>\n",
                              data->scsi_host.host);
            if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                virBufferAddLit(&buf, "    <capability type='fc_host'>\n");
                virBufferEscapeString(&buf, "      <wwnn>%s</wwnn>\n",
                                      data->scsi_host.wwnn);
                virBufferEscapeString(&buf, "      <wwpn>%s</wwpn>\n",
                                      data->scsi_host.wwpn);
                virBufferEscapeString(&buf, "      <fabric_wwn>%s</fabric_wwn>\n",
                                      data->scsi_host.fabric_wwn);
                virBufferAddLit(&buf, "    </capability>\n");
            }
            if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS) {
                virBufferAddLit(&buf, "    <capability type='vport_ops' />\n");
            }

            break;

        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            virBufferEscapeString(&buf, "    <target>%s</target>\n",
                                  data->scsi_target.name);
            break;

        case VIR_NODE_DEV_CAP_SCSI:
            virBufferAsprintf(&buf, "    <host>%d</host>\n", data->scsi.host);
            virBufferAsprintf(&buf, "    <bus>%d</bus>\n", data->scsi.bus);
            virBufferAsprintf(&buf, "    <target>%d</target>\n",
                              data->scsi.target);
            virBufferAsprintf(&buf, "    <lun>%d</lun>\n", data->scsi.lun);
            if (data->scsi.type)
                virBufferEscapeString(&buf, "    <type>%s</type>\n",
                                      data->scsi.type);
            break;
        case VIR_NODE_DEV_CAP_STORAGE:
            virBufferEscapeString(&buf, "    <block>%s</block>\n",
                              data->storage.block);
            if (data->storage.bus)
                virBufferEscapeString(&buf, "    <bus>%s</bus>\n",
                                  data->storage.bus);
            if (data->storage.drive_type)
                virBufferEscapeString(&buf, "    <drive_type>%s</drive_type>\n",
                                  data->storage.drive_type);
            if (data->storage.model)
                virBufferEscapeString(&buf, "    <model>%s</model>\n",
                                  data->storage.model);
            if (data->storage.vendor)
                virBufferEscapeString(&buf, "    <vendor>%s</vendor>\n",
                                  data->storage.vendor);
            if (data->storage.serial)
                virBufferAsprintf(&buf, "    <serial>%s</serial>\n",
                                  data->storage.serial);
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE) {
                int avl = data->storage.flags &
                    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;
                virBufferAddLit(&buf, "    <capability type='removable'>\n");
                virBufferAsprintf(&buf,
                                  "      <media_available>%d"
                                  "</media_available>\n", avl ? 1 : 0);
                virBufferAsprintf(&buf, "      <media_size>%llu</media_size>\n",
                                  data->storage.removable_media_size);
                if (data->storage.media_label)
                    virBufferEscapeString(&buf,
                                      "      <media_label>%s</media_label>\n",
                                      data->storage.media_label);

                if (data->storage.logical_block_size > 0)
                    virBufferAsprintf(&buf, "      <logical_block_size>%llu"
                                      "</logical_block_size>\n",
                                      data->storage.logical_block_size);
                if (data->storage.num_blocks > 0)
                    virBufferAsprintf(&buf,
                                      "      <num_blocks>%llu</num_blocks>\n",
                                      data->storage.num_blocks);
                virBufferAddLit(&buf, "    </capability>\n");
            } else {
                virBufferAsprintf(&buf, "    <size>%llu</size>\n",
                                  data->storage.size);
                if (data->storage.logical_block_size > 0)
                    virBufferAsprintf(&buf, "    <logical_block_size>%llu"
                                      "</logical_block_size>\n",
                                      data->storage.logical_block_size);
                if (data->storage.num_blocks > 0)
                    virBufferAsprintf(&buf,
                                      "    <num_blocks>%llu</num_blocks>\n",
                                      data->storage.num_blocks);
            }
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE)
                virBufferAddLit(&buf,
                                "    <capability type='hotpluggable' />\n");
            break;
        case VIR_NODE_DEV_CAP_LAST:
            /* ignore special LAST value */
            break;
        }

        virBufferAddLit(&buf, "  </capability>\n");
    }

    virBufferAddLit(&buf, "</device>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
    virBufferFreeAndReset(&buf);
    return NULL;
}

static int
virNodeDevCapsDefParseULong(const char *xpath,
                            xmlXPathContextPtr ctxt,
                            unsigned *value,
                            virNodeDeviceDefPtr def,
                            const char *missing_error_fmt,
                            const char *invalid_error_fmt)
{
    int ret;
    unsigned long val;

    ret = virXPathULong(xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapsDefParseULongLong(const char *xpath,
                                xmlXPathContextPtr ctxt,
                                unsigned long long *value,
                                virNodeDeviceDefPtr def,
                                const char *missing_error_fmt,
                                const char *invalid_error_fmt)
{
    int ret;
    unsigned long long val;

    ret = virXPathULongLong(xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapStorageParseXML(xmlXPathContextPtr ctxt,
                             virNodeDeviceDefPtr def,
                             xmlNodePtr node,
                             union _virNodeDevCapData *data)
{
    xmlNodePtr orignode, *nodes = NULL;
    int i, n, ret = -1;
    unsigned long long val;

    orignode = ctxt->node;
    ctxt->node = node;

    data->storage.block = virXPathString("string(./block[1])", ctxt);
    if (!data->storage.block) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("no block device path supplied for '%s'"),
                                 def->name);
        goto out;
    }

    data->storage.bus        = virXPathString("string(./bus[1])", ctxt);
    data->storage.drive_type = virXPathString("string(./drive_type[1])", ctxt);
    data->storage.model      = virXPathString("string(./model[1])", ctxt);
    data->storage.vendor     = virXPathString("string(./vendor[1])", ctxt);
    data->storage.serial     = virXPathString("string(./serial[1])", ctxt);

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0) {
        goto out;
    }

    for (i = 0 ; i < n ; i++) {
        char *type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("missing storage capability type for '%s'"),
                                     def->name);
            goto out;
        }

        if (STREQ(type, "hotpluggable"))
            data->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE;
        else if (STREQ(type, "removable")) {
            xmlNodePtr orignode2;

            data->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;

            orignode2 = ctxt->node;
            ctxt->node = nodes[i];

            if (virXPathBoolean("count(./media_available[. = '1']) > 0", ctxt))
                data->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

            data->storage.media_label = virXPathString("string(./media_label[1])", ctxt);

            val = 0;
            if (virNodeDevCapsDefParseULongLong("number(./media_size[1])", ctxt, &val, def,
                                                _("no removable media size supplied for '%s'"),
                                                _("invalid removable media size supplied for '%s'")) < 0) {
                ctxt->node = orignode2;
                VIR_FREE(type);
                goto out;
            }
            data->storage.removable_media_size = val;

            ctxt->node = orignode2;
        } else {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("unknown storage capability type '%s' for '%s'"),
                                     type, def->name);
            VIR_FREE(type);
            goto out;
        }

        VIR_FREE(type);
    }

    if (!(data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE)) {
        val = 0;
        if (virNodeDevCapsDefParseULongLong("number(./size[1])", ctxt, &val, def,
                                            _("no size supplied for '%s'"),
                                            _("invalid size supplied for '%s'")) < 0)
            goto out;
        data->storage.size = val;
    }

    ret = 0;
out:
    VIR_FREE(nodes);
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapScsiParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDefPtr def,
                          xmlNodePtr node,
                          union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong("number(./host[1])", ctxt,
                                    &data->scsi.host, def,
                                    _("no SCSI host ID supplied for '%s'"),
                                    _("invalid SCSI host ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./bus[1])", ctxt,
                                    &data->scsi.bus, def,
                                    _("no SCSI bus ID supplied for '%s'"),
                                    _("invalid SCSI bus ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./target[1])", ctxt,
                                    &data->scsi.target, def,
                                    _("no SCSI target ID supplied for '%s'"),
                                    _("invalid SCSI target ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./lun[1])", ctxt,
                                    &data->scsi.lun, def,
                                    _("no SCSI LUN ID supplied for '%s'"),
                                    _("invalid SCSI LUN ID supplied for '%s'")) < 0)
        goto out;

    data->scsi.type = virXPathString("string(./type[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}


static int
virNodeDevCapScsiTargetParseXML(xmlXPathContextPtr ctxt,
                                virNodeDeviceDefPtr def,
                                xmlNodePtr node,
                                union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    data->scsi_target.name = virXPathString("string(./name[1])", ctxt);
    if (!data->scsi_target.name) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("no target name supplied for '%s'"),
                                 def->name);
        goto out;
    }

    ret = 0;

out:
    ctxt->node = orignode;
    return ret;
}


static int
virNodeDevCapScsiHostParseXML(xmlXPathContextPtr ctxt,
                              virNodeDeviceDefPtr def,
                              xmlNodePtr node,
                              union _virNodeDevCapData *data,
                              int create,
                              const char *virt_type)
{
    xmlNodePtr orignode, *nodes = NULL;
    int ret = -1, n = 0, i;
    char *type = NULL;

    orignode = ctxt->node;
    ctxt->node = node;

    if (create == EXISTING_DEVICE &&
        virNodeDevCapsDefParseULong("number(./host[1])", ctxt,
                                    &data->scsi_host.host, def,
                                    _("no SCSI host ID supplied for '%s'"),
                                    _("invalid SCSI host ID supplied for '%s'")) < 0) {
        goto out;
    }

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0) {
        goto out;
    }

    for (i = 0 ; i < n ; i++) {
        type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("missing SCSI host capability type for '%s'"),
                                     def->name);
            goto out;
        }

        if (STREQ(type, "vport_ops")) {

            data->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;

        } else if (STREQ(type, "fc_host")) {

            xmlNodePtr orignode2;

            data->scsi_host.flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

            orignode2 = ctxt->node;
            ctxt->node = nodes[i];

            if (virNodeDevCapsDefParseString("string(./wwnn[1])",
                                             ctxt,
                                             &data->scsi_host.wwnn) < 0) {
                if (virRandomGenerateWWN(&data->scsi_host.wwnn, virt_type) < 0) {
                    virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                             _("no WWNN supplied for '%s', and "
                                               "auto-generation failed"),
                                             def->name);
                    goto out;
                }
            }

            if (virNodeDevCapsDefParseString("string(./wwpn[1])",
                                             ctxt,
                                             &data->scsi_host.wwpn) < 0) {
                if (virRandomGenerateWWN(&data->scsi_host.wwpn, virt_type) < 0) {
                    virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                             _("no WWPN supplied for '%s', and "
                                               "auto-generation failed"),
                                             def->name);
                    goto out;
                }
            }

            ctxt->node = orignode2;

        } else {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("unknown SCSI host capability type '%s' for '%s'"),
                                     type, def->name);
            goto out;
        }

        VIR_FREE(type);
    }

    ret = 0;

out:
    VIR_FREE(type);
    ctxt->node = orignode;
    VIR_FREE(nodes);
    return ret;
}


static int
virNodeDevCapNetParseXML(xmlXPathContextPtr ctxt,
                         virNodeDeviceDefPtr def,
                         xmlNodePtr node,
                         union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;
    char *tmp;

    orignode = ctxt->node;
    ctxt->node = node;

    data->net.ifname = virXPathString("string(./interface[1])", ctxt);
    if (!data->net.ifname) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("no network interface supplied for '%s'"),
                                 def->name);
        goto out;
    }

    data->net.address = virXPathString("string(./address[1])", ctxt);

    data->net.subtype = VIR_NODE_DEV_CAP_NET_LAST;

    tmp = virXPathString("string(./capability/@type)", ctxt);
    if (tmp) {
        int val = virNodeDevNetCapTypeFromString(tmp);
        VIR_FREE(tmp);
        if (val < 0) {
            virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                     _("invalid network type supplied for '%s'"),
                                     def->name);
            goto out;
        }
        data->net.subtype = val;
    }

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapUsbInterfaceParseXML(xmlXPathContextPtr ctxt,
                                  virNodeDeviceDefPtr def,
                                  xmlNodePtr node,
                                  union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong("number(./number[1])", ctxt,
                                    &data->usb_if.number, def,
                                    _("no USB interface number supplied for '%s'"),
                                    _("invalid USB interface number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./class[1])", ctxt,
                                    &data->usb_if._class, def,
                                    _("no USB interface class supplied for '%s'"),
                                    _("invalid USB interface class supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./subclass[1])", ctxt,
                                    &data->usb_if.subclass, def,
                                    _("no USB interface subclass supplied for '%s'"),
                                    _("invalid USB interface subclass supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./protocol[1])", ctxt,
                                    &data->usb_if.protocol, def,
                                    _("no USB interface protocol supplied for '%s'"),
                                    _("invalid USB interface protocol supplied for '%s'")) < 0)
        goto out;

    data->usb_if.description = virXPathString("string(./description[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapsDefParseHexId(const char *xpath,
                            xmlXPathContextPtr ctxt,
                            unsigned *value,
                            virNodeDeviceDefPtr def,
                            const char *missing_error_fmt,
                            const char *invalid_error_fmt)
{
    int ret;
    unsigned long val;

    ret = virXPathULongHex(xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapUsbDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong("number(./bus[1])", ctxt,
                                    &data->usb_dev.bus, def,
                                    _("no USB bus number supplied for '%s'"),
                                    _("invalid USB bus number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./device[1])", ctxt,
                                    &data->usb_dev.device, def,
                                    _("no USB device number supplied for '%s'"),
                                    _("invalid USB device number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./vendor[1]/@id)", ctxt,
                                    &data->usb_dev.vendor, def,
                                    _("no USB vendor ID supplied for '%s'"),
                                    _("invalid USB vendor ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./product[1]/@id)", ctxt,
                                    &data->usb_dev.product, def,
                                    _("no USB product ID supplied for '%s'"),
                                    _("invalid USB product ID supplied for '%s'")) < 0)
        goto out;

    data->usb_dev.vendor_name  = virXPathString("string(./vendor[1])", ctxt);
    data->usb_dev.product_name = virXPathString("string(./product[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapPciDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong("number(./domain[1])", ctxt,
                                    &data->pci_dev.domain, def,
                                    _("no PCI domain ID supplied for '%s'"),
                                    _("invalid PCI domain ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./bus[1])", ctxt,
                                    &data->pci_dev.bus, def,
                                    _("no PCI bus ID supplied for '%s'"),
                                    _("invalid PCI bus ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./slot[1])", ctxt,
                                    &data->pci_dev.slot, def,
                                    _("no PCI slot ID supplied for '%s'"),
                                    _("invalid PCI slot ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong("number(./function[1])", ctxt,
                                    &data->pci_dev.function, def,
                                    _("no PCI function ID supplied for '%s'"),
                                    _("invalid PCI function ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./vendor[1]/@id)", ctxt,
                                    &data->pci_dev.vendor, def,
                                    _("no PCI vendor ID supplied for '%s'"),
                                    _("invalid PCI vendor ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./product[1]/@id)", ctxt,
                                    &data->pci_dev.product, def,
                                    _("no PCI product ID supplied for '%s'"),
                                    _("invalid PCI product ID supplied for '%s'")) < 0)
        goto out;

    data->pci_dev.vendor_name  = virXPathString("string(./vendor[1])", ctxt);
    data->pci_dev.product_name = virXPathString("string(./product[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapSystemParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;
    char *tmp;

    orignode = ctxt->node;
    ctxt->node = node;

    data->system.product_name = virXPathString("string(./product[1])", ctxt);

    data->system.hardware.vendor_name = virXPathString("string(./hardware/vendor[1])", ctxt);
    data->system.hardware.version     = virXPathString("string(./hardware/version[1])", ctxt);
    data->system.hardware.serial      = virXPathString("string(./hardware/serial[1])", ctxt);

    tmp = virXPathString("string(./hardware/uuid[1])", ctxt);
    if (!tmp) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("no system UUID supplied for '%s'"), def->name);
        goto out;
    }

    if (virUUIDParse(tmp, data->system.hardware.uuid) < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("malformed uuid element for '%s'"), def->name);
        VIR_FREE(tmp);
        goto out;
    }
    VIR_FREE(tmp);

    data->system.firmware.vendor_name  = virXPathString("string(./firmware/vendor[1])", ctxt);
    data->system.firmware.version      = virXPathString("string(./firmware/version[1])", ctxt);
    data->system.firmware.release_date = virXPathString("string(./firmware/release_date[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static virNodeDevCapsDefPtr
virNodeDevCapsDefParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDefPtr def,
                          xmlNodePtr node,
                          int create,
                          const char *virt_type)
{
    virNodeDevCapsDefPtr caps;
    char *tmp;
    int val, ret;

    if (VIR_ALLOC(caps) < 0) {
        virReportOOMError();
        return NULL;
    }

    tmp = virXMLPropString(node, "type");
    if (!tmp) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("missing capability type"));
        goto error;
    }

    if ((val = virNodeDevCapTypeFromString(tmp)) < 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("unknown capability type '%s'"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    caps->type = val;
    VIR_FREE(tmp);

    switch (caps->type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        ret = virNodeDevCapSystemParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        ret = virNodeDevCapPciDevParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        ret = virNodeDevCapUsbDevParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        ret = virNodeDevCapUsbInterfaceParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_NET:
        ret = virNodeDevCapNetParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        ret = virNodeDevCapScsiHostParseXML(ctxt, def, node,
                                            &caps->data,
                                            create,
                                            virt_type);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        ret = virNodeDevCapScsiTargetParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        ret = virNodeDevCapScsiParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        ret = virNodeDevCapStorageParseXML(ctxt, def, node, &caps->data);
        break;
    default:
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("unknown capability type '%d' for '%s'"),
                                 caps->type, def->name);
        ret = -1;
        break;
    }

    if (ret < 0)
        goto error;
    return caps;

error:
    virNodeDevCapsDefFree(caps);
    return NULL;
}

static virNodeDeviceDefPtr
virNodeDeviceDefParseXML(xmlXPathContextPtr ctxt,
                         int create,
                         const char *virt_type)
{
    virNodeDeviceDefPtr def;
    virNodeDevCapsDefPtr *next_cap;
    xmlNodePtr *nodes;
    int n, i;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    /* Extract device name */
    if (create == EXISTING_DEVICE) {
        def->name = virXPathString("string(./name[1])", ctxt);

        if (!def->name) {
            virNodeDeviceReportError(VIR_ERR_NO_NAME, NULL);
            goto error;
        }
    } else {
        def->name = strdup("new device");

        if (!def->name) {
            virReportOOMError();
            goto error;
        }
    }

    /* Extract device parent, if any */
    def->parent = virXPathString("string(./parent[1])", ctxt);

    /* Parse device capabilities */
    nodes = NULL;
    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0) {
        goto error;
    }

    if (n == 0) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("no device capabilities for '%s'"),
                                 def->name);
        goto error;
    }

    next_cap = &def->caps;
    for (i = 0 ; i < n ; i++) {
        *next_cap = virNodeDevCapsDefParseXML(ctxt, def,
                                              nodes[i],
                                              create,
                                              virt_type);
        if (!*next_cap) {
            VIR_FREE(nodes);
            goto error;
        }

        next_cap = &(*next_cap)->next;
    }
    VIR_FREE(nodes);

    return def;

 error:
    virNodeDeviceDefFree(def);
    return NULL;
}

virNodeDeviceDefPtr
virNodeDeviceDefParseNode(xmlDocPtr xml,
                          xmlNodePtr root,
                          int create,
                          const char *virt_type)
{
    xmlXPathContextPtr ctxt = NULL;
    virNodeDeviceDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "device")) {
        virNodeDeviceReportError(VIR_ERR_XML_ERROR,
                                 _("unexpected root element <%s> "
                                   "expecting <device>"),
                                 root->name);
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virNodeDeviceDefParseXML(ctxt, create, virt_type);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

static virNodeDeviceDefPtr
virNodeDeviceDefParse(const char *str,
                      const char *filename,
                      int create,
                      const char *virt_type)
{
    xmlDocPtr xml;
    virNodeDeviceDefPtr def = NULL;

    if ((xml = virXMLParse(filename, str, _("(node_device_definition)")))) {
        def = virNodeDeviceDefParseNode(xml, xmlDocGetRootElement(xml),
                                        create, virt_type);
        xmlFreeDoc(xml);
    }

    return def;
}

virNodeDeviceDefPtr
virNodeDeviceDefParseString(const char *str,
                            int create,
                            const char *virt_type)
{
    return virNodeDeviceDefParse(str, NULL, create, virt_type);
}

virNodeDeviceDefPtr
virNodeDeviceDefParseFile(const char *filename,
                          int create,
                          const char *virt_type)
{
    return virNodeDeviceDefParse(NULL, filename, create, virt_type);
}

/*
 * Return fc_host dev's WWNN and WWPN
 */
int
virNodeDeviceGetWWNs(virNodeDeviceDefPtr def,
                     char **wwnn,
                     char **wwpn)
{
    virNodeDevCapsDefPtr cap = NULL;
    int ret = 0;

    cap = def->caps;
    while (cap != NULL) {
        if (cap->type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            cap->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
            *wwnn = strdup(cap->data.scsi_host.wwnn);
            *wwpn = strdup(cap->data.scsi_host.wwpn);
            break;
        }

        cap = cap->next;
    }

    if (cap == NULL) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("Device is not a fibre channel HBA"));
        ret = -1;
    } else if (*wwnn == NULL || *wwpn == NULL) {
        /* Free the other one, if allocated... */
        VIR_FREE(*wwnn);
        VIR_FREE(*wwpn);
        ret = -1;
        virReportOOMError();
    }

    return ret;
}

/*
 * Return the NPIV dev's parent device name
 */
int
virNodeDeviceGetParentHost(const virNodeDeviceObjListPtr devs,
                           const char *dev_name,
                           const char *parent_name,
                           int *parent_host)
{
    virNodeDeviceObjPtr parent = NULL;
    virNodeDevCapsDefPtr cap = NULL;
    int ret = 0;

    parent = virNodeDeviceFindByName(devs, parent_name);
    if (parent == NULL) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("Could not find parent device for '%s'"),
                                 dev_name);
        ret = -1;
        goto out;
    }

    cap = parent->def->caps;
    while (cap != NULL) {
        if (cap->type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (cap->data.scsi_host.flags &
             VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS)) {
                *parent_host = cap->data.scsi_host.host;
                break;
        }

        cap = cap->next;
    }

    if (cap == NULL) {
        virNodeDeviceReportError(VIR_ERR_INTERNAL_ERROR,
                                 _("Parent device %s is not capable "
                                   "of vport operations"),
                                 parent->def->name);
        ret = -1;
    }

    virNodeDeviceObjUnlock(parent);

out:
    return ret;
}

void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps)
{
    int i = 0;
    union _virNodeDevCapData *data = &caps->data;

    switch (caps->type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        VIR_FREE(data->system.product_name);
        VIR_FREE(data->system.hardware.vendor_name);
        VIR_FREE(data->system.hardware.version);
        VIR_FREE(data->system.hardware.serial);
        VIR_FREE(data->system.firmware.vendor_name);
        VIR_FREE(data->system.firmware.version);
        VIR_FREE(data->system.firmware.release_date);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        VIR_FREE(data->pci_dev.product_name);
        VIR_FREE(data->pci_dev.vendor_name);
        VIR_FREE(data->pci_dev.physical_function);
        for (i = 0 ; i < data->pci_dev.num_virtual_functions ; i++) {
            VIR_FREE(data->pci_dev.virtual_functions[i]);
        }
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        VIR_FREE(data->usb_dev.product_name);
        VIR_FREE(data->usb_dev.vendor_name);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        VIR_FREE(data->usb_if.description);
        break;
    case VIR_NODE_DEV_CAP_NET:
        VIR_FREE(data->net.ifname);
        VIR_FREE(data->net.address);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        VIR_FREE(data->scsi_host.wwnn);
        VIR_FREE(data->scsi_host.wwpn);
        VIR_FREE(data->scsi_host.fabric_wwn);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        VIR_FREE(data->scsi_target.name);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        VIR_FREE(data->scsi.type);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        VIR_FREE(data->storage.block);
        VIR_FREE(data->storage.bus);
        VIR_FREE(data->storage.drive_type);
        VIR_FREE(data->storage.model);
        VIR_FREE(data->storage.vendor);
        VIR_FREE(data->storage.serial);
        VIR_FREE(data->storage.media_label);
        break;
    case VIR_NODE_DEV_CAP_LAST:
        /* This case is here to shutup the compiler */
        break;
    }

    VIR_FREE(caps);
}


void virNodeDeviceObjLock(virNodeDeviceObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virNodeDeviceObjUnlock(virNodeDeviceObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}
