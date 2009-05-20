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

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_ENUM_IMPL(virNodeDevCap, VIR_NODE_DEV_CAP_LAST,
              "system",
              "pci",
              "usb_device",
              "usb",
              "net",
              "scsi_host",
              "scsi",
              "storage")

VIR_ENUM_IMPL(virNodeDevNetCap, VIR_NODE_DEV_CAP_NET_LAST,
              "80203",
              "80211")

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

virNodeDeviceObjPtr virNodeDeviceAssignDef(virConnectPtr conn,
                                           virNodeDeviceObjListPtr devs,
                                           const virNodeDeviceDefPtr def)
{
    virNodeDeviceObjPtr device;

    if ((device = virNodeDeviceFindByName(devs, def->name))) {
        virNodeDeviceDefFree(device->def);
        device->def = def;
        return device;
    }

    if (VIR_ALLOC(device) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (virMutexInit(&device->lock) < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
        virReportOOMError(conn);
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

char *virNodeDeviceDefFormat(virConnectPtr conn,
                             const virNodeDeviceDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNodeDevCapsDefPtr caps = def->caps;
    char *tmp;

    virBufferAddLit(&buf, "<device>\n");
    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);

    if (def->parent)
        virBufferEscapeString(&buf, "  <parent>%s</parent>\n", def->parent);

    for (caps = def->caps; caps; caps = caps->next) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        union _virNodeDevCapData *data = &caps->data;

        virBufferVSprintf(&buf, "  <capability type='%s'>\n",
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
            virBufferVSprintf(&buf, "      <uuid>%s</uuid>\n", uuidstr);
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
            virBufferVSprintf(&buf, "    <domain>%d</domain>\n",
                              data->pci_dev.domain);
            virBufferVSprintf(&buf, "    <bus>%d</bus>\n", data->pci_dev.bus);
            virBufferVSprintf(&buf, "    <slot>%d</slot>\n",
                              data->pci_dev.slot);
            virBufferVSprintf(&buf, "    <function>%d</function>\n",
                              data->pci_dev.function);
            virBufferVSprintf(&buf, "    <product id='0x%04x'",
                                  data->pci_dev.product);
            if (data->pci_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->pci_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferVSprintf(&buf, "    <vendor id='0x%04x'",
                                  data->pci_dev.vendor);
            if (data->pci_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->pci_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            break;
        case VIR_NODE_DEV_CAP_USB_DEV:
            virBufferVSprintf(&buf, "    <bus>%d</bus>\n", data->usb_dev.bus);
            virBufferVSprintf(&buf, "    <device>%d</device>\n",
                              data->usb_dev.device);
            virBufferVSprintf(&buf, "    <product id='0x%04x'",
                                  data->usb_dev.product);
            if (data->usb_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->usb_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferVSprintf(&buf, "    <vendor id='0x%04x'",
                                  data->usb_dev.vendor);
            if (data->usb_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->usb_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            break;
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
            virBufferVSprintf(&buf, "    <number>%d</number>\n",
                              data->usb_if.number);
            virBufferVSprintf(&buf, "    <class>%d</class>\n",
                              data->usb_if._class);
            virBufferVSprintf(&buf, "    <subclass>%d</subclass>\n",
                              data->usb_if.subclass);
            virBufferVSprintf(&buf, "    <protocol>%d</protocol>\n",
                              data->usb_if.protocol);
            if (data->usb_if.description)
                virBufferVSprintf(&buf, "    <description>%s</description>\n",
                                  data->usb_if.description);
            break;
        case VIR_NODE_DEV_CAP_NET:
            virBufferVSprintf(&buf, "    <interface>%s</interface>\n",
                              data->net.ifname);
            if (data->net.address)
                virBufferVSprintf(&buf, "    <address>%s</address>\n",
                                  data->net.address);
            if (data->net.subtype != VIR_NODE_DEV_CAP_NET_LAST) {
                const char *subtyp =
                    virNodeDevNetCapTypeToString(data->net.subtype);
                virBufferVSprintf(&buf, "    <capability type='%s'/>\n", subtyp);
            }
            break;
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            virBufferVSprintf(&buf, "    <host>%d</host>\n",
                              data->scsi_host.host);
            break;
        case VIR_NODE_DEV_CAP_SCSI:
            virBufferVSprintf(&buf, "    <host>%d</host>\n", data->scsi.host);
            virBufferVSprintf(&buf, "    <bus>%d</bus>\n", data->scsi.bus);
            virBufferVSprintf(&buf, "    <target>%d</target>\n",
                              data->scsi.target);
            virBufferVSprintf(&buf, "    <lun>%d</lun>\n", data->scsi.lun);
            if (data->scsi.type)
                virBufferVSprintf(&buf, "    <type>%s</type>\n",
                                  data->scsi.type);
            break;
        case VIR_NODE_DEV_CAP_STORAGE:
            virBufferVSprintf(&buf, "    <block>%s</block>\n",
                              data->storage.block);
            if (data->storage.bus)
                virBufferVSprintf(&buf, "    <bus>%s</bus>\n",
                                  data->storage.bus);
            if (data->storage.drive_type)
                virBufferVSprintf(&buf, "    <drive_type>%s</drive_type>\n",
                                  data->storage.drive_type);
            if (data->storage.model)
                virBufferVSprintf(&buf, "    <model>%s</model>\n",
                                  data->storage.model);
            if (data->storage.vendor)
                virBufferVSprintf(&buf, "    <vendor>%s</vendor>\n",
                                  data->storage.vendor);
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE) {
                int avl = data->storage.flags &
                    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;
                virBufferAddLit(&buf, "    <capability type='removable'>\n");
                virBufferVSprintf(&buf,
                                  "      <media_available>%d"
                                  "</media_available>\n", avl ? 1 : 0);
                virBufferVSprintf(&buf, "      <media_size>%llu</media_size>\n",
                                  data->storage.removable_media_size);
                virBufferAddLit(&buf, "    </capability>\n");
            } else {
                virBufferVSprintf(&buf, "    <size>%llu</size>\n",
                                  data->storage.size);
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
    virReportOOMError(conn);
    tmp = virBufferContentAndReset(&buf);
    VIR_FREE(tmp);
    return NULL;
}

static int
virNodeDevCapsDefParseULong(virConnectPtr conn,
                            const char *xpath,
                            xmlXPathContextPtr ctxt,
                            unsigned *value,
                            virNodeDeviceDefPtr def,
                            const char *missing_error_fmt,
                            const char *invalid_error_fmt)
{
    int ret;
    unsigned long val;

    ret = virXPathULong(conn, xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapsDefParseULongLong(virConnectPtr conn,
                                const char *xpath,
                                xmlXPathContextPtr ctxt,
                                unsigned long long *value,
                                virNodeDeviceDefPtr def,
                                const char *missing_error_fmt,
                                const char *invalid_error_fmt)
{
    int ret;
    unsigned long long val;

    ret = virXPathULongLong(conn, xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapStorageParseXML(virConnectPtr conn,
                             xmlXPathContextPtr ctxt,
                             virNodeDeviceDefPtr def,
                             xmlNodePtr node,
                             union _virNodeDevCapData *data)
{
    xmlNodePtr orignode, *nodes = NULL;
    int i, n, ret = -1;
    unsigned long long val;

    orignode = ctxt->node;
    ctxt->node = node;

    data->storage.block = virXPathString(conn, "string(./block[1])", ctxt);
    if (!data->storage.block) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no block device path supplied for '%s'"),
                                 def->name);
        goto out;
    }

    data->storage.bus        = virXPathString(conn, "string(./bus[1])", ctxt);
    data->storage.drive_type = virXPathString(conn, "string(./drive_type[1])", ctxt);
    data->storage.model      = virXPathString(conn, "string(./model[1])", ctxt);
    data->storage.vendor     = virXPathString(conn, "string(./vendor[1])", ctxt);

    if ((n = virXPathNodeSet(conn, "./capability", ctxt, &nodes)) < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("error parsing storage capabilities for '%s'"),
                                 def->name);
        goto out;
    }

    for (i = 0 ; i < n ; i++) {
        char *type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
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

            if (virXPathBoolean(conn, "count(./media_available[. = '1']) > 0", ctxt))
                data->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

            val = 0;
            if (virNodeDevCapsDefParseULongLong(conn, "number(./media_size[1])", ctxt, &val, def,
                                                _("no removable media size supplied for '%s'"),
                                                _("invalid removable media size supplied for '%s'")) < 0) {
                ctxt->node = orignode2;
                VIR_FREE(type);
                goto out;
            }
            data->storage.removable_media_size = val;

            ctxt->node = orignode2;
        } else {
            virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                     _("unknown storage capability type '%s' for '%s'"),
                                     type, def->name);
            VIR_FREE(type);
            goto out;
        }

        VIR_FREE(type);
    }

    if (!(data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE)) {
        val = 0;
        if (virNodeDevCapsDefParseULongLong(conn, "number(./size[1])", ctxt, &val, def,
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
virNodeDevCapScsiParseXML(virConnectPtr conn,
                          xmlXPathContextPtr ctxt,
                          virNodeDeviceDefPtr def,
                          xmlNodePtr node,
                          union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong(conn, "number(./host[1])", ctxt,
                                    &data->scsi.host, def,
                                    _("no SCSI host ID supplied for '%s'"),
                                    _("invalid SCSI host ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./bus[1])", ctxt,
                                    &data->scsi.bus, def,
                                    _("no SCSI bus ID supplied for '%s'"),
                                    _("invalid SCSI bus ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./target[1])", ctxt,
                                    &data->scsi.target, def,
                                    _("no SCSI target ID supplied for '%s'"),
                                    _("invalid SCSI target ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./lun[1])", ctxt,
                                    &data->scsi.lun, def,
                                    _("no SCSI LUN ID supplied for '%s'"),
                                    _("invalid SCSI LUN ID supplied for '%s'")) < 0)
        goto out;

    data->scsi.type = virXPathString(conn, "string(./type[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapScsiHostParseXML(virConnectPtr conn,
                              xmlXPathContextPtr ctxt,
                              virNodeDeviceDefPtr def,
                              xmlNodePtr node,
                              union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong(conn, "number(./host[1])", ctxt,
                                    &data->scsi_host.host, def,
                                    _("no SCSI host ID supplied for '%s'"),
                                    _("invalid SCSI host ID supplied for '%s'")) < 0)
        goto out;

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapNetParseXML(virConnectPtr conn,
                         xmlXPathContextPtr ctxt,
                         virNodeDeviceDefPtr def,
                         xmlNodePtr node,
                         union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;
    char *tmp;

    orignode = ctxt->node;
    ctxt->node = node;

    data->net.ifname = virXPathString(conn, "string(./interface[1])", ctxt);
    if (!data->net.ifname) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no network interface supplied for '%s'"),
                                 def->name);
        goto out;
    }

    data->net.address = virXPathString(conn, "string(./address[1])", ctxt);

    data->net.subtype = VIR_NODE_DEV_CAP_NET_LAST;

    tmp = virXPathString(conn, "string(./capability/@type)", ctxt);
    if (tmp) {
        int val = virNodeDevNetCapTypeFromString(tmp);
        VIR_FREE(tmp);
        if (val < 0) {
            virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
virNodeDevCapUsbInterfaceParseXML(virConnectPtr conn,
                                  xmlXPathContextPtr ctxt,
                                  virNodeDeviceDefPtr def,
                                  xmlNodePtr node,
                                  union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong(conn, "number(./number[1])", ctxt,
                                    &data->usb_if.number, def,
                                    _("no USB interface number supplied for '%s'"),
                                    _("invalid USB interface number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./class[1])", ctxt,
                                    &data->usb_if._class, def,
                                    _("no USB interface class supplied for '%s'"),
                                    _("invalid USB interface class supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./subclass[1])", ctxt,
                                    &data->usb_if.subclass, def,
                                    _("no USB interface subclass supplied for '%s'"),
                                    _("invalid USB interface subclass supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./protocol[1])", ctxt,
                                    &data->usb_if.protocol, def,
                                    _("no USB interface protocol supplied for '%s'"),
                                    _("invalid USB interface protocol supplied for '%s'")) < 0)
        goto out;

    data->usb_if.description = virXPathString(conn, "string(./description[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapsDefParseHexId(virConnectPtr conn,
                            const char *xpath,
                            xmlXPathContextPtr ctxt,
                            unsigned *value,
                            virNodeDeviceDefPtr def,
                            const char *missing_error_fmt,
                            const char *invalid_error_fmt)
{
    int ret;
    unsigned long val;

    ret = virXPathULongHex(conn, xpath, ctxt, &val);
    if (ret < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 ret == -1 ? missing_error_fmt : invalid_error_fmt,
                                 def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapUsbDevParseXML(virConnectPtr conn,
                            xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong(conn, "number(./bus[1])", ctxt,
                                    &data->usb_dev.bus, def,
                                    _("no USB bus number supplied for '%s'"),
                                    _("invalid USB bus number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./device[1])", ctxt,
                                    &data->usb_dev.device, def,
                                    _("no USB device number supplied for '%s'"),
                                    _("invalid USB device number supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId(conn, "string(./vendor[1]/@id)", ctxt,
                                    &data->usb_dev.vendor, def,
                                    _("no USB vendor ID supplied for '%s'"),
                                    _("invalid USB vendor ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId(conn, "string(./product[1]/@id)", ctxt,
                                    &data->usb_dev.product, def,
                                    _("no USB product ID supplied for '%s'"),
                                    _("invalid USB product ID supplied for '%s'")) < 0)
        goto out;

    data->usb_dev.vendor_name  = virXPathString(conn, "string(./vendor[1])", ctxt);
    data->usb_dev.product_name = virXPathString(conn, "string(./product[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapPciDevParseXML(virConnectPtr conn,
                            xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    if (virNodeDevCapsDefParseULong(conn, "number(./domain[1])", ctxt,
                                    &data->pci_dev.domain, def,
                                    _("no PCI domain ID supplied for '%s'"),
                                    _("invalid PCI domain ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./bus[1])", ctxt,
                                    &data->pci_dev.bus, def,
                                    _("no PCI bus ID supplied for '%s'"),
                                    _("invalid PCI bus ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./slot[1])", ctxt,
                                    &data->pci_dev.slot, def,
                                    _("no PCI slot ID supplied for '%s'"),
                                    _("invalid PCI slot ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseULong(conn, "number(./function[1])", ctxt,
                                    &data->pci_dev.function, def,
                                    _("no PCI function ID supplied for '%s'"),
                                    _("invalid PCI function ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId(conn, "string(./vendor[1]/@id)", ctxt,
                                    &data->pci_dev.vendor, def,
                                    _("no PCI vendor ID supplied for '%s'"),
                                    _("invalid PCI vendor ID supplied for '%s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId(conn, "string(./product[1]/@id)", ctxt,
                                    &data->pci_dev.product, def,
                                    _("no PCI product ID supplied for '%s'"),
                                    _("invalid PCI product ID supplied for '%s'")) < 0)
        goto out;

    data->pci_dev.vendor_name  = virXPathString(conn, "string(./vendor[1])", ctxt);
    data->pci_dev.product_name = virXPathString(conn, "string(./product[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapSystemParseXML(virConnectPtr conn,
                            xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            union _virNodeDevCapData *data)
{
    xmlNodePtr orignode;
    int ret = -1;
    char *tmp;

    orignode = ctxt->node;
    ctxt->node = node;

    data->system.product_name = virXPathString(conn, "string(./product[1])", ctxt);

    data->system.hardware.vendor_name = virXPathString(conn, "string(./hardware/vendor[1])", ctxt);
    data->system.hardware.version     = virXPathString(conn, "string(./hardware/version[1])", ctxt);
    data->system.hardware.serial      = virXPathString(conn, "string(./hardware/serial[1])", ctxt);

    tmp = virXPathString(conn, "string(./hardware/uuid[1])", ctxt);
    if (!tmp) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no system UUID supplied for '%s'"), def->name);
        goto out;
    }

    if (virUUIDParse(tmp, data->system.hardware.uuid) < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("malformed uuid element for '%s'"), def->name);
        VIR_FREE(tmp);
        goto out;
    }
    VIR_FREE(tmp);

    data->system.firmware.vendor_name  = virXPathString(conn, "string(./firmware/vendor[1])", ctxt);
    data->system.firmware.version      = virXPathString(conn, "string(./firmware/version[1])", ctxt);
    data->system.firmware.release_date = virXPathString(conn, "string(./firmware/release_date[1])", ctxt);

    ret = 0;
out:
    ctxt->node = orignode;
    return ret;
}

static virNodeDevCapsDefPtr
virNodeDevCapsDefParseXML(virConnectPtr conn,
                          xmlXPathContextPtr ctxt,
                          virNodeDeviceDefPtr def,
                          xmlNodePtr node)
{
    virNodeDevCapsDefPtr caps;
    char *tmp;
    int val, ret;

    if (VIR_ALLOC(caps) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    tmp = virXMLPropString(node, "type");
    if (!tmp) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("missing capability type"));
        goto error;
    }

    if ((val = virNodeDevCapTypeFromString(tmp)) < 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("unknown capability type '%s'"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    caps->type = val;
    VIR_FREE(tmp);

    switch (caps->type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        ret = virNodeDevCapSystemParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        ret = virNodeDevCapPciDevParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        ret = virNodeDevCapUsbDevParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        ret = virNodeDevCapUsbInterfaceParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_NET:
        ret = virNodeDevCapNetParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        ret = virNodeDevCapScsiHostParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        ret = virNodeDevCapScsiParseXML(conn, ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        ret = virNodeDevCapStorageParseXML(conn, ctxt, def, node, &caps->data);
        break;
    default:
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
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
virNodeDeviceDefParseXML(virConnectPtr conn, xmlXPathContextPtr ctxt)
{
    virNodeDeviceDefPtr def;
    virNodeDevCapsDefPtr *next_cap;
    xmlNodePtr *nodes;
    int n, i;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    /* Extract device name */
    def->name = virXPathString(conn, "string(./name[1])", ctxt);
    if (!def->name) {
        virNodeDeviceReportError(conn, VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract device parent, if any */
    def->parent = virXPathString(conn, "string(./parent[1])", ctxt);

    /* Parse device capabilities */
    nodes = NULL;
    if ((n = virXPathNodeSet(conn, "./capability", ctxt, &nodes)) <= 0) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 _("no device capabilities for '%s'"),
                                 def->name);
        goto error;
    }

    next_cap = &def->caps;
    for (i = 0 ; i < n ; i++) {
        *next_cap = virNodeDevCapsDefParseXML(conn, ctxt, def, nodes[i]);
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

static virNodeDeviceDefPtr
virNodeDeviceDefParseNode(virConnectPtr conn, xmlDocPtr xml, xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNodeDeviceDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "device")) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("incorrect root element"));
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError(conn);
        goto cleanup;
    }

    ctxt->node = root;
    def = virNodeDeviceDefParseXML(conn, ctxt);

cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}

/* Called from SAX on parsing errors in the XML. */
static void
catchXMLError(void *ctx, const char *msg ATTRIBUTE_UNUSED, ...)
{
    xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) ctx;

    if (ctxt) {
        virConnectPtr conn = ctxt->_private;

        if (virGetLastError() == NULL &&
            ctxt->lastError.level == XML_ERR_FATAL &&
            ctxt->lastError.message != NULL) {
            virNodeDeviceReportError(conn,  VIR_ERR_XML_DETAIL,
                                     _("at line %d: %s"),
                                     ctxt->lastError.line,
                                     ctxt->lastError.message);
        }
    }
}

virNodeDeviceDefPtr
virNodeDeviceDefParseString(virConnectPtr conn, const char *str)
{
    xmlParserCtxtPtr pctxt;
    xmlDocPtr xml = NULL;
    xmlNodePtr root;
    virNodeDeviceDefPtr def = NULL;

    /* Set up a parser context so we can catch the details of XML errors. */
    pctxt = xmlNewParserCtxt ();
    if (!pctxt || !pctxt->sax)
        goto cleanup;
    pctxt->sax->error = catchXMLError;
    pctxt->_private = conn;

    if (conn) virResetError (&conn->err);
    xml = xmlCtxtReadDoc(pctxt, BAD_CAST str, "device.xml", NULL,
                         XML_PARSE_NOENT | XML_PARSE_NONET |
                         XML_PARSE_NOWARNING);
    if (!xml) {
        if (conn && conn->err.code == VIR_ERR_NONE)
              virNodeDeviceReportError(conn, VIR_ERR_XML_ERROR,
                                       "%s", _("failed to parse xml document"));
        goto cleanup;
    }

    if ((root = xmlDocGetRootElement(xml)) == NULL) {
        virNodeDeviceReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                 "%s", _("missing root element"));
        goto cleanup;
    }

    def = virNodeDeviceDefParseNode(conn, xml, root);

cleanup:
    xmlFreeParserCtxt(pctxt);
    xmlFreeDoc(xml);
    return def;
}

void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps)
{
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
