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


#define virNodeDeviceLog(msg...) fprintf(stderr, msg)

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
