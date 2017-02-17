/*
 * node_device_conf.c: config handling for node devices
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: David F. Lively <dlively@virtualiron.com>
 */

#include <config.h>

#include <unistd.h>
#include <errno.h>

#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"
#include "virstring.h"
#include "node_device_conf.h"
#include "device_conf.h"
#include "virxml.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "virrandom.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_ENUM_IMPL(virNodeDevDevnode, VIR_NODE_DEV_DEVNODE_LAST,
              "dev",
              "link")

VIR_ENUM_IMPL(virNodeDevCap, VIR_NODE_DEV_CAP_LAST,
              "system",
              "pci",
              "usb_device",
              "usb",
              "net",
              "scsi_host",
              "scsi_target",
              "scsi",
              "storage",
              "fc_host",
              "vports",
              "scsi_generic",
              "drm")

VIR_ENUM_IMPL(virNodeDevNetCap, VIR_NODE_DEV_CAP_NET_LAST,
              "80203",
              "80211")

VIR_ENUM_IMPL(virNodeDevDRM, VIR_NODE_DEV_DRM_LAST,
              "primary",
              "control",
              "render")

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

int virNodeDeviceHasCap(const virNodeDeviceObj *dev, const char *cap)
{
    virNodeDevCapsDefPtr caps = dev->def->caps;
    const char *fc_host_cap =
        virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_FC_HOST);
    const char *vports_cap =
        virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_VPORTS);

    while (caps) {
        if (STREQ(cap, virNodeDevCapTypeToString(caps->data.type)))
            return 1;
        else if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST)
            if ((STREQ(cap, fc_host_cap) &&
                (caps->data.scsi_host.flags &
                 VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST)) ||
                (STREQ(cap, vports_cap) &&
                (caps->data.scsi_host.flags &
                 VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS)))
                return 1;
        caps = caps->next;
    }
    return 0;
}


/* virNodeDeviceFindFCCapDef:
 * @dev: Pointer to current device
 *
 * Search the device object 'caps' array for fc_host capability.
 *
 * Returns:
 * Pointer to the caps or NULL if not found
 */
static virNodeDevCapsDefPtr
virNodeDeviceFindFCCapDef(const virNodeDeviceObj *dev)
{
    virNodeDevCapsDefPtr caps = dev->def->caps;

    while (caps) {
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST))
            break;

        caps = caps->next;
    }
    return caps;
}


/* virNodeDeviceFindVPORTCapDef:
 * @dev: Pointer to current device
 *
 * Search the device object 'caps' array for vport_ops capability.
 *
 * Returns:
 * Pointer to the caps or NULL if not found
 */
static virNodeDevCapsDefPtr
virNodeDeviceFindVPORTCapDef(const virNodeDeviceObj *dev)
{
    virNodeDevCapsDefPtr caps = dev->def->caps;

    while (caps) {
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            (caps->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS))
            break;

        caps = caps->next;
    }
    return caps;
}


virNodeDeviceObjPtr
virNodeDeviceFindBySysfsPath(virNodeDeviceObjListPtr devs,
                             const char *sysfs_path)
{
    size_t i;

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


virNodeDeviceObjPtr virNodeDeviceFindByName(virNodeDeviceObjListPtr devs,
                                            const char *name)
{
    size_t i;

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(devs->objs[i]);
        if (STREQ(devs->objs[i]->def->name, name))
            return devs->objs[i];
        virNodeDeviceObjUnlock(devs->objs[i]);
    }

    return NULL;
}


static virNodeDeviceObjPtr
virNodeDeviceFindByWWNs(virNodeDeviceObjListPtr devs,
                        const char *parent_wwnn,
                        const char *parent_wwpn)
{
    size_t i;

    for (i = 0; i < devs->count; i++) {
        virNodeDevCapsDefPtr cap;
        virNodeDeviceObjLock(devs->objs[i]);
        if ((cap = virNodeDeviceFindFCCapDef(devs->objs[i])) &&
            STREQ_NULLABLE(cap->data.scsi_host.wwnn, parent_wwnn) &&
            STREQ_NULLABLE(cap->data.scsi_host.wwpn, parent_wwpn))
            return devs->objs[i];
        virNodeDeviceObjUnlock(devs->objs[i]);
    }

    return NULL;
}


static virNodeDeviceObjPtr
virNodeDeviceFindByFabricWWN(virNodeDeviceObjListPtr devs,
                             const char *parent_fabric_wwn)
{
    size_t i;

    for (i = 0; i < devs->count; i++) {
        virNodeDevCapsDefPtr cap;
        virNodeDeviceObjLock(devs->objs[i]);
        if ((cap = virNodeDeviceFindFCCapDef(devs->objs[i])) &&
            STREQ_NULLABLE(cap->data.scsi_host.fabric_wwn, parent_fabric_wwn))
            return devs->objs[i];
        virNodeDeviceObjUnlock(devs->objs[i]);
    }

    return NULL;
}


static virNodeDeviceObjPtr
virNodeDeviceFindByCap(virNodeDeviceObjListPtr devs,
                       const char *cap)
{
    size_t i;

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(devs->objs[i]);
        if (virNodeDeviceHasCap(devs->objs[i], cap))
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
    VIR_FREE(def->parent_wwnn);
    VIR_FREE(def->parent_wwpn);
    VIR_FREE(def->parent_fabric_wwn);
    VIR_FREE(def->driver);
    VIR_FREE(def->sysfs_path);
    VIR_FREE(def->parent_sysfs_path);
    VIR_FREE(def->devnode);
    virStringListFree(def->devlinks);

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
    size_t i;
    for (i = 0; i < devs->count; i++)
        virNodeDeviceObjFree(devs->objs[i]);
    VIR_FREE(devs->objs);
    devs->count = 0;
}

virNodeDeviceObjPtr virNodeDeviceAssignDef(virNodeDeviceObjListPtr devs,
                                           virNodeDeviceDefPtr def)
{
    virNodeDeviceObjPtr device;

    if ((device = virNodeDeviceFindByName(devs, def->name))) {
        virNodeDeviceDefFree(device->def);
        device->def = def;
        return device;
    }

    if (VIR_ALLOC(device) < 0)
        return NULL;

    if (virMutexInit(&device->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(device);
        return NULL;
    }
    virNodeDeviceObjLock(device);

    if (VIR_APPEND_ELEMENT_COPY(devs->objs, devs->count, device) < 0) {
        virNodeDeviceObjUnlock(device);
        virNodeDeviceObjFree(device);
        return NULL;
    }
    device->def = def;

    return device;

}

void virNodeDeviceObjRemove(virNodeDeviceObjListPtr devs,
                            virNodeDeviceObjPtr *dev)
{
    size_t i;

    virNodeDeviceObjUnlock(*dev);

    for (i = 0; i < devs->count; i++) {
        virNodeDeviceObjLock(*dev);
        if (devs->objs[i] == *dev) {
            virNodeDeviceObjUnlock(*dev);
            virNodeDeviceObjFree(devs->objs[i]);
            *dev = NULL;

            VIR_DELETE_ELEMENT(devs->objs, i, devs->count);
            break;
        }
        virNodeDeviceObjUnlock(*dev);
    }
}

static void
virPCIELinkFormat(virBufferPtr buf,
                  virPCIELinkPtr lnk,
                  const char *attrib)
{
    if (!lnk)
        return;

    virBufferAsprintf(buf, "<link validity='%s'", attrib);
    if (lnk->port >= 0)
        virBufferAsprintf(buf, " port='%d'", lnk->port);
    if (lnk->speed)
        virBufferAsprintf(buf, " speed='%s'",
                          virPCIELinkSpeedTypeToString(lnk->speed));
    virBufferAsprintf(buf, " width='%d'", lnk->width);
    virBufferAddLit(buf, "/>\n");
}

static void
virPCIEDeviceInfoFormat(virBufferPtr buf,
                        virPCIEDeviceInfoPtr info)
{
    if (!info->link_cap && !info->link_sta) {
        virBufferAddLit(buf, "<pci-express/>\n");
        return;
    }

    virBufferAddLit(buf, "<pci-express>\n");
    virBufferAdjustIndent(buf, 2);

    virPCIELinkFormat(buf, info->link_cap, "cap");
    virPCIELinkFormat(buf, info->link_sta, "sta");

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</pci-express>\n");
}

char *virNodeDeviceDefFormat(const virNodeDeviceDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virNodeDevCapsDefPtr caps;
    size_t i = 0;

    virBufferAddLit(&buf, "<device>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);
    virBufferEscapeString(&buf, "<path>%s</path>\n", def->sysfs_path);
    if (def->devnode)
        virBufferEscapeString(&buf, "<devnode type='dev'>%s</devnode>\n",
                              def->devnode);
    if (def->devlinks) {
        for (i = 0; def->devlinks[i]; i++)
            virBufferEscapeString(&buf, "<devnode type='link'>%s</devnode>\n",
                                  def->devlinks[i]);
    }
    if (def->parent)
        virBufferEscapeString(&buf, "<parent>%s</parent>\n", def->parent);
    if (def->driver) {
        virBufferAddLit(&buf, "<driver>\n");
        virBufferAdjustIndent(&buf, 2);
        virBufferEscapeString(&buf, "<name>%s</name>\n", def->driver);
        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</driver>\n");
    }

    for (caps = def->caps; caps; caps = caps->next) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];
        virNodeDevCapDataPtr data = &caps->data;

        virBufferAsprintf(&buf, "<capability type='%s'>\n",
                          virNodeDevCapTypeToString(caps->data.type));
        virBufferAdjustIndent(&buf, 2);
        switch (caps->data.type) {
        case VIR_NODE_DEV_CAP_SYSTEM:
            if (data->system.product_name)
                virBufferEscapeString(&buf, "<product>%s</product>\n",
                                      data->system.product_name);
            virBufferAddLit(&buf, "<hardware>\n");
            virBufferAdjustIndent(&buf, 2);
            if (data->system.hardware.vendor_name)
                virBufferEscapeString(&buf, "<vendor>%s</vendor>\n",
                                      data->system.hardware.vendor_name);
            if (data->system.hardware.version)
                virBufferEscapeString(&buf, "<version>%s</version>\n",
                                      data->system.hardware.version);
            if (data->system.hardware.serial)
                virBufferEscapeString(&buf, "<serial>%s</serial>\n",
                                      data->system.hardware.serial);
            virUUIDFormat(data->system.hardware.uuid, uuidstr);
            virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", uuidstr);
            virBufferAdjustIndent(&buf, -2);
            virBufferAddLit(&buf, "</hardware>\n");

            virBufferAddLit(&buf, "<firmware>\n");
            virBufferAdjustIndent(&buf, 2);
            if (data->system.firmware.vendor_name)
                virBufferEscapeString(&buf, "<vendor>%s</vendor>\n",
                                      data->system.firmware.vendor_name);
            if (data->system.firmware.version)
                virBufferEscapeString(&buf, "<version>%s</version>\n",
                                      data->system.firmware.version);
            if (data->system.firmware.release_date)
                virBufferEscapeString(&buf, "<release_date>%s</release_date>\n",
                                      data->system.firmware.release_date);
            virBufferAdjustIndent(&buf, -2);
            virBufferAddLit(&buf, "</firmware>\n");
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
            virBufferAsprintf(&buf, "<domain>%d</domain>\n",
                              data->pci_dev.domain);
            virBufferAsprintf(&buf, "<bus>%d</bus>\n", data->pci_dev.bus);
            virBufferAsprintf(&buf, "<slot>%d</slot>\n",
                              data->pci_dev.slot);
            virBufferAsprintf(&buf, "<function>%d</function>\n",
                              data->pci_dev.function);
            virBufferAsprintf(&buf, "<product id='0x%04x'",
                                  data->pci_dev.product);
            if (data->pci_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->pci_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferAsprintf(&buf, "<vendor id='0x%04x'",
                                  data->pci_dev.vendor);
            if (data->pci_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->pci_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION) {
                virBufferAddLit(&buf, "<capability type='phys_function'>\n");
                virBufferAdjustIndent(&buf, 2);
                virBufferAsprintf(&buf,
                                  "<address domain='0x%.4x' bus='0x%.2x' "
                                  "slot='0x%.2x' function='0x%.1x'/>\n",
                                  data->pci_dev.physical_function->domain,
                                  data->pci_dev.physical_function->bus,
                                  data->pci_dev.physical_function->slot,
                                  data->pci_dev.physical_function->function);
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</capability>\n");
            }
            if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION) {
                virBufferAddLit(&buf, "<capability type='virt_functions'");
                if (data->pci_dev.max_virtual_functions)
                    virBufferAsprintf(&buf, " maxCount='%u'",
                                      data->pci_dev.max_virtual_functions);
                if (data->pci_dev.num_virtual_functions == 0) {
                    virBufferAddLit(&buf, "/>\n");
                } else {
                    virBufferAddLit(&buf, ">\n");
                    virBufferAdjustIndent(&buf, 2);
                    for (i = 0; i < data->pci_dev.num_virtual_functions; i++) {
                        virBufferAsprintf(&buf,
                                          "<address domain='0x%.4x' bus='0x%.2x' "
                                          "slot='0x%.2x' function='0x%.1x'/>\n",
                                          data->pci_dev.virtual_functions[i]->domain,
                                          data->pci_dev.virtual_functions[i]->bus,
                                          data->pci_dev.virtual_functions[i]->slot,
                                          data->pci_dev.virtual_functions[i]->function);
                    }
                    virBufferAdjustIndent(&buf, -2);
                    virBufferAddLit(&buf, "</capability>\n");
                }
            }
            if (data->pci_dev.hdrType) {
                virBufferAsprintf(&buf, "<capability type='%s'/>\n",
                                  virPCIHeaderTypeToString(data->pci_dev.hdrType));
            }
            if (data->pci_dev.nIommuGroupDevices) {
                virBufferAsprintf(&buf, "<iommuGroup number='%d'>\n",
                                  data->pci_dev.iommuGroupNumber);
                virBufferAdjustIndent(&buf, 2);
                for (i = 0; i < data->pci_dev.nIommuGroupDevices; i++) {
                    virBufferAsprintf(&buf,
                                      "<address domain='0x%.4x' bus='0x%.2x' "
                                      "slot='0x%.2x' function='0x%.1x'/>\n",
                                      data->pci_dev.iommuGroupDevices[i]->domain,
                                      data->pci_dev.iommuGroupDevices[i]->bus,
                                      data->pci_dev.iommuGroupDevices[i]->slot,
                                      data->pci_dev.iommuGroupDevices[i]->function);
                }
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</iommuGroup>\n");
            }
            if (data->pci_dev.numa_node >= 0)
                virBufferAsprintf(&buf, "<numa node='%d'/>\n",
                                  data->pci_dev.numa_node);

            if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCIE)
                virPCIEDeviceInfoFormat(&buf, data->pci_dev.pci_express);
            break;
        case VIR_NODE_DEV_CAP_USB_DEV:
            virBufferAsprintf(&buf, "<bus>%d</bus>\n", data->usb_dev.bus);
            virBufferAsprintf(&buf, "<device>%d</device>\n",
                              data->usb_dev.device);
            virBufferAsprintf(&buf, "<product id='0x%04x'",
                                  data->usb_dev.product);
            if (data->usb_dev.product_name)
                virBufferEscapeString(&buf, ">%s</product>\n",
                                      data->usb_dev.product_name);
            else
                virBufferAddLit(&buf, " />\n");
            virBufferAsprintf(&buf, "<vendor id='0x%04x'",
                                  data->usb_dev.vendor);
            if (data->usb_dev.vendor_name)
                virBufferEscapeString(&buf, ">%s</vendor>\n",
                                      data->usb_dev.vendor_name);
            else
                virBufferAddLit(&buf, " />\n");
            break;
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
            virBufferAsprintf(&buf, "<number>%d</number>\n",
                              data->usb_if.number);
            virBufferAsprintf(&buf, "<class>%d</class>\n",
                              data->usb_if._class);
            virBufferAsprintf(&buf, "<subclass>%d</subclass>\n",
                              data->usb_if.subclass);
            virBufferAsprintf(&buf, "<protocol>%d</protocol>\n",
                              data->usb_if.protocol);
            if (data->usb_if.description)
                virBufferEscapeString(&buf,
                                  "<description>%s</description>\n",
                                  data->usb_if.description);
            break;
        case VIR_NODE_DEV_CAP_NET:
            virBufferEscapeString(&buf, "<interface>%s</interface>\n",
                              data->net.ifname);
            if (data->net.address)
                virBufferEscapeString(&buf, "<address>%s</address>\n",
                                  data->net.address);
            virInterfaceLinkFormat(&buf, &data->net.lnk);
            if (data->net.features) {
                for (i = 0; i < VIR_NET_DEV_FEAT_LAST; i++) {
                    if (virBitmapIsBitSet(data->net.features, i)) {
                        virBufferAsprintf(&buf, "<feature name='%s'/>\n",
                                          virNetDevFeatureTypeToString(i));
                    }
                }
            }
            if (data->net.subtype != VIR_NODE_DEV_CAP_NET_LAST) {
                const char *subtyp =
                    virNodeDevNetCapTypeToString(data->net.subtype);
                virBufferEscapeString(&buf, "<capability type='%s'/>\n",
                                      subtyp);
            }
            break;
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            virBufferAsprintf(&buf, "<host>%d</host>\n",
                              data->scsi_host.host);
            if (data->scsi_host.unique_id != -1)
                virBufferAsprintf(&buf, "<unique_id>%d</unique_id>\n",
                                  data->scsi_host.unique_id);
            if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                virBufferAddLit(&buf, "<capability type='fc_host'>\n");
                virBufferAdjustIndent(&buf, 2);
                virBufferEscapeString(&buf, "<wwnn>%s</wwnn>\n",
                                      data->scsi_host.wwnn);
                virBufferEscapeString(&buf, "<wwpn>%s</wwpn>\n",
                                      data->scsi_host.wwpn);
                virBufferEscapeString(&buf, "<fabric_wwn>%s</fabric_wwn>\n",
                                      data->scsi_host.fabric_wwn);
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</capability>\n");
            }
            if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS) {
                virBufferAddLit(&buf, "<capability type='vport_ops'>\n");
                virBufferAdjustIndent(&buf, 2);
                virBufferAsprintf(&buf, "<max_vports>%d</max_vports>\n",
                                  data->scsi_host.max_vports);
                virBufferAsprintf(&buf, "<vports>%d</vports>\n",
                                  data->scsi_host.vports);
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</capability>\n");
            }

            break;

        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            virBufferEscapeString(&buf, "<target>%s</target>\n",
                                  data->scsi_target.name);
            break;

        case VIR_NODE_DEV_CAP_SCSI:
            virBufferAsprintf(&buf, "<host>%d</host>\n", data->scsi.host);
            virBufferAsprintf(&buf, "<bus>%d</bus>\n", data->scsi.bus);
            virBufferAsprintf(&buf, "<target>%d</target>\n",
                              data->scsi.target);
            virBufferAsprintf(&buf, "<lun>%d</lun>\n", data->scsi.lun);
            if (data->scsi.type)
                virBufferEscapeString(&buf, "<type>%s</type>\n",
                                      data->scsi.type);
            break;
        case VIR_NODE_DEV_CAP_STORAGE:
            virBufferEscapeString(&buf, "<block>%s</block>\n",
                                  data->storage.block);
            if (data->storage.bus)
                virBufferEscapeString(&buf, "<bus>%s</bus>\n",
                                      data->storage.bus);
            if (data->storage.drive_type)
                virBufferEscapeString(&buf, "<drive_type>%s</drive_type>\n",
                                      data->storage.drive_type);
            if (data->storage.model)
                virBufferEscapeString(&buf, "<model>%s</model>\n",
                                      data->storage.model);
            if (data->storage.vendor)
                virBufferEscapeString(&buf, "<vendor>%s</vendor>\n",
                                      data->storage.vendor);
            if (data->storage.serial)
                virBufferEscapeString(&buf, "<serial>%s</serial>\n",
                                      data->storage.serial);
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE) {
                int avl = data->storage.flags &
                    VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;
                virBufferAddLit(&buf, "<capability type='removable'>\n");
                virBufferAdjustIndent(&buf, 2);
                virBufferAsprintf(&buf, "<media_available>%d"
                                  "</media_available>\n", avl ? 1 : 0);
                virBufferAsprintf(&buf, "<media_size>%llu</media_size>\n",
                                  data->storage.removable_media_size);
                if (data->storage.media_label)
                    virBufferEscapeString(&buf,
                                          "<media_label>%s</media_label>\n",
                                          data->storage.media_label);
                if (data->storage.logical_block_size > 0)
                    virBufferAsprintf(&buf, "<logical_block_size>%llu"
                                      "</logical_block_size>\n",
                                      data->storage.logical_block_size);
                if (data->storage.num_blocks > 0)
                    virBufferAsprintf(&buf,
                                      "<num_blocks>%llu</num_blocks>\n",
                                      data->storage.num_blocks);
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</capability>\n");
            } else {
                virBufferAsprintf(&buf, "<size>%llu</size>\n",
                                  data->storage.size);
                if (data->storage.logical_block_size > 0)
                    virBufferAsprintf(&buf, "<logical_block_size>%llu"
                                      "</logical_block_size>\n",
                                      data->storage.logical_block_size);
                if (data->storage.num_blocks > 0)
                    virBufferAsprintf(&buf, "<num_blocks>%llu</num_blocks>\n",
                                      data->storage.num_blocks);
            }
            if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE)
                virBufferAddLit(&buf, "<capability type='hotpluggable'/>\n");
            break;
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
            virBufferEscapeString(&buf, "<char>%s</char>\n",
                                  data->sg.path);
            break;
        case VIR_NODE_DEV_CAP_DRM:
            virBufferEscapeString(&buf, "<type>%s</type>\n", virNodeDevDRMTypeToString(data->drm.type));
            break;
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }

        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</capability>\n");
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</device>\n");

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}

/**
 * virNodeDevCapsDefParseIntOptional:
 * @xpath:  XPath to evaluate
 * @ctxt:   Context
 * @value:  Where to store parsed value
 * @def:    Node device which is parsed
 * @invalid_error_fmt:  error message to print on invalid format
 *
 * Returns: -1 on error (invalid int format under @xpath)
 *           0 if @xpath was not found (@value is untouched)
 *           1 on success
 */
static int
virNodeDevCapsDefParseIntOptional(const char *xpath,
                                  xmlXPathContextPtr ctxt,
                                  int *value,
                                  virNodeDeviceDefPtr def,
                                  const char *invalid_error_fmt)
{
    int ret;
    int val;

    ret = virXPathInt(xpath, ctxt, &val);
    if (ret < -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       invalid_error_fmt,
                       def->name);
        return -1;
    } else if (ret == -1) {
        return 0;
    }
    *value = val;
    return 1;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       ret == -1 ? missing_error_fmt : invalid_error_fmt,
                       def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapDRMParseXML(xmlXPathContextPtr ctxt,
                         virNodeDeviceDefPtr def,
                         xmlNodePtr node,
                         virNodeDevCapDataPtr data)
{
    xmlNodePtr orignode;
    int ret = -1;
    char *type = NULL;

    orignode = ctxt->node;
    ctxt->node = node;

    type = virXPathString("string(./type[1])", ctxt);

    if ((data->drm.type = virNodeDevDRMTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown drm type '%s' for '%s'"), type, def->name);
        goto out;
    }

    ret = 0;

 out:
    VIR_FREE(type);
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapStorageParseXML(xmlXPathContextPtr ctxt,
                             virNodeDeviceDefPtr def,
                             xmlNodePtr node,
                             virNodeDevCapDataPtr data)
{
    xmlNodePtr orignode, *nodes = NULL;
    size_t i;
    int n, ret = -1;
    unsigned long long val;

    orignode = ctxt->node;
    ctxt->node = node;

    data->storage.block = virXPathString("string(./block[1])", ctxt);
    if (!data->storage.block) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no block device path supplied for '%s'"),
                       def->name);
        goto out;
    }

    data->storage.bus        = virXPathString("string(./bus[1])", ctxt);
    data->storage.drive_type = virXPathString("string(./drive_type[1])", ctxt);
    data->storage.model      = virXPathString("string(./model[1])", ctxt);
    data->storage.vendor     = virXPathString("string(./vendor[1])", ctxt);
    data->storage.serial     = virXPathString("string(./serial[1])", ctxt);

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        goto out;

    for (i = 0; i < n; i++) {
        char *type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing storage capability type for '%s'"),
                           def->name);
            goto out;
        }

        if (STREQ(type, "hotpluggable")) {
            data->storage.flags |= VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE;
        } else if (STREQ(type, "removable")) {
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
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
virNodeDevCapSCSIParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDefPtr def,
                          xmlNodePtr node,
                          virNodeDevCapDataPtr data)
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
virNodeDevCapSCSITargetParseXML(xmlXPathContextPtr ctxt,
                                virNodeDeviceDefPtr def,
                                xmlNodePtr node,
                                virNodeDevCapDataPtr data)
{
    xmlNodePtr orignode;
    int ret = -1;

    orignode = ctxt->node;
    ctxt->node = node;

    data->scsi_target.name = virXPathString("string(./target[1])", ctxt);
    if (!data->scsi_target.name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
virNodeDevCapSCSIHostParseXML(xmlXPathContextPtr ctxt,
                              virNodeDeviceDefPtr def,
                              xmlNodePtr node,
                              virNodeDevCapDataPtr data,
                              int create,
                              const char *virt_type)
{
    xmlNodePtr orignode, *nodes = NULL;
    int ret = -1, n = 0;
    size_t i;
    char *type = NULL;

    orignode = ctxt->node;
    ctxt->node = node;

    if (create == EXISTING_DEVICE) {
        if (virNodeDevCapsDefParseULong("number(./host[1])", ctxt,
                                        &data->scsi_host.host, def,
                                        _("no SCSI host ID supplied for '%s'"),
                                        _("invalid SCSI host ID supplied for '%s'")) < 0) {
            goto out;
        }
        /* Optional unique_id value */
        data->scsi_host.unique_id = -1;
        if (virNodeDevCapsDefParseIntOptional("number(./unique_id[1])", ctxt,
                                              &data->scsi_host.unique_id, def,
                                              _("invalid unique_id supplied for '%s'")) < 0) {
            goto out;
        }
    }

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        goto out;

    for (i = 0; i < n; i++) {
        type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                    virReportError(VIR_ERR_INTERNAL_ERROR,
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
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("no WWPN supplied for '%s', and "
                                     "auto-generation failed"),
                                   def->name);
                    goto out;
                }
            }

            ctxt->node = orignode2;

        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                         virNodeDevCapDataPtr data)
{
    xmlNodePtr orignode, lnk;
    size_t i = -1;
    int ret = -1, n = -1;
    char *tmp = NULL;
    xmlNodePtr *nodes = NULL;

    orignode = ctxt->node;
    ctxt->node = node;

    data->net.ifname = virXPathString("string(./interface[1])", ctxt);
    if (!data->net.ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no network interface supplied for '%s'"),
                       def->name);
        goto out;
    }

    data->net.address = virXPathString("string(./address[1])", ctxt);

    if ((n = virXPathNodeSet("./feature", ctxt, &nodes)) < 0)
        goto out;

    if (n > 0) {
        if (!(data->net.features = virBitmapNew(VIR_NET_DEV_FEAT_LAST)))
            goto out;
    }

    for (i = 0; i < n; i++) {
        int val;
        if (!(tmp = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing network device feature name"));
            goto out;
        }

        if ((val = virNetDevFeatureTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown network device feature '%s'"),
                           tmp);
            goto out;
        }
        ignore_value(virBitmapSetBit(data->net.features, val));
        VIR_FREE(tmp);
    }

    data->net.subtype = VIR_NODE_DEV_CAP_NET_LAST;

    tmp = virXPathString("string(./capability/@type)", ctxt);
    if (tmp) {
        int val = virNodeDevNetCapTypeFromString(tmp);
        VIR_FREE(tmp);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid network type supplied for '%s'"),
                           def->name);
            goto out;
        }
        data->net.subtype = val;
    }

    lnk = virXPathNode("./link", ctxt);
    if (lnk && virInterfaceLinkParseXML(lnk, &data->net.lnk) < 0)
        goto out;

    ret = 0;
 out:
    ctxt->node = orignode;
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    return ret;
}

static int
virNodeDevCapUSBInterfaceParseXML(xmlXPathContextPtr ctxt,
                                  virNodeDeviceDefPtr def,
                                  xmlNodePtr node,
                                  virNodeDevCapDataPtr data)
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       ret == -1 ? missing_error_fmt : invalid_error_fmt,
                       def->name);
        return -1;
    }

    *value = val;
    return 0;
}

static int
virNodeDevCapUSBDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            virNodeDevCapDataPtr data)
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
virNodeDevCapPCIDevIommuGroupParseXML(xmlXPathContextPtr ctxt,
                                      xmlNodePtr iommuGroupNode,
                                      virNodeDevCapDataPtr data)
{
    xmlNodePtr origNode = ctxt->node;
    xmlNodePtr *addrNodes = NULL;
    char *numberStr = NULL;
    int nAddrNodes, ret = -1;
    size_t i;
    virPCIDeviceAddressPtr pciAddr = NULL;

    ctxt->node = iommuGroupNode;

    numberStr = virXMLPropString(iommuGroupNode, "number");
    if (!numberStr) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s", _("missing iommuGroup number attribute"));
        goto cleanup;
    }
    if (virStrToLong_ui(numberStr, NULL, 10,
                        &data->pci_dev.iommuGroupNumber) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid iommuGroup number attribute '%s'"),
                       numberStr);
        goto cleanup;
    }

    if ((nAddrNodes = virXPathNodeSet("./address", ctxt, &addrNodes)) < 0)
        goto cleanup;

    for (i = 0; i < nAddrNodes; i++) {
        virPCIDeviceAddress addr = {0};
        if (virPCIDeviceAddressParseXML(addrNodes[i], &addr) < 0)
            goto cleanup;
        if (VIR_ALLOC(pciAddr) < 0)
            goto cleanup;
        pciAddr->domain = addr.domain;
        pciAddr->bus = addr.bus;
        pciAddr->slot = addr.slot;
        pciAddr->function = addr.function;
        if (VIR_APPEND_ELEMENT(data->pci_dev.iommuGroupDevices,
                               data->pci_dev.nIommuGroupDevices,
                               pciAddr) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    ctxt->node = origNode;
    VIR_FREE(numberStr);
    VIR_FREE(addrNodes);
    VIR_FREE(pciAddr);
    return ret;
}

static int
virPCIEDeviceInfoLinkParseXML(xmlXPathContextPtr ctxt,
                              xmlNodePtr linkNode,
                              virPCIELinkPtr lnk)
{
    xmlNodePtr origNode = ctxt->node;
    int ret = -1, speed;
    char *speedStr = NULL, *portStr = NULL;

    ctxt->node = linkNode;

    if (virXPathUInt("number(./@width)", ctxt, &lnk->width) < 0) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("mandatory attribute 'width' is missing or malformed"));
        goto cleanup;
    }

    if ((speedStr = virXPathString("string(./@speed)", ctxt))) {
        if ((speed = virPCIELinkSpeedTypeFromString(speedStr)) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("malformed 'speed' attribute: %s"),
                           speedStr);
            goto cleanup;
        }
        lnk->speed = speed;
    }

    if ((portStr = virXPathString("string(./@port)", ctxt))) {
        if (virStrToLong_i(portStr, NULL, 10, &lnk->port) < 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("malformed 'port' attribute: %s"),
                           portStr);
            goto cleanup;
        }
    } else {
        lnk->port = -1;
    }

    ret = 0;
 cleanup:
    VIR_FREE(portStr);
    VIR_FREE(speedStr);
    ctxt->node = origNode;
    return ret;
}

static int
virPCIEDeviceInfoParseXML(xmlXPathContextPtr ctxt,
                          xmlNodePtr pciExpressNode,
                          virPCIEDeviceInfoPtr pci_express)
{
    xmlNodePtr lnk, origNode = ctxt->node;
    int ret = -1;

    ctxt->node = pciExpressNode;

    if ((lnk = virXPathNode("./link[@validity='cap']", ctxt))) {
        if (VIR_ALLOC(pci_express->link_cap) < 0)
            goto cleanup;

        if (virPCIEDeviceInfoLinkParseXML(ctxt, lnk,
                                          pci_express->link_cap) < 0)
            goto cleanup;
    }

    if ((lnk = virXPathNode("./link[@validity='sta']", ctxt))) {
        if (VIR_ALLOC(pci_express->link_sta) < 0)
            goto cleanup;

        if (virPCIEDeviceInfoLinkParseXML(ctxt, lnk,
                                          pci_express->link_sta) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    ctxt->node = origNode;
    return ret;
}


static int
virNodeDevPCICapabilityParseXML(xmlXPathContextPtr ctxt,
                                xmlNodePtr node,
                                virNodeDevCapDataPtr data)
{
    char *maxFuncsStr = virXMLPropString(node, "maxCount");
    char *type = virXMLPropString(node, "type");
    xmlNodePtr *addresses = NULL;
    xmlNodePtr orignode = ctxt->node;
    int ret = -1;
    size_t i = 0;

    ctxt->node = node;

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("Missing capability type"));
        goto out;
    }

    if (STREQ(type, "phys_function")) {
        xmlNodePtr address = virXPathNode("./address[1]", ctxt);

        if (VIR_ALLOC(data->pci_dev.physical_function) < 0)
            goto out;

        if (!address) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing address in 'phys_function' capability"));
            goto out;
        }

        if (virPCIDeviceAddressParseXML(address,
                                        data->pci_dev.physical_function) < 0)
            goto out;

        data->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;
    } else if (STREQ(type, "virt_functions")) {
        int naddresses;

        if ((naddresses = virXPathNodeSet("./address", ctxt, &addresses)) < 0)
            goto out;

        if (maxFuncsStr &&
            virStrToLong_uip(maxFuncsStr, NULL, 10,
                             &data->pci_dev.max_virtual_functions) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Malformed 'maxCount' parameter"));
            goto out;
        }

        if (VIR_ALLOC_N(data->pci_dev.virtual_functions, naddresses) < 0)
            goto out;

        for (i = 0; i < naddresses; i++) {
            virPCIDeviceAddressPtr addr = NULL;

            if (VIR_ALLOC(addr) < 0)
                goto out;

            if (virPCIDeviceAddressParseXML(addresses[i], addr) < 0) {
                VIR_FREE(addr);
                goto out;
            }

            if (VIR_APPEND_ELEMENT(data->pci_dev.virtual_functions,
                                   data->pci_dev.num_virtual_functions,
                                   addr) < 0)
                goto out;
        }

        data->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;
    } else {
        int hdrType = virPCIHeaderTypeFromString(type);

        if (hdrType > 0 && !data->pci_dev.hdrType)
            data->pci_dev.hdrType = hdrType;
    }

    ret = 0;
 out:
    VIR_FREE(addresses);
    VIR_FREE(maxFuncsStr);
    VIR_FREE(type);
    ctxt->node = orignode;
    return ret;
}


static int
virNodeDevCapPCIDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            virNodeDevCapDataPtr data)
{
    xmlNodePtr orignode, iommuGroupNode, pciExpress;
    xmlNodePtr *nodes = NULL;
    int n = 0;
    int ret = -1;
    virPCIEDeviceInfoPtr pci_express = NULL;
    char *tmp = NULL;
    size_t i = 0;

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

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        goto out;

    for (i = 0; i < n; i++) {
        if (virNodeDevPCICapabilityParseXML(ctxt, nodes[i], data) < 0)
            goto out;
    }
    VIR_FREE(nodes);

    if ((iommuGroupNode = virXPathNode("./iommuGroup[1]", ctxt))) {
        if (virNodeDevCapPCIDevIommuGroupParseXML(ctxt, iommuGroupNode,
                                                  data) < 0) {
            goto out;
        }
    }

    /* The default value is -1 since zero is valid NUMA node number */
    data->pci_dev.numa_node = -1;
    if (virNodeDevCapsDefParseIntOptional("number(./numa[1]/@node)", ctxt,
                                          &data->pci_dev.numa_node, def,
                                          _("invalid NUMA node ID supplied for '%s'")) < 0)
        goto out;

    if ((pciExpress = virXPathNode("./pci-express[1]", ctxt))) {
        if (VIR_ALLOC(pci_express) < 0)
            goto out;

        if (virPCIEDeviceInfoParseXML(ctxt, pciExpress, pci_express) < 0)
            goto out;

        data->pci_dev.pci_express = pci_express;
        pci_express = NULL;
        data->pci_dev.flags |= VIR_NODE_DEV_CAP_FLAG_PCIE;
    }

    ret = 0;
 out:
    VIR_FREE(nodes);
    VIR_FREE(tmp);
    virPCIEDeviceInfoFree(pci_express);
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDevCapSystemParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDefPtr def,
                            xmlNodePtr node,
                            virNodeDevCapDataPtr data)
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no system UUID supplied for '%s'"), def->name);
        goto out;
    }

    if (virUUIDParse(tmp, data->system.hardware.uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    int val, ret = -1;

    if (VIR_ALLOC(caps) < 0)
        return NULL;

    tmp = virXMLPropString(node, "type");
    if (!tmp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing capability type"));
        goto error;
    }

    if ((val = virNodeDevCapTypeFromString(tmp)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown capability type '%s'"), tmp);
        VIR_FREE(tmp);
        goto error;
    }
    caps->data.type = val;
    VIR_FREE(tmp);

    switch (caps->data.type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        ret = virNodeDevCapSystemParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        ret = virNodeDevCapPCIDevParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        ret = virNodeDevCapUSBDevParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        ret = virNodeDevCapUSBInterfaceParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_NET:
        ret = virNodeDevCapNetParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        ret = virNodeDevCapSCSIHostParseXML(ctxt, def, node,
                                            &caps->data,
                                            create,
                                            virt_type);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        ret = virNodeDevCapSCSITargetParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        ret = virNodeDevCapSCSIParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        ret = virNodeDevCapStorageParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_DRM:
        ret = virNodeDevCapDRMParseXML(ctxt, def, node, &caps->data);
        break;
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
    case VIR_NODE_DEV_CAP_SCSI_GENERIC:
    case VIR_NODE_DEV_CAP_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown capability type '%d' for '%s'"),
                       caps->data.type, def->name);
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
    int n, m;
    size_t i;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    /* Extract device name */
    if (create == EXISTING_DEVICE) {
        def->name = virXPathString("string(./name[1])", ctxt);

        if (!def->name) {
            virReportError(VIR_ERR_NO_NAME, NULL);
            goto error;
        }
    } else {
        if (VIR_STRDUP(def->name, "new device") < 0)
            goto error;
    }

    def->sysfs_path = virXPathString("string(./path[1])", ctxt);

    /* Parse devnodes */
    nodes = NULL;
    if ((n = virXPathNodeSet("./devnode", ctxt, &nodes)) < 0)
        goto error;

    if (VIR_ALLOC_N(def->devlinks, n + 1) < 0)
        goto error;

    for (i = 0, m = 0; i < n; i++) {
        xmlNodePtr node = nodes[i];
        char *tmp = virXMLPropString(node, "type");
        virNodeDevDevnodeType type;

        if (!tmp) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("missing devnode type"));
            goto error;
        }

        if ((type = virNodeDevDevnodeTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown devnode type '%s'"), tmp);
            VIR_FREE(tmp);
            goto error;
        }

        switch (type) {
        case VIR_NODE_DEV_DEVNODE_DEV:
            def->devnode = (char*)xmlNodeGetContent(node);
            break;
        case VIR_NODE_DEV_DEVNODE_LINK:
            def->devlinks[m++] = (char*)xmlNodeGetContent(node);
            break;
        case VIR_NODE_DEV_DEVNODE_LAST:
            break;
        }
    }

    /* Extract device parent, if any */
    def->parent = virXPathString("string(./parent[1])", ctxt);
    def->parent_wwnn = virXPathString("string(./parent[1]/@wwnn)", ctxt);
    def->parent_wwpn = virXPathString("string(./parent[1]/@wwpn)", ctxt);
    if ((def->parent_wwnn && !def->parent_wwpn) ||
        (!def->parent_wwnn && def->parent_wwpn)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("must supply both wwnn and wwpn for parent"));
        goto error;
    }
    def->parent_fabric_wwn = virXPathString("string(./parent[1]/@fabric_wwn)",
                                            ctxt);

    /* Parse device capabilities */
    nodes = NULL;
    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        goto error;

    if (n == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no device capabilities for '%s'"),
                       def->name);
        goto error;
    }

    next_cap = &def->caps;
    for (i = 0; i < n; i++) {
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
        virReportError(VIR_ERR_XML_ERROR,
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
    int ret = -1;

    cap = def->caps;
    while (cap != NULL) {
        if (cap->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            cap->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
            if (VIR_STRDUP(*wwnn, cap->data.scsi_host.wwnn) < 0 ||
                VIR_STRDUP(*wwpn, cap->data.scsi_host.wwpn) < 0) {
                /* Free the other one, if allocated... */
                VIR_FREE(*wwnn);
                goto cleanup;
            }
            break;
        }

        cap = cap->next;
    }

    if (cap == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Device is not a fibre channel HBA"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

/*
 * Return the NPIV dev's parent device name
 */
/* virNodeDeviceFindFCParentHost:
 * @parent: Pointer to node device object
 * @parent_host: Pointer to return parent host number
 *
 * Search the capabilities for the device to find the FC capabilities
 * in order to set the parent_host value.
 *
 * Returns:
 *   0 on success with parent_host set, -1 otherwise;
 */
static int
virNodeDeviceFindFCParentHost(virNodeDeviceObjPtr parent,
                              int *parent_host)
{
    virNodeDevCapsDefPtr cap = virNodeDeviceFindVPORTCapDef(parent);

    if (!cap) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parent device %s is not capable "
                         "of vport operations"),
                       parent->def->name);
        return -1;
    }

    *parent_host = cap->data.scsi_host.host;
    return 0;
}


int
virNodeDeviceGetParentHost(virNodeDeviceObjListPtr devs,
                           const char *dev_name,
                           const char *parent_name,
                           int *parent_host)
{
    virNodeDeviceObjPtr parent = NULL;
    int ret;

    if (!(parent = virNodeDeviceFindByName(devs, parent_name))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(parent, parent_host);

    virNodeDeviceObjUnlock(parent);

    return ret;
}


int
virNodeDeviceGetParentHostByWWNs(virNodeDeviceObjListPtr devs,
                                 const char *dev_name,
                                 const char *parent_wwnn,
                                 const char *parent_wwpn,
                                 int *parent_host)
{
    virNodeDeviceObjPtr parent = NULL;
    int ret;

    if (!(parent = virNodeDeviceFindByWWNs(devs, parent_wwnn, parent_wwpn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(parent, parent_host);

    virNodeDeviceObjUnlock(parent);

    return ret;
}


int
virNodeDeviceGetParentHostByFabricWWN(virNodeDeviceObjListPtr devs,
                                      const char *dev_name,
                                      const char *parent_fabric_wwn,
                                      int *parent_host)
{
    virNodeDeviceObjPtr parent = NULL;
    int ret;

    if (!(parent = virNodeDeviceFindByFabricWWN(devs, parent_fabric_wwn))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find parent device for '%s'"),
                       dev_name);
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(parent, parent_host);

    virNodeDeviceObjUnlock(parent);

    return ret;
}


int
virNodeDeviceFindVportParentHost(virNodeDeviceObjListPtr devs,
                                 int *parent_host)
{
    virNodeDeviceObjPtr parent = NULL;
    const char *cap = virNodeDevCapTypeToString(VIR_NODE_DEV_CAP_VPORTS);
    int ret;

    if (!(parent = virNodeDeviceFindByCap(devs, cap))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any vport capable device"));
        return -1;
    }

    ret = virNodeDeviceFindFCParentHost(parent, parent_host);

    virNodeDeviceObjUnlock(parent);

    return ret;
}


void virNodeDevCapsDefFree(virNodeDevCapsDefPtr caps)
{
    size_t i = 0;
    virNodeDevCapDataPtr data = &caps->data;

    switch (caps->data.type) {
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
        for (i = 0; i < data->pci_dev.num_virtual_functions; i++)
            VIR_FREE(data->pci_dev.virtual_functions[i]);
        VIR_FREE(data->pci_dev.virtual_functions);
        for (i = 0; i < data->pci_dev.nIommuGroupDevices; i++)
            VIR_FREE(data->pci_dev.iommuGroupDevices[i]);
        VIR_FREE(data->pci_dev.iommuGroupDevices);
        virPCIEDeviceInfoFree(data->pci_dev.pci_express);
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
        virBitmapFree(data->net.features);
        data->net.features = NULL;
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
    case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        VIR_FREE(data->sg.path);
        break;
    case VIR_NODE_DEV_CAP_DRM:
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
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

static bool
virNodeDeviceCapMatch(virNodeDeviceObjPtr devobj,
                      int type)
{
    virNodeDevCapsDefPtr cap = NULL;

    for (cap = devobj->def->caps; cap; cap = cap->next) {
        if (type == cap->data.type)
            return true;

        if (cap->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            if (type == VIR_NODE_DEV_CAP_FC_HOST &&
                (cap->data.scsi_host.flags &
                 VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST))
                return true;

            if (type == VIR_NODE_DEV_CAP_VPORTS &&
                (cap->data.scsi_host.flags &
                 VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS))
                return true;
        }
    }

    return false;
}

#define MATCH(FLAG) ((flags & (VIR_CONNECT_LIST_NODE_DEVICES_CAP_ ## FLAG)) && \
                     virNodeDeviceCapMatch(devobj, VIR_NODE_DEV_CAP_ ## FLAG))
static bool
virNodeDeviceMatch(virNodeDeviceObjPtr devobj,
                   unsigned int flags)
{
    /* filter by cap type */
    if (flags & VIR_CONNECT_LIST_NODE_DEVICES_FILTERS_CAP) {
        if (!(MATCH(SYSTEM)        ||
              MATCH(PCI_DEV)       ||
              MATCH(USB_DEV)       ||
              MATCH(USB_INTERFACE) ||
              MATCH(NET)           ||
              MATCH(SCSI_HOST)     ||
              MATCH(SCSI_TARGET)   ||
              MATCH(SCSI)          ||
              MATCH(STORAGE)       ||
              MATCH(FC_HOST)       ||
              MATCH(VPORTS)        ||
              MATCH(SCSI_GENERIC)  ||
              MATCH(DRM)))
            return false;
    }

    return true;
}
#undef MATCH

int
virNodeDeviceObjListExport(virConnectPtr conn,
                           virNodeDeviceObjList devobjs,
                           virNodeDevicePtr **devices,
                           virNodeDeviceObjListFilter filter,
                           unsigned int flags)
{
    virNodeDevicePtr *tmp_devices = NULL;
    virNodeDevicePtr device = NULL;
    int ndevices = 0;
    int ret = -1;
    size_t i;

    if (devices && VIR_ALLOC_N(tmp_devices, devobjs.count + 1) < 0)
        goto cleanup;

    for (i = 0; i < devobjs.count; i++) {
        virNodeDeviceObjPtr devobj = devobjs.objs[i];
        virNodeDeviceObjLock(devobj);
        if ((!filter || filter(conn, devobj->def)) &&
            virNodeDeviceMatch(devobj, flags)) {
            if (devices) {
                if (!(device = virGetNodeDevice(conn, devobj->def->name)) ||
                    VIR_STRDUP(device->parent, devobj->def->parent) < 0) {
                    virNodeDeviceObjUnlock(devobj);
                    goto cleanup;
                }
                tmp_devices[ndevices] = device;
            }
            ndevices++;
        }
        virNodeDeviceObjUnlock(devobj);
    }

    if (tmp_devices) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(tmp_devices, ndevices + 1));
        *devices = tmp_devices;
        tmp_devices = NULL;
    }

    ret = ndevices;

 cleanup:
    if (tmp_devices) {
        for (i = 0; i < ndevices; i++)
            virObjectUnref(tmp_devices[i]);
    }

    VIR_FREE(tmp_devices);
    return ret;
}
