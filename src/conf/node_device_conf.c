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
 */

#include <config.h>

#include <unistd.h>

#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"
#include "node_device_conf.h"
#include "device_conf.h"
#include "virxml.h"
#include "virbuffer.h"
#include "viruuid.h"
#include "virrandom.h"
#include "virlog.h"
#include "virfcp.h"
#include "virpcivpd.h"

#define VIR_FROM_THIS VIR_FROM_NODEDEV

VIR_LOG_INIT("conf.node_device_conf");

VIR_ENUM_IMPL(virNodeDevDevnode,
              VIR_NODE_DEV_DEVNODE_LAST,
              "dev",
              "link",
);

VIR_ENUM_IMPL(virNodeDevCap,
              VIR_NODE_DEV_CAP_LAST,
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
              "drm",
              "mdev_types",
              "mdev",
              "ccw",
              "css",
              "vdpa",
              "ap_card",
              "ap_queue",
              "ap_matrix",
              "vpd",
);

VIR_ENUM_IMPL(virNodeDevNetCap,
              VIR_NODE_DEV_CAP_NET_LAST,
              "80203",
              "80211",
);

VIR_ENUM_IMPL(virNodeDevDRM,
              VIR_NODE_DEV_DRM_LAST,
              "primary",
              "control",
              "render",
);

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


void
virNodeDeviceDefFree(virNodeDeviceDef *def)
{
    virNodeDevCapsDef *caps;

    if (!def)
        return;

    g_free(def->name);
    g_free(def->parent);
    g_free(def->parent_wwnn);
    g_free(def->parent_wwpn);
    g_free(def->parent_fabric_wwn);
    g_free(def->driver);
    g_free(def->sysfs_path);
    g_free(def->parent_sysfs_path);
    g_free(def->devnode);
    g_strfreev(def->devlinks);

    caps = def->caps;
    while (caps) {
        virNodeDevCapsDef *next = caps->next;
        virNodeDevCapsDefFree(caps);
        caps = next;
    }

    g_free(def);
}


static void
virPCIELinkFormat(virBuffer *buf,
                  virPCIELink *lnk,
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
virPCIEDeviceInfoFormat(virBuffer *buf,
                        virPCIEDeviceInfo *info)
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


static void
virNodeDeviceCapSystemDefFormat(virBuffer *buf,
                                const virNodeDevCapData *data)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (data->system.product_name)
        virBufferEscapeString(buf, "<product>%s</product>\n",
                              data->system.product_name);
    virBufferAddLit(buf, "<hardware>\n");
    virBufferAdjustIndent(buf, 2);
    if (data->system.hardware.vendor_name)
        virBufferEscapeString(buf, "<vendor>%s</vendor>\n",
                              data->system.hardware.vendor_name);
    if (data->system.hardware.version)
        virBufferEscapeString(buf, "<version>%s</version>\n",
                              data->system.hardware.version);
    if (data->system.hardware.serial)
        virBufferEscapeString(buf, "<serial>%s</serial>\n",
                              data->system.hardware.serial);
    virUUIDFormat(data->system.hardware.uuid, uuidstr);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</hardware>\n");

    virBufferAddLit(buf, "<firmware>\n");
    virBufferAdjustIndent(buf, 2);
    if (data->system.firmware.vendor_name)
        virBufferEscapeString(buf, "<vendor>%s</vendor>\n",
                              data->system.firmware.vendor_name);
    if (data->system.firmware.version)
        virBufferEscapeString(buf, "<version>%s</version>\n",
                              data->system.firmware.version);
    if (data->system.firmware.release_date)
        virBufferEscapeString(buf, "<release_date>%s</release_date>\n",
                              data->system.firmware.release_date);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</firmware>\n");
}


static void
virNodeDeviceCapMdevTypesFormat(virBuffer *buf,
                                virMediatedDeviceType **mdev_types,
                                const size_t nmdev_types)
{
    size_t i;

    if (nmdev_types > 0) {
        virBufferAddLit(buf, "<capability type='mdev_types'>\n");
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < nmdev_types; i++) {
            virMediatedDeviceType *type = mdev_types[i];
            virBufferEscapeString(buf, "<type id='%s'>\n", type->id);
            virBufferAdjustIndent(buf, 2);
            if (type->name)
                virBufferEscapeString(buf, "<name>%s</name>\n",
                                      type->name);
            virBufferEscapeString(buf, "<deviceAPI>%s</deviceAPI>\n",
                                  type->device_api);
            virBufferAsprintf(buf,
                              "<availableInstances>%u</availableInstances>\n",
                              type->available_instances);
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</type>\n");
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</capability>\n");
    }
}

static void
virNodeDeviceCapVPDFormatCustomVendorField(virPCIVPDResourceCustom *field, virBuffer *buf)
{
    if (field == NULL || field->value == NULL)
        return;

    virBufferAsprintf(buf, "<vendor_field index='%c'>%s</vendor_field>\n", field->idx,
                      field->value);
}

static void
virNodeDeviceCapVPDFormatCustomSystemField(virPCIVPDResourceCustom *field, virBuffer *buf)
{
    if (field == NULL || field->value == NULL)
        return;

    virBufferAsprintf(buf, "<system_field index='%c'>%s</system_field>\n", field->idx,
                      field->value);
}

static inline void
virNodeDeviceCapVPDFormatRegularField(virBuffer *buf, const char *keyword, const char *value)
{
    if (keyword == NULL || value == NULL)
        return;

    virBufferAsprintf(buf, "<%s>%s</%s>\n", keyword, value, keyword);
}

static void
virNodeDeviceCapVPDFormat(virBuffer *buf, virPCIVPDResource *res)
{
    if (res == NULL)
        return;

    virBufferAddLit(buf, "<capability type='vpd'>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", res->name);

    if (res->ro != NULL) {
        virBufferEscapeString(buf, "<fields access='%s'>\n", "readonly");

        virBufferAdjustIndent(buf, 2);
        virNodeDeviceCapVPDFormatRegularField(buf, "change_level", res->ro->change_level);
        virNodeDeviceCapVPDFormatRegularField(buf, "manufacture_id", res->ro->manufacture_id);
        virNodeDeviceCapVPDFormatRegularField(buf, "part_number", res->ro->part_number);
        virNodeDeviceCapVPDFormatRegularField(buf, "serial_number", res->ro->serial_number);
        g_ptr_array_foreach(res->ro->vendor_specific,
                            (GFunc)virNodeDeviceCapVPDFormatCustomVendorField, buf);
        virBufferAdjustIndent(buf, -2);

        virBufferAddLit(buf, "</fields>\n");
    }

    if (res->rw != NULL) {
        virBufferEscapeString(buf, "<fields access='%s'>\n", "readwrite");

        virBufferAdjustIndent(buf, 2);
        virNodeDeviceCapVPDFormatRegularField(buf, "asset_tag", res->rw->asset_tag);
        g_ptr_array_foreach(res->rw->vendor_specific,
                            (GFunc)virNodeDeviceCapVPDFormatCustomVendorField, buf);
        g_ptr_array_foreach(res->rw->system_specific,
                            (GFunc)virNodeDeviceCapVPDFormatCustomSystemField, buf);
        virBufferAdjustIndent(buf, -2);

        virBufferAddLit(buf, "</fields>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</capability>\n");
}

static void
virNodeDeviceCapPCIDefFormat(virBuffer *buf,
                             const virNodeDevCapData *data)
{
    size_t i;

    if (data->pci_dev.klass >= 0)
        virBufferAsprintf(buf, "<class>0x%.6x</class>\n", data->pci_dev.klass);
    virBufferAsprintf(buf, "<domain>%d</domain>\n",
                      data->pci_dev.domain);
    virBufferAsprintf(buf, "<bus>%u</bus>\n", data->pci_dev.bus);
    virBufferAsprintf(buf, "<slot>%u</slot>\n",
                      data->pci_dev.slot);
    virBufferAsprintf(buf, "<function>%u</function>\n",
                      data->pci_dev.function);
    virBufferAsprintf(buf, "<product id='0x%04x'",
                      data->pci_dev.product);
    if (data->pci_dev.product_name)
        virBufferEscapeString(buf, ">%s</product>\n",
                              data->pci_dev.product_name);
    else
        virBufferAddLit(buf, "/>\n");
    virBufferAsprintf(buf, "<vendor id='0x%04x'",
                      data->pci_dev.vendor);
    if (data->pci_dev.vendor_name)
        virBufferEscapeString(buf, ">%s</vendor>\n",
                              data->pci_dev.vendor_name);
    else
        virBufferAddLit(buf, "/>\n");
    if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION) {
        virBufferAddLit(buf, "<capability type='phys_function'>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf,
                          "<address domain='0x%04x' bus='0x%02x' "
                          "slot='0x%02x' function='0x%d'/>\n",
                          data->pci_dev.physical_function->domain,
                          data->pci_dev.physical_function->bus,
                          data->pci_dev.physical_function->slot,
                          data->pci_dev.physical_function->function);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</capability>\n");
    }
    if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION) {
        virBufferAddLit(buf, "<capability type='virt_functions'");
        if (data->pci_dev.max_virtual_functions)
            virBufferAsprintf(buf, " maxCount='%u'",
                              data->pci_dev.max_virtual_functions);
        if (data->pci_dev.num_virtual_functions == 0) {
            virBufferAddLit(buf, "/>\n");
        } else {
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            for (i = 0; i < data->pci_dev.num_virtual_functions; i++) {
                virBufferAsprintf(buf,
                                  "<address domain='0x%04x' bus='0x%02x' "
                                  "slot='0x%02x' function='0x%d'/>\n",
                                  data->pci_dev.virtual_functions[i]->domain,
                                  data->pci_dev.virtual_functions[i]->bus,
                                  data->pci_dev.virtual_functions[i]->slot,
                                  data->pci_dev.virtual_functions[i]->function);
            }
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</capability>\n");
        }
    }
    if (data->pci_dev.hdrType) {
        virBufferAsprintf(buf, "<capability type='%s'/>\n",
                          virPCIHeaderTypeToString(data->pci_dev.hdrType));
    }
    if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_MDEV) {
        virNodeDeviceCapMdevTypesFormat(buf,
                                        data->pci_dev.mdev_types,
                                        data->pci_dev.nmdev_types);
    }
    if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCI_VPD) {
        virNodeDeviceCapVPDFormat(buf, data->pci_dev.vpd);
    }
    if (data->pci_dev.nIommuGroupDevices) {
        virBufferAsprintf(buf, "<iommuGroup number='%d'>\n",
                          data->pci_dev.iommuGroupNumber);
        virBufferAdjustIndent(buf, 2);
        for (i = 0; i < data->pci_dev.nIommuGroupDevices; i++) {
            virBufferAsprintf(buf,
                              "<address domain='0x%04x' bus='0x%02x' "
                              "slot='0x%02x' function='0x%d'/>\n",
                              data->pci_dev.iommuGroupDevices[i]->domain,
                              data->pci_dev.iommuGroupDevices[i]->bus,
                              data->pci_dev.iommuGroupDevices[i]->slot,
                              data->pci_dev.iommuGroupDevices[i]->function);
        }
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</iommuGroup>\n");
    }
    if (data->pci_dev.numa_node >= 0)
        virBufferAsprintf(buf, "<numa node='%d'/>\n",
                          data->pci_dev.numa_node);

    if (data->pci_dev.flags & VIR_NODE_DEV_CAP_FLAG_PCIE)
        virPCIEDeviceInfoFormat(buf, data->pci_dev.pci_express);
}


static void
virNodeDeviceCapUSBDevDefFormat(virBuffer *buf,
                                const virNodeDevCapData *data)
{
    virBufferAsprintf(buf, "<bus>%d</bus>\n", data->usb_dev.bus);
    virBufferAsprintf(buf, "<device>%d</device>\n",
                      data->usb_dev.device);
    virBufferAsprintf(buf, "<product id='0x%04x'",
                      data->usb_dev.product);
    if (data->usb_dev.product_name)
        virBufferEscapeString(buf, ">%s</product>\n",
                              data->usb_dev.product_name);
    else
        virBufferAddLit(buf, " />\n");
    virBufferAsprintf(buf, "<vendor id='0x%04x'",
                      data->usb_dev.vendor);
    if (data->usb_dev.vendor_name)
        virBufferEscapeString(buf, ">%s</vendor>\n",
                              data->usb_dev.vendor_name);
    else
        virBufferAddLit(buf, " />\n");
}


static void
virNodeDeviceCapUSBInterfaceDefFormat(virBuffer *buf,
                                      const virNodeDevCapData *data)
{
    virBufferAsprintf(buf, "<number>%d</number>\n",
                      data->usb_if.number);
    virBufferAsprintf(buf, "<class>%d</class>\n",
                      data->usb_if.klass);
    virBufferAsprintf(buf, "<subclass>%d</subclass>\n",
                      data->usb_if.subclass);
    virBufferAsprintf(buf, "<protocol>%d</protocol>\n",
                      data->usb_if.protocol);
    if (data->usb_if.description)
        virBufferEscapeString(buf,
                              "<description>%s</description>\n",
                              data->usb_if.description);
}


static void
virNodeDeviceCapNetDefFormat(virBuffer *buf,
                             const virNodeDevCapData *data)
{
    size_t i;

    virBufferEscapeString(buf, "<interface>%s</interface>\n",
                          data->net.ifname);
    if (data->net.address)
        virBufferEscapeString(buf, "<address>%s</address>\n",
                              data->net.address);
    virInterfaceLinkFormat(buf, &data->net.lnk);
    if (data->net.features) {
        for (i = 0; i < VIR_NET_DEV_FEAT_LAST; i++) {
            if (virBitmapIsBitSet(data->net.features, i)) {
                virBufferAsprintf(buf, "<feature name='%s'/>\n",
                                  virNetDevFeatureTypeToString(i));
            }
        }
    }
    if (data->net.subtype != VIR_NODE_DEV_CAP_NET_LAST) {
        const char *subtyp =
            virNodeDevNetCapTypeToString(data->net.subtype);
        virBufferEscapeString(buf, "<capability type='%s'/>\n",
                              subtyp);
    }
}


static void
virNodeDeviceCapSCSIHostDefFormat(virBuffer *buf,
                                  const virNodeDevCapData *data)
{
    virBufferAsprintf(buf, "<host>%d</host>\n",
                      data->scsi_host.host);
    if (data->scsi_host.unique_id != -1)
        virBufferAsprintf(buf, "<unique_id>%d</unique_id>\n",
                          data->scsi_host.unique_id);
    if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
        virBufferAddLit(buf, "<capability type='fc_host'>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferEscapeString(buf, "<wwnn>%s</wwnn>\n",
                              data->scsi_host.wwnn);
        virBufferEscapeString(buf, "<wwpn>%s</wwpn>\n",
                              data->scsi_host.wwpn);
        virBufferEscapeString(buf, "<fabric_wwn>%s</fabric_wwn>\n",
                              data->scsi_host.fabric_wwn);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</capability>\n");
    }
    if (data->scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS) {
        virBufferAddLit(buf, "<capability type='vport_ops'>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<max_vports>%d</max_vports>\n",
                          data->scsi_host.max_vports);
        virBufferAsprintf(buf, "<vports>%d</vports>\n",
                          data->scsi_host.vports);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</capability>\n");
    }
}


static void
virNodeDeviceCapSCSIDefFormat(virBuffer *buf,
                              const virNodeDevCapData *data)
{
    virBufferAsprintf(buf, "<host>%d</host>\n", data->scsi.host);
    virBufferAsprintf(buf, "<bus>%d</bus>\n", data->scsi.bus);
    virBufferAsprintf(buf, "<target>%d</target>\n",
                      data->scsi.target);
    virBufferAsprintf(buf, "<lun>%d</lun>\n", data->scsi.lun);
    if (data->scsi.type)
        virBufferEscapeString(buf, "<type>%s</type>\n",
                              data->scsi.type);
}


static void
virNodeDeviceCapStorageDefFormat(virBuffer *buf,
                                 const virNodeDevCapData *data)
{
    virBufferEscapeString(buf, "<block>%s</block>\n",
                          data->storage.block);
    if (data->storage.bus)
        virBufferEscapeString(buf, "<bus>%s</bus>\n",
                              data->storage.bus);
    if (data->storage.drive_type)
        virBufferEscapeString(buf, "<drive_type>%s</drive_type>\n",
                              data->storage.drive_type);
    if (data->storage.model)
        virBufferEscapeString(buf, "<model>%s</model>\n",
                              data->storage.model);
    if (data->storage.vendor)
        virBufferEscapeString(buf, "<vendor>%s</vendor>\n",
                              data->storage.vendor);
    if (data->storage.serial)
        virBufferEscapeString(buf, "<serial>%s</serial>\n",
                              data->storage.serial);
    if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE) {
        int avl = data->storage.flags &
            VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;
        virBufferAddLit(buf, "<capability type='removable'>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<media_available>%d"
                          "</media_available>\n", avl ? 1 : 0);
        virBufferAsprintf(buf, "<media_size>%llu</media_size>\n",
                          data->storage.removable_media_size);
        if (data->storage.media_label)
            virBufferEscapeString(buf,
                                  "<media_label>%s</media_label>\n",
                                  data->storage.media_label);
        if (data->storage.logical_block_size > 0)
            virBufferAsprintf(buf, "<logical_block_size>%llu"
                              "</logical_block_size>\n",
                              data->storage.logical_block_size);
        if (data->storage.num_blocks > 0)
            virBufferAsprintf(buf,
                              "<num_blocks>%llu</num_blocks>\n",
                              data->storage.num_blocks);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</capability>\n");
    } else {
        virBufferAsprintf(buf, "<size>%llu</size>\n",
                          data->storage.size);
        if (data->storage.logical_block_size > 0)
            virBufferAsprintf(buf, "<logical_block_size>%llu"
                              "</logical_block_size>\n",
                              data->storage.logical_block_size);
        if (data->storage.num_blocks > 0)
            virBufferAsprintf(buf, "<num_blocks>%llu</num_blocks>\n",
                              data->storage.num_blocks);
    }
    if (data->storage.flags & VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE)
        virBufferAddLit(buf, "<capability type='hotpluggable'/>\n");
}

static void
virNodeDeviceCapMdevDefFormat(virBuffer *buf,
                              const virNodeDevCapData *data)
{
    size_t i;

    virBufferEscapeString(buf, "<type id='%s'/>\n", data->mdev.type);
    virBufferEscapeString(buf, "<uuid>%s</uuid>\n", data->mdev.uuid);
    virBufferEscapeString(buf, "<parent_addr>%s</parent_addr>\n",
                          data->mdev.parent_addr);
    virBufferAsprintf(buf, "<iommuGroup number='%u'/>\n",
                      data->mdev.iommuGroupNumber);

    for (i = 0; i < data->mdev.nattributes; i++) {
        virMediatedDeviceAttr *attr = data->mdev.attributes[i];
        virBufferAsprintf(buf, "<attr name='%s' value='%s'/>\n",
                          attr->name, attr->value);
    }
}

static void
virNodeDeviceCapVDPADefFormat(virBuffer *buf,
                              const virNodeDevCapData *data)
{
    virBufferEscapeString(buf, "<chardev>%s</chardev>\n", data->vdpa.chardev);
}


static void
virNodeDeviceCapCCWDefFormat(virBuffer *buf,
                             const virNodeDevCapData *data)
{
    virBufferAsprintf(buf, "<cssid>0x%x</cssid>\n",
                      data->ccw_dev.cssid);
    virBufferAsprintf(buf, "<ssid>0x%x</ssid>\n",
                      data->ccw_dev.ssid);
    virBufferAsprintf(buf, "<devno>0x%04x</devno>\n",
                      data->ccw_dev.devno);
}


static void
virNodeDeviceCapCSSDefFormat(virBuffer *buf,
                             const virNodeDevCapData *data)
{
    virNodeDevCapCCW ccw_dev = data->ccw_dev;

    virNodeDeviceCapCCWDefFormat(buf, data);

    if (ccw_dev.channel_dev_addr) {
        virCCWDeviceAddress *ccw = ccw_dev.channel_dev_addr;
        virBufferAddLit(buf, "<channel_dev_addr>\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<cssid>0x%x</cssid>\n", ccw->cssid);
        virBufferAsprintf(buf, "<ssid>0x%x</ssid>\n", ccw->ssid);
        virBufferAsprintf(buf, "<devno>0x%04x</devno>\n", ccw->devno);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</channel_dev_addr>\n");
    }

    if (ccw_dev.flags & VIR_NODE_DEV_CAP_FLAG_CSS_MDEV)
        virNodeDeviceCapMdevTypesFormat(buf,
                                        ccw_dev.mdev_types,
                                        ccw_dev.nmdev_types);
}


char *
virNodeDeviceDefFormat(const virNodeDeviceDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virNodeDevCapsDef *caps;
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
        virNodeDevCapData *data = &caps->data;

        virBufferAsprintf(&buf, "<capability type='%s'>\n",
                          virNodeDevCapTypeToString(caps->data.type));
        virBufferAdjustIndent(&buf, 2);
        switch (caps->data.type) {
        case VIR_NODE_DEV_CAP_SYSTEM:
            virNodeDeviceCapSystemDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
            virNodeDeviceCapPCIDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_USB_DEV:
            virNodeDeviceCapUSBDevDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
            virNodeDeviceCapUSBInterfaceDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_NET:
            virNodeDeviceCapNetDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            virNodeDeviceCapSCSIHostDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            virBufferEscapeString(&buf, "<target>%s</target>\n",
                                  data->scsi_target.name);
            if (data->scsi_target.flags & VIR_NODE_DEV_CAP_FLAG_FC_RPORT) {
                virBufferAddLit(&buf, "<capability type='fc_remote_port'>\n");
                virBufferAdjustIndent(&buf, 2);
                virBufferAsprintf(&buf, "<rport>%s</rport>\n",
                                  data->scsi_target.rport);
                virBufferAsprintf(&buf, "<wwpn>%s</wwpn>\n",
                                  data->scsi_target.wwpn);
                virBufferAdjustIndent(&buf, -2);
                virBufferAddLit(&buf, "</capability>\n");
            }
            break;
        case VIR_NODE_DEV_CAP_SCSI:
            virNodeDeviceCapSCSIDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_STORAGE:
            virNodeDeviceCapStorageDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
            virBufferEscapeString(&buf, "<char>%s</char>\n",
                                  data->sg.path);
            break;
        case VIR_NODE_DEV_CAP_DRM:
            virBufferEscapeString(&buf, "<type>%s</type>\n", virNodeDevDRMTypeToString(data->drm.type));
            break;
        case VIR_NODE_DEV_CAP_MDEV:
            virNodeDeviceCapMdevDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_CCW_DEV:
            virNodeDeviceCapCCWDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_CSS_DEV:
            virNodeDeviceCapCSSDefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_VDPA:
            virNodeDeviceCapVDPADefFormat(&buf, data);
            break;
        case VIR_NODE_DEV_CAP_AP_CARD:
            virBufferAsprintf(&buf, "<ap-adapter>0x%02x</ap-adapter>\n",
                              data->ap_card.ap_adapter);
            break;
        case VIR_NODE_DEV_CAP_AP_QUEUE:
            virBufferAsprintf(&buf, "<ap-adapter>0x%02x</ap-adapter>\n",
                              data->ap_queue.ap_adapter);
            virBufferAsprintf(&buf, "<ap-domain>0x%04x</ap-domain>\n",
                              data->ap_queue.ap_domain);
            break;
        case VIR_NODE_DEV_CAP_AP_MATRIX:
            if (data->ap_matrix.flags & VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV)
                virNodeDeviceCapMdevTypesFormat(&buf,
                                                data->ap_matrix.mdev_types,
                                                data->ap_matrix.nmdev_types);
            break;
        case VIR_NODE_DEV_CAP_MDEV_TYPES:
            virNodeDeviceCapMdevTypesFormat(&buf,
                                            data->mdev_parent.mdev_types,
                                            data->mdev_parent.nmdev_types);
            break;
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_VPD:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }

        virBufferAdjustIndent(&buf, -2);
        virBufferAddLit(&buf, "</capability>\n");
    }

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</device>\n");

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
                                  virNodeDeviceDef *def,
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
virNodeDevCapsDefParseUInt(const char *xpath,
                           xmlXPathContextPtr ctxt,
                           unsigned int *value,
                           virNodeDeviceDef *def,
                           const char *missing_error_fmt,
                           const char *invalid_error_fmt)
{
    int ret;

    ret = virXPathUInt(xpath, ctxt, value);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       ret == -1 ? missing_error_fmt : invalid_error_fmt,
                       def->name);
        return -1;
    }

    return 0;
}


static int
virNodeDevCapsDefParseULongLong(const char *xpath,
                                xmlXPathContextPtr ctxt,
                                unsigned long long *value,
                                virNodeDeviceDef *def,
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
                         virNodeDeviceDef *def,
                         xmlNodePtr node,
                         virNodeDevCapDRM *drm)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int val;
    g_autofree char *type = NULL;

    ctxt->node = node;

    type = virXPathString("string(./type[1])", ctxt);

    if ((val = virNodeDevDRMTypeFromString(type)) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown drm type '%1$s' for '%2$s'"), type, def->name);
        return -1;
    }
    drm->type = val;

    return 0;
}


static int
virNodeDevCapMdevTypesParseXML(xmlXPathContextPtr ctxt,
                               virMediatedDeviceType ***mdev_types,
                               size_t *nmdev_types)
{
    int ret = -1;
    xmlNodePtr orignode = NULL;
    g_autofree xmlNodePtr *nodes = NULL;
    int ntypes = -1;
    virMediatedDeviceType *type = NULL;
    size_t i;

    if ((ntypes = virXPathNodeSet("./type", ctxt, &nodes)) < 0)
        goto cleanup;

    if (nmdev_types == 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing <type> element in <capability> element"));
        goto cleanup;
    }

    orignode = ctxt->node;
    for (i = 0; i < ntypes; i++) {
        ctxt->node = nodes[i];

        type = g_new0(virMediatedDeviceType, 1);

        if (!(type->id = virXPathString("string(./@id[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing 'id' attribute for mediated device's <type> element"));
            goto cleanup;
        }

        if (!(type->device_api = virXPathString("string(./deviceAPI[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing device API for mediated device type '%1$s'"),
                           type->id);
            goto cleanup;
        }

        if (virXPathUInt("string(./availableInstances)", ctxt,
                         &type->available_instances) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing number of available instances for mediated device type '%1$s'"),
                           type->id);
            goto cleanup;
        }

        type->name = virXPathString("string(./name)", ctxt);

        VIR_APPEND_ELEMENT(*mdev_types, *nmdev_types, type);
    }

    ret = 0;
 cleanup:
    virMediatedDeviceTypeFree(type);
    ctxt->node = orignode;
    return ret;
}

static int
virNodeDeviceCapVPDParseCustomFields(xmlXPathContextPtr ctxt, virPCIVPDResource *res, bool readOnly)
{
    int nfields = -1;
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i = 0;

    if ((nfields = virXPathNodeSet("./vendor_field[@index]", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                _("failed to evaluate <vendor_field> elements"));
        return -1;
    }
    for (i = 0; i < nfields; i++) {
        g_autofree char *value = NULL;
        g_autofree char *index = NULL;
        VIR_XPATH_NODE_AUTORESTORE(ctxt)
        g_autofree char *keyword = NULL;

        ctxt->node = nodes[i];
        if (!(index = virXPathString("string(./@index[1])", ctxt)) ||
            strlen(index) > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                    _("<vendor_field> evaluation has failed"));
            continue;
        }
        if (!(value = virXPathString("string(./text())", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                    _("<vendor_field> value evaluation has failed"));
            continue;
        }
        keyword = g_strdup_printf("V%c", index[0]);
        virPCIVPDResourceUpdateKeyword(res, readOnly, keyword, value);
    }
    VIR_FREE(nodes);

    if (!readOnly) {
        if ((nfields = virXPathNodeSet("./system_field[@index]", ctxt, &nodes)) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                    _("failed to evaluate <system_field> elements"));
            return -1;
        }
        for (i = 0; i < nfields; i++) {
            g_autofree char *value = NULL;
            g_autofree char *index = NULL;
            g_autofree char *keyword = NULL;
            VIR_XPATH_NODE_AUTORESTORE(ctxt);

            ctxt->node = nodes[i];
            if (!(index = virXPathString("string(./@index[1])", ctxt)) ||
                strlen(index) > 1) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                        _("<system_field> evaluation has failed"));
                continue;
            }
            if (!(value = virXPathString("string(./text())", ctxt))) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                        _("<system_field> value evaluation has failed"));
                continue;
            }
            keyword = g_strdup_printf("Y%c", index[0]);
            virPCIVPDResourceUpdateKeyword(res, readOnly, keyword, value);
        }
    }

    return 0;
}

static int
virNodeDeviceCapVPDParseReadOnlyFields(xmlXPathContextPtr ctxt, virPCIVPDResource *res)
{
    const char *keywords[] = {"change_level", "manufacture_id",
                              "serial_number", "part_number", NULL};
    size_t i = 0;

    if (res == NULL)
        return -1;

    res->ro = virPCIVPDResourceRONew();

    while (keywords[i]) {
        g_autofree char *expression = g_strdup_printf("string(./%s)", keywords[i]);
        g_autofree char *result = virXPathString(expression, ctxt);

        virPCIVPDResourceUpdateKeyword(res, true, keywords[i], result);
        ++i;
    }
    if (virNodeDeviceCapVPDParseCustomFields(ctxt, res, true) < 0)
        return -1;

    return 0;
}

static int
virNodeDeviceCapVPDParseReadWriteFields(xmlXPathContextPtr ctxt, virPCIVPDResource *res)
{
    g_autofree char *assetTag = virXPathString("string(./asset_tag)", ctxt);
    res->rw = virPCIVPDResourceRWNew();
    virPCIVPDResourceUpdateKeyword(res, false, "asset_tag", assetTag);
    if (virNodeDeviceCapVPDParseCustomFields(ctxt, res, false) < 0)
        return -1;

    return 0;
}

static int
virNodeDeviceCapVPDParseXML(xmlXPathContextPtr ctxt, virPCIVPDResource **res)
{
    g_autofree xmlNodePtr *nodes = NULL;
    int nfields = -1;
    size_t i = 0;
    g_autoptr(virPCIVPDResource) newres = g_new0(virPCIVPDResource, 1);

    if (res == NULL)
        return -1;

    if (!(newres->name = virXPathString("string(./name)", ctxt))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                _("Could not read a device name from the <name> element"));
        return -1;
    }

    if ((nfields = virXPathNodeSet("./fields[@access]", ctxt, &nodes)) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                _("no VPD <fields> elements with an access type attribute found"));
        return -1;
    }

    for (i = 0; i < nfields; i++) {
        g_autofree char *access = NULL;
        VIR_XPATH_NODE_AUTORESTORE(ctxt);

        ctxt->node = nodes[i];
        if (!(access = virXPathString("string(./@access[1])", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                    _("VPD fields access type parsing has failed"));
            return -1;
        }

        if (STREQ(access, "readonly")) {
            if (virNodeDeviceCapVPDParseReadOnlyFields(ctxt, newres) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                        _("Could not parse %1$s VPD resource fields"), access);
                return -1;
            }
        } else if (STREQ(access, "readwrite")) {
            if (virNodeDeviceCapVPDParseReadWriteFields(ctxt, newres) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                        _("Could not parse %1$s VPD resource fields"), access);
                return -1;
            }
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Unsupported VPD field access type specified %1$s"),
                           access);
            return -1;
        }
    }

    /* Replace the existing VPD representation if there is one already. */
    if (*res != NULL)
        virPCIVPDResourceFree(*res);

    *res = g_steal_pointer(&newres);
    return 0;
}

static int
virNodeDevAPMatrixCapabilityParseXML(xmlXPathContextPtr ctxt,
                                     xmlNodePtr node,
                                     virNodeDevCapAPMatrix *apm_dev)
{
    g_autofree char *type = virXMLPropString(node, "type");
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("Missing capability type"));
        return -1;
    }

    if (STREQ(type, "mdev_types")) {
        if (virNodeDevCapMdevTypesParseXML(ctxt,
                                           &apm_dev->mdev_types,
                                           &apm_dev->nmdev_types) < 0)
            return -1;
        apm_dev->flags |= VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV;
    }

    return 0;
}


static int
virNodeDevCCWDeviceAddressParseXML(xmlXPathContextPtr ctxt,
                                   xmlNodePtr node,
                                   const char *dev_name,
                                   virCCWDeviceAddress *ccw_addr)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *cssid = NULL;
    g_autofree char *ssid = NULL;
    g_autofree char *devno = NULL;

    ctxt->node = node;

    if (!(cssid = virXPathString("string(./cssid[1])", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing cssid value for '%1$s'"), dev_name);
        return -1;
    }
    if (virStrToLong_uip(cssid, NULL, 0, &ccw_addr->cssid) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid cssid value '%1$s' for '%2$s'"),
                       cssid, dev_name);
        return -1;
    }

    if (!(ssid = virXPathString("string(./ssid[1])", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing ssid value for '%1$s'"), dev_name);
        return -1;
    }
    if (virStrToLong_uip(ssid, NULL, 0, &ccw_addr->ssid) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid ssid value '%1$s' for '%2$s'"),
                       ssid, dev_name);
        return -1;
    }

    if (!(devno = virXPathString("string(./devno[1])", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing devno value for '%1$s'"), dev_name);
        return -1;
    }
    if (virStrToLong_uip(devno, NULL, 16, &ccw_addr->devno) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid devno value '%1$s' for '%2$s'"),
                       devno, dev_name);
        return -1;
    }

    return 0;
}


static int
virNodeDevCapCCWParseXML(xmlXPathContextPtr ctxt,
                         virNodeDeviceDef *def,
                         xmlNodePtr node,
                         virNodeDevCapCCW *ccw_dev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree virCCWDeviceAddress *ccw_addr = NULL;

    ctxt->node = node;

    ccw_addr = g_new0(virCCWDeviceAddress, 1);

    if (virNodeDevCCWDeviceAddressParseXML(ctxt, node, def->name, ccw_addr) < 0)
        return -1;

    ccw_dev->cssid = ccw_addr->cssid;
    ccw_dev->ssid = ccw_addr->ssid;
    ccw_dev->devno = ccw_addr->devno;

    return 0;
}


static int
virNodeDevCSSCapabilityParseXML(xmlXPathContextPtr ctxt,
                                xmlNodePtr node,
                                virNodeDevCapCCW *ccw_dev)
{
    g_autofree char *type = virXMLPropString(node, "type");
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("Missing capability type"));
        return -1;
    }

    if (STREQ(type, "mdev_types")) {
        if (virNodeDevCapMdevTypesParseXML(ctxt,
                                           &ccw_dev->mdev_types,
                                           &ccw_dev->nmdev_types) < 0)
            return -1;
        ccw_dev->flags |= VIR_NODE_DEV_CAP_FLAG_CSS_MDEV;
    }

    return 0;
}


static int
virNodeDevCapCSSParseXML(xmlXPathContextPtr ctxt,
                         virNodeDeviceDef *def,
                         xmlNodePtr node,
                         virNodeDevCapCCW *ccw_dev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    int n = 0;
    size_t i = 0;
    xmlNodePtr channel_ddno = NULL;

    ctxt->node = node;

    if (virNodeDevCapCCWParseXML(ctxt, def, node, ccw_dev) < 0)
        return -1;

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        if (virNodeDevCSSCapabilityParseXML(ctxt, nodes[i], ccw_dev) < 0)
            return -1;
    }

    /* channel_dev_addr is optional */
    if ((channel_ddno = virXPathNode("./channel_dev_addr[1]", ctxt))) {
        g_autofree virCCWDeviceAddress *channel_dev = NULL;

        channel_dev = g_new0(virCCWDeviceAddress, 1);

        if (virNodeDevCCWDeviceAddressParseXML(ctxt,
                                               channel_ddno,
                                               def->name,
                                               channel_dev) < 0)
            return -1;

        ccw_dev->channel_dev_addr = g_steal_pointer(&channel_dev);
    }

    return 0;
}


static int
virNodeDevCapAPAdapterParseXML(xmlXPathContextPtr ctxt,
                               virNodeDeviceDef *def,
                               unsigned int *ap_adapter)
{
    g_autofree char *adapter = NULL;

    if (!(adapter = virXPathString("string(./ap-adapter[1])", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing ap-adapter value for '%1$s'"), def->name);
        return -1;
    }

    if (virStrToLong_uip(adapter, NULL, 0, ap_adapter) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid ap-adapter value '%1$s' for '%2$s'"),
                       adapter, def->name);
        return -1;
    }

    return 0;
}


static int
virNodeDevCapAPCardParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDef *def,
                            xmlNodePtr node,
                            virNodeDevCapAPCard *ap_card)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    ctxt->node = node;

    return virNodeDevCapAPAdapterParseXML(ctxt, def, &ap_card->ap_adapter);
}


static int
virNodeDevCapAPQueueParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDef *def,
                            xmlNodePtr node,
                            virNodeDevCapAPQueue *ap_queue)
{
    int ret = -1;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *dom = NULL;

    ctxt->node = node;

    ret = virNodeDevCapAPAdapterParseXML(ctxt, def, &ap_queue->ap_adapter);

    if (ret < 0)
        return ret;

    if (!(dom = virXPathString("string(./ap-domain[1])", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing ap-domain value for '%1$s'"), def->name);
        return -1;
    }

    if (virStrToLong_uip(dom, NULL, 0, &ap_queue->ap_domain) < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("invalid ap-domain value '%1$s' for '%2$s'"),
                       dom, def->name);
        return -1;
    }

    if (ap_queue->ap_domain > 255) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("ap-domain value '%1$s' is out of range for '%2$s'"),
                       dom, def->name);
        return -1;
    }

    return 0;
}


static int
virNodeDevCapAPMatrixParseXML(xmlXPathContextPtr ctxt,
                              virNodeDeviceDef *def G_GNUC_UNUSED,
                              xmlNodePtr node,
                              virNodeDevCapAPMatrix *ap_matrix)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    int n = 0;
    size_t i = 0;

    ctxt->node = node;

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        if (virNodeDevAPMatrixCapabilityParseXML(ctxt, nodes[i], ap_matrix) < 0)
            return -1;
    }

    return 0;
}


static int
virNodeDevCapStorageParseXML(xmlXPathContextPtr ctxt,
                             virNodeDeviceDef *def,
                             xmlNodePtr node,
                             virNodeDevCapStorage *storage)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    size_t i;
    int n;
    unsigned long long val;

    ctxt->node = node;

    storage->block = virXPathString("string(./block[1])", ctxt);
    if (!storage->block) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no block device path supplied for '%1$s'"),
                       def->name);
        return -1;
    }

    storage->bus        = virXPathString("string(./bus[1])", ctxt);
    storage->drive_type = virXPathString("string(./drive_type[1])", ctxt);
    storage->model      = virXPathString("string(./model[1])", ctxt);
    storage->vendor     = virXPathString("string(./vendor[1])", ctxt);
    storage->serial     = virXPathString("string(./serial[1])", ctxt);

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        g_autofree char *type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing storage capability type for '%1$s'"),
                           def->name);
            return -1;
        }

        if (STREQ(type, "hotpluggable")) {
            storage->flags |= VIR_NODE_DEV_CAP_STORAGE_HOTPLUGGABLE;
        } else if (STREQ(type, "removable")) {
            xmlNodePtr orignode2;

            storage->flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE;

            orignode2 = ctxt->node;
            ctxt->node = nodes[i];

            if (virXPathBoolean("count(./media_available[. = '1']) > 0", ctxt))
                storage->flags |= VIR_NODE_DEV_CAP_STORAGE_REMOVABLE_MEDIA_AVAILABLE;

            storage->media_label = virXPathString("string(./media_label[1])", ctxt);

            val = 0;
            if (virNodeDevCapsDefParseULongLong("string(./media_size[1])", ctxt, &val, def,
                                                _("no removable media size supplied for '%1$s'"),
                                                _("invalid removable media size supplied for '%1$s'")) < 0) {
                return -1;
            }
            storage->removable_media_size = val;

            ctxt->node = orignode2;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown storage capability type '%1$s' for '%2$s'"),
                           type, def->name);
            return -1;
        }
    }

    if (!(storage->flags & VIR_NODE_DEV_CAP_STORAGE_REMOVABLE)) {
        val = 0;
        if (virNodeDevCapsDefParseULongLong("string(./size[1])", ctxt, &val, def,
                                            _("no size supplied for '%1$s'"),
                                            _("invalid size supplied for '%1$s'")) < 0)
            return -1;
        storage->size = val;
    }

    return 0;
}


static int
virNodeDevCapSCSIParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDef *def,
                          xmlNodePtr node,
                          virNodeDevCapSCSI *scsi)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virNodeDevCapsDefParseUInt("string(./host[1])", ctxt,
                                   &scsi->host, def,
                                   _("no SCSI host ID supplied for '%1$s'"),
                                   _("invalid SCSI host ID supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./bus[1])", ctxt,
                                   &scsi->bus, def,
                                   _("no SCSI bus ID supplied for '%1$s'"),
                                   _("invalid SCSI bus ID supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./target[1])", ctxt,
                                   &scsi->target, def,
                                   _("no SCSI target ID supplied for '%1$s'"),
                                   _("invalid SCSI target ID supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./lun[1])", ctxt,
                                   &scsi->lun, def,
                                   _("no SCSI LUN ID supplied for '%1$s'"),
                                   _("invalid SCSI LUN ID supplied for '%1$s'")) < 0)
        return -1;

    scsi->type = virXPathString("string(./type[1])", ctxt);

    return 0;
}


static int
virNodeDevCapSCSITargetParseXML(xmlXPathContextPtr ctxt,
                                virNodeDeviceDef *def,
                                xmlNodePtr node,
                                virNodeDevCapSCSITarget *scsi_target)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    int n = 0;
    size_t i;

    ctxt->node = node;

    scsi_target->name = virXPathString("string(./target[1])", ctxt);
    if (!scsi_target->name) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no target name supplied for '%1$s'"),
                       def->name);
        return -1;
    }

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; ++i) {
        g_autofree char *type = NULL;
        type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing type for SCSI target capability for '%1$s'"),
                           def->name);
            return -1;
        }

        if (STREQ(type, "fc_remote_port")) {
            scsi_target->flags |= VIR_NODE_DEV_CAP_FLAG_FC_RPORT;

            ctxt->node = nodes[i];

            if (virNodeDevCapsDefParseString("string(./rport[1])",
                                             ctxt,
                                             &scsi_target->rport) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("missing rport name for '%1$s'"), def->name);
                return -1;
            }

            if (virNodeDevCapsDefParseString("string(./wwpn[1])",
                                             ctxt, &scsi_target->wwpn) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("missing wwpn identifier for '%1$s'"),
                               def->name);
                return -1;
            }
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown SCSI target capability type '%1$s' for '%2$s'"),
                           type, def->name);
            return -1;
        }
    }

    return 0;
}


static int
virNodeDevCapSCSIHostParseXML(xmlXPathContextPtr ctxt,
                              virNodeDeviceDef *def,
                              xmlNodePtr node,
                              virNodeDevCapSCSIHost *scsi_host,
                              int create,
                              const char *virt_type)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *nodes = NULL;
    int n = 0;
    size_t i;

    ctxt->node = node;

    if (create == EXISTING_DEVICE) {
        if (virNodeDevCapsDefParseUInt("string(./host[1])", ctxt,
                                       &scsi_host->host, def,
                                       _("no SCSI host ID supplied for '%1$s'"),
                                       _("invalid SCSI host ID supplied for '%1$s'")) < 0) {
            return -1;
        }
        /* Optional unique_id value */
        scsi_host->unique_id = -1;
        if (virNodeDevCapsDefParseIntOptional("string(./unique_id[1])", ctxt,
                                              &scsi_host->unique_id, def,
                                              _("invalid unique_id supplied for '%1$s'")) < 0) {
            return -1;
        }
    }

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        g_autofree char *type = NULL;
        type = virXMLPropString(nodes[i], "type");

        if (!type) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing SCSI host capability type for '%1$s'"),
                           def->name);
            return -1;
        }

        if (STREQ(type, "vport_ops")) {

            scsi_host->flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;

        } else if (STREQ(type, "fc_host")) {
            scsi_host->flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

            ctxt->node = nodes[i];

            if (virNodeDevCapsDefParseString("string(./wwnn[1])",
                                             ctxt,
                                             &scsi_host->wwnn) < 0) {
                if (virRandomGenerateWWN(&scsi_host->wwnn, virt_type) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("no WWNN supplied for '%1$s', and auto-generation failed"),
                                   def->name);
                    return -1;
                }
            }

            if (virNodeDevCapsDefParseString("string(./wwpn[1])",
                                             ctxt,
                                             &scsi_host->wwpn) < 0) {
                if (virRandomGenerateWWN(&scsi_host->wwpn, virt_type) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("no WWPN supplied for '%1$s', and auto-generation failed"),
                                   def->name);
                    return -1;
                }
            }

            if (virNodeDevCapsDefParseString("string(./fabric_wwn[1])",
                                             ctxt,
                                             &scsi_host->fabric_wwn) < 0)
                VIR_DEBUG("No fabric_wwn defined for '%s'", def->name);

        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unknown SCSI host capability type '%1$s' for '%2$s'"),
                           type, def->name);
            return -1;
        }
    }

    return 0;
}


static int
virNodeDevCapNetParseXML(xmlXPathContextPtr ctxt,
                         virNodeDeviceDef *def,
                         xmlNodePtr node,
                         virNodeDevCapNet *net)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr lnk;
    size_t i = -1;
    int n = -1;
    g_autofree char *type = NULL;
    g_autofree xmlNodePtr *nodes = NULL;

    ctxt->node = node;

    net->ifname = virXPathString("string(./interface[1])", ctxt);
    if (!net->ifname) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no network interface supplied for '%1$s'"),
                       def->name);
        return -1;
    }

    net->address = virXPathString("string(./address[1])", ctxt);

    if ((n = virXPathNodeSet("./feature", ctxt, &nodes)) < 0)
        return -1;

    if (n > 0)
        net->features = virBitmapNew(VIR_NET_DEV_FEAT_LAST);

    for (i = 0; i < n; i++) {
        g_autofree char *tmp = NULL;
        int val;
        if (!(tmp = virXMLPropString(nodes[i], "name"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("missing network device feature name"));
            return -1;
        }

        if ((val = virNetDevFeatureTypeFromString(tmp)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("unknown network device feature '%1$s'"),
                           tmp);
            return -1;
        }
        ignore_value(virBitmapSetBit(net->features, val));
    }

    net->subtype = VIR_NODE_DEV_CAP_NET_LAST;

    type = virXPathString("string(./capability/@type)", ctxt);
    if (type) {
        int val = virNodeDevNetCapTypeFromString(type);
        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid network type supplied for '%1$s'"),
                           def->name);
            return -1;
        }
        net->subtype = val;
    }

    lnk = virXPathNode("./link", ctxt);
    if (lnk && virInterfaceLinkParseXML(lnk, &net->lnk) < 0)
        return -1;

    return 0;
}


static int
virNodeDevCapUSBInterfaceParseXML(xmlXPathContextPtr ctxt,
                                  virNodeDeviceDef *def,
                                  xmlNodePtr node,
                                  virNodeDevCapUSBIf *usb_if)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virNodeDevCapsDefParseUInt("string(./number[1])", ctxt,
                                   &usb_if->number, def,
                                   _("no USB interface number supplied for '%1$s'"),
                                   _("invalid USB interface number supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./class[1])", ctxt,
                                   &usb_if->klass, def,
                                   _("no USB interface class supplied for '%1$s'"),
                                   _("invalid USB interface class supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./subclass[1])", ctxt,
                                   &usb_if->subclass, def,
                                   _("no USB interface subclass supplied for '%1$s'"),
                                   _("invalid USB interface subclass supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./protocol[1])", ctxt,
                                   &usb_if->protocol, def,
                                   _("no USB interface protocol supplied for '%1$s'"),
                                   _("invalid USB interface protocol supplied for '%1$s'")) < 0)
        return -1;

    usb_if->description = virXPathString("string(./description[1])", ctxt);

    return 0;
}


static int
virNodeDevCapsDefParseHexId(const char *xpath,
                            xmlXPathContextPtr ctxt,
                            unsigned int *value,
                            virNodeDeviceDef *def,
                            const char *missing_error_fmt,
                            const char *invalid_error_fmt)
{
    int ret;

    ret = virXPathUIntBase(xpath, ctxt, 16, value);
    if (ret < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       ret == -1 ? missing_error_fmt : invalid_error_fmt,
                       def->name);
        return -1;
    }

    return 0;
}


static int
virNodeDevCapUSBDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDef *def,
                            xmlNodePtr node,
                            virNodeDevCapUSBDev *usb_dev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (virNodeDevCapsDefParseUInt("string(./bus[1])", ctxt,
                                   &usb_dev->bus, def,
                                   _("no USB bus number supplied for '%1$s'"),
                                   _("invalid USB bus number supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseUInt("string(./device[1])", ctxt,
                                   &usb_dev->device, def,
                                   _("no USB device number supplied for '%1$s'"),
                                   _("invalid USB device number supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseHexId("string(./vendor[1]/@id)", ctxt,
                                    &usb_dev->vendor, def,
                                    _("no USB vendor ID supplied for '%1$s'"),
                                    _("invalid USB vendor ID supplied for '%1$s'")) < 0)
        return -1;

    if (virNodeDevCapsDefParseHexId("string(./product[1]/@id)", ctxt,
                                    &usb_dev->product, def,
                                    _("no USB product ID supplied for '%1$s'"),
                                    _("invalid USB product ID supplied for '%1$s'")) < 0)
        return -1;

    usb_dev->vendor_name  = virXPathString("string(./vendor[1])", ctxt);
    usb_dev->product_name = virXPathString("string(./product[1])", ctxt);

    return 0;
}


static int
virNodeDevCapPCIDevIommuGroupParseXML(xmlXPathContextPtr ctxt,
                                      xmlNodePtr iommuGroupNode,
                                      virNodeDevCapPCIDev *pci_dev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree xmlNodePtr *addrNodes = NULL;
    int nAddrNodes;
    size_t i;

    ctxt->node = iommuGroupNode;

    if (virXMLPropUInt(iommuGroupNode, "number", 10, VIR_XML_PROP_REQUIRED,
                       &pci_dev->iommuGroupNumber) < 0)
        return -1;

    if ((nAddrNodes = virXPathNodeSet("./address", ctxt, &addrNodes)) < 0)
        return -1;

    for (i = 0; i < nAddrNodes; i++) {
        g_autoptr(virPCIDeviceAddress) pciAddr = g_new0(virPCIDeviceAddress, 1);

        if (virPCIDeviceAddressParseXML(addrNodes[i], pciAddr) < 0)
            return -1;
        VIR_APPEND_ELEMENT(pci_dev->iommuGroupDevices,
                           pci_dev->nIommuGroupDevices,
                           pciAddr);
    }

    return 0;
}


static int
virPCIEDeviceInfoLinkParseXML(xmlNodePtr linkNode,
                              virPCIELink *lnk)
{
    if (virXMLPropUInt(linkNode, "width", 0, VIR_XML_PROP_REQUIRED, &lnk->width) < 0)
        return -1;

    if (virXMLPropEnum(linkNode, "speed", virPCIELinkSpeedTypeFromString,
                       VIR_XML_PROP_NONE, &lnk->speed) < 0)
        return -1;

    if (virXMLPropInt(linkNode, "port", 10, VIR_XML_PROP_NONE, &lnk->port, -1) < 0)
        return -1;

    return 0;
}


static int
virPCIEDeviceInfoParseXML(xmlXPathContextPtr ctxt,
                          xmlNodePtr pciExpressNode,
                          virPCIEDeviceInfo *pci_express)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr lnk;

    ctxt->node = pciExpressNode;

    if ((lnk = virXPathNode("./link[@validity='cap']", ctxt))) {
        pci_express->link_cap = g_new0(virPCIELink, 1);

        if (virPCIEDeviceInfoLinkParseXML(lnk, pci_express->link_cap) < 0)
            return -1;
    }

    if ((lnk = virXPathNode("./link[@validity='sta']", ctxt))) {
        pci_express->link_sta = g_new0(virPCIELink, 1);

        if (virPCIEDeviceInfoLinkParseXML(lnk, pci_express->link_sta) < 0)
            return -1;
    }

    return 0;
}


static int
virNodeDevPCICapSRIOVPhysicalParseXML(xmlXPathContextPtr ctxt,
                                      virNodeDevCapPCIDev *pci_dev)
{
    xmlNodePtr address = virXPathNode("./address[1]", ctxt);

    pci_dev->physical_function = g_new0(virPCIDeviceAddress, 1);

    if (!address) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing address in 'phys_function' capability"));
        return -1;
    }

    if (virPCIDeviceAddressParseXML(address,
                                    pci_dev->physical_function) < 0)
        return -1;

    pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    return 0;
}


static int
virNodeDevPCICapSRIOVVirtualParseXML(xmlXPathContextPtr ctxt,
                                     virNodeDevCapPCIDev *pci_dev)
{
    g_autofree xmlNodePtr *addresses = NULL;
    int naddresses = virXPathNodeSet("./address", ctxt, &addresses);
    g_autofree char *maxFuncsStr = virXPathString("string(./@maxCount)", ctxt);
    size_t i;

    if (naddresses < 0)
        return -1;

    if (maxFuncsStr &&
        virStrToLong_uip(maxFuncsStr, NULL, 10,
                         &pci_dev->max_virtual_functions) < 0) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Malformed 'maxCount' parameter"));
        return -1;
    }

    pci_dev->virtual_functions = g_new0(virPCIDeviceAddress *, naddresses);

    for (i = 0; i < naddresses; i++) {
        g_autoptr(virPCIDeviceAddress) addr = NULL;

        addr = g_new0(virPCIDeviceAddress, 1);

        if (virPCIDeviceAddressParseXML(addresses[i], addr) < 0)
            return -1;

        VIR_APPEND_ELEMENT(pci_dev->virtual_functions,
                           pci_dev->num_virtual_functions,
                           addr);
    }

    pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;
    return 0;
}


static int
virNodeDevPCICapabilityParseXML(xmlXPathContextPtr ctxt,
                                xmlNodePtr node,
                                virNodeDevCapPCIDev *pci_dev)
{
    g_autofree char *type = virXMLPropString(node, "type");
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if (!type) {
        virReportError(VIR_ERR_XML_ERROR, "%s", _("Missing capability type"));
        return -1;
    }

    if (STREQ(type, "phys_function") &&
        virNodeDevPCICapSRIOVPhysicalParseXML(ctxt, pci_dev) < 0) {
        return -1;
    } else if (STREQ(type, "virt_functions") &&
               virNodeDevPCICapSRIOVVirtualParseXML(ctxt, pci_dev) < 0) {
        return -1;
    } else if (STREQ(type, "mdev_types")) {
        if (virNodeDevCapMdevTypesParseXML(ctxt,
                                           &pci_dev->mdev_types,
                                           &pci_dev->nmdev_types) < 0)
            return -1;
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_MDEV;
    } else if (STREQ(type, "vpd")) {
        if (virNodeDeviceCapVPDParseXML(ctxt, &pci_dev->vpd) < 0)
            return -1;
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VPD;
    } else {
        int hdrType = virPCIHeaderTypeFromString(type);

        if (hdrType > 0 && !pci_dev->hdrType)
            pci_dev->hdrType = hdrType;
    }

    return 0;
}


static int
virNodeDevCapPCIDevParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDef *def,
                            xmlNodePtr node,
                            virNodeDevCapPCIDev *pci_dev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    xmlNodePtr iommuGroupNode;
    xmlNodePtr pciExpress;
    g_autofree xmlNodePtr *nodes = NULL;
    int n = 0;
    int ret = -1;
    virPCIEDeviceInfo *pci_express = NULL;
    g_autofree char *tmp = NULL;
    size_t i = 0;

    ctxt->node = node;

    if ((tmp = virXPathString("string(./class[1])", ctxt))) {
        if (virStrToLong_i(tmp, NULL, 16, &pci_dev->klass) < 0 ||
            pci_dev->klass > 0xffffff) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid PCI class supplied for '%1$s'"), def->name);
            goto out;
        }
    } else {
        pci_dev->klass = -1;
    }

    if (virNodeDevCapsDefParseUInt("string(./domain[1])", ctxt,
                                   &pci_dev->domain, def,
                                   _("no PCI domain ID supplied for '%1$s'"),
                                   _("invalid PCI domain ID supplied for '%1$s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseUInt("string(./bus[1])", ctxt,
                                   &pci_dev->bus, def,
                                   _("no PCI bus ID supplied for '%1$s'"),
                                   _("invalid PCI bus ID supplied for '%1$s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseUInt("string(./slot[1])", ctxt,
                                   &pci_dev->slot, def,
                                   _("no PCI slot ID supplied for '%1$s'"),
                                   _("invalid PCI slot ID supplied for '%1$s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseUInt("string(./function[1])", ctxt,
                                   &pci_dev->function, def,
                                   _("no PCI function ID supplied for '%1$s'"),
                                   _("invalid PCI function ID supplied for '%1$s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./vendor[1]/@id)", ctxt,
                                    &pci_dev->vendor, def,
                                    _("no PCI vendor ID supplied for '%1$s'"),
                                    _("invalid PCI vendor ID supplied for '%1$s'")) < 0)
        goto out;

    if (virNodeDevCapsDefParseHexId("string(./product[1]/@id)", ctxt,
                                    &pci_dev->product, def,
                                    _("no PCI product ID supplied for '%1$s'"),
                                    _("invalid PCI product ID supplied for '%1$s'")) < 0)
        goto out;

    pci_dev->vendor_name  = virXPathString("string(./vendor[1])", ctxt);
    pci_dev->product_name = virXPathString("string(./product[1])", ctxt);

    if ((n = virXPathNodeSet("./capability", ctxt, &nodes)) < 0)
        goto out;

    for (i = 0; i < n; i++) {
        if (virNodeDevPCICapabilityParseXML(ctxt, nodes[i], pci_dev) < 0)
            goto out;
    }

    if ((iommuGroupNode = virXPathNode("./iommuGroup[1]", ctxt))) {
        if (virNodeDevCapPCIDevIommuGroupParseXML(ctxt, iommuGroupNode,
                                                  pci_dev) < 0) {
            goto out;
        }
    }

    /* The default value is -1 since zero is valid NUMA node number */
    pci_dev->numa_node = -1;
    if (virNodeDevCapsDefParseIntOptional("string(./numa[1]/@node)", ctxt,
                                          &pci_dev->numa_node, def,
                                          _("invalid NUMA node ID supplied for '%1$s'")) < 0)
        goto out;

    if ((pciExpress = virXPathNode("./pci-express[1]", ctxt))) {
        pci_express = g_new0(virPCIEDeviceInfo, 1);

        if (virPCIEDeviceInfoParseXML(ctxt, pciExpress, pci_express) < 0)
            goto out;

        pci_dev->pci_express = g_steal_pointer(&pci_express);
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCIE;
    }

    ret = 0;
 out:
    virPCIEDeviceInfoFree(pci_express);
    return ret;
}


static int
virNodeDevCapSystemParseXML(xmlXPathContextPtr ctxt,
                            virNodeDeviceDef *def,
                            xmlNodePtr node,
                            virNodeDevCapSystem *syscap)
{
    virNodeDevCapSystemHardware *hardware = &syscap->hardware;
    virNodeDevCapSystemFirmware *firmware = &syscap->firmware;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autofree char *tmp = NULL;

    ctxt->node = node;

    syscap->product_name = virXPathString("string(./product[1])", ctxt);

    hardware->vendor_name = virXPathString("string(./hardware/vendor[1])", ctxt);
    hardware->version     = virXPathString("string(./hardware/version[1])", ctxt);
    hardware->serial      = virXPathString("string(./hardware/serial[1])", ctxt);

    tmp = virXPathString("string(./hardware/uuid[1])", ctxt);
    if (!tmp) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no system UUID supplied for '%1$s'"), def->name);
        return -1;
    }

    if (virUUIDParse(tmp, hardware->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("malformed uuid element for '%1$s'"), def->name);
        return -1;
    }

    firmware->vendor_name  = virXPathString("string(./firmware/vendor[1])", ctxt);
    firmware->version      = virXPathString("string(./firmware/version[1])", ctxt);
    firmware->release_date = virXPathString("string(./firmware/release_date[1])", ctxt);

    return 0;
}

static int
virNodeDevCapMdevAttributeParseXML(xmlXPathContextPtr ctxt,
                                   xmlNodePtr node,
                                   virNodeDevCapMdev *mdev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    g_autoptr(virMediatedDeviceAttr) attr = virMediatedDeviceAttrNew();

    ctxt->node = node;
    attr->name = virXPathString("string(./@name)", ctxt);
    attr->value = virXPathString("string(./@value)", ctxt);
    if (!attr->name || !attr->value) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("mdev attribute missing name or value"));
        return -1;
    }

    VIR_APPEND_ELEMENT(mdev->attributes, mdev->nattributes, attr);

    return 0;
}

static int
virNodeDevCapMdevParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDef *def,
                          xmlNodePtr node,
                          virNodeDevCapMdev *mdev)
{
    VIR_XPATH_NODE_AUTORESTORE(ctxt)
    int nattrs = 0;
    g_autofree xmlNodePtr *attrs = NULL;
    size_t i;
    g_autofree char *uuidstr = NULL;

    ctxt->node = node;

    if (!(mdev->type = virXPathString("string(./type[1]/@id)", ctxt))) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("missing type id attribute for '%1$s'"), def->name);
        return -1;
    }

    if ((uuidstr = virXPathString("string(./uuid[1])", ctxt))) {
        unsigned char uuidbuf[VIR_UUID_BUFLEN];
        /* make sure that the provided uuid is valid */
        if (virUUIDParse(uuidstr, uuidbuf) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid uuid '%1$s' for new mdev device"), uuidstr);
            return -1;
        }
        mdev->uuid = g_new0(char, VIR_UUID_STRING_BUFLEN);
        virUUIDFormat(uuidbuf, mdev->uuid);
    }

    /* 'iommuGroup' is optional, only report an error if the supplied value is
     * invalid (-2), not if it's missing (-1) */
    if (virXPathUInt("string(./iommuGroup[1]/@number)",
                     ctxt, &mdev->iommuGroupNumber) < -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("invalid iommuGroup number attribute for '%1$s'"),
                       def->name);
        return -1;
    }

    if ((nattrs = virXPathNodeSet("./attr", ctxt, &attrs)) < 0)
        return -1;

    for (i = 0; i < nattrs; i++)
        virNodeDevCapMdevAttributeParseXML(ctxt, attrs[i], mdev);

    return 0;
}


static virNodeDevCapsDef *
virNodeDevCapsDefParseXML(xmlXPathContextPtr ctxt,
                          virNodeDeviceDef *def,
                          xmlNodePtr node,
                          int create,
                          const char *virt_type)
{
    g_autoptr(virNodeDevCapsDef) caps = g_new0(virNodeDevCapsDef, 1);
    int ret = -1;

    if (virXMLPropEnum(node, "type", virNodeDevCapTypeFromString,
                       VIR_XML_PROP_REQUIRED, &caps->data.type) < 0)
        return NULL;

    switch (caps->data.type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        ret = virNodeDevCapSystemParseXML(ctxt, def, node, &caps->data.system);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        ret = virNodeDevCapPCIDevParseXML(ctxt, def, node, &caps->data.pci_dev);
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        ret = virNodeDevCapUSBDevParseXML(ctxt, def, node, &caps->data.usb_dev);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        ret = virNodeDevCapUSBInterfaceParseXML(ctxt, def, node,
                                                &caps->data.usb_if);
        break;
    case VIR_NODE_DEV_CAP_NET:
        ret = virNodeDevCapNetParseXML(ctxt, def, node, &caps->data.net);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        ret = virNodeDevCapSCSIHostParseXML(ctxt, def, node,
                                            &caps->data.scsi_host,
                                            create,
                                            virt_type);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        ret = virNodeDevCapSCSITargetParseXML(ctxt, def, node,
                                              &caps->data.scsi_target);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        ret = virNodeDevCapSCSIParseXML(ctxt, def, node, &caps->data.scsi);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        ret = virNodeDevCapStorageParseXML(ctxt, def, node,
                                           &caps->data.storage);
        break;
    case VIR_NODE_DEV_CAP_DRM:
        ret = virNodeDevCapDRMParseXML(ctxt, def, node, &caps->data.drm);
        break;
    case VIR_NODE_DEV_CAP_MDEV:
        ret = virNodeDevCapMdevParseXML(ctxt, def, node, &caps->data.mdev);
        break;
    case VIR_NODE_DEV_CAP_CCW_DEV:
        ret = virNodeDevCapCCWParseXML(ctxt, def, node, &caps->data.ccw_dev);
        break;
    case VIR_NODE_DEV_CAP_CSS_DEV:
        ret = virNodeDevCapCSSParseXML(ctxt, def, node, &caps->data.ccw_dev);
        break;
    case VIR_NODE_DEV_CAP_AP_CARD:
        ret = virNodeDevCapAPCardParseXML(ctxt, def, node,
                                          &caps->data.ap_card);
        break;
    case VIR_NODE_DEV_CAP_AP_QUEUE:
        ret = virNodeDevCapAPQueueParseXML(ctxt, def, node,
                                           &caps->data.ap_queue);
        break;
    case VIR_NODE_DEV_CAP_AP_MATRIX:
        ret = virNodeDevCapAPMatrixParseXML(ctxt, def, node,
                                            &caps->data.ap_matrix);
        break;
    case VIR_NODE_DEV_CAP_MDEV_TYPES:
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
    case VIR_NODE_DEV_CAP_SCSI_GENERIC:
    case VIR_NODE_DEV_CAP_VDPA:
    case VIR_NODE_DEV_CAP_VPD:
    case VIR_NODE_DEV_CAP_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown capability type '%1$d' for '%2$s'"),
                       caps->data.type, def->name);
        ret = -1;
        break;
    }

    if (ret < 0)
        return NULL;

    return g_steal_pointer(&caps);
}


virNodeDeviceDef *
virNodeDeviceDefParseXML(xmlXPathContextPtr ctxt,
                         int create,
                         const char *virt_type)
{
    g_autoptr(virNodeDeviceDef) def = g_new0(virNodeDeviceDef, 1);
    virNodeDevCapsDef **next_cap;
    g_autofree xmlNodePtr *devnode = NULL;
    g_autofree xmlNodePtr *capability = NULL;
    int n, m;
    size_t i;

    /* Extract device name */
    if (create == EXISTING_DEVICE) {
        def->name = virXPathString("string(./name[1])", ctxt);

        if (!def->name) {
            virReportError(VIR_ERR_NO_NAME, NULL);
            return NULL;
        }
    } else {
        def->name = g_strdup("new device");
    }

    def->sysfs_path = virXPathString("string(./path[1])", ctxt);

    /* Parse devnodes */
    if ((n = virXPathNodeSet("./devnode", ctxt, &devnode)) < 0)
        return NULL;

    def->devlinks = g_new0(char *, n + 1);

    for (i = 0, m = 0; i < n; i++) {
        xmlNodePtr node = devnode[i];
        virNodeDevDevnodeType val;

        if (virXMLPropEnum(node, "type", virNodeDevDevnodeTypeFromString,
                           VIR_XML_PROP_REQUIRED, &val) < 0)
            return NULL;

        switch (val) {
        case VIR_NODE_DEV_DEVNODE_DEV:
            if (!(def->devnode = virXMLNodeContentString(node)))
                return NULL;
            break;
        case VIR_NODE_DEV_DEVNODE_LINK:
            if (!(def->devlinks[m++] = virXMLNodeContentString(node)))
                return NULL;
            break;
        case VIR_NODE_DEV_DEVNODE_LAST:
            break;
        }
    }

    /* Extract device parent, if any */
    def->parent = virXPathString("string(./parent[1])", ctxt);
    def->parent_wwnn = virXPathString("string(./parent[1]/@wwnn)", ctxt);
    def->parent_wwpn = virXPathString("string(./parent[1]/@wwpn)", ctxt);
    if (def->parent_wwnn && !def->parent_wwpn) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("when providing parent wwnn='%1$s', the wwpn must also be provided"),
                       def->parent_wwnn);
        return NULL;
    }

    if (!def->parent_wwnn && def->parent_wwpn) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("when providing parent wwpn='%1$s', the wwnn must also be provided"),
                       def->parent_wwpn);
        return NULL;
    }
    def->parent_fabric_wwn = virXPathString("string(./parent[1]/@fabric_wwn)",
                                            ctxt);

    /* Parse device capabilities */
    if ((n = virXPathNodeSet("./capability", ctxt, &capability)) < 0)
        return NULL;

    if (n == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("no device capabilities for '%1$s'"),
                       def->name);
        return NULL;
    }

    next_cap = &def->caps;
    for (i = 0; i < n; i++) {
        *next_cap = virNodeDevCapsDefParseXML(ctxt, def,
                                              capability[i],
                                              create,
                                              virt_type);
        if (!*next_cap)
            return NULL;

        next_cap = &(*next_cap)->next;
    }

    return g_steal_pointer(&def);
}


virNodeDeviceDef *
virNodeDeviceDefParse(const char *str,
                      const char *filename,
                      int create,
                      const char *virt_type,
                      virNodeDeviceDefParserCallbacks *parserCallbacks,
                      void *opaque,
                      bool validate)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virNodeDeviceDef) def = NULL;

    if (!(xml = virXMLParse(filename, str, _("(node_device_definition)"),
                            "device", &ctxt, "nodedev.rng", validate)))
        return NULL;

    if (!(def = virNodeDeviceDefParseXML(ctxt, create, virt_type)))
        return NULL;

    if (parserCallbacks) {
        int ret = 0;
        /* fill in backend-specific aspects */
        if (parserCallbacks->postParse) {
            ret = parserCallbacks->postParse(def, opaque);
            if (ret < 0)
                return NULL;
        }

        /* validate definition */
        if (parserCallbacks->validate) {
            ret = parserCallbacks->validate(def, opaque);
            if (ret < 0)
                return NULL;
        }
    }

    return g_steal_pointer(&def);
}


/*
 * Return fc_host dev's WWNN and WWPN
 */
int
virNodeDeviceGetWWNs(virNodeDeviceDef *def,
                     char **wwnn,
                     char **wwpn)
{
    virNodeDevCapsDef *cap = NULL;

    cap = def->caps;
    while (cap != NULL) {
        if (cap->data.type == VIR_NODE_DEV_CAP_SCSI_HOST &&
            cap->data.scsi_host.flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
            *wwnn = g_strdup(cap->data.scsi_host.wwnn);
            *wwpn = g_strdup(cap->data.scsi_host.wwpn);
            break;
        }

        cap = cap->next;
    }

    if (cap == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Device is not a fibre channel HBA"));
        return -1;
    }

    return 0;
}


void
virNodeDevCapsDefFree(virNodeDevCapsDef *caps)
{
    size_t i = 0;
    virNodeDevCapData *data = &caps->data;

    switch (caps->data.type) {
    case VIR_NODE_DEV_CAP_SYSTEM:
        g_free(data->system.product_name);
        g_free(data->system.hardware.vendor_name);
        g_free(data->system.hardware.version);
        g_free(data->system.hardware.serial);
        g_free(data->system.firmware.vendor_name);
        g_free(data->system.firmware.version);
        g_free(data->system.firmware.release_date);
        break;
    case VIR_NODE_DEV_CAP_PCI_DEV:
        g_free(data->pci_dev.product_name);
        g_free(data->pci_dev.vendor_name);
        g_free(data->pci_dev.physical_function);
        for (i = 0; i < data->pci_dev.num_virtual_functions; i++)
            g_free(data->pci_dev.virtual_functions[i]);
        g_free(data->pci_dev.virtual_functions);
        for (i = 0; i < data->pci_dev.nIommuGroupDevices; i++)
            g_free(data->pci_dev.iommuGroupDevices[i]);
        g_free(data->pci_dev.iommuGroupDevices);
        virPCIEDeviceInfoFree(data->pci_dev.pci_express);
        for (i = 0; i < data->pci_dev.nmdev_types; i++)
            virMediatedDeviceTypeFree(data->pci_dev.mdev_types[i]);
        g_free(data->pci_dev.mdev_types);
        virPCIVPDResourceFree(g_steal_pointer(&data->pci_dev.vpd));
        break;
    case VIR_NODE_DEV_CAP_USB_DEV:
        g_free(data->usb_dev.product_name);
        g_free(data->usb_dev.vendor_name);
        break;
    case VIR_NODE_DEV_CAP_USB_INTERFACE:
        g_free(data->usb_if.description);
        break;
    case VIR_NODE_DEV_CAP_NET:
        g_free(data->net.ifname);
        g_free(data->net.address);
        virBitmapFree(data->net.features);
        break;
    case VIR_NODE_DEV_CAP_SCSI_HOST:
        g_free(data->scsi_host.wwnn);
        g_free(data->scsi_host.wwpn);
        g_free(data->scsi_host.fabric_wwn);
        break;
    case VIR_NODE_DEV_CAP_SCSI_TARGET:
        g_free(data->scsi_target.name);
        g_free(data->scsi_target.rport);
        g_free(data->scsi_target.wwpn);
        break;
    case VIR_NODE_DEV_CAP_SCSI:
        g_free(data->scsi.type);
        break;
    case VIR_NODE_DEV_CAP_STORAGE:
        g_free(data->storage.block);
        g_free(data->storage.bus);
        g_free(data->storage.drive_type);
        g_free(data->storage.model);
        g_free(data->storage.vendor);
        g_free(data->storage.serial);
        g_free(data->storage.media_label);
        break;
    case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        g_free(data->sg.path);
        break;
    case VIR_NODE_DEV_CAP_MDEV:
        g_free(data->mdev.type);
        g_free(data->mdev.uuid);
        for (i = 0; i < data->mdev.nattributes; i++)
            virMediatedDeviceAttrFree(data->mdev.attributes[i]);
        g_free(data->mdev.attributes);
        g_free(data->mdev.parent_addr);
        break;
    case VIR_NODE_DEV_CAP_CSS_DEV:
        for (i = 0; i < data->ccw_dev.nmdev_types; i++)
            virMediatedDeviceTypeFree(data->ccw_dev.mdev_types[i]);
        g_free(data->ccw_dev.mdev_types);
        g_free(data->ccw_dev.channel_dev_addr);
        break;
    case VIR_NODE_DEV_CAP_AP_MATRIX:
        g_free(data->ap_matrix.addr);
        for (i = 0; i < data->ap_matrix.nmdev_types; i++)
            virMediatedDeviceTypeFree(data->ap_matrix.mdev_types[i]);
        g_free(data->ap_matrix.mdev_types);
        break;
    case VIR_NODE_DEV_CAP_MDEV_TYPES:
        for (i = 0; i < data->mdev_parent.nmdev_types; i++)
            virMediatedDeviceTypeFree(data->mdev_parent.mdev_types[i]);
        g_free(data->mdev_parent.mdev_types);
        g_free(data->mdev_parent.address);
        break;
    case VIR_NODE_DEV_CAP_DRM:
    case VIR_NODE_DEV_CAP_FC_HOST:
    case VIR_NODE_DEV_CAP_VPORTS:
    case VIR_NODE_DEV_CAP_CCW_DEV:
    case VIR_NODE_DEV_CAP_VDPA:
    case VIR_NODE_DEV_CAP_AP_CARD:
    case VIR_NODE_DEV_CAP_AP_QUEUE:
    case VIR_NODE_DEV_CAP_VPD:
    case VIR_NODE_DEV_CAP_LAST:
        /* This case is here to shutup the compiler */
        break;
    }

    g_free(caps);
}


int
virNodeDeviceUpdateCaps(virNodeDeviceDef *def)
{
    virNodeDevCapsDef *cap = def->caps;

    while (cap) {
        switch (cap->data.type) {
        case VIR_NODE_DEV_CAP_SCSI_HOST:
            virNodeDeviceGetSCSIHostCaps(&cap->data.scsi_host);
            break;
        case VIR_NODE_DEV_CAP_SCSI_TARGET:
            virNodeDeviceGetSCSITargetCaps(def->sysfs_path,
                                           &cap->data.scsi_target);
            break;
        case VIR_NODE_DEV_CAP_NET:
            if (virNetDevGetLinkInfo(cap->data.net.ifname,
                                     &cap->data.net.lnk) < 0)
                return -1;
            virBitmapFree(cap->data.net.features);
            if (virNetDevGetFeatures(cap->data.net.ifname,
                                     &cap->data.net.features) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_PCI_DEV:
            if (virNodeDeviceGetPCIDynamicCaps(def->sysfs_path,
                                               &cap->data.pci_dev) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_CSS_DEV:
            if (virNodeDeviceGetCSSDynamicCaps(def->sysfs_path,
                                               &cap->data.ccw_dev) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_AP_MATRIX:
            if (virNodeDeviceGetAPMatrixDynamicCaps(def->sysfs_path,
                                                    &cap->data.ap_matrix) < 0)
                return -1;
            break;
        case VIR_NODE_DEV_CAP_MDEV_TYPES:
            if (virNodeDeviceGetMdevParentDynamicCaps(def->sysfs_path,
                                                      &cap->data.mdev_parent) < 0)
                return -1;
            break;

            /* all types that (supposedly) don't require any updates
             * relative to what's in the cache.
             */
        case VIR_NODE_DEV_CAP_DRM:
        case VIR_NODE_DEV_CAP_SYSTEM:
        case VIR_NODE_DEV_CAP_USB_DEV:
        case VIR_NODE_DEV_CAP_USB_INTERFACE:
        case VIR_NODE_DEV_CAP_SCSI:
        case VIR_NODE_DEV_CAP_STORAGE:
        case VIR_NODE_DEV_CAP_FC_HOST:
        case VIR_NODE_DEV_CAP_VPORTS:
        case VIR_NODE_DEV_CAP_SCSI_GENERIC:
        case VIR_NODE_DEV_CAP_MDEV:
        case VIR_NODE_DEV_CAP_CCW_DEV:
        case VIR_NODE_DEV_CAP_VDPA:
        case VIR_NODE_DEV_CAP_AP_CARD:
        case VIR_NODE_DEV_CAP_AP_QUEUE:
        case VIR_NODE_DEV_CAP_VPD:
        case VIR_NODE_DEV_CAP_LAST:
            break;
        }
        cap = cap->next;
    }

    return 0;
}


/**
 * virNodeDeviceCapsListExport:
 * @def: node device definition
 * @list: pointer to an array to store all supported capabilities by a device
 *
 * Takes the definition, scans through all the capabilities that the device
 * supports (including the nested caps) and populates a newly allocated list
 * with them. Caller is responsible for freeing the list.
 * If NULL is passed to @list, only the number of caps will be returned.
 *
 * Returns the number of capabilities the device supports, -1 on error.
 */
int
virNodeDeviceCapsListExport(virNodeDeviceDef *def,
                            virNodeDevCapType **list)
{
    virNodeDevCapsDef *caps = NULL;
    g_autofree virNodeDevCapType *tmp = NULL;
    bool want_list = !!list;
    int ncaps = 0;

#define MAYBE_ADD_CAP(cap) \
    do { \
        if (want_list) \
            tmp[ncaps] = cap; \
    } while (0)

    if (virNodeDeviceUpdateCaps(def) < 0)
        return -1;

    if (want_list)
        tmp = g_new0(virNodeDevCapType, VIR_NODE_DEV_CAP_LAST - 1);

    for (caps = def->caps; caps; caps = caps->next) {
        unsigned int flags;

        MAYBE_ADD_CAP(caps->data.type);
        ncaps++;

        /* check nested caps for a given type as well */
        if (caps->data.type == VIR_NODE_DEV_CAP_SCSI_HOST) {
            flags = caps->data.scsi_host.flags;

            if (flags & VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_FC_HOST);
                ncaps++;
            }

            if (flags  & VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_VPORTS);
                ncaps++;
            }
        }

        if (caps->data.type == VIR_NODE_DEV_CAP_PCI_DEV) {
            flags = caps->data.pci_dev.flags;

            if (flags & VIR_NODE_DEV_CAP_FLAG_PCI_MDEV) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_MDEV_TYPES);
                ncaps++;
            }
            if (flags & VIR_NODE_DEV_CAP_FLAG_PCI_VPD) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_VPD);
                ncaps++;
            }
        }

        if (caps->data.type == VIR_NODE_DEV_CAP_CSS_DEV) {
            flags = caps->data.ccw_dev.flags;

            if (flags & VIR_NODE_DEV_CAP_FLAG_CSS_MDEV) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_MDEV_TYPES);
                ncaps++;
            }
        }

        if (caps->data.type == VIR_NODE_DEV_CAP_AP_MATRIX) {
            flags = caps->data.ap_matrix.flags;

            if (flags & VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV) {
                MAYBE_ADD_CAP(VIR_NODE_DEV_CAP_MDEV_TYPES);
                ncaps++;
            }
        }
    }

#undef MAYBE_ADD_CAP

    if (want_list)
        *list = g_steal_pointer(&tmp);

    return ncaps;
}


#ifdef __linux__

int
virNodeDeviceGetSCSIHostCaps(virNodeDevCapSCSIHost *scsi_host)
{
    g_autofree char *tmp = NULL;
    int ret = -1;

    if ((scsi_host->unique_id =
         virSCSIHostGetUniqueId(NULL, scsi_host->host)) < 0) {
        VIR_DEBUG("Failed to read unique_id for host%d", scsi_host->host);
        scsi_host->unique_id = -1;
    }

    VIR_DEBUG("Checking if host%d is an FC HBA", scsi_host->host);

    if (virVHBAPathExists(NULL, scsi_host->host)) {
        scsi_host->flags |= VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST;

        if (!(tmp = virVHBAGetConfig(NULL, scsi_host->host, "port_name"))) {
            VIR_WARN("Failed to read WWPN for host%d", scsi_host->host);
            goto cleanup;
        }
        VIR_FREE(scsi_host->wwpn);
        scsi_host->wwpn = g_steal_pointer(&tmp);

        if (!(tmp = virVHBAGetConfig(NULL, scsi_host->host, "node_name"))) {
            VIR_WARN("Failed to read WWNN for host%d", scsi_host->host);
            goto cleanup;
        }
        VIR_FREE(scsi_host->wwnn);
        scsi_host->wwnn = g_steal_pointer(&tmp);

        if ((tmp = virVHBAGetConfig(NULL, scsi_host->host, "fabric_name"))) {
            VIR_FREE(scsi_host->fabric_wwn);
            scsi_host->fabric_wwn = g_steal_pointer(&tmp);
        }
    }

    if (virVHBAIsVportCapable(NULL, scsi_host->host)) {
        g_autofree char *max_vports = NULL;
        g_autofree char *vports = NULL;

        scsi_host->flags |= VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS;

        if (!(max_vports = virVHBAGetConfig(NULL, scsi_host->host,
                                            "max_npiv_vports"))) {
            VIR_WARN("Failed to read max_npiv_vports for host%d",
                     scsi_host->host);
            goto cleanup;
        }

        if (virStrToLong_i(max_vports, NULL, 10, &scsi_host->max_vports) < 0) {
            VIR_WARN("Failed to parse value of max_npiv_vports '%s'", max_vports);
            goto cleanup;
        }

        if (!(vports = virVHBAGetConfig(NULL, scsi_host->host,
                                        "npiv_vports_inuse"))) {
            VIR_WARN("Failed to read npiv_vports_inuse for host%d",
                     scsi_host->host);
            goto cleanup;
        }

        if (virStrToLong_i(vports, NULL, 10, &scsi_host->vports) < 0) {
            VIR_WARN("Failed to parse value of npiv_vports_inuse '%s'", vports);
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    if (ret < 0) {
        /* Clear the two flags in case of producing confusing XML output */
        scsi_host->flags &= ~(VIR_NODE_DEV_CAP_FLAG_HBA_FC_HOST |
                              VIR_NODE_DEV_CAP_FLAG_HBA_VPORT_OPS);

        VIR_FREE(scsi_host->wwnn);
        VIR_FREE(scsi_host->wwpn);
        VIR_FREE(scsi_host->fabric_wwn);
    }
    return ret;
}


int
virNodeDeviceGetSCSITargetCaps(const char *sysfsPath,
                               virNodeDevCapSCSITarget *scsi_target)
{
    int ret = -1;
    g_autofree char *dir = NULL;
    g_autofree char *rport = NULL;

    VIR_DEBUG("Checking if '%s' is an FC remote port", scsi_target->name);

    /* /sys/devices/[...]/host0/rport-0:0-0/target0:0:0 -> rport-0:0-0 */
    dir = g_path_get_dirname(sysfsPath);

    rport = g_path_get_basename(dir);

    if (!virFCIsCapableRport(rport))
        goto cleanup;

    VIR_FREE(scsi_target->rport);
    scsi_target->rport = g_steal_pointer(&rport);

    if (virFCReadRportValue(scsi_target->rport, "port_name",
                            &scsi_target->wwpn) < 0) {
        VIR_WARN("Failed to read port_name for '%s'", scsi_target->rport);
        goto cleanup;
    }

    scsi_target->flags |= VIR_NODE_DEV_CAP_FLAG_FC_RPORT;
    ret = 0;

 cleanup:
    if (ret < 0) {
        VIR_FREE(scsi_target->rport);
        VIR_FREE(scsi_target->wwpn);
        scsi_target->flags &= ~VIR_NODE_DEV_CAP_FLAG_FC_RPORT;
    }

    return ret;
}


static int
virNodeDeviceGetPCISRIOVCaps(const char *sysfsPath,
                             virNodeDevCapPCIDev *pci_dev)
{
    g_autoptr(virPCIVirtualFunctionList) vfs = NULL;
    size_t i;
    int ret;

    /* this could be a refresh, so clear out the old data */
    for (i = 0; i < pci_dev->num_virtual_functions; i++)
       VIR_FREE(pci_dev->virtual_functions[i]);
    VIR_FREE(pci_dev->virtual_functions);
    VIR_FREE(pci_dev->physical_function);
    pci_dev->num_virtual_functions = 0;
    pci_dev->max_virtual_functions = 0;
    pci_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;
    pci_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    ret = virPCIGetPhysicalFunction(sysfsPath,
                                    &pci_dev->physical_function);
    if (ret < 0)
        return ret;

    if (pci_dev->physical_function)
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_PHYSICAL_FUNCTION;

    if (virPCIGetVirtualFunctions(sysfsPath, &vfs) < 0)
        return -1;

    pci_dev->virtual_functions = g_new0(virPCIDeviceAddress *, vfs->nfunctions);

    for (i = 0; i < vfs->nfunctions; i++)
        pci_dev->virtual_functions[i] = g_steal_pointer(&vfs->functions[i].addr);

    pci_dev->num_virtual_functions = vfs->nfunctions;
    pci_dev->max_virtual_functions = vfs->maxfunctions;

    if (pci_dev->num_virtual_functions > 0 ||
        pci_dev->max_virtual_functions > 0)
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VIRTUAL_FUNCTION;

    return ret;
}


static int
virNodeDeviceGetPCIIOMMUGroupCaps(virNodeDevCapPCIDev *pci_dev)
{
    size_t i;
    int tmpGroup;
    virPCIDeviceAddress addr = { 0 };

    /* this could be a refresh, so clear out the old data */
    for (i = 0; i < pci_dev->nIommuGroupDevices; i++)
       VIR_FREE(pci_dev->iommuGroupDevices[i]);
    VIR_FREE(pci_dev->iommuGroupDevices);
    pci_dev->nIommuGroupDevices = 0;
    pci_dev->iommuGroupNumber = 0;

    addr.domain = pci_dev->domain;
    addr.bus = pci_dev->bus;
    addr.slot = pci_dev->slot;
    addr.function = pci_dev->function;
    tmpGroup = virPCIDeviceAddressGetIOMMUGroupNum(&addr);
    if (tmpGroup == -1) {
        /* error was already reported */
        return -1;
    }
    if (tmpGroup == -2)
        /* -2 return means there is no iommu_group data */
        return 0;
    if (tmpGroup >= 0) {
        if (virPCIDeviceAddressGetIOMMUGroupAddresses(&addr, &pci_dev->iommuGroupDevices,
                                                      &pci_dev->nIommuGroupDevices) < 0)
            return -1;
        pci_dev->iommuGroupNumber = tmpGroup;
    }

    return 0;
}


static int
virNodeDeviceGetMdevTypesCaps(const char *sysfspath,
                              virMediatedDeviceType ***mdev_types,
                              size_t *nmdev_types)
{
    virMediatedDeviceType **types = NULL;
    size_t ntypes = 0;
    size_t i;

    /* this could be a refresh, so clear out the old data */
    for (i = 0; i < *nmdev_types; i++)
       virMediatedDeviceTypeFree((*mdev_types)[i]);
    VIR_FREE(*mdev_types);
    *nmdev_types = 0;

    if (virMediatedDeviceGetMdevTypes(sysfspath, &types, &ntypes) < 0)
        return -1;

    *mdev_types = g_steal_pointer(&types);
    *nmdev_types = ntypes;

    return 0;
}


/**
 * virNodeDeviceGetPCIVPDDynamicCap:
 * @devCapPCIDev: a virNodeDevCapPCIDev for which to add VPD resources.
 *
 * While VPD has a read-only portion, there may be a read-write portion per
 * the specs which may change dynamically.
 *
 * Returns: 0 if the operation was successful (even if VPD is not present for
 * that device since it is optional in the specs, -1 otherwise.
 */
static int
virNodeDeviceGetPCIVPDDynamicCap(virNodeDevCapPCIDev *devCapPCIDev)
{
    g_autoptr(virPCIDevice) pciDev = NULL;
    virPCIDeviceAddress devAddr = { 0 };
    g_autoptr(virPCIVPDResource) res = NULL;

    g_clear_pointer(&devCapPCIDev->vpd, virPCIVPDResourceFree);
    devCapPCIDev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_VPD;

    devAddr.domain = devCapPCIDev->domain;
    devAddr.bus = devCapPCIDev->bus;
    devAddr.slot = devCapPCIDev->slot;
    devAddr.function = devCapPCIDev->function;

    if (!(pciDev = virPCIDeviceNew(&devAddr)))
        return -1;

    if (virPCIDeviceHasVPD(pciDev)) {
        /* VPD is optional in PCI(e) specs. If it is there, attempt to add it. */
        if ((res = virPCIDeviceGetVPD(pciDev))) {
            devCapPCIDev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_VPD;
            devCapPCIDev->vpd = g_steal_pointer(&res);
        }
    }
    return 0;
}


/* virNodeDeviceGetPCIDynamicCaps() get info that is stored in sysfs
 * about devices related to this device, i.e. things that can change
 * without this device itself changing. These must be refreshed
 * anytime full XML of the device is requested, because they can
 * change with no corresponding notification from the kernel/udev.
 */
int
virNodeDeviceGetPCIDynamicCaps(const char *sysfsPath,
                               virNodeDevCapPCIDev *pci_dev)
{
    if (virNodeDeviceGetPCISRIOVCaps(sysfsPath, pci_dev) < 0 ||
        virNodeDeviceGetPCIIOMMUGroupCaps(pci_dev) < 0)
        return -1;

    pci_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_PCI_MDEV;
    if (virNodeDeviceGetMdevTypesCaps(sysfsPath,
                                      &pci_dev->mdev_types,
                                      &pci_dev->nmdev_types) < 0)
        return -1;
    if (pci_dev->nmdev_types > 0)
        pci_dev->flags |= VIR_NODE_DEV_CAP_FLAG_PCI_MDEV;

    if (virNodeDeviceGetPCIVPDDynamicCap(pci_dev) < 0)
        return -1;

    return 0;
}


/* virNodeDeviceGetCSSDynamicCaps() get info that is stored in sysfs
 * about devices related to this device, i.e. things that can change
 * without this device itself changing. These must be refreshed
 * anytime full XML of the device is requested, because they can
 * change with no corresponding notification from the kernel/udev.
 */
int
virNodeDeviceGetCSSDynamicCaps(const char *sysfsPath,
                               virNodeDevCapCCW *ccw_dev)
{
    ccw_dev->flags &= ~VIR_NODE_DEV_CAP_FLAG_CSS_MDEV;
    if (virNodeDeviceGetMdevTypesCaps(sysfsPath,
                                      &ccw_dev->mdev_types,
                                      &ccw_dev->nmdev_types) < 0)
        return -1;
    if (ccw_dev->nmdev_types > 0)
        ccw_dev->flags |= VIR_NODE_DEV_CAP_FLAG_CSS_MDEV;

    return 0;
}

/* virNodeDeviceGetAPMatrixDynamicCaps() get info that is stored in sysfs
 * about devices related to this device, i.e. things that can change
 * without this device itself changing. These must be refreshed
 * anytime full XML of the device is requested, because they can
 * change with no corresponding notification from the kernel/udev.
 */
int
virNodeDeviceGetAPMatrixDynamicCaps(const char *sysfsPath,
                                    virNodeDevCapAPMatrix *ap_matrix)
{
    ap_matrix->flags &= ~VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV;
    if (virNodeDeviceGetMdevTypesCaps(sysfsPath,
                                      &ap_matrix->mdev_types,
                                      &ap_matrix->nmdev_types) < 0)
        return -1;
    if (ap_matrix->nmdev_types > 0)
        ap_matrix->flags |= VIR_NODE_DEV_CAP_FLAG_AP_MATRIX_MDEV;

    return 0;
}

/* virNodeDeviceGetMdevParentDynamicCaps() get info that is stored in sysfs
 * about devices related to this device, i.e. things that can change
 * without this device itself changing. These must be refreshed
 * anytime full XML of the device is requested, because they can
 * change with no corresponding notification from the kernel/udev.
 */
int
virNodeDeviceGetMdevParentDynamicCaps(const char *sysfsPath,
                                      virNodeDevCapMdevParent *mdev_parent)
{
    if (virNodeDeviceGetMdevTypesCaps(sysfsPath,
                                      &mdev_parent->mdev_types,
                                      &mdev_parent->nmdev_types) < 0)
        return -1;
    return 0;
}


#else

int
virNodeDeviceGetSCSIHostCaps(virNodeDevCapSCSIHost *scsi_host G_GNUC_UNUSED)
{
    return -1;
}

int
virNodeDeviceGetPCIDynamicCaps(const char *sysfsPath G_GNUC_UNUSED,
                               virNodeDevCapPCIDev *pci_dev G_GNUC_UNUSED)
{
    return -1;
}


int virNodeDeviceGetSCSITargetCaps(const char *sysfsPath G_GNUC_UNUSED,
                                   virNodeDevCapSCSITarget *scsi_target G_GNUC_UNUSED)
{
    return -1;
}

int
virNodeDeviceGetCSSDynamicCaps(const char *sysfsPath G_GNUC_UNUSED,
                               virNodeDevCapCCW *ccw_dev G_GNUC_UNUSED)
{
    return -1;
}

int
virNodeDeviceGetAPMatrixDynamicCaps(const char *sysfsPath G_GNUC_UNUSED,
                                    virNodeDevCapAPMatrix *ap_matrix G_GNUC_UNUSED)
{
    return -1;
}

int
virNodeDeviceGetMdevParentDynamicCaps(const char *sysfsPath G_GNUC_UNUSED,
                                      virNodeDevCapMdevParent *mdev_parent G_GNUC_UNUSED)
{
    return -1;
}


#endif /* __linux__ */
