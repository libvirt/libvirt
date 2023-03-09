/*
 * virnetworkportdef.c: network port XML processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "viralloc.h"
#include "virerror.h"
#include "virnetdevmacvlan.h"
#include "virnetworkportdef.h"
#include "network_conf.h"

#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "netdev_vport_profile_conf.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_ENUM_IMPL(virNetworkPortPlug,
              VIR_NETWORK_PORT_PLUG_TYPE_LAST,
              "none", "network", "bridge", "direct", "hostdev-pci");

void
virNetworkPortDefFree(virNetworkPortDef *def)
{
    if (!def)
        return;

    g_free(def->ownername);
    g_free(def->group);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    g_free(def->virtPortProfile);

    switch ((virNetworkPortPlugType)def->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        g_free(def->plug.bridge.brname);
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        g_free(def->plug.direct.linkdev);
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        break;
    }

    g_free(def);
}



static virNetworkPortDef *
virNetworkPortDefParseXML(xmlXPathContextPtr ctxt)
{
    g_autoptr(virNetworkPortDef) def = NULL;
    g_autofree char *uuid = NULL;
    xmlNodePtr virtPortNode;
    xmlNodePtr vlanNode;
    xmlNodePtr bandwidthNode;
    xmlNodePtr addressNode;
    xmlNodePtr rxfiltersNode = NULL;
    xmlNodePtr plugNode = NULL;
    g_autofree char *mac = NULL;
    g_autofree char *macmgr = NULL;
    g_autofree char *mode = NULL;
    g_autofree char *driver = NULL;

    def = g_new0(virNetworkPortDef, 1);

    uuid = virXPathString("string(./uuid)", ctxt);
    if (!uuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no uuid"));
        return NULL;
    }
    if (virUUIDParse(uuid, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse UUID '%1$s'"), uuid);
        return NULL;
    }

    def->ownername = virXPathString("string(./owner/name)", ctxt);
    if (!def->ownername) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no owner name"));
        return NULL;
    }

    VIR_FREE(uuid);
    uuid = virXPathString("string(./owner/uuid)", ctxt);
    if (!uuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no owner UUID"));
        return NULL;
    }

    if (virUUIDParse(uuid, def->owneruuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse UUID '%1$s'"), uuid);
        return NULL;
    }

    def->group = virXPathString("string(./group)", ctxt);

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode, 0)))) {
        return NULL;
    }

    mac = virXPathString("string(./mac/@address)", ctxt);
    if (!mac) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no mac"));
        return NULL;
    }
    if (virMacAddrParse(mac, &def->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse MAC '%1$s'"), mac);
        return NULL;
    }

    bandwidthNode = virXPathNode("./bandwidth", ctxt);
    /*
     * We don't know if the port will allow the "floor" param or
     * not at this stage, so we must just tell virNetDevBandwidthParse
     * to allow it regardless. Any bad config must be reported at
     * time of use instead.
     */
    if (bandwidthNode &&
        virNetDevBandwidthParse(&def->bandwidth, &def->class_id,
                                bandwidthNode, true) < 0)
        return NULL;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        return NULL;

    if (virNetworkPortOptionsParseXML(ctxt, &def->isolatedPort) < 0)
        return NULL;

    rxfiltersNode = virXPathNode("./rxfilters", ctxt);
    if (virXMLPropTristateBool(rxfiltersNode, "trustGuest",
                               VIR_XML_PROP_NONE,
                               &def->trustGuestRxFilters) < 0)
        return NULL;

    plugNode = virXPathNode("./plug", ctxt);

    if (virXMLPropEnum(plugNode, "type",
                       virNetworkPortPlugTypeFromString,
                       VIR_XML_PROP_NONE,
                       &def->plugtype) < 0)
        return NULL;

    switch (def->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        if (!(def->plug.bridge.brname = virXMLPropString(plugNode, "bridge"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port bridge name"));
            return NULL;
        }
        macmgr = virXMLPropString(plugNode, "macTableManager");
        if (macmgr &&
            (def->plug.bridge.macTableManager =
             virNetworkBridgeMACTableManagerTypeFromString(macmgr)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid macTableManager setting '%1$s' in network port"),
                           macmgr);
            return NULL;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        if (!(def->plug.direct.linkdev = virXMLPropString(plugNode, "dev"))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port link device name"));
            return NULL;
        }
        mode = virXMLPropString(plugNode, "mode");
        if (mode &&
            (def->plug.direct.mode =
             virNetDevMacVLanModeTypeFromString(mode)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid mode setting '%1$s' in network port"), mode);
            return NULL;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        if (virXMLPropTristateBool(plugNode, "managed",
                                   VIR_XML_PROP_NONE,
                                   &def->plug.hostdevpci.managed) < 0)
            return NULL;
        driver = virXPathString("string(./plug/driver/@name)", ctxt);
        if (driver &&
            (def->plug.hostdevpci.driver =
             virNetworkForwardDriverNameTypeFromString(driver)) <= 0) {
              virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port driver name"));
            return NULL;
        }
        if (!(addressNode = virXPathNode("./plug/address", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port PCI address"));
            return NULL;
        }

        if (virPCIDeviceAddressParseXML(addressNode, &def->plug.hostdevpci.addr) < 0)
            return NULL;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, def->plugtype);
        return NULL;
    }

    return g_steal_pointer(&def);
}


virNetworkPortDef *
virNetworkPortDefParse(const char *xmlStr,
                       const char *filename,
                       unsigned int flags)
{
    g_autoptr(xmlDoc) xml = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    bool validate = flags & VIR_NETWORK_PORT_CREATE_VALIDATE;

    if (!(xml = virXMLParse(filename, xmlStr, _("(networkport_definition)"),
                            "networkport", &ctxt, "networkport.rng", validate)))
        return NULL;

    return virNetworkPortDefParseXML(ctxt);
}


char *
virNetworkPortDefFormat(const virNetworkPortDef *def)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (virNetworkPortDefFormatBuf(&buf, def) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virNetworkPortDefFormatBuf(virBuffer *buf,
                           const virNetworkPortDef *def)
{
    char uuid[VIR_UUID_STRING_BUFLEN];
    char macaddr[VIR_MAC_STRING_BUFLEN];

    virBufferAddLit(buf, "<networkport>\n");

    virBufferAdjustIndent(buf, 2);

    virUUIDFormat(def->uuid, uuid);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuid);

    virBufferAddLit(buf, "<owner>\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", def->ownername);
    virUUIDFormat(def->owneruuid, uuid);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuid);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</owner>\n");

    virBufferEscapeString(buf, "<group>%s</group>\n", def->group);

    virMacAddrFormat(&def->mac, macaddr);
    virBufferAsprintf(buf, "<mac address='%s'/>\n", macaddr);

    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        return -1;
    if (def->bandwidth)
        virNetDevBandwidthFormat(def->bandwidth, def->class_id, buf);
    if (virNetDevVlanFormat(&def->vlan, buf) < 0)
        return -1;
    virNetworkPortOptionsFormat(def->isolatedPort, buf);
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, "<rxfilters trustGuest='%s'/>\n",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));

    if (def->plugtype != VIR_NETWORK_PORT_PLUG_TYPE_NONE) {
        virBufferAsprintf(buf, "<plug type='%s'",
                          virNetworkPortPlugTypeToString(def->plugtype));

        switch (def->plugtype) {
        case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
            break;

        case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
        case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
            virBufferEscapeString(buf, " bridge='%s'", def->plug.bridge.brname);
            if (def->plug.bridge.macTableManager)
                virBufferAsprintf(buf, " macTableManager='%s'",
                                  virNetworkBridgeMACTableManagerTypeToString(
                                      def->plug.bridge.macTableManager));
            virBufferAddLit(buf, "/>\n");
            break;

        case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
            virBufferEscapeString(buf, " dev='%s'", def->plug.direct.linkdev);
            virBufferAsprintf(buf, " mode='%s'",
                              virNetDevMacVLanModeTypeToString(
                                  def->plug.direct.mode));
            virBufferAddLit(buf, "/>\n");
            break;

        case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
            if (def->plug.hostdevpci.managed) {
                virBufferAsprintf(buf, " managed='%s'",
                                  virTristateBoolTypeToString(def->plug.hostdevpci.managed));
            }
            virBufferAddLit(buf, ">\n");
            virBufferAdjustIndent(buf, 2);
            if (def->plug.hostdevpci.driver)
                virBufferEscapeString(buf, "<driver name='%s'/>\n",
                                      virNetworkForwardDriverNameTypeToString(
                                          def->plug.hostdevpci.driver));

            virPCIDeviceAddressFormat(buf, def->plug.hostdevpci.addr, false);
            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</plug>\n");
            break;

        case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
        default:
            virReportEnumRangeError(virNetworkPortPlugType, def->plugtype);
            return -1;
        }
    }


    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</networkport>\n");

    return 0;
}


static char *
virNetworkPortDefConfigFile(const char *dir,
                            const char *name)
{
    return g_strdup_printf("%s/%s.xml", dir, name);
}


int
virNetworkPortDefSaveStatus(virNetworkPortDef *def,
                            const char *dir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *path = NULL;
    g_autofree char *xml = NULL;

    virUUIDFormat(def->uuid, uuidstr);

    if (g_mkdir_with_parents(dir, 0777) < 0)
        return -1;

    if (!(path = virNetworkPortDefConfigFile(dir, uuidstr)))
        return -1;

    if (!(xml = virNetworkPortDefFormat(def)))
        return -1;

    if (virXMLSaveFile(path, uuidstr, "net-port-create", xml) < 0)
        return -1;

    return 0;
}


int
virNetworkPortDefDeleteStatus(virNetworkPortDef *def,
                              const char *dir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *path = NULL;

    virUUIDFormat(def->uuid, uuidstr);

    if (!(path = virNetworkPortDefConfigFile(dir, uuidstr)))
        return -1;

    if (unlink(path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete %1$s"), path);
        return -1;
    }

    return 0;
}
