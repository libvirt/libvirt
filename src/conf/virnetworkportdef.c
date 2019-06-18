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

#include "viralloc.h"
#include "virerror.h"
#include "virstring.h"
#include "virfile.h"
#include "virnetworkportdef.h"
#include "network_conf.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_ENUM_IMPL(virNetworkPortPlug,
              VIR_NETWORK_PORT_PLUG_TYPE_LAST,
              "none", "network", "bridge", "direct", "hostdev-pci");

void
virNetworkPortDefFree(virNetworkPortDefPtr def)
{
    if (!def)
        return;

    VIR_FREE(def->ownername);
    VIR_FREE(def->group);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    VIR_FREE(def->virtPortProfile);

    switch ((virNetworkPortPlugType)def->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        VIR_FREE(def->plug.bridge.brname);
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        VIR_FREE(def->plug.direct.linkdev);
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        break;
    }

    VIR_FREE(def);
}



static virNetworkPortDefPtr
virNetworkPortDefParseXML(xmlXPathContextPtr ctxt)
{
    virNetworkPortDefPtr def;
    VIR_AUTOFREE(char *) uuid = NULL;
    xmlNodePtr virtPortNode;
    xmlNodePtr vlanNode;
    xmlNodePtr bandwidthNode;
    xmlNodePtr addressNode;
    VIR_AUTOFREE(char *) trustGuestRxFilters = NULL;
    VIR_AUTOFREE(char *) mac = NULL;
    VIR_AUTOFREE(char *) macmgr = NULL;
    VIR_AUTOFREE(char *) mode = NULL;
    VIR_AUTOFREE(char *) plugtype = NULL;
    VIR_AUTOFREE(char *) managed = NULL;
    VIR_AUTOFREE(char *) driver = NULL;
    VIR_AUTOFREE(char *) class_id = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    uuid = virXPathString("string(./uuid)", ctxt);
    if (!uuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no uuid"));
        goto error;
    }
    if (virUUIDParse(uuid, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse UUID '%s'"), uuid);
        goto error;
    }

    def->ownername = virXPathString("string(./owner/name)", ctxt);
    if (!def->ownername) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no owner name"));
        goto error;
    }

    VIR_FREE(uuid);
    uuid = virXPathString("string(./owner/uuid)", ctxt);
    if (!uuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no owner UUID"));
        goto error;
    }

    if (virUUIDParse(uuid, def->owneruuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse UUID '%s'"), uuid);
        goto error;
    }

    def->group = virXPathString("string(./group)", ctxt);

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode, 0)))) {
        goto error;
    }

    mac = virXPathString("string(./mac/@address)", ctxt);
    if (!mac) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("network port has no mac"));
        goto error;
    }
    if (virMacAddrParse(mac, &def->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse MAC '%s'"), mac);
        goto error;
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
        goto error;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto error;


    trustGuestRxFilters
        = virXPathString("string(./rxfilters/@trustGuest)", ctxt);
    if (trustGuestRxFilters) {
        if ((def->trustGuestRxFilters
             = virTristateBoolTypeFromString(trustGuestRxFilters)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid guest rx filters trust setting '%s' "),
                           trustGuestRxFilters);
            goto error;
        }
    }

    plugtype = virXPathString("string(./plug/@type)", ctxt);

    if (plugtype &&
        (def->plugtype = virNetworkPortPlugTypeFromString(plugtype)) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid network prt plug type '%s'"), plugtype);
    }

    switch (def->plugtype) {
    case VIR_NETWORK_PORT_PLUG_TYPE_NONE:
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_NETWORK:
    case VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE:
        if (!(def->plug.bridge.brname = virXPathString("string(./plug/@bridge)", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port bridge name"));
            goto error;
        }
        macmgr = virXPathString("string(./plug/@macTableManager)", ctxt);
        if (macmgr &&
            (def->plug.bridge.macTableManager =
             virNetworkBridgeMACTableManagerTypeFromString(macmgr)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid macTableManager setting '%s' "
                             "in network port"), macmgr);
            goto error;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_DIRECT:
        if (!(def->plug.direct.linkdev = virXPathString("string(./plug/@dev)", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port link device name"));
            goto error;
        }
        mode = virXPathString("string(./plug/@mode)", ctxt);
        if (mode &&
            (def->plug.direct.mode =
             virNetDevMacVLanModeTypeFromString(mode)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid mode setting '%s' in network port"), mode);
            goto error;
        }
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI:
        managed = virXPathString("string(./plug/@managed)", ctxt);
        if (managed &&
            (def->plug.hostdevpci.managed =
             virTristateBoolTypeFromString(managed)) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid managed setting '%s' in network port"), mode);
            goto error;
        }
        driver = virXPathString("string(./plug/driver/@name)", ctxt);
        if (driver &&
            (def->plug.hostdevpci.driver =
             virNetworkForwardDriverNameTypeFromString(driver)) <= 0) {
              virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port driver name"));
            goto error;
        }
        if (!(addressNode = virXPathNode("./plug/address", ctxt))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing network port PCI address"));
            goto error;
        }

        if (virPCIDeviceAddressParseXML(addressNode, &def->plug.hostdevpci.addr) < 0)
            goto error;
        break;

    case VIR_NETWORK_PORT_PLUG_TYPE_LAST:
    default:
        virReportEnumRangeError(virNetworkPortPlugType, def->plugtype);
        goto error;
    }

 cleanup:
    return def;

 error:
    virNetworkPortDefFree(def);
    def = NULL;
    goto cleanup;
}


virNetworkPortDefPtr
virNetworkPortDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNetworkPortDefPtr def = NULL;

    if (STRNEQ((const char *)root->name, "networkport")) {
        virReportError(VIR_ERR_XML_ERROR,
                       "%s",
                       _("unknown root element for network port"));
        goto cleanup;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virNetworkPortDefParseXML(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


static virNetworkPortDefPtr
virNetworkPortDefParse(const char *xmlStr,
                       const char *filename)
{
    virNetworkPortDefPtr def = NULL;
    xmlDocPtr xml;

    if ((xml = virXMLParse(filename, xmlStr, _("(networkport_definition)")))) {
        def = virNetworkPortDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    return def;
}


virNetworkPortDefPtr
virNetworkPortDefParseString(const char *xmlStr)
{
    return virNetworkPortDefParse(xmlStr, NULL);
}


virNetworkPortDefPtr
virNetworkPortDefParseFile(const char *filename)
{
    return virNetworkPortDefParse(NULL, filename);
}


char *
virNetworkPortDefFormat(const virNetworkPortDef *def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virNetworkPortDefFormatBuf(&buf, def) < 0) {
        virBufferFreeAndReset(&buf);
        return NULL;
    }

    if (virBufferCheckError(&buf) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


int
virNetworkPortDefFormatBuf(virBufferPtr buf,
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
            virBufferAsprintf(buf, " managed='%s'>\n",
                              def->plug.hostdevpci.managed ? "yes" : "no");
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
    char *ret = NULL;

    ignore_value(virAsprintf(&ret, "%s/%s.xml", dir, name));
    return ret;
}


int
virNetworkPortDefSaveStatus(virNetworkPortDef *def,
                            const char *dir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *path;
    char *xml = NULL;
    int ret = -1;

    virUUIDFormat(def->uuid, uuidstr);

    if (virFileMakePath(dir) < 0)
        goto cleanup;

    if (!(path = virNetworkPortDefConfigFile(dir, uuidstr)))
        goto cleanup;

    if (!(xml = virNetworkPortDefFormat(def)))
        goto cleanup;

    if (virXMLSaveFile(path, uuidstr, "net-port-create", xml) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    VIR_FREE(path);
    return ret;
}


int
virNetworkPortDefDeleteStatus(virNetworkPortDef *def,
                              const char *dir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *path;
    int ret = -1;

    virUUIDFormat(def->uuid, uuidstr);

    if (!(path = virNetworkPortDefConfigFile(dir, uuidstr)))
        goto cleanup;

    if (unlink(path) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete %s"), path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    return ret;
}
