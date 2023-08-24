/*
 * storage_adapter_conf.c: helpers to handle storage pool adapter manipulation
 *                         (derived from storage_conf.c)
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

#include "storage_conf.h"

#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virutil.h"
#include "virxml.h"

#define VIR_FROM_THIS VIR_FROM_STORAGE

VIR_LOG_INIT("conf.storage_adapter_conf");

VIR_ENUM_IMPL(virStorageAdapter,
              VIR_STORAGE_ADAPTER_TYPE_LAST,
              "default", "scsi_host", "fc_host",
);

static void
virStorageAdapterClearFCHost(virStorageAdapterFCHost *fchost)
{
    VIR_FREE(fchost->wwnn);
    VIR_FREE(fchost->wwpn);
    VIR_FREE(fchost->parent);
    VIR_FREE(fchost->parent_wwnn);
    VIR_FREE(fchost->parent_wwpn);
    VIR_FREE(fchost->parent_fabric_wwn);
}


void
virStorageAdapterClear(virStorageAdapter *adapter)
{
    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        virStorageAdapterClearFCHost(&adapter->data.fchost);

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST)
        VIR_FREE(adapter->data.scsi_host.name);
}


static int
virStorageAdapterParseXMLFCHost(xmlNodePtr node,
                                virStorageAdapterFCHost *fchost)
{
    if (virXMLPropTristateBool(node, "managed", VIR_XML_PROP_NONE,
                               &fchost->managed) < 0)
        return -1;

    fchost->parent = virXMLPropString(node, "parent");
    fchost->parent_wwnn = virXMLPropString(node, "parent_wwnn");
    fchost->parent_wwpn = virXMLPropString(node, "parent_wwpn");
    fchost->parent_fabric_wwn = virXMLPropString(node, "parent_fabric_wwn");
    fchost->wwpn = virXMLPropString(node, "wwpn");
    fchost->wwnn = virXMLPropString(node, "wwnn");

    return 0;
}


static int
virStorageAdapterParseXMLSCSIHost(xmlNodePtr node,
                                  xmlXPathContextPtr ctxt,
                                  virStorageAdapterSCSIHost *scsi_host)
{
    scsi_host->name = virXMLPropString(node, "name");
    if (virXPathNode("./parentaddr", ctxt)) {
        xmlNodePtr addrnode = virXPathNode("./parentaddr/address", ctxt);

        if (!addrnode) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing scsi_host PCI address element"));
            return -1;
        }
        scsi_host->has_parent = true;
        if (virPCIDeviceAddressParseXML(addrnode, &scsi_host->parentaddr) < 0)
            return -1;
        if ((virXPathInt("string(./parentaddr/@unique_id)",
                         ctxt,
                         &scsi_host->unique_id) < 0) ||
            (scsi_host->unique_id < 0)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Missing or invalid scsi adapter 'unique_id' value"));
            return -1;
        }
    }

    return 0;
}


/* Prior to adding 'type' attribute support all that was supported was a
 * 'name' attribute which designated which 'scsi_hostN' name was to be used.
 * This was proven to not be stable enough especially between reboots, so
 * future patches added other attributes (type, wwnn, wwpn, parent, etc.)
 * that would provide the capability to designate a more specific scsi_hostN
 * by more than just name. The 'type' attribute was the key to determine
 * whether a SCSI or FC host was to be used.
 *
 * This code will parse this "older" (or legacy) XML that only had the name
 * attribute. If other newer attributes are found, then a failure will
 * be generated so as to force usage of the 'type' attribute.
 */
static int
virStorageAdapterParseXMLLegacy(xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virStorageAdapter *adapter)
{
    char *wwnn = virXMLPropString(node, "wwnn");
    char *wwpn = virXMLPropString(node, "wwpn");
    char *parent = virXMLPropString(node, "parent");

    /* "type" was not specified in the XML, so we must verify that
     * "wwnn", "wwpn", "parent", or "parentaddr" are also not in the
     * XML. If any are found, then we cannot just use "name" alone".
     */
    if (wwnn || wwpn || parent) {
        VIR_FREE(wwnn);
        VIR_FREE(wwpn);
        VIR_FREE(parent);
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Use of 'wwnn', 'wwpn', and 'parent' attributes requires use of the adapter 'type'"));
        return -1;
    }

    if (virXPathNode("./parentaddr", ctxt)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Use of 'parentaddr' element requires use of the adapter 'type'"));
        return -1;
    }

    /* To keep back-compat, 'type' is not required to specify
     * for scsi_host adapter.
     */
    if ((adapter->data.scsi_host.name = virXMLPropString(node, "name")))
        adapter->type = VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST;

    return 0;
}


int
virStorageAdapterParseXML(virStorageAdapter *adapter,
                          xmlNodePtr node,
                          xmlXPathContextPtr ctxt)
{
    int type;
    VIR_XPATH_NODE_AUTORESTORE(ctxt)

    ctxt->node = node;

    if ((type = virXMLPropEnum(node, "type",
                               virStorageAdapterTypeFromString,
                               VIR_XML_PROP_NONZERO, &adapter->type)) < 0)
        return -1;

    if (type == 0)
        return virStorageAdapterParseXMLLegacy(node, ctxt, adapter);

    if ((adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST) &&
        (virStorageAdapterParseXMLFCHost(node, &adapter->data.fchost)) < 0)
        return -1;

    if ((adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST) &&
        (virStorageAdapterParseXMLSCSIHost(node, ctxt,
                                           &adapter->data.scsi_host)) < 0)
        return -1;

    return 0;
}


static int
virStorageAdapterValidateFCHost(virStorageAdapterFCHost *fchost)
{
    if (!fchost->wwnn || !fchost->wwpn) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("'wwnn' and 'wwpn' must be specified for adapter type 'fchost'"));
        return -1;
    }

    if (!virValidateWWN(fchost->wwnn) || !virValidateWWN(fchost->wwpn))
        return -1;

    if ((fchost->parent_wwnn && !fchost->parent_wwpn)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("when providing parent_wwnn='%1$s', the parent_wwpn must also be provided"),
                       fchost->parent_wwnn);
        return -1;
    }

    if (!fchost->parent_wwnn && fchost->parent_wwpn) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("when providing parent_wwpn='%1$s', the parent_wwnn must also be provided"),
                       fchost->parent_wwpn);
        return -1;
    }

    if (fchost->parent_wwnn && !virValidateWWN(fchost->parent_wwnn))
        return -1;

    if (fchost->parent_wwpn && !virValidateWWN(fchost->parent_wwpn))
        return -1;

    if (fchost->parent_fabric_wwn && !virValidateWWN(fchost->parent_fabric_wwn))
        return -1;

    return 0;
}


static int
virStorageAdapterValidateSCSIHost(virStorageAdapterSCSIHost *scsi_host)
{
    if (!scsi_host->name && !scsi_host->has_parent) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Either 'name' or 'parent' must be specified for the 'scsi_host' adapter"));
        return -1;
    }

    if (scsi_host->name && scsi_host->has_parent) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Both 'name' and 'parent' cannot be specified for the 'scsi_host' adapter"));
        return -1;
    }

    return 0;
}


int
virStorageAdapterValidate(virStorageAdapter *adapter)
{
    if (!adapter->type) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing storage pool source adapter"));
        return -1;
    }

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        return virStorageAdapterValidateFCHost(&adapter->data.fchost);

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST)
        return virStorageAdapterValidateSCSIHost(&adapter->data.scsi_host);

    return 0;
}


static void
virStorageAdapterFormatFCHost(virBuffer *buf,
                              virStorageAdapterFCHost *fchost)
{
    virBufferEscapeString(buf, " parent='%s'", fchost->parent);
    virBufferEscapeString(buf, " parent_wwnn='%s'", fchost->parent_wwnn);
    virBufferEscapeString(buf, " parent_wwpn='%s'", fchost->parent_wwpn);
    virBufferEscapeString(buf, " parent_fabric_wwn='%s'",
                          fchost->parent_fabric_wwn);
    if (fchost->managed != VIR_TRISTATE_BOOL_ABSENT)
        virBufferAsprintf(buf, " managed='%s'",
                          virTristateBoolTypeToString(fchost->managed));

    virBufferAsprintf(buf, " wwnn='%s' wwpn='%s'/>\n",
                      fchost->wwnn, fchost->wwpn);
}


static void
virStorageAdapterFormatSCSIHost(virBuffer *buf,
                                virStorageAdapterSCSIHost *scsi_host)
{
    if (scsi_host->name) {
        virBufferAsprintf(buf, " name='%s'/>\n", scsi_host->name);
    } else {
        virBufferAddLit(buf, ">\n");
        virBufferAdjustIndent(buf, 2);
        virBufferAsprintf(buf, "<parentaddr unique_id='%d'>\n",
                          scsi_host->unique_id);
        virBufferAdjustIndent(buf, 2);
        virPCIDeviceAddressFormat(buf, scsi_host->parentaddr,
                                  false);
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</parentaddr>\n");
        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</adapter>\n");
    }
}


void
virStorageAdapterFormat(virBuffer *buf,
                        virStorageAdapter *adapter)
{
    virBufferAsprintf(buf, "<adapter type='%s'",
                      virStorageAdapterTypeToString(adapter->type));

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_FC_HOST)
        virStorageAdapterFormatFCHost(buf, &adapter->data.fchost);

    if (adapter->type == VIR_STORAGE_ADAPTER_TYPE_SCSI_HOST)
        virStorageAdapterFormatSCSIHost(buf, &adapter->data.scsi_host);
}
