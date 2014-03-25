/*
 * Copyright (C) 2009-2014 Red Hat, Inc.
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "netdev_vport_profile_conf.h"
#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE


virNetDevVPortProfilePtr
virNetDevVPortProfileParse(xmlNodePtr node, unsigned int flags)
{
    char *virtPortType;
    char *virtPortManagerID = NULL;
    char *virtPortTypeID = NULL;
    char *virtPortTypeIDVersion = NULL;
    char *virtPortInstanceID = NULL;
    char *virtPortProfileID = NULL;
    char *virtPortInterfaceID = NULL;
    virNetDevVPortProfilePtr virtPort = NULL;
    xmlNodePtr cur = node->children;

    if (VIR_ALLOC(virtPort) < 0)
        return NULL;

    if ((virtPortType = virXMLPropString(node, "type")) &&
        (virtPort->virtPortType = virNetDevVPortTypeFromString(virtPortType)) <= 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unknown virtualport type %s"), virtPortType);
        goto error;
    }

    if ((virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_NONE) &&
        (flags & VIR_VPORT_XML_REQUIRE_TYPE)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing required virtualport type"));
        goto error;
    }

    while (cur != NULL) {
        if (xmlStrEqual(cur->name, BAD_CAST "parameters")) {
            virtPortManagerID = virXMLPropString(cur, "managerid");
            virtPortTypeID = virXMLPropString(cur, "typeid");
            virtPortTypeIDVersion = virXMLPropString(cur, "typeidversion");
            virtPortInstanceID = virXMLPropString(cur, "instanceid");
            virtPortProfileID = virXMLPropString(cur, "profileid");
            virtPortInterfaceID = virXMLPropString(cur, "interfaceid");
            break;
        }
        cur = cur->next;
    }

    if (virtPortManagerID) {
        unsigned int val;

        if (virStrToLong_ui(virtPortManagerID, NULL, 0, &val)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot parse value of managerid parameter"));
            goto error;
        }
        if (val > 0xff) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("value of managerid out of range"));
            goto error;
        }
        virtPort->managerID = (uint8_t)val;
        virtPort->managerID_specified = true;
    }

    if (virtPortTypeID) {
        unsigned int val;

        if (virStrToLong_ui(virtPortTypeID, NULL, 0, &val)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot parse value of typeid parameter"));
            goto error;
        }
        if (val > 0xffffff) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("value for typeid out of range"));
            goto error;
        }
        virtPort->typeID = (uint32_t)val;
        virtPort->typeID_specified = true;
    }

    if (virtPortTypeIDVersion) {
        unsigned int val;

        if (virStrToLong_ui(virtPortTypeIDVersion, NULL, 0, &val)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot parse value of typeidversion parameter"));
            goto error;
        }
        if (val > 0xff) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("value of typeidversion out of range"));
            goto error;
        }
        virtPort->typeIDVersion = (uint8_t)val;
        virtPort->typeIDVersion_specified = true;
    }

    if (virtPortInstanceID) {
        if (virUUIDParse(virtPortInstanceID, virtPort->instanceID) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot parse instanceid parameter as a uuid"));
            goto error;
        }
        virtPort->instanceID_specified = true;
    }

    if (virtPortProfileID &&
        !virStrcpyStatic(virtPort->profileID, virtPortProfileID)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("profileid parameter too long"));
        goto error;
    }

    if (virtPortInterfaceID) {
        if (virUUIDParse(virtPortInterfaceID, virtPort->interfaceID) < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("cannot parse interfaceid parameter as a uuid"));
            goto error;
        }
        virtPort->interfaceID_specified = true;
    }

    /* generate default instanceID/interfaceID if appropriate */
    if (flags & VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS) {
        if (!virtPort->instanceID_specified &&
            (virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_8021QBG ||
             virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_NONE)) {
            if (virUUIDGenerate(virtPort->instanceID) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot generate a random uuid for instanceid"));
                goto error;
            }
            virtPort->instanceID_specified = true;
        }
        if (!virtPort->interfaceID_specified &&
            (virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH ||
             virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_NONE)) {
            if (virUUIDGenerate(virtPort->interfaceID) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot generate a random uuid for interfaceid"));
                goto error;
            }
            virtPort->interfaceID_specified = true;
        }
    }

    /* check for required/unsupported attributes */

    if ((flags & VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES) &&
        (virNetDevVPortProfileCheckComplete(virtPort, false) < 0)) {
        goto error;
    }

    if (virNetDevVPortProfileCheckNoExtras(virtPort) < 0)
        goto error;

 cleanup:
    VIR_FREE(virtPortManagerID);
    VIR_FREE(virtPortTypeID);
    VIR_FREE(virtPortTypeIDVersion);
    VIR_FREE(virtPortInstanceID);
    VIR_FREE(virtPortProfileID);
    VIR_FREE(virtPortType);
    VIR_FREE(virtPortInterfaceID);

    return virtPort;

 error:
    VIR_FREE(virtPort);
    goto cleanup;
}


int
virNetDevVPortProfileFormat(virNetDevVPortProfilePtr virtPort,
                            virBufferPtr buf)
{
    enum virNetDevVPortProfile type;
    bool noParameters;

    if (!virtPort)
        return 0;

    noParameters = !(virtPort->managerID_specified ||
                     virtPort->typeID_specified ||
                     virtPort->typeIDVersion_specified ||
                     virtPort->instanceID_specified ||
                     virtPort->profileID[0] ||
                     virtPort->interfaceID_specified);

    type = virtPort->virtPortType;
    if (type == VIR_NETDEV_VPORT_PROFILE_NONE) {
        if (noParameters)
            return 0;
        virBufferAddLit(buf, "<virtualport>\n");
    } else {
        if (noParameters) {
            virBufferAsprintf(buf, "<virtualport type='%s'/>\n",
                              virNetDevVPortTypeToString(type));
            return 0;
        } else {
            virBufferAsprintf(buf, "<virtualport type='%s'>\n",
                              virNetDevVPortTypeToString(type));
        }
    }
    virBufferAdjustIndent(buf, 2);
    virBufferAddLit(buf, "<parameters");

    if (virtPort->managerID_specified &&
        (type == VIR_NETDEV_VPORT_PROFILE_8021QBG ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        virBufferAsprintf(buf, " managerid='%d'", virtPort->managerID);
    }
    if (virtPort->typeID_specified &&
        (type == VIR_NETDEV_VPORT_PROFILE_8021QBG ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        virBufferAsprintf(buf, " typeid='%d'", virtPort->typeID);
    }
    if (virtPort->typeIDVersion_specified &&
        (type == VIR_NETDEV_VPORT_PROFILE_8021QBG ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        virBufferAsprintf(buf, " typeidversion='%d'",
                          virtPort->typeIDVersion);
    }
    if (virtPort->instanceID_specified &&
        (type == VIR_NETDEV_VPORT_PROFILE_8021QBG ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(virtPort->instanceID, uuidstr);
        virBufferAsprintf(buf, " instanceid='%s'", uuidstr);
    }
    if (virtPort->interfaceID_specified &&
        (type == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        char uuidstr[VIR_UUID_STRING_BUFLEN];

        virUUIDFormat(virtPort->interfaceID, uuidstr);
        virBufferAsprintf(buf, " interfaceid='%s'", uuidstr);
    }
    if (virtPort->profileID[0] &&
        (type == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH ||
         type == VIR_NETDEV_VPORT_PROFILE_8021QBH ||
         type == VIR_NETDEV_VPORT_PROFILE_NONE)) {
        virBufferAsprintf(buf, " profileid='%s'", virtPort->profileID);
    }

    virBufferAddLit(buf, "/>\n");
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</virtualport>\n");
    return 0;
}
