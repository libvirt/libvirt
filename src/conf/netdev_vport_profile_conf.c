/*
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "netdev_vport_profile_conf.h"
#include "virterror_internal.h"
#include "memory.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define virNetDevError(code, ...)                                       \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                 \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


VIR_ENUM_IMPL(virNetDevVPort, VIR_NETDEV_VPORT_PROFILE_LAST,
              "none",
              "802.1Qbg",
              "802.1Qbh",
              "openvswitch")


virNetDevVPortProfilePtr
virNetDevVPortProfileParse(xmlNodePtr node)
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

    if (VIR_ALLOC(virtPort) < 0) {
        virReportOOMError();
        return NULL;
    }

    virtPortType = virXMLPropString(node, "type");
    if (!virtPortType) {
        virNetDevError(VIR_ERR_XML_ERROR, "%s",
                       _("missing virtualportprofile type"));
        goto error;
    }

    if ((virtPort->virtPortType = virNetDevVPortTypeFromString(virtPortType)) <= 0) {
        virNetDevError(VIR_ERR_XML_ERROR,
                       _("unknown virtualportprofile type %s"), virtPortType);
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

    switch (virtPort->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        if (virtPortManagerID     != NULL && virtPortTypeID     != NULL &&
            virtPortTypeIDVersion != NULL) {
            unsigned int val;

            if (virStrToLong_ui(virtPortManagerID, NULL, 0, &val)) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of managerid parameter"));
                goto error;
            }

            if (val > 0xff) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("value of managerid out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.managerID = (uint8_t)val;

            if (virStrToLong_ui(virtPortTypeID, NULL, 0, &val)) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of typeid parameter"));
                goto error;
            }

            if (val > 0xffffff) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("value for typeid out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.typeID = (uint32_t)val;

            if (virStrToLong_ui(virtPortTypeIDVersion, NULL, 0, &val)) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("cannot parse value of typeidversion parameter"));
                goto error;
            }

            if (val > 0xff) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("value of typeidversion out of range"));
                goto error;
            }

            virtPort->u.virtPort8021Qbg.typeIDVersion = (uint8_t)val;

            if (virtPortInstanceID != NULL) {
                if (virUUIDParse(virtPortInstanceID,
                                 virtPort->u.virtPort8021Qbg.instanceID)) {
                    virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                         _("cannot parse instanceid parameter as a uuid"));
                    goto error;
                }
            } else {
                if (virUUIDGenerate(virtPort->u.virtPort8021Qbg.instanceID)) {
                    virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                         _("cannot generate a random uuid for instanceid"));
                    goto error;
                }
            }

            virtPort->virtPortType = VIR_NETDEV_VPORT_PROFILE_8021QBG;

        } else {
                    virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                         _("a parameter is missing for 802.1Qbg description"));
            goto error;
        }
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        if (virtPortProfileID != NULL) {
            if (virStrcpyStatic(virtPort->u.virtPort8021Qbh.profileID,
                                virtPortProfileID) != NULL) {
                virtPort->virtPortType = VIR_NETDEV_VPORT_PROFILE_8021QBH;
            } else {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                     _("profileid parameter too long"));
                goto error;
            }
        } else {
            virNetDevError(VIR_ERR_XML_ERROR, "%s",
                                 _("profileid parameter is missing for 802.1Qbh description"));
            goto error;
        }
        break;
    case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
        if (virtPortInterfaceID != NULL) {
            if (virUUIDParse(virtPortInterfaceID,
                             virtPort->u.openvswitch.interfaceID)) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                               _("cannot parse interfaceid parameter as a uuid"));
                goto error;
            }
        } else {
            if (virUUIDGenerate(virtPort->u.openvswitch.interfaceID)) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                               _("cannot generate a random uuid for interfaceid"));
                goto error;
            }
        }
        /* profileid is not mandatory for Open vSwitch */
        if (virtPortProfileID != NULL) {
            if (virStrcpyStatic(virtPort->u.openvswitch.profileID,
                                virtPortProfileID) == NULL) {
                virNetDevError(VIR_ERR_XML_ERROR, "%s",
                               _("profileid parameter too long"));
                goto error;
            }
        } else {
            virtPort->u.openvswitch.profileID[0] = '\0';
        }
        break;

    default:
        virNetDevError(VIR_ERR_XML_ERROR,
                       _("unexpected virtualport type %d"), virtPort->virtPortType);
        goto error;
    }

cleanup:
    VIR_FREE(virtPortManagerID);
    VIR_FREE(virtPortTypeID);
    VIR_FREE(virtPortTypeIDVersion);
    VIR_FREE(virtPortInstanceID);
    VIR_FREE(virtPortProfileID);
    VIR_FREE(virtPortType);

    return virtPort;

error:
    VIR_FREE(virtPort);
    goto cleanup;
}


int
virNetDevVPortProfileFormat(virNetDevVPortProfilePtr virtPort,
                            virBufferPtr buf)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!virtPort || virtPort->virtPortType == VIR_NETDEV_VPORT_PROFILE_NONE)
        return 0;

    virBufferAsprintf(buf, "<virtualport type='%s'>\n",
                      virNetDevVPortTypeToString(virtPort->virtPortType));

    switch (virtPort->virtPortType) {
    case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        virUUIDFormat(virtPort->u.virtPort8021Qbg.instanceID,
                      uuidstr);
        virBufferAsprintf(buf,
                          "  <parameters managerid='%d' typeid='%d' "
                          "typeidversion='%d' instanceid='%s'/>\n",
                          virtPort->u.virtPort8021Qbg.managerID,
                          virtPort->u.virtPort8021Qbg.typeID,
                          virtPort->u.virtPort8021Qbg.typeIDVersion,
                          uuidstr);
        break;

    case VIR_NETDEV_VPORT_PROFILE_8021QBH:
        virBufferAsprintf(buf,
                          "  <parameters profileid='%s'/>\n",
                          virtPort->u.virtPort8021Qbh.profileID);
        break;

    case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
        virUUIDFormat(virtPort->u.openvswitch.interfaceID,
                      uuidstr);
        if (virtPort->u.openvswitch.profileID[0] == '\0') {
            virBufferAsprintf(buf, "  <parameters interfaceid='%s'/>\n",
                              uuidstr);
        } else {
            virBufferAsprintf(buf, "  <parameters interfaceid='%s' "
                              "profileid='%s'/>\n", uuidstr,
                              virtPort->u.openvswitch.profileID);
        }

        break;

    default:
        virNetDevError(VIR_ERR_XML_ERROR,
                       _("unexpected virtualport type %d"), virtPort->virtPortType);
        return -1;
    }

    virBufferAddLit(buf, "</virtualport>\n");
    return 0;
}
