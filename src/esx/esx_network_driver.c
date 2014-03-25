/*
 * esx_network_driver.c: network driver functions for managing VMware ESX
 *                       host networks
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright (C) 2010-2012 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#include <config.h>

#include "md5.h"
#include "internal.h"
#include "viralloc.h"
#include "viruuid.h"
#include "network_conf.h"
#include "esx_private.h"
#include "esx_network_driver.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * The UUID of a network is the MD5 sum of it's key. Therefore, verify that
 * UUID and MD5 sum match in size, because we rely on that.
 */
verify(MD5_DIGEST_SIZE == VIR_UUID_BUFLEN);



static virDrvOpenStatus
esxNetworkOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (conn->driver->no != VIR_DRV_ESX) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->networkPrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
esxNetworkClose(virConnectPtr conn)
{
    conn->networkPrivateData = NULL;

    return 0;
}



static int
esxConnectNumOfNetworks(virConnectPtr conn)
{
    esxPrivate *priv = conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitchList = NULL;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    int count = 0;

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupHostVirtualSwitchList(priv->primary,
                                          &hostVirtualSwitchList) < 0) {
        return -1;
    }

    for (hostVirtualSwitch = hostVirtualSwitchList; hostVirtualSwitch;
         hostVirtualSwitch = hostVirtualSwitch->_next) {
        ++count;
    }

    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitchList);

    return count;
}



static int
esxConnectListNetworks(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitchList = NULL;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    int count = 0;
    size_t i;

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupHostVirtualSwitchList(priv->primary,
                                          &hostVirtualSwitchList) < 0) {
        return -1;
    }

    for (hostVirtualSwitch = hostVirtualSwitchList; hostVirtualSwitch;
         hostVirtualSwitch = hostVirtualSwitch->_next) {
        if (VIR_STRDUP(names[count], hostVirtualSwitch->name) < 0)
            goto cleanup;

        ++count;
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i) {
            VIR_FREE(names[i]);
        }

        count = -1;
    }

    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitchList);

    return count;
}



static int
esxConnectNumOfDefinedNetworks(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* ESX networks are always active */
    return 0;
}



static int
esxConnectListDefinedNetworks(virConnectPtr conn ATTRIBUTE_UNUSED,
                              char **const names ATTRIBUTE_UNUSED,
                              int maxnames ATTRIBUTE_UNUSED)
{
    /* ESX networks are always active */
    return 0;
}



static virNetworkPtr
esxNetworkLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    virNetworkPtr network = NULL;
    esxPrivate *priv = conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitchList = NULL;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    unsigned char md5[MD5_DIGEST_SIZE]; /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupHostVirtualSwitchList(priv->primary,
                                          &hostVirtualSwitchList) < 0) {
        return NULL;
    }

    for (hostVirtualSwitch = hostVirtualSwitchList; hostVirtualSwitch;
         hostVirtualSwitch = hostVirtualSwitch->_next) {
        md5_buffer(hostVirtualSwitch->key, strlen(hostVirtualSwitch->key), md5);

        if (memcmp(uuid, md5, VIR_UUID_BUFLEN) == 0) {
            break;
        }
    }

    if (!hostVirtualSwitch) {
        virUUIDFormat(uuid, uuid_string);

        virReportError(VIR_ERR_NO_NETWORK,
                       _("Could not find HostVirtualSwitch with UUID '%s'"),
                       uuid_string);

        goto cleanup;
    }

    network = virGetNetwork(conn, hostVirtualSwitch->name, uuid);

 cleanup:
    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitchList);

    return network;
}



static virNetworkPtr
esxNetworkLookupByName(virConnectPtr conn, const char *name)
{
    virNetworkPtr network = NULL;
    esxPrivate *priv = conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    unsigned char md5[MD5_DIGEST_SIZE]; /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */

    if (esxVI_EnsureSession(priv->primary) < 0 ||
        esxVI_LookupHostVirtualSwitchByName(priv->primary, name,
                                            &hostVirtualSwitch,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        return NULL;
    }

    /*
     * HostVirtualSwitch doesn't have a UUID, but we can use the key property
     * as source for a UUID. The key is unique per host and cannot change
     * during the lifetime of the HostVirtualSwitch.
     *
     * The MD5 sum of the key can be used as UUID, assuming MD5 is considered
     * to be collision-free enough for this use case.
     */
    md5_buffer(hostVirtualSwitch->key, strlen(hostVirtualSwitch->key), md5);

    network = virGetNetwork(conn, hostVirtualSwitch->name, md5);

    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitch);

    return network;
}



static int
esxBandwidthToShapingPolicy(virNetDevBandwidthPtr bandwidth,
                            esxVI_HostNetworkTrafficShapingPolicy **shapingPolicy)
{
    int result = -1;

    if (!shapingPolicy || *shapingPolicy) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!bandwidth->in || !bandwidth->out ||
        bandwidth->in->average != bandwidth->out->average ||
        bandwidth->in->peak != bandwidth->out->peak ||
        bandwidth->in->burst != bandwidth->out->burst) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Different inbound and outbound bandwidth is unsupported"));
        return -1;
    }

    if (bandwidth->in->average == 0 && bandwidth->in->peak == 0 &&
        bandwidth->in->burst == 0) {
        return 0;
    }

    if (esxVI_HostNetworkTrafficShapingPolicy_Alloc(shapingPolicy) < 0) {
        goto cleanup;
    }

    (*shapingPolicy)->enabled = esxVI_Boolean_True;

    if (bandwidth->in->average > 0) {
        if (esxVI_Long_Alloc(&(*shapingPolicy)->averageBandwidth) < 0) {
            goto cleanup;
        }

        /* Scale kilobytes per second to bits per second */
        (*shapingPolicy)->averageBandwidth->value = bandwidth->in->average * 8 * 1000;
    }

    if (bandwidth->in->peak > 0) {
        if (esxVI_Long_Alloc(&(*shapingPolicy)->peakBandwidth) < 0) {
            goto cleanup;
        }

        /* Scale kilobytes per second to bits per second */
        (*shapingPolicy)->peakBandwidth->value = bandwidth->in->peak * 8 * 1000;
    }

    if (bandwidth->in->burst > 0) {
        if (esxVI_Long_Alloc(&(*shapingPolicy)->burstSize) < 0) {
            goto cleanup;
        }

        /* Scale kilobytes to bytes */
        (*shapingPolicy)->burstSize->value = bandwidth->in->burst * 1024;
    }

    result = 0;

 cleanup:
    if (result < 0) {
        esxVI_HostNetworkTrafficShapingPolicy_Free(shapingPolicy);
    }

    return result;
}



static virNetworkPtr
esxNetworkDefineXML(virConnectPtr conn, const char *xml)
{
    virNetworkPtr network = NULL;
    esxPrivate *priv = conn->networkPrivateData;
    virNetworkDefPtr def = NULL;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    esxVI_HostPortGroup *hostPortGroupList = NULL;
    esxVI_HostPortGroup *hostPortGroup = NULL;
    esxVI_HostVirtualSwitchSpec *hostVirtualSwitchSpec = NULL;
    esxVI_HostVirtualSwitchBondBridge *hostVirtualSwitchBondBridge = NULL;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *physicalNic = NULL;
    esxVI_HostPortGroupSpec *hostPortGroupSpec = NULL;
    size_t i;

    unsigned char md5[MD5_DIGEST_SIZE]; /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    /* Parse network XML */
    def = virNetworkDefParseString(xml);

    if (!def) {
        return NULL;
    }

    /* Check if an existing HostVirtualSwitch should be edited */
    if (esxVI_LookupHostVirtualSwitchByName(priv->primary, def->name,
                                            &hostVirtualSwitch,
                                            esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (hostVirtualSwitch) {
        /* FIXME */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("HostVirtualSwitch already exists, editing existing "
                         "ones is not supported yet"));
        goto cleanup;
    }

    /* UUID is derived from the HostVirtualSwitch's key and cannot be specified */
    if (def->uuid_specified) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use predefined UUID"));
        goto cleanup;
    }

    /* FIXME: Add support for NAT */
    if (def->forward.type != VIR_NETWORK_FORWARD_NONE &&
        def->forward.type != VIR_NETWORK_FORWARD_BRIDGE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported forward mode '%s'"),
                       virNetworkForwardTypeToString(def->forward.type));
        goto cleanup;
    }

    /* Verify that specified HostPortGroups don't exist already */
    if (def->nPortGroups > 0) {
        if (esxVI_LookupHostPortGroupList(priv->primary, &hostPortGroupList) < 0) {
            goto cleanup;
        }

        for (i = 0; i < def->nPortGroups; ++i) {
            for (hostPortGroup = hostPortGroupList; hostPortGroup;
                 hostPortGroup = hostPortGroup->_next) {
                if (STREQ(def->portGroups[i].name, hostPortGroup->spec->name)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("HostPortGroup with name '%s' exists already"),
                                   def->portGroups[i].name);
                    goto cleanup;
                }
            }
        }
    }

    /* Create HostVirtualSwitch */
    if (esxVI_HostVirtualSwitchSpec_Alloc(&hostVirtualSwitchSpec) < 0 ||
        esxVI_Int_Alloc(&hostVirtualSwitchSpec->numPorts) < 0) {
        goto cleanup;
    }

    if (def->forward.type != VIR_NETWORK_FORWARD_NONE && def->forward.nifs > 0) {
        if (esxVI_HostVirtualSwitchBondBridge_Alloc
              (&hostVirtualSwitchBondBridge) < 0) {
            goto cleanup;
        }

        hostVirtualSwitchSpec->bridge =
          (esxVI_HostVirtualSwitchBridge *)hostVirtualSwitchBondBridge;

        /* Lookup PhysicalNic list and match by name to get key */
        if (esxVI_LookupPhysicalNicList(priv->primary, &physicalNicList) < 0) {
            goto cleanup;
        }

        for (i = 0; i < def->forward.nifs; ++i) {
            bool found = false;

            if (def->forward.ifs[i].type !=
                VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported device type in network %s "
                                 "interface pool"),
                               def->name);
                goto cleanup;
            }

            for (physicalNic = physicalNicList; physicalNic;
                 physicalNic = physicalNic->_next) {
                if (STREQ(def->forward.ifs[i].device.dev, physicalNic->device)) {
                    if (esxVI_String_AppendValueToList
                          (&hostVirtualSwitchBondBridge->nicDevice,
                           physicalNic->key) < 0) {
                        goto cleanup;
                    }

                    found = true;
                    break;
                }
            }

            if (! found) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find PhysicalNic with name '%s'"),
                               def->forward.ifs[i].device.dev);
                goto cleanup;
            }
        }
    }

    hostVirtualSwitchSpec->numPorts->value = 128;

    if (def->bandwidth) {
        if (esxVI_HostNetworkPolicy_Alloc(&hostVirtualSwitchSpec->policy) < 0) {
            goto cleanup;
        }

        if (esxBandwidthToShapingPolicy
              (def->bandwidth,
               &hostVirtualSwitchSpec->policy->shapingPolicy) < 0) {
            goto cleanup;
        }
    }

    if (esxVI_AddVirtualSwitch
          (priv->primary,
           priv->primary->hostSystem->configManager->networkSystem,
           def->name, hostVirtualSwitchSpec) < 0) {
        goto cleanup;
    }

    /* Create HostPortGroup(s) */
    for (i = 0; i < def->nPortGroups; ++i) {
        esxVI_HostPortGroupSpec_Free(&hostPortGroupSpec);

        if (esxVI_HostPortGroupSpec_Alloc(&hostPortGroupSpec) < 0 ||
            esxVI_HostNetworkPolicy_Alloc(&hostPortGroupSpec->policy) < 0 ||
            esxVI_Int_Alloc(&hostPortGroupSpec->vlanId) < 0 ||
            VIR_STRDUP(hostPortGroupSpec->name, def->portGroups[i].name) < 0 ||
            VIR_STRDUP(hostPortGroupSpec->vswitchName, def->name) < 0) {
            goto cleanup;
        }

        hostPortGroupSpec->vlanId->value = 0;

        if (def->portGroups[i].bandwidth) {
            if (esxBandwidthToShapingPolicy
                  (def->portGroups[i].bandwidth,
                   &hostPortGroupSpec->policy->shapingPolicy) < 0) {
                goto cleanup;
            }
        }

        if (esxVI_AddPortGroup
              (priv->primary,
               priv->primary->hostSystem->configManager->networkSystem,
               hostPortGroupSpec) < 0) {
            goto cleanup;
        }
    }

    /* Lookup created HostVirtualSwitch to get the UUID */
    if (esxVI_LookupHostVirtualSwitchByName(priv->primary, def->name,
                                            &hostVirtualSwitch,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    md5_buffer(hostVirtualSwitch->key, strlen(hostVirtualSwitch->key), md5);

    network = virGetNetwork(conn, hostVirtualSwitch->name, md5);

 cleanup:
    virNetworkDefFree(def);
    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitch);
    esxVI_HostPortGroup_Free(&hostPortGroupList);
    esxVI_HostVirtualSwitchSpec_Free(&hostVirtualSwitchSpec);
    esxVI_PhysicalNic_Free(&physicalNicList);
    esxVI_HostPortGroupSpec_Free(&hostPortGroupSpec);

    return network;
}



static int
esxNetworkUndefine(virNetworkPtr network)
{
    int result = -1;
    esxPrivate *priv = network->conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    esxVI_HostPortGroup *hostPortGroupList = NULL;
    esxVI_String *hostPortGroupKey = NULL;
    esxVI_HostPortGroup *hostPortGroup = NULL;
    esxVI_HostPortGroupPort *hostPortGroupPort = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    /* Lookup HostVirtualSwitch and HostPortGroup list*/
    if (esxVI_LookupHostVirtualSwitchByName(priv->primary, network->name,
                                            &hostVirtualSwitch,
                                            esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_LookupHostPortGroupList(priv->primary, &hostPortGroupList) < 0) {
        goto cleanup;
    }

    /* Verify that the HostVirtualSwitch is connected to virtual machines only */
    for (hostPortGroupKey = hostVirtualSwitch->portgroup;
         hostPortGroupKey; hostPortGroupKey = hostPortGroupKey->_next) {
        bool found = false;

        for (hostPortGroup = hostPortGroupList; hostPortGroup;
             hostPortGroup = hostPortGroup->_next) {
            if (STREQ(hostPortGroupKey->value, hostPortGroup->key)) {
                for (hostPortGroupPort = hostPortGroup->port;
                     hostPortGroupPort;
                     hostPortGroupPort = hostPortGroupPort->_next) {
                    if (STRNEQ(hostPortGroupPort->type, "virtualMachine")) {
                        virReportError(VIR_ERR_OPERATION_INVALID,
                                       _("Cannot undefine HostVirtualSwitch that has a '%s' port"),
                                       hostPortGroupPort->type);
                        goto cleanup;
                    }
                }

                found = true;
                break;
            }
        }

        if (! found) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find HostPortGroup for key '%s'"),
                           hostPortGroupKey->value);
            goto cleanup;
        }
    }

    /* Remove all HostPortGroups from the HostVirtualSwitch */
    for (hostPortGroupKey = hostVirtualSwitch->portgroup;
         hostPortGroupKey; hostPortGroupKey = hostPortGroupKey->_next) {
        bool found = false;

        for (hostPortGroup = hostPortGroupList; hostPortGroup;
             hostPortGroup = hostPortGroup->_next) {
            if (STREQ(hostPortGroupKey->value, hostPortGroup->key)) {
                if (esxVI_RemovePortGroup
                      (priv->primary,
                       priv->primary->hostSystem->configManager->networkSystem,
                       hostPortGroup->spec->name) < 0) {
                    goto cleanup;
                }

                found = true;
                break;
            }
        }

        if (! found) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find HostPortGroup for key '%s'"),
                           hostPortGroupKey->value);
            goto cleanup;
        }
    }

    /* Finally, remove HostVirtualSwitch itself */
    if (esxVI_RemoveVirtualSwitch
          (priv->primary,
           priv->primary->hostSystem->configManager->networkSystem,
           network->name) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitch);
    esxVI_HostPortGroup_Free(&hostPortGroupList);

    return result;
}



static int
esxShapingPolicyToBandwidth(esxVI_HostNetworkTrafficShapingPolicy *shapingPolicy,
                            virNetDevBandwidthPtr *bandwidth)
{
    if (!bandwidth || *bandwidth) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("Invalid argument"));
        return -1;
    }

    if (!shapingPolicy || shapingPolicy->enabled != esxVI_Boolean_True) {
        return 0;
    }

    if (VIR_ALLOC(*bandwidth) < 0 ||
        VIR_ALLOC((*bandwidth)->in) < 0 ||
        VIR_ALLOC((*bandwidth)->out) < 0)
        return -1;

    if (shapingPolicy->averageBandwidth) {
        /* Scale bits per second to kilobytes per second */
        (*bandwidth)->in->average = shapingPolicy->averageBandwidth->value / 8 / 1000;
        (*bandwidth)->out->average = shapingPolicy->averageBandwidth->value / 8 / 1000;
    }

    if (shapingPolicy->peakBandwidth) {
        /* Scale bits per second to kilobytes per second */
        (*bandwidth)->in->peak = shapingPolicy->peakBandwidth->value / 8 / 1000;
        (*bandwidth)->out->peak = shapingPolicy->peakBandwidth->value / 8 / 1000;
    }

    if (shapingPolicy->burstSize) {
        /* Scale bytes to kilobytes */
        (*bandwidth)->in->burst = shapingPolicy->burstSize->value / 1024;
        (*bandwidth)->out->burst = shapingPolicy->burstSize->value / 1024;
    }

    return 0;
}



static char *
esxNetworkGetXMLDesc(virNetworkPtr network_, unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = network_->conn->networkPrivateData;
    esxVI_HostVirtualSwitch *hostVirtualSwitch = NULL;
    int count = 0;
    esxVI_PhysicalNic *physicalNicList = NULL;
    esxVI_PhysicalNic *physicalNic = NULL;
    esxVI_String *physicalNicKey = NULL;
    esxVI_HostPortGroup *hostPortGroupList = NULL;
    esxVI_HostPortGroup *hostPortGroup = NULL;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *networkList = NULL;
    esxVI_ObjectContent *network = NULL;
    esxVI_String *networkNameList = NULL;
    esxVI_String *hostPortGroupKey = NULL;
    esxVI_String *networkName = NULL;
    virNetworkDefPtr def;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    /* Lookup HostVirtualSwitch */
    if (esxVI_LookupHostVirtualSwitchByName(priv->primary, network_->name,
                                            &hostVirtualSwitch,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    md5_buffer(hostVirtualSwitch->key, strlen(hostVirtualSwitch->key), def->uuid);

    if (VIR_STRDUP(def->name, hostVirtualSwitch->name) < 0)
        goto cleanup;

    def->forward.type = VIR_NETWORK_FORWARD_NONE;

    /* Count PhysicalNics on HostVirtualSwitch */
    count = 0;

    for (physicalNicKey = hostVirtualSwitch->pnic;
         physicalNicKey; physicalNicKey = physicalNicKey->_next) {
        ++count;
    }

    if (count > 0) {
        def->forward.type = VIR_NETWORK_FORWARD_BRIDGE;

        if (VIR_ALLOC_N(def->forward.ifs, count) < 0)
            goto cleanup;

        /* Find PhysicalNic by key */
        if (esxVI_LookupPhysicalNicList(priv->primary, &physicalNicList) < 0) {
            goto cleanup;
        }

        for (physicalNicKey = hostVirtualSwitch->pnic;
             physicalNicKey; physicalNicKey = physicalNicKey->_next) {
            bool found = false;

            for (physicalNic = physicalNicList; physicalNic;
                 physicalNic = physicalNic->_next) {
                if (STREQ(physicalNicKey->value, physicalNic->key)) {
                    def->forward.ifs[def->forward.nifs].type
                        = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
                    if (VIR_STRDUP(def->forward.ifs[def->forward.nifs].device.dev,
                                   physicalNic->device) < 0)
                        goto cleanup;

                    ++def->forward.nifs;

                    found = true;
                    break;
                }
            }

            if (! found) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find PhysicalNic with key '%s'"),
                               physicalNicKey->value);
                goto cleanup;
            }
        }
    }

    /* Count HostPortGroups on HostVirtualSwitch */
    count = 0;

    for (hostPortGroupKey = hostVirtualSwitch->portgroup;
         hostPortGroupKey; hostPortGroupKey = hostPortGroupKey->_next) {
        ++count;
    }

    if (count > 0) {
        if (VIR_ALLOC_N(def->portGroups, count) < 0)
            goto cleanup;

        /* Lookup Network list and create name list */
        if (esxVI_String_AppendValueToList(&propertyNameList, "name") < 0 ||
            esxVI_LookupNetworkList(priv->primary, propertyNameList,
                                    &networkList) < 0) {
            goto cleanup;
        }

        for (network = networkList; network; network = network->_next) {
            char *tmp = NULL;

            if (esxVI_GetStringValue(network, "name", &tmp,
                                     esxVI_Occurrence_RequiredItem) < 0 ||
                esxVI_String_AppendValueToList(&networkNameList, tmp) < 0) {
                goto cleanup;
            }
        }

        /* Find HostPortGroup by key */
        if (esxVI_LookupHostPortGroupList(priv->primary, &hostPortGroupList) < 0) {
            goto cleanup;
        }

        for (hostPortGroupKey = hostVirtualSwitch->portgroup;
             hostPortGroupKey; hostPortGroupKey = hostPortGroupKey->_next) {
            bool found = false;

            for (hostPortGroup = hostPortGroupList; hostPortGroup;
                 hostPortGroup = hostPortGroup->_next) {
                if (STREQ(hostPortGroupKey->value, hostPortGroup->key)) {
                    /* Find Network for HostPortGroup, there might be none */
                    for (networkName = networkNameList; networkName;
                         networkName = networkName->_next) {
                        if (STREQ(networkName->value, hostPortGroup->spec->name)) {
                            if (VIR_STRDUP(def->portGroups[def->nPortGroups].name,
                                           networkName->value) < 0)
                                goto cleanup;

                            if (hostPortGroup->spec->policy) {
                                if (esxShapingPolicyToBandwidth
                                      (hostPortGroup->spec->policy->shapingPolicy,
                                       &def->portGroups[def->nPortGroups].bandwidth) < 0) {
                                    ++def->nPortGroups;
                                    goto cleanup;
                                }
                            }

                            ++def->nPortGroups;
                            break;
                        }
                    }

                    found = true;
                    break;
                }
            }

            if (! found) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find HostPortGroup with key '%s'"),
                               hostPortGroupKey->value);
                goto cleanup;
            }
        }
    }

    if (hostVirtualSwitch->spec->policy) {
        if (esxShapingPolicyToBandwidth
              (hostVirtualSwitch->spec->policy->shapingPolicy,
               &def->bandwidth) < 0) {
            goto cleanup;
        }
    }

    xml = virNetworkDefFormat(def, flags);

 cleanup:
    esxVI_HostVirtualSwitch_Free(&hostVirtualSwitch);
    esxVI_PhysicalNic_Free(&physicalNicList);
    esxVI_HostPortGroup_Free(&hostPortGroupList);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&networkList);
    esxVI_String_Free(&networkNameList);
    virNetworkDefFree(def);

    return xml;
}



static int
esxNetworkGetAutostart(virNetworkPtr network ATTRIBUTE_UNUSED,
                       int *autostart)
{
    /* ESX networks are always active */
    *autostart = 1;

    return 0;
}



static int
esxNetworkSetAutostart(virNetworkPtr network ATTRIBUTE_UNUSED,
                       int autostart)
{
    /* Just accept autostart activation, but fail on autostart deactivation */
    autostart = (autostart != 0);

    if (! autostart) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot deactivate network autostart"));
        return -1;
    }

    return 0;
}



static int
esxNetworkIsActive(virNetworkPtr network ATTRIBUTE_UNUSED)
{
    /* ESX networks are always active */
    return 1;
}



static int
esxNetworkIsPersistent(virNetworkPtr network ATTRIBUTE_UNUSED)
{
    /* ESX has no concept of transient networks, so all of them are persistent */
    return 1;
}



static virNetworkDriver esxNetworkDriver = {
    .name = "ESX",
    .networkOpen = esxNetworkOpen, /* 0.7.6 */
    .networkClose = esxNetworkClose, /* 0.7.6 */
    .connectNumOfNetworks = esxConnectNumOfNetworks, /* 0.10.0 */
    .connectListNetworks = esxConnectListNetworks, /* 0.10.0 */
    .connectNumOfDefinedNetworks = esxConnectNumOfDefinedNetworks, /* 0.10.0 */
    .connectListDefinedNetworks = esxConnectListDefinedNetworks, /* 0.10.0 */
    .networkLookupByUUID = esxNetworkLookupByUUID, /* 0.10.0 */
    .networkLookupByName = esxNetworkLookupByName, /* 0.10.0 */
    .networkDefineXML = esxNetworkDefineXML, /* 0.10.0 */
    .networkUndefine = esxNetworkUndefine, /* 0.10.0 */
    .networkGetXMLDesc = esxNetworkGetXMLDesc, /* 0.10.0 */
    .networkGetAutostart = esxNetworkGetAutostart, /* 0.10.0 */
    .networkSetAutostart = esxNetworkSetAutostart, /* 0.10.0 */
    .networkIsActive = esxNetworkIsActive, /* 0.10.0 */
    .networkIsPersistent = esxNetworkIsPersistent, /* 0.10.0 */
};



int
esxNetworkRegister(void)
{
    return virRegisterNetworkDriver(&esxNetworkDriver);
}
