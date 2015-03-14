/*
 * parallels_network.c: core privconn functions for managing
 * Parallels Cloud Server hosts
 *
 * Copyright (C) 2013-2014 Red Hat, Inc.
 * Copyright (C) 2012 Parallels, Inc.
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

#include "datatypes.h"
#include "dirname.h"
#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "md5.h"
#include "parallels_utils.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS
#define PARALLELS_ROUTED_NETWORK_UUID   "eb593dd1-6846-45b0-84a0-de0729286982"

#define parallelsParseError()                                                  \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,    \
                     __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

#define SYSFS_NET_DIR "/sys/class/net"

static int parallelsGetBridgedNetInfo(virNetworkDefPtr def, virJSONValuePtr jobj)
{
    const char *ifname;
    char *bridgeLink = NULL;
    char *bridgePath = NULL;
    char *bridgeAddressPath = NULL;
    char *bridgeAddress = NULL;
    int len = 0;
    int ret = -1;

    if (!(ifname = virJSONValueObjectGetString(jobj, "Bound To"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virAsprintf(&bridgeLink, "%s/%s/brport/bridge",
                    SYSFS_NET_DIR, ifname) < 0)
        goto cleanup;

    if (virFileResolveLink(bridgeLink, &bridgePath) < 0) {
        virReportSystemError(errno, _("cannot read link '%s'"), bridgeLink);
        goto cleanup;
    }

    if (VIR_STRDUP(def->bridge, last_component(bridgePath)) < 0)
        goto cleanup;

    if (virAsprintf(&bridgeAddressPath, "%s/%s/brport/bridge/address",
                    SYSFS_NET_DIR, ifname) < 0)
        goto cleanup;

    if ((len = virFileReadAll(bridgeAddressPath, 18, &bridgeAddress)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error reading file '%s'"), bridgeAddressPath);

        goto cleanup;
    }

    if (len < VIR_MAC_STRING_BUFLEN) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error reading MAC from '%s'"), bridgeAddressPath);
    }

    bridgeAddress[VIR_MAC_STRING_BUFLEN - 1] = '\0';
    if (virMacAddrParse(bridgeAddress, &def->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Can't parse MAC '%s'"), bridgeAddress);
        goto cleanup;
    }
    def->mac_specified = 1;

    ret = 0;

 cleanup:
    VIR_FREE(bridgeLink);
    VIR_FREE(bridgePath);
    VIR_FREE(bridgeAddress);
    VIR_FREE(bridgeAddressPath);
    return ret;
}

static int parallelsGetHostOnlyNetInfo(virNetworkDefPtr def, const char *name)
{
    const char *tmp;
    virJSONValuePtr jobj = NULL, jobj2;
    int ret = -1;

    if (VIR_EXPAND_N(def->ips, def->nips, 1) < 0)
        goto cleanup;

    jobj = parallelsParseOutput("prlsrvctl", "net", "info", "-j", name, NULL);

    if (!jobj) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(jobj2 = virJSONValueObjectGet(jobj, "Parallels adapter"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (VIR_STRDUP(def->ips[0].family, "ipv4") < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP address"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].address, tmp) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj2, "Subnet mask"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].netmask, tmp) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(jobj2 = virJSONValueObjectGet(jobj, "DHCPv4 server"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (VIR_EXPAND_N(def->ips[0].ranges, def->ips[0].nranges, 1) < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP scope start address"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].ranges[0].start, tmp) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP scope end address"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].ranges[0].end, tmp) < 0) {
        parallelsParseError();
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(jobj);
    return ret;
}

static int
parallelsLoadNetwork(parallelsConnPtr privconn, virJSONValuePtr jobj)
{
    int ret = -1;
    virNetworkObjPtr net = NULL;
    virNetworkDefPtr def;
    const char *tmp;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Network ID"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (VIR_STRDUP(def->name, tmp) < 0)
        goto cleanup;

    /* Network names are unique in Parallels Cloud Server, so we can make
     * a UUID from it */
    md5_buffer(tmp, strlen(tmp), md5);
    memcpy(def->uuid, md5, VIR_UUID_BUFLEN);
    def->uuid_specified = 1;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Type"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (STREQ(tmp, PARALLELS_BRIDGED_NETWORK_TYPE)) {
        def->forward.type = VIR_NETWORK_FORWARD_BRIDGE;

        if (parallelsGetBridgedNetInfo(def, jobj) < 0) {

            /* Only mandatory networks are required to be configured completely */
            if (STRNEQ(def->name, PARALLELS_REQUIRED_BRIDGED_NETWORK))
                ret = 0;

            goto cleanup;
        }
    } else if (STREQ(tmp, PARALLELS_HOSTONLY_NETWORK_TYPE)) {
        def->forward.type = VIR_NETWORK_FORWARD_NONE;

        if (parallelsGetHostOnlyNetInfo(def, def->name) < 0) {

            /* Only mandatory networks are required to be configured completely */
            if (STRNEQ(def->name, PARALLELS_REQUIRED_HOSTONLY_NETWORK))
                ret = 0;

            goto cleanup;
        }
    } else {
        parallelsParseError();
        goto cleanup;
    }

    if (!(net = virNetworkAssignDef(privconn->networks, def, 0)))
        goto cleanup;
    def = NULL;
    net->active = 1;
    net->autostart = 1;
    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&net);
    virNetworkDefFree(def);
    return ret;
}

static int
parallelsAddRoutedNetwork(parallelsConnPtr privconn)
{
    virNetworkObjPtr net = NULL;
    virNetworkDefPtr def;

    if (VIR_ALLOC(def) < 0)
        goto cleanup;

    def->forward.type = VIR_NETWORK_FORWARD_ROUTE;

    if (VIR_STRDUP(def->name, PARALLELS_DOMAIN_ROUTED_NETWORK_NAME) < 0)
        goto cleanup;

    if (virUUIDParse(PARALLELS_ROUTED_NETWORK_UUID, def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Can't parse UUID"));
        goto cleanup;
    }
    def->uuid_specified = 1;

    if (!(net = virNetworkAssignDef(privconn->networks, def, 0)))
        goto cleanup;

    net->active = 1;
    net->autostart = 1;
    virNetworkObjEndAPI(&net);

    return 0;

 cleanup:
    virNetworkDefFree(def);
    return -1;
}

static int parallelsLoadNetworks(parallelsConnPtr privconn)
{
    virJSONValuePtr jobj, jobj2;
    int ret = -1;
    int count;
    size_t i;

    jobj = parallelsParseOutput("prlsrvctl", "net", "list", "-j", NULL);

    if (!jobj) {
        parallelsParseError();
        goto cleanup;
    }

    count = virJSONValueArraySize(jobj);
    if (count < 0) {
        parallelsParseError();
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        jobj2 = virJSONValueArrayGet(jobj, i);
        if (!jobj2) {
            parallelsParseError();
            goto cleanup;
        }

        if (parallelsLoadNetwork(privconn, jobj2) < 0)
            goto cleanup;
    }

    if (parallelsAddRoutedNetwork(privconn) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(jobj);
    return ret;
}

virDrvOpenStatus
parallelsNetworkOpen(virConnectPtr conn,
                     unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "Parallels"))
        return VIR_DRV_OPEN_DECLINED;

    if (!(privconn->networks = virNetworkObjListNew()))
        goto error;

    if (parallelsLoadNetworks(conn->privateData) < 0)
        goto error;

    return VIR_DRV_OPEN_SUCCESS;
 error:
    virObjectUnref(privconn->networks);
    privconn->networks = NULL;
    return VIR_DRV_OPEN_DECLINED;
}

int parallelsNetworkClose(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;

    if (!privconn)
        return 0;

    virObjectUnref(privconn->networks);
    return 0;
}

static int parallelsConnectNumOfNetworks(virConnectPtr conn)
{
    int nactive;
    parallelsConnPtr privconn = conn->privateData;

    nactive = virNetworkObjListNumOfNetworks(privconn->networks,
                                             true, NULL, conn);
    return nactive;
}

static int parallelsConnectListNetworks(virConnectPtr conn,
                                        char **const names,
                                        int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int got;

    got = virNetworkObjListGetNames(privconn->networks,
                                    true, names, nnames, NULL, conn);
    return got;
}

static int parallelsConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    int ninactive;
    parallelsConnPtr privconn = conn->privateData;

    ninactive = virNetworkObjListNumOfNetworks(privconn->networks,
                                               false, NULL, conn);
    return ninactive;
}

static int parallelsConnectListDefinedNetworks(virConnectPtr conn,
                                               char **const names,
                                               int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int got;

    got = virNetworkObjListGetNames(privconn->networks,
                                    false, names, nnames, NULL, conn);
    return got;
}

static int parallelsConnectListAllNetworks(virConnectPtr conn,
                                           virNetworkPtr **nets,
                                           unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    return virNetworkObjListExport(conn, privconn->networks, nets, NULL, flags);
}

static virNetworkPtr parallelsNetworkLookupByUUID(virConnectPtr conn,
                                                  const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    network = virNetworkObjFindByUUID(privconn->networks, uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}

static virNetworkPtr parallelsNetworkLookupByName(virConnectPtr conn,
                                                  const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    network = virNetworkObjFindByName(privconn->networks, name);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}

static char *parallelsNetworkGetXMLDesc(virNetworkPtr net,
                                        unsigned int flags)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr network;
    char *ret = NULL;

    virCheckFlags(VIR_NETWORK_XML_INACTIVE, NULL);

    network = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virNetworkDefFormat(network->def, flags);

 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}

static int parallelsNetworkIsActive(virNetworkPtr net)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    obj = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = virNetworkObjIsActive(obj);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}

static int parallelsNetworkIsPersistent(virNetworkPtr net)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    obj = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}

static int parallelsNetworkGetAutostart(virNetworkPtr net,
                                 int *autostart)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr network;
    int ret = -1;

    network = virNetworkObjFindByUUID(privconn->networks, net->uuid);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    *autostart = network->autostart;
    ret = 0;

 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}

virNetworkDriver parallelsNetworkDriver = {
    .name = "Parallels",
    .connectNumOfNetworks = parallelsConnectNumOfNetworks, /* 1.0.1 */
    .connectListNetworks = parallelsConnectListNetworks, /* 1.0.1 */
    .connectNumOfDefinedNetworks = parallelsConnectNumOfDefinedNetworks, /* 1.0.1 */
    .connectListDefinedNetworks = parallelsConnectListDefinedNetworks, /* 1.0.1 */
    .connectListAllNetworks = parallelsConnectListAllNetworks, /* 1.0.1 */
    .networkLookupByUUID = parallelsNetworkLookupByUUID, /* 1.0.1 */
    .networkLookupByName = parallelsNetworkLookupByName, /* 1.0.1 */
    .networkGetXMLDesc = parallelsNetworkGetXMLDesc, /* 1.0.1 */
    .networkGetAutostart = parallelsNetworkGetAutostart, /* 1.0.1 */
    .networkIsActive = parallelsNetworkIsActive, /* 1.0.1 */
    .networkIsPersistent = parallelsNetworkIsPersistent, /* 1.0.1 */
};
