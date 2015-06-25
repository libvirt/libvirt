/*
 * vz_network.c: core privconn functions for managing
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
#include "virnetdev.h"
#include "md5.h"
#include "vz_utils.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS
#define PARALLELS_ROUTED_NETWORK_UUID   "eb593dd1-6846-45b0-84a0-de0729286982"

#define vzParseError()                                                          \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,     \
                         __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

static int vzGetBridgedNetInfo(virNetworkDefPtr def, virJSONValuePtr jobj)
{
    const char *ifname;
    char *bridgeLink = NULL;
    char *bridgePath = NULL;
    char *bridgeAddressPath = NULL;
    char *bridgeAddress = NULL;
    int len = 0;
    int ret = -1;

    if (!(ifname = virJSONValueObjectGetString(jobj, "Bound To"))) {
        vzParseError();
        goto cleanup;
    }

    if (virAsprintf(&bridgeLink, SYSFS_NET_DIR "%s/brport/bridge", ifname) < 0)
        goto cleanup;

    if (virFileResolveLink(bridgeLink, &bridgePath) < 0) {
        virReportSystemError(errno, _("cannot read link '%s'"), bridgeLink);
        goto cleanup;
    }

    if (VIR_STRDUP(def->bridge, last_component(bridgePath)) < 0)
        goto cleanup;

    if (virAsprintf(&bridgeAddressPath, SYSFS_NET_DIR "%s/brport/bridge/address",
                    ifname) < 0)
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

static int vzGetHostOnlyNetInfo(virNetworkDefPtr def, const char *name)
{
    const char *tmp;
    virJSONValuePtr jobj = NULL, jobj2;
    int ret = -1;

    if (VIR_EXPAND_N(def->ips, def->nips, 1) < 0)
        goto cleanup;

    jobj = vzParseOutput("prlsrvctl", "net", "info", "-j", name, NULL);

    if (!jobj) {
        vzParseError();
        goto cleanup;
    }

    if (!(jobj2 = virJSONValueObjectGet(jobj, "Parallels adapter"))) {
        vzParseError();
        goto cleanup;
    }

    if (VIR_STRDUP(def->ips[0].family, "ipv4") < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP address"))) {
        vzParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].address, tmp) < 0) {
        vzParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj2, "Subnet mask"))) {
        vzParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].netmask, tmp) < 0) {
        vzParseError();
        goto cleanup;
    }

    if (!(jobj2 = virJSONValueObjectGet(jobj, "DHCPv4 server"))) {
        vzParseError();
        goto cleanup;
    }

    if (VIR_EXPAND_N(def->ips[0].ranges, def->ips[0].nranges, 1) < 0)
        goto cleanup;

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP scope start address"))) {
        vzParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].ranges[0].start, tmp) < 0) {
        vzParseError();
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(jobj2, "IP scope end address"))) {
        vzParseError();
        goto cleanup;
    }

    if (virSocketAddrParseIPv4(&def->ips[0].ranges[0].end, tmp) < 0) {
        vzParseError();
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(jobj);
    return ret;
}

static int
vzLoadNetwork(vzConnPtr privconn, virJSONValuePtr jobj)
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
        vzParseError();
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
        vzParseError();
        goto cleanup;
    }

    if (STREQ(tmp, PARALLELS_BRIDGED_NETWORK_TYPE)) {
        def->forward.type = VIR_NETWORK_FORWARD_BRIDGE;

        if (vzGetBridgedNetInfo(def, jobj) < 0) {

            /* Only mandatory networks are required to be configured completely */
            if (STRNEQ(def->name, PARALLELS_REQUIRED_BRIDGED_NETWORK))
                ret = 0;

            goto cleanup;
        }
    } else if (STREQ(tmp, PARALLELS_HOSTONLY_NETWORK_TYPE)) {
        def->forward.type = VIR_NETWORK_FORWARD_NONE;

        if (vzGetHostOnlyNetInfo(def, def->name) < 0) {

            /* Only mandatory networks are required to be configured completely */
            if (STRNEQ(def->name, PARALLELS_REQUIRED_HOSTONLY_NETWORK))
                ret = 0;

            goto cleanup;
        }
    } else {
        vzParseError();
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
vzAddRoutedNetwork(vzConnPtr privconn)
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

static int vzLoadNetworks(vzConnPtr privconn)
{
    virJSONValuePtr jobj, jobj2;
    int ret = -1;
    int count;
    size_t i;

    jobj = vzParseOutput("prlsrvctl", "net", "list", "-j", NULL);

    if (!jobj) {
        vzParseError();
        goto cleanup;
    }

    count = virJSONValueArraySize(jobj);
    if (count < 0) {
        vzParseError();
        goto cleanup;
    }

    for (i = 0; i < count; i++) {
        jobj2 = virJSONValueArrayGet(jobj, i);
        if (!jobj2) {
            vzParseError();
            goto cleanup;
        }

        if (vzLoadNetwork(privconn, jobj2) < 0)
            goto cleanup;
    }

    if (vzAddRoutedNetwork(privconn) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(jobj);
    return ret;
}

virDrvOpenStatus
vzNetworkOpen(virConnectPtr conn,
              unsigned int flags)
{
    vzConnPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "vz") &&
        STRNEQ(conn->driver->name, "Parallels"))
        return VIR_DRV_OPEN_DECLINED;

    if (!(privconn->networks = virNetworkObjListNew()))
        goto error;

    if (vzLoadNetworks(conn->privateData) < 0)
        goto error;

    return VIR_DRV_OPEN_SUCCESS;
 error:
    virObjectUnref(privconn->networks);
    privconn->networks = NULL;
    return VIR_DRV_OPEN_ERROR;
}

int vzNetworkClose(virConnectPtr conn)
{
    vzConnPtr privconn = conn->privateData;

    if (!privconn)
        return 0;

    virObjectUnref(privconn->networks);
    return 0;
}

static int vzConnectNumOfNetworks(virConnectPtr conn)
{
    int nactive;
    vzConnPtr privconn = conn->privateData;

    nactive = virNetworkObjListNumOfNetworks(privconn->networks,
                                             true, NULL, conn);
    return nactive;
}

static int vzConnectListNetworks(virConnectPtr conn,
                                 char **const names,
                                 int nnames)
{
    vzConnPtr privconn = conn->privateData;
    int got;

    got = virNetworkObjListGetNames(privconn->networks,
                                    true, names, nnames, NULL, conn);
    return got;
}

static int vzConnectNumOfDefinedNetworks(virConnectPtr conn)
{
    int ninactive;
    vzConnPtr privconn = conn->privateData;

    ninactive = virNetworkObjListNumOfNetworks(privconn->networks,
                                               false, NULL, conn);
    return ninactive;
}

static int vzConnectListDefinedNetworks(virConnectPtr conn,
                                        char **const names,
                                        int nnames)
{
    vzConnPtr privconn = conn->privateData;
    int got;

    got = virNetworkObjListGetNames(privconn->networks,
                                    false, names, nnames, NULL, conn);
    return got;
}

static int vzConnectListAllNetworks(virConnectPtr conn,
                                    virNetworkPtr **nets,
                                    unsigned int flags)
{
    vzConnPtr privconn = conn->privateData;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    return virNetworkObjListExport(conn, privconn->networks, nets, NULL, flags);
}

static virNetworkPtr vzNetworkLookupByUUID(virConnectPtr conn,
                                           const unsigned char *uuid)
{
    vzConnPtr privconn = conn->privateData;
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

static virNetworkPtr vzNetworkLookupByName(virConnectPtr conn,
                                           const char *name)
{
    vzConnPtr privconn = conn->privateData;
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

static char *vzNetworkGetXMLDesc(virNetworkPtr net,
                                 unsigned int flags)
{
    vzConnPtr privconn = net->conn->privateData;
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

static int vzNetworkIsActive(virNetworkPtr net)
{
    vzConnPtr privconn = net->conn->privateData;
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

static int vzNetworkIsPersistent(virNetworkPtr net)
{
    vzConnPtr privconn = net->conn->privateData;
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

static int vzNetworkGetAutostart(virNetworkPtr net,
                                 int *autostart)
{
    vzConnPtr privconn = net->conn->privateData;
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

virNetworkDriver vzNetworkDriver = {
    .name = "Parallels",
    .connectNumOfNetworks = vzConnectNumOfNetworks, /* 1.0.1 */
    .connectListNetworks = vzConnectListNetworks, /* 1.0.1 */
    .connectNumOfDefinedNetworks = vzConnectNumOfDefinedNetworks, /* 1.0.1 */
    .connectListDefinedNetworks = vzConnectListDefinedNetworks, /* 1.0.1 */
    .connectListAllNetworks = vzConnectListAllNetworks, /* 1.0.1 */
    .networkLookupByUUID = vzNetworkLookupByUUID, /* 1.0.1 */
    .networkLookupByName = vzNetworkLookupByName, /* 1.0.1 */
    .networkGetXMLDesc = vzNetworkGetXMLDesc, /* 1.0.1 */
    .networkGetAutostart = vzNetworkGetAutostart, /* 1.0.1 */
    .networkIsActive = vzNetworkIsActive, /* 1.0.1 */
    .networkIsPersistent = vzNetworkIsPersistent, /* 1.0.1 */
};
