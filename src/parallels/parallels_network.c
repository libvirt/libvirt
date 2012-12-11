/*
 * parallels_storage.c: core privconn functions for managing
 * Parallels Cloud Server hosts
 *
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
#include "memory.h"
#include "virterror_internal.h"
#include "md5.h"

#include "parallels_utils.h"

#define VIR_FROM_THIS VIR_FROM_PARALLELS

#define parallelsParseError()                                                  \
    virReportErrorHelper(VIR_FROM_TEST, VIR_ERR_OPERATION_FAILED, __FILE__,    \
                     __FUNCTION__, __LINE__, _("Can't parse prlctl output"))

static virNetworkObjPtr
parallelsLoadNetwork(parallelsConnPtr privconn, virJSONValuePtr jobj)
{
    virNetworkObjPtr net;
    virNetworkDefPtr def;
    const char *tmp;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    if (!(tmp = virJSONValueObjectGetString(jobj, "Network ID"))) {
        parallelsParseError();
        goto cleanup;
    }

    if (!(def->name = strdup(tmp)))
        goto no_memory;

    /* Network names are unique in Parallels Cloud Server, so we can make
     * an UUID from it */
    md5_buffer(tmp, strlen(tmp), md5);
    memcpy(def->uuid, md5, VIR_UUID_BUFLEN);
    def->uuid_specified = 1;

    if (!(net = virNetworkAssignDef(&privconn->networks, def, false))) {
        virNetworkDefFree(def);
        goto cleanup;
    }
    net->active = 1;
    net->persistent = 1;
    net->autostart = 1;
    virNetworkObjUnlock(net);
    return net;

no_memory:
    virReportOOMError();
cleanup:
    virNetworkDefFree(def);
    return NULL;
}

static int parallelsLoadNetworks(parallelsConnPtr privconn)
{
    virJSONValuePtr jobj, jobj2;
    virNetworkObjPtr net;
    int ret = -1;
    int count, i;

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

        net = parallelsLoadNetwork(privconn, jobj2);
        if (!net)
            goto cleanup;

    }

    ret = 0;

cleanup:
    virJSONValueFree(jobj);
    return ret;
}

static virDrvOpenStatus
parallelsOpenNetwork(virConnectPtr conn,
                     virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                     unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

    if (STRNEQ(conn->driver->name, "Parallels"))
        return VIR_DRV_OPEN_DECLINED;

    conn->networkPrivateData = conn->privateData;

    if (parallelsLoadNetworks(conn->privateData) < 0)
        return VIR_DRV_OPEN_DECLINED;

    return VIR_DRV_OPEN_SUCCESS;
}

static int parallelsCloseNetwork(virConnectPtr conn)
{
    parallelsConnPtr privconn = conn->privateData;
    parallelsDriverLock(privconn);
    virNetworkObjListFree(&privconn->networks);
    parallelsDriverUnlock(privconn);
    return 0;
}

static int parallelsNumNetworks(virConnectPtr conn)
{
    int nactive = 0, i;
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (virNetworkObjIsActive(privconn->networks.objs[i]))
            nactive++;
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return nactive;
}

static int parallelsListNetworks(virConnectPtr conn,
                                 char **const names,
                                 int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int got = 0, i;

    parallelsDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count && got < nnames ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (virNetworkObjIsActive(privconn->networks.objs[i])) {
            if (!(names[got] = strdup(privconn->networks.objs[i]->def->name))) {
                virNetworkObjUnlock(privconn->networks.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return got;

 cleanup:
    parallelsDriverUnlock(privconn);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int parallelsNumDefinedNetworks(virConnectPtr conn)
{
    int ninactive = 0, i;
    parallelsConnPtr privconn = conn->privateData;

    parallelsDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (!virNetworkObjIsActive(privconn->networks.objs[i]))
            ninactive++;
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    parallelsDriverUnlock(privconn);

    return ninactive;
}

static int parallelsListDefinedNetworks(virConnectPtr conn,
                                        char **const names,
                                        int nnames)
{
    parallelsConnPtr privconn = conn->privateData;
    int got = 0, i;

    parallelsDriverLock(privconn);
    for (i = 0 ; i < privconn->networks.count && got < nnames ; i++) {
        virNetworkObjLock(privconn->networks.objs[i]);
        if (!virNetworkObjIsActive(privconn->networks.objs[i])) {
            if (!(names[got] = strdup(privconn->networks.objs[i]->def->name))) {
                virNetworkObjUnlock(privconn->networks.objs[i]);
                virReportOOMError();
                goto cleanup;
            }
            got++;
        }
        virNetworkObjUnlock(privconn->networks.objs[i]);
    }
    parallelsDriverUnlock(privconn);
    return got;

 cleanup:
    parallelsDriverUnlock(privconn);
    for (i = 0 ; i < got ; i++)
        VIR_FREE(names[i]);
    return -1;
}

static int parallelsListAllNetworks(virConnectPtr conn,
                                    virNetworkPtr **nets,
                                    unsigned int flags)
{
    parallelsConnPtr privconn = conn->privateData;
    int ret = -1;

    virCheckFlags(VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL, -1);

    parallelsDriverLock(privconn);
    ret = virNetworkList(conn, privconn->networks, nets, flags);
    parallelsDriverUnlock(privconn);

    return ret;
}

static virNetworkPtr parallelsNetworkLookupByUUID(virConnectPtr conn,
                                                  const unsigned char *uuid)
{
    parallelsConnPtr privconn = conn->privateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    parallelsDriverLock(privconn);
    network = virNetworkFindByUUID(&privconn->networks, uuid);
    parallelsDriverUnlock(privconn);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static virNetworkPtr parallelsNetworkLookupByName(virConnectPtr conn,
                                                  const char *name)
{
    parallelsConnPtr privconn = conn->privateData;
    virNetworkObjPtr network;
    virNetworkPtr ret = NULL;

    parallelsDriverLock(privconn);
    network = virNetworkFindByName(&privconn->networks, name);
    parallelsDriverUnlock(privconn);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       _("no network with matching name '%s'"), name);
        goto cleanup;
    }

    ret = virGetNetwork(conn, network->def->name, network->def->uuid);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static char *parallelsNetworkGetXMLDesc(virNetworkPtr net,
                                        unsigned int flags)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr network;
    char *ret = NULL;

    virCheckFlags(VIR_NETWORK_XML_INACTIVE, NULL);

    parallelsDriverLock(privconn);
    network = virNetworkFindByUUID(&privconn->networks, net->uuid);
    parallelsDriverUnlock(privconn);

    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    ret = virNetworkDefFormat(network->def, flags);

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}

static int parallelsNetworkIsActive(virNetworkPtr net)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    parallelsDriverLock(privconn);
    obj = virNetworkFindByUUID(&privconn->networks, net->uuid);
    parallelsDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = virNetworkObjIsActive(obj);

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}

static int parallelsNetworkIsPersistent(virNetworkPtr net)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr obj;
    int ret = -1;

    parallelsDriverLock(privconn);
    obj = virNetworkFindByUUID(&privconn->networks, net->uuid);
    parallelsDriverUnlock(privconn);
    if (!obj) {
        virReportError(VIR_ERR_NO_NETWORK, NULL);
        goto cleanup;
    }
    ret = obj->persistent;

cleanup:
    if (obj)
        virNetworkObjUnlock(obj);
    return ret;
}

static int parallelsNetworkGetAutostart(virNetworkPtr net,
                                 int *autostart)
{
    parallelsConnPtr privconn = net->conn->privateData;
    virNetworkObjPtr network;
    int ret = -1;

    parallelsDriverLock(privconn);
    network = virNetworkFindByUUID(&privconn->networks, net->uuid);
    parallelsDriverUnlock(privconn);
    if (!network) {
        virReportError(VIR_ERR_NO_NETWORK,
                       "%s", _("no network with matching uuid"));
        goto cleanup;
    }

    *autostart = network->autostart;
    ret = 0;

cleanup:
    if (network)
        virNetworkObjUnlock(network);
    return ret;
}
static virNetworkDriver parallelsNetworkDriver = {
    "Parallels",
    .open = parallelsOpenNetwork, /* 1.0.1 */
    .close = parallelsCloseNetwork, /* 1.0.1 */
    .numOfNetworks = parallelsNumNetworks, /* 1.0.1 */
    .listNetworks = parallelsListNetworks, /* 1.0.1 */
    .numOfDefinedNetworks = parallelsNumDefinedNetworks, /* 1.0.1 */
    .listDefinedNetworks = parallelsListDefinedNetworks, /* 1.0.1 */
    .listAllNetworks = parallelsListAllNetworks, /* 1.0.1 */
    .networkLookupByUUID = parallelsNetworkLookupByUUID, /* 1.0.1 */
    .networkLookupByName = parallelsNetworkLookupByName, /* 1.0.1 */
    .networkGetXMLDesc = parallelsNetworkGetXMLDesc, /* 1.0.1 */
    .networkGetAutostart = parallelsNetworkGetAutostart, /* 1.0.1 */
    .networkIsActive = parallelsNetworkIsActive, /* 1.0.1 */
    .networkIsPersistent = parallelsNetworkIsPersistent, /* 1.0.1 */
};

int
parallelsNetworkRegister(void)
{
    if (virRegisterNetworkDriver(&parallelsNetworkDriver) < 0)
        return -1;

    return 0;
}
