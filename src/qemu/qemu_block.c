/*
 * qemu_block.c: helper functions for QEMU block subsystem
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

#include "qemu_block.h"
#include "qemu_domain.h"
#include "qemu_alias.h"

#include "viralloc.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_block");

/* qemu declares the buffer for node names as a 32 byte array */
static const size_t qemuBlockNodeNameBufSize = 32;

static int
qemuBlockNodeNameValidate(const char *nn)
{
    if (!nn)
        return 0;

    if (strlen(nn) >= qemuBlockNodeNameBufSize) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("node-name '%s' too long for qemu"), nn);
        return -1;
    }

    return 0;
}


static int
qemuBlockNamedNodesArrayToHash(size_t pos ATTRIBUTE_UNUSED,
                               virJSONValuePtr item,
                               void *opaque)
{
    virHashTablePtr table = opaque;
    const char *name;

    if (!(name = virJSONValueObjectGetString(item, "node-name")))
        return 1;

    if (virHashAddEntry(table, name, item) < 0)
        return -1;

    return 0;
}


static void
qemuBlockNodeNameBackingChainDataFree(qemuBlockNodeNameBackingChainDataPtr data)
{
    if (!data)
        return;

    VIR_FREE(data->nodeformat);
    VIR_FREE(data->nodestorage);

    VIR_FREE(data->qemufilename);

    VIR_FREE(data->drvformat);
    VIR_FREE(data->drvstorage);

    qemuBlockNodeNameBackingChainDataFree(data->backing);

    VIR_FREE(data);
}


static void
qemuBlockNodeNameBackingChainDataHashEntryFree(void *opaque,
                                               const void *name ATTRIBUTE_UNUSED)
{
    qemuBlockNodeNameBackingChainDataFree(opaque);
}


/* list of driver names of layers that qemu automatically adds into the
 * backing chain */
static const char *qemuBlockDriversBlockjob[] = {
    "mirror_top", "commit_top", NULL };

static bool
qemuBlockDriverMatch(const char *drvname,
                     const char **drivers)
{
    while (*drivers) {
        if (STREQ(drvname, *drivers))
            return true;

        drivers++;
    }

    return false;
}


struct qemuBlockNodeNameGetBackingChainData {
    virHashTablePtr nodenamestable;
    virHashTablePtr disks;
};


static int
qemuBlockNodeNameGetBackingChainBacking(virJSONValuePtr next,
                                        virHashTablePtr nodenamestable,
                                        qemuBlockNodeNameBackingChainDataPtr *nodenamedata)
{
    qemuBlockNodeNameBackingChainDataPtr data = NULL;
    qemuBlockNodeNameBackingChainDataPtr backingdata = NULL;
    virJSONValuePtr backing = virJSONValueObjectGetObject(next, "backing");
    virJSONValuePtr parent = virJSONValueObjectGetObject(next, "parent");
    virJSONValuePtr parentnodedata;
    virJSONValuePtr nodedata;
    const char *nodename = virJSONValueObjectGetString(next, "node-name");
    const char *drvname = NULL;
    const char *drvparent = NULL;
    const char *parentnodename = NULL;
    const char *filename = NULL;
    int ret = -1;

    if (!nodename)
        return 0;

    if ((nodedata = virHashLookup(nodenamestable, nodename)) &&
        (drvname = virJSONValueObjectGetString(nodedata, "drv"))) {

        /* qemu 2.9 reports layers in the backing chain which don't correspond
         * to files. skip them */
        if (qemuBlockDriverMatch(drvname, qemuBlockDriversBlockjob)) {
            if (backing) {
                return qemuBlockNodeNameGetBackingChainBacking(backing,
                                                               nodenamestable,
                                                               nodenamedata);
            } else {
                return 0;
            }
        }
    }

    if (parent &&
        (parentnodename = virJSONValueObjectGetString(parent, "node-name"))) {
        if ((parentnodedata = virHashLookup(nodenamestable, parentnodename))) {
            filename = virJSONValueObjectGetString(parentnodedata, "file");
            drvparent = virJSONValueObjectGetString(parentnodedata, "drv");
        }
    }

    if (VIR_ALLOC(data) < 0)
        goto cleanup;

    if (VIR_STRDUP(data->nodeformat, nodename) < 0 ||
        VIR_STRDUP(data->nodestorage, parentnodename) < 0 ||
        VIR_STRDUP(data->qemufilename, filename) < 0 ||
        VIR_STRDUP(data->drvformat, drvname) < 0 ||
        VIR_STRDUP(data->drvstorage, drvparent) < 0)
        goto cleanup;

    if (backing &&
        qemuBlockNodeNameGetBackingChainBacking(backing, nodenamestable,
                                                &backingdata) < 0)
        goto cleanup;

    VIR_STEAL_PTR(data->backing, backingdata);
    VIR_STEAL_PTR(*nodenamedata, data);

    ret = 0;

 cleanup:
    qemuBlockNodeNameBackingChainDataFree(data);
    return ret;
}


static int
qemuBlockNodeNameGetBackingChainDisk(size_t pos ATTRIBUTE_UNUSED,
                                     virJSONValuePtr item,
                                     void *opaque)
{
    struct qemuBlockNodeNameGetBackingChainData *data = opaque;
    const char *device = virJSONValueObjectGetString(item, "device");
    qemuBlockNodeNameBackingChainDataPtr devicedata = NULL;
    int ret = -1;

    if (qemuBlockNodeNameGetBackingChainBacking(item, data->nodenamestable,
                                                &devicedata) < 0)
        goto cleanup;

    if (devicedata &&
        virHashAddEntry(data->disks, device, devicedata) < 0)
        goto cleanup;

    devicedata = NULL;
    ret = 1; /* we don't really want to steal @item */

 cleanup:
    qemuBlockNodeNameBackingChainDataFree(devicedata);

    return ret;
}


/**
 * qemuBlockNodeNameGetBackingChain:
 * @namednodes: JSON array of data returned from 'query-named-block-nodes'
 * @blockstats: JSON array of data returned from 'query-blockstats'
 *
 * Tries to reconstruct the backing chain from @json to allow detection of
 * node names that were auto-assigned by qemu. This is a best-effort operation
 * and may not be successful. The returned hash table contains the entries as
 * qemuBlockNodeNameBackingChainDataPtr accessible by the node name. The fields
 * then can be used to recover the full backing chain.
 *
 * Returns a hash table on success and NULL on failure.
 */
virHashTablePtr
qemuBlockNodeNameGetBackingChain(virJSONValuePtr namednodes,
                                 virJSONValuePtr blockstats)
{
    struct qemuBlockNodeNameGetBackingChainData data;
    virHashTablePtr namednodestable = NULL;
    virHashTablePtr disks = NULL;
    virHashTablePtr ret = NULL;

    memset(&data, 0, sizeof(data));

    if (!(namednodestable = virHashCreate(50, virJSONValueHashFree)))
        goto cleanup;

    if (virJSONValueArrayForeachSteal(namednodes,
                                      qemuBlockNamedNodesArrayToHash,
                                      namednodestable) < 0)
        goto cleanup;

    if (!(disks = virHashCreate(50, qemuBlockNodeNameBackingChainDataHashEntryFree)))
        goto cleanup;

    data.nodenamestable = namednodestable;
    data.disks = disks;

    if (virJSONValueArrayForeachSteal(blockstats,
                                      qemuBlockNodeNameGetBackingChainDisk,
                                      &data) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, disks);

 cleanup:
     virHashFree(namednodestable);
     virHashFree(disks);

     return ret;
}


static void
qemuBlockDiskClearDetectedNodes(virDomainDiskDefPtr disk)
{
    virStorageSourcePtr next = disk->src;

    while (virStorageSourceIsBacking(next)) {
        VIR_FREE(next->nodeformat);
        VIR_FREE(next->nodestorage);

        next = next->backingStore;
    }
}


static int
qemuBlockDiskDetectNodes(virDomainDiskDefPtr disk,
                         virHashTablePtr disktable)
{
    qemuBlockNodeNameBackingChainDataPtr entry = NULL;
    virStorageSourcePtr src = disk->src;
    char *alias = NULL;
    int ret = -1;

    /* don't attempt the detection if the top level already has node names */
    if (src->nodeformat || src->nodestorage)
        return 0;

    if (!(alias = qemuAliasDiskDriveFromDisk(disk)))
        goto cleanup;

    if (!(entry = virHashLookup(disktable, alias))) {
        ret = 0;
        goto cleanup;
    }

    while (virStorageSourceIsBacking(src) && entry) {
        if (src->nodeformat || src->nodestorage) {
            if (STRNEQ_NULLABLE(src->nodeformat, entry->nodeformat) ||
                STRNEQ_NULLABLE(src->nodestorage, entry->nodestorage))
                goto cleanup;

            break;
        } else {
            if (VIR_STRDUP(src->nodeformat, entry->nodeformat) < 0 ||
                VIR_STRDUP(src->nodestorage, entry->nodestorage) < 0)
                goto cleanup;
        }

        entry = entry->backing;
        src = src->backingStore;
    }

    ret = 0;

 cleanup:
    VIR_FREE(alias);
    if (ret < 0)
        qemuBlockDiskClearDetectedNodes(disk);

    return ret;
}


int
qemuBlockNodeNamesDetect(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr disktable = NULL;
    virJSONValuePtr data = NULL;
    virJSONValuePtr blockstats = NULL;
    virDomainDiskDefPtr disk;
    size_t i;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QUERY_NAMED_BLOCK_NODES))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    data = qemuMonitorQueryNamedBlockNodes(qemuDomainGetMonitor(vm));
    blockstats = qemuMonitorQueryBlockstats(qemuDomainGetMonitor(vm));

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || !data || !blockstats)
        goto cleanup;

    if (!(disktable = qemuBlockNodeNameGetBackingChain(data, blockstats)))
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];

        if (qemuBlockDiskDetectNodes(disk, disktable) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(data);
    virJSONValueFree(blockstats);
    virHashFree(disktable);

    return ret;
}


/**
 * qemuBlockGetNodeData:
 * @data: JSON object returned from query-named-block-nodes
 *
 * Returns a hash table organized by the node name of the JSON value objects of
 * data for given qemu block nodes.
 *
 * Returns a filled virHashTablePtr on success NULL on error.
 */
virHashTablePtr
qemuBlockGetNodeData(virJSONValuePtr data)
{
    virHashTablePtr ret = NULL;

    if (!(ret = virHashCreate(50, virJSONValueHashFree)))
        return NULL;

    if (virJSONValueArrayForeachSteal(data,
                                      qemuBlockNamedNodesArrayToHash, ret) < 0)
        goto error;

    return ret;

 error:
    virHashFree(ret);
    return NULL;
}


/**
 * qemuBlockStorageSourceSupportsConcurrentAccess:
 * @src: disk storage source
 *
 * Returns true if the given storage format supports concurrent access from two
 * separate processes.
 */
bool
qemuBlockStorageSourceSupportsConcurrentAccess(virStorageSourcePtr src)
{
    /* no need to check in backing chain since only RAW storage supports this */
    return src->format == VIR_STORAGE_FILE_RAW;
}


/**
 * qemuBlockStorageSourceGetURI:
 * @src: disk storage source
 *
 * Formats a URI from a virStorageSource.
 */
virURIPtr
qemuBlockStorageSourceGetURI(virStorageSourcePtr src)
{
    virURIPtr uri = NULL;
    virURIPtr ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("protocol '%s' accepts only one host"),
                       virStorageNetProtocolTypeToString(src->protocol));
        goto cleanup;
    }

    if (VIR_ALLOC(uri) < 0)
        goto cleanup;

    if (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {
        uri->port = src->hosts->port;

        if (VIR_STRDUP(uri->scheme,
                       virStorageNetProtocolTypeToString(src->protocol)) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&uri->scheme, "%s+%s",
                        virStorageNetProtocolTypeToString(src->protocol),
                        virStorageNetHostTransportTypeToString(src->hosts->transport)) < 0)
            goto cleanup;
    }

    if (src->path) {
        if (src->volume) {
            if (virAsprintf(&uri->path, "/%s/%s",
                            src->volume, src->path) < 0)
                goto cleanup;
        } else {
            if (virAsprintf(&uri->path, "%s%s",
                            src->path[0] == '/' ? "" : "/",
                            src->path) < 0)
                goto cleanup;
        }
    }

    if (VIR_STRDUP(uri->server, src->hosts->name) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, uri);

 cleanup:
    virURIFree(uri);
    return ret;
}


/**
 * qemuBlockStorageSourceBuildJSONSocketAddress
 * @host: the virStorageNetHostDefPtr definition to build
 * @legacy: use old field names/values
 *
 * Formats @hosts into a json object conforming to the 'SocketAddress' type
 * in qemu.
 *
 * For compatibility with old approach used in the gluster driver of old qemus
 * use the old spelling for TCP transport and, the path field of the unix socket.
 *
 * Returns a virJSONValuePtr for a single server.
 */
static virJSONValuePtr
qemuBlockStorageSourceBuildJSONSocketAddress(virStorageNetHostDefPtr host,
                                             bool legacy)
{
    virJSONValuePtr server = NULL;
    virJSONValuePtr ret = NULL;
    const char *transport;
    const char *field;
    char *port = NULL;

    switch ((virStorageNetHostTransport) host->transport) {
    case VIR_STORAGE_NET_HOST_TRANS_TCP:
        if (legacy)
            transport = "tcp";
        else
            transport = "inet";

        if (virAsprintf(&port, "%u", host->port) < 0)
            goto cleanup;

        if (virJSONValueObjectCreate(&server,
                                     "s:type", transport,
                                     "s:host", host->name,
                                     "s:port", port,
                                     NULL) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_UNIX:
        if (legacy)
            field = "s:socket";
        else
            field = "s:path";

        if (virJSONValueObjectCreate(&server,
                                     "s:type", "unix",
                                     field, host->socket,
                                     NULL) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_RDMA:
    case VIR_STORAGE_NET_HOST_TRANS_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("transport protocol '%s' is not yet supported"),
                       virStorageNetHostTransportTypeToString(host->transport));
        goto cleanup;
    }

    VIR_STEAL_PTR(ret, server);

 cleanup:
    VIR_FREE(port);
    virJSONValueFree(server);

    return ret;
}


/**
 * qemuBlockStorageSourceBuildHostsJSONSocketAddress:
 * @src: disk storage source
 * @legacy: use 'tcp' instead of 'inet' for compatibility reasons
 *
 * Formats src->hosts into a json object conforming to the 'SocketAddress' type
 * in qemu.
 */
static virJSONValuePtr
qemuBlockStorageSourceBuildHostsJSONSocketAddress(virStorageSourcePtr src,
                                                  bool legacy)
{
    virJSONValuePtr servers = NULL;
    virJSONValuePtr server = NULL;
    virJSONValuePtr ret = NULL;
    virStorageNetHostDefPtr host;
    size_t i;

    if (!(servers = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONSocketAddress(host, legacy)))
              goto cleanup;

        if (virJSONValueArrayAppend(servers, server) < 0)
            goto cleanup;

        server = NULL;
    }

    VIR_STEAL_PTR(ret, servers);

 cleanup:
    virJSONValueFree(servers);
    virJSONValueFree(server);

    return ret;
}


/**
 * qemuBlockStorageSourceBuildJSONInetSocketAddress
 * @host: the virStorageNetHostDefPtr definition to build
 *
 * Formats @hosts into a json object conforming to the 'InetSocketAddress' type
 * in qemu.
 *
 * Returns a virJSONValuePtr for a single server.
 */
static virJSONValuePtr
qemuBlockStorageSourceBuildJSONInetSocketAddress(virStorageNetHostDefPtr host)
{
    virJSONValuePtr ret = NULL;
    char *port = NULL;

    if (host->transport != VIR_STORAGE_NET_HOST_TRANS_TCP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("only TCP protocol can be converted to InetSocketAddress"));
        return NULL;
    }

    if (virAsprintf(&port, "%u", host->port) < 0)
        return NULL;

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:host", host->name,
                                          "s:port", port,
                                          NULL));

    VIR_FREE(port);
    return ret;
}


/**
 * qemuBlockStorageSourceBuildHostsJSONInetSocketAddress:
 * @src: disk storage source
 *
 * Formats src->hosts into a json object conforming to the 'InetSocketAddress'
 * type in qemu.
 */
static virJSONValuePtr
qemuBlockStorageSourceBuildHostsJSONInetSocketAddress(virStorageSourcePtr src)
{
    virJSONValuePtr servers = NULL;
    virJSONValuePtr server = NULL;
    virJSONValuePtr ret = NULL;
    virStorageNetHostDefPtr host;
    size_t i;

    if (!(servers = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(host)))
            goto cleanup;

        if (virJSONValueArrayAppend(servers, server) < 0)
            goto cleanup;

        server = NULL;
    }

    VIR_STEAL_PTR(ret, servers);

 cleanup:
    virJSONValueFree(servers);
    virJSONValueFree(server);

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetGlusterProps(virStorageSourcePtr src,
                                      bool legacy)
{
    virJSONValuePtr servers = NULL;
    virJSONValuePtr props = NULL;
    virJSONValuePtr ret = NULL;

    if (!(servers = qemuBlockStorageSourceBuildHostsJSONSocketAddress(src, legacy)))
        return NULL;

     /* { driver:"gluster",
      *   volume:"testvol",
      *   path:"/a.img",
      *   server :[{type:"tcp", host:"1.2.3.4", port:24007},
      *            {type:"unix", socket:"/tmp/glusterd.socket"}, ...]}
      */
    if (virJSONValueObjectCreate(&props,
                                 "s:driver", "gluster",
                                 "s:volume", src->volume,
                                 "s:path", src->path,
                                 "a:server", &servers, NULL) < 0)
        goto cleanup;

    if (src->debug &&
        virJSONValueObjectAdd(props, "u:debug", src->debugLevel, NULL) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, props);

 cleanup:
    virJSONValueFree(servers);
    virJSONValueFree(props);

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetVxHSProps(virStorageSourcePtr src)
{
    const char *protocol = virStorageNetProtocolTypeToString(src->protocol);
    virJSONValuePtr server = NULL;
    virJSONValuePtr ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VxHS protocol accepts only one host"));
        return NULL;
    }

    if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(&src->hosts[0])))
        return NULL;

    /* VxHS disk specification example:
     * { driver:"vxhs",
     *   tls-creds:"objvirtio-disk0_tls0",
     *   vdisk-id:"eb90327c-8302-4725-4e85ed4dc251",
     *   server:{type:"tcp", host:"1.2.3.4", port:9999}}
     */
    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", protocol,
                                 "S:tls-creds", src->tlsAlias,
                                 "s:vdisk-id", src->path,
                                 "a:server", &server, NULL) < 0)
        virJSONValueFree(server);

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetCURLProps(virStorageSourcePtr src)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *passwordalias = NULL;
    const char *username = NULL;
    virJSONValuePtr ret = NULL;
    virURIPtr uri = NULL;
    char *uristr = NULL;
    const char *driver;

    /**
     * Common options:
     * url, readahead, timeout, username, password-secret, proxy-username,
     * proxy-password-secret
     *
     * Options for http transport:
     * cookie, cookie-secret
     *
     * Options for secure transport (ftps, https):
     * sslverify
     */

    driver = virStorageNetProtocolTypeToString(src->protocol);

    if (!(uri = qemuBlockStorageSourceGetURI(src)))
        goto cleanup;

    if (!(uristr = virURIFormat(uri)))
        goto cleanup;

    if (src->auth) {
        username = src->auth->username;
        passwordalias = srcPriv->secinfo->s.aes.alias;
    }

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:driver", driver,
                                          "s:url", uristr,
                                          "S:username", username,
                                          "S:password-secret", passwordalias,
                                          NULL));

 cleanup:
    virURIFree(uri);
    VIR_FREE(uristr);

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetISCSIProps(virStorageSourcePtr src)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *protocol = virStorageNetProtocolTypeToString(src->protocol);
    char *target = NULL;
    char *lunStr = NULL;
    char *username = NULL;
    char *objalias = NULL;
    char *portal = NULL;
    unsigned int lun = 0;
    virJSONValuePtr ret = NULL;

    /* { driver:"iscsi",
     *   transport:"tcp",  ("iser" also possible)
     *   portal:"example.com",
     *   target:"iqn.2017-04.com.example:iscsi-disks",
     *   lun:1,
     *   user:"username",
     *   password-secret:"secret-alias",
     * }
     */

    if (VIR_STRDUP(target, src->path) < 0)
        goto cleanup;

    /* Separate the target and lun */
    if ((lunStr = strchr(target, '/'))) {
        *(lunStr++) = '\0';
        if (virStrToLong_ui(lunStr, NULL, 10, &lun) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse target for lunStr '%s'"),
                           target);
            goto cleanup;
        }
    }

    /* combine host and port into portal */
    if (virSocketAddrNumericFamily(src->hosts[0].name) == AF_INET6) {
        if (virAsprintf(&portal, "[%s]:%u",
                        src->hosts[0].name, src->hosts[0].port) < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&portal, "%s:%u",
                        src->hosts[0].name, src->hosts[0].port) < 0)
            goto cleanup;
    }

    if (src->auth) {
        username = src->auth->username;
        objalias = srcPriv->secinfo->s.aes.alias;
    }

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:driver", protocol,
                                          "s:portal", portal,
                                          "s:target", target,
                                          "u:lun", lun,
                                          "s:transport", "tcp",
                                          "S:user", username,
                                          "S:password-secret", objalias,
                                          NULL));
        goto cleanup;

 cleanup:
    VIR_FREE(target);
    VIR_FREE(portal);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetNBDProps(virStorageSourcePtr src)
{
    virJSONValuePtr serverprops;
    virJSONValuePtr ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("nbd protocol accepts only one host"));
        return NULL;
    }

    serverprops = qemuBlockStorageSourceBuildJSONSocketAddress(&src->hosts[0],
                                                               false);
    if (!serverprops)
        return NULL;

    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "nbd",
                                 "a:server", &serverprops,
                                 "S:export", src->path,
                                 "S:tls-creds", src->tlsAlias,
                                 NULL) < 0)
        goto cleanup;

 cleanup:
    virJSONValueFree(serverprops);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetRBDProps(virStorageSourcePtr src)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    virJSONValuePtr servers = NULL;
    virJSONValuePtr ret = NULL;
    const char *username = NULL;

    if (src->nhosts > 0 &&
        !(servers = qemuBlockStorageSourceBuildHostsJSONInetSocketAddress(src)))
        return NULL;

    if (src->auth)
        username = srcPriv->secinfo->s.aes.username;

    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "rbd",
                                 "s:pool", src->volume,
                                 "s:image", src->path,
                                 "S:snapshot", src->snapshot,
                                 "S:conf", src->configFile,
                                 "A:server", &servers,
                                 "S:user", username,
                                 NULL) < 0)
        goto cleanup;

 cleanup:
    virJSONValueFree(servers);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetSheepdogProps(virStorageSourcePtr src)
{
    virJSONValuePtr serverprops;
    virJSONValuePtr ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("sheepdog protocol accepts only one host"));
        return NULL;
    }

    serverprops = qemuBlockStorageSourceBuildJSONSocketAddress(&src->hosts[0],
                                                               false);
    if (!serverprops)
        return NULL;

    /* libvirt does not support the 'snap-id' and 'tag' properties */
    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "sheepdog",
                                 "a:server", &serverprops,
                                 "s:vdi", src->path,
                                 NULL) < 0)
        goto cleanup;

 cleanup:
    virJSONValueFree(serverprops);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetSshProps(virStorageSourcePtr src)
{
    virJSONValuePtr serverprops;
    virJSONValuePtr ret = NULL;
    const char *username = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("sheepdog protocol accepts only one host"));
        return NULL;
    }

    serverprops = qemuBlockStorageSourceBuildJSONInetSocketAddress(&src->hosts[0]);
    if (!serverprops)
        return NULL;

    if (src->auth)
        username = src->auth->username;

    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "ssh",
                                 "s:path", src->path,
                                 "a:server", &serverprops,
                                 "S:user", username,
                                 NULL) < 0)
        goto cleanup;

 cleanup:
    virJSONValueFree(serverprops);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetFileProps(virStorageSourcePtr src)
{
    const char *driver = "file";
    const char *iomode = NULL;
    const char *prManagerAlias = NULL;
    virJSONValuePtr ret = NULL;

    if (src->iomode != VIR_DOMAIN_DISK_IO_DEFAULT)
        iomode = virDomainDiskIoTypeToString(src->iomode);

    if (virStorageSourceIsBlockLocal(src)) {
        if (src->hostcdrom)
            driver = "host_cdrom";
        else
            driver = "host_device";
    }

    if (src->pr)
        prManagerAlias = src->pr->mgralias;

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:driver", driver,
                                          "s:filename", src->path,
                                          "S:aio", iomode,
                                          "S:pr-manager", prManagerAlias,
                                          NULL) < 0);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetVvfatProps(virStorageSourcePtr src)
{
    virJSONValuePtr ret = NULL;

    /* libvirt currently does not handle the following attributes:
     * '*fat-type': 'int'
     * '*label': 'str'
     */
    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:driver", "vvfat",
                                          "s:dir", src->path,
                                          "b:floppy", src->floppyimg,
                                          "b:rw", !src->readonly, NULL));

    return ret;
}


static int
qemuBlockStorageSourceGetBlockdevGetCacheProps(virStorageSourcePtr src,
                                               virJSONValuePtr props)
{
    virJSONValuePtr cacheobj;
    bool direct = false;
    bool noflush = false;

    if (src->cachemode == VIR_DOMAIN_DISK_CACHE_DEFAULT)
        return 0;

    if (qemuDomainDiskCachemodeFlags(src->cachemode, NULL, &direct, &noflush) < 0)
        return -1;

    if (virJSONValueObjectCreate(&cacheobj,
                                 "b:direct", direct,
                                 "b:no-flush", noflush,
                                 NULL) < 0)
        return -1;

    if (virJSONValueObjectAppend(props, "cache", cacheobj) < 0) {
        virJSONValueFree(cacheobj);
        return -1;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceGetBackendProps:
 * @src: disk source
 * @legacy: use legacy formatting of attributes (for -drive / old qemus)
 *
 * Creates a JSON object describing the underlying storage or protocol of a
 * storage source. Returns NULL on error and reports an appropriate error message.
 */
virJSONValuePtr
qemuBlockStorageSourceGetBackendProps(virStorageSourcePtr src,
                                      bool legacy)
{
    int actualType = virStorageSourceGetActualType(src);
    virJSONValuePtr fileprops = NULL;
    virJSONValuePtr ret = NULL;

    switch ((virStorageType)actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        if (!(fileprops = qemuBlockStorageSourceGetFileProps(src)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_DIR:
        /* qemu handles directories by exposing them as a device with emulated
         * FAT filesystem */
        if (!(fileprops = qemuBlockStorageSourceGetVvfatProps(src)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return NULL;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            if (!(fileprops = qemuBlockStorageSourceGetGlusterProps(src, legacy)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_VXHS:
            if (!(fileprops = qemuBlockStorageSourceGetVxHSProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            if (!(fileprops = qemuBlockStorageSourceGetCURLProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
            if (!(fileprops = qemuBlockStorageSourceGetISCSIProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
            if (!(fileprops = qemuBlockStorageSourceGetNBDProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            if (!(fileprops = qemuBlockStorageSourceGetRBDProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            if (!(fileprops = qemuBlockStorageSourceGetSheepdogProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            if (!(fileprops = qemuBlockStorageSourceGetSshProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            return NULL;
        }
        break;
    }

    if (qemuBlockNodeNameValidate(src->nodestorage) < 0 ||
        virJSONValueObjectAdd(fileprops, "S:node-name", src->nodestorage, NULL) < 0)
        goto cleanup;

    if (!legacy) {
        if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, fileprops) < 0)
            goto cleanup;

        if (virJSONValueObjectAdd(fileprops,
                                  "b:read-only", src->readonly,
                                  "s:discard", "unmap",
                                  NULL) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(ret, fileprops);

 cleanup:
    virJSONValueFree(fileprops);
    return ret;
}


static int
qemuBlockStorageSourceGetFormatRawProps(virStorageSourcePtr src,
                                        virJSONValuePtr props)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *driver = "raw";
    const char *secretalias = NULL;

    if (src->encryption &&
        src->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
        srcPriv &&
        srcPriv->encinfo) {
        driver = "luks";
        secretalias = srcPriv->encinfo->s.aes.alias;
    }

    /* currently unhandled properties for the 'raw' driver:
     * 'offset'
     * 'size'
     */

    if (virJSONValueObjectAdd(props,
                              "s:driver", driver,
                              "S:key-secret", secretalias, NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceGetCryptoProps(virStorageSourcePtr src,
                                     virJSONValuePtr *encprops)
{
    qemuDomainStorageSourcePrivatePtr srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *encformat = NULL;

    *encprops = NULL;

    /* qemu requires encrypted secrets regardless of encryption method used when
     * passed using the blockdev infrastructure, thus only
     * VIR_DOMAIN_SECRET_INFO_TYPE_AES works here. The correct type needs to be
     * instantiated elsewhere. */
    if (!src->encryption ||
        !srcpriv ||
        !srcpriv->encinfo ||
        srcpriv->encinfo->type != VIR_DOMAIN_SECRET_INFO_TYPE_AES)
        return 0;

    switch ((virStorageEncryptionFormatType) src->encryption->format) {
    case VIR_STORAGE_ENCRYPTION_FORMAT_QCOW:
        encformat = "aes";
        break;

    case VIR_STORAGE_ENCRYPTION_FORMAT_LUKS:
        encformat = "luks";
        break;

    case VIR_STORAGE_ENCRYPTION_FORMAT_DEFAULT:
    case VIR_STORAGE_ENCRYPTION_FORMAT_LAST:
    default:
        virReportEnumRangeError(virStorageEncryptionFormatType,
                                src->encryption->format);
        return -1;
    }

    return virJSONValueObjectCreate(encprops,
                                    "s:format", encformat,
                                    "s:key-secret", srcpriv->encinfo->s.aes.alias,
                                    NULL);
}


static int
qemuBlockStorageSourceGetFormatQcowGenericProps(virStorageSourcePtr src,
                                                const char *format,
                                                virJSONValuePtr props)
{
    virJSONValuePtr encprops = NULL;
    int ret = -1;

    if (qemuBlockStorageSourceGetCryptoProps(src, &encprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(props,
                              "s:driver", format,
                              "A:encrypt", &encprops, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(encprops);
    return ret;
}


static int
qemuBlockStorageSourceGetFormatQcow2Props(virStorageSourcePtr src,
                                          virJSONValuePtr props)
{
    /* currently unhandled qcow2 props:
     *
     * 'lazy-refcounts'
     * 'pass-discard-request'
     * 'pass-discard-snapshot'
     * 'pass-discard-other'
     * 'overlap-check'
     * 'l2-cache-size'
     * 'l2-cache-entry-size'
     * 'refcount-cache-size'
     * 'cache-clean-interval'
     */

    if (qemuBlockStorageSourceGetFormatQcowGenericProps(src, "qcow2", props) < 0)
        return -1;

    return 0;
}


static virJSONValuePtr
qemuBlockStorageSourceGetBlockdevFormatCommonProps(virStorageSourcePtr src)
{
    const char *detectZeroes = NULL;
    const char *discard = NULL;
    int detectZeroesMode = virDomainDiskGetDetectZeroesMode(src->discard,
                                                            src->detect_zeroes);
    virJSONValuePtr props = NULL;
    virJSONValuePtr ret = NULL;

    if (qemuBlockNodeNameValidate(src->nodeformat) < 0)
        return NULL;

    if (src->discard)
        discard = virDomainDiskDiscardTypeToString(src->discard);

    if (detectZeroesMode)
        detectZeroes = virDomainDiskDetectZeroesTypeToString(detectZeroesMode);

    /* currently unhandled global properties:
     * '*force-share': 'bool'
     */

    if (virJSONValueObjectCreate(&props,
                                 "s:node-name", src->nodeformat,
                                 "b:read-only", src->readonly,
                                 "S:discard", discard,
                                 "S:detect-zeroes", detectZeroes,
                                 NULL) < 0)
        return NULL;

    if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, props) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, props);

 cleanup:
    virJSONValueFree(props);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetBlockdevFormatProps(virStorageSourcePtr src)
{
    const char *driver = NULL;
    virJSONValuePtr props = NULL;
    virJSONValuePtr ret = NULL;

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatCommonProps(src)))
        goto cleanup;

    switch ((virStorageFileFormat) src->format) {
    case VIR_STORAGE_FILE_FAT:
        /* The fat layer is emulated by the storage access layer, so we need to
         * put a raw layer on top */
    case VIR_STORAGE_FILE_RAW:
        if (qemuBlockStorageSourceGetFormatRawProps(src, props) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_FILE_QCOW2:
        if (qemuBlockStorageSourceGetFormatQcow2Props(src, props) < 0)
            goto cleanup;
        break;

    case VIR_STORAGE_FILE_QCOW:
        if (qemuBlockStorageSourceGetFormatQcowGenericProps(src, "qcow", props) < 0)
            goto cleanup;
        break;

    /* formats without any special parameters */
    case VIR_STORAGE_FILE_PLOOP:
        driver = "parallels";
        break;

    case VIR_STORAGE_FILE_VHD:
        driver = "vhdx";
        break;

    case VIR_STORAGE_FILE_BOCHS:
    case VIR_STORAGE_FILE_CLOOP:
    case VIR_STORAGE_FILE_DMG:
    case VIR_STORAGE_FILE_VDI:
    case VIR_STORAGE_FILE_VPC:
    case VIR_STORAGE_FILE_QED:
    case VIR_STORAGE_FILE_VMDK:
        driver = virStorageFileFormatTypeToString(src->format);
        break;

    case VIR_STORAGE_FILE_AUTO_SAFE:
    case VIR_STORAGE_FILE_AUTO:
    case VIR_STORAGE_FILE_NONE:
    case VIR_STORAGE_FILE_COW:
    case VIR_STORAGE_FILE_ISO:
    case VIR_STORAGE_FILE_DIR:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("mishandled storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        goto cleanup;

    case VIR_STORAGE_FILE_LAST:
    default:
        virReportEnumRangeError(virStorageFileFormat, src->format);
        goto cleanup;
    }

    if (driver &&
        virJSONValueObjectAdd(props, "s:driver", driver, NULL) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, props);

 cleanup:
    virJSONValueFree(props);

    return ret;
}


/**
 * qemuBlockStorageSourceGetBlockdevProps:
 *
 * @src: storage source to format
 *
 * Formats @src into a JSON object which can be used with blockdev-add or
 * -blockdev. The formatted object contains both the storage and format layer
 * in nested form including link to the backing chain layer if necessary.
 */
virJSONValuePtr
qemuBlockStorageSourceGetBlockdevProps(virStorageSourcePtr src)
{
    bool backingSupported = src->format >= VIR_STORAGE_FILE_BACKING;
    virJSONValuePtr props = NULL;
    virJSONValuePtr ret = NULL;

    if (virStorageSourceHasBacking(src) && !backingSupported) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("storage format '%s' does not support backing store"),
                       virStorageFileFormatTypeToString(src->format));
        goto cleanup;
    }

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatProps(src)))
        goto cleanup;

    if (virJSONValueObjectAppendString(props, "file", src->nodestorage) < 0)
        goto cleanup;

    if (src->backingStore && backingSupported) {
        if (virStorageSourceHasBacking(src)) {
            if (virJSONValueObjectAppendString(props, "backing",
                                               src->backingStore->nodeformat) < 0)
                goto cleanup;
        } else {
            /* chain is terminated, indicate that no detection should happen
             * in qemu */
            if (virJSONValueObjectAppendNull(props, "backing") < 0)
                goto cleanup;
        }
    }

    VIR_STEAL_PTR(ret, props);

 cleanup:
    virJSONValueFree(props);
    return ret;
}


void
qemuBlockStorageSourceAttachDataFree(qemuBlockStorageSourceAttachDataPtr data)
{
    if (!data)
        return;

    virJSONValueFree(data->storageProps);
    virJSONValueFree(data->formatProps);
    virJSONValueFree(data->prmgrProps);
    virJSONValueFree(data->authsecretProps);
    virJSONValueFree(data->encryptsecretProps);
    virJSONValueFree(data->tlsProps);
    VIR_FREE(data->tlsAlias);
    VIR_FREE(data->authsecretAlias);
    VIR_FREE(data->encryptsecretAlias);
    VIR_FREE(data->driveCmd);
    VIR_FREE(data->driveAlias);
    VIR_FREE(data);
}


/**
 * qemuBlockStorageSourceAttachPrepareBlockdev:
 * @src: storage source to prepare data from
 *
 * Creates a qemuBlockStorageSourceAttachData structure containing data to attach
 * @src to a VM using the blockdev-add approach. Note that this function only
 * creates the data for the storage source itself, any other related
 * authentication/encryption/... objects need to be prepared separately.
 *
 * The changes are then applied using qemuBlockStorageSourceAttachApply.
 *
 * Returns the filled data structure on success or NULL on error and a libvirt
 * error is reported
 */
qemuBlockStorageSourceAttachDataPtr
qemuBlockStorageSourceAttachPrepareBlockdev(virStorageSourcePtr src)
{
    qemuBlockStorageSourceAttachDataPtr data;
    qemuBlockStorageSourceAttachDataPtr ret = NULL;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    if (!(data->formatProps = qemuBlockStorageSourceGetBlockdevProps(src)) ||
        !(data->storageProps = qemuBlockStorageSourceGetBackendProps(src, false)))
        goto cleanup;

    data->storageNodeName = src->nodestorage;
    data->formatNodeName = src->nodeformat;

    VIR_STEAL_PTR(ret, data);

 cleanup:
    qemuBlockStorageSourceAttachDataFree(data);
    return ret;
}


/**
 * qemuBlockStorageSourceAttachApply:
 * @mon: monitor object
 * @data: structure holding data of block device to apply
 *
 * Attaches a virStorageSource definition converted to
 * qemuBlockStorageSourceAttachData to a running VM. This function expects being
 * called after the monitor was entered.
 *
 * Returns 0 on success and -1 on error with a libvirt error reported. If an
 * error occured, changes which were already applied need to be rolled back by
 * calling qemuBlockStorageSourceAttachRollback.
 */
int
qemuBlockStorageSourceAttachApply(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceAttachDataPtr data)
{
    int rv;

    if (data->prmgrProps &&
        qemuMonitorAddObject(mon, &data->prmgrProps, &data->prmgrAlias) < 0)
        return -1;

    if (data->authsecretProps &&
        qemuMonitorAddObject(mon, &data->authsecretProps,
                             &data->authsecretAlias) < 0)
        return -1;

    if (data->encryptsecretProps &&
        qemuMonitorAddObject(mon, &data->encryptsecretProps,
                             &data->encryptsecretAlias) < 0)
        return -1;

    if (data->tlsProps &&
        qemuMonitorAddObject(mon, &data->tlsProps, &data->tlsAlias) < 0)
        return -1;

    if (data->storageProps) {
        rv = qemuMonitorBlockdevAdd(mon, data->storageProps);
        data->storageProps = NULL;

        if (rv < 0)
            return -1;

        data->storageAttached = true;
    }

    if (data->formatProps) {
        rv = qemuMonitorBlockdevAdd(mon, data->formatProps);
        data->formatProps = NULL;

        if (rv < 0)
            return -1;

        data->formatAttached = true;
    }

    if (data->driveCmd) {
        if (qemuMonitorAddDrive(mon, data->driveCmd) < 0)
            return -1;

        data->driveAdded = true;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceAttachRollback:
 * @mon: monitor object
 * @data: structure holding data of block device to roll back
 *
 * Attempts a best effort rollback of changes which were made to a running VM by
 * qemuBlockStorageSourceAttachApply. Preserves any existing errors.
 *
 * This function expects being called after the monitor was entered.
 */
void
qemuBlockStorageSourceAttachRollback(qemuMonitorPtr mon,
                                     qemuBlockStorageSourceAttachDataPtr data)
{
    virErrorPtr orig_err;

    virErrorPreserveLast(&orig_err);

    if (data->driveAdded) {
        if (qemuMonitorDriveDel(mon, data->driveAlias) < 0)
            VIR_WARN("Unable to remove drive %s (%s) after failed "
                     "qemuMonitorAddDevice", data->driveAlias, data->driveCmd);
    }

    if (data->formatAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->formatNodeName));

    if (data->storageAttached)
        ignore_value(qemuMonitorBlockdevDel(mon, data->storageNodeName));

    if (data->prmgrAlias)
        ignore_value(qemuMonitorDelObject(mon, data->prmgrAlias));

    if (data->authsecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->authsecretAlias));

    if (data->encryptsecretAlias)
        ignore_value(qemuMonitorDelObject(mon, data->encryptsecretAlias));

    if (data->tlsAlias)
        ignore_value(qemuMonitorDelObject(mon, data->tlsAlias));


    virErrorRestore(&orig_err);
}


/**
 * qemuBlockStorageSourceDetachOneBlockdev:
 * @driver: qemu driver object
 * @vm: domain object
 * @asyncJob: currently running async job
 * @src: storage source to detach
 *
 * Detaches one virStorageSource using blockdev-del. Note that this does not
 * detach any authentication/encryption objects. This function enters the
 * monitor internally.
 */
int
qemuBlockStorageSourceDetachOneBlockdev(virQEMUDriverPtr driver,
                                        virDomainObjPtr vm,
                                        qemuDomainAsyncJob asyncJob,
                                        virStorageSourcePtr src)
{
    int ret;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorBlockdevDel(qemuDomainGetMonitor(vm), src->nodeformat);

    if (ret == 0)
        ret = qemuMonitorBlockdevDel(qemuDomainGetMonitor(vm), src->nodestorage);

    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    return ret;
}
