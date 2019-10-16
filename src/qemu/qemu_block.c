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
#include "qemu_command.h"
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
qemuBlockNamedNodesArrayToHash(size_t pos G_GNUC_UNUSED,
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

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockNodeNameBackingChainData,
                        qemuBlockNodeNameBackingChainDataFree);


static void
qemuBlockNodeNameBackingChainDataHashEntryFree(void *opaque,
                                               const void *name G_GNUC_UNUSED)
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
    g_autoptr(qemuBlockNodeNameBackingChainData) data = NULL;
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
        return -1;

    if (VIR_STRDUP(data->nodeformat, nodename) < 0 ||
        VIR_STRDUP(data->nodestorage, parentnodename) < 0 ||
        VIR_STRDUP(data->qemufilename, filename) < 0 ||
        VIR_STRDUP(data->drvformat, drvname) < 0 ||
        VIR_STRDUP(data->drvstorage, drvparent) < 0)
        return -1;

    if (backing &&
        qemuBlockNodeNameGetBackingChainBacking(backing, nodenamestable,
                                                &backingdata) < 0)
        return -1;

    data->backing = g_steal_pointer(&backingdata);
    *nodenamedata = g_steal_pointer(&data);

    return 0;
}


static int
qemuBlockNodeNameGetBackingChainDisk(size_t pos G_GNUC_UNUSED,
                                     virJSONValuePtr item,
                                     void *opaque)
{
    struct qemuBlockNodeNameGetBackingChainData *data = opaque;
    const char *device = virJSONValueObjectGetString(item, "device");
    g_autoptr(qemuBlockNodeNameBackingChainData) devicedata = NULL;

    if (qemuBlockNodeNameGetBackingChainBacking(item, data->nodenamestable,
                                                &devicedata) < 0)
        return -1;

    if (devicedata &&
        virHashAddEntry(data->disks, device, devicedata) < 0)
        return -1;

    devicedata = NULL;
    return 1; /* we don't really want to steal @item */
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
    g_autoptr(virHashTable) namednodestable = NULL;
    g_autoptr(virHashTable) disks = NULL;

    memset(&data, 0, sizeof(data));

    if (!(namednodestable = virHashCreate(50, virJSONValueHashFree)))
        return NULL;

    if (virJSONValueArrayForeachSteal(namednodes,
                                      qemuBlockNamedNodesArrayToHash,
                                      namednodestable) < 0)
        return NULL;

    if (!(disks = virHashCreate(50, qemuBlockNodeNameBackingChainDataHashEntryFree)))
        return NULL;

    data.nodenamestable = namednodestable;
    data.disks = disks;

    if (virJSONValueArrayForeachSteal(blockstats,
                                      qemuBlockNodeNameGetBackingChainDisk,
                                      &data) < 0)
        return NULL;

    return g_steal_pointer(&disks);
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
    g_autofree char *alias = NULL;
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
    g_autoptr(virHashTable) disktable = NULL;
    g_autoptr(virJSONValue) data = NULL;
    g_autoptr(virJSONValue) blockstats = NULL;
    virDomainDiskDefPtr disk;
    size_t i;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QUERY_NAMED_BLOCK_NODES))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    data = qemuMonitorQueryNamedBlockNodes(qemuDomainGetMonitor(vm));
    blockstats = qemuMonitorQueryBlockstats(qemuDomainGetMonitor(vm));

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || !data || !blockstats)
        return -1;

    if (!(disktable = qemuBlockNodeNameGetBackingChain(data, blockstats)))
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];

        if (qemuBlockDiskDetectNodes(disk, disktable) < 0)
            return -1;
    }

    return 0;
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
    g_autoptr(virHashTable) nodedata = NULL;

    if (!(nodedata = virHashCreate(50, virJSONValueHashFree)))
        return NULL;

    if (virJSONValueArrayForeachSteal(data,
                                      qemuBlockNamedNodesArrayToHash, nodedata) < 0)
        return NULL;

    return g_steal_pointer(&nodedata);
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
    g_autoptr(virURI) uri = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("protocol '%s' accepts only one host"),
                       virStorageNetProtocolTypeToString(src->protocol));
        return NULL;
    }

    if (VIR_ALLOC(uri) < 0)
        return NULL;

    if (src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {
        uri->port = src->hosts->port;

        if (VIR_STRDUP(uri->scheme,
                       virStorageNetProtocolTypeToString(src->protocol)) < 0)
            return NULL;
    } else {
        if (virAsprintf(&uri->scheme, "%s+%s",
                        virStorageNetProtocolTypeToString(src->protocol),
                        virStorageNetHostTransportTypeToString(src->hosts->transport)) < 0)
            return NULL;
    }

    if (src->path) {
        if (src->volume) {
            if (virAsprintf(&uri->path, "/%s/%s",
                            src->volume, src->path) < 0)
                return NULL;
        } else {
            if (virAsprintf(&uri->path, "%s%s",
                            src->path[0] == '/' ? "" : "/",
                            src->path) < 0)
                return NULL;
        }
    }

    if (VIR_STRDUP(uri->server, src->hosts->name) < 0)
        return NULL;

    return g_steal_pointer(&uri);
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
    g_autoptr(virJSONValue) server = NULL;
    const char *transport;
    const char *field;
    g_autofree char *port = NULL;

    switch ((virStorageNetHostTransport) host->transport) {
    case VIR_STORAGE_NET_HOST_TRANS_TCP:
        if (legacy)
            transport = "tcp";
        else
            transport = "inet";

        if (virAsprintf(&port, "%u", host->port) < 0)
            return NULL;

        if (virJSONValueObjectCreate(&server,
                                     "s:type", transport,
                                     "s:host", host->name,
                                     "s:port", port,
                                     NULL) < 0)
            return NULL;
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
            return NULL;
        break;

    case VIR_STORAGE_NET_HOST_TRANS_RDMA:
    case VIR_STORAGE_NET_HOST_TRANS_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("transport protocol '%s' is not yet supported"),
                       virStorageNetHostTransportTypeToString(host->transport));
        return NULL;
    }

    return g_steal_pointer(&server);
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
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) server = NULL;
    virStorageNetHostDefPtr host;
    size_t i;

    if (!(servers = virJSONValueNewArray()))
        return NULL;

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONSocketAddress(host, legacy)))
              return NULL;

        if (virJSONValueArrayAppend(servers, server) < 0)
            return NULL;

        server = NULL;
    }

    return g_steal_pointer(&servers);
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
    g_autofree char *port = NULL;

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
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) server = NULL;
    virStorageNetHostDefPtr host;
    size_t i;

    if (!(servers = virJSONValueNewArray()))
        return NULL;

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

        if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(host)))
            return NULL;

        if (virJSONValueArrayAppend(servers, server) < 0)
            return NULL;

        server = NULL;
    }

    return g_steal_pointer(&servers);
}


static virJSONValuePtr
qemuBlockStorageSourceGetGlusterProps(virStorageSourcePtr src,
                                      bool legacy,
                                      bool onlytarget)
{
    g_autoptr(virJSONValue) servers = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(servers = qemuBlockStorageSourceBuildHostsJSONSocketAddress(src, legacy)))
        return NULL;

     /* { driver:"gluster",
      *   volume:"testvol",
      *   path:"/a.img",
      *   server :[{type:"tcp", host:"1.2.3.4", port:24007},
      *            {type:"unix", socket:"/tmp/glusterd.socket"}, ...]}
      */
    if (virJSONValueObjectCreate(&props,
                                 "s:volume", src->volume,
                                 "s:path", src->path,
                                 "a:server", &servers, NULL) < 0)
        return NULL;

    if (!onlytarget &&
        src->debug &&
        virJSONValueObjectAdd(props, "u:debug", src->debugLevel, NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValuePtr
qemuBlockStorageSourceGetVxHSProps(virStorageSourcePtr src,
                                   bool onlytarget)
{
    g_autoptr(virJSONValue) server = NULL;
    const char *tlsAlias = src->tlsAlias;
    virJSONValuePtr ret = NULL;

    if (src->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("VxHS protocol accepts only one host"));
        return NULL;
    }

    if (!(server = qemuBlockStorageSourceBuildJSONInetSocketAddress(&src->hosts[0])))
        return NULL;

    if (onlytarget)
        tlsAlias = NULL;

    /* VxHS disk specification example:
     * { driver:"vxhs",
     *   tls-creds:"objvirtio-disk0_tls0",
     *   vdisk-id:"eb90327c-8302-4725-4e85ed4dc251",
     *   server:{type:"tcp", host:"1.2.3.4", port:9999}}
     */
    ignore_value(virJSONValueObjectCreate(&ret,
                                          "S:tls-creds", tlsAlias,
                                          "s:vdisk-id", src->path,
                                          "a:server", &server, NULL));

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetCURLProps(virStorageSourcePtr src,
                                   bool onlytarget)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    const char *passwordalias = NULL;
    const char *username = NULL;
    virJSONValuePtr ret = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *uristr = NULL;

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


    if (!(uri = qemuBlockStorageSourceGetURI(src)))
        return NULL;

    if (!(uristr = virURIFormat(uri)))
        return NULL;

    if (!onlytarget && src->auth) {
        username = src->auth->username;
        passwordalias = srcPriv->secinfo->s.aes.alias;
    }

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:url", uristr,
                                          "S:username", username,
                                          "S:password-secret", passwordalias,
                                          NULL));

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetISCSIProps(virStorageSourcePtr src,
                                    bool onlytarget)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autofree char *target = NULL;
    char *lunStr = NULL;
    char *username = NULL;
    char *objalias = NULL;
    g_autofree char *portal = NULL;
    unsigned int lun = 0;
    virJSONValuePtr ret = NULL;

    /* { driver:"iscsi",
     *   transport:"tcp",  ("iser" also possible)
     *   portal:"example.com",
     *   target:"iqn.2017-04.com.example:iscsi-disks",
     *   lun:1,
     *   user:"username",
     *   password-secret:"secret-alias",
     *   initiator-name:"iqn.2017-04.com.example:client"
     * }
     */

    if (VIR_STRDUP(target, src->path) < 0)
        return NULL;

    /* Separate the target and lun */
    if ((lunStr = strchr(target, '/'))) {
        *(lunStr++) = '\0';
        if (virStrToLong_ui(lunStr, NULL, 10, &lun) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse target for lunStr '%s'"),
                           target);
            return NULL;
        }
    }

    /* combine host and port into portal */
    if (virSocketAddrNumericFamily(src->hosts[0].name) == AF_INET6) {
        if (virAsprintf(&portal, "[%s]:%u",
                        src->hosts[0].name, src->hosts[0].port) < 0)
            return NULL;
    } else {
        if (virAsprintf(&portal, "%s:%u",
                        src->hosts[0].name, src->hosts[0].port) < 0)
            return NULL;
    }

    if (!onlytarget && src->auth) {
        username = src->auth->username;
        objalias = srcPriv->secinfo->s.aes.alias;
    }

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:portal", portal,
                                          "s:target", target,
                                          "u:lun", lun,
                                          "s:transport", "tcp",
                                          "S:user", username,
                                          "S:password-secret", objalias,
                                          "S:initiator-name", src->initiator.iqn,
                                          NULL));
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetNBDProps(virStorageSourcePtr src,
                                  bool onlytarget)
{
    g_autoptr(virJSONValue) serverprops = NULL;
    const char *tlsAlias = src->tlsAlias;
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

    if (onlytarget)
        tlsAlias = NULL;

    if (virJSONValueObjectCreate(&ret,
                                 "a:server", &serverprops,
                                 "S:export", src->path,
                                 "S:tls-creds", tlsAlias,
                                 NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetRBDProps(virStorageSourcePtr src,
                                  bool onlytarget)
{
    qemuDomainStorageSourcePrivatePtr srcPriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(virJSONValue) servers = NULL;
    virJSONValuePtr ret = NULL;
    const char *username = NULL;
    g_autoptr(virJSONValue) authmodes = NULL;
    g_autoptr(virJSONValue) mode = NULL;
    const char *keysecret = NULL;

    if (src->nhosts > 0 &&
        !(servers = qemuBlockStorageSourceBuildHostsJSONInetSocketAddress(src)))
        return NULL;

    if (!onlytarget && src->auth) {
        username = srcPriv->secinfo->s.aes.username;
        keysecret = srcPriv->secinfo->s.aes.alias;
        /* the auth modes are modelled after our old command line generator */
        if (!(authmodes = virJSONValueNewArray()))
            return NULL;

        if (!(mode = virJSONValueNewString("cephx")) ||
            virJSONValueArrayAppend(authmodes, mode) < 0)
            return NULL;

        mode = NULL;

        if (!(mode = virJSONValueNewString("none")) ||
            virJSONValueArrayAppend(authmodes, mode) < 0)
            return NULL;

        mode = NULL;
    }

    if (virJSONValueObjectCreate(&ret,
                                 "s:pool", src->volume,
                                 "s:image", src->path,
                                 "S:snapshot", src->snapshot,
                                 "S:conf", src->configFile,
                                 "A:server", &servers,
                                 "S:user", username,
                                 "A:auth-client-required", &authmodes,
                                 "S:key-secret", keysecret,
                                 NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetSheepdogProps(virStorageSourcePtr src)
{
    g_autoptr(virJSONValue) serverprops = NULL;
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
                                 "a:server", &serverprops,
                                 "s:vdi", src->path,
                                 NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetSshProps(virStorageSourcePtr src)
{
    g_autoptr(virJSONValue) serverprops = NULL;
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
                                 "s:path", src->path,
                                 "a:server", &serverprops,
                                 "S:user", username,
                                 NULL) < 0)
        return NULL;

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetFileProps(virStorageSourcePtr src,
                                   bool onlytarget)
{
    const char *iomode = NULL;
    const char *prManagerAlias = NULL;
    virJSONValuePtr ret = NULL;

    if (!onlytarget) {
        if (src->pr)
            prManagerAlias = src->pr->mgralias;

        if (src->iomode != VIR_DOMAIN_DISK_IO_DEFAULT)
            iomode = virDomainDiskIoTypeToString(src->iomode);
    }

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:filename", src->path,
                                          "S:aio", iomode,
                                          "S:pr-manager", prManagerAlias,
                                          NULL) < 0);
    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetVvfatProps(virStorageSourcePtr src,
                                    bool onlytarget)
{
    g_autoptr(virJSONValue) ret = NULL;

    /* libvirt currently does not handle the following attributes:
     * '*fat-type': 'int'
     * '*label': 'str'
     */
    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "vvfat",
                                 "s:dir", src->path,
                                 "b:floppy", src->floppyimg, NULL) < 0)
        return NULL;

    if (!onlytarget &&
        virJSONValueObjectAdd(ret, "b:rw", !src->readonly, NULL) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


static int
qemuBlockStorageSourceGetBlockdevGetCacheProps(virStorageSourcePtr src,
                                               virJSONValuePtr props)
{
    g_autoptr(virJSONValue) cacheobj = NULL;
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

    if (virJSONValueObjectAppend(props, "cache", cacheobj) < 0)
        return -1;
    cacheobj = NULL;

    return 0;
}


/**
 * qemuBlockStorageSourceGetBackendProps:
 * @src: disk source
 * @legacy: use legacy formatting of attributes (for -drive / old qemus)
 * @onlytarget: omit any data which does not identify the image itself
 * @autoreadonly: use the auto-read-only feature of qemu
 *
 * Creates a JSON object describing the underlying storage or protocol of a
 * storage source. Returns NULL on error and reports an appropriate error message.
 */
virJSONValuePtr
qemuBlockStorageSourceGetBackendProps(virStorageSourcePtr src,
                                      bool legacy,
                                      bool onlytarget,
                                      bool autoreadonly)
{
    int actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) fileprops = NULL;
    const char *driver = NULL;
    virTristateBool aro = VIR_TRISTATE_BOOL_ABSENT;
    virTristateBool ro = VIR_TRISTATE_BOOL_ABSENT;

    if (autoreadonly) {
        aro = VIR_TRISTATE_BOOL_YES;
    } else {
        if (src->readonly)
            ro = VIR_TRISTATE_BOOL_YES;
        else
            ro = VIR_TRISTATE_BOOL_NO;
    }

    switch ((virStorageType)actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
        if (virStorageSourceIsBlockLocal(src)) {
            if (src->hostcdrom)
                driver = "host_cdrom";
            else
                driver = "host_device";
        } else {
            driver = "file";
        }

        if (!(fileprops = qemuBlockStorageSourceGetFileProps(src, onlytarget)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_DIR:
        /* qemu handles directories by exposing them as a device with emulated
         * FAT filesystem */
        if (!(fileprops = qemuBlockStorageSourceGetVvfatProps(src, onlytarget)))
            return NULL;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        return NULL;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            driver = "gluster";
            if (!(fileprops = qemuBlockStorageSourceGetGlusterProps(src, legacy, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_VXHS:
            driver = "vxhs";
            if (!(fileprops = qemuBlockStorageSourceGetVxHSProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
            driver = virStorageNetProtocolTypeToString(src->protocol);
            if (!(fileprops = qemuBlockStorageSourceGetCURLProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
            driver = "iscsi";
            if (!(fileprops = qemuBlockStorageSourceGetISCSIProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
            driver = "nbd";
            if (!(fileprops = qemuBlockStorageSourceGetNBDProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            driver = "rbd";
            if (!(fileprops = qemuBlockStorageSourceGetRBDProps(src, onlytarget)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            driver = "sheepdog";
            if (!(fileprops = qemuBlockStorageSourceGetSheepdogProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            driver = "ssh";
            if (!(fileprops = qemuBlockStorageSourceGetSshProps(src)))
                return NULL;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            return NULL;
        }
        break;
    }

    if (driver && virJSONValueObjectPrependString(fileprops, "driver", driver) < 0)
        return NULL;

    if (!onlytarget) {
        if (qemuBlockNodeNameValidate(src->nodestorage) < 0 ||
            virJSONValueObjectAdd(fileprops, "S:node-name", src->nodestorage, NULL) < 0)
            return NULL;

        if (!legacy) {
            if (qemuBlockStorageSourceGetBlockdevGetCacheProps(src, fileprops) < 0)
                return NULL;

            if (virJSONValueObjectAdd(fileprops,
                                      "T:read-only", ro,
                                      "T:auto-read-only", aro,
                                      "s:discard", "unmap",
                                      NULL) < 0)
                return NULL;
        }
    }

    return g_steal_pointer(&fileprops);
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
    g_autoptr(virJSONValue) encprops = NULL;

    if (qemuBlockStorageSourceGetCryptoProps(src, &encprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(props,
                              "s:driver", format,
                              "A:encrypt", &encprops, NULL) < 0)
        return -1;

    return 0;
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
    g_autoptr(virJSONValue) props = NULL;

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
        return NULL;

    return g_steal_pointer(&props);
}


static virJSONValuePtr
qemuBlockStorageSourceGetBlockdevFormatProps(virStorageSourcePtr src)
{
    const char *driver = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatCommonProps(src)))
        return NULL;

    switch ((virStorageFileFormat) src->format) {
    case VIR_STORAGE_FILE_FAT:
        /* The fat layer is emulated by the storage access layer, so we need to
         * put a raw layer on top */
    case VIR_STORAGE_FILE_RAW:
        if (qemuBlockStorageSourceGetFormatRawProps(src, props) < 0)
            return NULL;
        break;

    case VIR_STORAGE_FILE_QCOW2:
        if (qemuBlockStorageSourceGetFormatQcow2Props(src, props) < 0)
            return NULL;
        break;

    case VIR_STORAGE_FILE_QCOW:
        if (qemuBlockStorageSourceGetFormatQcowGenericProps(src, "qcow", props) < 0)
            return NULL;
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
        return NULL;

    case VIR_STORAGE_FILE_LAST:
    default:
        virReportEnumRangeError(virStorageFileFormat, src->format);
        return NULL;
    }

    if (driver &&
        virJSONValueObjectAdd(props, "s:driver", driver, NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


/**
 * qemuBlockStorageSourceGetBlockdevProps:
 *
 * @src: storage source to format
 * @backingStore: a storage source to use as backing of @src
 *
 * Formats @src into a JSON object which can be used with blockdev-add or
 * -blockdev. The formatted object contains both the storage and format layer
 * in nested form including link to the backing chain layer if necessary.
 */
virJSONValuePtr
qemuBlockStorageSourceGetBlockdevProps(virStorageSourcePtr src,
                                       virStorageSourcePtr backingStore)
{
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuBlockStorageSourceGetBlockdevFormatProps(src)))
        return NULL;

    if (virJSONValueObjectAppendString(props, "file", src->nodestorage) < 0)
        return NULL;

    if (backingStore) {
        if (src->format >= VIR_STORAGE_FILE_BACKING) {
            if (virStorageSourceIsBacking(backingStore)) {
                if (virJSONValueObjectAppendString(props, "backing",
                                                   backingStore->nodeformat) < 0)
                    return NULL;
            } else {
                /* chain is terminated, indicate that no detection should happen
                 * in qemu */
                if (virJSONValueObjectAppendNull(props, "backing") < 0)
                    return NULL;
            }
        } else {
            if (virStorageSourceIsBacking(backingStore)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("storage format '%s' does not support backing store"),
                               virStorageFileFormatTypeToString(src->format));
                return NULL;
            }
        }
    }

    return g_steal_pointer(&props);
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
 * @backingStore: storage source to use as backing of @src
 * @autoreadonly: use 'auto-read-only' feature of qemu
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
qemuBlockStorageSourceAttachPrepareBlockdev(virStorageSourcePtr src,
                                            virStorageSourcePtr backingStore,
                                            bool autoreadonly)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    if (!(data->formatProps = qemuBlockStorageSourceGetBlockdevProps(src,
                                                                     backingStore)) ||
        !(data->storageProps = qemuBlockStorageSourceGetBackendProps(src, false,
                                                                     false,
                                                                     autoreadonly)))
        return NULL;

    data->storageNodeName = src->nodestorage;
    data->formatNodeName = src->nodeformat;

    return g_steal_pointer(&data);
}


static int
qemuBlockStorageSourceAttachApplyStorageDeps(qemuMonitorPtr mon,
                                             qemuBlockStorageSourceAttachDataPtr data)
{
    if (data->prmgrProps &&
        qemuMonitorAddObject(mon, &data->prmgrProps, &data->prmgrAlias) < 0)
        return -1;

    if (data->authsecretProps &&
        qemuMonitorAddObject(mon, &data->authsecretProps,
                             &data->authsecretAlias) < 0)
        return -1;

    if (data->tlsProps &&
        qemuMonitorAddObject(mon, &data->tlsProps, &data->tlsAlias) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyStorage(qemuMonitorPtr mon,
                                         qemuBlockStorageSourceAttachDataPtr data)
{
    int rv;

    if (data->storageProps) {
        rv = qemuMonitorBlockdevAdd(mon, data->storageProps);
        data->storageProps = NULL;

        if (rv < 0)
            return -1;

        data->storageAttached = true;
    }

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyFormatDeps(qemuMonitorPtr mon,
                                            qemuBlockStorageSourceAttachDataPtr data)
{
    if (data->encryptsecretProps &&
        qemuMonitorAddObject(mon, &data->encryptsecretProps,
                             &data->encryptsecretAlias) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceAttachApplyFormat(qemuMonitorPtr mon,
                                        qemuBlockStorageSourceAttachDataPtr data)
{
    int rv;

    if (data->formatProps) {
        rv = qemuMonitorBlockdevAdd(mon, data->formatProps);
        data->formatProps = NULL;

        if (rv < 0)
            return -1;

        data->formatAttached = true;
    }

    return 0;
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
 * error occurred, changes which were already applied need to be rolled back by
 * calling qemuBlockStorageSourceAttachRollback.
 */
int
qemuBlockStorageSourceAttachApply(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceAttachDataPtr data)
{
    if (qemuBlockStorageSourceAttachApplyStorageDeps(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyStorage(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyFormatDeps(mon, data) < 0 ||
        qemuBlockStorageSourceAttachApplyFormat(mon, data) < 0)
        return -1;

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
 * qemuBlockStorageSourceDetachPrepare:
 * @src: disk source structure
 * @driveAlias: Alias of the -drive backend, the pointer is always consumed
 *
 * Prepare qemuBlockStorageSourceAttachDataPtr for detaching a single source
 * from a VM. If @driveAlias is NULL -blockdev is assumed.
 */
qemuBlockStorageSourceAttachDataPtr
qemuBlockStorageSourceDetachPrepare(virStorageSourcePtr src,
                                    char *driveAlias)
{
    qemuDomainStorageSourcePrivatePtr srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;
    qemuBlockStorageSourceAttachDataPtr ret = NULL;

    if (VIR_ALLOC(data) < 0)
        goto cleanup;

    if (driveAlias) {
        data->driveAlias = g_steal_pointer(&driveAlias);
        data->driveAdded = true;
    } else {
        data->formatNodeName = src->nodeformat;
        data->formatAttached = true;
        data->storageNodeName = src->nodestorage;
        data->storageAttached = true;
    }

    if (src->pr &&
        !virStoragePRDefIsManaged(src->pr) &&
        VIR_STRDUP(data->prmgrAlias, src->pr->mgralias) < 0)
        goto cleanup;

    if (VIR_STRDUP(data->tlsAlias, src->tlsAlias) < 0)
        goto cleanup;

    if (srcpriv) {
        if (srcpriv->secinfo &&
            srcpriv->secinfo->type == VIR_DOMAIN_SECRET_INFO_TYPE_AES &&
            VIR_STRDUP(data->authsecretAlias, srcpriv->secinfo->s.aes.alias) < 0)
            goto cleanup;

        if (srcpriv->encinfo &&
            srcpriv->encinfo->type == VIR_DOMAIN_SECRET_INFO_TYPE_AES &&
            VIR_STRDUP(data->encryptsecretAlias, srcpriv->encinfo->s.aes.alias) < 0)
            goto cleanup;
    }

    ret = g_steal_pointer(&data);

 cleanup:
    VIR_FREE(driveAlias);
    return ret;
}


void
qemuBlockStorageSourceChainDataFree(qemuBlockStorageSourceChainDataPtr data)
{
    size_t i;

    if (!data)
        return;

    for (i = 0; i < data->nsrcdata; i++)
        qemuBlockStorageSourceAttachDataFree(data->srcdata[i]);

    VIR_FREE(data->srcdata);
    VIR_FREE(data);
}


/**
 * qemuBlockStorageSourceChainDetachPrepareBlockdev
 * @src: storage source chain to remove
 *
 * Prepares qemuBlockStorageSourceChainDataPtr for detaching @src and its
 * backingStore if -blockdev was used.
 */
qemuBlockStorageSourceChainDataPtr
qemuBlockStorageSourceChainDetachPrepareBlockdev(virStorageSourcePtr src)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;
    virStorageSourcePtr n;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    for (n = src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (!(backend = qemuBlockStorageSourceDetachPrepare(n, NULL)))
            return NULL;

        if (VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, backend) < 0)
            return NULL;
    }

    return g_steal_pointer(&data);
}


/**
 * qemuBlockStorageSourceChainDetachPrepareLegacy
 * @src: storage source chain to remove
 * @driveAlias: Alias of the 'drive' backend (always consumed)
 *
 * Prepares qemuBlockStorageSourceChainDataPtr for detaching @src and its
 * backingStore if -drive was used.
 */
qemuBlockStorageSourceChainDataPtr
qemuBlockStorageSourceChainDetachPrepareDrive(virStorageSourcePtr src,
                                              char *driveAlias)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    if (VIR_ALLOC(data) < 0)
        return NULL;

    if (!(backend = qemuBlockStorageSourceDetachPrepare(src, driveAlias)))
        return NULL;

    if (VIR_APPEND_ELEMENT(data->srcdata, data->nsrcdata, backend) < 0)
        return NULL;

    return g_steal_pointer(&data);
}


/**
 * qemuBlockStorageSourceChainAttach:
 * @mon: monitor object
 * @data: storage source chain data
 *
 * Attach a storage source including its backing chain and supporting objects.
 * Caller must enter @mon prior calling this function. In case of error this
 * function returns -1. @data is updated so that qemuBlockStorageSourceChainDetach
 * can be used to roll-back the changes.
 */
int
qemuBlockStorageSourceChainAttach(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceChainDataPtr data)
{
    size_t i;

    for (i = data->nsrcdata; i > 0; i--) {
        if (qemuBlockStorageSourceAttachApply(mon, data->srcdata[i - 1]) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuBlockStorageSourceChainDetach:
 * @mon: monitor object
 * @data: storage source chain data
 *
 * Detach a unused storage source including all its backing chain and related
 * objects described by @data.
 */
void
qemuBlockStorageSourceChainDetach(qemuMonitorPtr mon,
                                  qemuBlockStorageSourceChainDataPtr data)
{
    size_t i;

    for (i = 0; i < data->nsrcdata; i++)
        qemuBlockStorageSourceAttachRollback(mon, data->srcdata[i]);
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


int
qemuBlockSnapshotAddLegacy(virJSONValuePtr actions,
                           virDomainDiskDefPtr disk,
                           virStorageSourcePtr newsrc,
                           bool reuse)
{
    const char *format = virStorageFileFormatTypeToString(newsrc->format);
    g_autofree char *device = NULL;
    g_autofree char *source = NULL;

    if (!(device = qemuAliasDiskDriveFromDisk(disk)))
        return -1;

    if (qemuGetDriveSourceString(newsrc, NULL, &source) < 0)
        return -1;

    return qemuMonitorTransactionSnapshotLegacy(actions, device, source, format, reuse);
}


int
qemuBlockSnapshotAddBlockdev(virJSONValuePtr actions,
                             virDomainDiskDefPtr disk,
                             virStorageSourcePtr newsrc)
{
    return qemuMonitorTransactionSnapshotBlockdev(actions,
                                                  disk->src->nodeformat,
                                                  newsrc->nodeformat);
}


/**
 * qemuBlockStorageGetCopyOnReadProps:
 * @disk: disk with copy-on-read enabled
 *
 * Creates blockdev properties for a disk copy-on-read layer.
 */
virJSONValuePtr
qemuBlockStorageGetCopyOnReadProps(virDomainDiskDefPtr disk)
{
    qemuDomainDiskPrivatePtr priv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    virJSONValuePtr ret = NULL;

    ignore_value(virJSONValueObjectCreate(&ret,
                                          "s:driver", "copy-on-read",
                                          "s:node-name", priv->nodeCopyOnRead,
                                          "s:file", disk->src->nodeformat,
                                          NULL));

    return ret;
}


/**
 * qemuBlockGetBackingStoreString:
 * @src: storage source to get the string for
 *
 * Formats a string used in the backing store field of a disk image which
 * supports backing store. Non-local storage may result in use of the json:
 * pseudo protocol for any complex configuration.
 */
char *
qemuBlockGetBackingStoreString(virStorageSourcePtr src)
{
    int actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) backingProps = NULL;
    g_autoptr(virURI) uri = NULL;
    g_autofree char *backingJSON = NULL;
    char *ret = NULL;

    if (virStorageSourceIsLocalStorage(src)) {
        ignore_value(VIR_STRDUP(ret, src->path));
        return ret;
    }

    /* generate simplified URIs for the easy cases */
    if (actualType == VIR_STORAGE_TYPE_NETWORK &&
        src->nhosts == 1 &&
        src->hosts->transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {

        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            if (!(uri = qemuBlockStorageSourceGetURI(src)))
                return NULL;

            if (!(ret = virURIFormat(uri)))
                return NULL;

            return ret;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_SSH:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
            break;
        }
    }

    /* use json: pseudo protocol otherwise */
    if (!(backingProps = qemuBlockStorageSourceGetBackendProps(src, false, true, false)))
        return NULL;

    if (!(backingJSON = virJSONValueToString(backingProps, false)))
        return NULL;

    if (virAsprintf(&ret, "json:%s", backingJSON) < 0)
        return NULL;

    return ret;
}


static int
qemuBlockStorageSourceCreateAddBacking(virStorageSourcePtr backing,
                                       virJSONValuePtr props,
                                       bool format)
{
    g_autofree char *backingFileStr = NULL;
    const char *backingFormatStr = NULL;

    if (!virStorageSourceIsBacking(backing))
        return 0;

    if (format) {
        if (backing->encryption &&
            backing->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS)
            backingFormatStr = "luks";
        else
            backingFormatStr = virStorageFileFormatTypeToString(backing->format);
    }

    if (!(backingFileStr = qemuBlockGetBackingStoreString(backing)))
        return -1;

    if (virJSONValueObjectAdd(props,
                              "S:backing-file", backingFileStr,
                              "S:backing-fmt", backingFormatStr,
                              NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsGeneric(virStorageSourcePtr src,
                                                  const char *driver,
                                                  virJSONValuePtr *retprops,
                                                  virStorageSourcePtr backing)
{
    g_autoptr(virJSONValue) props = NULL;

    if (virJSONValueObjectCreate(&props,
                                 "s:driver", driver,
                                 "s:file", src->nodestorage,
                                 "U:size", src->capacity,
                                 NULL) < 0)
        return -1;

    if (backing &&
        qemuBlockStorageSourceCreateAddBacking(backing, props, false) < 0)
        return -1;

    *retprops = g_steal_pointer(&props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetEncryptionLUKS(virStorageSourcePtr src,
                                              virJSONValuePtr *luksProps)
{
    qemuDomainStorageSourcePrivatePtr srcpriv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(src);
    g_autoptr(virJSONValue) props = NULL;
    g_autofree char *cipheralg = NULL;
    const char *keysecret = NULL;

    if (srcpriv &&
        srcpriv->encinfo &&
        srcpriv->encinfo->type == VIR_DOMAIN_SECRET_INFO_TYPE_AES)
        keysecret = srcpriv->encinfo->s.aes.alias;

    if (virJSONValueObjectCreate(&props,
                                 "s:key-secret", keysecret,
                                 NULL) < 0)
        return -1;

    if (src->encryption) {
        if (src->encryption->encinfo.cipher_name &&
            virAsprintf(&cipheralg, "%s-%u",
                        src->encryption->encinfo.cipher_name,
                        src->encryption->encinfo.cipher_size) < 0)
            return -1;

        if (virJSONValueObjectAdd(props,
                                  "S:cipher-alg", cipheralg,
                                  "S:cipher-mode", src->encryption->encinfo.cipher_mode,
                                  "S:hash-alg", src->encryption->encinfo.cipher_hash,
                                  "S:ivgen-alg", src->encryption->encinfo.ivgen_name,
                                  "S:ivgen-hash-alg", src->encryption->encinfo.ivgen_hash,
                                  NULL) < 0)
            return -1;
    }

    *luksProps = g_steal_pointer(&props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsLUKS(virStorageSourcePtr src,
                                               virJSONValuePtr *props)
{
    g_autoptr(virJSONValue) luksprops = NULL;

    if (qemuBlockStorageSourceCreateGetEncryptionLUKS(src, &luksprops) < 0)
        return -1;

    if (virJSONValueObjectAdd(luksprops,
                              "s:driver", "luks",
                              "s:file", src->nodestorage,
                              "U:size", src->capacity,
                              NULL) < 0)
        return -1;

    *props = g_steal_pointer(&luksprops);
    return 0;
}


static int
qemuBlockStorageSourceCreateAddEncryptionQcow(virStorageSourcePtr src,
                                              virJSONValuePtr props)
{
    g_autoptr(virJSONValue) encryptProps = NULL;

    if (!src->encryption)
        return 0;

    if (src->encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("creation of qcow/qcow2 files supports only 'luks' encryption"));
        return -1;
    }

    if (qemuBlockStorageSourceCreateGetEncryptionLUKS(src, &encryptProps) < 0)
        return -1;

    if (virJSONValueObjectAdd(encryptProps, "s:format", "luks", NULL) < 0)
        return -1;

    if (virJSONValueObjectAdd(props, "a:encrypt", &encryptProps, NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQcow2(virStorageSourcePtr src,
                                                virStorageSourcePtr backing,
                                                virJSONValuePtr *props)
{
    g_autoptr(virJSONValue) qcow2props = NULL;
    const char *qcow2version = NULL;

    if (STREQ_NULLABLE(src->compat, "0.10"))
        qcow2version = "v2";
    else if (STREQ_NULLABLE(src->compat, "1.1"))
        qcow2version = "v3";

    if (virJSONValueObjectCreate(&qcow2props,
                                 "s:driver", "qcow2",
                                 "s:file", src->nodestorage,
                                 "U:size", src->capacity,
                                 "S:version", qcow2version,
                                 NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qcow2props, true) < 0 ||
        qemuBlockStorageSourceCreateAddEncryptionQcow(src, qcow2props) < 0)
        return -1;

    *props = g_steal_pointer(&qcow2props);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQcow(virStorageSourcePtr src,
                                               virStorageSourcePtr backing,
                                               virJSONValuePtr *props)
{
    g_autoptr(virJSONValue) qcowprops = NULL;

    if (virJSONValueObjectCreate(&qcowprops,
                                 "s:driver", "qcow",
                                 "s:file", src->nodestorage,
                                 "U:size", src->capacity,
                                 NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qcowprops, false) < 0 ||
        qemuBlockStorageSourceCreateAddEncryptionQcow(src, qcowprops) < 0)
        return -1;

    *props = g_steal_pointer(&qcowprops);
    return 0;
}


static int
qemuBlockStorageSourceCreateGetFormatPropsQed(virStorageSourcePtr src,
                                              virStorageSourcePtr backing,
                                              virJSONValuePtr *props)
{
    g_autoptr(virJSONValue) qedprops = NULL;

    if (virJSONValueObjectCreate(&qedprops,
                                 "s:driver", "qed",
                                 "s:file", src->nodestorage,
                                 "U:size", src->capacity,
                                 NULL) < 0)
        return -1;

    if (qemuBlockStorageSourceCreateAddBacking(backing, qedprops, true) < 0)
        return -1;

    *props = g_steal_pointer(&qedprops);
    return 0;
}


/**
 * qemuBlockStorageSourceCreateGetFormatProps:
 * @src: storage source to format
 * @backing: storage source describing backing image of @src (if necessary)
 * @props: filled with props to be used with 'blockdev-create' to format @src
 *
 * @src must be properly initialized to contain node-names of the protocol layer
 * which should be formatted. @props may be NULL with success returned in which
 * case creation of given storage format is not supported. Note that creation
 * of 'raw' storage is also returns NULL as there is nothing to do.
 */
int
qemuBlockStorageSourceCreateGetFormatProps(virStorageSourcePtr src,
                                           virStorageSourcePtr backing,
                                           virJSONValuePtr *props)
{
    switch ((virStorageFileFormat) src->format) {
    case VIR_STORAGE_FILE_RAW:
        if (!src->encryption ||
            src->encryption->format != VIR_STORAGE_ENCRYPTION_FORMAT_LUKS)
            return 0;

        return qemuBlockStorageSourceCreateGetFormatPropsLUKS(src, props);

    case VIR_STORAGE_FILE_QCOW2:
        return qemuBlockStorageSourceCreateGetFormatPropsQcow2(src, backing, props);

    case VIR_STORAGE_FILE_QCOW:
        return qemuBlockStorageSourceCreateGetFormatPropsQcow(src, backing, props);

    case VIR_STORAGE_FILE_QED:
        return qemuBlockStorageSourceCreateGetFormatPropsQed(src, backing, props);

    case VIR_STORAGE_FILE_VPC:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vpc",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_PLOOP:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "parallels",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VDI:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vdi",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VHD:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vhdx",
                                                                 props, NULL);

    case VIR_STORAGE_FILE_VMDK:
        return qemuBlockStorageSourceCreateGetFormatPropsGeneric(src, "vmdk",
                                                                 props, backing);

    /* unsupported by qemu / impossible */
    case VIR_STORAGE_FILE_FAT:
    case VIR_STORAGE_FILE_BOCHS:
    case VIR_STORAGE_FILE_CLOOP:
    case VIR_STORAGE_FILE_DMG:
    case VIR_STORAGE_FILE_COW:
    case VIR_STORAGE_FILE_ISO:
    case VIR_STORAGE_FILE_DIR:
        return 0;

    case VIR_STORAGE_FILE_AUTO_SAFE:
    case VIR_STORAGE_FILE_AUTO:
    case VIR_STORAGE_FILE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("mishandled storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        return -1;

    case VIR_STORAGE_FILE_LAST:
    default:
        break;
    }

    virReportEnumRangeError(virStorageFileFormat, src->format);
    return -1;
}


/**
 * qemuBlockStorageSourceCreateGetStorageProps:
 * @src: storage source to create
 * @props: filled with props to be used with 'blockdev-create' to create @src
 *
 * This function should be used only if @src->type is VIR_STORAGE_TYPE_NETWORK.
 * Note that @props may be NULL if qemu does not support creation storage
 * on given protocol. @src->physical is used as size for the storage.
 */
int
qemuBlockStorageSourceCreateGetStorageProps(virStorageSourcePtr src,
                                            virJSONValuePtr *props)
{
    int actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) location = NULL;
    const char *driver = NULL;
    const char *filename = NULL;

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_FILE:
        driver = "file";
        filename = src->path;
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            driver = "gluster";
            if (!(location = qemuBlockStorageSourceGetGlusterProps(src, false, false)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_RBD:
            driver = "rbd";
            if (!(location = qemuBlockStorageSourceGetRBDProps(src, false)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
            driver = "sheepdog";
            if (!(location = qemuBlockStorageSourceGetSheepdogProps(src)))
                return -1;
            break;

        case VIR_STORAGE_NET_PROTOCOL_SSH:
            driver = "ssh";
            if (!(location = qemuBlockStorageSourceGetSshProps(src)))
                return -1;
            break;

            /* unsupported/impossible */
        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_VXHS:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            return 0;
        }
        break;

    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
        return 0;

    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
         virReportEnumRangeError(virStorageType, actualType);
         return -1;
    }

    if (virJSONValueObjectCreate(props,
                                 "s:driver", driver,
                                 "S:filename", filename,
                                 "A:location", &location,
                                 "U:size", src->physical,
                                 NULL) < 0)
        return -1;

    return 0;
}


static int
qemuBlockStorageSourceCreateGeneric(virDomainObjPtr vm,
                                    virJSONValuePtr createProps,
                                    virStorageSourcePtr src,
                                    virStorageSourcePtr chain,
                                    bool storageCreate,
                                    qemuDomainAsyncJob asyncJob)
{
    g_autoptr(virJSONValue) props = createProps;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuBlockJobDataPtr job = NULL;
    int ret = -1;
    int rc;

    if (!(job = qemuBlockJobNewCreate(vm, src, chain, storageCreate)))
        return -1;

    qemuBlockJobSyncBegin(job);

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuMonitorBlockdevCreate(priv->mon, job->name, props);
    props = NULL;

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        goto cleanup;

    qemuBlockJobStarted(job, vm);

    qemuBlockJobUpdate(vm, job, QEMU_ASYNC_JOB_NONE);
    while (qemuBlockJobIsRunning(job))  {
        if (virDomainObjWait(vm) < 0)
            goto cleanup;
        qemuBlockJobUpdate(vm, job, QEMU_ASYNC_JOB_NONE);
    }

    if (job->state == QEMU_BLOCKJOB_STATE_FAILED ||
        job->state == QEMU_BLOCKJOB_STATE_CANCELLED) {
        if (job->state == QEMU_BLOCKJOB_STATE_CANCELLED && !job->errmsg) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("blockdev-create job was cancelled"));
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to format image: '%s'"), NULLSTR(job->errmsg));
        }
        goto cleanup;
    }

    ret = 0;

 cleanup:
    qemuBlockJobStartupFinalize(vm, job);
    return ret;
}


static int
qemuBlockStorageSourceCreateStorage(virDomainObjPtr vm,
                                    virStorageSourcePtr src,
                                    virStorageSourcePtr chain,
                                    qemuDomainAsyncJob asyncJob)
{
    int actualType = virStorageSourceGetActualType(src);
    g_autoptr(virJSONValue) createstorageprops = NULL;
    int ret;

    /* We create local files directly to be able to apply security labels
     * properly. This is enough for formats which store the capacity of the image
     * in the metadata as they will grow. We must create a correctly sized
     * image for 'raw' and 'luks' though as the image size influences the
     * capacity.
     */
    if (actualType != VIR_STORAGE_TYPE_NETWORK &&
        !(actualType == VIR_STORAGE_TYPE_FILE && src->format == VIR_STORAGE_FILE_RAW))
        return 0;

    if (qemuBlockStorageSourceCreateGetStorageProps(src, &createstorageprops) < 0)
        return -1;

    if (!createstorageprops) {
        /* we can always try opening it to see whether it was existing */
        return 0;
    }

    ret = qemuBlockStorageSourceCreateGeneric(vm, createstorageprops, src, chain,
                                              true, asyncJob);
    createstorageprops = NULL;

    return ret;
}


static int
qemuBlockStorageSourceCreateFormat(virDomainObjPtr vm,
                                   virStorageSourcePtr src,
                                   virStorageSourcePtr backingStore,
                                   virStorageSourcePtr chain,
                                   qemuDomainAsyncJob asyncJob)
{
    g_autoptr(virJSONValue) createformatprops = NULL;
    int ret;

    if (src->format == VIR_STORAGE_FILE_RAW)
        return 0;

    if (qemuBlockStorageSourceCreateGetFormatProps(src, backingStore,
                                                   &createformatprops) < 0)
        return -1;

    if (!createformatprops) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("can't create storage format '%s'"),
                       virStorageFileFormatTypeToString(src->format));
        return -1;
    }

    ret = qemuBlockStorageSourceCreateGeneric(vm, createformatprops, src, chain,
                                              false, asyncJob);
    createformatprops = NULL;

    return ret;
}


/**
 * qemuBlockStorageSourceCreate:
 * @vm: domain object
 * @src: storage source definition to create
 * @backingStore: backingStore of the new image (used only in image metadata)
 * @chain: backing chain to unplug in case of a long-running job failure
 * @data: qemuBlockStorageSourceAttachData for @src so that it can be attached
 * @asyncJob: qemu asynchronous job type
 *
 * Creates and formats a storage volume according to @src and attaches it to @vm.
 * @data must provide attachment data as if @src was existing. @src is attached
 * after successful return of this function. If libvirtd is restarted during
 * the create job @chain is unplugged, otherwise it's left for the caller.
 * If @backingStore is provided, the new image will refer to it as its backing
 * store.
 */
int
qemuBlockStorageSourceCreate(virDomainObjPtr vm,
                             virStorageSourcePtr src,
                             virStorageSourcePtr backingStore,
                             virStorageSourcePtr chain,
                             qemuBlockStorageSourceAttachDataPtr data,
                             qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyStorageDeps(priv->mon, data);

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        goto cleanup;

    if (qemuBlockStorageSourceCreateStorage(vm, src, chain, asyncJob) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyStorage(priv->mon, data);

    if (rc == 0)
        rc = qemuBlockStorageSourceAttachApplyFormatDeps(priv->mon, data);

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        goto cleanup;

    if (qemuBlockStorageSourceCreateFormat(vm, src, backingStore, chain,
                                           asyncJob) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
        goto cleanup;

    rc = qemuBlockStorageSourceAttachApplyFormat(priv->mon, data);

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (ret < 0 &&
        virDomainObjIsActive(vm) &&
        qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) == 0) {

        qemuBlockStorageSourceAttachRollback(priv->mon, data);
        ignore_value(qemuDomainObjExitMonitor(priv->driver, vm));
    }

    return ret;
}


/**
 * qemuBlockStorageSourceCreateDetectSize:
 * @vm: domain object
 * @src: storage source to update size/capacity on
 * @templ: storage source template
 * @asyncJob: qemu asynchronous job type
 *
 * When creating a storage source via blockdev-create we need to know the size
 * and capacity of the original volume (e.g. when creating a snapshot or copy).
 * This function updates @src's 'capacity' and 'physical' attributes according
 * to the detected sizes from @templ.
 */
int
qemuBlockStorageSourceCreateDetectSize(virDomainObjPtr vm,
                                       virStorageSourcePtr src,
                                       virStorageSourcePtr templ,
                                       qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virHashTable) stats = NULL;
    qemuBlockStatsPtr entry;
    int rc;

    if (!(stats = virHashCreate(10, virHashValueFree)))
        return -1;

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorBlockStatsUpdateCapacityBlockdev(priv->mon, stats);

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        return -1;

    if (!(entry = virHashLookup(stats, templ->nodeformat))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to update capacity data for block node '%s'"),
                       templ->nodeformat);
        return -1;
    }

    if (src->format == VIR_STORAGE_FILE_RAW) {
        src->physical = entry->capacity;
    } else {
        src->physical = entry->physical;
    }

    src->capacity = entry->capacity;

    return 0;
}
