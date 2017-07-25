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

#include "viralloc.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_QEMU


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

    while (next) {
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

    if (!(entry = virHashLookup(disktable, disk->info.alias)))
        return 0;

    /* don't attempt the detection if the top level already has node names */
    if (src->nodeformat || src->nodestorage)
        return 0;

    while (src && entry) {
        if (src->nodeformat || src->nodestorage) {
            if (STRNEQ_NULLABLE(src->nodeformat, entry->nodeformat) ||
                STRNEQ_NULLABLE(src->nodestorage, entry->nodestorage))
                goto error;

            break;
        } else {
            if (VIR_STRDUP(src->nodeformat, entry->nodeformat) < 0 ||
                VIR_STRDUP(src->nodestorage, entry->nodestorage) < 0)
                goto error;
        }

        entry = entry->backing;
        src = src->backingStore;
    }

    return 0;

 error:
    qemuBlockDiskClearDetectedNodes(disk);
    return -1;
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
    const char *transport;
    char *port = NULL;
    size_t i;

    if (!(servers = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; i < src->nhosts; i++) {
        host = src->hosts + i;

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
            if (virJSONValueObjectCreate(&server,
                                         "s:type", "unix",
                                         "s:socket", host->socket,
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

        if (virJSONValueArrayAppend(servers, server) < 0)
            goto cleanup;

        server = NULL;
    }

    VIR_STEAL_PTR(ret, servers);

 cleanup:
    virJSONValueFree(servers);
    virJSONValueFree(server);
    VIR_FREE(port);

    return ret;
}


static virJSONValuePtr
qemuBlockStorageSourceGetGlusterProps(virStorageSourcePtr src)
{
    virJSONValuePtr servers = NULL;
    virJSONValuePtr ret = NULL;

    if (!(servers = qemuBlockStorageSourceBuildHostsJSONSocketAddress(src, true)))
        return NULL;

     /* { driver:"gluster",
      *   volume:"testvol",
      *   path:"/a.img",
      *   server :[{type:"tcp", host:"1.2.3.4", port:24007},
      *            {type:"unix", socket:"/tmp/glusterd.socket"}, ...]}
      */
    if (virJSONValueObjectCreate(&ret,
                                 "s:driver", "gluster",
                                 "s:volume", src->volume,
                                 "s:path", src->path,
                                 "a:server", servers, NULL) < 0)
          virJSONValueFree(servers);

    return ret;
}


/**
 * qemuBlockStorageSourceGetBackendProps:
 * @src: disk source
 *
 * Creates a JSON object describing the underlying storage or protocol of a
 * storage source. Returns NULL on error and reports an appropriate error message.
 */
virJSONValuePtr
qemuBlockStorageSourceGetBackendProps(virStorageSourcePtr src)
{
    int actualType = virStorageSourceGetActualType(src);
    virJSONValuePtr fileprops = NULL;
    virJSONValuePtr ret = NULL;

    switch ((virStorageType) actualType) {
    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_FILE:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_VOLUME:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        switch ((virStorageNetProtocol) src->protocol) {
        case VIR_STORAGE_NET_PROTOCOL_GLUSTER:
            if (!(fileprops = qemuBlockStorageSourceGetGlusterProps(src)))
                goto cleanup;
            break;

        case VIR_STORAGE_NET_PROTOCOL_NBD:
        case VIR_STORAGE_NET_PROTOCOL_RBD:
        case VIR_STORAGE_NET_PROTOCOL_SHEEPDOG:
        case VIR_STORAGE_NET_PROTOCOL_ISCSI:
        case VIR_STORAGE_NET_PROTOCOL_HTTP:
        case VIR_STORAGE_NET_PROTOCOL_HTTPS:
        case VIR_STORAGE_NET_PROTOCOL_FTP:
        case VIR_STORAGE_NET_PROTOCOL_FTPS:
        case VIR_STORAGE_NET_PROTOCOL_TFTP:
        case VIR_STORAGE_NET_PROTOCOL_SSH:
        case VIR_STORAGE_NET_PROTOCOL_NONE:
        case VIR_STORAGE_NET_PROTOCOL_LAST:
            break;
        }
        break;
    }

    if (virJSONValueObjectCreate(&ret, "a:file", fileprops, NULL) < 0)
        goto cleanup;

    fileprops = NULL;

 cleanup:
    virJSONValueFree(fileprops);
    return ret;
}
