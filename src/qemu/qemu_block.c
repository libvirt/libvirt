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


static void
qemuBlockNodeNameBackingChainDataFree(qemuBlockNodeNameBackingChainDataPtr data)
{
    size_t i;

    if (!data)
        return;

    for (i = 0; i < data->nelems; i++)
        virJSONValueFree(data->elems[i]);

    VIR_FREE(data->nodeformat);
    VIR_FREE(data->nodestorage);
    VIR_FREE(data->nodebacking);

    VIR_FREE(data->qemufilename);
    VIR_FREE(data->backingstore);

    VIR_FREE(data);
}


static void
qemuBlockNodeNameBackingChainDataHashEntryFree(void *opaque,
                                               const void *name ATTRIBUTE_UNUSED)
{
    qemuBlockNodeNameBackingChainDataFree(opaque);
}


struct qemuBlockNodeNameGetBackingChainData {
    virHashTablePtr table;
    qemuBlockNodeNameBackingChainDataPtr *entries;
    size_t nentries;
};


static int
qemuBlockNodeNameDetectProcessByFilename(size_t pos ATTRIBUTE_UNUSED,
                                         virJSONValuePtr item,
                                         void *opaque)
{
    struct qemuBlockNodeNameGetBackingChainData *data = opaque;
    qemuBlockNodeNameBackingChainDataPtr entry;
    const char *file;

    if (!(file = virJSONValueObjectGetString(item, "file")))
        return 1;

    if (!(entry = virHashLookup(data->table, file))) {
        if (VIR_ALLOC(entry) < 0)
            return -1;

        if (VIR_APPEND_ELEMENT_COPY(data->entries, data->nentries, entry) < 0) {
            VIR_FREE(entry);
            return -1;
        }

        if (VIR_STRDUP(entry->qemufilename, file) < 0)
            return -1;

        if (virHashAddEntry(data->table, file, entry) < 0)
            return -1;
    }

    if (VIR_APPEND_ELEMENT(entry->elems, entry->nelems, item) < 0)
        return -1;

    return 0;
}


static const char *qemuBlockDriversFormat[] = {
    "qcow2", "raw", "qcow", "luks", "qed", "bochs", "cloop", "dmg", "parallels",
    "vdi", "vhdx", "vmdk", "vpc", "vvfat", NULL};
static const char *qemuBlockDriversStorage[] = {
    "file", "iscsi", "nbd", "host_cdrom", "host_device", "ftp", "ftps",
    "gluster", "http", "https", "nfs", "rbd", "sheepdog", "ssh", "tftp", NULL};


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


static int
qemuBlockNodeNameDetectProcessExtract(qemuBlockNodeNameBackingChainDataPtr data)
{
    const char *drv;
    const char *nodename;
    const char *backingstore;
    size_t i;

    /* Since the only way to construct the backing chain is to look up the files
     * by file name, if two disks share a backing image we can't know which node
     * belongs to which backing chain. Refuse to detect such chains. */
    if (data->nelems > 2)
        return 0;

    for (i = 0; i < data->nelems; i++) {
        drv = virJSONValueObjectGetString(data->elems[i], "drv");
        nodename = virJSONValueObjectGetString(data->elems[i], "node-name");
        backingstore = virJSONValueObjectGetString(data->elems[i], "backing_file");

        if (!drv || !nodename)
            continue;

        if (qemuBlockDriverMatch(drv, qemuBlockDriversFormat)) {
            if (data->nodeformat)
                continue;

            if (VIR_STRDUP(data->nodeformat, nodename) < 0)
                return -1;

            /* extract the backing store file name for the protocol layer */
            if (VIR_STRDUP(data->backingstore, backingstore) < 0)
                return -1;
        } else if (qemuBlockDriverMatch(drv, qemuBlockDriversStorage)) {
            if (data->nodestorage)
                continue;

            if (VIR_STRDUP(data->nodestorage, nodename) < 0)
                return -1;
        }
    }

    return 0;
}


static int
qemuBlockNodeNameDetectProcessLinkBacking(qemuBlockNodeNameBackingChainDataPtr data,
                                          virHashTablePtr table)
{
    qemuBlockNodeNameBackingChainDataPtr backing;

    if (!data->backingstore)
        return 0;

    if (!(backing = virHashLookup(table, data->backingstore)))
        return 0;

    if (VIR_STRDUP(data->nodebacking, backing->nodeformat) < 0)
        return -1;

    return 0;
}


static void
qemuBlockNodeNameGetBackingChainDataClearLookup(qemuBlockNodeNameBackingChainDataPtr data)
{
    size_t i;

    for (i = 0; i < data->nelems; i++)
        virJSONValueFree(data->elems[i]);

    VIR_FREE(data->elems);
    data->nelems = 0;
}


/**
 * qemuBlockNodeNameGetBackingChain:
 * @json: JSON array of data returned from 'query-named-block-nodes'
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
qemuBlockNodeNameGetBackingChain(virJSONValuePtr json)
{
    struct qemuBlockNodeNameGetBackingChainData data;
    virHashTablePtr nodetable = NULL;
    virHashTablePtr ret = NULL;
    size_t i;

    memset(&data, 0, sizeof(data));

    /* hash table keeps the entries accessible by the 'file' in qemu */
    if (!(data.table = virHashCreate(50, NULL)))
        goto cleanup;

    /* first group the named entries by the 'file' field */
    if (virJSONValueArrayForeachSteal(json,
                                      qemuBlockNodeNameDetectProcessByFilename,
                                      &data) < 0)
        goto cleanup;

    /* extract the node names for the format and storage layer */
    for (i = 0; i < data.nentries; i++) {
        if (qemuBlockNodeNameDetectProcessExtract(data.entries[i]) < 0)
            goto cleanup;
    }

    /* extract the node name for the backing file */
    for (i = 0; i < data.nentries; i++) {
        if (qemuBlockNodeNameDetectProcessLinkBacking(data.entries[i],
                                                      data.table) < 0)
            goto cleanup;
    }

    /* clear JSON data necessary only for the lookup procedure */
    for (i = 0; i < data.nentries; i++)
        qemuBlockNodeNameGetBackingChainDataClearLookup(data.entries[i]);

    /* create hash table hashed by the format node name */
    if (!(nodetable = virHashCreate(50,
                                    qemuBlockNodeNameBackingChainDataHashEntryFree)))
        goto cleanup;

    /* fill the entries */
    for (i = 0; i < data.nentries; i++) {
        if (!data.entries[i]->nodeformat)
            continue;

        if (virHashAddEntry(nodetable, data.entries[i]->nodeformat,
                            data.entries[i]) < 0)
            goto cleanup;

        /* hash table steals the entry and then frees it by itself */
        data.entries[i] = NULL;
    }

    VIR_STEAL_PTR(ret, nodetable);

 cleanup:
     virHashFree(data.table);
     virHashFree(nodetable);
     for (i = 0; i < data.nentries; i++)
         qemuBlockNodeNameBackingChainDataFree(data.entries[i]);

    VIR_FREE(data.entries);

     return ret;
}


static void
qemuBlockDiskClearDetectedNodes(virDomainDiskDefPtr disk)
{
    virStorageSourcePtr next = disk->src;

    while (next) {
        VIR_FREE(next->nodeformat);
        VIR_FREE(next->nodebacking);

        next = next->backingStore;
    }
}


static int
qemuBlockDiskDetectNodes(virDomainDiskDefPtr disk,
                         const char *parentnode,
                         virHashTablePtr table)
{
    qemuBlockNodeNameBackingChainDataPtr entry = NULL;
    virStorageSourcePtr src = disk->src;

    /* don't attempt the detection if the top level already has node names */
    if (!parentnode || src->nodeformat || src->nodebacking)
        return 0;

    while (src && parentnode) {
        if (!(entry = virHashLookup(table, parentnode)))
            break;

        if (src->nodeformat || src->nodebacking) {
            if (STRNEQ_NULLABLE(src->nodeformat, entry->nodeformat) ||
                STRNEQ_NULLABLE(src->nodebacking, entry->nodestorage))
                goto error;

            break;
        } else {
            if (VIR_STRDUP(src->nodeformat, entry->nodeformat) < 0 ||
                VIR_STRDUP(src->nodebacking, entry->nodestorage) < 0)
                goto error;
        }

        parentnode = entry->nodebacking;
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
    virHashTablePtr nodenametable = NULL;
    virJSONValuePtr data = NULL;
    virDomainDiskDefPtr disk;
    struct qemuDomainDiskInfo *info;
    size_t i;
    int ret = -1;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_QUERY_NAMED_BLOCK_NODES))
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    disktable = qemuMonitorGetBlockInfo(qemuDomainGetMonitor(vm));
    data = qemuMonitorQueryNamedBlockNodes(qemuDomainGetMonitor(vm));

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || !data || !disktable)
        goto cleanup;

    if (!(nodenametable = qemuBlockNodeNameGetBackingChain(data)))
        goto cleanup;

    for (i = 0; i < vm->def->ndisks; i++) {
        disk = vm->def->disks[i];

        if (!(info = virHashLookup(disktable, disk->info.alias)))
            continue;

        if (qemuBlockDiskDetectNodes(disk, info->nodename, nodenametable) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(data);
    virHashFree(nodenametable);
    virHashFree(disktable);

    return ret;
}


static int
qemuBlockFillNodeData(size_t pos ATTRIBUTE_UNUSED,
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

    if (virJSONValueArrayForeachSteal(data, qemuBlockFillNodeData, ret) < 0)
        goto error;

    return ret;

 error:
    virHashFree(ret);
    return NULL;
}
