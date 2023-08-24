/*
 * esx_storage_backend_vmfs.c: ESX storage driver backend for
 *                             managing VMFS datastores
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright (C) 2010-2012 Matthias Bolte <matthias.bolte@googlemail.com>
 * Copyright (C) 2012 Ata E Husain Bohra <ata.husain@hotmail.com>
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

#include <unistd.h>

#include "internal.h"
#include "viralloc.h"
#include "virlog.h"
#include "storage_conf.h"
#include "storage_source_conf.h"
#include "esx_storage_backend_vmfs.h"
#include "esx_private.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "vircrypto.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX

VIR_LOG_INIT("esx.esx_storage_backend_vmfs");

/*
 * The UUID of a storage pool is the MD5 sum of its mount path. Therefore,
 * verify that UUID and MD5 sum match in size, because we rely on that.
 */
G_STATIC_ASSERT(VIR_CRYPTO_HASH_SIZE_MD5 == VIR_UUID_BUFLEN);



static int
datastorePoolType(esxVI_ObjectContent *datastore, int *poolType)
{
    int result = -1;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_DatastoreInfo *datastoreInfo = NULL;

    for (dynamicProperty = datastore->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "info")) {
            if (esxVI_DatastoreInfo_CastFromAnyType(dynamicProperty->val,
                                                    &datastoreInfo) < 0) {
                goto cleanup;
            }

            break;
        }
    }

    if (esxVI_LocalDatastoreInfo_DynamicCast(datastoreInfo)) {
        *poolType = VIR_STORAGE_POOL_DIR;
    } else if (esxVI_NasDatastoreInfo_DynamicCast(datastoreInfo)) {
        *poolType = VIR_STORAGE_POOL_NETFS;
    } else if (esxVI_VmfsDatastoreInfo_DynamicCast(datastoreInfo)) {
        *poolType = VIR_STORAGE_POOL_FS;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DatastoreInfo has unexpected type"));
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_DatastoreInfo_Free(&datastoreInfo);

    return result;
}



static int
esxLookupVMFSStoragePoolType(esxVI_Context *ctx, const char *poolName,
                             int *poolType)
{
    int result = -1;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;

    if (esxVI_String_AppendValueToList(&propertyNameList, "info") < 0 ||
        esxVI_LookupDatastoreByName(ctx, poolName, propertyNameList, &datastore,
                                    esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!datastore) {
        /* Not found, let the base storage driver handle error reporting */
        goto cleanup;
    }

    if (datastorePoolType(datastore, poolType) < 0)
        goto cleanup;

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);

    return result;
}



static int
esxConnectNumOfStoragePools(virConnectPtr conn)
{
    int count = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;

    if (esxVI_LookupDatastoreList(priv->primary, NULL, &datastoreList) < 0)
        return -1;

    for (datastore = datastoreList; datastore;
         datastore = datastore->_next) {
        ++count;
    }

    esxVI_ObjectContent_Free(&datastoreList);

    return count;
}



static int
esxConnectListStoragePools(virConnectPtr conn, char **const names,
                           const int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    int count = 0;
    size_t i;

    if (maxnames == 0)
        return 0;

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "summary.name") < 0 ||
        esxVI_LookupDatastoreList(priv->primary, propertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    for (datastore = datastoreList; datastore;
         datastore = datastore->_next) {
        for (dynamicProperty = datastore->propSet; dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto cleanup;
                }

                names[count] = g_strdup(dynamicProperty->val->string);

                ++count;
                break;
            } else {
                VIR_WARN("Unexpected '%s' property", dynamicProperty->name);
            }
        }
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);

        count = -1;
    }

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);

    return count;
}



static virStoragePoolPtr
datastoreToStoragePoolPtr(virConnectPtr conn,
                          const char *name,
                          esxVI_ObjectContent *datastore)
{
    esxPrivate *priv = conn->privateData;
    esxVI_DatastoreHostMount *hostMount = NULL;
    /* VIR_CRYPTO_HASH_SIZE_MD5 = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[VIR_CRYPTO_HASH_SIZE_MD5];
    virStoragePoolPtr pool = NULL;

    /*
     * Datastores don't have a UUID, but we can use the 'host.mountInfo.path'
     * property as source for a UUID. The mount path is unique per host and
     * cannot change during the lifetime of the datastore.
     *
     * The MD5 sum of the mount path can be used as UUID, assuming MD5 is
     * considered to be collision-free enough for this use case.
     */
    if (esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj, &hostMount,
                                       esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!hostMount) {
        /* Not found, let the base storage driver handle error reporting */
        goto cleanup;
    }

    if (virCryptoHashBuf(VIR_CRYPTO_HASH_MD5, hostMount->mountInfo->path, md5) < 0)
        goto cleanup;

    pool = virGetStoragePool(conn, name, md5, &esxStorageBackendVMFS, NULL);

 cleanup:
    esxVI_DatastoreHostMount_Free(&hostMount);

    return pool;
}



static virStoragePoolPtr
esxStoragePoolLookupByName(virConnectPtr conn,
                           const char *name)
{
    esxPrivate *priv = conn->privateData;
    esxVI_ObjectContent *datastore = NULL;
    virStoragePoolPtr pool = NULL;

    if (esxVI_LookupDatastoreByName(priv->primary, name, NULL, &datastore,
                                    esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!datastore) {
        /* Not found, let the base storage driver handle error reporting */
        goto cleanup;
    }

    pool = datastoreToStoragePoolPtr(conn, name, datastore);

 cleanup:
    esxVI_ObjectContent_Free(&datastore);

    return pool;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn,
                           const unsigned char *uuid)
{
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    /* VIR_CRYPTO_HASH_SIZE_MD5 = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[VIR_CRYPTO_HASH_SIZE_MD5];
    char *name = NULL;
    virStoragePoolPtr pool = NULL;


    if (esxVI_String_AppendValueToList(&propertyNameList, "summary.name") < 0 ||
        esxVI_LookupDatastoreList(priv->primary, propertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    for (datastore = datastoreList; datastore;
         datastore = datastore->_next) {
        esxVI_DatastoreHostMount_Free(&hostMount);

        if (esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj,
                                           &hostMount,
                                           esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (!hostMount) {
            /*
             * Storage pool is not of VMFS type, leave error reporting to the
             * base storage driver.
             */
            goto cleanup;
        }

        if (virCryptoHashBuf(VIR_CRYPTO_HASH_MD5, hostMount->mountInfo->path, md5) < 0)
            goto cleanup;

        if (memcmp(uuid, md5, VIR_UUID_BUFLEN) == 0)
            break;
    }

    if (!datastore) {
        /* Not found, let the base storage driver handle error reporting */
        goto cleanup;
    }

    if (esxVI_GetStringValue(datastore, "summary.name", &name,
                             esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    pool = virGetStoragePool(conn, name, uuid, &esxStorageBackendVMFS, NULL);

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);
    esxVI_DatastoreHostMount_Free(&hostMount);

    return pool;
}



static int
esxStoragePoolRefresh(virStoragePoolPtr pool, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_ObjectContent *datastore = NULL;

    virCheckFlags(0, -1);

    if (esxVI_LookupDatastoreByName(priv->primary, pool->name, NULL, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_RefreshDatastore(priv->primary, datastore->obj) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ObjectContent_Free(&datastore);

    return result;
}



static int
esxStoragePoolGetInfo(virStoragePoolPtr pool,
                      virStoragePoolInfoPtr info)
{
    int result = -1;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.accessible\0"
                                           "summary.capacity\0"
                                           "summary.freeSpace\0") < 0 ||
        esxVI_LookupDatastoreByName(priv->primary, pool->name,
                                    propertyNameList, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetBoolean(datastore, "summary.accessible",
                         &accessible, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    if (accessible == esxVI_Boolean_True) {
        info->state = VIR_STORAGE_POOL_RUNNING;

        for (dynamicProperty = datastore->propSet; dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.capacity")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_Long) < 0) {
                    goto cleanup;
                }

                info->capacity = dynamicProperty->val->int64;
            } else if (STREQ(dynamicProperty->name, "summary.freeSpace")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_Long) < 0) {
                    goto cleanup;
                }

                info->available = dynamicProperty->val->int64;
            }
        }

        info->allocation = info->capacity - info->available;
    } else {
        info->state = VIR_STORAGE_POOL_INACCESSIBLE;
    }

    result = 0;

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);

    return result;
}



static char *
esxStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    esxPrivate *priv = pool->conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;
    virStoragePoolDef def = { 0 };
    esxVI_DatastoreInfo *info = NULL;
    esxVI_NasDatastoreInfo *nasInfo = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.accessible\0"
                                           "summary.capacity\0"
                                           "summary.freeSpace\0"
                                           "info\0") < 0 ||
        esxVI_LookupDatastoreByName(priv->primary, pool->name,
                                    propertyNameList, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetBoolean(datastore, "summary.accessible",
                         &accessible, esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj, &hostMount,
                                       esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    def.name = pool->name;
    memcpy(def.uuid, pool->uuid, VIR_UUID_BUFLEN);

    def.target.path = hostMount->mountInfo->path;

    if (accessible == esxVI_Boolean_True) {
        for (dynamicProperty = datastore->propSet; dynamicProperty;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.capacity")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_Long) < 0) {
                    goto cleanup;
                }

                def.capacity = dynamicProperty->val->int64;
            } else if (STREQ(dynamicProperty->name, "summary.freeSpace")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_Long) < 0) {
                    goto cleanup;
                }

                def.available = dynamicProperty->val->int64;
            }
        }

        def.allocation = def.capacity - def.available;
    }

    for (dynamicProperty = datastore->propSet; dynamicProperty;
         dynamicProperty = dynamicProperty->_next) {
        if (STREQ(dynamicProperty->name, "info")) {
            if (esxVI_DatastoreInfo_CastFromAnyType(dynamicProperty->val,
                                                    &info) < 0) {
                goto cleanup;
            }

            break;
        }
    }

    /* See vSphere API documentation about HostDatastoreSystem for details */
    if (esxVI_LocalDatastoreInfo_DynamicCast(info)) {
        def.type = VIR_STORAGE_POOL_DIR;
    } else if ((nasInfo = esxVI_NasDatastoreInfo_DynamicCast(info))) {
        def.source.hosts = g_new0(virStoragePoolSourceHost, 1);
        def.type = VIR_STORAGE_POOL_NETFS;
        def.source.nhost = 1;
        def.source.hosts[0].name = nasInfo->nas->remoteHost;
        def.source.dir = nasInfo->nas->remotePath;

        if (STRCASEEQ(nasInfo->nas->type, "NFS")) {
            def.source.format = VIR_STORAGE_POOL_NETFS_NFS;
        } else  if (STRCASEEQ(nasInfo->nas->type, "CIFS")) {
            def.source.format = VIR_STORAGE_POOL_NETFS_CIFS;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Datastore has unexpected type '%1$s'"),
                           nasInfo->nas->type);
            goto cleanup;
        }
    } else if (esxVI_VmfsDatastoreInfo_DynamicCast(info)) {
        def.type = VIR_STORAGE_POOL_FS;
        def.source.format = VIR_STORAGE_POOL_FS_VMFS;
        /*
         * FIXME: I'm not sure how to represent the source and target of a
         * VMFS based datastore in libvirt terms
         */
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("DatastoreInfo has unexpected type"));
        goto cleanup;
    }

    xml = virStoragePoolDefFormat(&def);

 cleanup:
    g_free(def.source.hosts);
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);
    esxVI_DatastoreHostMount_Free(&hostMount);
    esxVI_DatastoreInfo_Free(&info);

    return xml;
}



static int
esxStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    bool success = false;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostDatastoreBrowserSearchResults *searchResultsList = NULL;
    esxVI_HostDatastoreBrowserSearchResults *searchResults = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    int count = 0;

    if (esxVI_LookupDatastoreContentByDatastoreName(priv->primary, pool->name,
                                                    &searchResultsList) < 0) {
        goto cleanup;
    }

    /* Interpret search result */
    for (searchResults = searchResultsList; searchResults;
         searchResults = searchResults->_next) {
        for (fileInfo = searchResults->file; fileInfo;
             fileInfo = fileInfo->_next) {
            ++count;
        }
    }

    success = true;

 cleanup:
    esxVI_HostDatastoreBrowserSearchResults_Free(&searchResultsList);

    return success ? count : -1;
}



static int
esxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names,
                          int maxnames)
{
    bool success = false;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostDatastoreBrowserSearchResults *searchResultsList = NULL;
    esxVI_HostDatastoreBrowserSearchResults *searchResults = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    size_t length;
    int count = 0;
    size_t i;

    if (!names || maxnames < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (maxnames == 0)
        return 0;

    if (esxVI_LookupDatastoreContentByDatastoreName(priv->primary, pool->name,
                                                    &searchResultsList) < 0) {
        goto cleanup;
    }

    /* Interpret search result */
    for (searchResults = searchResultsList; searchResults;
         searchResults = searchResults->_next) {
        g_autofree char *directoryAndFileName = NULL;

        if (esxUtil_ParseDatastorePath(searchResults->folderPath, NULL, NULL,
                                       &directoryAndFileName) < 0) {
            goto cleanup;
        }

        /* Strip trailing separators */
        length = strlen(directoryAndFileName);

        while (length > 0 && directoryAndFileName[length - 1] == '/') {
            directoryAndFileName[length - 1] = '\0';
            --length;
        }

        /* Build volume names */
        for (fileInfo = searchResults->file; fileInfo;
             fileInfo = fileInfo->_next) {
            if (length < 1) {
                names[count] = g_strdup(fileInfo->path);
            } else {
                names[count] = g_strdup_printf("%s/%s",
                                               directoryAndFileName, fileInfo->path);
            }

            ++count;
        }
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);

        count = -1;
    }

    esxVI_HostDatastoreBrowserSearchResults_Free(&searchResultsList);
    return count;
}



static virStorageVolPtr
esxStorageVolLookupByName(virStoragePoolPtr pool,
                          const char *name)
{
    esxPrivate *priv = pool->conn->privateData;
    g_autofree char *datastorePath = NULL;
    g_autofree char *key = NULL;

    datastorePath = g_strdup_printf("[%s] %s", pool->name, name);

    if (esxVI_LookupStorageVolumeKeyByDatastorePath(priv->primary,
                                                    datastorePath, &key) < 0) {
        return NULL;
    }

    return virGetStorageVol(pool->conn, pool->name, name, key,
                            &esxStorageBackendVMFS, NULL);
}



static virStorageVolPtr
esxStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    esxPrivate *priv = conn->privateData;
    g_autofree char *datastoreName = NULL;
    g_autofree char *directoryAndFileName = NULL;
    g_autofree char *key = NULL;

    if (esxUtil_ParseDatastorePath(path, &datastoreName, NULL,
                                   &directoryAndFileName) < 0) {
        return NULL;
    }

    if (esxVI_LookupStorageVolumeKeyByDatastorePath(priv->primary, path,
                                                    &key) < 0) {
        return NULL;
    }

    return virGetStorageVol(conn, datastoreName, directoryAndFileName, key,
                            &esxStorageBackendVMFS, NULL);
}



static virStorageVolPtr
esxStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = conn->privateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    char *datastoreName = NULL;
    esxVI_HostDatastoreBrowserSearchResults *searchResultsList = NULL;
    esxVI_HostDatastoreBrowserSearchResults *searchResults = NULL;
    size_t length;
    esxVI_FileInfo *fileInfo = NULL;
    char key_candidate[VIR_UUID_STRING_BUFLEN] = "";

    if (STRPREFIX(key, "[")) {
        /* Key is probably a datastore path */
        return esxStorageVolLookupByPath(conn, key);
    }

    if (!priv->primary->hasQueryVirtualDiskUuid) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("QueryVirtualDiskUuid not available, cannot lookup storage volume by UUID"));
        return NULL;
    }

    /* Lookup all datastores */
    if (esxVI_String_AppendValueToList(&propertyNameList, "summary.name") < 0 ||
        esxVI_LookupDatastoreList(priv->primary, propertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    for (datastore = datastoreList; datastore;
         datastore = datastore->_next) {
        datastoreName = NULL;

        if (esxVI_GetStringValue(datastore, "summary.name", &datastoreName,
                                 esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        /* Lookup datastore content */
        esxVI_HostDatastoreBrowserSearchResults_Free(&searchResultsList);

        if (esxVI_LookupDatastoreContentByDatastoreName
              (priv->primary, datastoreName, &searchResultsList) < 0) {
            goto cleanup;
        }

        /* Interpret search result */
        for (searchResults = searchResultsList; searchResults;
             searchResults = searchResults->_next) {
            g_autofree char *directoryAndFileName = NULL;

            if (esxUtil_ParseDatastorePath(searchResults->folderPath, NULL,
                                           NULL, &directoryAndFileName) < 0) {
                goto cleanup;
            }

            /* Strip trailing separators */
            length = strlen(directoryAndFileName);

            while (length > 0 && directoryAndFileName[length - 1] == '/') {
                directoryAndFileName[length - 1] = '\0';
                --length;
            }

            /* Build datastore path and query the UUID */
            for (fileInfo = searchResults->file; fileInfo;
                 fileInfo = fileInfo->_next) {
                g_autofree char *volumeName = NULL;
                g_autofree char *datastorePath = NULL;
                g_autofree char *uuid_string = NULL;

                if (length < 1) {
                    volumeName = g_strdup(fileInfo->path);
                } else {
                    volumeName = g_strdup_printf("%s/%s",
                                                 directoryAndFileName, fileInfo->path);
                }

                datastorePath = g_strdup_printf("[%s] %s", datastoreName, volumeName);

                if (!esxVI_VmDiskFileInfo_DynamicCast(fileInfo)) {
                    /* Only a VirtualDisk has a UUID */
                    continue;
                }

                if (esxVI_QueryVirtualDiskUuid
                      (priv->primary, datastorePath,
                       priv->primary->datacenter->_reference,
                       &uuid_string) < 0) {
                    goto cleanup;
                }

                if (esxUtil_ReformatUuid(uuid_string, key_candidate) < 0)
                    goto cleanup;

                if (STREQ(key, key_candidate)) {
                    /* Found matching UUID */
                    volume = virGetStorageVol(conn, datastoreName,
                                              volumeName, key,
                                              &esxStorageBackendVMFS, NULL);
                    goto cleanup;
                }
            }
        }
    }

 cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);
    esxVI_HostDatastoreBrowserSearchResults_Free(&searchResultsList);
    return volume;
}



static virStorageVolPtr
esxStorageVolCreateXML(virStoragePoolPtr pool,
                       const char *xmldesc,
                       unsigned int flags)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = pool->conn->privateData;
    virStoragePoolDef poolDef = { 0 };
    char *tmp;
    g_autofree char *unescapedDatastorePath = NULL;
    g_autofree char *unescapedDirectoryName = NULL;
    g_autofree char *unescapedDirectoryAndFileName = NULL;
    g_autofree char *directoryName = NULL;
    g_autofree char *fileName = NULL;
    g_autofree char *datastorePathWithoutFileName = NULL;
    g_autofree char *datastorePath = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    esxVI_FileBackedVirtualDiskSpec *virtualDiskSpec = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    g_autofree char *taskInfoErrorMessage = NULL;
    g_autofree char *uuid_string = NULL;
    g_autofree char *key = NULL;
    g_autoptr(virStorageVolDef) def = NULL;

    virCheckFlags(0, NULL);

    if (esxLookupVMFSStoragePoolType(priv->primary, pool->name,
                                     &poolDef.type) < 0) {
        goto cleanup;
    }

    /* Parse config */
    def = virStorageVolDefParse(&poolDef, xmldesc, NULL, 0);

    if (!def)
        goto cleanup;

    if (def->type != VIR_STORAGE_VOL_FILE) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("Creating non-file volumes is not supported"));
        goto cleanup;
    }

    /* Validate config */
    tmp = strrchr(def->name, '/');

    if (!tmp || *def->name == '/' || tmp[1] == '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume name '%1$s' doesn't have expected format '<directory>/<file>'"),
                       def->name);
        goto cleanup;
    }

    if (!virStringHasCaseSuffix(def->name, ".vmdk")) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Volume name '%1$s' has unsupported suffix, expecting '.vmdk'"),
                       def->name);
        goto cleanup;
    }

    unescapedDatastorePath = g_strdup_printf("[%s] %s", pool->name, def->name);

    if (def->target.format == VIR_STORAGE_FILE_VMDK) {
        /* Parse and escape datastore path */
        if (esxUtil_ParseDatastorePath(unescapedDatastorePath, NULL,
                                       &unescapedDirectoryName,
                                       &unescapedDirectoryAndFileName) < 0) {
            goto cleanup;
        }

        directoryName = esxUtil_EscapeDatastoreItem(unescapedDirectoryName);

        if (!directoryName)
            goto cleanup;

        fileName = esxUtil_EscapeDatastoreItem(unescapedDirectoryAndFileName +
                                               strlen(unescapedDirectoryName) + 1);

        if (!fileName)
            goto cleanup;

        datastorePathWithoutFileName = g_strdup_printf("[%s] %s", pool->name,
                                                       directoryName);

        datastorePath = g_strdup_printf("[%s] %s/%s", pool->name, directoryName,
                                        fileName);

        /* Create directory, if it doesn't exist yet */
        if (esxVI_LookupFileInfoByDatastorePath
              (priv->primary, datastorePathWithoutFileName, true, &fileInfo,
               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (!fileInfo) {
            if (esxVI_MakeDirectory(priv->primary, datastorePathWithoutFileName,
                                    priv->primary->datacenter->_reference,
                                    esxVI_Boolean_True) < 0) {
                goto cleanup;
            }
        }

        /* Create VirtualDisk */
        if (esxVI_FileBackedVirtualDiskSpec_Alloc(&virtualDiskSpec) < 0 ||
            esxVI_Long_Alloc(&virtualDiskSpec->capacityKb) < 0) {
            goto cleanup;
        }

        /* From the vSphere API documentation about VirtualDiskType ... */
        if (def->target.allocation == def->target.capacity) {
            /*
             * "A preallocated disk has all space allocated at creation time
             *  and the space is zeroed on demand as the space is used."
             */
            virtualDiskSpec->diskType = (char *)"preallocated";
        } else if (def->target.allocation == 0) {
            /*
             * "Space required for thin-provisioned virtual disk is allocated
             *  and zeroed on demand as the space is used."
             */
            virtualDiskSpec->diskType = (char *)"thin";
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unsupported capacity-to-allocation relation"));
            goto cleanup;
        }

        /*
         * FIXME: The adapter type is a required parameter, but there is no
         * way to let the user specify it in the volume XML config. Therefore,
         * default to 'lsiLogic' here.
         */
        virtualDiskSpec->adapterType = (char *)"lsiLogic";

        virtualDiskSpec->capacityKb->value =
          VIR_DIV_UP(def->target.capacity, 1024); /* Scale from byte to kilobyte */

        if (esxVI_CreateVirtualDisk_Task
              (priv->primary, datastorePath,
               priv->primary->datacenter->_reference,
               esxVI_VirtualDiskSpec_DynamicCast(virtualDiskSpec), &task) < 0 ||
            esxVI_WaitForTaskCompletion(priv->primary, task, NULL,
                                        esxVI_Occurrence_None,
                                        priv->parsedUri->autoAnswer,
                                        &taskInfoState,
                                        &taskInfoErrorMessage) < 0) {
            goto cleanup;
        }

        if (taskInfoState != esxVI_TaskInfoState_Success) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not create volume: %1$s"),
                           taskInfoErrorMessage);
            goto cleanup;
        }

        if (priv->primary->hasQueryVirtualDiskUuid) {
            key = g_new0(char, VIR_UUID_STRING_BUFLEN);

            if (esxVI_QueryVirtualDiskUuid(priv->primary, datastorePath,
                                           priv->primary->datacenter->_reference,
                                           &uuid_string) < 0) {
                goto cleanup;
            }

            if (esxUtil_ReformatUuid(uuid_string, key) < 0)
                goto cleanup;
        } else {
            /* Fall back to the path as key */
            key = g_strdup(datastorePath);
        }
    } else {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Creation of %1$s volumes is not supported"),
                       virStorageFileFormatTypeToString(def->target.format));
        goto cleanup;
    }

    volume = virGetStorageVol(pool->conn, pool->name, def->name, key,
                              &esxStorageBackendVMFS, NULL);

 cleanup:
    if (virtualDiskSpec) {
        virtualDiskSpec->diskType = NULL;
        virtualDiskSpec->adapterType = NULL;
    }

    esxVI_FileInfo_Free(&fileInfo);
    esxVI_FileBackedVirtualDiskSpec_Free(&virtualDiskSpec);
    esxVI_ManagedObjectReference_Free(&task);
    return volume;
}



static virStorageVolPtr
esxStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                           const char *xmldesc,
                           virStorageVolPtr sourceVolume,
                           unsigned int flags)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = pool->conn->privateData;
    virStoragePoolDef poolDef = { 0 };
    g_autofree char *sourceDatastorePath = NULL;
    char *tmp;
    g_autofree char *unescapedDatastorePath = NULL;
    g_autofree char *unescapedDirectoryName = NULL;
    g_autofree char *unescapedDirectoryAndFileName = NULL;
    g_autofree char *directoryName = NULL;
    g_autofree char *fileName = NULL;
    g_autofree char *datastorePathWithoutFileName = NULL;
    g_autofree char *datastorePath = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    g_autofree char *taskInfoErrorMessage = NULL;
    g_autofree char *uuid_string = NULL;
    g_autofree char *key = NULL;
    g_autoptr(virStorageVolDef) def = NULL;

    virCheckFlags(0, NULL);

    if (esxLookupVMFSStoragePoolType(priv->primary, pool->name,
                                     &poolDef.type) < 0) {
        goto cleanup;
    }

    sourceDatastorePath = g_strdup_printf("[%s] %s", sourceVolume->pool,
                                          sourceVolume->name);

    /* Parse config */
    def = virStorageVolDefParse(&poolDef, xmldesc, NULL, 0);

    if (!def)
        goto cleanup;

    if (def->type != VIR_STORAGE_VOL_FILE) {
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("Creating non-file volumes is not supported"));
        goto cleanup;
    }

    /* Validate config */
    tmp = strrchr(def->name, '/');

    if (!tmp || *def->name == '/' || tmp[1] == '\0') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Volume name '%1$s' doesn't have expected format '<directory>/<file>'"),
                       def->name);
        goto cleanup;
    }

    if (!virStringHasCaseSuffix(def->name, ".vmdk")) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Volume name '%1$s' has unsupported suffix, expecting '.vmdk'"),
                       def->name);
        goto cleanup;
    }

    unescapedDatastorePath = g_strdup_printf("[%s] %s", pool->name, def->name);

    if (def->target.format == VIR_STORAGE_FILE_VMDK) {
        /* Parse and escape datastore path */
        if (esxUtil_ParseDatastorePath(unescapedDatastorePath, NULL,
                                       &unescapedDirectoryName,
                                       &unescapedDirectoryAndFileName) < 0) {
            goto cleanup;
        }

        directoryName = esxUtil_EscapeDatastoreItem(unescapedDirectoryName);

        if (!directoryName)
            goto cleanup;

        fileName = esxUtil_EscapeDatastoreItem(unescapedDirectoryAndFileName +
                                               strlen(unescapedDirectoryName) + 1);

        if (!fileName)
            goto cleanup;

        datastorePathWithoutFileName = g_strdup_printf("[%s] %s", pool->name,
                                                       directoryName);

        datastorePath = g_strdup_printf("[%s] %s/%s", pool->name, directoryName,
                                        fileName);

        /* Create directory, if it doesn't exist yet */
        if (esxVI_LookupFileInfoByDatastorePath
              (priv->primary, datastorePathWithoutFileName, true, &fileInfo,
               esxVI_Occurrence_OptionalItem) < 0) {
            goto cleanup;
        }

        if (!fileInfo) {
            if (esxVI_MakeDirectory(priv->primary, datastorePathWithoutFileName,
                                    priv->primary->datacenter->_reference,
                                    esxVI_Boolean_True) < 0) {
                goto cleanup;
            }
        }

        /* Copy VirtualDisk */
        if (esxVI_CopyVirtualDisk_Task(priv->primary, sourceDatastorePath,
                                       priv->primary->datacenter->_reference,
                                       datastorePath,
                                       priv->primary->datacenter->_reference,
                                       NULL, esxVI_Boolean_False, &task) < 0 ||
            esxVI_WaitForTaskCompletion(priv->primary, task, NULL,
                                        esxVI_Occurrence_None,
                                        priv->parsedUri->autoAnswer,
                                        &taskInfoState,
                                        &taskInfoErrorMessage) < 0) {
            goto cleanup;
        }

        if (taskInfoState != esxVI_TaskInfoState_Success) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not copy volume: %1$s"),
                           taskInfoErrorMessage);
            goto cleanup;
        }

        if (priv->primary->hasQueryVirtualDiskUuid) {
            key = g_new0(char, VIR_UUID_STRING_BUFLEN);

            if (esxVI_QueryVirtualDiskUuid(priv->primary, datastorePath,
                                           priv->primary->datacenter->_reference,
                                           &uuid_string) < 0) {
                goto cleanup;
            }

            if (esxUtil_ReformatUuid(uuid_string, key) < 0)
                goto cleanup;
        } else {
            /* Fall back to the path as key */
            key = g_strdup(datastorePath);
        }
    } else {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("Creation of %1$s volumes is not supported"),
                       virStorageFileFormatTypeToString(def->target.format));
        goto cleanup;
    }

    volume = virGetStorageVol(pool->conn, pool->name, def->name, key,
                              &esxStorageBackendVMFS, NULL);

 cleanup:
    esxVI_FileInfo_Free(&fileInfo);
    esxVI_ManagedObjectReference_Free(&task);
    return volume;
}



static int
esxStorageVolDelete(virStorageVolPtr volume, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = volume->conn->privateData;
    g_autofree char *datastorePath = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    g_autofree char *taskInfoErrorMessage = NULL;

    virCheckFlags(0, -1);

    datastorePath = g_strdup_printf("[%s] %s", volume->pool, volume->name);

    if (esxVI_DeleteVirtualDisk_Task(priv->primary, datastorePath,
                                     priv->primary->datacenter->_reference,
                                     &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, NULL,
                                    esxVI_Occurrence_None,
                                    priv->parsedUri->autoAnswer,
                                    &taskInfoState, &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not delete volume: %1$s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ManagedObjectReference_Free(&task);
    return result;
}



static int
esxStorageVolWipe(virStorageVolPtr volume, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = volume->conn->privateData;
    g_autofree char *datastorePath = NULL;
    esxVI_ManagedObjectReference *task = NULL;
    esxVI_TaskInfoState taskInfoState;
    g_autofree char *taskInfoErrorMessage = NULL;

    virCheckFlags(0, -1);

    datastorePath = g_strdup_printf("[%s] %s", volume->pool, volume->name);

    if (esxVI_ZeroFillVirtualDisk_Task(priv->primary, datastorePath,
                                       priv->primary->datacenter->_reference,
                                       &task) < 0 ||
        esxVI_WaitForTaskCompletion(priv->primary, task, NULL,
                                    esxVI_Occurrence_None,
                                    priv->parsedUri->autoAnswer,
                                    &taskInfoState, &taskInfoErrorMessage) < 0) {
        goto cleanup;
    }

    if (taskInfoState != esxVI_TaskInfoState_Success) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Could not wipe volume: %1$s"),
                       taskInfoErrorMessage);
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_ManagedObjectReference_Free(&task);
    return result;
}



static int
esxStorageVolGetInfo(virStorageVolPtr volume,
                     virStorageVolInfoPtr info)
{
    int result = -1;
    esxPrivate *priv = volume->conn->privateData;
    g_autofree char *datastorePath = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    esxVI_VmDiskFileInfo *vmDiskFileInfo = NULL;

    memset(info, 0, sizeof(*info));

    datastorePath = g_strdup_printf("[%s] %s", volume->pool, volume->name);

    if (esxVI_LookupFileInfoByDatastorePath(priv->primary, datastorePath,
                                            false, &fileInfo,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    vmDiskFileInfo = esxVI_VmDiskFileInfo_DynamicCast(fileInfo);

    info->type = VIR_STORAGE_VOL_FILE;

    if (vmDiskFileInfo) {
        /* Scale from kilobyte to byte */
        info->capacity = vmDiskFileInfo->capacityKb->value * 1024;
        info->allocation = vmDiskFileInfo->fileSize->value;
    } else {
        info->capacity = fileInfo->fileSize->value;
        info->allocation = fileInfo->fileSize->value;
    }

    result = 0;

 cleanup:
    esxVI_FileInfo_Free(&fileInfo);

    return result;
}



static char *
esxStorageVolGetXMLDesc(virStorageVolPtr volume,
                        unsigned int flags)
{
    esxPrivate *priv = volume->conn->privateData;
    virStoragePoolDef pool = { 0 };
    g_autofree char *datastorePath = NULL;
    esxVI_FileInfo *fileInfo = NULL;
    esxVI_VmDiskFileInfo *vmDiskFileInfo = NULL;
    esxVI_IsoImageFileInfo *isoImageFileInfo = NULL;
    esxVI_FloppyImageFileInfo *floppyImageFileInfo = NULL;
    virStorageVolDef def = { 0 };
    char *xml = NULL;

    virCheckFlags(0, NULL);

    if (esxLookupVMFSStoragePoolType(priv->primary, volume->pool,
                                     &pool.type) < 0) {
        return NULL;
    }

    /* Lookup file info */
    datastorePath = g_strdup_printf("[%s] %s", volume->pool, volume->name);

    if (esxVI_LookupFileInfoByDatastorePath(priv->primary, datastorePath,
                                            false, &fileInfo,
                                            esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    vmDiskFileInfo = esxVI_VmDiskFileInfo_DynamicCast(fileInfo);
    isoImageFileInfo = esxVI_IsoImageFileInfo_DynamicCast(fileInfo);
    floppyImageFileInfo = esxVI_FloppyImageFileInfo_DynamicCast(fileInfo);

    def.name = volume->name;

    if (esxVI_LookupStorageVolumeKeyByDatastorePath(priv->primary, datastorePath,
                                                    &def.key) < 0) {
        goto cleanup;
    }

    def.type = VIR_STORAGE_VOL_FILE;
    def.target.path = datastorePath;

    if (vmDiskFileInfo) {
        /* Scale from kilobyte to byte */
        def.target.capacity = vmDiskFileInfo->capacityKb->value * 1024;
        def.target.allocation = vmDiskFileInfo->fileSize->value;

        def.target.format = VIR_STORAGE_FILE_VMDK;
    } else if (isoImageFileInfo) {
        def.target.capacity = fileInfo->fileSize->value;
        def.target.allocation = fileInfo->fileSize->value;

        def.target.format = VIR_STORAGE_FILE_ISO;
    } else if (floppyImageFileInfo) {
        def.target.capacity = fileInfo->fileSize->value;
        def.target.allocation = fileInfo->fileSize->value;

        def.target.format = VIR_STORAGE_FILE_RAW;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("File '%1$s' has unknown type"), datastorePath);
        goto cleanup;
    }

    xml = virStorageVolDefFormat(&pool, &def);

 cleanup:
    esxVI_FileInfo_Free(&fileInfo);
    g_free(def.key);

    return xml;
}



static char *
esxStorageVolGetPath(virStorageVolPtr volume)
{
    return g_strdup_printf("[%s] %s", volume->pool, volume->name);
}



virStorageDriver esxStorageBackendVMFS = {
    .connectNumOfStoragePools = esxConnectNumOfStoragePools, /* 0.8.2 */
    .connectListStoragePools = esxConnectListStoragePools, /* 0.8.2 */
    .storagePoolLookupByName = esxStoragePoolLookupByName, /* 0.8.2 */
    .storagePoolLookupByUUID = esxStoragePoolLookupByUUID, /* 0.8.2 */
    .storagePoolRefresh = esxStoragePoolRefresh, /* 0.8.2 */
    .storagePoolGetInfo = esxStoragePoolGetInfo, /* 0.8.2 */
    .storagePoolGetXMLDesc = esxStoragePoolGetXMLDesc, /* 0.8.2 */
    .storagePoolNumOfVolumes = esxStoragePoolNumOfVolumes, /* 0.8.4 */
    .storagePoolListVolumes = esxStoragePoolListVolumes, /* 0.8.4 */
    .storageVolLookupByName = esxStorageVolLookupByName, /* 0.8.4 */
    .storageVolLookupByPath = esxStorageVolLookupByPath, /* 0.8.4 */
    .storageVolLookupByKey = esxStorageVolLookupByKey, /* 0.8.4 */
    .storageVolCreateXML = esxStorageVolCreateXML, /* 0.8.4 */
    .storageVolCreateXMLFrom = esxStorageVolCreateXMLFrom, /* 0.8.7 */
    .storageVolDelete = esxStorageVolDelete, /* 0.8.7 */
    .storageVolWipe = esxStorageVolWipe, /* 0.8.7 */
    .storageVolGetInfo = esxStorageVolGetInfo, /* 0.8.4 */
    .storageVolGetXMLDesc = esxStorageVolGetXMLDesc, /* 0.8.4 */
    .storageVolGetPath = esxStorageVolGetPath, /* 0.8.4 */
};
