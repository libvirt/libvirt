
/*
 * esx_storage_driver.c: storage driver functions for managing VMware ESX
 *                       host storage
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright (C) 2010 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#include <config.h>

#include "md5.h"
#include "verify.h"
#include "internal.h"
#include "util.h"
#include "memory.h"
#include "logging.h"
#include "uuid.h"
#include "storage_conf.h"
#include "esx_private.h"
#include "esx_storage_driver.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * The UUID of a storage pool is the MD5 sum of it's mount path. Therefore,
 * verify that UUID and MD5 sum match in size, because we rely on that.
 */
verify(MD5_DIGEST_SIZE == VIR_UUID_BUFLEN);



static virDrvOpenStatus
esxStorageOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               int flags ATTRIBUTE_UNUSED)
{
    if (conn->driver->no != VIR_DRV_ESX) {
        return VIR_DRV_OPEN_DECLINED;
    }

    conn->storagePrivateData = conn->privateData;

    return VIR_DRV_OPEN_SUCCESS;
}



static int
esxStorageClose(virConnectPtr conn)
{
    conn->storagePrivateData = NULL;

    return 0;
}



static int
esxNumberOfStoragePools(virConnectPtr conn)
{
    int count = 0;
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    if (esxVI_LookupDatastoreList(priv->primary, NULL, &datastoreList) < 0) {
        return -1;
    }

    for (datastore = datastoreList; datastore != NULL;
         datastore = datastore->_next) {
        ++count;
    }

    esxVI_ObjectContent_Free(&datastoreList);

    return count;
}



static int
esxListStoragePools(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    int count = 0;
    int i;

    if (names == NULL || maxnames < 0) {
        ESX_ERROR(VIR_ERR_INVALID_ARG, "%s", _("Invalid argument"));
        return -1;
    }

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "summary.name") < 0 ||
        esxVI_LookupDatastoreList(priv->primary, propertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    for (datastore = datastoreList; datastore != NULL;
         datastore = datastore->_next) {
        for (dynamicProperty = datastore->propSet; dynamicProperty != NULL;
             dynamicProperty = dynamicProperty->_next) {
            if (STREQ(dynamicProperty->name, "summary.name")) {
                if (esxVI_AnyType_ExpectType(dynamicProperty->val,
                                             esxVI_Type_String) < 0) {
                    goto cleanup;
                }

                names[count] = strdup(dynamicProperty->val->string);

                if (names[count] == NULL) {
                    virReportOOMError();
                    goto cleanup;
                }

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
        for (i = 0; i < count; ++i) {
            VIR_FREE(names[i]);
        }

        count = -1;
    }

    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastoreList);

    return count;
}



static int
esxNumberOfDefinedStoragePools(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    /* ESX storage pools are always active */
    return 0;
}



static int
esxListDefinedStoragePools(virConnectPtr conn ATTRIBUTE_UNUSED,
                           char **const names ATTRIBUTE_UNUSED,
                           int maxnames ATTRIBUTE_UNUSED)
{
    /* ESX storage pools are always active */
    return 0;
}



static virStoragePoolPtr
esxStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    unsigned char md5[MD5_DIGEST_SIZE]; /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    virStoragePoolPtr pool = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    if (esxVI_LookupDatastoreByName(priv->primary, name, NULL, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /*
     * Datastores don't have a UUID, but we can use the 'host.mountInfo.path'
     * property as source for a UUID. The mount path is unique per host and
     * cannot change during the lifetime of the datastore.
     *
     * The MD5 sum of the mount path can be used as UUID, assuming MD5 is
     * considered to be collision-free enough for this use case.
     */
    if (esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj,
                                       &hostMount) < 0) {
        goto cleanup;
    }

    md5_buffer(hostMount->mountInfo->path,
               strlen(hostMount->mountInfo->path), md5);

    pool = virGetStoragePool(conn, name, md5);

  cleanup:
    esxVI_ObjectContent_Free(&datastore);
    esxVI_DatastoreHostMount_Free(&hostMount);

    return pool;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastoreList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    unsigned char md5[MD5_DIGEST_SIZE]; /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";
    char *name = NULL;
    virStoragePoolPtr pool = NULL;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList, "summary.name") < 0 ||
        esxVI_LookupDatastoreList(priv->primary, propertyNameList,
                                  &datastoreList) < 0) {
        goto cleanup;
    }

    for (datastore = datastoreList; datastore != NULL;
         datastore = datastore->_next) {
        esxVI_DatastoreHostMount_Free(&hostMount);

        if (esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj,
                                           &hostMount) < 0) {
            goto cleanup;
        }

        md5_buffer(hostMount->mountInfo->path,
                   strlen(hostMount->mountInfo->path), md5);

        if (memcmp(uuid, md5, VIR_UUID_BUFLEN) == 0) {
            break;
        }
    }

    if (datastore == NULL) {
        virUUIDFormat(uuid, uuid_string);

        ESX_VI_ERROR(VIR_ERR_NO_STORAGE_POOL,
                     _("Could not find datastore with UUID '%s'"),
                     uuid_string);

        goto cleanup;
    }

    if (esxVI_GetStringValue(datastore, "summary.name", &name,
                             esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    pool = virGetStoragePool(conn, name, uuid);

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
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_ObjectContent *datastore = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

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
esxStoragePoolGetInfo(virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    int result = -1;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;

    memset(info, 0, sizeof (*info));

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

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

        for (dynamicProperty = datastore->propSet; dynamicProperty != NULL;
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
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_DatastoreHostMount *hostMount = NULL;
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;
    virStoragePoolDef def;
    esxVI_DatastoreInfo *info = NULL;
    esxVI_NasDatastoreInfo *nasInfo = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    memset(&def, 0, sizeof (def));

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

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
        esxVI_LookupDatastoreHostMount(priv->primary, datastore->obj,
                                       &hostMount) < 0) {
        goto cleanup;
    }

    def.name = pool->name;
    memcpy(def.uuid, pool->uuid, VIR_UUID_BUFLEN);

    def.target.path = hostMount->mountInfo->path;

    if (accessible == esxVI_Boolean_True) {
        for (dynamicProperty = datastore->propSet; dynamicProperty != NULL;
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

    for (dynamicProperty = datastore->propSet; dynamicProperty != NULL;
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
    if (esxVI_LocalDatastoreInfo_DynamicCast(info) != NULL) {
        def.type = VIR_STORAGE_POOL_DIR;
    } else if ((nasInfo = esxVI_NasDatastoreInfo_DynamicCast(info)) != NULL) {
        def.type = VIR_STORAGE_POOL_NETFS;
        def.source.host.name = nasInfo->nas->remoteHost;
        def.source.dir = nasInfo->nas->remotePath;

        if (STRCASEEQ(nasInfo->nas->type, "NFS")) {
            def.source.format = VIR_STORAGE_POOL_NETFS_NFS;
        } else  if (STRCASEEQ(nasInfo->nas->type, "CIFS")) {
            def.source.format = VIR_STORAGE_POOL_NETFS_CIFS;
        } else {
            ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                      _("Datastore has unexpected type '%s'"),
                      nasInfo->nas->type);
            goto cleanup;
        }
    } else if (esxVI_VmfsDatastoreInfo_DynamicCast(info) != NULL) {
        def.type = VIR_STORAGE_POOL_FS;
        /*
         * FIXME: I'm not sure how to represent the source and target of a
         * VMFS based datastore in libvirt terms
         */
    } else {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("DatastoreInfo has unexpected type"));
        goto cleanup;
    }

    xml = virStoragePoolDefFormat(&def);

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);
    esxVI_DatastoreHostMount_Free(&hostMount);
    esxVI_DatastoreInfo_Free(&info);

    return xml;
}



static int
esxStoragePoolGetAutostart(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                           int *autostart)
{
    /* ESX storage pools are always active */
    *autostart = 1;

    return 0;
}



static int
esxStoragePoolSetAutostart(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                           int autostart)
{
    /* Just accept autostart activation, but fail on autostart deactivation */
    autostart = (autostart != 0);

    if (! autostart) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Cannot deactivate storage pool autostart"));
        return -1;
    }

    return 0;
}



static int
esxStoragePoolIsActive(virStoragePoolPtr pool ATTRIBUTE_UNUSED)
{
    /* ESX storage pools are always active */
    return 1;
}



static int
esxStoragePoolIsPersistent(virStoragePoolPtr pool ATTRIBUTE_UNUSED)
{
    /* ESX has no concept of transient pools, so all of them are persistent */
    return 1;
}


static virStorageDriver esxStorageDriver = {
    "ESX",                                 /* name */
    esxStorageOpen,                        /* open */
    esxStorageClose,                       /* close */
    esxNumberOfStoragePools,               /* numOfPools */
    esxListStoragePools,                   /* listPools */
    esxNumberOfDefinedStoragePools,        /* numOfDefinedPools */
    esxListDefinedStoragePools,            /* listDefinedPools */
    NULL,                                  /* findPoolSources */
    esxStoragePoolLookupByName,            /* poolLookupByName */
    esxStoragePoolLookupByUUID,            /* poolLookupByUUID */
    NULL,                                  /* poolLookupByVolume */
    NULL,                                  /* poolCreateXML */
    NULL,                                  /* poolDefineXML */
    NULL,                                  /* poolBuild */
    NULL,                                  /* poolUndefine */
    NULL,                                  /* poolCreate */
    NULL,                                  /* poolDestroy */
    NULL,                                  /* poolDelete */
    esxStoragePoolRefresh,                 /* poolRefresh */
    esxStoragePoolGetInfo,                 /* poolGetInfo */
    esxStoragePoolGetXMLDesc,              /* poolGetXMLDesc */
    esxStoragePoolGetAutostart,            /* poolGetAutostart */
    esxStoragePoolSetAutostart,            /* poolSetAutostart */
    NULL,                                  /* poolNumOfVolumes */
    NULL,                                  /* poolListVolumes */
    NULL,                                  /* volLookupByName */
    NULL,                                  /* volLookupByKey */
    NULL,                                  /* volLookupByPath */
    NULL,                                  /* volCreateXML */
    NULL,                                  /* volCreateXMLFrom */
    NULL,                                  /* volDelete */
    NULL,                                  /* volWipe */
    NULL,                                  /* volGetInfo */
    NULL,                                  /* volGetXMLDesc */
    NULL,                                  /* volGetPath */
    esxStoragePoolIsActive,                /* poolIsActive */
    esxStoragePoolIsPersistent,            /* poolIsPersistent */
};



int
esxStorageRegister(void)
{
    return virRegisterStorageDriver(&esxStorageDriver);
}
