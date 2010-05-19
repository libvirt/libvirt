
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



static virDrvOpenStatus
esxStorageOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               int flags ATTRIBUTE_UNUSED)
{
    if (STRNEQ(conn->driver->name, "ESX")) {
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

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    if (esxVI_LookupObjectContentByType(priv->host, priv->host->datacenter,
                                        "Datastore", NULL, esxVI_Boolean_True,
                                        &datastoreList) < 0) {
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

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    if (esxVI_String_AppendValueToList(&propertyNameList,
                                       "summary.name") < 0 ||
        esxVI_LookupObjectContentByType(priv->host, priv->host->datacenter,
                                        "Datastore", propertyNameList,
                                        esxVI_Boolean_True,
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
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;
    char *summaryUrl = NULL;
    char *suffix = NULL;
    int suffixLength;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "00000000-00000000-0000-000000000000";
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *realName = NULL;
    virStoragePoolPtr pool = NULL;

    if (esxVI_EnsureSession(priv->host) < 0) {
        return NULL;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.accessible\0"
                                           "summary.name\0"
                                           "summary.url\0") < 0 ||
        esxVI_LookupDatastoreByName(priv->host, name,
                                    propertyNameList, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetBoolean(datastore, "summary.accessible",
                         &accessible, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    /*
     * Datastores don't have a UUID. We can use the 'summary.url' property as
     * source for a "UUID" on ESX, because the property value has this format:
     *
     *   summary.url = /vmfs/volumes/4b0beca7-7fd401f3-1d7f-000ae484a6a3
     *   summary.url = /vmfs/volumes/b24b7a78-9d82b4f5    (short format)
     *
     * The 'summary.url' property comes in two forms, with a complete "UUID"
     * and a short "UUID".
     *
     * But this trailing "UUID" is not guaranteed to be there. On the other
     * hand we already rely on another implementation detail of the ESX server:
     * The object name of virtual machine contains an integer, we use that as
     * domain ID.
     *
     * The 'summary.url' property of an inaccessible datastore is invalid.
     */
    if (accessible == esxVI_Boolean_True &&
        priv->host->productVersion & esxVI_ProductVersion_ESX) {
        if (esxVI_GetStringValue(datastore, "summary.url", &summaryUrl,
                                 esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }

        if ((suffix = STRSKIP(summaryUrl, "/vmfs/volumes/")) == NULL) {
            ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
                         _("Datastore URL '%s' has unexpected prefix, "
                           "expecting '/vmfs/volumes/' prefix"), summaryUrl);
            goto cleanup;
        }

        suffixLength = strlen(suffix);

        if ((suffixLength == 35 && /* = strlen("4b0beca7-7fd401f3-1d7f-000ae484a6a3") */
             suffix[8] == '-' && suffix[17] == '-' && suffix[22] == '-') ||
            (suffixLength == 17 && /* = strlen("b24b7a78-9d82b4f5") */
             suffix[8] == '-')) {
            /*
             * Intentionally use memcpy here, because we want to be able to
             * replace a prefix of the initial Zero-UUID. virStrncpy would
             * null-terminate the string in an unwanted place.
             */
            memcpy(uuid_string, suffix, suffixLength);
        } else {
            VIR_WARN("Datastore URL suffix '%s' has unexpected format, "
                     "cannot deduce a UUID from it", suffix);
        }
    }

    if (virUUIDParse(uuid_string, uuid) < 0) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR,
                  _("Could not parse UUID from string '%s'"),
                  uuid_string);
        goto cleanup;
    }

    if (esxVI_GetStringValue(datastore, "summary.name", &realName,
                             esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    pool = virGetStoragePool(conn, realName, uuid);

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);

    return pool;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_String *propertyNameList = NULL;
    esxVI_ObjectContent *datastore = NULL;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";
    char *name = NULL;
    virStoragePoolPtr pool = NULL;

    if (! (priv->host->productVersion & esxVI_ProductVersion_ESX)) {
        ESX_ERROR(VIR_ERR_INTERNAL_ERROR, "%s",
                  _("Lookup by UUID is supported on ESX only"));
        return NULL;
    }

    if (esxVI_EnsureSession(priv->host) < 0) {
        return NULL;
    }

    /*
     * Convert from UUID to datastore URL form by stripping the second '-':
     *
     * <---- 14 ----><-------- 22 -------->    <---- 13 ---><-------- 22 -------->
     * 4b0beca7-7fd4-01f3-1d7f-000ae484a6a3 -> 4b0beca7-7fd401f3-1d7f-000ae484a6a3
     */
    virUUIDFormat(uuid, uuid_string);
    memmove(uuid_string + 13, uuid_string + 14, 22 + 1);

    /*
     * Use esxVI_LookupDatastoreByName because it also does try to match "UUID"
     * part of the 'summary.url' property if there is no name match.
     */
    if (esxVI_String_AppendValueToList(&propertyNameList, "summary.name") < 0 ||
        esxVI_LookupDatastoreByName(priv->host, uuid_string,
                                    propertyNameList, &datastore,
                                    esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    /*
     * If the first try didn't succeed and the trailing 16 digits are zero then
     * the "UUID" could be a short one. Strip the 16 zeros and try again:
     *
     * <------ 17 ----->                      <------ 17 ----->
     * b24b7a78-9d82b4f5-0000-000000000000 -> b24b7a78-9d82b4f5
     */
    if (datastore == NULL && STREQ(uuid_string + 17, "-0000-000000000000")) {
        uuid_string[17] = '\0';

        if (esxVI_LookupDatastoreByName(priv->host, uuid_string,
                                        propertyNameList, &datastore,
                                        esxVI_Occurrence_RequiredItem) < 0) {
            goto cleanup;
        }
    }

    if (datastore == NULL) {
        virUUIDFormat(uuid, uuid_string);

        ESX_VI_ERROR(VIR_ERR_INTERNAL_ERROR,
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
    esxVI_ObjectContent_Free(&datastore);

    return pool;
}



static int
esxStoragePoolRefresh(virStoragePoolPtr pool, unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_ObjectContent *datastore = NULL;

    virCheckFlags(0, -1);

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    if (esxVI_LookupDatastoreByName(priv->host, pool->name, NULL, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_RefreshDatastore(priv->host, datastore->obj) < 0) {
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

    if (esxVI_EnsureSession(priv->host) < 0) {
        return -1;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.accessible\0"
                                           "summary.capacity\0"
                                           "summary.freeSpace\0") < 0 ||
        esxVI_LookupDatastoreByName(priv->host, pool->name,
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
    esxVI_DynamicProperty *dynamicProperty = NULL;
    esxVI_Boolean accessible = esxVI_Boolean_Undefined;
    virStoragePoolDef def;
    esxVI_DatastoreInfo *info = NULL;
    esxVI_LocalDatastoreInfo *localInfo = NULL;
    esxVI_NasDatastoreInfo *nasInfo = NULL;
    esxVI_VmfsDatastoreInfo *vmfsInfo = NULL;
    char *xml = NULL;

    virCheckFlags(0, NULL);

    memset(&def, 0, sizeof (def));

    if (esxVI_EnsureSession(priv->host) < 0) {
        return NULL;
    }

    if (esxVI_String_AppendValueListToList(&propertyNameList,
                                           "summary.accessible\0"
                                           "summary.capacity\0"
                                           "summary.freeSpace\0"
                                           "info\0") < 0 ||
        esxVI_LookupDatastoreByName(priv->host, pool->name,
                                    propertyNameList, &datastore,
                                    esxVI_Occurrence_RequiredItem) < 0 ||
        esxVI_GetBoolean(datastore, "summary.accessible",
                         &accessible, esxVI_Occurrence_RequiredItem) < 0) {
        goto cleanup;
    }

    def.name = pool->name;
    memcpy(def.uuid, pool->uuid, VIR_UUID_BUFLEN);

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
            } else if (STREQ(dynamicProperty->name, "info")) {
                if (esxVI_DatastoreInfo_CastFromAnyType(dynamicProperty->val,
                                                        &info) < 0) {
                    goto cleanup;
                }
            }
        }

        def.allocation = def.capacity - def.available;

        /* See vSphere API documentation about HostDatastoreSystem for details */
        if ((localInfo = esxVI_LocalDatastoreInfo_DynamicCast(info)) != NULL) {
            def.type = VIR_STORAGE_POOL_DIR;
            def.target.path = localInfo->path;
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
        } else if ((vmfsInfo = esxVI_VmfsDatastoreInfo_DynamicCast(info)) != NULL) {
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
    }

    xml = virStoragePoolDefFormat(&def);

  cleanup:
    esxVI_String_Free(&propertyNameList);
    esxVI_ObjectContent_Free(&datastore);
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
