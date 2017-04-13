/*
 * esx_storage_backend_iscsi.c: ESX storage backend for iSCSI handling
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "internal.h"
#include "md5.h"
#include "viralloc.h"
#include "viruuid.h"
#include "storage_conf.h"
#include "virstoragefile.h"
#include "esx_storage_backend_iscsi.h"
#include "esx_private.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * The UUID of a storage pool is the MD5 sum of its mount path. Therefore,
 * verify that UUID and MD5 sum match in size, because we rely on that.
 */
verify(MD5_DIGEST_SIZE == VIR_UUID_BUFLEN);



static int
esxConnectNumOfStoragePools(virConnectPtr conn)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain iSCSI adapter"));
        goto cleanup;
    }

    /* FIXME: code looks for software iSCSI adapter only */
    if (!hostInternetScsiHba) {
        /* iSCSI adapter may not be enabled for this host */
        return 0;
    }

    /*
     * ESX has two kind of targets:
     * 1. staticIscsiTargets
     * 2. dynamicIscsiTargets
     * For each dynamic target if its reachable a static target is added.
     * return iSCSI names for all static targets to avoid duplicate names.
     */
    for (target = hostInternetScsiHba->configuredStaticTarget;
         target; target = target->_next) {
        ++count;
    }

    success = true;

 cleanup:
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return success ? count : -1;
}



static int
esxConnectListStoragePools(virConnectPtr conn, char **const names,
                           const int maxnames)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = conn->privateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;
    size_t i;

    if (maxnames == 0)
        return 0;

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain iSCSI adapter"));
        goto cleanup;
    }

    /* FIXME: code looks for software iSCSI adapter only */
    if (!hostInternetScsiHba) {
        /* iSCSI adapter may not be enabled for this host */
        return 0;
    }

    /*
     * ESX has two kind of targets:
     * 1. staticIscsiTargets
     * 2. dynamicIscsiTargets
     * For each dynamic target if its reachable a static target is added.
     * return iSCSI names for all static targets to avoid duplicate names.
     */
    for (target = hostInternetScsiHba->configuredStaticTarget;
         target && count < maxnames; target = target->_next) {
        if (VIR_STRDUP(names[count], target->iScsiName) < 0)
            goto cleanup;

        ++count;
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);
    }

    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return success ? count : -1;
}



static virStoragePoolPtr
esxStoragePoolLookupByName(virConnectPtr conn,
                           const char *name)
{
    esxPrivate *priv = conn->privateData;
    esxVI_HostInternetScsiHbaStaticTarget *target = NULL;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    virStoragePoolPtr pool = NULL;

    /*
     * Lookup routine are used by the base driver to determine
     * appropriate backend driver, lookup targetName as optional
     * parameter
     */
    if (esxVI_LookupHostInternetScsiHbaStaticTargetByName
          (priv->primary, name, &target, esxVI_Occurrence_OptionalItem) < 0) {
        goto cleanup;
    }

    if (!target) {
        /* pool not found, error handling done by the base driver */
        goto cleanup;
    }

    /*
     * HostInternetScsiHbaStaticTarget does not provide a uuid field,
     * but iScsiName (or widely known as IQN) is unique across the multiple
     * hosts, using it to compute key
     */
    md5_buffer(target->iScsiName, strlen(target->iScsiName), md5);

    pool = virGetStoragePool(conn, name, md5, &esxStorageBackendISCSI, NULL);

 cleanup:
    esxVI_HostInternetScsiHbaStaticTarget_Free(&target);

    return pool;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn,
                           const unsigned char *uuid)
{
    virStoragePoolPtr pool = NULL;
    esxPrivate *priv = conn->privateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain iSCSI adapter"));
        goto cleanup;
    }

    /* FIXME: code just looks for software iSCSI adapter */
    if (!hostInternetScsiHba) {
        /* iSCSI adapter may not be enabled for this host */
        return NULL;
    }

    for (target = hostInternetScsiHba->configuredStaticTarget;
         target; target = target->_next) {
        md5_buffer(target->iScsiName, strlen(target->iScsiName), md5);

        if (memcmp(uuid, md5, VIR_UUID_BUFLEN) == 0)
            break;
    }

    if (!target) {
        /* pool not found, error handling done by the base driver */
        goto cleanup;
    }

    pool = virGetStoragePool(conn, target->iScsiName, md5,
                             &esxStorageBackendISCSI, NULL);

 cleanup:
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return pool;
}



static int
esxStoragePoolRefresh(virStoragePoolPtr pool,
                      unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;

    virCheckFlags(0, -1);

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        goto cleanup;
    }

    /*
     * ESX does not allow rescan on a particular target,
     * rescan all the static targets
     */
    if (esxVI_RescanHba(priv->primary,
                        priv->primary->hostSystem->configManager->storageSystem,
                        hostInternetScsiHba->device) < 0) {
        goto cleanup;
    }

    result = 0;

 cleanup:
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return result;
}



static int
esxStoragePoolGetInfo(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                      virStoragePoolInfoPtr info)
{
    /* These fields are not valid for iSCSI pool */
    info->allocation = info->capacity = info->available = 0;
    info->state = VIR_STORAGE_POOL_RUNNING;

    return 0;
}



static char *
esxStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;
    virStoragePoolDef def;

    virCheckFlags(0, NULL);

    memset(&def, 0, sizeof(def));

    if (esxVI_LookupHostInternetScsiHba(priv->primary, &hostInternetScsiHba))
        goto cleanup;

    for (target = hostInternetScsiHba->configuredStaticTarget;
         target; target = target->_next) {
        if (STREQ(target->iScsiName, pool->name))
            break;
    }

    if (!target) {
        /* pool not found */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could not find storage pool with name '%s'"),
                       pool->name);
        goto cleanup;
    }

    def.name = pool->name;

    memcpy(def.uuid, pool->uuid, VIR_UUID_BUFLEN);

    def.type = VIR_STORAGE_POOL_ISCSI;

    def.source.initiator.iqn = target->iScsiName;

    def.source.nhost = 1;

    if (VIR_ALLOC_N(def.source.hosts, def.source.nhost) < 0)
        goto cleanup;

    def.source.hosts[0].name = target->address;

    if (target->port)
        def.source.hosts[0].port = target->port->value;

    /* TODO: add CHAP authentication params */
    xml = virStoragePoolDefFormat(&def);

 cleanup:
    VIR_FREE(def.source.hosts);
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return xml;
}



static int
esxStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    int count = 0;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLunList = NULL;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLun;

    if (esxVI_LookupHostScsiTopologyLunListByTargetName
          (priv->primary, pool->name, &hostScsiTopologyLunList) < 0) {
        return -1;
    }

    for (hostScsiTopologyLun = hostScsiTopologyLunList;
         hostScsiTopologyLun;
         hostScsiTopologyLun = hostScsiTopologyLun->_next) {
        ++count;
    }

    esxVI_HostScsiTopologyLun_Free(&hostScsiTopologyLunList);

    return count;
}



static int
esxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names,
                          int maxnames)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLunList = NULL;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLun;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun = NULL;
    size_t i;

    if (esxVI_LookupHostScsiTopologyLunListByTargetName
          (priv->primary, pool->name, &hostScsiTopologyLunList) < 0) {
        goto cleanup;
    }

    if (!hostScsiTopologyLunList) {
        /* iSCSI adapter may not be enabled on ESX host */
        return 0;
    }

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun && count < maxnames;
         scsiLun = scsiLun->_next) {
        for (hostScsiTopologyLun = hostScsiTopologyLunList;
             hostScsiTopologyLun && count < maxnames;
             hostScsiTopologyLun = hostScsiTopologyLun->_next) {
            if (STREQ(hostScsiTopologyLun->scsiLun, scsiLun->key)) {
                if (VIR_STRDUP(names[count], scsiLun->deviceName) < 0)
                    goto cleanup;

                ++count;
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

    esxVI_HostScsiTopologyLun_Free(&hostScsiTopologyLunList);
    esxVI_ScsiLun_Free(&scsiLunList);

    return count;
}



static virStorageVolPtr
esxStorageVolLookupByName(virStoragePoolPtr pool,
                          const char *name)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = pool->conn->privateData;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun;
         scsiLun = scsiLun->_next) {
        if (STREQ(scsiLun->deviceName, name)) {
            /*
             * ScsiLun provides a UUID field that is unique across
             * multiple servers. But this field length is ~55 characters
             * compute MD5 hash to transform it to an acceptable
             * libvirt format
             */
            md5_buffer(scsiLun->uuid, strlen(scsiLun->uuid), md5);
            virUUIDFormat(md5, uuid_string);

            /*
             * ScsiLun provides displayName and canonicalName but both are
             * optional and its observed that they can be NULL, using
             * deviceName to create volume.
             */
            volume = virGetStorageVol(pool->conn, pool->name, name, uuid_string,
                                      &esxStorageBackendISCSI, NULL);
            break;
        }
    }

 cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);

    return volume;
}



static virStorageVolPtr
esxStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = conn->privateData;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    esxVI_HostScsiDisk *hostScsiDisk = NULL;
    char *poolName = NULL;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun; scsiLun = scsiLun->_next) {
        hostScsiDisk = esxVI_HostScsiDisk_DynamicCast(scsiLun);

        if (hostScsiDisk && STREQ(hostScsiDisk->devicePath, path)) {
            /* Found matching device */
            VIR_FREE(poolName);

            if (esxVI_LookupStoragePoolNameByScsiLunKey(priv->primary,
                                                        hostScsiDisk->key,
                                                        &poolName) < 0) {
                goto cleanup;
            }

            md5_buffer(scsiLun->uuid, strlen(scsiLun->uuid), md5);
            virUUIDFormat(md5, uuid_string);

            volume = virGetStorageVol(conn, poolName, path, uuid_string,
                                      &esxStorageBackendISCSI, NULL);
            break;
        }
    }

 cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);
    VIR_FREE(poolName);

    return volume;
}



static virStorageVolPtr
esxStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = conn->privateData;
    char *poolName = NULL;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    /* key may be LUN device path */
    if (STRPREFIX(key, "/"))
        return esxStorageVolLookupByPath(conn, key);

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun;
         scsiLun = scsiLun->_next) {
        memset(uuid_string, '\0', sizeof(uuid_string));
        memset(md5, '\0', sizeof(md5));

        md5_buffer(scsiLun->uuid, strlen(scsiLun->uuid), md5);
        virUUIDFormat(md5, uuid_string);

        if (STREQ(key, uuid_string)) {
            /* Found matching UUID */
            VIR_FREE(poolName);

            if (esxVI_LookupStoragePoolNameByScsiLunKey(priv->primary,
                                                        scsiLun->key,
                                                        &poolName) < 0) {
                goto cleanup;
            }

            volume = virGetStorageVol(conn, poolName, scsiLun->deviceName,
                                      uuid_string, &esxStorageBackendISCSI,
                                      NULL);
            break;
        }
    }

 cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);
    VIR_FREE(poolName);

    return volume;
}



static virStorageVolPtr
esxStorageVolCreateXML(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                       const char *xmldesc ATTRIBUTE_UNUSED,
                       unsigned int flags)
{
    virCheckFlags(0, NULL);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume creation"));

    return NULL;
}



static virStorageVolPtr
esxStorageVolCreateXMLFrom(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                           const char *xmldesc ATTRIBUTE_UNUSED,
                           virStorageVolPtr sourceVolume ATTRIBUTE_UNUSED,
                           unsigned int flags)
{
    virCheckFlags(0, NULL);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume creation"));

    return NULL;
}



static int
esxStorageVolGetInfo(virStorageVolPtr volume,
                     virStorageVolInfoPtr info)
{
    int result = -1;
    esxPrivate *priv = volume->conn->privateData;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    esxVI_HostScsiDisk *hostScsiDisk = NULL;

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun;
         scsiLun = scsiLun->_next) {
        hostScsiDisk = esxVI_HostScsiDisk_DynamicCast(scsiLun);

        if (hostScsiDisk &&
            STREQ(hostScsiDisk->deviceName, volume->name)) {
            break;
        }
    }

    if (!hostScsiDisk) {
        virReportError(VIR_ERR_NO_STORAGE_VOL,
                       _("Could not find volume with name: %s"),
                       volume->name);
        goto cleanup;
    }

    info->type = VIR_STORAGE_VOL_BLOCK;
    info->capacity = hostScsiDisk->capacity->block->value *
                     hostScsiDisk->capacity->blockSize->value;
    info->allocation = info->capacity;

    result = 0;

 cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);

    return result;
}



static char *
esxStorageVolGetXMLDesc(virStorageVolPtr volume,
                        unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = volume->conn->privateData;
    virStoragePoolDef pool;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    esxVI_HostScsiDisk *hostScsiDisk = NULL;
    virStorageVolDef def;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    virCheckFlags(0, NULL);

    memset(&pool, 0, sizeof(pool));
    memset(&def, 0, sizeof(def));

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0)
        goto cleanup;

    for (scsiLun = scsiLunList; scsiLun;
         scsiLun = scsiLun->_next) {
        hostScsiDisk = esxVI_HostScsiDisk_DynamicCast(scsiLun);

        if (hostScsiDisk &&
            STREQ(hostScsiDisk->deviceName, volume->name)) {
            break;
        }
    }

    if (!scsiLun) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could find volume with name: %s"), volume->name);
        goto cleanup;
    }

    pool.type = VIR_STORAGE_POOL_ISCSI;

    def.name = volume->name;

    md5_buffer(scsiLun->uuid, strlen(scsiLun->uuid), md5);

    virUUIDFormat(md5, uuid_string);

    if (VIR_STRDUP(def.key, uuid_string) < 0)
        goto cleanup;

    /* iSCSI LUN exposes a block device */
    def.type = VIR_STORAGE_VOL_BLOCK;

    def.target.path = hostScsiDisk->devicePath;

    def.target.capacity = hostScsiDisk->capacity->block->value *
                   hostScsiDisk->capacity->blockSize->value;

    def.target.allocation = def.target.capacity;

    /* iSCSI LUN(s) hosting a datastore will be auto-mounted by ESX host */
    def.target.format = VIR_STORAGE_FILE_RAW;

    xml = virStorageVolDefFormat(&pool, &def);

 cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);
    VIR_FREE(def.key);

    return xml;
}



static int
esxStorageVolDelete(virStorageVolPtr volume ATTRIBUTE_UNUSED,
                    unsigned int flags)
{
    virCheckFlags(0, -1);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume deletion"));

    return -1;
}



static int
esxStorageVolWipe(virStorageVolPtr volume ATTRIBUTE_UNUSED,
                  unsigned int flags)
{
    virCheckFlags(0, -1);


    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume wiping"));

    return -1;
}



static char *
esxStorageVolGetPath(virStorageVolPtr volume)
{
    char *path;

    ignore_value(VIR_STRDUP(path, volume->name));
    return path;
}



virStorageDriver esxStorageBackendISCSI = {
    .connectNumOfStoragePools = esxConnectNumOfStoragePools, /* 1.0.1 */
    .connectListStoragePools = esxConnectListStoragePools, /* 1.0.1 */
    .storagePoolLookupByName = esxStoragePoolLookupByName, /* 1.0.1 */
    .storagePoolLookupByUUID = esxStoragePoolLookupByUUID, /* 1.0.1 */
    .storagePoolRefresh = esxStoragePoolRefresh, /* 1.0.1 */
    .storagePoolGetInfo = esxStoragePoolGetInfo, /* 1.0.1 */
    .storagePoolGetXMLDesc = esxStoragePoolGetXMLDesc, /* 1.0.1 */
    .storagePoolNumOfVolumes = esxStoragePoolNumOfVolumes, /* 1.0.1 */
    .storagePoolListVolumes = esxStoragePoolListVolumes, /* 1.0.1 */
    .storageVolLookupByName = esxStorageVolLookupByName, /* 1.0.1 */
    .storageVolLookupByPath = esxStorageVolLookupByPath, /* 1.0.1 */
    .storageVolLookupByKey = esxStorageVolLookupByKey, /* 1.0.1 */
    .storageVolCreateXML = esxStorageVolCreateXML, /* 1.0.1 */
    .storageVolCreateXMLFrom = esxStorageVolCreateXMLFrom, /* 1.0.1 */
    .storageVolGetInfo = esxStorageVolGetInfo, /* 1.2.5 */
    .storageVolGetXMLDesc = esxStorageVolGetXMLDesc, /* 1.0.1 */
    .storageVolDelete = esxStorageVolDelete, /* 1.0.1 */
    .storageVolWipe = esxStorageVolWipe, /* 1.0.1 */
    .storageVolGetPath = esxStorageVolGetPath, /* 1.0.1 */
};
