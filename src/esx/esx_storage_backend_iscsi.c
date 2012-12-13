
/*
 * esx_storage_backend_iscsi.c: ESX storage backend for iSCSI handling
 *
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
#include "virutil.h"
#include "viralloc.h"
#include "virlog.h"
#include "viruuid.h"
#include "storage_conf.h"
#include "virstoragefile.h"
#include "esx_storage_backend_iscsi.h"
#include "esx_private.h"
#include "esx_vi.h"
#include "esx_vi_methods.h"
#include "esx_util.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * The UUID of a storage pool is the MD5 sum of it's mount path. Therefore,
 * verify that UUID and MD5 sum match in size, because we rely on that.
 */
verify(MD5_DIGEST_SIZE == VIR_UUID_BUFLEN);



static int
esxStorageBackendISCSINumberOfPools(virConnectPtr conn)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain iSCSI adapter"));
        goto cleanup;
    }

    /* FIXME: code looks for software iSCSI adapter only */
    if (hostInternetScsiHba == NULL) {
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
         target != NULL; target = target->_next) {
        ++count;
    }

    success = true;

  cleanup:
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return success ? count : -1;
}



static int
esxStorageBackendISCSIListPools(virConnectPtr conn, char **const names,
                                const int maxnames)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;
    int i;

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_LookupHostInternetScsiHba(priv->primary,
                                        &hostInternetScsiHba) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to obtain iSCSI adapter"));
        goto cleanup;
    }

    /* FIXME: code looks for software iSCSI adapter only */
    if (hostInternetScsiHba == NULL) {
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
         target != NULL && count < maxnames; target = target->_next) {
        names[count] = strdup(target->iScsiName);

        if (names[count] == NULL) {
            virReportOOMError();
            goto cleanup;
        }

        ++count;
    }

    success = true;

  cleanup:
    if (! success) {
        for (i = 0; i < count; ++i) {
            VIR_FREE(names[i]);
        }
    }

    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return success ? count : -1;
}



static virStoragePoolPtr
esxStorageBackendISCSIPoolLookupByName(virConnectPtr conn,
                                       const char *name)
{
    esxPrivate *priv = conn->storagePrivateData;
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

    if (target == NULL) {
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
esxStorageBackendISCSIPoolLookupByUUID(virConnectPtr conn,
                                       const unsigned char *uuid)
{
    virStoragePoolPtr pool = NULL;
    esxPrivate *priv = conn->storagePrivateData;
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
    if (hostInternetScsiHba == NULL) {
        /* iSCSI adapter may not be enabled for this host */
        return NULL;
    }

    for (target = hostInternetScsiHba->configuredStaticTarget;
         target != NULL; target = target->_next) {
        md5_buffer(target->iScsiName, strlen(target->iScsiName), md5);

        if (memcmp(uuid, md5, VIR_UUID_STRING_BUFLEN) == 0) {
            break;
        }
    }

    if (target == NULL) {
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
esxStorageBackendISCSIPoolRefresh(virStoragePoolPtr pool,
                                  unsigned int flags)
{
    int result = -1;
    esxPrivate *priv = pool->conn->storagePrivateData;
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
esxStorageBackendISCSIPoolGetInfo(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                                  virStoragePoolInfoPtr info)
{
    /* These fields are not valid for iSCSI pool */
    info->allocation = info->capacity = info->available = 0;
    info->state = VIR_STORAGE_POOL_RUNNING;

    return 0;
}



static char *
esxStorageBackendISCSIPoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_HostInternetScsiHba *hostInternetScsiHba = NULL;
    esxVI_HostInternetScsiHbaStaticTarget *target;
    virStoragePoolDef def;

    virCheckFlags(0, NULL);

    memset(&def, 0, sizeof(def));

    if (esxVI_LookupHostInternetScsiHba(priv->primary, &hostInternetScsiHba)) {
        goto cleanup;
    }

    for (target = hostInternetScsiHba->configuredStaticTarget;
         target != NULL; target = target->_next) {
        if (STREQ(target->iScsiName, pool->name)) {
            break;
        }
    }

    if (target == NULL) {
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

    if (VIR_ALLOC_N(def.source.hosts, def.source.nhost) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    def.source.hosts[0].name = target->address;

    if (target->port != NULL) {
        def.source.hosts[0].port = target->port->value;
    }

    /* TODO: add CHAP authentication params */
    xml = virStoragePoolDefFormat(&def);

  cleanup:
    VIR_FREE(def.source.hosts);
    esxVI_HostInternetScsiHba_Free(&hostInternetScsiHba);

    return xml;
}



static int
esxStorageBackendISCSIPoolNumberOfVolumes(virStoragePoolPtr pool)
{
    int count = 0;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLunList = NULL;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLun;

    if (esxVI_LookupHostScsiTopologyLunListByTargetName
          (priv->primary, pool->name, &hostScsiTopologyLunList) < 0) {
        return -1;
    }

    for (hostScsiTopologyLun = hostScsiTopologyLunList;
         hostScsiTopologyLun != NULL;
         hostScsiTopologyLun = hostScsiTopologyLun->_next) {
        ++count;
    }

    esxVI_HostScsiTopologyLun_Free(&hostScsiTopologyLunList);

    return count;
}



static int
esxStorageBackendISCSIPoolListVolumes(virStoragePoolPtr pool, char **const names,
                                      int maxnames)
{
    bool success = false;
    int count = 0;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLunList = NULL;
    esxVI_HostScsiTopologyLun *hostScsiTopologyLun;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun = NULL;
    int i;

    if (esxVI_LookupHostScsiTopologyLunListByTargetName
          (priv->primary, pool->name, &hostScsiTopologyLunList) < 0) {
        goto cleanup;
    }

    if (hostScsiTopologyLunList == NULL) {
        /* iSCSI adapter may not be enabled on ESX host */
        return 0;
    }

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0) {
        goto cleanup;
    }

    for (scsiLun = scsiLunList; scsiLun != NULL && count < maxnames;
         scsiLun = scsiLun->_next) {
        for (hostScsiTopologyLun = hostScsiTopologyLunList;
             hostScsiTopologyLun != NULL && count < maxnames;
             hostScsiTopologyLun = hostScsiTopologyLun->_next) {
            if (STREQ(hostScsiTopologyLun->scsiLun, scsiLun->key)) {
                names[count] = strdup(scsiLun->deviceName);

                if (names[count] == NULL) {
                    virReportOOMError();
                    goto cleanup;
                }

                ++count;
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

    esxVI_HostScsiTopologyLun_Free(&hostScsiTopologyLunList);
    esxVI_ScsiLun_Free(&scsiLunList);

    return count;
}



static virStorageVolPtr
esxStorageBackendISCSIVolumeLookupByName(virStoragePoolPtr pool,
                                         const char *name)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = pool->conn->storagePrivateData;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0) {
        goto cleanup;
    }

    for (scsiLun = scsiLunList; scsiLun != NULL;
         scsiLun = scsiLun->_next) {
        if (STREQ(scsiLun->deviceName, name)) {
            /*
             * ScsiLun provides an UUID field that is unique accross
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
esxStorageBackendISCSIVolumeLookupByPath(virConnectPtr conn, const char *path)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = conn->storagePrivateData;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    esxVI_HostScsiDisk *hostScsiDisk = NULL;
    char *poolName = NULL;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0) {
        goto cleanup;
    }

    for (scsiLun = scsiLunList; scsiLun != NULL; scsiLun = scsiLun->_next) {
        hostScsiDisk = esxVI_HostScsiDisk_DynamicCast(scsiLun);

        if (hostScsiDisk != NULL && STREQ(hostScsiDisk->devicePath, path)) {
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
esxStorageBackendISCSIVolumeLookupByKey(virConnectPtr conn, const char *key)
{
    virStorageVolPtr volume = NULL;
    esxPrivate *priv = conn->storagePrivateData;
    char *poolName = NULL;
    esxVI_ScsiLun *scsiLunList = NULL;
    esxVI_ScsiLun *scsiLun;
    /* MD5_DIGEST_SIZE = VIR_UUID_BUFLEN = 16 */
    unsigned char md5[MD5_DIGEST_SIZE];
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    /* key may be LUN device path */
    if (STRPREFIX(key, "/")) {
        return esxStorageBackendISCSIVolumeLookupByPath(conn, key);
    }

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0) {
        goto cleanup;
    }

    for (scsiLun = scsiLunList; scsiLun != NULL;
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
esxStorageBackendISCSIVolumeCreateXML(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                                      const char *xmldesc ATTRIBUTE_UNUSED,
                                      unsigned int flags)
{
    virCheckFlags(0, NULL);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume creation"));

    return NULL;
}



static virStorageVolPtr
esxStorageBackendISCSIVolumeCreateXMLFrom(virStoragePoolPtr pool ATTRIBUTE_UNUSED,
                                          const char *xmldesc ATTRIBUTE_UNUSED,
                                          virStorageVolPtr sourceVolume ATTRIBUTE_UNUSED,
                                          unsigned int flags)
{
    virCheckFlags(0, NULL);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume creation"));

    return NULL;
}



static char *
esxStorageBackendISCSIVolumeGetXMLDesc(virStorageVolPtr volume,
                                       unsigned int flags)
{
    char *xml = NULL;
    esxPrivate *priv = volume->conn->storagePrivateData;
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

    if (esxVI_LookupScsiLunList(priv->primary, &scsiLunList) < 0) {
        goto cleanup;
    }

    for (scsiLun = scsiLunList; scsiLun != NULL;
         scsiLun = scsiLun->_next) {
        hostScsiDisk = esxVI_HostScsiDisk_DynamicCast(scsiLun);

        if (hostScsiDisk != NULL &&
            STREQ(hostScsiDisk->deviceName, volume->name)) {
            break;
        }
    }

    if (hostScsiDisk == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Could find volume with name: %s"), volume->name);
        goto cleanup;
    }

    pool.type = VIR_STORAGE_POOL_ISCSI;

    def.name = volume->name;

    md5_buffer(scsiLun->uuid, strlen(hostScsiDisk->uuid), md5);

    virUUIDFormat(md5, uuid_string);

    if (esxVI_String_DeepCopyValue(&def.key, uuid_string) < 0) {
        goto cleanup;
    }

    /* iSCSI LUN exposes a block device */
    def.type = VIR_STORAGE_VOL_BLOCK;

    def.target.path = hostScsiDisk->devicePath;

    def.capacity = hostScsiDisk->capacity->block->value *
                   hostScsiDisk->capacity->blockSize->value;

    def.allocation = def.capacity;

    /* iSCSI LUN(s) hosting a datastore will be auto-mounted by ESX host */
    def.target.format = VIR_STORAGE_FILE_RAW;

    xml = virStorageVolDefFormat(&pool, &def);

  cleanup:
    esxVI_ScsiLun_Free(&scsiLunList);
    VIR_FREE(def.key);

    return xml;
}



static int
esxStorageBackendISCSIVolumeDelete(virStorageVolPtr volume ATTRIBUTE_UNUSED,
                                   unsigned int flags)
{
    virCheckFlags(0, -1);

    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume deletion"));

    return -1;
}



static int
esxStorageBackendISCSIVolumeWipe(virStorageVolPtr volume ATTRIBUTE_UNUSED,
                                 unsigned int flags)
{
    virCheckFlags(0, -1);


    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("iSCSI storage pool does not support volume wiping"));

    return -1;
}



static char *
esxStorageBackendISCSIVolumeGetPath(virStorageVolPtr volume)
{
    char *path = strdup(volume->name);

    if (path == NULL) {
        virReportOOMError();
        return NULL;
    }

    return path;
}



virStorageDriver esxStorageBackendISCSI = {
    .numOfPools = esxStorageBackendISCSINumberOfPools, /* 1.0.1 */
    .listPools = esxStorageBackendISCSIListPools, /* 1.0.1 */
    .poolLookupByName = esxStorageBackendISCSIPoolLookupByName, /* 1.0.1 */
    .poolLookupByUUID = esxStorageBackendISCSIPoolLookupByUUID, /* 1.0.1 */
    .poolRefresh = esxStorageBackendISCSIPoolRefresh, /* 1.0.1 */
    .poolGetInfo = esxStorageBackendISCSIPoolGetInfo, /* 1.0.1 */
    .poolGetXMLDesc = esxStorageBackendISCSIPoolGetXMLDesc, /* 1.0.1 */
    .poolNumOfVolumes = esxStorageBackendISCSIPoolNumberOfVolumes, /* 1.0.1 */
    .poolListVolumes = esxStorageBackendISCSIPoolListVolumes, /* 1.0.1 */
    .volLookupByName = esxStorageBackendISCSIVolumeLookupByName, /* 1.0.1 */
    .volLookupByPath = esxStorageBackendISCSIVolumeLookupByPath, /* 1.0.1 */
    .volLookupByKey = esxStorageBackendISCSIVolumeLookupByKey, /* 1.0.1 */
    .volCreateXML = esxStorageBackendISCSIVolumeCreateXML, /* 1.0.1 */
    .volCreateXMLFrom = esxStorageBackendISCSIVolumeCreateXMLFrom, /* 1.0.1 */
    .volGetXMLDesc = esxStorageBackendISCSIVolumeGetXMLDesc, /* 1.0.1 */
    .volDelete = esxStorageBackendISCSIVolumeDelete, /* 1.0.1 */
    .volWipe = esxStorageBackendISCSIVolumeWipe, /* 1.0.1 */
    .volGetPath = esxStorageBackendISCSIVolumeGetPath, /* 1.0.1 */
};
