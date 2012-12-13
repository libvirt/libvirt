
/*
 * esx_storage_driver.c: storage driver functions for managing VMware ESX
 *                       host storage
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "viruuid.h"
#include "viralloc.h"
#include "storage_conf.h"
#include "esx_private.h"
#include "esx_storage_driver.h"
#include "esx_storage_backend_vmfs.h"
#include "esx_storage_backend_iscsi.h"

#define VIR_FROM_THIS VIR_FROM_ESX

/*
 * ESX storage driver implements a facade pattern;
 * the driver exposes the routines supported by libvirt
 * public interface to manage ESX storage devices. Internally
 * it uses backend drivers to perform the required task.
 */
enum {
    VMFS = 0,
    ISCSI,
    LAST_BACKEND
};

static virStorageDriverPtr backends[] = {
    &esxStorageBackendVMFS,
    &esxStorageBackendISCSI
};



static virDrvOpenStatus
esxStorageOpen(virConnectPtr conn,
               virConnectAuthPtr auth ATTRIBUTE_UNUSED,
               unsigned int flags)
{
    virCheckFlags(VIR_CONNECT_RO, VIR_DRV_OPEN_ERROR);

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
    int i;
    int tmp;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    for (i = 0; i < LAST_BACKEND; ++i) {
        tmp = backends[i]->numOfPools(conn);

        if (tmp < 0) {
            return -1;
        }

        count += tmp;
    }

    return count;
}



static int
esxListStoragePools(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->storagePrivateData;
    int count = 0;
    int i;
    int tmp;

    if (maxnames == 0) {
        return 0;
    }

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    for (i = 0; i < LAST_BACKEND; ++i) {
        tmp = backends[i]->listPools(conn, &names[count], maxnames - count);

        if (tmp < 0) {
            goto cleanup;
        }

        count += tmp;
    }

    success = true;

  cleanup:
    if (! success) {
        for (i = 0; i < count; ++i) {
            VIR_FREE(names[i]);
        }

        count = -1;
    }

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
    int i;
    virStoragePoolPtr pool;

    virCheckNonNullArgReturn(name, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    for (i = 0; i < LAST_BACKEND; ++i) {
        pool = backends[i]->poolLookupByName(conn, name);

        if (pool != NULL) {
            return pool;
        }
    }

    virReportError(VIR_ERR_NO_STORAGE_POOL,
                   _("Could not find storage pool with name '%s'"), name);

    return NULL;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    esxPrivate *priv = conn->storagePrivateData;
    int i;
    virStoragePoolPtr pool;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    /* invoke backend drive method to search all known pools */
    for (i = 0; i < LAST_BACKEND; ++i) {
        pool = backends[i]->poolLookupByUUID(conn, uuid);

        if (pool != NULL) {
            return pool;
        }
    }

    virUUIDFormat(uuid, uuid_string);
    virReportError(VIR_ERR_NO_STORAGE_POOL,
                   _("Could not find storage pool with uuid '%s'"),
                   uuid_string);

    return NULL;
}



static virStoragePoolPtr
esxStoragePoolLookupByVolume(virStorageVolPtr volume)
{
    return esxStoragePoolLookupByName(volume->conn, volume->pool);
}



static int
esxStoragePoolRefresh(virStoragePoolPtr pool, unsigned int flags)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->poolRefresh(pool, flags);
}



static int
esxStoragePoolGetInfo(virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    memset(info, 0, sizeof(*info));

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->poolGetInfo(pool, info);
}



static char *
esxStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->poolGetXMLDesc(pool, flags);
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
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot deactivate storage pool autostart"));
        return -1;
    }

    return 0;
}



static int
esxStoragePoolNumberOfStorageVolumes(virStoragePoolPtr pool)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->poolNumOfVolumes(pool);
}



static int
esxStoragePoolListStorageVolumes(virStoragePoolPtr pool, char **const names,
                                 int maxnames)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->poolListVolumes(pool, names, maxnames);
}



static virStorageVolPtr
esxStorageVolumeLookupByName(virStoragePoolPtr pool, const char *name)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->volLookupByName(pool, name);
}



static virStorageVolPtr
esxStorageVolumeLookupByPath(virConnectPtr conn, const char *path)
{
    esxPrivate *priv = conn->storagePrivateData;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    /*
     * FIXME: calling backends blindly may set unwanted error codes
     *
     * VMFS Datastore path follows cannonical format i.e.:
     * [<datastore_name>] <file_path>
     *          WHEREAS
     * iSCSI LUNs device path follows normal linux path convention
     */
    if (STRPREFIX(path, "[")) {
        return backends[VMFS]->volLookupByPath(conn, path);
    } else if (STRPREFIX(path, "/")) {
        return backends[ISCSI]->volLookupByPath(conn, path);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unexpected volume path format: %s"), path);

        return NULL;
    }
}



static virStorageVolPtr
esxStorageVolumeLookupByKey(virConnectPtr conn, const char *key)
{
    virStorageVolPtr volume;
    esxPrivate *priv = conn->storagePrivateData;
    int i;

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    for (i = 0; i < LAST_BACKEND; ++i) {
        volume = backends[i]->volLookupByKey(conn, key);

        if (volume != NULL) {
            return volume;
        }
    }

    virReportError(VIR_ERR_NO_STORAGE_VOL,
                   _("Could not find storage volume with key '%s'"),
                   key);

    return NULL;
}



static virStorageVolPtr
esxStorageVolumeCreateXML(virStoragePoolPtr pool, const char *xmldesc,
                          unsigned int flags)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->volCreateXML(pool, xmldesc, flags);
}



static virStorageVolPtr
esxStorageVolumeCreateXMLFrom(virStoragePoolPtr pool, const char *xmldesc,
                              virStorageVolPtr sourceVolume, unsigned int flags)
{
    esxPrivate *priv = pool->conn->storagePrivateData;
    virStorageDriverPtr backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->volCreateXMLFrom(pool, xmldesc, sourceVolume, flags);
}



static int
esxStorageVolumeDelete(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->storagePrivateData;
    virStorageDriverPtr backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->volDelete(volume, flags);
}



static int
esxStorageVolumeWipe(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->storagePrivateData;
    virStorageDriverPtr backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->volWipe(volume, flags);
}



static int
esxStorageVolumeGetInfo(virStorageVolPtr volume, virStorageVolInfoPtr info)
{
    esxPrivate *priv = volume->conn->storagePrivateData;
    virStorageDriverPtr backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return -1;
    }

    return backend->volGetInfo(volume, info);
}



static char *
esxStorageVolumeGetXMLDesc(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->storagePrivateData;
    virStorageDriverPtr backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->volGetXMLDesc(volume, flags);
}



static char *
esxStorageVolumeGetPath(virStorageVolPtr volume)
{
    esxPrivate *priv = volume->conn->storagePrivateData;
    virStorageDriverPtr backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0) {
        return NULL;
    }

    return backend->volGetPath(volume);
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
    .name = "ESX",
    .open = esxStorageOpen, /* 0.7.6 */
    .close = esxStorageClose, /* 0.7.6 */
    .numOfPools = esxNumberOfStoragePools, /* 0.8.2 */
    .listPools = esxListStoragePools, /* 0.8.2 */
    .numOfDefinedPools = esxNumberOfDefinedStoragePools, /* 0.8.2 */
    .listDefinedPools = esxListDefinedStoragePools, /* 0.8.2 */
    .poolLookupByName = esxStoragePoolLookupByName, /* 0.8.2 */
    .poolLookupByUUID = esxStoragePoolLookupByUUID, /* 0.8.2 */
    .poolLookupByVolume = esxStoragePoolLookupByVolume, /* 0.8.4 */
    .poolRefresh = esxStoragePoolRefresh, /* 0.8.2 */
    .poolGetInfo = esxStoragePoolGetInfo, /* 0.8.2 */
    .poolGetXMLDesc = esxStoragePoolGetXMLDesc, /* 0.8.2 */
    .poolGetAutostart = esxStoragePoolGetAutostart, /* 0.8.2 */
    .poolSetAutostart = esxStoragePoolSetAutostart, /* 0.8.2 */
    .poolNumOfVolumes = esxStoragePoolNumberOfStorageVolumes, /* 0.8.4 */
    .poolListVolumes = esxStoragePoolListStorageVolumes, /* 0.8.4 */
    .volLookupByName = esxStorageVolumeLookupByName, /* 0.8.4 */
    .volLookupByPath = esxStorageVolumeLookupByPath, /* 0.8.4 */
    .volLookupByKey = esxStorageVolumeLookupByKey, /* 0.8.4 */
    .volCreateXML = esxStorageVolumeCreateXML, /* 0.8.4 */
    .volCreateXMLFrom = esxStorageVolumeCreateXMLFrom, /* 0.8.7 */
    .volDelete = esxStorageVolumeDelete, /* 0.8.7 */
    .volWipe = esxStorageVolumeWipe, /* 0.8.7 */
    .volGetInfo = esxStorageVolumeGetInfo, /* 0.8.4 */
    .volGetXMLDesc = esxStorageVolumeGetXMLDesc, /* 0.8.4 */
    .volGetPath = esxStorageVolumeGetPath, /* 0.8.4 */
    .poolIsActive = esxStoragePoolIsActive, /* 0.8.2 */
    .poolIsPersistent = esxStoragePoolIsPersistent, /* 0.8.2 */
};



int
esxStorageRegister(void)
{
    return virRegisterStorageDriver(&esxStorageDriver);
}
