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
#include "esx_private.h"
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

static virStorageDriver *backends[] = {
    &esxStorageBackendVMFS,
    &esxStorageBackendISCSI
};


static int
esxConnectNumOfStoragePools(virConnectPtr conn)
{
    int count = 0;
    esxPrivate *priv = conn->privateData;
    size_t i;
    int tmp;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    for (i = 0; i < LAST_BACKEND; ++i) {
        tmp = backends[i]->connectNumOfStoragePools(conn);

        if (tmp < 0)
            return -1;

        count += tmp;
    }

    return count;
}



static int
esxConnectListStoragePools(virConnectPtr conn, char **const names, int maxnames)
{
    bool success = false;
    esxPrivate *priv = conn->privateData;
    int count = 0;
    size_t i;
    int tmp;

    if (maxnames == 0)
        return 0;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    for (i = 0; i < LAST_BACKEND; ++i) {
        tmp = backends[i]->connectListStoragePools(conn, &names[count], maxnames - count);

        if (tmp < 0)
            goto cleanup;

        count += tmp;
    }

    success = true;

 cleanup:
    if (! success) {
        for (i = 0; i < count; ++i)
            VIR_FREE(names[i]);

        count = -1;
    }

    return count;
}



static int
esxConnectNumOfDefinedStoragePools(virConnectPtr conn G_GNUC_UNUSED)
{
    /* ESX storage pools are always active */
    return 0;
}



static int
esxConnectListDefinedStoragePools(virConnectPtr conn G_GNUC_UNUSED,
                                  char **const names G_GNUC_UNUSED,
                                  int maxnames G_GNUC_UNUSED)
{
    /* ESX storage pools are always active */
    return 0;
}



static virStoragePoolPtr
esxStoragePoolLookupByName(virConnectPtr conn, const char *name)
{
    esxPrivate *priv = conn->privateData;
    size_t i;
    virStoragePoolPtr pool;

    virCheckNonNullArgReturn(name, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    for (i = 0; i < LAST_BACKEND; ++i) {
        pool = backends[i]->storagePoolLookupByName(conn, name);

        if (pool)
            return pool;
    }

    virReportError(VIR_ERR_NO_STORAGE_POOL,
                   _("Could not find storage pool with name '%1$s'"), name);

    return NULL;
}



static virStoragePoolPtr
esxStoragePoolLookupByUUID(virConnectPtr conn, const unsigned char *uuid)
{
    esxPrivate *priv = conn->privateData;
    size_t i;
    virStoragePoolPtr pool;
    char uuid_string[VIR_UUID_STRING_BUFLEN] = "";

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    /* invoke backend drive method to search all known pools */
    for (i = 0; i < LAST_BACKEND; ++i) {
        pool = backends[i]->storagePoolLookupByUUID(conn, uuid);

        if (pool)
            return pool;
    }

    virUUIDFormat(uuid, uuid_string);
    virReportError(VIR_ERR_NO_STORAGE_POOL,
                   _("Could not find storage pool with uuid '%1$s'"),
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
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storagePoolRefresh(pool, flags);
}



static int
esxStoragePoolGetInfo(virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    memset(info, 0, sizeof(*info));

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storagePoolGetInfo(pool, info);
}



static char *
esxStoragePoolGetXMLDesc(virStoragePoolPtr pool, unsigned int flags)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storagePoolGetXMLDesc(pool, flags);
}



static int
esxStoragePoolGetAutostart(virStoragePoolPtr pool G_GNUC_UNUSED,
                           int *autostart)
{
    /* ESX storage pools are always active */
    *autostart = 1;

    return 0;
}



static int
esxStoragePoolSetAutostart(virStoragePoolPtr pool G_GNUC_UNUSED,
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
esxStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storagePoolNumOfVolumes(pool);
}



static int
esxStoragePoolListVolumes(virStoragePoolPtr pool, char **const names,
                          int maxnames)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storagePoolListVolumes(pool, names, maxnames);
}



static virStorageVolPtr
esxStorageVolLookupByName(virStoragePoolPtr pool, const char *name)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storageVolLookupByName(pool, name);
}



static virStorageVolPtr
esxStorageVolLookupByPath(virConnectPtr conn, const char *path)
{
    esxPrivate *priv = conn->privateData;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    /*
     * FIXME: calling backends blindly may set unwanted error codes
     *
     * VMFS Datastore path follows canonical format i.e.:
     * [<datastore_name>] <file_path>
     *          WHEREAS
     * iSCSI LUNs device path follows normal linux path convention
     */
    if (STRPREFIX(path, "[")) {
        return backends[VMFS]->storageVolLookupByPath(conn, path);
    } else if (STRPREFIX(path, "/")) {
        return backends[ISCSI]->storageVolLookupByPath(conn, path);
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Unexpected volume path format: %1$s"), path);

        return NULL;
    }
}



static virStorageVolPtr
esxStorageVolLookupByKey(virConnectPtr conn, const char *key)
{
    virStorageVolPtr volume;
    esxPrivate *priv = conn->privateData;
    size_t i;

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    for (i = 0; i < LAST_BACKEND; ++i) {
        volume = backends[i]->storageVolLookupByKey(conn, key);

        if (volume)
            return volume;
    }

    virReportError(VIR_ERR_NO_STORAGE_VOL,
                   _("Could not find storage volume with key '%1$s'"),
                   key);

    return NULL;
}



static virStorageVolPtr
esxStorageVolCreateXML(virStoragePoolPtr pool, const char *xmldesc,
                       unsigned int flags)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storageVolCreateXML(pool, xmldesc, flags);
}



static virStorageVolPtr
esxStorageVolCreateXMLFrom(virStoragePoolPtr pool, const char *xmldesc,
                           virStorageVolPtr sourceVolume, unsigned int flags)
{
    esxPrivate *priv = pool->conn->privateData;
    virStorageDriver *backend = pool->privateData;

    virCheckNonNullArgReturn(pool->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storageVolCreateXMLFrom(pool, xmldesc, sourceVolume, flags);
}



static int
esxStorageVolDelete(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->privateData;
    virStorageDriver *backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storageVolDelete(volume, flags);
}



static int
esxStorageVolWipe(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->privateData;
    virStorageDriver *backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storageVolWipe(volume, flags);
}



static int
esxStorageVolGetInfo(virStorageVolPtr volume, virStorageVolInfoPtr info)
{
    esxPrivate *priv = volume->conn->privateData;
    virStorageDriver *backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, -1);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return -1;

    return backend->storageVolGetInfo(volume, info);
}



static char *
esxStorageVolGetXMLDesc(virStorageVolPtr volume, unsigned int flags)
{
    esxPrivate *priv = volume->conn->privateData;
    virStorageDriver *backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storageVolGetXMLDesc(volume, flags);
}



static char *
esxStorageVolGetPath(virStorageVolPtr volume)
{
    esxPrivate *priv = volume->conn->privateData;
    virStorageDriver *backend = volume->privateData;

    virCheckNonNullArgReturn(volume->privateData, NULL);

    if (esxVI_EnsureSession(priv->primary) < 0)
        return NULL;

    return backend->storageVolGetPath(volume);
}



static int
esxStoragePoolIsActive(virStoragePoolPtr pool G_GNUC_UNUSED)
{
    /* ESX storage pools are always active */
    return 1;
}



static int
esxStoragePoolIsPersistent(virStoragePoolPtr pool G_GNUC_UNUSED)
{
    /* ESX has no concept of transient pools, so all of them are persistent */
    return 1;
}



virStorageDriver esxStorageDriver = {
    .connectNumOfStoragePools = esxConnectNumOfStoragePools, /* 0.8.2 */
    .connectListStoragePools = esxConnectListStoragePools, /* 0.8.2 */
    .connectNumOfDefinedStoragePools = esxConnectNumOfDefinedStoragePools, /* 0.8.2 */
    .connectListDefinedStoragePools = esxConnectListDefinedStoragePools, /* 0.8.2 */
    .storagePoolLookupByName = esxStoragePoolLookupByName, /* 0.8.2 */
    .storagePoolLookupByUUID = esxStoragePoolLookupByUUID, /* 0.8.2 */
    .storagePoolLookupByVolume = esxStoragePoolLookupByVolume, /* 0.8.4 */
    .storagePoolRefresh = esxStoragePoolRefresh, /* 0.8.2 */
    .storagePoolGetInfo = esxStoragePoolGetInfo, /* 0.8.2 */
    .storagePoolGetXMLDesc = esxStoragePoolGetXMLDesc, /* 0.8.2 */
    .storagePoolGetAutostart = esxStoragePoolGetAutostart, /* 0.8.2 */
    .storagePoolSetAutostart = esxStoragePoolSetAutostart, /* 0.8.2 */
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
    .storagePoolIsActive = esxStoragePoolIsActive, /* 0.8.2 */
    .storagePoolIsPersistent = esxStoragePoolIsPersistent, /* 0.8.2 */
};
