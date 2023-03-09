/*
 * libvirt-storage.c: entry points for virStorage{Pool,Vol}Ptr APIs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#include "datatypes.h"
#include "virlog.h"

VIR_LOG_INIT("libvirt.storage");

#define VIR_FROM_THIS VIR_FROM_STORAGE


/**
 * virStoragePoolGetConnect:
 * @pool: pointer to a pool
 *
 * Provides the connection pointer associated with a storage pool.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 *
 * Since: 0.4.1
 */
virConnectPtr
virStoragePoolGetConnect(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);

    return pool->conn;
}


/**
 * virConnectListAllStoragePools:
 * @conn: Pointer to the hypervisor connection.
 * @pools: Pointer to a variable to store the array containing storage pool
 *         objects or NULL if the list is not required (just returns number
 *         of pools).
 * @flags: bitwise-OR of virConnectListAllStoragePoolsFlags.
 *
 * Collect the list of storage pools, and allocate an array to store those
 * objects. This API solves the race inherent between
 * virConnectListStoragePools and virConnectListDefinedStoragePools.
 *
 * Normally, all storage pools are returned; however, @flags can be used to
 * filter the results for a smaller list of targeted pools.  The valid
 * flags are divided into groups, where each group contains bits that
 * describe mutually exclusive attributes of a pool, and where all bits
 * within a group describe all possible pools.
 *
 * The first group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_ACTIVE (online)
 * and VIR_CONNECT_LIST_STORAGE_POOLS_INACTIVE (offline) to filter the pools
 * by state.
 *
 * The second group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_PERSITENT
 * (defined) and VIR_CONNECT_LIST_STORAGE_POOLS_TRANSIENT (running but not
 * defined), to filter the pools by whether they have persistent config or not.
 *
 * The third group of @flags is VIR_CONNECT_LIST_STORAGE_POOLS_AUTOSTART
 * and VIR_CONNECT_LIST_STORAGE_POOLS_NO_AUTOSTART, to filter the pools by
 * whether they are marked as autostart or not.
 *
 * The last group of @flags is provided to filter the pools by the types,
 * the flags include:
 * VIR_CONNECT_LIST_STORAGE_POOLS_DIR
 * VIR_CONNECT_LIST_STORAGE_POOLS_FS
 * VIR_CONNECT_LIST_STORAGE_POOLS_NETFS
 * VIR_CONNECT_LIST_STORAGE_POOLS_LOGICAL
 * VIR_CONNECT_LIST_STORAGE_POOLS_DISK
 * VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI
 * VIR_CONNECT_LIST_STORAGE_POOLS_SCSI
 * VIR_CONNECT_LIST_STORAGE_POOLS_MPATH
 * VIR_CONNECT_LIST_STORAGE_POOLS_RBD
 * VIR_CONNECT_LIST_STORAGE_POOLS_SHEEPDOG
 * VIR_CONNECT_LIST_STORAGE_POOLS_GLUSTER
 * VIR_CONNECT_LIST_STORAGE_POOLS_ZFS
 * VIR_CONNECT_LIST_STORAGE_POOLS_VSTORAGE
 * VIR_CONNECT_LIST_STORAGE_POOLS_ISCSI_DIRECT
 *
 * Returns the number of storage pools found or -1 and sets @pools to
 * NULL in case of error.  On success, the array stored into @pools is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virStoragePoolFree() on each array element, then calling
 * free() on @pools.
 *
 * Since: 0.10.2
 */
int
virConnectListAllStoragePools(virConnectPtr conn,
                              virStoragePoolPtr **pools,
                              unsigned int flags)
{
    VIR_DEBUG("conn=%p, pools=%p, flags=0x%x", conn, pools, flags);

    virResetLastError();

    if (pools)
        *pools = NULL;

    virCheckConnectReturn(conn, -1);

    if (conn->storageDriver &&
        conn->storageDriver->connectListAllStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListAllStoragePools(conn, pools, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectNumOfStoragePools:
 * @conn: pointer to hypervisor connection
 *
 * Provides the number of active storage pools
 *
 * Returns the number of pools found, or -1 on error
 *
 * Since: 0.4.1
 */
int
virConnectNumOfStoragePools(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->storageDriver && conn->storageDriver->connectNumOfStoragePools) {
        int ret;
        ret = conn->storageDriver->connectNumOfStoragePools(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectListStoragePools:
 * @conn: pointer to hypervisor connection
 * @names: array of char * to fill with pool names (allocated by caller)
 * @maxnames: size of the names array
 *
 * Provides the list of names of active storage pools up to maxnames.
 * If there are more than maxnames, the remaining names will be silently
 * ignored.
 *
 * The use of this function is discouraged. Instead, use
 * virConnectListAllStoragePools().
 *
 * Returns the number of pools found or -1 in case of error.  Note that
 * this command is inherently racy; a pool can be started between a call to
 * virConnectNumOfStoragePools() and this call; you are only guaranteed
 * that all currently active pools were listed if the return is less than
 * @maxnames. The client must call free() on each returned name.
 *
 * Since: 0.4.1
 */
int
virConnectListStoragePools(virConnectPtr conn,
                           char **const names,
                           int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->storageDriver && conn->storageDriver->connectListStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListStoragePools(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectNumOfDefinedStoragePools:
 * @conn: pointer to hypervisor connection
 *
 * Provides the number of inactive storage pools
 *
 * Returns the number of pools found, or -1 on error
 *
 * Since: 0.4.1
 */
int
virConnectNumOfDefinedStoragePools(virConnectPtr conn)
{
    VIR_DEBUG("conn=%p", conn);

    virResetLastError();

    virCheckConnectReturn(conn, -1);

    if (conn->storageDriver && conn->storageDriver->connectNumOfDefinedStoragePools) {
        int ret;
        ret = conn->storageDriver->connectNumOfDefinedStoragePools(conn);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectListDefinedStoragePools:
 * @conn: pointer to hypervisor connection
 * @names: array of char * to fill with pool names (allocated by caller)
 * @maxnames: size of the names array
 *
 * Provides the list of names of inactive storage pools up to maxnames.
 * If there are more than maxnames, the remaining names will be silently
 * ignored.
 *
 * The use of this function is discouraged. Instead, use
 * virConnectListAllStoragePools().
 *
 * Returns the number of names provided in the array or -1 in case of error.
 * Note that this command is inherently racy; a pool can be defined between
 * a call to virConnectNumOfDefinedStoragePools() and this call; you are only
 * guaranteed that all currently defined pools were listed if the return
 * is less than @maxnames.  The client must call free() on each returned name.
 *
 * Since: 0.4.1
 */
int
virConnectListDefinedStoragePools(virConnectPtr conn,
                                  char **const names,
                                  int maxnames)
{
    VIR_DEBUG("conn=%p, names=%p, maxnames=%d", conn, names, maxnames);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (conn->storageDriver && conn->storageDriver->connectListDefinedStoragePools) {
        int ret;
        ret = conn->storageDriver->connectListDefinedStoragePools(conn, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectFindStoragePoolSources:
 * @conn: pointer to hypervisor connection
 * @type: type of storage pool sources to discover
 * @srcSpec: XML document specifying discovery source
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Talks to a storage backend and attempts to auto-discover the set of
 * available storage pool sources. e.g. For iSCSI this would be a set of
 * iSCSI targets. For NFS this would be a list of exported paths.  The
 * srcSpec (optional for some storage pool types, e.g. local ones) is
 * an instance of the storage pool's source element specifying where
 * to look for the pools.
 *
 * srcSpec is not required for some types (e.g., those querying
 * local storage resources only)
 *
 * Returns an xml document consisting of a SourceList element
 * containing a source document appropriate to the given pool
 * type for each discovered source.
 *
 * Since: 0.4.5
 */
char *
virConnectFindStoragePoolSources(virConnectPtr conn,
                                 const char *type,
                                 const char *srcSpec,
                                 unsigned int flags)
{
    VIR_DEBUG("conn=%p, type=%s, src=%s, flags=0x%x",
              conn, NULLSTR(type), NULLSTR(srcSpec), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(type, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->connectFindStoragePoolSources) {
        char *ret;
        ret = conn->storageDriver->connectFindStoragePoolSources(conn, type, srcSpec, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByName:
 * @conn: pointer to hypervisor connection
 * @name: name of pool to fetch
 *
 * Fetch a storage pool based on its unique name
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolLookupByName(virConnectPtr conn,
                           const char *name)
{
    VIR_DEBUG("conn=%p, name=%s", conn, NULLSTR(name));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(name, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolLookupByName) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolLookupByName(conn, name);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByUUID:
 * @conn: pointer to hypervisor connection
 * @uuid: globally unique id of pool to fetch
 *
 * Fetch a storage pool based on its globally unique id
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolLookupByUUID(virConnectPtr conn,
                           const unsigned char *uuid)
{
    VIR_UUID_DEBUG(conn, uuid);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuid, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolLookupByUUID) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolLookupByUUID(conn, uuid);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByUUIDString:
 * @conn: pointer to hypervisor connection
 * @uuidstr: globally unique id of pool to fetch
 *
 * Fetch a storage pool based on its globally unique id
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolLookupByUUIDString(virConnectPtr conn,
                                 const char *uuidstr)
{
    unsigned char uuid[VIR_UUID_BUFLEN];
    VIR_DEBUG("conn=%p, uuidstr=%s", conn, NULLSTR(uuidstr));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(uuidstr, error);

    if (virUUIDParse(uuidstr, uuid) < 0) {
        virReportInvalidArg(uuidstr,
                            _("uuidstr in %1$s must be a valid UUID"),
                            __FUNCTION__);
        goto error;
    }

    return virStoragePoolLookupByUUID(conn, uuid);

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolLookupByVolume:
 * @vol: pointer to storage volume
 *
 * Fetch a storage pool which contains a particular volume
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolLookupByVolume(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);

    if (vol->conn->storageDriver && vol->conn->storageDriver->storagePoolLookupByVolume) {
        virStoragePoolPtr ret;
        ret = vol->conn->storageDriver->storagePoolLookupByVolume(vol);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return NULL;
}


/**
 * virStoragePoolLookupByTargetPath:
 * @conn: pointer to hypervisor connection
 * @path: path at which the pool is exposed
 *
 * Fetch a storage pool which maps to a particular target directory.
 * If more than one pool maps to the path, it is undefined which
 * will be returned first.
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if no matching pool is found
 *
 * Since: 4.1.0
 */
virStoragePoolPtr
virStoragePoolLookupByTargetPath(virConnectPtr conn,
                                 const char *path)
{
    VIR_DEBUG("conn=%p, path=%s", conn, NULLSTR(path));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(path, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolLookupByTargetPath) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolLookupByTargetPath(conn, path);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virStoragePoolCreateXML:
 * @conn: pointer to hypervisor connection
 * @xmlDesc: XML description for new pool
 * @flags: bitwise-OR of virStoragePoolCreateFlags
 *
 * Create a new storage based on its XML description. The
 * pool is not persistent, so its definition will disappear
 * when it is destroyed, or if the host is restarted
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if creation failed
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolCreateXML(virConnectPtr conn,
                        const char *xmlDesc,
                        unsigned int flags)
{
    VIR_DEBUG("conn=%p, xmlDesc=%s, flags=0x%x", conn, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolCreateXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolCreateXML(conn, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolDefineXML:
 * @conn: pointer to hypervisor connection
 * @xml: XML description for new pool
 * @flags: bitwise-OR of virStoragePoolDefineFlags
 *
 * Define an inactive persistent storage pool or modify an existing persistent
 * one from the XML description.
 *
 * virStoragePoolFree should be used to free the resources after the
 * storage pool object is no longer needed.
 *
 * Returns a virStoragePoolPtr object, or NULL if creation failed
 *
 * Since: 0.4.1
 */
virStoragePoolPtr
virStoragePoolDefineXML(virConnectPtr conn,
                        const char *xml,
                        unsigned int flags)
{
    VIR_DEBUG("conn=%p, xml=%s, flags=0x%x", conn, NULLSTR(xml), flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckReadOnlyGoto(conn->flags, error);
    virCheckNonNullArgGoto(xml, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolDefineXML) {
        virStoragePoolPtr ret;
        ret = conn->storageDriver->storagePoolDefineXML(conn, xml, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStoragePoolBuild:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStoragePoolBuildFlags
 *
 * Currently only filesystem pool accepts flags VIR_STORAGE_POOL_BUILD_OVERWRITE
 * and VIR_STORAGE_POOL_BUILD_NO_OVERWRITE.
 *
 * Build the underlying storage pool
 *
 * Returns 0 on success, or -1 upon failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolBuild(virStoragePoolPtr pool,
                    unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, flags=0x%x", pool, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolBuild) {
        int ret;
        ret = conn->storageDriver->storagePoolBuild(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolUndefine:
 * @pool: pointer to storage pool
 *
 * Undefine an inactive storage pool
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolUndefine(virStoragePoolPtr pool)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolUndefine) {
        int ret;
        ret = conn->storageDriver->storagePoolUndefine(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolCreate:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStoragePoolCreateFlags
 *
 * Starts an inactive storage pool
 *
 * Returns 0 on success, or -1 if it could not be started
 *
 * Since: 0.4.1
 */
int
virStoragePoolCreate(virStoragePoolPtr pool,
                     unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, flags=0x%x", pool, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolCreate) {
        int ret;
        ret = conn->storageDriver->storagePoolCreate(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolDestroy:
 * @pool: pointer to storage pool
 *
 * Destroy an active storage pool. This will deactivate the
 * pool on the host, but keep any persistent config associated
 * with it. If it has a persistent config it can later be
 * restarted with virStoragePoolCreate(). This does not free
 * the associated virStoragePoolPtr object.
 *
 * Returns 0 on success, or -1 if it could not be destroyed
 *
 * Since: 0.4.1
 */
int
virStoragePoolDestroy(virStoragePoolPtr pool)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolDestroy) {
        int ret;
        ret = conn->storageDriver->storagePoolDestroy(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolDelete:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStoragePoolDeleteFlags
 *
 * Delete the underlying pool resources. This is
 * a non-recoverable operation. The virStoragePoolPtr object
 * itself is not free'd.
 *
 * Returns 0 on success, or -1 if it could not be obliterate
 *
 * Since: 0.4.1
 */
int
virStoragePoolDelete(virStoragePoolPtr pool,
                     unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, flags=0x%x", pool, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolDelete) {
        int ret;
        ret = conn->storageDriver->storagePoolDelete(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolFree:
 * @pool: pointer to storage pool
 *
 * Free a storage pool object, releasing all memory associated with
 * it. Does not change the state of the pool on the host.
 *
 * Returns 0 on success, or -1 if it could not be free'd.
 *
 * Since: 0.4.1
 */
int
virStoragePoolFree(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    virObjectUnref(pool);
    return 0;

}


/**
 * virStoragePoolRef:
 * @pool: the pool to hold a reference on
 *
 * Increment the reference count on the pool. For each
 * additional call to this method, there shall be a corresponding
 * call to virStoragePoolFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a pool would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 0.6.0
 */
int
virStoragePoolRef(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    virObjectRef(pool);
    return 0;
}


/**
 * virStoragePoolRefresh:
 * @pool: pointer to storage pool
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Request that the pool refresh its list of volumes. This may
 * involve communicating with a remote server, and/or initializing
 * new devices at the OS layer
 *
 * Returns 0 if the volume list was refreshed, -1 on failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolRefresh(virStoragePoolPtr pool,
                      unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, flags=0x%x", pool, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolRefresh) {
        int ret;
        ret = conn->storageDriver->storagePoolRefresh(pool, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetName:
 * @pool: pointer to storage pool
 *
 * Fetch the locally unique name of the storage pool
 *
 * Returns the name of the pool, or NULL on error
 *
 * Since: 0.4.1
 */
const char*
virStoragePoolGetName(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);

    return pool->name;
}


/**
 * virStoragePoolGetUUID:
 * @pool: pointer to storage pool
 * @uuid: buffer of VIR_UUID_BUFLEN bytes in size
 *
 * Fetch the globally unique ID of the storage pool
 *
 * Returns 0 on success, or -1 on error;
 *
 * Since: 0.4.1
 */
int
virStoragePoolGetUUID(virStoragePoolPtr pool,
                      unsigned char *uuid)
{
    VIR_DEBUG("pool=%p, uuid=%p", pool, uuid);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    virCheckNonNullArgGoto(uuid, error);

    memcpy(uuid, &pool->uuid[0], VIR_UUID_BUFLEN);

    return 0;

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetUUIDString:
 * @pool: pointer to storage pool
 * @buf: buffer of VIR_UUID_STRING_BUFLEN bytes in size
 *
 * Fetch the globally unique ID of the storage pool as a string
 *
 * Returns 0 on success, or -1 on error;
 *
 * Since: 0.4.1
 */
int
virStoragePoolGetUUIDString(virStoragePoolPtr pool,
                            char *buf)
{
    VIR_DEBUG("pool=%p, buf=%p", pool, buf);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    virCheckNonNullArgGoto(buf, error);

    virUUIDFormat(pool->uuid, buf);
    return 0;

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetInfo:
 * @pool: pointer to storage pool
 * @info: pointer at which to store info
 *
 * Get volatile information about the storage pool
 * such as free space / usage summary
 *
 * Returns 0 on success, or -1 on failure.
 *
 * Since: 0.4.1
 */
int
virStoragePoolGetInfo(virStoragePoolPtr pool,
                      virStoragePoolInfoPtr info)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, info=%p", pool, info);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckStoragePoolReturn(pool, -1);
    virCheckNonNullArgGoto(info, error);

    conn = pool->conn;

    if (conn->storageDriver->storagePoolGetInfo) {
        int ret;
        ret = conn->storageDriver->storagePoolGetInfo(pool, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolGetXMLDesc:
 * @pool: pointer to storage pool
 * @flags: bitwise-OR of virStorageXMLFlags
 *
 * Fetch an XML document describing all aspects of the
 * storage pool. This is suitable for later feeding back
 * into the virStoragePoolCreateXML method.
 *
 * Returns a XML document (caller frees), or NULL on error
 *
 * Since: 0.4.1
 */
char *
virStoragePoolGetXMLDesc(virStoragePoolPtr pool,
                         unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, flags=0x%x", pool, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);
    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->storagePoolGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->storagePoolGetXMLDesc(pool, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStoragePoolGetAutostart:
 * @pool: pointer to storage pool
 * @autostart: location in which to store autostart flag
 *
 * Fetches the value of the autostart flag, which determines
 * whether the pool is automatically started at boot time
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolGetAutostart(virStoragePoolPtr pool,
                           int *autostart)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, autostart=%p", pool, autostart);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    virCheckNonNullArgGoto(autostart, error);

    conn = pool->conn;

    if (conn->storageDriver && conn->storageDriver->storagePoolGetAutostart) {
        int ret;
        ret = conn->storageDriver->storagePoolGetAutostart(pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolSetAutostart:
 * @pool: pointer to storage pool
 * @autostart: whether the storage pool should be automatically started 0 or 1
 *
 * Configure the storage pool to be automatically started
 * when the host machine boots.
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolSetAutostart(virStoragePoolPtr pool,
                           int autostart)
{
    virConnectPtr conn;
    VIR_DEBUG("pool=%p, autostart=%d", pool, autostart);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    conn = pool->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storagePoolSetAutostart) {
        int ret;
        ret = conn->storageDriver->storagePoolSetAutostart(pool, autostart);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolListAllVolumes:
 * @pool: Pointer to storage pool
 * @vols: Pointer to a variable to store the array containing storage volume
 *        objects or NULL if the list is not required (just returns number
 *        of volumes).
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Collect the list of storage volumes, and allocate an array to store those
 * objects.
 *
 * Returns the number of storage volumes found or -1 and sets @vols to
 * NULL in case of error.  On success, the array stored into @vols is
 * guaranteed to have an extra allocated element set to NULL but not included
 * in the return count, to make iteration easier.  The caller is responsible
 * for calling virStorageVolFree() on each array element, then calling
 * free() on @vols.
 *
 * Since: 0.10.2
 */
int
virStoragePoolListAllVolumes(virStoragePoolPtr pool,
                             virStorageVolPtr **vols,
                             unsigned int flags)
{
    VIR_DEBUG("pool=%p, vols=%p, flags=0x%x", pool, vols, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    if (pool->conn->storageDriver &&
        pool->conn->storageDriver->storagePoolListAllVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolListAllVolumes(pool, vols, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolNumOfVolumes:
 * @pool: pointer to storage pool
 *
 * Fetch the number of storage volumes within a pool
 *
 * Returns the number of storage pools, or -1 on failure
 *
 * Since: 0.4.1
 */
int
virStoragePoolNumOfVolumes(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storagePoolNumOfVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolNumOfVolumes(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolListVolumes:
 * @pool: pointer to storage pool
 * @names: array in which to storage volume names
 * @maxnames: size of names array
 *
 * Fetch list of storage volume names, limiting to
 * at most maxnames.
 *
 * The use of this function is discouraged. Instead, use
 * virStoragePoolListAllVolumes().
 *
 * Returns the number of names fetched, or -1 on error
 *
 * Since: 0.4.1
 */
int
virStoragePoolListVolumes(virStoragePoolPtr pool,
                          char **const names,
                          int maxnames)
{
    VIR_DEBUG("pool=%p, names=%p, maxnames=%d", pool, names, maxnames);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);
    virCheckNonNullArrayArgGoto(names, maxnames, error);
    virCheckNonNegativeArgGoto(maxnames, error);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storagePoolListVolumes) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolListVolumes(pool, names, maxnames);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStorageVolGetConnect:
 * @vol: pointer to a pool
 *
 * Provides the connection pointer associated with a storage volume.  The
 * reference counter on the connection is not increased by this
 * call.
 *
 * Returns the virConnectPtr or NULL in case of failure.
 *
 * Since: 0.4.1
 */
virConnectPtr
virStorageVolGetConnect(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);

    return vol->conn;
}


/**
 * virStorageVolLookupByName:
 * @pool: pointer to storage pool
 * @name: name of storage volume
 *
 * Fetch a pointer to a storage volume based on its name
 * within a pool
 *
 * virStorageVolFree should be used to free the resources after the
 * storage volume object is no longer needed.
 *
 * Returns a storage volume, or NULL if not found / error
 *
 * Since: 0.4.1
 */
virStorageVolPtr
virStorageVolLookupByName(virStoragePoolPtr pool,
                          const char *name)
{
    VIR_DEBUG("pool=%p, name=%s", pool, NULLSTR(name));

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);
    virCheckNonNullArgGoto(name, error);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storageVolLookupByName) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolLookupByName(pool, name);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolLookupByKey:
 * @conn: pointer to hypervisor connection
 * @key: globally unique key
 *
 * Fetch a pointer to a storage volume based on its
 * globally unique key
 *
 * virStorageVolFree should be used to free the resources after the
 * storage volume object is no longer needed.
 *
 * Returns a storage volume, or NULL if not found / error
 *
 * Since: 0.4.1
 */
virStorageVolPtr
virStorageVolLookupByKey(virConnectPtr conn,
                         const char *key)
{
    VIR_DEBUG("conn=%p, key=%s", conn, NULLSTR(key));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(key, error);

    if (conn->storageDriver && conn->storageDriver->storageVolLookupByKey) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->storageVolLookupByKey(conn, key);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStorageVolLookupByPath:
 * @conn: pointer to hypervisor connection
 * @path: locally unique path
 *
 * Fetch a pointer to a storage volume based on its
 * locally (host) unique path
 *
 * virStorageVolFree should be used to free the resources after the
 * storage volume object is no longer needed.
 *
 * Returns a storage volume, or NULL if not found / error
 *
 * Since: 0.4.1
 */
virStorageVolPtr
virStorageVolLookupByPath(virConnectPtr conn,
                          const char *path)
{
    VIR_DEBUG("conn=%p, path=%s", conn, NULLSTR(path));

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgGoto(path, error);

    if (conn->storageDriver && conn->storageDriver->storageVolLookupByPath) {
        virStorageVolPtr ret;
        ret = conn->storageDriver->storageVolLookupByPath(conn, path);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virStorageVolGetName:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume name. This is unique
 * within the scope of a pool
 *
 * Returns the volume name, or NULL on error
 *
 * Since: 0.4.1
 */
const char*
virStorageVolGetName(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);

    return vol->name;
}


/**
 * virStorageVolGetKey:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume key. This is globally
 * unique, so the same volume will have the same
 * key no matter what host it is accessed from
 *
 * Returns the volume key, or NULL on error
 *
 * Since: 0.4.1
 */
const char*
virStorageVolGetKey(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);

    return vol->key;
}


/**
 * virStorageVolCreateXML:
 * @pool: pointer to storage pool
 * @xmlDesc: description of volume to create
 * @flags: bitwise-OR of virStorageVolCreateFlags
 *
 * Create a storage volume within a pool based
 * on an XML description. Not all pools support
 * creation of volumes.
 *
 * Since 1.0.1 VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA
 * in flags can be used to get higher performance with
 * qcow2 image files which don't support full preallocation,
 * by creating a sparse image file with metadata.
 *
 * virStorageVolFree should be used to free the resources after the
 * storage volume object is no longer needed.
 *
 * Returns the storage volume, or NULL on error
 *
 * Since: 0.4.1
 */
virStorageVolPtr
virStorageVolCreateXML(virStoragePoolPtr pool,
                       const char *xmlDesc,
                       unsigned int flags)
{
    VIR_DEBUG("pool=%p, xmlDesc=%s, flags=0x%x", pool, NULLSTR(xmlDesc), flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(pool->conn->flags, error);

    if (pool->conn->storageDriver && pool->conn->storageDriver->storageVolCreateXML) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolCreateXML(pool, xmlDesc, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolCreateXMLFrom:
 * @pool: pointer to parent pool for the new volume
 * @xmlDesc: description of volume to create
 * @clonevol: storage volume to use as input
 * @flags: bitwise-OR of virStorageVolCreateFlags
 *
 * Create a storage volume in the parent pool, using the
 * 'clonevol' volume as input. Information for the new
 * volume (name, perms)  are passed via a typical volume
 * XML description.
 *
 * Since 1.0.1 VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA
 * in flags can be used to get higher performance with
 * qcow2 image files which don't support full preallocation,
 * by creating a sparse image file with metadata.
 *
 * virStorageVolFree should be used to free the resources after the
 * storage volume object is no longer needed.
 *
 * Returns the storage volume, or NULL on error
 *
 * Since: 0.6.4
 */
virStorageVolPtr
virStorageVolCreateXMLFrom(virStoragePoolPtr pool,
                           const char *xmlDesc,
                           virStorageVolPtr clonevol,
                           unsigned int flags)
{
    VIR_DEBUG("pool=%p, xmlDesc=%s, clonevol=%p, flags=0x%x",
              pool, NULLSTR(xmlDesc), clonevol, flags);

    virResetLastError();

    virCheckStoragePoolReturn(pool, NULL);
    virCheckStorageVolGoto(clonevol, error);
    virCheckNonNullArgGoto(xmlDesc, error);
    virCheckReadOnlyGoto(pool->conn->flags | clonevol->conn->flags, error);

    if (pool->conn->storageDriver &&
        pool->conn->storageDriver->storageVolCreateXMLFrom) {
        virStorageVolPtr ret;
        ret = pool->conn->storageDriver->storageVolCreateXMLFrom(pool, xmlDesc,
                                                          clonevol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(pool->conn);
    return NULL;
}


/**
 * virStorageVolDownload:
 * @vol: pointer to volume to download from
 * @stream: stream to use as output
 * @offset: position in @vol to start reading from
 * @length: limit on amount of data to download
 * @flags: bitwise-OR of virStorageVolDownloadFlags
 *
 * Download the content of the volume as a stream. If @length
 * is zero, then the remaining contents of the volume after
 * @offset will be downloaded. Please note that the stream
 * transports the volume itself as is, so the downloaded data may
 * not correspond to guest OS visible state in cases when a
 * complex storage format such as qcow2 or vmdk is used.
 *
 * If VIR_STORAGE_VOL_DOWNLOAD_SPARSE_STREAM is set in @flags
 * effective transmission of holes is enabled. This assumes using
 * the @stream with combination of virStreamSparseRecvAll() or
 * virStreamRecvFlags(stream, ..., flags =
 * VIR_STREAM_RECV_STOP_AT_HOLE) for honouring holes sent by
 * server.
 *
 * This call sets up an asynchronous stream; subsequent use of
 * stream APIs is necessary to transfer the actual data,
 * determine how much data is successfully transferred, and
 * detect any errors. The results will be unpredictable if
 * another active stream is writing to the storage volume.
 *
 * Returns 0, or -1 upon error.
 *
 * Since: 0.9.0
 */
int
virStorageVolDownload(virStorageVolPtr vol,
                      virStreamPtr stream,
                      unsigned long long offset,
                      unsigned long long length,
                      unsigned int flags)
{
    VIR_DEBUG("vol=%p, stream=%p, offset=%llu, length=%llu, flags=0x%x",
              vol, stream, offset, length, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    virCheckStreamGoto(stream, error);
    virCheckReadOnlyGoto(vol->conn->flags, error);

    if (vol->conn != stream->conn) {
        virReportInvalidArg(stream,
                            _("stream in %1$s must match connection of volume '%2$s'"),
                            __FUNCTION__, vol->name);
        goto error;
    }

    if (vol->conn->storageDriver &&
        vol->conn->storageDriver->storageVolDownload) {
        int ret;
        ret = vol->conn->storageDriver->storageVolDownload(vol,
                                                           stream,
                                                           offset,
                                                           length,
                                                           flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolUpload:
 * @vol: pointer to volume to upload
 * @stream: stream to use as input
 * @offset: position to start writing to
 * @length: limit on amount of data to upload
 * @flags: bitwise-OR of virStorageVolUploadFlags
 *
 * Upload new content to the volume from a stream. This call
 * will fail if @offset + @length exceeds the size of the
 * volume. Otherwise, if @length is non-zero, an error
 * will be raised if an attempt is made to upload greater
 * than @length bytes of data. Please note that the stream
 * transports the volume itself as is, so the downloaded data may
 * not correspond to guest OS visible state in cases when a
 * complex storage format such as qcow2 or vmdk is used.
 *
 * If VIR_STORAGE_VOL_UPLOAD_SPARSE_STREAM is set in @flags
 * effective transmission of holes is enabled. This assumes using
 * the @stream with combination of virStreamSparseSendAll() or
 * virStreamSendHole() to preserve source file sparseness.
 *
 * This call sets up an asynchronous stream; subsequent use of
 * stream APIs is necessary to transfer the actual data,
 * determine how much data is successfully transferred, and
 * detect any errors. The results will be unpredictable if
 * another active stream is writing to the storage volume.
 *
 * When the data stream is closed whether the upload is successful
 * or not an attempt will be made to refresh the target storage pool
 * if an asynchronous build is not running in order to reflect pool
 * and volume changes as a result of the upload. Depending on
 * the target volume storage backend and the source stream type
 * for a successful upload, the target volume may take on the
 * characteristics from the source stream such as format type,
 * capacity, and allocation.
 *
 * Returns 0, or -1 upon error.
 *
 * Since: 0.9.0
 */
int
virStorageVolUpload(virStorageVolPtr vol,
                    virStreamPtr stream,
                    unsigned long long offset,
                    unsigned long long length,
                    unsigned int flags)
{
    VIR_DEBUG("vol=%p, stream=%p, offset=%llu, length=%llu, flags=0x%x",
              vol, stream, offset, length, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    virCheckStreamGoto(stream, error);
    virCheckReadOnlyGoto(vol->conn->flags, error);

    if (vol->conn != stream->conn) {
        virReportInvalidArg(stream,
                            _("stream in %1$s must match connection of volume '%2$s'"),
                            __FUNCTION__, vol->name);
        goto error;
    }

    if (vol->conn->storageDriver &&
        vol->conn->storageDriver->storageVolUpload) {
        int ret;
        ret = vol->conn->storageDriver->storageVolUpload(vol,
                                                  stream,
                                                  offset,
                                                  length,
                                                  flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolDelete:
 * @vol: pointer to storage volume
 * @flags: bitwise-OR of virStorageVolDeleteFlags
 *
 * Delete the storage volume from the pool
 *
 * Returns 0 on success, or -1 on error
 *
 * Since: 0.4.1
 */
int
virStorageVolDelete(virStorageVolPtr vol,
                    unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, flags=0x%x", vol, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    conn = vol->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storageVolDelete) {
        int ret;
        ret = conn->storageDriver->storageVolDelete(vol, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolWipe:
 * @vol: pointer to storage volume
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Ensure data previously on a volume is not accessible to future reads.
 *
 * The data to be wiped may include the format and possibly size information,
 * so non-raw images might become raw with a different size. It is storage
 * backend dependent whether the format and size information is regenerated
 * once the initial volume wipe is completed.
 *
 * Depending on the actual volume representation, this call may not
 * overwrite the physical location of the volume. For instance, files
 * stored journaled, log structured, copy-on-write, versioned, and
 * network file systems are known to be problematic.
 *
 * Returns 0 on success, or -1 on error
 *
 * Since: 0.8.0
 */
int
virStorageVolWipe(virStorageVolPtr vol,
                  unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, flags=0x%x", vol, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    conn = vol->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storageVolWipe) {
        int ret;
        ret = conn->storageDriver->storageVolWipe(vol, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolWipePattern:
 * @vol: pointer to storage volume
 * @algorithm: one of virStorageVolWipeAlgorithm
 * @flags: future flags, use 0 for now
 *
 * Similar to virStorageVolWipe, but one can choose between
 * different wiping algorithms. Also note, that depending on the
 * actual volume representation, this call may not really
 * overwrite the physical location of the volume. For instance,
 * files stored journaled, log structured, copy-on-write,
 * versioned, and network file systems are known to be
 * problematic.
 *
 * Returns 0 on success, or -1 on error.
 *
 * Since: 0.9.10
 */
int
virStorageVolWipePattern(virStorageVolPtr vol,
                         unsigned int algorithm,
                         unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, algorithm=%u, flags=0x%x", vol, algorithm, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    conn = vol->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->storageDriver && conn->storageDriver->storageVolWipePattern) {
        int ret;
        ret = conn->storageDriver->storageVolWipePattern(vol, algorithm, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolFree:
 * @vol: pointer to storage volume
 *
 * Release the storage volume handle. The underlying
 * storage volume continues to exist.
 *
 * Returns 0 on success, or -1 on error
 *
 * Since: 0.4.1
 */
int
virStorageVolFree(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);

    virObjectUnref(vol);
    return 0;
}


/**
 * virStorageVolRef:
 * @vol: the vol to hold a reference on
 *
 * Increment the reference count on the vol. For each
 * additional call to this method, there shall be a corresponding
 * call to virStorageVolFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * This method is typically useful for applications where multiple
 * threads are using a connection, and it is required that the
 * connection remain open until all threads have finished using
 * it. ie, each new thread using a vol would increment
 * the reference count.
 *
 * Returns 0 in case of success, -1 in case of failure.
 *
 * Since: 0.6.0
 */
int
virStorageVolRef(virStorageVolPtr vol)
{
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);

    virObjectRef(vol);
    return 0;
}


/**
 * virStorageVolGetInfo:
 * @vol: pointer to storage volume
 * @info: pointer at which to store info
 *
 * Fetches volatile information about the storage
 * volume such as its current allocation
 *
 * Returns 0 on success, or -1 on failure
 *
 * Since: 0.4.1
 */
int
virStorageVolGetInfo(virStorageVolPtr vol,
                     virStorageVolInfoPtr info)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, info=%p", vol, info);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckStorageVolReturn(vol, -1);
    virCheckNonNullArgGoto(info, error);

    conn = vol->conn;

    if (conn->storageDriver->storageVolGetInfo) {
        int ret;
        ret = conn->storageDriver->storageVolGetInfo(vol, info);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolGetInfoFlags:
 * @vol: pointer to storage volume
 * @info: pointer at which to store info
 * @flags: bitwise-OR of virStorageVolInfoFlags
 *
 * Fetches volatile information about the storage
 * volume such as its current allocation.
 *
 * If the @flags argument is VIR_STORAGE_VOL_GET_PHYSICAL, then the physical
 * bytes used for the volume will be returned in the @info allocation field.
 * This is useful for sparse files and certain volume file types where the
 * physical on disk usage can be different than the calculated allocation value
 * as is the case with qcow2 files.
 *
 * Returns 0 on success, or -1 on failure
 *
 * Since: 3.0.0
 */
int
virStorageVolGetInfoFlags(virStorageVolPtr vol,
                          virStorageVolInfoPtr info,
                          unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, info=%p, flags=0x%x", vol, info, flags);

    virResetLastError();

    if (info)
        memset(info, 0, sizeof(*info));

    virCheckStorageVolReturn(vol, -1);
    virCheckNonNullArgGoto(info, error);

    conn = vol->conn;

    if (conn->storageDriver->storageVolGetInfoFlags) {
        int ret;
        ret = conn->storageDriver->storageVolGetInfoFlags(vol, info, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStorageVolGetXMLDesc:
 * @vol: pointer to storage volume
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Fetch an XML document describing all aspects of
 * the storage volume
 *
 * Returns the XML document, or NULL on error
 *
 * Since: 0.4.1
 */
char *
virStorageVolGetXMLDesc(virStorageVolPtr vol,
                        unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p, flags=0x%x", vol, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);
    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->storageVolGetXMLDesc) {
        char *ret;
        ret = conn->storageDriver->storageVolGetXMLDesc(vol, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return NULL;
}


/**
 * virStorageVolGetPath:
 * @vol: pointer to storage volume
 *
 * Fetch the storage volume path. Depending on the pool
 * configuration this is either persistent across hosts,
 * or dynamically assigned at pool startup. Consult
 * pool documentation for information on getting the
 * persistent naming
 *
 * Returns the storage volume path, or NULL on error. The
 * caller must free() the returned path after use.
 *
 * Since: 0.4.1
 */
char *
virStorageVolGetPath(virStorageVolPtr vol)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p", vol);

    virResetLastError();

    virCheckStorageVolReturn(vol, NULL);
    conn = vol->conn;

    if (conn->storageDriver && conn->storageDriver->storageVolGetPath) {
        char *ret;
        ret = conn->storageDriver->storageVolGetPath(vol);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return NULL;
}


/**
 * virStorageVolResize:
 * @vol: pointer to storage volume
 * @capacity: new capacity, in bytes
 * @flags: bitwise-OR of virStorageVolResizeFlags
 *
 * Changes the capacity of the storage volume @vol to @capacity. The
 * operation will fail if the new capacity requires allocation that would
 * exceed the remaining free space in the parent pool.  The contents of
 * the new capacity will appear as all zero bytes. The capacity value will
 * be rounded to the granularity supported by the hypervisor.
 *
 * Normally, the operation will attempt to affect capacity with a minimum
 * impact on allocation (that is, the default operation favors a sparse
 * resize).  If @flags contains VIR_STORAGE_VOL_RESIZE_ALLOCATE, then the
 * operation will ensure that allocation is sufficient for the new
 * capacity; this may make the operation take noticeably longer.
 *
 * Normally, the operation treats @capacity as the new size in bytes;
 * but if @flags contains VIR_STORAGE_VOL_RESIZE_DELTA, then @capacity
 * represents the size difference to add to the current size.  It is
 * up to the storage pool implementation whether unaligned requests are
 * rounded up to the next valid boundary, or rejected.
 *
 * Normally, this operation should only be used to enlarge capacity;
 * but if @flags contains VIR_STORAGE_VOL_RESIZE_SHRINK, it is possible to
 * attempt a reduction in capacity even though it might cause data loss.
 * If VIR_STORAGE_VOL_RESIZE_DELTA is also present, then @capacity is
 * subtracted from the current size; without it, @capacity represents
 * the absolute new size regardless of whether it is larger or smaller
 * than the current size.
 *
 * Returns 0 on success, or -1 on error.
 *
 * Since: 0.9.10
 */
int
virStorageVolResize(virStorageVolPtr vol,
                    unsigned long long capacity,
                    unsigned int flags)
{
    virConnectPtr conn;
    VIR_DEBUG("vol=%p capacity=%llu flags=0x%x", vol, capacity, flags);

    virResetLastError();

    virCheckStorageVolReturn(vol, -1);
    conn = vol->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    /* Zero capacity is only valid with either delta or shrink.  */
    if (capacity == 0 && !((flags & VIR_STORAGE_VOL_RESIZE_DELTA) ||
                           (flags & VIR_STORAGE_VOL_RESIZE_SHRINK))) {
        virReportInvalidArg(capacity,
                            _("capacity in %1$s cannot be zero without 'delta' or 'shrink' flags set"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->storageDriver && conn->storageDriver->storageVolResize) {
        int ret;
        ret = conn->storageDriver->storageVolResize(vol, capacity, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(vol->conn);
    return -1;
}


/**
 * virStoragePoolIsActive:
 * @pool: pointer to the storage pool object
 *
 * Determine if the storage pool is currently running
 *
 * Returns 1 if running, 0 if inactive, -1 on error
 *
 * Since: 0.7.3
 */
int
virStoragePoolIsActive(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    if (pool->conn->storageDriver->storagePoolIsActive) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolIsActive(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(pool->conn);
    return -1;
}


/**
 * virStoragePoolIsPersistent:
 * @pool: pointer to the storage pool object
 *
 * Determine if the storage pool has a persistent configuration
 * which means it will still exist after shutting down
 *
 * Returns 1 if persistent, 0 if transient, -1 on error
 *
 * Since: 0.7.3
 */
int
virStoragePoolIsPersistent(virStoragePoolPtr pool)
{
    VIR_DEBUG("pool=%p", pool);

    virResetLastError();

    virCheckStoragePoolReturn(pool, -1);

    if (pool->conn->storageDriver->storagePoolIsPersistent) {
        int ret;
        ret = pool->conn->storageDriver->storagePoolIsPersistent(pool);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(pool->conn);
    return -1;
}

/**
 * virConnectStoragePoolEventRegisterAny:
 * @conn: pointer to the connection
 * @pool: pointer to the storage pool
 * @eventID: the event type to receive
 * @cb: callback to the function handling network events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 *
 * Adds a callback to receive notifications of arbitrary storage pool events
 * occurring on a storage pool. This function requires that an event loop
 * has been previously registered with virEventRegisterImpl() or
 * virEventRegisterDefaultImpl().
 *
 * If @pool is NULL, then events will be monitored for any storage pool.
 * If @pool is non-NULL, then only the specific storage pool will be monitored.
 *
 * Most types of events have a callback providing a custom set of parameters
 * for the event. When registering an event, it is thus necessary to use
 * the VIR_STORAGE_POOL_EVENT_CALLBACK() macro to cast the
 * supplied function pointer to match the signature of this method.
 *
 * The virStoragePoolPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the storage pool object after the callback
 * returns, it shall take a reference to it, by calling virStoragePoolRef().
 * The reference can be released once the object is no longer required
 * by calling virStoragePoolFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectStoragePoolEventDeregisterAny() method.
 *
 * Returns a callback identifier on success, -1 on failure.
 *
 * Since: 2.0.0
 */
int
virConnectStoragePoolEventRegisterAny(virConnectPtr conn,
                                      virStoragePoolPtr pool,
                                      int eventID,
                                      virConnectStoragePoolEventGenericCallback cb,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    VIR_DEBUG("conn=%p, pool=%p, eventID=%d, cb=%p, opaque=%p, freecb=%p",
              conn, pool, eventID, cb, opaque, freecb);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (pool) {
        virCheckStoragePoolGoto(pool, error);
        if (pool->conn != conn) {
            virReportInvalidArg(pool,
                                _("storage pool '%1$s' in %2$s must match connection"),
                                pool->name, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckNonNegativeArgGoto(eventID, error);

    if (eventID >= VIR_STORAGE_POOL_EVENT_ID_LAST) {
        virReportInvalidArg(eventID,
                            _("eventID in %1$s must be less than %2$d"),
                            __FUNCTION__, VIR_STORAGE_POOL_EVENT_ID_LAST);
        goto error;
    }

    if (conn->storageDriver &&
        conn->storageDriver->connectStoragePoolEventRegisterAny) {
        int ret;
        ret = conn->storageDriver->connectStoragePoolEventRegisterAny(conn,
                                                                      pool,
                                                                      eventID,
                                                                      cb,
                                                                      opaque,
                                                                      freecb);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}

/**
 * virConnectStoragePoolEventDeregisterAny:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectStoragePoolEventRegisterAny() method.
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 2.0.0
 */
int
virConnectStoragePoolEventDeregisterAny(virConnectPtr conn,
                                        int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);

    if (conn->storageDriver &&
        conn->storageDriver->connectStoragePoolEventDeregisterAny) {
        int ret;
        ret = conn->storageDriver->connectStoragePoolEventDeregisterAny(conn,
                                                                        callbackID);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectGetStoragePoolCapabilities:
 * @conn: pointer to the hypervisor connection
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Prior creating a storage pool (for instance via virStoragePoolCreateXML
 * or virStoragePoolDefineXML) it may be suitable to know what pool types
 * are supported along with the file/disk formats for each pool.
 *
 * Returns NULL in case of error or an XML string defining the capabilities.
 *
 * Since: 5.2.0
 */
char *
virConnectGetStoragePoolCapabilities(virConnectPtr conn,
                                     unsigned int flags)
{
    VIR_DEBUG("conn=%p, flags=0x%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    if (conn->storageDriver &&
        conn->storageDriver->connectGetStoragePoolCapabilities) {
        char *ret;
        ret = conn->storageDriver->connectGetStoragePoolCapabilities(conn,
                                                                     flags);
        if (!ret)
            goto error;
        VIR_DEBUG("conn=%p, ret=%s", conn, ret);
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}
