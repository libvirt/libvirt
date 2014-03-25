/*
 * datatypes.c: management of structs for public data types
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#include "datatypes.h"
#include "virerror.h"
#include "virlog.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("datatypes");

virClassPtr virConnectClass;
virClassPtr virConnectCloseCallbackDataClass;
virClassPtr virDomainClass;
virClassPtr virDomainSnapshotClass;
virClassPtr virInterfaceClass;
virClassPtr virNetworkClass;
virClassPtr virNodeDeviceClass;
virClassPtr virNWFilterClass;
virClassPtr virSecretClass;
virClassPtr virStreamClass;
virClassPtr virStorageVolClass;
virClassPtr virStoragePoolClass;

static void virConnectDispose(void *obj);
static void virConnectCloseCallbackDataDispose(void *obj);
static void virDomainDispose(void *obj);
static void virDomainSnapshotDispose(void *obj);
static void virInterfaceDispose(void *obj);
static void virNetworkDispose(void *obj);
static void virNodeDeviceDispose(void *obj);
static void virNWFilterDispose(void *obj);
static void virSecretDispose(void *obj);
static void virStreamDispose(void *obj);
static void virStorageVolDispose(void *obj);
static void virStoragePoolDispose(void *obj);

static int
virDataTypesOnceInit(void)
{
#define DECLARE_CLASS_COMMON(basename, parent)                   \
    if (!(basename ## Class = virClassNew(parent,                \
                                          #basename,             \
                                          sizeof(basename),      \
                                          basename ## Dispose))) \
        return -1;
#define DECLARE_CLASS(basename)                                  \
    DECLARE_CLASS_COMMON(basename, virClassForObject())
#define DECLARE_CLASS_LOCKABLE(basename)                         \
    DECLARE_CLASS_COMMON(basename, virClassForObjectLockable())

    DECLARE_CLASS(virConnect);
    DECLARE_CLASS_LOCKABLE(virConnectCloseCallbackData);
    DECLARE_CLASS(virDomain);
    DECLARE_CLASS(virDomainSnapshot);
    DECLARE_CLASS(virInterface);
    DECLARE_CLASS(virNetwork);
    DECLARE_CLASS(virNodeDevice);
    DECLARE_CLASS(virNWFilter);
    DECLARE_CLASS(virSecret);
    DECLARE_CLASS(virStream);
    DECLARE_CLASS(virStorageVol);
    DECLARE_CLASS(virStoragePool);

#undef DECLARE_CLASS_COMMON
#undef DECLARE_CLASS_LOCKABLE
#undef DECLARE_CLASS

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDataTypes)

/**
 * virGetConnect:
 *
 * Allocates a new hypervisor connection object.
 *
 * Returns a pointer to the connection object, or NULL on error.
 */
virConnectPtr
virGetConnect(void)
{
    virConnectPtr ret;

    if (virDataTypesInitialize() < 0)
        return NULL;

    if (!(ret = virObjectNew(virConnectClass)))
        return NULL;

    if (!(ret->closeCallback = virObjectNew(virConnectCloseCallbackDataClass)))
        goto error;

    if (virMutexInit(&ret->lock) < 0)
        goto error;

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virConnectDispose:
 * @obj: the hypervisor connection to release
 *
 * Unconditionally release all memory associated with a connection.
 * The connection object must not be used once this method returns.
 */
static void
virConnectDispose(void *obj)
{
    virConnectPtr conn = obj;

    if (conn->networkDriver)
        conn->networkDriver->networkClose(conn);
    if (conn->interfaceDriver)
        conn->interfaceDriver->interfaceClose(conn);
    if (conn->storageDriver)
        conn->storageDriver->storageClose(conn);
    if (conn->nodeDeviceDriver)
        conn->nodeDeviceDriver->nodeDeviceClose(conn);
    if (conn->secretDriver)
        conn->secretDriver->secretClose(conn);
    if (conn->nwfilterDriver)
        conn->nwfilterDriver->nwfilterClose(conn);
    if (conn->driver)
        conn->driver->connectClose(conn);

    virMutexLock(&conn->lock);

    virResetError(&conn->err);

    virURIFree(conn->uri);

    if (conn->closeCallback) {
        virObjectLock(conn->closeCallback);
        conn->closeCallback->callback = NULL;
        virObjectUnlock(conn->closeCallback);

        virObjectUnref(conn->closeCallback);
    }

    virMutexUnlock(&conn->lock);
    virMutexDestroy(&conn->lock);
}


/**
 * virConnectCloseCallbackDataDispose:
 * @obj: the close callback data to release
 *
 * Release resources bound to the connection close callback.
 */
static void
virConnectCloseCallbackDataDispose(void *obj)
{
    virConnectCloseCallbackDataPtr cb = obj;

    virObjectLock(cb);

    if (cb->freeCallback)
        cb->freeCallback(cb->opaque);

    virObjectUnlock(cb);
}


/**
 * virGetDomain:
 * @conn: the hypervisor connection
 * @name: pointer to the domain name
 * @uuid: pointer to the uuid
 *
 * Allocates a new domain object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the domain object, or NULL on error.
 */
virDomainPtr
virGetDomain(virConnectPtr conn, const char *name, const unsigned char *uuid)
{
    virDomainPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);
    virCheckNonNullArgGoto(uuid, error);

    if (!(ret = virObjectNew(virDomainClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    ret->conn = virObjectRef(conn);
    ret->id = -1;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virDomainDispose:
 * @obj: the domain to release
 *
 * Unconditionally release all memory associated with a domain.
 * The domain object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virDomainDispose(void *obj)
{
    virDomainPtr domain = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(domain->uuid, uuidstr);
    VIR_DEBUG("release domain %p %s %s", domain, domain->name, uuidstr);

    VIR_FREE(domain->name);
    virObjectUnref(domain->conn);
}


/**
 * virGetNetwork:
 * @conn: the hypervisor connection
 * @name: pointer to the network name
 * @uuid: pointer to the uuid
 *
 * Allocates a new network object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the network object, or NULL on error.
 */
virNetworkPtr
virGetNetwork(virConnectPtr conn, const char *name, const unsigned char *uuid)
{
    virNetworkPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);
    virCheckNonNullArgGoto(uuid, error);

    if (!(ret = virObjectNew(virNetworkClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    ret->conn = virObjectRef(conn);
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virNetworkDispose:
 * @obj: the network to release
 *
 * Unconditionally release all memory associated with a network.
 * The network object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virNetworkDispose(void *obj)
{
    virNetworkPtr network = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(network->uuid, uuidstr);
    VIR_DEBUG("release network %p %s %s", network, network->name, uuidstr);

    VIR_FREE(network->name);
    virObjectUnref(network->conn);
}


/**
 * virGetInterface:
 * @conn: the hypervisor connection
 * @name: pointer to the interface name
 * @mac: pointer to the mac
 *
 * Allocates a new interface object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the interface object, or NULL on error.
 */
virInterfacePtr
virGetInterface(virConnectPtr conn, const char *name, const char *mac)
{
    virInterfacePtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);

    /* a NULL mac from caller is okay. Treat it as blank */
    if (mac == NULL)
       mac = "";

    if (!(ret = virObjectNew(virInterfaceClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0 ||
        VIR_STRDUP(ret->mac, mac) < 0)
        goto error;

    ret->conn = virObjectRef(conn);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virInterfaceDispose:
 * @obj: the interface to release
 *
 * Unconditionally release all memory associated with an interface.
 * The interface object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virInterfaceDispose(void *obj)
{
    virInterfacePtr iface = obj;
    VIR_DEBUG("release interface %p %s", iface, iface->name);

    VIR_FREE(iface->name);
    VIR_FREE(iface->mac);
    virObjectUnref(iface->conn);
}


/**
 * virGetStoragePool:
 * @conn: the hypervisor connection
 * @name: pointer to the storage pool name
 * @uuid: pointer to the uuid
 * @privateData: pointer to driver specific private data
 * @freeFunc: private data cleanup function pointer specfic to driver
 *
 * Allocates a new storage pool object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the storage pool object, or NULL on error.
 */
virStoragePoolPtr
virGetStoragePool(virConnectPtr conn, const char *name,
                  const unsigned char *uuid,
                  void *privateData, virFreeCallback freeFunc)
{
    virStoragePoolPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);
    virCheckNonNullArgGoto(uuid, error);

    if (!(ret = virObjectNew(virStoragePoolClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    ret->conn = virObjectRef(conn);
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    /* set the driver specific data */
    ret->privateData = privateData;
    ret->privateDataFreeFunc = freeFunc;

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virStoragePoolDispose:
 * @obj: the storage pool to release
 *
 * Unconditionally release all memory associated with a pool.
 * The pool object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virStoragePoolDispose(void *obj)
{
    virStoragePoolPtr pool = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(pool->uuid, uuidstr);
    VIR_DEBUG("release pool %p %s %s", pool, pool->name, uuidstr);

    if (pool->privateDataFreeFunc) {
        pool->privateDataFreeFunc(pool->privateData);
    }

    VIR_FREE(pool->name);
    virObjectUnref(pool->conn);
}


/**
 * virGetStorageVol:
 * @conn: the hypervisor connection
 * @pool: pool owning the volume
 * @name: pointer to the storage vol name
 * @key: pointer to unique key of the volume
 * @privateData: pointer to driver specific private data
 * @freeFunc: private data cleanup function pointer specfic to driver
 *
 * Allocates a new storage volume object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the storage volume object, or NULL on error.
 */
virStorageVolPtr
virGetStorageVol(virConnectPtr conn, const char *pool, const char *name,
                 const char *key, void *privateData, virFreeCallback freeFunc)
{
    virStorageVolPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(pool, error);
    virCheckNonNullArgGoto(name, error);
    virCheckNonNullArgGoto(key, error);

    if (!(ret = virObjectNew(virStorageVolClass)))
        goto error;

    if (VIR_STRDUP(ret->pool, pool) < 0 ||
        VIR_STRDUP(ret->name, name) < 0 ||
        VIR_STRDUP(ret->key, key) < 0)
        goto error;

    ret->conn = virObjectRef(conn);

    /* set driver specific data */
    ret->privateData = privateData;
    ret->privateDataFreeFunc = freeFunc;

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virStorageVolDispose:
 * @obj: the storage volume to release
 *
 * Unconditionally release all memory associated with a volume.
 * The volume object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virStorageVolDispose(void *obj)
{
    virStorageVolPtr vol = obj;
    VIR_DEBUG("release vol %p %s", vol, vol->name);

    if (vol->privateDataFreeFunc) {
        vol->privateDataFreeFunc(vol->privateData);
    }

    VIR_FREE(vol->key);
    VIR_FREE(vol->name);
    VIR_FREE(vol->pool);
    virObjectUnref(vol->conn);
}


/**
 * virGetNodeDevice:
 * @conn: the hypervisor connection
 * @name: device name (unique on node)
 *
 * Allocates a new node device object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the node device object, or NULL on error.
 */
virNodeDevicePtr
virGetNodeDevice(virConnectPtr conn, const char *name)
{
    virNodeDevicePtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);

    if (!(ret = virObjectNew(virNodeDeviceClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    ret->conn = virObjectRef(conn);
    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virNodeDeviceDispose:
 * @obj: the node device to release
 *
 * Unconditionally release all memory associated with a device.
 * The device object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virNodeDeviceDispose(void *obj)
{
    virNodeDevicePtr dev = obj;
    VIR_DEBUG("release dev %p %s", dev, dev->name);

    VIR_FREE(dev->name);
    VIR_FREE(dev->parent);

    virObjectUnref(dev->conn);
}


/**
 * virGetSecret:
 * @conn: the hypervisor connection
 * @uuid: secret UUID
 *
 * Allocates a new secret object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the secret object, or NULL on error.
 */
virSecretPtr
virGetSecret(virConnectPtr conn, const unsigned char *uuid,
             int usageType, const char *usageID)
{
    virSecretPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(uuid, error);
    virCheckNonNullArgGoto(usageID, error);

    if (!(ret = virObjectNew(virSecretClass)))
        return NULL;

    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);
    ret->usageType = usageType;
    if (VIR_STRDUP(ret->usageID, usageID) < 0)
        goto error;

    ret->conn = virObjectRef(conn);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virSecretDispose:
 * @obj: the secret to release
 *
 * Unconditionally release all memory associated with a secret.
 * The secret object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virSecretDispose(void *obj)
{
    virSecretPtr secret = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(secret->uuid, uuidstr);
    VIR_DEBUG("release secret %p %s", secret, uuidstr);

    VIR_FREE(secret->usageID);
    virObjectUnref(secret->conn);
}


/**
 * virGetStream:
 * @conn: the hypervisor connection
 *
 * Allocates a new stream object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the stream object, or NULL on error.
 */
virStreamPtr
virGetStream(virConnectPtr conn)
{
    virStreamPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    if (!(ret = virObjectNew(virStreamClass)))
        return NULL;

    ret->conn = virObjectRef(conn);

    return ret;
}

/**
 * virStreamDispose:
 * @obj: the stream to release
 *
 * Unconditionally release all memory associated with a stream.
 * The stream object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virStreamDispose(void *obj)
{
    virStreamPtr st = obj;
    VIR_DEBUG("release dev %p", st);

    virObjectUnref(st->conn);
}


/**
 * virGetNWFilter:
 * @conn: the hypervisor connection
 * @name: pointer to the network filter pool name
 * @uuid: pointer to the uuid
 *
 * Allocates a new network filter object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the network filter object, or NULL on error.
 */
virNWFilterPtr
virGetNWFilter(virConnectPtr conn, const char *name,
               const unsigned char *uuid)
{
    virNWFilterPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(name, error);
    virCheckNonNullArgGoto(uuid, error);

    if (!(ret = virObjectNew(virNWFilterClass)))
        goto error;

    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    ret->conn = virObjectRef(conn);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virNWFilterDispose:
 * @obj: the network filter to release
 *
 * Unconditionally release all memory associated with a nwfilter.
 * The nwfilter object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virNWFilterDispose(void *obj)
{
    virNWFilterPtr nwfilter = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(nwfilter->uuid, uuidstr);
    VIR_DEBUG("release nwfilter %p %s %s", nwfilter, nwfilter->name, uuidstr);

    VIR_FREE(nwfilter->name);
    virObjectUnref(nwfilter->conn);
}


/**
 * virGetDomainSnapshot:
 * @domain: the domain to snapshot
 * @name: pointer to the domain snapshot name
 *
 * Allocates a new domain snapshot object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the domain snapshot object, or NULL on error.
 */
virDomainSnapshotPtr
virGetDomainSnapshot(virDomainPtr domain, const char *name)
{
    virDomainSnapshotPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckDomainGoto(domain, error);
    virCheckNonNullArgGoto(name, error);

    if (!(ret = virObjectNew(virDomainSnapshotClass)))
        goto error;
    if (VIR_STRDUP(ret->name, name) < 0)
        goto error;

    ret->domain = virObjectRef(domain);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virDomainSnapshotDispose:
 * @obj: the domain snapshot to release
 *
 * Unconditionally release all memory associated with a snapshot.
 * The snapshot object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virDomainSnapshotDispose(void *obj)
{
    virDomainSnapshotPtr snapshot = obj;
    VIR_DEBUG("release snapshot %p %s", snapshot, snapshot->name);

    VIR_FREE(snapshot->name);
    virObjectUnref(snapshot->domain);
}
