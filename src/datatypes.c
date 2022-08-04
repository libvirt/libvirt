/*
 * datatypes.c: management of structs for public data types
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
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

virClass *virConnectClass;
virClass *virConnectCloseCallbackDataClass;
virClass *virDomainClass;
virClass *virDomainCheckpointClass;
virClass *virDomainSnapshotClass;
virClass *virInterfaceClass;
virClass *virNetworkClass;
virClass *virNetworkPortClass;
virClass *virNodeDeviceClass;
virClass *virNWFilterClass;
virClass *virNWFilterBindingClass;
virClass *virSecretClass;
virClass *virStreamClass;
virClass *virStorageVolClass;
virClass *virStoragePoolClass;

static void virConnectDispose(void *obj);
static void virConnectCloseCallbackDataDispose(void *obj);
static void virDomainDispose(void *obj);
static void virDomainCheckpointDispose(void *obj);
static void virDomainSnapshotDispose(void *obj);
static void virInterfaceDispose(void *obj);
static void virNetworkDispose(void *obj);
static void virNetworkPortDispose(void *obj);
static void virNodeDeviceDispose(void *obj);
static void virNWFilterDispose(void *obj);
static void virNWFilterBindingDispose(void *obj);
static void virSecretDispose(void *obj);
static void virStreamDispose(void *obj);
static void virStorageVolDispose(void *obj);
static void virStoragePoolDispose(void *obj);

virClass *virAdmConnectClass;
virClass *virAdmConnectCloseCallbackDataClass;

static void virAdmConnectDispose(void *obj);
static void virAdmConnectCloseCallbackDataDispose(void *obj);

virClass *virAdmServerClass;
virClass *virAdmClientClass;
static void virAdmServerDispose(void *obj);
static void virAdmClientDispose(void *obj);

static __thread bool connectDisposed;
static __thread bool admConnectDisposed;

static int
virDataTypesOnceInit(void)
{
#define DECLARE_CLASS_COMMON(basename, parent) \
    if (!(VIR_CLASS_NEW(basename, parent))) \
        return -1;
#define DECLARE_CLASS(basename) \
    DECLARE_CLASS_COMMON(basename, virClassForObject())
#define DECLARE_CLASS_LOCKABLE(basename) \
    DECLARE_CLASS_COMMON(basename, virClassForObjectLockable())

    DECLARE_CLASS_LOCKABLE(virConnect);
    DECLARE_CLASS_LOCKABLE(virConnectCloseCallbackData);
    DECLARE_CLASS(virDomain);
    DECLARE_CLASS(virDomainCheckpoint);
    DECLARE_CLASS(virDomainSnapshot);
    DECLARE_CLASS(virInterface);
    DECLARE_CLASS(virNetwork);
    DECLARE_CLASS(virNetworkPort);
    DECLARE_CLASS(virNodeDevice);
    DECLARE_CLASS(virNWFilter);
    DECLARE_CLASS(virNWFilterBinding);
    DECLARE_CLASS(virSecret);
    DECLARE_CLASS(virStream);
    DECLARE_CLASS(virStorageVol);
    DECLARE_CLASS(virStoragePool);

    DECLARE_CLASS_LOCKABLE(virAdmConnect);
    DECLARE_CLASS_LOCKABLE(virAdmConnectCloseCallbackData);
    DECLARE_CLASS(virAdmServer);
    DECLARE_CLASS(virAdmClient);

#undef DECLARE_CLASS_COMMON
#undef DECLARE_CLASS_LOCKABLE
#undef DECLARE_CLASS

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDataTypes);

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
    if (virDataTypesInitialize() < 0)
        return NULL;

    return virObjectLockableNew(virConnectClass);
}


void virConnectWatchDispose(void)
{
    connectDisposed = false;
}

bool virConnectWasDisposed(void)
{
    return connectDisposed;
}

void virAdmConnectWatchDispose(void)
{
    admConnectDisposed = false;
}

bool virAdmConnectWasDisposed(void)
{
    return admConnectDisposed;
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

    connectDisposed = true;
    if (conn->driver)
        conn->driver->connectClose(conn);

    virResetError(&conn->err);

    virURIFree(conn->uri);
}


static void
virConnectCloseCallbackDataReset(virConnectCloseCallbackData *closeData)
{
    if (closeData->freeCallback)
        closeData->freeCallback(closeData->opaque);

    closeData->freeCallback = NULL;
    closeData->opaque = NULL;
    g_clear_pointer(&closeData->conn, virObjectUnref);
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
    virConnectCloseCallbackDataReset(obj);
}

virConnectCloseCallbackData *
virNewConnectCloseCallbackData(void)
{
    if (virDataTypesInitialize() < 0)
        return NULL;

    return virObjectLockableNew(virConnectCloseCallbackDataClass);
}

void virConnectCloseCallbackDataRegister(virConnectCloseCallbackData *closeData,
                                         virConnectPtr conn,
                                         virConnectCloseFunc cb,
                                         void *opaque,
                                         virFreeCallback freecb)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(closeData);

    if (closeData->callback != NULL) {
        VIR_WARN("Attempt to register callback on armed close callback object %p",
                 closeData);
        return;
    }

    closeData->conn = virObjectRef(conn);
    closeData->callback = cb;
    closeData->opaque = opaque;
    closeData->freeCallback = freecb;
}

void virConnectCloseCallbackDataUnregister(virConnectCloseCallbackData *closeData,
                                           virConnectCloseFunc cb)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(closeData);

    if (closeData->callback != cb) {
        VIR_WARN("Attempt to unregister different callback on  close callback object %p",
                 closeData);
        return;
    }

    virConnectCloseCallbackDataReset(closeData);
    closeData->callback = NULL;
}

void virConnectCloseCallbackDataCall(virConnectCloseCallbackData *closeData,
                                     int reason)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(closeData);

    if (!closeData->conn)
        return;

    VIR_DEBUG("Triggering connection close callback %p reason=%d, opaque=%p",
              closeData->callback, reason, closeData->opaque);
    closeData->callback(closeData->conn, reason, closeData->opaque);

    virConnectCloseCallbackDataReset(closeData);
}

virConnectCloseFunc
virConnectCloseCallbackDataGetCallback(virConnectCloseCallbackData *closeData)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(closeData);

    return closeData->callback;
}

/**
 * virGetDomain:
 * @conn: the hypervisor connection
 * @name: pointer to the domain name
 * @uuid: pointer to the uuid
 * @id: domain ID
 *
 * Allocates a new domain object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the domain object, or NULL on error.
 */
virDomainPtr
virGetDomain(virConnectPtr conn,
             const char *name,
             const unsigned char *uuid,
             int id)
{
    virDomainPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectReturn(conn, NULL);
    virCheckNonNullArgReturn(name, NULL);
    virCheckNonNullArgReturn(uuid, NULL);

    ret = virObjectNew(virDomainClass);
    ret->name = g_strdup(name);

    ret->conn = virObjectRef(conn);
    ret->id = id;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    return ret;
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

    g_free(domain->name);
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

    ret->name = g_strdup(name);

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

    g_free(network->name);
    virObjectUnref(network->conn);
}


/**
 * virGetNetworkPort:
 * @net: the network object
 * @uuid: pointer to the uuid
 *
 * Allocates a new network port object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the network port object, or NULL on error.
 */
virNetworkPortPtr
virGetNetworkPort(virNetworkPtr net, const unsigned char *uuid)
{
    virNetworkPortPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckNetworkGoto(net, error);
    virCheckNonNullArgGoto(uuid, error);

    if (!(ret = virObjectNew(virNetworkPortClass)))
        goto error;

    ret->net = virObjectRef(net);
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

/**
 * virNetworkPortDispose:
 * @obj: the network port to release
 *
 * Unconditionally release all memory associated with a network port.
 * The network port object must not be used once this method returns.
 *
 * It will also unreference the associated network object,
 * which may also be released if its ref count hits zero.
 */
static void
virNetworkPortDispose(void *obj)
{
    virNetworkPortPtr port = obj;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(port->uuid, uuidstr);
    VIR_DEBUG("release network port %p %s", port, uuidstr);

    virObjectUnref(port->net);
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

    ret->name = g_strdup(name);
    ret->mac = g_strdup(mac);

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

    g_free(iface->name);
    g_free(iface->mac);
    virObjectUnref(iface->conn);
}


/**
 * virGetStoragePool:
 * @conn: the hypervisor connection
 * @name: pointer to the storage pool name
 * @uuid: pointer to the uuid
 * @privateData: pointer to driver specific private data
 * @freeFunc: private data cleanup function pointer specific to driver
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

    ret->name = g_strdup(name);

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

    if (pool->privateDataFreeFunc)
        pool->privateDataFreeFunc(pool->privateData);

    g_free(pool->name);
    virObjectUnref(pool->conn);
}


/**
 * virGetStorageVol:
 * @conn: the hypervisor connection
 * @pool: pool owning the volume
 * @name: pointer to the storage vol name
 * @key: pointer to unique key of the volume
 * @privateData: pointer to driver specific private data
 * @freeFunc: private data cleanup function pointer specific to driver
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

    ret->pool = g_strdup(pool);
    ret->name = g_strdup(name);
    ret->key = g_strdup(key);

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

    if (vol->privateDataFreeFunc)
        vol->privateDataFreeFunc(vol->privateData);

    g_free(vol->key);
    g_free(vol->name);
    g_free(vol->pool);
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

    ret->name = g_strdup(name);

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

    g_free(dev->name);
    g_free(dev->parentName);

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

    if (!(ret = virObjectNew(virSecretClass)))
        return NULL;

    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);
    ret->usageType = usageType;
    ret->usageID = g_strdup(NULLSTR_EMPTY(usageID));

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

    g_free(secret->usageID);
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

    if (st->ff)
        st->ff(st->privateData);
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

    ret->name = g_strdup(name);

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

    g_free(nwfilter->name);
    virObjectUnref(nwfilter->conn);
}


/**
 * virGetNWFilterBinding:
 * @conn: the hypervisor connection
 * @portdev: pointer to the network filter port device name
 * @filtername: name of the network filter
 *
 * Allocates a new network filter binding object. When the object is no longer
 * needed, virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the network filter binding object, or NULL on error.
 */
virNWFilterBindingPtr
virGetNWFilterBinding(virConnectPtr conn, const char *portdev,
                      const char *filtername)
{
    virNWFilterBindingPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckConnectGoto(conn, error);
    virCheckNonNullArgGoto(portdev, error);

    if (!(ret = virObjectNew(virNWFilterBindingClass)))
        goto error;

    ret->portdev = g_strdup(portdev);

    ret->filtername = g_strdup(filtername);

    ret->conn = virObjectRef(conn);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virNWFilterBindingDispose:
 * @obj: the network filter binding to release
 *
 * Unconditionally release all memory associated with a nwfilter binding.
 * The nwfilter binding object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virNWFilterBindingDispose(void *obj)
{
    virNWFilterBindingPtr binding = obj;

    VIR_DEBUG("release binding %p %s", binding, binding->portdev);

    g_free(binding->portdev);
    g_free(binding->filtername);
    virObjectUnref(binding->conn);
}


/**
 * virGetDomainCheckpoint:
 * @domain: the domain to checkpoint
 * @name: pointer to the domain checkpoint name
 *
 * Allocates a new domain checkpoint object. When the object is no longer needed,
 * virObjectUnref() must be called in order to not leak data.
 *
 * Returns a pointer to the domain checkpoint object, or NULL on error.
 */
virDomainCheckpointPtr
virGetDomainCheckpoint(virDomainPtr domain,
                       const char *name)
{
    virDomainCheckpointPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        return NULL;

    virCheckDomainGoto(domain, error);
    virCheckNonNullArgGoto(name, error);

    if (!(ret = virObjectNew(virDomainCheckpointClass)))
        goto error;
    ret->name = g_strdup(name);

    ret->domain = virObjectRef(domain);

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}


/**
 * virDomainCheckpointDispose:
 * @obj: the domain checkpoint to release
 *
 * Unconditionally release all memory associated with a checkpoint.
 * The checkpoint object must not be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virDomainCheckpointDispose(void *obj)
{
    virDomainCheckpointPtr checkpoint = obj;
    VIR_DEBUG("release checkpoint %p %s", checkpoint, checkpoint->name);

    g_free(checkpoint->name);
    virObjectUnref(checkpoint->domain);
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
    ret->name = g_strdup(name);

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

    g_free(snapshot->name);
    virObjectUnref(snapshot->domain);
}


virAdmConnectPtr
virAdmConnectNew(void)
{
    virAdmConnectPtr ret;

    if (virDataTypesInitialize() < 0)
        return NULL;

    if (!(ret = virObjectLockableNew(virAdmConnectClass)))
        return NULL;

    if (!(ret->closeCallback = virObjectLockableNew(virAdmConnectCloseCallbackDataClass)))
        goto error;

    return ret;

 error:
    virObjectUnref(ret);
    return NULL;
}

static void
virAdmConnectDispose(void *obj)
{
    virAdmConnectPtr conn = obj;

    admConnectDisposed = true;
    if (conn->privateDataFreeFunc)
        conn->privateDataFreeFunc(conn);

    virURIFree(conn->uri);
    virObjectUnref(conn->closeCallback);
}

static void
virAdmConnectCloseCallbackDataDispose(void *obj)
{
    virAdmConnectCloseCallbackData *cb_data = obj;
    VIR_LOCK_GUARD lock = virObjectLockGuard(cb_data);

    virAdmConnectCloseCallbackDataReset(cb_data);
}

void
virAdmConnectCloseCallbackDataReset(virAdmConnectCloseCallbackData *cbdata)
{
    if (cbdata->freeCallback)
        cbdata->freeCallback(cbdata->opaque);

    g_clear_pointer(&cbdata->conn, virObjectUnref);
    cbdata->freeCallback = NULL;
    cbdata->callback = NULL;
    cbdata->opaque = NULL;
}

int
virAdmConnectCloseCallbackDataUnregister(virAdmConnectCloseCallbackData *cbdata,
                                         virAdmConnectCloseFunc cb)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(cbdata);

    if (cbdata->callback != cb) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A different callback was requested"));
        return -1;
    }

    virAdmConnectCloseCallbackDataReset(cbdata);
    return 0;
}

int
virAdmConnectCloseCallbackDataRegister(virAdmConnectCloseCallbackData *cbdata,
                                       virAdmConnectPtr conn,
                                       virAdmConnectCloseFunc cb,
                                       void *opaque,
                                       virFreeCallback freecb)
{
    VIR_LOCK_GUARD lock = virObjectLockGuard(cbdata);

    if (cbdata->callback) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("A close callback is already registered"));
        return -1;
    }

    cbdata->conn = virObjectRef(conn);
    cbdata->callback = cb;
    cbdata->opaque = opaque;
    cbdata->freeCallback = freecb;

    return 0;
}

virAdmServerPtr
virAdmGetServer(virAdmConnectPtr conn, const char *name)
{
    virAdmServerPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        goto error;

    if (!(ret = virObjectNew(virAdmServerClass)))
        goto error;
    ret->name = g_strdup(name);

    ret->conn = virObjectRef(conn);

    return ret;
 error:
    virObjectUnref(ret);
    return NULL;
}

static void
virAdmServerDispose(void *obj)
{
    virAdmServerPtr srv = obj;
    VIR_DEBUG("release server srv=%p name=%s", srv, srv->name);

    g_free(srv->name);
    virObjectUnref(srv->conn);
}

virAdmClientPtr
virAdmGetClient(virAdmServerPtr srv, const unsigned long long id,
                unsigned long long timestamp, unsigned int transport)
{
    virAdmClientPtr ret = NULL;

    if (virDataTypesInitialize() < 0)
        goto error;

    if (!(ret = virObjectNew(virAdmClientClass)))
        goto error;

    ret->id = id;
    ret->timestamp = timestamp;
    ret->transport = transport;
    ret->srv = virObjectRef(srv);

    return ret;
 error:
    virObjectUnref(ret);
    return NULL;
}

static void
virAdmClientDispose(void *obj)
{
    virAdmClientPtr clt = obj;
    VIR_DEBUG("release client clt=%p, id=%llu", clt, clt->id);

    virObjectUnref(clt->srv);
}
