/*
 * datatypes.h: management of structs for public data types
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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
#include <unistd.h>

#include "datatypes.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "uuid.h"
#include "util.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virLibConnError(code, ...)                                \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/************************************************************************
 *									*
 *			Domain and Connections allocations		*
 *									*
 ************************************************************************/


/**
 * virGetConnect:
 *
 * Allocates a new hypervisor connection structure
 *
 * Returns a new pointer or NULL in case of error.
 */
virConnectPtr
virGetConnect(void) {
    virConnectPtr ret;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        goto failed;
    }
    if (virMutexInit(&ret->lock) < 0) {
        VIR_FREE(ret);
        goto failed;
    }

    ret->magic = VIR_CONNECT_MAGIC;
    ret->driver = NULL;
    ret->networkDriver = NULL;
    ret->privateData = NULL;
    ret->networkPrivateData = NULL;
    ret->interfacePrivateData = NULL;

    ret->refs = 1;
    return ret;

failed:
    if (ret != NULL) {
        virMutexDestroy(&ret->lock);
        VIR_FREE(ret);
    }
    return NULL;
}

/**
 * virReleaseConnect:
 * @conn: the hypervisor connection to release
 *
 * Unconditionally release all memory associated with a connection.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The connection obj must not
 * be used once this method returns.
 */
static void
virReleaseConnect(virConnectPtr conn) {
    VIR_DEBUG("release connection %p", conn);

    /* make sure to release the connection lock before we call the
     * close callbacks, otherwise we will deadlock if an error
     * is raised by any of the callbacks */
    virMutexUnlock(&conn->lock);

    if (conn->networkDriver)
        conn->networkDriver->close(conn);
    if (conn->interfaceDriver)
        conn->interfaceDriver->close(conn);
    if (conn->storageDriver)
        conn->storageDriver->close(conn);
    if (conn->deviceMonitor)
        conn->deviceMonitor->close(conn);
    if (conn->secretDriver)
        conn->secretDriver->close(conn);
    if (conn->nwfilterDriver)
        conn->nwfilterDriver->close(conn);
    if (conn->driver)
        conn->driver->close(conn);

    virMutexLock(&conn->lock);

    virResetError(&conn->err);

    virURIFree(conn->uri);

    virMutexUnlock(&conn->lock);
    virMutexDestroy(&conn->lock);
    VIR_FREE(conn);
}

/**
 * virUnrefConnect:
 * @conn: the hypervisor connection to unreference
 *
 * Unreference the connection. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefConnect(virConnectPtr conn) {
    int refs;

    if ((!VIR_IS_CONNECT(conn))) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return -1;
    }
    virMutexLock(&conn->lock);
    VIR_DEBUG("unref connection %p %d", conn, conn->refs);
    conn->refs--;
    refs = conn->refs;
    if (refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return 0;
    }
    virMutexUnlock(&conn->lock);
    return refs;
}

/**
 * virGetDomain:
 * @conn: the hypervisor connection
 * @name: pointer to the domain name
 * @uuid: pointer to the uuid
 *
 * Lookup if the domain is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefDomain() is needed to not leak data.
 *
 * Returns a pointer to the domain, or NULL in case of failure
 */
virDomainPtr
virGetDomain(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virDomainPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    if (uuid == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing uuid"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_DOMAIN_MAGIC;
    ret->conn = conn;
    ret->id = -1;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}

/**
 * virReleaseDomain:
 * @domain: the domain to release
 *
 * Unconditionally release all memory associated with a domain.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The domain obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseDomain(virDomainPtr domain) {
    virConnectPtr conn = domain->conn;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(domain->uuid, uuidstr);
    VIR_DEBUG("release domain %p %s %s", domain, domain->name, uuidstr);

    domain->magic = -1;
    domain->id = -1;
    VIR_FREE(domain->name);
    VIR_FREE(domain);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefDomain:
 * @domain: the domain to unreference
 *
 * Unreference the domain. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefDomain(virDomainPtr domain) {
    int refs;

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("bad domain or no connection"));
        return -1;
    }
    virMutexLock(&domain->conn->lock);
    VIR_DEBUG("unref domain %p %s %d", domain, domain->name, domain->refs);
    domain->refs--;
    refs = domain->refs;
    if (refs == 0) {
        virReleaseDomain(domain);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&domain->conn->lock);
    return refs;
}

/**
 * virGetNetwork:
 * @conn: the hypervisor connection
 * @name: pointer to the network name
 * @uuid: pointer to the uuid
 *
 * Lookup if the network is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefNetwork() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virNetworkPtr
virGetNetwork(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virNetworkPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    if (uuid == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing uuid"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_NETWORK_MAGIC;
    ret->conn = conn;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}

/**
 * virReleaseNetwork:
 * @network: the network to release
 *
 * Unconditionally release all memory associated with a network.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The network obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseNetwork(virNetworkPtr network) {
    virConnectPtr conn = network->conn;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(network->uuid, uuidstr);
    VIR_DEBUG("release network %p %s %s", network, network->name, uuidstr);

    network->magic = -1;
    VIR_FREE(network->name);
    VIR_FREE(network);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefNetwork:
 * @network: the network to unreference
 *
 * Unreference the network. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefNetwork(virNetworkPtr network) {
    int refs;

    if (!VIR_IS_CONNECTED_NETWORK(network)) {
        virLibConnError(VIR_ERR_INVALID_ARG,
                        _("bad network or no connection"));
        return -1;
    }
    virMutexLock(&network->conn->lock);
    VIR_DEBUG("unref network %p %s %d", network, network->name, network->refs);
    network->refs--;
    refs = network->refs;
    if (refs == 0) {
        virReleaseNetwork(network);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&network->conn->lock);
    return refs;
}


/**
 * virGetInterface:
 * @conn: the hypervisor connection
 * @name: pointer to the interface name
 * @mac: pointer to the mac
 *
 * Lookup if the interface is already registered for that connection,
 * if yes return a new pointer to it (possibly updating the MAC
 * address), if no allocate a new structure, and register it in the
 * table. In any case a corresponding call to virUnrefInterface() is
 * needed to not leak data.
 *
 * Returns a pointer to the interface, or NULL in case of failure
 */
virInterfacePtr
virGetInterface(virConnectPtr conn, const char *name, const char *mac) {
    virInterfacePtr ret = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }

    /* a NULL mac from caller is okay. Treat it as blank */
    if (mac == NULL)
       mac = "";

    virMutexLock(&conn->lock);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->mac = strdup(mac);
    if (ret->mac == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }

    ret->magic = VIR_INTERFACE_MAGIC;
    ret->conn = conn;

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret->mac);
        VIR_FREE(ret);
    }
    return NULL;
}

/**
 * virReleaseInterface:
 * @interface: the interface to release
 *
 * Unconditionally release all memory associated with an interface.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The interface obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseInterface(virInterfacePtr iface) {
    virConnectPtr conn = iface->conn;
    VIR_DEBUG("release interface %p %s", iface, iface->name);

    iface->magic = -1;
    VIR_FREE(iface->name);
    VIR_FREE(iface->mac);
    VIR_FREE(iface);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefInterface:
 * @interface: the interface to unreference
 *
 * Unreference the interface. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefInterface(virInterfacePtr iface) {
    int refs;

    if (!VIR_IS_CONNECTED_INTERFACE(iface)) {
        virLibConnError(VIR_ERR_INVALID_ARG,
                        _("bad interface or no connection"));
        return -1;
    }
    virMutexLock(&iface->conn->lock);
    VIR_DEBUG("unref interface %p %s %d", iface, iface->name, iface->refs);
    iface->refs--;
    refs = iface->refs;
    if (refs == 0) {
        virReleaseInterface(iface);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&iface->conn->lock);
    return refs;
}


/**
 * virGetStoragePool:
 * @conn: the hypervisor connection
 * @name: pointer to the storage pool name
 * @uuid: pointer to the uuid
 *
 * Lookup if the storage pool is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefStoragePool() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virStoragePoolPtr
virGetStoragePool(virConnectPtr conn, const char *name,
                  const unsigned char *uuid) {
    virStoragePoolPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    if (uuid == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing uuid"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_STORAGE_POOL_MAGIC;
    ret->conn = conn;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}


/**
 * virReleaseStoragePool:
 * @pool: the pool to release
 *
 * Unconditionally release all memory associated with a pool.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The pool obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseStoragePool(virStoragePoolPtr pool) {
    virConnectPtr conn = pool->conn;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(pool->uuid, uuidstr);
    VIR_DEBUG("release pool %p %s %s", pool, pool->name, uuidstr);

    pool->magic = -1;
    VIR_FREE(pool->name);
    VIR_FREE(pool);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefStoragePool:
 * @pool: the pool to unreference
 *
 * Unreference the pool. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefStoragePool(virStoragePoolPtr pool) {
    int refs;

    if (!VIR_IS_CONNECTED_STORAGE_POOL(pool)) {
        virLibConnError(VIR_ERR_INVALID_ARG,
                        _("bad storage pool or no connection"));
        return -1;
    }
    virMutexLock(&pool->conn->lock);
    VIR_DEBUG("unref pool %p %s %d", pool, pool->name, pool->refs);
    pool->refs--;
    refs = pool->refs;
    if (refs == 0) {
        virReleaseStoragePool(pool);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&pool->conn->lock);
    return refs;
}


/**
 * virGetStorageVol:
 * @conn: the hypervisor connection
 * @pool: pool owning the volume
 * @name: pointer to the storage vol name
 * @key: pointer to unique key of the volume
 *
 * Lookup if the storage vol is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefStorageVol() is needed to not leak data.
 *
 * Returns a pointer to the storage vol, or NULL in case of failure
 */
virStorageVolPtr
virGetStorageVol(virConnectPtr conn, const char *pool, const char *name,
                 const char *key) {
    virStorageVolPtr ret = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    if (key == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing key"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->pool = strdup(pool);
    if (ret->pool == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->key = strdup(key);
    if (ret->key == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_STORAGE_VOL_MAGIC;
    ret->conn = conn;

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->key);
        VIR_FREE(ret->name);
        VIR_FREE(ret->pool);
        VIR_FREE(ret);
    }
    return NULL;
}


/**
 * virReleaseStorageVol:
 * @vol: the vol to release
 *
 * Unconditionally release all memory associated with a vol.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The vol obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseStorageVol(virStorageVolPtr vol) {
    virConnectPtr conn = vol->conn;
    VIR_DEBUG("release vol %p %s", vol, vol->name);

    vol->magic = -1;
    VIR_FREE(vol->key);
    VIR_FREE(vol->name);
    VIR_FREE(vol->pool);
    VIR_FREE(vol);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefStorageVol:
 * @vol: the vol to unreference
 *
 * Unreference the vol. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefStorageVol(virStorageVolPtr vol) {
    int refs;

    if (!VIR_IS_CONNECTED_STORAGE_VOL(vol)) {
        virLibConnError(VIR_ERR_INVALID_ARG,
                        _("bad storage volume or no connection"));
        return -1;
    }
    virMutexLock(&vol->conn->lock);
    VIR_DEBUG("unref vol %p %s %d", vol, vol->name, vol->refs);
    vol->refs--;
    refs = vol->refs;
    if (refs == 0) {
        virReleaseStorageVol(vol);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&vol->conn->lock);
    return refs;
}


/**
 * virGetNodeDevice:
 * @conn: the hypervisor connection
 * @name: device name (unique on node)
 *
 * Lookup if the device is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefNodeDevice() is needed to not leak data.
 *
 * Returns a pointer to the node device, or NULL in case of failure
 */
virNodeDevicePtr
virGetNodeDevice(virConnectPtr conn, const char *name)
{
    virNodeDevicePtr ret = NULL;

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_NODE_DEVICE_MAGIC;
    ret->conn = conn;
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}


/**
 * virReleaseNodeDevice:
 * @dev: the dev to release
 *
 * Unconditionally release all memory associated with a dev.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The dev obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseNodeDevice(virNodeDevicePtr dev) {
    virConnectPtr conn = dev->conn;
    VIR_DEBUG("release dev %p %s", dev, dev->name);

    dev->magic = -1;
    VIR_FREE(dev->name);
    VIR_FREE(dev->parent);
    VIR_FREE(dev);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefNodeDevice:
 * @dev: the dev to unreference
 *
 * Unreference the dev. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefNodeDevice(virNodeDevicePtr dev) {
    int refs;

    virMutexLock(&dev->conn->lock);
    VIR_DEBUG("unref dev %p %s %d", dev, dev->name, dev->refs);
    dev->refs--;
    refs = dev->refs;
    if (refs == 0) {
        virReleaseNodeDevice(dev);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&dev->conn->lock);
    return refs;
}


/**
 * virGetSecret:
 * @conn: the hypervisor connection
 * @uuid: secret UUID
 *
 * Lookup if the secret is already registered for that connection, if so return
 * a pointer to it, otherwise allocate a new structure, and register it in the
 * table. In any case a corresponding call to virUnrefSecret() is needed to not
 * leak data.
 *
 * Returns a pointer to the secret, or NULL in case of failure
 */
virSecretPtr
virGetSecret(virConnectPtr conn, const unsigned char *uuid,
             int usageType, const char *usageID)
{
    virSecretPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (uuid == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing uuid"));
        return NULL;
    }
    if (usageID == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing usageID"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_SECRET_MAGIC;
    ret->conn = conn;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);
    ret->usageType = usageType;
    if (!(ret->usageID = strdup(usageID))) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->usageID);
        VIR_FREE(ret);
    }
    return NULL;
}

/**
 * virReleaseSecret:
 * @secret: the secret to release
 *
 * Unconditionally release all memory associated with a secret.  The conn.lock
 * mutex must be held prior to calling this, and will be released prior to this
 * returning. The secret obj must not be used once this method returns.
 *
 * It will also unreference the associated connection object, which may also be
 * released if its ref count hits zero.
 */
static void
virReleaseSecret(virSecretPtr secret) {
    virConnectPtr conn = secret->conn;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(secret->uuid, uuidstr);
    VIR_DEBUG("release secret %p %s", secret, uuidstr);

    VIR_FREE(secret->usageID);
    secret->magic = -1;
    VIR_FREE(secret);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}

/**
 * virUnrefSecret:
 * @secret: the secret to unreference
 *
 * Unreference the secret. If the use count drops to zero, the structure is
 * actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefSecret(virSecretPtr secret) {
    int refs;

    if (!VIR_IS_CONNECTED_SECRET(secret)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("bad secret or no connection"));
        return -1;
    }
    virMutexLock(&secret->conn->lock);
    VIR_DEBUG("unref secret %p %p %d", secret, secret->uuid, secret->refs);
    secret->refs--;
    refs = secret->refs;
    if (refs == 0) {
        virReleaseSecret(secret);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&secret->conn->lock);
    return refs;
}

virStreamPtr virGetStream(virConnectPtr conn) {
    virStreamPtr ret = NULL;

    virMutexLock(&conn->lock);

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_STREAM_MAGIC;
    ret->conn = conn;
    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    virMutexUnlock(&conn->lock);
    VIR_FREE(ret);
    return NULL;
}

static void
virReleaseStream(virStreamPtr st) {
    virConnectPtr conn = st->conn;
    VIR_DEBUG("release dev %p", st);

    st->magic = -1;
    VIR_FREE(st);

    VIR_DEBUG("unref connection %p %d", conn, conn->refs);
    conn->refs--;
    if (conn->refs == 0) {
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return;
    }

    virMutexUnlock(&conn->lock);
}

int virUnrefStream(virStreamPtr st) {
    int refs;

    virMutexLock(&st->conn->lock);
    VIR_DEBUG("unref stream %p %d", st, st->refs);
    st->refs--;
    refs = st->refs;
    if (refs == 0) {
        virReleaseStream(st);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&st->conn->lock);
    return refs;
}


/**
 * virGetNWFilter:
 * @conn: the hypervisor connection
 * @name: pointer to the network filter pool name
 * @uuid: pointer to the uuid
 *
 * Lookup if the network filter is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virUnrefNWFilter() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virNWFilterPtr
virGetNWFilter(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virNWFilterPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("no connection"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    if (uuid == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing uuid"));
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_NWFILTER_MAGIC;
    ret->conn = conn;
    memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

    conn->refs++;
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}


/**
 * virReleaseNWFilter:
 * @nwfilter: the nwfilter to release
 *
 * Unconditionally release all memory associated with a nwfilter.
 * The conn.lock mutex must be held prior to calling this, and will
 * be released prior to this returning. The nwfilter obj must not
 * be used once this method returns.
 *
 * It will also unreference the associated connection object,
 * which may also be released if its ref count hits zero.
 */
static void
virReleaseNWFilter(virNWFilterPtr nwfilter)
{
    virConnectPtr conn = nwfilter->conn;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(nwfilter->uuid, uuidstr);
    VIR_DEBUG("release nwfilter %p %s %s", nwfilter, nwfilter->name, uuidstr);

    nwfilter->magic = -1;
    VIR_FREE(nwfilter->name);
    VIR_FREE(nwfilter);

    if (conn) {
        VIR_DEBUG("unref connection %p %d", conn, conn->refs);
        conn->refs--;
        if (conn->refs == 0) {
            virReleaseConnect(conn);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&conn->lock);
    }
}


/**
 * virUnrefNWFilter:
 * @nwfilter: the nwfilter to unreference
 *
 * Unreference the networkf itler. If the use count drops to zero, the
 * structure is actually freed.
 *
 * Returns the reference count or -1 in case of failure.
 */
int
virUnrefNWFilter(virNWFilterPtr nwfilter)
{
    int refs;

    if (!VIR_IS_CONNECTED_NWFILTER(nwfilter)) {
        virLibConnError(VIR_ERR_INVALID_ARG,
                        _("bad nwfilter or no connection"));
        return -1;
    }
    virMutexLock(&nwfilter->conn->lock);
    VIR_DEBUG("unref nwfilter %p %s %d", nwfilter, nwfilter->name,
              nwfilter->refs);
    nwfilter->refs--;
    refs = nwfilter->refs;
    if (refs == 0) {
        virReleaseNWFilter(nwfilter);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&nwfilter->conn->lock);
    return refs;
}


virDomainSnapshotPtr
virGetDomainSnapshot(virDomainPtr domain, const char *name)
{
    virDomainSnapshotPtr ret = NULL;

    if (!VIR_IS_DOMAIN(domain)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("bad domain"));
        return NULL;
    }
    if (name == NULL) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("missing name"));
        return NULL;
    }
    virMutexLock(&domain->conn->lock);

    if (VIR_ALLOC(ret) < 0) {
        virMutexUnlock(&domain->conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->name = strdup(name);
    if (ret->name == NULL) {
        virMutexUnlock(&domain->conn->lock);
        virReportOOMError();
        goto error;
    }
    ret->magic = VIR_SNAPSHOT_MAGIC;
    ret->domain = domain;

    domain->refs++;
    ret->refs++;
    virMutexUnlock(&domain->conn->lock);
    return ret;

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return NULL;
}


static void
virReleaseDomainSnapshot(virDomainSnapshotPtr snapshot)
{
    virDomainPtr domain = snapshot->domain;
    VIR_DEBUG("release snapshot %p %s", snapshot, snapshot->name);

    snapshot->magic = -1;
    VIR_FREE(snapshot->name);
    VIR_FREE(snapshot);

    if (domain) {
        VIR_DEBUG("unref domain %p %d", domain, domain->refs);
        domain->refs--;
        if (domain->refs == 0) {
            virReleaseDomain(domain);
            /* Already unlocked mutex */
            return;
        }
        virMutexUnlock(&domain->conn->lock);
    }
}

int
virUnrefDomainSnapshot(virDomainSnapshotPtr snapshot)
{
    int refs;

    if (!VIR_IS_DOMAIN_SNAPSHOT(snapshot)) {
        virLibConnError(VIR_ERR_INVALID_ARG, _("not a snapshot"));
        return -1;
    }

    virMutexLock(&snapshot->domain->conn->lock);
    VIR_DEBUG("unref snapshot %p %s %d", snapshot, snapshot->name, snapshot->refs);
    snapshot->refs--;
    refs = snapshot->refs;
    if (refs == 0) {
        virReleaseDomainSnapshot(snapshot);
        /* Already unlocked mutex */
        return 0;
    }

    virMutexUnlock(&snapshot->domain->conn->lock);
    return refs;
}
