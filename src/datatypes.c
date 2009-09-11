/*
 * datatypes.h: management of structs for public data types
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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

#include "datatypes.h"
#include "virterror_internal.h"
#include "logging.h"
#include "memory.h"
#include "uuid.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virLibConnError(conn, code, fmt...)                       \
    virReportErrorHelper(conn, VIR_FROM_THIS, code, __FILE__,     \
                         __FUNCTION__, __LINE__, fmt)

/************************************************************************
 *									*
 *			Domain and Connections allocations		*
 *									*
 ************************************************************************/

/**
 * virDomainFreeName:
 * @domain: a domain object
 *
 * Destroy the domain object, this is just used by the domain hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virDomainFreeName(virDomainPtr domain, const char *name ATTRIBUTE_UNUSED)
{
    return (virUnrefDomain(domain));
}

/**
 * virNetworkFreeName:
 * @network: a network object
 *
 * Destroy the network object, this is just used by the network hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virNetworkFreeName(virNetworkPtr network, const char *name ATTRIBUTE_UNUSED)
{
    return (virUnrefNetwork(network));
}

/**
 * virInterfaceFreeName:
 * @interface: a interface object
 *
 * Destroy the interface object, this is just used by the interface hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virInterfaceFreeName(virInterfacePtr iface, const char *name ATTRIBUTE_UNUSED)
{
    return (virUnrefInterface(iface));
}

/**
 * virStoragePoolFreeName:
 * @pool: a pool object
 *
 * Destroy the pool object, this is just used by the pool hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virStoragePoolFreeName(virStoragePoolPtr pool, const char *name ATTRIBUTE_UNUSED)
{
    return (virUnrefStoragePool(pool));
}

/**
 * virStorageVolFreeName:
 * @vol: a vol object
 *
 * Destroy the vol object, this is just used by the vol hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static int
virStorageVolFreeName(virStorageVolPtr vol, const char *name ATTRIBUTE_UNUSED)
{
    return (virUnrefStorageVol(vol));
}

/**
 * virSecretFreeName:
 * @secret_: a secret object
 *
 * Destroy the secret object, this is just used by the secret hash callback.
 *
 * Returns 0 in case of success and -1 in case of failure.
 */
static void
virSecretFreeName(void *secret_, const char *name ATTRIBUTE_UNUSED)
{
    virSecretPtr secret;

    secret = secret_;
    virUnrefSecret(secret);
}

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
        virReportOOMError(NULL);
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
    ret->domains = virHashCreate(20);
    if (ret->domains == NULL)
        goto failed;
    ret->networks = virHashCreate(20);
    if (ret->networks == NULL)
        goto failed;
    ret->interfaces = virHashCreate(20);
    if (ret->interfaces == NULL)
        goto failed;
    ret->storagePools = virHashCreate(20);
    if (ret->storagePools == NULL)
        goto failed;
    ret->storageVols = virHashCreate(20);
    if (ret->storageVols == NULL)
        goto failed;
    ret->nodeDevices = virHashCreate(256);
    if (ret->nodeDevices == NULL)
        goto failed;
    ret->secrets = virHashCreate(20);
    if (ret->secrets == NULL)
        goto failed;

    ret->refs = 1;
    return(ret);

failed:
    if (ret != NULL) {
        if (ret->domains != NULL)
            virHashFree(ret->domains, (virHashDeallocator) virDomainFreeName);
        if (ret->networks != NULL)
            virHashFree(ret->networks, (virHashDeallocator) virNetworkFreeName);
        if (ret->interfaces != NULL)
           virHashFree(ret->interfaces, (virHashDeallocator) virInterfaceFreeName);
        if (ret->storagePools != NULL)
            virHashFree(ret->storagePools, (virHashDeallocator) virStoragePoolFreeName);
        if (ret->storageVols != NULL)
            virHashFree(ret->storageVols, (virHashDeallocator) virStorageVolFreeName);
        if (ret->nodeDevices != NULL)
            virHashFree(ret->nodeDevices, (virHashDeallocator) virNodeDeviceFree);
        if (ret->secrets != NULL)
            virHashFree(ret->secrets, virSecretFreeName);

        virMutexDestroy(&ret->lock);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release connection %p", conn);
    if (conn->domains != NULL)
        virHashFree(conn->domains, (virHashDeallocator) virDomainFreeName);
    if (conn->networks != NULL)
        virHashFree(conn->networks, (virHashDeallocator) virNetworkFreeName);
    if (conn->interfaces != NULL)
        virHashFree(conn->interfaces, (virHashDeallocator) virInterfaceFreeName);
    if (conn->storagePools != NULL)
        virHashFree(conn->storagePools, (virHashDeallocator) virStoragePoolFreeName);
    if (conn->storageVols != NULL)
        virHashFree(conn->storageVols, (virHashDeallocator) virStorageVolFreeName);
    if (conn->nodeDevices != NULL)
        virHashFree(conn->nodeDevices, (virHashDeallocator) virNodeDeviceFree);
    if (conn->secrets != NULL)
        virHashFree(conn->secrets, virSecretFreeName);

    virResetError(&conn->err);

    xmlFreeURI(conn->uri);

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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&conn->lock);
    DEBUG("unref connection %p %d", conn, conn->refs);
    conn->refs--;
    refs = conn->refs;
    if (refs == 0) {
        /* make sure to release the connection lock before we call the
         * close() callbacks, otherwise we will deadlock if an error
         * is raised by any of the callbacks
         */
        virMutexUnlock(&conn->lock);
        if (conn->networkDriver)
            conn->networkDriver->close (conn);
        if (conn->interfaceDriver)
            conn->interfaceDriver->close (conn);
        if (conn->storageDriver)
            conn->storageDriver->close (conn);
        if (conn->deviceMonitor)
            conn->deviceMonitor->close (conn);
        if (conn->secretDriver)
            conn->secretDriver->close (conn);
        if (conn->driver)
            conn->driver->close (conn);

        /* reacquire the connection lock since virReleaseConnect expects
         * it to already be held
         */
        virMutexLock(&conn->lock);
        virReleaseConnect(conn);
        /* Already unlocked mutex */
        return (0);
    }
    virMutexUnlock(&conn->lock);
    return (refs);
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

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virDomainPtr) virHashLookup(conn->domains, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->magic = VIR_DOMAIN_MAGIC;
        ret->conn = conn;
        ret->id = -1;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->domains, name, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add domain to connection hash table"));
            goto error;
        }
        conn->refs++;
        DEBUG("New hash entry %p", ret);
    } else {
        DEBUG("Existing hash entry %p: refs now %d", ret, ret->refs+1);
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release domain %p %s", domain, domain->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->domains, domain->name, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("domain missing from connection hash table"));
        conn = NULL;
    }

    domain->magic = -1;
    domain->id = -1;
    VIR_FREE(domain->name);
    VIR_FREE(domain);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&domain->conn->lock);
    DEBUG("unref domain %p %s %d", domain, domain->name, domain->refs);
    domain->refs--;
    refs = domain->refs;
    if (refs == 0) {
        virReleaseDomain(domain);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&domain->conn->lock);
    return (refs);
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

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virNetworkPtr) virHashLookup(conn->networks, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->magic = VIR_NETWORK_MAGIC;
        ret->conn = conn;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->networks, name, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add network to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release network %p %s", network, network->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->networks, network->name, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("network missing from connection hash table"));
        conn = NULL;
    }

    network->magic = -1;
    VIR_FREE(network->name);
    VIR_FREE(network);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&network->conn->lock);
    DEBUG("unref network %p %s %d", network, network->name, network->refs);
    network->refs--;
    refs = network->refs;
    if (refs == 0) {
        virReleaseNetwork(network);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&network->conn->lock);
    return (refs);
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

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (mac == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    ret = (virInterfacePtr) virHashLookup(conn->interfaces, name);

    if (ret != NULL) {
        if (STRCASENEQ(ret->mac, mac)) {
            /*
             * If the mac address has changed, try to modify it in
             * place, which will only work if the new mac is the
             * same length as, or shorter than, the old mac.
             */
            size_t newmaclen = strlen(mac);
            size_t oldmaclen = strlen(ret->mac);
            if (newmaclen <= oldmaclen) {
                strcpy(ret->mac, mac);
            } else {
                /*
                 * If it's longer, we're kind of screwed, because we
                 * can't add a new hashtable entry (it would clash
                 * with the existing entry of same name), and we can't
                 * free/re-alloc the existing entry's mac, as some
                 * other thread may already be using the existing mac
                 * pointer.  Fortunately, this should never happen,
                 * since the length of the mac address for any
                 * interface is determined by the type of the
                 * interface, and that is unlikely to change.
                 */
                virMutexUnlock(&conn->lock);
                virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
_("Failed to change interface mac address from %s to %s due to differing lengths."),
                                ret->mac, mac);
                ret = NULL;
                goto error;
            }
        }
    } else {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->mac = strdup(mac);
        if (ret->mac == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }

        ret->magic = VIR_INTERFACE_MAGIC;
        ret->conn = conn;

        if (virHashAddEntry(conn->interfaces, name, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add interface to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

 error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret->mac);
        VIR_FREE(ret);
    }
    return(NULL);
}

/**
 * virReleaseInterface:
 * @interface: the interface to release
 *
 * Unconditionally release all memory associated with a interface.
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
    DEBUG("release interface %p %s", iface, iface->name);

    if (virHashRemoveEntry(conn->interfaces, iface->name, NULL) < 0) {
        /* unlock before reporting error because error report grabs lock */
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("interface missing from connection hash table"));
        /* don't decr the conn refct if we weren't connected to it */
        conn = NULL;
    }

    iface->magic = -1;
    VIR_FREE(iface->name);
    VIR_FREE(iface->mac);
    VIR_FREE(iface);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&iface->conn->lock);
    DEBUG("unref interface %p %s %d", iface, iface->name, iface->refs);
    iface->refs--;
    refs = iface->refs;
    if (refs == 0) {
        virReleaseInterface(iface);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&iface->conn->lock);
    return (refs);
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
 * virFreeStoragePool() is needed to not leak data.
 *
 * Returns a pointer to the network, or NULL in case of failure
 */
virStoragePoolPtr
virGetStoragePool(virConnectPtr conn, const char *name, const unsigned char *uuid) {
    virStoragePoolPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (uuid == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    /* TODO search by UUID first as they are better differenciators */

    ret = (virStoragePoolPtr) virHashLookup(conn->storagePools, name);
    /* TODO check the UUID */
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->magic = VIR_STORAGE_POOL_MAGIC;
        ret->conn = conn;
        if (uuid != NULL)
            memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);

        if (virHashAddEntry(conn->storagePools, name, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add storage pool to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release pool %p %s", pool, pool->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->storagePools, pool->name, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("pool missing from connection hash table"));
        conn = NULL;
    }

    pool->magic = -1;
    VIR_FREE(pool->name);
    VIR_FREE(pool);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&pool->conn->lock);
    DEBUG("unref pool %p %s %d", pool, pool->name, pool->refs);
    pool->refs--;
    refs = pool->refs;
    if (refs == 0) {
        virReleaseStoragePool(pool);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&pool->conn->lock);
    return (refs);
}


/**
 * virGetStorageVol:
 * @conn: the hypervisor connection
 * @pool: pool owning the volume
 * @name: pointer to the storage vol name
 * @uuid: pointer to the uuid
 *
 * Lookup if the storage vol is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virFreeStorageVol() is needed to not leak data.
 *
 * Returns a pointer to the storage vol, or NULL in case of failure
 */
virStorageVolPtr
virGetStorageVol(virConnectPtr conn, const char *pool, const char *name, const char *key) {
    virStorageVolPtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL) || (key == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    ret = (virStorageVolPtr) virHashLookup(conn->storageVols, key);
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->pool = strdup(pool);
        if (ret->pool == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        strncpy(ret->key, key, sizeof(ret->key)-1);
        ret->key[sizeof(ret->key)-1] = '\0';
        ret->magic = VIR_STORAGE_VOL_MAGIC;
        ret->conn = conn;

        if (virHashAddEntry(conn->storageVols, key, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add storage vol to connection hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret->pool);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release vol %p %s", vol, vol->name);

    /* TODO search by UUID first as they are better differenciators */
    if (virHashRemoveEntry(conn->storageVols, vol->key, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("vol missing from connection hash table"));
        conn = NULL;
    }

    vol->magic = -1;
    VIR_FREE(vol->name);
    VIR_FREE(vol->pool);
    VIR_FREE(vol);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(-1);
    }
    virMutexLock(&vol->conn->lock);
    DEBUG("unref vol %p %s %d", vol, vol->name, vol->refs);
    vol->refs--;
    refs = vol->refs;
    if (refs == 0) {
        virReleaseStorageVol(vol);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&vol->conn->lock);
    return (refs);
}


/**
 * virGetNodeDevice:
 * @conn: the hypervisor connection
 * @name: device name (unique on node)
 *
 * Lookup if the device is already registered for that connection,
 * if yes return a new pointer to it, if no allocate a new structure,
 * and register it in the table. In any case a corresponding call to
 * virFreeNodeDevice() is needed to not leak data.
 *
 * Returns a pointer to the node device, or NULL in case of failure
 */
virNodeDevicePtr
virGetNodeDevice(virConnectPtr conn, const char *name)
{
    virNodeDevicePtr ret = NULL;

    if ((!VIR_IS_CONNECT(conn)) || (name == NULL)) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return(NULL);
    }
    virMutexLock(&conn->lock);

    ret = (virNodeDevicePtr) virHashLookup(conn->nodeDevices, name);
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->magic = VIR_NODE_DEVICE_MAGIC;
        ret->conn = conn;
        ret->name = strdup(name);
        if (ret->name == NULL) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }

        if (virHashAddEntry(conn->nodeDevices, name, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add node dev to conn hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return(ret);

error:
    if (ret != NULL) {
        VIR_FREE(ret->name);
        VIR_FREE(ret);
    }
    return(NULL);
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
    DEBUG("release dev %p %s", dev, dev->name);

    if (virHashRemoveEntry(conn->nodeDevices, dev->name, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("dev missing from connection hash table"));
        conn = NULL;
    }

    dev->magic = -1;
    VIR_FREE(dev->name);
    VIR_FREE(dev->parent);
    VIR_FREE(dev);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
    DEBUG("unref dev %p %s %d", dev, dev->name, dev->refs);
    dev->refs--;
    refs = dev->refs;
    if (refs == 0) {
        virReleaseNodeDevice(dev);
        /* Already unlocked mutex */
        return (0);
    }

    virMutexUnlock(&dev->conn->lock);
    return (refs);
}

/**
 * virGetSecret:
 * @conn: the hypervisor connection
 * @uuid: secret UUID
 *
 * Lookup if the secret is already registered for that connection, if so return
 * a pointer to it, otherwise allocate a new structure, and register it in the
 * table. In any case a corresponding call to virFreeSecret() is needed to not
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

    if (!VIR_IS_CONNECT(conn) || uuid == NULL || usageID == NULL) {
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return NULL;
    }
    virMutexLock(&conn->lock);

    virUUIDFormat(uuid, uuidstr);

    ret = virHashLookup(conn->secrets, uuidstr);
    if (ret == NULL) {
        if (VIR_ALLOC(ret) < 0) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        ret->magic = VIR_SECRET_MAGIC;
        ret->conn = conn;
        memcpy(&(ret->uuid[0]), uuid, VIR_UUID_BUFLEN);
        ret->usageType = usageType;
        if (!(ret->usageID = strdup(usageID))) {
            virMutexUnlock(&conn->lock);
            virReportOOMError(conn);
            goto error;
        }
        if (virHashAddEntry(conn->secrets, uuidstr, ret) < 0) {
            virMutexUnlock(&conn->lock);
            virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                            "%s", _("failed to add secret to conn hash table"));
            goto error;
        }
        conn->refs++;
    }
    ret->refs++;
    virMutexUnlock(&conn->lock);
    return ret;

error:
    if (ret != NULL) {
        VIR_FREE(ret->usageID);
        VIR_FREE(ret->uuid);
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
    DEBUG("release secret %p %p", secret, secret->uuid);

    virUUIDFormat(secret->uuid, uuidstr);
    if (virHashRemoveEntry(conn->secrets, uuidstr, NULL) < 0) {
        virMutexUnlock(&conn->lock);
        virLibConnError(conn, VIR_ERR_INTERNAL_ERROR,
                        "%s", _("secret missing from connection hash table"));
        conn = NULL;
    }

    VIR_FREE(secret->usageID);
    secret->magic = -1;
    VIR_FREE(secret);

    if (conn) {
        DEBUG("unref connection %p %d", conn, conn->refs);
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
        virLibConnError(NULL, VIR_ERR_INVALID_ARG, __FUNCTION__);
        return -1;
    }
    virMutexLock(&secret->conn->lock);
    DEBUG("unref secret %p %p %d", secret, secret->uuid, secret->refs);
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
