/*
 * datatypes.h: management of structs for public data types
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

#ifndef LIBVIRT_DATATYPES_H
# define LIBVIRT_DATATYPES_H

# include "internal.h"

# include "driver.h"
# include "virthread.h"
# include "virobject.h"
# include "viruuid.h"

extern virClassPtr virConnectClass;
extern virClassPtr virDomainClass;
extern virClassPtr virDomainCheckpointClass;
extern virClassPtr virDomainSnapshotClass;
extern virClassPtr virInterfaceClass;
extern virClassPtr virNetworkClass;
extern virClassPtr virNodeDeviceClass;
extern virClassPtr virNWFilterClass;
extern virClassPtr virNWFilterBindingClass;
extern virClassPtr virSecretClass;
extern virClassPtr virStreamClass;
extern virClassPtr virStorageVolClass;
extern virClassPtr virStoragePoolClass;

extern virClassPtr virAdmConnectClass;
extern virClassPtr virAdmServerClass;
extern virClassPtr virAdmClientClass;

# define virCheckConnectReturn(obj, retval) \
    do { \
        if (!virObjectIsClass(obj, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckConnectGoto(obj, label) \
    do { \
        if (!virObjectIsClass(obj, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckDomainReturn(obj, retval) \
    do { \
        virDomainPtr _dom = (obj); \
        if (!virObjectIsClass(_dom, virDomainClass) || \
            !virObjectIsClass(_dom->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_DOM, VIR_ERR_INVALID_DOMAIN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckDomainGoto(obj, label) \
    do { \
        virDomainPtr _dom = (obj); \
        if (!virObjectIsClass(_dom, virDomainClass) || \
            !virObjectIsClass(_dom->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_DOM, VIR_ERR_INVALID_DOMAIN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckNetworkReturn(obj, retval) \
    do { \
        virNetworkPtr _net = (obj); \
        if (!virObjectIsClass(_net, virNetworkClass) || \
            !virObjectIsClass(_net->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NETWORK, \
                                 VIR_ERR_INVALID_NETWORK, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckNetworkGoto(obj, label) \
    do { \
        virNetworkPtr _net = (obj); \
        if (!virObjectIsClass(_net, virNetworkClass) || \
            !virObjectIsClass(_net->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NETWORK, \
                                 VIR_ERR_INVALID_NETWORK, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckInterfaceReturn(obj, retval) \
    do { \
        virInterfacePtr _iface = (obj); \
        if (!virObjectIsClass(_iface, virInterfaceClass) || \
            !virObjectIsClass(_iface->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_INTERFACE, \
                                 VIR_ERR_INVALID_INTERFACE, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckStoragePoolReturn(obj, retval) \
    do { \
        virStoragePoolPtr _pool = (obj); \
        if (!virObjectIsClass(_pool, virStoragePoolClass) || \
            !virObjectIsClass(_pool->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STORAGE, \
                                 VIR_ERR_INVALID_STORAGE_POOL, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckStoragePoolGoto(obj, label) \
    do { \
        virStoragePoolPtr _pool= (obj); \
        if (!virObjectIsClass(_pool, virStoragePoolClass) || \
            !virObjectIsClass(_pool->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STORAGE, \
                                 VIR_ERR_INVALID_STORAGE_POOL, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckStorageVolReturn(obj, retval) \
    do { \
        virStorageVolPtr _vol = (obj); \
        if (!virObjectIsClass(_vol, virStorageVolClass) || \
            !virObjectIsClass(_vol->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STORAGE, \
                                 VIR_ERR_INVALID_STORAGE_VOL, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckStorageVolGoto(obj, label) \
    do { \
        virStorageVolPtr _vol = (obj); \
        if (!virObjectIsClass(_vol, virStorageVolClass) || \
            !virObjectIsClass(_vol->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STORAGE, \
                                 VIR_ERR_INVALID_STORAGE_VOL, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckNodeDeviceReturn(obj, retval) \
    do { \
        virNodeDevicePtr _node = (obj); \
        if (!virObjectIsClass(_node, virNodeDeviceClass) || \
            !virObjectIsClass(_node->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NODEDEV, \
                                 VIR_ERR_INVALID_NODE_DEVICE, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckNodeDeviceGoto(obj, label) \
    do { \
        virNodeDevicePtr _dev= (obj); \
        if (!virObjectIsClass(_dev, virNodeDeviceClass) || \
            !virObjectIsClass(_dev->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NODEDEV, \
                                 VIR_ERR_INVALID_NODE_DEVICE, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckSecretReturn(obj, retval) \
    do { \
        virSecretPtr _secret = (obj); \
        if (!virObjectIsClass(_secret, virSecretClass) || \
            !virObjectIsClass(_secret->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_SECRET, \
                                 VIR_ERR_INVALID_SECRET, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckSecretGoto(obj, label) \
    do { \
        virSecretPtr _secret = (obj); \
        if (!virObjectIsClass(_secret, virSecretClass) || \
            !virObjectIsClass(_secret->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_SECRET, \
                                 VIR_ERR_INVALID_SECRET, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            goto label; \
        } \
    } while (0)

# define virCheckStreamReturn(obj, retval) \
    do { \
        virStreamPtr _st = (obj); \
        if (!virObjectIsClass(_st, virStreamClass) || \
            !virObjectIsClass(_st->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STREAMS, \
                                 VIR_ERR_INVALID_STREAM, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckStreamGoto(obj, label) \
    do { \
        virStreamPtr _st = (obj); \
        if (!virObjectIsClass(_st, virStreamClass) || \
            !virObjectIsClass(_st->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_STREAMS, \
                                 VIR_ERR_INVALID_STREAM, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckNWFilterReturn(obj, retval) \
    do { \
        virNWFilterPtr _nw = (obj); \
        if (!virObjectIsClass(_nw, virNWFilterClass) || \
            !virObjectIsClass(_nw->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NWFILTER, \
                                 VIR_ERR_INVALID_NWFILTER, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckNWFilterBindingReturn(obj, retval) \
    do { \
        virNWFilterBindingPtr _nw = (obj); \
        if (!virObjectIsClass(_nw, virNWFilterBindingClass) || \
            !virObjectIsClass(_nw->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_NWFILTER, \
                                 VIR_ERR_INVALID_NWFILTER_BINDING, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckDomainCheckpointReturn(obj, retval) \
    do { \
        virDomainCheckpointPtr _check = (obj); \
        if (!virObjectIsClass(_check, virDomainCheckpointClass) || \
            !virObjectIsClass(_check->domain, virDomainClass) || \
            !virObjectIsClass(_check->domain->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_DOMAIN_CHECKPOINT, \
                                 VIR_ERR_INVALID_DOMAIN_CHECKPOINT, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)

# define virCheckDomainSnapshotReturn(obj, retval) \
    do { \
        virDomainSnapshotPtr _snap = (obj); \
        if (!virObjectIsClass(_snap, virDomainSnapshotClass) || \
            !virObjectIsClass(_snap->domain, virDomainClass) || \
            !virObjectIsClass(_snap->domain->conn, virConnectClass)) { \
            virReportErrorHelper(VIR_FROM_DOMAIN_SNAPSHOT, \
                                 VIR_ERR_INVALID_DOMAIN_SNAPSHOT, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)


/* Helper macros to implement VIR_DOMAIN_DEBUG using just C99.  This
 * assumes you pass fewer than 15 arguments to VIR_DOMAIN_DEBUG, but
 * can easily be expanded if needed.
 *
 * Note that gcc provides extensions of "define a(b...) b" or
 * "define a(b,...) b,##__VA_ARGS__" as a means of eliding a comma
 * when no var-args are present, but we don't want to require gcc.
 */
# define VIR_ARG15(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, \
                   _11, _12, _13, _14, _15, ...) _15
# define VIR_HAS_COMMA(...) VIR_ARG15(__VA_ARGS__, \
                                      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0)

/* Form the name VIR_DOMAIN_DEBUG_[01], then call that macro,
 * according to how many arguments are present.  Two-phase due to
 * macro expansion rules.  */
# define VIR_DOMAIN_DEBUG_EXPAND(a, b, ...) \
    VIR_DOMAIN_DEBUG_PASTE(a, b, __VA_ARGS__)
# define VIR_DOMAIN_DEBUG_PASTE(a, b, ...) \
    a##b(__VA_ARGS__)

/* Internal use only, when VIR_DOMAIN_DEBUG has one argument.  */
# define VIR_DOMAIN_DEBUG_0(dom) \
    VIR_DOMAIN_DEBUG_2(dom, "%s", "")

/* Internal use only, when VIR_DOMAIN_DEBUG has three or more arguments.  */
# define VIR_DOMAIN_DEBUG_1(dom, fmt, ...) \
    VIR_DOMAIN_DEBUG_2(dom, ", " fmt, __VA_ARGS__)

/* Internal use only, with final format.  */
# define VIR_DOMAIN_DEBUG_2(dom, fmt, ...) \
    do { \
        char _uuidstr[VIR_UUID_STRING_BUFLEN]; \
        const char *_domname = NULL; \
 \
        if (!virObjectIsClass(dom, virDomainClass)) { \
            memset(_uuidstr, 0, sizeof(_uuidstr)); \
        } else { \
            virUUIDFormat((dom)->uuid, _uuidstr); \
            _domname = (dom)->name; \
        } \
 \
        VIR_DEBUG("dom=%p, (VM: name=%s, uuid=%s)" fmt, \
                  dom, NULLSTR(_domname), _uuidstr, __VA_ARGS__); \
    } while (0)

# define virCheckAdmConnectReturn(obj, retval) \
    do { \
        if (!virObjectIsClass(obj, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckAdmConnectGoto(obj, label) \
    do { \
        if (!virObjectIsClass(obj, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0)

# define virCheckAdmServerReturn(obj, retval) \
    do { \
        virAdmServerPtr _srv = (obj); \
        if (!virObjectIsClass(_srv, virAdmServerClass) || \
            !virObjectIsClass(_srv->conn, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckAdmServerGoto(obj, label) \
    do { \
        virAdmServerPtr _srv = (obj); \
        if (!virObjectIsClass(_srv, virAdmServerClass) || \
            !virObjectIsClass(_srv->conn, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0);

# define virCheckAdmClientReturn(obj, retval) \
    do { \
        virAdmClientPtr _clt = (obj); \
        if (!virObjectIsClass(_clt, virAdmClientClass) || \
            !virObjectIsClass(_clt->srv, virAdmServerClass) || \
            !virObjectIsClass(_clt->srv->conn, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            virDispatchError(NULL); \
            return retval; \
        } \
    } while (0)
# define virCheckAdmClientGoto(obj, label) \
    do { \
        virAdmClientPtr _clt = (obj); \
        if (!virObjectIsClass(_clt, virAdmClientClass) || \
            !virObjectIsClass(_clt->srv, virAdmServerClass) || \
            !virObjectIsClass(_clt->srv->conn, virAdmConnectClass)) { \
            virReportErrorHelper(VIR_FROM_THIS, VIR_ERR_INVALID_CONN, \
                                 __FILE__, __FUNCTION__, __LINE__, \
                                 __FUNCTION__); \
            goto label; \
        } \
    } while (0);

/**
 * VIR_DOMAIN_DEBUG:
 * @dom: domain
 * @fmt: optional format for additional information
 * @...: optional arguments corresponding to @fmt.
 */
# define VIR_DOMAIN_DEBUG(...) \
    VIR_DOMAIN_DEBUG_EXPAND(VIR_DOMAIN_DEBUG_, \
                            VIR_HAS_COMMA(__VA_ARGS__), \
                            __VA_ARGS__)


typedef struct _virConnectCloseCallbackData virConnectCloseCallbackData;
typedef virConnectCloseCallbackData *virConnectCloseCallbackDataPtr;
typedef struct _virAdmConnectCloseCallbackData virAdmConnectCloseCallbackData;
typedef virAdmConnectCloseCallbackData *virAdmConnectCloseCallbackDataPtr;

/**
 * Internal structures holding data related to connection close callbacks.
 */
struct _virConnectCloseCallbackData {
    virObjectLockable parent;

    virConnectPtr conn;
    virConnectCloseFunc callback;
    void *opaque;
    virFreeCallback freeCallback;
};

struct _virAdmConnectCloseCallbackData {
    virObjectLockable parent;

    virAdmConnectPtr conn;
    virAdmConnectCloseFunc callback;
    void *opaque;
    virFreeCallback freeCallback;
};

/**
 * _virConnect:
 *
 * Internal structure associated to a connection
 */
struct _virConnect {
    virObjectLockable parent;

    /* All the variables from here, until declared otherwise in one of
     * the following comments, are setup at time of connection open
     * and never changed since. Thus no need to lock when accessing
     * them.
     */
    unsigned int flags;     /* a set of connection flags */
    virURIPtr uri;          /* connection URI */

    /* The underlying hypervisor driver and network driver. */
    virHypervisorDriverPtr driver;
    virNetworkDriverPtr networkDriver;
    virInterfaceDriverPtr interfaceDriver;
    virStorageDriverPtr storageDriver;
    virNodeDeviceDriverPtr nodeDeviceDriver;
    virSecretDriverPtr secretDriver;
    virNWFilterDriverPtr nwfilterDriver;

    /* Private data pointer which can be used by domain driver as
     * it pleases.
     * NB: 'private' is a reserved word in C++.
     */
    void *            privateData;

    /*
     * Object lock must be acquired before accessing/changing any of
     * members following this point, or changing the ref count of any
     * virDomain/virNetwork object associated with this connection.
     */

    /* Per-connection error. */
    virError err;           /* the last error */
    virErrorFunc handler;   /* associated handler */
    void *userData;         /* the user data */
};

/**
 * _virAdmConnect:
 *
 * Internal structure associated to an admin connection
 */
struct _virAdmConnect {
    virObjectLockable parent;
    virURIPtr uri;

    void *privateData;
    virFreeCallback privateDataFreeFunc;

    /* Per-connection close callback */
    virAdmConnectCloseCallbackDataPtr closeCallback;
};

/**
 * _virAdmServer:
 *
 * Internal structure associated to a daemon server
 */
struct _virAdmServer {
    virObject parent;
    virAdmConnectPtr conn;          /* pointer back to the admin connection */
    char *name;                     /* the server external name */
};

/**
 * _virAdmClient:
 *
 * Internal structure associated to a client connected to daemon
 */
struct _virAdmClient {
    virObject parent;
    virAdmServerPtr srv;            /* pointer to the server client is
                                     * connected to, which also holds a
                                     * reference back to the admin connection
                                     */
    unsigned long long id;          /* client's ID */
    long long timestamp;            /* connection timestamp */
    unsigned int transport;         /* connection type as virClientTransport */
};

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the domain external name */
    int id;                              /* the domain ID */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the domain unique identifier */
};

/**
* _virNetwork:
*
* Internal structure associated to a domain
*/
struct _virNetwork {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network unique identifier */
};

/**
* _virInterface:
*
* Internal structure associated to a physical host interface
*/
struct _virInterface {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network external name */
    char *mac;                           /* the interface MAC address */
};

/**
* _virStoragePool:
*
* Internal structure associated to a storage pool
*/
struct _virStoragePool {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the storage pool external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the storage pool unique identifier */

    /* Private data pointer which can be used by driver as they wish.
     * Cleanup function pointer can be hooked to provide custom cleanup
     * operation.
     */
    void *privateData;
    virFreeCallback privateDataFreeFunc;
};

/**
* _virStorageVol:
*
* Internal structure associated to a storage volume
*/
struct _virStorageVol {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *pool;                          /* Pool name of owner */
    char *name;                          /* the storage vol external name */
    char *key;                           /* unique key for storage vol */

    /* Private data pointer which can be used by driver as they wish.
     * Cleanup function pointer can be hooked to provide custom cleanup
     * operation.
     */
    void *privateData;
    virFreeCallback privateDataFreeFunc;
};

/**
 * _virNodeDevice:
 *
 * Internal structure associated with a node device
 */
struct _virNodeDevice {
    virObject parent;
    virConnectPtr conn;                 /* pointer back to the connection */
    char *name;                         /* device name (unique on node) */
    char *parentName;                   /* parent device name */
};

/**
 * _virSecret:
 *
 * Internal structure associated with a secret
 */
struct _virSecret {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the secret unique identifier */
    int usageType;                       /* the type of usage */
    char *usageID;                       /* the usage's unique identifier */
};


typedef int (*virStreamAbortFunc)(virStreamPtr, void *opaque);
typedef int (*virStreamFinishFunc)(virStreamPtr, void *opaque);

/**
 * _virStream:
 *
 * Internal structure associated with an input stream
 */
struct _virStream {
    virObject parent;
    virConnectPtr conn;
    unsigned int flags;

    virStreamDriverPtr driver;
    void *privateData;
    virFreeCallback ff;
};


/**
 * _virDomainCheckpoint
 *
 * Internal structure associated with a domain checkpoint
 */
struct _virDomainCheckpoint {
    virObject parent;
    char *name;
    virDomainPtr domain;
};


/**
 * _virDomainSnapshot
 *
 * Internal structure associated with a domain snapshot
 */
struct _virDomainSnapshot {
    virObject parent;
    char *name;
    virDomainPtr domain;
};

/**
* _virNWFilter:
*
* Internal structure associated to a network filter
*/
struct _virNWFilter {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network filter external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network filter unique identifier */
};


/**
* _virNWFilterBinding:
*
* Internal structure associated to a network filter port binding
*/
struct _virNWFilterBinding {
    virObject parent;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *portdev;                       /* the network filter port device name */
    char *filtername;                    /* the network filter name */
};


/*
 * Helper APIs for allocating new object instances
 */

virConnectPtr virGetConnect(void);
virDomainPtr virGetDomain(virConnectPtr conn,
                          const char *name,
                          const unsigned char *uuid,
                          int id);
virNetworkPtr virGetNetwork(virConnectPtr conn,
                            const char *name,
                            const unsigned char *uuid);
virInterfacePtr virGetInterface(virConnectPtr conn,
                                const char *name,
                                const char *mac);
virStoragePoolPtr virGetStoragePool(virConnectPtr conn,
                                    const char *name,
                                    const unsigned char *uuid,
                                    void *privateData,
                                    virFreeCallback freeFunc);
virStorageVolPtr virGetStorageVol(virConnectPtr conn,
                                  const char *pool,
                                  const char *name,
                                  const char *key,
                                  void *privateData,
                                  virFreeCallback freeFunc);
virNodeDevicePtr virGetNodeDevice(virConnectPtr conn,
                                  const char *name);
virSecretPtr virGetSecret(virConnectPtr conn,
                          const unsigned char *uuid,
                          int usageType,
                          const char *usageID);
virStreamPtr virGetStream(virConnectPtr conn);
virNWFilterPtr virGetNWFilter(virConnectPtr conn,
                              const char *name,
                              const unsigned char *uuid);
virNWFilterBindingPtr virGetNWFilterBinding(virConnectPtr conn,
                                            const char *portdev,
                                            const char *filtername);
virDomainCheckpointPtr virGetDomainCheckpoint(virDomainPtr domain,
                                              const char *name);
virDomainSnapshotPtr virGetDomainSnapshot(virDomainPtr domain,
                                          const char *name);

virAdmConnectPtr virAdmConnectNew(void);

virAdmServerPtr virAdmGetServer(virAdmConnectPtr conn,
                                const char *name);

virAdmClientPtr virAdmGetClient(virAdmServerPtr srv,
                                unsigned long long id,
                                unsigned long long timestamp,
                                unsigned int transport);

virConnectCloseCallbackDataPtr virNewConnectCloseCallbackData(void);
void virConnectCloseCallbackDataRegister(virConnectCloseCallbackDataPtr close,
                                         virConnectPtr conn,
                                         virConnectCloseFunc cb,
                                         void *opaque,
                                         virFreeCallback freecb);
void virConnectCloseCallbackDataUnregister(virConnectCloseCallbackDataPtr close,
                                           virConnectCloseFunc cb);
void virConnectCloseCallbackDataCall(virConnectCloseCallbackDataPtr close,
                                     int reason);
virConnectCloseFunc
virConnectCloseCallbackDataGetCallback(virConnectCloseCallbackDataPtr close);
void virAdmConnectCloseCallbackDataReset(virAdmConnectCloseCallbackDataPtr cbdata);
int virAdmConnectCloseCallbackDataRegister(virAdmConnectCloseCallbackDataPtr cbdata,
                                           virAdmConnectPtr conn,
                                           virAdmConnectCloseFunc cb,
                                           void *opaque,
                                           virFreeCallback freecb);
int virAdmConnectCloseCallbackDataUnregister(virAdmConnectCloseCallbackDataPtr cbdata,
                                             virAdmConnectCloseFunc cb);

#endif /* LIBVIRT_DATATYPES_H */
