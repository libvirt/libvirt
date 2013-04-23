/*
 * datatypes.h: management of structs for public data types
 *
 * Copyright (C) 2006-2008, 2010-2011 Red Hat, Inc.
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

#ifndef __VIR_DATATYPES_H_
# define __VIR_DATATYPES_H_

# include "internal.h"

# include "driver.h"
# include "virthread.h"
# include "virobject.h"

extern virClassPtr virConnectClass;
extern virClassPtr virDomainClass;
extern virClassPtr virDomainSnapshotClass;
extern virClassPtr virInterfaceClass;
extern virClassPtr virNetworkClass;
extern virClassPtr virNodeDeviceClass;
extern virClassPtr virNWFilterClass;
extern virClassPtr virSecretClass;
extern virClassPtr virStreamClass;
extern virClassPtr virStorageVolClass;
extern virClassPtr virStoragePoolClass;

# define VIR_IS_CONNECT(obj) \
    (virObjectIsClass((obj), virConnectClass))

# define VIR_IS_DOMAIN(obj) \
    (virObjectIsClass((obj), virDomainClass))
# define VIR_IS_CONNECTED_DOMAIN(obj) \
    (VIR_IS_DOMAIN(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_NETWORK(obj) \
    (virObjectIsClass((obj), virNetworkClass))
# define VIR_IS_CONNECTED_NETWORK(obj) \
    (VIR_IS_NETWORK(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_INTERFACE(obj) \
    (virObjectIsClass((obj), virInterfaceClass))
# define VIR_IS_CONNECTED_INTERFACE(obj) \
    (VIR_IS_INTERFACE(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_STORAGE_POOL(obj) \
    (virObjectIsClass((obj), virStoragePoolClass))
# define VIR_IS_CONNECTED_STORAGE_POOL(obj) \
    (VIR_IS_STORAGE_POOL(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_STORAGE_VOL(obj) \
    (virObjectIsClass((obj), virStorageVolClass))
# define VIR_IS_CONNECTED_STORAGE_VOL(obj) \
    (VIR_IS_STORAGE_VOL(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_NODE_DEVICE(obj) \
    (virObjectIsClass((obj), virNodeDeviceClass))
# define VIR_IS_CONNECTED_NODE_DEVICE(obj) \
    (VIR_IS_NODE_DEVICE(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_SECRET(obj) \
    (virObjectIsClass((obj), virSecretClass))
# define VIR_IS_CONNECTED_SECRET(obj) \
    (VIR_IS_SECRET(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_STREAM(obj) \
    (virObjectIsClass((obj), virStreamClass))
# define VIR_IS_CONNECTED_STREAM(obj) \
    (VIR_IS_STREAM(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_NWFILTER(obj) \
    (virObjectIsClass((obj), virNWFilterClass))
# define VIR_IS_CONNECTED_NWFILTER(obj) \
    (VIR_IS_NWFILTER(obj) && VIR_IS_CONNECT((obj)->conn))

# define VIR_IS_SNAPSHOT(obj) \
    (virObjectIsClass((obj), virDomainSnapshotClass))
# define VIR_IS_DOMAIN_SNAPSHOT(obj) \
    (VIR_IS_SNAPSHOT(obj) && VIR_IS_DOMAIN((obj)->domain))


typedef struct _virConnectCloseCallbackData virConnectCloseCallbackData;
typedef virConnectCloseCallbackData *virConnectCloseCallbackDataPtr;

/**
 * Internal structure holding data related to connection close callbacks.
 */
struct _virConnectCloseCallbackData {
    virObjectLockable parent;

    virConnectPtr conn;
    virConnectCloseFunc callback;
    void *opaque;
    virFreeCallback freeCallback;
};

/**
 * _virConnect:
 *
 * Internal structure associated to a connection
 */
struct _virConnect {
    virObject object;
    /* All the variables from here, until the 'lock' declaration
     * are setup at time of connection open, and never changed
     * since. Thus no need to lock when accessing them
     */
    unsigned int flags;     /* a set of connection flags */
    virURIPtr uri;          /* connection URI */

    /* The underlying hypervisor driver and network driver. */
    virDriverPtr      driver;
    virNetworkDriverPtr networkDriver;
    virInterfaceDriverPtr interfaceDriver;
    virStorageDriverPtr storageDriver;
    virNodeDeviceDriverPtr  nodeDeviceDriver;
    virSecretDriverPtr secretDriver;
    virNWFilterDriverPtr nwfilterDriver;

    /* Private data pointer which can be used by driver and
     * network driver as they wish.
     * NB: 'private' is a reserved word in C++.
     */
    void *            privateData;
    void *            networkPrivateData;
    void *            interfacePrivateData;
    void *            storagePrivateData;
    void *            nodeDevicePrivateData;
    void *            secretPrivateData;
    void *            nwfilterPrivateData;

    /*
     * The lock mutex must be acquired before accessing/changing
     * any of members following this point, or changing the ref
     * count of any virDomain/virNetwork object associated with
     * this connection
     */
    virMutex lock;

    /* Per-connection error. */
    virError err;           /* the last error */
    virErrorFunc handler;   /* associated handlet */
    void *userData;         /* the user data */

    /* Per-connection close callback */
    virConnectCloseCallbackDataPtr closeCallback;
};

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    virObject object;
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
    virObject object;
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
    virObject object;
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
    virObject object;
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
    virObject object;
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
    virObject object;
    virConnectPtr conn;                 /* pointer back to the connection */
    char *name;                         /* device name (unique on node) */
    char *parent;                       /* parent device name */
};

/**
 * _virSecret:
 *
 * Internal structure associated with a secret
 */
struct _virSecret {
    virObject object;
    virConnectPtr conn;                  /* pointer back to the connection */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the domain unique identifier */
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
    virObject object;
    virConnectPtr conn;
    unsigned int flags;

    virStreamDriverPtr driver;
    void *privateData;
};

/**
 * _virDomainSnapshot
 *
 * Internal structure associated with a domain snapshot
 */
struct _virDomainSnapshot {
    virObject object;
    char *name;
    virDomainPtr domain;
};

/**
* _virNWFilter:
*
* Internal structure associated to a network filter
*/
struct _virNWFilter {
    virObject object;
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network filter external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network filter unique identifier */
};


/*
 * Helper APIs for allocating new object instances
 */

virConnectPtr virGetConnect(void);
virDomainPtr virGetDomain(virConnectPtr conn,
                          const char *name,
                          const unsigned char *uuid);
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
virDomainSnapshotPtr virGetDomainSnapshot(virDomainPtr domain,
                                          const char *name);

#endif /* __VIR_DATATYPES_H__ */
