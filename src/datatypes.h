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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#ifndef __VIRT_DATATYPES_H_
# define __VIRT_DATATYPES_H_

# include "internal.h"

# include "driver.h"
# include "threads.h"

/**
 * VIR_CONNECT_MAGIC:
 *
 * magic value used to protect the API when pointers to connection structures
 * are passed down by the users.
 */
# define VIR_CONNECT_MAGIC	0x4F23DEAD
# define VIR_IS_CONNECT(obj)	((obj) && (obj)->magic==VIR_CONNECT_MAGIC)


/**
 * VIR_DOMAIN_MAGIC:
 *
 * magic value used to protect the API when pointers to domain structures
 * are passed down by the users.
 */
# define VIR_DOMAIN_MAGIC		0xDEAD4321
# define VIR_IS_DOMAIN(obj)		((obj) && (obj)->magic==VIR_DOMAIN_MAGIC)
# define VIR_IS_CONNECTED_DOMAIN(obj)	(VIR_IS_DOMAIN(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_NETWORK_MAGIC:
 *
 * magic value used to protect the API when pointers to network structures
 * are passed down by the users.
 */
# define VIR_NETWORK_MAGIC		0xDEAD1234
# define VIR_IS_NETWORK(obj)		((obj) && (obj)->magic==VIR_NETWORK_MAGIC)
# define VIR_IS_CONNECTED_NETWORK(obj)	(VIR_IS_NETWORK(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_INTERFACE_MAGIC:
 *
 * magic value used to protect the API when pointers to interface structures
 * are passed down by the users.
 */
# define VIR_INTERFACE_MAGIC		0xDEAD5309
# define VIR_IS_INTERFACE(obj)		((obj) && (obj)->magic==VIR_INTERFACE_MAGIC)
# define VIR_IS_CONNECTED_INTERFACE(obj)	(VIR_IS_INTERFACE(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_STORAGE_POOL_MAGIC:
 *
 * magic value used to protect the API when pointers to storage pool structures
 * are passed down by the users.
 */
# define VIR_STORAGE_POOL_MAGIC		0xDEAD5678
# define VIR_IS_STORAGE_POOL(obj)		((obj) && (obj)->magic==VIR_STORAGE_POOL_MAGIC)
# define VIR_IS_CONNECTED_STORAGE_POOL(obj)	(VIR_IS_STORAGE_POOL(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_STORAGE_VOL_MAGIC:
 *
 * magic value used to protect the API when pointers to storage vol structures
 * are passed down by the users.
 */
# define VIR_STORAGE_VOL_MAGIC		0xDEAD8765
# define VIR_IS_STORAGE_VOL(obj)		((obj) && (obj)->magic==VIR_STORAGE_VOL_MAGIC)
# define VIR_IS_CONNECTED_STORAGE_VOL(obj)	(VIR_IS_STORAGE_VOL(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_NODE_DEVICE_MAGIC:
 *
 * magic value used to protect the API when pointers to storage vol structures
 * are passed down by the users.
 */
# define VIR_NODE_DEVICE_MAGIC                   0xDEAD5679
# define VIR_IS_NODE_DEVICE(obj)                 ((obj) && (obj)->magic==VIR_NODE_DEVICE_MAGIC)
# define VIR_IS_CONNECTED_NODE_DEVICE(obj)       (VIR_IS_NODE_DEVICE(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_SECRET_MAGIC:
 *
 * magic value used to protect the API when pointers to secret structures are
 * passed down by the users.
 */
# define VIR_SECRET_MAGIC		0x5678DEAD
# define VIR_IS_SECRET(obj)		((obj) && (obj)->magic==VIR_SECRET_MAGIC)
# define VIR_IS_CONNECTED_SECRET(obj)	(VIR_IS_SECRET(obj) && VIR_IS_CONNECT((obj)->conn))


/**
 * VIR_STREAM_MAGIC:
 *
 * magic value used to protect the API when pointers to stream structures
 * are passed down by the users.
 */
# define VIR_STREAM_MAGIC                   0x1DEAD666
# define VIR_IS_STREAM(obj)                 ((obj) && (obj)->magic==VIR_STREAM_MAGIC)
# define VIR_IS_CONNECTED_STREAM(obj)       (VIR_IS_STREAM(obj) && VIR_IS_CONNECT((obj)->conn))


/**
 * VIR_NWFILTER_MAGIC:
 *
 * magic value used to protect the API when pointers to network filter
 * pool structures are passed down by the users.
 */
# define VIR_NWFILTER_MAGIC			0xDEAD7777
# define VIR_IS_NWFILTER(obj)			((obj) && (obj)->magic==VIR_NWFILTER_MAGIC)
# define VIR_IS_CONNECTED_NWFILTER(obj)		(VIR_IS_NWFILTER(obj) && VIR_IS_CONNECT((obj)->conn))

/**
 * VIR_SNAPSHOT_MAGIC:
 *
 * magic value used to protect the API when pointers to snapshot structures
 * are passed down by the users.
 */
# define VIR_SNAPSHOT_MAGIC                0x6666DEAD
# define VIR_IS_SNAPSHOT(obj)              ((obj) && (obj)->magic==VIR_SNAPSHOT_MAGIC)
# define VIR_IS_DOMAIN_SNAPSHOT(obj)    (VIR_IS_SNAPSHOT(obj) && VIR_IS_DOMAIN((obj)->domain))

/**
 * _virConnect:
 *
 * Internal structure associated to a connection
 */
struct _virConnect {
    /* All the variables from here, until the 'lock' declaration
     * are setup at time of connection open, and never changed
     * since. Thus no need to lock when accessing them
     */
    unsigned int magic;     /* specific value to check */
    unsigned int flags;     /* a set of connection flags */
    virURIPtr uri;          /* connection URI */

    /* The underlying hypervisor driver and network driver. */
    virDriverPtr      driver;
    virNetworkDriverPtr networkDriver;
    virInterfaceDriverPtr interfaceDriver;
    virStorageDriverPtr storageDriver;
    virDeviceMonitorPtr  deviceMonitor;
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
    void *            devMonPrivateData;
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

    int refs;                 /* reference count */
};

/**
* _virDomain:
*
* Internal structure associated to a domain
*/
struct _virDomain {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
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
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
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
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
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
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the storage pool external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the storage pool unique identifier */
};

/**
* _virStorageVol:
*
* Internal structure associated to a storage volume
*/
struct _virStorageVol {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *pool;                          /* Pool name of owner */
    char *name;                          /* the storage vol external name */
    char *key;                           /* unique key for storage vol */
};

/**
 * _virNodeDevice:
 *
 * Internal structure associated with a node device
 */
struct _virNodeDevice {
    unsigned int magic;                 /* specific value to check */
    int refs;                           /* reference count */
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
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
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
    unsigned int magic;
    virConnectPtr conn;
    int refs;
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
    unsigned int magic;
    int refs;
    char *name;
    virDomainPtr domain;
};

/************************************************************************
 *									*
 *	API for domain/connections (de)allocations and lookups		*
 *									*
 ************************************************************************/

virConnectPtr virGetConnect(void);
int virUnrefConnect(virConnectPtr conn);
virDomainPtr virGetDomain(virConnectPtr conn,
                            const char *name,
                            const unsigned char *uuid);
int virUnrefDomain(virDomainPtr domain);
virNetworkPtr virGetNetwork(virConnectPtr conn,
                              const char *name,
                              const unsigned char *uuid);
int virUnrefNetwork(virNetworkPtr network);

virInterfacePtr virGetInterface(virConnectPtr conn,
                                const char *name,
                                const char *mac);
int virUnrefInterface(virInterfacePtr iface);

virStoragePoolPtr virGetStoragePool(virConnectPtr conn,
                                      const char *name,
                                      const unsigned char *uuid);
int virUnrefStoragePool(virStoragePoolPtr pool);
virStorageVolPtr virGetStorageVol(virConnectPtr conn,
                                     const char *pool,
                                    const char *name,
                                    const char *key);
int virUnrefStorageVol(virStorageVolPtr vol);

virNodeDevicePtr virGetNodeDevice(virConnectPtr conn,
                                  const char *name);
int virUnrefNodeDevice(virNodeDevicePtr dev);

virSecretPtr virGetSecret(virConnectPtr conn,
                          const unsigned char *uuid,
                          int usageType,
                          const char *usageID);
int virUnrefSecret(virSecretPtr secret);

virStreamPtr virGetStream(virConnectPtr conn);
int virUnrefStream(virStreamPtr st);

/**
* _virNWFilter:
*
* Internal structure associated to a network filter
*/
struct _virNWFilter {
    unsigned int magic;                  /* specific value to check */
    int refs;                            /* reference count */
    virConnectPtr conn;                  /* pointer back to the connection */
    char *name;                          /* the network filter external name */
    unsigned char uuid[VIR_UUID_BUFLEN]; /* the network filter unique identifier */
};

virNWFilterPtr virGetNWFilter(virConnectPtr conn,
                                  const char *name,
                                  const unsigned char *uuid);
int virUnrefNWFilter(virNWFilterPtr nwfilter);

virDomainSnapshotPtr virGetDomainSnapshot(virDomainPtr domain,
                                          const char *name);
int virUnrefDomainSnapshot(virDomainSnapshotPtr snapshot);

#endif
