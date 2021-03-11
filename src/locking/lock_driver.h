/*
 * lock_driver.h: Defines the lock driver plugin API
 *
 * Copyright (C) 2010-2011, 2013 Red Hat, Inc.
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

#pragma once

#include "internal.h"
#include "domain_conf.h"

typedef struct _virLockManager virLockManager;

typedef struct _virLockDriver virLockDriver;

typedef struct _virLockManagerParam virLockManagerParam;

typedef enum {
    /* State passing is used to re-acquire existing leases */
    VIR_LOCK_MANAGER_USES_STATE = (1 << 0)
} virLockManagerFlags;

typedef enum {
    /* The managed object is a virtual guest domain */
    VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN = 0,
} virLockManagerObjectType;

typedef enum {
    /* The resource to be locked is a virtual disk */
    VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK = 0,
    /* A lease against an arbitrary resource */
    VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE = 1,
} virLockManagerResourceType;

typedef enum {
    /* The resource is assigned in readonly mode */
    VIR_LOCK_MANAGER_RESOURCE_READONLY = (1 << 0),
    /* The resource is assigned in shared, writable mode */
    VIR_LOCK_MANAGER_RESOURCE_SHARED   = (1 << 1),
} virLockManagerResourceFlags;

typedef enum {
    /* Don't acquire the resources, just register the object PID */
    VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY = (1 << 0),
    /* Prevent further lock/unlock calls from this process */
    VIR_LOCK_MANAGER_ACQUIRE_RESTRICT = (1 << 1),
} virLockManagerAcquireFlags;

typedef enum {
    /* virLockManagerNew called for a freshly started domain */
    VIR_LOCK_MANAGER_NEW_STARTED = (1 << 0),
} virLockManagerNewFlags;

enum {
    VIR_LOCK_MANAGER_PARAM_TYPE_STRING,
    VIR_LOCK_MANAGER_PARAM_TYPE_CSTRING,
    VIR_LOCK_MANAGER_PARAM_TYPE_INT,
    VIR_LOCK_MANAGER_PARAM_TYPE_LONG,
    VIR_LOCK_MANAGER_PARAM_TYPE_UINT,
    VIR_LOCK_MANAGER_PARAM_TYPE_ULONG,
    VIR_LOCK_MANAGER_PARAM_TYPE_DOUBLE,
    VIR_LOCK_MANAGER_PARAM_TYPE_UUID,
};

struct _virLockManagerParam {
    int type;
    const char *key;
    union {
        int iv;
        long long l;
        unsigned int ui;
        unsigned long long ul;
        double d;
        char *str;
        const char *cstr;
        unsigned char uuid[16];
    } value;
};


/*
 * Changes in major version denote incompatible ABI changes
 * Changes in minor version denote new compatible API entry points
 * Changes in micro version denote new compatible flags
 */
#define VIR_LOCK_MANAGER_VERSION_MAJOR 1
#define VIR_LOCK_MANAGER_VERSION_MINOR 0
#define VIR_LOCK_MANAGER_VERSION_MICRO 0

#define VIR_LOCK_MANAGER_VERSION \
    ((VIR_LOCK_MANAGER_VERSION_MAJOR * 1000 * 1000) + \
     (VIR_LOCK_MANAGER_VERSION_MINOR * 1000) + \
     (VIR_LOCK_MANAGER_VERSION_MICRO))



/**
 * virLockDriverInit:
 * @version: the libvirt requested plugin ABI version
 * @flags: the libvirt requested plugin optional extras
 *
 * Allow the plugin to validate the libvirt requested
 * plugin version / flags. This allows the plugin impl
 * to block its use in versions of libvirtd which are
 * too old to support key features.
 *
 * NB: A plugin may be loaded multiple times, for different
 * libvirt drivers (eg QEMU, LXC)
 *
 * Returns -1 if the requested version/flags were inadequate
 */
typedef int (*virLockDriverInit)(unsigned int version,
                                 const char *configFile,
                                 unsigned int flags);

/**
 * virLockDriverDeinit:
 *
 * Called to release any resources prior to the plugin
 * being unloaded from memory. Returns -1 to prevent
 * plugin from being unloaded from memory.
 */
typedef int (*virLockDriverDeinit)(void);

/**
 * virLockManagerNew:
 * @man: the lock manager context
 * @type: the type of process to be supervised
 * @nparams: number of metadata parameters
 * @params: extra metadata parameters
 * @flags: bitwise-OR of virLockManagerNewFlags
 *
 * Initialize a new context to supervise a process, usually
 * a virtual machine. The lock driver implementation can use
 * the <code>privateData</code> field of <code>man</code>
 * to store a pointer to any driver specific state.
 *
 * If @flags contains VIR_LOCK_MANAGER_NEW_STARTED, this API is called for
 * a domain that has just been started and may therefore skip some actions.
 * Specifically, checking whether the domain is registered with a lock
 * daemon is useless in this case.
 *
 * A process of VIR_LOCK_MANAGER_START_DOMAIN will be
 * given the following parameters
 *
 * - id: the domain unique id (unsigned int)
 * - uuid: the domain uuid (uuid)
 * - name: the domain name (string)
 * - pid: process ID to own/owning the lock (unsigned int)
 * - uri: URI for connecting to the driver the domain belongs to (string)
 *
 * Returns 0 if successful initialized a new context, -1 on error
 */
typedef int (*virLockDriverNew)(virLockManager *man,
                                unsigned int type,
                                size_t nparams,
                                virLockManagerParam *params,
                                unsigned int flags);

/**
 * virLockDriverFree:
 * @manager: the lock manager context
 *
 * Release any resources associated with the lock manager
 * context private data
 */
typedef void (*virLockDriverFree)(virLockManager *man);

/**
 * virLockDriverAddResource:
 * @manager: the lock manager context
 * @type: the resource type virLockManagerResourceType
 * @name: the resource name
 * @nparams: number of metadata parameters
 * @params: extra metadata parameters
 * @flags: the resource access flags
 *
 * Assign a resource to a managed object. This will
 * only be called prior to the object is being locked
 * when it is inactive (e.g. to set the initial  boot
 * time disk assignments on a VM).
 * The format of @name varies according to
 * the resource @type. A VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK
 * will have the fully qualified file path, while a resource
 * of type VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE will have the
 * unique name of the lease
 *
 * A resource of type VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE
 * will receive at least the following extra parameters
 *
 *  - 'path': a fully qualified path to the lockspace
 *  - 'lockspace': globally string identifying the lockspace name
 *  - 'offset': byte offset within the lease (unsigned long long)
 *
 * If no flags are given, the resource is assumed to be
 * used in exclusive, read-write mode. Access can be
 * relaxed to readonly, or shared read-write.
 *
 * Returns 0 on success, or -1 on failure
 */
typedef int (*virLockDriverAddResource)(virLockManager *man,
                                        unsigned int type,
                                        const char *name,
                                        size_t nparams,
                                        virLockManagerParam *params,
                                        unsigned int flags);

/**
 * virLockDriverAcquire:
 * @manager: the lock manager context
 * @state: the current lock state
 * @flags: optional flags, currently unused
 * @action: action to take when lock is lost
 * @fd: optional return the leaked FD
 *
 * Start managing resources for the object. This
 * must be called from the PID that represents the
 * object to be managed. If the lock is lost at any
 * time, the specified action will be taken.
 * The optional state contains information about the
 * locks previously held for the object.
 *
 * The file descriptor returned in @fd is one that
 * is intentionally leaked and should not be closed.
 * It is returned so that it can be labelled by the
 * security managers (if required).
 *
 * Returns 0 on success, or -1 on failure
 */
typedef int (*virLockDriverAcquire)(virLockManager *man,
                                    const char *state,
                                    unsigned int flags,
                                    virDomainLockFailureAction action,
                                    int *fd);

/**
 * virLockDriverRelease:
 * @manager: the lock manager context
 * @state: pointer to be filled with lock state
 * @flags: optional flags
 *
 * Inform the lock manager that the supervised process has
 * been, or can be stopped.
 *
 * Returns 0 on success, or -1 on failure
 */
typedef int (*virLockDriverRelease)(virLockManager *man,
                                    char **state,
                                    unsigned int flags);

/**
 * virLockDriverInquire:
 * @manager: the lock manager context
 * @state: pointer to be filled with lock state
 * @flags: optional flags, currently unused
 *
 * Retrieve the current lock state. The returned
 * lock state may be NULL if none is required. The
 * caller is responsible for freeing the lock
 * state string when it is no longer required
 *
 * Returns 0 on success, or -1 on failure.
 */
typedef int (*virLockDriverInquire)(virLockManager *man,
                                    char **state,
                                    unsigned int flags);


struct _virLockManager {
    virLockDriver *driver;
    void *privateData;
};

/**
 * The plugin must export a static instance of this
 * driver table, with the name 'virLockDriverImpl'
 */
struct _virLockDriver {
    /**
     * @version: the newest implemented plugin ABI version
     * @flags: optional flags, currently unused
     */
    unsigned int version;
    unsigned int flags;

    virLockDriverInit drvInit;
    virLockDriverDeinit drvDeinit;

    virLockDriverNew drvNew;
    virLockDriverFree drvFree;

    virLockDriverAddResource drvAddResource;

    virLockDriverAcquire drvAcquire;
    virLockDriverRelease drvRelease;
    virLockDriverInquire drvInquire;
};
