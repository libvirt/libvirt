/*
 * lock_driver_lockd.c: A lock driver which locks nothing
 *
 * Copyright (C) 2010-2011, 2014 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "lock_driver.h"
#include "virconf.h"
#include "viralloc.h"
#include "vircrypto.h"
#include "virlog.h"
#include "viruuid.h"
#include "virfile.h"
#include "virerror.h"
#include "rpc/virnetclient.h"
#include "lock_protocol.h"
#include "configmake.h"
#include "virstring.h"

#include "lock_driver_lockd.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_driver_lockd");

typedef struct _virLockManagerLockDaemonPrivate virLockManagerLockDaemonPrivate;
typedef virLockManagerLockDaemonPrivate *virLockManagerLockDaemonPrivatePtr;

typedef struct _virLockManagerLockDaemonResource virLockManagerLockDaemonResource;
typedef virLockManagerLockDaemonResource *virLockManagerLockDaemonResourcePtr;

typedef struct _virLockManagerLockDaemonDriver virLockManagerLockDaemonDriver;
typedef virLockManagerLockDaemonDriver *virLockManagerLockDaemonDriverPtr;

struct _virLockManagerLockDaemonResource {
    char *lockspace;
    char *name;
    unsigned int flags;
};

struct _virLockManagerLockDaemonPrivate {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;
    int id;
    pid_t pid;

    size_t nresources;
    virLockManagerLockDaemonResourcePtr resources;

    bool hasRWDisks;
};


struct _virLockManagerLockDaemonDriver {
    bool autoDiskLease;
    bool requireLeaseForDisks;

    char *fileLockSpaceDir;
    char *lvmLockSpaceDir;
    char *scsiLockSpaceDir;
};

static virLockManagerLockDaemonDriverPtr driver;

static int virLockManagerLockDaemonLoadConfig(const char *configFile)
{
    virConfPtr conf;
    int ret = -1;

    if (access(configFile, R_OK) == -1) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to access config file %s"),
                                 configFile);
            return -1;
        }
        return 0;
    }

    if (!(conf = virConfReadFile(configFile, 0)))
        return -1;

    if (virConfGetValueBool(conf, "auto_disk_leases", &driver->autoDiskLease) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "file_lockspace_dir", &driver->fileLockSpaceDir) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "lvm_lockspace_dir", &driver->lvmLockSpaceDir) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "scsi_lockspace_dir", &driver->scsiLockSpaceDir) < 0)
        goto cleanup;

    driver->requireLeaseForDisks = !driver->autoDiskLease;
    if (virConfGetValueBool(conf, "require_lease_for_disks", &driver->requireLeaseForDisks) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virConfFree(conf);
    return ret;
}


static char *virLockManagerLockDaemonPath(bool privileged)
{
    char *path;
    if (privileged) {
        if (VIR_STRDUP(path, LOCALSTATEDIR "/run/libvirt/virtlockd-sock") < 0)
            return NULL;
    } else {
        char *rundir = NULL;

        if (!(rundir = virGetUserRuntimeDirectory()))
            return NULL;

        if (virAsprintf(&path, "%s/virtlockd-sock", rundir) < 0) {
            VIR_FREE(rundir);
            return NULL;
        }

        VIR_FREE(rundir);
    }
    return path;
}


static int
virLockManagerLockDaemonConnectionRegister(virLockManagerPtr lock,
                                           virNetClientPtr client,
                                           virNetClientProgramPtr program,
                                           int *counter)
{
    virLockManagerLockDaemonPrivatePtr priv = lock->privateData;
    virLockSpaceProtocolRegisterArgs args;
    int rv = -1;

    memset(&args, 0, sizeof(args));

    args.flags = 0;
    memcpy(args.owner.uuid, priv->uuid, VIR_UUID_BUFLEN);
    args.owner.name = priv->name;
    args.owner.id = priv->id;
    args.owner.pid = priv->pid;

    if (virNetClientProgramCall(program,
                                client,
                                (*counter)++,
                                VIR_LOCK_SPACE_PROTOCOL_PROC_REGISTER,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLockSpaceProtocolRegisterArgs, (char*)&args,
                                (xdrproc_t)xdr_void, NULL) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    return rv;
}


static int
virLockManagerLockDaemonConnectionRestrict(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                           virNetClientPtr client,
                                           virNetClientProgramPtr program,
                                           int *counter)
{
    virLockSpaceProtocolRestrictArgs args;
    int rv = -1;

    memset(&args, 0, sizeof(args));

    args.flags = 0;

    if (virNetClientProgramCall(program,
                                client,
                                (*counter)++,
                                VIR_LOCK_SPACE_PROTOCOL_PROC_RESTRICT,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLockSpaceProtocolRestrictArgs, (char*)&args,
                                (xdrproc_t)xdr_void, NULL) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    return rv;
}


static virNetClientPtr virLockManagerLockDaemonConnectionNew(bool privileged,
                                                             virNetClientProgramPtr *prog)
{
    virNetClientPtr client = NULL;
    char *lockdpath;
    char *daemonPath = NULL;

    *prog = NULL;

    if (!(lockdpath = virLockManagerLockDaemonPath(privileged)))
        goto error;

    if (!privileged &&
        !(daemonPath = virFileFindResourceFull("virtlockd",
                                               NULL, NULL,
                                               abs_top_builddir "/src",
                                               SBINDIR,
                                               "VIRTLOCKD_PATH")))
        goto error;

    if (!(client = virNetClientNewUNIX(lockdpath,
                                       daemonPath != NULL,
                                       daemonPath)))
        goto error;

    if (!(*prog = virNetClientProgramNew(VIR_LOCK_SPACE_PROTOCOL_PROGRAM,
                                         VIR_LOCK_SPACE_PROTOCOL_PROGRAM_VERSION,
                                         NULL,
                                         0,
                                         NULL)))
        goto error;

    if (virNetClientAddProgram(client, *prog) < 0)
        goto error;

    VIR_FREE(daemonPath);
    VIR_FREE(lockdpath);

    return client;

 error:
    VIR_FREE(daemonPath);
    VIR_FREE(lockdpath);
    virNetClientClose(client);
    virObjectUnref(client);
    virObjectUnref(*prog);
    return NULL;
}


static virNetClientPtr
virLockManagerLockDaemonConnect(virLockManagerPtr lock,
                                virNetClientProgramPtr *program,
                                int *counter)
{
    virNetClientPtr client;

    if (!(client = virLockManagerLockDaemonConnectionNew(geteuid() == 0, program)))
        return NULL;

    if (virLockManagerLockDaemonConnectionRegister(lock,
                                                   client,
                                                   *program,
                                                   counter) < 0)
        goto error;

    return client;

 error:
    virNetClientClose(client);
    virObjectUnref(client);
    return NULL;
}


static int virLockManagerLockDaemonSetupLockspace(const char *path)
{
    virNetClientPtr client;
    virNetClientProgramPtr program = NULL;
    virLockSpaceProtocolCreateLockSpaceArgs args;
    int rv = -1;
    int counter = 0;

    memset(&args, 0, sizeof(args));
    args.path = (char*)path;

    if (!(client = virLockManagerLockDaemonConnectionNew(geteuid() == 0, &program)))
        return -1;

    if (virNetClientProgramCall(program,
                                client,
                                counter++,
                                VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_LOCKSPACE,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLockSpaceProtocolCreateLockSpaceArgs, (char*)&args,
                                (xdrproc_t)xdr_void, NULL) < 0) {
        if (virGetLastErrorCode() == VIR_ERR_OPERATION_INVALID) {
            /* The lockspace already exists */
            virResetLastError();
            rv = 0;
        } else {
            goto cleanup;
        }
    }

    rv = 0;

 cleanup:
    virObjectUnref(program);
    virNetClientClose(client);
    virObjectUnref(client);
    return rv;
}


static int virLockManagerLockDaemonDeinit(void);

static int virLockManagerLockDaemonInit(unsigned int version,
                                        const char *configFile,
                                        unsigned int flags)
{
    VIR_DEBUG("version=%u configFile=%s flags=0x%x", version, NULLSTR(configFile), flags);

    virCheckFlags(0, -1);

    if (driver)
        return 0;

    if (VIR_ALLOC(driver) < 0)
        return -1;

    driver->requireLeaseForDisks = true;
    driver->autoDiskLease = true;

    if (virLockManagerLockDaemonLoadConfig(configFile) < 0)
        goto error;

    if (driver->autoDiskLease) {
        if (driver->fileLockSpaceDir &&
            virLockManagerLockDaemonSetupLockspace(driver->fileLockSpaceDir) < 0)
            goto error;

        if (driver->lvmLockSpaceDir &&
            virLockManagerLockDaemonSetupLockspace(driver->lvmLockSpaceDir) < 0)
            goto error;

        if (driver->scsiLockSpaceDir &&
            virLockManagerLockDaemonSetupLockspace(driver->scsiLockSpaceDir) < 0)
            goto error;
    }

    return 0;

 error:
    virLockManagerLockDaemonDeinit();
    return -1;
}

static int virLockManagerLockDaemonDeinit(void)
{
    if (!driver)
        return 0;

    VIR_FREE(driver->scsiLockSpaceDir);
    VIR_FREE(driver->lvmLockSpaceDir);
    VIR_FREE(driver->fileLockSpaceDir);
    VIR_FREE(driver);

    return 0;
}

static void
virLockManagerLockDaemonPrivateFree(virLockManagerLockDaemonPrivatePtr priv)
{
    size_t i;

    if (!priv)
        return;

    for (i = 0; i < priv->nresources; i++) {
        VIR_FREE(priv->resources[i].lockspace);
        VIR_FREE(priv->resources[i].name);
    }
    VIR_FREE(priv->resources);

    VIR_FREE(priv->name);
    VIR_FREE(priv);
}

static void virLockManagerLockDaemonFree(virLockManagerPtr lock)
{
    if (!lock)
        return;

    virLockManagerLockDaemonPrivateFree(lock->privateData);
    lock->privateData = NULL;
}


static int virLockManagerLockDaemonNew(virLockManagerPtr lock,
                                       unsigned int type,
                                       size_t nparams,
                                       virLockManagerParamPtr params,
                                       unsigned int flags)
{
    virLockManagerLockDaemonPrivatePtr priv = NULL;
    size_t i;
    int ret = -1;

    virCheckFlags(VIR_LOCK_MANAGER_NEW_STARTED, -1);

    if (VIR_ALLOC(priv) < 0)
        return -1;

    switch (type) {
    case VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN:
        for (i = 0; i < nparams; i++) {
            if (STREQ(params[i].key, "uuid")) {
                memcpy(priv->uuid, params[i].value.uuid, VIR_UUID_BUFLEN);
            } else if (STREQ(params[i].key, "name")) {
                if (VIR_STRDUP(priv->name, params[i].value.str) < 0)
                    goto cleanup;
            } else if (STREQ(params[i].key, "id")) {
                priv->id = params[i].value.iv;
            } else if (STREQ(params[i].key, "pid")) {
                priv->pid = params[i].value.iv;
            } else if (STREQ(params[i].key, "uri")) {
                /* ignored */
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected parameter %s for object"),
                               params[i].key);
                goto cleanup;
            }
        }
        if (priv->id == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing ID parameter for domain object"));
            goto cleanup;
        }
        if (priv->pid == 0)
            VIR_DEBUG("Missing PID parameter for domain object");
        if (!priv->name) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing name parameter for domain object"));
            goto cleanup;
        }
        if (!virUUIDIsValid(priv->uuid)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing UUID parameter for domain object"));
            goto cleanup;
        }
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown lock manager object type %d"),
                       type);
        goto cleanup;
    }

    VIR_STEAL_PTR(lock->privateData, priv);
    ret = 0;
 cleanup:
    virLockManagerLockDaemonPrivateFree(priv);
    return ret;
}


static int virLockManagerLockDaemonAddResource(virLockManagerPtr lock,
                                               unsigned int type,
                                               const char *name,
                                               size_t nparams,
                                               virLockManagerParamPtr params,
                                               unsigned int flags)
{
    virLockManagerLockDaemonPrivatePtr priv = lock->privateData;
    char *newName = NULL;
    char *newLockspace = NULL;
    bool autoCreate = false;
    int ret = -1;

    virCheckFlags(VIR_LOCK_MANAGER_RESOURCE_READONLY |
                  VIR_LOCK_MANAGER_RESOURCE_SHARED, -1);

    if (flags & VIR_LOCK_MANAGER_RESOURCE_READONLY)
        return 0;

    switch (type) {
    case VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK:
        if (params || nparams) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unexpected parameters for disk resource"));
            goto cleanup;
        }
        if (!driver->autoDiskLease) {
            if (!(flags & (VIR_LOCK_MANAGER_RESOURCE_SHARED |
                           VIR_LOCK_MANAGER_RESOURCE_READONLY)))
                priv->hasRWDisks = true;
            return 0;
        }

        /* XXX we should somehow pass in TYPE=BLOCK info
         * from the domain_lock code, instead of assuming /dev
         */
        if (STRPREFIX(name, "/dev") &&
            driver->lvmLockSpaceDir) {
            VIR_DEBUG("Trying to find an LVM UUID for %s", name);
            if (virStorageFileGetLVMKey(name, &newName) < 0)
                goto cleanup;

            if (newName) {
                VIR_DEBUG("Got an LVM UUID %s for %s", newName, name);
                if (VIR_STRDUP(newLockspace, driver->lvmLockSpaceDir) < 0)
                    goto cleanup;
                autoCreate = true;
                break;
            }
            virResetLastError();
            /* Fallback to generic non-block code */
        }

        if (STRPREFIX(name, "/dev") &&
            driver->scsiLockSpaceDir) {
            VIR_DEBUG("Trying to find an SCSI ID for %s", name);
            if (virStorageFileGetSCSIKey(name, &newName, false) < 0)
                goto cleanup;

            if (newName) {
                VIR_DEBUG("Got an SCSI ID %s for %s", newName, name);
                if (VIR_STRDUP(newLockspace, driver->scsiLockSpaceDir) < 0)
                    goto cleanup;
                autoCreate = true;
                break;
            }
            virResetLastError();
            /* Fallback to generic non-block code */
        }

        if (driver->fileLockSpaceDir) {
            if (VIR_STRDUP(newLockspace, driver->fileLockSpaceDir) < 0)
                goto cleanup;
            if (virCryptoHashString(VIR_CRYPTO_HASH_SHA256, name, &newName) < 0)
                goto cleanup;
            autoCreate = true;
            VIR_DEBUG("Using indirect lease %s for %s", newName, name);
        } else {
            if (VIR_STRDUP(newLockspace, "") < 0)
                goto cleanup;
            if (VIR_STRDUP(newName, name) < 0)
                goto cleanup;
            VIR_DEBUG("Using direct lease for %s", name);
        }

        break;
    case VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE: {
        size_t i;
        char *path = NULL;
        char *lockspace = NULL;
        for (i = 0; i < nparams; i++) {
            if (STREQ(params[i].key, "offset")) {
                if (params[i].value.ul != 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Offset must be zero for this lock manager"));
                    goto cleanup;
                }
            } else if (STREQ(params[i].key, "lockspace")) {
                lockspace = params[i].value.str;
            } else if (STREQ(params[i].key, "path")) {
                path = params[i].value.str;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected parameter %s for lease resource"),
                               params[i].key);
                goto cleanup;
            }
        }
        if (!path || !lockspace) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing path or lockspace for lease resource"));
            goto cleanup;
        }
        if (virAsprintf(&newLockspace, "%s/%s",
                        path, lockspace) < 0)
            goto cleanup;
        if (VIR_STRDUP(newName, name) < 0)
            goto cleanup;

    }   break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown lock manager object type %d"),
                       type);
        goto cleanup;
    }

    if (VIR_EXPAND_N(priv->resources, priv->nresources, 1) < 0)
        goto cleanup;

    VIR_STEAL_PTR(priv->resources[priv->nresources-1].lockspace, newLockspace);
    VIR_STEAL_PTR(priv->resources[priv->nresources-1].name, newName);

    if (flags & VIR_LOCK_MANAGER_RESOURCE_SHARED)
        priv->resources[priv->nresources-1].flags |=
            VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED;

    if (autoCreate)
        priv->resources[priv->nresources-1].flags |=
            VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE;

    ret = 0;
 cleanup:
    VIR_FREE(newLockspace);
    VIR_FREE(newName);
    return ret;
}


static int virLockManagerLockDaemonAcquire(virLockManagerPtr lock,
                                           const char *state ATTRIBUTE_UNUSED,
                                           unsigned int flags,
                                           virDomainLockFailureAction action ATTRIBUTE_UNUSED,
                                           int *fd)
{
    virNetClientPtr client = NULL;
    virNetClientProgramPtr program = NULL;
    int counter = 0;
    int rv = -1;
    virLockManagerLockDaemonPrivatePtr priv = lock->privateData;

    virCheckFlags(VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY |
                  VIR_LOCK_MANAGER_ACQUIRE_RESTRICT, -1);

    if (priv->nresources == 0 &&
        priv->hasRWDisks &&
        driver->requireLeaseForDisks) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Read/write, exclusive access, disks were present, but no leases specified"));
        return -1;
    }

    if (!(client = virLockManagerLockDaemonConnect(lock, &program, &counter)))
        goto cleanup;

    if (fd &&
        (*fd = virNetClientDupFD(client, false)) < 0)
        goto cleanup;

    if (!(flags & VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY)) {
        size_t i;
        for (i = 0; i < priv->nresources; i++) {
            virLockSpaceProtocolAcquireResourceArgs args;

            memset(&args, 0, sizeof(args));

            args.path = priv->resources[i].lockspace;
            args.name = priv->resources[i].name;
            args.flags = priv->resources[i].flags;

            if (virNetClientProgramCall(program,
                                        client,
                                        counter++,
                                        VIR_LOCK_SPACE_PROTOCOL_PROC_ACQUIRE_RESOURCE,
                                        0, NULL, NULL, NULL,
                                        (xdrproc_t)xdr_virLockSpaceProtocolAcquireResourceArgs, &args,
                                        (xdrproc_t)xdr_void, NULL) < 0)
                goto cleanup;
        }
    }

    if ((flags & VIR_LOCK_MANAGER_ACQUIRE_RESTRICT) &&
        virLockManagerLockDaemonConnectionRestrict(lock, client, program, &counter) < 0)
        goto cleanup;

    rv = 0;

 cleanup:
    if (rv != 0 && fd)
        VIR_FORCE_CLOSE(*fd);
    virNetClientClose(client);
    virObjectUnref(client);
    virObjectUnref(program);

    return rv;
}

static int virLockManagerLockDaemonRelease(virLockManagerPtr lock,
                                           char **state,
                                           unsigned int flags)
{
    virNetClientPtr client = NULL;
    virNetClientProgramPtr program = NULL;
    int counter = 0;
    int rv = -1;
    size_t i;
    virLockManagerLockDaemonPrivatePtr priv = lock->privateData;

    virCheckFlags(0, -1);

    if (state)
        *state = NULL;

    if (!(client = virLockManagerLockDaemonConnect(lock, &program, &counter)))
        goto cleanup;

    for (i = 0; i < priv->nresources; i++) {
        virLockSpaceProtocolReleaseResourceArgs args;

        memset(&args, 0, sizeof(args));

        if (priv->resources[i].lockspace)
            args.path = priv->resources[i].lockspace;
        args.name = priv->resources[i].name;
        args.flags = priv->resources[i].flags;

        args.flags &=
            ~(VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED |
              VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE);

        if (virNetClientProgramCall(program,
                                    client,
                                    counter++,
                                    VIR_LOCK_SPACE_PROTOCOL_PROC_RELEASE_RESOURCE,
                                    0, NULL, NULL, NULL,
                                    (xdrproc_t)xdr_virLockSpaceProtocolReleaseResourceArgs, &args,
                                    (xdrproc_t)xdr_void, NULL) < 0)
            goto cleanup;
    }

    rv = 0;

 cleanup:
    virNetClientClose(client);
    virObjectUnref(client);
    virObjectUnref(program);

    return rv;
}


static int virLockManagerLockDaemonInquire(virLockManagerPtr lock ATTRIBUTE_UNUSED,
                                           char **state,
                                           unsigned int flags)
{
    virCheckFlags(0, -1);

    if (state)
        *state = NULL;

    return 0;
}

virLockDriver virLockDriverImpl =
{
    .version = VIR_LOCK_MANAGER_VERSION,
    .flags = 0,

    .drvInit = virLockManagerLockDaemonInit,
    .drvDeinit = virLockManagerLockDaemonDeinit,

    .drvNew = virLockManagerLockDaemonNew,
    .drvFree = virLockManagerLockDaemonFree,

    .drvAddResource = virLockManagerLockDaemonAddResource,

    .drvAcquire = virLockManagerLockDaemonAcquire,
    .drvRelease = virLockManagerLockDaemonRelease,

    .drvInquire = virLockManagerLockDaemonInquire,
};
