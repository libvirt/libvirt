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
#include "vircommand.h"
#include "vircrypto.h"
#include "virlog.h"
#include "viruuid.h"
#include "virfile.h"
#include "virerror.h"
#include "rpc/virnetclient.h"
#include "lock_protocol.h"
#include "configmake.h"
#include "virstoragefile.h"
#include "virutil.h"

#include "lock_driver_lockd.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.lock_driver_lockd");

typedef struct _virLockManagerLockDaemonPrivate virLockManagerLockDaemonPrivate;

typedef struct _virLockManagerLockDaemonResource virLockManagerLockDaemonResource;

typedef struct _virLockManagerLockDaemonDriver virLockManagerLockDaemonDriver;

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
    virLockManagerLockDaemonResource *resources;

    bool hasRWDisks;
};


struct _virLockManagerLockDaemonDriver {
    bool autoDiskLease;
    bool requireLeaseForDisks;

    char *fileLockSpaceDir;
    char *lvmLockSpaceDir;
    char *scsiLockSpaceDir;
};

static virLockManagerLockDaemonDriver *driver;

static int virLockManagerLockDaemonLoadConfig(const char *configFile)
{
    g_autoptr(virConf) conf = NULL;

    if (access(configFile, R_OK) == -1) {
        if (errno != ENOENT) {
            virReportSystemError(errno,
                                 _("Unable to access config file %1$s"),
                                 configFile);
            return -1;
        }
        return 0;
    }

    if (!(conf = virConfReadFile(configFile, 0)))
        return -1;

    if (virConfGetValueBool(conf, "auto_disk_leases", &driver->autoDiskLease) < 0)
        return -1;

    if (virConfGetValueString(conf, "file_lockspace_dir", &driver->fileLockSpaceDir) < 0)
        return -1;

    if (virConfGetValueString(conf, "lvm_lockspace_dir", &driver->lvmLockSpaceDir) < 0)
        return -1;

    if (virConfGetValueString(conf, "scsi_lockspace_dir", &driver->scsiLockSpaceDir) < 0)
        return -1;

    driver->requireLeaseForDisks = !driver->autoDiskLease;
    if (virConfGetValueBool(conf, "require_lease_for_disks", &driver->requireLeaseForDisks) < 0)
        return -1;

    return 0;
}


static char *virLockManagerLockDaemonPath(bool privileged)
{
    char *path;
    if (privileged) {
        path = g_strdup(RUNSTATEDIR "/libvirt/virtlockd-sock");
    } else {
        g_autofree char *rundir = NULL;

        rundir = virGetUserRuntimeDirectory();

        path = g_strdup_printf("%s/virtlockd-sock", rundir);
    }
    return path;
}


static int
virLockManagerLockDaemonConnectionRegister(virLockManager *lock,
                                           virNetClient *client,
                                           virNetClientProgram *program,
                                           int *counter)
{
    virLockManagerLockDaemonPrivate *priv = lock->privateData;
    virLockSpaceProtocolRegisterArgs args = { 0 };

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
        return -1;

    return 0;
}


static int
virLockManagerLockDaemonConnectionRestrict(virLockManager *lock G_GNUC_UNUSED,
                                           virNetClient *client,
                                           virNetClientProgram *program,
                                           int *counter)
{
    virLockSpaceProtocolRestrictArgs args = { 0 };

    args.flags = 0;

    if (virNetClientProgramCall(program,
                                client,
                                (*counter)++,
                                VIR_LOCK_SPACE_PROTOCOL_PROC_RESTRICT,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLockSpaceProtocolRestrictArgs, (char*)&args,
                                (xdrproc_t)xdr_void, NULL) < 0)
        return -1;

    return 0;
}


static virNetClient *virLockManagerLockDaemonConnectionNew(bool privileged,
                                                             virNetClientProgram **prog)
{
    virNetClient *client = NULL;
    g_autofree char *lockdpath = NULL;
    g_autofree char *daemonPath = NULL;

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

    return client;

 error:
    virNetClientClose(client);
    virObjectUnref(client);
    virObjectUnref(*prog);
    return NULL;
}


static virNetClient *
virLockManagerLockDaemonConnect(virLockManager *lock,
                                virNetClientProgram **program,
                                int *counter)
{
    virNetClient *client;

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
    virNetClient *client;
    virNetClientProgram *program = NULL;
    virLockSpaceProtocolCreateLockSpaceArgs args = { 0 };
    int rv = -1;
    int counter = 0;

    args.path = (char*)path;

    if (!(client = virLockManagerLockDaemonConnectionNew(geteuid() == 0, &program)))
        return -1;

    if (virNetClientProgramCall(program,
                                client,
                                counter++,
                                VIR_LOCK_SPACE_PROTOCOL_PROC_CREATE_LOCKSPACE,
                                0, NULL, NULL, NULL,
                                (xdrproc_t)xdr_virLockSpaceProtocolCreateLockSpaceArgs, (char*)&args,
                                (xdrproc_t)xdr_void, NULL) < 0)
        goto cleanup;

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

    driver = g_new0(virLockManagerLockDaemonDriver, 1);

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
virLockManagerLockDaemonPrivateFree(virLockManagerLockDaemonPrivate *priv)
{
    size_t i;

    if (!priv)
        return;

    for (i = 0; i < priv->nresources; i++) {
        g_free(priv->resources[i].lockspace);
        g_free(priv->resources[i].name);
    }
    g_free(priv->resources);

    g_free(priv->name);
    g_free(priv);
}

static void virLockManagerLockDaemonFree(virLockManager *lock)
{
    if (!lock)
        return;

    g_clear_pointer(&lock->privateData, virLockManagerLockDaemonPrivateFree);
}


static int virLockManagerLockDaemonNew(virLockManager *lock,
                                       unsigned int type,
                                       size_t nparams,
                                       virLockManagerParam *params,
                                       unsigned int flags)
{
    virLockManagerLockDaemonPrivate *priv = NULL;
    size_t i;
    int ret = -1;

    virCheckFlags(VIR_LOCK_MANAGER_NEW_STARTED, -1);

    priv = g_new0(virLockManagerLockDaemonPrivate,
                  1);

    switch (type) {
    case VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN:
        for (i = 0; i < nparams; i++) {
            if (STREQ(params[i].key, "uuid")) {
                memcpy(priv->uuid, params[i].value.uuid, VIR_UUID_BUFLEN);
            } else if (STREQ(params[i].key, "name")) {
                priv->name = g_strdup(params[i].value.str);
            } else if (STREQ(params[i].key, "id")) {
                priv->id = params[i].value.iv;
            } else if (STREQ(params[i].key, "pid")) {
                priv->pid = params[i].value.iv;
            } else if (STREQ(params[i].key, "uri")) {
                /* ignored */
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected parameter %1$s for object"),
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
                       _("Unknown lock manager object type %1$d"),
                       type);
        goto cleanup;
    }

    lock->privateData = g_steal_pointer(&priv);
    ret = 0;
 cleanup:
    virLockManagerLockDaemonPrivateFree(priv);
    return ret;
}


#ifdef LVS
static int
virLockManagerGetLVMKey(const char *path,
                        char **key)
{
    /*
     *  # lvs --noheadings --unbuffered --nosuffix --options "uuid" LVNAME
     *    06UgP5-2rhb-w3Bo-3mdR-WeoL-pytO-SAa2ky
     */
    int status;
    int ret = -1;
    g_autoptr(virCommand) cmd = NULL;

    cmd = virCommandNewArgList(LVS, "--noheadings",
                               "--unbuffered", "--nosuffix",
                               "--options", "uuid", path,
                               NULL
                               );
    *key = NULL;

    /* Run the program and capture its output */
    virCommandSetOutputBuffer(cmd, key);
    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    /* Explicitly check status == 0, rather than passing NULL
     * to virCommandRun because we don't want to raise an actual
     * error in this scenario, just return a NULL key.
     */

    if (status == 0 && *key) {
        char *nl;
        char *tmp = *key;

        /* Find first non-space character */
        while (*tmp && g_ascii_isspace(*tmp))
            tmp++;
        /* Kill leading spaces */
        if (tmp != *key)
            memmove(*key, tmp, strlen(tmp)+1);

        /* Kill trailing newline */
        if ((nl = strchr(*key, '\n')))
            *nl = '\0';
    }

    ret = 0;

 cleanup:
    if (*key && STREQ(*key, ""))
        VIR_FREE(*key);

    return ret;
}
#else
static int
virLockManagerGetLVMKey(const char *path,
                        char **key G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, _("Unable to get LVM key for %1$s"), path);
    return -1;
}
#endif


static int virLockManagerLockDaemonAddResource(virLockManager *lock,
                                               unsigned int type,
                                               const char *name,
                                               size_t nparams,
                                               virLockManagerParam *params,
                                               unsigned int flags)
{
    virLockManagerLockDaemonPrivate *priv = lock->privateData;
    g_autofree char *newName = NULL;
    g_autofree char *newLockspace = NULL;
    bool autoCreate = false;

    virCheckFlags(VIR_LOCK_MANAGER_RESOURCE_READONLY |
                  VIR_LOCK_MANAGER_RESOURCE_SHARED, -1);

    if (flags & VIR_LOCK_MANAGER_RESOURCE_READONLY)
        return 0;

    switch (type) {
    case VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK:
        if (params || nparams) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unexpected parameters for disk resource"));
            return -1;
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
            if (virLockManagerGetLVMKey(name, &newName) < 0)
                return -1;

            if (newName) {
                VIR_DEBUG("Got an LVM UUID %s for %s", newName, name);
                newLockspace = g_strdup(driver->lvmLockSpaceDir);
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
                return -1;

            if (newName) {
                VIR_DEBUG("Got an SCSI ID %s for %s", newName, name);
                newLockspace = g_strdup(driver->scsiLockSpaceDir);
                autoCreate = true;
                break;
            }
            virResetLastError();
            /* Fallback to generic non-block code */
        }

        if (driver->fileLockSpaceDir) {
            newLockspace = g_strdup(driver->fileLockSpaceDir);
            if (virCryptoHashString(VIR_CRYPTO_HASH_SHA256, name, &newName) < 0)
                return -1;
            autoCreate = true;
            VIR_DEBUG("Using indirect lease %s for %s", newName, name);
        } else {
            newLockspace = g_strdup("");
            newName = g_strdup(name);
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
                    return -1;
                }
            } else if (STREQ(params[i].key, "lockspace")) {
                lockspace = params[i].value.str;
            } else if (STREQ(params[i].key, "path")) {
                path = params[i].value.str;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unexpected parameter %1$s for lease resource"),
                               params[i].key);
                return -1;
            }
        }
        if (!path || !lockspace) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing path or lockspace for lease resource"));
            return -1;
        }
        newLockspace = g_strdup_printf("%s/%s", path, lockspace);
        newName = g_strdup(name);

    }   break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown lock manager object type %1$d"),
                       type);
        return -1;
    }

    VIR_EXPAND_N(priv->resources, priv->nresources, 1);
    priv->resources[priv->nresources-1].lockspace = g_steal_pointer(&newLockspace);
    priv->resources[priv->nresources-1].name = g_steal_pointer(&newName);

    if (flags & VIR_LOCK_MANAGER_RESOURCE_SHARED)
        priv->resources[priv->nresources-1].flags |=
            VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_SHARED;

    if (autoCreate)
        priv->resources[priv->nresources-1].flags |=
            VIR_LOCK_SPACE_PROTOCOL_ACQUIRE_RESOURCE_AUTOCREATE;

    return 0;
}


static int virLockManagerLockDaemonAcquire(virLockManager *lock,
                                           const char *state G_GNUC_UNUSED,
                                           unsigned int flags,
                                           virDomainLockFailureAction action G_GNUC_UNUSED,
                                           int *fd)
{
    virNetClient *client = NULL;
    virNetClientProgram *program = NULL;
    int counter = 0;
    int rv = -1;
    virLockManagerLockDaemonPrivate *priv = lock->privateData;

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
            virLockSpaceProtocolAcquireResourceArgs args = { 0 };

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

static int virLockManagerLockDaemonRelease(virLockManager *lock,
                                           char **state,
                                           unsigned int flags)
{
    virNetClient *client = NULL;
    virNetClientProgram *program = NULL;
    int counter = 0;
    int rv = -1;
    size_t i;
    virLockManagerLockDaemonPrivate *priv = lock->privateData;

    virCheckFlags(0, -1);

    if (state)
        *state = NULL;

    if (!(client = virLockManagerLockDaemonConnect(lock, &program, &counter)))
        goto cleanup;

    for (i = 0; i < priv->nresources; i++) {
        virLockSpaceProtocolReleaseResourceArgs args = { 0 };

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


static int virLockManagerLockDaemonInquire(virLockManager *lock G_GNUC_UNUSED,
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
