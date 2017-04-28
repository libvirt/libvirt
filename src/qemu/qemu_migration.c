/*
 * qemu_migration.c: QEMU migration handling
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>

#include "qemu_migration.h"
#include "qemu_migration_cookie.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_capabilities.h"
#include "qemu_alias.h"
#include "qemu_cgroup.h"
#include "qemu_hotplug.h"
#include "qemu_blockjob.h"
#include "qemu_security.h"

#include "domain_audit.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virnetdevopenvswitch.h"
#include "datatypes.h"
#include "virfdstream.h"
#include "viruuid.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "rpc/virnetsocket.h"
#include "virstoragefile.h"
#include "viruri.h"
#include "virhook.h"
#include "virstring.h"
#include "virtypedparam.h"
#include "virprocess.h"
#include "nwfilter_conf.h"
#include "storage/storage_driver.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration");

VIR_ENUM_IMPL(qemuMigrationJobPhase, QEMU_MIGRATION_PHASE_LAST,
              "none",
              "perform2",
              "begin3",
              "perform3",
              "perform3_done",
              "confirm3_cancelled",
              "confirm3",
              "prepare",
              "finish2",
              "finish3",
);

VIR_ENUM_IMPL(qemuMigrationCompressMethod, QEMU_MIGRATION_COMPRESS_LAST,
              "xbzrle",
              "mt",
);

#define QEMU_MIGRATION_TLS_ALIAS_BASE "libvirt_migrate"


/* qemuMigrationCheckTLSCreds
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 *
 * Query the migration parameters looking for the 'tls-creds' parameter.
 * If found, then we can support setting or clearing the parameters and thus
 * can support TLS for migration.
 *
 * Returns 0 if we were able to successfully fetch the params and
 * additionally if the tls-creds parameter exists, saves it in the
 * private domain structure. Returns -1 on failure.
 */
static int
qemuMigrationCheckTLSCreds(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorMigrationParams migParams = { 0 };

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (qemuMonitorGetMigrationParams(priv->mon, &migParams) < 0)
        goto cleanup;

    /* NB: Could steal NULL pointer too! Let caller decide what to do. */
    VIR_STEAL_PTR(priv->migTLSAlias, migParams.migrateTLSAlias);

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    qemuMigrationParamsClear(&migParams);

    return ret;
}


/* qemuMigrationCheckSetupTLS
 * @conn: Connection pointer
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @cfg: configuration pointer
 * @asyncJob: migration job to join
 *
 * Check if TLS is possible and set up the environment. Assumes the caller
 * desires to use TLS (e.g. caller found VIR_MIGRATE_TLS flag).
 *
 * Ensure the qemu.conf has been properly configured to add an entry for
 * "migrate_tls_x509_cert_dir". Also check if the "tls-creds" parameter
 * was present from a query of migration parameters
 *
 * Returns 0 on success, -1 on error/failure
 */
static int
qemuMigrationCheckSetupTLS(virConnectPtr conn,
                           virQEMUDriverPtr driver,
                           virQEMUDriverConfigPtr cfg,
                           virDomainObjPtr vm,
                           qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!cfg->migrateTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("host migration TLS directory not configured"));
        return -1;
    }

    if (qemuMigrationCheckTLSCreds(driver, vm, asyncJob) < 0)
        return -1;

    if (!priv->migTLSAlias) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("TLS migration is not supported with this "
                         "QEMU binary"));
        return -1;
    }

    /* If there's a secret, then grab/store it now using the connection */
    if (cfg->migrateTLSx509secretUUID &&
        !(priv->migSecinfo =
          qemuDomainSecretInfoTLSNew(conn, priv, QEMU_MIGRATION_TLS_ALIAS_BASE,
                                     cfg->migrateTLSx509secretUUID)))
        return -1;

    return 0;
}


/* qemuMigrationAddTLSObjects
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @cfg: configuration pointer
 * @tlsListen: server or client
 * @asyncJob: Migration job to join
 * @tlsAlias: alias to be generated for TLS object
 * @secAlias: alias to be generated for a secinfo object
 * @migParams: migration parameters to set
 *
 * Create the TLS objects for the migration and set the migParams value
 *
 * Returns 0 on success, -1 on failure
 */
static int
qemuMigrationAddTLSObjects(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virQEMUDriverConfigPtr cfg,
                           bool tlsListen,
                           qemuDomainAsyncJob asyncJob,
                           char **tlsAlias,
                           char **secAlias,
                           qemuMonitorMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virJSONValuePtr tlsProps = NULL;
    virJSONValuePtr secProps = NULL;

    if (qemuDomainGetTLSObjects(priv->qemuCaps, priv->migSecinfo,
                                cfg->migrateTLSx509certdir, tlsListen,
                                cfg->migrateTLSx509verify,
                                QEMU_MIGRATION_TLS_ALIAS_BASE,
                                &tlsProps, tlsAlias, &secProps, secAlias) < 0)
        goto error;

    /* Ensure the domain doesn't already have the TLS objects defined...
     * This should prevent any issues just in case some cleanup wasn't
     * properly completed (both src and dst use the same alias) or
     * some other error path between now and perform . */
    qemuDomainDelTLSObjects(driver, vm, asyncJob, *secAlias, *tlsAlias);

    if (qemuDomainAddTLSObjects(driver, vm, asyncJob, *secAlias, &secProps,
                                *tlsAlias, &tlsProps) < 0)
        goto error;

    if (VIR_STRDUP(migParams->migrateTLSAlias, *tlsAlias) < 0)
        goto error;

    return 0;

 error:
    virJSONValueFree(tlsProps);
    virJSONValueFree(secProps);
    return -1;
}


static void
qemuMigrationStoreDomainState(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    priv->preMigrationState = virDomainObjGetState(vm, NULL);

    VIR_DEBUG("Storing pre-migration state=%d domain=%p",
              priv->preMigrationState, vm);
}

/* Returns true if the domain was resumed, false otherwise */
static bool
qemuMigrationRestoreDomainState(virConnectPtr conn, virDomainObjPtr vm)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int reason;
    virDomainState state = virDomainObjGetState(vm, &reason);
    bool ret = false;

    VIR_DEBUG("driver=%p, vm=%p, pre-mig-state=%s, state=%s, reason=%s",
              driver, vm,
              virDomainStateTypeToString(priv->preMigrationState),
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason));

    if (state != VIR_DOMAIN_PAUSED ||
        reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED)
        goto cleanup;

    if (priv->preMigrationState == VIR_DOMAIN_RUNNING) {
        /* This is basically the only restore possibility that's safe
         * and we should attempt to do */

        VIR_DEBUG("Restoring pre-migration state due to migration error");

        /* we got here through some sort of failure; start the domain again */
        if (qemuProcessStartCPUs(driver, vm, conn,
                                 VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best */
            VIR_ERROR(_("Failed to resume guest %s after failure"), vm->def->name);
            goto cleanup;
        }
        ret = true;
    }

 cleanup:
    priv->preMigrationState = VIR_DOMAIN_NOSTATE;
    return ret;
}


static int
qemuMigrationPrecreateDisk(virConnectPtr conn,
                           virDomainDiskDefPtr disk,
                           unsigned long long capacity)
{
    int ret = -1;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    char *volName = NULL, *basePath = NULL;
    char *volStr = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *format = NULL;
    unsigned int flags = 0;

    VIR_DEBUG("Precreate disk type=%s", virStorageTypeToString(disk->src->type));

    switch ((virStorageType) disk->src->type) {
    case VIR_STORAGE_TYPE_FILE:
        if (!virDomainDiskGetSource(disk)) {
            VIR_DEBUG("Dropping sourceless disk '%s'",
                      disk->dst);
            return 0;
        }

        if (VIR_STRDUP(basePath, disk->src->path) < 0)
            goto cleanup;

        if (!(volName = strrchr(basePath, '/'))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("malformed disk path: %s"),
                           disk->src->path);
            goto cleanup;
        }

        *volName = '\0';
        volName++;

        if (!(pool = storagePoolLookupByTargetPath(conn, basePath)))
            goto cleanup;
        format = virStorageFileFormatTypeToString(disk->src->format);
        if (disk->src->format == VIR_STORAGE_FILE_QCOW2)
            flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
        break;

    case VIR_STORAGE_TYPE_VOLUME:
        if (!(pool = virStoragePoolLookupByName(conn, disk->src->srcpool->pool)))
            goto cleanup;
        format = virStorageFileFormatTypeToString(disk->src->format);
        volName = disk->src->srcpool->volume;
        if (disk->src->format == VIR_STORAGE_FILE_QCOW2)
            flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
        break;

    case VIR_STORAGE_TYPE_NETWORK:
        VIR_DEBUG("Skipping creation of network disk '%s'",
                  disk->dst);
        return 0;

    case VIR_STORAGE_TYPE_BLOCK:
    case VIR_STORAGE_TYPE_DIR:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot precreate storage for disk type '%s'"),
                       virStorageTypeToString(disk->src->type));
        goto cleanup;
    }

    if ((vol = virStorageVolLookupByName(pool, volName))) {
        VIR_DEBUG("Skipping creation of already existing volume of name '%s'",
                  volName);
        ret = 0;
        goto cleanup;
    }

    virBufferAddLit(&buf, "<volume>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", volName);
    virBufferAsprintf(&buf, "<capacity>%llu</capacity>\n", capacity);
    virBufferAddLit(&buf, "<target>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<format type='%s'/>\n", format);
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</target>\n");
    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</volume>\n");

    if (!(volStr = virBufferContentAndReset(&buf))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to create volume XML"));
        goto cleanup;
    }

    if (!(vol = virStorageVolCreateXML(pool, volStr, flags)))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(basePath);
    VIR_FREE(volStr);
    virObjectUnref(vol);
    virObjectUnref(pool);
    return ret;
}

static bool
qemuMigrateDisk(virDomainDiskDef const *disk,
                size_t nmigrate_disks, const char **migrate_disks)
{
    size_t i;

    /* Check if the disk alias is in the list */
    if (nmigrate_disks) {
        for (i = 0; i < nmigrate_disks; i++) {
            if (STREQ(disk->dst, migrate_disks[i]))
                return true;
        }
        return false;
    }

    /* Default is to migrate only non-shared non-readonly disks
     * with source */
    return !disk->src->shared && !disk->src->readonly &&
           !virStorageSourceIsEmpty(disk->src);
}


static int
qemuMigrationPrecreateStorage(virConnectPtr conn,
                              virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                              virDomainObjPtr vm,
                              qemuMigrationCookieNBDPtr nbd,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              bool incremental)
{
    int ret = -1;
    size_t i = 0;

    if (!nbd || !nbd->ndisks)
        return 0;

    for (i = 0; i < nbd->ndisks; i++) {
        virDomainDiskDefPtr disk;
        const char *diskSrcPath;

        VIR_DEBUG("Looking up disk target '%s' (capacity=%llu)",
                  nbd->disks[i].target, nbd->disks[i].capacity);

        if (!(disk = virDomainDiskByName(vm->def, nbd->disks[i].target,
                                         false))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to find disk by target: %s"),
                           nbd->disks[i].target);
            goto cleanup;
        }

        diskSrcPath = virDomainDiskGetSource(disk);

        /* Skip disks we don't want to migrate and already existing disks. */
        if (!qemuMigrateDisk(disk, nmigrate_disks, migrate_disks) ||
            (diskSrcPath && virFileExists(diskSrcPath))) {
            continue;
        }

        if (incremental) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("pre-creation of storage targets for incremental "
                             "storage migration is not supported"));
            goto cleanup;
        }

        VIR_DEBUG("Proceeding with disk source %s", NULLSTR(diskSrcPath));

        if (qemuMigrationPrecreateDisk(conn, disk, nbd->disks[i].capacity) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/**
 * qemuMigrationStartNBDServer:
 * @driver: qemu driver
 * @vm: domain
 *
 * Starts NBD server. This is a newer method to copy
 * storage during migration than using 'blk' and 'inc'
 * arguments in 'migrate' monitor command.
 * Error is reported here.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationStartNBDServer(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            const char *listenAddr,
                            size_t nmigrate_disks,
                            const char **migrate_disks,
                            int nbdPort)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned short port = 0;
    char *diskAlias = NULL;
    size_t i;

    if (nbdPort < 0 || nbdPort > USHRT_MAX) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("nbd port must be in range 0-65535"));
        return -1;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];

        /* check whether disk should be migrated */
        if (!qemuMigrateDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (disk->src->readonly || virStorageSourceIsEmpty(disk->src)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("Cannot migrate empty or read-only disk %s"),
                           disk->dst);
            goto cleanup;
        }

        VIR_FREE(diskAlias);
        if (!(diskAlias = qemuAliasFromDisk(disk)))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
            goto cleanup;

        if (port == 0) {
            if (nbdPort)
                port = nbdPort;
            else if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto exit_monitor;

            if (qemuMonitorNBDServerStart(priv->mon, listenAddr, port) < 0)
                goto exit_monitor;
        }

        if (qemuMonitorNBDServerAdd(priv->mon, diskAlias, true) < 0)
            goto exit_monitor;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            goto cleanup;
    }

    priv->nbdPort = port;
    ret = 0;

 cleanup:
    VIR_FREE(diskAlias);
    if (ret < 0 && nbdPort == 0)
        virPortAllocatorRelease(driver->migrationPorts, port);
    return ret;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto cleanup;
}


static int
qemuMigrationStopNBDServer(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuMigrationCookiePtr mig)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!mig->nbd)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        return -1;

    if (qemuMonitorNBDServerStop(priv->mon) < 0)
        VIR_WARN("Unable to stop NBD server");
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return -1;

    virPortAllocatorRelease(driver->migrationPorts, priv->nbdPort);
    priv->nbdPort = 0;
    return 0;
}


/**
 * qemuMigrationDriveMirrorReady:
 * @driver: qemu driver
 * @vm: domain
 *
 * Check the status of all drive-mirrors started by
 * qemuMigrationDriveMirror. Any pending block job events
 * for the mirrored disks will be processed.
 *
 * Returns 1 if all mirrors are "ready",
 *         0 if some mirrors are still performing initial sync,
 *        -1 on error.
 */
static int
qemuMigrationDriveMirrorReady(virQEMUDriverPtr driver,
                              virDomainObjPtr vm,
                              qemuDomainAsyncJob asyncJob)
{
    size_t i;
    size_t notReady = 0;
    int status;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        status = qemuBlockJobUpdate(driver, vm, asyncJob, disk);
        if (status == VIR_DOMAIN_BLOCK_JOB_FAILED) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("migration of disk %s failed"),
                           disk->dst);
            return -1;
        }

        if (disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_READY)
            notReady++;
    }

    if (notReady) {
        VIR_DEBUG("Waiting for %zu disk mirrors to get ready", notReady);
        return 0;
    } else {
        VIR_DEBUG("All disk mirrors are ready");
        return 1;
    }
}


/*
 * If @check is true, the function will report an error and return a different
 * code in case a block job fails. This way we can properly abort migration in
 * case some block jobs failed once all memory has already been transferred.
 *
 * Returns 1 if all mirrors are gone,
 *         0 if some mirrors are still active,
 *         -1 some mirrors failed but some are still active,
 *         -2 all mirrors are gone but some of them failed.
 */
static int
qemuMigrationDriveMirrorCancelled(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuDomainAsyncJob asyncJob,
                                  bool check)
{
    size_t i;
    size_t active = 0;
    size_t completed = 0;
    int status;
    bool failed = false;

 retry:
    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        status = qemuBlockJobUpdate(driver, vm, asyncJob, disk);
        switch (status) {
        case VIR_DOMAIN_BLOCK_JOB_FAILED:
            if (check) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("migration of disk %s failed"),
                               disk->dst);
                failed = true;
            }
            /* fallthrough */
        case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
            qemuBlockJobSyncEnd(driver, vm, asyncJob, disk);
            diskPriv->migrating = false;
            break;

        default:
            active++;
        }

        if (status == VIR_DOMAIN_BLOCK_JOB_COMPLETED)
            completed++;
    }

    /* Updating completed block job drops the lock thus we have to recheck
     * block jobs for disks that reside before the disk(s) with completed
     * block job.
     */
    if (completed > 0) {
        completed = 0;
        active = 0;
        goto retry;
    }

    if (failed) {
        if (active) {
            VIR_DEBUG("Some disk mirrors failed; still waiting for %zu "
                      "disk mirrors to finish", active);
            return -1;
        } else {
            VIR_DEBUG("All disk mirrors are gone; some of them failed");
            return -2;
        }
    } else {
        if (active) {
            VIR_DEBUG("Waiting for %zu disk mirrors to finish", active);
            return 0;
        } else {
            VIR_DEBUG("All disk mirrors are gone");
            return 1;
        }
    }
}


/*
 * Returns 0 on success,
 *         1 when job is already completed or it failed and failNoJob is false,
 *         -1 on error or when job failed and failNoJob is true.
 */
static int
qemuMigrationCancelOneDriveMirror(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  virDomainDiskDefPtr disk,
                                  bool failNoJob,
                                  qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *diskAlias = NULL;
    int ret = -1;
    int status;
    int rv;

    status = qemuBlockJobUpdate(driver, vm, asyncJob, disk);
    switch (status) {
    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        if (failNoJob) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("migration of disk %s failed"),
                           disk->dst);
            return -1;
        }
        return 1;

    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        return 1;
    }

    if (!(diskAlias = qemuAliasFromDisk(disk)))
        return -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    rv = qemuMonitorBlockJobCancel(priv->mon, diskAlias, true);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(diskAlias);
    return ret;
}


/**
 * qemuMigrationCancelDriveMirror:
 * @driver: qemu driver
 * @vm: domain
 * @check: if true report an error when some of the mirrors fails
 *
 * Cancel all drive-mirrors started by qemuMigrationDriveMirror.
 * Any pending block job events for the affected disks will be
 * processed.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationCancelDriveMirror(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               bool check,
                               qemuDomainAsyncJob asyncJob,
                               virConnectPtr dconn)
{
    virErrorPtr err = NULL;
    int ret = -1;
    size_t i;
    int rv;
    bool failed = false;

    VIR_DEBUG("Cancelling drive mirrors for domain %s", vm->def->name);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        rv = qemuMigrationCancelOneDriveMirror(driver, vm, disk,
                                               check, asyncJob);
        if (rv != 0) {
            if (rv < 0) {
                if (!err)
                    err = virSaveLastError();
                failed = true;
            }
            qemuBlockJobSyncEnd(driver, vm, asyncJob, disk);
            diskPriv->migrating = false;
        }
    }

    while ((rv = qemuMigrationDriveMirrorCancelled(driver, vm, asyncJob,
                                                   check)) != 1) {
        if (check && !failed &&
            dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            failed = true;
        }

        if (rv < 0) {
            failed = true;
            if (rv == -2)
                break;
        }

        if (failed && !err)
            err = virSaveLastError();

        if (virDomainObjWait(vm) < 0)
            goto cleanup;
    }

    ret = failed ? -1 : 0;

 cleanup:
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
    return ret;
}


/**
 * qemuMigrationDriveMirror:
 * @driver: qemu driver
 * @vm: domain
 * @mig: migration cookie
 * @host: where are we migrating to
 * @speed: bandwidth limit in MiB/s
 * @migrate_flags: migrate monitor command flags
 *
 * Run drive-mirror to feed NBD server running on dst and wait
 * till the process switches into another phase where writes go
 * simultaneously to both source and destination. On success,
 * update @migrate_flags so we don't tell 'migrate' command
 * to do the very same operation. On failure, the caller is
 * expected to call qemuMigrationCancelDriveMirror to stop all
 * running mirrors.
 *
 * Returns 0 on success (@migrate_flags updated),
 *        -1 otherwise.
 */
static int
qemuMigrationDriveMirror(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMigrationCookiePtr mig,
                         const char *host,
                         unsigned long speed,
                         unsigned int *migrate_flags,
                         size_t nmigrate_disks,
                         const char **migrate_disks,
                         virConnectPtr dconn)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int port;
    size_t i;
    char *diskAlias = NULL;
    char *nbd_dest = NULL;
    char *hoststr = NULL;
    unsigned long long mirror_speed = speed;
    unsigned int mirror_flags = VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT;
    int rv;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    VIR_DEBUG("Starting drive mirrors for domain %s", vm->def->name);

    if (mirror_speed > LLONG_MAX >> 20) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth must be less than %llu"),
                       LLONG_MAX >> 20);
        goto cleanup;
    }
    mirror_speed <<= 20;

    /* steal NBD port and thus prevent its propagation back to destination */
    port = mig->nbd->port;
    mig->nbd->port = 0;

    /* escape literal IPv6 address */
    if (strchr(host, ':')) {
        if (virAsprintf(&hoststr, "[%s]", host) < 0)
            goto cleanup;
    } else if (VIR_STRDUP(hoststr, host) < 0) {
        goto cleanup;
    }

    if (*migrate_flags & QEMU_MONITOR_MIGRATE_NON_SHARED_INC)
        mirror_flags |= VIR_DOMAIN_BLOCK_REBASE_SHALLOW;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        int mon_ret;

        /* check whether disk should be migrated */
        if (!qemuMigrateDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (!(diskAlias = qemuAliasFromDisk(disk)) ||
            (virAsprintf(&nbd_dest, "nbd:%s:%d:exportname=%s",
                         hoststr, port, diskAlias) < 0))
            goto cleanup;

        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;

        qemuBlockJobSyncBegin(disk);
        /* Force "raw" format for NBD export */
        mon_ret = qemuMonitorDriveMirror(priv->mon, diskAlias, nbd_dest,
                                         "raw", mirror_speed, 0, 0, mirror_flags);
        VIR_FREE(diskAlias);
        VIR_FREE(nbd_dest);

        if (qemuDomainObjExitMonitor(driver, vm) < 0 || mon_ret < 0) {
            qemuBlockJobSyncEnd(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT, disk);
            goto cleanup;
        }
        diskPriv->migrating = true;

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            goto cleanup;
        }
    }

    while ((rv = qemuMigrationDriveMirrorReady(driver, vm,
                                               QEMU_ASYNC_JOB_MIGRATION_OUT)) != 1) {
        if (rv < 0)
            goto cleanup;

        if (priv->job.abortJob) {
            priv->job.current->type = VIR_DOMAIN_JOB_CANCELLED;
            virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                           qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                           _("canceled by client"));
            goto cleanup;
        }

        if (dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            goto cleanup;
        }

        if (virDomainObjWait(vm) < 0)
            goto cleanup;
    }

    /* Okay, all disks are ready. Modify migrate_flags */
    *migrate_flags &= ~(QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                        QEMU_MONITOR_MIGRATE_NON_SHARED_INC);
    ret = 0;

 cleanup:
    virObjectUnref(cfg);
    VIR_FREE(diskAlias);
    VIR_FREE(nbd_dest);
    VIR_FREE(hoststr);
    return ret;
}


/**
 * qemuMigrationIsAllowedHostdev:
 * @def: domain definition
 *
 * Checks that @def does not contain any host devices unsupported accross
 * migrations. Returns true if the vm is allowed to migrate.
 */
static bool
qemuMigrationIsAllowedHostdev(const virDomainDef *def)
{
    size_t i;

    /* Migration with USB host devices is allowed, all other devices are
     * forbidden. */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has assigned non-USB host devices"));
            return false;
        }
    }

    return true;
}


/**
 * qemuMigrationIsAllowed:
 * @driver: qemu driver struct
 * @vm: domain object
 * @remote: migration is remote
 * @flags: migration flags (see struct virDomainMigrateFlags)
 *
 * Validates that the configuration of @vm can be migrated in various
 * situations. If @remote is true, the migration happens to remote host. @flags
 * is used to check various special migration types according to the request.
 *
 * Returns true if migration is supported. Reports libvirt error and returns
 * false otherwise.
 */
bool
qemuMigrationIsAllowed(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       bool remote,
                       unsigned int flags)
{
    int nsnapshots;
    int pauseReason;
    size_t i;

    /* perform these checks only when migrating to remote hosts */
    if (remote) {
        nsnapshots = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0);
        if (nsnapshots < 0)
            return false;

        if (nsnapshots > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot migrate domain with %d snapshots"),
                           nsnapshots);
            return false;
        }

        /* cancel migration if disk I/O error is emitted while migrating */
        if (flags & VIR_MIGRATE_ABORT_ON_ERROR &&
            !(flags & VIR_MIGRATE_OFFLINE) &&
            virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
            pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot migrate domain with I/O error"));
            return false;
        }

    }

    /* following checks don't make sense for offline migration */
    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        if (qemuProcessAutoDestroyActive(driver, vm)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("domain is marked for auto destroy"));
            return false;
        }


        if (qemuDomainHasBlockjob(vm, false)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has active block job"));
            return false;
        }

        if (!qemuMigrationIsAllowedHostdev(vm->def))
            return false;

        if (vm->def->cpu) {
            /* QEMU blocks migration and save with invariant TSC enabled
             * unless TSC frequency is explicitly set.
             */
            if (virCPUCheckFeature(vm->def->os.arch, vm->def->cpu,
                                   "invtsc") == 1) {
                bool block = true;

                for (i = 0; i < vm->def->clock.ntimers; i++) {
                    virDomainTimerDefPtr timer = vm->def->clock.timers[i];

                    if (timer->name == VIR_DOMAIN_TIMER_NAME_TSC &&
                        timer->frequency > 0) {
                        block = false;
                        break;
                    }
                }

                if (block) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("domain has 'invtsc' CPU feature but "
                                     "TSC frequency is not specified"));
                    return false;
                }
            }
        }

        /* Verify that memory device config can be transferred reliably */
        for (i = 0; i < vm->def->nmems; i++) {
            virDomainMemoryDefPtr mem = vm->def->mems[i];

            if (mem->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
                mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("domain's dimm info lacks slot ID "
                                 "or base address"));

                return false;
            }
        }

        if (vm->def->nshmems) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("migration with shmem device is not supported"));
            return false;
        }
    }

    return true;
}

static bool
qemuMigrationIsSafe(virDomainDefPtr def,
                    size_t nmigrate_disks,
                    const char **migrate_disks,
                    unsigned int flags)

{
    bool storagemigration = flags & (VIR_MIGRATE_NON_SHARED_DISK |
                                     VIR_MIGRATE_NON_SHARED_INC);
    size_t i;
    int rc;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk = def->disks[i];
        const char *src = virDomainDiskGetSource(disk);

        /* Our code elsewhere guarantees shared disks are either readonly (in
         * which case cache mode doesn't matter) or used with cache=none */
        if (virStorageSourceIsEmpty(disk->src) ||
            disk->src->readonly ||
            disk->src->shared ||
            disk->cachemode == VIR_DOMAIN_DISK_CACHE_DISABLE)
            continue;

        /* disks which are migrated by qemu are safe too */
        if (storagemigration &&
            qemuMigrateDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_FILE) {
            if ((rc = virFileIsSharedFS(src)) < 0)
                return false;
            else if (rc == 0)
                continue;
            if ((rc = virStorageFileIsClusterFS(src)) < 0)
                return false;
            else if (rc == 1)
                continue;
        } else if (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
                   disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD) {
            continue;
        }

        virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                       _("Migration may lead to data corruption if disks"
                         " use cache != none"));
        return false;
    }

    return true;
}

/** qemuMigrationSetOffline
 * Pause domain for non-live migration.
 */
int
qemuMigrationSetOffline(virQEMUDriverPtr driver,
                        virDomainObjPtr vm)
{
    int ret;
    VIR_DEBUG("driver=%p vm=%p", driver, vm);
    ret = qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_MIGRATION,
                              QEMU_ASYNC_JOB_MIGRATION_OUT);
    if (ret == 0) {
        virObjectEventPtr event;

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_SUSPENDED,
                                         VIR_DOMAIN_EVENT_SUSPENDED_MIGRATED);
        qemuDomainEventQueue(driver, event);
    }

    return ret;
}


void
qemuMigrationPostcopyFailed(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    if (state != VIR_DOMAIN_PAUSED &&
        state != VIR_DOMAIN_RUNNING)
        return;

    if (state == VIR_DOMAIN_PAUSED &&
        reason == VIR_DOMAIN_PAUSED_POSTCOPY_FAILED)
        return;

    VIR_WARN("Migration of domain %s failed during post-copy; "
             "leaving the domain paused", vm->def->name);

    if (state == VIR_DOMAIN_RUNNING) {
        virObjectEventPtr event;

        if (qemuProcessStopCPUs(driver, vm,
                                VIR_DOMAIN_PAUSED_POSTCOPY_FAILED,
                                QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
            VIR_WARN("Unable to pause guest CPUs for %s", vm->def->name);
            return;
        }

        event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_SUSPENDED,
                                VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED);
        qemuDomainEventQueue(driver, event);
    } else {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                             VIR_DOMAIN_PAUSED_POSTCOPY_FAILED);
    }
}


static int
qemuMigrationSetOption(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       qemuMonitorMigrationCaps capability,
                       bool state,
                       qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, job) < 0)
        return -1;

    ret = qemuMonitorGetMigrationCapability(priv->mon, capability);

    if (ret < 0) {
        goto cleanup;
    } else if (ret == 0 && !state) {
        /* Unsupported but we want it off anyway */
        goto cleanup;
    } else if (ret == 0) {
        if (job == QEMU_ASYNC_JOB_MIGRATION_IN) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("Migration option '%s' is not supported by "
                             "target QEMU binary"),
                           qemuMonitorMigrationCapsTypeToString(capability));
        } else {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("Migration option '%s' is not supported by "
                             "source QEMU binary"),
                           qemuMonitorMigrationCapsTypeToString(capability));
        }
        ret = -1;
        goto cleanup;
    }

    ret = qemuMonitorSetMigrationCapability(priv->mon, capability, state);

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    return ret;
}


static int
qemuMigrationSetPostCopy(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         bool state,
                         qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_POSTCOPY,
                               state, job) < 0)
        return -1;

    priv->job.postcopyEnabled = state;
    return 0;
}


static int
qemuMigrationWaitForSpice(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_SEAMLESS_MIGRATION) ||
        !priv->job.spiceMigration)
        return 0;

    VIR_DEBUG("Waiting for SPICE to finish migration");
    while (!priv->job.spiceMigrated && !priv->job.abortJob) {
        if (virDomainObjWait(vm) < 0)
            return -1;
    }
    return 0;
}


static void
qemuMigrationUpdateJobType(qemuDomainJobInfoPtr jobInfo)
{
    switch ((qemuMonitorMigrationStatus) jobInfo->stats.status) {
    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
        jobInfo->type = VIR_DOMAIN_JOB_COMPLETED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
        jobInfo->type = VIR_DOMAIN_JOB_NONE;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
        jobInfo->type = VIR_DOMAIN_JOB_FAILED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
        jobInfo->type = VIR_DOMAIN_JOB_CANCELLED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        break;
    }
}


int
qemuMigrationFetchJobStatus(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            qemuDomainAsyncJob asyncJob,
                            qemuDomainJobInfoPtr jobInfo)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rv;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    memset(&jobInfo->stats, 0, sizeof(jobInfo->stats));
    rv = qemuMonitorGetMigrationStats(priv->mon, &jobInfo->stats);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        return -1;

    qemuMigrationUpdateJobType(jobInfo);
    return qemuDomainJobInfoUpdateTime(jobInfo);
}


static const char *
qemuMigrationJobName(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    switch (priv->job.asyncJob) {
    case QEMU_ASYNC_JOB_MIGRATION_OUT:
        return _("migration job");
    case QEMU_ASYNC_JOB_SAVE:
        return _("domain save job");
    case QEMU_ASYNC_JOB_DUMP:
        return _("domain core dump job");
    default:
        return _("job");
    }
}


static int
qemuMigrationUpdateJobStatus(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    qemuDomainJobInfo newInfo = *jobInfo;

    if (qemuMigrationFetchJobStatus(driver, vm, asyncJob, &newInfo) < 0)
        return -1;

    *jobInfo = newInfo;
    return 0;
}


static int
qemuMigrationCheckJobStatus(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            qemuDomainAsyncJob asyncJob,
                            bool updateJobStats)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;

    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);

    if (events)
        qemuMigrationUpdateJobType(jobInfo);
    else if (qemuMigrationUpdateJobStatus(driver, vm, asyncJob) < 0)
        return -1;

    switch (jobInfo->type) {
    case VIR_DOMAIN_JOB_NONE:
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("is not active"));
        return -1;

    case VIR_DOMAIN_JOB_FAILED:
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("unexpectedly failed"));
        return -1;

    case VIR_DOMAIN_JOB_CANCELLED:
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("canceled by client"));
        return -1;

    case VIR_DOMAIN_JOB_COMPLETED:
        /* Fetch statistics of a completed migration */
        if (events && updateJobStats &&
            qemuMigrationUpdateJobStatus(driver, vm, asyncJob) < 0)
            return -1;
        break;

    case VIR_DOMAIN_JOB_BOUNDED:
    case VIR_DOMAIN_JOB_UNBOUNDED:
    case VIR_DOMAIN_JOB_LAST:
        break;
    }
    return 0;
}


enum qemuMigrationCompletedFlags {
    QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR = (1 << 0),
    QEMU_MIGRATION_COMPLETED_CHECK_STORAGE  = (1 << 1),
    QEMU_MIGRATION_COMPLETED_UPDATE_STATS   = (1 << 2),
    QEMU_MIGRATION_COMPLETED_POSTCOPY       = (1 << 3),
};

/**
 * Returns 1 if migration completed successfully,
 *         0 if the domain is still being migrated,
 *         -1 migration failed,
 *         -2 something else failed, we need to cancel migration.
 */
static int
qemuMigrationCompleted(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       qemuDomainAsyncJob asyncJob,
                       virConnectPtr dconn,
                       unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    int pauseReason;
    bool updateStats = !!(flags & QEMU_MIGRATION_COMPLETED_UPDATE_STATS);

    if (qemuMigrationCheckJobStatus(driver, vm, asyncJob, updateStats) < 0)
        goto error;

    if (flags & QEMU_MIGRATION_COMPLETED_CHECK_STORAGE &&
        qemuMigrationDriveMirrorReady(driver, vm, asyncJob) < 0)
        goto error;

    if (flags & QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR &&
        virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
        pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
        virReportError(VIR_ERR_OPERATION_FAILED, _("%s: %s"),
                       qemuMigrationJobName(vm), _("failed due to I/O error"));
        goto error;
    }

    if (dconn && virConnectIsAlive(dconn) <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Lost connection to destination host"));
        goto error;
    }

    /* In case of postcopy the source considers migration completed at the
     * moment it switched from active to postcopy-active state. The destination
     * will continue waiting until the migrate state changes to completed.
     */
    if (flags & QEMU_MIGRATION_COMPLETED_POSTCOPY &&
        jobInfo->type == VIR_DOMAIN_JOB_UNBOUNDED &&
        jobInfo->stats.status == QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY) {
        VIR_DEBUG("Migration switched to post-copy");
        if (updateStats &&
            qemuMigrationUpdateJobStatus(driver, vm, asyncJob) < 0)
            goto error;
        return 1;
    }

    if (jobInfo->type == VIR_DOMAIN_JOB_COMPLETED)
        return 1;
    else
        return 0;

 error:
    if (jobInfo->type == VIR_DOMAIN_JOB_UNBOUNDED) {
        /* The migration was aborted by us rather than QEMU itself. */
        jobInfo->type = VIR_DOMAIN_JOB_FAILED;
        return -2;
    } else if (jobInfo->type == VIR_DOMAIN_JOB_COMPLETED) {
        jobInfo->type = VIR_DOMAIN_JOB_FAILED;
        return -1;
    } else {
        return -1;
    }
}


/* Returns 0 on success, -2 when migration needs to be cancelled, or -1 when
 * QEMU reports failed migration.
 */
static int
qemuMigrationWaitForCompletion(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               qemuDomainAsyncJob asyncJob,
                               virConnectPtr dconn,
                               unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = priv->job.current;
    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    int rv;

    flags |= QEMU_MIGRATION_COMPLETED_UPDATE_STATS;

    jobInfo->type = VIR_DOMAIN_JOB_UNBOUNDED;
    while ((rv = qemuMigrationCompleted(driver, vm, asyncJob,
                                        dconn, flags)) != 1) {
        if (rv < 0)
            return rv;

        if (events) {
            if (virDomainObjWait(vm) < 0) {
                jobInfo->type = VIR_DOMAIN_JOB_FAILED;
                return -2;
            }
        } else {
            /* Poll every 50ms for progress & to allow cancellation */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000ull };

            virObjectUnlock(vm);
            nanosleep(&ts, NULL);
            virObjectLock(vm);
        }
    }

    qemuDomainJobInfoUpdateDowntime(jobInfo);
    VIR_FREE(priv->job.completed);
    if (VIR_ALLOC(priv->job.completed) == 0)
        *priv->job.completed = *jobInfo;

    return 0;
}


static int
qemuMigrationWaitForDestCompletion(virQEMUDriverPtr driver,
                                   virDomainObjPtr vm,
                                   qemuDomainAsyncJob asyncJob,
                                   bool postcopy)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    unsigned int flags = 0;
    int rv;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT))
        return 0;

    VIR_DEBUG("Waiting for incoming migration to complete");

    if (postcopy)
        flags = QEMU_MIGRATION_COMPLETED_POSTCOPY;

    while ((rv = qemuMigrationCompleted(driver, vm, asyncJob,
                                        NULL, flags)) != 1) {
        if (rv < 0 || virDomainObjWait(vm) < 0)
            return -1;
    }

    return 0;
}


static int
qemuDomainMigrateGraphicsRelocate(virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuMigrationCookiePtr cookie,
                                  const char *graphicsuri)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    const char *listenAddress = NULL;
    virSocketAddr addr;
    virURIPtr uri = NULL;
    int type = -1;
    int port = -1;
    int tlsPort = -1;
    const char *tlsSubject = NULL;

    if (!cookie || (!cookie->graphics && !graphicsuri))
        return 0;

    if (graphicsuri && !(uri = virURIParse(graphicsuri)))
        goto cleanup;

    if (cookie->graphics) {
        type = cookie->graphics->type;

        listenAddress = cookie->graphics->listen;

        if (!listenAddress ||
            (virSocketAddrParse(&addr, listenAddress, AF_UNSPEC) > 0 &&
             virSocketAddrIsWildcard(&addr)))
            listenAddress = cookie->remoteHostname;

        port = cookie->graphics->port;
        tlsPort = cookie->graphics->tlsPort;
        tlsSubject = cookie->graphics->tlsSubject;
    }

    if (uri) {
        size_t i;

        if ((type = virDomainGraphicsTypeFromString(uri->scheme)) < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("unknown graphics type %s"), uri->scheme);
            goto cleanup;
        }

        if (uri->server)
            listenAddress = uri->server;
        if (uri->port > 0)
            port = uri->port;

        for (i = 0; i < uri->paramsCount; i++) {
            virURIParamPtr param = uri->params + i;

            if (STRCASEEQ(param->name, "tlsPort")) {
                if (virStrToLong_i(param->value, NULL, 10, &tlsPort) < 0) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("invalid tlsPort number: %s"),
                                   param->value);
                    goto cleanup;
                }
            } else if (STRCASEEQ(param->name, "tlsSubject")) {
                tlsSubject = param->value;
            }
        }
    }

    /* QEMU doesn't support VNC relocation yet, so
     * skip it to avoid generating an error
     */
    if (type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        ret = 0;
        goto cleanup;
    }

    /* Older libvirt sends port == 0 for listen type='none' graphics. It's
     * safe to ignore such requests since relocation to unknown port does
     * not make sense in general.
     */
    if (port <= 0 && tlsPort <= 0) {
        ret = 0;
        goto cleanup;
    }

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
        ret = qemuMonitorGraphicsRelocate(priv->mon, type, listenAddress,
                                          port, tlsPort, tlsSubject);
        priv->job.spiceMigration = !ret;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            ret = -1;
    }

 cleanup:
    virURIFree(uri);
    return ret;
}


static int
qemuDomainMigrateOPDRelocate(virQEMUDriverPtr driver ATTRIBUTE_UNUSED,
                             virDomainObjPtr vm,
                             qemuMigrationCookiePtr cookie)
{
    virDomainNetDefPtr netptr;
    int ret = -1;
    size_t i;

    for (i = 0; i < cookie->network->nnets; i++) {
        netptr = vm->def->nets[i];

        switch (cookie->network->net[i].vporttype) {
        case VIR_NETDEV_VPORT_PROFILE_NONE:
        case VIR_NETDEV_VPORT_PROFILE_8021QBG:
        case VIR_NETDEV_VPORT_PROFILE_8021QBH:
           break;
        case VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH:
            if (virNetDevOpenvswitchSetMigrateData(cookie->network->net[i].portdata,
                                                   netptr->ifname) != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to run command to set OVS port data for "
                                 "interface %s"), netptr->ifname);
                goto cleanup;
            }
            break;
        default:
            break;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


int
qemuMigrationCheckIncoming(virQEMUCapsPtr qemuCaps,
                           const char *migrateFrom)
{
    if (STRPREFIX(migrateFrom, "rdma")) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("incoming RDMA migration is not supported "
                             "with this QEMU binary"));
            return -1;
        }
    } else if (!STRPREFIX(migrateFrom, "tcp") &&
               !STRPREFIX(migrateFrom, "exec") &&
               !STRPREFIX(migrateFrom, "fd") &&
               !STRPREFIX(migrateFrom, "unix") &&
               STRNEQ(migrateFrom, "stdio")) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("unknown migration protocol"));
        return -1;
    }

    return 0;
}


char *
qemuMigrationIncomingURI(const char *migrateFrom,
                         int migrateFd)
{
    char *uri = NULL;

    if (STREQ(migrateFrom, "stdio"))
        ignore_value(virAsprintf(&uri, "fd:%d", migrateFd));
    else
        ignore_value(VIR_STRDUP(uri, migrateFrom));

    return uri;
}


int
qemuMigrationRunIncoming(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         const char *uri,
                         qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;
    int rv;

    VIR_DEBUG("Setting up incoming migration with URI %s", uri);

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return -1;

    rv = qemuMonitorMigrateIncoming(priv->mon, uri);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rv < 0)
        goto cleanup;

    if (asyncJob == QEMU_ASYNC_JOB_MIGRATION_IN) {
        /* qemuMigrationWaitForDestCompletion is called from the Finish phase */
        ret = 0;
        goto cleanup;
    }

    if (qemuMigrationWaitForDestCompletion(driver, vm, asyncJob, false) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


/* This is called for outgoing non-p2p migrations when a connection to the
 * client which initiated the migration was closed but we were waiting for it
 * to follow up with the next phase, that is, in between
 * qemuDomainMigrateBegin3 and qemuDomainMigratePerform3 or
 * qemuDomainMigratePerform3 and qemuDomainMigrateConfirm3.
 */
static virDomainObjPtr
qemuMigrationCleanup(virDomainObjPtr vm,
                     virConnectPtr conn,
                     void *opaque)
{
    virQEMUDriverPtr driver = opaque;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("vm=%s, conn=%p, asyncJob=%s, phase=%s",
              vm->def->name, conn,
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
              qemuDomainAsyncJobPhaseToString(priv->job.asyncJob,
                                              priv->job.phase));

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        goto cleanup;

    VIR_DEBUG("The connection which started outgoing migration of domain %s"
              " was closed; canceling the migration",
              vm->def->name);

    switch ((qemuMigrationJobPhase) priv->job.phase) {
    case QEMU_MIGRATION_PHASE_BEGIN3:
        /* just forget we were about to migrate */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        VIR_WARN("Migration of domain %s finished but we don't know if the"
                 " domain was successfully started on destination or not",
                 vm->def->name);
        /* clear the job and let higher levels decide what to do */
        qemuDomainObjDiscardAsyncJob(driver, vm);
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3:
        /* cannot be seen without an active migration API; unreachable */
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
        /* all done; unreachable */
    case QEMU_MIGRATION_PHASE_PREPARE:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
        /* incoming migration; unreachable */
    case QEMU_MIGRATION_PHASE_PERFORM2:
        /* single phase outgoing migration; unreachable */
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_LAST:
        /* unreachable */
        ;
    }

 cleanup:
    return vm;
}


/* The caller is supposed to lock the vm and start a migration job. */
static char *
qemuMigrationBeginPhase(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        const char *xmlin,
                        const char *dname,
                        char **cookieout,
                        int *cookieoutlen,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        unsigned long flags)
{
    char *rv = NULL;
    qemuMigrationCookiePtr mig = NULL;
    virDomainDefPtr def = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virCapsPtr caps = NULL;
    unsigned int cookieFlags = QEMU_MIGRATION_COOKIE_LOCKSTATE;

    VIR_DEBUG("driver=%p, vm=%p, xmlin=%s, dname=%s,"
              " cookieout=%p, cookieoutlen=%p,"
              " nmigrate_disks=%zu, migrate_disks=%p, flags=%lx",
              driver, vm, NULLSTR(xmlin), NULLSTR(dname),
              cookieout, cookieoutlen, nmigrate_disks,
              migrate_disks, flags);

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    /* Only set the phase if we are inside QEMU_ASYNC_JOB_MIGRATION_OUT.
     * Otherwise we will start the async job later in the perform phase losing
     * change protection.
     */
    if (priv->job.asyncJob == QEMU_ASYNC_JOB_MIGRATION_OUT)
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_BEGIN3);

    if (!qemuMigrationIsAllowed(driver, vm, true, flags))
        goto cleanup;

    if (!(flags & VIR_MIGRATE_UNSAFE) &&
        !qemuMigrationIsSafe(vm->def, nmigrate_disks, migrate_disks, flags))
        goto cleanup;

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live "
                         "or paused migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        goto cleanup;
    }

    if (flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC)) {
        bool has_drive_mirror =  virQEMUCapsGet(priv->qemuCaps,
                                                QEMU_CAPS_DRIVE_MIRROR);

        if (nmigrate_disks) {
            if (has_drive_mirror) {
                size_t i, j;
                /* Check user requested only known disk targets. */
                for (i = 0; i < nmigrate_disks; i++) {
                    for (j = 0; j < vm->def->ndisks; j++) {
                        if (STREQ(vm->def->disks[j]->dst, migrate_disks[i]))
                            break;
                    }

                    if (j == vm->def->ndisks) {
                        virReportError(VIR_ERR_INVALID_ARG,
                                       _("disk target %s not found"),
                                       migrate_disks[i]);
                        goto cleanup;
                    }
                }

                if (flags & VIR_MIGRATE_TUNNELLED) {
                    virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                                   _("Selecting disks to migrate is not "
                                     "implemented for tunnelled migration"));
                    goto cleanup;
                }
            } else {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("qemu does not support drive-mirror command"));
                goto cleanup;
            }
        }

        if (has_drive_mirror) {
            /* TODO support NBD for TUNNELLED migration */
            if (flags & VIR_MIGRATE_TUNNELLED) {
                VIR_WARN("NBD in tunnelled migration is currently not supported");
            } else {
                cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
                priv->nbdPort = 0;
            }
        }
    }

    if (virDomainDefHasMemoryHotplug(vm->def) ||
        ((flags & VIR_MIGRATE_PERSIST_DEST) &&
         vm->newDef && virDomainDefHasMemoryHotplug(vm->newDef)))
        cookieFlags |= QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG;

    if (!qemuDomainVcpuHotplugIsInOrder(vm->def) ||
        ((flags & VIR_MIGRATE_PERSIST_DEST) &&
         vm->newDef && !qemuDomainVcpuHotplugIsInOrder(vm->newDef)))
        cookieFlags |= QEMU_MIGRATION_COOKIE_CPU_HOTPLUG;

    if (!(mig = qemuMigrationEatCookie(driver, vm, NULL, 0, 0)))
        goto cleanup;

    if (qemuMigrationBakeCookie(mig, driver, vm,
                                cookieout, cookieoutlen,
                                cookieFlags) < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
    }

    if (xmlin) {
        if (!(def = virDomainDefParseString(xmlin, caps, driver->xmlopt, priv->qemuCaps,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            goto cleanup;

        if (!qemuDomainDefCheckABIStability(driver, vm->def, def))
            goto cleanup;

        rv = qemuDomainDefFormatLive(driver, def, false, true);
    } else {
        rv = qemuDomainDefFormatLive(driver, vm->def, false, true);
    }

 cleanup:
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    virDomainDefFree(def);
    return rv;
}

char *
qemuMigrationBegin(virConnectPtr conn,
                   virDomainObjPtr vm,
                   const char *xmlin,
                   const char *dname,
                   char **cookieout,
                   int *cookieoutlen,
                   size_t nmigrate_disks,
                   const char **migrate_disks,
                   unsigned long flags)
{
    virQEMUDriverPtr driver = conn->privateData;
    virQEMUDriverConfigPtr cfg = NULL;
    char *xml = NULL;
    qemuDomainAsyncJob asyncJob;

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;
        asyncJob = QEMU_ASYNC_JOB_MIGRATION_OUT;
    } else {
        if (qemuDomainObjBeginJob(driver, vm, QEMU_JOB_MODIFY) < 0)
            goto cleanup;
        asyncJob = QEMU_ASYNC_JOB_NONE;
    }

    qemuMigrationStoreDomainState(vm);

    if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    /* Check if there is any ejected media.
     * We don't want to require them on the destination.
     */
    if (!(flags & VIR_MIGRATE_OFFLINE) &&
        qemuProcessRefreshDisks(driver, vm, asyncJob) < 0)
        goto endjob;

    if (!(xml = qemuMigrationBeginPhase(driver, vm, xmlin, dname,
                                        cookieout, cookieoutlen,
                                        nmigrate_disks, migrate_disks, flags)))
        goto endjob;

    if (flags & VIR_MIGRATE_TLS) {
        cfg = virQEMUDriverGetConfig(driver);
        if (qemuMigrationCheckSetupTLS(conn, driver, cfg, vm, asyncJob) < 0)
            goto endjob;
    }

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        /* We keep the job active across API calls until the confirm() call.
         * This prevents any other APIs being invoked while migration is taking
         * place.
         */
        if (virCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                                 qemuMigrationCleanup) < 0) {
            VIR_FREE(xml);
            goto endjob;
        }
        qemuMigrationJobContinue(vm);
    } else {
        goto endjob;
    }

 cleanup:
    virObjectUnref(cfg);
    virDomainObjEndAPI(&vm);
    return xml;

 endjob:
    if (flags & VIR_MIGRATE_CHANGE_PROTECTION)
        qemuMigrationJobFinish(driver, vm);
    else
        qemuDomainObjEndJob(driver, vm);
    goto cleanup;
}


/* Prepare is the first step, and it runs on the destination host.
 */

static void
qemuMigrationPrepareCleanup(virQEMUDriverPtr driver,
                            virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    VIR_DEBUG("driver=%p, vm=%s, job=%s, asyncJob=%s",
              driver,
              vm->def->name,
              qemuDomainJobTypeToString(priv->job.active),
              qemuDomainAsyncJobTypeToString(priv->job.asyncJob));

    virPortAllocatorRelease(driver->migrationPorts, priv->migrationPort);
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN))
        return;
    qemuDomainObjDiscardAsyncJob(driver, vm);
}

static qemuProcessIncomingDefPtr
qemuMigrationPrepareIncoming(virDomainObjPtr vm,
                             bool tunnel,
                             const char *protocol,
                             const char *listenAddress,
                             unsigned short port,
                             int fd)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuProcessIncomingDefPtr inc = NULL;
    char *migrateFrom = NULL;

    if (tunnel) {
        if (VIR_STRDUP(migrateFrom, "stdio") < 0)
            goto cleanup;
    } else {
        bool encloseAddress = false;
        bool hostIPv6Capable = false;
        bool qemuIPv6Capable = false;
        struct addrinfo *info = NULL;
        struct addrinfo hints = { .ai_flags = AI_ADDRCONFIG,
                                  .ai_socktype = SOCK_STREAM };
        const char *incFormat;

        if (getaddrinfo("::", NULL, &hints, &info) == 0) {
            freeaddrinfo(info);
            hostIPv6Capable = true;
        }
        qemuIPv6Capable = virQEMUCapsGet(priv->qemuCaps,
                                         QEMU_CAPS_IPV6_MIGRATION);

        if (listenAddress) {
            if (virSocketAddrNumericFamily(listenAddress) == AF_INET6) {
                if (!qemuIPv6Capable) {
                    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                                   _("qemu isn't capable of IPv6"));
                    goto cleanup;
                }
                if (!hostIPv6Capable) {
                    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                                   _("host isn't capable of IPv6"));
                    goto cleanup;
                }
                /* IPv6 address must be escaped in brackets on the cmd line */
                encloseAddress = true;
            } else {
                /* listenAddress is a hostname or IPv4 */
            }
        } else if (qemuIPv6Capable && hostIPv6Capable) {
            /* Listen on :: instead of 0.0.0.0 if QEMU understands it
             * and there is at least one IPv6 address configured
             */
            listenAddress = "::";
            encloseAddress = true;
        } else {
            listenAddress = "0.0.0.0";
        }

        /* QEMU will be started with
         *   -incoming protocol:[<IPv6 addr>]:port,
         *   -incoming protocol:<IPv4 addr>:port, or
         *   -incoming protocol:<hostname>:port
         */
        if (encloseAddress)
            incFormat = "%s:[%s]:%d";
        else
            incFormat = "%s:%s:%d";
        if (virAsprintf(&migrateFrom, incFormat,
                        protocol, listenAddress, port) < 0)
            goto cleanup;
    }

    inc = qemuProcessIncomingDefNew(priv->qemuCaps, listenAddress,
                                    migrateFrom, fd, NULL);

 cleanup:
    VIR_FREE(migrateFrom);
    return inc;
}

static int
qemuMigrationSetCompression(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            qemuDomainAsyncJob job,
                            qemuMigrationCompressionPtr compression,
                            qemuMonitorMigrationParamsPtr migParams)
{
    int ret = -1;
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_XBZRLE,
                               compression->methods &
                                   (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE),
                               job) < 0)
        return -1;

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_COMPRESS,
                               compression->methods &
                                   (1ULL << QEMU_MIGRATION_COMPRESS_MT),
                               job) < 0)
        return -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, job) < 0)
        return -1;

    migParams->compressLevel_set = compression->level_set;
    migParams->compressLevel = compression->level;

    migParams->compressThreads_set = compression->threads_set;
    migParams->compressThreads = compression->threads;

    migParams->decompressThreads_set = compression->dthreads_set;
    migParams->decompressThreads = compression->dthreads;

    if (compression->xbzrle_cache_set &&
        qemuMonitorSetMigrationCacheSize(priv->mon,
                                         compression->xbzrle_cache) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}


void
qemuMigrationParamsClear(qemuMonitorMigrationParamsPtr migParams)
{
    if (!migParams)
        return;

    VIR_FREE(migParams->migrateTLSAlias);
    VIR_FREE(migParams->migrateTLSHostname);
}


void
qemuMigrationParamsFree(qemuMonitorMigrationParamsPtr *migParams)
{
    if (!*migParams)
        return;

    qemuMigrationParamsClear(*migParams);
    VIR_FREE(*migParams);
}


/* qemuMigrationSetEmptyTLSParams
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 * @migParams: Pointer to a migration parameters block
 *
 * If we support setting the tls-creds, then set both tls-creds and
 * tls-hostname to the empty string ("") which indicates to not use
 * TLS on this migration.
 *
 * Returns 0 on success, -1 on failure
 */
static int
qemuMigrationSetEmptyTLSParams(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               qemuDomainAsyncJob asyncJob,
                               qemuMonitorMigrationParamsPtr migParams)
{
   qemuDomainObjPrivatePtr priv = vm->privateData;

   if (qemuMigrationCheckTLSCreds(driver, vm, asyncJob) < 0)
       return -1;

   if (!priv->migTLSAlias)
       return 0;

   if (VIR_STRDUP(migParams->migrateTLSAlias, "") < 0 ||
       VIR_STRDUP(migParams->migrateTLSHostname, "") < 0)
       return -1;

    return 0;
}


qemuMonitorMigrationParamsPtr
qemuMigrationParams(virTypedParameterPtr params,
                    int nparams,
                    unsigned long flags)
{
    qemuMonitorMigrationParamsPtr migParams;

    if (VIR_ALLOC(migParams) < 0)
        return NULL;

    if (!params)
        return migParams;

#define GET(PARAM, VAR)                                                     \
    do {                                                                    \
        int rc;                                                             \
        if ((rc = virTypedParamsGetInt(params, nparams,                     \
                                       VIR_MIGRATE_PARAM_ ## PARAM,         \
                                       &migParams->VAR)) < 0)               \
            goto error;                                                     \
                                                                            \
        if (rc == 1)                                                        \
            migParams->VAR ## _set = true;                                  \
    } while (0)

    GET(AUTO_CONVERGE_INITIAL, cpuThrottleInitial);
    GET(AUTO_CONVERGE_INCREMENT, cpuThrottleIncrement);

#undef GET

    if ((migParams->cpuThrottleInitial_set ||
         migParams->cpuThrottleIncrement_set) &&
        !(flags & VIR_MIGRATE_AUTO_CONVERGE)) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn auto convergence on to tune it"));
        goto error;
    }

    return migParams;

 error:
    qemuMigrationParamsFree(&migParams);
    return NULL;
}


static int
qemuMigrationSetParams(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       qemuDomainAsyncJob job,
                       qemuMonitorMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int ret = -1;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, job) < 0)
        return -1;

    if (qemuMonitorSetMigrationParams(priv->mon, migParams) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;

    return ret;
}


/* qemuMigrationResetTLS
 * @driver: pointer to qemu driver
 * @vm: domain object
 * @asyncJob: migration job to join
 *
 * Deconstruct all the setup possibly done for TLS - delete the TLS and
 * security objects, free the secinfo, and reset the migration params to "".
 *
 * Returns 0 on success, -1 on failure
 */
static int
qemuMigrationResetTLS(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    char *tlsAlias = NULL;
    char *secAlias = NULL;
    qemuMonitorMigrationParams migParams = { 0 };
    int ret = -1;

    if (qemuMigrationCheckTLSCreds(driver, vm, asyncJob) < 0)
        return -1;

    /* If the tls-creds doesn't exist or if they're set to "" then there's
     * nothing to do since we never set anything up */
    if (!priv->migTLSAlias || !*priv->migTLSAlias)
        return 0;

    /* NB: If either or both fail to allocate memory we can still proceed
     *     since the next time we migrate another deletion attempt will be
     *     made after successfully generating the aliases. */
    tlsAlias = qemuAliasTLSObjFromSrcAlias(QEMU_MIGRATION_TLS_ALIAS_BASE);
    secAlias = qemuDomainGetSecretAESAlias(QEMU_MIGRATION_TLS_ALIAS_BASE, false);

    qemuDomainDelTLSObjects(driver, vm, asyncJob, secAlias, tlsAlias);
    qemuDomainSecretInfoFree(&priv->migSecinfo);

    if (VIR_STRDUP(migParams.migrateTLSAlias, "") < 0 ||
        VIR_STRDUP(migParams.migrateTLSHostname, "") < 0 ||
        qemuMigrationSetParams(driver, vm, asyncJob, &migParams) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(tlsAlias);
    VIR_FREE(secAlias);
    qemuMigrationParamsClear(&migParams);

    return ret;
}


static int
qemuMigrationPrepareAny(virQEMUDriverPtr driver,
                        virConnectPtr dconn,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        virDomainDefPtr *def,
                        const char *origname,
                        virStreamPtr st,
                        const char *protocol,
                        unsigned short port,
                        bool autoPort,
                        const char *listenAddress,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        int nbdPort,
                        qemuMigrationCompressionPtr compression,
                        unsigned long flags)
{
    virDomainObjPtr vm = NULL;
    virObjectEventPtr event = NULL;
    virQEMUDriverConfigPtr cfg = NULL;
    int ret = -1;
    int dataFD[2] = { -1, -1 };
    qemuDomainObjPrivatePtr priv = NULL;
    qemuMigrationCookiePtr mig = NULL;
    bool tunnel = !!st;
    char *xmlout = NULL;
    unsigned int cookieFlags;
    virCapsPtr caps = NULL;
    qemuProcessIncomingDefPtr incoming = NULL;
    bool taint_hook = false;
    bool stopProcess = false;
    bool relabel = false;
    int rv;
    char *tlsAlias = NULL;
    char *secAlias = NULL;
    qemuMonitorMigrationParams migParams = { 0 };

    virNWFilterReadLockFilterUpdates();

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle "
                             "non-shared storage"));
            goto cleanup;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with "
                             "the persistent flag set"));
            goto cleanup;
        }
        if (tunnel) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not "
                             "make sense"));
            goto cleanup;
        }
        cookieFlags = 0;
    } else {
        cookieFlags = QEMU_MIGRATION_COOKIE_GRAPHICS;
    }

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live "
                         "or paused migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        goto cleanup;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    if (!qemuMigrationIsAllowedHostdev(*def))
        goto cleanup;

    /* Let migration hook filter domain XML */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        char *xml;
        int hookret;

        if (!(xml = qemuDomainDefFormatXML(driver, *def,
                                           VIR_DOMAIN_XML_SECURE |
                                           VIR_DOMAIN_XML_MIGRATABLE)))
            goto cleanup;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, (*def)->name,
                              VIR_HOOK_QEMU_OP_MIGRATE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, &xmlout);
        VIR_FREE(xml);

        if (hookret < 0) {
            goto cleanup;
        } else if (hookret == 0) {
            if (virStringIsEmpty(xmlout)) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                virDomainDefPtr newdef;

                VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);
                newdef = virDomainDefParseString(xmlout, caps, driver->xmlopt, NULL,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                 VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
                if (!newdef)
                    goto cleanup;

                if (!qemuDomainDefCheckABIStability(driver, *def, newdef)) {
                    virDomainDefFree(newdef);
                    goto cleanup;
                }

                virDomainDefFree(*def);
                *def = newdef;
                /* We should taint the domain here. However, @vm and therefore
                 * privateData too are still NULL, so just notice the fact and
                 * taint it later. */
                taint_hook = true;
            }
        }
    }

    if (!(vm = virDomainObjListAdd(driver->domains, *def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    virObjectRef(vm);
    *def = NULL;
    priv = vm->privateData;
    if (VIR_STRDUP(priv->origname, origname) < 0)
        goto cleanup;

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                       QEMU_MIGRATION_COOKIE_LOCKSTATE |
                                       QEMU_MIGRATION_COOKIE_NBD |
                                       QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG |
                                       QEMU_MIGRATION_COOKIE_CPU_HOTPLUG)))
        goto cleanup;

    if (STREQ_NULLABLE(protocol, "rdma") &&
        !virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot start RDMA migration with no memory hard "
                         "limit set"));
        goto cleanup;
    }

    if (qemuMigrationPrecreateStorage(dconn, driver, vm, mig->nbd,
                                      nmigrate_disks, migrate_disks,
                                      !!(flags & VIR_MIGRATE_NON_SHARED_INC)) < 0)
        goto cleanup;

    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto cleanup;
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PREPARE);

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    if (tunnel &&
        (pipe(dataFD) < 0 || virSetCloseExec(dataFD[1]) < 0)) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto stopjob;
    }

    if (qemuProcessInit(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                        true, VIR_QEMU_PROCESS_START_AUTODESTROY) < 0)
        goto stopjob;
    stopProcess = true;

    if (!(incoming = qemuMigrationPrepareIncoming(vm, tunnel, protocol,
                                                  listenAddress, port,
                                                  dataFD[0])))
        goto stopjob;
    dataFD[0] = -1; /* the FD is now owned by incoming */

    if (qemuProcessPrepareDomain(dconn, driver, vm,
                                 VIR_QEMU_PROCESS_START_AUTODESTROY) < 0)
        goto stopjob;

    if (qemuProcessPrepareHost(driver, vm, !!incoming) < 0)
        goto stopjob;

    rv = qemuProcessLaunch(dconn, driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                           incoming, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
                           VIR_QEMU_PROCESS_START_AUTODESTROY);
    if (rv < 0) {
        if (rv == -2)
            relabel = true;
        goto stopjob;
    }
    relabel = true;

    if (tunnel) {
        if (virFDStreamOpen(st, dataFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot pass pipe for tunnelled migration"));
            goto stopjob;
        }
        dataFD[1] = -1; /* 'st' owns the FD now & will close it */
    }

    if (qemuMigrationSetCompression(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                                    compression, &migParams) < 0)
        goto stopjob;

    /* Migrations using TLS need to add the "tls-creds-x509" object and
     * set the migration TLS parameters */
    if (flags & VIR_MIGRATE_TLS) {
        cfg = virQEMUDriverGetConfig(driver);
        if (qemuMigrationCheckSetupTLS(dconn, driver, cfg, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
            goto stopjob;

        if (qemuMigrationAddTLSObjects(driver, vm, cfg, true,
                                       QEMU_ASYNC_JOB_MIGRATION_IN,
                                       &tlsAlias, &secAlias, &migParams) < 0)
            goto stopjob;

        /* Force reset of 'tls-hostname', it's a source only parameter */
        if (VIR_STRDUP(migParams.migrateTLSHostname, "") < 0)
            goto stopjob;

    } else {
        if (qemuMigrationSetEmptyTLSParams(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_IN,
                                           &migParams) < 0)
            goto stopjob;
    }

    if (STREQ_NULLABLE(protocol, "rdma") &&
        virProcessSetMaxMemLock(vm->pid, vm->def->mem.hard_limit << 10) < 0) {
        goto stopjob;
    }

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_RDMA_PIN_ALL,
                               flags & VIR_MIGRATE_RDMA_PIN_ALL,
                               QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto stopjob;

    if (qemuMigrationSetPostCopy(driver, vm,
                                 flags & VIR_MIGRATE_POSTCOPY,
                                 QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto stopjob;

    if (qemuMigrationSetParams(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                               &migParams) < 0)
        goto stopjob;

    if (mig->nbd &&
        flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC) &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_SERVER)) {
        if (qemuMigrationStartNBDServer(driver, vm, incoming->address,
                                        nmigrate_disks, migrate_disks,
                                        nbdPort) < 0) {
            goto stopjob;
        }
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (mig->lockState) {
        VIR_DEBUG("Received lockstate %s", mig->lockState);
        VIR_FREE(priv->lockState);
        priv->lockState = mig->lockState;
        mig->lockState = NULL;
    } else {
        VIR_DEBUG("Received no lockstate");
    }

    if (incoming->deferredURI &&
        qemuMigrationRunIncoming(driver, vm, incoming->deferredURI,
                                 QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto stopjob;

    if (qemuProcessFinishStartup(dconn, driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN,
                                 false, VIR_DOMAIN_PAUSED_MIGRATION) < 0)
        goto stopjob;

 done:
    if (qemuMigrationBakeCookie(mig, driver, vm, cookieout,
                                cookieoutlen, cookieFlags) < 0) {
        /* We could tear down the whole guest here, but
         * cookie data is (so far) non-critical, so that
         * seems a little harsh. We'll just warn for now.
         */
        VIR_WARN("Unable to encode migration cookie");
    }

    if (qemuDomainCleanupAdd(vm, qemuMigrationPrepareCleanup) < 0)
        goto stopjob;

    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        virDomainAuditStart(vm, "migrated", true);
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STARTED,
                                         VIR_DOMAIN_EVENT_STARTED_MIGRATED);
    }

    /* We keep the job active across API calls until the finish() call.
     * This prevents any other APIs being invoked while incoming
     * migration is taking place.
     */
    qemuMigrationJobContinue(vm);

    if (autoPort)
        priv->migrationPort = port;
    /* in this case port is not auto selected and we don't need to manage it
     * anymore after cookie is baked
     */
    if (nbdPort != 0)
        priv->nbdPort = 0;
    ret = 0;

 cleanup:
    VIR_FREE(tlsAlias);
    VIR_FREE(secAlias);
    virObjectUnref(cfg);
    qemuProcessIncomingDefFree(incoming);
    VIR_FREE(xmlout);
    VIR_FORCE_CLOSE(dataFD[0]);
    VIR_FORCE_CLOSE(dataFD[1]);
    if (ret < 0 && priv) {
        /* priv is set right after vm is added to the list of domains
         * and there is no 'goto cleanup;' in the middle of those */
        VIR_FREE(priv->origname);
        /* release if port is auto selected which is not the case if
         * it is given in parameters
         */
        if (nbdPort == 0)
            virPortAllocatorRelease(driver->migrationPorts, priv->nbdPort);
        priv->nbdPort = 0;
        virDomainObjRemoveTransientDef(vm);
        qemuDomainRemoveInactive(driver, vm);
    }
    qemuMigrationParamsClear(&migParams);
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    qemuMigrationCookieFree(mig);
    virObjectUnref(caps);
    virNWFilterUnlockFilterUpdates();
    return ret;

 stopjob:
    qemuMigrationReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN);

    if (stopProcess) {
        unsigned int stopFlags = VIR_QEMU_PROCESS_STOP_MIGRATED;
        if (!relabel)
            stopFlags |= VIR_QEMU_PROCESS_STOP_NO_RELABEL;
        virDomainAuditStart(vm, "migrated", false);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                        QEMU_ASYNC_JOB_MIGRATION_IN, stopFlags);
    }

    qemuMigrationJobFinish(driver, vm);
    goto cleanup;
}


/*
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
int
qemuMigrationPrepareTunnel(virQEMUDriverPtr driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           virStreamPtr st,
                           virDomainDefPtr *def,
                           const char *origname,
                           unsigned long flags)
{
    qemuMigrationCompressionPtr compression = NULL;
    int ret;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, st=%p, def=%p, "
              "origname=%s, flags=%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, st, *def, origname, flags);

    if (st == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("tunnelled migration requested but NULL stream passed"));
        return -1;
    }

    if (!(compression = qemuMigrationCompressionParse(NULL, 0, flags)))
        return -1;

    ret = qemuMigrationPrepareAny(driver, dconn, cookiein, cookieinlen,
                                  cookieout, cookieoutlen, def, origname,
                                  st, NULL, 0, false, NULL, 0, NULL, 0,
                                  compression, flags);
    VIR_FREE(compression);
    return ret;
}


static virURIPtr
qemuMigrationParseURI(const char *uri, bool *wellFormed)
{
    char *tmp = NULL;
    virURIPtr parsed;

    /* For compatibility reasons tcp://... URIs are sent as tcp:...
     * We need to transform them to a well-formed URI before parsing. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri + 4, "//")) {
        if (virAsprintf(&tmp, "tcp://%s", uri + 4) < 0)
            return NULL;
        uri = tmp;
    }

    parsed = virURIParse(uri);
    if (parsed && wellFormed)
        *wellFormed = !tmp;
    VIR_FREE(tmp);

    return parsed;
}


int
qemuMigrationPrepareDirect(virQEMUDriverPtr driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           const char *uri_in,
                           char **uri_out,
                           virDomainDefPtr *def,
                           const char *origname,
                           const char *listenAddress,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           int nbdPort,
                           qemuMigrationCompressionPtr compression,
                           unsigned long flags)
{
    unsigned short port = 0;
    bool autoPort = true;
    char *hostname = NULL;
    int ret = -1;
    virURIPtr uri = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const char *migrateHost = cfg->migrateHost;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_in=%s, uri_out=%p, "
              "def=%p, origname=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, flags=%lx",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, NULLSTR(uri_in), uri_out,
              *def, origname, NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, flags);

    *uri_out = NULL;

    /* The URI passed in may be NULL or a string "tcp://somehostname:port".
     *
     * If the URI passed in is NULL then we allocate a port number
     * from our pool of port numbers, and if the migrateHost is configured,
     * we return a URI of "tcp://migrateHost:port", otherwise return a URI
     * of "tcp://ourhostname:port".
     *
     * If the URI passed in is not NULL then we try to parse out the
     * port number and use that (note that the hostname is assumed
     * to be a correct hostname which refers to the target machine).
     */
    if (uri_in == NULL) {
        bool encloseAddress = false;
        const char *incFormat;

        if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
            goto cleanup;

        if (migrateHost != NULL) {
            if (virSocketAddrNumericFamily(migrateHost) == AF_INET6)
                encloseAddress = true;

            if (VIR_STRDUP(hostname, migrateHost) < 0)
                goto cleanup;
        } else {
            if ((hostname = virGetHostname()) == NULL)
                goto cleanup;
        }

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost,"
                             " but migration requires an FQDN"));
            goto cleanup;
        }

        /* XXX this really should have been a properly well-formed
         * URI, but we can't add in tcp:// now without breaking
         * compatibility with old targets. We at least make the
         * new targets accept both syntaxes though.
         */
        if (encloseAddress)
            incFormat = "%s:[%s]:%d";
        else
            incFormat = "%s:%s:%d";

        if (virAsprintf(uri_out, incFormat, "tcp", hostname, port) < 0)
            goto cleanup;
    } else {
        bool well_formed_uri;

        if (!(uri = qemuMigrationParseURI(uri_in, &well_formed_uri)))
            goto cleanup;

        if (uri->scheme == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing scheme in migration URI: %s"),
                           uri_in);
            goto cleanup;
        }

        if (STRNEQ(uri->scheme, "tcp") &&
            STRNEQ(uri->scheme, "rdma")) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("unsupported scheme %s in migration URI %s"),
                           uri->scheme, uri_in);
            goto cleanup;
        }

        if (uri->server == NULL) {
            virReportError(VIR_ERR_INVALID_ARG, _("missing host in migration"
                                                  " URI: %s"), uri_in);
            goto cleanup;
        }

        if (uri->port == 0) {
            if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                goto cleanup;

            /* Send well-formed URI only if uri_in was well-formed */
            if (well_formed_uri) {
                uri->port = port;
                if (!(*uri_out = virURIFormat(uri)))
                    goto cleanup;
            } else {
                if (virAsprintf(uri_out, "%s:%d", uri_in, port) < 0)
                    goto cleanup;
            }
        } else {
            port = uri->port;
            autoPort = false;
        }
    }

    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    ret = qemuMigrationPrepareAny(driver, dconn, cookiein, cookieinlen,
                                  cookieout, cookieoutlen, def, origname,
                                  NULL, uri ? uri->scheme : "tcp",
                                  port, autoPort, listenAddress,
                                  nmigrate_disks, migrate_disks, nbdPort,
                                  compression, flags);
 cleanup:
    virURIFree(uri);
    VIR_FREE(hostname);
    virObjectUnref(cfg);
    if (ret != 0) {
        VIR_FREE(*uri_out);
        if (autoPort)
            virPortAllocatorRelease(driver->migrationPorts, port);
    }
    return ret;
}


virDomainDefPtr
qemuMigrationPrepareDef(virQEMUDriverPtr driver,
                        const char *dom_xml,
                        const char *dname,
                        char **origname)
{
    virCapsPtr caps = NULL;
    virDomainDefPtr def;
    char *name = NULL;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        return NULL;

    if (!(def = virDomainDefParseString(dom_xml, caps, driver->xmlopt, NULL,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (dname) {
        name = def->name;
        if (VIR_STRDUP(def->name, dname) < 0) {
            virDomainDefFree(def);
            def = NULL;
        }
    }

 cleanup:
    virObjectUnref(caps);
    if (def && origname)
        *origname = name;
    else
        VIR_FREE(name);
    return def;
}


static int
qemuMigrationConfirmPhase(virQEMUDriverPtr driver,
                          virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *cookiein,
                          int cookieinlen,
                          unsigned int flags,
                          int retcode)
{
    qemuMigrationCookiePtr mig;
    virObjectEventPtr event;
    int rv = -1;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainJobInfoPtr jobInfo = NULL;

    VIR_DEBUG("driver=%p, conn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "flags=%x, retcode=%d",
              driver, conn, vm, NULLSTR(cookiein), cookieinlen,
              flags, retcode);

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    qemuMigrationJobSetPhase(driver, vm,
                             retcode == 0
                             ? QEMU_MIGRATION_PHASE_CONFIRM3
                             : QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED);

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                       QEMU_MIGRATION_COOKIE_STATS)))
        goto cleanup;

    if (retcode == 0)
        jobInfo = priv->job.completed;
    else
        VIR_FREE(priv->job.completed);

    /* Update times with the values sent by the destination daemon */
    if (mig->jobInfo && jobInfo) {
        int reason;

        /* We need to refresh migration statistics after a completed post-copy
         * migration since priv->job.completed contains obsolete data from the
         * time we switched to post-copy mode.
         */
        if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_POSTCOPY &&
            qemuMigrationFetchJobStatus(driver, vm,
                                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                                        jobInfo) < 0)
            VIR_WARN("Could not refresh migration statistics");

        qemuDomainJobInfoUpdateTime(jobInfo);
        jobInfo->timeDeltaSet = mig->jobInfo->timeDeltaSet;
        jobInfo->timeDelta = mig->jobInfo->timeDelta;
        jobInfo->stats.downtime_set = mig->jobInfo->stats.downtime_set;
        jobInfo->stats.downtime = mig->jobInfo->stats.downtime;
    }

    if (flags & VIR_MIGRATE_OFFLINE)
        goto done;

    /* Did the migration go as planned?  If yes, kill off the domain object.
     * If something failed, resume CPUs, but only if we didn't use post-copy.
     */
    if (retcode == 0) {
        /* If guest uses SPICE and supports seamless migration we have to hold
         * up domain shutdown until SPICE server transfers its data */
        qemuMigrationWaitForSpice(vm);

        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");

        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
        qemuDomainEventQueue(driver, event);
        qemuDomainEventEmitJobCompleted(driver, vm);
    } else {
        virErrorPtr orig_err = virSaveLastError();
        int reason;

        /* cancel any outstanding NBD jobs */
        qemuMigrationCancelDriveMirror(driver, vm, false,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT, NULL);

        virSetError(orig_err);
        virFreeError(orig_err);

        if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_POSTCOPY) {
            qemuMigrationPostcopyFailed(driver, vm);
        } else if (qemuMigrationRestoreDomainState(conn, vm)) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                                      VIR_DOMAIN_EVENT_RESUMED,
                                                      VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
            qemuDomainEventQueue(driver, event);
        }

        qemuMigrationReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT);

        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
    }

 done:
    qemuMigrationCookieFree(mig);
    rv = 0;

 cleanup:
    virObjectUnref(cfg);
    return rv;
}

int
qemuMigrationConfirm(virConnectPtr conn,
                     virDomainObjPtr vm,
                     const char *cookiein,
                     int cookieinlen,
                     unsigned int flags,
                     int cancelled)
{
    virQEMUDriverPtr driver = conn->privateData;
    qemuMigrationJobPhase phase;
    virQEMUDriverConfigPtr cfg = NULL;
    int ret = -1;

    cfg = virQEMUDriverGetConfig(driver);

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT))
        goto cleanup;

    if (cancelled)
        phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
    else
        phase = QEMU_MIGRATION_PHASE_CONFIRM3;

    qemuMigrationJobStartPhase(driver, vm, phase);
    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           qemuMigrationCleanup);

    ret = qemuMigrationConfirmPhase(driver, conn, vm,
                                    cookiein, cookieinlen,
                                    flags, cancelled);

    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm)) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactive(driver, vm);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    virObjectUnref(cfg);
    return ret;
}


enum qemuMigrationDestinationType {
    MIGRATION_DEST_HOST,
    MIGRATION_DEST_CONNECT_HOST,
    MIGRATION_DEST_FD,
};

enum qemuMigrationForwardType {
    MIGRATION_FWD_DIRECT,
    MIGRATION_FWD_STREAM,
};

typedef struct _qemuMigrationSpec qemuMigrationSpec;
typedef qemuMigrationSpec *qemuMigrationSpecPtr;
struct _qemuMigrationSpec {
    enum qemuMigrationDestinationType destType;
    union {
        struct {
            const char *protocol;
            const char *name;
            int port;
        } host;

        struct {
            int qemu;
            int local;
        } fd;
    } dest;

    enum qemuMigrationForwardType fwdType;
    union {
        virStreamPtr stream;
    } fwd;
};

#define TUNNEL_SEND_BUF_SIZE 65536

typedef struct _qemuMigrationIOThread qemuMigrationIOThread;
typedef qemuMigrationIOThread *qemuMigrationIOThreadPtr;
struct _qemuMigrationIOThread {
    virThread thread;
    virStreamPtr st;
    int sock;
    virError err;
    int wakeupRecvFD;
    int wakeupSendFD;
};

static void qemuMigrationIOFunc(void *arg)
{
    qemuMigrationIOThreadPtr data = arg;
    char *buffer = NULL;
    struct pollfd fds[2];
    int timeout = -1;
    virErrorPtr err = NULL;

    VIR_DEBUG("Running migration tunnel; stream=%p, sock=%d",
              data->st, data->sock);

    if (VIR_ALLOC_N(buffer, TUNNEL_SEND_BUF_SIZE) < 0)
        goto abrt;

    fds[0].fd = data->sock;
    fds[1].fd = data->wakeupRecvFD;

    for (;;) {
        int ret;

        fds[0].events = fds[1].events = POLLIN;
        fds[0].revents = fds[1].revents = 0;

        ret = poll(fds, ARRAY_CARDINALITY(fds), timeout);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("poll failed in migration tunnel"));
            goto abrt;
        }

        if (ret == 0) {
            /* We were asked to gracefully stop but reading would block. This
             * can only happen if qemu told us migration finished but didn't
             * close the migration fd. We handle this in the same way as EOF.
             */
            VIR_DEBUG("QEMU forgot to close migration fd");
            break;
        }

        if (fds[1].revents & (POLLIN | POLLERR | POLLHUP)) {
            char stop = 0;

            if (saferead(data->wakeupRecvFD, &stop, 1) != 1) {
                virReportSystemError(errno, "%s",
                                     _("failed to read from wakeup fd"));
                goto abrt;
            }

            VIR_DEBUG("Migration tunnel was asked to %s",
                      stop ? "abort" : "finish");
            if (stop) {
                goto abrt;
            } else {
                timeout = 0;
            }
        }

        if (fds[0].revents & (POLLIN | POLLERR | POLLHUP)) {
            int nbytes;

            nbytes = saferead(data->sock, buffer, TUNNEL_SEND_BUF_SIZE);
            if (nbytes > 0) {
                if (virStreamSend(data->st, buffer, nbytes) < 0)
                    goto error;
            } else if (nbytes < 0) {
                virReportSystemError(errno, "%s",
                        _("tunnelled migration failed to read from qemu"));
                goto abrt;
            } else {
                /* EOF; get out of here */
                break;
            }
        }
    }

    if (virStreamFinish(data->st) < 0)
        goto error;

    VIR_FORCE_CLOSE(data->sock);
    VIR_FREE(buffer);

    return;

 abrt:
    err = virSaveLastError();
    if (err && err->code == VIR_ERR_OK) {
        virFreeError(err);
        err = NULL;
    }
    virStreamAbort(data->st);
    if (err) {
        virSetError(err);
        virFreeError(err);
    }

 error:
    /* Let the source qemu know that the transfer cant continue anymore.
     * Don't copy the error for EPIPE as destination has the actual error. */
    VIR_FORCE_CLOSE(data->sock);
    if (!virLastErrorIsSystemErrno(EPIPE))
        virCopyLastError(&data->err);
    virResetLastError();
    VIR_FREE(buffer);
}


static qemuMigrationIOThreadPtr
qemuMigrationStartTunnel(virStreamPtr st,
                         int sock)
{
    qemuMigrationIOThreadPtr io = NULL;
    int wakeupFD[2] = { -1, -1 };

    if (pipe2(wakeupFD, O_CLOEXEC) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to make pipe"));
        goto error;
    }

    if (VIR_ALLOC(io) < 0)
        goto error;

    io->st = st;
    io->sock = sock;
    io->wakeupRecvFD = wakeupFD[0];
    io->wakeupSendFD = wakeupFD[1];

    if (virThreadCreate(&io->thread, true,
                        qemuMigrationIOFunc,
                        io) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to create migration thread"));
        goto error;
    }

    return io;

 error:
    VIR_FORCE_CLOSE(wakeupFD[0]);
    VIR_FORCE_CLOSE(wakeupFD[1]);
    VIR_FREE(io);
    return NULL;
}

static int
qemuMigrationStopTunnel(qemuMigrationIOThreadPtr io, bool error)
{
    int rv = -1;
    char stop = error ? 1 : 0;

    /* make sure the thread finishes its job and is joinable */
    if (safewrite(io->wakeupSendFD, &stop, 1) != 1) {
        virReportSystemError(errno, "%s",
                             _("failed to wakeup migration tunnel"));
        goto cleanup;
    }

    virThreadJoin(&io->thread);

    /* Forward error from the IO thread, to this thread */
    if (io->err.code != VIR_ERR_OK) {
        if (error)
            rv = 0;
        else
            virSetError(&io->err);
        virResetError(&io->err);
        goto cleanup;
    }

    rv = 0;

 cleanup:
    VIR_FORCE_CLOSE(io->wakeupSendFD);
    VIR_FORCE_CLOSE(io->wakeupRecvFD);
    VIR_FREE(io);
    return rv;
}

static int
qemuMigrationConnect(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     qemuMigrationSpecPtr spec)
{
    virNetSocketPtr sock;
    const char *host;
    char *port = NULL;
    int ret = -1;

    host = spec->dest.host.name;
    if (virAsprintf(&port, "%d", spec->dest.host.port) < 0)
        return -1;

    spec->destType = MIGRATION_DEST_FD;
    spec->dest.fd.qemu = -1;

    if (qemuSecuritySetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;
    if (virNetSocketNewConnectTCP(host, port,
                                  AF_UNSPEC,
                                  &sock) == 0) {
        spec->dest.fd.qemu = virNetSocketDupFD(sock, true);
        virObjectUnref(sock);
    }
    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0 ||
        spec->dest.fd.qemu == -1)
        goto cleanup;

    /* Migration expects a blocking FD */
    if (virSetBlocking(spec->dest.fd.qemu, true) < 0) {
        virReportSystemError(errno, _("Unable to set FD %d blocking"),
                             spec->dest.fd.qemu);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(port);
    if (ret < 0)
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
    return ret;
}

static int
qemuMigrationRun(virQEMUDriverPtr driver,
                 virDomainObjPtr vm,
                 const char *persist_xml,
                 const char *cookiein,
                 int cookieinlen,
                 char **cookieout,
                 int *cookieoutlen,
                 unsigned long flags,
                 unsigned long resource,
                 qemuMigrationSpecPtr spec,
                 virConnectPtr dconn,
                 const char *graphicsuri,
                 size_t nmigrate_disks,
                 const char **migrate_disks,
                 qemuMigrationCompressionPtr compression,
                 qemuMonitorMigrationParamsPtr migParams)
{
    int ret = -1;
    unsigned int migrate_flags = QEMU_MONITOR_MIGRATE_BACKGROUND;
    virQEMUDriverConfigPtr cfg = NULL;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMigrationCookiePtr mig = NULL;
    char *tlsAlias = NULL;
    char *secAlias = NULL;
    qemuMigrationIOThreadPtr iothread = NULL;
    int fd = -1;
    unsigned long migrate_speed = resource ? resource : priv->migMaxBandwidth;
    virErrorPtr orig_err = NULL;
    unsigned int cookieFlags = 0;
    bool abort_on_error = !!(flags & VIR_MIGRATE_ABORT_ON_ERROR);
    bool events = virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_EVENT);
    bool inPostCopy = false;
    unsigned int waitFlags;
    virDomainDefPtr persistDef = NULL;
    char *timestamp;
    int rc;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu, "
              "spec=%p (dest=%d, fwd=%d), dconn=%p, graphicsuri=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              spec, spec->destType, spec->fwdType, dconn,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    if (flags & VIR_MIGRATE_NON_SHARED_DISK) {
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_DISK;
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (flags & VIR_MIGRATE_NON_SHARED_INC) {
        migrate_flags |= QEMU_MONITOR_MIGRATE_NON_SHARED_INC;
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (virLockManagerPluginUsesState(driver->lockManager) &&
        !cookieout) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Migration with lock driver %s requires"
                         " cookie support"),
                       virLockManagerPluginGetName(driver->lockManager));
        return -1;
    }

    if (events)
        priv->signalIOError = abort_on_error;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        if (persist_xml) {
            persistDef = qemuMigrationPrepareDef(driver, persist_xml,
                                                 NULL, NULL);
        } else {
            persistDef = qemuDomainDefCopy(driver, vm->newDef,
                                           VIR_DOMAIN_XML_SECURE |
                                           VIR_DOMAIN_XML_MIGRATABLE);
        }
        if (!persistDef)
            goto cleanup;
    }

    mig = qemuMigrationEatCookie(driver, vm, cookiein, cookieinlen,
                                 cookieFlags | QEMU_MIGRATION_COOKIE_GRAPHICS);
    if (!mig)
        goto cleanup;

    if (qemuDomainMigrateGraphicsRelocate(driver, vm, mig, graphicsuri) < 0)
        VIR_WARN("unable to provide data for graphics client relocation");

    if (flags & VIR_MIGRATE_TLS) {
        cfg = virQEMUDriverGetConfig(driver);

        /* Begin/CheckSetupTLS already set up migTLSAlias, the following
         * assumes that and adds the TLS objects to the domain. */
        if (qemuMigrationAddTLSObjects(driver, vm, cfg, false,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT,
                                       &tlsAlias, &secAlias, migParams) < 0)
            goto cleanup;

        /* We need to add tls-hostname whenever QEMU itself does not
         * connect directly to the destination. */
        if (spec->destType == MIGRATION_DEST_CONNECT_HOST ||
            spec->destType == MIGRATION_DEST_FD) {
            if (VIR_STRDUP(migParams->migrateTLSHostname,
                           spec->dest.host.name) < 0)
                goto cleanup;
        } else {
            /* Be sure there's nothing from a previous migration */
            if (VIR_STRDUP(migParams->migrateTLSHostname, "") < 0)
                goto cleanup;
        }
    } else {
        if (qemuMigrationSetEmptyTLSParams(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT,
                                           migParams) < 0)
            goto cleanup;
    }

    if (migrate_flags & (QEMU_MONITOR_MIGRATE_NON_SHARED_DISK |
                         QEMU_MONITOR_MIGRATE_NON_SHARED_INC)) {
        if (mig->nbd) {
            /* This will update migrate_flags on success */
            if (qemuMigrationDriveMirror(driver, vm, mig,
                                         spec->dest.host.name,
                                         migrate_speed,
                                         &migrate_flags,
                                         nmigrate_disks,
                                         migrate_disks,
                                         dconn) < 0) {
                goto cleanup;
            }
        } else {
            /* Destination doesn't support NBD server.
             * Fall back to previous implementation. */
            VIR_DEBUG("Destination doesn't support NBD server "
                      "Falling back to previous implementation.");
        }
    }

    /* Before EnterMonitor, since qemuMigrationSetOffline already does that */
    if (!(flags & VIR_MIGRATE_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuMigrationSetOffline(driver, vm) < 0)
            goto cleanup;
    }

    if (qemuMigrationSetCompression(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                                    compression, migParams) < 0)
        goto cleanup;

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_AUTO_CONVERGE,
                               flags & VIR_MIGRATE_AUTO_CONVERGE,
                               QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (qemuMigrationSetOption(driver, vm,
                               QEMU_MONITOR_MIGRATION_CAPS_RDMA_PIN_ALL,
                               flags & VIR_MIGRATE_RDMA_PIN_ALL,
                               QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (qemuMigrationSetPostCopy(driver, vm,
                                 flags & VIR_MIGRATE_POSTCOPY,
                                 QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (qemuMigrationSetParams(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT,
                               migParams) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                       QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (priv->job.abortJob) {
        /* explicitly do this *after* we entered the monitor,
         * as this is a critical section so we are guaranteed
         * priv->job.abortJob will not change */
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
        priv->job.current->type = VIR_DOMAIN_JOB_CANCELLED;
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%s: %s"),
                       qemuDomainAsyncJobTypeToString(priv->job.asyncJob),
                       _("canceled by client"));
        goto cleanup;
    }

    if (qemuMonitorSetMigrationSpeed(priv->mon, migrate_speed) < 0)
        goto exit_monitor;

    /* connect to the destination qemu if needed */
    if (spec->destType == MIGRATION_DEST_CONNECT_HOST &&
        qemuMigrationConnect(driver, vm, spec) < 0) {
        goto exit_monitor;
    }

    /* log start of migration */
    if ((timestamp = virTimeStringNow()) != NULL) {
        qemuDomainLogAppendMessage(driver, vm, "%s: initiating migration\n", timestamp);
        VIR_FREE(timestamp);
    }

    switch (spec->destType) {
    case MIGRATION_DEST_HOST:
        if (STREQ(spec->dest.host.protocol, "rdma") &&
            virProcessSetMaxMemLock(vm->pid, vm->def->mem.hard_limit << 10) < 0) {
            goto exit_monitor;
        }
        ret = qemuMonitorMigrateToHost(priv->mon, migrate_flags,
                                       spec->dest.host.protocol,
                                       spec->dest.host.name,
                                       spec->dest.host.port);
        break;

    case MIGRATION_DEST_CONNECT_HOST:
        /* handled above and transformed into MIGRATION_DEST_FD */
        break;

    case MIGRATION_DEST_FD:
        if (spec->fwdType != MIGRATION_FWD_DIRECT) {
            fd = spec->dest.fd.local;
            spec->dest.fd.local = -1;
        }
        ret = qemuMonitorMigrateToFd(priv->mon, migrate_flags,
                                     spec->dest.fd.qemu);
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
        break;
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        ret = -1;
    if (ret < 0)
        goto cleanup;
    ret = -1;

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */

    if (spec->fwdType != MIGRATION_FWD_DIRECT) {
        if (!(iothread = qemuMigrationStartTunnel(spec->fwd.stream, fd)))
            goto cancel;
        /* If we've created a tunnel, then the 'fd' will be closed in the
         * qemuMigrationIOFunc as data->sock.
         */
        fd = -1;
    }

    waitFlags = 0;
    if (abort_on_error)
        waitFlags |= QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR;
    if (mig->nbd)
        waitFlags |= QEMU_MIGRATION_COMPLETED_CHECK_STORAGE;
    if (flags & VIR_MIGRATE_POSTCOPY)
        waitFlags |= QEMU_MIGRATION_COMPLETED_POSTCOPY;

    rc = qemuMigrationWaitForCompletion(driver, vm,
                                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                                        dconn, waitFlags);
    if (rc == -2)
        goto cancel;
    else if (rc == -1)
        goto cleanup;

    if (priv->job.current->stats.status == QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY)
        inPostCopy = true;

    /* When migration completed, QEMU will have paused the CPUs for us.
     * Wait for the STOP event to be processed or explicitly stop CPUs
     * (for old QEMU which does not send events) to release the lock state.
     */
    if (priv->monJSON) {
        while (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
            priv->signalStop = true;
            rc = virDomainObjWait(vm);
            priv->signalStop = false;
            if (rc < 0)
                goto cancelPostCopy;
        }
    } else if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING &&
               qemuMigrationSetOffline(driver, vm) < 0) {
        goto cancelPostCopy;
    }
    if (priv->job.completed)
        priv->job.completed->stopped = priv->job.current->stopped;

    ret = 0;

 cleanup:
    if (ret < 0 && !orig_err)
        orig_err = virSaveLastError();

    /* cancel any outstanding NBD jobs */
    if (mig && mig->nbd) {
        if (qemuMigrationCancelDriveMirror(driver, vm, ret == 0,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT,
                                           dconn) < 0)
            ret = -1;
    }

    VIR_FREE(tlsAlias);
    VIR_FREE(secAlias);
    virObjectUnref(cfg);

    if (spec->fwdType != MIGRATION_FWD_DIRECT) {
        if (iothread && qemuMigrationStopTunnel(iothread, ret < 0) < 0)
            ret = -1;
    }
    VIR_FORCE_CLOSE(fd);

    if (priv->job.completed) {
        qemuDomainJobInfoUpdateTime(priv->job.completed);
        qemuDomainJobInfoUpdateDowntime(priv->job.completed);
        ignore_value(virTimeMillisNow(&priv->job.completed->sent));
    }

    if (priv->job.current->type == VIR_DOMAIN_JOB_UNBOUNDED && !inPostCopy)
        priv->job.current->type = VIR_DOMAIN_JOB_FAILED;

    cookieFlags |= QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS;

    if (ret == 0 &&
        (qemuMigrationCookieAddPersistent(mig, &persistDef) < 0 ||
         qemuMigrationBakeCookie(mig, driver, vm, cookieout,
                                 cookieoutlen, cookieFlags) < 0)) {
        VIR_WARN("Unable to encode migration cookie");
    }

    virDomainDefFree(persistDef);
    qemuMigrationCookieFree(mig);

    if (events)
        priv->signalIOError = false;

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    return ret;

 exit_monitor:
    ignore_value(qemuDomainObjExitMonitor(driver, vm));
    goto cleanup;

 cancel:
    orig_err = virSaveLastError();

    if (virDomainObjIsActive(vm)) {
        if (qemuDomainObjEnterMonitorAsync(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_OUT) == 0) {
            qemuMonitorMigrateCancel(priv->mon);
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
        }
    }
    goto cleanup;

 cancelPostCopy:
    priv->job.current->type = VIR_DOMAIN_JOB_FAILED;
    if (inPostCopy)
        goto cancel;
    else
        goto cleanup;
}

/* Perform migration using QEMU's native migrate support,
 * not encrypted obviously
 */
static int doNativeMigrate(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           const char *persist_xml,
                           const char *uri,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned long flags,
                           unsigned long resource,
                           virConnectPtr dconn,
                           const char *graphicsuri,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           qemuMigrationCompressionPtr compression,
                           qemuMonitorMigrationParamsPtr migParams)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virURIPtr uribits = NULL;
    int ret = -1;
    qemuMigrationSpec spec;

    VIR_DEBUG("driver=%p, vm=%p, uri=%s, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu migrate_disks=%p",
              driver, vm, uri, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    if (!(uribits = qemuMigrationParseURI(uri, NULL)))
        return -1;

    if (uribits->scheme == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing scheme in migration URI: %s"),
                       uri);
        goto cleanup;
    }

    if (STREQ(uribits->scheme, "rdma")) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("outgoing RDMA migration is not supported "
                             "with this QEMU binary"));
            goto cleanup;
        }
        if (!virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot start RDMA migration with no memory hard "
                             "limit set"));
            goto cleanup;
        }
    }

    if (STRNEQ(uribits->scheme, "rdma"))
        spec.destType = MIGRATION_DEST_CONNECT_HOST;
    else
        spec.destType = MIGRATION_DEST_HOST;
    spec.dest.host.protocol = uribits->scheme;
    spec.dest.host.name = uribits->server;
    spec.dest.host.port = uribits->port;
    spec.fwdType = MIGRATION_FWD_DIRECT;

    ret = qemuMigrationRun(driver, vm, persist_xml, cookiein, cookieinlen, cookieout,
                           cookieoutlen, flags, resource, &spec, dconn,
                           graphicsuri, nmigrate_disks, migrate_disks,
                           compression, migParams);

    if (spec.destType == MIGRATION_DEST_FD)
        VIR_FORCE_CLOSE(spec.dest.fd.qemu);

 cleanup:
    virURIFree(uribits);

    return ret;
}


static int doTunnelMigrate(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virStreamPtr st,
                           const char *persist_xml,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned long flags,
                           unsigned long resource,
                           virConnectPtr dconn,
                           const char *graphicsuri,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           qemuMigrationCompressionPtr compression,
                           qemuMonitorMigrationParamsPtr migParams)
{
    int ret = -1;
    qemuMigrationSpec spec;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    int fds[2] = { -1, -1 };

    VIR_DEBUG("driver=%p, vm=%p, st=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, st, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    spec.fwdType = MIGRATION_FWD_STREAM;
    spec.fwd.stream = st;


    spec.destType = MIGRATION_DEST_FD;
    spec.dest.fd.qemu = -1;
    spec.dest.fd.local = -1;

    if (pipe2(fds, O_CLOEXEC) == 0) {
        spec.dest.fd.qemu = fds[1];
        spec.dest.fd.local = fds[0];
    }
    if (spec.dest.fd.qemu == -1 ||
        qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    spec.dest.fd.qemu) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto cleanup;
    }

    ret = qemuMigrationRun(driver, vm, persist_xml, cookiein, cookieinlen,
                           cookieout, cookieoutlen, flags, resource, &spec,
                           dconn, graphicsuri, nmigrate_disks, migrate_disks,
                           compression, migParams);

 cleanup:
    VIR_FORCE_CLOSE(spec.dest.fd.qemu);
    VIR_FORCE_CLOSE(spec.dest.fd.local);

    virObjectUnref(cfg);
    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion2
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int doPeer2PeerMigrate2(virQEMUDriverPtr driver,
                               virConnectPtr sconn ATTRIBUTE_UNUSED,
                               virConnectPtr dconn,
                               virDomainObjPtr vm,
                               const char *dconnuri,
                               unsigned long flags,
                               const char *dname,
                               unsigned long resource)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookie = NULL;
    char *dom_xml = NULL;
    int cookielen = 0, ret;
    virErrorPtr orig_err = NULL;
    bool cancelled;
    virStreamPtr st = NULL;
    unsigned long destflags;
    qemuMigrationCompressionPtr compression = NULL;
    qemuMonitorMigrationParams migParams = { 0 };

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, vm=%p, dconnuri=%s, "
              "flags=%lx, dname=%s, resource=%lu",
              driver, sconn, dconn, vm, NULLSTR(dconnuri),
              flags, NULLSTR(dname), resource);

    /* In version 2 of the protocol, the prepare step is slightly
     * different.  We fetch the domain XML of the source domain
     * and pass it to Prepare2.
     */
    if (!(dom_xml = qemuDomainFormatXML(driver, vm,
                                        QEMU_DOMAIN_FORMAT_LIVE_FLAGS |
                                        VIR_DOMAIN_XML_MIGRATABLE)))
        return -1;

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    if (!(compression = qemuMigrationCompressionParse(NULL, 0, flags)))
        goto cleanup;

    VIR_DEBUG("Prepare2 %p", dconn);
    if (flags & VIR_MIGRATE_TUNNELLED) {
        /*
         * Tunnelled Migrate Version 2 does not support cookies
         * due to missing parameters in the prepareTunnel() API.
         */

        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepareTunnel
            (dconn, st, destflags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    } else {
        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepare2
            (dconn, &cookie, &cookielen, NULL, &uri_out,
             destflags, dname, resource, dom_xml);
        qemuDomainObjExitRemote(vm);
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    /* the domain may have shutdown or crashed while we had the locks dropped
     * in qemuDomainObjEnterRemote, so check again
     */
    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_TUNNELLED) &&
        (uri_out == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare2 did not set uri"));
        cancelled = true;
        orig_err = virSaveLastError();
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", sconn);
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = doTunnelMigrate(driver, vm, st, NULL,
                              NULL, 0, NULL, NULL,
                              flags, resource, dconn,
                              NULL, 0, NULL, compression, &migParams);
    else
        ret = doNativeMigrate(driver, vm, NULL, uri_out,
                              cookie, cookielen,
                              NULL, NULL, /* No out cookie with v2 migration */
                              flags, resource, dconn, NULL, 0, NULL,
                              compression, &migParams);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        orig_err = virSaveLastError();

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0;

 finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    dname = dname ? dname : vm->def->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    qemuDomainObjEnterRemote(vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen,
         uri_out ? uri_out : dconnuri, destflags, cancelled);
    qemuDomainObjExitRemote(vm);
    if (cancelled && ddomain)
        VIR_ERROR(_("finish step ignored that migration was cancelled"));

 cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    qemuMigrationParamsClear(&migParams);
    VIR_FREE(uri_out);
    VIR_FREE(cookie);
    VIR_FREE(compression);

    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion3
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int
doPeer2PeerMigrate3(virQEMUDriverPtr driver,
                    virConnectPtr sconn,
                    virConnectPtr dconn,
                    const char *dconnuri,
                    virDomainObjPtr vm,
                    const char *xmlin,
                    const char *persist_xml,
                    const char *dname,
                    const char *uri,
                    const char *graphicsuri,
                    const char *listenAddress,
                    size_t nmigrate_disks,
                    const char **migrate_disks,
                    int nbdPort,
                    qemuMigrationCompressionPtr compression,
                    qemuMonitorMigrationParamsPtr migParams,
                    unsigned long long bandwidth,
                    bool useParams,
                    unsigned long flags)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    char *dom_xml = NULL;
    int cookieinlen = 0;
    int cookieoutlen = 0;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    bool cancelled = true;
    virStreamPtr st = NULL;
    unsigned long destflags;
    virTypedParameterPtr params = NULL;
    int nparams = 0;
    int maxparams = 0;
    size_t i;

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, dconnuri=%s, vm=%p, xmlin=%s, "
              "dname=%s, uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "bandwidth=%llu, useParams=%d, flags=%lx",
              driver, sconn, dconn, NULLSTR(dconnuri), vm, NULLSTR(xmlin),
              NULLSTR(dname), NULLSTR(uri), NULLSTR(graphicsuri),
              NULLSTR(listenAddress), nmigrate_disks, migrate_disks, nbdPort,
              bandwidth, useParams, flags);

    /* Unlike the virDomainMigrateVersion3 counterpart, we don't need
     * to worry about auto-setting the VIR_MIGRATE_CHANGE_PROTECTION
     * bit here, because we are already running inside the context of
     * a single job.  */

    dom_xml = qemuMigrationBeginPhase(driver, vm, xmlin, dname,
                                      &cookieout, &cookieoutlen,
                                      nmigrate_disks, migrate_disks, flags);
    if (!dom_xml)
        goto cleanup;

    if (useParams) {
        if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_XML, dom_xml) < 0)
            goto cleanup;

        if (dname &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, dname) < 0)
            goto cleanup;

        if (uri &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_URI, uri) < 0)
            goto cleanup;

        if (bandwidth &&
            virTypedParamsAddULLong(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_BANDWIDTH,
                                    bandwidth) < 0)
            goto cleanup;

        if (graphicsuri &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_GRAPHICS_URI,
                                    graphicsuri) < 0)
            goto cleanup;
        if (listenAddress &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_LISTEN_ADDRESS,
                                    listenAddress) < 0)
            goto cleanup;
        for (i = 0; i < nmigrate_disks; i++)
            if (virTypedParamsAddString(&params, &nparams, &maxparams,
                                        VIR_MIGRATE_PARAM_MIGRATE_DISKS,
                                        migrate_disks[i]) < 0)
                goto cleanup;
        if (nbdPort &&
            virTypedParamsAddInt(&params, &nparams, &maxparams,
                                 VIR_MIGRATE_PARAM_DISKS_PORT,
                                 nbdPort) < 0)
            goto cleanup;

        if (qemuMigrationCompressionDump(compression, &params, &nparams,
                                         &maxparams, &flags) < 0)
            goto cleanup;
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare3 %p", dconn);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED) {
        if (!(st = virStreamNew(dconn, 0)))
            goto cleanup;

        qemuDomainObjEnterRemote(vm);
        if (useParams) {
            ret = dconn->driver->domainMigratePrepareTunnel3Params
                (dconn, st, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags);
        } else {
            ret = dconn->driver->domainMigratePrepareTunnel3
                (dconn, st, cookiein, cookieinlen, &cookieout, &cookieoutlen,
                 destflags, dname, bandwidth, dom_xml);
        }
        qemuDomainObjExitRemote(vm);
    } else {
        qemuDomainObjEnterRemote(vm);
        if (useParams) {
            ret = dconn->driver->domainMigratePrepare3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, &uri_out, destflags);
        } else {
            ret = dconn->driver->domainMigratePrepare3
                (dconn, cookiein, cookieinlen, &cookieout, &cookieoutlen,
                 uri, &uri_out, destflags, dname, bandwidth, dom_xml);
        }
        qemuDomainObjExitRemote(vm);
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (flags & VIR_MIGRATE_OFFLINE) {
        VIR_DEBUG("Offline migration, skipping Perform phase");
        VIR_FREE(cookieout);
        cookieoutlen = 0;
        cancelled = false;
        goto finish;
    }

    if (uri_out) {
        uri = uri_out;
        if (useParams &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_URI, uri_out) < 0) {
            orig_err = virSaveLastError();
            goto finish;
        }
    } else if (!uri && !(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare3 did not set uri"));
        orig_err = virSaveLastError();
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s", sconn, NULLSTR(uri));
    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    if (flags & VIR_MIGRATE_TUNNELLED) {
        ret = doTunnelMigrate(driver, vm, st, persist_xml,
                              cookiein, cookieinlen,
                              &cookieout, &cookieoutlen,
                              flags, bandwidth, dconn, graphicsuri,
                              nmigrate_disks, migrate_disks, compression,
                              migParams);
    } else {
        ret = doNativeMigrate(driver, vm, persist_xml, uri,
                              cookiein, cookieinlen,
                              &cookieout, &cookieoutlen,
                              flags, bandwidth, dconn, graphicsuri,
                              nmigrate_disks, migrate_disks, compression,
                              migParams);
    }

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0) {
        orig_err = virSaveLastError();
    } else {
        qemuMigrationJobSetPhase(driver, vm,
                                 QEMU_MIGRATION_PHASE_PERFORM3_DONE);
    }

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0;

 finish:
    /*
     * The status code from the source is passed to the destination.
     * The dest can cleanup in the source indicated it failed to
     * send all migration data. Returns NULL for ddomain if
     * the dest was unable to complete migration.
     */
    VIR_DEBUG("Finish3 %p ret=%d", dconn, ret);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;

    if (useParams) {
        if (virTypedParamsGetString(params, nparams,
                                    VIR_MIGRATE_PARAM_DEST_NAME, NULL) <= 0 &&
            virTypedParamsReplaceString(&params, &nparams,
                                        VIR_MIGRATE_PARAM_DEST_NAME,
                                        vm->def->name) < 0) {
            ddomain = NULL;
        } else {
            qemuDomainObjEnterRemote(vm);
            ddomain = dconn->driver->domainMigrateFinish3Params
                (dconn, params, nparams, cookiein, cookieinlen,
                 &cookieout, &cookieoutlen, destflags, cancelled);
            qemuDomainObjExitRemote(vm);
        }
    } else {
        dname = dname ? dname : vm->def->name;
        qemuDomainObjEnterRemote(vm);
        ddomain = dconn->driver->domainMigrateFinish3
            (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             dconnuri, uri, destflags, cancelled);
        qemuDomainObjExitRemote(vm);
    }

    if (cancelled) {
        if (ddomain) {
            VIR_ERROR(_("finish step ignored that migration was cancelled"));
        } else {
            /* If Finish reported a useful error, use it instead of the
             * original "migration unexpectedly failed" error.
             *
             * This is ugly but we can't do better with the APIs we have. We
             * only replace the error if Finish was called with cancelled == 1
             * and reported a real error (old libvirt would report an error
             * from RPC instead of MIGRATE_FINISH_OK), which only happens when
             * the domain died on destination. To further reduce a possibility
             * of false positives we also check that Perform returned
             * VIR_ERR_OPERATION_FAILED.
             */
            if (orig_err &&
                orig_err->domain == VIR_FROM_QEMU &&
                orig_err->code == VIR_ERR_OPERATION_FAILED) {
                virErrorPtr err = virGetLastError();
                if (err &&
                    err->domain == VIR_FROM_QEMU &&
                    err->code != VIR_ERR_MIGRATE_FINISH_OK) {
                    virFreeError(orig_err);
                    orig_err = NULL;
                }
            }
        }
    }

    /* If ddomain is NULL, then we were unable to start
     * the guest on the target, and must restart on the
     * source. There is a small chance that the ddomain
     * is NULL due to an RPC failure, in which case
     * ddomain could in fact be running on the dest.
     * The lock manager plugins should take care of
     * safety in this scenario.
     */
    cancelled = ddomain == NULL;

    /* If finish3 set an error, and we don't have an earlier
     * one we need to preserve it in case confirm3 overwrites
     */
    if (!orig_err)
        orig_err = virSaveLastError();

    /*
     * If cancelled, then src VM will be restarted, else
     * it will be killed
     */
    VIR_DEBUG("Confirm3 %p cancelled=%d vm=%p", sconn, cancelled, vm);
    VIR_FREE(cookiein);
    cookiein = cookieout;
    cookieinlen = cookieoutlen;
    cookieout = NULL;
    cookieoutlen = 0;
    ret = qemuMigrationConfirmPhase(driver, sconn, vm,
                                    cookiein, cookieinlen,
                                    flags, cancelled);
    /* If Confirm3 returns -1, there's nothing more we can
     * do, but fortunately worst case is that there is a
     * domain left in 'paused' state on source.
     */
    if (ret < 0)
        VIR_WARN("Guest %s probably left in 'paused' state on source",
                 vm->def->name);

 cleanup:
    if (ddomain) {
        virObjectUnref(ddomain);
        ret = 0;
    } else {
        ret = -1;
    }

    virObjectUnref(st);

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);
    virTypedParamsFree(params, nparams);
    return ret;
}


static void
qemuMigrationConnectionClosed(virConnectPtr conn,
                              int reason,
                              void *opaque)
{
    virDomainObjPtr vm = opaque;

    VIR_DEBUG("conn=%p, reason=%d, vm=%s", conn, reason, vm->def->name);
    virDomainObjBroadcast(vm);
}


static int virConnectCredType[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE,
};


static virConnectAuth virConnectAuthConfig = {
    .credtype = virConnectCredType,
    .ncredtype = ARRAY_CARDINALITY(virConnectCredType),
};


static int doPeer2PeerMigrate(virQEMUDriverPtr driver,
                              virConnectPtr sconn,
                              virDomainObjPtr vm,
                              const char *xmlin,
                              const char *persist_xml,
                              const char *dconnuri,
                              const char *uri,
                              const char *graphicsuri,
                              const char *listenAddress,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              int nbdPort,
                              qemuMigrationCompressionPtr compression,
                              qemuMonitorMigrationParamsPtr migParams,
                              unsigned long flags,
                              const char *dname,
                              unsigned long resource,
                              bool *v3proto)
{
    int ret = -1;
    virConnectPtr dconn = NULL;
    bool p2p;
    virErrorPtr orig_err = NULL;
    bool offline = false;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    bool useParams;

    VIR_DEBUG("driver=%p, sconn=%p, vm=%p, xmlin=%s, dconnuri=%s, uri=%s, "
              "graphicsuri=%s, listenAddress=%s, nmigrate_disks=%zu, "
              "migrate_disks=%p, nbdPort=%d, flags=%lx, dname=%s, "
              "resource=%lu",
              driver, sconn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, flags, NULLSTR(dname),
              resource);

    if (flags & VIR_MIGRATE_TUNNELLED && uri) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("migration URI is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && listenAddress) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("listen address is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && nbdPort) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("disk port address is not supported by tunnelled "
                         "migration"));
        goto cleanup;
    }

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    qemuDomainObjEnterRemote(vm);
    dconn = virConnectOpenAuth(dconnuri, &virConnectAuthConfig, 0);
    qemuDomainObjExitRemote(vm);
    if (dconn == NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Failed to connect to remote libvirt URI %s: %s"),
                       dconnuri, virGetLastErrorMessage());
        virObjectUnref(cfg);
        return -1;
    }

    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    if (virConnectRegisterCloseCallback(dconn, qemuMigrationConnectionClosed,
                                        vm, NULL) < 0) {
        goto cleanup;
    }

    qemuDomainObjEnterRemote(vm);
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
        /* v3proto reflects whether the caller used Perform3, but with
         * p2p migrate, regardless of whether Perform2 or Perform3
         * were used, we decide protocol based on what target supports
         */
    *v3proto = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                        VIR_DRV_FEATURE_MIGRATION_V3);
    useParams = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                         VIR_DRV_FEATURE_MIGRATION_PARAMS);
    if (flags & VIR_MIGRATE_OFFLINE)
        offline = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                           VIR_DRV_FEATURE_MIGRATION_OFFLINE);
    qemuDomainObjExitRemote(vm);

    if (!p2p) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    /* Only xmlin, dname, uri, and bandwidth parameters can be used with
     * old-style APIs. */
    if (!useParams && (graphicsuri || listenAddress || nmigrate_disks)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Migration APIs with extensible parameters are not "
                         "supported but extended parameters were passed"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_OFFLINE && !offline) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("offline migration is not supported by "
                         "the destination host"));
        goto cleanup;
    }

    /* domain may have been stopped while we were talking to remote daemon */
    if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        goto cleanup;
    }

    /* Change protection is only required on the source side (us), and
     * only for v3 migration when begin and perform are separate jobs.
     * But peer-2-peer is already a single job, and we still want to
     * talk to older destinations that would reject the flag.
     * Therefore it is safe to clear the bit here.  */
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    if (*v3proto) {
        ret = doPeer2PeerMigrate3(driver, sconn, dconn, dconnuri, vm, xmlin,
                                  persist_xml, dname, uri, graphicsuri,
                                  listenAddress, nmigrate_disks, migrate_disks,
                                  nbdPort, compression, migParams, resource,
                                  useParams, flags);
    } else {
        ret = doPeer2PeerMigrate2(driver, sconn, dconn, vm,
                                  dconnuri, flags, dname, resource);
    }

 cleanup:
    orig_err = virSaveLastError();
    qemuDomainObjEnterRemote(vm);
    virConnectUnregisterCloseCallback(dconn, qemuMigrationConnectionClosed);
    virObjectUnref(dconn);
    qemuDomainObjExitRemote(vm);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(cfg);
    return ret;
}


/*
 * This implements perform part of the migration protocol when migration job
 * does not need to be active across several APIs, i.e., peer2peer migration or
 * perform phase of v2 non-peer2peer migration.
 */
static int
qemuMigrationPerformJob(virQEMUDriverPtr driver,
                        virConnectPtr conn,
                        virDomainObjPtr vm,
                        const char *xmlin,
                        const char *persist_xml,
                        const char *dconnuri,
                        const char *uri,
                        const char *graphicsuri,
                        const char *listenAddress,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        int nbdPort,
                        qemuMigrationCompressionPtr compression,
                        qemuMonitorMigrationParamsPtr migParams,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned long flags,
                        const char *dname,
                        unsigned long resource,
                        bool v3proto)
{
    virObjectEventPtr event = NULL;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto cleanup;

    if (!virDomainObjIsActive(vm) && !(flags & VIR_MIGRATE_OFFLINE)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       "%s", _("domain is not running"));
        goto endjob;
    }

    if (!qemuMigrationIsAllowed(driver, vm, true, flags))
        goto endjob;

    if (!(flags & VIR_MIGRATE_UNSAFE) &&
        !qemuMigrationIsSafe(vm->def, nmigrate_disks, migrate_disks, flags))
        goto endjob;

    qemuMigrationStoreDomainState(vm);

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        ret = doPeer2PeerMigrate(driver, conn, vm, xmlin, persist_xml,
                                 dconnuri, uri, graphicsuri, listenAddress,
                                 nmigrate_disks, migrate_disks, nbdPort,
                                 compression, migParams, flags, dname, resource,
                                 &v3proto);
    } else {
        qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM2);
        ret = doNativeMigrate(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                              cookieout, cookieoutlen,
                              flags, resource, NULL, NULL, 0, NULL,
                              compression, migParams);
    }
    if (ret < 0)
        goto endjob;

    /*
     * In v3 protocol, the source VM is not killed off until the
     * confirm step.
     */
    if (!v3proto) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        QEMU_ASYNC_JOB_MIGRATION_OUT,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    }

 endjob:
    if (ret < 0)
        orig_err = virSaveLastError();

    /* v2 proto has no confirm phase so we need to reset migration parameters
     * here
     */
    if (!v3proto && ret < 0)
        qemuMigrationReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT);

    if (qemuMigrationRestoreDomainState(conn, vm)) {
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_RESUMED,
                                         VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    }

    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm) && ret == 0) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactive(driver, vm);
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    virObjectUnref(cfg);
    return ret;
}

/*
 * This implements perform phase of v3 migration protocol.
 */
static int
qemuMigrationPerformPhase(virQEMUDriverPtr driver,
                          virConnectPtr conn,
                          virDomainObjPtr vm,
                          const char *persist_xml,
                          const char *uri,
                          const char *graphicsuri,
                          size_t nmigrate_disks,
                          const char **migrate_disks,
                          qemuMigrationCompressionPtr compression,
                          qemuMonitorMigrationParamsPtr migParams,
                          const char *cookiein,
                          int cookieinlen,
                          char **cookieout,
                          int *cookieoutlen,
                          unsigned long flags,
                          unsigned long resource)
{
    virObjectEventPtr event = NULL;
    int ret = -1;

    /* If we didn't start the job in the begin phase, start it now. */
    if (!(flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto cleanup;
    } else if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_OUT)) {
        goto cleanup;
    }

    qemuMigrationJobStartPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3);
    virCloseCallbacksUnset(driver->closeCallbacks, vm,
                           qemuMigrationCleanup);

    ret = doNativeMigrate(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                          cookieout, cookieoutlen,
                          flags, resource, NULL, graphicsuri,
                          nmigrate_disks, migrate_disks, compression, migParams);

    if (ret < 0) {
        if (qemuMigrationRestoreDomainState(conn, vm)) {
            event = virDomainEventLifecycleNewFromObj(vm,
                                                      VIR_DOMAIN_EVENT_RESUMED,
                                                      VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        }
        goto endjob;
    }

    qemuMigrationJobSetPhase(driver, vm, QEMU_MIGRATION_PHASE_PERFORM3_DONE);

    if (virCloseCallbacksSet(driver->closeCallbacks, vm, conn,
                             qemuMigrationCleanup) < 0)
        goto endjob;

 endjob:
    if (ret < 0) {
        qemuMigrationReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_OUT);
        qemuMigrationJobFinish(driver, vm);
    } else {
        qemuMigrationJobContinue(vm);
    }

    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm);

 cleanup:
    virDomainObjEndAPI(&vm);
    qemuDomainEventQueue(driver, event);
    return ret;
}

int
qemuMigrationPerform(virQEMUDriverPtr driver,
                     virConnectPtr conn,
                     virDomainObjPtr vm,
                     const char *xmlin,
                     const char *persist_xml,
                     const char *dconnuri,
                     const char *uri,
                     const char *graphicsuri,
                     const char *listenAddress,
                     size_t nmigrate_disks,
                     const char **migrate_disks,
                     int nbdPort,
                     qemuMigrationCompressionPtr compression,
                     qemuMonitorMigrationParamsPtr migParams,
                     const char *cookiein,
                     int cookieinlen,
                     char **cookieout,
                     int *cookieoutlen,
                     unsigned long flags,
                     const char *dname,
                     unsigned long resource,
                     bool v3proto)
{
    VIR_DEBUG("driver=%p, conn=%p, vm=%p, xmlin=%s, dconnuri=%s, "
              "uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "cookiein=%s, cookieinlen=%d, cookieout=%p, cookieoutlen=%p, "
              "flags=%lx, dname=%s, resource=%lu, v3proto=%d",
              driver, conn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort,
              NULLSTR(cookiein), cookieinlen, cookieout, cookieoutlen,
              flags, NULLSTR(dname), resource, v3proto);

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (cookieinlen) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("received unexpected cookie with P2P migration"));
            return -1;
        }

        return qemuMigrationPerformJob(driver, conn, vm, xmlin, persist_xml, dconnuri, uri,
                                       graphicsuri, listenAddress,
                                       nmigrate_disks, migrate_disks, nbdPort,
                                       compression, migParams,
                                       cookiein, cookieinlen,
                                       cookieout, cookieoutlen,
                                       flags, dname, resource, v3proto);
    } else {
        if (dconnuri) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Unexpected dconnuri parameter with non-peer2peer migration"));
            return -1;
        }

        if (v3proto) {
            return qemuMigrationPerformPhase(driver, conn, vm, persist_xml, uri,
                                             graphicsuri,
                                             nmigrate_disks, migrate_disks,
                                             compression, migParams,
                                             cookiein, cookieinlen,
                                             cookieout, cookieoutlen,
                                             flags, resource);
        } else {
            return qemuMigrationPerformJob(driver, conn, vm, xmlin, persist_xml, NULL,
                                           uri, graphicsuri, listenAddress,
                                           nmigrate_disks, migrate_disks, nbdPort,
                                           compression, migParams,
                                           cookiein, cookieinlen,
                                           cookieout, cookieoutlen, flags,
                                           dname, resource, v3proto);
        }
    }
}

static int
qemuMigrationVPAssociatePortProfiles(virDomainDefPtr def)
{
    size_t i;
    int last_good_net = -1;
    virDomainNetDefPtr net;

    for (i = 0; i < def->nnets; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            if (virNetDevVPortProfileAssociate(net->ifname,
                                               virDomainNetGetActualVirtPortProfile(net),
                                               &net->mac,
                                               virDomainNetGetActualDirectDev(net),
                                               -1,
                                               def->uuid,
                                               VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH,
                                               false) < 0) {
                virReportError(VIR_ERR_OPERATION_FAILED,
                               _("Port profile Associate failed for %s"),
                               net->ifname);
                goto err_exit;
            }
            last_good_net = i;
            VIR_DEBUG("Port profile Associate succeeded for %s", net->ifname);

            if (virNetDevMacVLanVPortProfileRegisterCallback(net->ifname, &net->mac,
                                                             virDomainNetGetActualDirectDev(net), def->uuid,
                                                             virDomainNetGetActualVirtPortProfile(net),
                                                             VIR_NETDEV_VPORT_PROFILE_OP_CREATE))
                goto err_exit;
        }
    }

    return 0;

 err_exit:
    for (i = 0; last_good_net != -1 && i <= last_good_net; i++) {
        net = def->nets[i];
        if (virDomainNetGetActualType(net) == VIR_DOMAIN_NET_TYPE_DIRECT) {
            ignore_value(virNetDevVPortProfileDisassociate(net->ifname,
                                                           virDomainNetGetActualVirtPortProfile(net),
                                                           &net->mac,
                                                           virDomainNetGetActualDirectDev(net),
                                                           -1,
                                                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH));
        }
    }
    return -1;
}


static int
qemuMigrationPersist(virQEMUDriverPtr driver,
                     virDomainObjPtr vm,
                     qemuMigrationCookiePtr mig,
                     bool ignoreSaveError)
{
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virCapsPtr caps = NULL;
    virDomainDefPtr vmdef;
    virDomainDefPtr oldDef = NULL;
    unsigned int oldPersist = vm->persistent;
    virObjectEventPtr event;
    int ret = -1;

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        goto cleanup;

    vm->persistent = 1;
    oldDef = vm->newDef;
    vm->newDef = qemuMigrationCookieGetPersistent(mig);

    if (!(vmdef = virDomainObjGetPersistentDef(caps, driver->xmlopt, vm)))
        goto error;

    if (virDomainSaveConfig(cfg->configDir, driver->caps, vmdef) < 0 &&
        !ignoreSaveError)
        goto error;

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_DEFINED,
                                              oldPersist ?
                                              VIR_DOMAIN_EVENT_DEFINED_UPDATED :
                                              VIR_DOMAIN_EVENT_DEFINED_ADDED);
    qemuDomainEventQueue(driver, event);

    ret = 0;

 cleanup:
    virDomainDefFree(oldDef);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return ret;

 error:
    virDomainDefFree(vm->newDef);
    vm->persistent = oldPersist;
    vm->newDef = oldDef;
    oldDef = NULL;
    goto cleanup;
}


virDomainPtr
qemuMigrationFinish(virQEMUDriverPtr driver,
                    virConnectPtr dconn,
                    virDomainObjPtr vm,
                    const char *cookiein,
                    int cookieinlen,
                    char **cookieout,
                    int *cookieoutlen,
                    unsigned long flags,
                    int retcode,
                    bool v3proto)
{
    virDomainPtr dom = NULL;
    qemuMigrationCookiePtr mig = NULL;
    virErrorPtr orig_err = NULL;
    int cookie_flags = 0;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    unsigned short port;
    unsigned long long timeReceived = 0;
    virObjectEventPtr event;
    qemuDomainJobInfoPtr jobInfo = NULL;
    bool inPostCopy = false;
    bool doKill = true;

    VIR_DEBUG("driver=%p, dconn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=%lx, retcode=%d",
              driver, dconn, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, retcode);

    port = priv->migrationPort;
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, QEMU_ASYNC_JOB_MIGRATION_IN)) {
        qemuMigrationErrorReport(driver, vm->def->name);
        goto cleanup;
    }

    ignore_value(virTimeMillisNow(&timeReceived));

    qemuMigrationJobStartPhase(driver, vm,
                               v3proto ? QEMU_MIGRATION_PHASE_FINISH3
                                       : QEMU_MIGRATION_PHASE_FINISH2);

    qemuDomainCleanupRemove(vm, qemuMigrationPrepareCleanup);
    VIR_FREE(priv->job.completed);

    cookie_flags = QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS |
                   QEMU_MIGRATION_COOKIE_NBD;
    /* Some older versions of libvirt always send persistent XML in the cookie
     * even though VIR_MIGRATE_PERSIST_DEST was not used. */
    cookie_flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;

    if (!(mig = qemuMigrationEatCookie(driver, vm, cookiein,
                                       cookieinlen, cookie_flags)))
        goto endjob;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (retcode == 0 &&
            qemuMigrationPersist(driver, vm, mig, false) == 0)
            dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, -1);
        goto endjob;
    }

    if (retcode != 0) {
        /* Check for a possible error on the monitor in case Finish was called
         * earlier than monitor EOF handler got a chance to process the error
         */
        qemuDomainCheckMonitor(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN);
        goto endjob;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        qemuMigrationErrorReport(driver, vm->def->name);
        goto endjob;
    }

    if (qemuMigrationVPAssociatePortProfiles(vm->def) < 0)
        goto endjob;

    if (mig->network && qemuDomainMigrateOPDRelocate(driver, vm, mig) < 0)
        VIR_WARN("unable to provide network data for relocation");

    if (qemuMigrationStopNBDServer(driver, vm, mig) < 0)
        goto endjob;

    if (qemuRefreshVirtioChannelState(driver, vm,
                                      QEMU_ASYNC_JOB_MIGRATION_IN) < 0)
        goto endjob;

    if (qemuConnectAgent(driver, vm) < 0)
        goto endjob;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        if (qemuMigrationPersist(driver, vm, mig, !v3proto) < 0) {
            /* Hmpf.  Migration was successful, but making it persistent
             * was not.  If we report successful, then when this domain
             * shuts down, management tools are in for a surprise.  On the
             * other hand, if we report failure, then the management tools
             * might try to restart the domain on the source side, even
             * though the domain is actually running on the destination.
             * Pretend success and hope that this is a rare situation and
             * management tools are smart.
             *
             * However, in v3 protocol, the source VM is still available
             * to restart during confirm() step, so we kill it off now.
             */
            if (v3proto)
                goto endjob;
        }
    }

    /* We need to wait for QEMU to process all data sent by the source
     * before starting guest CPUs.
     */
    if (qemuMigrationWaitForDestCompletion(driver, vm,
                                           QEMU_ASYNC_JOB_MIGRATION_IN,
                                           !!(flags & VIR_MIGRATE_POSTCOPY)) < 0) {
        /* There's not much we can do for v2 protocol since the
         * original domain on the source host is already gone.
         */
        if (v3proto)
            goto endjob;
    }

    if (priv->job.current->stats.status == QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY)
        inPostCopy = true;

    if (!(flags & VIR_MIGRATE_PAUSED)) {
        /* run 'cont' on the destination, which allows migration on qemu
         * >= 0.10.6 to work properly.  This isn't strictly necessary on
         * older qemu's, but it also doesn't hurt anything there
         */
        if (qemuProcessStartCPUs(driver, vm, dconn,
                                 inPostCopy ? VIR_DOMAIN_RUNNING_POSTCOPY
                                            : VIR_DOMAIN_RUNNING_MIGRATED,
                                 QEMU_ASYNC_JOB_MIGRATION_IN) < 0) {
            if (virGetLastError() == NULL)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("resume operation failed"));
            /* Need to save the current error, in case shutting
             * down the process overwrites it
             */
            orig_err = virSaveLastError();

            /*
             * In v3 protocol, the source VM is still available to
             * restart during confirm() step, so we kill it off
             * now.
             * In v2 protocol, the source is dead, so we leave
             * target in paused state, in case admin can fix
             * things up.
             */
            if (v3proto)
                goto endjob;
        }

        if (inPostCopy) {
            doKill = false;
            event = virDomainEventLifecycleNewFromObj(vm,
                                        VIR_DOMAIN_EVENT_RESUMED,
                                        VIR_DOMAIN_EVENT_RESUMED_POSTCOPY);
            qemuDomainEventQueue(driver, event);
        }
    }

    if (mig->jobInfo) {
        jobInfo = mig->jobInfo;
        mig->jobInfo = NULL;

        if (jobInfo->sent && timeReceived) {
            jobInfo->timeDelta = timeReceived - jobInfo->sent;
            jobInfo->received = timeReceived;
            jobInfo->timeDeltaSet = true;
        }
        qemuDomainJobInfoUpdateTime(jobInfo);
        qemuDomainJobInfoUpdateDowntime(jobInfo);
    }

    if (inPostCopy) {
        if (qemuMigrationWaitForDestCompletion(driver, vm,
                                               QEMU_ASYNC_JOB_MIGRATION_IN,
                                               false) < 0) {
            goto endjob;
        }
        if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
            virDomainObjSetState(vm,
                                 VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_MIGRATED);
        }
    }

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id);

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_RESUMED,
                                              VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
    qemuDomainEventQueue(driver, event);

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        qemuDomainEventQueue(driver, event);
    }

    if (virDomainObjIsActive(vm) &&
        virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
        VIR_WARN("Failed to save status on vm %s", vm->def->name);

    /* Guest is successfully running, so cancel previous auto destroy */
    qemuProcessAutoDestroyRemove(driver, vm);

 endjob:
    if (!dom &&
        !(flags & VIR_MIGRATE_OFFLINE) &&
        virDomainObjIsActive(vm)) {
        if (doKill) {
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                            QEMU_ASYNC_JOB_MIGRATION_IN,
                            VIR_QEMU_PROCESS_STOP_MIGRATED);
            virDomainAuditStop(vm, "failed");
            event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_STOPPED,
                                VIR_DOMAIN_EVENT_STOPPED_FAILED);
            qemuDomainEventQueue(driver, event);
        } else {
            qemuMigrationPostcopyFailed(driver, vm);
        }
    }

    if (dom) {
        priv->job.completed = jobInfo;
        jobInfo = NULL;
        if (qemuMigrationBakeCookie(mig, driver, vm, cookieout, cookieoutlen,
                                    QEMU_MIGRATION_COOKIE_STATS) < 0)
            VIR_WARN("Unable to encode migration cookie");

        /* Remove completed stats for post-copy, everything but timing fields
         * is obsolete anyway.
         */
        if (inPostCopy)
            VIR_FREE(priv->job.completed);
    }

    qemuMigrationReset(driver, vm, QEMU_ASYNC_JOB_MIGRATION_IN);

    qemuMigrationJobFinish(driver, vm);
    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm);

 cleanup:
    VIR_FREE(jobInfo);
    virPortAllocatorRelease(driver->migrationPorts, port);
    if (priv->mon)
        qemuMonitorSetDomainLog(priv->mon, NULL, NULL, NULL);
    VIR_FREE(priv->origname);
    virDomainObjEndAPI(&vm);
    qemuMigrationCookieFree(mig);
    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }
    virObjectUnref(cfg);

    /* Set a special error if Finish is expected to return NULL as a result of
     * successful call with retcode != 0
     */
    if (retcode != 0 && !dom && !virGetLastError())
        virReportError(VIR_ERR_MIGRATE_FINISH_OK, NULL);
    return dom;
}


/* Helper function called while vm is active.  */
int
qemuMigrationToFile(virQEMUDriverPtr driver, virDomainObjPtr vm,
                    int fd,
                    const char *compressor,
                    qemuDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;
    int ret = -1;
    virCommandPtr cmd = NULL;
    int pipeFD[2] = { -1, -1 };
    unsigned long saveMigBandwidth = priv->migMaxBandwidth;
    char *errbuf = NULL;
    virErrorPtr orig_err = NULL;

    /* Increase migration bandwidth to unlimited since target is a file.
     * Failure to change migration speed is not fatal. */
    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        qemuMonitorSetMigrationSpeed(priv->mon,
                                     QEMU_DOMAIN_MIG_BANDWIDTH_MAX);
        priv->migMaxBandwidth = QEMU_DOMAIN_MIG_BANDWIDTH_MAX;
        if (qemuDomainObjExitMonitor(driver, vm) < 0)
            return -1;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        /* nothing to tear down */
        return -1;
    }

    if (compressor && pipe(pipeFD) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to create pipe for migration"));
        return -1;
    }

    /* All right! We can use fd migration, which means that qemu
     * doesn't have to open() the file, so while we still have to
     * grant SELinux access, we can do it on fd and avoid cleanup
     * later, as well as skip futzing with cgroup.  */
    if (qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    compressor ? pipeFD[1] : fd) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    if (!compressor) {
        rc = qemuMonitorMigrateToFd(priv->mon,
                                    QEMU_MONITOR_MIGRATE_BACKGROUND,
                                    fd);
    } else {
        const char *prog = compressor;
        const char *args[] = {
            prog,
            "-c",
            NULL
        };

        cmd = virCommandNewArgs(args);
        virCommandSetInputFD(cmd, pipeFD[0]);
        virCommandSetOutputFD(cmd, &fd);
        virCommandSetErrorBuffer(cmd, &errbuf);
        virCommandDoAsyncIO(cmd);
        if (virSetCloseExec(pipeFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to set cloexec flag"));
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
        if (virCommandRunAsync(cmd, NULL) < 0) {
            ignore_value(qemuDomainObjExitMonitor(driver, vm));
            goto cleanup;
        }
        rc = qemuMonitorMigrateToFd(priv->mon,
                                    QEMU_MONITOR_MIGRATE_BACKGROUND,
                                    pipeFD[1]);
        if (VIR_CLOSE(pipeFD[0]) < 0 ||
            VIR_CLOSE(pipeFD[1]) < 0)
            VIR_WARN("failed to close intermediate pipe");
    }
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        goto cleanup;
    if (rc < 0)
        goto cleanup;

    rc = qemuMigrationWaitForCompletion(driver, vm, asyncJob, NULL, 0);

    if (rc < 0) {
        if (rc == -2) {
            orig_err = virSaveLastError();
            virCommandAbort(cmd);
            if (virDomainObjIsActive(vm) &&
                qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
                qemuMonitorMigrateCancel(priv->mon);
                ignore_value(qemuDomainObjExitMonitor(driver, vm));
            }
        }
        goto cleanup;
    }

    if (cmd && virCommandWait(cmd, NULL) < 0)
        goto cleanup;

    qemuDomainEventEmitJobCompleted(driver, vm);
    ret = 0;

 cleanup:
    if (ret < 0 && !orig_err)
        orig_err = virSaveLastError();

    /* Restore max migration bandwidth */
    if (virDomainObjIsActive(vm) &&
        qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) == 0) {
        qemuMonitorSetMigrationSpeed(priv->mon, saveMigBandwidth);
        priv->migMaxBandwidth = saveMigBandwidth;
        ignore_value(qemuDomainObjExitMonitor(driver, vm));
    }

    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    if (cmd) {
        VIR_DEBUG("Compression binary stderr: %s", NULLSTR(errbuf));
        VIR_FREE(errbuf);
        virCommandFree(cmd);
    }

    if (orig_err) {
        virSetError(orig_err);
        virFreeError(orig_err);
    }

    return ret;
}


int
qemuMigrationCancel(virQEMUDriverPtr driver,
                    virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virHashTablePtr blockJobs = NULL;
    bool storage = false;
    size_t i;
    int ret = -1;

    VIR_DEBUG("Canceling unfinished outgoing migration of domain %s",
              vm->def->name);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        if (QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating) {
            qemuBlockJobSyncBegin(disk);
            storage = true;
        }
    }

    qemuDomainObjEnterMonitor(driver, vm);

    ignore_value(qemuMonitorMigrateCancel(priv->mon));
    if (storage)
        blockJobs = qemuMonitorGetAllBlockJobInfo(priv->mon);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || (storage && !blockJobs))
        goto endsyncjob;

    if (!storage) {
        ret = 0;
        goto cleanup;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDefPtr disk = vm->def->disks[i];
        qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrating)
            continue;

        if (virHashLookup(blockJobs, disk->info.alias)) {
            VIR_DEBUG("Drive mirror on disk %s is still running", disk->dst);
        } else {
            VIR_DEBUG("Drive mirror on disk %s is gone", disk->dst);
            qemuBlockJobSyncEnd(driver, vm, QEMU_ASYNC_JOB_NONE, disk);
            diskPriv->migrating = false;
        }
    }

    if (qemuMigrationCancelDriveMirror(driver, vm, false,
                                       QEMU_ASYNC_JOB_NONE, NULL) < 0)
        goto endsyncjob;

    ret = 0;

 cleanup:
    virHashFree(blockJobs);
    return ret;

 endsyncjob:
    if (storage) {
        for (i = 0; i < vm->def->ndisks; i++) {
            virDomainDiskDefPtr disk = vm->def->disks[i];
            qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

            if (diskPriv->migrating) {
                qemuBlockJobSyncEnd(driver, vm, QEMU_ASYNC_JOB_NONE, disk);
                diskPriv->migrating = false;
            }
        }
    }
    goto cleanup;
}


int
qemuMigrationJobStart(virQEMUDriverPtr driver,
                      virDomainObjPtr vm,
                      qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    virDomainJobOperation op;
    unsigned long long mask;

    if (job == QEMU_ASYNC_JOB_MIGRATION_IN) {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN;
        mask = QEMU_JOB_NONE;
    } else {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT;
        mask = QEMU_JOB_DEFAULT_MASK |
               JOB_MASK(QEMU_JOB_SUSPEND) |
               JOB_MASK(QEMU_JOB_MIGRATION_OP);
    }

    if (qemuDomainObjBeginAsyncJob(driver, vm, job, op) < 0)
        return -1;

    qemuDomainObjSetAsyncJobMask(vm, mask);
    priv->job.current->type = VIR_DOMAIN_JOB_UNBOUNDED;

    return 0;
}

void
qemuMigrationJobSetPhase(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuMigrationJobPhase phase)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (phase < priv->job.phase) {
        VIR_ERROR(_("migration protocol going backwards %s => %s"),
                  qemuMigrationJobPhaseTypeToString(priv->job.phase),
                  qemuMigrationJobPhaseTypeToString(phase));
        return;
    }

    qemuDomainObjSetJobPhase(driver, vm, phase);
}

void
qemuMigrationJobStartPhase(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           qemuMigrationJobPhase phase)
{
    qemuMigrationJobSetPhase(driver, vm, phase);
}

void
qemuMigrationJobContinue(virDomainObjPtr vm)
{
    qemuDomainObjReleaseAsyncJob(vm);
}

bool
qemuMigrationJobIsActive(virDomainObjPtr vm,
                         qemuDomainAsyncJob job)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (priv->job.asyncJob != job) {
        const char *msg;

        if (job == QEMU_ASYNC_JOB_MIGRATION_IN)
            msg = _("domain '%s' is not processing incoming migration");
        else
            msg = _("domain '%s' is not being migrated");

        virReportError(VIR_ERR_OPERATION_INVALID, msg, vm->def->name);
        return false;
    }
    return true;
}

void
qemuMigrationJobFinish(virQEMUDriverPtr driver, virDomainObjPtr vm)
{
    qemuDomainObjEndAsyncJob(driver, vm);
}


static void
qemuMigrationErrorFree(void *data,
                       const void *name ATTRIBUTE_UNUSED)
{
    virErrorPtr err = data;
    virFreeError(err);
}

int
qemuMigrationErrorInit(virQEMUDriverPtr driver)
{
    driver->migrationErrors = virHashAtomicNew(64, qemuMigrationErrorFree);
    if (driver->migrationErrors)
        return 0;
    else
        return -1;
}

/**
 * This function consumes @err; the caller should consider the @err pointer
 * invalid after calling this function.
 */
void
qemuMigrationErrorSave(virQEMUDriverPtr driver,
                       const char *name,
                       virErrorPtr err)
{
    if (!err)
        return;

    VIR_DEBUG("Saving incoming migration error for domain %s: %s",
              name, err->message);
    if (virHashAtomicUpdate(driver->migrationErrors, name, err) < 0) {
        VIR_WARN("Failed to save migration error for domain '%s'", name);
        virFreeError(err);
    }
}

void
qemuMigrationErrorReport(virQEMUDriverPtr driver,
                         const char *name)
{
    virErrorPtr err;

    if (!(err = virHashAtomicSteal(driver->migrationErrors, name)))
        return;

    VIR_DEBUG("Restoring saved incoming migration error for domain %s: %s",
              name, err->message);
    virSetError(err);
    virFreeError(err);
}


/* don't ever pass NULL params with non zero nparams */
qemuMigrationCompressionPtr
qemuMigrationCompressionParse(virTypedParameterPtr params,
                              int nparams,
                              unsigned long flags)
{
    size_t i;
    qemuMigrationCompressionPtr compression = NULL;

    if (VIR_ALLOC(compression) < 0)
        return NULL;

    for (i = 0; i < nparams; i++) {
        int method;

        if (STRNEQ(params[i].field, VIR_MIGRATE_PARAM_COMPRESSION))
            continue;

        method = qemuMigrationCompressMethodTypeFromString(params[i].value.s);
        if (method < 0) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported compression method '%s'"),
                           params[i].value.s);
            goto error;
        }

        if (compression->methods & (1ULL << method)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Compression method '%s' is specified twice"),
                           params[i].value.s);
            goto error;
        }

        compression->methods |= 1ULL << method;
    }

#define GET_PARAM(PARAM, TYPE, VALUE)                                       \
    do {                                                                    \
        int rc;                                                             \
        const char *par = VIR_MIGRATE_PARAM_COMPRESSION_ ## PARAM;          \
                                                                            \
        if ((rc = virTypedParamsGet ## TYPE(params, nparams,                \
                                            par, &compression->VALUE)) < 0) \
            goto error;                                                     \
                                                                            \
        if (rc == 1)                                                        \
            compression->VALUE ## _set = true;                              \
    } while (0)

    if (params) {
        GET_PARAM(MT_LEVEL, Int, level);
        GET_PARAM(MT_THREADS, Int, threads);
        GET_PARAM(MT_DTHREADS, Int, dthreads);
        GET_PARAM(XBZRLE_CACHE, ULLong, xbzrle_cache);
    }

#undef GET_PARAM

    if ((compression->level_set ||
         compression->threads_set ||
         compression->dthreads_set) &&
        !(compression->methods & (1ULL << QEMU_MIGRATION_COMPRESS_MT))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn multithread compression on to tune it"));
        goto error;
    }

    if (compression->xbzrle_cache_set &&
        !(compression->methods & (1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE))) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Turn xbzrle compression on to tune it"));
        goto error;
    }

    if (!compression->methods && (flags & VIR_MIGRATE_COMPRESSED))
        compression->methods = 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE;

    return compression;

 error:
    VIR_FREE(compression);
    return NULL;
}

int
qemuMigrationCompressionDump(qemuMigrationCompressionPtr compression,
                             virTypedParameterPtr *params,
                             int *nparams,
                             int *maxparams,
                             unsigned long *flags)
{
    size_t i;

    if (compression->methods == 1ULL << QEMU_MIGRATION_COMPRESS_XBZRLE &&
        !compression->xbzrle_cache_set) {
        *flags |= VIR_MIGRATE_COMPRESSED;
        return 0;
    }

    for (i = 0; i < QEMU_MIGRATION_COMPRESS_LAST; ++i) {
        if ((compression->methods & (1ULL << i)) &&
            virTypedParamsAddString(params, nparams, maxparams,
                                    VIR_MIGRATE_PARAM_COMPRESSION,
                                    qemuMigrationCompressMethodTypeToString(i)) < 0)
            return -1;
    }

    if (compression->level_set &&
        virTypedParamsAddInt(params, nparams, maxparams,
                             VIR_MIGRATE_PARAM_COMPRESSION_MT_LEVEL,
                             compression->level) < 0)
        return -1;

    if (compression->threads_set &&
        virTypedParamsAddInt(params, nparams, maxparams,
                             VIR_MIGRATE_PARAM_COMPRESSION_MT_THREADS,
                             compression->threads) < 0)
        return -1;

    if (compression->dthreads_set &&
        virTypedParamsAddInt(params, nparams, maxparams,
                             VIR_MIGRATE_PARAM_COMPRESSION_MT_DTHREADS,
                             compression->dthreads) < 0)
        return -1;

    if (compression->xbzrle_cache_set &&
        virTypedParamsAddULLong(params, nparams, maxparams,
                                VIR_MIGRATE_PARAM_COMPRESSION_XBZRLE_CACHE,
                                compression->xbzrle_cache) < 0)
        return -1;

    return 0;
}


/*
 * qemuMigrationReset:
 *
 * Reset all migration parameters so that the next job which internally uses
 * migration (save, managedsave, snapshots, dump) will not try to use them.
 */
void
qemuMigrationReset(virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   qemuDomainAsyncJob job)
{
    qemuMonitorMigrationCaps cap;
    virErrorPtr err = virSaveLastError();

    if (!virDomainObjIsActive(vm))
        goto cleanup;

    if (qemuMigrationResetTLS(driver, vm, job) < 0)
        goto cleanup;

    for (cap = 0; cap < QEMU_MONITOR_MIGRATION_CAPS_LAST; cap++) {
        /* "events" capability is set (when supported) in qemuConnectMonitor
         * and should never be cleared */
        if (cap == QEMU_MONITOR_MIGRATION_CAPS_EVENTS)
            continue;

        if (qemuMigrationSetOption(driver, vm, cap, false, job) < 0)
            goto cleanup;
    }

 cleanup:
    if (err) {
        virSetError(err);
        virFreeError(err);
    }
}
