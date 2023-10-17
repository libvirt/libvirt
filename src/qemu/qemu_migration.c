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

#include <sys/time.h>
#include <fcntl.h>
#include <poll.h>

#include "qemu_migration.h"
#include "qemu_migration_cookie.h"
#include "qemu_migration_params.h"
#include "qemu_monitor.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "qemu_capabilities.h"
#include "qemu_alias.h"
#include "qemu_hotplug.h"
#include "qemu_blockjob.h"
#include "qemu_security.h"
#include "qemu_slirp.h"
#include "qemu_block.h"
#include "qemu_tpm.h"

#include "domain_audit.h"
#include "virlog.h"
#include "virerror.h"
#include "viralloc.h"
#include "virfile.h"
#include "virnetdevopenvswitch.h"
#include "datatypes.h"
#include "virfdstream.h"
#include "virtime.h"
#include "rpc/virnetsocket.h"
#include "storage_source_conf.h"
#include "viruri.h"
#include "virhook.h"
#include "virstring.h"
#include "virtypedparam.h"
#include "virprocess.h"
#include "virdomainsnapshotobjlist.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_migration");

VIR_ENUM_IMPL(qemuMigrationJobPhase,
              QEMU_MIGRATION_PHASE_LAST,
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
              "postcopy_failed",
              "begin_resume",
              "perform_resume",
              "confirm_resume",
              "prepare_resume",
              "finish_resume",
);


static bool ATTRIBUTE_NONNULL(1)
qemuMigrationJobIsAllowed(virDomainObj *vm)
{
    if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_IN ||
        vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("another migration job is already running for domain '%1$s'"),
                       vm->def->name);
        return false;
    }

    return true;
}


static int ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT
qemuMigrationJobStart(virDomainObj *vm,
                      virDomainAsyncJob job,
                      unsigned int apiFlags)
{
    virDomainJobOperation op;
    unsigned long long mask;

    if (!qemuMigrationJobIsAllowed(vm))
        return -1;

    if (job == VIR_ASYNC_JOB_MIGRATION_IN) {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_IN;
        mask = VIR_JOB_NONE;
    } else {
        op = VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT;
        mask = VIR_JOB_DEFAULT_MASK |
               JOB_MASK(VIR_JOB_SUSPEND) |
               JOB_MASK(VIR_JOB_MIGRATION_OP);
    }
    mask |= JOB_MASK(VIR_JOB_MODIFY_MIGRATION_SAFE);

    if (virDomainObjBeginAsyncJob(vm, job, op, apiFlags) < 0)
        return -1;

    qemuDomainJobSetStatsType(vm->job->current,
                              QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION);

    qemuDomainObjSetAsyncJobMask(vm, mask);
    return 0;
}


static int
qemuMigrationCheckPhase(virDomainObj *vm,
                        qemuMigrationJobPhase phase)
{
    if (phase < QEMU_MIGRATION_PHASE_POSTCOPY_FAILED &&
        phase < vm->job->phase) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("migration protocol going backwards %1$s => %2$s"),
                       qemuMigrationJobPhaseTypeToString(vm->job->phase),
                       qemuMigrationJobPhaseTypeToString(phase));
        return -1;
    }

    return 0;
}


static int G_GNUC_WARN_UNUSED_RESULT
qemuMigrationJobSetPhase(virDomainObj *vm,
                         qemuMigrationJobPhase phase)
{
    if (qemuMigrationCheckPhase(vm, phase) < 0)
        return -1;

    qemuDomainObjSetJobPhase(vm, phase);
    return 0;
}


static int G_GNUC_WARN_UNUSED_RESULT
qemuMigrationJobStartPhase(virDomainObj *vm,
                           qemuMigrationJobPhase phase)
{
    if (qemuMigrationCheckPhase(vm, phase) < 0)
        return -1;

    qemuDomainObjStartJobPhase(vm, phase);
    return 0;
}


static void ATTRIBUTE_NONNULL(1)
qemuMigrationJobContinue(virDomainObj *vm,
                         qemuDomainCleanupCallback cleanup)
{
    qemuDomainCleanupAdd(vm, cleanup);
    qemuDomainObjReleaseAsyncJob(vm);
}


static bool ATTRIBUTE_NONNULL(1)
qemuMigrationJobIsActive(virDomainObj *vm,
                         virDomainAsyncJob job)
{
    if (vm->job->asyncJob != job) {
        const char *msg;

        if (job == VIR_ASYNC_JOB_MIGRATION_IN)
            msg = _("domain '%1$s' is not processing incoming migration");
        else
            msg = _("domain '%1$s' is not being migrated");

        virReportError(VIR_ERR_OPERATION_INVALID, msg, vm->def->name);
        return false;
    }
    return true;
}


static void ATTRIBUTE_NONNULL(1)
qemuMigrationJobFinish(virDomainObj *vm)
{
    virDomainObjEndAsyncJob(vm);
}


static void
qemuMigrationSrcStoreDomainState(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    priv->preMigrationState = virDomainObjGetState(vm, NULL);

    VIR_DEBUG("Storing pre-migration state=%d domain=%p",
              priv->preMigrationState, vm);
}

/* Returns true if the domain was resumed, false otherwise */
static bool
qemuMigrationSrcRestoreDomainState(virQEMUDriver *driver, virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
        if (qemuProcessStartCPUs(driver, vm,
                                 VIR_DOMAIN_RUNNING_MIGRATION_CANCELED,
                                 VIR_ASYNC_JOB_MIGRATION_OUT) < 0) {
            /* Hm, we already know we are in error here.  We don't want to
             * overwrite the previous error, though, so we just throw something
             * to the logs and hope for the best */
            VIR_ERROR(_("Failed to resume guest %1$s after failure"), vm->def->name);
            if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
                virObjectEvent *event;

                virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                                     VIR_DOMAIN_PAUSED_API_ERROR);
                event = virDomainEventLifecycleNewFromObj(vm,
                                                          VIR_DOMAIN_EVENT_SUSPENDED,
                                                          VIR_DOMAIN_EVENT_SUSPENDED_API_ERROR);
                virObjectEventStateQueue(driver->domainEventState, event);
            }
            goto cleanup;
        }
        ret = true;
    }

 cleanup:
    priv->preMigrationState = VIR_DOMAIN_NOSTATE;
    return ret;
}


static int
qemuMigrationDstPrecreateDisk(virConnectPtr *conn,
                              virDomainDiskDef *disk,
                              unsigned long long capacity)
{
    int ret = -1;
    virStoragePoolPtr pool = NULL;
    virStorageVolPtr vol = NULL;
    char *volName = NULL, *basePath = NULL;
    char *volStr = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *format = NULL;
    const char *compat = NULL;
    unsigned int flags = 0;

    VIR_DEBUG("Precreate disk type=%s", virStorageTypeToString(disk->src->type));

    switch (disk->src->type) {
    case VIR_STORAGE_TYPE_FILE:
        if (!virDomainDiskGetSource(disk)) {
            VIR_DEBUG("Dropping sourceless disk '%s'",
                      disk->dst);
            return 0;
        }

        basePath = g_strdup(disk->src->path);

        if (!(volName = strrchr(basePath, '/'))) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("malformed disk path: %1$s"),
                           disk->src->path);
            goto cleanup;
        }

        *volName = '\0';
        volName++;

        if (!*conn) {
            if (!(*conn = virGetConnectStorage()))
                goto cleanup;
        }

        if (!(pool = virStoragePoolLookupByTargetPath(*conn, basePath)))
            goto cleanup;
        format = virStorageFileFormatTypeToString(disk->src->format);
        if (disk->src->format == VIR_STORAGE_FILE_QCOW2) {
            flags |= VIR_STORAGE_VOL_CREATE_PREALLOC_METADATA;
            /* format qcow2v3 image */
            compat = "1.1";
        }
        break;

    case VIR_STORAGE_TYPE_VOLUME:
        if (!*conn) {
            if (!(*conn = virGetConnectStorage()))
                goto cleanup;
        }

        if (!(pool = virStoragePoolLookupByName(*conn, disk->src->srcpool->pool)))
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
    case VIR_STORAGE_TYPE_NVME:
    case VIR_STORAGE_TYPE_VHOST_USER:
    case VIR_STORAGE_TYPE_VHOST_VDPA:
    case VIR_STORAGE_TYPE_NONE:
    case VIR_STORAGE_TYPE_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot precreate storage for disk type '%1$s'"),
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
    if (compat)
        virBufferAsprintf(&buf, "<compat>%s</compat>\n", compat);
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
qemuMigrationAnyCopyDisk(virDomainDiskDef const *disk,
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


static bool
qemuMigrationHasAnyStorageMigrationDisks(virDomainDef *def,
                                         const char **migrate_disks,
                                         size_t nmigrate_disks)
{
    size_t i;

    for (i = 0; i < def->ndisks; i++) {
        if (qemuMigrationAnyCopyDisk(def->disks[i], nmigrate_disks, migrate_disks))
            return true;
    }

    return false;
}


static int
qemuMigrationDstPrecreateStorage(virDomainObj *vm,
                                 qemuMigrationCookieNBD *nbd,
                                 size_t nmigrate_disks,
                                 const char **migrate_disks,
                                 bool incremental)
{
    int ret = -1;
    size_t i = 0;
    virConnectPtr conn = NULL;

    if (!nbd || !nbd->ndisks)
        return 0;

    for (i = 0; i < nbd->ndisks; i++) {
        virDomainDiskDef *disk;
        const char *diskSrcPath;
        g_autofree char *nvmePath = NULL;

        VIR_DEBUG("Looking up disk target '%s' (capacity=%llu)",
                  nbd->disks[i].target, nbd->disks[i].capacity);

        if (!(disk = virDomainDiskByTarget(vm->def, nbd->disks[i].target))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to find disk by target: %1$s"),
                           nbd->disks[i].target);
            goto cleanup;
        }

        if (disk->src->type == VIR_STORAGE_TYPE_NVME) {
            virPCIDeviceAddressGetSysfsFile(&disk->src->nvme->pciAddr, &nvmePath);
            diskSrcPath = nvmePath;
        } else {
            diskSrcPath = virDomainDiskGetSource(disk);
        }

        /* Skip disks we don't want to migrate and already existing disks. */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks) ||
            (diskSrcPath && virFileExists(diskSrcPath))) {
            continue;
        }

        if (incremental) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("pre-creation of storage targets for incremental storage migration is not supported"));
            goto cleanup;
        }

        VIR_DEBUG("Proceeding with disk source %s", NULLSTR(diskSrcPath));

        if (qemuMigrationDstPrecreateDisk(&conn,
                                          disk, nbd->disks[i].capacity) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnref(conn);
    return ret;
}


/**
 * qemuMigrationDstStartNBDServer:
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
qemuMigrationDstStartNBDServer(virQEMUDriver *driver,
                               virDomainObj *vm,
                               const char *listenAddr,
                               size_t nmigrate_disks,
                               const char **migrate_disks,
                               int nbdPort,
                               const char *nbdURI,
                               const char *tls_alias)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    size_t i;
    virStorageNetHostDef server = {
        .name = (char *)listenAddr, /* cast away const */
        .transport = VIR_STORAGE_NET_HOST_TRANS_TCP,
        .port = nbdPort,
    };
    bool server_started = false;
    g_autoptr(virURI) uri = NULL;

    /* Prefer nbdURI */
    if (nbdURI) {
        uri = virURIParse(nbdURI);

        if (!uri)
            return -1;

        if (!uri->scheme) {
            virReportError(VIR_ERR_INVALID_ARG, _("No URI scheme specified: %1$s"), nbdURI);
            return -1;
        }

        if (STREQ(uri->scheme, "tcp")) {
            server.transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            if (!uri->server || STREQ(uri->server, "")) {
                /* Since tcp://:<port>/ is parsed as server = NULL and port = 0
                 * we should rather error out instead of auto-allocating a port
                 * as that would be the exact opposite of what was requested. */
                virReportError(VIR_ERR_INVALID_ARG,
                               _("URI with tcp scheme did not provide a server part: %1$s"),
                               nbdURI);
                return -1;
            }
            server.name = (char *)uri->server;
            if (uri->port)
                server.port = uri->port;
        } else if (STREQ(uri->scheme, "unix")) {
            if (!uri->path) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("UNIX disks URI does not include path"));
                return -1;
            }
            server.transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
            server.socket = (char *)uri->path;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported scheme in disks URI: %1$s"),
                           uri->scheme);
            return -1;
        }
    } else if (nbdPort < 0 || nbdPort > USHRT_MAX) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("nbd port must be in range 0-65535"));
        return -1;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        g_autofree char *diskAlias = NULL;

        /* check whether disk should be migrated */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (disk->src->readonly || virStorageSourceIsEmpty(disk->src)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                           _("Cannot migrate empty or read-only disk %1$s"),
                           disk->dst);
            goto cleanup;
        }

        if (!(diskAlias = qemuAliasDiskDriveFromDisk(disk)))
            goto cleanup;

        if (!server_started &&
            server.transport == VIR_STORAGE_NET_HOST_TRANS_TCP) {
            if (server.port) {
                if (virPortAllocatorSetUsed(server.port) < 0)
                    goto cleanup;
            } else {
                unsigned short port = 0;

                if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                    goto cleanup;

                server.port = port;
            }
        }

        if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_IN) < 0)
            goto cleanup;

        if (!server_started) {
            if (qemuMonitorNBDServerStart(priv->mon, &server, tls_alias) < 0)
                goto exit_monitor;
            server_started = true;
        }

        if (qemuBlockExportAddNBD(vm, disk->src, diskAlias, true, NULL) < 0)
            goto exit_monitor;
        qemuDomainObjExitMonitor(vm);
    }

    if (server.transport == VIR_STORAGE_NET_HOST_TRANS_TCP)
        priv->nbdPort = server.port;

    ret = 0;

 cleanup:
    if (ret < 0)
        virPortAllocatorRelease(server.port);
    return ret;

 exit_monitor:
    qemuDomainObjExitMonitor(vm);
    goto cleanup;
}


static int
qemuMigrationDstStopNBDServer(virDomainObj *vm,
                              qemuMigrationCookie *mig)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (!mig->nbd)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_IN) < 0)
        return -1;

    if (qemuMonitorNBDServerStop(priv->mon) < 0)
        VIR_WARN("Unable to stop NBD server");
    qemuDomainObjExitMonitor(vm);

    virPortAllocatorRelease(priv->nbdPort);
    priv->nbdPort = 0;
    return 0;
}


static void
qemuMigrationNBDReportMirrorError(qemuBlockJobData *job,
                                  const char *diskdst)
{
    if (job->errmsg) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("migration of disk %1$s failed: %2$s"),
                       diskdst, job->errmsg);
    } else {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("migration of disk %1$s failed"), diskdst);
    }
}


/**
 * qemuMigrationSrcNBDStorageCopyReady:
 * @vm: domain
 *
 * Check the status of all drives copied via qemuMigrationSrcNBDStorageCopy.
 * Any pending block job events for the mirrored disks will be processed.
 *
 * Returns 1 if all mirrors are "ready",
 *         0 if some mirrors are still performing initial sync,
 *        -1 on error.
 */
static int
qemuMigrationSrcNBDStorageCopyReady(virDomainObj *vm,
                                    virDomainAsyncJob asyncJob)
{
    size_t i;
    size_t notReady = 0;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        qemuBlockJobData *job;

        if (!diskPriv->migrating)
            continue;

        if (!(job = qemuBlockJobDiskGetJob(disk))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("missing block job data for disk '%1$s'"), disk->dst);
            return -1;
        }

        qemuBlockJobUpdate(vm, job, asyncJob);
        if (job->state == VIR_DOMAIN_BLOCK_JOB_FAILED) {
            qemuMigrationNBDReportMirrorError(job, disk->dst);
            virObjectUnref(job);
            return -1;
        }

        if (job->state != VIR_DOMAIN_BLOCK_JOB_READY)
            notReady++;

        virObjectUnref(job);
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
 * If @abortMigration is false, the function will report an error and return a
 * different code in case a block job fails. This way we can properly abort
 * migration in case some block jobs failed once all memory has already been
 * transferred.
 *
 * Returns 1 if all mirrors are gone,
 *         0 if some mirrors are still active,
 *         -1 some mirrors failed but some are still active,
 *         -2 all mirrors are gone but some of them failed.
 */
static int
qemuMigrationSrcNBDCopyCancelled(virDomainObj *vm,
                                 virDomainAsyncJob asyncJob,
                                 bool abortMigration)
{
    size_t i;
    size_t active = 0;
    size_t completed = 0;
    bool failed = false;

    do {
        active = 0;
        completed = 0;

        for (i = 0; i < vm->def->ndisks; i++) {
            virDomainDiskDef *disk = vm->def->disks[i];
            qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
            qemuBlockJobData *job;

            if (!diskPriv->migrating)
                continue;

            if (!(job = qemuBlockJobDiskGetJob(disk)))
                continue;

            qemuBlockJobUpdate(vm, job, asyncJob);
            switch (job->state) {
            case VIR_DOMAIN_BLOCK_JOB_FAILED:
                if (!abortMigration) {
                    qemuMigrationNBDReportMirrorError(job, disk->dst);
                    failed = true;
                }
                G_GNUC_FALLTHROUGH;
            case VIR_DOMAIN_BLOCK_JOB_CANCELED:
            case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
                diskPriv->migrating = false;
                break;

            default:
                active++;
            }

            if (job->state == VIR_DOMAIN_BLOCK_JOB_COMPLETED)
                completed++;

            virObjectUnref(job);
        }

        /* Updating completed block job drops the lock thus we have to recheck
         * block jobs for disks that reside before the disk(s) with completed
         * block job.
         */
    } while (completed > 0);

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
qemuMigrationSrcNBDCopyCancelOne(virDomainObj *vm,
                                 virDomainDiskDef *disk,
                                 qemuBlockJobData *job,
                                 bool abortMigration,
                                 virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rv;

    qemuBlockJobUpdate(vm, job, asyncJob);
    switch (job->state) {
    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        if (!abortMigration) {
            qemuMigrationNBDReportMirrorError(job, disk->dst);
            return -1;
        }
        G_GNUC_FALLTHROUGH;
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        return 1;
    }

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    /* when we are aborting the migration we don't care about the data
     * consistency on the destination so that we can force cancel the mirror */
    rv = qemuMonitorBlockJobCancel(priv->mon, job->name, abortMigration);

    qemuDomainObjExitMonitor(vm);
    if (rv < 0)
        return -1;

    return 0;
}


/**
 * qemuMigrationSrcNBDCopyCancel:
 * @driver: qemu driver
 * @vm: domain
 * @abortMigration: The migration is being cancelled.
 *
 * Cancel all drive-mirrors started by qemuMigrationSrcNBDStorageCopy.
 * Any pending block job events for the affected disks will be processed and
 * synchronous block job terminated regardless of return value unless qemu
 * has crashed.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
qemuMigrationSrcNBDCopyCancel(virDomainObj *vm,
                              bool abortMigration,
                              virDomainAsyncJob asyncJob,
                              virConnectPtr dconn)
{
    virErrorPtr err = NULL;
    int ret = -1;
    size_t i;
    int rv;
    bool failed = false;

    VIR_DEBUG("Cancelling drive mirrors for domain %s", vm->def->name);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        qemuBlockJobData *job;

        if (!(job = qemuBlockJobDiskGetJob(disk)) ||
            !qemuBlockJobIsRunning(job))
            diskPriv->migrating = false;

        if (!diskPriv->migrating) {
            virObjectUnref(job);
            continue;
        }

        rv = qemuMigrationSrcNBDCopyCancelOne(vm, disk, job,
                                              abortMigration, asyncJob);
        if (rv != 0) {
            if (rv < 0) {
                if (!err)
                    virErrorPreserveLast(&err);
                failed = true;
            }
            qemuBlockJobSyncEnd(vm, job, asyncJob);
            diskPriv->migrating = false;
        }

        virObjectUnref(job);
    }

    while ((rv = qemuMigrationSrcNBDCopyCancelled(vm, asyncJob, abortMigration)) != 1) {
        if (!abortMigration && !failed &&
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
            virErrorPreserveLast(&err);

        if (qemuDomainObjWait(vm) < 0)
            goto cleanup;
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

        if (!diskPriv->migrSource)
            continue;

        qemuBlockStorageSourceDetachOneBlockdev(vm, asyncJob,
                                                diskPriv->migrSource);
        g_clear_pointer(&diskPriv->migrSource, virObjectUnref);
    }

    ret = failed ? -1 : 0;

 cleanup:
    virErrorRestore(&err);
    return ret;
}


static int
qemuMigrationSrcCancelRemoveTempBitmaps(virDomainObj *vm,
                                        virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    GSList *next;

    for (next = jobPriv->migTempBitmaps; next; next = next->next) {
        qemuDomainJobPrivateMigrateTempBitmap *t = next->data;

        if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
            return -1;
        qemuMonitorBitmapRemove(priv->mon, t->nodename, t->bitmapname);
        qemuDomainObjExitMonitor(vm);
    }

    return 0;
}


static virStorageSource *
qemuMigrationSrcNBDStorageCopyBlockdevPrepareSource(virDomainDiskDef *disk,
                                                    const char *host,
                                                    int port,
                                                    const char *socket,
                                                    const char *tlsAlias,
                                                    const char *tlsHostname)
{
    g_autoptr(virStorageSource) copysrc = NULL;

    copysrc = virStorageSourceNew();
    copysrc->type = VIR_STORAGE_TYPE_NETWORK;
    copysrc->protocol = VIR_STORAGE_NET_PROTOCOL_NBD;
    copysrc->format = VIR_STORAGE_FILE_RAW;

    copysrc->backingStore = virStorageSourceNew();

    if (!(copysrc->path = qemuAliasDiskDriveFromDisk(disk)))
        return NULL;

    copysrc->hosts = g_new0(virStorageNetHostDef, 1);

    copysrc->nhosts = 1;
    if (socket) {
        copysrc->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_UNIX;
        copysrc->hosts->socket = g_strdup(socket);
    } else {
        copysrc->hosts->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
        copysrc->hosts->port = port;
        copysrc->hosts->name = g_strdup(host);
    }

    copysrc->tlsAlias = g_strdup(tlsAlias);
    copysrc->tlsHostname = g_strdup(tlsHostname);

    qemuBlockStorageSourceSetStorageNodename(copysrc, g_strdup_printf("migration-%s-storage", disk->dst));
    qemuBlockStorageSourceSetFormatNodename(copysrc, g_strdup_printf("migration-%s-format", disk->dst));

    return g_steal_pointer(&copysrc);
}


static int
qemuMigrationSrcNBDStorageCopyBlockdev(virDomainObj *vm,
                                       virDomainDiskDef *disk,
                                       const char *host,
                                       int port,
                                       const char *socket,
                                       unsigned long long mirror_speed,
                                       unsigned int mirror_shallow,
                                       const char *tlsAlias,
                                       const char *tlsHostname,
                                       bool syncWrites)
{
    g_autoptr(qemuBlockStorageSourceAttachData) data = NULL;
    qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    int mon_ret = 0;
    g_autoptr(virStorageSource) copysrc = NULL;
    g_autofree char *diskAlias = qemuAliasDiskDriveFromDisk(disk);

    if (!diskAlias)
        return -1;

    VIR_DEBUG("starting blockdev mirror for disk=%s to host=%s", disk->dst, host);

    if (!(copysrc = qemuMigrationSrcNBDStorageCopyBlockdevPrepareSource(disk, host, port, socket,
                                                                        tlsAlias, tlsHostname)))
        return -1;

    if (!(data = qemuBlockStorageSourceAttachPrepareBlockdev(copysrc,
                                                             copysrc->backingStore)))
        return -1;

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
        return -1;

    mon_ret = qemuBlockStorageSourceAttachApply(qemuDomainGetMonitor(vm), data);

    if (mon_ret == 0)
        mon_ret = qemuMonitorBlockdevMirror(qemuDomainGetMonitor(vm), diskAlias, true,
                                            qemuDomainDiskGetTopNodename(disk),
                                            qemuBlockStorageSourceGetEffectiveNodename(copysrc),
                                            mirror_speed, 0, 0, mirror_shallow,
                                            syncWrites);

    if (mon_ret != 0)
        qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm), data);

    qemuDomainObjExitMonitor(vm);
    if (mon_ret < 0)
        return -1;

    diskPriv->migrSource = g_steal_pointer(&copysrc);

    return 0;
}


static int
qemuMigrationSrcNBDStorageCopyOne(virDomainObj *vm,
                                  virDomainDiskDef *disk,
                                  const char *host,
                                  int port,
                                  const char *socket,
                                  unsigned long long mirror_speed,
                                  bool mirror_shallow,
                                  const char *tlsAlias,
                                  const char *tlsHostname,
                                  unsigned int flags)
{
    qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    qemuBlockJobData *job = NULL;
    g_autofree char *diskAlias = NULL;
    bool syncWrites = !!(flags & VIR_MIGRATE_NON_SHARED_SYNCHRONOUS_WRITES);
    int rc;
    int ret = -1;

    if (!(diskAlias = qemuAliasDiskDriveFromDisk(disk)))
        return -1;

    if (!(job = qemuBlockJobDiskNew(vm, disk, QEMU_BLOCKJOB_TYPE_COPY, diskAlias)))
        return -1;

    qemuBlockJobSyncBegin(job);

    rc = qemuMigrationSrcNBDStorageCopyBlockdev(vm,
                                                disk,
                                                host, port, socket,
                                                mirror_speed,
                                                mirror_shallow,
                                                tlsAlias,
                                                tlsHostname,
                                                syncWrites);

    if (rc == 0) {
        diskPriv->migrating = true;
        qemuBlockJobStarted(job, vm);
        ret = 0;
    }

    qemuBlockJobStartupFinalize(vm, job);
    return ret;
}


/**
 * qemuMigrationSrcNBDStorageCopy:
 * @driver: qemu driver
 * @vm: domain
 * @mig: migration cookie
 * @host: where are we migrating to
 * @speed: bandwidth limit in MiB/s
 *
 * Migrate non-shared storage using the NBD protocol to the server running
 * inside the qemu process on dst and wait until the copy converges.
 * On failure, the caller is expected to call qemuMigrationSrcNBDCopyCancel
 * to stop all running copy operations.
 *
 * Returns 0 on success (@migrate_flags updated),
 *        -1 otherwise.
 */
static int
qemuMigrationSrcNBDStorageCopy(virQEMUDriver *driver,
                               virDomainObj *vm,
                               qemuMigrationCookie *mig,
                               const char *host,
                               unsigned long speed,
                               size_t nmigrate_disks,
                               const char **migrate_disks,
                               virConnectPtr dconn,
                               const char *tlsAlias,
                               const char *tlsHostname,
                               const char *nbdURI,
                               unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int port;
    size_t i;
    unsigned long long mirror_speed = speed;
    bool mirror_shallow = flags & VIR_MIGRATE_NON_SHARED_INC;
    int rv;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virURI) uri = NULL;
    const char *socket = NULL;

    VIR_DEBUG("Starting drive mirrors for domain %s", vm->def->name);

    if (mirror_speed > LLONG_MAX >> 20) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth must be less than %1$llu"),
                       LLONG_MAX >> 20);
        return -1;
    }
    mirror_speed <<= 20;

    /* If qemu doesn't support overriding of TLS hostname for NBD connections
     * we won't attempt it */
    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_NBD_TLS_HOSTNAME))
        tlsHostname = NULL;

    /* steal NBD port and thus prevent its propagation back to destination */
    port = mig->nbd->port;
    mig->nbd->port = 0;

    if (nbdURI) {
        uri = virURIParse(nbdURI);
        if (!uri)
            return -1;

        if (STREQ(uri->scheme, "tcp")) {
            if (uri->server && STRNEQ(uri->server, ""))
                host = (char *)uri->server;
            if (uri->port)
                port = uri->port;
        } else if (STREQ(uri->scheme, "unix")) {
            if (flags & VIR_MIGRATE_TLS) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("NBD migration with TLS is not supported over UNIX socket"));
                return -1;
            }

            if (!uri->path) {
                virReportError(VIR_ERR_INVALID_ARG, "%s",
                               _("UNIX disks URI does not include path"));
                return -1;
            }
            socket = uri->path;

            if (qemuSecurityDomainSetPathLabel(driver, vm, socket, false) < 0)
                return -1;
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Unsupported scheme in disks URI: %1$s"),
                           uri->scheme);
            return -1;
        }
    }

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];

        /* check whether disk should be migrated */
        if (!qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        if (qemuMigrationSrcNBDStorageCopyOne(vm, disk, host, port,
                                              socket,
                                              mirror_speed, mirror_shallow,
                                              tlsAlias, tlsHostname, flags) < 0)
            return -1;

        if (virDomainObjSave(vm, driver->xmlopt, cfg->stateDir) < 0) {
            VIR_WARN("Failed to save status on vm %s", vm->def->name);
            return -1;
        }
    }

    while ((rv = qemuMigrationSrcNBDStorageCopyReady(vm, VIR_ASYNC_JOB_MIGRATION_OUT)) != 1) {
        if (rv < 0)
            return -1;

        if (vm->job->abortJob) {
            vm->job->current->status = VIR_DOMAIN_JOB_STATUS_CANCELED;
            virReportError(VIR_ERR_OPERATION_ABORTED, _("%1$s: %2$s"),
                           virDomainAsyncJobTypeToString(vm->job->asyncJob),
                           _("canceled by client"));
            return -1;
        }

        if (dconn && virConnectIsAlive(dconn) <= 0) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Lost connection to destination host"));
            return -1;
        }

        if (qemuDomainObjWait(vm) < 0)
            return -1;
    }

    qemuMigrationSrcFetchMirrorStats(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                     vm->job->current);
    return 0;
}


/**
 * qemuMigrationSrcIsAllowedHostdev:
 * @def: domain definition
 *
 * Checks that @def does not contain any host devices unsupported across
 * migrations. Returns true if the vm is allowed to migrate.
 */
static bool
qemuMigrationSrcIsAllowedHostdev(const virDomainDef *def)
{
    size_t i;

    /* Migration with USB host devices is allowed, all other devices are
     * forbidden. */
    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDef *hostdev = def->hostdevs[i];
        switch (hostdev->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("cannot migrate a domain with <hostdev mode='capabilities'>"));
            return false;

        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            switch (hostdev->source.subsys.type) {
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
                /* USB devices can be "migrated" */
                continue;

            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                               _("cannot migrate a domain with <hostdev mode='subsystem' type='%1$s'>"),
                               virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
                return false;

            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
                /*
                 * if the device has a <teaming type='transient'>
                 * element, then migration *is* allowed because the
                 * device will be auto-unplugged by QEMU during
                 * migration. Generic <hostdev> and <interface
                 * type='hostdev'> have their teaming configuration
                 * stored in different places.
                 */
                if ((hostdev->teaming &&
                     hostdev->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT) ||
                    (hostdev->parentnet && hostdev->parentnet->teaming &&
                     hostdev->parentnet->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT)) {
                    continue;
                }

                /* all other PCI hostdevs can't be migrated */
                if (hostdev->parentnet) {
                    virDomainNetType actualType = virDomainNetGetActualType(hostdev->parentnet);

                    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                                   _("cannot migrate a domain with <interface type='%1$s'>"),
                                   virDomainNetTypeToString(actualType));
                } else {
                    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                                   _("cannot migrate a domain with <hostdev mode='subsystem' type='%1$s'>"),
                                   virDomainHostdevSubsysTypeToString(hostdev->source.subsys.type));
                }
                return false;

            case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("invalid hostdev subsystem type"));
                return false;
            }
            break;

        case VIR_DOMAIN_HOSTDEV_MODE_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("invalid hostdev mode"));
            return false;
        }
    }

    return true;
}


static int
qemuDomainGetMigrationBlockers(virDomainObj *vm,
                               int asyncJob,
                               char ***blockers)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorGetMigrationBlockers(priv->mon, blockers);
    qemuDomainObjExitMonitor(vm);

    return rc;
}


/**
 * qemuMigrationSrcIsAllowed:
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
qemuMigrationSrcIsAllowed(virDomainObj *vm,
                          bool remote,
                          int asyncJob,
                          unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
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
                           _("cannot migrate domain with %1$d snapshots"),
                           nsnapshots);
            return false;
        }
    }

    /* following checks don't make sense for offline migration */
    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        bool blockedReasonsCap = virQEMUCapsGet(priv->qemuCaps,
                                                QEMU_CAPS_MIGRATION_BLOCKED_REASONS);

        /* Ask qemu if it has a migration blocker */
        if (blockedReasonsCap) {
            g_auto(GStrv) blockers = NULL;

            if (qemuDomainGetMigrationBlockers(vm,
                                               asyncJob,
                                               &blockers) < 0) {
                return false;
            }

            if (blockers && blockers[0]) {
                g_autofree char *reasons = g_strjoinv("; ", blockers);
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("cannot migrate domain: %1$s"), reasons);
                return false;
            }
        } else {
            /* checks here are for anything that doesn't need to be
             * checked by libvirt if running QEMU that can be queried
             * about migration blockers.
             */

            if (!qemuMigrationSrcIsAllowedHostdev(vm->def))
                return false;
        }

        if (remote) {
            /* cancel migration if disk I/O error is emitted while migrating */
            if (flags & VIR_MIGRATE_ABORT_ON_ERROR &&
                virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
                pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("cannot migrate domain with I/O error"));
                return false;
            }

            if (virCloseCallbacksDomainIsRegistered(vm, NULL, qemuProcessAutoDestroy)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               "%s", _("domain is marked for auto destroy"));
                return false;
            }
        }


        if (qemuDomainHasBlockjob(vm, false)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("domain has active block job"));
            return false;
        }

        if (vm->def->cpu) {
            /* QEMU blocks migration and save with invariant TSC enabled
             * unless TSC frequency is explicitly set.
             */
            if (virCPUCheckFeature(vm->def->os.arch, vm->def->cpu,
                                   "invtsc") == 1) {
                bool block = true;

                for (i = 0; i < vm->def->clock.ntimers; i++) {
                    virDomainTimerDef *timer = vm->def->clock.timers[i];

                    if (timer->name == VIR_DOMAIN_TIMER_NAME_TSC &&
                        timer->frequency > 0) {
                        block = false;
                        break;
                    }
                }

                if (block) {
                    virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                                   _("domain has 'invtsc' CPU feature but TSC frequency is not specified"));
                    return false;
                }
            }
        }

        /* Verify that memory device config can be transferred reliably */
        for (i = 0; i < vm->def->nmems; i++) {
            virDomainMemoryDef *mem = vm->def->mems[i];

            if (mem->model == VIR_DOMAIN_MEMORY_MODEL_DIMM &&
                mem->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DIMM) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("domain's dimm info lacks slot ID or base address"));

                return false;
            }
        }

        for (i = 0; i < vm->def->nshmems; i++) {
            virDomainShmemDef *shmem = vm->def->shmems[i];

            if (shmem->role != VIR_DOMAIN_SHMEM_ROLE_MASTER) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("shmem device '%1$s' cannot be migrated, only shmem with role='%2$s' can be migrated"),
                               shmem->name,
                               virDomainShmemRoleTypeToString(VIR_DOMAIN_SHMEM_ROLE_MASTER));
                return false;
            }
        }

        for (i = 0; i < vm->def->nnets; i++) {
            virDomainNetDef *net = vm->def->nets[i];
            qemuSlirp *slirp;

            if (!blockedReasonsCap && net->type == VIR_DOMAIN_NET_TYPE_VDPA) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("vDPA devices cannot be migrated"));
                return false;
            }

            slirp = QEMU_DOMAIN_NETWORK_PRIVATE(net)->slirp;

            if (slirp && !qemuSlirpHasFeature(slirp, QEMU_SLIRP_FEATURE_MIGRATE)) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("a slirp-helper cannot be migrated"));
                return false;
            }
        }

        for (i = 0; i < vm->def->nfss; i++) {
            virDomainFSDef *fs = vm->def->fss[i];

            if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                               _("migration with virtiofs device is not supported"));
                return false;
            }
        }

        if (priv->dbusVMStateIds &&
            !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_DBUS_VMSTATE)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot migrate this domain without dbus-vmstate support"));
            return false;
        }

        for (i = 0; i < vm->def->ndisks; i++) {
            virDomainDiskDef *disk = vm->def->disks[i];

            if (disk->transient) {
                virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("migration with transient disk is not supported"));
                return false;
            }
        }

        if (qemuTPMHasSharedStorage(vm->def)&&
            !qemuTPMCanMigrateSharedStorage(vm->def)) {
            virReportError(VIR_ERR_NO_SUPPORT, "%s",
                           _("the running swtpm does not support migration with shared storage"));
            return false;
        }
    }

    return true;
}

static bool
qemuMigrationSrcIsSafe(virDomainDef *def,
                       virQEMUCaps *qemuCaps,
                       size_t nmigrate_disks,
                       const char **migrate_disks,
                       unsigned int flags)

{
    bool storagemigration = flags & (VIR_MIGRATE_NON_SHARED_DISK |
                                     VIR_MIGRATE_NON_SHARED_INC);
    size_t i;
    int rc;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        const char *src = virDomainDiskGetSource(disk);
        virStorageType actualType = virStorageSourceGetActualType(disk->src);
        bool unsafe = false;

        /* Disks without any source (i.e. floppies and CD-ROMs)
         * OR readonly are safe. */
        if (virStorageSourceIsEmpty(disk->src) ||
            disk->src->readonly)
            continue;

        /* Disks which are migrated by qemu are safe too. */
        if (storagemigration &&
            qemuMigrationAnyCopyDisk(disk, nmigrate_disks, migrate_disks))
            continue;

        /* However, disks on local FS (e.g. ext4) are not safe. */
        switch (actualType) {
        case VIR_STORAGE_TYPE_FILE:
            if ((rc = virFileIsSharedFS(src)) < 0) {
                return false;
            } else if (rc == 0) {
                unsafe = true;
            }
            if ((rc = virFileIsClusterFS(src)) < 0)
                return false;
            else if (rc == 1)
                continue;
            break;
        case VIR_STORAGE_TYPE_NETWORK:
            /* But network disks are safe again. */
            continue;

        case VIR_STORAGE_TYPE_NVME:
            unsafe = true;
            break;

        case VIR_STORAGE_TYPE_VHOST_USER:
        case VIR_STORAGE_TYPE_VHOST_VDPA:
        case VIR_STORAGE_TYPE_NONE:
        case VIR_STORAGE_TYPE_BLOCK:
        case VIR_STORAGE_TYPE_DIR:
        case VIR_STORAGE_TYPE_VOLUME:
        case VIR_STORAGE_TYPE_LAST:
            break;
        }

        if (unsafe) {
            virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                           _("Migration without shared storage is unsafe"));
            return false;
        }

        /* Our code elsewhere guarantees shared disks are either readonly (in
         * which case cache mode doesn't matter) or used with cache=none or used with cache=directsync */
        if (disk->src->shared ||
            disk->cachemode == VIR_DOMAIN_DISK_CACHE_DISABLE ||
            disk->cachemode == VIR_DOMAIN_DISK_CACHE_DIRECTSYNC)
            continue;

        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_MIGRATION_FILE_DROP_CACHE)) {
            VIR_DEBUG("QEMU supports flushing caches; migration is safe");
            continue;
        }

        virReportError(VIR_ERR_MIGRATE_UNSAFE, "%s",
                       _("Migration may lead to data corruption if disks use cache other than none or directsync"));
        return false;
    }

    return true;
}


void
qemuMigrationSrcPostcopyFailed(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virObjectEvent *event = NULL;
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    VIR_DEBUG("%s/%s, asyncPaused=%u",
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason),
              vm->job->asyncPaused);

    if (state != VIR_DOMAIN_PAUSED ||
        virDomainObjIsFailedPostcopy(vm, vm->job))
        return;

    VIR_WARN("Migration of domain %s failed during post-copy; "
             "leaving the domain paused", vm->def->name);

    vm->job->asyncPaused = true;
    virDomainObjSetState(vm, VIR_DOMAIN_PAUSED,
                         VIR_DOMAIN_PAUSED_POSTCOPY_FAILED);
    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                              VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED);
    virObjectEventStateQueue(driver->domainEventState, event);
}


void
qemuMigrationDstPostcopyFailed(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    virObjectEvent *event = NULL;
    virDomainState state;
    int reason;

    state = virDomainObjGetState(vm, &reason);

    VIR_DEBUG("%s/%s, asyncPaused=%u",
              virDomainStateTypeToString(state),
              virDomainStateReasonToString(state, reason),
              vm->job->asyncPaused);

    if ((state != VIR_DOMAIN_RUNNING && state != VIR_DOMAIN_PAUSED) ||
        virDomainObjIsFailedPostcopy(vm, vm->job))
        return;

    VIR_WARN("Incoming migration of domain '%s' failed during post-copy; "
             "leaving the domain running", vm->def->name);

    vm->job->asyncPaused = true;
    if (state == VIR_DOMAIN_RUNNING) {
        virDomainObjSetState(vm, VIR_DOMAIN_RUNNING,
                             VIR_DOMAIN_RUNNING_POSTCOPY_FAILED);
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_RESUMED,
                                                  VIR_DOMAIN_EVENT_RESUMED_POSTCOPY_FAILED);
    } else {
        /* The domain was paused for other reasons (I/O error, ...) so we don't
         * want to rewrite the original reason and just emit a postcopy-failed
         * event. */
        event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_POSTCOPY_FAILED);
    }
    virObjectEventStateQueue(driver->domainEventState, event);
}


static void
qemuMigrationSrcWaitForSpice(virDomainObj *vm)
{
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;

    if (!jobPriv->spiceMigration)
        return;

    VIR_DEBUG("Waiting for SPICE to finish migration");
    while (!jobPriv->spiceMigrated && !vm->job->abortJob) {
        if (qemuDomainObjWait(vm) < 0)
            return;
    }
}


static void
qemuMigrationUpdateJobType(virDomainJobData *jobData)
{
    qemuDomainJobDataPrivate *priv = jobData->privateData;

    switch ((qemuMonitorMigrationStatus) priv->stats.mig.status) {
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_RECOVER:
        jobData->status = VIR_DOMAIN_JOB_STATUS_POSTCOPY;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_PAUSED:
        jobData->status = VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
        jobData->status = VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
        jobData->status = VIR_DOMAIN_JOB_STATUS_NONE;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
        jobData->status = VIR_DOMAIN_JOB_STATUS_FAILED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
        jobData->status = VIR_DOMAIN_JOB_STATUS_CANCELED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER:
        jobData->status = VIR_DOMAIN_JOB_STATUS_PAUSED;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_DEVICE:
        jobData->status = VIR_DOMAIN_JOB_STATUS_MIGRATING;
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_WAIT_UNPLUG:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        break;
    }
}


int
qemuMigrationAnyFetchStats(virDomainObj *vm,
                           virDomainAsyncJob asyncJob,
                           virDomainJobData *jobData,
                           char **error)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuMonitorMigrationStats stats;
    qemuDomainJobDataPrivate *privJob = jobData->privateData;
    int rv;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rv = qemuMonitorGetMigrationStats(priv->mon, &stats, error);

    qemuDomainObjExitMonitor(vm);
    if (rv < 0)
        return -1;

    privJob->stats.mig = stats;

    return 0;
}


static const char *
qemuMigrationJobName(virDomainObj *vm)
{
    switch (vm->job->asyncJob) {
    case VIR_ASYNC_JOB_MIGRATION_OUT:
        return _("migration out");
    case VIR_ASYNC_JOB_SAVE:
        return _("domain save");
    case VIR_ASYNC_JOB_DUMP:
        return _("domain core dump");
    case VIR_ASYNC_JOB_MIGRATION_IN:
        return _("migration in");
    case VIR_ASYNC_JOB_SNAPSHOT:
        return _("snapshot");
    case VIR_ASYNC_JOB_START:
        return _("start");
    case VIR_ASYNC_JOB_BACKUP:
        return _("backup");
    case VIR_ASYNC_JOB_NONE:
    case VIR_ASYNC_JOB_LAST:
    default:
        return _("undefined");
    }
}


static int
qemuMigrationJobCheckStatus(virDomainObj *vm,
                            virDomainAsyncJob asyncJob)
{
    virDomainJobData *jobData = vm->job->current;
    qemuDomainJobDataPrivate *privJob = jobData->privateData;
    g_autofree char *error = NULL;

    if (privJob->stats.mig.status == QEMU_MONITOR_MIGRATION_STATUS_ERROR) {
        if (qemuMigrationAnyFetchStats(vm, asyncJob, jobData, &error) < 0)
            return -1;
    }

    qemuMigrationUpdateJobType(jobData);

    switch (jobData->status) {
    case VIR_DOMAIN_JOB_STATUS_NONE:
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("job '%1$s' is not active"),
                       qemuMigrationJobName(vm));
        return -1;

    case VIR_DOMAIN_JOB_STATUS_FAILED:
        if (error) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("job '%1$s' failed: %2$s"),
                           qemuMigrationJobName(vm), error);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("job '%1$s' unexpectedly failed"),
                           qemuMigrationJobName(vm));
        }
        return -1;

    case VIR_DOMAIN_JOB_STATUS_CANCELED:
        virReportError(VIR_ERR_OPERATION_ABORTED,
                       _("job '%1$s' canceled by client"),
                       qemuMigrationJobName(vm));
        return -1;

    case VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED:
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("job '%1$s' failed in post-copy phase"),
                       qemuMigrationJobName(vm));
        return -1;

    case VIR_DOMAIN_JOB_STATUS_COMPLETED:
    case VIR_DOMAIN_JOB_STATUS_ACTIVE:
    case VIR_DOMAIN_JOB_STATUS_MIGRATING:
    case VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED:
    case VIR_DOMAIN_JOB_STATUS_POSTCOPY:
    case VIR_DOMAIN_JOB_STATUS_PAUSED:
        break;
    }

    return 0;
}


enum qemuMigrationCompletedFlags {
    QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR = (1 << 0),
    /* This flag should only be set when run on src host */
    QEMU_MIGRATION_COMPLETED_CHECK_STORAGE  = (1 << 1),
    QEMU_MIGRATION_COMPLETED_POSTCOPY       = (1 << 2),
    QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER = (1 << 3),
};


/**
 * Returns 1 if migration completed successfully,
 *         0 if the domain is still being migrated,
 *         -1 migration failed,
 *         -2 something else failed, we need to cancel migration.
 */
static int
qemuMigrationAnyCompleted(virDomainObj *vm,
                          virDomainAsyncJob asyncJob,
                          virConnectPtr dconn,
                          unsigned int flags)
{
    virDomainJobData *jobData = vm->job->current;
    int pauseReason;

    if (qemuMigrationJobCheckStatus(vm, asyncJob) < 0)
        goto error;

    /* This flag should only be set when run on src host */
    if (flags & QEMU_MIGRATION_COMPLETED_CHECK_STORAGE &&
        qemuMigrationSrcNBDStorageCopyReady(vm, asyncJob) < 0)
        goto error;

    if (flags & QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR &&
        virDomainObjGetState(vm, &pauseReason) == VIR_DOMAIN_PAUSED &&
        pauseReason == VIR_DOMAIN_PAUSED_IOERROR) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("job '%1$s' failed due to I/O error"),
                       qemuMigrationJobName(vm));
        goto error;
    }

    if (dconn && virConnectIsAlive(dconn) <= 0) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Lost connection to destination host"));
        goto error;
    }

    /* Migration was paused before serializing device state, let's return to
     * the caller so that it can finish all block jobs, resume migration, and
     * wait again for the real end of the migration.
     */
    if (flags & QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER &&
        jobData->status == VIR_DOMAIN_JOB_STATUS_PAUSED) {
        VIR_DEBUG("Migration paused before switchover");
        return 1;
    }

    /* In case of postcopy the source considers migration completed at the
     * moment it switched from active to postcopy-active state. The destination
     * will continue waiting until the migrate state changes to completed.
     */
    if (flags & QEMU_MIGRATION_COMPLETED_POSTCOPY &&
        jobData->status == VIR_DOMAIN_JOB_STATUS_POSTCOPY) {
        VIR_DEBUG("Migration switched to post-copy");
        return 1;
    }

    if (jobData->status == VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED)
        return 1;
    else
        return 0;

 error:
    switch (jobData->status) {
    case VIR_DOMAIN_JOB_STATUS_MIGRATING:
    case VIR_DOMAIN_JOB_STATUS_POSTCOPY:
    case VIR_DOMAIN_JOB_STATUS_PAUSED:
        /* The migration was aborted by us rather than QEMU itself. */
        jobData->status = VIR_DOMAIN_JOB_STATUS_FAILED;
        return -2;

    case VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED:
        /* Something failed after QEMU already finished the migration. */
        jobData->status = VIR_DOMAIN_JOB_STATUS_FAILED;
        return -1;

    case VIR_DOMAIN_JOB_STATUS_FAILED:
    case VIR_DOMAIN_JOB_STATUS_CANCELED:
    case VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED:
        /* QEMU aborted the migration. */
        return -1;

    case VIR_DOMAIN_JOB_STATUS_ACTIVE:
    case VIR_DOMAIN_JOB_STATUS_COMPLETED:
    case VIR_DOMAIN_JOB_STATUS_NONE:
        /* Impossible. */
        break;
    }

    return -1;
}


/* Returns 0 on success, -2 when migration needs to be cancelled, or -1 when
 * QEMU reports failed migration.
 */
static int
qemuMigrationSrcWaitForCompletion(virDomainObj *vm,
                                  virDomainAsyncJob asyncJob,
                                  virConnectPtr dconn,
                                  unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainJobData *jobData = vm->job->current;
    int rv;

    jobData->status = VIR_DOMAIN_JOB_STATUS_MIGRATING;

    while ((rv = qemuMigrationAnyCompleted(vm, asyncJob, dconn, flags)) != 1) {
        if (rv < 0)
            return rv;

        if (qemuDomainObjWait(vm) < 0) {
            if (virDomainObjIsActive(vm) && !priv->beingDestroyed)
                jobData->status = VIR_DOMAIN_JOB_STATUS_FAILED;
            return -2;
        }
    }

    ignore_value(qemuMigrationAnyFetchStats(vm, asyncJob, jobData, NULL));

    qemuDomainJobDataUpdateTime(jobData);
    qemuDomainJobDataUpdateDowntime(jobData);
    g_clear_pointer(&vm->job->completed, virDomainJobDataFree);
    vm->job->completed = virDomainJobDataCopy(jobData);
    vm->job->completed->status = VIR_DOMAIN_JOB_STATUS_COMPLETED;

    if (asyncJob != VIR_ASYNC_JOB_MIGRATION_OUT &&
        jobData->status == VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED)
        jobData->status = VIR_DOMAIN_JOB_STATUS_COMPLETED;

    return 0;
}


static int
qemuMigrationDstWaitForCompletion(virDomainObj *vm,
                                  virDomainAsyncJob asyncJob,
                                  bool postcopy)
{
    unsigned int flags = 0;
    int rv;

    VIR_DEBUG("Waiting for incoming migration to complete");

    if (postcopy)
        flags = QEMU_MIGRATION_COMPLETED_POSTCOPY;

    while ((rv = qemuMigrationAnyCompleted(vm, asyncJob, NULL, flags)) != 1) {
        if (rv < 0 || qemuDomainObjWait(vm) < 0)
            return -1;
    }

    return 0;
}


static int
qemuMigrationSrcGraphicsRelocate(virDomainObj *vm,
                                 qemuMigrationCookie *cookie,
                                 const char *graphicsuri)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    const char *listenAddress = NULL;
    virSocketAddr addr;
    g_autoptr(virURI) uri = NULL;
    int type = -1;
    int port = -1;
    int tlsPort = -1;
    const char *tlsSubject = NULL;
    int rc = -1;

    if (!cookie || (!cookie->graphics && !graphicsuri))
        return 0;

    if (graphicsuri && !(uri = virURIParse(graphicsuri)))
        return -1;

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
                           _("unknown graphics type %1$s"), uri->scheme);
            return -1;
        }

        if (uri->server)
            listenAddress = uri->server;
        if (uri->port > 0)
            port = uri->port;

        for (i = 0; i < uri->paramsCount; i++) {
            virURIParam *param = uri->params + i;

            if (STRCASEEQ(param->name, "tlsPort")) {
                if (virStrToLong_i(param->value, NULL, 10, &tlsPort) < 0) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("invalid tlsPort number: %1$s"),
                                   param->value);
                    return -1;
                }
            } else if (STRCASEEQ(param->name, "tlsSubject")) {
                tlsSubject = param->value;
            }
        }
    }

    /* QEMU doesn't support VNC relocation yet, so
     * skip it to avoid generating an error
     */
    if (type != VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
        return 0;

    /* Older libvirt sends port == 0 for listen type='none' graphics. It's
     * safe to ignore such requests since relocation to unknown port does
     * not make sense in general.
     */
    if (port <= 0 && tlsPort <= 0)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_OUT) == 0) {
        qemuDomainJobPrivate *jobPriv = vm->job->privateData;

        rc = qemuMonitorGraphicsRelocate(priv->mon, type, listenAddress,
                                         port, tlsPort, tlsSubject);
        jobPriv->spiceMigration = !rc;
        qemuDomainObjExitMonitor(vm);
    }

    return rc;
}


static int
qemuMigrationDstOPDRelocate(virQEMUDriver *driver G_GNUC_UNUSED,
                            virDomainObj *vm,
                            qemuMigrationCookie *cookie)
{
    virDomainNetDef *netptr;
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
                               _("Unable to run command to set OVS port data for interface %1$s"),
                               netptr->ifname);
                return -1;
            }
            break;
        default:
            break;
        }
    }

    return 0;
}


int
qemuMigrationDstCheckProtocol(virQEMUCaps *qemuCaps,
                              const char *migrateFrom)
{
    if (STRPREFIX(migrateFrom, "rdma")) {
        if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("incoming RDMA migration is not supported with this QEMU binary"));
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
qemuMigrationDstGetURI(const char *migrateFrom,
                       int migrateFd)
{
    char *uri = NULL;

    if (STREQ(migrateFrom, "stdio"))
        uri = g_strdup_printf("fd:%d", migrateFd);
    else
        uri = g_strdup(migrateFrom);

    return uri;
}


int
qemuMigrationDstRun(virDomainObj *vm,
                    const char *uri,
                    virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rv;

    VIR_DEBUG("Setting up incoming migration with URI %s", uri);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rv = qemuMonitorSetDBusVMStateIdList(priv->mon, priv->dbusVMStateIds);
    if (rv < 0)
        goto exit_monitor;

    rv = qemuMonitorMigrateIncoming(priv->mon, uri);

 exit_monitor:
    qemuDomainObjExitMonitor(vm);
    if (rv < 0)
        return -1;

    if (asyncJob == VIR_ASYNC_JOB_MIGRATION_IN) {
        /* qemuMigrationDstWaitForCompletion is called from the Finish phase */
        return 0;
    }

    if (qemuMigrationDstWaitForCompletion(vm, asyncJob, false) < 0)
        return -1;

    return 0;
}


/* This is called for outgoing non-p2p and incoming migrations when a
 * connection to the client which controls the migration was closed but we
 * were waiting for it to follow up with the next phase, that is, in between
 * qemuDomainMigrateBegin3 and qemuDomainMigratePerform3,
 * qemuDomainMigratePerform3 and qemuDomainMigrateConfirm3, or
 * qemuDomainMigratePrepare3 and qemuDomainMigrateFinish3.
 */
static void
qemuMigrationAnyConnectionClosed(virDomainObj *vm,
                                 virConnectPtr conn)
{
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    bool postcopy = false;
    int phase;

    VIR_DEBUG("vm=%s, conn=%p, asyncJob=%s, phase=%s",
              vm->def->name, conn,
              virDomainAsyncJobTypeToString(vm->job->asyncJob),
              qemuDomainAsyncJobPhaseToString(vm->job->asyncJob,
                                              vm->job->phase));

    if (!qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_IN) &&
        !qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_OUT))
        return;

    VIR_WARN("The connection which controls migration of domain %s was closed",
              vm->def->name);

    switch ((qemuMigrationJobPhase) vm->job->phase) {
    case QEMU_MIGRATION_PHASE_BEGIN3:
        VIR_DEBUG("Aborting outgoing migration after Begin phase");
        break;

    case QEMU_MIGRATION_PHASE_PERFORM3_DONE:
        if (virDomainObjIsPostcopy(vm, vm->job)) {
            VIR_DEBUG("Migration protocol interrupted in post-copy mode");
            postcopy = true;
        } else {
            VIR_WARN("Migration of domain %s finished but we don't know if the "
                     "domain was successfully started on destination or not",
                     vm->def->name);
        }
        break;

    case QEMU_MIGRATION_PHASE_POSTCOPY_FAILED:
    case QEMU_MIGRATION_PHASE_BEGIN_RESUME:
    case QEMU_MIGRATION_PHASE_PERFORM_RESUME:
    case QEMU_MIGRATION_PHASE_PREPARE_RESUME:
        VIR_DEBUG("Connection closed while resuming failed post-copy migration");
        postcopy = true;
        break;

    case QEMU_MIGRATION_PHASE_PREPARE:
        /* incoming migration; the domain will be autodestroyed */
        return;

    case QEMU_MIGRATION_PHASE_PERFORM3:
        /* cannot be seen without an active migration API; unreachable */
    case QEMU_MIGRATION_PHASE_CONFIRM3:
    case QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED:
    case QEMU_MIGRATION_PHASE_CONFIRM_RESUME:
    case QEMU_MIGRATION_PHASE_FINISH2:
    case QEMU_MIGRATION_PHASE_FINISH3:
    case QEMU_MIGRATION_PHASE_FINISH_RESUME:
        /* all done; unreachable */
    case QEMU_MIGRATION_PHASE_PERFORM2:
        /* single phase outgoing migration; unreachable */
    case QEMU_MIGRATION_PHASE_NONE:
    case QEMU_MIGRATION_PHASE_LAST:
        /* unreachable */
        return;
    }

    if (postcopy)
        phase = QEMU_MIGRATION_PHASE_POSTCOPY_FAILED;
    else
        phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
    ignore_value(qemuMigrationJobStartPhase(vm, phase));

    if (postcopy) {
        if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT)
            qemuMigrationSrcPostcopyFailed(vm);
        else
            qemuMigrationDstPostcopyFailed(vm);
        qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    } else {
        qemuMigrationParamsReset(vm, vm->job->asyncJob,
                                 jobPriv->migParams, vm->job->apiFlags);
        qemuMigrationJobFinish(vm);
    }
}


/**
 * qemuMigrationSrcBeginPhaseBlockDirtyBitmaps:
 * @mig: migration cookie struct
 * @vm: domain object
 * @migrate_disks: disks which are being migrated
 * @nmigrage_disks: number of @migrate_disks
 *
 * Enumerates block dirty bitmaps on disks which will undergo storage migration
 * and fills them into @mig to be offered to the destination.
 */
static int
qemuMigrationSrcBeginPhaseBlockDirtyBitmaps(qemuMigrationCookie *mig,
                                            virDomainObj *vm,
                                            const char **migrate_disks,
                                            size_t nmigrate_disks)

{
    GSList *disks = NULL;
    size_t i;

    g_autoptr(GHashTable) blockNamedNodeData = NULL;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, vm->job->asyncJob)))
        return -1;

    for (i = 0; i < vm->def->ndisks; i++) {
        qemuMigrationBlockDirtyBitmapsDisk *disk;
        GSList *bitmaps = NULL;
        virDomainDiskDef *diskdef = vm->def->disks[i];
        qemuBlockNamedNodeData *nodedata = virHashLookup(blockNamedNodeData,
                                                         qemuBlockStorageSourceGetEffectiveNodename(diskdef->src));
        size_t j;

        if (!nodedata)
            continue;

        if (migrate_disks) {
            bool migrating = false;

            for (j = 0; j < nmigrate_disks; j++) {
                if (STREQ(migrate_disks[j], diskdef->dst)) {
                    migrating = true;
                    break;
                }
            }

            if (!migrating)
                continue;
        }

        for (j = 0; j < nodedata->nbitmaps; j++) {
            qemuMigrationBlockDirtyBitmapsDiskBitmap *bitmap;

            if (!qemuBlockBitmapChainIsValid(diskdef->src,
                                             nodedata->bitmaps[j]->name,
                                             blockNamedNodeData))
                continue;

            bitmap = g_new0(qemuMigrationBlockDirtyBitmapsDiskBitmap, 1);
            bitmap->bitmapname = g_strdup(nodedata->bitmaps[j]->name);
            bitmap->alias = g_strdup_printf("libvirt-%s-%s",
                                            diskdef->dst,
                                            nodedata->bitmaps[j]->name);
            bitmaps = g_slist_prepend(bitmaps, bitmap);
        }

        if (!bitmaps)
            continue;

        disk = g_new0(qemuMigrationBlockDirtyBitmapsDisk, 1);
        disk->target = g_strdup(diskdef->dst);
        disk->bitmaps = bitmaps;
        disks = g_slist_prepend(disks, disk);
    }

    if (!disks)
        return 0;

    mig->blockDirtyBitmaps = disks;
    mig->flags |= QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS;

    return 0;
}


int
qemuMigrationAnyRefreshStatus(virDomainObj *vm,
                              virDomainAsyncJob asyncJob,
                              virDomainJobStatus *status)
{
    g_autoptr(virDomainJobData) jobData = NULL;
    qemuDomainJobDataPrivate *priv;

    jobData = virDomainJobDataInit(&virQEMUDriverDomainJobConfig.jobDataPrivateCb);
    priv = jobData->privateData;

    if (qemuMigrationAnyFetchStats(vm, asyncJob, jobData, NULL) < 0)
        return -1;

    qemuMigrationUpdateJobType(jobData);
    VIR_DEBUG("QEMU reports domain '%s' is in '%s' migration state, translated as %d",
              vm->def->name,
              qemuMonitorMigrationStatusTypeToString(priv->stats.mig.status),
              jobData->status);

    *status = jobData->status;
    return 0;
}


static char *
qemuMigrationSrcBeginXML(virDomainObj *vm,
                         const char *xmlin,
                         char **cookieout,
                         int *cookieoutlen,
                         unsigned int cookieFlags,
                         const char **migrate_disks,
                         size_t nmigrate_disks,
                         unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(qemuMigrationCookie) mig = NULL;

    if (priv->origCPU)
        cookieFlags |= QEMU_MIGRATION_COOKIE_CPU;

    if (!(flags & VIR_MIGRATE_OFFLINE))
        cookieFlags |= QEMU_MIGRATION_COOKIE_CAPS;

    if (!(mig = qemuMigrationCookieNew(vm->def, priv->origname)))
        return NULL;

    if (cookieFlags & QEMU_MIGRATION_COOKIE_NBD &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_PARAM_BLOCK_BITMAP_MAPPING) &&
        qemuMigrationSrcBeginPhaseBlockDirtyBitmaps(mig, vm, migrate_disks,
                                                    nmigrate_disks) < 0)
        return NULL;

    if (qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_SOURCE,
                                  cookieout, cookieoutlen,
                                  cookieFlags) < 0)
        return NULL;

    if (xmlin) {
        g_autoptr(virDomainDef) def = NULL;

        if (!(def = virDomainDefParseString(xmlin, driver->xmlopt, priv->qemuCaps,
                                            VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                            VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
            return NULL;

        if (!qemuDomainCheckABIStability(driver, vm, def))
            return NULL;

        return qemuDomainDefFormatLive(driver, priv->qemuCaps, def, NULL, false, true);
    }

    return qemuDomainDefFormatLive(driver, priv->qemuCaps, vm->def, priv->origCPU,
                                   false, true);
}


/* The caller is supposed to lock the vm and start a migration job. */
static char *
qemuMigrationSrcBeginPhase(virQEMUDriver *driver,
                           virDomainObj *vm,
                           const char *xmlin,
                           const char *dname,
                           char **cookieout,
                           int *cookieoutlen,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    unsigned int cookieFlags = QEMU_MIGRATION_COOKIE_LOCKSTATE;

    VIR_DEBUG("driver=%p, vm=%p, xmlin=%s, dname=%s,"
              " cookieout=%p, cookieoutlen=%p,"
              " nmigrate_disks=%zu, migrate_disks=%p, flags=0x%x",
              driver, vm, NULLSTR(xmlin), NULLSTR(dname),
              cookieout, cookieoutlen, nmigrate_disks,
              migrate_disks, flags);

    /* Only set the phase if we are inside VIR_ASYNC_JOB_MIGRATION_OUT.
     * Otherwise we will start the async job later in the perform phase losing
     * change protection.
     */
    if (vm->job->asyncJob == VIR_ASYNC_JOB_MIGRATION_OUT &&
        qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_BEGIN3) < 0)
        return NULL;

    if (!qemuMigrationSrcIsAllowed(vm, true, vm->job->asyncJob, flags))
        return NULL;

    if (!(flags & (VIR_MIGRATE_UNSAFE | VIR_MIGRATE_OFFLINE)) &&
        !qemuMigrationSrcIsSafe(vm->def, priv->qemuCaps,
                                nmigrate_disks, migrate_disks, flags))
        return NULL;

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live or paused migration"));
        return NULL;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        return NULL;
    }

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle non-shared storage"));
            return NULL;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with the persistent flag set"));
            return NULL;
        }
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not make sense"));
            return NULL;
        }
    }

    if (flags & VIR_MIGRATE_ZEROCOPY && !(flags & VIR_MIGRATE_PARALLEL)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("zero-copy is only available for parallel migration"));
        return NULL;
    }

    if (flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC)) {
        if (flags & VIR_MIGRATE_TUNNELLED) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("migration of non-shared storage is not supported with tunnelled migration and this QEMU"));
            return NULL;
        }

        if (nmigrate_disks) {
            size_t i, j;
            /* Check user requested only known disk targets. */
            for (i = 0; i < nmigrate_disks; i++) {
                for (j = 0; j < vm->def->ndisks; j++) {
                    if (STREQ(vm->def->disks[j]->dst, migrate_disks[i]))
                        break;
                }

                if (j == vm->def->ndisks) {
                    virReportError(VIR_ERR_INVALID_ARG,
                                   _("disk target %1$s not found"),
                                   migrate_disks[i]);
                    return NULL;
                }
            }
        }

        priv->nbdPort = 0;

        if (qemuMigrationHasAnyStorageMigrationDisks(vm->def,
                                                     migrate_disks,
                                                     nmigrate_disks))
            cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    } else {
        if (nmigrate_disks > 0) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("use of 'VIR_MIGRATE_PARAM_MIGRATE_DISKS' requires use of 'VIR_MIGRATE_NON_SHARED_DISK' or 'VIR_MIGRATE_NON_SHARED_INC' flag"));
            return NULL;
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

    return qemuMigrationSrcBeginXML(vm, xmlin,
                                    cookieout, cookieoutlen, cookieFlags,
                                    migrate_disks, nmigrate_disks,
                                    flags);
}


static bool
qemuMigrationAnyCanResume(virDomainObj *vm,
                          virDomainAsyncJob job,
                          unsigned int flags,
                          qemuMigrationJobPhase expectedPhase)
{
    VIR_DEBUG("vm=%p, job=%s, flags=0x%x, expectedPhase=%s",
              vm, virDomainAsyncJobTypeToString(job), flags,
              qemuDomainAsyncJobPhaseToString(VIR_ASYNC_JOB_MIGRATION_OUT,
                                              expectedPhase));

    if (!(flags & VIR_MIGRATE_POSTCOPY)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("resuming failed post-copy migration requires post-copy to be enabled"));
        return false;
    }

    /* This should never happen since POSTCOPY_RESUME is newer than
     * CHANGE_PROTECTION, but let's check it anyway in case we're talking to
     * a weird client.
     */
    if (job == VIR_ASYNC_JOB_MIGRATION_OUT &&
        expectedPhase < QEMU_MIGRATION_PHASE_PERFORM_RESUME &&
        !(flags & (VIR_MIGRATE_CHANGE_PROTECTION | VIR_MIGRATE_PEER2PEER))) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("resuming failed post-copy migration requires change protection"));
        return false;
    }

    if (!qemuMigrationJobIsActive(vm, job))
        return false;

    if (vm->job->asyncOwner != 0 &&
        vm->job->asyncOwner != virThreadSelfID()) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("migration of domain %1$s is being actively monitored by another thread"),
                       vm->def->name);
        return false;
    }

    if (!virDomainObjIsPostcopy(vm, vm->job)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("migration of domain %1$s is not in post-copy phase"),
                       vm->def->name);
        return false;
    }

    if (vm->job->phase < QEMU_MIGRATION_PHASE_POSTCOPY_FAILED &&
        !virDomainObjIsFailedPostcopy(vm, vm->job)) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("post-copy migration of domain %1$s has not failed"),
                       vm->def->name);
        return false;
    }

    if (vm->job->phase > expectedPhase) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("resuming failed post-copy migration of domain %1$s already in progress"),
                       vm->def->name);
        return false;
    }

    return true;
}


static char *
qemuMigrationSrcBeginResume(virDomainObj *vm,
                            const char *xmlin,
                            char **cookieout,
                            int *cookieoutlen,
                            unsigned int flags)
{
    virDomainJobStatus status;

    if (qemuMigrationAnyRefreshStatus(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                      &status) < 0)
        return NULL;

    if (status != VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("QEMU reports migration is still running"));
        return NULL;
    }

    return qemuMigrationSrcBeginXML(vm, xmlin,
                                    cookieout, cookieoutlen, 0, NULL, 0, flags);
}


static char *
qemuMigrationSrcBeginResumePhase(virConnectPtr conn,
                                 virDomainObj *vm,
                                 const char *xmlin,
                                 char **cookieout,
                                 int *cookieoutlen,
                                 unsigned int flags)
{
    g_autofree char *xml = NULL;

    VIR_DEBUG("vm=%p", vm);

    if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags,
                                   QEMU_MIGRATION_PHASE_POSTCOPY_FAILED))
        return NULL;

    if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_BEGIN_RESUME) < 0)
        return NULL;

    virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);
    qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);

    xml = qemuMigrationSrcBeginResume(vm, xmlin, cookieout, cookieoutlen, flags);

    virCloseCallbacksDomainAdd(vm, conn, qemuMigrationAnyConnectionClosed);

    if (!xml)
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));

    qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    return g_steal_pointer(&xml);
}


char *
qemuMigrationSrcBegin(virConnectPtr conn,
                      virDomainObj *vm,
                      const char *xmlin,
                      const char *dname,
                      char **cookieout,
                      int *cookieoutlen,
                      size_t nmigrate_disks,
                      const char **migrate_disks,
                      unsigned int flags)
{
    virQEMUDriver *driver = conn->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autofree char *xml = NULL;
    char *ret = NULL;
    virDomainAsyncJob asyncJob;

    if (cfg->migrateTLSForce &&
        !(flags & VIR_MIGRATE_TUNNELLED) &&
        !(flags & VIR_MIGRATE_TLS)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this libvirtd instance allows migration only with VIR_MIGRATE_TLS flag"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        ret = qemuMigrationSrcBeginResumePhase(conn, vm, xmlin,
                                               cookieout, cookieoutlen, flags);
        goto cleanup;
    }

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags) < 0)
            goto cleanup;
        asyncJob = VIR_ASYNC_JOB_MIGRATION_OUT;
    } else {
        if (!qemuMigrationJobIsAllowed(vm))
            goto cleanup;

        if (virDomainObjBeginJob(vm, VIR_JOB_MODIFY) < 0)
            goto cleanup;
        asyncJob = VIR_ASYNC_JOB_NONE;
    }

    qemuMigrationSrcStoreDomainState(vm);

    if (!(flags & VIR_MIGRATE_OFFLINE) && virDomainObjCheckActive(vm) < 0)
        goto endjob;

    /* Check if there is any ejected media.
     * We don't want to require them on the destination.
     */
    if (!(flags & VIR_MIGRATE_OFFLINE) &&
        qemuProcessRefreshDisks(vm, asyncJob) < 0)
        goto endjob;

    if (!(xml = qemuMigrationSrcBeginPhase(driver, vm, xmlin, dname,
                                           cookieout, cookieoutlen,
                                           nmigrate_disks, migrate_disks, flags)))
        goto endjob;

    if ((flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        /* We keep the job active across API calls until the confirm() call.
         * This prevents any other APIs being invoked while migration is taking
         * place.
         */
        virCloseCallbacksDomainAdd(vm, conn, qemuMigrationAnyConnectionClosed);
    }

    ret = g_steal_pointer(&xml);

 endjob:
    if (flags & VIR_MIGRATE_CHANGE_PROTECTION) {
        if (ret)
            qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
        else
            qemuMigrationJobFinish(vm);
    } else {
        virDomainObjEndJob(vm);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


/* Prepare is the first step, and it runs on the destination host.
 */

static void
qemuMigrationDstPrepareCleanup(virQEMUDriver *driver,
                               virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("driver=%p, vm=%s, job=%s, asyncJob=%s",
              driver,
              vm->def->name,
              virDomainJobTypeToString(vm->job->active),
              virDomainAsyncJobTypeToString(vm->job->asyncJob));

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_IN))
        return;
    qemuDomainObjDiscardAsyncJob(vm);
}

static qemuProcessIncomingDef *
qemuMigrationDstPrepare(virDomainObj *vm,
                        bool tunnel,
                        const char *protocol,
                        const char *listenAddress,
                        unsigned short port,
                        int fd)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autofree char *migrateFrom = NULL;

    if (tunnel) {
        migrateFrom = g_strdup("stdio");
    } else if (g_strcmp0(protocol, "unix") == 0) {
        migrateFrom = g_strdup_printf("%s:%s", protocol, listenAddress);
    } else {
        bool encloseAddress = false;
        bool hostIPv6Capable = false;
        struct addrinfo *info = NULL;
        struct addrinfo hints = { .ai_flags = AI_ADDRCONFIG,
                                  .ai_socktype = SOCK_STREAM };
        const char *incFormat;

        if (getaddrinfo("::", NULL, &hints, &info) == 0) {
            freeaddrinfo(info);
            hostIPv6Capable = true;
        }

        if (listenAddress) {
            if (virSocketAddrNumericFamily(listenAddress) == AF_INET6) {
                if (!hostIPv6Capable) {
                    virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                                   _("host isn't capable of IPv6"));
                    return NULL;
                }
                /* IPv6 address must be escaped in brackets on the cmd line */
                encloseAddress = true;
            } else {
                /* listenAddress is a hostname or IPv4 */
            }
        } else if (hostIPv6Capable) {
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
        migrateFrom = g_strdup_printf(incFormat, protocol, listenAddress, port);
    }

    return qemuProcessIncomingDefNew(priv->qemuCaps, listenAddress,
                                     migrateFrom, fd, NULL);
}


/**
 * qemuMigrationDstPrepareAnyBlockDirtyBitmaps:
 * @vm: domain object
 * @mig: migration cookie
 * @migParams: migration parameters
 * @flags: migration flags
 *
 * Checks whether block dirty bitmaps offered by the migration source are
 * to be migrated (e.g. they don't exist, the destination is compatible etc)
 * and sets up destination qemu for migrating the bitmaps as well as updates the
 * list of eligible bitmaps in the migration cookie to be sent back to the
 * source.
 */
static int
qemuMigrationDstPrepareAnyBlockDirtyBitmaps(virDomainObj *vm,
                                            qemuMigrationCookie *mig,
                                            qemuMigrationParams *migParams,
                                            unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virJSONValue) mapping = NULL;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    GSList *nextdisk;

    if (!mig->nbd ||
        !mig->blockDirtyBitmaps ||
        !(flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC)) ||
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATION_PARAM_BLOCK_BITMAP_MAPPING))
        return 0;

    if (qemuMigrationCookieBlockDirtyBitmapsMatchDisks(vm->def, mig->blockDirtyBitmaps) < 0)
        return -1;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_MIGRATION_IN)))
        return -1;

    for (nextdisk = mig->blockDirtyBitmaps; nextdisk; nextdisk = nextdisk->next) {
        qemuMigrationBlockDirtyBitmapsDisk *disk = nextdisk->data;
        qemuBlockNamedNodeData *nodedata;
        GSList *nextbitmap;

        if (!(nodedata = virHashLookup(blockNamedNodeData, disk->nodename))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to find data for block node '%1$s'"),
                           disk->nodename);
            return -1;
        }

        /* Bitmaps can only be migrated to qcow2 v3+ */
        if (disk->disk->src->format != VIR_STORAGE_FILE_QCOW2 ||
            nodedata->qcow2v2) {
            disk->skip = true;
            continue;
        }

        for (nextbitmap = disk->bitmaps; nextbitmap; nextbitmap = nextbitmap->next) {
            qemuMigrationBlockDirtyBitmapsDiskBitmap *bitmap = nextbitmap->data;
            size_t k;

            /* don't migrate into existing bitmaps */
            for (k = 0; k < nodedata->nbitmaps; k++) {
                if (STREQ(bitmap->bitmapname, nodedata->bitmaps[k]->name)) {
                    bitmap->skip = true;
                    break;
                }
            }

            if (bitmap->skip)
                continue;
        }
    }

    if (qemuMigrationCookieBlockDirtyBitmapsToParams(mig->blockDirtyBitmaps,
                                                     &mapping) < 0)
        return -1;

    if (!mapping)
        return 0;

    qemuMigrationParamsSetBlockDirtyBitmapMapping(migParams, &mapping);
    mig->flags |= QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS;
    return 0;
}


static int
qemuMigrationDstPrepareActive(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virConnectPtr dconn,
                              qemuMigrationCookie *mig,
                              virStreamPtr st,
                              const char *protocol,
                              unsigned short port,
                              const char *listenAddress,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              int nbdPort,
                              const char *nbdURI,
                              qemuMigrationParams *migParams,
                              unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    qemuProcessIncomingDef *incoming = NULL;
    g_autofree char *tlsAlias = NULL;
    virObjectEvent *event = NULL;
    virErrorPtr origErr = NULL;
    int dataFD[2] = { -1, -1 };
    bool stopProcess = false;
    unsigned int startFlags;
    bool relabel = false;
    bool tunnel = !!st;
    int ret = -1;
    int rv;

    if (STREQ_NULLABLE(protocol, "rdma") &&
        !virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("cannot start RDMA migration with no memory hard limit set"));
        goto error;
    }

    if (qemuMigrationDstPrecreateStorage(vm, mig->nbd,
                                         nmigrate_disks, migrate_disks,
                                         !!(flags & VIR_MIGRATE_NON_SHARED_INC)) < 0)
        goto error;

    if (tunnel &&
        virPipe(dataFD) < 0)
        goto error;

    startFlags = VIR_QEMU_PROCESS_START_AUTODESTROY;

    if (qemuProcessInit(driver, vm, mig->cpu, VIR_ASYNC_JOB_MIGRATION_IN,
                        true, startFlags) < 0)
        goto error;
    stopProcess = true;

    if (!(incoming = qemuMigrationDstPrepare(vm, tunnel, protocol,
                                             listenAddress, port,
                                             dataFD[0])))
        goto error;

    if (qemuProcessPrepareDomain(driver, vm, startFlags) < 0)
        goto error;

    if (qemuProcessPrepareHost(driver, vm, startFlags) < 0)
        goto error;

    rv = qemuProcessLaunch(dconn, driver, vm, VIR_ASYNC_JOB_MIGRATION_IN,
                           incoming, NULL,
                           VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
                           startFlags);
    if (rv < 0) {
        if (rv == -2)
            relabel = true;
        goto error;
    }
    relabel = true;

    if (tunnel) {
        if (virFDStreamOpen(st, dataFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot pass pipe for tunnelled migration"));
            goto error;
        }
        dataFD[1] = -1; /* 'st' owns the FD now & will close it */
    }

    if (STREQ_NULLABLE(protocol, "rdma") &&
        virMemoryLimitIsSet(vm->def->mem.hard_limit) &&
        qemuDomainSetMaxMemLock(vm, vm->def->mem.hard_limit << 10,
                                &priv->preMigrationMemlock) < 0) {
        goto error;
    }

    if (qemuMigrationDstPrepareAnyBlockDirtyBitmaps(vm, mig, migParams, flags) < 0)
        goto error;

    if (qemuMigrationParamsCheck(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                                 migParams, mig->caps->automatic) < 0)
        goto error;

    /* Save original migration parameters */
    qemuDomainSaveStatus(vm);

    /* Migrations using TLS need to add the "tls-creds-x509" object and
     * set the migration TLS parameters */
    if (flags & VIR_MIGRATE_TLS) {
        if (qemuMigrationParamsEnableTLS(driver, vm, true,
                                         VIR_ASYNC_JOB_MIGRATION_IN,
                                         &tlsAlias, NULL,
                                         migParams) < 0)
            goto error;
    } else {
        if (qemuMigrationParamsDisableTLS(vm, migParams) < 0)
            goto error;
    }

    if (qemuMigrationParamsApply(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                                 migParams, flags) < 0)
        goto error;

    if (mig->nbd &&
        flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC)) {
        const char *nbdTLSAlias = NULL;

        if (flags & VIR_MIGRATE_TLS) {
            if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_NBD_TLS)) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("QEMU NBD server does not support TLS transport"));
                goto error;
            }

            nbdTLSAlias = tlsAlias;
        }

        if (qemuMigrationDstStartNBDServer(driver, vm, incoming->address,
                                           nmigrate_disks, migrate_disks,
                                           nbdPort, nbdURI,
                                           nbdTLSAlias) < 0) {
            goto error;
        }
    }

    if (mig->lockState) {
        VIR_DEBUG("Received lockstate %s", mig->lockState);
        VIR_FREE(priv->lockState);
        priv->lockState = g_steal_pointer(&mig->lockState);
    } else {
        VIR_DEBUG("Received no lockstate");
    }

    if (qemuMigrationDstRun(vm, incoming->uri,
                            VIR_ASYNC_JOB_MIGRATION_IN) < 0)
        goto error;

    if (qemuProcessFinishStartup(driver, vm, VIR_ASYNC_JOB_MIGRATION_IN,
                                 false, VIR_DOMAIN_PAUSED_MIGRATION) < 0)
        goto error;

    virDomainAuditStart(vm, "migrated", true);
    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STARTED,
                                              VIR_DOMAIN_EVENT_STARTED_MIGRATED);

    ret = 0;

 cleanup:
    qemuProcessIncomingDefFree(incoming);
    VIR_FORCE_CLOSE(dataFD[0]);
    VIR_FORCE_CLOSE(dataFD[1]);
    virObjectEventStateQueue(driver->domainEventState, event);
    virErrorRestore(&origErr);
    return ret;

 error:
    virErrorPreserveLast(&origErr);
    qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                             jobPriv->migParams, vm->job->apiFlags);

    if (stopProcess) {
        unsigned int stopFlags = VIR_QEMU_PROCESS_STOP_MIGRATED;
        if (!relabel)
            stopFlags |= VIR_QEMU_PROCESS_STOP_NO_RELABEL;
        virDomainAuditStart(vm, "migrated", false);
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                        VIR_ASYNC_JOB_MIGRATION_IN, stopFlags);
        /* release if port is auto selected which is not the case if
         * it is given in parameters
         */
        if (nbdPort == 0)
            virPortAllocatorRelease(priv->nbdPort);
        priv->nbdPort = 0;
    }
    goto cleanup;
}


static int
qemuMigrationDstPrepareFresh(virQEMUDriver *driver,
                             virConnectPtr dconn,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             virDomainDef **def,
                             const char *origname,
                             virStreamPtr st,
                             const char *protocol,
                             unsigned short port,
                             bool autoPort,
                             const char *listenAddress,
                             size_t nmigrate_disks,
                             const char **migrate_disks,
                             int nbdPort,
                             const char *nbdURI,
                             qemuMigrationParams *migParams,
                             unsigned int flags)
{
    virDomainObj *vm = NULL;
    virErrorPtr origErr;
    int ret = -1;
    qemuDomainObjPrivate *priv = NULL;
    g_autoptr(qemuMigrationCookie) mig = NULL;
    g_autofree char *xmlout = NULL;
    unsigned int cookieFlags = 0;
    bool taint_hook = false;

    VIR_DEBUG("name=%s, origname=%s, protocol=%s, port=%hu, "
              "listenAddress=%s, nbdPort=%d, nbdURI=%s, flags=0x%x",
              (*def)->name, NULLSTR(origname), protocol, port,
              listenAddress, nbdPort, NULLSTR(nbdURI), flags);

    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        cookieFlags = QEMU_MIGRATION_COOKIE_GRAPHICS |
                      QEMU_MIGRATION_COOKIE_CAPS;
    }

    /* Let migration hook filter domain XML */
    if (virHookPresent(VIR_HOOK_DRIVER_QEMU)) {
        g_autofree char *xml = NULL;
        int hookret;

        if (!(xml = qemuDomainDefFormatXML(driver, NULL, *def,
                                           VIR_DOMAIN_XML_SECURE |
                                           VIR_DOMAIN_XML_MIGRATABLE)))
            goto cleanup;

        hookret = virHookCall(VIR_HOOK_DRIVER_QEMU, (*def)->name,
                              VIR_HOOK_QEMU_OP_MIGRATE, VIR_HOOK_SUBOP_BEGIN,
                              NULL, xml, &xmlout);

        if (hookret < 0) {
            goto cleanup;
        } else if (hookret == 0) {
            if (virStringIsEmpty(xmlout)) {
                VIR_DEBUG("Migrate hook filter returned nothing; using the"
                          " original XML");
            } else {
                g_autoptr(virDomainDef) newdef = NULL;

                VIR_DEBUG("Using hook-filtered domain XML: %s", xmlout);
                newdef = virDomainDefParseString(xmlout, driver->xmlopt, NULL,
                                                 VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                                 VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE);
                if (!newdef)
                    goto cleanup;

                if (!qemuDomainDefCheckABIStability(driver, NULL, *def, newdef))
                    goto cleanup;

                virDomainDefFree(*def);
                *def = g_steal_pointer(&newdef);
                /* We should taint the domain here. However, @vm and therefore
                 * privateData too are still NULL, so just notice the fact and
                 * taint it later. */
                taint_hook = true;
            }
        }
    }

    /* Parse cookie earlier than adding the domain onto the
     * domain list. Parsing/validation may fail and there's no
     * point in having the domain in the list at that point. */
    if (!(mig = qemuMigrationCookieParse(driver, NULL, *def, origname, NULL,
                                         cookiein, cookieinlen,
                                         QEMU_MIGRATION_COOKIE_LOCKSTATE |
                                         QEMU_MIGRATION_COOKIE_NBD |
                                         QEMU_MIGRATION_COOKIE_MEMORY_HOTPLUG |
                                         QEMU_MIGRATION_COOKIE_CPU_HOTPLUG |
                                         QEMU_MIGRATION_COOKIE_CPU |
                                         QEMU_MIGRATION_COOKIE_CAPS |
                                         QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS)))
        goto cleanup;

    if (!(vm = virDomainObjListAdd(driver->domains, def,
                                   driver->xmlopt,
                                   VIR_DOMAIN_OBJ_LIST_ADD_LIVE |
                                   VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE,
                                   NULL)))
        goto cleanup;

    priv = vm->privateData;
    priv->origname = g_strdup(origname);

    if (taint_hook) {
        /* Domain XML has been altered by a hook script. */
        priv->hookRun = true;
    }

    if (qemuMigrationJobStart(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                              flags) < 0)
        goto cleanup;

    if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PREPARE) < 0)
        goto stopjob;

    /* Domain starts inactive, even if the domain XML had an id field. */
    vm->def->id = -1;

    if (!(flags & VIR_MIGRATE_OFFLINE)) {
        if (qemuMigrationDstPrepareActive(driver, vm, dconn, mig, st,
                                          protocol, port, listenAddress,
                                          nmigrate_disks, migrate_disks,
                                          nbdPort, nbdURI,
                                          migParams, flags) < 0) {
            goto stopjob;
        }

        if (mig->nbd &&
            flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC))
            cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;
    }

    if (qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_DESTINATION,
                                  cookieout, cookieoutlen, cookieFlags) < 0) {
        /* We could tear down the whole guest here, but
         * cookie data is (so far) non-critical, so that
         * seems a little harsh. We'll just warn for now.
         */
        VIR_WARN("Unable to encode migration cookie");
    }

    /* We keep the job active across API calls until the finish() call.
     * This prevents any other APIs being invoked while incoming
     * migration is taking place.
     */
    qemuMigrationJobContinue(vm, qemuMigrationDstPrepareCleanup);

    if (autoPort)
        priv->migrationPort = port;
    /* in this case port is not auto selected and we don't need to manage it
     * anymore after cookie is baked
     */
    if (nbdPort != 0)
        priv->nbdPort = 0;
    ret = 0;

 cleanup:
    virErrorPreserveLast(&origErr);
    if (ret < 0 && priv) {
        /* priv is set right after vm is added to the list of domains
         * and there is no 'goto cleanup;' in the middle of those */
        VIR_FREE(priv->origname);
        virDomainObjRemoveTransientDef(vm);
        qemuDomainRemoveInactive(driver, vm, 0, false);
    }
    virDomainObjEndAPI(&vm);
    virErrorRestore(&origErr);
    return ret;

 stopjob:
    qemuMigrationJobFinish(vm);
    goto cleanup;
}


static int
qemuMigrationDstPrepareResume(virQEMUDriver *driver,
                              virConnectPtr conn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              virDomainDef *def,
                              const char *origname,
                              const char *protocol,
                              unsigned short port,
                              bool autoPort,
                              const char *listenAddress,
                              unsigned int flags)
{
    g_autoptr(qemuMigrationCookie) mig = NULL;
    qemuProcessIncomingDef *incoming = NULL;
    qemuDomainObjPrivate *priv;
    virDomainJobStatus status;
    virDomainObj *vm;
    int ret = -1;

    VIR_DEBUG("name=%s, origname=%s, protocol=%s, port=%hu, "
              "listenAddress=%s, flags=0x%x",
              def->name, NULLSTR(origname), protocol, port,
              NULLSTR(listenAddress), flags);

    vm = virDomainObjListFindByName(driver->domains, def->name);
    if (!vm) {
        virReportError(VIR_ERR_NO_DOMAIN,
                       _("no domain with matching name '%1$s'"), def->name);
        qemuMigrationDstErrorReport(driver, def->name);
        return -1;
    }
    priv = vm->privateData;

    if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_IN, flags,
                                   QEMU_MIGRATION_PHASE_POSTCOPY_FAILED))
        goto cleanup;

    if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PREPARE_RESUME) < 0)
        goto cleanup;

    qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);

    if (qemuMigrationAnyRefreshStatus(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                                      &status) < 0)
        goto cleanup;

    if (status != VIR_DOMAIN_JOB_STATUS_POSTCOPY_PAUSED) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("QEMU reports migration is still running"));
        goto cleanup;
    }

    if (!(mig = qemuMigrationCookieParse(driver, vm, def, origname, NULL,
                                         cookiein, cookieinlen,
                                         QEMU_MIGRATION_COOKIE_CAPS)))
        goto cleanup;

    priv->origname = g_strdup(origname);

    if (!(incoming = qemuMigrationDstPrepare(vm, false, protocol,
                                             listenAddress, port, -1)))
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_IN) < 0)
        goto cleanup;

    ret = qemuMonitorMigrateRecover(priv->mon, incoming->uri);
    qemuDomainObjExitMonitor(vm);

    if (ret < 0)
        goto cleanup;

    if (qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_DESTINATION,
                                  cookieout, cookieoutlen,
                                  QEMU_MIGRATION_COOKIE_CAPS) < 0)
        VIR_WARN("Unable to encode migration cookie");

    virCloseCallbacksDomainAdd(vm, conn, qemuMigrationAnyConnectionClosed);

    if (autoPort)
        priv->migrationPort = port;

 cleanup:
    qemuProcessIncomingDefFree(incoming);
    if (ret < 0) {
        VIR_FREE(priv->origname);
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));
    }
    qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    virDomainObjEndAPI(&vm);
    return ret;
}


static int
qemuMigrationDstPrepareAny(virQEMUDriver *driver,
                           virConnectPtr dconn,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           virDomainDef **def,
                           const char *origname,
                           virStreamPtr st,
                           const char *protocol,
                           unsigned short port,
                           bool autoPort,
                           const char *listenAddress,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           int nbdPort,
                           const char *nbdURI,
                           qemuMigrationParams *migParams,
                           unsigned int flags)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (flags & (VIR_MIGRATE_NON_SHARED_DISK |
                     VIR_MIGRATE_NON_SHARED_INC)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration cannot handle non-shared storage"));
            return -1;
        }
        if (!(flags & VIR_MIGRATE_PERSIST_DEST)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("offline migration must be specified with the persistent flag set"));
            return -1;
        }
        if (st) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("tunnelled offline migration does not make sense"));
            return -1;
        }
    }

    if (flags & VIR_MIGRATE_POSTCOPY &&
        (!(flags & VIR_MIGRATE_LIVE) ||
         flags & VIR_MIGRATE_PAUSED)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy migration is not supported with non-live or paused migration"));
        return -1;
    }

    if (flags & VIR_MIGRATE_POSTCOPY && flags & VIR_MIGRATE_TUNNELLED) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("post-copy is not supported with tunnelled migration"));
        return -1;
    }

    if (cfg->migrateTLSForce &&
        !(flags & VIR_MIGRATE_TUNNELLED) &&
        !(flags & VIR_MIGRATE_TLS)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this libvirtd instance allows migration only with VIR_MIGRATE_TLS flag"));
        return -1;
    }

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        return qemuMigrationDstPrepareResume(driver, dconn, cookiein, cookieinlen,
                                             cookieout, cookieoutlen,
                                             *def, origname, protocol,
                                             port, autoPort,
                                             listenAddress, flags);
    }

    return qemuMigrationDstPrepareFresh(driver, dconn,
                                        cookiein, cookieinlen,
                                        cookieout, cookieoutlen,
                                        def, origname, st, protocol,
                                        port, autoPort, listenAddress,
                                        nmigrate_disks, migrate_disks,
                                        nbdPort, nbdURI,
                                        migParams, flags);
}


/*
 * This version starts an empty VM listening on a localhost TCP port, and
 * sets up the corresponding virStream to handle the incoming data.
 */
int
qemuMigrationDstPrepareTunnel(virQEMUDriver *driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              virStreamPtr st,
                              virDomainDef **def,
                              const char *origname,
                              qemuMigrationParams *migParams,
                              unsigned int flags)
{
    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, st=%p, def=%p, "
              "origname=%s, flags=0x%x",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, st, *def, origname, flags);

    if (st == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("tunnelled migration requested but NULL stream passed"));
        return -1;
    }

    return qemuMigrationDstPrepareAny(driver, dconn, cookiein, cookieinlen,
                                      cookieout, cookieoutlen, def, origname,
                                      st, NULL, 0, false, NULL, 0, NULL, 0,
                                      NULL, migParams, flags);
}


static virURI *
qemuMigrationAnyParseURI(const char *uri, bool *wellFormed)
{
    char *tmp = NULL;
    virURI *parsed;

    /* For compatibility reasons tcp://... URIs are sent as tcp:...
     * We need to transform them to a well-formed URI before parsing. */
    if (STRPREFIX(uri, "tcp:") && !STRPREFIX(uri + 4, "//")) {
        tmp = g_strdup_printf("tcp://%s", uri + 4);
        uri = tmp;
    }

    parsed = virURIParse(uri);
    if (parsed && wellFormed)
        *wellFormed = !tmp;
    VIR_FREE(tmp);

    return parsed;
}


int
qemuMigrationDstPrepareDirect(virQEMUDriver *driver,
                              virConnectPtr dconn,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              const char *uri_in,
                              char **uri_out,
                              virDomainDef **def,
                              const char *origname,
                              const char *listenAddress,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              int nbdPort,
                              const char *nbdURI,
                              qemuMigrationParams *migParams,
                              unsigned int flags)
{
    unsigned short port = 0;
    bool autoPort = true;
    g_autofree char *hostname = NULL;
    int ret = -1;
    g_autoptr(virURI) uri = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *migrateHost = cfg->migrateHost;

    VIR_DEBUG("driver=%p, dconn=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, uri_in=%s, uri_out=%p, "
              "def=%p, origname=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "nbdURI=%s, flags=0x%x",
              driver, dconn, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, NULLSTR(uri_in), uri_out,
              *def, origname, NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, NULLSTR(nbdURI),
              flags);

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

            hostname = g_strdup(migrateHost);
        } else {
            if ((hostname = virGetHostname()) == NULL)
                goto cleanup;
        }

        if (STRPREFIX(hostname, "localhost")) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("hostname on destination resolved to localhost, but migration requires an FQDN"));
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

        *uri_out = g_strdup_printf(incFormat, "tcp", hostname, port);
    } else {
        bool well_formed_uri = false;

        if (!(uri = qemuMigrationAnyParseURI(uri_in, &well_formed_uri)))
            goto cleanup;

        if (uri->scheme == NULL) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("missing scheme in migration URI: %1$s"),
                           uri_in);
            goto cleanup;
        }

        if (STRNEQ(uri->scheme, "tcp") &&
            STRNEQ(uri->scheme, "rdma") &&
            STRNEQ(uri->scheme, "unix")) {
            virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED,
                           _("unsupported scheme %1$s in migration URI %2$s"),
                           uri->scheme, uri_in);
            goto cleanup;
        }

        if (STREQ(uri->scheme, "unix")) {
            autoPort = false;
            listenAddress = uri->path;
        } else {
            if (uri->server == NULL) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("missing host in migration URI: %1$s"),
                               uri_in);
                goto cleanup;
            }

            if (uri->port == 0) {
                if (virPortAllocatorAcquire(driver->migrationPorts, &port) < 0)
                    goto cleanup;

                /* Send well-formed URI only if uri_in was well-formed */
                if (well_formed_uri) {
                    uri->port = port;
                    *uri_out = virURIFormat(uri);
                } else {
                    *uri_out = g_strdup_printf("%s:%d", uri_in, port);
                }
            } else {
                port = uri->port;
                autoPort = false;
            }
        }
    }

    if (*uri_out)
        VIR_DEBUG("Generated uri_out=%s", *uri_out);

    ret = qemuMigrationDstPrepareAny(driver, dconn, cookiein, cookieinlen,
                                     cookieout, cookieoutlen, def, origname,
                                     NULL, uri ? uri->scheme : "tcp",
                                     port, autoPort, listenAddress,
                                     nmigrate_disks, migrate_disks, nbdPort,
                                     nbdURI, migParams, flags);
 cleanup:
    if (ret != 0) {
        VIR_FREE(*uri_out);
        if (autoPort)
            virPortAllocatorRelease(port);
    }
    return ret;
}


virDomainDef *
qemuMigrationAnyPrepareDef(virQEMUDriver *driver,
                           virQEMUCaps *qemuCaps,
                           const char *dom_xml,
                           const char *dname,
                           char **origname)
{
    virDomainDef *def;
    char *name = NULL;

    if (!dom_xml) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no domain XML passed"));
        return NULL;
    }

    if (!(def = virDomainDefParseString(dom_xml, driver->xmlopt,
                                        qemuCaps,
                                        VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                        VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto cleanup;

    if (dname) {
        name = def->name;
        def->name = g_strdup(dname);
    }

 cleanup:
    if (def && origname)
        *origname = name;
    else
        VIR_FREE(name);
    return def;
}


void
qemuMigrationSrcComplete(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainJobData *jobData = vm->job->completed;
    virObjectEvent *event;
    int reason;

    if (!jobData) {
        vm->job->completed = virDomainJobDataCopy(vm->job->current);
        jobData = vm->job->completed;
        jobData->status = VIR_DOMAIN_JOB_STATUS_COMPLETED;
    }

    /* We need to refresh migration statistics after a completed post-copy
     * migration since jobData contains obsolete data from the time we
     * switched to post-copy mode.
     */
    if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
        reason == VIR_DOMAIN_PAUSED_POSTCOPY) {
        VIR_DEBUG("Refreshing migration statistics");
        if (qemuMigrationAnyFetchStats(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                       jobData, NULL) < 0)
            VIR_WARN("Could not refresh migration statistics");
    }

    qemuDomainJobDataUpdateTime(jobData);

    /* If guest uses SPICE and supports seamless migration we have to hold
     * up domain shutdown until SPICE server transfers its data */
    qemuMigrationSrcWaitForSpice(vm);

    qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED, asyncJob,
                    VIR_QEMU_PROCESS_STOP_MIGRATED);
    virDomainAuditStop(vm, "migrated");

    event = virDomainEventLifecycleNewFromObj(vm,
                                              VIR_DOMAIN_EVENT_STOPPED,
                                              VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    virObjectEventStateQueue(driver->domainEventState, event);
    qemuDomainEventEmitJobCompleted(driver, vm);
    priv->preMigrationMemlock = 0;
}


static int
qemuMigrationSrcConfirmPhase(virQEMUDriver *driver,
                             virDomainObj *vm,
                             const char *cookiein,
                             int cookieinlen,
                             unsigned int flags,
                             int retcode)
{
    g_autoptr(qemuMigrationCookie) mig = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    qemuDomainJobDataPrivate *currentData = vm->job->current->privateData;
    virDomainJobData *jobData = NULL;
    qemuMigrationJobPhase phase;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "flags=0x%x, retcode=%d",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              flags, retcode);

    virCheckFlags(QEMU_MIGRATION_FLAGS, -1);

    if (retcode != 0 &&
        virDomainObjIsPostcopy(vm, vm->job) &&
        currentData->stats.mig.status == QEMU_MONITOR_MIGRATION_STATUS_COMPLETED) {
        VIR_DEBUG("Finish phase failed, but QEMU reports post-copy migration is completed; forcing success");
        retcode = 0;
    }

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        phase = QEMU_MIGRATION_PHASE_CONFIRM_RESUME;
    } else if (virDomainObjIsFailedPostcopy(vm, vm->job)) {
        /* Keep the original migration phase in case post-copy failed as the
         * job will stay active even though migration API finishes with an
         * error.
         */
        phase = vm->job->phase;
    } else if (retcode == 0) {
        phase = QEMU_MIGRATION_PHASE_CONFIRM3;
    } else {
        phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
    }

    if (qemuMigrationJobStartPhase(vm, phase) < 0)
        return -1;

    if (!(mig = qemuMigrationCookieParse(driver, vm, vm->def, priv->origname,
                                         priv->qemuCaps,
                                         cookiein, cookieinlen,
                                         QEMU_MIGRATION_COOKIE_STATS)))
        return -1;

    if (retcode == 0)
        jobData = vm->job->completed;
    else
        g_clear_pointer(&vm->job->completed, virDomainJobDataFree);

    /* Update times with the values sent by the destination daemon */
    if (mig->jobData && jobData) {
        qemuDomainJobDataPrivate *privJob = jobData->privateData;
        qemuDomainJobDataPrivate *privMigJob = mig->jobData->privateData;

        jobData->timeDeltaSet = mig->jobData->timeDeltaSet;
        jobData->timeDelta = mig->jobData->timeDelta;
        privJob->stats.mig.downtime_set = privMigJob->stats.mig.downtime_set;
        privJob->stats.mig.downtime = privMigJob->stats.mig.downtime;
    }

    if (flags & VIR_MIGRATE_OFFLINE)
        return 0;

    /* Did the migration go as planned?  If yes, kill off the domain object.
     * If something failed, resume CPUs, but only if we didn't use post-copy.
     */
    if (retcode == 0) {
        qemuMigrationSrcComplete(driver, vm, VIR_ASYNC_JOB_MIGRATION_OUT);
    } else {
        virErrorPtr orig_err;
        int reason;

        virErrorPreserveLast(&orig_err);

        /* cancel any outstanding NBD jobs */
        qemuMigrationSrcNBDCopyCancel(vm, false,
                                      VIR_ASYNC_JOB_MIGRATION_OUT, NULL);

        virErrorRestore(&orig_err);

        if (virDomainObjGetState(vm, &reason) == VIR_DOMAIN_PAUSED &&
            reason == VIR_DOMAIN_PAUSED_POSTCOPY) {
            qemuMigrationSrcPostcopyFailed(vm);
        } else if (!virDomainObjIsFailedPostcopy(vm, vm->job)) {
            qemuMigrationSrcRestoreDomainState(driver, vm);

            qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                     jobPriv->migParams, vm->job->apiFlags);
            qemuDomainSetMaxMemLock(vm, 0, &priv->preMigrationMemlock);
        }

        qemuDomainSaveStatus(vm);
    }

    return 0;
}

int
qemuMigrationSrcConfirm(virQEMUDriver *driver,
                        virDomainObj *vm,
                        const char *cookiein,
                        int cookieinlen,
                        unsigned int flags,
                        int cancelled)
{
    qemuMigrationJobPhase phase;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int ret = -1;

    VIR_DEBUG("vm=%p, flags=0x%x, cancelled=%d", vm, flags, cancelled);

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags,
                                       QEMU_MIGRATION_PHASE_PERFORM_RESUME))
            goto cleanup;
        phase = QEMU_MIGRATION_PHASE_CONFIRM_RESUME;
    } else {
        if (!qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_OUT))
            goto cleanup;

        /* Keep the original migration phase in case post-copy failed as the
         * job will stay active even though migration API finishes with an
         * error.
         */
        if (virDomainObjIsFailedPostcopy(vm, vm->job))
            phase = vm->job->phase;
        else if (cancelled)
            phase = QEMU_MIGRATION_PHASE_CONFIRM3_CANCELLED;
        else
            phase = QEMU_MIGRATION_PHASE_CONFIRM3;
    }

    if (qemuMigrationJobStartPhase(vm, phase) < 0)
        goto cleanup;

    virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);
    qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);

    ret = qemuMigrationSrcConfirmPhase(driver, vm,
                                       cookiein, cookieinlen,
                                       flags, cancelled);

    if (virDomainObjIsFailedPostcopy(vm, vm->job)) {
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));
        qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    } else {
        qemuMigrationJobFinish(vm);
    }

    if (!virDomainObjIsActive(vm)) {
        if (!cancelled && ret == 0 && flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactive(driver, vm, VIR_DOMAIN_UNDEFINE_TPM, true);
    }

 cleanup:
    virDomainObjEndAPI(&vm);
    return ret;
}


enum qemuMigrationDestinationType {
    MIGRATION_DEST_HOST,
    MIGRATION_DEST_CONNECT_HOST,
    MIGRATION_DEST_SOCKET,
    MIGRATION_DEST_CONNECT_SOCKET,
    MIGRATION_DEST_FD,
};

enum qemuMigrationForwardType {
    MIGRATION_FWD_DIRECT,
    MIGRATION_FWD_STREAM,
};

typedef struct _qemuMigrationSpec qemuMigrationSpec;
struct _qemuMigrationSpec {
    enum qemuMigrationDestinationType destType;
    union {
        struct {
            const char *protocol;
            const char *name;
            int port;
        } host;

        struct {
            const char *path;
        } socket;

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
struct _qemuMigrationIOThread {
    virThread thread;
    virStreamPtr st;
    int sock;
    virError err;
    int wakeupRecvFD;
    int wakeupSendFD;
};

static void qemuMigrationSrcIOFunc(void *arg)
{
    qemuMigrationIOThread *data = arg;
    char *buffer = NULL;
    struct pollfd fds[2];
    int timeout = -1;
    virErrorPtr err = NULL;

    VIR_DEBUG("Running migration tunnel; stream=%p, sock=%d",
              data->st, data->sock);

    buffer = g_new0(char, TUNNEL_SEND_BUF_SIZE);

    fds[0].fd = data->sock;
    fds[1].fd = data->wakeupRecvFD;

    for (;;) {
        int ret;

        fds[0].events = fds[1].events = POLLIN;
        fds[0].revents = fds[1].revents = 0;

        ret = poll(fds, G_N_ELEMENTS(fds), timeout);

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

            if (stop) {
                VIR_DEBUG("Migration tunnel was asked to abort");
                goto abrt;
            } else {
                VIR_DEBUG("Migration tunnel was asked to finish");
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
    virErrorPreserveLast(&err);
    if (err && err->code == VIR_ERR_OK) {
        g_clear_pointer(&err, virFreeError);
    }
    virStreamAbort(data->st);
    virErrorRestore(&err);

 error:
    /* Let the source qemu know that the transfer can't continue anymore.
     * Don't copy the error for EPIPE as destination has the actual error. */
    VIR_FORCE_CLOSE(data->sock);
    if (!virLastErrorIsSystemErrno(EPIPE))
        virCopyLastError(&data->err);
    virResetLastError();
    VIR_FREE(buffer);
}


static qemuMigrationIOThread *
qemuMigrationSrcStartTunnel(virStreamPtr st,
                            int sock)
{
    qemuMigrationIOThread *io = NULL;
    int wakeupFD[2] = { -1, -1 };

    if (virPipe(wakeupFD) < 0)
        goto error;

    io = g_new0(qemuMigrationIOThread, 1);

    io->st = st;
    io->sock = sock;
    io->wakeupRecvFD = wakeupFD[0];
    io->wakeupSendFD = wakeupFD[1];

    if (virThreadCreateFull(&io->thread, true,
                            qemuMigrationSrcIOFunc,
                            "qemu-mig-tunnel",
                            false,
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
qemuMigrationSrcStopTunnel(qemuMigrationIOThread *io, bool error)
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
qemuMigrationSrcConnect(virQEMUDriver *driver,
                        virDomainObj *vm,
                        qemuMigrationSpec *spec)
{
    virNetSocket *sock;
    g_autofree char *port = NULL;
    int fd_qemu = -1;
    int ret = -1;

    if (qemuSecuritySetSocketLabel(driver->securityManager, vm->def) < 0)
        goto cleanup;

    switch (spec->destType) {
    case MIGRATION_DEST_CONNECT_HOST:
        port = g_strdup_printf("%d", spec->dest.host.port);
        if (virNetSocketNewConnectTCP(spec->dest.host.name,
                                      port,
                                      AF_UNSPEC,
                                      &sock) == 0) {
            fd_qemu = virNetSocketDupFD(sock, true);
            virObjectUnref(sock);
        }
        break;
    case MIGRATION_DEST_CONNECT_SOCKET:
        if (virNetSocketNewConnectUNIX(spec->dest.socket.path,
                                       NULL, &sock) == 0) {
            fd_qemu = virNetSocketDupFD(sock, true);
            virObjectUnref(sock);
        }
        break;
    case MIGRATION_DEST_HOST:
    case MIGRATION_DEST_SOCKET:
    case MIGRATION_DEST_FD:
        break;
    }

    spec->destType = MIGRATION_DEST_FD;
    spec->dest.fd.qemu = fd_qemu;

    if (qemuSecurityClearSocketLabel(driver->securityManager, vm->def) < 0 ||
        spec->dest.fd.qemu == -1)
        goto cleanup;

    /* Migration expects a blocking FD */
    if (virSetBlocking(spec->dest.fd.qemu, true) < 0) {
        virReportSystemError(errno, _("Unable to set FD %1$d blocking"),
                             spec->dest.fd.qemu);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    if (ret < 0)
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
    return ret;
}


static int
qemuMigrationSrcContinue(virDomainObj *vm,
                         qemuMonitorMigrationStatus status,
                         virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int ret;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    ret = qemuMonitorMigrateContinue(priv->mon, status);

    qemuDomainObjExitMonitor(vm);

    return ret;
}


static int
qemuMigrationSetDBusVMState(virQEMUDriver *driver,
                            virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (priv->dbusVMStateIds) {
        int rv;

        if (qemuHotplugAttachDBusVMState(driver, vm, VIR_ASYNC_JOB_NONE) < 0)
            return -1;

        if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_NONE) < 0)
            return -1;

        rv = qemuMonitorSetDBusVMStateIdList(priv->mon, priv->dbusVMStateIds);

        qemuDomainObjExitMonitor(vm);

        return rv;
    } else {
        if (qemuHotplugRemoveDBusVMState(vm, VIR_ASYNC_JOB_NONE) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuMigrationSrcRunPrepareBlockDirtyBitmapsMerge:
 * @vm: domain object
 * @mig: migration cookie
 *
 * When migrating full disks, which means that the backing chain of the disk
 * will be squashed into a single image we need to calculate bitmaps
 * corresponding to the checkpoints which express the same set of changes
 * for migration.
 *
 * This function prepares temporary bitmaps and corresponding merges, updates
 * the data so that the temporary bitmaps are used and registers the temporary
 * bitmaps for deletion on failed migration.
 */
static int
qemuMigrationSrcRunPrepareBlockDirtyBitmapsMerge(virDomainObj *vm,
                                                 qemuMigrationCookie *mig)
{
    g_autoslist(qemuDomainJobPrivateMigrateTempBitmap) tmpbitmaps = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    g_autoptr(virJSONValue) actions = virJSONValueNewArray();
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    GSList *nextdisk;
    int rc;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, VIR_ASYNC_JOB_MIGRATION_OUT)))
        return -1;

    for (nextdisk = mig->blockDirtyBitmaps; nextdisk; nextdisk = nextdisk->next) {
        qemuMigrationBlockDirtyBitmapsDisk *disk = nextdisk->data;
        GSList *nextbitmap;

        /* if a disk doesn't have a backing chain we don't need the code below */
        if (!virStorageSourceHasBacking(disk->disk->src))
            continue;

        for (nextbitmap = disk->bitmaps; nextbitmap; nextbitmap = nextbitmap->next) {
            qemuMigrationBlockDirtyBitmapsDiskBitmap *bitmap = nextbitmap->data;
            qemuDomainJobPrivateMigrateTempBitmap *tmpbmp;
            virStorageSource *n;
            unsigned long long granularity = 0;
            g_autoptr(virJSONValue) merge = virJSONValueNewArray();

            for (n = disk->disk->src; virStorageSourceIsBacking(n); n = n->backingStore) {
                qemuBlockNamedNodeDataBitmap *b;

                if (!(b = qemuBlockNamedNodeDataGetBitmapByName(blockNamedNodeData, n,
                                                                bitmap->bitmapname)))
                    break;

                if (granularity == 0)
                    granularity = b->granularity;

                if (qemuMonitorTransactionBitmapMergeSourceAddBitmap(merge,
                                                                     qemuBlockStorageSourceGetEffectiveNodename(n),
                                                                     b->name) < 0)
                    return -1;
            }

            bitmap->sourcebitmap = g_strdup_printf("libvirt-migration-%s", bitmap->alias);
            bitmap->persistent = VIR_TRISTATE_BOOL_YES;

            if (qemuMonitorTransactionBitmapAdd(actions,
                                                qemuBlockStorageSourceGetEffectiveNodename(disk->disk->src),
                                                bitmap->sourcebitmap,
                                                false, false, granularity) < 0)
                return -1;

            if (qemuMonitorTransactionBitmapMerge(actions,
                                                  qemuBlockStorageSourceGetEffectiveNodename(disk->disk->src),
                                                  bitmap->sourcebitmap,
                                                  &merge) < 0)
                return -1;

            tmpbmp = g_new0(qemuDomainJobPrivateMigrateTempBitmap, 1);
            tmpbmp->nodename = g_strdup(qemuBlockStorageSourceGetEffectiveNodename(disk->disk->src));
            tmpbmp->bitmapname = g_strdup(bitmap->sourcebitmap);
            tmpbitmaps = g_slist_prepend(tmpbitmaps, tmpbmp);
        }
    }

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
        return -1;

    rc = qemuMonitorTransaction(priv->mon, &actions);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    jobPriv->migTempBitmaps = g_steal_pointer(&tmpbitmaps);

    return 0;
}


/**
 * qemuMigrationSrcRunPrepareBlockDirtyBitmaps:
 * @vm: domain object
 * @mig: migration cookie
 * @migParams: migration parameters
 * @flags: migration flags
 *
 * Configures the source for bitmap migration when the destination asks
 * for bitmaps.
 */
static int
qemuMigrationSrcRunPrepareBlockDirtyBitmaps(virDomainObj *vm,
                                            qemuMigrationCookie *mig,
                                            qemuMigrationParams *migParams,
                                            unsigned int flags)

{
    g_autoptr(virJSONValue) mapping = NULL;

    if (!mig->blockDirtyBitmaps)
        return 0;

    if (qemuMigrationCookieBlockDirtyBitmapsMatchDisks(vm->def, mig->blockDirtyBitmaps) < 0)
        return -1;

    /* For VIR_MIGRATE_NON_SHARED_INC we can migrate the bitmaps directly,
     * otherwise we must create merged bitmaps from the whole chain */

    if (!(flags & VIR_MIGRATE_NON_SHARED_INC) &&
        qemuMigrationSrcRunPrepareBlockDirtyBitmapsMerge(vm, mig) < 0)
        return -1;

    if (qemuMigrationCookieBlockDirtyBitmapsToParams(mig->blockDirtyBitmaps,
                                                     &mapping) < 0)
        return -1;

    qemuMigrationParamsSetBlockDirtyBitmapMapping(migParams, &mapping);
    return 0;
}


/* The caller is supposed to enter monitor before calling this. */
static int
qemuMigrationSrcStart(virDomainObj *vm,
                      qemuMigrationSpec *spec,
                      unsigned int migrateFlags,
                      int *tunnelFd)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autofree char *timestamp = NULL;
    int rc;

    /* connect to the destination qemu if needed */
    if ((spec->destType == MIGRATION_DEST_CONNECT_HOST ||
         spec->destType == MIGRATION_DEST_CONNECT_SOCKET) &&
        qemuMigrationSrcConnect(driver, vm, spec) < 0) {
        return -1;
    }

    /* log start of migration */
    if ((timestamp = virTimeStringNow()) != NULL) {
        if (migrateFlags & QEMU_MONITOR_MIGRATE_RESUME)
            qemuDomainLogAppendMessage(driver, vm, "%s: resuming migration\n", timestamp);
        else
            qemuDomainLogAppendMessage(driver, vm, "%s: initiating migration\n", timestamp);
    }

    switch (spec->destType) {
    case MIGRATION_DEST_HOST:
        if (STREQ(spec->dest.host.protocol, "rdma") &&
            virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
            if (qemuDomainSetMaxMemLock(vm, vm->def->mem.hard_limit << 10,
                                        &priv->preMigrationMemlock) < 0)
                return -1;
            /* Store the original memory locking limit */
            qemuDomainSaveStatus(vm);
        }
        return qemuMonitorMigrateToHost(priv->mon, migrateFlags,
                                        spec->dest.host.protocol,
                                        spec->dest.host.name,
                                        spec->dest.host.port);

    case MIGRATION_DEST_SOCKET:
        qemuSecurityDomainSetPathLabel(driver, vm, spec->dest.socket.path, false);
        return qemuMonitorMigrateToSocket(priv->mon, migrateFlags,
                                          spec->dest.socket.path);

    case MIGRATION_DEST_CONNECT_HOST:
    case MIGRATION_DEST_CONNECT_SOCKET:
        /* handled above and transformed into MIGRATION_DEST_FD */
        break;

    case MIGRATION_DEST_FD:
        if (spec->fwdType != MIGRATION_FWD_DIRECT) {
            if (!tunnelFd) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("tunnelFD argument is required for tunnelled migration"));
                VIR_FORCE_CLOSE(spec->dest.fd.local);
                VIR_FORCE_CLOSE(spec->dest.fd.qemu);
                return -1;
            }
            *tunnelFd = spec->dest.fd.local;
            spec->dest.fd.local = -1;
        }
        rc = qemuMonitorMigrateToFd(priv->mon, migrateFlags,
                                    spec->dest.fd.qemu);
        VIR_FORCE_CLOSE(spec->dest.fd.qemu);
        return rc;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("unexpected migration schema: %1$d"), spec->destType);
    return -1;
}


static bool
qemuMigrationSrcIsCanceled(virDomainObj *vm)
{
    virDomainJobData *jobData = vm->job->current;
    qemuDomainJobDataPrivate *priv = jobData->privateData;
    qemuMonitorMigrationStatus status = priv->stats.mig.status;

    switch (status) {
    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
        VIR_DEBUG("QEMU migration status: %s; waiting finished",
                  qemuMonitorMigrationStatusTypeToString(status));
        return true;

    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_RECOVER:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_PAUSED:
    case QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER:
    case QEMU_MONITOR_MIGRATION_STATUS_DEVICE:
    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_WAIT_UNPLUG:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        VIR_DEBUG("QEMU migration status: %s; still waiting",
                  qemuMonitorMigrationStatusTypeToString(status));
        break;
    }

    return false;
}


/**
 * Requests outgoing migration to be canceled and optionally waits for the
 * cancellation to complete.
 *
 * The thread (the caller itself in most cases) which is watching the migration
 * will do all the cleanup once migration is canceled.
 */
int
qemuMigrationSrcCancel(virDomainObj *vm,
                       virDomainAsyncJob asyncJob,
                       bool wait)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;

    VIR_DEBUG("Cancelling outgoing migration of domain %s", vm->def->name);

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    rc = qemuMonitorMigrateCancel(priv->mon);
    qemuDomainObjExitMonitor(vm);

    if (rc < 0)
        return -1;

    if (virDomainObjIsActive(vm) && wait) {
        VIR_DEBUG("Waiting for migration to be canceled");

        while (!qemuMigrationSrcIsCanceled(vm)) {
            if (qemuDomainObjWait(vm) < 0)
                return -1;
        }
    }

    return 0;
}


static int
qemuMigrationSrcRun(virQEMUDriver *driver,
                    virDomainObj *vm,
                    const char *persist_xml,
                    const char *cookiein,
                    int cookieinlen,
                    char **cookieout,
                    int *cookieoutlen,
                    unsigned int flags,
                    unsigned long resource,
                    qemuMigrationSpec *spec,
                    virConnectPtr dconn,
                    const char *graphicsuri,
                    size_t nmigrate_disks,
                    const char **migrate_disks,
                    qemuMigrationParams *migParams,
                    const char *nbdURI)
{
    int ret = -1;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(qemuMigrationCookie) mig = NULL;
    g_autofree char *tlsAlias = NULL;
    qemuMigrationIOThread *iothread = NULL;
    VIR_AUTOCLOSE fd = -1;
    unsigned long restore_max_bandwidth = priv->migMaxBandwidth;
    virErrorPtr orig_err = NULL;
    unsigned int cookieFlags = 0;
    bool abort_on_error = !!(flags & VIR_MIGRATE_ABORT_ON_ERROR);
    bool storageMigration = flags & (VIR_MIGRATE_NON_SHARED_DISK | VIR_MIGRATE_NON_SHARED_INC);
    bool cancel = false;
    unsigned int waitFlags;
    g_autoptr(virDomainDef) persistDef = NULL;
    int rc;

    if (resource > 0)
        priv->migMaxBandwidth = resource;

    VIR_DEBUG("driver=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%x, resource=%lu, "
              "spec=%p (dest=%d, fwd=%d), dconn=%p, graphicsuri=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              spec, spec->destType, spec->fwdType, dconn,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    if (storageMigration)
        storageMigration = qemuMigrationHasAnyStorageMigrationDisks(vm->def,
                                                                    migrate_disks,
                                                                    nmigrate_disks);

    if (storageMigration) {
        cookieFlags |= QEMU_MIGRATION_COOKIE_NBD;

        if (virQEMUCapsGet(priv->qemuCaps,
                           QEMU_CAPS_MIGRATION_PARAM_BLOCK_BITMAP_MAPPING))
            cookieFlags |= QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS;
    }

    if (virLockManagerPluginUsesState(driver->lockManager) &&
        !cookieout) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Migration with lock driver %1$s requires cookie support"),
                       virLockManagerPluginGetName(driver->lockManager));
        return -1;
    }

    priv->signalIOError = abort_on_error;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        if (persist_xml) {
            if (!(persistDef = qemuMigrationAnyPrepareDef(driver,
                                                          priv->qemuCaps,
                                                          persist_xml,
                                                          NULL, NULL)))
                goto error;
        } else {
            virDomainDef *def = vm->newDef ? vm->newDef : vm->def;
            if (!(persistDef = qemuDomainDefCopy(driver, priv->qemuCaps, def,
                                                 VIR_DOMAIN_XML_SECURE |
                                                 VIR_DOMAIN_XML_MIGRATABLE)))
                goto error;
        }
    }

    mig = qemuMigrationCookieParse(driver, vm, vm->def, priv->origname,
                                   priv->qemuCaps,
                                   cookiein, cookieinlen,
                                   cookieFlags |
                                   QEMU_MIGRATION_COOKIE_GRAPHICS |
                                   QEMU_MIGRATION_COOKIE_CAPS |
                                   QEMU_MIGRATION_COOKIE_BLOCK_DIRTY_BITMAPS);
    if (!mig)
        goto error;

    if (qemuMigrationSrcGraphicsRelocate(vm, mig, graphicsuri) < 0)
        VIR_WARN("unable to provide data for graphics client relocation");

    if (mig->blockDirtyBitmaps &&
        qemuMigrationSrcRunPrepareBlockDirtyBitmaps(vm, mig, migParams, flags) < 0)
        goto error;

    if (qemuMigrationParamsCheck(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                 migParams, mig->caps->automatic) < 0)
        goto error;

    /* Save original migration parameters */
    qemuDomainSaveStatus(vm);

    if (flags & VIR_MIGRATE_TLS) {
        const char *hostname = NULL;

        /* We need to add tls-hostname whenever QEMU itself does not
         * connect directly to the destination. */
        if (spec->destType == MIGRATION_DEST_CONNECT_HOST ||
            spec->destType == MIGRATION_DEST_FD)
            hostname = spec->dest.host.name;

        if (qemuMigrationParamsEnableTLS(driver, vm, false,
                                         VIR_ASYNC_JOB_MIGRATION_OUT,
                                         &tlsAlias, hostname,
                                         migParams) < 0)
            goto error;
    } else {
        if (qemuMigrationParamsDisableTLS(vm, migParams) < 0)
            goto error;
    }

    if (qemuMigrationParamsSetULL(migParams, QEMU_MIGRATION_PARAM_MAX_BANDWIDTH,
                                  priv->migMaxBandwidth * 1024 * 1024) < 0)
        goto error;

    if (qemuMigrationParamsApply(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                 migParams, flags) < 0)
        goto error;

    if (flags & VIR_MIGRATE_ZEROCOPY) {
        /* Zero-copy requires pages in transfer to be locked in host memory.
         * Unfortunately, we have no reliable way of computing how many pages
         * will need to be locked at the same time. Thus we set the limit to
         * the whole guest memory and reset it back once migration is done. */
        unsigned long long limit;

        if (virMemoryLimitIsSet(vm->def->mem.hard_limit))
            limit = vm->def->mem.hard_limit;
        else
            limit = virDomainDefGetMemoryTotal(vm->def);

        if (qemuDomainSetMaxMemLock(vm, limit << 10, &priv->preMigrationMemlock) < 0)
            goto error;

        /* Store the original memory locking limit */
        qemuDomainSaveStatus(vm);
    }

    if (storageMigration) {
        const char *host = "";
        const char *tlsHostname = qemuMigrationParamsGetTLSHostname(migParams);

        if (!mig->nbd) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("migration of non-shared disks requested but NBD is not set up"));
            goto error;
        }

        if (spec->destType == MIGRATION_DEST_HOST ||
            spec->destType == MIGRATION_DEST_CONNECT_HOST) {
            host = spec->dest.host.name;
        }

        if (qemuMigrationSrcNBDStorageCopy(driver, vm, mig,
                                           host,
                                           priv->migMaxBandwidth,
                                           nmigrate_disks,
                                           migrate_disks,
                                           dconn, tlsAlias, tlsHostname,
                                           nbdURI, flags) < 0) {
            goto error;
        }
    }

    if (qemuMigrationSetDBusVMState(driver, vm) < 0)
        goto error;

    /* Before EnterMonitor, since already qemuProcessStopCPUs does that */
    if (!(flags & VIR_MIGRATE_LIVE) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        if (qemuProcessStopCPUs(driver, vm, VIR_DOMAIN_PAUSED_MIGRATION,
                                VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto error;
    }

    if (qemuDomainObjEnterMonitorAsync(vm, VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
        goto error;

    if (vm->job->abortJob) {
        /* explicitly do this *after* we entered the monitor,
         * as this is a critical section so we are guaranteed
         * vm->job->abortJob will not change */
        vm->job->current->status = VIR_DOMAIN_JOB_STATUS_CANCELED;
        virReportError(VIR_ERR_OPERATION_ABORTED, _("%1$s: %2$s"),
                       virDomainAsyncJobTypeToString(vm->job->asyncJob),
                       _("canceled by client"));
        goto exit_monitor;
    }

    rc = qemuMigrationSrcStart(vm, spec, 0, &fd);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto error;

    /* From this point onwards we *must* call cancel to abort the
     * migration on source if anything goes wrong */
    cancel = true;

    if (spec->fwdType != MIGRATION_FWD_DIRECT) {
        if (!(iothread = qemuMigrationSrcStartTunnel(spec->fwd.stream, fd)))
            goto error;
        /* If we've created a tunnel, then the 'fd' will be closed in the
         * qemuMigrationIOFunc as data->sock.
         */
        fd = -1;
    }

    waitFlags = QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER;
    if (abort_on_error)
        waitFlags |= QEMU_MIGRATION_COMPLETED_ABORT_ON_ERROR;
    if (mig->nbd)
        waitFlags |= QEMU_MIGRATION_COMPLETED_CHECK_STORAGE;
    if (flags & VIR_MIGRATE_POSTCOPY)
        waitFlags |= QEMU_MIGRATION_COMPLETED_POSTCOPY;

    rc = qemuMigrationSrcWaitForCompletion(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                           dconn, waitFlags);
    if (rc == -2)
        goto error;

    if (rc == -1) {
        /* QEMU reported failed migration, nothing to cancel anymore */
        cancel = false;
        goto error;
    }

    /* When migration completed, QEMU will have paused the CPUs for us.
     * Wait for the STOP event to be processed to release the lock state.
     */
    while (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
        priv->signalStop = true;
        rc = qemuDomainObjWait(vm);
        priv->signalStop = false;
        if (rc < 0)
            goto error;
    }

    if (mig->nbd &&
        qemuMigrationSrcNBDCopyCancel(vm, false,
                                      VIR_ASYNC_JOB_MIGRATION_OUT,
                                      dconn) < 0)
        goto error;

    /* When migration was paused before serializing device state we need to
     * resume it now once we finished all block jobs and wait for the real
     * end of the migration.
     */
    if (vm->job->current->status == VIR_DOMAIN_JOB_STATUS_PAUSED) {
        if (qemuMigrationSrcContinue(vm,
                                     QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER,
                                     VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
            goto error;

        waitFlags ^= QEMU_MIGRATION_COMPLETED_PRE_SWITCHOVER;

        rc = qemuMigrationSrcWaitForCompletion(vm,
                                               VIR_ASYNC_JOB_MIGRATION_OUT,
                                               dconn, waitFlags);
        if (rc == -2)
            goto error;

        if (rc == -1) {
            /* QEMU reported failed migration, nothing to cancel anymore */
            cancel = false;
            goto error;
        }
    }

    if (iothread) {
        qemuMigrationIOThread *io;

        io = g_steal_pointer(&iothread);
        if (qemuMigrationSrcStopTunnel(io, false) < 0)
            goto error;
    }

    if (vm->job->completed) {
        vm->job->completed->stopped = vm->job->current->stopped;
        qemuDomainJobDataUpdateTime(vm->job->completed);
        qemuDomainJobDataUpdateDowntime(vm->job->completed);
        ignore_value(virTimeMillisNow(&vm->job->completed->sent));
    }

    cookieFlags |= QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS;

    if (qemuMigrationCookieAddPersistent(mig, &persistDef) < 0 ||
        qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_SOURCE,
                                  cookieout, cookieoutlen, cookieFlags) < 0) {
        VIR_WARN("Unable to encode migration cookie");
    }

    ret = 0;

 cleanup:
    priv->signalIOError = false;
    priv->migMaxBandwidth = restore_max_bandwidth;
    virErrorRestore(&orig_err);

    return ret;

 error:
    virErrorPreserveLast(&orig_err);

    if (virDomainObjIsActive(vm)) {
        int reason;
        virDomainState state = virDomainObjGetState(vm, &reason);

        if (state == VIR_DOMAIN_PAUSED && reason == VIR_DOMAIN_PAUSED_POSTCOPY) {
            VIR_DEBUG("Aborting failed post-copy migration as the destination is not running yet");
            virDomainObjSetState(vm, state, VIR_DOMAIN_PAUSED_MIGRATION);
        }

        if (cancel &&
            vm->job->current->status != VIR_DOMAIN_JOB_STATUS_HYPERVISOR_COMPLETED)
            qemuMigrationSrcCancel(vm, VIR_ASYNC_JOB_MIGRATION_OUT, true);

        /* cancel any outstanding NBD jobs */
        if (mig && mig->nbd)
            qemuMigrationSrcNBDCopyCancel(vm, true,
                                          VIR_ASYNC_JOB_MIGRATION_OUT,
                                          dconn);

        qemuMigrationSrcCancelRemoveTempBitmaps(vm, VIR_ASYNC_JOB_MIGRATION_OUT);

        if (vm->job->current->status != VIR_DOMAIN_JOB_STATUS_CANCELED)
            vm->job->current->status = VIR_DOMAIN_JOB_STATUS_FAILED;
    }

    if (iothread)
        qemuMigrationSrcStopTunnel(iothread, true);

    goto cleanup;

 exit_monitor:
    qemuDomainObjExitMonitor(vm);
    goto error;
}


static int
qemuMigrationSrcResume(virDomainObj *vm,
                       qemuMigrationParams *migParams,
                       const char *cookiein,
                       int cookieinlen,
                       char **cookieout,
                       int *cookieoutlen,
                       qemuMigrationSpec *spec,
                       unsigned int flags)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virQEMUDriver *driver = priv->driver;
    g_autoptr(qemuMigrationCookie) mig = NULL;
    int rc;

    VIR_DEBUG("vm=%p", vm);

    mig = qemuMigrationCookieParse(driver, vm, vm->def, priv->origname,
                                   priv->qemuCaps,
                                   cookiein, cookieinlen,
                                   QEMU_MIGRATION_COOKIE_CAPS);
    if (!mig)
        return -1;

    if (qemuMigrationParamsApply(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                 migParams, flags) < 0)
        return -1;

    if (qemuDomainObjEnterMonitorAsync(vm,
                                       VIR_ASYNC_JOB_MIGRATION_OUT) < 0)
        return -1;

    rc = qemuMigrationSrcStart(vm, spec, QEMU_MONITOR_MIGRATE_RESUME, NULL);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        return -1;

    if (qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_SOURCE,
                                  cookieout, cookieoutlen,
                                  QEMU_MIGRATION_COOKIE_STATS) < 0) {
        VIR_WARN("Unable to encode migration cookie");
    }

    return 0;
}


/* Perform migration using QEMU's native migrate support,
 * not encrypted obviously
 */
static int
qemuMigrationSrcPerformNative(virQEMUDriver *driver,
                              virDomainObj *vm,
                              const char *persist_xml,
                              const char *uri,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags,
                              unsigned long resource,
                              virConnectPtr dconn,
                              const char *graphicsuri,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              qemuMigrationParams *migParams,
                              const char *nbdURI)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(virURI) uribits = NULL;
    int ret = -1;
    qemuMigrationSpec spec;

    VIR_DEBUG("driver=%p, vm=%p, uri=%s, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%x, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu migrate_disks=%p",
              driver, vm, uri, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    if (!(uribits = qemuMigrationAnyParseURI(uri, NULL)))
        return -1;

    if (uribits->scheme == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("missing scheme in migration URI: %1$s"),
                       uri);
        return -1;
    }

    if (STREQ(uribits->scheme, "rdma")) {
        if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_MIGRATE_RDMA)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("outgoing RDMA migration is not supported with this QEMU binary"));
            return -1;
        }
        if (!virMemoryLimitIsSet(vm->def->mem.hard_limit)) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot start RDMA migration with no memory hard limit set"));
            return -1;
        }
    }

    if (STREQ(uribits->scheme, "unix")) {
        if ((flags & VIR_MIGRATE_TLS) &&
            !(flags & VIR_MIGRATE_POSTCOPY_RESUME) &&
            !qemuMigrationParamsTLSHostnameIsSet(migParams)) {
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                           _("Explicit destination hostname is required for TLS migration over UNIX socket"));
            return -1;
        }

        if (flags & VIR_MIGRATE_PARALLEL)
            spec.destType = MIGRATION_DEST_SOCKET;
        else
            spec.destType = MIGRATION_DEST_CONNECT_SOCKET;

        spec.dest.socket.path = uribits->path;
    } else {
        /* RDMA and multi-fd migration requires QEMU to connect to the destination
         * itself.
         */
        if (STREQ(uribits->scheme, "rdma") || (flags & VIR_MIGRATE_PARALLEL))
            spec.destType = MIGRATION_DEST_HOST;
        else
            spec.destType = MIGRATION_DEST_CONNECT_HOST;

        spec.dest.host.protocol = uribits->scheme;
        spec.dest.host.name = uribits->server;
        spec.dest.host.port = uribits->port;
    }

    spec.fwdType = MIGRATION_FWD_DIRECT;

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        ret = qemuMigrationSrcResume(vm, migParams, cookiein, cookieinlen,
                                     cookieout, cookieoutlen, &spec, flags);
    } else {
        ret = qemuMigrationSrcRun(driver, vm, persist_xml, cookiein, cookieinlen,
                                  cookieout, cookieoutlen, flags, resource,
                                  &spec, dconn, graphicsuri,
                                  nmigrate_disks, migrate_disks,
                                  migParams, nbdURI);
    }

    if (spec.destType == MIGRATION_DEST_FD)
        VIR_FORCE_CLOSE(spec.dest.fd.qemu);

    return ret;
}


static int
qemuMigrationSrcPerformTunnel(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virStreamPtr st,
                              const char *persist_xml,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags,
                              unsigned long resource,
                              virConnectPtr dconn,
                              const char *graphicsuri,
                              size_t nmigrate_disks,
                              const char **migrate_disks,
                              qemuMigrationParams *migParams)
{
    int ret = -1;
    qemuMigrationSpec spec;
    int fds[2] = { -1, -1 };

    VIR_DEBUG("driver=%p, vm=%p, st=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%x, resource=%lu, "
              "graphicsuri=%s, nmigrate_disks=%zu, migrate_disks=%p",
              driver, vm, st, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, resource,
              NULLSTR(graphicsuri), nmigrate_disks, migrate_disks);

    spec.fwdType = MIGRATION_FWD_STREAM;
    spec.fwd.stream = st;


    spec.destType = MIGRATION_DEST_FD;
    spec.dest.fd.qemu = -1;
    spec.dest.fd.local = -1;

    if (virPipe(fds) < 0)
        goto cleanup;

    spec.dest.fd.qemu = fds[1];
    spec.dest.fd.local = fds[0];

    if (spec.dest.fd.qemu == -1 ||
        qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    spec.dest.fd.qemu) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot create pipe for tunnelled migration"));
        goto cleanup;
    }

    ret = qemuMigrationSrcRun(driver, vm, persist_xml, cookiein, cookieinlen,
                              cookieout, cookieoutlen, flags, resource, &spec,
                              dconn, graphicsuri, nmigrate_disks, migrate_disks,
                              migParams, NULL);

 cleanup:
    VIR_FORCE_CLOSE(spec.dest.fd.qemu);
    VIR_FORCE_CLOSE(spec.dest.fd.local);

    return ret;
}


static int
qemuMigrationSrcPerformResume(virQEMUDriver *driver,
                              virConnectPtr conn,
                              virDomainObj *vm,
                              const char *uri,
                              qemuMigrationParams *migParams,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen,
                              unsigned int flags)
{
    int ret;

    VIR_DEBUG("vm=%p, uri=%s", vm, uri);

    if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags,
                                   QEMU_MIGRATION_PHASE_BEGIN_RESUME))
        return -1;

    if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PERFORM_RESUME) < 0)
        return -1;

    virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);
    qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);

    ret = qemuMigrationSrcPerformNative(driver, vm, NULL, uri,
                                        cookiein, cookieinlen,
                                        cookieout, cookieoutlen, flags,
                                        0, NULL, NULL, 0, NULL, migParams, NULL);

    virCloseCallbacksDomainAdd(vm, conn, qemuMigrationAnyConnectionClosed);

    if (ret < 0)
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));

    qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion2
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int
qemuMigrationSrcPerformPeer2Peer2(virQEMUDriver *driver,
                                  virConnectPtr sconn,
                                  virConnectPtr dconn,
                                  virDomainObj *vm,
                                  const char *dconnuri,
                                  unsigned int flags,
                                  const char *dname,
                                  unsigned long resource,
                                  qemuMigrationParams *migParams)
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

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, vm=%p, dconnuri=%s, "
              "flags=0x%x, dname=%s, resource=%lu",
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
        if (qemuDomainObjExitRemote(vm, true) < 0)
            goto cleanup;
    } else {
        qemuDomainObjEnterRemote(vm);
        ret = dconn->driver->domainMigratePrepare2
            (dconn, &cookie, &cookielen, NULL, &uri_out,
             destflags, dname, resource, dom_xml);
        if (qemuDomainObjExitRemote(vm, true) < 0)
            goto cleanup;
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (!(flags & VIR_MIGRATE_TUNNELLED) &&
        (uri_out == NULL)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare2 did not set uri"));
        cancelled = true;
        virErrorPreserveLast(&orig_err);
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete.
     */
    VIR_DEBUG("Perform %p", sconn);
    ignore_value(qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PERFORM2));
    if (flags & VIR_MIGRATE_TUNNELLED)
        ret = qemuMigrationSrcPerformTunnel(driver, vm, st, NULL,
                                            NULL, 0, NULL, NULL,
                                            flags, resource, dconn,
                                            NULL, 0, NULL, migParams);
    else
        ret = qemuMigrationSrcPerformNative(driver, vm, NULL, uri_out,
                                            cookie, cookielen,
                                            NULL, NULL, /* No out cookie with v2 migration */
                                            flags, resource, dconn, NULL, 0, NULL,
                                            migParams, NULL);

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        virErrorPreserveLast(&orig_err);

    /* If Perform returns < 0, then we need to cancel the VM
     * startup on the destination
     */
    cancelled = ret < 0;

 finish:
    /* In version 2 of the migration protocol, we pass the
     * status code from the sender to the destination host,
     * so it can do any cleanup if the migration failed.
     */
    if (!dname)
        dname = vm->def->name;
    VIR_DEBUG("Finish2 %p ret=%d", dconn, ret);
    qemuDomainObjEnterRemote(vm);
    ddomain = dconn->driver->domainMigrateFinish2
        (dconn, dname, cookie, cookielen,
         uri_out ? uri_out : dconnuri, destflags, cancelled);
    /* The domain is already gone at this point */
    ignore_value(qemuDomainObjExitRemote(vm, false));
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

    virErrorRestore(&orig_err);
    VIR_FREE(uri_out);
    VIR_FREE(cookie);

    return ret;
}


/* This is essentially a re-impl of virDomainMigrateVersion3
 * from libvirt.c, but running in source libvirtd context,
 * instead of client app context & also adding in tunnel
 * handling */
static int
qemuMigrationSrcPerformPeer2Peer3(virQEMUDriver *driver,
                                  virConnectPtr sconn,
                                  virConnectPtr dconn,
                                  const char *dconnuri,
                                  virDomainObj *vm,
                                  const char *xmlin,
                                  const char *persist_xml,
                                  const char *dname,
                                  const char *uri,
                                  const char *graphicsuri,
                                  const char *listenAddress,
                                  size_t nmigrate_disks,
                                  const char **migrate_disks,
                                  int nbdPort,
                                  const char *nbdURI,
                                  qemuMigrationParams *migParams,
                                  unsigned long long bandwidth,
                                  bool useParams,
                                  unsigned int flags)
{
    virDomainPtr ddomain = NULL;
    char *uri_out = NULL;
    char *cookiein = NULL;
    char *cookieout = NULL;
    g_autofree char *dom_xml = NULL;
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
    bool offline = !!(flags & VIR_MIGRATE_OFFLINE);

    VIR_DEBUG("driver=%p, sconn=%p, dconn=%p, dconnuri=%s, vm=%p, xmlin=%s, "
              "dname=%s, uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, nbdURI=%s, "
              "bandwidth=%llu, useParams=%d, flags=0x%x",
              driver, sconn, dconn, NULLSTR(dconnuri), vm, NULLSTR(xmlin),
              NULLSTR(dname), NULLSTR(uri), NULLSTR(graphicsuri),
              NULLSTR(listenAddress), nmigrate_disks, migrate_disks, nbdPort,
              NULLSTR(nbdURI), bandwidth, useParams, flags);

    /* Unlike the virDomainMigrateVersion3 counterpart, we don't need
     * to worry about auto-setting the VIR_MIGRATE_CHANGE_PROTECTION
     * bit here, because we are already running inside the context of
     * a single job.  */

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        dom_xml = qemuMigrationSrcBeginResume(vm, xmlin,
                                              &cookieout, &cookieoutlen, flags);
    } else {
        dom_xml = qemuMigrationSrcBeginPhase(driver, vm, xmlin, dname,
                                             &cookieout, &cookieoutlen,
                                             nmigrate_disks, migrate_disks, flags);
    }
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
        if (nbdURI &&
            virTypedParamsAddString(&params, &nparams, &maxparams,
                                    VIR_MIGRATE_PARAM_DISKS_URI,
                                    nbdURI) < 0)
            goto cleanup;

        if (qemuMigrationParamsDump(migParams, &params, &nparams,
                                    &maxparams, &flags) < 0)
            goto cleanup;
    }

    if (!(flags & VIR_MIGRATE_POSTCOPY_RESUME) &&
        virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED)
        flags |= VIR_MIGRATE_PAUSED;

    destflags = flags & ~(VIR_MIGRATE_ABORT_ON_ERROR |
                          VIR_MIGRATE_AUTO_CONVERGE);

    VIR_DEBUG("Prepare3 %p", dconn);
    cookiein = g_steal_pointer(&cookieout);
    cookieinlen = cookieoutlen;
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
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
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
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
    }
    VIR_FREE(dom_xml);
    if (ret == -1)
        goto cleanup;

    if (offline) {
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
            virErrorPreserveLast(&orig_err);
            goto finish;
        }
    } else if (!uri && !(flags & VIR_MIGRATE_TUNNELLED)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("domainMigratePrepare3 did not set uri"));
        virErrorPreserveLast(&orig_err);
        goto finish;
    }

    /* Perform the migration.  The driver isn't supposed to return
     * until the migration is complete. The src VM should remain
     * running, but in paused state until the destination can
     * confirm migration completion.
     */
    VIR_DEBUG("Perform3 %p uri=%s", sconn, NULLSTR(uri));
    VIR_FREE(cookiein);
    cookiein = g_steal_pointer(&cookieout);
    cookieinlen = cookieoutlen;
    cookieoutlen = 0;

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        ret = qemuMigrationSrcPerformResume(driver, dconn, vm, uri, migParams,
                                            cookiein, cookieinlen,
                                            &cookieout, &cookieoutlen, flags);
    } else {
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_PERFORM3));
        if (flags & VIR_MIGRATE_TUNNELLED) {
            ret = qemuMigrationSrcPerformTunnel(driver, vm, st, persist_xml,
                                                cookiein, cookieinlen,
                                                &cookieout, &cookieoutlen,
                                                flags, bandwidth, dconn, graphicsuri,
                                                nmigrate_disks, migrate_disks,
                                                migParams);
        } else {
            ret = qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri,
                                                cookiein, cookieinlen,
                                                &cookieout, &cookieoutlen,
                                                flags, bandwidth, dconn, graphicsuri,
                                                nmigrate_disks, migrate_disks,
                                                migParams, nbdURI);
        }

        if (ret == 0)
            ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_PERFORM3_DONE));
    }

    /* Perform failed. Make sure Finish doesn't overwrite the error */
    if (ret < 0)
        virErrorPreserveLast(&orig_err);

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
    cookiein = g_steal_pointer(&cookieout);
    cookieinlen = cookieoutlen;
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
            if (qemuDomainObjExitRemote(vm, !offline) < 0)
                goto cleanup;
        }
    } else {
        if (!dname)
            dname = vm->def->name;
        qemuDomainObjEnterRemote(vm);
        ddomain = dconn->driver->domainMigrateFinish3
            (dconn, dname, cookiein, cookieinlen, &cookieout, &cookieoutlen,
             dconnuri, uri, destflags, cancelled);
        if (qemuDomainObjExitRemote(vm, !offline) < 0)
            goto cleanup;
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
                    g_clear_pointer(&orig_err, virFreeError);
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
        virErrorPreserveLast(&orig_err);

    /*
     * If cancelled, then src VM will be restarted, else
     * it will be killed
     */
    VIR_DEBUG("Confirm3 %p cancelled=%d vm=%p", sconn, cancelled, vm);
    VIR_FREE(cookiein);
    cookiein = g_steal_pointer(&cookieout);
    cookieinlen = cookieoutlen;
    cookieoutlen = 0;
    ret = qemuMigrationSrcConfirmPhase(driver, vm,
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

    virErrorRestore(&orig_err);
    VIR_FREE(uri_out);
    VIR_FREE(cookiein);
    VIR_FREE(cookieout);
    virTypedParamsFree(params, nparams);
    return ret;
}


static void
qemuMigrationSrcConnectionClosed(virConnectPtr conn,
                                 int reason,
                                 void *opaque)
{
    virDomainObj *vm = opaque;

    VIR_DEBUG("conn=%p, reason=%d, vm=%s", conn, reason, vm->def->name);
    virDomainObjBroadcast(vm);
}


static int virConnectCredType[] = {
    VIR_CRED_AUTHNAME,
    VIR_CRED_PASSPHRASE,
};


static virConnectAuth virConnectAuthConfig = {
    .credtype = virConnectCredType,
    .ncredtype = G_N_ELEMENTS(virConnectCredType),
};


static int
qemuMigrationSrcPerformPeer2Peer(virQEMUDriver *driver,
                                 virConnectPtr sconn,
                                 virDomainObj *vm,
                                 const char *xmlin,
                                 const char *persist_xml,
                                 const char *dconnuri,
                                 const char *uri,
                                 const char *graphicsuri,
                                 const char *listenAddress,
                                 size_t nmigrate_disks,
                                 const char **migrate_disks,
                                 int nbdPort,
                                 const char *nbdURI,
                                 qemuMigrationParams *migParams,
                                 unsigned int flags,
                                 const char *dname,
                                 unsigned long resource,
                                 bool *v3proto)
{
    int ret = -1;
    g_autoptr(virConnect) dconn = NULL;
    int p2p;
    virErrorPtr orig_err = NULL;
    bool offline = !!(flags & VIR_MIGRATE_OFFLINE);
    int dstOffline = 0;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    int useParams;
    int rc;

    VIR_DEBUG("driver=%p, sconn=%p, vm=%p, xmlin=%s, dconnuri=%s, uri=%s, "
              "graphicsuri=%s, listenAddress=%s, nmigrate_disks=%zu, "
              "migrate_disks=%p, nbdPort=%d, nbdURI=%s, flags=0x%x, "
              "dname=%s, resource=%lu",
              driver, sconn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, NULLSTR(nbdURI),
              flags, NULLSTR(dname), resource);

    if (flags & VIR_MIGRATE_TUNNELLED && uri) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("migration URI is not supported by tunnelled migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && listenAddress) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("listen address is not supported by tunnelled migration"));
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_TUNNELLED && nbdPort) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("disk port address is not supported by tunnelled migration"));
        goto cleanup;
    }

    /* the order of operations is important here; we make sure the
     * destination side is completely setup before we touch the source
     */

    qemuDomainObjEnterRemote(vm);
    dconn = virConnectOpenAuth(dconnuri, &virConnectAuthConfig, 0);
    if (qemuDomainObjExitRemote(vm, !offline) < 0)
        goto cleanup;

    if (dconn == NULL) {
        return -1;
    }

    if (virConnectSetKeepAlive(dconn, cfg->keepAliveInterval,
                               cfg->keepAliveCount) < 0)
        goto cleanup;

    if (virConnectRegisterCloseCallback(dconn, qemuMigrationSrcConnectionClosed,
                                        vm, NULL) < 0) {
        goto cleanup;
    }

    qemuDomainObjEnterRemote(vm);
    p2p = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                   VIR_DRV_FEATURE_MIGRATION_P2P);
    if (p2p < 0)
        goto cleanup;
    /* v3proto reflects whether the caller used Perform3, but with
     * p2p migrate, regardless of whether Perform2 or Perform3
     * were used, we decide protocol based on what target supports
     */
    rc = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                  VIR_DRV_FEATURE_MIGRATION_V3);
    if (rc < 0)
        goto cleanup;
    *v3proto = !!rc;
    useParams = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                         VIR_DRV_FEATURE_MIGRATION_PARAMS);
    if (useParams < 0)
        goto cleanup;
    if (offline) {
        dstOffline = VIR_DRV_SUPPORTS_FEATURE(dconn->driver, dconn,
                                              VIR_DRV_FEATURE_MIGRATION_OFFLINE);
        if (dstOffline < 0)
            goto cleanup;
    }
    if (qemuDomainObjExitRemote(vm, !offline) < 0)
        goto cleanup;

    if (!p2p) {
        virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                       _("Destination libvirt does not support peer-to-peer migration protocol"));
        goto cleanup;
    }

    /* Only xmlin, dname, uri, and bandwidth parameters can be used with
     * old-style APIs. */
    if (!useParams && (graphicsuri || listenAddress || nmigrate_disks)) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("Migration APIs with extensible parameters are not supported but extended parameters were passed"));
        goto cleanup;
    }

    if (offline && !dstOffline) {
        virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                       _("offline migration is not supported by the destination host"));
        goto cleanup;
    }

    /* Change protection is only required on the source side (us), and
     * only for v3 migration when begin and perform are separate jobs.
     * But peer-2-peer is already a single job, and we still want to
     * talk to older destinations that would reject the flag.
     * Therefore it is safe to clear the bit here.  */
    flags &= ~VIR_MIGRATE_CHANGE_PROTECTION;

    if (*v3proto) {
        ret = qemuMigrationSrcPerformPeer2Peer3(driver, sconn, dconn, dconnuri, vm, xmlin,
                                                persist_xml, dname, uri, graphicsuri,
                                                listenAddress, nmigrate_disks, migrate_disks,
                                                nbdPort, nbdURI, migParams, resource,
                                                !!useParams, flags);
    } else {
        ret = qemuMigrationSrcPerformPeer2Peer2(driver, sconn, dconn, vm,
                                                dconnuri, flags, dname, resource,
                                                migParams);
    }

 cleanup:
    virErrorPreserveLast(&orig_err);
    if (dconn && virConnectIsAlive(dconn) == 1) {
        qemuDomainObjEnterRemote(vm);
        virConnectUnregisterCloseCallback(dconn, qemuMigrationSrcConnectionClosed);
        ignore_value(qemuDomainObjExitRemote(vm, false));
    }
    virErrorRestore(&orig_err);
    return ret;
}


/*
 * This implements perform part of the migration protocol when migration job
 * does not need to be active across several APIs, i.e., peer2peer migration or
 * perform phase of v2 non-peer2peer migration.
 */
static int
qemuMigrationSrcPerformJob(virQEMUDriver *driver,
                           virConnectPtr conn,
                           virDomainObj *vm,
                           const char *xmlin,
                           const char *persist_xml,
                           const char *dconnuri,
                           const char *uri,
                           const char *graphicsuri,
                           const char *listenAddress,
                           size_t nmigrate_disks,
                           const char **migrate_disks,
                           int nbdPort,
                           const char *nbdURI,
                           qemuMigrationParams *migParams,
                           const char *cookiein,
                           int cookieinlen,
                           char **cookieout,
                           int *cookieoutlen,
                           unsigned int flags,
                           const char *dname,
                           unsigned long resource,
                           bool v3proto)
{
    virObjectEvent *event = NULL;
    int ret = -1;
    virErrorPtr orig_err = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags,
                                       QEMU_MIGRATION_PHASE_POSTCOPY_FAILED))
            goto cleanup;

        if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_BEGIN_RESUME) < 0)
            goto cleanup;

        virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);
        qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);
    } else {
        if (qemuMigrationJobStart(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                  flags) < 0)
            goto cleanup;

        if (!(flags & VIR_MIGRATE_OFFLINE) && virDomainObjCheckActive(vm) < 0)
            goto endjob;

        if (!qemuMigrationSrcIsAllowed(vm, true, VIR_ASYNC_JOB_MIGRATION_OUT, flags))
            goto endjob;

        if (!(flags & (VIR_MIGRATE_UNSAFE | VIR_MIGRATE_OFFLINE)) &&
            !qemuMigrationSrcIsSafe(vm->def, priv->qemuCaps,
                                    nmigrate_disks, migrate_disks, flags))
            goto endjob;

        qemuMigrationSrcStoreDomainState(vm);
    }

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        ret = qemuMigrationSrcPerformPeer2Peer(driver, conn, vm, xmlin, persist_xml,
                                               dconnuri, uri, graphicsuri, listenAddress,
                                               nmigrate_disks, migrate_disks, nbdPort,
                                               nbdURI,
                                               migParams, flags, dname, resource,
                                               &v3proto);
    } else {
        if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PERFORM2) < 0)
            goto endjob;

        ret = qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                                            cookieout, cookieoutlen,
                                            flags, resource, NULL, NULL, 0, NULL,
                                            migParams, nbdURI);
    }
    if (ret < 0)
        goto endjob;

    /*
     * In v3 protocol, the source VM is not killed off until the
     * confirm step.
     */
    if (!v3proto) {
        qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_MIGRATED,
                        VIR_ASYNC_JOB_MIGRATION_OUT,
                        VIR_QEMU_PROCESS_STOP_MIGRATED);
        virDomainAuditStop(vm, "migrated");
        event = virDomainEventLifecycleNewFromObj(vm,
                                         VIR_DOMAIN_EVENT_STOPPED,
                                         VIR_DOMAIN_EVENT_STOPPED_MIGRATED);
    }

 endjob:
    if (ret < 0)
        virErrorPreserveLast(&orig_err);

    if (virDomainObjIsFailedPostcopy(vm, vm->job)) {
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));
        qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    } else {
        /* v2 proto has no confirm phase so we need to reset migration parameters
         * here
         */
        if (!v3proto && ret < 0)
            qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                     jobPriv->migParams, vm->job->apiFlags);

        qemuMigrationSrcRestoreDomainState(driver, vm);

        qemuMigrationJobFinish(vm);
    }

    if (!virDomainObjIsActive(vm) && ret == 0) {
        if (flags & VIR_MIGRATE_UNDEFINE_SOURCE) {
            virDomainDeleteConfig(cfg->configDir, cfg->autostartDir, vm);
            vm->persistent = 0;
        }
        qemuDomainRemoveInactive(driver, vm, 0, true);
    }

    virErrorRestore(&orig_err);

 cleanup:
    virObjectEventStateQueue(driver->domainEventState, event);
    return ret;
}


/*
 * This implements perform phase of v3 migration protocol.
 */
static int
qemuMigrationSrcPerformPhase(virQEMUDriver *driver,
                             virConnectPtr conn,
                             virDomainObj *vm,
                             const char *persist_xml,
                             const char *uri,
                             const char *graphicsuri,
                             size_t nmigrate_disks,
                             const char **migrate_disks,
                             qemuMigrationParams *migParams,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned int flags,
                             unsigned long resource,
                             const char *nbdURI)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    int ret = -1;

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        return qemuMigrationSrcPerformResume(driver, conn, vm, uri, migParams,
                                             cookiein, cookieinlen,
                                             cookieout, cookieoutlen, flags);
    }

    /* If we didn't start the job in the begin phase, start it now. */
    if (!(flags & VIR_MIGRATE_CHANGE_PROTECTION)) {
        if (qemuMigrationJobStart(vm, VIR_ASYNC_JOB_MIGRATION_OUT, flags) < 0)
            return ret;
    } else if (!qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_OUT)) {
        return ret;
    }

    if (qemuMigrationJobStartPhase(vm, QEMU_MIGRATION_PHASE_PERFORM3) < 0)
        goto cleanup;

    virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);

    if (qemuMigrationSrcPerformNative(driver, vm, persist_xml, uri, cookiein, cookieinlen,
                                      cookieout, cookieoutlen,
                                      flags, resource, NULL, graphicsuri,
                                      nmigrate_disks, migrate_disks, migParams, nbdURI) < 0)
        goto cleanup;

    virCloseCallbacksDomainAdd(vm, conn, qemuMigrationAnyConnectionClosed);

    ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_PERFORM3_DONE));
    ret = 0;

 cleanup:
    if (ret < 0 && !virDomainObjIsFailedPostcopy(vm, vm->job)) {
        qemuMigrationSrcRestoreDomainState(driver, vm);
        qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                 jobPriv->migParams, vm->job->apiFlags);
        qemuDomainSetMaxMemLock(vm, 0, &priv->preMigrationMemlock);
        qemuMigrationJobFinish(vm);
    } else {
        if (ret < 0)
            ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));
        qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    }

    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm, 0, true);

    return ret;
}

int
qemuMigrationSrcPerform(virQEMUDriver *driver,
                        virConnectPtr conn,
                        virDomainObj *vm,
                        const char *xmlin,
                        const char *persist_xml,
                        const char *dconnuri,
                        const char *uri,
                        const char *graphicsuri,
                        const char *listenAddress,
                        size_t nmigrate_disks,
                        const char **migrate_disks,
                        int nbdPort,
                        const char *nbdURI,
                        qemuMigrationParams *migParams,
                        const char *cookiein,
                        int cookieinlen,
                        char **cookieout,
                        int *cookieoutlen,
                        unsigned int flags,
                        const char *dname,
                        unsigned long resource,
                        bool v3proto)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    VIR_DEBUG("driver=%p, conn=%p, vm=%p, xmlin=%s, dconnuri=%s, "
              "uri=%s, graphicsuri=%s, listenAddress=%s, "
              "nmigrate_disks=%zu, migrate_disks=%p, nbdPort=%d, "
              "nbdURI=%s, "
              "cookiein=%s, cookieinlen=%d, cookieout=%p, cookieoutlen=%p, "
              "flags=0x%x, dname=%s, resource=%lu, v3proto=%d",
              driver, conn, vm, NULLSTR(xmlin), NULLSTR(dconnuri),
              NULLSTR(uri), NULLSTR(graphicsuri), NULLSTR(listenAddress),
              nmigrate_disks, migrate_disks, nbdPort, NULLSTR(nbdURI),
              NULLSTR(cookiein), cookieinlen, cookieout, cookieoutlen,
              flags, NULLSTR(dname), resource, v3proto);

    if (cfg->migrateTLSForce &&
        !(flags & VIR_MIGRATE_TUNNELLED) &&
        !(flags & VIR_MIGRATE_TLS)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("this libvirtd instance allows migration only with VIR_MIGRATE_TLS flag"));
        return -1;
    }

    if ((flags & (VIR_MIGRATE_TUNNELLED | VIR_MIGRATE_PEER2PEER))) {
        if (cookieinlen) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           "%s", _("received unexpected cookie with P2P migration"));
            return -1;
        }

        return qemuMigrationSrcPerformJob(driver, conn, vm, xmlin, persist_xml, dconnuri, uri,
                                          graphicsuri, listenAddress,
                                          nmigrate_disks, migrate_disks, nbdPort,
                                          nbdURI, migParams,
                                          cookiein, cookieinlen,
                                          cookieout, cookieoutlen,
                                          flags, dname, resource, v3proto);
    }

    if (dconnuri) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Unexpected dconnuri parameter with non-peer2peer migration"));
        return -1;
    }

    if (v3proto) {
        return qemuMigrationSrcPerformPhase(driver, conn, vm, persist_xml, uri,
                                            graphicsuri,
                                            nmigrate_disks, migrate_disks,
                                            migParams,
                                            cookiein, cookieinlen,
                                            cookieout, cookieoutlen,
                                            flags, resource, nbdURI);
    }

    return qemuMigrationSrcPerformJob(driver, conn, vm, xmlin, persist_xml, NULL,
                                      uri, graphicsuri, listenAddress,
                                      nmigrate_disks, migrate_disks, nbdPort,
                                      nbdURI, migParams,
                                      cookiein, cookieinlen,
                                      cookieout, cookieoutlen, flags,
                                      dname, resource, v3proto);
}

static int
qemuMigrationDstVPAssociatePortProfiles(virDomainDef *def)
{
    size_t i;
    int last_good_net = -1;
    virDomainNetDef *net;

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
                               _("Port profile Associate failed for %1$s"),
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
qemuMigrationDstPersist(virQEMUDriver *driver,
                        virDomainObj *vm,
                        qemuMigrationCookie *mig,
                        bool ignoreSaveError)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDef *vmdef;
    g_autoptr(virDomainDef) oldDef = NULL;
    unsigned int oldPersist = vm->persistent;
    virObjectEvent *event;
    virDomainEventDefinedDetailType eventDetail = VIR_DOMAIN_EVENT_DEFINED_UPDATED;

    vm->persistent = 1;
    oldDef = vm->newDef;
    vm->newDef = qemuMigrationCookieGetPersistent(mig);

    if (!(vmdef = virDomainObjGetPersistentDef(driver->xmlopt, vm,
                                               priv->qemuCaps)))
        goto error;

    if (!oldPersist) {
        eventDetail = VIR_DOMAIN_EVENT_DEFINED_ADDED;

        if (qemuDomainNamePathsCleanup(cfg, vmdef->name, false) < 0)
            goto error;
    }

    if (virDomainDefSave(vmdef, driver->xmlopt, cfg->configDir) < 0 &&
        !ignoreSaveError)
        goto error;

    event = virDomainEventLifecycleNewFromObj(vm, VIR_DOMAIN_EVENT_DEFINED,
                                              eventDetail);
    virObjectEventStateQueue(driver->domainEventState, event);

    return 0;

 error:
    virDomainDefFree(vm->newDef);
    vm->persistent = oldPersist;
    vm->newDef = g_steal_pointer(&oldDef);
    return -1;
}


void
qemuMigrationDstComplete(virQEMUDriver *driver,
                         virDomainObj *vm,
                         bool inPostCopy,
                         virDomainAsyncJob asyncJob,
                         virDomainJobObj *job)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = job->privateData;
    virObjectEvent *event;

    if (inPostCopy) {
        if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_RUNNING) {
            virDomainObjSetState(vm,
                                 VIR_DOMAIN_RUNNING,
                                 VIR_DOMAIN_RUNNING_MIGRATED);
        }

        /* The only RESUME event during post-copy migration is triggered by
         * QEMU when the running domain moves from the source to the
         * destination host, but then the migration keeps running until all
         * modified memory is transferred from the source host. This will
         * result in VIR_DOMAIN_EVENT_RESUMED with RESUMED_POSTCOPY detail.
         * However, our API documentation says we need to fire another RESUMED
         * event at the very end of migration with RESUMED_MIGRATED detail.
         */
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_RESUMED,
                                                  VIR_DOMAIN_EVENT_RESUMED_MIGRATED);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    if (virDomainObjGetState(vm, NULL) == VIR_DOMAIN_PAUSED) {
        virDomainObjSetState(vm, VIR_DOMAIN_PAUSED, VIR_DOMAIN_PAUSED_USER);
        event = virDomainEventLifecycleNewFromObj(vm,
                                                  VIR_DOMAIN_EVENT_SUSPENDED,
                                                  VIR_DOMAIN_EVENT_SUSPENDED_PAUSED);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    qemuDomainSaveStatus(vm);

    /* Guest is successfully running, so cancel previous auto destroy. There's
     * nothing to remove when we are resuming post-copy migration.
     */
    if (job->phase < QEMU_MIGRATION_PHASE_POSTCOPY_FAILED)
        virCloseCallbacksDomainRemove(vm, NULL, qemuProcessAutoDestroy);

    /* Remove completed stats for post-copy, everything but timing fields
     * is obsolete anyway.
     */
    if (inPostCopy)
        g_clear_pointer(&job->completed, virDomainJobDataFree);

    qemuMigrationParamsReset(vm, asyncJob, jobPriv->migParams,
                             job->apiFlags);

    virPortAllocatorRelease(priv->migrationPort);
    priv->migrationPort = 0;
    qemuDomainSetMaxMemLock(vm, 0, &priv->preMigrationMemlock);
}


static virDomainPtr
qemuMigrationDstFinishOffline(virQEMUDriver *driver,
                              virConnectPtr dconn,
                              virDomainObj *vm,
                              int cookie_flags,
                              const char *cookiein,
                              int cookieinlen,
                              char **cookieout,
                              int *cookieoutlen)
{
    virDomainPtr dom = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(qemuMigrationCookie) mig = NULL;

    if (!(mig = qemuMigrationCookieParse(driver, vm, vm->def, priv->origname,
                                         priv->qemuCaps,
                                         cookiein, cookieinlen, cookie_flags)))
        return NULL;

    if (qemuMigrationDstPersist(driver, vm, mig, false) < 0)
        return NULL;

    dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, -1);

    if (dom &&
        qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_DESTINATION,
                                  cookieout, cookieoutlen,
                                  QEMU_MIGRATION_COOKIE_STATS) < 0)
        VIR_WARN("Unable to encode migration cookie");

    return dom;
}


/*
 * Perform Finish phase of a fresh (i.e., not recovery) migration of an active
 * domain.
 */
static int
qemuMigrationDstFinishFresh(virQEMUDriver *driver,
                            virDomainObj *vm,
                            qemuMigrationCookie *mig,
                            unsigned int flags,
                            bool v3proto,
                            unsigned long long timeReceived,
                            bool *doKill,
                            bool *inPostCopy)
{
    g_autoptr(virDomainJobData) jobData = NULL;

    if (qemuMigrationDstVPAssociatePortProfiles(vm->def) < 0)
        return -1;

    if (mig->network && qemuMigrationDstOPDRelocate(driver, vm, mig) < 0)
        VIR_WARN("unable to provide network data for relocation");

    if (qemuMigrationDstStopNBDServer(vm, mig) < 0)
        return -1;

    if (qemuRefreshVirtioChannelState(driver, vm,
                                      VIR_ASYNC_JOB_MIGRATION_IN) < 0)
        return -1;

    if (qemuConnectAgent(driver, vm) < 0)
        return -1;

    if (flags & VIR_MIGRATE_PERSIST_DEST) {
        if (qemuMigrationDstPersist(driver, vm, mig, !v3proto) < 0) {
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
                return -1;
        }
    }

    /* We need to wait for QEMU to process all data sent by the source
     * before starting guest CPUs.
     */
    if (qemuMigrationDstWaitForCompletion(vm,
                                          VIR_ASYNC_JOB_MIGRATION_IN,
                                          !!(flags & VIR_MIGRATE_POSTCOPY)) < 0) {
        /* There's not much we can do for v2 protocol since the
         * original domain on the source host is already gone.
         */
        if (v3proto)
            return -1;
    }

    /* Now that the state data was transferred we can refresh the actual state
     * of the devices */
    if (qemuProcessRefreshState(driver, vm, VIR_ASYNC_JOB_MIGRATION_IN) < 0) {
        /* Similarly to the case above v2 protocol will not be able to recover
         * from this. Let's ignore this and perhaps stuff will not break. */
        if (v3proto)
            return -1;
    }

    if (vm->job->current->status == VIR_DOMAIN_JOB_STATUS_POSTCOPY)
        *inPostCopy = true;

    if (!(flags & VIR_MIGRATE_PAUSED)) {
        virDomainRunningReason runningReason = VIR_DOMAIN_RUNNING_MIGRATED;

        if (*inPostCopy)
            runningReason = VIR_DOMAIN_RUNNING_POSTCOPY;

        if (qemuProcessStartCPUs(driver, vm, runningReason,
                                 VIR_ASYNC_JOB_MIGRATION_IN) < 0) {
            if (virGetLastErrorCode() == VIR_ERR_OK)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               "%s", _("resume operation failed"));
            /*
             * In v3 protocol, the source VM is still available to
             * restart during confirm() step, so we kill it off
             * now.
             * In v2 protocol, the source is dead, so we leave
             * target in paused state, in case admin can fix
             * things up.
             */
            if (v3proto)
                return -1;
        }

        if (*inPostCopy)
            *doKill = false;
    }

    if (mig->jobData) {
        jobData = g_steal_pointer(&mig->jobData);

        if (jobData->sent && timeReceived) {
            jobData->timeDelta = timeReceived - jobData->sent;
            jobData->received = timeReceived;
            jobData->timeDeltaSet = true;
        }
        qemuDomainJobDataUpdateTime(jobData);
        qemuDomainJobDataUpdateDowntime(jobData);
    }

    if (*inPostCopy &&
        qemuMigrationDstWaitForCompletion(vm,
                                          VIR_ASYNC_JOB_MIGRATION_IN,
                                          false) < 0) {
        return -1;
    }

    if (jobData) {
        vm->job->completed = g_steal_pointer(&jobData);
        vm->job->completed->status = VIR_DOMAIN_JOB_STATUS_COMPLETED;
        qemuDomainJobSetStatsType(vm->job->completed,
                                  QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION);
    }

    return 0;
}


static int
qemuMigrationDstFinishResume(virDomainObj *vm)
{
    VIR_DEBUG("vm=%p", vm);

    if (qemuMigrationDstWaitForCompletion(vm,
                                          VIR_ASYNC_JOB_MIGRATION_IN,
                                          false) < 0) {
        return -1;
    }

    return 0;
}


static virDomainPtr
qemuMigrationDstFinishActive(virQEMUDriver *driver,
                             virConnectPtr dconn,
                             virDomainObj *vm,
                             int cookie_flags,
                             const char *cookiein,
                             int cookieinlen,
                             char **cookieout,
                             int *cookieoutlen,
                             unsigned int flags,
                             int retcode,
                             bool v3proto,
                             unsigned long long timeReceived,
                             bool *finishJob)
{
    virErrorPtr orig_err = NULL;
    virDomainPtr dom = NULL;
    g_autoptr(qemuMigrationCookie) mig = NULL;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobPrivate *jobPriv = vm->job->privateData;
    virObjectEvent *event;
    bool inPostCopy = false;
    bool doKill = vm->job->phase != QEMU_MIGRATION_PHASE_FINISH_RESUME;
    int rc;

    VIR_DEBUG("vm=%p, flags=0x%x, retcode=%d",
              vm, flags, retcode);

    if (!(mig = qemuMigrationCookieParse(driver, vm, vm->def, priv->origname,
                                         priv->qemuCaps,
                                         cookiein, cookieinlen, cookie_flags)))
        goto error;

    if (retcode != 0) {
        /* Check for a possible error on the monitor in case Finish was called
         * earlier than monitor EOF handler got a chance to process the error
         */
        qemuDomainCheckMonitor(vm, VIR_ASYNC_JOB_MIGRATION_IN);
        goto error;
    }

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        qemuMigrationDstErrorReport(driver, vm->def->name);
        goto error;
    }

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        rc = qemuMigrationDstFinishResume(vm);
        inPostCopy = true;
    } else {
        rc = qemuMigrationDstFinishFresh(driver, vm, mig, flags, v3proto,
                                         timeReceived, &doKill, &inPostCopy);
    }

    if (rc < 0 ||
        !(dom = virGetDomain(dconn, vm->def->name, vm->def->uuid, vm->def->id)))
        goto error;

    if (qemuMigrationCookieFormat(mig, driver, vm,
                                  QEMU_MIGRATION_DESTINATION,
                                  cookieout, cookieoutlen,
                                  QEMU_MIGRATION_COOKIE_STATS) < 0)
        VIR_WARN("Unable to encode migration cookie");

    qemuMigrationDstComplete(driver, vm, inPostCopy,
                             VIR_ASYNC_JOB_MIGRATION_IN, vm->job);

    return dom;

 error:
    /* Need to save the current error, in case shutting down the process
     * overwrites it. */
    virErrorPreserveLast(&orig_err);

    if (virDomainObjIsActive(vm)) {
        if (doKill) {
            qemuProcessStop(driver, vm, VIR_DOMAIN_SHUTOFF_FAILED,
                            VIR_ASYNC_JOB_MIGRATION_IN,
                            VIR_QEMU_PROCESS_STOP_MIGRATED);
            virDomainAuditStop(vm, "failed");
            event = virDomainEventLifecycleNewFromObj(vm,
                                VIR_DOMAIN_EVENT_STOPPED,
                                VIR_DOMAIN_EVENT_STOPPED_FAILED);
            virObjectEventStateQueue(driver->domainEventState, event);
        } else {
            qemuMigrationDstPostcopyFailed(vm);
        }
    }

    if (virDomainObjIsFailedPostcopy(vm, vm->job)) {
        ignore_value(qemuMigrationJobSetPhase(vm, QEMU_MIGRATION_PHASE_POSTCOPY_FAILED));
        virCloseCallbacksDomainRemove(vm, NULL, qemuProcessAutoDestroy);
        *finishJob = false;
    } else {
        qemuMigrationParamsReset(vm, VIR_ASYNC_JOB_MIGRATION_IN,
                                 jobPriv->migParams, vm->job->apiFlags);
    }

    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm, VIR_DOMAIN_UNDEFINE_TPM, false);

    virErrorRestore(&orig_err);
    return NULL;
}


virDomainPtr
qemuMigrationDstFinish(virQEMUDriver *driver,
                       virConnectPtr dconn,
                       virDomainObj *vm,
                       const char *cookiein,
                       int cookieinlen,
                       char **cookieout,
                       int *cookieoutlen,
                       unsigned int flags,
                       int retcode,
                       bool v3proto)
{
    virDomainPtr dom = NULL;
    int cookie_flags = 0;
    qemuDomainObjPrivate *priv = vm->privateData;
    unsigned short port;
    unsigned long long timeReceived = 0;
    int phase = v3proto ? QEMU_MIGRATION_PHASE_FINISH3
                        : QEMU_MIGRATION_PHASE_FINISH2;

    VIR_DEBUG("driver=%p, dconn=%p, vm=%p, cookiein=%s, cookieinlen=%d, "
              "cookieout=%p, cookieoutlen=%p, flags=0x%x, retcode=%d",
              driver, dconn, vm, NULLSTR(cookiein), cookieinlen,
              cookieout, cookieoutlen, flags, retcode);

    port = priv->migrationPort;
    priv->migrationPort = 0;

    if (!qemuMigrationJobIsActive(vm, VIR_ASYNC_JOB_MIGRATION_IN)) {
        qemuMigrationDstErrorReport(driver, vm->def->name);
        goto cleanup;
    }

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        if (!qemuMigrationAnyCanResume(vm, VIR_ASYNC_JOB_MIGRATION_IN, flags,
                                       QEMU_MIGRATION_PHASE_PREPARE_RESUME))
            goto cleanup;
        phase = QEMU_MIGRATION_PHASE_FINISH_RESUME;
    }
    ignore_value(virTimeMillisNow(&timeReceived));

    if (qemuMigrationJobStartPhase(vm, phase) < 0)
        goto cleanup;

    if (flags & VIR_MIGRATE_POSTCOPY_RESUME) {
        virCloseCallbacksDomainRemove(vm, NULL, qemuMigrationAnyConnectionClosed);
        qemuDomainCleanupRemove(vm, qemuProcessCleanupMigrationJob);
    } else {
        qemuDomainCleanupRemove(vm, qemuMigrationDstPrepareCleanup);
    }
    g_clear_pointer(&vm->job->completed, virDomainJobDataFree);

    cookie_flags = QEMU_MIGRATION_COOKIE_NETWORK |
                   QEMU_MIGRATION_COOKIE_STATS |
                   QEMU_MIGRATION_COOKIE_NBD;
    /* Some older versions of libvirt always send persistent XML in the cookie
     * even though VIR_MIGRATE_PERSIST_DEST was not used. */
    cookie_flags |= QEMU_MIGRATION_COOKIE_PERSISTENT;

    if (flags & VIR_MIGRATE_OFFLINE) {
        if (retcode == 0) {
            dom = qemuMigrationDstFinishOffline(driver, dconn, vm,
                                                cookie_flags,
                                                cookiein, cookieinlen,
                                                cookieout, cookieoutlen);
        }
        qemuMigrationJobFinish(vm);
    } else {
        bool finishJob = true;

        dom = qemuMigrationDstFinishActive(driver, dconn, vm, cookie_flags,
                                           cookiein, cookieinlen,
                                           cookieout, cookieoutlen,
                                           flags, retcode, v3proto, timeReceived,
                                           &finishJob);
        if (finishJob)
            qemuMigrationJobFinish(vm);
        else
            qemuMigrationJobContinue(vm, qemuProcessCleanupMigrationJob);
    }

 cleanup:
    virPortAllocatorRelease(port);
    if (priv->mon)
        qemuMonitorSetDomainLog(priv->mon, NULL, NULL, NULL);
    VIR_FREE(priv->origname);
    virDomainObjEndAPI(&vm);

    /* Set a special error if Finish is expected to return NULL as a result of
     * successful call with retcode != 0
     */
    if (retcode != 0 && !dom && virGetLastErrorCode() == VIR_ERR_OK)
        virReportError(VIR_ERR_MIGRATE_FINISH_OK, NULL);
    return dom;
}


void
qemuMigrationProcessUnattended(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainAsyncJob job,
                               qemuMonitorMigrationStatus status)
{
    qemuMigrationJobPhase phase;

    if (!qemuMigrationJobIsActive(vm, job) ||
        status != QEMU_MONITOR_MIGRATION_STATUS_COMPLETED)
        return;

    VIR_DEBUG("Unattended %s migration of domain %s successfully finished",
              job == VIR_ASYNC_JOB_MIGRATION_IN ? "incoming" : "outgoing",
              vm->def->name);

    if (job == VIR_ASYNC_JOB_MIGRATION_IN)
        phase = QEMU_MIGRATION_PHASE_FINISH_RESUME;
    else
        phase = QEMU_MIGRATION_PHASE_CONFIRM_RESUME;

    if (qemuMigrationJobStartPhase(vm, phase) < 0)
        return;

    if (job == VIR_ASYNC_JOB_MIGRATION_IN)
        qemuMigrationDstComplete(driver, vm, true, job, vm->job);
    else
        qemuMigrationSrcComplete(driver, vm, job);

    qemuMigrationJobFinish(vm);

    if (!virDomainObjIsActive(vm))
        qemuDomainRemoveInactive(driver, vm, 0, false);
}


/* Helper function called while vm is active.  */
int
qemuMigrationSrcToFile(virQEMUDriver *driver, virDomainObj *vm,
                       int fd,
                       virCommand *compressor,
                       virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    int rc;
    int ret = -1;
    int pipeFD[2] = { -1, -1 };
    unsigned long saveMigBandwidth = priv->migMaxBandwidth;
    char *errbuf = NULL;
    virErrorPtr orig_err = NULL;
    g_autoptr(qemuMigrationParams) migParams = NULL;

    if (qemuMigrationSetDBusVMState(driver, vm) < 0)
        return -1;

    /* Increase migration bandwidth to unlimited since target is a file.
     * Failure to change migration speed is not fatal. */
    if (!(migParams = qemuMigrationParamsNew()))
        return -1;

    if (qemuMigrationParamsSetULL(migParams,
                                  QEMU_MIGRATION_PARAM_MAX_BANDWIDTH,
                                  QEMU_DOMAIN_MIG_BANDWIDTH_MAX * 1024 * 1024) < 0)
        return -1;

    if (qemuMigrationParamsApply(vm, asyncJob, migParams, 0) < 0)
        return -1;

    priv->migMaxBandwidth = QEMU_DOMAIN_MIG_BANDWIDTH_MAX;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("guest unexpectedly quit"));
        /* nothing to tear down */
        return -1;
    }

    if (compressor && virPipe(pipeFD) < 0)
        return -1;

    /* All right! We can use fd migration, which means that qemu
     * doesn't have to open() the file, so while we still have to
     * grant SELinux access, we can do it on fd and avoid cleanup
     * later, as well as skip futzing with cgroup.  */
    if (qemuSecuritySetImageFDLabel(driver->securityManager, vm->def,
                                    compressor ? pipeFD[1] : fd) < 0)
        goto cleanup;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    if (!compressor) {
        rc = qemuMonitorMigrateToFd(priv->mon, 0, fd);
    } else {
        virCommandSetInputFD(compressor, pipeFD[0]);
        virCommandSetOutputFD(compressor, &fd);
        virCommandSetErrorBuffer(compressor, &errbuf);
        virCommandDoAsyncIO(compressor);
        if (virSetCloseExec(pipeFD[1]) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to set cloexec flag"));
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
        if (virCommandRunAsync(compressor, NULL) < 0) {
            qemuDomainObjExitMonitor(vm);
            goto cleanup;
        }
        rc = qemuMonitorMigrateToFd(priv->mon, 0, pipeFD[1]);
        if (VIR_CLOSE(pipeFD[0]) < 0 ||
            VIR_CLOSE(pipeFD[1]) < 0)
            VIR_WARN("failed to close intermediate pipe");
    }
    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    rc = qemuMigrationSrcWaitForCompletion(vm, asyncJob, NULL, 0);

    if (rc < 0) {
        if (rc == -2) {
            virErrorPreserveLast(&orig_err);
            virCommandAbort(compressor);
            if (virDomainObjIsActive(vm))
                qemuMigrationSrcCancel(vm, asyncJob, true);
        }
        goto cleanup;
    }

    if (compressor && virCommandWait(compressor, NULL) < 0)
        goto cleanup;

    qemuDomainEventEmitJobCompleted(driver, vm);
    ret = 0;

 cleanup:
    if (ret < 0 && !orig_err)
        virErrorPreserveLast(&orig_err);

    /* Restore max migration bandwidth */
    if (virDomainObjIsActive(vm)) {
        if (qemuMigrationParamsSetULL(migParams,
                                      QEMU_MIGRATION_PARAM_MAX_BANDWIDTH,
                                      saveMigBandwidth * 1024 * 1024) == 0)
            ignore_value(qemuMigrationParamsApply(vm, asyncJob,
                                                  migParams, 0));
        priv->migMaxBandwidth = saveMigBandwidth;
    }

    VIR_FORCE_CLOSE(pipeFD[0]);
    VIR_FORCE_CLOSE(pipeFD[1]);
    if (errbuf) {
        VIR_DEBUG("Compression binary stderr: %s", NULLSTR(errbuf));
        VIR_FREE(errbuf);
    }

    virErrorRestore(&orig_err);

    return ret;
}


/**
 * This function is supposed to be used only to while reconnecting to a domain
 * with an active migration job.
 */
int
qemuMigrationSrcCancelUnattended(virDomainObj *vm,
                                 virDomainJobObj *oldJob)
{
    bool storage = false;
    size_t i;

    VIR_DEBUG("Canceling unfinished outgoing migration of domain %s",
              vm->def->name);

    /* Make sure MIGRATION event handler can store the current migration state
     * in the job.
     */
    if (!vm->job->current) {
        qemuDomainObjRestoreAsyncJob(vm, VIR_ASYNC_JOB_MIGRATION_OUT,
                                     oldJob->phase, oldJob->asyncStarted,
                                     VIR_DOMAIN_JOB_OPERATION_MIGRATION_OUT,
                                     QEMU_DOMAIN_JOB_STATS_TYPE_MIGRATION,
                                     VIR_DOMAIN_JOB_STATUS_FAILED,
                                     VIR_JOB_NONE);
    }

    /* We're inside a MODIFY job and the restored MIGRATION_OUT async job is
     * used only for processing migration events from QEMU. Thus we don't want
     * to start a nested job for talking to QEMU.
     */
    qemuMigrationSrcCancel(vm, VIR_ASYNC_JOB_NONE, true);

    virDomainObjEndAsyncJob(vm);

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        qemuBlockJobData *job;

        if (!(job = qemuBlockJobDiskGetJob(disk)) ||
            !qemuBlockJobIsRunning(job))
            diskPriv->migrating = false;

        if (diskPriv->migrating) {
            qemuBlockJobSyncBegin(job);
            storage = true;
        }

        virObjectUnref(job);
    }

    if (storage &&
        qemuMigrationSrcNBDCopyCancel(vm, true,
                                      VIR_ASYNC_JOB_NONE, NULL) < 0)
        return -1;

    if (qemuMigrationSrcCancelRemoveTempBitmaps(vm, VIR_ASYNC_JOB_NONE) < 0)
        return -1;

    return 0;
}


static void
qemuMigrationDstErrorFree(void *data)
{
    virErrorPtr err = data;
    virFreeError(err);
}

int
qemuMigrationDstErrorInit(virQEMUDriver *driver)
{
    driver->migrationErrors = virHashAtomicNew(qemuMigrationDstErrorFree);
    if (driver->migrationErrors)
        return 0;

    return -1;
}

/**
 * This function consumes @err; the caller should consider the @err pointer
 * invalid after calling this function.
 */
void
qemuMigrationDstErrorSave(virQEMUDriver *driver,
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
qemuMigrationDstErrorReport(virQEMUDriver *driver,
                            const char *name)
{
    virErrorPtr err;

    if (!(err = virHashAtomicSteal(driver->migrationErrors, name)))
        return;

    VIR_DEBUG("Restoring saved incoming migration error for domain %s: %s",
              name, err->message);
    virErrorRestore(&err);
}


int
qemuMigrationSrcFetchMirrorStats(virDomainObj *vm,
                                 virDomainAsyncJob asyncJob,
                                 virDomainJobData *jobData)
{
    size_t i;
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainJobDataPrivate *privJob = jobData->privateData;
    bool nbd = false;
    g_autoptr(GHashTable) blockinfo = NULL;
    qemuDomainMirrorStats *stats = &privJob->mirrorStats;

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        if (QEMU_DOMAIN_DISK_PRIVATE(disk)->migrating) {
            nbd = true;
            break;
        }
    }

    if (!nbd)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    blockinfo = qemuMonitorGetAllBlockJobInfo(priv->mon, false);

    qemuDomainObjExitMonitor(vm);
    if (!blockinfo)
        return -1;

    memset(stats, 0, sizeof(*stats));

    for (i = 0; i < vm->def->ndisks; i++) {
        virDomainDiskDef *disk = vm->def->disks[i];
        qemuDomainDiskPrivate *diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
        qemuMonitorBlockJobInfo *data;

        if (!diskPriv->migrating ||
            !(data = virHashLookup(blockinfo, disk->info.alias)))
            continue;

        stats->transferred += data->cur;
        stats->total += data->end;
    }

    return 0;
}
