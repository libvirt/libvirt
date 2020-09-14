/*
 * qemu_backup.c: Implementation and handling of the backup jobs
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
 */

#include <config.h>

#include "qemu_alias.h"
#include "qemu_block.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_monitor.h"
#include "qemu_process.h"
#include "qemu_backup.h"
#include "qemu_monitor_json.h"
#include "qemu_checkpoint.h"
#include "qemu_command.h"

#include "virerror.h"
#include "virlog.h"
#include "virbuffer.h"
#include "viralloc.h"
#include "virxml.h"
#include "virstoragefile.h"
#include "virstring.h"
#include "backup_conf.h"
#include "virdomaincheckpointobjlist.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_backup");


static virDomainBackupDefPtr
qemuDomainGetBackup(virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!priv->backup) {
        virReportError(VIR_ERR_NO_DOMAIN_BACKUP, "%s",
                       _("no domain backup job present"));
        return NULL;
    }

    return priv->backup;
}


static int
qemuBackupPrepare(virDomainBackupDefPtr def)
{

    if (def->type == VIR_DOMAIN_BACKUP_TYPE_PULL) {
        if (!def->server) {
            def->server = g_new0(virStorageNetHostDef, 1);

            def->server->transport = VIR_STORAGE_NET_HOST_TRANS_TCP;
            def->server->name = g_strdup("localhost");
        }

        switch ((virStorageNetHostTransport) def->server->transport) {
        case VIR_STORAGE_NET_HOST_TRANS_TCP:
            /* TODO: Update qemu.conf to provide a port range,
             * probably starting at 10809, for obtaining automatic
             * port via virPortAllocatorAcquire, as well as store
             * somewhere if we need to call virPortAllocatorRelease
             * during BackupEnd. Until then, user must provide port */
            if (!def->server->port) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("<domainbackup> must specify TCP port for now"));
                return -1;
            }
            break;

        case VIR_STORAGE_NET_HOST_TRANS_UNIX:
            /* TODO: Do we need to mess with selinux? */
            break;

        case VIR_STORAGE_NET_HOST_TRANS_RDMA:
        case VIR_STORAGE_NET_HOST_TRANS_LAST:
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected transport in <domainbackup>"));
            return -1;
        }
    }

    return 0;
}


struct qemuBackupDiskData {
    virDomainBackupDiskDefPtr backupdisk;
    virDomainDiskDefPtr domdisk;
    qemuBlockJobDataPtr blockjob;
    virStorageSourcePtr store;
    virStorageSourcePtr terminator;
    virStorageSourcePtr backingStore;
    char *incrementalBitmap;
    qemuBlockStorageSourceChainDataPtr crdata;
    bool labelled;
    bool initialized;
    bool created;
    bool added;
    bool started;
    bool done;
};


static void
qemuBackupDiskDataCleanupOne(virDomainObjPtr vm,
                             struct qemuBackupDiskData *dd)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (!dd->started) {
        if (dd->added) {
            qemuDomainObjEnterMonitor(priv->driver, vm);
            qemuBlockStorageSourceAttachRollback(priv->mon, dd->crdata->srcdata[0]);
            ignore_value(qemuDomainObjExitMonitor(priv->driver, vm));
        }

        if (dd->created) {
            if (virStorageFileUnlink(dd->store) < 0)
                VIR_WARN("Unable to remove just-created %s", NULLSTR(dd->store->path));
        }

        if (dd->labelled)
            qemuDomainStorageSourceAccessRevoke(priv->driver, vm, dd->store);
    }

    if (dd->initialized)
        virStorageFileDeinit(dd->store);

    if (dd->blockjob)
        qemuBlockJobStartupFinalize(vm, dd->blockjob);

    qemuBlockStorageSourceChainDataFree(dd->crdata);
    virObjectUnref(dd->terminator);
    g_free(dd->incrementalBitmap);
}


static void
qemuBackupDiskDataCleanup(virDomainObjPtr vm,
                          struct qemuBackupDiskData *dd,
                          size_t ndd)
{
    virErrorPtr orig_err;
    size_t i;

    if (!dd)
        return;

    virErrorPreserveLast(&orig_err);

    for (i = 0; i < ndd; i++)
        qemuBackupDiskDataCleanupOne(vm, dd + i);

    g_free(dd);
    virErrorRestore(&orig_err);
}


int
qemuBackupDiskPrepareOneBitmapsChain(virStorageSourcePtr backingChain,
                                     virStorageSourcePtr targetsrc,
                                     const char *targetbitmap,
                                     const char *incremental,
                                     virJSONValuePtr actions,
                                     virHashTablePtr blockNamedNodeData)
{
    g_autoptr(virJSONValue) tmpactions = NULL;

    if (qemuBlockGetBitmapMergeActions(backingChain, NULL, targetsrc,
                                       incremental, targetbitmap, NULL,
                                       &tmpactions,
                                       blockNamedNodeData) < 0)
        return -1;

    if (tmpactions &&
        virJSONValueArrayConcat(actions, tmpactions) < 0)
        return -1;

    return 0;
}


static int
qemuBackupDiskPrepareOneBitmaps(struct qemuBackupDiskData *dd,
                                virJSONValuePtr actions,
                                virHashTablePtr blockNamedNodeData)
{
    if (!qemuBlockBitmapChainIsValid(dd->domdisk->src,
                                     dd->backupdisk->incremental,
                                     blockNamedNodeData)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("missing or broken bitmap '%s' for disk '%s'"),
                       dd->backupdisk->incremental, dd->domdisk->dst);
        return -1;
    }

    if (qemuBackupDiskPrepareOneBitmapsChain(dd->domdisk->src,
                                             dd->domdisk->src,
                                             dd->incrementalBitmap,
                                             dd->backupdisk->incremental,
                                             actions,
                                             blockNamedNodeData) < 0)
        return -1;

    if (qemuBackupDiskPrepareOneBitmapsChain(dd->domdisk->src,
                                             dd->store,
                                             dd->incrementalBitmap,
                                             dd->backupdisk->incremental,
                                             actions,
                                             blockNamedNodeData) < 0)
        return -1;

    return 0;
}


static int
qemuBackupDiskPrepareDataOne(virDomainObjPtr vm,
                             virDomainBackupDiskDefPtr backupdisk,
                             struct qemuBackupDiskData *dd,
                             virJSONValuePtr actions,
                             bool pull,
                             virHashTablePtr blockNamedNodeData,
                             virQEMUDriverConfigPtr cfg)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    /* set data structure */
    dd->backupdisk = backupdisk;
    dd->store = dd->backupdisk->store;

    if (!(dd->domdisk = virDomainDiskByTarget(vm->def, dd->backupdisk->name))) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("no disk named '%s'"), dd->backupdisk->name);
        return -1;
    }

    if (!qemuDomainDiskBlockJobIsSupported(vm, dd->domdisk))
        return -1;

    if (!dd->store->format)
        dd->store->format = VIR_STORAGE_FILE_QCOW2;

    /* calculate backing store to use:
     * push mode:
     *   full backups: no backing store
     *   incremental: original disk if format supports backing store
     * pull mode:
     *   both: original disk
     */
    if (pull || (dd->backupdisk->incremental &&
                 dd->store->format >= VIR_STORAGE_FILE_BACKING)) {
        dd->backingStore = dd->domdisk->src;
    } else {
        dd->backingStore = dd->terminator = virStorageSourceNew();
    }

    if (qemuDomainPrepareStorageSourceBlockdev(NULL, dd->store, priv, cfg) < 0)
        return -1;

    if (dd->backupdisk->incremental) {
        if (dd->backupdisk->exportbitmap)
            dd->incrementalBitmap = g_strdup(dd->backupdisk->exportbitmap);
        else
            dd->incrementalBitmap = g_strdup_printf("backup-%s", dd->domdisk->dst);

        if (qemuBackupDiskPrepareOneBitmaps(dd, actions, blockNamedNodeData) < 0)
            return -1;
    }

    if (!(dd->blockjob = qemuBlockJobDiskNewBackup(vm, dd->domdisk, dd->store,
                                                   dd->incrementalBitmap)))
        return -1;

    /* use original disk as backing to prevent opening the backing chain */
    if (!(dd->crdata = qemuBuildStorageSourceChainAttachPrepareBlockdevTop(dd->store,
                                                                           dd->backingStore,
                                                                           priv->qemuCaps)))
        return -1;

    return 0;
}


static int
qemuBackupDiskPrepareDataOnePush(virJSONValuePtr actions,
                                 struct qemuBackupDiskData *dd)
{
    qemuMonitorTransactionBackupSyncMode syncmode = QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_FULL;

    if (dd->incrementalBitmap)
        syncmode = QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_INCREMENTAL;

    if (qemuMonitorTransactionBackup(actions,
                                     dd->domdisk->src->nodeformat,
                                     dd->blockjob->name,
                                     dd->store->nodeformat,
                                     dd->incrementalBitmap,
                                     syncmode) < 0)
        return -1;

    return 0;
}


static int
qemuBackupDiskPrepareDataOnePull(virJSONValuePtr actions,
                                 struct qemuBackupDiskData *dd)
{
    if (!dd->backupdisk->exportbitmap &&
        dd->incrementalBitmap)
        dd->backupdisk->exportbitmap = g_strdup(dd->incrementalBitmap);

    if (qemuMonitorTransactionBackup(actions,
                                     dd->domdisk->src->nodeformat,
                                     dd->blockjob->name,
                                     dd->store->nodeformat,
                                     NULL,
                                     QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_NONE) < 0)
        return -1;

    return 0;
}


static ssize_t
qemuBackupDiskPrepareData(virDomainObjPtr vm,
                          virDomainBackupDefPtr def,
                          virHashTablePtr blockNamedNodeData,
                          virJSONValuePtr actions,
                          virQEMUDriverConfigPtr cfg,
                          struct qemuBackupDiskData **rdd)
{
    struct qemuBackupDiskData *disks = NULL;
    ssize_t ndisks = 0;
    size_t i;
    bool pull = def->type == VIR_DOMAIN_BACKUP_TYPE_PULL;

    disks = g_new0(struct qemuBackupDiskData, def->ndisks);

    for (i = 0; i < def->ndisks; i++) {
        virDomainBackupDiskDef *backupdisk = &def->disks[i];
        struct qemuBackupDiskData *dd = disks + ndisks;

        if (!backupdisk->store)
            continue;

        ndisks++;

        if (qemuBackupDiskPrepareDataOne(vm, backupdisk, dd, actions, pull,
                                         blockNamedNodeData, cfg) < 0)
            goto error;

        if (pull) {
            if (qemuBackupDiskPrepareDataOnePull(actions, dd) < 0)
                goto error;
        } else {
            if (qemuBackupDiskPrepareDataOnePush(actions, dd) < 0)
                goto error;
        }
    }

    *rdd = g_steal_pointer(&disks);

    return ndisks;

 error:
    qemuBackupDiskDataCleanup(vm, disks, ndisks);
    return -1;
}


static int
qemuBackupDiskPrepareOneStorage(virDomainObjPtr vm,
                                virHashTablePtr blockNamedNodeData,
                                struct qemuBackupDiskData *dd,
                                bool reuse_external)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    int rc;

    if (!reuse_external &&
        dd->store->type == VIR_STORAGE_TYPE_FILE &&
        virStorageFileSupportsCreate(dd->store)) {

        if (virFileExists(dd->store->path)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("store '%s' for backup of '%s' exists"),
                           dd->store->path, dd->domdisk->dst);
            return -1;
        }

        if (qemuDomainStorageFileInit(priv->driver, vm, dd->store, dd->domdisk->src) < 0)
            return -1;

        dd->initialized = true;

        if (virStorageFileCreate(dd->store) < 0) {
            virReportSystemError(errno,
                                 _("failed to create image file '%s'"),
                                 NULLSTR(dd->store->path));
            return -1;
        }

        dd->created = true;
    }

    if (qemuDomainStorageSourceAccessAllow(priv->driver, vm, dd->store,
                                           false, true, true) < 0)
        return -1;

    dd->labelled = true;

    if (!reuse_external) {
        if (qemuBlockStorageSourceCreateDetectSize(blockNamedNodeData,
                                                   dd->store, dd->domdisk->src) < 0)
            return -1;

        if (qemuBlockStorageSourceCreate(vm, dd->store, dd->backingStore, NULL,
                                         dd->crdata->srcdata[0],
                                         QEMU_ASYNC_JOB_BACKUP) < 0)
            return -1;
    } else {
        if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, QEMU_ASYNC_JOB_BACKUP) < 0)
            return -1;

        rc = qemuBlockStorageSourceAttachApply(priv->mon, dd->crdata->srcdata[0]);

        if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
            return -1;
    }

    dd->added = true;

    return 0;
}


static int
qemuBackupDiskPrepareStorage(virDomainObjPtr vm,
                             struct qemuBackupDiskData *disks,
                             size_t ndisks,
                             virHashTablePtr blockNamedNodeData,
                             bool reuse_external)
{
    size_t i;

    for (i = 0; i < ndisks; i++) {
        if (qemuBackupDiskPrepareOneStorage(vm, blockNamedNodeData, disks + i,
                                            reuse_external) < 0)
            return -1;
    }

    return 0;
}


static void
qemuBackupDiskStarted(virDomainObjPtr vm,
                      struct qemuBackupDiskData *dd,
                      size_t ndd)
{
    size_t i;

    for (i = 0; i < ndd; i++) {
        dd[i].started = true;
        dd[i].backupdisk->state = VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING;
        qemuBlockJobStarted(dd[i].blockjob, vm);
    }
}


/**
 * qemuBackupBeginPullExportDisks:
 * @vm: domain object
 * @disks: backup disk data list
 * @ndisks: number of valid disks in @disks
 *
 * Exports all disks from @dd when doing a pull backup in the NBD server. This
 * function must be called while in the monitor context.
 */
static int
qemuBackupBeginPullExportDisks(virDomainObjPtr vm,
                               struct qemuBackupDiskData *disks,
                               size_t ndisks)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    for (i = 0; i < ndisks; i++) {
        struct qemuBackupDiskData *dd = disks + i;

        if (!dd->backupdisk->exportname)
            dd->backupdisk->exportname = g_strdup(dd->domdisk->dst);

        if (qemuMonitorNBDServerAdd(priv->mon,
                                    dd->store->nodeformat,
                                    dd->backupdisk->exportname,
                                    false,
                                    dd->incrementalBitmap) < 0)
            return -1;
    }

    return 0;
}


void
qemuBackupJobTerminate(virDomainObjPtr vm,
                       qemuDomainJobStatus jobstatus)

{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;

    qemuDomainJobInfoUpdateTime(priv->job.current);

    g_clear_pointer(&priv->job.completed, qemuDomainJobInfoFree);
    priv->job.completed = qemuDomainJobInfoCopy(priv->job.current);

    priv->job.completed->stats.backup.total = priv->backup->push_total;
    priv->job.completed->stats.backup.transferred = priv->backup->push_transferred;
    priv->job.completed->stats.backup.tmp_used = priv->backup->pull_tmp_used;
    priv->job.completed->stats.backup.tmp_total = priv->backup->pull_tmp_total;

    priv->job.completed->status = jobstatus;
    priv->job.completed->errmsg = g_strdup(priv->backup->errmsg);

    qemuDomainEventEmitJobCompleted(priv->driver, vm);

    if (!(priv->job.apiFlags & VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL) &&
        (priv->backup->type == VIR_DOMAIN_BACKUP_TYPE_PULL ||
         (priv->backup->type == VIR_DOMAIN_BACKUP_TYPE_PUSH &&
          jobstatus != QEMU_DOMAIN_JOB_STATUS_COMPLETED))) {

        g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);

        for (i = 0; i < priv->backup->ndisks; i++) {
            virDomainBackupDiskDefPtr backupdisk = priv->backup->disks + i;
            uid_t uid;
            gid_t gid;

            if (!backupdisk->store ||
                backupdisk->store->type != VIR_STORAGE_TYPE_FILE)
                continue;

            qemuDomainGetImageIds(cfg, vm, backupdisk->store, NULL, &uid, &gid);
            if (virFileRemove(backupdisk->store->path, uid, gid) < 0)
                VIR_WARN("failed to remove scratch file '%s'",
                         backupdisk->store->path);
        }
    }

    virDomainBackupDefFree(priv->backup);
    priv->backup = NULL;
    qemuDomainObjEndAsyncJob(priv->driver, vm);
}


/**
 * qemuBackupJobCancelBlockjobs:
 * @vm: domain object
 * @backup: backup definition
 * @terminatebackup: flag whether to terminate and unregister the backup
 * @asyncJob: currently used qemu asynchronous job type
 *
 * Sends all active blockjobs which are part of @backup of @vm a signal to
 * cancel. If @terminatebackup is true qemuBackupJobTerminate is also called
 * if there are no outstanding active blockjobs.
 */
void
qemuBackupJobCancelBlockjobs(virDomainObjPtr vm,
                             virDomainBackupDefPtr backup,
                             bool terminatebackup,
                             int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    size_t i;
    int rc = 0;
    bool has_active = false;

    if (!backup)
        return;

    for (i = 0; i < backup->ndisks; i++) {
        virDomainBackupDiskDefPtr backupdisk = backup->disks + i;
        virDomainDiskDefPtr disk;
        g_autoptr(qemuBlockJobData) job = NULL;

        if (!backupdisk->store)
            continue;

        /* Look up corresponding disk as backupdisk->idx is no longer reliable */
        if (!(disk = virDomainDiskByTarget(vm->def, backupdisk->name)))
            continue;

        if (!(job = qemuBlockJobDiskGetJob(disk)))
            continue;

        if (backupdisk->state != VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING &&
            backupdisk->state != VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLING)
            continue;

        has_active = true;

        if (backupdisk->state != VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING)
            continue;

        if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
            return;

        rc = qemuMonitorJobCancel(priv->mon, job->name, false);

        if (qemuDomainObjExitMonitor(priv->driver, vm) < 0)
            return;

        if (rc == 0) {
            backupdisk->state = VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLING;
            job->state = QEMU_BLOCKJOB_STATE_ABORTING;
        }
    }

    if (terminatebackup && !has_active)
        qemuBackupJobTerminate(vm, QEMU_DOMAIN_JOB_STATUS_CANCELED);
}


#define QEMU_BACKUP_TLS_ALIAS_BASE "libvirt_backup"

static int
qemuBackupBeginPrepareTLS(virDomainObjPtr vm,
                          virQEMUDriverConfigPtr cfg,
                          virDomainBackupDefPtr def,
                          virJSONValuePtr *tlsProps,
                          virJSONValuePtr *tlsSecretProps)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autofree char *tlsObjAlias = qemuAliasTLSObjFromSrcAlias(QEMU_BACKUP_TLS_ALIAS_BASE);
    g_autoptr(qemuDomainSecretInfo) secinfo = NULL;
    const char *tlsKeySecretAlias = NULL;

    if (def->tls != VIR_TRISTATE_BOOL_YES)
        return 0;

    if (!cfg->backupTLSx509certdir) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("backup TLS directory not configured"));
        return -1;
    }

    if (cfg->backupTLSx509secretUUID) {
        if (!(secinfo = qemuDomainSecretInfoTLSNew(priv, tlsObjAlias,
                                                   cfg->backupTLSx509secretUUID)))
            return -1;

        if (qemuBuildSecretInfoProps(secinfo, tlsSecretProps) < 0)
            return -1;

        tlsKeySecretAlias = secinfo->s.aes.alias;
    }

    if (qemuBuildTLSx509BackendProps(cfg->backupTLSx509certdir, true,
                                     cfg->backupTLSx509verify, tlsObjAlias,
                                     tlsKeySecretAlias, priv->qemuCaps,
                                     tlsProps) < 0)
        return -1;

    return 0;
}


int
qemuBackupBegin(virDomainObjPtr vm,
                const char *backupXML,
                const char *checkpointXML,
                unsigned int flags)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(priv->driver);
    g_autoptr(virDomainBackupDef) def = NULL;
    g_autofree char *suffix = NULL;
    bool pull = false;
    virDomainMomentObjPtr chk = NULL;
    g_autoptr(virDomainCheckpointDef) chkdef = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    g_autoptr(virJSONValue) tlsProps = NULL;
    g_autofree char *tlsAlias = NULL;
    g_autoptr(virJSONValue) tlsSecretProps = NULL;
    g_autofree char *tlsSecretAlias = NULL;
    struct qemuBackupDiskData *dd = NULL;
    ssize_t ndd = 0;
    g_autoptr(virHashTable) blockNamedNodeData = NULL;
    bool job_started = false;
    bool nbd_running = false;
    bool reuse = (flags & VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL);
    int rc = 0;
    int ret = -1;

    virCheckFlags(VIR_DOMAIN_BACKUP_BEGIN_REUSE_EXTERNAL, -1);

    if (!(def = virDomainBackupDefParseString(backupXML, priv->driver->xmlopt, 0)))
        return -1;

    if (checkpointXML) {
        if (!(chkdef = virDomainCheckpointDefParseString(checkpointXML,
                                                         priv->driver->xmlopt,
                                                         priv->qemuCaps, 0)))
            return -1;

        suffix = g_strdup(chkdef->parent.name);
    } else {
        gint64 now_us = g_get_real_time();
        suffix = g_strdup_printf("%lld", (long long)now_us/(1000*1000));
    }

    if (def->type == VIR_DOMAIN_BACKUP_TYPE_PULL)
        pull = true;

    /* we'll treat this kind of backup job as an asyncjob as it uses some of the
     * infrastructure for async jobs. We'll allow standard modify-type jobs
     * as the interlocking of conflicting operations is handled on the block
     * job level */
    if (qemuDomainObjBeginAsyncJob(priv->driver, vm, QEMU_ASYNC_JOB_BACKUP,
                                   VIR_DOMAIN_JOB_OPERATION_BACKUP, flags) < 0)
        return -1;

    qemuDomainObjSetAsyncJobMask(vm, (QEMU_JOB_DEFAULT_MASK |
                                      JOB_MASK(QEMU_JOB_SUSPEND) |
                                      JOB_MASK(QEMU_JOB_MODIFY)));
    priv->job.current->statsType = QEMU_DOMAIN_JOB_STATS_TYPE_BACKUP;

    if (!virDomainObjIsActive(vm)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("cannot perform disk backup for inactive domain"));
        goto endjob;
    }

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_INCREMENTAL_BACKUP)) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("incremental backup is not supported yet"));
        goto endjob;
    }

    if (priv->backup) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("another backup job is already running"));
        goto endjob;
    }

    if (qemuBackupPrepare(def) < 0)
        goto endjob;

    if (qemuBackupBeginPrepareTLS(vm, cfg, def, &tlsProps, &tlsSecretProps) < 0)
        goto endjob;

    if (virDomainBackupAlignDisks(def, vm->def, suffix) < 0)
        goto endjob;

    actions = virJSONValueNewArray();

    /* The 'chk' checkpoint must be rolled back if the transaction command
     * which creates it on disk is not executed or fails */
    if (chkdef) {
        if (qemuCheckpointCreateCommon(priv->driver, vm, &chkdef,
                                       &actions, &chk) < 0)
            goto endjob;
    }

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, QEMU_ASYNC_JOB_BACKUP)))
        goto endjob;

    if ((ndd = qemuBackupDiskPrepareData(vm, def, blockNamedNodeData, actions,
                                         cfg, &dd)) <= 0) {
        if (ndd == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("no disks selected for backup"));
        }

        goto endjob;
    }

    if (qemuBackupDiskPrepareStorage(vm, dd, ndd, blockNamedNodeData, reuse) < 0)
        goto endjob;

    priv->backup = g_steal_pointer(&def);

    if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, QEMU_ASYNC_JOB_BACKUP) < 0)
        goto endjob;

    if (pull) {
        if (tlsSecretProps)
            rc = qemuMonitorAddObject(priv->mon, &tlsSecretProps, &tlsSecretAlias);

        if (rc == 0 && tlsProps)
            rc = qemuMonitorAddObject(priv->mon, &tlsProps, &tlsAlias);

        if (rc == 0) {
            if ((rc = qemuMonitorNBDServerStart(priv->mon, priv->backup->server, tlsAlias)) == 0)
                nbd_running = true;
        }
    }

    if (rc == 0)
        rc = qemuMonitorTransaction(priv->mon, &actions);

    if (qemuDomainObjExitMonitor(priv->driver, vm) < 0 || rc < 0)
        goto endjob;

    job_started = true;
    priv->backup->tlsAlias = g_steal_pointer(&tlsAlias);
    priv->backup->tlsSecretAlias = g_steal_pointer(&tlsSecretAlias);
    /* qemuBackupDiskStarted saves the status XML */
    qemuBackupDiskStarted(vm, dd, ndd);

    if (chk) {
        virDomainMomentObjPtr tmpchk = g_steal_pointer(&chk);
        if (qemuCheckpointCreateFinalize(priv->driver, vm, cfg, tmpchk, true) < 0)
            goto endjob;
    }

    if (pull) {
        if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, QEMU_ASYNC_JOB_BACKUP) < 0)
            goto endjob;
        /* note that if the export fails we've already created the checkpoint
         * and we will not delete it */
        rc = qemuBackupBeginPullExportDisks(vm, dd, ndd);
        if (qemuDomainObjExitMonitor(priv->driver, vm) < 0)
            goto endjob;

        if (rc < 0) {
            qemuBackupJobCancelBlockjobs(vm, priv->backup, false, QEMU_ASYNC_JOB_BACKUP);
            goto endjob;
        }
    }

    ret = 0;

 endjob:
    qemuBackupDiskDataCleanup(vm, dd, ndd);

    /* if 'chk' is non-NULL here it's a failure and it must be rolled back */
    qemuCheckpointRollbackMetadata(vm, chk);

    if (!job_started && (nbd_running || tlsAlias || tlsSecretAlias) &&
        qemuDomainObjEnterMonitorAsync(priv->driver, vm, QEMU_ASYNC_JOB_BACKUP) == 0) {
        if (nbd_running)
            ignore_value(qemuMonitorNBDServerStop(priv->mon));
        if (tlsAlias)
            ignore_value(qemuMonitorDelObject(priv->mon, tlsAlias, false));
        if (tlsSecretAlias)
            ignore_value(qemuMonitorDelObject(priv->mon, tlsSecretAlias, false));
        ignore_value(qemuDomainObjExitMonitor(priv->driver, vm));
    }

    if (ret < 0 && !job_started && priv->backup)
        def = g_steal_pointer(&priv->backup);

    if (ret == 0)
        qemuDomainObjReleaseAsyncJob(vm);
    else
        qemuDomainObjEndAsyncJob(priv->driver, vm);

    return ret;
}


char *
qemuBackupGetXMLDesc(virDomainObjPtr vm,
                     unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    virDomainBackupDefPtr backup;

    virCheckFlags(0, NULL);

    if (!(backup = qemuDomainGetBackup(vm)))
        return NULL;

    if (virDomainBackupDefFormat(&buf, backup, false) < 0)
        return NULL;

    return virBufferContentAndReset(&buf);
}


void
qemuBackupNotifyBlockjobEnd(virDomainObjPtr vm,
                            virDomainDiskDefPtr disk,
                            qemuBlockjobState state,
                            const char *errmsg,
                            unsigned long long cur,
                            unsigned long long end,
                            int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    bool has_running = false;
    bool has_cancelling = false;
    bool has_cancelled = false;
    bool has_failed = false;
    qemuDomainJobStatus jobstatus = QEMU_DOMAIN_JOB_STATUS_COMPLETED;
    virDomainBackupDefPtr backup = priv->backup;
    size_t i;

    VIR_DEBUG("vm: '%s', disk:'%s', state:'%d' errmsg:'%s'",
              vm->def->name, disk->dst, state, NULLSTR(errmsg));

    if (!backup)
        return;

    if (backup->type == VIR_DOMAIN_BACKUP_TYPE_PULL) {
        if (qemuDomainObjEnterMonitorAsync(priv->driver, vm, asyncJob) < 0)
            return;
        ignore_value(qemuMonitorNBDServerStop(priv->mon));
        if (backup->tlsAlias)
            ignore_value(qemuMonitorDelObject(priv->mon, backup->tlsAlias, false));
        if (backup->tlsSecretAlias)
            ignore_value(qemuMonitorDelObject(priv->mon, backup->tlsSecretAlias, false));
        if (qemuDomainObjExitMonitor(priv->driver, vm) < 0)
            return;

        /* update the final statistics with the current job's data */
        backup->pull_tmp_used += cur;
        backup->pull_tmp_total += end;
    } else {
        backup->push_transferred += cur;
        backup->push_total += end;
    }

    /* record first error message */
    if (!backup->errmsg)
        backup->errmsg = g_strdup(errmsg);

    for (i = 0; i < backup->ndisks; i++) {
        virDomainBackupDiskDefPtr backupdisk = backup->disks + i;

        if (!backupdisk->store)
            continue;

        if (STREQ(disk->dst, backupdisk->name)) {
            switch (state) {
            case QEMU_BLOCKJOB_STATE_COMPLETED:
                backupdisk->state = VIR_DOMAIN_BACKUP_DISK_STATE_COMPLETE;
                break;

            case QEMU_BLOCKJOB_STATE_CONCLUDED:
            case QEMU_BLOCKJOB_STATE_FAILED:
                backupdisk->state = VIR_DOMAIN_BACKUP_DISK_STATE_FAILED;
                break;

            case QEMU_BLOCKJOB_STATE_CANCELLED:
                backupdisk->state = VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLED;
                break;

            case QEMU_BLOCKJOB_STATE_READY:
            case QEMU_BLOCKJOB_STATE_NEW:
            case QEMU_BLOCKJOB_STATE_RUNNING:
            case QEMU_BLOCKJOB_STATE_ABORTING:
            case QEMU_BLOCKJOB_STATE_PIVOTING:
            case QEMU_BLOCKJOB_STATE_LAST:
            default:
                break;
            }
        }

        switch (backupdisk->state) {
        case VIR_DOMAIN_BACKUP_DISK_STATE_COMPLETE:
            break;

        case VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING:
            has_running = true;
            break;

        case VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLING:
            has_cancelling = true;
            break;

        case VIR_DOMAIN_BACKUP_DISK_STATE_FAILED:
            has_failed = true;
            break;

        case VIR_DOMAIN_BACKUP_DISK_STATE_CANCELLED:
            has_cancelled = true;
            break;

        case VIR_DOMAIN_BACKUP_DISK_STATE_NONE:
        case VIR_DOMAIN_BACKUP_DISK_STATE_LAST:
            break;
        }
    }

    if (has_running && (has_failed || has_cancelled)) {
        /* cancel the rest of the jobs */
        qemuBackupJobCancelBlockjobs(vm, backup, false, asyncJob);
    } else if (!has_running && !has_cancelling) {
        /* all sub-jobs have stopped */

        if (has_failed)
            jobstatus = QEMU_DOMAIN_JOB_STATUS_FAILED;
        else if (has_cancelled && backup->type == VIR_DOMAIN_BACKUP_TYPE_PUSH)
            jobstatus = QEMU_DOMAIN_JOB_STATUS_CANCELED;

        qemuBackupJobTerminate(vm, jobstatus);
    }

    /* otherwise we must wait for the jobs to end */
}


static void
qemuBackupGetJobInfoStatsUpdateOne(virDomainObjPtr vm,
                                   bool push,
                                   const char *diskdst,
                                   qemuDomainBackupStats *stats,
                                   qemuMonitorJobInfoPtr *blockjobs,
                                   size_t nblockjobs)
{
    virDomainDiskDefPtr domdisk;
    qemuMonitorJobInfoPtr monblockjob = NULL;
    g_autoptr(qemuBlockJobData) diskblockjob = NULL;
    size_t i;

    /* it's just statistics so let's not worry so much about errors */
    if (!(domdisk = virDomainDiskByTarget(vm->def, diskdst)))
        return;

    if (!(diskblockjob = qemuBlockJobDiskGetJob(domdisk)))
        return;

    for (i = 0; i < nblockjobs; i++) {
        if (STREQ_NULLABLE(blockjobs[i]->id, diskblockjob->name)) {
            monblockjob = blockjobs[i];
            break;
        }
    }
    if (!monblockjob)
        return;

    if (push) {
        stats->total += monblockjob->progressTotal;
        stats->transferred += monblockjob->progressCurrent;
    } else {
        stats->tmp_used += monblockjob->progressCurrent;
        stats->tmp_total += monblockjob->progressTotal;
    }
}


int
qemuBackupGetJobInfoStats(virQEMUDriverPtr driver,
                          virDomainObjPtr vm,
                          qemuDomainJobInfoPtr jobInfo)
{
    qemuDomainBackupStats *stats = &jobInfo->stats.backup;
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorJobInfoPtr *blockjobs = NULL;
    size_t nblockjobs = 0;
    size_t i;
    int rc;
    int ret = -1;

    if (!priv->backup) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("backup job data missing"));
        return -1;
    }

    if (qemuDomainJobInfoUpdateTime(jobInfo) < 0)
        return -1;

    jobInfo->status = QEMU_DOMAIN_JOB_STATUS_ACTIVE;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorGetJobInfo(priv->mon, &blockjobs, &nblockjobs);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    /* count in completed jobs */
    stats->total = priv->backup->push_total;
    stats->transferred = priv->backup->push_transferred;
    stats->tmp_used = priv->backup->pull_tmp_used;
    stats->tmp_total = priv->backup->pull_tmp_total;

    for (i = 0; i < priv->backup->ndisks; i++) {
        if (priv->backup->disks[i].state != VIR_DOMAIN_BACKUP_DISK_STATE_RUNNING)
            continue;

        qemuBackupGetJobInfoStatsUpdateOne(vm,
                                           priv->backup->type == VIR_DOMAIN_BACKUP_TYPE_PUSH,
                                           priv->backup->disks[i].name,
                                           stats,
                                           blockjobs,
                                           nblockjobs);
    }

    ret = 0;

 cleanup:
    for (i = 0; i < nblockjobs; i++)
        qemuMonitorJobInfoFree(blockjobs[i]);
    g_free(blockjobs);
    return ret;
}
