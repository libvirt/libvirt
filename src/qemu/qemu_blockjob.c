/*
 * qemu_blockjob.c: helper functions for QEMU block jobs
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include "internal.h"

#include "qemu_blockjob.h"
#include "qemu_block.h"
#include "qemu_domain.h"
#include "qemu_alias.h"
#include "qemu_backup.h"

#include "conf/domain_conf.h"
#include "conf/domain_event.h"

#include "storage_source_conf.h"
#include "virlog.h"
#include "virthread.h"
#include "locking/domain_lock.h"
#include "viralloc.h"
#include "qemu_security.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_blockjob");

/* Note that qemuBlockjobState and qemuBlockjobType values are formatted into
 * the status XML */
VIR_ENUM_IMPL(qemuBlockjobState,
              QEMU_BLOCKJOB_STATE_LAST,
              "completed",
              "failed",
              "cancelled",
              "ready",
              "new",
              "running",
              "concluded",
              "aborting",
              "pending",
              "pivoting");

VIR_ENUM_IMPL(qemuBlockjob,
              QEMU_BLOCKJOB_TYPE_LAST,
              "",
              "pull",
              "copy",
              "commit",
              "active-commit",
              "backup",
              "",
              "create",
              "broken");

static virClass *qemuBlockJobDataClass;


static void
qemuBlockJobDataDisposeJobdata(qemuBlockJobData *job)
{
    if (job->type == QEMU_BLOCKJOB_TYPE_CREATE)
        virObjectUnref(job->data.create.src);

    if (job->type == QEMU_BLOCKJOB_TYPE_BACKUP) {
        virObjectUnref(job->data.backup.store);
        g_free(job->data.backup.bitmap);
    }
}


static void
qemuBlockJobDataDispose(void *obj)
{
    qemuBlockJobData *job = obj;

    virObjectUnref(job->chain);
    virObjectUnref(job->mirrorChain);

    qemuBlockJobDataDisposeJobdata(job);

    g_free(job->name);
    g_free(job->errmsg);
}


static int
qemuBlockJobDataOnceInit(void)
{
    if (!VIR_CLASS_NEW(qemuBlockJobData, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(qemuBlockJobData);

qemuBlockJobData *
qemuBlockJobDataNew(qemuBlockJobType type,
                    const char *name)
{
    g_autoptr(qemuBlockJobData) job = NULL;

    if (qemuBlockJobDataInitialize() < 0)
        return NULL;

    if (!(job = virObjectNew(qemuBlockJobDataClass)))
        return NULL;

    job->name = g_strdup(name);

    job->state = QEMU_BLOCKJOB_STATE_NEW;
    job->newstate = -1;
    job->type = type;

    return g_steal_pointer(&job);
}


/**
 * qemuBlockJobMarkBroken:
 * @job: job to mark as broken
 *
 * In case when we are unable to parse the block job data from the XML
 * successfully we'll need to mark the job as broken and then attempt to abort
 * it. This function marks the job as broken.
 */
static void
qemuBlockJobMarkBroken(qemuBlockJobData *job)
{
    qemuBlockJobDataDisposeJobdata(job);
    job->brokentype = job->type;
    job->type = QEMU_BLOCKJOB_TYPE_BROKEN;
}


/**
 * qemuBlockJobRegister:
 * @job: job to register
 * @vm: domain to register @job with
 * @disk: disk to register @job with
 * @savestatus: save the status XML after registering
 *
 * This function registers @job with @disk and @vm and records it into the status
 * xml (if @savestatus is true).
 *
 * Note that if @job also references a separate chain e.g. for disk mirroring,
 * then job->mirrorchain needs to be set manually.
 */
int
qemuBlockJobRegister(qemuBlockJobData *job,
                     virDomainObj *vm,
                     virDomainDiskDef *disk,
                     bool savestatus)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (disk && QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("disk '%1$s' has a blockjob assigned"), disk->dst);
        return -1;
    }

    if (virHashAddEntry(priv->blockjobs, job->name, virObjectRef(job)) < 0) {
        virObjectUnref(job);
        return -1;
    }

    if (disk) {
        job->disk = disk;
        job->chain = virObjectRef(disk->src);
        QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob = virObjectRef(job);
    }

    if (savestatus)
        qemuDomainSaveStatus(vm);

    return 0;
}


static void
qemuBlockJobUnregister(qemuBlockJobData *job,
                       virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuDomainDiskPrivate *diskPriv;

    if (job->disk) {
        diskPriv = QEMU_DOMAIN_DISK_PRIVATE(job->disk);

        if (job == diskPriv->blockjob) {
            g_clear_pointer(&diskPriv->blockjob, virObjectUnref);
        }

        job->disk = NULL;
    }

    /* this may remove the last reference of 'job' */
    virHashRemoveEntry(priv->blockjobs, job->name);

    qemuDomainSaveStatus(vm);
}


/**
 * qemuBlockJobDiskNew:
 * @disk: disk definition
 *
 * Start/associate a new blockjob with @disk.
 */
qemuBlockJobData *
qemuBlockJobDiskNew(virDomainObj *vm,
                    virDomainDiskDef *disk,
                    qemuBlockJobType type,
                    const char *jobname)
{
    g_autoptr(qemuBlockJobData) job = NULL;

    if (!(job = qemuBlockJobDataNew(type, jobname)))
        return NULL;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


qemuBlockJobData *
qemuBlockJobDiskNewPull(virDomainObj *vm,
                        virDomainDiskDef *disk,
                        virStorageSource *base,
                        unsigned int jobflags)
{
    g_autoptr(qemuBlockJobData) job = NULL;
    g_autofree char *jobname = g_strdup_printf("pull-%s-%s", disk->dst,
                                               qemuBlockStorageSourceGetEffectiveNodename(disk->src));

    if (!(job = qemuBlockJobDataNew(QEMU_BLOCKJOB_TYPE_PULL, jobname)))
        return NULL;

    job->data.pull.base = base;
    job->jobflags = jobflags;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


qemuBlockJobData *
qemuBlockJobDiskNewCommit(virDomainObj *vm,
                          virDomainDiskDef *disk,
                          virStorageSource *topparent,
                          virStorageSource *top,
                          virStorageSource *base,
                          bool delete_imgs,
                          virTristateBool autofinalize,
                          unsigned int jobflags)
{
    g_autoptr(qemuBlockJobData) job = NULL;
    g_autofree char *jobname = g_strdup_printf("commit-%s-%s", disk->dst,
                                               qemuBlockStorageSourceGetEffectiveNodename(top));
    qemuBlockJobType jobtype = QEMU_BLOCKJOB_TYPE_COMMIT;

    if (topparent == NULL)
        jobtype = QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT;

    if (!(job = qemuBlockJobDataNew(jobtype, jobname)))
        return NULL;

    job->data.commit.topparent = topparent;
    job->data.commit.top = top;
    job->data.commit.base = base;
    job->data.commit.deleteCommittedImages = delete_imgs;
    job->processPending = autofinalize == VIR_TRISTATE_BOOL_NO;
    job->jobflags = jobflags;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


qemuBlockJobData *
qemuBlockJobNewCreate(virDomainObj *vm,
                      virStorageSource *src,
                      virStorageSource *chain,
                      bool storage)
{
    g_autoptr(qemuBlockJobData) job = NULL;
    g_autofree char *jobname = NULL;
    const char *nodename = qemuBlockStorageSourceGetEffectiveNodename(src);

    if (storage)
        nodename = qemuBlockStorageSourceGetStorageNodename(src);

    jobname = g_strdup_printf("create-%s", nodename);

    if (!(job = qemuBlockJobDataNew(QEMU_BLOCKJOB_TYPE_CREATE, jobname)))
        return NULL;

    if (virStorageSourceIsBacking(chain))
        job->chain = virObjectRef(chain);

     job->data.create.src = virObjectRef(src);

    if (qemuBlockJobRegister(job, vm, NULL, true) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


qemuBlockJobData *
qemuBlockJobDiskNewCopy(virDomainObj *vm,
                        virDomainDiskDef *disk,
                        virStorageSource *mirror,
                        bool shallow,
                        bool reuse,
                        unsigned int jobflags)
{
    g_autoptr(qemuBlockJobData) job = NULL;
    g_autofree char *jobname = g_strdup_printf("copy-%s-%s", disk->dst,
                                               qemuBlockStorageSourceGetEffectiveNodename(disk->src));

    if (!(job = qemuBlockJobDataNew(QEMU_BLOCKJOB_TYPE_COPY, jobname)))
        return NULL;

    job->mirrorChain = virObjectRef(mirror);

    if (shallow && !reuse)
        job->data.copy.shallownew = true;

    job->jobflags = jobflags;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


qemuBlockJobData *
qemuBlockJobDiskNewBackup(virDomainObj *vm,
                          virDomainDiskDef *disk,
                          virStorageSource *store,
                          const char *bitmap)
{
    g_autoptr(qemuBlockJobData) job = NULL;
    g_autofree char *jobname = NULL;

    jobname = g_strdup_printf("backup-%s-%s", disk->dst,
                              qemuBlockStorageSourceGetEffectiveNodename(disk->src));

    if (!(job = qemuBlockJobDataNew(QEMU_BLOCKJOB_TYPE_BACKUP, jobname)))
        return NULL;

    job->data.backup.bitmap = g_strdup(bitmap);
    job->data.backup.store = virObjectRef(store);

    /* backup jobs are usually started in bulk by transaction so the caller
     * shall save the status XML */
    if (qemuBlockJobRegister(job, vm, disk, false) < 0)
        return NULL;

    return g_steal_pointer(&job);
}


/**
 * qemuBlockJobDiskGetJob:
 * @disk: disk definition
 *
 * Get a reference to the block job data object associated with @disk.
 */
qemuBlockJobData *
qemuBlockJobDiskGetJob(virDomainDiskDef *disk)
{
    qemuBlockJobData *job = QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob;

    if (!job)
        return NULL;

    return virObjectRef(job);
}


/**
 * qemuBlockJobStarted:
 * @job: job data
 *
 * Mark @job as started in qemu.
 */
void
qemuBlockJobStarted(qemuBlockJobData *job,
                    virDomainObj *vm)
{
    if (job->state == QEMU_BLOCKJOB_STATE_NEW)
        job->state = QEMU_BLOCKJOB_STATE_RUNNING;

    qemuDomainSaveStatus(vm);
}


/**
 * qemuBlockJobStartupFinalize:
 * @job: job being started
 *
 * Cancels and clears the job private data if the job was not started with
 * qemu (see qemuBlockJobStarted) or just clears up the local reference
 * to @job if it was started.
 */
void
qemuBlockJobStartupFinalize(virDomainObj *vm,
                            qemuBlockJobData *job)
{
    if (!job)
        return;

    if (job->state == QEMU_BLOCKJOB_STATE_NEW)
        qemuBlockJobUnregister(job, vm);

    virObjectUnref(job);
}


bool
qemuBlockJobIsRunning(qemuBlockJobData *job)
{
    return job->state == QEMU_BLOCKJOB_STATE_RUNNING ||
           job->state == QEMU_BLOCKJOB_STATE_READY ||
           job->state == QEMU_BLOCKJOB_STATE_ABORTING ||
           job->state == QEMU_BLOCKJOB_STATE_PIVOTING;
}


/* returns 1 for a job we didn't reconnect to */
static int
qemuBlockJobRefreshJobsFindInactive(const void *payload,
                                    const char *name G_GNUC_UNUSED,
                                    const void *data G_GNUC_UNUSED)
{
    const qemuBlockJobData *job = payload;

    return !job->reconnected;
}


int
qemuBlockJobRefreshJobs(virDomainObj *vm)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    qemuMonitorJobInfo **jobinfo = NULL;
    size_t njobinfo = 0;
    qemuBlockJobData *job = NULL;
    int newstate;
    size_t i;
    int ret = -1;
    int rc;

    qemuDomainObjEnterMonitor(vm);

    rc = qemuMonitorGetJobInfo(priv->mon, &jobinfo, &njobinfo);

    qemuDomainObjExitMonitor(vm);
    if (rc < 0)
        goto cleanup;

    for (i = 0; i < njobinfo; i++) {
        if (!(job = virHashLookup(priv->blockjobs, jobinfo[i]->id))) {
            VIR_DEBUG("ignoring untracked job '%s'", jobinfo[i]->id);
            continue;
        }

        /* try cancelling invalid jobs - this works only if the job is not
         * concluded. In such case it will fail. We'll leave such job linger
         * in qemu and just forget about it in libvirt because there's not much
         * we could do besides killing the VM */
        if (job->invalidData) {

            qemuBlockJobMarkBroken(job);

            qemuDomainObjEnterMonitor(vm);

            rc = qemuMonitorBlockJobCancel(priv->mon, job->name, true);
            if (rc == -1 && jobinfo[i]->status == QEMU_MONITOR_JOB_STATUS_CONCLUDED)
                VIR_WARN("can't cancel job '%s' with invalid data", job->name);

            qemuDomainObjExitMonitor(vm);

            if (rc < 0)
                qemuBlockJobUnregister(job, vm);
            else
                job->reconnected = true;
            continue;
        }

        if ((newstate = qemuBlockjobConvertMonitorStatus(jobinfo[i]->status)) < 0)
            continue;

        if (newstate != job->state) {
            if ((job->state == QEMU_BLOCKJOB_STATE_FAILED ||
                 job->state == QEMU_BLOCKJOB_STATE_COMPLETED)) {
                /* preserve the old state but allow the job to be bumped to
                 * execute the finishing steps */
                job->newstate = job->state;
            } else if (newstate == QEMU_BLOCKJOB_STATE_CONCLUDED) {
                job->errmsg = g_strdup(jobinfo[i]->error);

                if (job->errmsg)
                    job->newstate = QEMU_BLOCKJOB_STATE_FAILED;
                else
                    job->newstate = QEMU_BLOCKJOB_STATE_COMPLETED;
            } else if (newstate == QEMU_BLOCKJOB_STATE_READY) {
                /* Apply _READY state only if it was not applied before */
                if (job->state == QEMU_BLOCKJOB_STATE_NEW ||
                    job->state == QEMU_BLOCKJOB_STATE_RUNNING)
                    job->newstate = newstate;
            }
            /* don't update the job otherwise */
        }

        job->reconnected = true;

        if (job->newstate != -1)
            qemuBlockJobUpdate(vm, job, VIR_ASYNC_JOB_NONE);
        /* 'job' may be invalid after this update */
    }

    /* remove data for job which qemu didn't report (the algorithm is
     * inefficient, but the possibility of such jobs is very low */
    while ((job = virHashSearch(priv->blockjobs, qemuBlockJobRefreshJobsFindInactive, NULL, NULL))) {
        VIR_WARN("dropping blockjob '%s' untracked by qemu", job->name);
        qemuBlockJobUnregister(job, vm);
    }

    ret = 0;

 cleanup:
    for (i = 0; i < njobinfo; i++)
        qemuMonitorJobInfoFree(jobinfo[i]);
    VIR_FREE(jobinfo);

    return ret;
}


/**
 * qemuBlockJobEmitEvents:
 *
 * Emits the VIR_DOMAIN_EVENT_ID_BLOCK_JOB and VIR_DOMAIN_EVENT_ID_BLOCK_JOB_2
 * for a block job. The former event is emitted only for local disks.
 */
static void
qemuBlockJobEmitEvents(virQEMUDriver *driver,
                       virDomainObj *vm,
                       virDomainDiskDef *disk,
                       virDomainBlockJobType type,
                       virConnectDomainEventBlockJobStatus status)
{
    virObjectEvent *event = NULL;
    virObjectEvent *event2 = NULL;

    /* don't emit events for jobs without disk */
    if (!disk)
        return;

    /* don't emit events for internal jobs and states */
    if (type >= VIR_DOMAIN_BLOCK_JOB_TYPE_LAST ||
        status >= VIR_DOMAIN_BLOCK_JOB_LAST)
        return;

    if (virStorageSourceIsLocalStorage(disk->src) &&
        !virStorageSourceIsEmpty(disk->src)) {
        event = virDomainEventBlockJobNewFromObj(vm, virDomainDiskGetSource(disk),
                                                 type, status);
        virObjectEventStateQueue(driver->domainEventState, event);
    }

    event2 = virDomainEventBlockJob2NewFromObj(vm, disk->dst, type, status);
    virObjectEventStateQueue(driver->domainEventState, event2);
}

/**
 * qemuBlockJobCleanStorageSourceRuntime:
 * @src: storage source to clean from runtime data
 *
 * Remove all runtime related data from the storage source.
 */
static void
qemuBlockJobCleanStorageSourceRuntime(virStorageSource *src)
{
    src->id = 0;
    src->detected = false;
    VIR_FREE(src->relPath);
    VIR_FREE(src->backingStoreRaw);
    VIR_FREE(src->nodenamestorage);
    VIR_FREE(src->nodenameformat);
    VIR_FREE(src->tlsAlias);
    VIR_FREE(src->tlsCertdir);
}


/**
 * qemuBlockJobRewriteConfigDiskSource:
 * @vm: domain object
 * @disk: live definition disk
 * @newsrc: new source which should be also considered for the new disk
 *
 * For block jobs which modify the running disk source it is required that we
 * try our best to update the config XML's disk source as well in most cases.
 *
 * This helper finds the disk from the persistent definition corresponding to
 * @disk and updates its source to @newsrc.
 */
static void
qemuBlockJobRewriteConfigDiskSource(virDomainObj *vm,
                                    virDomainDiskDef *disk,
                                    virStorageSource *newsrc)
{
    virDomainDiskDef *persistDisk = NULL;
    g_autoptr(virStorageSource) copy = NULL;
    virStorageSource *n;

    if (!vm->newDef) {
        VIR_DEBUG("not updating disk '%s' in persistent definition: no persistent definition",
                  disk->dst);
        return;
    }

    if (!(persistDisk = virDomainDiskByTarget(vm->newDef, disk->dst))) {
        VIR_DEBUG("not updating disk '%s' in persistent definition: disk not present",
                  disk->dst);
        return;
    }

    if (!virStorageSourceIsSameLocation(disk->src, persistDisk->src)) {
        VIR_DEBUG("not updating disk '%s' in persistent definition: disk source doesn't match",
                  disk->dst);
        return;
    }

    if (!(copy = virStorageSourceCopy(newsrc, true)) ||
        virStorageSourceInitChainElement(copy, persistDisk->src, true) < 0) {
        VIR_WARN("Unable to update persistent definition on vm %s after block job",
                 vm->def->name);
        return;
    }

    for (n = copy; virStorageSourceIsBacking(n); n = n->backingStore) {
        qemuBlockJobCleanStorageSourceRuntime(n);

        /* discard any detected backing store */
        if (virStorageSourceIsBacking(n->backingStore) &&
            n->backingStore->detected) {
            g_clear_pointer(&n->backingStore, virObjectUnref);
            break;
        }
    }

    virObjectUnref(persistDisk->src);
    persistDisk->src = g_steal_pointer(&copy);
}


static void
qemuBlockJobEventProcessConcludedRemoveChain(virQEMUDriver *driver,
                                             virDomainObj *vm,
                                             virDomainAsyncJob asyncJob,
                                             virStorageSource *chain)
{
    g_autoptr(qemuBlockStorageSourceChainData) data = NULL;

    if (!(data = qemuBlockStorageSourceChainDetachPrepareBlockdev(chain)))
        return;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return;

    qemuBlockStorageSourceChainDetach(qemuDomainGetMonitor(vm), data);

    qemuDomainObjExitMonitor(vm);

    qemuDomainStorageSourceChainAccessRevoke(driver, vm, chain);
}


/**
 * qemuBlockJobGetConfigDisk:
 * @vm: domain object
 * @disk: disk from the running definition
 * @diskChainBottom: the last element of backing chain of @disk which is relevant
 *
 * Finds and returns the disk corresponding to @disk in the inactive definition.
 * The inactive disk must have the backing chain starting from the source until
 * @@diskChainBottom identical. If @diskChainBottom is NULL the whole backing
 * chains of both @disk and the persistent config definition equivalent must
 * be identical.
 */
static virDomainDiskDef *
qemuBlockJobGetConfigDisk(virDomainObj *vm,
                          virDomainDiskDef *disk,
                          virStorageSource *diskChainBottom)
{
    virStorageSource *disksrc = NULL;
    virStorageSource *cfgsrc = NULL;
    virDomainDiskDef *ret = NULL;

    if (!vm->newDef || !disk)
        return NULL;

    disksrc = disk->src;

    if (!(ret = virDomainDiskByTarget(vm->newDef, disk->dst)))
        return NULL;

    cfgsrc = ret->src;

    while (disksrc && cfgsrc) {
        if (!virStorageSourceIsSameLocation(disksrc, cfgsrc))
            return NULL;

        if (diskChainBottom && diskChainBottom == disksrc)
            return ret;

        disksrc = disksrc->backingStore;
        cfgsrc = cfgsrc->backingStore;
    }

    if (disksrc || cfgsrc)
        return NULL;

    return ret;
}


/**
 * qemuBlockJobClearConfigChain:
 * @vm: domain object
 * @disk: disk object from running definition of @vm
 *
 * In cases when the backing chain definitions of the live disk differ from
 * the definition for the next start config and the backing chain would touch
 * it we'd not be able to restore the chain in the next start config properly.
 *
 * This function checks that the source of the running disk definition and the
 * config disk definition are the same and if such it clears the backing chain
 * data.
 */
static void
qemuBlockJobClearConfigChain(virDomainObj *vm,
                             virDomainDiskDef *disk)
{
    virDomainDiskDef *cfgdisk = NULL;

    if (!vm->newDef || !disk)
        return;

    if (!(cfgdisk = virDomainDiskByTarget(vm->newDef, disk->dst)))
        return;

    if (!virStorageSourceIsSameLocation(disk->src, cfgdisk->src))
        return;

    g_clear_pointer(&cfgdisk->src->backingStore, virObjectUnref);
}


static int
qemuBlockJobProcessEventCompletedPullBitmaps(virDomainObj *vm,
                                             qemuBlockJobData *job,
                                             virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    g_autoptr(virJSONValue) actions = NULL;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
        return -1;

    if (qemuBlockGetBitmapMergeActions(job->disk->src,
                                       job->data.pull.base,
                                       job->disk->src,
                                       NULL, NULL, NULL,
                                       &actions,
                                       blockNamedNodeData) < 0)
        return -1;

    if (!actions)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    qemuMonitorTransaction(priv->mon, &actions);

    qemuDomainObjExitMonitor(vm);

    return 0;
}


/**
 * qemuBlockJobProcessEventCompletedPull:
 * @driver: qemu driver object
 * @vm: domain object
 * @job: job data
 * @asyncJob: qemu asynchronous job type (for monitor interaction)
 *
 * This function executes the finalizing steps after a successful block pull job
 * (block-stream in qemu terminology. The pull job copies all the data from the
 * images in the backing chain up to the 'base' image. The 'base' image becomes
 * the backing store of the active top level image. If 'base' was not used
 * everything is pulled into the top level image and the top level image will
 * cease to have backing store. All intermediate images between the active image
 * and base image are no longer required and can be unplugged.
 */
static void
qemuBlockJobProcessEventCompletedPull(virQEMUDriver *driver,
                                      virDomainObj *vm,
                                      qemuBlockJobData *job,
                                      virDomainAsyncJob asyncJob)
{
    virStorageSource *base = NULL;
    virStorageSource *baseparent = NULL;
    virDomainDiskDef *cfgdisk = NULL;
    virStorageSource *cfgbase = NULL;
    virStorageSource *cfgbaseparent = NULL;
    virStorageSource *n;
    virStorageSource *tmp;

    VIR_DEBUG("pull job '%s' on VM '%s' completed", job->name, vm->def->name);

    /* if the job isn't associated with a disk there's nothing to do */
    if (!job->disk)
        return;

    if (!(cfgdisk = qemuBlockJobGetConfigDisk(vm, job->disk, job->data.pull.base)))
        qemuBlockJobClearConfigChain(vm, job->disk);

    qemuBlockJobProcessEventCompletedPullBitmaps(vm, job, asyncJob);

    /* when pulling if 'base' is right below the top image we don't have to modify it */
    if (job->disk->src->backingStore == job->data.pull.base)
        return;

    if (job->data.pull.base) {
        base = job->data.pull.base;

        if (cfgdisk)
            cfgbase = cfgdisk->src->backingStore;

        for (n = job->disk->src->backingStore; n && n != job->data.pull.base; n = n->backingStore) {
            /* find the image on top of 'base' */

            if (cfgbase) {
                cfgbaseparent = cfgbase;
                cfgbase = cfgbase->backingStore;
            }

            baseparent = n;
        }
    } else {
        /* create terminators for the chain; since we are pulling everything
         * into the top image the chain is automatically considered terminated */
        base = virStorageSourceNew();

        if (cfgdisk)
            cfgbase = virStorageSourceNew();
    }

    tmp = job->disk->src->backingStore;
    job->disk->src->backingStore = base;
    if (baseparent)
        baseparent->backingStore = NULL;
    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, tmp);
    virObjectUnref(tmp);

    if (cfgdisk) {
        tmp = cfgdisk->src->backingStore;
        cfgdisk->src->backingStore = cfgbase;
        if (cfgbaseparent)
            cfgbaseparent->backingStore = NULL;
        virObjectUnref(tmp);
    }
}


/**
 * qemuBlockJobDeleteImages:
 * @driver: qemu driver object
 * @vm: domain object
 * @disk: disk object that the chain to be deleted is associated with
 * @top: top snapshot of the chain to be deleted
 *
 * Helper for removing snapshot images.  Intended for callers like
 * qemuBlockJobProcessEventCompletedCommit() and
 * qemuBlockJobProcessEventCompletedActiveCommit() as it relies on adjustments
 * these functions perform on the 'backingStore' chain to function correctly.
 *
 * TODO look into removing backing store for non-local snapshots too
 */
static void
qemuBlockJobDeleteImages(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainDiskDef *disk,
                         virStorageSource *top)
{
    virStorageSource *p = top;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    uid_t uid;
    gid_t gid;

    for (; p != NULL; p = p->backingStore) {
        if (virStorageSourceGetActualType(p) == VIR_STORAGE_TYPE_FILE) {

            qemuDomainGetImageIds(cfg, vm->def, p, disk->src, &uid, &gid);

            if (virFileRemove(p->path, uid, gid) < 0) {
                VIR_WARN("Unable to remove snapshot image file '%s' (%s)",
                         p->path, g_strerror(errno));
            }
        }
    }
}


/**
 * qemuBlockJobProcessEventCompletedCommitBitmaps:
 *
 * Handles the bitmap changes after commit. This returns -1 on monitor failures.
 */
static int
qemuBlockJobProcessEventCompletedCommitBitmaps(virDomainObj *vm,
                                               qemuBlockJobData *job,
                                               virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    bool active = job->type == QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT;

    if (!active &&
        !virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN))
        return 0;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
        return -1;

    if (qemuBlockBitmapsHandleCommitFinish(job->data.commit.top,
                                           job->data.commit.base,
                                           active,
                                           blockNamedNodeData,
                                           &actions) < 0)
        return 0;

    if (!actions)
        return 0;

    if (!active) {
        if (qemuBlockReopenReadWrite(vm, job->data.commit.base, asyncJob) < 0)
            return -1;
    }

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    qemuMonitorTransaction(priv->mon, &actions);

    qemuDomainObjExitMonitor(vm);

    if (!active) {
        if (qemuBlockReopenReadOnly(vm, job->data.commit.base, asyncJob) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuBlockJobProcessEventCompletedCommit:
 * @driver: qemu driver object
 * @vm: domain object
 * @job: job data
 * @asyncJob: qemu asynchronous job type (for monitor interaction)
 *
 * This function executes the finalizing steps after a successful block commit
 * job. The commit job moves the blocks from backing chain images starting from
 * 'top' into the 'base' image. The overlay of the 'top' image ('topparent')
 * then directly references the 'base' image. All intermediate images can be
 * removed/deleted.
 */
static void
qemuBlockJobProcessEventCompletedCommit(virQEMUDriver *driver,
                                        virDomainObj *vm,
                                        qemuBlockJobData *job,
                                        virDomainAsyncJob asyncJob)
{
    virStorageSource *baseparent = NULL;
    virDomainDiskDef *cfgdisk = NULL;
    virStorageSource *cfgnext = NULL;
    virStorageSource *cfgtopparent = NULL;
    virStorageSource *cfgtop = NULL;
    virStorageSource *cfgbase = NULL;
    virStorageSource *cfgbaseparent = NULL;
    virStorageSource *n;

    VIR_DEBUG("commit job '%s' on VM '%s' completed", job->name, vm->def->name);

    /* if the job isn't associated with a disk there's nothing to do */
    if (!job->disk)
        return;

    if ((cfgdisk = qemuBlockJobGetConfigDisk(vm, job->disk, job->data.commit.base)))
        cfgnext = cfgdisk->src;

    if (!cfgdisk)
        qemuBlockJobClearConfigChain(vm, job->disk);

    for (n = job->disk->src; n && n != job->data.commit.base; n = n->backingStore) {
        if (cfgnext) {
            if (n == job->data.commit.topparent)
                cfgtopparent = cfgnext;

            if (n == job->data.commit.top)
                cfgtop = cfgnext;

            cfgbaseparent = cfgnext;
            cfgnext = cfgnext->backingStore;
        }
        baseparent = n;
    }

    if (!n)
        return;

    if (qemuBlockJobProcessEventCompletedCommitBitmaps(vm, job, asyncJob) < 0)
        return;

    /* revert access to images */
    qemuDomainStorageSourceAccessAllow(driver, vm, job->data.commit.base,
                                       true, false, false);
    if (job->data.commit.topparent != job->disk->src)
        qemuDomainStorageSourceAccessAllow(driver, vm, job->data.commit.topparent,
                                           true, false, true);

    baseparent->backingStore = NULL;
    job->data.commit.topparent->backingStore = job->data.commit.base;

    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->data.commit.top);

    if (job->data.commit.deleteCommittedImages)
        qemuBlockJobDeleteImages(driver, vm, job->disk, job->data.commit.top);

    g_clear_pointer(&job->data.commit.top, virObjectUnref);

    if (cfgbaseparent) {
        cfgbase = g_steal_pointer(&cfgbaseparent->backingStore);

        if (cfgtopparent)
            cfgtopparent->backingStore = cfgbase;
        else
            cfgdisk->src = cfgbase;

        virObjectUnref(cfgtop);
    }
}


/**
 * qemuBlockJobProcessEventCompletedActiveCommit:
 * @driver: qemu driver object
 * @vm: domain object
 * @job: job data
 * @asyncJob: qemu asynchronous job type (for monitor interaction)
 *
 * This function executes the finalizing steps after a successful active layer
 * block commit job. The commit job moves the blocks from backing chain images
 * starting from the active disk source image into the 'base' image. The disk
 * source then changes to the 'base' image. All intermediate images can be
 * removed/deleted.
 */
static void
qemuBlockJobProcessEventCompletedActiveCommit(virQEMUDriver *driver,
                                              virDomainObj *vm,
                                              qemuBlockJobData *job,
                                              virDomainAsyncJob asyncJob)
{
    virStorageSource *baseparent = NULL;
    virDomainDiskDef *cfgdisk = NULL;
    virStorageSource *cfgnext = NULL;
    virStorageSource *cfgtop = NULL;
    virStorageSource *cfgbase = NULL;
    virStorageSource *cfgbaseparent = NULL;
    virStorageSource *n;

    VIR_DEBUG("active commit job '%s' on VM '%s' completed", job->name, vm->def->name);

    /* if the job isn't associated with a disk there's nothing to do */
    if (!job->disk)
        return;

    if ((cfgdisk = qemuBlockJobGetConfigDisk(vm, job->disk, job->data.commit.base)))
        cfgnext = cfgdisk->src;

    for (n = job->disk->src; n && n != job->data.commit.base; n = n->backingStore) {
        if (cfgnext) {
            if (n == job->data.commit.top)
                cfgtop = cfgnext;

            cfgbaseparent = cfgnext;
            cfgnext = cfgnext->backingStore;
        }
        baseparent = n;
    }

    if (!n)
        return;

    if (!cfgdisk) {
        /* in case when the config disk chain didn't match but the disk top seems
         * to be identical we need to modify the disk source since the active
         * commit makes the top level image invalid.
         */
        qemuBlockJobRewriteConfigDiskSource(vm, job->disk, job->data.commit.base);
    } else {
        cfgbase = g_steal_pointer(&cfgbaseparent->backingStore);
        cfgdisk->src = cfgbase;
        cfgdisk->src->readonly = cfgtop->readonly;
        virObjectUnref(cfgtop);
    }

    /* Move security driver metadata */
    if (qemuSecurityMoveImageMetadata(driver, vm, job->disk->src, job->data.commit.base) < 0)
        VIR_WARN("Unable to move disk metadata on vm %s", vm->def->name);

    baseparent->backingStore = NULL;
    job->disk->src = job->data.commit.base;
    job->disk->src->readonly = job->data.commit.top->readonly;

    if (qemuBlockJobProcessEventCompletedCommitBitmaps(vm, job, asyncJob) < 0)
        return;

    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->data.commit.top);

    if (job->data.commit.deleteCommittedImages)
        qemuBlockJobDeleteImages(driver, vm, job->disk, job->data.commit.top);

    g_clear_pointer(&job->data.commit.top, virObjectUnref);
    /* the mirror element does not serve functional purpose for the commit job */
    g_clear_pointer(&job->disk->mirror, virObjectUnref);
}


static int
qemuBlockJobProcessEventCompletedCopyBitmaps(virDomainObj *vm,
                                             qemuBlockJobData *job,
                                             virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    g_autoptr(GHashTable) blockNamedNodeData = NULL;
    g_autoptr(virJSONValue) actions = NULL;
    bool shallow = job->jobflags & VIR_DOMAIN_BLOCK_COPY_SHALLOW;

    if (!virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN))
        return 0;

    if (!(blockNamedNodeData = qemuBlockGetNamedNodeData(vm, asyncJob)))
        return -1;

    if (qemuBlockBitmapsHandleBlockcopy(job->disk->src,
                                        job->disk->mirror,
                                        blockNamedNodeData,
                                        shallow,
                                        &actions) < 0)
        return 0;

    if (!actions)
        return 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return -1;

    qemuMonitorTransaction(priv->mon, &actions);

    qemuDomainObjExitMonitor(vm);

    return 0;
}

static void
qemuBlockJobProcessEventConcludedCopyPivot(virQEMUDriver *driver,
                                           virDomainObj *vm,
                                           qemuBlockJobData *job,
                                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    VIR_DEBUG("copy job '%s' on VM '%s' pivoted", job->name, vm->def->name);

    /* mirror may be NULL for copy job corresponding to migration */
    if (!job->disk ||
        !job->disk->mirror)
        return;

    qemuBlockJobProcessEventCompletedCopyBitmaps(vm, job, asyncJob);

    /* for shallow copy without reusing external image the user can either not
     * specify the backing chain in which case libvirt will open and use the
     * chain the user provided or not specify a chain in which case we'll
     * inherit the rest of the chain */
    if (job->data.copy.shallownew &&
        !virStorageSourceIsBacking(job->disk->mirror->backingStore))
        job->disk->mirror->backingStore = g_steal_pointer(&job->disk->src->backingStore);

    if (job->disk->src->readonly &&
        virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_REOPEN))
        ignore_value(qemuBlockReopenReadOnly(vm, job->disk->mirror, asyncJob));

    qemuBlockJobRewriteConfigDiskSource(vm, job->disk, job->disk->mirror);

    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->disk->src);
    virObjectUnref(job->disk->src);
    job->disk->src = g_steal_pointer(&job->disk->mirror);
}


static void
qemuBlockJobProcessEventConcludedCopyAbort(virQEMUDriver *driver,
                                           virDomainObj *vm,
                                           qemuBlockJobData *job,
                                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    VIR_DEBUG("copy job '%s' on VM '%s' aborted", job->name, vm->def->name);

    /* mirror may be NULL for copy job corresponding to migration */
    if (!job->disk ||
        !job->disk->mirror)
        return;

    if (!job->jobflagsmissing) {
        bool shallow = job->jobflags & VIR_DOMAIN_BLOCK_COPY_SHALLOW;
        bool reuse = job->jobflags & VIR_DOMAIN_BLOCK_COPY_REUSE_EXT;

        /* In the special case of a shallow copy with reused image we don't
         * hotplug the full chain when QEMU_CAPS_BLOCKDEV_SNAPSHOT_ALLOW_WRITE_ONLY
         * is supported. Attempting to delete it would thus result in spurious
         * errors as we'd attempt to blockdev-del images which were not added
         * yet */
        if (reuse && shallow &&
            virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV_SNAPSHOT_ALLOW_WRITE_ONLY) &&
            virStorageSourceHasBacking(job->disk->mirror))
            g_clear_pointer(&job->disk->mirror->backingStore, virObjectUnref);
    }

    /* activeWrite bitmap is removed automatically here */
    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->disk->mirror);
    g_clear_pointer(&job->disk->mirror, virObjectUnref);
}


static void
qemuBlockJobProcessEventFailedActiveCommit(virQEMUDriver *driver,
                                           virDomainObj *vm,
                                           qemuBlockJobData *job,
                                           virDomainAsyncJob asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;
    virDomainDiskDef *disk = job->disk;

    VIR_DEBUG("active commit job '%s' on VM '%s' failed", job->name, vm->def->name);

    if (!disk)
        return;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return;

    qemuMonitorBitmapRemove(priv->mon,
                            qemuBlockStorageSourceGetEffectiveNodename(disk->mirror),
                            "libvirt-tmp-activewrite");

    qemuDomainObjExitMonitor(vm);

    /* Ideally, we would make the backing chain read only again (yes, SELinux
     * can do that using different labels). But that is not implemented yet and
     * not leaking security driver metadata is more important. */
    qemuBlockRemoveImageMetadata(driver, vm, disk->dst, disk->mirror);

    g_clear_pointer(&disk->mirror, virObjectUnref);
}


static void
qemuBlockJobProcessEventConcludedCreate(virQEMUDriver *driver,
                                        virDomainObj *vm,
                                        qemuBlockJobData *job,
                                        virDomainAsyncJob asyncJob)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;

    /* if there is a synchronous client waiting for this job that means that
     * it will handle further hotplug of the created volume and also that
     * the 'chain' which was registered is under their control */
    if (job->synchronous) {
        g_clear_pointer(&job->chain, virObjectUnref);
        return;
    }

    if (!job->data.create.src)
        return;

    if (!(backend = qemuBlockStorageSourceDetachPrepare(job->data.create.src)))
        return;

    /* the format node part was not attached yet, so we don't need to detach it */
    backend->formatAttached = false;
    if (job->data.create.storage) {
        size_t i;

        backend->storageAttached = false;
        backend->storageSliceAttached = false;
        for (i = 0; i < backend->encryptsecretCount; ++i) {
            VIR_FREE(backend->encryptsecretAlias[i]);
        }
        VIR_FREE(backend->encryptsecretAlias);
        VIR_FREE(backend->encryptsecretProps);
    }

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return;

    qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm), backend);

    qemuDomainObjExitMonitor(vm);

    qemuDomainStorageSourceAccessRevoke(driver, vm, job->data.create.src);
}


static void
qemuBlockJobProcessEventConcludedBackup(virQEMUDriver *driver,
                                        virDomainObj *vm,
                                        qemuBlockJobData *job,
                                        virDomainAsyncJob asyncJob,
                                        qemuBlockjobState newstate,
                                        unsigned long long progressCurrent,
                                        unsigned long long progressTotal)
{
    g_autoptr(qemuBlockStorageSourceAttachData) backend = NULL;

    qemuBackupNotifyBlockjobEnd(vm, job->disk, newstate, job->errmsg,
                                progressCurrent, progressTotal, asyncJob);

    if (job->data.backup.store &&
        !(backend = qemuBlockStorageSourceDetachPrepare(job->data.backup.store)))
        return;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        return;

    if (backend)
        qemuBlockStorageSourceAttachRollback(qemuDomainGetMonitor(vm), backend);

    if (job->data.backup.bitmap)
        qemuMonitorBitmapRemove(qemuDomainGetMonitor(vm),
                                qemuBlockStorageSourceGetEffectiveNodename(job->disk->src),
                                job->data.backup.bitmap);

    qemuDomainObjExitMonitor(vm);

    if (job->data.backup.store)
        qemuDomainStorageSourceAccessRevoke(driver, vm, job->data.backup.store);
}


static void
qemuBlockJobEventProcessConcludedTransition(qemuBlockJobData *job,
                                            virQEMUDriver *driver,
                                            virDomainObj *vm,
                                            virDomainAsyncJob asyncJob,
                                            unsigned long long progressCurrent,
                                            unsigned long long progressTotal)
{
    bool success = job->newstate == QEMU_BLOCKJOB_STATE_COMPLETED;

    switch ((qemuBlockJobType) job->type) {
    case QEMU_BLOCKJOB_TYPE_PULL:
        if (success)
            qemuBlockJobProcessEventCompletedPull(driver, vm, job, asyncJob);
        break;

    case QEMU_BLOCKJOB_TYPE_COMMIT:
        if (success)
            qemuBlockJobProcessEventCompletedCommit(driver, vm, job, asyncJob);
        break;

    case QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT:
        if (success) {
            qemuBlockJobProcessEventCompletedActiveCommit(driver, vm, job, asyncJob);
        } else {
            qemuBlockJobProcessEventFailedActiveCommit(driver, vm, job, asyncJob);
        }
        break;

    case QEMU_BLOCKJOB_TYPE_CREATE:
        qemuBlockJobProcessEventConcludedCreate(driver, vm, job, asyncJob);
        break;

    case QEMU_BLOCKJOB_TYPE_COPY:
        if (job->state == QEMU_BLOCKJOB_STATE_PIVOTING && success)
            qemuBlockJobProcessEventConcludedCopyPivot(driver, vm, job, asyncJob);
        else
            qemuBlockJobProcessEventConcludedCopyAbort(driver, vm, job, asyncJob);
        break;

    case QEMU_BLOCKJOB_TYPE_BACKUP:
        qemuBlockJobProcessEventConcludedBackup(driver, vm, job, asyncJob,
                                                job->newstate, progressCurrent,
                                                progressTotal);
        break;

    case QEMU_BLOCKJOB_TYPE_BROKEN:
    case QEMU_BLOCKJOB_TYPE_NONE:
    case QEMU_BLOCKJOB_TYPE_INTERNAL:
    case QEMU_BLOCKJOB_TYPE_LAST:
    default:
        break;
    }

    qemuBlockJobEmitEvents(driver, vm, job->disk, job->type, job->newstate);
    job->state = job->newstate;
    job->newstate = -1;
}


static void
qemuBlockJobEventProcessConcluded(qemuBlockJobData *job,
                                  virQEMUDriver *driver,
                                  virDomainObj *vm,
                                  virDomainAsyncJob asyncJob)
{
    qemuMonitorJobInfo **jobinfo = NULL;
    size_t njobinfo = 0;
    size_t i;
    bool refreshed = false;
    unsigned long long progressCurrent = 0;
    unsigned long long progressTotal = 0;

    if (qemuDomainObjEnterMonitorAsync(vm, asyncJob) < 0)
        goto cleanup;

    /* we need to fetch the error state as the event does not propagate it */
    if (job->newstate == QEMU_BLOCKJOB_STATE_CONCLUDED &&
        qemuMonitorGetJobInfo(qemuDomainGetMonitor(vm), &jobinfo, &njobinfo) == 0) {

        for (i = 0; i < njobinfo; i++) {
            if (STRNEQ_NULLABLE(job->name, jobinfo[i]->id))
                continue;

            progressCurrent = jobinfo[i]->progressCurrent;
            progressTotal = jobinfo[i]->progressTotal;

            job->errmsg = g_strdup(jobinfo[i]->error);

            if (job->errmsg)
                job->newstate = QEMU_BLOCKJOB_STATE_FAILED;
            else
                job->newstate = QEMU_BLOCKJOB_STATE_COMPLETED;

            refreshed = true;

            break;
        }

        if (i == njobinfo)
            VIR_WARN("failed to refresh job '%s'", job->name);
    }

    /* dismiss job in qemu */
    ignore_value(qemuMonitorJobDismiss(qemuDomainGetMonitor(vm), job->name));

    qemuDomainObjExitMonitor(vm);

    if ((job->newstate == QEMU_BLOCKJOB_STATE_COMPLETED ||
         job->newstate == QEMU_BLOCKJOB_STATE_FAILED) &&
        job->state == QEMU_BLOCKJOB_STATE_ABORTING)
        job->newstate = QEMU_BLOCKJOB_STATE_CANCELLED;

    if (refreshed)
        qemuDomainSaveStatus(vm);

    VIR_DEBUG("handling job '%s' state '%d' newstate '%d'", job->name, job->state, job->newstate);

    qemuBlockJobEventProcessConcludedTransition(job, driver, vm, asyncJob,
                                                progressCurrent, progressTotal);

    /* unplug the backing chains in case the job inherited them */
    if (!job->disk) {
        if (job->chain)
            qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob,
                                                         job->chain);
        if (job->mirrorChain)
            qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob,
                                                         job->mirrorChain);
    }

 cleanup:
    qemuBlockJobUnregister(job, vm);
    qemuDomainSaveConfig(vm);

    for (i = 0; i < njobinfo; i++)
        qemuMonitorJobInfoFree(jobinfo[i]);
    VIR_FREE(jobinfo);
}


static void
qemuBlockJobEventProcess(virQEMUDriver *driver,
                         virDomainObj *vm,
                         qemuBlockJobData *job,
                         virDomainAsyncJob asyncJob)

{
    switch ((qemuBlockjobState) job->newstate) {
    case QEMU_BLOCKJOB_STATE_COMPLETED:
    case QEMU_BLOCKJOB_STATE_FAILED:
    case QEMU_BLOCKJOB_STATE_CANCELLED:
    case QEMU_BLOCKJOB_STATE_CONCLUDED:
        if (job->disk) {
            job->disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
            job->disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        }
        qemuBlockJobEventProcessConcluded(job, driver, vm, asyncJob);
        break;

    case QEMU_BLOCKJOB_STATE_READY:
        /* in certain cases qemu can blip out and back into 'ready' state for
         * a blockjob. In cases when we already are past RUNNING the job such
         * as when pivoting/aborting this could reset the internally set job
         * state, thus we ignore it if the job isn't in expected state */
        if (job->state == QEMU_BLOCKJOB_STATE_NEW ||
            job->state == QEMU_BLOCKJOB_STATE_RUNNING) {
            /* mirror may be NULL for copy job corresponding to migration */
            if (job->disk) {
                job->disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
                qemuBlockJobEmitEvents(driver, vm, job->disk, job->type, job->newstate);
            }
            job->state = job->newstate;
            qemuDomainSaveStatus(vm);
        }
        job->newstate = -1;
        break;

    case QEMU_BLOCKJOB_STATE_PENDING:
        /* Similarly as for 'ready' state we should handle it only when
         * previous state was 'new' or 'running' and only if the blockjob code
         * is handling finalization of the job explicitly. */
        if (job->processPending) {
            if (job->state == QEMU_BLOCKJOB_STATE_NEW ||
                job->state == QEMU_BLOCKJOB_STATE_RUNNING) {
                job->state = job->newstate;
                qemuDomainSaveStatus(vm);
            }
        }
        job->newstate = -1;
        break;

    case QEMU_BLOCKJOB_STATE_NEW:
    case QEMU_BLOCKJOB_STATE_RUNNING:
    case QEMU_BLOCKJOB_STATE_LAST:
    /* these are never processed as 'newstate' */
    case QEMU_BLOCKJOB_STATE_ABORTING:
    case QEMU_BLOCKJOB_STATE_PIVOTING:
    default:
        job->newstate = -1;
    }
}


/**
 * qemuBlockJobUpdate:
 * @vm: domain
 * @job: job data
 * @asyncJob: current qemu asynchronous job type
 *
 * Update disk's mirror state in response to a block job event stored in
 * blockJobStatus by qemuProcessHandleBlockJob event handler.
 */
void
qemuBlockJobUpdate(virDomainObj *vm,
                   qemuBlockJobData *job,
                   int asyncJob)
{
    qemuDomainObjPrivate *priv = vm->privateData;

    if (job->newstate == -1)
        return;

    qemuBlockJobEventProcess(priv->driver, vm, job, asyncJob);
}


/**
 * qemuBlockJobSyncBegin:
 * @job: block job data
 * @disk: domain disk
 *
 * Begin a new synchronous block job for @disk. The synchronous
 * block job is ended by a call to qemuBlockJobSyncEnd, or by
 * the guest quitting.
 *
 * During a synchronous block job, a block job event for @disk
 * will not be processed asynchronously. Instead, it will be
 * processed only when qemuBlockJobUpdate or qemuBlockJobSyncEnd
 * is called.
 */
void
qemuBlockJobSyncBegin(qemuBlockJobData *job)
{
    const char *diskdst = NULL;

    if (job->disk)
        diskdst = job->disk->dst;

    VIR_DEBUG("disk=%s", NULLSTR(diskdst));
    job->synchronous = true;
}


/**
 * qemuBlockJobSyncEnd:
 * @vm: domain
 * @disk: domain disk
 *
 * End a synchronous block job for @disk. Any pending block job event
 * for the disk is processed. Note that it's not necessary to call this function
 * in case the block job was not started successfully if
 * qemuBlockJobStartupFinalize will be called.
 */
void
qemuBlockJobSyncEnd(virDomainObj *vm,
                    qemuBlockJobData *job,
                    int asyncJob)
{
    const char *diskdst = NULL;

    if (job->disk)
        diskdst = job->disk->dst;

    VIR_DEBUG("disk=%s", NULLSTR(diskdst));
    job->synchronous = false;
    qemuBlockJobUpdate(vm, job, asyncJob);
}


qemuBlockJobData *
qemuBlockJobGetByDisk(virDomainDiskDef *disk)
{
    qemuBlockJobData *job = QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob;

    if (!job)
        return NULL;

    return virObjectRef(job);
}


/**
 * @monitorstatus: Status of the blockjob from qemu monitor (qemuMonitorJobStatus)
 *
 * Converts the block job status from the monitor to the one used by
 * qemuBlockJobData. If the status is unknown or does not require any handling
 * QEMU_BLOCKJOB_TYPE_LAST is returned.
 */
qemuBlockjobState
qemuBlockjobConvertMonitorStatus(int monitorstatus)
{
    qemuBlockjobState ret = QEMU_BLOCKJOB_STATE_LAST;

    switch ((qemuMonitorJobStatus) monitorstatus) {
    case QEMU_MONITOR_JOB_STATUS_READY:
        ret = QEMU_BLOCKJOB_STATE_READY;
        break;

    case QEMU_MONITOR_JOB_STATUS_CONCLUDED:
        ret = QEMU_BLOCKJOB_STATE_CONCLUDED;
        break;

    case QEMU_MONITOR_JOB_STATUS_PENDING:
        ret = QEMU_BLOCKJOB_STATE_PENDING;
        break;

    case QEMU_MONITOR_JOB_STATUS_UNKNOWN:
    case QEMU_MONITOR_JOB_STATUS_CREATED:
    case QEMU_MONITOR_JOB_STATUS_RUNNING:
    case QEMU_MONITOR_JOB_STATUS_PAUSED:
    case QEMU_MONITOR_JOB_STATUS_STANDBY:
    case QEMU_MONITOR_JOB_STATUS_WAITING:
    case QEMU_MONITOR_JOB_STATUS_ABORTING:
    case QEMU_MONITOR_JOB_STATUS_UNDEFINED:
    case QEMU_MONITOR_JOB_STATUS_NULL:
    case QEMU_MONITOR_JOB_STATUS_LAST:
    default:
        break;
    }

    return ret;

}
