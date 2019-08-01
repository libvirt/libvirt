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

#include "conf/domain_conf.h"
#include "conf/domain_event.h"

#include "virlog.h"
#include "virstoragefile.h"
#include "virthread.h"
#include "virtime.h"
#include "locking/domain_lock.h"
#include "viralloc.h"
#include "virstring.h"
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
              "pivoting");

VIR_ENUM_IMPL(qemuBlockjob,
              QEMU_BLOCKJOB_TYPE_LAST,
              "",
              "pull",
              "copy",
              "commit",
              "active-commit",
              "");

static virClassPtr qemuBlockJobDataClass;


static void
qemuBlockJobDataDispose(void *obj)
{
    qemuBlockJobDataPtr job = obj;

    virObjectUnref(job->chain);
    virObjectUnref(job->mirrorChain);

    VIR_FREE(job->name);
    VIR_FREE(job->errmsg);
}


static int
qemuBlockJobDataOnceInit(void)
{
    if (!VIR_CLASS_NEW(qemuBlockJobData, virClassForObject()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(qemuBlockJobData);

qemuBlockJobDataPtr
qemuBlockJobDataNew(qemuBlockJobType type,
                    const char *name)
{
    VIR_AUTOUNREF(qemuBlockJobDataPtr) job = NULL;

    if (qemuBlockJobDataInitialize() < 0)
        return NULL;

    if (!(job = virObjectNew(qemuBlockJobDataClass)))
        return NULL;

    if (VIR_STRDUP(job->name, name) < 0)
        return NULL;

    job->state = QEMU_BLOCKJOB_STATE_NEW;
    job->newstate = -1;
    job->type = type;

    VIR_RETURN_PTR(job);
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
qemuBlockJobRegister(qemuBlockJobDataPtr job,
                     virDomainObjPtr vm,
                     virDomainDiskDefPtr disk,
                     bool savestatus)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

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
qemuBlockJobUnregister(qemuBlockJobDataPtr job,
                       virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuDomainDiskPrivatePtr diskPriv;

    if (job->disk) {
        diskPriv = QEMU_DOMAIN_DISK_PRIVATE(job->disk);

        if (job == diskPriv->blockjob) {
            virObjectUnref(diskPriv->blockjob);
            diskPriv->blockjob = NULL;
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
 *
 * Returns 0 on success and -1 on failure.
 */
qemuBlockJobDataPtr
qemuBlockJobDiskNew(virDomainObjPtr vm,
                    virDomainDiskDefPtr disk,
                    qemuBlockJobType type,
                    const char *jobname)
{
    VIR_AUTOUNREF(qemuBlockJobDataPtr) job = NULL;

    if (!(job = qemuBlockJobDataNew(type, jobname)))
        return NULL;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    VIR_RETURN_PTR(job);
}


qemuBlockJobDataPtr
qemuBlockJobDiskNewPull(virDomainObjPtr vm,
                        virDomainDiskDefPtr disk,
                        virStorageSourcePtr base)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    VIR_AUTOUNREF(qemuBlockJobDataPtr) job = NULL;
    VIR_AUTOFREE(char *) jobname = NULL;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV)) {
        if (virAsprintf(&jobname, "pull-%s-%s", disk->dst, disk->src->nodeformat) < 0)
            return NULL;
    } else {
        if (!(jobname = qemuAliasDiskDriveFromDisk(disk)))
            return NULL;
    }

    if (!(job = qemuBlockJobDataNew(QEMU_BLOCKJOB_TYPE_PULL, jobname)))
        return NULL;

    job->data.pull.base = base;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    VIR_RETURN_PTR(job);
}


qemuBlockJobDataPtr
qemuBlockJobDiskNewCommit(virDomainObjPtr vm,
                          virDomainDiskDefPtr disk,
                          virStorageSourcePtr topparent,
                          virStorageSourcePtr top,
                          virStorageSourcePtr base)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    VIR_AUTOUNREF(qemuBlockJobDataPtr) job = NULL;
    VIR_AUTOFREE(char *) jobname = NULL;
    qemuBlockJobType jobtype = QEMU_BLOCKJOB_TYPE_COMMIT;

    if (topparent == NULL)
        jobtype = QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV)) {
        if (virAsprintf(&jobname, "commit-%s-%s", disk->dst, top->nodeformat) < 0)
            return NULL;
    } else {
        if (!(jobname = qemuAliasDiskDriveFromDisk(disk)))
            return NULL;
    }

    if (!(job = qemuBlockJobDataNew(jobtype, jobname)))
        return NULL;

    job->data.commit.topparent = topparent;
    job->data.commit.top = top;
    job->data.commit.base = base;

    if (qemuBlockJobRegister(job, vm, disk, true) < 0)
        return NULL;

    VIR_RETURN_PTR(job);
}


/**
 * qemuBlockJobDiskGetJob:
 * @disk: disk definition
 *
 * Get a reference to the block job data object associated with @disk.
 */
qemuBlockJobDataPtr
qemuBlockJobDiskGetJob(virDomainDiskDefPtr disk)
{
    qemuBlockJobDataPtr job = QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob;

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
qemuBlockJobStarted(qemuBlockJobDataPtr job,
                    virDomainObjPtr vm)
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
qemuBlockJobStartupFinalize(virDomainObjPtr vm,
                            qemuBlockJobDataPtr job)
{
    if (!job)
        return;

    if (job->state == QEMU_BLOCKJOB_STATE_NEW)
        qemuBlockJobUnregister(job, vm);

    virObjectUnref(job);
}


bool
qemuBlockJobIsRunning(qemuBlockJobDataPtr job)
{
    return job->state == QEMU_BLOCKJOB_STATE_RUNNING ||
           job->state == QEMU_BLOCKJOB_STATE_READY ||
           job->state == QEMU_BLOCKJOB_STATE_ABORTING ||
           job->state == QEMU_BLOCKJOB_STATE_PIVOTING;
}


/* returns 1 for a job we didn't reconnect to */
static int
qemuBlockJobRefreshJobsFindInactive(const void *payload,
                                    const void *name ATTRIBUTE_UNUSED,
                                    const void *data ATTRIBUTE_UNUSED)
{
    const qemuBlockJobData *job = payload;

    return !job->reconnected;
}


int
qemuBlockJobRefreshJobs(virQEMUDriverPtr driver,
                        virDomainObjPtr vm)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;
    qemuMonitorJobInfoPtr *jobinfo = NULL;
    size_t njobinfo = 0;
    qemuBlockJobDataPtr job = NULL;
    int newstate;
    size_t i;
    int ret = -1;
    int rc;

    qemuDomainObjEnterMonitor(driver, vm);

    rc = qemuMonitorGetJobInfo(priv->mon, &jobinfo, &njobinfo);

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    for (i = 0; i < njobinfo; i++) {
        if (!(job = virHashLookup(priv->blockjobs, jobinfo[i]->id))) {
            VIR_DEBUG("ignoring untracked job '%s'", jobinfo[i]->id);
            continue;
        }

        /* try cancelling invalid jobs - this works only if the job is not
         * concluded. In such case it will fail. We'll leave such job linger
         * in qemu and just forget about it in libvirt because there's not much
         * we coud do besides killing the VM */
        if (job->invalidData) {
            qemuDomainObjEnterMonitor(driver, vm);

            rc = qemuMonitorJobCancel(priv->mon, job->name, true);
            if (rc == -1 && jobinfo[i]->status == QEMU_MONITOR_JOB_STATUS_CONCLUDED)
                VIR_WARN("can't cancel job '%s' with invalid data", job->name);

            if (qemuDomainObjExitMonitor(driver, vm) < 0)
                goto cleanup;

            if (rc < 0)
                qemuBlockJobUnregister(job, vm);
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
                if (VIR_STRDUP(job->errmsg, jobinfo[i]->error) < 0)
                    goto cleanup;

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
            qemuBlockJobUpdate(vm, job, QEMU_ASYNC_JOB_NONE);
    }

    /* remove data for job which qemu didn't report (the algorithm is
     * inefficient, but the possibility of such jobs is very low */
    while ((job = virHashSearch(priv->blockjobs, qemuBlockJobRefreshJobsFindInactive, NULL, NULL)))
        qemuBlockJobUnregister(job, vm);

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
qemuBlockJobEmitEvents(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       virDomainDiskDefPtr disk,
                       virDomainBlockJobType type,
                       virConnectDomainEventBlockJobStatus status)
{
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;

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
qemuBlockJobCleanStorageSourceRuntime(virStorageSourcePtr src)
{
    src->id = 0;
    src->detected = false;
    VIR_FREE(src->relPath);
    VIR_FREE(src->backingStoreRaw);
    VIR_FREE(src->nodestorage);
    VIR_FREE(src->nodeformat);
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
qemuBlockJobRewriteConfigDiskSource(virDomainObjPtr vm,
                                    virDomainDiskDefPtr disk,
                                    virStorageSourcePtr newsrc)
{
    virDomainDiskDefPtr persistDisk = NULL;
    VIR_AUTOUNREF(virStorageSourcePtr) copy = NULL;

    if (!vm->newDef)
        return;

    if (!(persistDisk = virDomainDiskByName(vm->newDef, disk->dst, false)))
        return;

    if (!virStorageSourceIsSameLocation(disk->src, persistDisk->src))
        return;

    if (!(copy = virStorageSourceCopy(newsrc, false)) ||
        virStorageSourceInitChainElement(copy, persistDisk->src, true) < 0) {
        VIR_WARN("Unable to update persistent definition on vm %s after block job",
                 vm->def->name);
        return;
    }

    qemuBlockJobCleanStorageSourceRuntime(copy);

    virObjectUnref(persistDisk->src);
    VIR_STEAL_PTR(persistDisk->src, copy);
}


static void
qemuBlockJobEventProcessLegacyCompleted(virQEMUDriverPtr driver,
                                        virDomainObjPtr vm,
                                        qemuBlockJobDataPtr job,
                                        int asyncJob)
{
    virDomainDiskDefPtr disk = job->disk;

    if (!disk)
        return;

    if (disk->mirrorState == VIR_DOMAIN_DISK_MIRROR_STATE_PIVOT) {
        qemuBlockJobRewriteConfigDiskSource(vm, disk, disk->mirror);
        /* XXX We want to revoke security labels as well as audit that
         * revocation, before dropping the original source.  But it gets
         * tricky if both source and mirror share common backing files (we
         * want to only revoke the non-shared portion of the chain); so for
         * now, we leak the access to the original.  */
        virDomainLockImageDetach(driver->lockManager, vm, disk->src);

        /* Move secret driver metadata */
        if (qemuSecurityMoveImageMetadata(driver, vm, disk->src, disk->mirror) < 0)
            VIR_WARN("Unable to move disk metadata on vm %s", vm->def->name);

        virObjectUnref(disk->src);
        disk->src = disk->mirror;
    } else {
        if (disk->mirror) {
            virDomainLockImageDetach(driver->lockManager, vm, disk->mirror);
            virObjectUnref(disk->mirror);
        }
    }

    /* Recompute the cached backing chain to match our
     * updates.  Better would be storing the chain ourselves
     * rather than reprobing, but we haven't quite completed
     * that conversion to use our XML tracking. */
    disk->mirror = NULL;
    disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
    disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
    disk->src->id = 0;
    virStorageSourceBackingStoreClear(disk->src);
    ignore_value(qemuDomainDetermineDiskChain(driver, vm, disk, NULL, true));
    ignore_value(qemuBlockNodeNamesDetect(driver, vm, asyncJob));
    qemuBlockJobUnregister(job, vm);
    qemuDomainSaveConfig(vm);
}


/**
 * qemuBlockJobEventProcessLegacy:
 * @driver: qemu driver
 * @vm: domain
 * @job: job to process events for
 *
 * Update disk's mirror state in response to a block job event
 * from QEMU. For mirror state's that must survive libvirt
 * restart, also update the domain's status XML.
 */
static void
qemuBlockJobEventProcessLegacy(virQEMUDriverPtr driver,
                               virDomainObjPtr vm,
                               qemuBlockJobDataPtr job,
                               int asyncJob)
{
    virDomainDiskDefPtr disk = job->disk;

    VIR_DEBUG("disk=%s, mirrorState=%s, type=%d, state=%d, newstate=%d",
              disk->dst,
              NULLSTR(virDomainDiskMirrorStateTypeToString(disk->mirrorState)),
              job->type,
              job->state,
              job->newstate);

    if (job->newstate == -1)
        return;

    qemuBlockJobEmitEvents(driver, vm, disk, job->type, job->newstate);

    job->state = job->newstate;
    job->newstate = -1;

    /* If we completed a block pull or commit, then update the XML
     * to match.  */
    switch ((virConnectDomainEventBlockJobStatus) job->state) {
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        qemuBlockJobEventProcessLegacyCompleted(driver, vm, job, asyncJob);
        break;

    case VIR_DOMAIN_BLOCK_JOB_READY:
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
        qemuDomainSaveStatus(vm);
        break;

    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        if (disk->mirror) {
            virDomainLockImageDetach(driver->lockManager, vm, disk->mirror);
            virObjectUnref(disk->mirror);
            disk->mirror = NULL;
        }
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        qemuBlockJobUnregister(job, vm);
        break;

    case VIR_DOMAIN_BLOCK_JOB_LAST:
        break;
    }
}


static void
qemuBlockJobEventProcessConcludedRemoveChain(virQEMUDriverPtr driver,
                                             virDomainObjPtr vm,
                                             qemuDomainAsyncJob asyncJob,
                                             virStorageSourcePtr chain)
{
    VIR_AUTOPTR(qemuBlockStorageSourceChainData) data = NULL;

    if (!(data = qemuBlockStorageSourceChainDetachPrepareBlockdev(chain)))
        return;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        return;

    qemuBlockStorageSourceChainDetach(qemuDomainGetMonitor(vm), data);
    if (qemuDomainObjExitMonitor(driver, vm) < 0)
        return;

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
static virDomainDiskDefPtr
qemuBlockJobGetConfigDisk(virDomainObjPtr vm,
                          virDomainDiskDefPtr disk,
                          virStorageSourcePtr diskChainBottom)
{
    virStorageSourcePtr disksrc = NULL;
    virStorageSourcePtr cfgsrc = NULL;
    virDomainDiskDefPtr ret = NULL;

    if (!vm->newDef || !disk)
        return NULL;

    disksrc = disk->src;

    if (!(ret = virDomainDiskByName(vm->newDef, disk->dst, false)))
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
qemuBlockJobClearConfigChain(virDomainObjPtr vm,
                             virDomainDiskDefPtr disk)
{
    virDomainDiskDefPtr cfgdisk = NULL;

    if (!vm->newDef || !disk)
        return;

    if (!(cfgdisk = virDomainDiskByName(vm->newDef, disk->dst, false)))
        return;

    if (!virStorageSourceIsSameLocation(disk->src, cfgdisk->src))
        return;

    virObjectUnref(cfgdisk->src->backingStore);
    cfgdisk->src->backingStore = NULL;
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
qemuBlockJobProcessEventCompletedPull(virQEMUDriverPtr driver,
                                      virDomainObjPtr vm,
                                      qemuBlockJobDataPtr job,
                                      qemuDomainAsyncJob asyncJob)
{
    virStorageSourcePtr baseparent = NULL;
    virDomainDiskDefPtr cfgdisk = NULL;
    virStorageSourcePtr cfgbase = NULL;
    virStorageSourcePtr cfgbaseparent = NULL;
    virStorageSourcePtr n;
    virStorageSourcePtr tmp;

    VIR_DEBUG("pull job '%s' on VM '%s' completed", job->name, vm->def->name);

    /* if the job isn't associated with a disk there's nothing to do */
    if (!job->disk)
        return;

    if ((cfgdisk = qemuBlockJobGetConfigDisk(vm, job->disk, job->data.pull.base)))
        cfgbase = cfgdisk->src->backingStore;

    if (!cfgdisk)
        qemuBlockJobClearConfigChain(vm, job->disk);

    /* when pulling if 'base' is right below the top image we don't have to modify it */
    if (job->disk->src->backingStore == job->data.pull.base)
        return;

    if (job->data.pull.base) {
        for (n = job->disk->src->backingStore; n && n != job->data.pull.base; n = n->backingStore) {
            /* find the image on top of 'base' */

            if (cfgbase) {
                cfgbaseparent = cfgbase;
                cfgbase = cfgbase->backingStore;
            }

            baseparent = n;
        }
    }

    tmp = job->disk->src->backingStore;
    job->disk->src->backingStore = job->data.pull.base;
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
qemuBlockJobProcessEventCompletedCommit(virQEMUDriverPtr driver,
                                        virDomainObjPtr vm,
                                        qemuBlockJobDataPtr job,
                                        qemuDomainAsyncJob asyncJob)
{
    virStorageSourcePtr baseparent = NULL;
    virDomainDiskDefPtr cfgdisk = NULL;
    virStorageSourcePtr cfgnext = NULL;
    virStorageSourcePtr cfgtopparent = NULL;
    virStorageSourcePtr cfgtop = NULL;
    virStorageSourcePtr cfgbase = NULL;
    virStorageSourcePtr cfgbaseparent = NULL;
    virStorageSourcePtr n;

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

    /* revert access to images */
    qemuDomainStorageSourceAccessAllow(driver, vm, job->data.commit.base, true, false);
    if (job->data.commit.topparent != job->disk->src)
        qemuDomainStorageSourceAccessAllow(driver, vm, job->data.commit.topparent, true, false);

    baseparent->backingStore = NULL;
    job->data.commit.topparent->backingStore = job->data.commit.base;

    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->data.commit.top);
    virObjectUnref(job->data.commit.top);
    job->data.commit.top = NULL;

    if (cfgbaseparent) {
        cfgbase = cfgbaseparent->backingStore;
        cfgbaseparent->backingStore = NULL;

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
qemuBlockJobProcessEventCompletedActiveCommit(virQEMUDriverPtr driver,
                                              virDomainObjPtr vm,
                                              qemuBlockJobDataPtr job,
                                              qemuDomainAsyncJob asyncJob)
{
    virStorageSourcePtr baseparent = NULL;
    virDomainDiskDefPtr cfgdisk = NULL;
    virStorageSourcePtr cfgnext = NULL;
    virStorageSourcePtr cfgtop = NULL;
    virStorageSourcePtr cfgbase = NULL;
    virStorageSourcePtr cfgbaseparent = NULL;
    virStorageSourcePtr n;

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
        cfgbase = cfgbaseparent->backingStore;
        cfgbaseparent->backingStore = NULL;
        cfgdisk->src = cfgbase;
        virObjectUnref(cfgtop);
    }

    /* Move security driver metadata */
    if (qemuSecurityMoveImageMetadata(driver, vm, job->disk->src, job->data.commit.base) < 0)
        VIR_WARN("Unable to move disk metadata on vm %s", vm->def->name);

    baseparent->backingStore = NULL;
    job->disk->src = job->data.commit.base;

    qemuBlockJobEventProcessConcludedRemoveChain(driver, vm, asyncJob, job->data.commit.top);
    virObjectUnref(job->data.commit.top);
    job->data.commit.top = NULL;
    /* the mirror element does not serve functional purpose for the commit job */
    virObjectUnref(job->disk->mirror);
    job->disk->mirror = NULL;
}

static void
qemuBlockJobEventProcessConcludedTransition(qemuBlockJobDataPtr job,
                                            virQEMUDriverPtr driver,
                                            virDomainObjPtr vm,
                                            qemuDomainAsyncJob asyncJob)
{
    switch ((qemuBlockjobState) job->newstate) {
    case QEMU_BLOCKJOB_STATE_COMPLETED:
        switch ((qemuBlockJobType) job->type) {
        case QEMU_BLOCKJOB_TYPE_PULL:
            qemuBlockJobProcessEventCompletedPull(driver, vm, job, asyncJob);
            break;

        case QEMU_BLOCKJOB_TYPE_COMMIT:
            qemuBlockJobProcessEventCompletedCommit(driver, vm, job, asyncJob);
            break;

        case QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT:
            qemuBlockJobProcessEventCompletedActiveCommit(driver, vm, job, asyncJob);
            break;

        case QEMU_BLOCKJOB_TYPE_COPY:
        case QEMU_BLOCKJOB_TYPE_NONE:
        case QEMU_BLOCKJOB_TYPE_INTERNAL:
        case QEMU_BLOCKJOB_TYPE_LAST:
        default:
            break;
        }
        break;

    case QEMU_BLOCKJOB_STATE_FAILED:
    case QEMU_BLOCKJOB_STATE_CANCELLED:
        switch ((qemuBlockJobType) job->type) {
        case QEMU_BLOCKJOB_TYPE_PULL:
        case QEMU_BLOCKJOB_TYPE_COMMIT:
            break;

        case QEMU_BLOCKJOB_TYPE_ACTIVE_COMMIT:
            if (job->disk) {
                virObjectUnref(job->disk->mirror);
                job->disk->mirror = NULL;
            }
            break;

        case QEMU_BLOCKJOB_TYPE_COPY:
        case QEMU_BLOCKJOB_TYPE_NONE:
        case QEMU_BLOCKJOB_TYPE_INTERNAL:
        case QEMU_BLOCKJOB_TYPE_LAST:
        default:
            break;
        }
        break;

    /* states below are impossible in this handler */
    case QEMU_BLOCKJOB_STATE_READY:
    case QEMU_BLOCKJOB_STATE_NEW:
    case QEMU_BLOCKJOB_STATE_RUNNING:
    case QEMU_BLOCKJOB_STATE_CONCLUDED:
    case QEMU_BLOCKJOB_STATE_ABORTING:
    case QEMU_BLOCKJOB_STATE_PIVOTING:
    case QEMU_BLOCKJOB_STATE_LAST:
    default:
        break;
    }

    qemuBlockJobEmitEvents(driver, vm, job->disk, job->type, job->newstate);
    job->state = job->newstate;
    job->newstate = -1;
}


static void
qemuBlockJobEventProcessConcluded(qemuBlockJobDataPtr job,
                                  virQEMUDriverPtr driver,
                                  virDomainObjPtr vm,
                                  qemuDomainAsyncJob asyncJob)
{
    qemuMonitorJobInfoPtr *jobinfo = NULL;
    size_t njobinfo = 0;
    size_t i;
    int rc = 0;
    bool dismissed = false;
    bool refreshed = false;

    if (qemuDomainObjEnterMonitorAsync(driver, vm, asyncJob) < 0)
        goto cleanup;

    /* we need to fetch the error state as the event does not propagate it */
    if (job->newstate == QEMU_BLOCKJOB_STATE_CONCLUDED &&
        (rc = qemuMonitorGetJobInfo(qemuDomainGetMonitor(vm), &jobinfo, &njobinfo)) == 0) {

        for (i = 0; i < njobinfo; i++) {
            if (STRNEQ_NULLABLE(job->name, jobinfo[i]->id))
                continue;

            if (VIR_STRDUP(job->errmsg, jobinfo[i]->error) < 0)
                rc = -1;

            if (job->errmsg)
                job->newstate = QEMU_BLOCKJOB_STATE_FAILED;
            else
                job->newstate = QEMU_BLOCKJOB_STATE_COMPLETED;

            refreshed = true;

            break;
        }

        if (i == njobinfo) {
            VIR_WARN("failed to refresh job '%s'", job->name);
            rc = -1;
        }
    }

    /* dismiss job in qemu */
    if (rc >= 0) {
        if ((rc = qemuMonitorJobDismiss(qemuDomainGetMonitor(vm), job->name)) >= 0)
            dismissed = true;
    }

    if (job->invalidData) {
        VIR_WARN("terminating job '%s' with invalid data", job->name);
        goto cleanup;
    }

    if (qemuDomainObjExitMonitor(driver, vm) < 0 || rc < 0)
        goto cleanup;

    if (job->newstate == QEMU_BLOCKJOB_STATE_COMPLETED &&
        job->state == QEMU_BLOCKJOB_STATE_ABORTING)
        job->newstate = QEMU_BLOCKJOB_STATE_CANCELLED;

    if (refreshed)
        qemuDomainSaveStatus(vm);

    VIR_DEBUG("handling job '%s' state '%d' newstate '%d'", job->name, job->state, job->newstate);

    qemuBlockJobEventProcessConcludedTransition(job, driver, vm, asyncJob);

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
    if (dismissed) {
        qemuBlockJobUnregister(job, vm);
        qemuDomainSaveConfig(vm);
    }

    for (i = 0; i < njobinfo; i++)
        qemuMonitorJobInfoFree(jobinfo[i]);
    VIR_FREE(jobinfo);
}


static void
qemuBlockJobEventProcess(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         qemuBlockJobDataPtr job,
                         qemuDomainAsyncJob asyncJob)

{
    switch ((qemuBlockjobState) job->newstate) {
    case QEMU_BLOCKJOB_STATE_COMPLETED:
    case QEMU_BLOCKJOB_STATE_FAILED:
    case QEMU_BLOCKJOB_STATE_CANCELLED:
    case QEMU_BLOCKJOB_STATE_CONCLUDED:
        qemuBlockJobEventProcessConcluded(job, driver, vm, asyncJob);
        break;

    case QEMU_BLOCKJOB_STATE_READY:
        if (job->disk && job->disk->mirror) {
            job->disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
            qemuBlockJobEmitEvents(driver, vm, job->disk, job->type, job->newstate);
        }
        job->state = job->newstate;
        job->newstate = -1;
        qemuDomainSaveStatus(vm);
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
 *
 * Returns the block job event processed or -1 if there was no pending event.
 */
int
qemuBlockJobUpdate(virDomainObjPtr vm,
                   qemuBlockJobDataPtr job,
                   int asyncJob)
{
    qemuDomainObjPrivatePtr priv = vm->privateData;

    if (job->newstate == -1)
        return -1;

    if (virQEMUCapsGet(priv->qemuCaps, QEMU_CAPS_BLOCKDEV))
        qemuBlockJobEventProcess(priv->driver, vm, job, asyncJob);
    else
        qemuBlockJobEventProcessLegacy(priv->driver, vm, job, asyncJob);

    return job->state;
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
qemuBlockJobSyncBegin(qemuBlockJobDataPtr job)
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
qemuBlockJobSyncEnd(virDomainObjPtr vm,
                    qemuBlockJobDataPtr job,
                    int asyncJob)
{
    const char *diskdst = NULL;

    if (job->disk)
        diskdst = job->disk->dst;

    VIR_DEBUG("disk=%s", NULLSTR(diskdst));
    job->synchronous = false;
    qemuBlockJobUpdate(vm, job, asyncJob);
}


qemuBlockJobDataPtr
qemuBlockJobGetByDisk(virDomainDiskDefPtr disk)
{
    qemuBlockJobDataPtr job = QEMU_DOMAIN_DISK_PRIVATE(disk)->blockjob;

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

    case QEMU_MONITOR_JOB_STATUS_UNKNOWN:
    case QEMU_MONITOR_JOB_STATUS_CREATED:
    case QEMU_MONITOR_JOB_STATUS_RUNNING:
    case QEMU_MONITOR_JOB_STATUS_PAUSED:
    case QEMU_MONITOR_JOB_STATUS_STANDBY:
    case QEMU_MONITOR_JOB_STATUS_WAITING:
    case QEMU_MONITOR_JOB_STATUS_PENDING:
    case QEMU_MONITOR_JOB_STATUS_ABORTING:
    case QEMU_MONITOR_JOB_STATUS_UNDEFINED:
    case QEMU_MONITOR_JOB_STATUS_NULL:
    case QEMU_MONITOR_JOB_STATUS_LAST:
    default:
        break;
    }

    return ret;

}
