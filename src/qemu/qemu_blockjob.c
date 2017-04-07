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

#include "conf/domain_conf.h"
#include "conf/domain_event.h"

#include "virlog.h"
#include "virstoragefile.h"
#include "virthread.h"
#include "virtime.h"
#include "locking/domain_lock.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_blockjob");


/**
 * qemuBlockJobUpdate:
 * @driver: qemu driver
 * @vm: domain
 * @disk: domain disk
 *
 * Update disk's mirror state in response to a block job event stored in
 * blockJobStatus by qemuProcessHandleBlockJob event handler.
 *
 * Returns the block job event processed or -1 if there was no pending event.
 */
int
qemuBlockJobUpdate(virQEMUDriverPtr driver,
                   virDomainObjPtr vm,
                   qemuDomainAsyncJob asyncJob,
                   virDomainDiskDefPtr disk)
{
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);
    int status = diskPriv->blockJobStatus;

    if (status != -1) {
        qemuBlockJobEventProcess(driver, vm, disk, asyncJob,
                                 diskPriv->blockJobType,
                                 diskPriv->blockJobStatus);
        diskPriv->blockJobStatus = -1;
    }

    return status;
}


/**
 * qemuBlockJobEventProcess:
 * @driver: qemu driver
 * @vm: domain
 * @disk: domain disk
 * @type: block job type
 * @status: block job status
 *
 * Update disk's mirror state in response to a block job event
 * from QEMU. For mirror state's that must survive libvirt
 * restart, also update the domain's status XML.
 */
void
qemuBlockJobEventProcess(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainDiskDefPtr disk,
                         qemuDomainAsyncJob asyncJob,
                         int type,
                         int status)
{
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    const char *path;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainDiskDefPtr persistDisk = NULL;
    bool save = false;
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

    VIR_DEBUG("disk=%s, mirrorState=%s, type=%d, status=%d",
              disk->dst,
              NULLSTR(virDomainDiskMirrorStateTypeToString(disk->mirrorState)),
              type,
              status);

    /* Have to generate two variants of the event for old vs. new
     * client callbacks */
    if (type == VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT &&
        disk->mirrorJob == VIR_DOMAIN_BLOCK_JOB_TYPE_ACTIVE_COMMIT)
        type = disk->mirrorJob;
    path = virDomainDiskGetSource(disk);
    event = virDomainEventBlockJobNewFromObj(vm, path, type, status);
    event2 = virDomainEventBlockJob2NewFromObj(vm, disk->dst, type, status);

    /* If we completed a block pull or commit, then update the XML
     * to match.  */
    switch ((virConnectDomainEventBlockJobStatus) status) {
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        if (disk->mirrorState == VIR_DOMAIN_DISK_MIRROR_STATE_PIVOT) {
            if (vm->newDef) {
                virStorageSourcePtr copy = NULL;

                if ((persistDisk = virDomainDiskByName(vm->newDef,
                                                       disk->dst, false))) {
                    copy = virStorageSourceCopy(disk->mirror, false);
                    if (!copy ||
                        virStorageSourceInitChainElement(copy,
                                                         persistDisk->src,
                                                         true) < 0) {
                        VIR_WARN("Unable to update persistent definition "
                                 "on vm %s after block job",
                                 vm->def->name);
                        virStorageSourceFree(copy);
                        copy = NULL;
                        persistDisk = NULL;
                    }
                }
                if (copy) {
                    virStorageSourceFree(persistDisk->src);
                    persistDisk->src = copy;
                }
            }

            /* XXX We want to revoke security labels as well as audit that
             * revocation, before dropping the original source.  But it gets
             * tricky if both source and mirror share common backing files (we
             * want to only revoke the non-shared portion of the chain); so for
             * now, we leak the access to the original.  */
            virDomainLockImageDetach(driver->lockManager, vm, disk->src);
            virStorageSourceFree(disk->src);
            disk->src = disk->mirror;
        } else {
            if (disk->mirror) {
                virDomainLockImageDetach(driver->lockManager, vm, disk->mirror);
                virStorageSourceFree(disk->mirror);
            }
        }

        /* Recompute the cached backing chain to match our
         * updates.  Better would be storing the chain ourselves
         * rather than reprobing, but we haven't quite completed
         * that conversion to use our XML tracking. */
        disk->mirror = NULL;
        save = disk->mirrorState != VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        ignore_value(qemuDomainDetermineDiskChain(driver, vm, disk,
                                                  true, true));
        ignore_value(qemuBlockNodeNamesDetect(driver, vm, asyncJob));
        diskPriv->blockjob = false;
        break;

    case VIR_DOMAIN_BLOCK_JOB_READY:
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
        save = true;
        break;

    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        if (disk->mirror) {
            virDomainLockImageDetach(driver->lockManager, vm, disk->mirror);
            virStorageSourceFree(disk->mirror);
            disk->mirror = NULL;
        }
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        save = true;
        diskPriv->blockjob = false;
        break;

    case VIR_DOMAIN_BLOCK_JOB_LAST:
        break;
    }

    if (save) {
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm, driver->caps) < 0)
            VIR_WARN("Unable to save status on vm %s after block job",
                     vm->def->name);
        if (persistDisk && virDomainSaveConfig(cfg->configDir,
                                               driver->caps,
                                               vm->newDef) < 0)
            VIR_WARN("Unable to update persistent definition on vm %s "
                     "after block job", vm->def->name);
    }

    qemuDomainEventQueue(driver, event);
    qemuDomainEventQueue(driver, event2);

    virObjectUnref(cfg);
}


/**
 * qemuBlockJobSyncBegin:
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
qemuBlockJobSyncBegin(virDomainDiskDefPtr disk)
{
    qemuDomainDiskPrivatePtr diskPriv = QEMU_DOMAIN_DISK_PRIVATE(disk);

    VIR_DEBUG("disk=%s", disk->dst);
    diskPriv->blockJobSync = true;
    diskPriv->blockJobStatus = -1;
}


/**
 * qemuBlockJobSyncEnd:
 * @driver: qemu driver
 * @vm: domain
 * @disk: domain disk
 *
 * End a synchronous block job for @disk. Any pending block job event
 * for the disk is processed.
 */
void
qemuBlockJobSyncEnd(virQEMUDriverPtr driver,
                    virDomainObjPtr vm,
                    qemuDomainAsyncJob asyncJob,
                    virDomainDiskDefPtr disk)
{
    VIR_DEBUG("disk=%s", disk->dst);
    qemuBlockJobUpdate(driver, vm, asyncJob, disk);
    QEMU_DOMAIN_DISK_PRIVATE(disk)->blockJobSync = false;
}
