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
#include "qemu_domain.h"

#include "conf/domain_conf.h"
#include "conf/domain_event.h"

#include "virlog.h"
#include "virstoragefile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_blockjob");

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
 *
 * Returns 0 on success, -1 otherwise.
 */
void
qemuBlockJobEventProcess(virQEMUDriverPtr driver,
                         virDomainObjPtr vm,
                         virDomainDiskDefPtr disk,
                         int type,
                         int status)
{
    virObjectEventPtr event = NULL;
    virObjectEventPtr event2 = NULL;
    const char *path;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    virDomainDiskDefPtr persistDisk = NULL;
    bool save = false;

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
                int indx = virDomainDiskIndexByName(vm->newDef, disk->dst, false);
                virStorageSourcePtr copy = NULL;

                if (indx >= 0) {
                    persistDisk = vm->newDef->disks[indx];
                    copy = virStorageSourceCopy(disk->mirror, false);
                    if (virStorageSourceInitChainElement(copy,
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

            /* XXX We want to revoke security labels and disk
             * lease, as well as audit that revocation, before
             * dropping the original source.  But it gets tricky
             * if both source and mirror share common backing
             * files (we want to only revoke the non-shared
             * portion of the chain); so for now, we leak the
             * access to the original.  */
            virStorageSourceFree(disk->src);
            disk->src = disk->mirror;
        } else {
            virStorageSourceFree(disk->mirror);
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
        disk->blockjob = false;
        break;

    case VIR_DOMAIN_BLOCK_JOB_READY:
        disk->mirrorState = VIR_DOMAIN_DISK_MIRROR_STATE_READY;
        save = true;
        break;

    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
        virStorageSourceFree(disk->mirror);
        disk->mirror = NULL;
        disk->mirrorState = status == VIR_DOMAIN_BLOCK_JOB_FAILED ?
            VIR_DOMAIN_DISK_MIRROR_STATE_ABORT : VIR_DOMAIN_DISK_MIRROR_STATE_NONE;
        disk->mirrorJob = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
        save = true;
        disk->blockjob = false;
        break;

    case VIR_DOMAIN_BLOCK_JOB_LAST:
        break;
    }

    if (save) {
        if (virDomainSaveStatus(driver->xmlopt, cfg->stateDir, vm) < 0)
            VIR_WARN("Unable to save status on vm %s after block job",
                     vm->def->name);
        if (persistDisk && virDomainSaveConfig(cfg->configDir,
                                               vm->newDef) < 0)
            VIR_WARN("Unable to update persistent definition on vm %s "
                     "after block job", vm->def->name);
    }

    if (event)
        qemuDomainEventQueue(driver, event);
    if (event2)
        qemuDomainEventQueue(driver, event2);

    virObjectUnref(cfg);
}
