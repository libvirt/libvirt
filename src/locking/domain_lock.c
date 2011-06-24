/*
 * domain_lock.c: Locking for domain lifecycle operations
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include "domain_lock.h"
#include "memory.h"
#include "uuid.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING


static int virDomainLockManagerAddLease(virLockManagerPtr lock,
                                        virDomainLeaseDefPtr lease)
{
    unsigned int leaseFlags = 0;
    virLockManagerParam lparams[] = {
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_STRING,
          .key = "path",
          .value = { .str = lease->path },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_ULONG,
          .key = "offset",
          .value = { .ul = lease->offset },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_STRING,
          .key = "lockspace",
          .value = { .str = lease->lockspace },
        },
    };
    size_t nparams = ARRAY_CARDINALITY(lparams);
    if (!lease->lockspace)
        nparams--;

    VIR_DEBUG("Add lease %s", lease->path);
    if (virLockManagerAddResource(lock,
                                  VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE,
                                  lease->key,
                                  nparams,
                                  lparams,
                                  leaseFlags) < 0) {
        VIR_DEBUG("Failed to add lease %s", lease->path);
        return -1;
    }
    return 0;
}


static int virDomainLockManagerAddDisk(virLockManagerPtr lock,
                                       virDomainDiskDefPtr disk)
{
    unsigned int diskFlags = 0;
    if (!disk->src)
        return 0;

    if (!(disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK ||
          disk->type == VIR_DOMAIN_DISK_TYPE_FILE ||
          disk->type == VIR_DOMAIN_DISK_TYPE_DIR))
        return 0;

    if (disk->readonly)
        diskFlags |= VIR_LOCK_MANAGER_RESOURCE_READONLY;
    if (disk->shared)
        diskFlags |= VIR_LOCK_MANAGER_RESOURCE_SHARED;

    VIR_DEBUG("Add disk %s", disk->src);
    if (virLockManagerAddResource(lock,
                                  VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK,
                                  disk->src,
                                  0,
                                  NULL,
                                  diskFlags) < 0) {
        VIR_DEBUG("Failed add disk %s", disk->src);
        return -1;
    }
    return 0;
}

static virLockManagerPtr virDomainLockManagerNew(virLockManagerPluginPtr plugin,
                                                 virDomainObjPtr dom,
                                                 bool withResources)
{
    virLockManagerPtr lock;
    int i;
    virLockManagerParam params[] = {
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_UUID,
          .key = "uuid",
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_STRING,
          .key = "name",
          .value = { .str = dom->def->name },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_UINT,
          .key = "id",
          .value = { .i = dom->def->id },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_UINT,
          .key = "pid",
          .value = { .i = dom->pid },
        },
    };
    VIR_DEBUG("plugin=%p dom=%p withResources=%d",
              plugin, dom, withResources);

    memcpy(params[0].value.uuid, dom->def->uuid, VIR_UUID_BUFLEN);

    if (!(lock = virLockManagerNew(plugin,
                                   VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN,
                                   ARRAY_CARDINALITY(params),
                                   params,
                                   0)))
        goto error;

    if (withResources) {
        VIR_DEBUG("Adding leases");
        for (i = 0 ; i < dom->def->nleases ; i++)
            if (virDomainLockManagerAddLease(lock, dom->def->leases[i]) < 0)
                goto error;

        VIR_DEBUG("Adding disks");
        for (i = 0 ; i < dom->def->ndisks ; i++)
            if (virDomainLockManagerAddDisk(lock, dom->def->disks[i]) < 0)
                goto error;
    }

    return lock;

error:
    virLockManagerFree(lock);
    return NULL;
}


int virDomainLockProcessStart(virLockManagerPluginPtr plugin,
                              virDomainObjPtr dom,
                              bool paused,
                              int *fd)
{
    virLockManagerPtr lock;
    int ret;
    int flags = VIR_LOCK_MANAGER_ACQUIRE_RESTRICT;

    if (!(lock = virDomainLockManagerNew(plugin, dom, true)))
        return -1;

    if (paused)
        flags |= VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY;

    ret = virLockManagerAcquire(lock, NULL, flags, fd);

    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessPause(virLockManagerPluginPtr plugin,
                              virDomainObjPtr dom,
                              char **state)
{
    virLockManagerPtr lock;
    int ret;

    if (!(lock = virDomainLockManagerNew(plugin, dom, true)))
        return -1;

    ret = virLockManagerRelease(lock, state, 0);
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessResume(virLockManagerPluginPtr plugin,
                               virDomainObjPtr dom,
                               const char *state)
{
    virLockManagerPtr lock;
    int ret;

    if (!(lock = virDomainLockManagerNew(plugin, dom, true)))
        return -1;

    ret = virLockManagerAcquire(lock, state, 0, NULL);
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessInquire(virLockManagerPluginPtr plugin,
                                virDomainObjPtr dom,
                                char **state)
{
    virLockManagerPtr lock;
    int ret;

    if (!(lock = virDomainLockManagerNew(plugin, dom, true)))
        return -1;

    ret = virLockManagerInquire(lock, state, 0);
    virLockManagerFree(lock);

    return ret;
}


int virDomainLockDiskAttach(virLockManagerPluginPtr plugin,
                            virDomainObjPtr dom,
                            virDomainDiskDefPtr disk)
{
    virLockManagerPtr lock;
    int ret = -1;

    if (!(lock = virDomainLockManagerNew(plugin, dom, false)))
        return -1;

    if (virDomainLockManagerAddDisk(lock, disk) < 0)
        goto cleanup;

    if (virLockManagerAcquire(lock, NULL, 0, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockDiskDetach(virLockManagerPluginPtr plugin,
                            virDomainObjPtr dom,
                            virDomainDiskDefPtr disk)
{
    virLockManagerPtr lock;
    int ret = -1;

    if (!(lock = virDomainLockManagerNew(plugin, dom, false)))
        return -1;

    if (virDomainLockManagerAddDisk(lock, disk) < 0)
        goto cleanup;

    if (virLockManagerRelease(lock, NULL, 0) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virLockManagerFree(lock);

    return ret;
}


int virDomainLockLeaseAttach(virLockManagerPluginPtr plugin,
                             virDomainObjPtr dom,
                             virDomainLeaseDefPtr lease)
{
    virLockManagerPtr lock;
    int ret = -1;

    if (!(lock = virDomainLockManagerNew(plugin, dom, false)))
        return -1;

    if (virDomainLockManagerAddLease(lock, lease) < 0)
        goto cleanup;

    if (virLockManagerAcquire(lock, NULL, 0, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockLeaseDetach(virLockManagerPluginPtr plugin,
                             virDomainObjPtr dom,
                             virDomainLeaseDefPtr lease)
{
    virLockManagerPtr lock;
    int ret = -1;

    if (!(lock = virDomainLockManagerNew(plugin, dom, false)))
        return -1;

    if (virDomainLockManagerAddLease(lock, lease) < 0)
        goto cleanup;

    if (virLockManagerRelease(lock, NULL, 0) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    virLockManagerFree(lock);

    return ret;
}
