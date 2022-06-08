/*
 * domain_lock.c: Locking for domain lifecycle operations
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include "domain_lock.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

VIR_LOG_INIT("locking.domain_lock");


static int virDomainLockManagerAddLease(virLockManager *lock,
                                        virDomainLeaseDef *lease)
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
    size_t nparams = G_N_ELEMENTS(lparams);
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


static int virDomainLockManagerAddImage(virLockManager *lock,
                                        virStorageSource *src)
{
    unsigned int diskFlags = 0;
    virStorageType type = virStorageSourceGetActualType(src);

    if (!src->path)
        return 0;

    if (!(type == VIR_STORAGE_TYPE_BLOCK ||
          type == VIR_STORAGE_TYPE_FILE ||
          type == VIR_STORAGE_TYPE_DIR))
        return 0;

    if (src->readonly)
        diskFlags |= VIR_LOCK_MANAGER_RESOURCE_READONLY;
    if (src->shared)
        diskFlags |= VIR_LOCK_MANAGER_RESOURCE_SHARED;

    VIR_DEBUG("Add disk %s", src->path);
    if (virLockManagerAddResource(lock,
                                  VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK,
                                  src->path,
                                  0,
                                  NULL,
                                  diskFlags) < 0) {
        VIR_DEBUG("Failed add disk %s", src->path);
        return -1;
    }
    return 0;
}


static virLockManager *virDomainLockManagerNew(virLockManagerPlugin *plugin,
                                                 const char *uri,
                                                 virDomainObj *dom,
                                                 bool withResources,
                                                 unsigned int flags)
{
    virLockManager *lock;
    size_t i;
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
          .value = { .iv = dom->def->id },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_UINT,
          .key = "pid",
          .value = { .iv = dom->pid },
        },
        { .type = VIR_LOCK_MANAGER_PARAM_TYPE_CSTRING,
          .key = "uri",
          .value = { .cstr = uri },
        },
    };
    VIR_DEBUG("plugin=%p dom=%p withResources=%d",
              plugin, dom, withResources);

    memcpy(params[0].value.uuid, dom->def->uuid, VIR_UUID_BUFLEN);

    if (!(lock = virLockManagerNew(virLockManagerPluginGetDriver(plugin),
                                   VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN,
                                   G_N_ELEMENTS(params),
                                   params,
                                   flags)))
        goto error;

    if (withResources) {
        VIR_DEBUG("Adding leases");
        for (i = 0; i < dom->def->nleases; i++)
            if (virDomainLockManagerAddLease(lock, dom->def->leases[i]) < 0)
                goto error;

        VIR_DEBUG("Adding disks");
        for (i = 0; i < dom->def->ndisks; i++) {
            virDomainDiskDef *disk = dom->def->disks[i];

            if (virDomainLockManagerAddImage(lock, disk->src) < 0)
                goto error;
        }
    }

    return lock;

 error:
    virLockManagerFree(lock);
    return NULL;
}


int virDomainLockProcessStart(virLockManagerPlugin *plugin,
                              const char *uri,
                              virDomainObj *dom,
                              bool paused,
                              int *fd)
{
    virLockManager *lock;
    int ret;
    int flags = VIR_LOCK_MANAGER_ACQUIRE_RESTRICT;

    VIR_DEBUG("plugin=%p dom=%p paused=%d fd=%p",
              plugin, dom, paused, fd);

    if (!(lock = virDomainLockManagerNew(plugin, uri, dom, true,
                                         VIR_LOCK_MANAGER_NEW_STARTED)))
        return -1;

    if (paused)
        flags |= VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY;

    ret = virLockManagerAcquire(lock, NULL, flags,
                                dom->def->onLockFailure, fd);

    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessPause(virLockManagerPlugin *plugin,
                              virDomainObj *dom,
                              char **state)
{
    virLockManager *lock;
    int ret;

    VIR_DEBUG("plugin=%p dom=%p state=%p",
              plugin, dom, state);

    if (!(lock = virDomainLockManagerNew(plugin, NULL, dom, true, 0)))
        return -1;

    ret = virLockManagerRelease(lock, state, 0);
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessResume(virLockManagerPlugin *plugin,
                               const char *uri,
                               virDomainObj *dom,
                               const char *state)
{
    virLockManager *lock;
    int ret;

    VIR_DEBUG("plugin=%p dom=%p state=%s",
              plugin, dom, NULLSTR(state));

    if (!(lock = virDomainLockManagerNew(plugin, uri, dom, true, 0)))
        return -1;

    ret = virLockManagerAcquire(lock, state, 0, dom->def->onLockFailure, NULL);
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockProcessInquire(virLockManagerPlugin *plugin,
                                virDomainObj *dom,
                                char **state)
{
    virLockManager *lock;
    int ret;

    VIR_DEBUG("plugin=%p dom=%p state=%p",
              plugin, dom, state);

    if (!(lock = virDomainLockManagerNew(plugin, NULL, dom, true, 0)))
        return -1;

    ret = virLockManagerInquire(lock, state, 0);
    virLockManagerFree(lock);

    return ret;
}


int virDomainLockImageAttach(virLockManagerPlugin *plugin,
                             const char *uri,
                             virDomainObj *dom,
                             virStorageSource *src)
{
    virLockManager *lock;
    int ret = -1;

    VIR_DEBUG("plugin=%p dom=%p src=%p", plugin, dom, src);

    if (!(lock = virDomainLockManagerNew(plugin, uri, dom, false, 0)))
        return -1;

    if (virDomainLockManagerAddImage(lock, src) < 0)
        goto cleanup;

    if (virLockManagerAcquire(lock, NULL, 0,
                              dom->def->onLockFailure, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virLockManagerFree(lock);

    return ret;
}


int virDomainLockImageDetach(virLockManagerPlugin *plugin,
                             virDomainObj *dom,
                             virStorageSource *src)
{
    virLockManager *lock;
    int ret = -1;

    VIR_DEBUG("plugin=%p dom=%p src=%p", plugin, dom, src);

    if (!(lock = virDomainLockManagerNew(plugin, NULL, dom, false, 0)))
        return -1;

    if (virDomainLockManagerAddImage(lock, src) < 0)
        goto cleanup;

    if (virLockManagerRelease(lock, NULL, 0) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virLockManagerFree(lock);

    return ret;
}


int virDomainLockLeaseAttach(virLockManagerPlugin *plugin,
                             const char *uri,
                             virDomainObj *dom,
                             virDomainLeaseDef *lease)
{
    virLockManager *lock;
    int ret = -1;

    VIR_DEBUG("plugin=%p dom=%p lease=%p",
              plugin, dom, lease);

    if (!(lock = virDomainLockManagerNew(plugin, uri, dom, false, 0)))
        return -1;

    if (virDomainLockManagerAddLease(lock, lease) < 0)
        goto cleanup;

    if (virLockManagerAcquire(lock, NULL, 0,
                              dom->def->onLockFailure, NULL) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virLockManagerFree(lock);

    return ret;
}

int virDomainLockLeaseDetach(virLockManagerPlugin *plugin,
                             virDomainObj *dom,
                             virDomainLeaseDef *lease)
{
    virLockManager *lock;
    int ret = -1;

    VIR_DEBUG("plugin=%p dom=%p lease=%p",
              plugin, dom, lease);

    if (!(lock = virDomainLockManagerNew(plugin, NULL, dom, false, 0)))
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
