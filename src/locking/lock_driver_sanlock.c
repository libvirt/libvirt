/*
 * lock_driver_sanlock.c: A lock driver for Sanlock
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

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#include <sanlock.h>
#include <sanlock_resource.h>

#include "lock_driver.h"
#include "logging.h"
#include "virterror_internal.h"
#include "memory.h"
#include "util.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_LOCKING

#define virLockError(code, ...)                                     \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,             \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

typedef struct _virLockManagerSanlockPrivate virLockManagerSanlockPrivate;
typedef virLockManagerSanlockPrivate *virLockManagerSanlockPrivatePtr;

struct _virLockManagerSanlockPrivate {
    char vm_name[SANLK_NAME_LEN];
    char vm_uuid[VIR_UUID_BUFLEN];
    unsigned int vm_id;
    unsigned int vm_pid;
    unsigned int flags;
    bool hasRWDisks;
    int res_count;
    struct sanlk_resource *res_args[SANLK_MAX_RESOURCES];
};

/*
 * sanlock plugin for the libvirt virLockManager API
 */

static int virLockManagerSanlockInit(unsigned int version ATTRIBUTE_UNUSED,
                                     unsigned int flags)
{
    virCheckFlags(0, -1);
    return 0;
}

static int virLockManagerSanlockDeinit(void)
{
    virLockError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unloading sanlock plugin is forbidden"));
    return -1;
}

static int virLockManagerSanlockNew(virLockManagerPtr lock,
                                    unsigned int type,
                                    size_t nparams,
                                    virLockManagerParamPtr params,
                                    unsigned int flags)
{
    virLockManagerParamPtr param;
    virLockManagerSanlockPrivatePtr priv;
    int i;

    virCheckFlags(0, -1);

    if (type != VIR_LOCK_MANAGER_OBJECT_TYPE_DOMAIN) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Unsupported object type %d"), type);
        return -1;
    }

    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return -1;
    }

    priv->flags = flags;

    for (i = 0; i < nparams; i++) {
        param = &params[i];

        if (STREQ(param->key, "uuid")) {
            memcpy(priv->vm_uuid, param->value.uuid, 16);
        } else if (STREQ(param->key, "name")) {
            if (!virStrcpy(priv->vm_name, param->value.str, SANLK_NAME_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Domain name '%s' exceeded %d characters"),
                             param->value.str, SANLK_NAME_LEN);
                goto error;
            }
        } else if (STREQ(param->key, "pid")) {
            priv->vm_pid = param->value.ui;
        } else if (STREQ(param->key, "id")) {
            priv->vm_id = param->value.ui;
        }
    }

    lock->privateData = priv;
    return 0;

error:
    VIR_FREE(priv);
    return -1;
}

static void virLockManagerSanlockFree(virLockManagerPtr lock)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int i;

    if (!priv)
        return;

    for (i = 0; i < priv->res_count; i++)
        VIR_FREE(priv->res_args[i]);
    VIR_FREE(priv);
    lock->privateData = NULL;
}

static int virLockManagerSanlockAddResource(virLockManagerPtr lock,
                                            unsigned int type,
                                            const char *name,
                                            size_t nparams,
                                            virLockManagerParamPtr params,
                                            unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    struct sanlk_resource *res;
    int i;

    virCheckFlags(VIR_LOCK_MANAGER_RESOURCE_READONLY |
                  VIR_LOCK_MANAGER_RESOURCE_SHARED, -1);

    if (priv->res_count == SANLK_MAX_RESOURCES) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Too many resources %d for object"),
                     SANLK_MAX_RESOURCES);
        return -1;
    }

    if (type == VIR_LOCK_MANAGER_RESOURCE_TYPE_DISK) {
        if (!(flags & (VIR_LOCK_MANAGER_RESOURCE_SHARED |
                       VIR_LOCK_MANAGER_RESOURCE_READONLY)))
            priv->hasRWDisks = true;
        return 0;
    }

    if (type != VIR_LOCK_MANAGER_RESOURCE_TYPE_LEASE)
        return 0;

    if (flags & VIR_LOCK_MANAGER_RESOURCE_READONLY) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Readonly leases are not supported"));
        return -1;
    }
    if (flags & VIR_LOCK_MANAGER_RESOURCE_SHARED) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Sharable leases are not supported"));
        return -1;
    }

    if (VIR_ALLOC_VAR(res, struct sanlk_disk, 1) < 0) {
        virReportOOMError();
        return -1;
    }

    res->num_disks = 1;
    if (!virStrcpy(res->name, name, SANLK_NAME_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Resource name '%s' exceeds %d characters"),
                     name, SANLK_NAME_LEN);
        goto error;
    }

    for (i = 0; i < nparams; i++) {
        if (STREQ(params[i].key, "path")) {
            if (!virStrcpy(res->disks[0].path, params[i].value.str, SANLK_PATH_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Lease path '%s' exceeds %d characters"),
                             params[i].value.str, SANLK_PATH_LEN);
                goto error;
            }
        } else if (STREQ(params[i].key, "offset")) {
            res->disks[0].offset = params[i].value.ul;
        } else if (STREQ(params[i].key, "lockspace")) {
            if (!virStrcpy(res->lockspace_name, params[i].value.str, SANLK_NAME_LEN)) {
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Resource lockspace '%s' exceeds %d characters"),
                             params[i].value.str, SANLK_NAME_LEN);
                goto error;
            }
        }
    }

    priv->res_args[priv->res_count] = res;
    priv->res_count++;
    return 0;

error:
    VIR_FREE(res);
    return -1;
}

static int virLockManagerSanlockAcquire(virLockManagerPtr lock,
                                        const char *state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    struct sanlk_options *opt;
    struct sanlk_resource **res_args;
    int res_count;
    bool res_free = false;
    int sock = -1;
    int rv;
    int i;

    virCheckFlags(VIR_LOCK_MANAGER_ACQUIRE_RESTRICT |
                  VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY, -1);

    if (priv->res_count == 0 &&
        priv->hasRWDisks) {
        virLockError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                     _("Read/write, exclusive access, disks were present, but no leases specified"));
        return -1;
    }

    if (VIR_ALLOC(opt) < 0) {
        virReportOOMError();
        return -1;
    }

    if (!virStrcpy(opt->owner_name, priv->vm_name, SANLK_NAME_LEN)) {
        virLockError(VIR_ERR_INTERNAL_ERROR,
                     _("Domain name '%s' exceeded %d characters"),
                     priv->vm_name, SANLK_NAME_LEN);
        goto error;
    }

    if (state && STRNEQ(state, "") && 0) {
        if ((rv = sanlock_state_to_args((char *)state,
                                        &res_count,
                                        &res_args)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to parse lock state %s: error %d"),
                             state, rv);
            else
                virReportSystemError(-rv,
                                     _("Unable to parse lock state %s"),
                                     state);
            goto error;
        }
        res_free = true;
    } else {
        res_args = priv->res_args;
        res_count = priv->res_count;
    }

    VIR_DEBUG("Register sanlock %d", flags);
    /* We only initialize 'sock' if we are in the real
     * child process and we need it to be inherited
     *
     * If sock==-1, then sanlock auto-open/closes a
     * temporary sock
     */
    if (priv->vm_pid == getpid() &&
        (sock = sanlock_register()) < 0) {
        if (sock <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to open socket to sanlock daemon: error %d"),
                         sock);
        else
            virReportSystemError(-sock, "%s",
                                 _("Failed to open socket to sanlock daemon"));
        goto error;
    }

    if (!(flags & VIR_LOCK_MANAGER_ACQUIRE_REGISTER_ONLY)) {
        VIR_DEBUG("Acquiring object %u", priv->res_count);
        if ((rv = sanlock_acquire(sock, priv->vm_pid, 0,
                                  priv->res_count, priv->res_args,
                                  opt)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to acquire lock: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to acquire lock"));
            goto error;
        }
    }

    VIR_FREE(opt);

    /*
     * We are *intentionally* "leaking" sock file descriptor
     * because we want it to be inherited by QEMU. When the
     * sock FD finally closes upon QEMU exit (or crash) then
     * sanlock will notice EOF and release the lock
     */
    if (sock != -1 &&
        virSetInherit(sock, true) < 0)
        goto error;

    if (flags & VIR_LOCK_MANAGER_ACQUIRE_RESTRICT) {
        if ((rv = sanlock_restrict(sock, SANLK_RESTRICT_ALL)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to restrict process: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to restrict process"));
            goto error;
        }
    }

    VIR_DEBUG("Acquire completed fd=%d", sock);

    if (res_free) {
        for (i = 0 ; i < res_count ; i++) {
            VIR_FREE(res_args[i]);
        }
        VIR_FREE(res_args);
    }

    return 0;

error:
    if (res_free) {
        for (i = 0 ; i < res_count ; i++) {
            VIR_FREE(res_args[i]);
        }
        VIR_FREE(res_args);
    }
    VIR_FREE(opt);
    VIR_FORCE_CLOSE(sock);
    return -1;
}


static int virLockManagerSanlockRelease(virLockManagerPtr lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int res_count;
    int rv;

    virCheckFlags(0, -1);

    if (state) {
        if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
            if (rv <= -200)
                virLockError(VIR_ERR_INTERNAL_ERROR,
                             _("Failed to inquire lock: error %d"), rv);
            else
                virReportSystemError(-rv, "%s",
                                     _("Failed to inquire lock"));
            return -1;
        }

        if (STREQ(*state, ""))
            VIR_FREE(*state);
    }

    if ((rv = sanlock_release(-1, priv->vm_pid, SANLK_REL_ALL, 0, NULL)) < 0) {
        if (rv <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to release lock: error %d"), rv);
        else
            virReportSystemError(-rv, "%s",
                                 _("Failed to release lock"));
        return -1;
    }

    return 0;
}

static int virLockManagerSanlockInquire(virLockManagerPtr lock,
                                        char **state,
                                        unsigned int flags)
{
    virLockManagerSanlockPrivatePtr priv = lock->privateData;
    int rv, res_count;

    virCheckFlags(0, -1);

    if (!state) {
        virLockError(VIR_ERR_INVALID_ARG, "state");
        return -1;
    }

    VIR_DEBUG("pid=%d", priv->vm_pid);

    if ((rv = sanlock_inquire(-1, priv->vm_pid, 0, &res_count, state)) < 0) {
        if (rv <= -200)
            virLockError(VIR_ERR_INTERNAL_ERROR,
                         _("Failed to inquire lock: error %d"), rv);
        else
            virReportSystemError(-rv, "%s",
                                 _("Failed to inquire lock"));
        return -1;
    }

    if (STREQ(*state, ""))
        VIR_FREE(*state);

    return 0;
}

virLockDriver virLockDriverImpl =
{
    .version = VIR_LOCK_MANAGER_VERSION,

    .flags = VIR_LOCK_MANAGER_USES_STATE,

    .drvInit = virLockManagerSanlockInit,
    .drvDeinit = virLockManagerSanlockDeinit,

    .drvNew = virLockManagerSanlockNew,
    .drvFree = virLockManagerSanlockFree,

    .drvAddResource = virLockManagerSanlockAddResource,

    .drvAcquire = virLockManagerSanlockAcquire,
    .drvRelease = virLockManagerSanlockRelease,
    .drvInquire = virLockManagerSanlockInquire,
};
