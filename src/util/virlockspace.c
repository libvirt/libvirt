/*
 * virlockspace.c: simple file based lockspaces
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include "virlockspace.h"
#include "virlog.h"
#include "viralloc.h"
#include "virerror.h"
#include "virutil.h"
#include "virfile.h"
#include "virhash.h"
#include "virthread.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define VIR_FROM_THIS VIR_FROM_LOCKSPACE

VIR_LOG_INIT("util.lockspace");

#define VIR_LOCKSPACE_TABLE_SIZE 10

typedef struct _virLockSpaceResource virLockSpaceResource;
struct _virLockSpaceResource {
    char *name;
    char *path;
    int fd;
    bool lockHeld;
    unsigned int flags;
    size_t nOwners;
    pid_t *owners;
};

struct _virLockSpace {
    char *dir;
    virMutex lock;

    GHashTable *resources;
};


static char *virLockSpaceGetResourcePath(virLockSpace *lockspace,
                                         const char *resname)
{
    char *ret;
    if (lockspace->dir)
        ret = g_strdup_printf("%s/%s", lockspace->dir, resname);
    else
        ret = g_strdup(resname);
    return ret;
}


static void virLockSpaceResourceFree(virLockSpaceResource *res)
{
    if (!res)
        return;

    if (res->lockHeld &&
        (res->flags & VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE)) {
        if (res->flags & VIR_LOCK_SPACE_ACQUIRE_SHARED) {
            /* We must upgrade to an exclusive lock to ensure
             * no one else still has it before trying to delete */
            if (virFileLock(res->fd, false, 0, 1, false) < 0) {
                VIR_DEBUG("Could not upgrade shared lease to exclusive, not deleting");
            } else {
                if (unlink(res->path) < 0 &&
                    errno != ENOENT) {
                    VIR_WARN("Failed to unlink resource %s: %s",
                             res->path, g_strerror(errno));
                }
            }
        } else {
            if (unlink(res->path) < 0 &&
                errno != ENOENT) {
                VIR_WARN("Failed to unlink resource %s: %s",
                         res->path, g_strerror(errno));
            }
        }
    }

    g_free(res->owners);
    VIR_FORCE_CLOSE(res->fd);
    g_free(res->path);
    g_free(res->name);
    g_free(res);
}


static virLockSpaceResource *
virLockSpaceResourceNew(virLockSpace *lockspace,
                        const char *resname,
                        unsigned int flags,
                        pid_t owner)
{
    virLockSpaceResource *res;
    bool shared = !!(flags & VIR_LOCK_SPACE_ACQUIRE_SHARED);

    res = g_new0(virLockSpaceResource, 1);

    res->fd = -1;
    res->flags = flags;

    res->name = g_strdup(resname);

    if (!(res->path = virLockSpaceGetResourcePath(lockspace, resname)))
        goto error;

    if (flags & VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) {
        while (1) {
            struct stat a, b;
            if ((res->fd = open(res->path, O_RDWR|O_CREAT, 0600)) < 0) {
                virReportSystemError(errno,
                                     _("Unable to open/create resource %1$s"),
                                     res->path);
                goto error;
            }

            if (virSetCloseExec(res->fd) < 0) {
                virReportSystemError(errno,
                                     _("Failed to set close-on-exec flag '%1$s'"),
                                     res->path);
                goto error;
            }

            if (fstat(res->fd, &b) < 0) {
                virReportSystemError(errno,
                                     _("Unable to check status of pid file '%1$s'"),
                                     res->path);
                goto error;
            }

            if (virFileLock(res->fd, shared, 0, 1, false) < 0) {
                if (errno == EACCES || errno == EAGAIN) {
                    virReportError(VIR_ERR_RESOURCE_BUSY,
                                   _("Lockspace resource '%1$s' is locked"),
                                   resname);
                } else {
                    virReportSystemError(errno,
                                         _("Unable to acquire lock on '%1$s'"),
                                         res->path);
                }
                goto error;
            }

            /* Now make sure the pidfile we locked is the same
             * one that now exists on the filesystem
             */
            if (stat(res->path, &a) < 0) {
                VIR_DEBUG("Resource '%s' disappeared: %s",
                          res->path, g_strerror(errno));
                VIR_FORCE_CLOSE(res->fd);
                /* Someone else must be racing with us, so try again */
                continue;
            }

            if (a.st_ino == b.st_ino)
                break;

            VIR_DEBUG("Resource '%s' was recreated", res->path);
            VIR_FORCE_CLOSE(res->fd);
            /* Someone else must be racing with us, so try again */
        }
    } else {
        if ((res->fd = open(res->path, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open resource %1$s"),
                                 res->path);
            goto error;
        }

        if (virSetCloseExec(res->fd) < 0) {
            virReportSystemError(errno,
                                 _("Failed to set close-on-exec flag '%1$s'"),
                                 res->path);
            goto error;
        }

        if (virFileLock(res->fd, shared, 0, 1, false) < 0) {
            if (errno == EACCES || errno == EAGAIN) {
                virReportError(VIR_ERR_RESOURCE_BUSY,
                               _("Lockspace resource '%1$s' is locked"),
                               resname);
            } else {
                virReportSystemError(errno,
                                     _("Unable to acquire lock on '%1$s'"),
                                     res->path);
            }
            goto error;
        }
    }
    res->lockHeld = true;

    VIR_EXPAND_N(res->owners, res->nOwners, 1);
    res->owners[res->nOwners-1] = owner;

    return res;

 error:
    virLockSpaceResourceFree(res);
    return NULL;
}


static void virLockSpaceResourceDataFree(void *opaque)
{
    virLockSpaceResource *res = opaque;
    virLockSpaceResourceFree(res);
}


virLockSpace *virLockSpaceNew(const char *directory)
{
    virLockSpace *lockspace;

    VIR_DEBUG("directory=%s", NULLSTR(directory));

    lockspace = g_new0(virLockSpace, 1);

    if (virMutexInit(&lockspace->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize lockspace mutex"));
        VIR_FREE(lockspace);
        return NULL;
    }

    lockspace->dir = g_strdup(directory);

    lockspace->resources = virHashNew(virLockSpaceResourceDataFree);

    if (directory) {
        if (virFileExists(directory)) {
            if (!virFileIsDir(directory)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Lockspace location %1$s exists, but is not a directory"),
                               directory);
                goto error;
            }
        } else {
            if (g_mkdir_with_parents(directory, 0700) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %1$s"),
                                     directory);
                goto error;
            }
        }
    }

    return lockspace;

 error:
    virLockSpaceFree(lockspace);
    return NULL;
}



virLockSpace *virLockSpaceNewPostExecRestart(virJSONValue *object)
{
    virLockSpace *lockspace;
    virJSONValue *resources;
    size_t i;

    VIR_DEBUG("object=%p", object);

    lockspace = g_new0(virLockSpace, 1);

    if (virMutexInit(&lockspace->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize lockspace mutex"));
        VIR_FREE(lockspace);
        return NULL;
    }

    lockspace->resources = virHashNew(virLockSpaceResourceDataFree);

    if (virJSONValueObjectHasKey(object, "directory")) {
        const char *dir = virJSONValueObjectGetString(object, "directory");
        lockspace->dir = g_strdup(dir);
    }

    if (!(resources = virJSONValueObjectGet(object, "resources"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing resources value in JSON document"));
        goto error;
    }

    if (!virJSONValueIsArray(resources)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed resources array"));
        goto error;
    }

    for (i = 0; i < virJSONValueArraySize(resources); i++) {
        virJSONValue *child = virJSONValueArrayGet(resources, i);
        virLockSpaceResource *res;
        const char *tmp;
        virJSONValue *owners;
        size_t j;

        res = g_new0(virLockSpaceResource, 1);
        res->fd = -1;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource name in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        res->name = g_strdup(tmp);

        if (!(tmp = virJSONValueObjectGetString(child, "path"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource path in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        res->path = g_strdup(tmp);
        if (virJSONValueObjectGetNumberInt(child, "fd", &res->fd) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource fd in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        if (virSetInherit(res->fd, false) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot enable close-on-exec flag"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        if (virJSONValueObjectGetBoolean(child, "lockHeld", &res->lockHeld) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource lockHeld in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }

        if (virJSONValueObjectGetNumberUint(child, "flags", &res->flags) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource flags in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }

        if (!(owners = virJSONValueObjectGet(child, "owners"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource owners in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }

        if (!virJSONValueIsArray(owners)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed owners array"));
            virLockSpaceResourceFree(res);
            goto error;
        }

        res->nOwners = virJSONValueArraySize(owners);
        res->owners = g_new0(pid_t, res->nOwners);

        for (j = 0; j < res->nOwners; j++) {
            unsigned long long int owner;
            virJSONValue *ownerval = virJSONValueArrayGet(owners, j);

            if (virJSONValueGetNumberUlong(ownerval, &owner) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Malformed owner value in JSON document"));
                virLockSpaceResourceFree(res);
                goto error;
            }

            res->owners[j] = (pid_t)owner;
        }

        if (virHashAddEntry(lockspace->resources, res->name, res) < 0) {
            virLockSpaceResourceFree(res);
            goto error;
        }
    }

    return lockspace;

 error:
    virLockSpaceFree(lockspace);
    return NULL;
}


virJSONValue *virLockSpacePreExecRestart(virLockSpace *lockspace)
{
    g_autoptr(virJSONValue) object = virJSONValueNewObject();
    g_autoptr(virJSONValue) resources = virJSONValueNewArray();
    g_autofree virHashKeyValuePair *pairs = NULL;
    virHashKeyValuePair *tmp;
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    if (lockspace->dir &&
        virJSONValueObjectAppendString(object, "directory", lockspace->dir) < 0)
        return NULL;


    tmp = pairs = virHashGetItems(lockspace->resources, NULL, false);
    while (tmp && tmp->value) {
        virLockSpaceResource *res = (virLockSpaceResource *)tmp->value;
        g_autoptr(virJSONValue) child = virJSONValueNewObject();
        g_autoptr(virJSONValue) owners = virJSONValueNewArray();
        size_t i;

        if (virJSONValueObjectAppendString(child, "name", res->name) < 0 ||
            virJSONValueObjectAppendString(child, "path", res->path) < 0 ||
            virJSONValueObjectAppendNumberInt(child, "fd", res->fd) < 0 ||
            virJSONValueObjectAppendBoolean(child, "lockHeld", res->lockHeld) < 0 ||
            virJSONValueObjectAppendNumberUint(child, "flags", res->flags) < 0)
            return NULL;

        if (virSetInherit(res->fd, true) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot disable close-on-exec flag"));
            return NULL;
        }

        for (i = 0; i < res->nOwners; i++) {
            g_autoptr(virJSONValue) owner = virJSONValueNewNumberUlong(res->owners[i]);
            if (!owner)
                return NULL;

            if (virJSONValueArrayAppend(owners, &owner) < 0)
                return NULL;
        }

        if (virJSONValueObjectAppend(child, "owners", &owners) < 0)
            return NULL;

        if (virJSONValueArrayAppend(resources, &child) < 0)
            return NULL;

        tmp++;
    }

    if (virJSONValueObjectAppend(object, "resources", &resources) < 0)
        return NULL;

    return g_steal_pointer(&object);
}


void virLockSpaceFree(virLockSpace *lockspace)
{
    if (!lockspace)
        return;

    g_clear_pointer(&lockspace->resources, g_hash_table_unref);
    g_free(lockspace->dir);
    virMutexDestroy(&lockspace->lock);
    g_free(lockspace);
}


const char *virLockSpaceGetDirectory(virLockSpace *lockspace)
{
    return lockspace->dir;
}


int virLockSpaceCreateResource(virLockSpace *lockspace,
                               const char *resname)
{
    g_autofree char *respath = NULL;
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    VIR_DEBUG("lockspace=%p resname=%s", lockspace, resname);

    if (virHashLookup(lockspace->resources, resname) != NULL) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%1$s' is locked"),
                       resname);
        return -1;
    }

    if (!(respath = virLockSpaceGetResourcePath(lockspace, resname)))
        return -1;

    if (virFileTouch(respath, 0600) < 0)
        return -1;

    return 0;
}


int virLockSpaceDeleteResource(virLockSpace *lockspace,
                               const char *resname)
{
    g_autofree char *respath = NULL;
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    VIR_DEBUG("lockspace=%p resname=%s", lockspace, resname);

    if (virHashLookup(lockspace->resources, resname) != NULL) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%1$s' is locked"),
                       resname);
        return -1;
    }

    if (!(respath = virLockSpaceGetResourcePath(lockspace, resname)))
        return -1;

    if (unlink(respath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete lockspace resource %1$s"),
                             respath);
        return -1;
    }

    return 0;
}


int virLockSpaceAcquireResource(virLockSpace *lockspace,
                                const char *resname,
                                pid_t owner,
                                unsigned int flags)
{
    virLockSpaceResource *res;
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    VIR_DEBUG("lockspace=%p resname=%s flags=0x%x owner=%lld",
              lockspace, resname, flags, (unsigned long long)owner);

    virCheckFlags(VIR_LOCK_SPACE_ACQUIRE_SHARED |
                  VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE, -1);

    if ((res = virHashLookup(lockspace->resources, resname))) {
        if ((res->flags & VIR_LOCK_SPACE_ACQUIRE_SHARED) &&
            (flags & VIR_LOCK_SPACE_ACQUIRE_SHARED)) {

            VIR_EXPAND_N(res->owners, res->nOwners, 1);
            res->owners[res->nOwners-1] = owner;

            return 0;
        }
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%1$s' is locked"),
                       resname);
        return -1;
    }

    if (!(res = virLockSpaceResourceNew(lockspace, resname, flags, owner)))
        return -1;

    if (virHashAddEntry(lockspace->resources, resname, res) < 0) {
        virLockSpaceResourceFree(res);
        return -1;
    }

    return 0;
}


int virLockSpaceReleaseResource(virLockSpace *lockspace,
                                const char *resname,
                                pid_t owner)
{
    virLockSpaceResource *res;
    size_t i;
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    VIR_DEBUG("lockspace=%p resname=%s owner=%lld",
              lockspace, resname, (unsigned long long)owner);

    if (!(res = virHashLookup(lockspace->resources, resname))) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%1$s' is not locked"),
                       resname);
        return -1;
    }

    for (i = 0; i < res->nOwners; i++) {
        if (res->owners[i] == owner)
            break;
    }

    if (i == res->nOwners) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("owner %1$lld does not hold the resource lock"),
                       (unsigned long long)owner);
        return -1;
    }

    VIR_DELETE_ELEMENT(res->owners, i, res->nOwners);

    if ((res->nOwners == 0) &&
        virHashRemoveEntry(lockspace->resources, resname) < 0)
        return -1;

    return 0;
}


struct virLockSpaceRemoveData {
    pid_t owner;
    size_t count;
};


static int
virLockSpaceRemoveResourcesForOwner(const void *payload,
                                    const char *name G_GNUC_UNUSED,
                                    const void *opaque)
{
    virLockSpaceResource *res = (virLockSpaceResource *)payload;
    struct virLockSpaceRemoveData *data = (struct virLockSpaceRemoveData *)opaque;
    size_t i;

    VIR_DEBUG("res %s owner %lld", res->name, (unsigned long long)data->owner);

    for (i = 0; i < res->nOwners; i++) {
        if (res->owners[i] == data->owner)
            break;
    }

    if (i == res->nOwners)
        return 0;

    data->count++;

    VIR_DELETE_ELEMENT(res->owners, i, res->nOwners);

    if (res->nOwners) {
        VIR_DEBUG("Other shared owners remain");
        return 0;
    }

    VIR_DEBUG("No more owners, remove it");
    return 1;
}


int virLockSpaceReleaseResourcesForOwner(virLockSpace *lockspace,
                                         pid_t owner)
{
    struct virLockSpaceRemoveData data = {
        owner, 0
    };
    VIR_LOCK_GUARD lock = virLockGuardLock(&lockspace->lock);

    VIR_DEBUG("lockspace=%p owner=%lld", lockspace, (unsigned long long)owner);

    if (virHashRemoveSet(lockspace->resources,
                         virLockSpaceRemoveResourcesForOwner,
                         &data) < 0)
        return -1;

    return data.count;
}
