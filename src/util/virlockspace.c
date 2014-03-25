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
#include "virstring.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define VIR_FROM_THIS VIR_FROM_LOCKSPACE

VIR_LOG_INIT("util.lockspace");

#define VIR_LOCKSPACE_TABLE_SIZE 10

typedef struct _virLockSpaceResource virLockSpaceResource;
typedef virLockSpaceResource *virLockSpaceResourcePtr;

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

    virHashTablePtr resources;
};


static char *virLockSpaceGetResourcePath(virLockSpacePtr lockspace,
                                         const char *resname)
{
    char *ret;
    if (lockspace->dir)
        ignore_value(virAsprintf(&ret, "%s/%s", lockspace->dir, resname));
    else
        ignore_value(VIR_STRDUP(ret, resname));
    return ret;
}


static void virLockSpaceResourceFree(virLockSpaceResourcePtr res)
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
                    char ebuf[1024];
                    VIR_WARN("Failed to unlink resource %s: %s",
                             res->path, virStrerror(errno, ebuf, sizeof(ebuf)));
                }
            }
        } else {
            if (unlink(res->path) < 0 &&
                errno != ENOENT) {
                char ebuf[1024];
                VIR_WARN("Failed to unlink resource %s: %s",
                         res->path, virStrerror(errno, ebuf, sizeof(ebuf)));
            }
        }
    }

    VIR_FREE(res->owners);
    VIR_FORCE_CLOSE(res->fd);
    VIR_FREE(res->path);
    VIR_FREE(res->name);
    VIR_FREE(res);
}


static virLockSpaceResourcePtr
virLockSpaceResourceNew(virLockSpacePtr lockspace,
                        const char *resname,
                        unsigned int flags,
                        pid_t owner)
{
    virLockSpaceResourcePtr res;
    bool shared = !!(flags & VIR_LOCK_SPACE_ACQUIRE_SHARED);

    if (VIR_ALLOC(res) < 0)
        return NULL;

    res->fd = -1;
    res->flags = flags;

    if (VIR_STRDUP(res->name, resname) < 0)
        goto error;

    if (!(res->path = virLockSpaceGetResourcePath(lockspace, resname)))
        goto error;

    if (flags & VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE) {
        while (1) {
            struct stat a, b;
            if ((res->fd = open(res->path, O_RDWR|O_CREAT, 0600)) < 0) {
                virReportSystemError(errno,
                                     _("Unable to open/create resource %s"),
                                     res->path);
                goto error;
            }

            if (virSetCloseExec(res->fd) < 0) {
                virReportSystemError(errno,
                                     _("Failed to set close-on-exec flag '%s'"),
                                     res->path);
                goto error;
            }

            if (fstat(res->fd, &b) < 0) {
                virReportSystemError(errno,
                                     _("Unable to check status of pid file '%s'"),
                                     res->path);
                goto error;
            }

            if (virFileLock(res->fd, shared, 0, 1, false) < 0) {
                if (errno == EACCES || errno == EAGAIN) {
                    virReportError(VIR_ERR_RESOURCE_BUSY,
                                   _("Lockspace resource '%s' is locked"),
                                   resname);
                } else {
                    virReportSystemError(errno,
                                         _("Unable to acquire lock on '%s'"),
                                         res->path);
                }
                goto error;
            }

            /* Now make sure the pidfile we locked is the same
             * one that now exists on the filesystem
             */
            if (stat(res->path, &a) < 0) {
                char ebuf[1024] ATTRIBUTE_UNUSED;
                VIR_DEBUG("Resource '%s' disappeared: %s",
                          res->path, virStrerror(errno, ebuf, sizeof(ebuf)));
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
                                 _("Unable to open resource %s"),
                                 res->path);
            goto error;
        }

        if (virSetCloseExec(res->fd) < 0) {
            virReportSystemError(errno,
                                 _("Failed to set close-on-exec flag '%s'"),
                                 res->path);
            goto error;
        }

        if (virFileLock(res->fd, shared, 0, 1, false) < 0) {
            if (errno == EACCES || errno == EAGAIN) {
                virReportError(VIR_ERR_RESOURCE_BUSY,
                               _("Lockspace resource '%s' is locked"),
                               resname);
            } else {
                virReportSystemError(errno,
                                     _("Unable to acquire lock on '%s'"),
                                     res->path);
            }
            goto error;
        }
    }
    res->lockHeld = true;

    if (VIR_EXPAND_N(res->owners, res->nOwners, 1) < 0)
        goto error;

    res->owners[res->nOwners-1] = owner;

    return res;

 error:
    virLockSpaceResourceFree(res);
    return NULL;
}


static void virLockSpaceResourceDataFree(void *opaque, const void *name ATTRIBUTE_UNUSED)
{
    virLockSpaceResourcePtr res = opaque;
    virLockSpaceResourceFree(res);
}


virLockSpacePtr virLockSpaceNew(const char *directory)
{
    virLockSpacePtr lockspace;

    VIR_DEBUG("directory=%s", NULLSTR(directory));

    if (VIR_ALLOC(lockspace) < 0)
        return NULL;

    if (virMutexInit(&lockspace->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize lockspace mutex"));
        VIR_FREE(lockspace);
        return NULL;
    }

    if (VIR_STRDUP(lockspace->dir, directory) < 0)
        goto error;

    if (!(lockspace->resources = virHashCreate(VIR_LOCKSPACE_TABLE_SIZE,
                                               virLockSpaceResourceDataFree)))
        goto error;

    if (directory) {
        if (virFileExists(directory)) {
            if (!virFileIsDir(directory)) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Lockspace location %s exists, but is not a directory"),
                           directory);
                goto error;
            }
        } else {
            if (virFileMakePathWithMode(directory, 0700) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create lockspace %s"),
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



virLockSpacePtr virLockSpaceNewPostExecRestart(virJSONValuePtr object)
{
    virLockSpacePtr lockspace;
    virJSONValuePtr resources;
    int n;
    size_t i;

    VIR_DEBUG("object=%p", object);

    if (VIR_ALLOC(lockspace) < 0)
        return NULL;

    if (virMutexInit(&lockspace->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize lockspace mutex"));
        VIR_FREE(lockspace);
        return NULL;
    }

    if (!(lockspace->resources = virHashCreate(VIR_LOCKSPACE_TABLE_SIZE,
                                               virLockSpaceResourceDataFree)))
        goto error;

    if (virJSONValueObjectHasKey(object, "directory")) {
        const char *dir = virJSONValueObjectGetString(object, "directory");
        if (VIR_STRDUP(lockspace->dir, dir) < 0)
            goto error;
    }

    if (!(resources = virJSONValueObjectGet(object, "resources"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing resources value in JSON document"));
        goto error;
    }

    if ((n = virJSONValueArraySize(resources)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed resources value in JSON document"));
        goto error;
    }

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(resources, i);
        virLockSpaceResourcePtr res;
        const char *tmp;
        virJSONValuePtr owners;
        size_t j;
        int m;

        if (VIR_ALLOC(res) < 0)
            goto error;
        res->fd = -1;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource name in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        if (VIR_STRDUP(res->name, tmp) < 0) {
            virLockSpaceResourceFree(res);
            goto error;
        }

        if (!(tmp = virJSONValueObjectGetString(child, "path"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing resource path in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }
        if (VIR_STRDUP(res->path, tmp) < 0) {
            virLockSpaceResourceFree(res);
            goto error;
        }
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

        if ((m = virJSONValueArraySize(owners)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed owners value in JSON document"));
            virLockSpaceResourceFree(res);
            goto error;
        }

        res->nOwners = m;
        if (VIR_ALLOC_N(res->owners, res->nOwners) < 0) {
            virLockSpaceResourceFree(res);
            goto error;
        }

        for (j = 0; j < res->nOwners; j++) {
            unsigned long long int owner;
            virJSONValuePtr ownerval = virJSONValueArrayGet(owners, j);

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


virJSONValuePtr virLockSpacePreExecRestart(virLockSpacePtr lockspace)
{
    virJSONValuePtr object = virJSONValueNewObject();
    virJSONValuePtr resources;
    virHashKeyValuePairPtr pairs = NULL, tmp;

    if (!object)
        return NULL;

    virMutexLock(&lockspace->lock);

    if (lockspace->dir &&
        virJSONValueObjectAppendString(object, "directory", lockspace->dir) < 0)
        goto error;

    if (!(resources = virJSONValueNewArray()))
        goto error;

    if (virJSONValueObjectAppend(object, "resources", resources) < 0) {
        virJSONValueFree(resources);
        goto error;
    }

    tmp = pairs = virHashGetItems(lockspace->resources, NULL);
    while (tmp && tmp->value) {
        virLockSpaceResourcePtr res = (virLockSpaceResourcePtr)tmp->value;
        virJSONValuePtr child = virJSONValueNewObject();
        virJSONValuePtr owners = NULL;
        size_t i;

        if (!child)
            goto error;

        if (virJSONValueArrayAppend(resources, child) < 0) {
            virJSONValueFree(child);
            goto error;
        }

        if (virJSONValueObjectAppendString(child, "name", res->name) < 0 ||
            virJSONValueObjectAppendString(child, "path", res->path) < 0 ||
            virJSONValueObjectAppendNumberInt(child, "fd", res->fd) < 0 ||
            virJSONValueObjectAppendBoolean(child, "lockHeld", res->lockHeld) < 0 ||
            virJSONValueObjectAppendNumberUint(child, "flags", res->flags) < 0)
            goto error;

        if (virSetInherit(res->fd, true) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot disable close-on-exec flag"));
            goto error;
        }

        if (!(owners = virJSONValueNewArray()))
            goto error;

        if (virJSONValueObjectAppend(child, "owners", owners) < 0) {
            virJSONValueFree(owners);
            goto error;
        }

        for (i = 0; i < res->nOwners; i++) {
            virJSONValuePtr owner = virJSONValueNewNumberUlong(res->owners[i]);
            if (!owner)
                goto error;

            if (virJSONValueArrayAppend(owners, owner) < 0) {
                virJSONValueFree(owner);
                goto error;
            }
        }

        tmp++;
    }
    VIR_FREE(pairs);

    virMutexUnlock(&lockspace->lock);
    return object;

 error:
    VIR_FREE(pairs);
    virJSONValueFree(object);
    virMutexUnlock(&lockspace->lock);
    return NULL;
}


void virLockSpaceFree(virLockSpacePtr lockspace)
{
    if (!lockspace)
        return;

    virHashFree(lockspace->resources);
    VIR_FREE(lockspace->dir);
    virMutexDestroy(&lockspace->lock);
    VIR_FREE(lockspace);
}


const char *virLockSpaceGetDirectory(virLockSpacePtr lockspace)
{
    return lockspace->dir;
}


int virLockSpaceCreateResource(virLockSpacePtr lockspace,
                               const char *resname)
{
    int ret = -1;
    char *respath = NULL;

    VIR_DEBUG("lockspace=%p resname=%s", lockspace, resname);

    virMutexLock(&lockspace->lock);

    if (virHashLookup(lockspace->resources, resname) != NULL) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%s' is locked"),
                       resname);
        goto cleanup;
    }

    if (!(respath = virLockSpaceGetResourcePath(lockspace, resname)))
        goto cleanup;

    if (virFileTouch(respath, 0600) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virMutexUnlock(&lockspace->lock);
    VIR_FREE(respath);
    return ret;
}


int virLockSpaceDeleteResource(virLockSpacePtr lockspace,
                               const char *resname)
{
    int ret = -1;
    char *respath = NULL;

    VIR_DEBUG("lockspace=%p resname=%s", lockspace, resname);

    virMutexLock(&lockspace->lock);

    if (virHashLookup(lockspace->resources, resname) != NULL) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%s' is locked"),
                       resname);
        goto cleanup;
    }

    if (!(respath = virLockSpaceGetResourcePath(lockspace, resname)))
        goto cleanup;

    if (unlink(respath) < 0 &&
        errno != ENOENT) {
        virReportSystemError(errno,
                             _("Unable to delete lockspace resource %s"),
                             respath);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virMutexUnlock(&lockspace->lock);
    VIR_FREE(respath);
    return ret;
}


int virLockSpaceAcquireResource(virLockSpacePtr lockspace,
                                const char *resname,
                                pid_t owner,
                                unsigned int flags)
{
    int ret = -1;
    virLockSpaceResourcePtr res;

    VIR_DEBUG("lockspace=%p resname=%s flags=%x owner=%lld",
              lockspace, resname, flags, (unsigned long long)owner);

    virCheckFlags(VIR_LOCK_SPACE_ACQUIRE_SHARED |
                  VIR_LOCK_SPACE_ACQUIRE_AUTOCREATE, -1);

    virMutexLock(&lockspace->lock);

    if ((res = virHashLookup(lockspace->resources, resname))) {
        if ((res->flags & VIR_LOCK_SPACE_ACQUIRE_SHARED) &&
            (flags & VIR_LOCK_SPACE_ACQUIRE_SHARED)) {

            if (VIR_EXPAND_N(res->owners, res->nOwners, 1) < 0)
                goto cleanup;
            res->owners[res->nOwners-1] = owner;

            goto done;
        }
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%s' is locked"),
                       resname);
        goto cleanup;
    }

    if (!(res = virLockSpaceResourceNew(lockspace, resname, flags, owner)))
        goto cleanup;

    if (virHashAddEntry(lockspace->resources, resname, res) < 0) {
        virLockSpaceResourceFree(res);
        goto cleanup;
    }

 done:
    ret = 0;

 cleanup:
    virMutexUnlock(&lockspace->lock);
    return ret;
}


int virLockSpaceReleaseResource(virLockSpacePtr lockspace,
                                const char *resname,
                                pid_t owner)
{
    int ret = -1;
    virLockSpaceResourcePtr res;
    size_t i;

    VIR_DEBUG("lockspace=%p resname=%s owner=%lld",
              lockspace, resname, (unsigned long long)owner);

    virMutexLock(&lockspace->lock);

    if (!(res = virHashLookup(lockspace->resources, resname))) {
        virReportError(VIR_ERR_RESOURCE_BUSY,
                       _("Lockspace resource '%s' is not locked"),
                       resname);
        goto cleanup;
    }

    for (i = 0; i < res->nOwners; i++) {
        if (res->owners[i] == owner) {
            break;
        }
    }

    if (i == res->nOwners) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("owner %lld does not hold the resource lock"),
                       (unsigned long long)owner);
        goto cleanup;
    }

    VIR_DELETE_ELEMENT(res->owners, i, res->nOwners);

    if ((res->nOwners == 0) &&
        virHashRemoveEntry(lockspace->resources, resname) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virMutexUnlock(&lockspace->lock);
    return ret;
}


struct virLockSpaceRemoveData {
    pid_t owner;
    size_t count;
};


static int
virLockSpaceRemoveResourcesForOwner(const void *payload,
                                    const void *name ATTRIBUTE_UNUSED,
                                    const void *opaque)
{
    virLockSpaceResourcePtr res = (virLockSpaceResourcePtr)payload;
    struct virLockSpaceRemoveData *data = (struct virLockSpaceRemoveData *)opaque;
    size_t i;

    VIR_DEBUG("res %s owner %lld", res->name, (unsigned long long)data->owner);

    for (i = 0; i < res->nOwners; i++) {
        if (res->owners[i] == data->owner) {
            break;
        }
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


int virLockSpaceReleaseResourcesForOwner(virLockSpacePtr lockspace,
                                         pid_t owner)
{
    int ret = 0;
    struct virLockSpaceRemoveData data = {
        owner, 0
    };

    VIR_DEBUG("lockspace=%p owner=%lld", lockspace, (unsigned long long)owner);

    virMutexLock(&lockspace->lock);

    if (virHashRemoveSet(lockspace->resources,
                         virLockSpaceRemoveResourcesForOwner,
                         &data) < 0)
        goto error;

    ret = data.count;

    virMutexUnlock(&lockspace->lock);
    return ret;

 error:
    virMutexUnlock(&lockspace->lock);
    return -1;
}
