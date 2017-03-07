/**
 * virchrdev.c: api to guarantee mutually exclusive
 * access to domain's character devices
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
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
 * Author: Peter Krempa <pkrempa@redhat.com>
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include "virchrdev.h"
#include "virhash.h"
#include "virfdstream.h"
#include "internal.h"
#include "virthread.h"
#include "viralloc.h"
#include "virpidfile.h"
#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.chrdev");

/* structure holding information about character devices
 * open in a given domain */
struct _virChrdevs {
    virMutex lock;
    virHashTablePtr hash;
};

typedef struct _virChrdevStreamInfo virChrdevStreamInfo;
typedef virChrdevStreamInfo *virChrdevStreamInfoPtr;
struct _virChrdevStreamInfo {
    virChrdevsPtr devs;
    char *path;
};

#ifdef VIR_CHRDEV_LOCK_FILE_PATH
/**
 * Create a full filename with path to the lock file based on
 * name/path of corresponding device
 *
 * @dev path of the character device
 *
 * Returns a modified name that the caller has to free, or NULL
 * on error.
 */
static char *virChrdevLockFilePath(const char *dev)
{
    char *path = NULL;
    char *sanitizedPath = NULL;
    char *devCopy;
    char *filename;
    char *p;

    if (VIR_STRDUP(devCopy, dev) < 0)
        goto cleanup;

    /* skip the leading "/dev/" */
    filename = STRSKIP(devCopy, "/dev");
    if (!filename)
        filename = devCopy;

    /* substitute path forward slashes for underscores */
    p = filename;
    while (*p) {
        if (*p == '/')
            *p = '_';
        ++p;
    }

    if (virAsprintf(&path, "%s/LCK..%s", VIR_CHRDEV_LOCK_FILE_PATH, filename) < 0)
        goto cleanup;

    sanitizedPath = virFileSanitizePath(path);

 cleanup:
    VIR_FREE(path);
    VIR_FREE(devCopy);

    return sanitizedPath;
}

/**
 * Verify and create a lock file for a character device
 *
 * @dev Path of the character device
 *
 * Returns 0 on success, -1 on error
 */
static int virChrdevLockFileCreate(const char *dev)
{
    char *path = NULL;
    int ret = -1;
    int lockfd = -1;
    char *pidStr = NULL;
    pid_t pid;

    /* build lock file path */
    if (!(path = virChrdevLockFilePath(dev)))
        goto cleanup;

    /* check if a log file and process holding the lock still exists */
    if (virPidFileReadPathIfAlive(path, &pid, NULL) == 0 && pid >= 0) {
        /* the process exists, the lockfile is valid */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Requested device '%s' is locked by "
                         "lock file '%s' held by process %lld"),
                       dev, path, (long long) pid);
        goto cleanup;
    } else {
        /* clean up the stale/corrupted/nonexistent lockfile */
        unlink(path);
    }
    /* lockfile doesn't (shouldn't) exist */

    /* ensure correct format according to filesystem hierarchy standard */
    /* http://www.pathname.com/fhs/pub/fhs-2.3.html#VARLOCKLOCKFILES */
    if (virAsprintf(&pidStr, "%10lld\n", (long long) getpid()) < 0)
        goto cleanup;

    /* create the lock file */
    if ((lockfd = open(path, O_WRONLY | O_CREAT | O_EXCL, 00644)) < 0) {
        /* If we run in session mode, we might have no access to the lock
         * file directory. We have to check for an permission denied error
         * and see if we can reach it. This should cause an error only if
         * we run in daemon mode and thus privileged.
         */
        if (errno == EACCES && geteuid() != 0) {
            VIR_DEBUG("Skipping lock file creation for device '%s in path '%s'.",
                      dev, path);
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno,
                             _("Couldn't create lock file for "
                               "device '%s' in path '%s'"),
                             dev, path);
        goto cleanup;
    }

    /* write the pid to the file */
    if (safewrite(lockfd, pidStr, strlen(pidStr)) < 0) {
        virReportSystemError(errno,
                             _("Couldn't write to lock file for "
                               "device '%s' in path '%s'"),
                             dev, path);
        VIR_FORCE_CLOSE(lockfd);
        unlink(path);
        goto cleanup;
    }

    /* we hold the lock */
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(lockfd);
    VIR_FREE(path);
    VIR_FREE(pidStr);

    return ret;
}

/**
 * Remove a lock file for a device
 *
 * @dev Path of the device
 */
static void virChrdevLockFileRemove(const char *dev)
{
    char *path = virChrdevLockFilePath(dev);
    if (path)
        unlink(path);
    VIR_FREE(path);
}
#else /* #ifdef VIR_CHRDEV_LOCK_FILE_PATH */
/* file locking for character devices is disabled */
static int virChrdevLockFileCreate(const char *dev ATTRIBUTE_UNUSED)
{
    return 0;
}

static void virChrdevLockFileRemove(const char *dev ATTRIBUTE_UNUSED)
{
    return;
}
#endif /* #ifdef VIR_CHRDEV_LOCK_FILE_PATH */

/**
 * Frees an entry from the hash containing domain's active devices
 *
 * @data Opaque data, struct holding information about the device
 * @name Path of the device.
 */
static void virChrdevHashEntryFree(void *data,
                                    const void *name)
{
    const char *dev = name;
    virStreamPtr st = data;

    /* free stream reference */
    virObjectUnref(st);

    /* delete lock file */
    virChrdevLockFileRemove(dev);
}

/**
 * Frees opaque data provided for the stream closing callback
 *
 * @opaque Data to be freed.
 */
static void virChrdevFDStreamCloseCbFree(void *opaque)
{
    virChrdevStreamInfoPtr priv = opaque;

    VIR_FREE(priv->path);
    VIR_FREE(priv);
}

/**
 * Callback being called if a FDstream is closed. Frees device entries
 * from data structures and removes lockfiles.
 *
 * @st Pointer to stream being closed.
 * @opaque Domain's device information structure.
 */
static void virChrdevFDStreamCloseCb(virStreamPtr st ATTRIBUTE_UNUSED,
                                      void *opaque)
{
    virChrdevStreamInfoPtr priv = opaque;
    virMutexLock(&priv->devs->lock);

    /* remove entry from hash */
    virHashRemoveEntry(priv->devs->hash, priv->path);

    virMutexUnlock(&priv->devs->lock);
}

/**
 * Allocate structures for storing information about active device streams
 * in domain's private data section.
 *
 * Returns pointer to the allocated structure or NULL on error
 */
virChrdevsPtr virChrdevAlloc(void)
{
    virChrdevsPtr devs;
    if (VIR_ALLOC(devs) < 0)
        return NULL;

    if (virMutexInit(&devs->lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to init device stream mutex"));
        VIR_FREE(devs);
        return NULL;
    }

    /* there will hardly be any devices most of the time, the hash
     * does not have to be huge */
    if (!(devs->hash = virHashCreate(3, virChrdevHashEntryFree)))
        goto error;

    return devs;
 error:
    virChrdevFree(devs);
    return NULL;
}

/**
 * Helper to clear stream callbacks when freeing the hash
 */
static int virChrdevFreeClearCallbacks(void *payload,
                                       const void *name ATTRIBUTE_UNUSED,
                                       void *data ATTRIBUTE_UNUSED)
{
    virStreamPtr st = payload;

    virFDStreamSetInternalCloseCb(st, NULL, NULL, NULL);
    return 0;
}

/**
 * Free structures for handling open device streams.
 *
 * @devs Pointer to the private structure.
 */
void virChrdevFree(virChrdevsPtr devs)
{
    if (!devs || !devs->hash)
        return;

    virMutexLock(&devs->lock);
    virHashForEach(devs->hash, virChrdevFreeClearCallbacks, NULL);
    virHashFree(devs->hash);
    virMutexUnlock(&devs->lock);
    virMutexDestroy(&devs->lock);

    VIR_FREE(devs);
}

/**
 * Open a device stream for a domain ensuring that other streams are
 * not using the device, nor any lockfiles exist. This ensures that
 * the device stream does not get corrupted due to a race on reading
 * same FD by two processes.
 *
 * @devs Pointer to private structure holding data about device streams.
 * @source Pointer to private structure holding data about device source.
 * @st Stream the client wishes to use for the device connection.
 * @force On true, close active device streams for the selected character
 *        device before opening this connection.
 *
 * Returns 0 on success and st is connected to the selected device and
 * corresponding lock file is created (if configured). Returns -1 on
 * error and 1 if the device stream is open and busy.
 */
int virChrdevOpen(virChrdevsPtr devs,
                  virDomainChrSourceDefPtr source,
                  virStreamPtr st,
                  bool force)
{
    virChrdevStreamInfoPtr cbdata = NULL;
    virStreamPtr savedStream;
    char *path;
    int ret;
    bool added = false;

    switch (source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        path = source->data.file.path;
        if (!path) {
            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("PTY device is not yet assigned"));
            return -1;
        }
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        path = source->data.nix.path;
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported device type '%s'"),
                       virDomainChrTypeToString(source->type));
        return -1;
    }

    virMutexLock(&devs->lock);

    if ((savedStream = virHashLookup(devs->hash, path))) {
        if (!force) {
             /* entry found, device is busy */
            virMutexUnlock(&devs->lock);
            return 1;
       } else {
           /* terminate existing connection */
           /* The internal close callback handler needs to lock devs->lock to
            * remove the aborted stream from the hash. This would cause a
            * deadlock as we would try to enter the lock twice from the very
            * same thread. We need to unregister the callback and abort the
            * stream manually before we create a new device connection.
            */
           virFDStreamSetInternalCloseCb(savedStream, NULL, NULL, NULL);
           virStreamAbort(savedStream);
           virHashRemoveEntry(devs->hash, path);
           /* continue adding a new stream connection */
       }
    }

    /* create the lock file */
    if ((ret = virChrdevLockFileCreate(path)) < 0) {
        virMutexUnlock(&devs->lock);
        return ret;
    }

    /* obtain a reference to the stream */
    if (virStreamRef(st) < 0) {
        virMutexUnlock(&devs->lock);
        return -1;
    }

    if (VIR_ALLOC(cbdata) < 0)
        goto error;

    if (virHashAddEntry(devs->hash, path, st) < 0)
        goto error;
    added = true;

    cbdata->devs = devs;
    if (VIR_STRDUP(cbdata->path, path) < 0)
        goto error;

    /* open the character device */
    switch (source->type) {
    case VIR_DOMAIN_CHR_TYPE_PTY:
        if (virFDStreamOpenPTY(st, path, 0, 0, O_RDWR) < 0)
            goto error;
        break;
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        if (virFDStreamConnectUNIX(st, path, false) < 0)
            goto error;
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported device type '%s'"),
                       virDomainChrTypeToString(source->type));
        goto error;
    }

    /* add cleanup callback */
    virFDStreamSetInternalCloseCb(st,
                                  virChrdevFDStreamCloseCb,
                                  cbdata,
                                  virChrdevFDStreamCloseCbFree);

    virMutexUnlock(&devs->lock);
    return 0;

 error:
    if (added)
        virHashRemoveEntry(devs->hash, path);
    else
        virObjectUnref(st);

    if (cbdata)
        VIR_FREE(cbdata->path);
    VIR_FREE(cbdata);
    virMutexUnlock(&devs->lock);
    return -1;
}
