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

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("conf.chrdev");

/* structure holding information about character devices
 * open in a given domain */
struct _virChrdevs {
    virMutex lock;
    GHashTable *hash;
};

typedef struct _virChrdevStreamInfo virChrdevStreamInfo;
struct _virChrdevStreamInfo {
    virChrdevs *devs;
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
    g_autofree char *path = NULL;
    g_autofree char *sanitizedPath = NULL;
    g_autofree char *devCopy = NULL;
    char *filename;
    char *p;

    devCopy = g_strdup(dev);

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

    path = g_strdup_printf("%s/LCK..%s", VIR_CHRDEV_LOCK_FILE_PATH, filename);

    sanitizedPath = virFileSanitizePath(path);

    return g_steal_pointer(&sanitizedPath);
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
    g_autofree char *path = NULL;
    g_autofree char *pidStr = NULL;
    VIR_AUTOCLOSE lockfd = -1;
    pid_t pid;

    /* build lock file path */
    if (!(path = virChrdevLockFilePath(dev)))
        return -1;

    /* check if a log file and process holding the lock still exists */
    if (virPidFileReadPathIfAlive(path, &pid, NULL) == 0 && pid >= 0) {
        /* the process exists, the lockfile is valid */
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Requested device '%1$s' is locked by lock file '%2$s' held by process %3$lld"),
                       dev, path, (long long) pid);
        return -1;
    } else {
        /* clean up the stale/corrupted/nonexistent lockfile */
        unlink(path);
    }
    /* lockfile doesn't (shouldn't) exist */

    /* ensure correct format according to filesystem hierarchy standard */
    /* https://www.pathname.com/fhs/pub/fhs-2.3.html#VARLOCKLOCKFILES */
    pidStr = g_strdup_printf("%10lld\n", (long long)getpid());

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
            return 0;
        }
        virReportSystemError(errno,
                             _("Couldn't create lock file for device '%1$s' in path '%2$s'"),
                             dev, path);
        return -1;
    }

    /* write the pid to the file */
    if (safewrite(lockfd, pidStr, strlen(pidStr)) < 0) {
        virReportSystemError(errno,
                             _("Couldn't write to lock file for device '%1$s' in path '%2$s'"),
                             dev, path);
        unlink(path);
        return -1;
    }

    /* we hold the lock */
    return 0;
}

/**
 * Remove a lock file for a device
 *
 * @dev Path of the device
 */
static void virChrdevLockFileRemove(const char *dev)
{
    g_autofree char *path = virChrdevLockFilePath(dev);
    unlink(path);
}
#else /* #ifdef VIR_CHRDEV_LOCK_FILE_PATH */
/* file locking for character devices is disabled */
static int virChrdevLockFileCreate(const char *dev G_GNUC_UNUSED)
{
    return 0;
}

static void virChrdevLockFileRemove(const char *dev G_GNUC_UNUSED)
{
    return;
}
#endif /* #ifdef VIR_CHRDEV_LOCK_FILE_PATH */

typedef struct {
    char *dev;
    virStreamPtr st;
} virChrdevHashEntry;

/**
 * Frees an entry from the hash containing domain's active devices
 *
 * @data Opaque data, struct holding information about the device
 */
static void virChrdevHashEntryFree(void *data)
{
    virChrdevHashEntry *ent = data;

    if (!ent)
        return;

    /* free stream reference */
    virObjectUnref(ent->st);

    /* delete lock file */
    virChrdevLockFileRemove(ent->dev);

    g_free(ent->dev);
    g_free(ent);
}

/**
 * Frees opaque data provided for the stream closing callback
 *
 * @opaque Data to be freed.
 */
static void virChrdevFDStreamCloseCbFree(void *opaque)
{
    virChrdevStreamInfo *priv = opaque;

    g_free(priv->path);
    g_free(priv);
}

/**
 * Callback being called if a FDstream is closed. Frees device entries
 * from data structures and removes lockfiles.
 *
 * @st Pointer to stream being closed.
 * @opaque Domain's device information structure.
 */
static void virChrdevFDStreamCloseCb(virStreamPtr st G_GNUC_UNUSED,
                                      void *opaque)
{
    virChrdevStreamInfo *priv = opaque;
    VIR_LOCK_GUARD lock = virLockGuardLock(&priv->devs->lock);

    /* remove entry from hash */
    virHashRemoveEntry(priv->devs->hash, priv->path);
}

/**
 * Allocate structures for storing information about active device streams
 * in domain's private data section.
 *
 * Returns pointer to the allocated structure or NULL on error
 */
virChrdevs *virChrdevAlloc(void)
{
    virChrdevs *devs;
    devs = g_new0(virChrdevs, 1);

    if (virMutexInit(&devs->lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to init device stream mutex"));
        VIR_FREE(devs);
        return NULL;
    }

    /* there will hardly be any devices most of the time, the hash
     * does not have to be huge */
    devs->hash = virHashNew(virChrdevHashEntryFree);

    return devs;
}

/**
 * Helper to clear stream callbacks when freeing the hash
 */
static int virChrdevFreeClearCallbacks(void *payload,
                                       const char *name G_GNUC_UNUSED,
                                       void *data G_GNUC_UNUSED)
{
    virChrdevHashEntry *ent = payload;

    virFDStreamSetInternalCloseCb(ent->st, NULL, NULL, NULL);
    return 0;
}

/**
 * Free structures for handling open device streams.
 *
 * @devs Pointer to the private structure.
 */
void virChrdevFree(virChrdevs *devs)
{
    if (!devs)
        return;

    VIR_WITH_MUTEX_LOCK_GUARD(&devs->lock) {
        virHashForEachSafe(devs->hash, virChrdevFreeClearCallbacks, NULL);
        g_clear_pointer(&devs->hash, g_hash_table_unref);
    }
    virMutexDestroy(&devs->lock);

    g_free(devs);
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
int virChrdevOpen(virChrdevs *devs,
                  virDomainChrSourceDef *source,
                  virStreamPtr st,
                  bool force)
{
    virChrdevStreamInfo *cbdata = NULL;
    virChrdevHashEntry *ent;
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
                       _("Unsupported device type '%1$s'"),
                       virDomainChrTypeToString(source->type));
        return -1;
    }

    virMutexLock(&devs->lock);

    if ((ent = virHashLookup(devs->hash, path))) {
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
           virFDStreamSetInternalCloseCb(ent->st, NULL, NULL, NULL);
           virStreamAbort(ent->st);
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

    cbdata = g_new0(virChrdevStreamInfo, 1);
    ent = g_new0(virChrdevHashEntry, 1);

    ent->st = st;
    ent->dev = g_strdup(path);

    if (virHashAddEntry(devs->hash, path, ent) < 0)
        goto error;
    ent = NULL;
    added = true;

    cbdata->devs = devs;
    cbdata->path = g_strdup(path);

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
                       _("Unsupported device type '%1$s'"),
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
    virChrdevHashEntryFree(ent);
    return -1;
}
