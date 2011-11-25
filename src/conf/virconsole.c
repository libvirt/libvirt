/**
 * virconsole.c: api to guarantee mutually exclusive
 * access to domain's consoles
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Peter Krempa <pkrempa@redhat.com>
 */

#include <config.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>

#include "virconsole.h"
#include "virhash.h"
#include "fdstream.h"
#include "internal.h"
#include "threads.h"
#include "memory.h"
#include "virpidfile.h"
#include "logging.h"
#include "virterror_internal.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_NONE
#define virConsoleError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,                  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/* structure holding information about consoles
 * open in a given domain */
struct _virConsoles {
    virMutex lock;
    virHashTablePtr hash;
};

typedef struct _virConsoleStreamInfo virConsoleStreamInfo;
typedef virConsoleStreamInfo *virConsoleStreamInfoPtr;
struct _virConsoleStreamInfo {
    virConsolesPtr cons;
    const char *pty;
};

#ifdef VIR_PTY_LOCK_FILE_PATH
/**
 * Create a full filename with path to the lock file based on
 * name/path of corresponding pty
 *
 * @pty path of the console device
 *
 * Returns a modified name that the caller has to free, or NULL
 * on error.
 */
static char *virConsoleLockFilePath(const char *pty)
{
    char *path = NULL;
    char *sanitizedPath = NULL;
    char *ptyCopy;
    char *filename;
    char *p;

    if (!(ptyCopy = strdup(pty))) {
        virReportOOMError();
        goto cleanup;
    }

    /* skip the leading "/dev/" */
    filename = STRSKIP(ptyCopy, "/dev");
    if (!filename)
        filename = ptyCopy;

    /* substitute path forward slashes for underscores */
    p = filename;
    while (*p) {
        if (*p == '/')
            *p = '_';
        ++p;
    }

    if (virAsprintf(&path, "%s/LCK..%s", VIR_PTY_LOCK_FILE_PATH, filename) < 0)
        goto cleanup;

    sanitizedPath = virFileSanitizePath(path);

cleanup:
    VIR_FREE(path);
    VIR_FREE(ptyCopy);

    return sanitizedPath;
}

/**
 * Verify and create a lock file for a console pty
 *
 * @pty Path of the console device
 *
 * Returns 0 on success, -1 on error
 */
static int virConsoleLockFileCreate(const char *pty)
{
    char *path = NULL;
    int ret = -1;
    int lockfd = -1;
    char *pidStr = NULL;
    pid_t pid;

    /* build lock file path */
    if (!(path = virConsoleLockFilePath(pty)))
        goto cleanup;

    /* check if a log file and process holding the lock still exists */
    if (virPidFileReadPathIfAlive(path, &pid, NULL) == 0 && pid >= 0) {
        /* the process exists, the lockfile is valid */
        virConsoleError(VIR_ERR_OPERATION_FAILED,
                        _("Requested console pty '%s' is locked by "
                          "lock file '%s' held by process %lld"),
                        pty, path, (long long) pid);
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
            VIR_DEBUG("Skipping lock file creation for pty '%s in path '%s'.",
                      pty, path);
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno,
                             _("Couldn't create lock file for "
                               "pty '%s' in path '%s'"),
                             pty, path);
        goto cleanup;
    }

    /* write the pid to the file */
    if (safewrite(lockfd, pidStr, strlen(pidStr)) < 0) {
        virReportSystemError(errno,
                             _("Couldn't write to lock file for "
                               "pty '%s' in path '%s'"),
                             pty, path);
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
 * Remove a lock file for a pty
 *
 * @pty Path of the pty device
 */
static void virConsoleLockFileRemove(const char *pty)
{
    char *path = virConsoleLockFilePath(pty);
    if (path)
        unlink(path);
    VIR_FREE(path);
}
#else /* #ifdef VIR_PTY_LOCK_FILE_PATH */
/* file locking for console devices is disabled */
static int virConsoleLockFileCreate(const char *pty ATTRIBUTE_UNUSED)
{
    return 0;
}

static void virConsoleLockFileRemove(const char *pty ATTRIBUTE_UNUSED)
{
    return;
}
#endif /* #ifdef VIR_PTY_LOCK_FILE_PATH */

/**
 * Frees an entry from the hash containing domain's active consoles
 *
 * @data Opaque data, struct holding information about the console
 * @name Path of the pty.
 */
static void virConsoleHashEntryFree(void *data,
                                    const void *name)
{
    const char *pty = name;
    virStreamPtr st = data;

    /* free stream reference */
    virStreamFree(st);

    /* delete lock file */
    virConsoleLockFileRemove(pty);
}

/**
 * Frees opaque data provided for the stream closing callback
 *
 * @opaque Data to be freed.
 */
static void virConsoleFDStreamCloseCbFree(void *opaque)
{
    virConsoleStreamInfoPtr priv = opaque;

    VIR_FREE(priv->pty);
    VIR_FREE(priv);
}

/**
 * Callback being called if a FDstream is closed. Frees console entries
 * from data structures and removes lockfiles.
 *
 * @st Pointer to stream being closed.
 * @opaque Domain's console information structure.
 */
static void virConsoleFDStreamCloseCb(virStreamPtr st ATTRIBUTE_UNUSED,
                                      void *opaque)
{
    virConsoleStreamInfoPtr priv = opaque;
    virMutexLock(&priv->cons->lock);

    /* remove entry from hash */
    virHashRemoveEntry(priv->cons->hash, priv->pty);

    virMutexUnlock(&priv->cons->lock);
}

/**
 * Allocate structures for storing information about active console streams
 * in domain's private data section.
 *
 * Returns pointer to the allocated structure or NULL on error
 */
virConsolesPtr virConsoleAlloc(void)
{
    virConsolesPtr cons;
    if (VIR_ALLOC(cons) < 0)
        return NULL;

    if (virMutexInit(&cons->lock) < 0) {
        VIR_FREE(cons);
        return NULL;
    }

    /* there will hardly be any consoles most of the time, the hash
     * does not have to be huge */
    if (!(cons->hash = virHashCreate(3, virConsoleHashEntryFree)))
        goto error;

    return cons;
error:
    virConsoleFree(cons);
    return NULL;
}

/**
 * Free structures for handling open console streams.
 *
 * @cons Pointer to the private structure.
 */
void virConsoleFree(virConsolesPtr cons)
{
    if (!cons || !cons->hash)
        return;

    virMutexLock(&cons->lock);
    virHashFree(cons->hash);
    virMutexUnlock(&cons->lock);
    virMutexDestroy(&cons->lock);

    VIR_FREE(cons);
}

/**
 * Open a console stream for a domain ensuring that other streams are
 * not using the console, nor any lockfiles exist. This ensures that
 * the console stream does not get corrupted due to a race on reading
 * same FD by two processes.
 *
 * @cons Pointer to private structure holding data about console streams.
 * @pty Path to the pseudo tty to be opened.
 * @st Stream the client wishes to use for the console connection.
 * @force On true, close active console streams for the selected console pty
 *        before opening this connection.
 *
 * Returns 0 on success and st is connected to the selected pty and
 * corresponding lock file is created (if configured). Returns -1 on
 * error and 1 if the console stream is open and busy.
 */
int virConsoleOpen(virConsolesPtr cons,
                   const char *pty,
                   virStreamPtr st,
                   bool force)
{
    virConsoleStreamInfoPtr cbdata = NULL;
    virStreamPtr savedStream;
    int ret;

    virMutexLock(&cons->lock);

    if ((savedStream = virHashLookup(cons->hash, pty))) {
        if (!force) {
             /* entry found, console is busy */
            virMutexUnlock(&cons->lock);
            return 1;
       } else {
           /* terminate existing connection */
           /* The internal close callback handler needs to lock cons->lock to
            * remove the aborted stream from the hash. This would cause a
            * deadlock as we would try to enter the lock twice from the very
            * same thread. We need to unregister the callback and abort the
            * stream manually before we create a new console connection.
            */
           virFDStreamSetInternalCloseCb(savedStream, NULL, NULL, NULL);
           virStreamAbort(savedStream);
           virHashRemoveEntry(cons->hash, pty);
           /* continue adding a new stream connection */
       }
    }

    /* create the lock file */
    if ((ret = virConsoleLockFileCreate(pty)) < 0) {
        virMutexUnlock(&cons->lock);
        return ret;
    }

    /* obtain a reference to the stream */
    if (virStreamRef(st) < 0) {
        virMutexUnlock(&cons->lock);
        return -1;
    }

    if (VIR_ALLOC(cbdata) < 0) {
        virReportOOMError();
        goto error;
    }

    if (virHashAddEntry(cons->hash, pty, st) < 0)
        goto error;

    cbdata->cons = cons;
    if (!(cbdata->pty = strdup(pty))) {
        virReportOOMError();
        goto error;
    }

    /* open the console pty */
    if (virFDStreamOpenFile(st, pty, 0, 0, O_RDWR) < 0)
        goto error;

    savedStream = st;
    st = NULL;

    /* add cleanup callback */
    virFDStreamSetInternalCloseCb(savedStream,
                                  virConsoleFDStreamCloseCb,
                                  cbdata,
                                  virConsoleFDStreamCloseCbFree);
    cbdata = NULL;

    virMutexUnlock(&cons->lock);
    return 0;

error:
    virStreamFree(st);
    virHashRemoveEntry(cons->hash, pty);
    if (cbdata)
        VIR_FREE(cbdata->pty);
    VIR_FREE(cbdata);
    virMutexUnlock(&cons->lock);
    return -1;
}
