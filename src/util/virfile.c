/*
 * virfile.c: safer file handling
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
 * Copyright (C) 2010 Eric Blake
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
#include "internal.h"

#include "virfile.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#ifdef __linux__
# include <linux/loop.h>
# include <sys/ioctl.h>
#endif

#include "command.h"
#include "configmake.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_NONE

int virFileClose(int *fdptr, virFileCloseFlags flags)
{
    int saved_errno = 0;
    int rc = 0;

    if (*fdptr < 0)
        return 0;

    if (flags & VIR_FILE_CLOSE_PRESERVE_ERRNO)
        saved_errno = errno;

    rc = close(*fdptr);

    if (!(flags & VIR_FILE_CLOSE_DONT_LOG)) {
        if (rc < 0) {
            if (errno == EBADF) {
                if (!(flags & VIR_FILE_CLOSE_IGNORE_EBADF))
                    VIR_WARN("Tried to close invalid fd %d", *fdptr);
            } else {
                char ebuf[1024] ATTRIBUTE_UNUSED;
                VIR_DEBUG("Failed to close fd %d: %s",
                          *fdptr, virStrerror(errno, ebuf, sizeof(ebuf)));
            }
        } else {
            VIR_DEBUG("Closed fd %d", *fdptr);
        }
    }
    *fdptr = -1;

    if (flags & VIR_FILE_CLOSE_PRESERVE_ERRNO)
        errno = saved_errno;

    return rc;
}


int virFileFclose(FILE **file, bool preserve_errno)
{
    int saved_errno = 0;
    int rc = 0;

    if (*file) {
        if (preserve_errno)
            saved_errno = errno;
        rc = fclose(*file);
        *file = NULL;
        if (preserve_errno)
            errno = saved_errno;
    }

    return rc;
}


FILE *virFileFdopen(int *fdptr, const char *mode)
{
    FILE *file = NULL;

    if (*fdptr >= 0) {
        file = fdopen(*fdptr, mode);
        if (file)
            *fdptr = -1;
    } else {
        errno = EBADF;
    }

    return file;
}


/**
 * virFileDirectFdFlag:
 *
 * Returns 0 if the kernel can avoid file system cache pollution
 * without any additional flags, O_DIRECT if the original fd must be
 * opened in direct mode, or -1 if there is no support for bypassing
 * the file system cache.
 */
int
virFileDirectFdFlag(void)
{
    /* XXX For now, Linux posix_fadvise is not powerful enough to
     * avoid O_DIRECT.  */
    return O_DIRECT ? O_DIRECT : -1;
}

/* Opaque type for managing a wrapper around a fd.  For now,
 * read-write is not supported, just a single direction.  */
struct _virFileWrapperFd {
    virCommandPtr cmd; /* Child iohelper process to do the I/O.  */
};

#ifndef WIN32
/**
 * virFileWrapperFdNew:
 * @fd: pointer to fd to wrap
 * @name: name of fd, for diagnostics
 * @flags: bitwise-OR of virFileWrapperFdFlags
 *
 * Update @fd so that it meets parameters requested by @flags.
 *
 * If VIR_FILE_WRAPPER_BYPASS_CACHE bit is set in @flags, @fd will be updated
 * in a way that all I/O to that file will bypass the system cache.  The
 * original fd must have been created with virFileDirectFdFlag() among the
 * flags to open().
 *
 * If VIR_FILE_WRAPPER_NON_BLOCKING bit is set in @flags, @fd will be updated
 * to ensure it properly supports non-blocking I/O, i.e., it will report
 * EAGAIN.
 *
 * This must be called after open() and optional fchown() or fchmod(), but
 * before any seek or I/O, and only on seekable fd.  The file must be O_RDONLY
 * (to read the entire existing file) or O_WRONLY (to write to an empty file).
 * In some cases, @fd is changed to a non-seekable pipe; in this case, the
 * caller must not do anything further with the original fd.
 *
 * On success, the new wrapper object is returned, which must be later
 * freed with virFileWrapperFdFree().  On failure, @fd is unchanged, an
 * error message is output, and NULL is returned.
 */
virFileWrapperFdPtr
virFileWrapperFdNew(int *fd, const char *name, unsigned int flags)
{
    virFileWrapperFdPtr ret = NULL;
    bool output = false;
    int pipefd[2] = { -1, -1 };
    int mode = -1;

    if (!flags) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid use with no flags"));
        return NULL;
    }

    /* XXX support posix_fadvise rather than O_DIRECT, if the kernel support
     * for that is decent enough. In that case, we will also need to
     * explicitly support VIR_FILE_WRAPPER_NON_BLOCKING since
     * VIR_FILE_WRAPPER_BYPASS_CACHE alone will no longer require spawning
     * iohelper.
     */

    if ((flags & VIR_FILE_WRAPPER_BYPASS_CACHE) && !O_DIRECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("O_DIRECT unsupported on this platform"));
        return NULL;
    }

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    mode = fcntl(*fd, F_GETFL);

    if (mode < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("invalid fd %d for %s"),
                       *fd, name);
        goto error;
    } else if ((mode & O_ACCMODE) == O_WRONLY) {
        output = true;
    } else if ((mode & O_ACCMODE) != O_RDONLY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("unexpected mode %x for %s"),
                       mode & O_ACCMODE, name);
        goto error;
    }

    if (pipe2(pipefd, O_CLOEXEC) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to create pipe for %s"), name);
        goto error;
    }

    ret->cmd = virCommandNewArgList(LIBEXECDIR "/libvirt_iohelper",
                                    name, "0", NULL);
    if (output) {
        virCommandSetInputFD(ret->cmd, pipefd[0]);
        virCommandSetOutputFD(ret->cmd, fd);
        virCommandAddArg(ret->cmd, "1");
    } else {
        virCommandSetInputFD(ret->cmd, *fd);
        virCommandSetOutputFD(ret->cmd, &pipefd[1]);
        virCommandAddArg(ret->cmd, "0");
    }

    if (virCommandRunAsync(ret->cmd, NULL) < 0)
        goto error;

    if (VIR_CLOSE(pipefd[!output]) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("unable to close pipe"));
        goto error;
    }

    VIR_FORCE_CLOSE(*fd);
    *fd = pipefd[output];
    return ret;

error:
    VIR_FORCE_CLOSE(pipefd[0]);
    VIR_FORCE_CLOSE(pipefd[1]);
    virFileWrapperFdFree(ret);
    return NULL;
}
#else
virFileWrapperFdPtr
virFileWrapperFdNew(int *fd ATTRIBUTE_UNUSED,
                    const char *name ATTRIBUTE_UNUSED,
                    unsigned int fdflags ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("virFileWrapperFd unsupported on this platform"));
    return NULL;
}
#endif

/**
 * virFileWrapperFdClose:
 * @wfd: fd wrapper, or NULL
 *
 * If @wfd is valid, then ensure that I/O has completed, which may
 * include reaping a child process.  Return 0 if all data for the
 * wrapped fd is complete, or -1 on failure with an error emitted.
 * This function intentionally returns 0 when @wfd is NULL, so that
 * callers can conditionally create a virFileWrapperFd wrapper but
 * unconditionally call the cleanup code.  To avoid deadlock, only
 * call this after closing the fd resulting from virFileWrapperFdNew().
 */
int
virFileWrapperFdClose(virFileWrapperFdPtr wfd)
{
    if (!wfd)
        return 0;

    return virCommandWait(wfd->cmd, NULL);
}

/**
 * virFileWrapperFdFree:
 * @wfd: fd wrapper, or NULL
 *
 * Free all remaining resources associated with @wfd.  If
 * virFileWrapperFdClose() was not previously called, then this may
 * discard some previous I/O.  To avoid deadlock, only call this after
 * closing the fd resulting from virFileWrapperFdNew().
 */
void
virFileWrapperFdFree(virFileWrapperFdPtr wfd)
{
    if (!wfd)
        return;

    virCommandFree(wfd->cmd);
    VIR_FREE(wfd);
}


#ifndef WIN32
/**
 * virFileLock:
 * @fd: file descriptor to acquire the lock on
 * @shared: type of lock to acquire
 * @start: byte offset to start lock
 * @len: length of lock (0 to acquire entire remaining file from @start)
 *
 * Attempt to acquire a lock on the file @fd. If @shared
 * is true, then a shared lock will be acquired,
 * otherwise an exclusive lock will be acquired. If
 * the lock cannot be acquired, an error will be
 * returned. This will not wait to acquire the lock if
 * another process already holds it.
 *
 * The lock will be released when @fd is closed. The lock
 * will also be released if *any* other open file descriptor
 * pointing to the same underlying file is closed. As such
 * this function should not be relied on in multi-threaded
 * apps where other threads can be opening/closing arbitrary
 * files.
 *
 * Returns 0 on success, or -errno otherwise
 */
int virFileLock(int fd, bool shared, off_t start, off_t len)
{
    struct flock fl = {
        .l_type = shared ? F_RDLCK : F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };

    if (fcntl(fd, F_SETLK, &fl) < 0)
        return -errno;

    return 0;
}


/**
 * virFileUnlock:
 * @fd: file descriptor to release the lock on
 * @start: byte offset to start unlock
 * @len: length of lock (0 to release entire remaining file from @start)
 *
 * Release a lock previously acquired with virFileUnlock().
 * NB the lock will also be released if any open file descriptor
 * pointing to the same file as @fd is closed
 *
 * Returns 0 on succcess, or -errno on error
 */
int virFileUnlock(int fd, off_t start, off_t len)
{
    struct flock fl = {
        .l_type = F_UNLCK,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };

    if (fcntl(fd, F_SETLK, &fl) < 0)
        return -errno;

    return 0;
}
#else
int virFileLock(int fd ATTRIBUTE_UNUSED,
                bool shared ATTRIBUTE_UNUSED,
                off_t start ATTRIBUTE_UNUSED,
                off_t len ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
int virFileUnlock(int fd ATTRIBUTE_UNUSED,
                  off_t start ATTRIBUTE_UNUSED,
                  off_t len ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif

int
virFileRewrite(const char *path,
               mode_t mode,
               virFileRewriteFunc rewrite,
               void *opaque)
{
    char *newfile = NULL;
    int fd = -1;
    int ret = -1;

    if (virAsprintf(&newfile, "%s.new", path) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if ((fd = open(newfile, O_WRONLY | O_CREAT | O_TRUNC, mode)) < 0) {
        virReportSystemError(errno, _("cannot create file '%s'"),
                             newfile);
        goto cleanup;
    }

    if (rewrite(fd, opaque) < 0) {
        virReportSystemError(errno, _("cannot write data to file '%s'"),
                             newfile);
        goto cleanup;
    }

    if (fsync(fd) < 0) {
        virReportSystemError(errno, _("cannot sync file '%s'"),
                             newfile);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("cannot save file '%s'"),
                             newfile);
        goto cleanup;
    }

    if (rename(newfile, path) < 0) {
        virReportSystemError(errno, _("cannot rename file '%s' as '%s'"),
                             newfile, path);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    if (newfile) {
        unlink(newfile);
        VIR_FREE(newfile);
    }
    return ret;
}


int virFileTouch(const char *path, mode_t mode)
{
    int fd = -1;

    if ((fd = open(path, O_WRONLY | O_CREAT, mode)) < 0) {
        virReportSystemError(errno, _("cannot create file '%s'"),
                             path);
        return -1;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("cannot save file '%s'"),
                             path);
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    return 0;
}


#define MODE_BITS (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)

int virFileUpdatePerm(const char *path,
                      mode_t mode_remove,
                      mode_t mode_add)
{
    struct stat sb;
    mode_t mode;

    if (mode_remove & ~MODE_BITS || mode_add & ~MODE_BITS) {
        virReportError(VIR_ERR_INVALID_ARG, "%s", _("invalid mode"));
        return -1;
    }

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno, _("cannot stat '%s'"), path);
        return -1;
    }

    mode = sb.st_mode & MODE_BITS;

    if ((mode & mode_remove) == 0 && (mode & mode_add) == mode_add)
        return 0;

    mode &= MODE_BITS ^ mode_remove;
    mode |= mode_add;

    if (chmod(path, mode) < 0) {
        virReportSystemError(errno, _("cannot change permission of '%s'"),
                             path);
        return -1;
    }

    return 0;
}


#ifdef __linux__
static int virFileLoopDeviceOpen(char **dev_name)
{
    int fd = -1;
    DIR *dh = NULL;
    struct dirent *de;
    char *looppath;
    struct loop_info64 lo;

    VIR_DEBUG("Looking for loop devices in /dev");

    if (!(dh = opendir("/dev"))) {
        virReportSystemError(errno, "%s",
                             _("Unable to read /dev"));
        goto cleanup;
    }

    while ((de = readdir(dh)) != NULL) {
        if (!STRPREFIX(de->d_name, "loop"))
            continue;

        if (virAsprintf(&looppath, "/dev/%s", de->d_name) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        VIR_DEBUG("Checking up on device %s", looppath);
        if ((fd = open(looppath, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %s"), looppath);
            goto cleanup;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &lo) < 0) {
            /* Got a free device, return the fd */
            if (errno == ENXIO)
                goto cleanup;

            VIR_FORCE_CLOSE(fd);
            virReportSystemError(errno,
                                 _("Unable to get loop status on %s"),
                                 looppath);
            goto cleanup;
        }

        /* Oh well, try the next device */
        VIR_FORCE_CLOSE(fd);
        VIR_FREE(looppath);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Unable to find a free loop device in /dev"));

cleanup:
    if (fd != -1) {
        VIR_DEBUG("Got free loop device %s %d", looppath, fd);
        *dev_name = looppath;
    } else {
        VIR_DEBUG("No free loop devices available");
        VIR_FREE(looppath);
    }
    if (dh)
        closedir(dh);
    return fd;
}


int virFileLoopDeviceAssociate(const char *file,
                               char **dev)
{
    int lofd = -1;
    int fsfd = -1;
    struct loop_info64 lo;
    char *loname = NULL;
    int ret = -1;

    if ((lofd = virFileLoopDeviceOpen(&loname)) < 0)
        return -1;

    memset(&lo, 0, sizeof(lo));
    lo.lo_flags = LO_FLAGS_AUTOCLEAR;

    if ((fsfd = open(file, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %s"), file);
        goto cleanup;
    }

    if (ioctl(lofd, LOOP_SET_FD, fsfd) < 0) {
        virReportSystemError(errno,
                             _("Unable to attach %s to loop device"),
                             file);
        goto cleanup;
    }

    if (ioctl(lofd, LOOP_SET_STATUS64, &lo) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to mark loop device as autoclear"));

        if (ioctl(lofd, LOOP_CLR_FD, 0) < 0)
            VIR_WARN("Unable to detach %s from loop device", file);
        goto cleanup;
    }

    VIR_DEBUG("Attached loop device  %s %d to %s", file, lofd, loname);
    *dev = loname;
    loname = NULL;

    ret = 0;

cleanup:
    VIR_FREE(loname);
    VIR_FORCE_CLOSE(fsfd);
    if (ret == -1)
        VIR_FORCE_CLOSE(lofd);
    return lofd;
}

#else /* __linux__ */

int virFileLoopDeviceAssociate(const char *file,
                               char **dev)
{
    virReportSystemError(ENOSYS,
                         _("Unable to associate file %s with loop device"),
                         file);
    *dev = NULL;
    return -1;
}

#endif /* __linux__ */
