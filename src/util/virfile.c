/*
 * virfile.c: safer file handling
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>
#include "internal.h"

#include <passfd.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#if defined(HAVE_SYS_MOUNT_H)
# include <sys/mount.h>
#endif
#include <unistd.h>
#include <dirent.h>
#include <dirname.h>
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# include <mntent.h>
#endif
#include <stdlib.h>
#if HAVE_MMAP
# include <sys/mman.h>
#endif
#if HAVE_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#if HAVE_SYS_ACL_H
# include <sys/acl.h>
#endif

#ifdef __linux__
# if HAVE_LINUX_MAGIC_H
#  include <linux/magic.h>
# endif
# include <sys/statfs.h>
#endif

#if defined(__linux__) && HAVE_DECL_LO_FLAGS_AUTOCLEAR
# include <linux/loop.h>
# include <sys/ioctl.h>
#endif

#include "configmake.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virkmod.h"
#include "virlog.h"
#include "virprocess.h"
#include "virstring.h"
#include "virutil.h"

#include "c-ctype.h"
#include "areadlink.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.file");

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
    char *err_msg; /* stderr of @cmd */
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
    char *iohelper_path = NULL;

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

    if (VIR_ALLOC(ret) < 0)
        return NULL;

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

    if (!(iohelper_path = virFileFindResource("libvirt_iohelper",
                                              abs_topbuilddir "/src",
                                              LIBEXECDIR)))
        goto error;

    ret->cmd = virCommandNewArgList(iohelper_path, name, "0", NULL);

    VIR_FREE(iohelper_path);

    if (output) {
        virCommandSetInputFD(ret->cmd, pipefd[0]);
        virCommandSetOutputFD(ret->cmd, fd);
        virCommandAddArg(ret->cmd, "1");
    } else {
        virCommandSetInputFD(ret->cmd, *fd);
        virCommandSetOutputFD(ret->cmd, &pipefd[1]);
        virCommandAddArg(ret->cmd, "0");
    }

    /* In order to catch iohelper stderr, we must change
     * iohelper's env so virLog functions print to stderr
     */
    virCommandAddEnvPair(ret->cmd, "LIBVIRT_LOG_OUTPUTS", "1:stderr");
    virCommandSetErrorBuffer(ret->cmd, &ret->err_msg);
    virCommandDoAsyncIO(ret->cmd);

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
    VIR_FREE(iohelper_path);
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
    int ret;

    if (!wfd)
        return 0;

    ret = virCommandWait(wfd->cmd, NULL);
    if (wfd->err_msg && *wfd->err_msg)
        VIR_WARN("iohelper reports: %s", wfd->err_msg);

    return ret;
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

    VIR_FREE(wfd->err_msg);

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
 * @waitForLock: wait for previously held lock or not
 *
 * Attempt to acquire a lock on the file @fd. If @shared
 * is true, then a shared lock will be acquired,
 * otherwise an exclusive lock will be acquired. If
 * the lock cannot be acquired, an error will be
 * returned. If @waitForLock is true, this will wait
 * for the lock if another process has already acquired it.
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
int virFileLock(int fd, bool shared, off_t start, off_t len, bool waitForLock)
{
    struct flock fl = {
        .l_type = shared ? F_RDLCK : F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = start,
        .l_len = len,
    };

    int cmd = waitForLock ? F_SETLKW : F_SETLK;

    if (fcntl(fd, cmd, &fl) < 0)
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
 * Returns 0 on success, or -errno on error
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
                off_t len ATTRIBUTE_UNUSED,
                bool waitForLock ATTRIBUTE_UNUSED)
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
               const void *opaque)
{
    char *newfile = NULL;
    int fd = -1;
    int ret = -1;

    if (virAsprintf(&newfile, "%s.new", path) < 0)
        goto cleanup;

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


static int
virFileRewriteStrHelper(int fd, const void *opaque)
{
    const char *data = opaque;

    if (safewrite(fd, data, strlen(data)) < 0)
        return -1;

    return 0;
}


int
virFileRewriteStr(const char *path,
                  mode_t mode,
                  const char *str)
{
    return virFileRewrite(path, mode,
                          virFileRewriteStrHelper, str);
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


#if defined(__linux__) && HAVE_DECL_LO_FLAGS_AUTOCLEAR && \
    !defined(LIBVIRT_SETUID_RPC_CLIENT) && !defined(LIBVIRT_NSS)

# if HAVE_DECL_LOOP_CTL_GET_FREE

/* virFileLoopDeviceOpenLoopCtl() returns -1 when a real failure has occurred
 * while in the process of allocating or opening the loop device.  On success
 * we return 0 and modify the fd to the appropriate file descriptor.
 * If /dev/loop-control does not exist, we return 0 and do not set fd. */

static int virFileLoopDeviceOpenLoopCtl(char **dev_name, int *fd)
{
    int devnr;
    int ctl_fd;
    char *looppath = NULL;

    VIR_DEBUG("Opening loop-control device");
    if ((ctl_fd = open("/dev/loop-control", O_RDWR)) < 0) {
        if (errno == ENOENT)
            return 0;

        virReportSystemError(errno, "%s",
                             _("Unable to open /dev/loop-control"));
        return -1;
    }

    if ((devnr = ioctl(ctl_fd, LOOP_CTL_GET_FREE)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get free loop device via ioctl"));
        close(ctl_fd);
        return -1;
    }
    close(ctl_fd);

    VIR_DEBUG("Found free loop device number %i", devnr);

    if (virAsprintf(&looppath, "/dev/loop%i", devnr) < 0)
        return -1;

    if ((*fd = open(looppath, O_RDWR)) < 0) {
        virReportSystemError(errno,
                _("Unable to open %s"), looppath);
        VIR_FREE(looppath);
        return -1;
    }

    *dev_name = looppath;
    return 0;
}
# endif /* HAVE_DECL_LOOP_CTL_GET_FREE */

static int virFileLoopDeviceOpenSearch(char **dev_name)
{
    int fd = -1;
    DIR *dh = NULL;
    struct dirent *de;
    char *looppath = NULL;
    struct loop_info64 lo;
    int direrr;

    VIR_DEBUG("Looking for loop devices in /dev");

    if (virDirOpen(&dh, "/dev") < 0)
        goto cleanup;

    while ((direrr = virDirRead(dh, &de, "/dev")) > 0) {
        /* Checking 'loop' prefix is insufficient, since
         * new kernels have a dev named 'loop-control'
         */
        if (!STRPREFIX(de->d_name, "loop") ||
            !c_isdigit(de->d_name[4]))
            continue;

        if (virAsprintf(&looppath, "/dev/%s", de->d_name) < 0)
            goto cleanup;

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
    if (direrr < 0)
        goto cleanup;
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
    VIR_DIR_CLOSE(dh);
    return fd;
}

static int virFileLoopDeviceOpen(char **dev_name)
{
    int loop_fd = -1;

# if HAVE_DECL_LOOP_CTL_GET_FREE
    if (virFileLoopDeviceOpenLoopCtl(dev_name, &loop_fd) < 0)
        return -1;

    VIR_DEBUG("Return from loop-control got fd %d", loop_fd);

    if (loop_fd >= 0)
        return loop_fd;
# endif /* HAVE_DECL_LOOP_CTL_GET_FREE */

    /* Without the loop control device we just use the old technique. */
    loop_fd = virFileLoopDeviceOpenSearch(dev_name);

    return loop_fd;
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


# define SYSFS_BLOCK_DIR "/sys/block"
# define NBD_DRIVER "nbd"


static int
virFileNBDDeviceIsBusy(const char *dev_name)
{
    char *path;
    int ret = -1;

    if (virAsprintf(&path, SYSFS_BLOCK_DIR "/%s/pid",
                    dev_name) < 0)
        return -1;

    if (!virFileExists(path)) {
        if (errno == ENOENT)
            ret = 0;
        else
            virReportSystemError(errno,
                                 _("Cannot check NBD device %s pid"),
                                 dev_name);
        goto cleanup;
    }
    ret = 1;

 cleanup:
    VIR_FREE(path);
    return ret;
}


static char *
virFileNBDDeviceFindUnused(void)
{
    DIR *dh;
    char *ret = NULL;
    struct dirent *de;
    int direrr;

    if (virDirOpen(&dh, SYSFS_BLOCK_DIR) < 0)
        return NULL;

    while ((direrr = virDirRead(dh, &de, SYSFS_BLOCK_DIR)) > 0) {
        if (STRPREFIX(de->d_name, "nbd")) {
            int rv = virFileNBDDeviceIsBusy(de->d_name);
            if (rv < 0)
                goto cleanup;
            if (rv == 0) {
                ignore_value(virAsprintf(&ret, "/dev/%s", de->d_name));
                goto cleanup;
            }
        }
    }
    if (direrr < 0)
        goto cleanup;
    virReportSystemError(EBUSY, "%s",
                         _("No free NBD devices"));

 cleanup:
    VIR_DIR_CLOSE(dh);
    return ret;
}

static bool
virFileNBDLoadDriver(void)
{
    if (virKModIsBlacklisted(NBD_DRIVER)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to load nbd module: "
                         "administratively prohibited"));
        return false;
    } else {
        char *errbuf = NULL;

        if ((errbuf = virKModLoad(NBD_DRIVER, true))) {
            VIR_FREE(errbuf);
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to load nbd module"));
            return false;
        }
        VIR_FREE(errbuf);
    }
    return true;
}

int virFileNBDDeviceAssociate(const char *file,
                              virStorageFileFormat fmt,
                              bool readonly,
                              char **dev)
{
    char *nbddev = NULL;
    char *qemunbd = NULL;
    virCommandPtr cmd = NULL;
    int ret = -1;
    const char *fmtstr = NULL;

    if (!virFileNBDLoadDriver())
        goto cleanup;

    if (!(nbddev = virFileNBDDeviceFindUnused()))
        goto cleanup;

    if (!(qemunbd = virFindFileInPath("qemu-nbd"))) {
        virReportSystemError(ENOENT, "%s",
                             _("Unable to find 'qemu-nbd' binary in $PATH"));
        goto cleanup;
    }

    if (fmt > 0)
        fmtstr = virStorageFileFormatTypeToString(fmt);

    cmd = virCommandNew(qemunbd);

    /* Explicitly not trying to cope with old qemu-nbd which
     * lacked --format. We want to see a fatal error in that
     * case since it would be security flaw to continue */
    if (fmtstr)
        virCommandAddArgList(cmd, "--format", fmtstr, NULL);

    if (readonly)
        virCommandAddArg(cmd, "-r");

    virCommandAddArgList(cmd,
                         "-n", /* Don't cache in qemu-nbd layer */
                         "-c", nbddev,
                         file, NULL);

    /* qemu-nbd will daemonize itself */

    if (virCommandRun(cmd, NULL) < 0)
        goto cleanup;

    VIR_DEBUG("Associated NBD device %s with file %s and format %s",
              nbddev, file, fmtstr);
    *dev = nbddev;
    nbddev = NULL;
    ret = 0;

 cleanup:
    VIR_FREE(nbddev);
    VIR_FREE(qemunbd);
    virCommandFree(cmd);
    return ret;
}

#else /* __linux__ */

int virFileLoopDeviceAssociate(const char *file,
                               char **dev ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to associate file %s with loop device"),
                         file);
    *dev = NULL;
    return -1;
}

int virFileNBDDeviceAssociate(const char *file,
                              virStorageFileFormat fmt ATTRIBUTE_UNUSED,
                              bool readonly ATTRIBUTE_UNUSED,
                              char **dev ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to associate file %s with NBD device"),
                         file);
    return -1;
}

#endif /* __linux__ */


/**
 * virFileDeleteTree:
 *
 * Recursively deletes all files / directories
 * starting from the directory @dir. Does not
 * follow symlinks
 *
 * NB the algorithm is not efficient, and is subject to
 * race conditions which can be exploited by malicious
 * code. It should not be used in any scenarios where
 * performance is important, or security is critical.
 */
int virFileDeleteTree(const char *dir)
{
    DIR *dh;
    struct dirent *de;
    char *filepath = NULL;
    int ret = -1;
    int direrr;

    /* Silently return 0 if passed NULL or directory doesn't exist */
    if (!dir || !virFileExists(dir))
        return 0;

    if (virDirOpen(&dh, dir) < 0)
        return -1;

    while ((direrr = virDirRead(dh, &de, dir)) > 0) {
        struct stat sb;

        if (virAsprintf(&filepath, "%s/%s",
                        dir, de->d_name) < 0)
            goto cleanup;

        if (lstat(filepath, &sb) < 0) {
            virReportSystemError(errno, _("Cannot access '%s'"),
                                 filepath);
            goto cleanup;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (virFileDeleteTree(filepath) < 0)
                goto cleanup;
        } else {
            if (unlink(filepath) < 0 && errno != ENOENT) {
                virReportSystemError(errno,
                                     _("Cannot delete file '%s'"),
                                     filepath);
                goto cleanup;
            }
        }

        VIR_FREE(filepath);
    }
    if (direrr < 0)
        goto cleanup;

    if (rmdir(dir) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot delete directory '%s'"),
                             dir);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(filepath);
    VIR_DIR_CLOSE(dh);
    return ret;
}

int
virFileStripSuffix(char *str, const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return 0;

    if (STRNEQ(str + len - suffixlen, suffix))
        return 0;

    str[len-suffixlen] = '\0';

    return 1;
}


/* Like read(), but restarts after EINTR.  Doesn't play
 * nicely with nonblocking FD and EAGAIN, in which case
 * you want to use bare read(). Or even use virSocket()
 * if the FD is related to a socket rather than a plain
 * file or pipe. */
ssize_t
saferead(int fd, void *buf, size_t count)
{
    size_t nread = 0;
    while (count > 0) {
        ssize_t r = read(fd, buf, count);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return r;
        if (r == 0)
            return nread;
        buf = (char *)buf + r;
        count -= r;
        nread += r;
    }
    return nread;
}

/* Like write(), but restarts after EINTR. Doesn't play
 * nicely with nonblocking FD and EAGAIN, in which case
 * you want to use bare write(). Or even use virSocket()
 * if the FD is related to a socket rather than a plain
 * file or pipe. */
ssize_t
safewrite(int fd, const void *buf, size_t count)
{
    size_t nwritten = 0;
    while (count > 0) {
        ssize_t r = write(fd, buf, count);

        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return r;
        if (r == 0)
            return nwritten;
        buf = (const char *)buf + r;
        count -= r;
        nwritten += r;
    }
    return nwritten;
}

#ifdef HAVE_POSIX_FALLOCATE
static int
safezero_posix_fallocate(int fd, off_t offset, off_t len)
{
    int ret = posix_fallocate(fd, offset, len);
    if (ret == 0)
        return 0;
    errno = ret;
    return -1;
}
#else /* !HAVE_POSIX_FALLOCATE */
static int
safezero_posix_fallocate(int fd ATTRIBUTE_UNUSED,
                         off_t offset ATTRIBUTE_UNUSED,
                         off_t len ATTRIBUTE_UNUSED)
{
    return -2;
}
#endif /* !HAVE_POSIX_FALLOCATE */

#if HAVE_SYS_SYSCALL_H && defined(SYS_fallocate)
static int
safezero_sys_fallocate(int fd,
                       off_t offset,
                       off_t len)
{
    return syscall(SYS_fallocate, fd, 0, offset, len);
}
#else /* !HAVE_SYS_SYSCALL_H || !defined(SYS_fallocate) */
static int
safezero_sys_fallocate(int fd ATTRIBUTE_UNUSED,
                       off_t offset ATTRIBUTE_UNUSED,
                       off_t len ATTRIBUTE_UNUSED)
{
    return -2;
}
#endif /* !HAVE_SYS_SYSCALL_H || !defined(SYS_fallocate) */

#ifdef HAVE_MMAP
static int
safezero_mmap(int fd, off_t offset, off_t len)
{
    int r;
    char *buf;
    static long pagemask;
    off_t map_skip;

    /* align offset and length, rounding offset down and length up */
    if (pagemask == 0)
        pagemask = ~(virGetSystemPageSize() - 1);
    map_skip = offset - (offset & pagemask);

    /* memset wants the mmap'ed file to be present on disk so create a
     * sparse file
     */
    r = ftruncate(fd, offset + len);
    if (r < 0)
        return -1;

    buf = mmap(NULL, len + map_skip, PROT_READ | PROT_WRITE, MAP_SHARED,
               fd, offset - map_skip);
    if (buf != MAP_FAILED) {
        memset(buf + map_skip, 0, len);
        munmap(buf, len + map_skip);

        return 0;
    }

    /* fall back to writing zeroes using safewrite if mmap fails (for
     * example because of virtual memory limits) */
    return -2;
}
#else /* !HAVE_MMAP */
static int
safezero_mmap(int fd ATTRIBUTE_UNUSED,
              off_t offset ATTRIBUTE_UNUSED,
              off_t len ATTRIBUTE_UNUSED)
{
    return -2;
}
#endif /* !HAVE_MMAP */

static int
safezero_slow(int fd, off_t offset, off_t len)
{
    int r;
    char *buf;
    unsigned long long remain, bytes;

    if (lseek(fd, offset, SEEK_SET) < 0)
        return -1;

    /* Split up the write in small chunks so as not to allocate lots of RAM */
    remain = len;
    bytes = MIN(1024 * 1024, len);

    r = VIR_ALLOC_N(buf, bytes);
    if (r < 0) {
        errno = ENOMEM;
        return -1;
    }

    while (remain) {
        if (bytes > remain)
            bytes = remain;

        r = safewrite(fd, buf, bytes);
        if (r < 0) {
            VIR_FREE(buf);
            return -1;
        }

        /* safewrite() guarantees all data will be written */
        remain -= bytes;
    }
    VIR_FREE(buf);
    return 0;
}

int safezero(int fd, off_t offset, off_t len)
{
    int ret;

    ret = safezero_posix_fallocate(fd, offset, len);
    if (ret != -2)
        return ret;

    if (safezero_sys_fallocate(fd, offset, len) == 0)
        return 0;

    ret = safezero_mmap(fd, offset, len);
    if (ret != -2)
        return ret;
    return safezero_slow(fd, offset, len);
}

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
/* search /proc/mounts for mount point of *type; return pointer to
 * malloc'ed string of the path if found, otherwise return NULL
 * with errno set to an appropriate value.
 */
char *
virFileFindMountPoint(const char *type)
{
    FILE *f;
    struct mntent mb;
    char mntbuf[1024];
    char *ret = NULL;

    f = setmntent("/proc/mounts", "r");
    if (!f)
        return NULL;

    while (getmntent_r(f, &mb, mntbuf, sizeof(mntbuf))) {
        if (STREQ(mb.mnt_type, type)) {
            ignore_value(VIR_STRDUP_QUIET(ret, mb.mnt_dir));
            goto cleanup;
        }
    }

    if (!ret)
        errno = ENOENT;

 cleanup:
    endmntent(f);

    return ret;
}

#else /* defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

char *
virFileFindMountPoint(const char *type ATTRIBUTE_UNUSED)
{
    errno = ENOSYS;

    return NULL;
}

#endif /* defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

int
virBuildPathInternal(char **path, ...)
{
    char *path_component = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    va_list ap;
    int ret = 0;

    va_start(ap, path);

    path_component = va_arg(ap, char *);
    virBufferAdd(&buf, path_component, -1);

    while ((path_component = va_arg(ap, char *)) != NULL) {
        virBufferAddChar(&buf, '/');
        virBufferAdd(&buf, path_component, -1);
    }

    va_end(ap);

    *path = virBufferContentAndReset(&buf);
    if (*path == NULL)
        ret = -1;

    return ret;
}

/* Like gnulib's fread_file, but read no more than the specified maximum
   number of bytes.  If the length of the input is <= max_len, and
   upon error while reading that data, it works just like fread_file.  */
static char *
saferead_lim(int fd, size_t max_len, size_t *length)
{
    char *buf = NULL;
    size_t alloc = 0;
    size_t size = 0;
    int save_errno;

    for (;;) {
        int count;
        int requested;

        if (size + BUFSIZ + 1 > alloc) {
            alloc += alloc / 2;
            if (alloc < size + BUFSIZ + 1)
                alloc = size + BUFSIZ + 1;

            if (VIR_REALLOC_N(buf, alloc) < 0) {
                save_errno = errno;
                break;
            }
        }

        /* Ensure that (size + requested <= max_len); */
        requested = MIN(size < max_len ? max_len - size : 0,
                        alloc - size - 1);
        count = saferead(fd, buf + size, requested);
        size += count;

        if (count != requested || requested == 0) {
            save_errno = errno;
            if (count < 0)
                break;
            buf[size] = '\0';
            *length = size;
            return buf;
        }
    }

    VIR_FREE(buf);
    errno = save_errno;
    return NULL;
}


/* A wrapper around saferead_lim that merely stops reading at the
 * specified maximum size.  */
int
virFileReadHeaderFD(int fd, int maxlen, char **buf)
{
    size_t len;
    char *s;

    if (maxlen <= 0) {
        errno = EINVAL;
        return -1;
    }
    s = saferead_lim(fd, maxlen, &len);
    if (s == NULL)
        return -1;
    *buf = s;
    return len;
}


/* A wrapper around saferead_lim that maps a failure due to
   exceeding the maximum size limitation to EOVERFLOW.  */
int
virFileReadLimFD(int fd, int maxlen, char **buf)
{
    size_t len;
    char *s;

    if (maxlen <= 0) {
        errno = EINVAL;
        return -1;
    }
    s = saferead_lim(fd, maxlen+1, &len);
    if (s == NULL)
        return -1;
    if (len > maxlen || (int)len != len) {
        VIR_FREE(s);
        /* There was at least one byte more than MAXLEN.
           Set errno accordingly. */
        errno = EOVERFLOW;
        return -1;
    }
    *buf = s;
    return len;
}

int
virFileReadAll(const char *path, int maxlen, char **buf)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno, _("Failed to open file '%s'"), path);
        return -1;
    }

    int len = virFileReadLimFD(fd, maxlen, buf);
    VIR_FORCE_CLOSE(fd);
    if (len < 0) {
        virReportSystemError(errno, _("Failed to read file '%s'"), path);
        return -1;
    }

    return len;
}

int
virFileReadAllQuiet(const char *path, int maxlen, char **buf)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -errno;

    int len = virFileReadLimFD(fd, maxlen, buf);
    VIR_FORCE_CLOSE(fd);
    if (len < 0)
        return -errno;

    return len;
}

/* Read @file into preallocated buffer @buf of size @len.
 * Return value is -errno in case of errors and size
 * of data read (no trailing zero) in case of success.
 * If there is more data then @len - 1 then data will be
 * truncated. */
int
virFileReadBufQuiet(const char *file, char *buf, int len)
{
    int fd;
    ssize_t sz;

    fd = open(file, O_RDONLY);
    if (fd < 0)
        return -errno;

    sz = saferead(fd, buf, len - 1);
    VIR_FORCE_CLOSE(fd);
    if (sz < 0)
        return -errno;

    buf[sz] = '\0';
    return sz;
}

/* Truncate @path and write @str to it.  If @mode is 0, ensure that
   @path exists; otherwise, use @mode if @path must be created.
   Return 0 for success, nonzero for failure.
   Be careful to preserve any errno value upon failure. */
int
virFileWriteStr(const char *path, const char *str, mode_t mode)
{
    int fd;

    if (mode)
        fd = open(path, O_WRONLY|O_TRUNC|O_CREAT, mode);
    else
        fd = open(path, O_WRONLY|O_TRUNC);
    if (fd == -1)
        return -1;

    if (safewrite(fd, str, strlen(str)) < 0) {
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    /* Use errno from failed close only if there was no write error.  */
    if (VIR_CLOSE(fd) != 0)
        return -1;

    return 0;
}

int
virFileMatchesNameSuffix(const char *file,
                         const char *name,
                         const char *suffix)
{
    int filelen = strlen(file);
    int namelen = strlen(name);
    int suffixlen = strlen(suffix);

    if (filelen == (namelen + suffixlen) &&
        STREQLEN(file, name, namelen) &&
        STREQLEN(file + namelen, suffix, suffixlen))
        return 1;
    else
        return 0;
}

int
virFileHasSuffix(const char *str,
                 const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return 0;

    return STRCASEEQ(str + len - suffixlen, suffix);
}

#define SAME_INODE(Stat_buf_1, Stat_buf_2) \
  ((Stat_buf_1).st_ino == (Stat_buf_2).st_ino \
   && (Stat_buf_1).st_dev == (Stat_buf_2).st_dev)

/* Return nonzero if checkLink and checkDest
 * refer to the same file.  Otherwise, return 0.
 */
int
virFileLinkPointsTo(const char *checkLink,
                    const char *checkDest)
{
    struct stat src_sb;
    struct stat dest_sb;

    return (stat(checkLink, &src_sb) == 0
            && stat(checkDest, &dest_sb) == 0
            && SAME_INODE(src_sb, dest_sb));
}


/* Return positive if checkLink (residing within directory if not
 * absolute) and checkDest refer to the same file.  Otherwise, return
 * -1 on allocation failure (error reported), or 0 if not the same
 * (silent).
 */
int
virFileRelLinkPointsTo(const char *directory,
                       const char *checkLink,
                       const char *checkDest)
{
    char *candidate;
    int ret;

    if (*checkLink == '/')
        return virFileLinkPointsTo(checkLink, checkDest);
    if (!directory) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot resolve '%s' without starting directory"),
                       checkLink);
        return -1;
    }
    if (virAsprintf(&candidate, "%s/%s", directory, checkLink) < 0)
        return -1;
    ret = virFileLinkPointsTo(candidate, checkDest);
    VIR_FREE(candidate);
    return ret;
}


static int
virFileResolveLinkHelper(const char *linkpath,
                         bool intermediatePaths,
                         char **resultpath)
{
    struct stat st;

    *resultpath = NULL;

    /* We don't need the full canonicalization of intermediate
     * directories, if linkpath is absolute and the basename is
     * already a non-symlink.  */
    if (IS_ABSOLUTE_FILE_NAME(linkpath) && !intermediatePaths) {
        if (lstat(linkpath, &st) < 0)
            return -1;

        if (!S_ISLNK(st.st_mode))
            return VIR_STRDUP_QUIET(*resultpath, linkpath) < 0 ? -1 : 0;
    }

    *resultpath = canonicalize_file_name(linkpath);

    return *resultpath == NULL ? -1 : 0;
}

/*
 * Attempt to resolve a symbolic link, returning an
 * absolute path where only the last component is guaranteed
 * not to be a symlink.
 *
 * Return 0 if path was not a symbolic, or the link was
 * resolved. Return -1 with errno set upon error
 */
int
virFileResolveLink(const char *linkpath, char **resultpath)
{
    return virFileResolveLinkHelper(linkpath, false, resultpath);
}

/*
 * Attempt to resolve a symbolic link, returning an
 * absolute path where every component is guaranteed
 * not to be a symlink.
 *
 * Return 0 if path was not a symbolic, or the link was
 * resolved. Return -1 with errno set upon error
 */
int
virFileResolveAllLinks(const char *linkpath, char **resultpath)
{
    return virFileResolveLinkHelper(linkpath, true, resultpath);
}

/*
 * Check whether the given file is a link.
 * Returns 1 in case of the file being a link, 0 in case it is not
 * a link and the negative errno in all other cases.
 */
int
virFileIsLink(const char *linkpath)
{
    struct stat st;

    if (lstat(linkpath, &st) < 0)
        return -errno;

    return S_ISLNK(st.st_mode) != 0;
}

/*
 * Read where symlink is pointing to.
 *
 * Returns 0 on success (@linkpath is a successfully read link),
 *        -1 with errno set upon error.
 */
int
virFileReadLink(const char *linkpath, char **resultpath)
{
    return (*resultpath = areadlink(linkpath)) ? 0 : -1;
}

/*
 * Finds a requested executable file in the PATH env. e.g.:
 * "qemu-img" will return "/usr/bin/qemu-img"
 *
 * You must free the result
 */
char *
virFindFileInPath(const char *file)
{
    const char *origpath = NULL;
    char *path = NULL;
    char *pathiter;
    char *pathseg;
    char *fullpath = NULL;

    if (file == NULL)
        return NULL;

    /* if we are passed an absolute path (starting with /), return a
     * copy of that path, after validating that it is executable
     */
    if (IS_ABSOLUTE_FILE_NAME(file)) {
        char *ret = NULL;
        if (virFileIsExecutable(file))
            ignore_value(VIR_STRDUP_QUIET(ret, file));
        return ret;
    }

    /* If we are passed an anchored path (containing a /), then there
     * is no path search - it must exist in the current directory
     */
    if (strchr(file, '/')) {
        if (virFileIsExecutable(file))
            ignore_value(virFileAbsPath(file, &path));
        return path;
    }

    /* copy PATH env so we can tweak it */
    origpath = virGetEnvBlockSUID("PATH");
    if (!origpath)
        origpath = "/bin:/usr/bin";

    if (VIR_STRDUP_QUIET(path, origpath) <= 0)
        return NULL;

    /* for each path segment, append the file to search for and test for
     * it. return it if found.
     */
    pathiter = path;
    while ((pathseg = strsep(&pathiter, ":")) != NULL) {
        if (virAsprintf(&fullpath, "%s/%s", pathseg, file) < 0 ||
            virFileIsExecutable(fullpath))
            break;
        VIR_FREE(fullpath);
    }

    VIR_FREE(path);
    return fullpath;
}


static bool useDirOverride;

/**
 * virFileFindResourceFull:
 * @filename: libvirt distributed filename without any path
 * @prefix: optional string to prepend to filename
 * @suffix: optional string to append to filename
 * @builddir: location of the filename in the build tree including
 *            abs_topsrcdir or abs_topbuilddir prefix
 * @installdir: location of the installed binary
 * @envname: environment variable used to override all dirs
 *
 * A helper which will return a path to @filename within
 * the current build tree, if the calling binary is being
 * run from the source tree. Otherwise it will return the
 * path in the installed location.
 *
 * If @envname is non-NULL it will override all other
 * directory lookup.
 *
 * Only use this with @filename files that are part of
 * the libvirt tree, not 3rd party binaries/files.
 *
 * Returns the resolved path (caller frees) or NULL on error
 */
char *
virFileFindResourceFull(const char *filename,
                        const char *prefix,
                        const char *suffix,
                        const char *builddir,
                        const char *installdir,
                        const char *envname)
{
    char *ret = NULL;
    const char *envval = envname ? virGetEnvBlockSUID(envname) : NULL;
    const char *path;

    if (!prefix)
        prefix = "";
    if (!suffix)
        suffix = "";

    if (envval)
        path = envval;
    else if (useDirOverride)
        path = builddir;
    else
        path = installdir;

    if (virAsprintf(&ret, "%s/%s%s%s", path, prefix, filename, suffix) < 0)
        return NULL;

    VIR_DEBUG("Resolved '%s' to '%s'", filename, ret);
    return ret;
}

char *
virFileFindResource(const char *filename,
                    const char *builddir,
                    const char *installdir)
{
    return virFileFindResourceFull(filename, NULL, NULL, builddir, installdir, NULL);
}


/**
 * virFileActivateDirOverride:
 * @argv0: argv[0] of the calling program
 *
 * Look at @argv0 and try to detect if running from
 * a build directory, by looking for a 'lt-' prefix
 * on the binary name, or '/.libs/' in the path
 */
void
virFileActivateDirOverride(const char *argv0)
{
    char *file = strrchr(argv0, '/');
    if (!file || file[1] == '\0')
        return;
    file++;
    if (STRPREFIX(file, "lt-") ||
        strstr(argv0, "/.libs/")) {
        useDirOverride = true;
        VIR_DEBUG("Activating build dir override for %s", argv0);
    }
}


/**
 * virFileLength:
 * @path: full path of the file
 * @fd: open file descriptor for file (or -1 to use @path)
 *
 * If fd >= 0, return the length of the open file indicated by @fd.
 * If fd < 0 (i.e. -1) return the length of the file indicated by
 * @path.
 *
 * Returns the length, or -1 if the file doesn't
 * exist or its info was inaccessible. No error is logged.
 */
off_t
virFileLength(const char *path, int fd)
{
    struct stat s;

    if (fd >= 0) {
        if (fstat(fd, &s) < 0)
            return -1;
    } else {
        if (stat(path, &s) < 0)
            return -1;
    }

    if (!S_ISREG(s.st_mode))
       return -1;

    return s.st_size;

}


bool
virFileIsDir(const char *path)
{
    struct stat s;
    return (stat(path, &s) == 0) && S_ISDIR(s.st_mode);
}

/**
 * virFileExists: Check for presence of file
 * @path: Path of file to check
 *
 * Returns if the file exists. Preserves errno in case it does not exist.
 */
bool
virFileExists(const char *path)
{
    return access(path, F_OK) == 0;
}

/* Check that a file is regular and has executable bits.  If false is
 * returned, errno is valid.
 *
 * Note: In the presence of ACLs, this may return true for a file that
 * would actually fail with EACCES for a given user, or false for a
 * file that the user could actually execute, but setups with ACLs
 * that weird are unusual. */
bool
virFileIsExecutable(const char *file)
{
    struct stat sb;

    /* We would also want to check faccessat if we cared about ACLs,
     * but we don't.  */
    if (stat(file, &sb) < 0)
        return false;
    if (S_ISREG(sb.st_mode) && (sb.st_mode & 0111) != 0)
        return true;
    errno = S_ISDIR(sb.st_mode) ? EISDIR : EACCES;
    return false;
}


/*
 * Check that a file refers to a mount point. Trick is that for
 * a mount point, the st_dev field will differ from the parent
 * directory.
 *
 * Note that this will not detect bind mounts of dirs/files,
 * only true filesystem mounts.
 */
int virFileIsMountPoint(const char *file)
{
    char *parent = NULL;
    int ret = -1;
    struct stat sb1, sb2;

    if (!(parent = mdir_name(file))) {
        virReportOOMError();
        goto cleanup;
    }

    VIR_DEBUG("Comparing '%s' to '%s'", file, parent);

    if (stat(file, &sb1) < 0) {
        if (errno == ENOENT)
            ret = 0;
        else
            virReportSystemError(errno,
                                 _("Cannot stat '%s'"),
                                 file);
        goto cleanup;
    }

    if (stat(parent, &sb2) < 0) {
        virReportSystemError(errno,
                             _("Cannot stat '%s'"),
                             parent);
        goto cleanup;
    }

    if (!S_ISDIR(sb1.st_mode)) {
        ret = 0;
        goto cleanup;
    }

    ret = sb1.st_dev != sb2.st_dev;
    VIR_DEBUG("Is mount %d", ret);

 cleanup:
    VIR_FREE(parent);
    return ret;
}


#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int
virFileGetMountSubtreeImpl(const char *mtabpath,
                           const char *prefix,
                           char ***mountsret,
                           size_t *nmountsret,
                           bool reverse)
{
    FILE *procmnt;
    struct mntent mntent;
    char mntbuf[1024];
    int ret = -1;
    char **mounts = NULL;
    size_t nmounts = 0;

    VIR_DEBUG("prefix=%s", prefix);

    *mountsret = NULL;
    *nmountsret = 0;

    if (!(procmnt = setmntent(mtabpath, "r"))) {
        virReportSystemError(errno,
                             _("Failed to read %s"), mtabpath);
        return -1;
    }

    while (getmntent_r(procmnt, &mntent, mntbuf, sizeof(mntbuf)) != NULL) {
        if (!(STREQ(mntent.mnt_dir, prefix) ||
              (STRPREFIX(mntent.mnt_dir, prefix) &&
               mntent.mnt_dir[strlen(prefix)] == '/')))
            continue;

        if (VIR_EXPAND_N(mounts, nmounts, nmounts ? 1 : 2) < 0)
            goto cleanup;
        if (VIR_STRDUP(mounts[nmounts - 2], mntent.mnt_dir) < 0)
            goto cleanup;
    }

    if (mounts)
        qsort(mounts, nmounts - 1, sizeof(mounts[0]),
              reverse ? virStringSortRevCompare : virStringSortCompare);

    *mountsret = mounts;
    *nmountsret = nmounts ? nmounts - 1 : 0;
    ret = 0;

 cleanup:
    if (ret < 0)
        virStringListFree(mounts);
    endmntent(procmnt);
    return ret;
}
#else /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */
static int
virFileGetMountSubtreeImpl(const char *mtabpath ATTRIBUTE_UNUSED,
                           const char *prefix ATTRIBUTE_UNUSED,
                           char ***mountsret ATTRIBUTE_UNUSED,
                           size_t *nmountsret ATTRIBUTE_UNUSED,
                           bool reverse ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to determine mount table on this platform"));
    return -1;
}
#endif /* ! defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R */

/**
 * virFileGetMountSubtree:
 * @mtabpath: mount file to parser (eg /proc/mounts)
 * @prefix: mount path prefix to match
 * @mountsret: allocated and filled with matching mounts
 * @nmountsret: filled with number of matching mounts, not counting NULL terminator
 *
 * Return the list of mounts from @mtabpath which contain
 * the path @prefix, sorted alphabetically.
 *
 * The @mountsret array will be NULL terminated and should
 * be freed with virStringListFree
 *
 * Returns 0 on success, -1 on error
 */
int virFileGetMountSubtree(const char *mtabpath,
                           const char *prefix,
                           char ***mountsret,
                           size_t *nmountsret)
{
    return virFileGetMountSubtreeImpl(mtabpath, prefix, mountsret, nmountsret, false);
}

/**
 * virFileGetMountReverseSubtree:
 * @mtabpath: mount file to parser (eg /proc/mounts)
 * @prefix: mount path prefix to match
 * @mountsret: allocated and filled with matching mounts
 * @nmountsret: filled with number of matching mounts, not counting NULL terminator
 *
 * Return the list of mounts from @mtabpath which contain
 * the path @prefix, reverse-sorted alphabetically.
 *
 * The @mountsret array will be NULL terminated and should
 * be freed with virStringListFree
 *
 * Returns 0 on success, -1 on error
 */
int virFileGetMountReverseSubtree(const char *mtabpath,
                                  const char *prefix,
                                  char ***mountsret,
                                  size_t *nmountsret)
{
    return virFileGetMountSubtreeImpl(mtabpath, prefix, mountsret, nmountsret, true);
}

#ifndef WIN32
/* Check that a file is accessible under certain
 * user & gid.
 * @mode can be F_OK, or a bitwise combination of R_OK, W_OK, and X_OK.
 * see 'man access' for more details.
 * Returns 0 on success, -1 on fail with errno set.
 */
int
virFileAccessibleAs(const char *path, int mode,
                    uid_t uid, gid_t gid)
{
    pid_t pid = 0;
    int status, ret = 0;
    int forkRet = 0;
    gid_t *groups;
    int ngroups;

    if (uid == geteuid() &&
        gid == getegid())
        return access(path, mode);

    ngroups = virGetGroupList(uid, gid, &groups);
    if (ngroups < 0)
        return -1;

    pid = virFork();

    if (pid < 0) {
        VIR_FREE(groups);
        return -1;
    }

    if (pid) { /* parent */
        VIR_FREE(groups);
        if (virProcessWait(pid, &status, false) < 0) {
            /* virProcessWait() already reported error */
            errno = EINTR;
            return -1;
        }

        if (status) {
            errno = status;
            return -1;
        }

        return 0;
    }

    /* child.
     * Return positive value here. Parent
     * will change it to negative one. */

    if (forkRet < 0) {
        ret = errno;
        goto childerror;
    }

    if (virSetUIDGID(uid, gid, groups, ngroups) < 0) {
        ret = errno;
        goto childerror;
    }

    if (access(path, mode) < 0)
        ret = errno;

 childerror:
    if ((ret & 0xFF) != ret) {
        VIR_WARN("unable to pass desired return value %d", ret);
        ret = 0xFF;
    }

    _exit(ret);
}

/* virFileOpenForceOwnerMode() - an internal utility function called
 * only by virFileOpenAs().  Sets the owner and mode of the file
 * opened as "fd" if it's not correct AND the flags say it should be
 * forced. */
static int
virFileOpenForceOwnerMode(const char *path, int fd, mode_t mode,
                          uid_t uid, gid_t gid, unsigned int flags)
{
    int ret = 0;
    struct stat st;

    if (!(flags & (VIR_FILE_OPEN_FORCE_OWNER | VIR_FILE_OPEN_FORCE_MODE)))
        return 0;

    if (fstat(fd, &st) == -1) {
        ret = -errno;
        virReportSystemError(errno, _("stat of '%s' failed"), path);
        return ret;
    }
    /* NB: uid:gid are never "-1" (default) at this point - the caller
     * has always changed -1 to the value of get[gu]id().
    */
    if ((flags & VIR_FILE_OPEN_FORCE_OWNER) &&
        ((st.st_uid != uid) || (st.st_gid != gid)) &&
        (fchown(fd, uid, gid) < 0)) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot chown '%s' to (%u, %u)"),
                             path, (unsigned int) uid,
                             (unsigned int) gid);
        return ret;
    }
    if ((flags & VIR_FILE_OPEN_FORCE_MODE) &&
        ((mode & (S_IRWXU|S_IRWXG|S_IRWXO)) !=
         (st.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO))) &&
        (fchmod(fd, mode) < 0)) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        return ret;
    }
    return ret;
}

/* virFileOpenForked() - an internal utility function called only by
 * virFileOpenAs(). It forks, then the child does setuid+setgid to
 * given uid:gid and attempts to open the file, while the parent just
 * calls recvfd to get the open fd back from the child. returns the
 * fd, or -errno if there is an error. Additionally, to avoid another
 * round-trip to unlink the file in a forked process; on error if this
 * function created the file, but failed to perform some action after
 * creation, then perform the unlink of the file. The storage driver
 * buildVol backend function expects the file to be deleted on error.
 */
static int
virFileOpenForked(const char *path, int openflags, mode_t mode,
                  uid_t uid, gid_t gid, unsigned int flags)
{
    pid_t pid;
    int status = 0, ret = 0;
    int recvfd_errno = 0;
    int fd = -1;
    int pair[2] = { -1, -1 };
    gid_t *groups;
    int ngroups;
    bool created = false;

    /* parent is running as root, but caller requested that the
     * file be opened as some other user and/or group). The
     * following dance avoids problems caused by root-squashing
     * NFS servers. */

    ngroups = virGetGroupList(uid, gid, &groups);
    if (ngroups < 0)
        return -errno;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("failed to create socket needed for '%s'"),
                             path);
        VIR_FREE(groups);
        return ret;
    }

    pid = virFork();
    if (pid < 0) {
        ret = -errno;
        VIR_FREE(groups);
        return ret;
    }

    if (pid == 0) {

        /* child */

        /* set desired uid/gid, then attempt to create the file */
        VIR_FORCE_CLOSE(pair[0]);
        if (virSetUIDGID(uid, gid, groups, ngroups) < 0) {
            ret = -errno;
            goto childerror;
        }

        if ((fd = open(path, openflags, mode)) < 0) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("child process failed to create file '%s'"),
                                 path);
            goto childerror;
        }
        if (openflags & O_CREAT)
            created = true;

        /* File is successfully open. Set permissions if requested. */
        ret = virFileOpenForceOwnerMode(path, fd, mode, uid, gid, flags);
        if (ret < 0) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("child process failed to force owner mode file '%s'"),
                                 path);
            goto childerror;
        }

        do {
            ret = sendfd(pair[1], fd);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0) {
            ret = -errno;
            virReportSystemError(errno, "%s",
                                 _("child process failed to send fd to parent"));
            goto childerror;
        }

    childerror:
        /* ret tracks -errno on failure, but exit value must be positive.
         * If the child exits with EACCES, then the parent tries again.  */
        /* XXX This makes assumptions about errno being < 255, which is
         * not true on Hurd.  */
        VIR_FORCE_CLOSE(pair[1]);
        if (ret < 0) {
            VIR_FORCE_CLOSE(fd);
            if (created)
                unlink(path);
        }
        ret = -ret;
        if ((ret & 0xff) != ret) {
            VIR_WARN("unable to pass desired return value %d", ret);
            ret = 0xff;
        }
        _exit(ret);
    }

    /* parent */

    VIR_FREE(groups);
    VIR_FORCE_CLOSE(pair[1]);

    do {
        fd = recvfd(pair[0], 0);
    } while (fd < 0 && errno == EINTR);
    VIR_FORCE_CLOSE(pair[0]); /* NB: this preserves errno */
    if (fd < 0)
        recvfd_errno = errno;

    if (virProcessWait(pid, &status, 0) < 0) {
        /* virProcessWait() reports errno on waitpid failure, so we'll just
         * set our return status to EINTR; otherwise, set status to EACCES
         * since the original failure for the fork+setuid path would have
         * been EACCES or EPERM by definition.
         */
        if (virLastErrorIsSystemErrno(0))
            status = EINTR;
        else if (!status)
            status = EACCES;
    }

    if (status) {
        VIR_FORCE_CLOSE(fd);
        return -status;
    }

    /* if waitpid succeeded, but recvfd failed, report recvfd_errno */
    if (recvfd_errno != 0) {
        virReportSystemError(recvfd_errno,
                             _("failed recvfd for child creating '%s'"),
                             path);
        return -recvfd_errno;
    }

    /* otherwise, waitpid and recvfd succeeded, return the fd */
    return fd;
}

/**
 * virFileOpenAs:
 * @path: file to open or create
 * @openflags: flags to pass to open
 * @mode: mode to use on creation or when forcing permissions
 * @uid: uid that should own file on creation
 * @gid: gid that should own file
 * @flags: bit-wise or of VIR_FILE_OPEN_* flags
 *
 * Open @path, and return an fd to the open file. @openflags contains
 * the flags normally passed to open(2), while those in @flags are
 * used internally. If @flags includes VIR_FILE_OPEN_NOFORK, then try
 * opening the file while executing with the current uid:gid
 * (i.e. don't fork+setuid+setgid before the call to open()).  If
 * @flags includes VIR_FILE_OPEN_FORK, then try opening the file while
 * the effective user id is @uid (by forking a child process); this
 * allows one to bypass root-squashing NFS issues; NOFORK is always
 * tried before FORK (the absence of both flags is treated identically
 * to (VIR_FILE_OPEN_NOFORK | VIR_FILE_OPEN_FORK)). If @flags includes
 * VIR_FILE_OPEN_FORCE_OWNER, then ensure that @path is owned by
 * uid:gid before returning (even if it already existed with a
 * different owner). If @flags includes VIR_FILE_OPEN_FORCE_MODE,
 * ensure it has those permissions before returning (again, even if
 * the file already existed with different permissions).
 *
 * The return value (if non-negative) is the file descriptor, left
 * open.  Returns -errno on failure. Additionally, to avoid another
 * round-trip to unlink the file; on error if this function created the
 * file, but failed to perform some action after creation, then perform
 * the unlink of the file. The storage driver buildVol backend function
 * expects the file to be deleted on error.
 */
int
virFileOpenAs(const char *path, int openflags, mode_t mode,
              uid_t uid, gid_t gid, unsigned int flags)
{
    int ret = 0, fd = -1;
    bool created = false;

    /* allow using -1 to mean "current value" */
    if (uid == (uid_t) -1)
        uid = geteuid();
    if (gid == (gid_t) -1)
        gid = getegid();

    /* treat absence of both flags as presence of both for simpler
     * calling. */
    if (!(flags & (VIR_FILE_OPEN_NOFORK|VIR_FILE_OPEN_FORK)))
        flags |= VIR_FILE_OPEN_NOFORK|VIR_FILE_OPEN_FORK;

    if ((flags & VIR_FILE_OPEN_NOFORK)
        || (geteuid() != 0)
        || ((uid == 0) && (gid == 0))) {

        if ((fd = open(path, openflags, mode)) < 0) {
            ret = -errno;
            if (!(flags & VIR_FILE_OPEN_FORK))
                goto error;
        } else {
            if (openflags & O_CREAT)
                created = true;
            ret = virFileOpenForceOwnerMode(path, fd, mode, uid, gid, flags);
            if (ret < 0)
                goto error;
        }
    }

    /* If we either 1) didn't try opening as current user at all, or
     * 2) failed, and errno/virStorageFileIsSharedFS indicate we might
     * be successful if we try as a different uid, then try doing
     * fork+setuid+setgid before opening.
     */
    if ((fd < 0) && (flags & VIR_FILE_OPEN_FORK)) {

        if (ret < 0) {
            /* An open(2) that failed due to insufficient permissions
             * could return one or the other of these depending on OS
             * version and circumstances. Any other errno indicates a
             * problem that couldn't be remedied by fork+setuid
             * anyway. */
            if (ret != -EACCES && ret != -EPERM)
                goto error;

            /* On Linux we can also verify the FS-type of the
             * directory.  (this is a NOP on other platforms). */
            if (virFileIsSharedFS(path) <= 0)
                goto error;
        }

        /* passed all prerequisites - retry the open w/fork+setuid */
        if ((fd = virFileOpenForked(path, openflags, mode, uid, gid, flags)) < 0) {
            ret = fd;
            goto error;
        }
    }

    /* File is successfully opened */
    return fd;

 error:
    if (fd >= 0) {
        /* some other failure after the open succeeded */
        VIR_FORCE_CLOSE(fd);
        if (created)
            unlink(path);
    }
    /* whoever failed the open last has already set ret = -errno */
    return ret;
}


/* virFileRemoveNeedsSetuid:
 * @path: file we plan to remove
 * @uid: file uid to check
 * @gid: file gid to check
 *
 * Return true if we should use setuid/setgid before deleting a file
 * owned by the passed uid/gid pair. Needed for NFS with root-squash
 */
static bool
virFileRemoveNeedsSetuid(const char *path, uid_t uid, gid_t gid)
{
    /* If running unprivileged, setuid isn't going to work */
    if (geteuid() != 0)
        return false;

    /* uid/gid weren't specified */
    if ((uid == (uid_t) -1) && (gid == (gid_t) -1))
        return false;

    /* already running as proper uid/gid */
    if (uid == geteuid() && gid == getegid())
        return false;

    /* Only perform the setuid stuff for NFS, which is the only case
       that may actually need it. This can error, but just be safe and
       only check for a clear negative result. */
    if (virFileIsSharedFSType(path, VIR_FILE_SHFS_NFS) == 0)
        return false;

    return true;
}


/* virFileRemove:
 * @path: file to unlink or directory to remove
 * @uid: uid that was used to create the file (not required)
 * @gid: gid that was used to create the file (not required)
 *
 * If a file/volume was created in an NFS root-squash environment,
 * then we must 'unlink' the file in the same environment. Unlike
 * the virFileOpenAs[Forked] and virDirCreate[NoFork], this code
 * takes no extra flags and does not bother with EACCES failures
 * from the child.
 */
int
virFileRemove(const char *path,
              uid_t uid,
              gid_t gid)
{
    pid_t pid;
    int status = 0, ret = 0;
    gid_t *groups;
    int ngroups;

    if (!virFileRemoveNeedsSetuid(path, uid, gid)) {
        if (virFileIsDir(path))
            return rmdir(path);
        else
            return unlink(path);
    }

    /* Otherwise, we have to deal with the NFS root-squash craziness
     * to run under the uid/gid that created the volume in order to
     * perform the unlink of the volume.
     */
    if (uid == (uid_t) -1)
        uid = geteuid();
    if (gid == (gid_t) -1)
        gid = getegid();

    ngroups = virGetGroupList(uid, gid, &groups);
    if (ngroups < 0)
        return -errno;

    pid = virFork();

    if (pid < 0) {
        ret = -errno;
        VIR_FREE(groups);
        return ret;
    }

    if (pid) { /* parent */
        /* wait for child to complete, and retrieve its exit code */
        VIR_FREE(groups);

        if (virProcessWait(pid, &status, 0) < 0) {
            /* virProcessWait() reports errno on waitpid failure, so we'll just
             * set our return status to EINTR; otherwise, set status to EACCES
             * since the original failure for the fork+setuid path would have
             * been EACCES or EPERM by definition.
             */
            if (virLastErrorIsSystemErrno(0))
                status = EINTR;
            else if (!status)
                status = EACCES;
        }

        if (status) {
            errno = status;
            ret = -1;
        }

        return ret;
    }

    /* child */

    /* set desired uid/gid, then attempt to unlink the file */
    if (virSetUIDGID(uid, gid, groups, ngroups) < 0) {
        ret = errno;
        goto childerror;
    }

    if (virFileIsDir(path)) {
        if (rmdir(path) < 0) {
            ret = errno;
            goto childerror;
        }
    } else {
        if (unlink(path) < 0) {
            ret = errno;
            goto childerror;
        }
    }

 childerror:
    if ((ret & 0xff) != ret) {
        VIR_WARN("unable to pass desired return value %d", ret);
        ret = 0xff;
    }
    _exit(ret);
}


/* Attempt to create a directory and possibly adjust its owner/group and
 * permissions.
 *
 * return 0 on success or -errno on failure. Additionally to avoid another
 * round-trip to remove the directory on failure, perform the rmdir when
 * a mkdir was successful, but some other failure would cause a -1 return.
 * The storage driver buildVol backend function expects the directory to
 * be deleted on error.
 */
static int
virDirCreateNoFork(const char *path,
                   mode_t mode, uid_t uid, gid_t gid,
                   unsigned int flags)
{
    int ret = 0;
    struct stat st;
    bool created = false;

    if (!((flags & VIR_DIR_CREATE_ALLOW_EXIST) && virFileExists(path))) {
        if (mkdir(path, mode) < 0) {
            ret = -errno;
            virReportSystemError(errno, _("failed to create directory '%s'"),
                                 path);
            goto error;
        }
        created = true;
    }

    if (stat(path, &st) == -1) {
        ret = -errno;
        virReportSystemError(errno, _("stat of '%s' failed"), path);
        goto error;
    }
    if (((uid != (uid_t) -1 && st.st_uid != uid) ||
         (gid != (gid_t) -1 && st.st_gid != gid))
        && (chown(path, uid, gid) < 0)) {
        ret = -errno;
        virReportSystemError(errno, _("cannot chown '%s' to (%u, %u)"),
                             path, (unsigned int) uid, (unsigned int) gid);
        goto error;
    }
    if (mode != (mode_t) -1 && chmod(path, mode) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        goto error;
    }
 error:
    if (ret < 0 && created)
        rmdir(path);
    return ret;
}

/*
 * virDirCreate:
 * @path: directory to create
 * @mode: mode to use on creation or when forcing permissions
 * @uid: uid that should own directory
 * @gid: gid that should own directory
 * @flags: bit-wise or of VIR_DIR_CREATE_* flags
 *
 * Attempt to create a directory and possibly adjust its owner/group and
 * permissions. If conditions allow, use the *NoFork code in order to create
 * the directory under current owner/group rather than via a forked process.
 *
 * return 0 on success or -errno on failure. Additionally to avoid another
 * round-trip to remove the directory on failure, perform the rmdir if a
 * mkdir was successful, but some other failure would cause a -1 return.
 * The storage driver buildVol backend function expects the directory to
 * be deleted on error.
 *
 */
int
virDirCreate(const char *path,
             mode_t mode, uid_t uid, gid_t gid,
             unsigned int flags)
{
    struct stat st;
    pid_t pid;
    int status = 0, ret = 0;
    gid_t *groups;
    int ngroups;
    bool created = false;

    /* Everything after this check is crazyness to allow setting uid/gid
     * on directories that are on root-squash NFS shares. We only want
     * to go that route if the follow conditions are true:
     *
     * 1) VIR_DIR_CREATE_AS_UID was passed, currently only used when
     *    directory is being created for a NETFS pool
     * 2) We are running as root, since that's when the root-squash
     *    workaround is required.
     * 3) An explicit uid/gid was requested
     * 4) The directory doesn't already exist and the ALLOW_EXIST flag
     *    wasn't passed.
     *
     * If any of those conditions are _not_ met, ignore the fork crazyness
     */
    if ((!(flags & VIR_DIR_CREATE_AS_UID))
        || (geteuid() != 0)
        || ((uid == (uid_t) -1) && (gid == (gid_t) -1))
        || ((flags & VIR_DIR_CREATE_ALLOW_EXIST) && virFileExists(path))) {
        return virDirCreateNoFork(path, mode, uid, gid, flags);
    }

    if (uid == (uid_t) -1)
        uid = geteuid();
    if (gid == (gid_t) -1)
        gid = getegid();

    ngroups = virGetGroupList(uid, gid, &groups);
    if (ngroups < 0)
        return -errno;

    pid = virFork();

    if (pid < 0) {
        ret = -errno;
        VIR_FREE(groups);
        return ret;
    }

    if (pid) { /* parent */
        /* wait for child to complete, and retrieve its exit code */
        VIR_FREE(groups);

        if (virProcessWait(pid, &status, 0) < 0) {
            /* virProcessWait() reports errno on waitpid failure, so we'll just
             * set our return status to EINTR; otherwise, set status to EACCES
             * since the original failure for the fork+setuid path would have
             * been EACCES or EPERM by definition.
             */
            if (virLastErrorIsSystemErrno(0))
                status = EINTR;
            else if (!status)
                status = EACCES;
        }

        /*
         * If the child exited with EACCES, then fall back to non-fork method
         * as in the original logic introduced and explained by commit 98f6f381.
         */
        if (status == EACCES) {
            virResetLastError();
            return virDirCreateNoFork(path, mode, uid, gid, flags);
        }

        if (status)
            ret = -status;

        return ret;
    }

    /* child */

    /* set desired uid/gid, then attempt to create the directory */
    if (virSetUIDGID(uid, gid, groups, ngroups) < 0) {
        ret = errno;
        goto childerror;
    }

    if (mkdir(path, mode) < 0) {
        ret = errno;
        if (ret != EACCES) {
            /* in case of EACCES, the parent will retry */
            virReportSystemError(errno, _("child failed to create directory '%s'"),
                                 path);
        }
        goto childerror;
    }
    created = true;

    /* check if group was set properly by creating after
     * setgid. If not, try doing it with chown */
    if (stat(path, &st) == -1) {
        ret = errno;
        virReportSystemError(errno,
                             _("stat of '%s' failed"), path);
        goto childerror;
    }

    if ((st.st_gid != gid) && (chown(path, (uid_t) -1, gid) < 0)) {
        ret = errno;
        virReportSystemError(errno,
                             _("cannot chown '%s' to group %u"),
                             path, (unsigned int) gid);
        goto childerror;
    }

    if (mode != (mode_t) -1 && chmod(path, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        goto childerror;
    }

 childerror:
    if (ret != 0 && created)
        rmdir(path);

    if ((ret & 0xff) != ret) {
        VIR_WARN("unable to pass desired return value %d", ret);
        ret = 0xff;
    }
    _exit(ret);
}

#else /* WIN32 */

int
virFileAccessibleAs(const char *path,
                    int mode,
                    uid_t uid ATTRIBUTE_UNUSED,
                    gid_t gid ATTRIBUTE_UNUSED)
{

    VIR_WARN("Ignoring uid/gid due to WIN32");

    return access(path, mode);
}

/* return -errno on failure, or 0 on success */
int
virFileOpenAs(const char *path ATTRIBUTE_UNUSED,
              int openflags ATTRIBUTE_UNUSED,
              mode_t mode ATTRIBUTE_UNUSED,
              uid_t uid ATTRIBUTE_UNUSED,
              gid_t gid ATTRIBUTE_UNUSED,
              unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virFileOpenAs is not implemented for WIN32"));

    return -ENOSYS;
}

int
virDirCreate(const char *path ATTRIBUTE_UNUSED,
             mode_t mode ATTRIBUTE_UNUSED,
             uid_t uid ATTRIBUTE_UNUSED,
             gid_t gid ATTRIBUTE_UNUSED,
             unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virDirCreate is not implemented for WIN32"));

    return -ENOSYS;
}

int
virFileRemove(const char *path,
              uid_t uid ATTRIBUTE_UNUSED,
              gid_t gid ATTRIBUTE_UNUSED)
{
    if (unlink(path) < 0) {
        virReportSystemError(errno, _("Unable to unlink path '%s'"),
                             path);
        return -1;
    }

    return 0;
}
#endif /* WIN32 */

static int
virDirOpenInternal(DIR **dirp, const char *name, bool ignoreENOENT, bool quiet)
{
    *dirp = opendir(name); /* exempt from syntax-check */
    if (!*dirp) {
        if (quiet)
            return -1;

        if (ignoreENOENT && errno == ENOENT)
            return 0;
        virReportSystemError(errno, _("cannot open directory '%s'"), name);
        return -1;
    }
    return 1;
}

/**
 * virDirOpen
 * @dirp: directory stream
 * @name: path of the directory
 *
 * Returns 1 on success.
 * On failure, -1 is returned and an error is reported.
 */
int
virDirOpen(DIR **dirp, const char *name)
{
    return virDirOpenInternal(dirp, name, false, false);
}

/**
 * virDirOpenIfExists
 * @dirp: directory stream
 * @name: path of the directory
 *
 * Returns 1 on success.
 * If opendir returns ENOENT, 0 is returned without reporting an error.
 * On other errors, -1 is returned and an error is reported.
 */
int
virDirOpenIfExists(DIR **dirp, const char *name)
{
    return virDirOpenInternal(dirp, name, true, false);
}

/**
 * virDirOpenQuiet
 * @dirp: directory stream
 * @name: path of the directory
 *
 * Returns 1 on success.
 *        -1 on failure.
 *
 * Does not report any errors and errno is preserved.
 */
int
virDirOpenQuiet(DIR **dirp, const char *name)
{
    return virDirOpenInternal(dirp, name, false, true);
}

/**
 * virDirRead:
 * @dirp: directory to read
 * @end: output one entry
 * @name: if non-NULL, the name related to @dirp for use in error reporting
 *
 * Wrapper around readdir. Typical usage:
 *   struct dirent ent;
 *   int rc;
 *   DIR *dir;
 *   if (virDirOpen(&dir, name) < 0)
 *       goto error;
 *   while ((rc = virDirRead(dir, &ent, name)) > 0)
 *       process ent;
 *   if (rc < 0)
 *       goto error;
 *
 * Returns -1 on error, with error already reported if @name was
 * supplied.  On success, returns 1 for entry read, 0 for end-of-dir.
 */
int virDirRead(DIR *dirp, struct dirent **ent, const char *name)
{
    do {
        errno = 0;
        *ent = readdir(dirp); /* exempt from syntax-check */
        if (!*ent && errno) {
            if (name)
                virReportSystemError(errno, _("Unable to read directory '%s'"),
                                     name);
            return -1;
        }
    } while (*ent && (STREQ((*ent)->d_name, ".") ||
                      STREQ((*ent)->d_name, "..")));
    return !!*ent;
}

void virDirClose(DIR **dirp)
{
    if (!*dirp)
        return;

    closedir(*dirp); /* exempt from syntax-check */
    *dirp = NULL;
}

static int
virFileMakePathHelper(char *path, mode_t mode)
{
    struct stat st;
    char *p;

    VIR_DEBUG("path=%s mode=0%o", path, mode);

    if (stat(path, &st) >= 0) {
        if (S_ISDIR(st.st_mode))
            return 0;

        errno = ENOTDIR;
        return -1;
    }

    if (errno != ENOENT)
        return -1;

    if ((p = strrchr(path, '/')) == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (p != path) {
        *p = '\0';

        if (virFileMakePathHelper(path, mode) < 0)
            return -1;

        *p = '/';
    }

    if (mkdir(path, mode) < 0 && errno != EEXIST)
        return -1;

    return 0;
}

/**
 * Creates the given directory with mode 0777 if it's not already existing.
 *
 * Returns 0 on success, or -1 if an error occurred (in which case, errno
 * is set appropriately).
 */
int
virFileMakePath(const char *path)
{
    return virFileMakePathWithMode(path, 0777);
}

int
virFileMakePathWithMode(const char *path,
                        mode_t mode)
{
    int ret = -1;
    char *tmp;

    if (VIR_STRDUP(tmp, path) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    ret = virFileMakePathHelper(tmp, mode);

 cleanup:
    VIR_FREE(tmp);
    return ret;
}


int
virFileMakeParentPath(const char *path)
{
    char *p;
    char *tmp;
    int ret = -1;

    VIR_DEBUG("path=%s", path);

    if (VIR_STRDUP(tmp, path) < 0) {
        errno = ENOMEM;
        return -1;
    }

    if ((p = strrchr(tmp, '/')) == NULL) {
        errno = EINVAL;
        goto cleanup;
    }
    *p = '\0';

    ret = virFileMakePathHelper(tmp, 0777);

 cleanup:
    VIR_FREE(tmp);
    return ret;
}


/* Build up a fully qualified path for a config file to be
 * associated with a persistent guest or network */
char *
virFileBuildPath(const char *dir, const char *name, const char *ext)
{
    char *path;

    if (ext == NULL) {
        ignore_value(virAsprintf(&path, "%s/%s", dir, name));
    } else {
        ignore_value(virAsprintf(&path, "%s/%s%s", dir, name, ext));
    }

    return path;
}

/* Open a non-blocking master side of a pty.  If ttyName is not NULL,
 * then populate it with the name of the slave.  If rawmode is set,
 * also put the master side into raw mode before returning.  */
#ifndef WIN32
int
virFileOpenTty(int *ttymaster, char **ttyName, int rawmode)
{
    /* XXX A word of caution - on some platforms (Solaris and HP-UX),
     * additional ioctl() calls are needs after opening the slave
     * before it will cause isatty() to return true.  Should we make
     * virFileOpenTty also return the opened slave fd, so the caller
     * doesn't have to worry about that mess?  */
    int ret = -1;
    int slave = -1;
    char *name = NULL;

    /* Unfortunately, we can't use the name argument of openpty, since
     * there is no guarantee on how large the buffer has to be.
     * Likewise, we can't use the termios argument: we have to use
     * read-modify-write since there is no portable way to initialize
     * a struct termios without use of tcgetattr.  */
    if (openpty(ttymaster, &slave, NULL, NULL, NULL) < 0)
        return -1;

    /* What a shame that openpty cannot atomically set FD_CLOEXEC, but
     * that using posix_openpt/grantpt/unlockpt/ptsname is not
     * thread-safe, and that ptsname_r is not portable.  */
    if (virSetNonBlock(*ttymaster) < 0 ||
        virSetCloseExec(*ttymaster) < 0)
        goto cleanup;

    /* While Linux supports tcgetattr on either the master or the
     * slave, Solaris requires it to be on the slave.  */
    if (rawmode) {
        struct termios ttyAttr;
        if (tcgetattr(slave, &ttyAttr) < 0)
            goto cleanup;

        cfmakeraw(&ttyAttr);

        if (tcsetattr(slave, TCSADRAIN, &ttyAttr) < 0)
            goto cleanup;
    }

    /* ttyname_r on the slave is required by POSIX, while ptsname_r on
     * the master is a glibc extension, and the POSIX ptsname is not
     * thread-safe.  Since openpty gave us both descriptors, guess
     * which way we will determine the name?  :)  */
    if (ttyName) {
        /* Initial guess of 64 is generally sufficient; rely on ERANGE
         * to tell us if we need to grow.  */
        size_t len = 64;
        int rc;

        if (VIR_ALLOC_N(name, len) < 0)
            goto cleanup;

        while ((rc = ttyname_r(slave, name, len)) == ERANGE) {
            if (VIR_RESIZE_N(name, len, len, len) < 0)
                goto cleanup;
        }
        if (rc != 0) {
            errno = rc;
            goto cleanup;
        }
        *ttyName = name;
        name = NULL;
    }

    ret = 0;

 cleanup:
    if (ret != 0)
        VIR_FORCE_CLOSE(*ttymaster);
    VIR_FORCE_CLOSE(slave);
    VIR_FREE(name);

    return ret;
}
#else /* WIN32 */
int
virFileOpenTty(int *ttymaster ATTRIBUTE_UNUSED,
               char **ttyName ATTRIBUTE_UNUSED,
               int rawmode ATTRIBUTE_UNUSED)
{
    /* mingw completely lacks pseudo-terminals, and the gnulib
     * replacements are not (yet) license compatible.  */
    errno = ENOSYS;
    return -1;
}
#endif /* WIN32 */

bool
virFileIsAbsPath(const char *path)
{
    if (!path)
        return false;

    if (VIR_FILE_IS_DIR_SEPARATOR(path[0]))
        return true;

#ifdef WIN32
    if (c_isalpha(path[0]) &&
        path[1] == ':' &&
        VIR_FILE_IS_DIR_SEPARATOR(path[2]))
        return true;
#endif

    return false;
}


const char *
virFileSkipRoot(const char *path)
{
#ifdef WIN32
    /* Skip \\server\share or //server/share */
    if (VIR_FILE_IS_DIR_SEPARATOR(path[0]) &&
        VIR_FILE_IS_DIR_SEPARATOR(path[1]) &&
        path[2] &&
        !VIR_FILE_IS_DIR_SEPARATOR(path[2]))
    {
        const char *p = strchr(path + 2, VIR_FILE_DIR_SEPARATOR);
        const char *q = strchr(path + 2, '/');

        if (p == NULL || (q != NULL && q < p))
            p = q;

        if (p && p > path + 2 && p[1]) {
            path = p + 1;

            while (path[0] &&
                   !VIR_FILE_IS_DIR_SEPARATOR(path[0]))
                path++;

            /* Possibly skip a backslash after the share name */
            if (VIR_FILE_IS_DIR_SEPARATOR(path[0]))
                path++;

            return path;
        }
    }
#endif

    /* Skip initial slashes */
    if (VIR_FILE_IS_DIR_SEPARATOR(path[0])) {
        while (VIR_FILE_IS_DIR_SEPARATOR(path[0]))
            path++;

        return path;
    }

#ifdef WIN32
    /* Skip X:\ */
    if (c_isalpha(path[0]) &&
        path[1] == ':' &&
        VIR_FILE_IS_DIR_SEPARATOR(path[2]))
        return path + 3;
#endif

    return path;
}



/*
 * Creates an absolute path for a potentially relative path.
 * Return 0 if the path was not relative, or on success.
 * Return -1 on error.
 *
 * You must free the result.
 */
int
virFileAbsPath(const char *path, char **abspath)
{
    char *buf;

    if (path[0] == '/') {
        if (VIR_STRDUP(*abspath, path) < 0)
            return -1;
    } else {
        buf = getcwd(NULL, 0);
        if (buf == NULL)
            return -1;

        if (virAsprintf(abspath, "%s/%s", buf, path) < 0) {
            VIR_FREE(buf);
            return -1;
        }
        VIR_FREE(buf);
    }

    return 0;
}

/* Remove spurious / characters from a path. The result must be freed */
char *
virFileSanitizePath(const char *path)
{
    const char *cur = path;
    char *uri;
    char *cleanpath;
    int idx = 0;

    if (VIR_STRDUP(cleanpath, path) < 0)
        return NULL;

    /* don't sanitize URIs - rfc3986 states that two slashes may lead to a
     * different resource, thus removing them would possibly change the path */
    if ((uri = strstr(path, "://")) && strchr(path, '/') > uri)
        return cleanpath;

    /* Need to sanitize:
     * //           -> //
     * ///          -> /
     * /../foo      -> /../foo
     * /foo///bar/  -> /foo/bar
     */

    /* Starting with // is valid posix, but ///foo == /foo */
    if (cur[0] == '/' && cur[1] == '/' && cur[2] != '/') {
        idx = 2;
        cur += 2;
    }

    /* Sanitize path in place */
    while (*cur != '\0') {
        if (*cur != '/') {
            cleanpath[idx++] = *cur++;
            continue;
        }

        /* Skip all extra / */
        while (*++cur == '/')
            continue;

        /* Don't add a trailing / */
        if (idx != 0 && *cur == '\0')
            break;

        cleanpath[idx++] = '/';
    }
    cleanpath[idx] = '\0';

    return cleanpath;
}

/**
 * virFileRemoveLastComponent:
 *
 * For given path cut off the last component. If there's no dir
 * separator (whole path is one file name), @path is turned into
 * an empty string.
 */
void
virFileRemoveLastComponent(char *path)
{
    char *tmp;

    if ((tmp = strrchr(path, VIR_FILE_DIR_SEPARATOR)))
        tmp[1] = '\0';
    else
        path[0] = '\0';
}

/**
 * virFilePrintf:
 *
 * A replacement for fprintf() which uses virVasprintf to
 * ensure that portable string format placeholders can be
 * used, since gnulib's fprintf() replacement is not
 * LGPLV2+ compatible
 */
int virFilePrintf(FILE *fp, const char *msg, ...)
{
    va_list vargs;
    char *str;
    int ret;

    va_start(vargs, msg);

    if ((ret = virVasprintf(&str, msg, vargs)) < 0)
        goto cleanup;

    if (fwrite(str, 1, ret, fp) != ret) {
        virReportSystemError(errno, "%s",
                             _("Could not write to stream"));
        ret = -1;
    }

    VIR_FREE(str);

 cleanup:
    va_end(vargs);

    return ret;
}


#ifdef __linux__

# ifndef NFS_SUPER_MAGIC
#  define NFS_SUPER_MAGIC 0x6969
# endif
# ifndef OCFS2_SUPER_MAGIC
#  define OCFS2_SUPER_MAGIC 0x7461636f
# endif
# ifndef GFS2_MAGIC
#  define GFS2_MAGIC 0x01161970
# endif
# ifndef AFS_FS_MAGIC
#  define AFS_FS_MAGIC 0x6B414653
# endif
# ifndef SMB_SUPER_MAGIC
#  define SMB_SUPER_MAGIC 0x517B
# endif
# ifndef CIFS_SUPER_MAGIC
#  define CIFS_SUPER_MAGIC 0xFF534D42
# endif
# ifndef HUGETLBFS_MAGIC
#  define HUGETLBFS_MAGIC 0x958458f6
# endif

int
virFileIsSharedFSType(const char *path,
                      int fstypes)
{
    char *dirpath, *p;
    struct statfs sb;
    int statfs_ret;

    if (VIR_STRDUP(dirpath, path) < 0)
        return -1;

    do {

        /* Try less and less of the path until we get to a
         * directory we can stat. Even if we don't have 'x'
         * permission on any directory in the path on the NFS
         * server (assuming it's NFS), we will be able to stat the
         * mount point, and that will properly tell us if the
         * fstype is NFS.
         */

        if ((p = strrchr(dirpath, '/')) == NULL) {
            virReportSystemError(EINVAL,
                         _("Invalid relative path '%s'"), path);
            VIR_FREE(dirpath);
            return -1;
        }

        if (p == dirpath)
            *(p+1) = '\0';
        else
            *p = '\0';

        statfs_ret = statfs(dirpath, &sb);

    } while ((statfs_ret < 0) && (p != dirpath));

    VIR_FREE(dirpath);

    if (statfs_ret < 0) {
        virReportSystemError(errno,
                             _("cannot determine filesystem for '%s'"),
                             path);
        return -1;
    }

    VIR_DEBUG("Check if path %s with FS magic %lld is shared",
              path, (long long int)sb.f_type);

    if ((fstypes & VIR_FILE_SHFS_NFS) &&
        (sb.f_type == NFS_SUPER_MAGIC))
        return 1;

    if ((fstypes & VIR_FILE_SHFS_GFS2) &&
        (sb.f_type == GFS2_MAGIC))
        return 1;
    if ((fstypes & VIR_FILE_SHFS_OCFS) &&
        (sb.f_type == OCFS2_SUPER_MAGIC))
        return 1;
    if ((fstypes & VIR_FILE_SHFS_AFS) &&
        (sb.f_type == AFS_FS_MAGIC))
        return 1;
    if ((fstypes & VIR_FILE_SHFS_SMB) &&
        (sb.f_type == SMB_SUPER_MAGIC))
        return 1;
    if ((fstypes & VIR_FILE_SHFS_CIFS) &&
        (sb.f_type == CIFS_SUPER_MAGIC))
        return 1;

    return 0;
}

int
virFileGetHugepageSize(const char *path,
                       unsigned long long *size)
{
    int ret = -1;
    struct statfs fs;

    if (statfs(path, &fs) < 0) {
        virReportSystemError(errno,
                             _("cannot determine filesystem for '%s'"),
                             path);
        goto cleanup;
    }

    if (fs.f_type != HUGETLBFS_MAGIC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("not a hugetlbfs mount: '%s'"),
                       path);
        goto cleanup;
    }

    *size = fs.f_bsize / 1024; /* we are storing size in KiB */
    ret = 0;
 cleanup:
    return ret;
}

# define PROC_MEMINFO "/proc/meminfo"
# define HUGEPAGESIZE_STR "Hugepagesize:"

static int
virFileGetDefaultHugepageSize(unsigned long long *size)
{
    int ret = -1;
    char *meminfo, *c, *n, *unit;

    if (virFileReadAll(PROC_MEMINFO, 4096, &meminfo) < 0)
        goto cleanup;

    if (!(c = strstr(meminfo, HUGEPAGESIZE_STR))) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("%s not found in %s"),
                       HUGEPAGESIZE_STR,
                       PROC_MEMINFO);
        goto cleanup;
    }
    c += strlen(HUGEPAGESIZE_STR);

    if ((n = strchr(c, '\n'))) {
        /* Cut off the rest of the meminfo file */
        *n = '\0';
    }

    if (virStrToLong_ull(c, &unit, 10, size) < 0 || STRNEQ(unit, " kB")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse %s %s"),
                       HUGEPAGESIZE_STR, c);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(meminfo);
    return ret;
}

# define PROC_MOUNTS "/proc/mounts"

int
virFileFindHugeTLBFS(virHugeTLBFSPtr *ret_fs,
                     size_t *ret_nfs)
{
    int ret = -1;
    FILE *f = NULL;
    struct mntent mb;
    char mntbuf[1024];
    virHugeTLBFSPtr fs = NULL;
    size_t nfs = 0;
    unsigned long long default_hugepagesz = 0;

    if (!(f = setmntent(PROC_MOUNTS, "r"))) {
        virReportSystemError(errno,
                             _("Unable to open %s"),
                             PROC_MOUNTS);
        goto cleanup;
    }

    while (getmntent_r(f, &mb, mntbuf, sizeof(mntbuf))) {
        virHugeTLBFSPtr tmp;

        if (STRNEQ(mb.mnt_type, "hugetlbfs"))
            continue;

        if (VIR_EXPAND_N(fs, nfs, 1) < 0)
             goto cleanup;

        tmp = &fs[nfs - 1];

        if (VIR_STRDUP(tmp->mnt_dir, mb.mnt_dir) < 0)
            goto cleanup;

        if (virFileGetHugepageSize(tmp->mnt_dir, &tmp->size) < 0)
            goto cleanup;

        if (!default_hugepagesz &&
            virFileGetDefaultHugepageSize(&default_hugepagesz) < 0)
            goto cleanup;

        tmp->deflt = tmp->size == default_hugepagesz;
    }

    *ret_fs = fs;
    *ret_nfs = nfs;
    fs = NULL;
    nfs = 0;
    ret = 0;

 cleanup:
    endmntent(f);
    while (nfs)
        VIR_FREE(fs[--nfs].mnt_dir);
    VIR_FREE(fs);
    return ret;
}

#else /* defined __linux__ */

int virFileIsSharedFSType(const char *path ATTRIBUTE_UNUSED,
                          int fstypes ATTRIBUTE_UNUSED)
{
    /* XXX implement me :-) */
    return 0;
}

int
virFileGetHugepageSize(const char *path ATTRIBUTE_UNUSED,
                       unsigned long long *size ATTRIBUTE_UNUSED)
{
    /* XXX implement me :-) */
    virReportUnsupportedError();
    return -1;
}

int
virFileFindHugeTLBFS(virHugeTLBFSPtr *ret_fs ATTRIBUTE_UNUSED,
                     size_t *ret_nfs ATTRIBUTE_UNUSED)
{
    /* XXX implement me :-) */
    virReportUnsupportedError();
    return -1;
}
#endif /* defined __linux__ */

int virFileIsSharedFS(const char *path)
{
    return virFileIsSharedFSType(path,
                                 VIR_FILE_SHFS_NFS |
                                 VIR_FILE_SHFS_GFS2 |
                                 VIR_FILE_SHFS_OCFS |
                                 VIR_FILE_SHFS_AFS |
                                 VIR_FILE_SHFS_SMB |
                                 VIR_FILE_SHFS_CIFS);
}


#if defined(__linux__) && defined(HAVE_SYS_MOUNT_H)
int
virFileSetupDev(const char *path,
                const char *mount_options)
{
    const unsigned long mount_flags = MS_NOSUID;
    const char *mount_fs = "tmpfs";
    int ret = -1;

    if (virFileMakePath(path) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %s"), path);
        goto cleanup;
    }

    VIR_DEBUG("Mount devfs on %s type=tmpfs flags=%lx, opts=%s",
              path, mount_flags, mount_options);
    if (mount("devfs", path, mount_fs, mount_flags, mount_options) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devfs on %s type %s (%s)"),
                             path, mount_fs, mount_options);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


int
virFileBindMountDevice(const char *src,
                       const char *dst)
{
    if (virFileTouch(dst, 0666) < 0)
        return -1;

    if (mount(src, dst, "none", MS_BIND, NULL) < 0) {
        virReportSystemError(errno, _("Failed to bind %s on to %s"), src,
                             dst);
        return -1;
    }

    return 0;
}


int
virFileMoveMount(const char *src,
                 const char *dst)
{
    const unsigned long mount_flags = MS_MOVE;

    if (mount(src, dst, NULL, mount_flags, NULL) < 0) {
        virReportSystemError(errno,
                             _("Unable to move %s mount to %s"),
                             src, dst);
        return -1;
    }

    return 0;
}


#else /* !defined(__linux__) || !defined(HAVE_SYS_MOUNT_H) */

int
virFileSetupDev(const char *path ATTRIBUTE_UNUSED,
                const char *mount_options ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount is not supported on this platform."));
    return -1;
}


int
virFileBindMountDevice(const char *src ATTRIBUTE_UNUSED,
                       const char *dst ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount is not supported on this platform."));
    return -1;
}


int
virFileMoveMount(const char *src ATTRIBUTE_UNUSED,
                 const char *dst ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount move is not supported on this platform."));
    return -1;
}
#endif /* !defined(__linux__) || !defined(HAVE_SYS_MOUNT_H) */


#if defined(HAVE_SYS_ACL_H)
int
virFileGetACLs(const char *file,
               void **acl)
{
    if (!(*acl = acl_get_file(file, ACL_TYPE_ACCESS)))
        return -1;

    return 0;
}


int
virFileSetACLs(const char *file,
               void *acl)
{
    if (acl_set_file(file, ACL_TYPE_ACCESS, acl) < 0)
        return -1;

    return 0;
}


void
virFileFreeACLs(void **acl)
{
    acl_free(*acl);
    *acl = NULL;
}

#else /* !defined(HAVE_SYS_ACL_H) */

int
virFileGetACLs(const char *file ATTRIBUTE_UNUSED,
               void **acl ATTRIBUTE_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}


int
virFileSetACLs(const char *file ATTRIBUTE_UNUSED,
               void *acl ATTRIBUTE_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}


void
virFileFreeACLs(void **acl)
{
    *acl = NULL;
}

#endif /* !defined(HAVE_SYS_ACL_H) */

int
virFileCopyACLs(const char *src,
                const char *dst)
{
    void *acl = NULL;
    int ret = -1;

    if (virFileGetACLs(src, &acl) < 0)
        return ret;

    if (virFileSetACLs(dst, acl) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virFileFreeACLs(&acl);
    return ret;
}
