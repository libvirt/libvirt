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

#include <fcntl.h>
#ifndef WIN32
# include <termios.h>
#endif
#ifdef WITH_PTY_H
/* Linux openpty */
# include <pty.h>
#endif
#ifdef WITH_UTIL_H
/* macOS openpty */
# include <util.h>
#endif
#ifdef WITH_LIBUTIL_H
/* FreeBSD openpty */
# include <libutil.h>
#endif
#include <sys/stat.h>
#if defined(WITH_SYS_MOUNT_H)
# include <sys/mount.h>
#endif
#include <unistd.h>
#include <dirent.h>
#if defined WITH_MNTENT_H && defined WITH_GETMNTENT_R
# include <mntent.h>
#endif
#if WITH_MMAP
# include <sys/mman.h>
#endif
#if WITH_SYS_SYSCALL_H
# include <sys/syscall.h>
#endif
#if WITH_LIBACL
# include <sys/acl.h>
#endif
#include <sys/file.h>

#ifdef __linux__
# include <linux/magic.h>
# include <sys/statfs.h>
# include <linux/loop.h>
# include <sys/ioctl.h>
# include <linux/cdrom.h>
/* These come from linux/fs.h, but that header conflicts with
 * sys/mount.h on glibc 2.36+ */
# define FS_IOC_GETFLAGS _IOR('f', 1, long)
# define FS_IOC_SETFLAGS _IOW('f', 2, long)
# define FS_NOCOW_FL 0x00800000
#endif

#if WITH_LIBATTR
# include <sys/xattr.h>
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
#include "virthread.h"
#include "virutil.h"
#include "virsocket.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.file");

#ifndef S_ISUID
# define S_ISUID 04000
#endif
#ifndef S_ISGID
# define S_ISGID 02000
#endif
#ifndef S_ISVTX
# define S_ISVTX 01000
#endif


#ifndef O_DIRECT
# define O_DIRECT 0
#endif

static virOnceControl virCloseRangeOnce = VIR_ONCE_CONTROL_INITIALIZER;
static bool virCloseRangeSupported;

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
                VIR_DEBUG("Failed to close fd %d: %s",
                          *fdptr, g_strerror(errno));
            }
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


static int
virCloseRangeImpl(unsigned int first G_GNUC_UNUSED,
                  unsigned int last G_GNUC_UNUSED)
{
#if defined(WITH_SYS_SYSCALL_H) && defined(__NR_close_range)
    return syscall(__NR_close_range, first, last, 0);
#endif

    errno = ENOSYS;
    return -1;
}


static void
virCloseRangeOnceInit(void)
{
    int fd[2] = {-1, -1};

    if (virPipeQuiet(fd) < 0)
        return;

    VIR_FORCE_CLOSE(fd[1]);
    if (virCloseRangeImpl(fd[0], fd[0]) < 0) {
        VIR_FORCE_CLOSE(fd[0]);
        return;
    }

    virCloseRangeSupported = true;
}


/**
 * virCloseRange:
 *
 * Closes all open file descriptors from @first to @last (included).
 *
 * Returns: 0 on success,
 *         -1 on failure (with errno set).
 */
int
virCloseRange(unsigned int first,
              unsigned int last)
{
    if (virCloseRangeInit() < 0)
        return -1;

    if (!virCloseRangeSupported) {
        errno = ENOSYS;
        return -1;
    }

    return virCloseRangeImpl(first, last);
}


/**
 * virCloseRangeInit:
 *
 * Detects whether close_range() is available and cache the result.
 */
int
virCloseRangeInit(void)
{
    if (virOnce(&virCloseRangeOnce, virCloseRangeOnceInit) < 0)
        return -1;

    return 0;
}


/**
 * virCloseRangeIsSupported:
 *
 * Returns whether close_range() is supported or not.
 */
bool
virCloseRangeIsSupported(void)
{
    if (virCloseRangeInit() < 0)
        return false;

    return virCloseRangeSupported;
}


/**
 * virCloseFrom:
 *
 * Closes all open file descriptors greater than or equal to @fromfd.
 *
 * Returns: 0 on success,
 *         -1 on error (with errno set).
 */
int
virCloseFrom(int fromfd)
{
#ifdef __FreeBSD__
    /* FreeBSD has closefrom() since FreeBSD-8.0, i.e. since 2009. */
    closefrom(fromfd);
    return 0;
#else /* !__FreeBSD__ */
    return virCloseRange(fromfd, ~0U);
#endif /* !__FreeBSD__ */
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
    bool closed; /* Whether virFileWrapperFdClose() has been already called */
    virCommand *cmd; /* Child iohelper process to do the I/O.  */
    char *err_msg; /* stderr of @cmd */
};

#ifndef WIN32

# ifdef __linux__

/**
 * virFileWrapperSetPipeSize:
 * @fd: the fd of the pipe
 *
 * Set best pipe size on the passed file descriptor for bulk transfers of data.
 *
 * default pipe size (usually 64K) is generally not suited for large transfers
 * to fast devices. A value of 1MB has been measured to improve virsh save
 * by 400% in ideal conditions. We retry multiple times with smaller sizes
 * on EPERM to account for possible small values of /proc/sys/fs/pipe-max-size.
 *
 * OS note: only for linux, on other OS this is a no-op.
 */
static int
virFileWrapperSetPipeSize(int fd)
{
    int sz;

    for (sz = 1024 * 1024; sz >= 64 * 1024; sz /= 2) {
        int rv = fcntl(fd, F_SETPIPE_SZ, sz);

        if (rv < 0 && errno == EPERM) {
            VIR_DEBUG("EPERM trying to set fd %d pipe size to %d", fd, sz);
            continue; /* retry with half the size */
        }
        if (rv < 0) {
            virReportSystemError(errno, "%s",
                                 _("unable to set pipe size"));
            return -1;
        }
        VIR_DEBUG("fd %d pipe size adjusted to %d", fd, sz);
        return 0;
    }

    VIR_WARN("unable to set pipe size, data transfer might be slow: %s",
             g_strerror(errno));
    return 0;
}

# else /* !__linux__ */
static int
virFileWrapperSetPipeSize(int fd G_GNUC_UNUSED)
{
    return 0;
}
# endif /* !__linux__ */


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
virFileWrapperFd *
virFileWrapperFdNew(int *fd, const char *name, unsigned int flags)
{
    virFileWrapperFd *ret = NULL;
    bool output = false;
    int pipefd[2] = { -1, -1 };
    int mode = -1;
    g_autofree char *iohelper_path = NULL;

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

    ret = g_new0(virFileWrapperFd, 1);

    mode = fcntl(*fd, F_GETFL);

    if (mode < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("invalid fd %1$d for %2$s"),
                       *fd, name);
        goto error;
    } else if ((mode & O_ACCMODE) == O_WRONLY) {
        output = true;
    } else if ((mode & O_ACCMODE) != O_RDONLY) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("unexpected mode 0x%1$x for %2$s"),
                       mode & O_ACCMODE, name);
        goto error;
    }

    if (virPipe(pipefd) < 0)
        goto error;

    if (virFileWrapperSetPipeSize(pipefd[output]) < 0)
        goto error;

    if (!(iohelper_path = virFileFindResource("libvirt_iohelper",
                                              abs_top_builddir "/src",
                                              LIBEXECDIR)))
        goto error;

    ret->cmd = virCommandNewArgList(iohelper_path, name, NULL);

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
    VIR_FORCE_CLOSE(pipefd[0]);
    VIR_FORCE_CLOSE(pipefd[1]);
    virFileWrapperFdFree(ret);
    return NULL;
}
#else /* WIN32 */
virFileWrapperFd *
virFileWrapperFdNew(int *fd G_GNUC_UNUSED,
                    const char *name G_GNUC_UNUSED,
                    unsigned int fdflags G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("virFileWrapperFd unsupported on this platform"));
    return NULL;
}
#endif /* WIN32 */

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
 *
 * This function can be safely called multiple times on the same @wfd.
 */
int
virFileWrapperFdClose(virFileWrapperFd *wfd)
{
    int ret;

    if (!wfd || wfd->closed)
        return 0;

    ret = virCommandWait(wfd->cmd, NULL);

    /* If the command used to process I/O has failed and produced some
     * messages on stderr, it's fair to assume those will be more
     * relevant to the user than whatever eg. QEMU can figure out on its
     * own having no knowledge of the fact a command is handling its I/O
     * in the first place, so it's okay if we end up discarding an
     * existing error here */
    if (ret < 0 && wfd->err_msg && *wfd->err_msg)
        virReportError(VIR_ERR_OPERATION_FAILED, "%s", wfd->err_msg);

    wfd->closed = true;

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
virFileWrapperFdFree(virFileWrapperFd *wfd)
{
    if (!wfd)
        return;

    g_free(wfd->err_msg);
    virCommandFree(wfd->cmd);
    g_free(wfd);
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


#else /* WIN32 */


int virFileLock(int fd G_GNUC_UNUSED,
                bool shared G_GNUC_UNUSED,
                off_t start G_GNUC_UNUSED,
                off_t len G_GNUC_UNUSED,
                bool waitForLock G_GNUC_UNUSED)
{
    return -ENOSYS;
}


int virFileUnlock(int fd G_GNUC_UNUSED,
                  off_t start G_GNUC_UNUSED,
                  off_t len G_GNUC_UNUSED)
{
    return -ENOSYS;
}


#endif /* WIN32 */


/**
 * virFileRewrite:
 * @path: file to rewrite
 * @mode: mode of the file
 * @uid: uid that should own file
 * @gid: gid that should own file
 * @rewrite: callback to write file contents
 * @opaque: opaque data to pass to the callback
 *
 * Rewrite given @path atomically. This is achieved by writing a
 * temporary file on a side and renaming it to the desired name.
 * The temporary file is created using supplied @mode and
 * @uid:@gid (pass -1 for current uid/gid) and written by
 * @rewrite callback. It's callback's responsibility to report
 * errors.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported)
 */
int
virFileRewrite(const char *path,
               mode_t mode,
               uid_t uid, gid_t gid,
               virFileRewriteFunc rewrite,
               const void *opaque)
{
    g_autofree char *newfile = NULL;
    int fd = -1;
    int ret = -1;
    int rc;

    newfile = g_strdup_printf("%s.new", path);

    if ((fd = virFileOpenAs(newfile, O_WRONLY | O_CREAT | O_TRUNC, mode,
                            uid, gid,
                            VIR_FILE_OPEN_FORCE_OWNER | VIR_FILE_OPEN_FORCE_MODE)) < 0) {
        virReportSystemError(-fd,
                             _("Failed to create file '%1$s'"),
                             newfile);
        goto cleanup;
    }

    if ((rc = rewrite(fd, newfile, opaque)) < 0) {
        goto cleanup;
    }

    if (g_fsync(fd) < 0) {
        virReportSystemError(errno, _("cannot sync file '%1$s'"),
                             newfile);
        goto cleanup;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("cannot save file '%1$s'"),
                             newfile);
        goto cleanup;
    }

    if (rename(newfile, path) < 0) {
        virReportSystemError(errno, _("cannot rename file '%1$s' as '%2$s'"),
                             newfile, path);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    unlink(newfile);
    return ret;
}


static int
virFileRewriteStrHelper(int fd,
                        const char *path,
                        const void *opaque)
{
    const char *data = opaque;

    if (safewrite(fd, data, strlen(data)) < 0) {
        virReportSystemError(errno,
                             _("cannot write data to file '%1$s'"),
                             path);
        return -1;
    }

    return 0;
}


int
virFileRewriteStr(const char *path,
                  mode_t mode,
                  const char *str)
{
    return virFileRewrite(path, mode, -1, -1,
                          virFileRewriteStrHelper, str);
}


/**
 * virFileResize:
 *
 * Change the capacity of the raw storage file at 'path'.
 */
int
virFileResize(const char *path,
              unsigned long long capacity,
              bool pre_allocate)
{
    int rc;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(path, O_RDWR)) < 0) {
        virReportSystemError(errno, _("Unable to open '%1$s'"), path);
        return -1;
    }

    if (pre_allocate) {
        if ((rc = virFileAllocate(fd, 0, capacity)) != 0) {
            if (rc == -2) {
                virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                               _("preallocate is not supported on this platform"));
            } else {
                virReportSystemError(errno,
                                     _("Failed to pre-allocate space for file '%1$s'"),
                                     path);
            }
            return -1;
        }
    }

    if (ftruncate(fd, capacity) < 0) {
        virReportSystemError(errno,
                             _("Failed to truncate file '%1$s'"), path);
        return -1;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Unable to save '%1$s'"), path);
        return -1;
    }

    return 0;
}


int virFileTouch(const char *path, mode_t mode)
{
    int fd = -1;

    if ((fd = open(path, O_WRONLY | O_CREAT, mode)) < 0) {
        virReportSystemError(errno, _("cannot create file '%1$s'"),
                             path);
        return -1;
    }

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("cannot save file '%1$s'"),
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
        virReportSystemError(errno, _("cannot stat '%1$s'"), path);
        return -1;
    }

    mode = sb.st_mode & MODE_BITS;

    if ((mode & mode_remove) == 0 && (mode & mode_add) == mode_add)
        return 0;

    mode &= MODE_BITS ^ mode_remove;
    mode |= mode_add;

    if (chmod(path, mode) < 0) {
        virReportSystemError(errno, _("cannot change permission of '%1$s'"),
                             path);
        return -1;
    }

    return 0;
}


#if defined(__linux__)

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

    looppath = g_strdup_printf("/dev/loop%i", devnr);

    if ((*fd = open(looppath, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %1$s"), looppath);
        VIR_FREE(looppath);
        return -1;
    }

    *dev_name = looppath;
    return 0;
}

static int virFileLoopDeviceOpenSearch(char **dev_name)
{
    int fd = -1;
    g_autoptr(DIR) dh = NULL;
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
            !g_ascii_isdigit(de->d_name[4]))
            continue;

        looppath = g_build_filename("/dev", de->d_name, NULL);

        VIR_DEBUG("Checking up on device %s", looppath);
        if ((fd = open(looppath, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %1$s"), looppath);
            goto cleanup;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &lo) < 0) {
            /* Got a free device, return the fd */
            if (errno == ENXIO)
                goto cleanup;

            VIR_FORCE_CLOSE(fd);
            virReportSystemError(errno,
                                 _("Unable to get loop status on %1$s"),
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
    return fd;
}

static int virFileLoopDeviceOpen(char **dev_name)
{
    int loop_fd = -1;

    if (virFileLoopDeviceOpenLoopCtl(dev_name, &loop_fd) < 0)
        return -1;

    VIR_DEBUG("Return from loop-control got fd %d", loop_fd);

    if (loop_fd >= 0)
        return loop_fd;

    /* Without the loop control device we just use the old technique. */
    loop_fd = virFileLoopDeviceOpenSearch(dev_name);

    return loop_fd;
}

int virFileLoopDeviceAssociate(const char *file,
                               char **dev)
{
    int lofd = -1;
    int fsfd = -1;
    struct loop_info64 lo = { 0 };
    g_autofree char *loname = NULL;
    int ret = -1;

    if ((lofd = virFileLoopDeviceOpen(&loname)) < 0)
        return -1;

    lo.lo_flags = LO_FLAGS_AUTOCLEAR;

    /* Set backing file name for LOOP_GET_STATUS64 queries */
    if (virStrcpy((char *) lo.lo_file_name, file, LO_NAME_SIZE) < 0) {
        virReportSystemError(errno,
                             _("Unable to set backing file %1$s"), file);
        goto cleanup;
    }

    if ((fsfd = open(file, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %1$s"), file);
        goto cleanup;
    }

    if (ioctl(lofd, LOOP_SET_FD, fsfd) < 0) {
        virReportSystemError(errno,
                             _("Unable to attach %1$s to loop device"),
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
    *dev = g_steal_pointer(&loname);

    ret = 0;

 cleanup:
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
    g_autofree char *path = NULL;

    path = g_build_filename(SYSFS_BLOCK_DIR, dev_name, "pid", NULL);

    if (!virFileExists(path)) {
        if (errno == ENOENT)
            return 0;
        else
            virReportSystemError(errno,
                                 _("Cannot check NBD device %1$s pid"),
                                 dev_name);
        return -1;
    }
    return 1;
}


static char *
virFileNBDDeviceFindUnused(void)
{
    g_autoptr(DIR) dh = NULL;
    struct dirent *de;
    int direrr;

    if (virDirOpen(&dh, SYSFS_BLOCK_DIR) < 0)
        return NULL;

    while ((direrr = virDirRead(dh, &de, SYSFS_BLOCK_DIR)) > 0) {
        if (STRPREFIX(de->d_name, "nbd")) {
            int rv = virFileNBDDeviceIsBusy(de->d_name);

            if (rv < 0)
                return NULL;

            if (rv == 0)
                return g_build_filename("/dev", de->d_name, NULL);
        }
    }
    if (direrr < 0)
        return NULL;

    virReportSystemError(EBUSY, "%s", _("No free NBD devices"));
    return NULL;
}

static bool
virFileNBDLoadDriver(void)
{
    if (virKModIsProhibited(NBD_DRIVER)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to load nbd module: administratively prohibited"));
        return false;
    } else {
        g_autofree char *errbuf = NULL;

        if ((errbuf = virKModLoad(NBD_DRIVER))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Failed to load nbd module"));
            return false;
        }
    }
    return true;
}

int virFileNBDDeviceAssociate(const char *file,
                              const char *fmtstr,
                              bool readonly,
                              char **dev)
{
    g_autofree char *nbddev = NULL;
    g_autofree char *qemunbd = NULL;
    g_autoptr(virCommand) cmd = NULL;

    if (!virFileNBDLoadDriver())
        return -1;

    if (!(nbddev = virFileNBDDeviceFindUnused()))
        return -1;

    if (!(qemunbd = virFindFileInPath("qemu-nbd"))) {
        virReportSystemError(ENOENT, "%s",
                             _("Unable to find 'qemu-nbd' binary in $PATH"));
        return -1;
    }

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
        return -1;

    VIR_DEBUG("Associated NBD device %s with file %s and format %s",
              nbddev, file, fmtstr);
    *dev = g_steal_pointer(&nbddev);

    return 0;
}

#else /* __linux__ */

int virFileLoopDeviceAssociate(const char *file,
                               char **dev G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to associate file %1$s with loop device"),
                         file);
    *dev = NULL;
    return -1;
}

int virFileNBDDeviceAssociate(const char *file,
                              const char *fmtstr G_GNUC_UNUSED,
                              bool readonly G_GNUC_UNUSED,
                              char **dev G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS,
                         _("Unable to associate file %1$s with NBD device"),
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
    g_autoptr(DIR) dh = NULL;
    struct dirent *de;
    int direrr;

    /* Silently return 0 if passed NULL or directory doesn't exist */
    if (!dir || !virFileExists(dir))
        return 0;

    if (virDirOpen(&dh, dir) < 0)
        return -1;

    while ((direrr = virDirRead(dh, &de, dir)) > 0) {
        g_autofree char *filepath = NULL;
        GStatBuf sb;

        filepath = g_build_filename(dir, de->d_name, NULL);

        if (g_lstat(filepath, &sb) < 0) {
            virReportSystemError(errno, _("Cannot access '%1$s'"),
                                 filepath);
            return -1;
        }

        if (S_ISDIR(sb.st_mode)) {
            if (virFileDeleteTree(filepath) < 0)
                return -1;
        } else {
            if (unlink(filepath) < 0 && errno != ENOENT) {
                virReportSystemError(errno,
                                     _("Cannot delete file '%1$s'"),
                                     filepath);
                return -1;
            }
        }
    }
    if (direrr < 0)
        return -1;

    if (rmdir(dir) < 0 && errno != ENOENT) {
        virReportSystemError(errno,
                             _("Cannot delete directory '%1$s'"),
                             dir);
        return -1;
    }

    return 0;
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

/* Like write(), but restarts after EINTR. Encouraged by sc_avoid_write.
 * Doesn't play nicely with nonblocking FD and EAGAIN, in which case
 * you want to use bare write() and mark it's use with sc_avoid_write.
 * Or even use virSocket() if the FD is related to a socket rather than a plain
 * file or pipe. */
ssize_t
safewrite(int fd, const void *buf, size_t count)
{
    size_t nwritten = 0;
    while (count > 0) {
        ssize_t r = write(fd, buf, count); /* sc_avoid_write */

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

#ifdef WITH_POSIX_FALLOCATE
static int
safezero_posix_fallocate(int fd, off_t offset, off_t len)
{
    int ret = posix_fallocate(fd, offset, len);
    if (ret == 0) {
        return 0;
    } else if (ret == EINVAL) {
        /* EINVAL is returned when either:
           - Operation is not supported by the underlying filesystem,
           - offset or len argument values are invalid.
           Assuming that offset and len are valid, this error means
           the operation is not supported, and we need to fall back
           to other methods.
        */
        return -2;
    }

    errno = ret;
    return -1;
}
#else /* !WITH_POSIX_FALLOCATE */
static int
safezero_posix_fallocate(int fd G_GNUC_UNUSED,
                         off_t offset G_GNUC_UNUSED,
                         off_t len G_GNUC_UNUSED)
{
    return -2;
}
#endif /* !WITH_POSIX_FALLOCATE */

#if WITH_SYS_SYSCALL_H && defined(SYS_fallocate)
static int
safezero_sys_fallocate(int fd,
                       off_t offset,
                       off_t len)
{
    return syscall(SYS_fallocate, fd, 0, offset, len);
}
#else /* !WITH_SYS_SYSCALL_H || !defined(SYS_fallocate) */
static int
safezero_sys_fallocate(int fd G_GNUC_UNUSED,
                       off_t offset G_GNUC_UNUSED,
                       off_t len G_GNUC_UNUSED)
{
    return -2;
}
#endif /* !WITH_SYS_SYSCALL_H || !defined(SYS_fallocate) */

#ifdef WITH_MMAP
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
#else /* !WITH_MMAP */
static int
safezero_mmap(int fd G_GNUC_UNUSED,
              off_t offset G_GNUC_UNUSED,
              off_t len G_GNUC_UNUSED)
{
    return -2;
}
#endif /* !WITH_MMAP */

static int
safezero_slow(int fd, off_t offset, off_t len)
{
    int r;
    g_autofree char *buf = NULL;
    unsigned long long remain, bytes;

    if (lseek(fd, offset, SEEK_SET) < 0)
        return -1;

    /* Split up the write in small chunks so as not to allocate lots of RAM */
    remain = len;
    bytes = MIN(1024 * 1024, len);

    buf = g_new0(char, bytes);

    while (remain) {
        if (bytes > remain)
            bytes = remain;

        r = safewrite(fd, buf, bytes);
        if (r < 0)
            return -1;

        /* safewrite() guarantees all data will be written */
        remain -= bytes;
    }
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

int virFileAllocate(int fd, off_t offset, off_t len)
{
    int ret;

    ret = safezero_posix_fallocate(fd, offset, len);
    if (ret != -2)
        return ret;

    return safezero_sys_fallocate(fd, offset, len);
}

#if defined WITH_MNTENT_H && defined WITH_GETMNTENT_R
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
            ret = g_strdup(mb.mnt_dir);
            goto cleanup;
        }
    }

    if (!ret)
        errno = ENOENT;

 cleanup:
    endmntent(f);

    return ret;
}

#else /* defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */

char *
virFileFindMountPoint(const char *type G_GNUC_UNUSED)
{
    errno = ENOSYS;

    return NULL;
}

#endif /* defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */

/* Read no more than the specified maximum number of bytes. */
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

            VIR_REALLOC_N(buf, alloc);
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


int
virFileReadHeaderQuiet(const char *path,
                       int maxlen,
                       char **buf)
{
    int fd;
    int len;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    len = virFileReadHeaderFD(fd, maxlen, buf);
    VIR_FORCE_CLOSE(fd);

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
    s = saferead_lim(fd, (size_t) maxlen + 1, &len);
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
    int fd;
    int len;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        virReportSystemError(errno, _("Failed to open file '%1$s'"), path);
        return -1;
    }

    len = virFileReadLimFD(fd, maxlen, buf);
    VIR_FORCE_CLOSE(fd);
    if (len < 0) {
        virReportSystemError(errno, _("Failed to read file '%1$s'"), path);
        return -1;
    }

    return len;
}

int
virFileReadAllQuiet(const char *path, int maxlen, char **buf)
{
    int fd;
    int len;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -errno;

    len = virFileReadLimFD(fd, maxlen, buf);
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
    g_autofree char *candidate = NULL;

    if (*checkLink == '/')
        return virFileLinkPointsTo(checkLink, checkDest);
    if (!directory) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot resolve '%1$s' without starting directory"),
                       checkLink);
        return -1;
    }
    candidate = g_build_filename(directory, checkLink, NULL);
    return virFileLinkPointsTo(candidate, checkDest);
}


static int
virFileResolveLinkHelper(const char *linkpath,
                         bool intermediatePaths,
                         char **resultpath)
{
    GStatBuf st;

    *resultpath = NULL;

    /* We don't need the full canonicalization of intermediate
     * directories, if linkpath is absolute and the basename is
     * already a non-symlink.  */
    if (g_path_is_absolute(linkpath) && !intermediatePaths) {
        if (g_lstat(linkpath, &st) < 0)
            return -1;

#ifndef WIN32
        if (!S_ISLNK(st.st_mode)) {
            *resultpath = g_strdup(linkpath);
            return 0;
        }
#endif /* WIN32 */
    }

    *resultpath = virFileCanonicalizePath(linkpath);

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
    GStatBuf st;

    /* Still do this on Windows so we report
     * errors like ENOENT, etc
     */
    if (g_lstat(linkpath, &st) < 0)
        return -errno;

#ifndef WIN32
    return S_ISLNK(st.st_mode) != 0;
#else /* WIN32 */
    return 0;
#endif /* WIN32 */
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
    return virFindFileInPathFull(file, NULL);
}

/* virFindFileInPathFull:
 * @file: name of the program
 * @extraDirs: NULL-terminated list of additional directories
 *
 * Like virFindFileInPath(), but in addition to searching $PATH also
 * looks into all directories listed in @extraDirs. This is useful to
 * locate helpers that are installed outside of $PATH.
 *
 * The returned path must be freed by the caller.
 *
 * Returns: absolute path of the program or NULL
 */
char *
virFindFileInPathFull(const char *file,
                      const char *const *extraDirs)
{
    g_autofree char *path = NULL;
    if (file == NULL)
        return NULL;

    path = g_find_program_in_path(file);

    if (path) {
        /* Workaround for a bug in g_find_program_in_path() not returning absolute
         * path as documented. TODO drop it once we require GLib >= 2.69.0
         */
        return g_canonicalize_filename(path, NULL);
    }

    if (extraDirs) {
        while (*extraDirs) {
            g_autofree char *extraPath = NULL;

            extraPath = g_strdup_printf("%s/%s", *extraDirs, file);

            if (virFileIsExecutable(extraPath)) {
                return g_steal_pointer(&extraPath);
            }

            extraDirs++;
        }
    }

    return NULL;
}


static bool useDirOverride;

/**
 * virFileFindResourceFull:
 * @filename: libvirt distributed filename without any path
 * @prefix: optional string to prepend to filename
 * @suffix: optional string to append to filename
 * @builddir: location of the filename in the build tree including
 *            abs_top_srcdir or abs_top_builddir prefix
 * @installdir: location of the installed binary
 * @envname: environment variable used to override all dirs
 *
 * A helper which will return a path to @filename within
 * the current build tree, if the calling binary is being
 * run from the source tree. Otherwise it will return the
 * path in the installed location.
 *
 * Note that this function does not actually check whether
 * the file exists on disk, it merely builds the fully
 * qualified path where it is supposed to exist.
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
    const char *envval = envname ? getenv(envname) : NULL;
    const char *path;
    g_autofree char *fullFilename = NULL;

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

    fullFilename = g_strdup_printf("%s%s%s", prefix, filename, suffix);
    ret = g_build_filename(path, fullFilename, NULL);

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
 * virFileActivateDirOverrideForProg:
 * @argv0: argv[0] of the calling program
 *
 * Canonicalize current process path from argv0 and check if abs_top_builddir
 * matches as prefix in the path.
 */
void
virFileActivateDirOverrideForProg(const char *argv0)
{
    g_autofree char *path = virFileCanonicalizePath(argv0);

    if (!path) {
        VIR_DEBUG("Failed to get canonicalized path errno=%d", errno);
        return;
    }

    if (STRPREFIX(path, abs_top_builddir)) {
        useDirOverride = true;
        VIR_DEBUG("Activating build dir override for %s", path);
    }
}


/**
 * virFileActivateDirOverrideForLib:
 *
 * Look for LIBVIRT_DIR_OVERRIDE env var to see if we should find files from
 * the build/src tree instead of install tree.
 */
void
virFileActivateDirOverrideForLib(void)
{
    if (getenv("LIBVIRT_DIR_OVERRIDE") != NULL)
        useDirOverride = true;
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


bool
virFileIsRegular(const char *path)
{
    struct stat s;
    return (stat(path, &s) == 0) && S_ISREG(s.st_mode);
}


/**
 * virFileExists: Check for presence of file
 * @path: Path of file to check
 *
 * Returns true if the file exists, false if it doesn't, setting errno
 * appropriately.
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
    g_autofree char *parent = NULL;
    int ret;
    struct stat sb1, sb2;

    parent = g_path_get_dirname(file);

    VIR_DEBUG("Comparing '%s' to '%s'", file, parent);

    if (stat(file, &sb1) < 0) {
        if (errno == ENOENT)
            return 0;
        else
            virReportSystemError(errno,
                                 _("Cannot stat '%1$s'"),
                                 file);
        return -1;
    }

    if (stat(parent, &sb2) < 0) {
        virReportSystemError(errno,
                             _("Cannot stat '%1$s'"),
                             parent);
        return -1;
    }

    if (!S_ISDIR(sb1.st_mode))
        return 0;

    ret = sb1.st_dev != sb2.st_dev;
    VIR_DEBUG("Is mount %d", ret);

    return ret;
}


#if defined(__linux__)
/**
 * virFileIsCDROM:
 * @path: File to check
 *
 * Returns 1 if @path is a cdrom device 0 if it is not a cdrom and -1 on
 * error. 'errno' of the failure is preserved and no libvirt errors are
 * reported.
 */
int
virFileIsCDROM(const char *path)
{
    struct stat st;
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(path, O_RDONLY | O_NONBLOCK)) < 0)
        return -1;

    if (fstat(fd, &st) < 0)
        return -1;

    if (!S_ISBLK(st.st_mode))
        return 0;

    /* Attempt to detect via a CDROM specific ioctl */
    if (ioctl(fd, CDROM_DRIVE_STATUS, CDSL_CURRENT) >= 0)
        return 1;

    return 0;
}

#else

int
virFileIsCDROM(const char *path)
{
    if (STRPREFIX(path, "/dev/cd") ||
        STRPREFIX(path, "/dev/acd"))
        return 1;

    return 0;
}

#endif /* defined(__linux__) */


#if defined WITH_MNTENT_H && defined WITH_GETMNTENT_R
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
    char **mounts = NULL;
    size_t nmounts = 0;

    VIR_DEBUG("prefix=%s", prefix);

    *mountsret = NULL;
    *nmountsret = 0;

    if (!(procmnt = setmntent(mtabpath, "r"))) {
        virReportSystemError(errno,
                             _("Failed to read %1$s"), mtabpath);
        return -1;
    }

    while (getmntent_r(procmnt, &mntent, mntbuf, sizeof(mntbuf)) != NULL) {
        if (!(STREQ(mntent.mnt_dir, prefix) ||
              (STRPREFIX(mntent.mnt_dir, prefix) &&
               mntent.mnt_dir[strlen(prefix)] == '/')))
            continue;

        VIR_EXPAND_N(mounts, nmounts, nmounts ? 1 : 2);
        mounts[nmounts - 2] = g_strdup(mntent.mnt_dir);
    }

    if (mounts)
        qsort(mounts, nmounts - 1, sizeof(mounts[0]),
              reverse ? virStringSortRevCompare : virStringSortCompare);

    *mountsret = mounts;
    *nmountsret = nmounts ? nmounts - 1 : 0;
    endmntent(procmnt);
    return 0;
}
#else /* ! defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */
static int
virFileGetMountSubtreeImpl(const char *mtabpath G_GNUC_UNUSED,
                           const char *prefix G_GNUC_UNUSED,
                           char ***mountsret G_GNUC_UNUSED,
                           size_t *nmountsret G_GNUC_UNUSED,
                           bool reverse G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Unable to determine mount table on this platform"));
    return -1;
}
#endif /* ! defined WITH_MNTENT_H && defined WITH_GETMNTENT_R */

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
 * be freed with g_strfreev
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
 * be freed with g_strfreev
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
    g_autofree gid_t *groups = NULL;
    int ngroups;

    if (uid == geteuid() &&
        gid == getegid())
        return access(path, mode);

    ngroups = virGetGroupList(uid, gid, &groups);
    if (ngroups < 0)
        return -1;

    pid = virFork();

    if (pid < 0)
        return -1;

    if (pid) { /* parent */
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
        virReportSystemError(errno, _("stat of '%1$s' failed"), path);
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
                             _("cannot chown '%1$s' to (%2$u, %3$u)"),
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
                             _("cannot set mode of '%1$s' to %2$04o"),
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
    g_autofree gid_t *groups = NULL;
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
                             _("failed to create socket needed for '%1$s'"),
                             path);
        return ret;
    }

    pid = virFork();
    if (pid < 0)
        return -errno;

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
                                 _("child process failed to create file '%1$s'"),
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
                                 _("child process failed to force owner mode file '%1$s'"),
                                 path);
            goto childerror;
        }

        do {
            ret = virSocketSendFD(pair[1], fd);
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

    VIR_FORCE_CLOSE(pair[1]);

    do {
        fd = virSocketRecvFD(pair[0], 0);
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
                             _("failed recvfd for child creating '%1$s'"),
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
    g_autofree gid_t *groups = NULL;
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

    if (pid < 0)
        return -errno;

    if (pid) { /* parent */
        /* wait for child to complete, and retrieve its exit code */

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
            virReportSystemError(errno, _("failed to create directory '%1$s'"),
                                 path);
            goto error;
        }
        created = true;
    }

    if (stat(path, &st) == -1) {
        ret = -errno;
        virReportSystemError(errno, _("stat of '%1$s' failed"), path);
        goto error;
    }

    if (((uid != (uid_t) -1 && st.st_uid != uid) ||
         (gid != (gid_t) -1 && st.st_gid != gid))
        && (chown(path, uid, gid) < 0)) {
        ret = -errno;
        virReportSystemError(errno, _("cannot chown '%1$s' to (%2$u, %3$u)"),
                             path, (unsigned int) uid, (unsigned int) gid);
        goto error;
    }

    if (mode != (mode_t) -1 && chmod(path, mode) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot set mode of '%1$s' to %2$04o"),
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
    g_autofree gid_t *groups = NULL;
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

    if (pid < 0)
        return -errno;

    if (pid) { /* parent */
        /* wait for child to complete, and retrieve its exit code */

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
            virReportSystemError(errno, _("child failed to create directory '%1$s'"),
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
                             _("stat of '%1$s' failed"), path);
        goto childerror;
    }

    if ((st.st_gid != gid) && (chown(path, (uid_t) -1, gid) < 0)) {
        ret = errno;
        virReportSystemError(errno,
                             _("cannot chown '%1$s' to group %2$u"),
                             path, (unsigned int) gid);
        goto childerror;
    }

    if (mode != (mode_t) -1 && chmod(path, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%1$s' to %2$04o"),
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
                    uid_t uid G_GNUC_UNUSED,
                    gid_t gid G_GNUC_UNUSED)
{
    VIR_WARN("Ignoring uid/gid due to WIN32");

    return access(path, mode);
}

/* return -errno on failure, or 0 on success */
int
virFileOpenAs(const char *path G_GNUC_UNUSED,
              int openflags G_GNUC_UNUSED,
              mode_t mode G_GNUC_UNUSED,
              uid_t uid G_GNUC_UNUSED,
              gid_t gid G_GNUC_UNUSED,
              unsigned int flags_unused G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virFileOpenAs is not implemented for WIN32"));

    return -ENOSYS;
}

int
virDirCreate(const char *path G_GNUC_UNUSED,
             mode_t mode G_GNUC_UNUSED,
             uid_t uid G_GNUC_UNUSED,
             gid_t gid G_GNUC_UNUSED,
             unsigned int flags_unused G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("virDirCreate is not implemented for WIN32"));

    return -ENOSYS;
}

int
virFileRemove(const char *path,
              uid_t uid G_GNUC_UNUSED,
              gid_t gid G_GNUC_UNUSED)
{
    if (unlink(path) < 0) {
        virReportSystemError(errno, _("Unable to unlink path '%1$s'"),
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
        virReportSystemError(errno, _("cannot open directory '%1$s'"), name);
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
 * @ent: output one entry
 * @name: if non-NULL, the name related to @dirp for use in error reporting
 *
 * Wrapper around readdir. Typical usage:
 *   g_autoptr(DIR) dir = NULL;
 *   struct dirent *ent;
 *   int rc;
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
                virReportSystemError(errno, _("Unable to read directory '%1$s'"),
                                     name);
            return -1;
        }
    } while (*ent && (STREQ((*ent)->d_name, ".") ||
                      STREQ((*ent)->d_name, "..")));
    return !!*ent;
}

void virDirClose(DIR *dirp)
{
    if (!dirp)
        return;

    closedir(dirp); /* exempt from syntax-check */
}

/**
 * virDirIsEmpty:
 * @path: path to the directory
 * @hidden: whether hidden files matter
 *
 * Check whether given directory (@path) is empty, i.e. it
 * contains just the usual entries '.' and '..'. Hidden files are
 * ignored unless @hidden is true. IOW, a directory containing
 * nothing but hidden files is considered empty if @hidden is
 * false and not empty if @hidden is true.
 *
 * Returns: 1 if the directory is empty,
 *          0 if the directory is not empty,
 *         -1 otherwise (no error reported).
 */
int virDirIsEmpty(const char *path,
                  bool hidden)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *ent;
    int direrr;

    if (virDirOpenQuiet(&dir, path) < 0)
        return -1;

    while ((direrr = virDirRead(dir, &ent, NULL)) > 0) {
        /* virDirRead() skips over '.' and '..' so here we have
         * actual directory entry. */
        if (!hidden ||
            (hidden && ent->d_name[0] != '.'))
            return 0;
    }

    if (direrr < 0)
        return -1;

    return 1;
}


/*
 * virFileChownFiles:
 * @name: name of the directory
 * @uid: uid
 * @gid: gid
 *
 * Change ownership of all regular files in a directory.
 *
 * Returns -1 on error, with error already reported, 0 on success.
 */
#ifndef WIN32
int virFileChownFiles(const char *name,
                      uid_t uid,
                      gid_t gid)
{
    struct dirent *ent;
    int direrr;
    g_autoptr(DIR) dir = NULL;

    if (virDirOpen(&dir, name) < 0)
        return -1;

    while ((direrr = virDirRead(dir, &ent, name)) > 0) {
        g_autofree char *path = NULL;

        path = g_build_filename(name, ent->d_name, NULL);

        if (!virFileIsRegular(path))
            continue;

        if (chown(path, uid, gid) < 0) {
            virReportSystemError(errno,
                                 _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                 ent->d_name, (unsigned int) uid,
                                 (unsigned int) gid);
            return -1;
        }
    }

    if (direrr < 0)
        return -1;

    return 0;
}

#else /* WIN32 */

int virFileChownFiles(const char *name,
                      uid_t uid,
                      gid_t gid)
{
    virReportSystemError(ENOSYS,
                         _("cannot chown '%1$s' to (%2$u, %3$u)"),
                         name, (unsigned int) uid,
                         (unsigned int) gid);
    return -1;
}
#endif /* WIN32 */

int
virFileMakeParentPath(const char *path)
{
    char *p;
    g_autofree char *tmp = NULL;

    VIR_DEBUG("path=%s", path);

    tmp = g_strdup(path);

    if ((p = strrchr(tmp, '/')) == NULL) {
        errno = EINVAL;
        return -1;
    }
    *p = '\0';

    return g_mkdir_with_parents(tmp, 0777);
}


/* Build up a fully qualified path for a config file to be
 * associated with a persistent guest or network */
char *
virFileBuildPath(const char *dir, const char *name, const char *ext)
{
    char *path;

    if (ext == NULL) {
        path = g_build_filename(dir, name, NULL);
    } else {
        g_autofree char *extName = g_strdup_printf("%s%s", name, ext);
        path = g_build_filename(dir, extName, NULL);
    }

    return path;
}

/* Open a non-blocking primary side of a pty. If ttyName is not NULL,
 * then populate it with the name of the secondary peer. If rawmode is
 * set, also put the primary side into raw mode before returning.  */
#ifndef WIN32
int
virFileOpenTty(int *ttyprimary, char **ttyName, int rawmode)
{
    /* XXX A word of caution - on some platforms (Solaris and HP-UX),
     * additional ioctl() calls are needs after opening the secondary
     * before it will cause isatty() to return true.  Should we make
     * virFileOpenTty also return the opened secondary fd, so the caller
     * doesn't have to worry about that mess?  */
    int ret = -1;
    int secondary = -1;
    g_autofree char *name = NULL;

    /* Unfortunately, we can't use the name argument of openpty, since
     * there is no guarantee on how large the buffer has to be.
     * Likewise, we can't use the termios argument: we have to use
     * read-modify-write since there is no portable way to initialize
     * a struct termios without use of tcgetattr.  */
    if (openpty(ttyprimary, &secondary, NULL, NULL, NULL) < 0)
        return -1;

    /* What a shame that openpty cannot atomically set FD_CLOEXEC, but
     * that using posix_openpt/grantpt/unlockpt/ptsname is not
     * thread-safe, and that ptsname_r is not portable.  */
    if (virSetNonBlock(*ttyprimary) < 0 ||
        virSetCloseExec(*ttyprimary) < 0)
        goto cleanup;

    /* While Linux supports tcgetattr on either the primary or the
     * secondary, Solaris requires it to be on the secondary.  */
    if (rawmode) {
        struct termios ttyAttr;
        if (tcgetattr(secondary, &ttyAttr) < 0)
            goto cleanup;

        cfmakeraw(&ttyAttr);

        if (tcsetattr(secondary, TCSADRAIN, &ttyAttr) < 0)
            goto cleanup;
    }

    /* ttyname_r on the secondary is required by POSIX, while ptsname_r on
     * the primary is a glibc extension, and the POSIX ptsname is not
     * thread-safe.  Since openpty gave us both descriptors, guess
     * which way we will determine the name?  :)  */
    if (ttyName) {
        /* Initial guess of 64 is generally sufficient; rely on ERANGE
         * to tell us if we need to grow.  */
        size_t len = 64;
        int rc;

        name = g_new0(char, len);

        while ((rc = ttyname_r(secondary, name, len)) == ERANGE) {
            VIR_RESIZE_N(name, len, len, len);
        }
        if (rc != 0) {
            errno = rc;
            goto cleanup;
        }
        *ttyName = g_steal_pointer(&name);
    }

    ret = 0;

 cleanup:
    if (ret != 0)
        VIR_FORCE_CLOSE(*ttyprimary);
    VIR_FORCE_CLOSE(secondary);

    return ret;
}
#else /* WIN32 */
int
virFileOpenTty(int *ttyprimary G_GNUC_UNUSED,
               char **ttyName G_GNUC_UNUSED,
               int rawmode G_GNUC_UNUSED)
{
    /* mingw completely lacks pseudo-terminals */
    errno = ENOSYS;
    return -1;
}
#endif /* WIN32 */

/* Remove spurious / characters from a path. The result must be freed */
char *
virFileSanitizePath(const char *path)
{
    const char *cur = path;
    char *uri;
    char *cleanpath;
    int idx = 0;

    cleanpath = g_strdup(path);

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
 * virFileCanonicalizePath:
 *
 * Returns the canonical representation of @path.
 *
 * The returned string must be freed after use.
 */
char *
virFileCanonicalizePath(const char *path)
{
#ifdef WIN32
    /* Does not resolve symlinks, only expands . & .. & repeated /.
     * It will never fail, so sanitize errno to indicate success */
    errno = 0;
    return g_canonicalize_filename(path, NULL);
#else
    return realpath(path, NULL); /* exempt from syntax-check */
#endif
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

    if ((tmp = strrchr(path, G_DIR_SEPARATOR)))
        tmp[1] = '\0';
    else
        path[0] = '\0';
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
# ifndef FUSE_SUPER_MAGIC
#  define FUSE_SUPER_MAGIC 0x65735546
# endif
# ifndef CEPH_SUPER_MAGIC
#  define CEPH_SUPER_MAGIC 0x00C36400
# endif
# ifndef GPFS_SUPER_MAGIC
#  define GPFS_SUPER_MAGIC 0x47504653
# endif

# define VIR_ACFS_MAGIC 0x61636673
/* https://git.beegfs.io/pub/v7/-/blob/master/client_module/source/filesystem/FhgfsOpsSuper.h#L14 */
# define VIR_BEEGFS_MAGIC 0x19830326 /* formerly fhgfs */

# define PROC_MOUNTS "/proc/mounts"


struct virFileSharedFsData {
    const char *mnttype;
    unsigned int magic;
    unsigned int fstype;
};

static const struct virFileSharedFsData virFileSharedFsFUSE[] = {
    { .mnttype = "fuse.glusterfs", .fstype = VIR_FILE_SHFS_GLUSTERFS },
    { .mnttype = "fuse.quobyte", .fstype = VIR_FILE_SHFS_QB },
};

static int
virFileIsSharedFsFUSE(const char *path,
                      unsigned int fstypes)
{
    FILE *f = NULL;
    struct mntent mb;
    char mntbuf[1024];
    g_autofree char *canonPath = NULL;
    size_t maxMatching = 0;
    bool isShared = false;

    if (!(canonPath = virFileCanonicalizePath(path))) {
        virReportSystemError(errno, _("unable to canonicalize %1$s"), path);
        return -1;
    }

    VIR_DEBUG("Path canonicalization: %s->%s", path, canonPath);

    if (!(f = setmntent(PROC_MOUNTS, "r"))) {
        virReportSystemError(errno, _("Unable to open %1$s"), PROC_MOUNTS);
        return -1;
    }

    while (getmntent_r(f, &mb, mntbuf, sizeof(mntbuf))) {
        const char *p;
        size_t len = strlen(mb.mnt_dir);

        if (!(p = STRSKIP(canonPath, mb.mnt_dir)))
            continue;

        if (*(p - 1) != '/' && *p != '/' && *p != '\0')
            continue;

        if (len > maxMatching) {
            size_t i;
            bool found = false;

            for (i = 0; i < G_N_ELEMENTS(virFileSharedFsFUSE); i++) {
                if (STREQ_NULLABLE(mb.mnt_type, virFileSharedFsFUSE[i].mnttype) &&
                    (fstypes & virFileSharedFsFUSE[i].fstype) > 0) {
                    found = true;
                    break;
                }
            }

            VIR_DEBUG("Updating shared='%d' for mountpoint '%s' type '%s'",
                      found, p, mb.mnt_type);

            isShared = found;
            maxMatching = len;
        }
    }

    endmntent(f);

    if (isShared)
        return 1;

    return 0;
}


static const struct virFileSharedFsData virFileSharedFs[] = {
    { .fstype = VIR_FILE_SHFS_NFS, .magic = NFS_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_GFS2, .magic = GFS2_MAGIC },
    { .fstype = VIR_FILE_SHFS_OCFS, .magic = OCFS2_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_AFS, .magic = AFS_FS_MAGIC },
    { .fstype = VIR_FILE_SHFS_SMB, .magic = SMB_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_CIFS, .magic = CIFS_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_CEPH, .magic = CEPH_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_GPFS, .magic = GPFS_SUPER_MAGIC },
    { .fstype = VIR_FILE_SHFS_ACFS, .magic = VIR_ACFS_MAGIC },
    { .fstype = VIR_FILE_SHFS_BEEGFS, .magic = VIR_BEEGFS_MAGIC },
};


int
virFileIsSharedFSType(const char *path,
                      unsigned int fstypes)
{
    g_autofree char *dirpath = NULL;
    char *p = NULL;
    struct statfs sb;
    int statfs_ret;
    long long f_type = 0;
    size_t i;

    dirpath = g_strdup(path);

    statfs_ret = statfs(dirpath, &sb);

    while ((statfs_ret < 0) && (p != dirpath)) {
        /* Try less and less of the path until we get to a
         * directory we can stat. Even if we don't have 'x'
         * permission on any directory in the path on the NFS
         * server (assuming it's NFS), we will be able to stat the
         * mount point, and that will properly tell us if the
         * fstype is NFS.
         */

        if ((p = strrchr(dirpath, '/')) == NULL) {
            virReportSystemError(EINVAL,
                                 _("Invalid relative path '%1$s'"), path);
            return -1;
        }

        if (p == dirpath)
            *(p+1) = '\0';
        else
            *p = '\0';

        statfs_ret = statfs(dirpath, &sb);
    }

    if (statfs_ret < 0) {
        virReportSystemError(errno,
                             _("cannot determine filesystem for '%1$s'"),
                             path);
        return -1;
    }

    f_type = sb.f_type;

    if (f_type == FUSE_SUPER_MAGIC) {
        VIR_DEBUG("Found FUSE mount for path=%s", path);
        return virFileIsSharedFsFUSE(path, fstypes);
    }

    VIR_DEBUG("Check if path %s with FS magic %lld is shared",
              path, f_type);

    for (i = 0; i < G_N_ELEMENTS(virFileSharedFs); i++) {
        if (f_type == virFileSharedFs[i].magic &&
            (fstypes & virFileSharedFs[i].fstype) > 0)
            return 1;
    }

    return 0;
}

int
virFileGetHugepageSize(const char *path,
                       unsigned long long *size)
{
    struct statfs fs;

    if (statfs(path, &fs) < 0) {
        virReportSystemError(errno,
                             _("cannot determine filesystem for '%1$s'"),
                             path);
        return -1;
    }

    if (fs.f_type != HUGETLBFS_MAGIC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("not a hugetlbfs mount: '%1$s'"),
                       path);
        return -1;
    }

    *size = fs.f_bsize / 1024; /* we are storing size in KiB */

    return 0;
}

# define PROC_MEMINFO "/proc/meminfo"
# define HUGEPAGESIZE_STR "Hugepagesize:"

static int
virFileGetDefaultHugepageSize(unsigned long long *size)
{
    g_autofree char *meminfo = NULL;
    char *c;
    char *n;
    char *unit;

    if (virFileReadAll(PROC_MEMINFO, 4096, &meminfo) < 0)
        return -1;

    if (!(c = strstr(meminfo, HUGEPAGESIZE_STR))) {
        virReportError(VIR_ERR_NO_SUPPORT,
                       _("%1$s not found in %2$s"),
                       HUGEPAGESIZE_STR,
                       PROC_MEMINFO);
        return -1;
    }
    c += strlen(HUGEPAGESIZE_STR);

    if ((n = strchr(c, '\n'))) {
        /* Cut off the rest of the meminfo file */
        *n = '\0';
    }

    if (virStrToLong_ull(c, &unit, 10, size) < 0 || STRNEQ(unit, " kB")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse %1$s %2$s"),
                       HUGEPAGESIZE_STR, c);
        return -1;
    }

    return 0;
}

int
virFileFindHugeTLBFS(virHugeTLBFS **ret_fs,
                     size_t *ret_nfs)
{
    int ret = -1;
    FILE *f = NULL;
    struct mntent mb;
    char mntbuf[1024];
    virHugeTLBFS *fs = NULL;
    size_t nfs = 0;
    unsigned long long default_hugepagesz = 0;

    if (!(f = setmntent(PROC_MOUNTS, "r"))) {
        virReportSystemError(errno,
                             _("Unable to open %1$s"),
                             PROC_MOUNTS);
        goto cleanup;
    }

    while (getmntent_r(f, &mb, mntbuf, sizeof(mntbuf))) {
        virHugeTLBFS *tmp;

        if (STRNEQ(mb.mnt_type, "hugetlbfs"))
            continue;

        VIR_EXPAND_N(fs, nfs, 1);

        tmp = &fs[nfs - 1];

        tmp->mnt_dir = g_strdup(mb.mnt_dir);

        if (virFileGetHugepageSize(tmp->mnt_dir, &tmp->size) < 0)
            goto cleanup;

        if (!default_hugepagesz &&
            virFileGetDefaultHugepageSize(&default_hugepagesz) < 0)
            goto cleanup;

        tmp->deflt = tmp->size == default_hugepagesz;
    }

    *ret_nfs = nfs;
    *ret_fs = g_steal_pointer(&fs);
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

int virFileIsSharedFSType(const char *path G_GNUC_UNUSED,
                          unsigned int fstypes G_GNUC_UNUSED)
{
    /* XXX implement me :-) */
    return 0;
}

int
virFileGetHugepageSize(const char *path G_GNUC_UNUSED,
                       unsigned long long *size G_GNUC_UNUSED)
{
    /* XXX implement me :-) */
    virReportUnsupportedError();
    return -1;
}

int
virFileFindHugeTLBFS(virHugeTLBFS **ret_fs G_GNUC_UNUSED,
                     size_t *ret_nfs G_GNUC_UNUSED)
{
    /* XXX implement me :-) */
    virReportUnsupportedError();
    return -1;
}
#endif /* defined __linux__ */

/**
 * virFileGetDefaultHugepage:
 * @fs: array of hugetlbfs mount points
 * @nfs: number of items in @fs
 *
 * In the passed array of hugetlbfs mount points @fs find the
 * default one. It's the one which has no '-o pagesize'.
 *
 * Returns: default hugepage, or
 *          NULL if none found
 */
virHugeTLBFS *
virFileGetDefaultHugepage(virHugeTLBFS *fs,
                          size_t nfs)
{
    size_t i;

    for (i = 0; i < nfs; i++) {
        if (fs[i].deflt)
            return &fs[i];
    }

    return NULL;
}

int virFileIsSharedFS(const char *path)
{
    return virFileIsSharedFSType(path,
                                 VIR_FILE_SHFS_NFS |
                                 VIR_FILE_SHFS_GFS2 |
                                 VIR_FILE_SHFS_OCFS |
                                 VIR_FILE_SHFS_AFS |
                                 VIR_FILE_SHFS_SMB |
                                 VIR_FILE_SHFS_CIFS |
                                 VIR_FILE_SHFS_CEPH |
                                 VIR_FILE_SHFS_GPFS|
                                 VIR_FILE_SHFS_QB |
                                 VIR_FILE_SHFS_ACFS |
                                 VIR_FILE_SHFS_GLUSTERFS |
                                 VIR_FILE_SHFS_BEEGFS);
}


int
virFileIsClusterFS(const char *path)
{
    /* These are coherent cluster filesystems known to be safe for
     * migration with cache != none
     */
    return virFileIsSharedFSType(path,
                                 VIR_FILE_SHFS_GFS2 |
                                 VIR_FILE_SHFS_OCFS |
                                 VIR_FILE_SHFS_CEPH |
                                 VIR_FILE_SHFS_GLUSTERFS);
}


#if defined(__linux__) && defined(WITH_SYS_MOUNT_H)
int
virFileSetupDev(const char *path,
                const char *mount_options)
{
    const unsigned long mount_flags = MS_NOSUID;
    const char *mount_fs = "tmpfs";

    if (g_mkdir_with_parents(path, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %1$s"), path);
        return -1;
    }

    VIR_DEBUG("Mount devfs on %s type=tmpfs flags=0x%lx, opts=%s",
              path, mount_flags, mount_options);
    if (mount("devfs", path, mount_fs, mount_flags, mount_options) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devfs on %1$s type %2$s (%3$s)"),
                             path, mount_fs, mount_options);
        return -1;
    }

    return 0;
}


int
virFileBindMountDevice(const char *src,
                       const char *dst)
{
    if (!virFileExists(dst)) {
        if (virFileIsDir(src)) {
            if (g_mkdir_with_parents(dst, 0777) < 0) {
                virReportSystemError(errno, _("Unable to make dir %1$s"), dst);
                return -1;
            }
        } else {
            if (virFileTouch(dst, 0666) < 0)
                return -1;
        }
    }

    if (mount(src, dst, "none", MS_BIND, NULL) < 0) {
        virReportSystemError(errno, _("Failed to bind %1$s on to %2$s"), src,
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

    if (mount(src, dst, "none", mount_flags, NULL) < 0) {
        virReportSystemError(errno,
                             _("Unable to move %1$s mount to %2$s"),
                             src, dst);
        return -1;
    }

    return 0;
}


#else /* !defined(__linux__) || !defined(WITH_SYS_MOUNT_H) */

int
virFileSetupDev(const char *path G_GNUC_UNUSED,
                const char *mount_options G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount is not supported on this platform."));
    return -1;
}


int
virFileBindMountDevice(const char *src G_GNUC_UNUSED,
                       const char *dst G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount is not supported on this platform."));
    return -1;
}


int
virFileMoveMount(const char *src G_GNUC_UNUSED,
                 const char *dst G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("mount move is not supported on this platform."));
    return -1;
}
#endif /* !defined(__linux__) || !defined(WITH_SYS_MOUNT_H) */


#if defined(WITH_LIBACL)
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
    g_clear_pointer(acl, acl_free);
}

#else /* !defined(WITH_LIBACL) */

int
virFileGetACLs(const char *file G_GNUC_UNUSED,
               void **acl G_GNUC_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}


int
virFileSetACLs(const char *file G_GNUC_UNUSED,
               void *acl G_GNUC_UNUSED)
{
    errno = ENOTSUP;
    return -1;
}


void
virFileFreeACLs(void **acl)
{
    *acl = NULL;
}

#endif /* !defined(WITH_LIBACL) */

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

/*
 * virFileComparePaths:
 * @p1: source path 1
 * @p2: source path 2
 *
 * Compares two paths for equality. To do so, it first canonicalizes both paths
 * to resolve all symlinks and discard relative path components. If symlinks
 * resolution or path canonicalization fails, plain string equality of @p1
 * and @p2 is performed.
 *
 * Returns:
 *  1 : Equal
 *  0 : Non-Equal
 */
int
virFileComparePaths(const char *p1, const char *p2)
{
    g_autofree char *res1 = NULL;
    g_autofree char *res2 = NULL;

    /* Assume p1 and p2 are symlinks, so try to resolve and canonicalize them.
     * Canonicalization fails for example on file systems names like 'proc' or
     * 'sysfs', since they're no real paths so fallback to plain string
     * comparison.
     */
    ignore_value(virFileResolveLink(p1, &res1));
    if (!res1)
        res1 = g_strdup(p1);

    ignore_value(virFileResolveLink(p2, &res2));
    if (!res2)
        res2 = g_strdup(p2);

    return STREQ_NULLABLE(res1, res2);
}


#if WITH_DECL_SEEK_HOLE
/**
 * virFileInData:
 * @fd: file to check
 * @inData: true if current position in the @fd is in data section
 * @length: amount of bytes until the end of the current section
 *
 * With sparse files not every extent has to be physically stored on
 * the disk. This results in so called data or hole sections.  This
 * function checks whether the current position in the file @fd is
 * in a data section (@inData = 1) or in a hole (@inData = 0). Also,
 * it sets @length to match the number of bytes remaining until the
 * end of the current section.
 *
 * As a special case, there is an implicit hole at the end of any
 * file. In this case, the function sets @inData = 0, @length = 0.
 *
 * Upon its return, the position in the @fd is left unchanged, i.e.
 * despite this function lseek()-ing back and forth it always
 * restores the original position in the file.
 *
 * NB, @length is type of long long because it corresponds to off_t
 * the best.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
int
virFileInData(int fd,
              int *inData,
              long long *length)
{
    int ret = -1;
    off_t cur, data, hole, end;

    /* Get current position */
    cur = lseek(fd, 0, SEEK_CUR);
    if (cur == (off_t) -1) {
        virReportSystemError(errno, "%s",
                             _("Unable to get current position in file"));
        goto cleanup;
    }

    /* Now try to get data and hole offsets */
    data = lseek(fd, cur, SEEK_DATA);

    /* There are four options:
     * 1) data == cur;  @cur is in data
     * 2) data > cur; @cur is in a hole, next data at @data
     * 3) data < 0, errno = ENXIO; either @cur is in trailing hole, or @cur is beyond EOF.
     * 4) data < 0, errno != ENXIO; we learned nothing
     */

    if (data == (off_t) -1) {
        /* cases 3 and 4 */
        if (errno != ENXIO) {
            virReportSystemError(errno, "%s",
                                 _("Unable to seek to data"));
            goto cleanup;
        }

        *inData = 0;
        /* There are two situations now. There is always an
         * implicit hole at EOF. However, there might be a
         * trailing hole just before EOF too. If that's the case
         * report it. */
        if ((end = lseek(fd, 0, SEEK_END)) == (off_t) -1) {
            virReportSystemError(errno, "%s",
                                 _("Unable to seek to EOF"));
            goto cleanup;
        }
        *length = end - cur;
    } else if (data > cur) {
        /* case 2 */
        *inData = 0;
        *length = data - cur;
    } else {
        /* case 1 */
        *inData = 1;

        /* We don't know where does the next hole start. Let's
         * find out. Here we get the same 4 possibilities as
         * described above.*/
        hole = lseek(fd, data, SEEK_HOLE);
        if (hole == (off_t) -1 || hole == data) {
            /* cases 1, 3 and 4 */
            /* Wait a second. The reason why we are here is
             * because we are in data. But at the same time we
             * are in a trailing hole? Wut!? Do the best what we
             * can do here. */
            virReportSystemError(errno, "%s",
                                 _("unable to seek to hole"));
            goto cleanup;
        } else {
            /* case 2 */
            *length = (hole - data);
        }
    }

    ret = 0;
 cleanup:
    /* At any rate, reposition back to where we started. */
    if (cur != (off_t) -1) {
        int theerrno = errno;

        if (lseek(fd, cur, SEEK_SET) == (off_t) -1) {
            virReportSystemError(errno, "%s",
                                 _("unable to restore position in file"));
            ret = -1;
            if (theerrno == 0)
                theerrno = errno;
        }

        errno = theerrno;
    }
    return ret;
}

#else /* !WITH_DECL_SEEK_HOLE */

int
virFileInData(int fd G_GNUC_UNUSED,
              int *inData G_GNUC_UNUSED,
              long long *length G_GNUC_UNUSED)
{
    errno = ENOSYS;
    virReportSystemError(errno, "%s",
                         _("sparse files not supported"));
    return -1;
}

#endif /* !WITH_DECL_SEEK_HOLE */


/**
 * virFileReadValueInt:
 * @value: pointer to int to be filled in with the value
 * @format, ...: file to read from
 *
 * Read int from @format and put it into @value.
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueInt(int *value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, VIR_INT64_STR_BUFLEN, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    if (virStrToLong_i(str, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid integer value '%1$s' in file '%2$s'"),
                       str, path);
        return -1;
    }

    return 0;
}


/**
 * virFileReadValueUint:
 * @value: pointer to int to be filled in with the value
 * @format, ...: file to read from
 *
 * Read unsigned int from @format and put it into @value.
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueUint(unsigned int *value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, VIR_INT64_STR_BUFLEN, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    if (virStrToLong_uip(str, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid unsigned integer value '%1$s' in file '%2$s'"),
                       str, path);
        return -1;
    }

    return 0;
}


/**
 * virFileReadValueUllong:
 * @value: pointer to unsigned long long to be filled in with the value
 * @format, ...: file to read from
 *
 * Read unsigned int from @format and put it into @value.
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueUllong(unsigned long long *value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, VIR_INT64_STR_BUFLEN, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    if (virStrToLong_ullp(str, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid unsigned long long value '%1$s' in file '%2$s'"),
                       str, path);
        return -1;
    }

    return 0;
}

int
virFileReadValueUllongQuiet(unsigned long long *value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAllQuiet(path, VIR_INT64_STR_BUFLEN, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    if (virStrToLong_ullp(str, NULL, 10, value) < 0)
        return -1;

    return 0;
}

/**
 * virFileReadValueScaledInt:
 * @value: pointer to unsigned long long int to be filled in with the value
 * @format, ...: file to read from
 *
 * Read unsigned scaled int from @format and put it into @value.
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueScaledInt(unsigned long long *value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    char *endp = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, VIR_INT64_STR_BUFLEN, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    if (virStrToLong_ullp(str, &endp, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid unsigned scaled integer value '%1$s' in file '%2$s'"),
                       str, path);
        return -1;
    }

    return virScaleInteger(value, endp, 1024, ULLONG_MAX);
}

/* Arbitrarily sized number, feel free to change, but the function should be
 * used for small, interface-like files, so it should not be huge (subjective) */
#define VIR_FILE_READ_VALUE_STRING_MAX 4096

/**
 * virFileReadValueBitmap:
 * @value: pointer to virBitmap * to be allocated and filled in with the value
 * @format, ...: file to read from
 *
 * Read int from @format and put it into @value.
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueBitmap(virBitmap **value, const char *format, ...)
{
    g_autofree char *str = NULL;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    if (virFileReadAll(path, VIR_FILE_READ_VALUE_STRING_MAX, &str) < 0)
        return -1;

    virStringTrimOptionalNewline(str);

    *value = virBitmapParseUnlimited(str);
    if (!*value)
        return -1;

    return 0;
}

/**
 * virFileReadValueString:
 * @value: pointer to char * to be allocated and filled in with the value
 * @format, ...: file to read from
 *
 * Read string from @format and put it into @value.  Don't get this mixed with
 * virFileReadAll().  This function is a wrapper over it with the behaviour
 * aligned to other virFileReadValue* functions
 *
 * Return -2 for non-existing file, -1 on other errors and 0 if everything went
 * fine.
 */
int
virFileReadValueString(char **value, const char *format, ...)
{
    int ret;
    g_autofree char *path = NULL;
    va_list ap;

    va_start(ap, format);
    path = g_strdup_vprintf(format, ap);
    va_end(ap);

    if (!virFileExists(path))
        return -2;

    ret = virFileReadAll(path, VIR_FILE_READ_VALUE_STRING_MAX, value);

    if (*value)
        virStringTrimOptionalNewline(*value);

    return ret;
}


/**
 * virFileWaitForExists:
 * @path: absolute path to a sysfs attribute (can be a symlink)
 * @ms: how long to wait (in milliseconds)
 * @tries: how many times should we try to wait for @path to become accessible
 *
 * Checks the existence of @path. In case the file defined by @path
 * doesn't exist, we wait for it to appear in @ms milliseconds (for up to
 * @tries attempts).
 *
 * Returns 0 on success, -1 on error, setting errno appropriately.
 */
int
virFileWaitForExists(const char *path,
                     size_t ms,
                     size_t tries)
{
    errno = 0;

    /* wait for @path to be accessible in @ms milliseconds, up to @tries */
    while (tries-- > 0 && !virFileExists(path)) {
        if (tries == 0 || errno != ENOENT)
            return -1;

        g_usleep(ms * 1000);
    }

    return 0;
}


#if WITH_LIBATTR
/**
 * virFileGetXAttrQuiet;
 * @path: a filename
 * @name: name of xattr
 * @value: read value
 *
 * Reads xattr with @name for given @path and stores it into
 * @value. Caller is responsible for freeing @value.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with errno set).
 */
int
virFileGetXAttrQuiet(const char *path,
                     const char *name,
                     char **value)
{
    g_autofree char *buf = NULL;

    /* We might be racing with somebody who sets the same attribute. */
    while (1) {
        ssize_t need;
        ssize_t got;

        /* The first call determines how many bytes we need to allocate. */
        if ((need = getxattr(path, name, NULL, 0)) < 0)
            return -1;

        buf = g_renew(char, buf, need + 1);

        if ((got = getxattr(path, name, buf, need)) < 0) {
            if (errno == ERANGE)
                continue;
            return -1;
        }

        buf[got] = '\0';
        break;
    }

    *value = g_steal_pointer(&buf);
    return 0;
}

/**
 * virFileSetXAttr:
 * @path: a filename
 * @name: name of xattr
 * @value: value to set
 *
 * Sets xattr of @name and @value on @path.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with errno set AND error reported).
 */
int
virFileSetXAttr(const char *path,
                const char *name,
                const char *value)
{
    if (setxattr(path, name, value, strlen(value), 0) < 0) {
        virReportSystemError(errno,
                             _("Unable to set XATTR %1$s on %2$s"),
                             name, path);
        return -1;
    }

    return 0;
}

/**
 * virFileRemoveXAttr:
 * @path: a filename
 * @name: name of xattr
 *
 * Remove xattr of @name on @path.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with errno set AND error reported).
 */
int
virFileRemoveXAttr(const char *path,
                   const char *name)
{
    if (removexattr(path, name) < 0) {
        virReportSystemError(errno,
                             _("Unable to remove XATTR %1$s on %2$s"),
                             name, path);
        return -1;
    }

    return 0;
}

#else /* !WITH_LIBATTR */

int
virFileGetXAttrQuiet(const char *path G_GNUC_UNUSED,
                     const char *name G_GNUC_UNUSED,
                     char **value G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}

int
virFileSetXAttr(const char *path,
                const char *name,
                const char *value G_GNUC_UNUSED)
{
    errno = ENOSYS;
    virReportSystemError(errno,
                         _("Unable to set XATTR %1$s on %2$s"),
                         name, path);
    return -1;
}

int
virFileRemoveXAttr(const char *path,
                   const char *name)
{
    errno = ENOSYS;
    virReportSystemError(errno,
                         _("Unable to remove XATTR %1$s on %2$s"),
                         name, path);
    return -1;
}

#endif /* WITH_LIBATTR */

/**
 * virFileGetXAttr;
 * @path: a filename
 * @name: name of xattr
 * @value: read value
 *
 * Reads xattr with @name for given @path and stores it into
 * @value. Caller is responsible for freeing @value.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with errno set AND error reported).
 */
int
virFileGetXAttr(const char *path,
                const char *name,
                char **value)
{
    int ret;

    if ((ret = virFileGetXAttrQuiet(path, name, value)) < 0) {
        virReportSystemError(errno,
                             _("Unable to get XATTR %1$s on %2$s"),
                             name, path);
    }

    return ret;
}


int
virFileDataSync(int fd)
{
#if defined(__APPLE__) || defined(WIN32)
    return g_fsync(fd);
#else
    return fdatasync(fd);
#endif
}


/**
 * virFileSetCow:
 * @path: file or directory to control the COW flag on
 * @state: the desired state of the COW flag
 *
 * When @state is VIR_TRISTATE_BOOL_ABSENT, some helpful
 * default logic will be used. Specifically if the filesystem
 * containing @path is 'btrfs', then it will attempt to
 * disable the COW flag, but errors will be ignored. For
 * any other filesystem no change will be made.
 *
 * When @state is VIR_TRISTATE_BOOL_YES or VIR_TRISTATE_BOOL_NO,
 * it will attempt to set the COW flag state to that explicit
 * value, and always return an error if it fails. Note this
 * means it will always return error if the filesystem is not
 * 'btrfs'.
 */
int
virFileSetCOW(const char *path,
              virTristateBool state)
{
#if __linux__
    int val = 0;
    struct statfs buf;
    VIR_AUTOCLOSE fd = -1;

    VIR_DEBUG("Setting COW flag on '%s' to '%s'",
              path, virTristateBoolTypeToString(state));

    fd = open(path, O_RDONLY|O_NONBLOCK|O_LARGEFILE);
    if (fd < 0) {
        virReportSystemError(errno, _("unable to open '%1$s'"),
                             path);
        return -1;
    }

    if (fstatfs(fd, &buf) < 0)  {
        virReportSystemError(errno, _("unable query filesystem type on '%1$s'"),
                             path);
        return -1;
    }

    if (buf.f_type != BTRFS_SUPER_MAGIC) {
        if (state != VIR_TRISTATE_BOOL_ABSENT) {
            virReportSystemError(ENOSYS,
                                 _("unable to control COW flag on '%1$s', not btrfs"),
                                 path);
            return -1;
        }
        return 0;
    }

    if (ioctl(fd, FS_IOC_GETFLAGS, &val) < 0) {
        virReportSystemError(errno, _("unable get directory flags on '%1$s'"),
                             path);
        return -1;
    }

    VIR_DEBUG("Current flags on '%s' are 0x%x", path, val);
    if (state == VIR_TRISTATE_BOOL_YES) {
        val &= ~FS_NOCOW_FL;
    } else {
        val |= FS_NOCOW_FL;
    }

    VIR_DEBUG("New flags on '%s' will be 0x%x", path, val);
    if (ioctl(fd, FS_IOC_SETFLAGS, &val) < 0) {
        int saved_err = errno;
        VIR_DEBUG("Failed to set flags on '%s': %s", path, g_strerror(saved_err));
        if (state != VIR_TRISTATE_BOOL_ABSENT) {
            virReportSystemError(saved_err,
                                 _("unable control COW flag on '%1$s'"),
                                 path);
            return -1;
        } else {
            VIR_DEBUG("Ignoring failure to set COW");
        }
    }

    return 0;
#else /* ! __linux__ */
    if (state != VIR_TRISTATE_BOOL_ABSENT) {
        virReportSystemError(ENOSYS,
                             _("Unable to set copy-on-write state on '%1$s' to '%2$s'"),
                             path, virTristateBoolTypeToString(state));
        return -1;
    }
    return 0;
#endif /* ! __linux__ */
}

#ifndef WIN32
struct runIOParams {
    bool isBlockDev;
    bool isDirect;
    bool isWrite;
    int fdin;
    const char *fdinname;
    int fdout;
    const char *fdoutname;
};

/**
 * runIOCopy: execute the IO copy based on the passed parameters
 * @p: the IO parameters
 *
 * Execute the copy based on the passed parameters.
 *
 * Returns: size transferred, or < 0 on error.
 */

static off_t
runIOCopy(const struct runIOParams p)
{
    g_autofree void *base = NULL; /* Location to be freed */
    char *buf = NULL; /* Aligned location within base */
    size_t buflen = 1024*1024;
    intptr_t alignMask = 64*1024 - 1;
    off_t total = 0;

# if WITH_POSIX_MEMALIGN
    if (posix_memalign(&base, alignMask + 1, buflen))
        abort();
    buf = base;
# else
    buf = g_new0(char, buflen + alignMask);
    base = buf;
    buf = (char *) (((intptr_t) base + alignMask) & ~alignMask);
# endif

    while (1) {
        ssize_t got;

        /* If we read with O_DIRECT from file we can't use saferead as
         * it can lead to unaligned read after reading last bytes.
         * If we write with O_DIRECT use should use saferead so that
         * writes will be aligned.
         * In other cases using saferead reduces number of syscalls.
         */
        if (!p.isWrite && p.isDirect) {
            if ((got = read(p.fdin, buf, buflen)) < 0 &&
                errno == EINTR)
                continue;
        } else {
            got = saferead(p.fdin, buf, buflen);
        }

        if (got < 0) {
            virReportSystemError(errno, _("Unable to read %1$s"), p.fdinname);
            return -2;
        }
        if (got == 0)
            break;

        total += got;

        /* handle last write size align in direct case */
        if (got < buflen && p.isDirect && p.isWrite) {
            ssize_t aligned_got = (got + alignMask) & ~alignMask;

            memset(buf + got, 0, aligned_got - got);

            if (safewrite(p.fdout, buf, aligned_got) < 0) {
                virReportSystemError(errno, _("Unable to write %1$s"), p.fdoutname);
                return -3;
            }

            if (!p.isBlockDev && ftruncate(p.fdout, total) < 0) {
                virReportSystemError(errno, _("Unable to truncate %1$s"), p.fdoutname);
                return -4;
            }

            break;
        }

        if (safewrite(p.fdout, buf, got) < 0) {
            virReportSystemError(errno, _("Unable to write %1$s"), p.fdoutname);
            return -3;
        }
    }
    return total;
}

/**
 * virFileDiskCopy: run IO to copy data between storage and a pipe or socket.
 *
 * @disk_fd:     the already open regular file or block device
 * @disk_path:   the pathname corresponding to disk_fd (for error reporting)
 * @remote_fd:   the pipe or socket
 *               Use -1 to auto-choose between STDIN or STDOUT.
 * @remote_path: the pathname corresponding to remote_fd (for error reporting)
 *
 * Note that the direction of the transfer is detected based on the @disk_fd
 * file access mode (man 2 open). Therefore @disk_fd must be opened with
 * O_RDONLY or O_WRONLY. O_RDWR is not supported.
 *
 * virFileDiskCopy always closes the file descriptor disk_fd,
 * and any error during close(2) is reported and considered a failure.
 *
 * Returns: bytes transferred or < 0 on failure.
 */

off_t
virFileDiskCopy(int disk_fd, const char *disk_path, int remote_fd, const char *remote_path)
{
    int ret = -1;
    off_t total = 0;
    struct stat sb;
    struct runIOParams p;
    int oflags = -1;

    oflags = fcntl(disk_fd, F_GETFL);

    if (oflags < 0) {
        virReportSystemError(errno,
                             _("unable to determine access mode of %1$s"),
                             disk_path);
        goto cleanup;
    }
    if (fstat(disk_fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("unable to stat file descriptor %1$d path %2$s"),
                             disk_fd, disk_path);
        goto cleanup;
    }
    p.isBlockDev = S_ISBLK(sb.st_mode);
    p.isDirect = O_DIRECT && (oflags & O_DIRECT);

    switch (oflags & O_ACCMODE) {
    case O_RDONLY:
        p.isWrite = false;
        p.fdin = disk_fd;
        p.fdinname = disk_path;
        p.fdout = remote_fd >= 0 ? remote_fd : STDOUT_FILENO;
        p.fdoutname = remote_path;
        break;
    case O_WRONLY:
        p.isWrite = true;
        p.fdin = remote_fd >= 0 ? remote_fd : STDIN_FILENO;
        p.fdinname = remote_path;
        p.fdout = disk_fd;
        p.fdoutname = disk_path;
        break;
    case O_RDWR:
    default:
        virReportSystemError(EINVAL, _("Unable to process file with flags %1$d"),
                             (oflags & O_ACCMODE));
        goto cleanup;
    }
    /* To make the implementation simpler, we give up on any
     * attempt to use O_DIRECT in a non-trivial manner.  */
    if (!p.isBlockDev && p.isDirect) {
        off_t off;
        if (p.isWrite) {
            /*
             * note: for write we do not only check that disk_fd is seekable,
             * we also want to know that the file is empty, so we need SEEK_END.
             */
            if ((off = lseek(disk_fd, 0, SEEK_END)) != 0) {
                virReportSystemError(off < 0 ? errno : EINVAL, "%s",
                                     _("O_DIRECT write needs empty seekable file"));
                goto cleanup;
            }
        } else if ((off = lseek(disk_fd, 0, SEEK_CUR)) != 0) {
            virReportSystemError(off < 0 ? errno : EINVAL, "%s",
                                 _("O_DIRECT read needs entire seekable file"));
            goto cleanup;
        }
    }
    total = runIOCopy(p);
    if (total < 0)
        goto cleanup;

    /* Ensure all data is written */
    if (virFileDataSync(p.fdout) < 0) {
        if (errno != EINVAL && errno != EROFS) {
            /* fdatasync() may fail on some special FDs, e.g. pipes */
            virReportSystemError(errno, _("unable to fsync %1$s"), p.fdoutname);
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    if (VIR_CLOSE(disk_fd) < 0 && ret == 0) {
        virReportSystemError(errno, _("Unable to close %1$s"), disk_path);
        ret = -1;
    }
    return ret;
}

#else /* WIN32 */

off_t
virFileDiskCopy(int disk_fd G_GNUC_UNUSED,
                const char *disk_path G_GNUC_UNUSED,
                int remote_fd G_GNUC_UNUSED,
                const char *remote_path G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("virFileDiskCopy unsupported on this platform"));
    return -1;
}
#endif /* WIN32 */
