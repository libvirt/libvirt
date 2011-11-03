/*
 * utils.c: common, generic utility functions
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
 * Copyright (C) 2006, 2007 Binary Karma
 * Copyright (C) 2006 Shuveb Hussain
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 * File created Jul 18, 2007 - Shuveb Hussain <shuveb@binarykarma.com>
 */

#include <config.h>

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/time.h>
#if HAVE_MMAP
# include <sys/mman.h>
#endif
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <pty.h>

#if HAVE_LIBDEVMAPPER_H
# include <libdevmapper.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif
#include <netdb.h>
#ifdef HAVE_GETPWUID_R
# include <pwd.h>
# include <grp.h>
#endif
#if HAVE_CAPNG
# include <cap-ng.h>
#endif
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# include <mntent.h>
#endif

#include "c-ctype.h"
#include "dirname.h"
#include "virterror_internal.h"
#include "logging.h"
#include "buf.h"
#include "util.h"
#include "memory.h"
#include "threads.h"
#include "verify.h"
#include "virfile.h"
#include "command.h"
#include "nonblocking.h"
#include "passfd.h"

#ifndef NSIG
# define NSIG 32
#endif

verify(sizeof(gid_t) <= sizeof (unsigned int) &&
       sizeof(uid_t) <= sizeof (unsigned int));

#define VIR_FROM_THIS VIR_FROM_NONE

#define virUtilError(code, ...)                                            \
        virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,                \
                             __FUNCTION__, __LINE__, __VA_ARGS__)

/* Like read(), but restarts after EINTR */
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

/* Like write(), but restarts after EINTR */
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
int safezero(int fd, off_t offset, off_t len)
{
    int ret = posix_fallocate(fd, offset, len);
    if (ret == 0)
        return 0;
    errno = ret;
    return -1;
}
#else

# ifdef HAVE_MMAP
int safezero(int fd, off_t offset, off_t len)
{
    int r;
    char *buf;

    /* memset wants the mmap'ed file to be present on disk so create a
     * sparse file
     */
    r = ftruncate(fd, offset + len);
    if (r < 0)
        return -1;

    buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
    if (buf == MAP_FAILED)
        return -1;

    memset(buf, 0, len);
    munmap(buf, len);

    return 0;
}

# else /* HAVE_MMAP */

int safezero(int fd, off_t offset, off_t len)
{
    int r;
    char *buf;
    unsigned long long remain, bytes;

    if (lseek(fd, offset, SEEK_SET) < 0)
        return -1;

    /* Split up the write in small chunks so as not to allocate lots of RAM */
    remain = len;
    bytes = 1024 * 1024;

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
# endif /* HAVE_MMAP */
#endif /* HAVE_POSIX_FALLOCATE */

int virFileStripSuffix(char *str,
                       const char *suffix)
{
    int len = strlen(str);
    int suffixlen = strlen(suffix);

    if (len < suffixlen)
        return 0;

    if (!STREQ(str + len - suffixlen, suffix))
        return 0;

    str[len-suffixlen] = '\0';

    return 1;
}

char *
virArgvToString(const char *const *argv)
{
    int len, i;
    char *ret, *p;

    for (len = 1, i = 0; argv[i]; i++)
        len += strlen(argv[i]) + 1;

    if (VIR_ALLOC_N(ret, len) < 0)
        return NULL;
    p = ret;

    for (i = 0; argv[i]; i++) {
        if (i != 0)
            *(p++) = ' ';

        strcpy(p, argv[i]);
        p += strlen(argv[i]);
    }

    *p = '\0';

    return ret;
}

#ifndef WIN32

int virSetInherit(int fd, bool inherit) {
    int fflags;
    if ((fflags = fcntl(fd, F_GETFD)) < 0)
        return -1;
    if (inherit)
        fflags &= ~FD_CLOEXEC;
    else
        fflags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, fflags)) < 0)
        return -1;
    return 0;
}

#else /* WIN32 */

int virSetInherit(int fd ATTRIBUTE_UNUSED, bool inherit ATTRIBUTE_UNUSED)
{
    return -1;
}

#endif /* WIN32 */

int virSetBlocking(int fd, bool blocking) {
    return set_nonblocking_flag (fd, !blocking);
}

int virSetNonBlock(int fd) {
    return virSetBlocking(fd, false);
}

int virSetCloseExec(int fd)
{
    return virSetInherit(fd, false);
}

int
virPipeReadUntilEOF(int outfd, int errfd,
                    char **outbuf, char **errbuf) {

    struct pollfd fds[2];
    int i;
    int finished[2];

    fds[0].fd = outfd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    finished[0] = 0;
    fds[1].fd = errfd;
    fds[1].events = POLLIN;
    fds[1].revents = 0;
    finished[1] = 0;

    while(!(finished[0] && finished[1])) {

        if (poll(fds, ARRAY_CARDINALITY(fds), -1) < 0) {
            if ((errno == EAGAIN) || (errno == EINTR))
                continue;
            goto pollerr;
        }

        for (i = 0; i < ARRAY_CARDINALITY(fds); ++i) {
            char data[1024], **buf;
            int got, size;

            if (!(fds[i].revents))
                continue;
            else if (fds[i].revents & POLLHUP)
                finished[i] = 1;

            if (!(fds[i].revents & POLLIN)) {
                if (fds[i].revents & POLLHUP)
                    continue;

                virUtilError(VIR_ERR_INTERNAL_ERROR,
                             "%s", _("Unknown poll response."));
                goto error;
            }

            got = read(fds[i].fd, data, sizeof(data));

            if (got == sizeof(data))
                finished[i] = 0;

            if (got == 0) {
                finished[i] = 1;
                continue;
            }
            if (got < 0) {
                if (errno == EINTR)
                    continue;
                if (errno == EAGAIN)
                    break;
                goto pollerr;
            }

            buf = ((fds[i].fd == outfd) ? outbuf : errbuf);
            size = (*buf ? strlen(*buf) : 0);
            if (VIR_REALLOC_N(*buf, size+got+1) < 0) {
                virReportOOMError();
                goto error;
            }
            memmove(*buf+size, data, got);
            (*buf)[size+got] = '\0';
        }
        continue;

    pollerr:
        virReportSystemError(errno,
                             "%s", _("poll error"));
        goto error;
    }

    return 0;

error:
    VIR_FREE(*outbuf);
    VIR_FREE(*errbuf);
    return -1;
}

/* Like gnulib's fread_file, but read no more than the specified maximum
   number of bytes.  If the length of the input is <= max_len, and
   upon error while reading that data, it works just like fread_file.  */
static char *
saferead_lim (int fd, size_t max_len, size_t *length)
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
        requested = MIN (size < max_len ? max_len - size : 0,
                         alloc - size - 1);
        count = saferead (fd, buf + size, requested);
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
    s = saferead_lim (fd, maxlen+1, &len);
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

int virFileReadAll(const char *path, int maxlen, char **buf)
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

/* Truncate @path and write @str to it.  If @mode is 0, ensure that
   @path exists; otherwise, use @mode if @path must be created.
   Return 0 for success, nonzero for failure.
   Be careful to preserve any errno value upon failure. */
int virFileWriteStr(const char *path, const char *str, mode_t mode)
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

int virFileMatchesNameSuffix(const char *file,
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

int virFileHasSuffix(const char *str,
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
   refer to the same file.  Otherwise, return 0.  */
int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest)
{
    struct stat src_sb;
    struct stat dest_sb;

    return (stat (checkLink, &src_sb) == 0
            && stat (checkDest, &dest_sb) == 0
            && SAME_INODE (src_sb, dest_sb));
}



/*
 * Attempt to resolve a symbolic link, returning an
 * absolute path where only the last component is guaranteed
 * not to be a symlink.
 *
 * Return 0 if path was not a symbolic, or the link was
 * resolved. Return -1 with errno set upon error
 */
int virFileResolveLink(const char *linkpath,
                       char **resultpath)
{
    struct stat st;

    *resultpath = NULL;

    /* We don't need the full canonicalization of intermediate
     * directories, if linkpath is absolute and the basename is
     * already a non-symlink.  */
    if (IS_ABSOLUTE_FILE_NAME(linkpath)) {
        if (lstat(linkpath, &st) < 0)
            return -1;

        if (!S_ISLNK(st.st_mode)) {
            if (!(*resultpath = strdup(linkpath)))
                return -1;
            return 0;
        }
    }

    *resultpath = canonicalize_file_name(linkpath);

    return *resultpath == NULL ? -1 : 0;
}


/*
 * Check whether the given file is a link.
 * Returns 1 in case of the file being a link, 0 in case it is not
 * a link and the negative errno in all other cases.
 */
int virFileIsLink(const char *linkpath)
{
    struct stat st;

    if (lstat(linkpath, &st) < 0)
        return -errno;

    return (S_ISLNK(st.st_mode) != 0);
}


/*
 * Finds a requested executable file in the PATH env. e.g.:
 * "kvm-img" will return "/usr/bin/kvm-img"
 *
 * You must free the result
 */
char *virFindFileInPath(const char *file)
{
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
        if (virFileIsExecutable(file))
            return strdup(file);
        else
            return NULL;
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
    path = getenv("PATH");

    if (path == NULL || (path = strdup(path)) == NULL)
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

bool virFileExists(const char *path)
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

    if (uid == getuid() &&
        gid == getgid())
        return access(path, mode);

    forkRet = virFork(&pid);

    if (pid < 0) {
        return -1;
    }

    if (pid) { /* parent */
        if (virPidWait(pid, &status) < 0) {
            /* virPidWait() already
             * reported error */
                return -1;
        }

        errno = status;
        return -1;
    }

    /* child.
     * Return positive value here. Parent
     * will change it to negative one. */

    if (forkRet < 0) {
        ret = errno;
        goto childerror;
    }

    if (virSetUIDGID(uid, gid) < 0) {
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

/* return -errno on failure, or 0 on success */
static int
virFileOpenAsNoFork(const char *path, int openflags, mode_t mode,
                    uid_t uid, gid_t gid, unsigned int flags)
{
    int fd = -1;
    int ret = 0;

    if ((fd = open(path, openflags, mode)) < 0) {
        ret = -errno;
        virReportSystemError(errno, _("failed to create file '%s'"),
                             path);
        goto error;
    }

    /* VIR_FILE_OPEN_AS_UID in flags means we are running in a child process
     * owned by uid and gid */
    if (!(flags & VIR_FILE_OPEN_AS_UID)) {
        struct stat st;

        if (fstat(fd, &st) == -1) {
            ret = -errno;
            virReportSystemError(errno, _("stat of '%s' failed"), path);
            goto error;
        }
        if (((st.st_uid != uid) || (st.st_gid != gid))
            && (openflags & O_CREAT)
            && (fchown(fd, uid, gid) < 0)) {
            ret = -errno;
            virReportSystemError(errno, _("cannot chown '%s' to (%u, %u)"),
                                 path, (unsigned int) uid, (unsigned int) gid);
            goto error;
        }
    }

    if ((flags & VIR_FILE_OPEN_FORCE_PERMS)
        && (fchmod(fd, mode) < 0)) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        goto error;
    }
    return fd;

error:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

/* return -errno on failure, or 0 on success */
static int virDirCreateNoFork(const char *path, mode_t mode, uid_t uid, gid_t gid,
                              unsigned int flags) {
    int ret = 0;
    struct stat st;

    if ((mkdir(path, mode) < 0)
        && !((errno == EEXIST) && (flags & VIR_DIR_CREATE_ALLOW_EXIST))) {
        ret = -errno;
        virReportSystemError(errno, _("failed to create directory '%s'"),
                             path);
        goto error;
    }

    if (stat(path, &st) == -1) {
        ret = -errno;
        virReportSystemError(errno, _("stat of '%s' failed"), path);
        goto error;
    }
    if (((st.st_uid != uid) || (st.st_gid != gid))
        && (chown(path, uid, gid) < 0)) {
        ret = -errno;
        virReportSystemError(errno, _("cannot chown '%s' to (%u, %u)"),
                             path, (unsigned int) uid, (unsigned int) gid);
        goto error;
    }
    if ((flags & VIR_DIR_CREATE_FORCE_PERMS)
        && (chmod(path, mode) < 0)) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        goto error;
    }
error:
    return ret;
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
 * Open @path, and execute an optional callback @hook on the open file
 * description.  @hook must return 0 on success, or -errno on failure.
 * If @flags includes VIR_FILE_OPEN_AS_UID, then open the file while the
 * effective user id is @uid (by using a child process); this allows
 * one to bypass root-squashing NFS issues.  If @flags includes
 * VIR_FILE_OPEN_FORCE_PERMS, then ensure that @path has those
 * permissions before the callback, even if the file already existed
 * with different permissions.  The return value (if non-negative)
 * is the file descriptor, left open.  Return -errno on failure.  */
int
virFileOpenAs(const char *path, int openflags, mode_t mode,
              uid_t uid, gid_t gid, unsigned int flags)
{
    pid_t pid;
    int waitret, status, ret = 0;
    int fd = -1;
    int pair[2] = { -1, -1 };
    int forkRet;

    if ((!(flags & VIR_FILE_OPEN_AS_UID))
        || (getuid() != 0)
        || ((uid == 0) && (gid == 0))) {
        flags &= ~VIR_FILE_OPEN_AS_UID;
        return virFileOpenAsNoFork(path, openflags, mode, uid, gid, flags);
    }

    /* parent is running as root, but caller requested that the
     * file be created as some other user and/or group). The
     * following dance avoids problems caused by root-squashing
     * NFS servers. */

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) < 0) {
        ret = -errno;
        virReportSystemError(errno,
                             _("failed to create socket needed for '%s'"),
                             path);
        return ret;
    }

    forkRet = virFork(&pid);

    if (pid < 0) {
        ret = -errno;
        return ret;
    }

    if (pid) { /* parent */
        VIR_FORCE_CLOSE(pair[1]);

        do {
            ret = recvfd(pair[0], 0);
        } while (ret < 0 && errno == EINTR);

        if (ret < 0 && errno != EACCES) {
            ret = -errno;
            VIR_FORCE_CLOSE(pair[0]);
            while (waitpid(pid, NULL, 0) == -1 && errno == EINTR);
            goto parenterror;
        } else {
            fd = ret;
        }
        VIR_FORCE_CLOSE(pair[0]);

        /* wait for child to complete, and retrieve its exit code */
        while ((waitret = waitpid(pid, &status, 0) == -1)
               && (errno == EINTR));
        if (waitret == -1) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("failed to wait for child creating '%s'"),
                                 path);
            VIR_FORCE_CLOSE(fd);
            goto parenterror;
        }
        if (!WIFEXITED(status) || (ret = -WEXITSTATUS(status)) == -EACCES ||
            fd == -1) {
            /* fall back to the simpler method, which works better in
             * some cases */
            VIR_FORCE_CLOSE(fd);
            flags &= ~VIR_FILE_OPEN_AS_UID;
            return virFileOpenAsNoFork(path, openflags, mode, uid, gid, flags);
        }
        if (!ret)
            ret = fd;
parenterror:
        return ret;
    }


    /* child */

    if (forkRet < 0) {
        /* error encountered and logged in virFork() after the fork. */
        ret = -errno;
        goto childerror;
    }
    VIR_FORCE_CLOSE(pair[0]);

    /* set desired uid/gid, then attempt to create the file */

    if (virSetUIDGID(uid, gid) < 0) {
        ret = -errno;
        goto childerror;
    }

    ret = virFileOpenAsNoFork(path, openflags, mode, uid, gid, flags);
    if (ret < 0)
        goto childerror;
    fd = ret;

    do {
        ret = sendfd(pair[1], fd);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        ret = -errno;
        goto childerror;
    }

childerror:
    /* ret tracks -errno on failure, but exit value must be positive.
     * If the child exits with EACCES, then the parent tries again.  */
    /* XXX This makes assumptions about errno being < 255, which is
     * not true on Hurd.  */
    VIR_FORCE_CLOSE(pair[1]);
    ret = -ret;
    if ((ret & 0xff) != ret) {
        VIR_WARN("unable to pass desired return value %d", ret);
        ret = 0xff;
    }
    _exit(ret);

}

/* return -errno on failure, or 0 on success */
int virDirCreate(const char *path, mode_t mode,
                 uid_t uid, gid_t gid, unsigned int flags) {
    struct stat st;
    pid_t pid;
    int waitret;
    int status, ret = 0;

    if ((!(flags & VIR_DIR_CREATE_AS_UID))
        || (getuid() != 0)
        || ((uid == 0) && (gid == 0))
        || ((flags & VIR_DIR_CREATE_ALLOW_EXIST) && (stat(path, &st) >= 0))) {
        return virDirCreateNoFork(path, mode, uid, gid, flags);
    }

    int forkRet = virFork(&pid);

    if (pid < 0) {
        ret = -errno;
        return ret;
    }

    if (pid) { /* parent */
        /* wait for child to complete, and retrieve its exit code */
        while ((waitret = waitpid(pid, &status, 0) == -1)  && (errno == EINTR));
        if (waitret == -1) {
            ret = -errno;
            virReportSystemError(errno,
                                 _("failed to wait for child creating '%s'"),
                                 path);
            goto parenterror;
        }
        if (!WIFEXITED(status) || (ret = -WEXITSTATUS(status)) == -EACCES) {
            /* fall back to the simpler method, which works better in
             * some cases */
            return virDirCreateNoFork(path, mode, uid, gid, flags);
        }
parenterror:
        return ret;
    }

    /* child */

    if (forkRet < 0) {
        /* error encountered and logged in virFork() after the fork. */
        goto childerror;
    }

    /* set desired uid/gid, then attempt to create the directory */

    if (virSetUIDGID(uid, gid) < 0) {
        ret = -errno;
        goto childerror;
    }
    if (mkdir(path, mode) < 0) {
        ret = -errno;
        if (ret != -EACCES) {
            /* in case of EACCES, the parent will retry */
            virReportSystemError(errno, _("child failed to create directory '%s'"),
                                 path);
        }
        goto childerror;
    }
    /* check if group was set properly by creating after
     * setgid. If not, try doing it with chown */
    if (stat(path, &st) == -1) {
        ret = -errno;
        virReportSystemError(errno,
                             _("stat of '%s' failed"), path);
        goto childerror;
    }
    if ((st.st_gid != gid) && (chown(path, -1, gid) < 0)) {
        ret = -errno;
        virReportSystemError(errno,
                             _("cannot chown '%s' to group %u"),
                             path, (unsigned int) gid);
        goto childerror;
    }
    if ((flags & VIR_DIR_CREATE_FORCE_PERMS)
        && chmod(path, mode) < 0) {
        virReportSystemError(errno,
                             _("cannot set mode of '%s' to %04o"),
                             path, mode);
        goto childerror;
    }
childerror:
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
int virFileOpenAs(const char *path ATTRIBUTE_UNUSED,
                  int openflags ATTRIBUTE_UNUSED,
                  mode_t mode ATTRIBUTE_UNUSED,
                  uid_t uid ATTRIBUTE_UNUSED,
                  gid_t gid ATTRIBUTE_UNUSED,
                  unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virFileOpenAs is not implemented for WIN32"));

    return -ENOSYS;
}

int virDirCreate(const char *path ATTRIBUTE_UNUSED,
                 mode_t mode ATTRIBUTE_UNUSED,
                 uid_t uid ATTRIBUTE_UNUSED,
                 gid_t gid ATTRIBUTE_UNUSED,
                 unsigned int flags_unused ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virDirCreate is not implemented for WIN32"));

    return -ENOSYS;
}
#endif /* WIN32 */

static int virFileMakePathHelper(char *path)
{
    struct stat st;
    char *p;

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

        if (virFileMakePathHelper(path) < 0)
            return -1;

        *p = '/';
    }

    if (mkdir(path, 0777) < 0 && errno != EEXIST)
        return -1;

    return 0;
}

/**
 * Creates the given directory with mode 0777 if it's not already existing.
 *
 * Returns 0 on success, or -1 if an error occurred (in which case, errno
 * is set appropriately).
 */
int virFileMakePath(const char *path)
{
    int ret = -1;
    char *tmp;

    if ((tmp = strdup(path)) == NULL)
        goto cleanup;

    ret = virFileMakePathHelper(tmp);

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
        if (virAsprintf(&path, "%s/%s", dir, name) < 0) {
            virReportOOMError();
            return NULL;
        }
    } else {
        if (virAsprintf(&path, "%s/%s%s", dir, name, ext) < 0) {
            virReportOOMError();
            return NULL;
        }
    }

    return path;
}

/* Open a non-blocking master side of a pty.  If ttyName is not NULL,
 * then populate it with the name of the slave.  If rawmode is set,
 * also put the master side into raw mode before returning.  */
#ifndef WIN32
int virFileOpenTty(int *ttymaster,
                   char **ttyName,
                   int rawmode)
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
int virFileOpenTty(int *ttymaster ATTRIBUTE_UNUSED,
                   char **ttyName ATTRIBUTE_UNUSED,
                   int rawmode ATTRIBUTE_UNUSED)
{
    /* mingw completely lacks pseudo-terminals, and the gnulib
     * replacements are not (yet) license compatible.  */
    errno = ENOSYS;
    return -1;
}
#endif /* WIN32 */

/*
 * Creates an absolute path for a potentially relative path.
 * Return 0 if the path was not relative, or on success.
 * Return -1 on error.
 *
 * You must free the result.
 */
int virFileAbsPath(const char *path, char **abspath)
{
    char *buf;

    if (path[0] == '/') {
        if (!(*abspath = strdup(path)))
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
    char *cleanpath;
    int idx = 0;

    cleanpath = strdup(path);
    if (!cleanpath) {
        virReportOOMError();
        return NULL;
    }

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

/* Like strtol, but produce an "int" result, and check more carefully.
   Return 0 upon success;  return -1 to indicate failure.
   When END_PTR is NULL, the byte after the final valid digit must be NUL.
   Otherwise, it's like strtol and lets the caller check any suffix for
   validity.  This function is careful to return -1 when the string S
   represents a number that is not representable as an "int". */
int
virStrToLong_i(char const *s, char **end_ptr, int base, int *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned int" value.  */
int
virStrToLong_ui(char const *s, char **end_ptr, int base, unsigned int *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (unsigned int) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce a "long" value.  */
int
virStrToLong_l(char const *s, char **end_ptr, int base, long *result)
{
    long int val;
    char *p;
    int err;

    errno = 0;
    val = strtol(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long" value.  */
int
virStrToLong_ul(char const *s, char **end_ptr, int base, unsigned long *result)
{
    unsigned long int val;
    char *p;
    int err;

    errno = 0;
    val = strtoul(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce a "long long" value.  */
int
virStrToLong_ll(char const *s, char **end_ptr, int base, long long *result)
{
    long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoll(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (long long) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Just like virStrToLong_i, above, but produce an "unsigned long long" value.  */
int
virStrToLong_ull(char const *s, char **end_ptr, int base, unsigned long long *result)
{
    unsigned long long val;
    char *p;
    int err;

    errno = 0;
    val = strtoull(s, &p, base);
    err = (errno || (!end_ptr && *p) || p == s || (unsigned long long) val != val);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

int
virStrToDouble(char const *s,
               char **end_ptr,
               double *result)
{
    double val;
    char *p;
    int err;

    errno = 0;
    val = strtod(s, &p);
    err = (errno || (!end_ptr && *p) || p == s);
    if (end_ptr)
        *end_ptr = p;
    if (err)
        return -1;
    *result = val;
    return 0;
}

/* Convert C from hexadecimal character to integer.  */
int
virHexToBin(unsigned char c)
{
    switch (c) {
    default: return c - '0';
    case 'a': case 'A': return 10;
    case 'b': case 'B': return 11;
    case 'c': case 'C': return 12;
    case 'd': case 'D': return 13;
    case 'e': case 'E': return 14;
    case 'f': case 'F': return 15;
    }
}

/**
 * virSkipSpaces:
 * @str: pointer to the char pointer used
 *
 * Skip potential blanks, this includes space tabs, line feed,
 * carriage returns.
 */
void
virSkipSpaces(const char **str)
{
    const char *cur = *str;

    while (c_isspace(*cur))
        cur++;
    *str = cur;
}

/**
 * virSkipSpacesAndBackslash:
 * @str: pointer to the char pointer used
 *
 * Like virSkipSpaces, but also skip backslashes erroneously emitted
 * by xend
 */
void
virSkipSpacesAndBackslash(const char **str)
{
    const char *cur = *str;

    while (c_isspace(*cur) || *cur == '\\')
        cur++;
    *str = cur;
}

/**
 * virTrimSpaces:
 * @str: string to modify to remove all trailing spaces
 * @endp: track the end of the string
 *
 * If @endp is NULL on entry, then all spaces prior to the trailing
 * NUL in @str are removed, by writing NUL into the appropriate
 * location.  If @endp is non-NULL but points to a NULL pointer,
 * then all spaces prior to the trailing NUL in @str are removed,
 * NUL is written to the new string end, and endp is set to the
 * location of the (new) string end.  If @endp is non-NULL and
 * points to a non-NULL pointer, then that pointer is used as
 * the end of the string, endp is set to the (new) location, but
 * no NUL pointer is written into the string.
 */
void
virTrimSpaces(char *str, char **endp)
{
    char *end;

    if (!endp || !*endp)
        end = str + strlen(str);
    else
        end = *endp;
    while (end > str && c_isspace(end[-1]))
        end--;
    if (endp) {
        if (!*endp)
            *end = '\0';
        *endp = end;
    } else {
        *end = '\0';
    }
}

/**
 * virSkipSpacesBackwards:
 * @str: start of string
 * @endp: on entry, *endp must be NULL or a location within @str, on exit,
 * will be adjusted to skip trailing spaces, or to NULL if @str had nothing
 * but spaces.
 */
void
virSkipSpacesBackwards(const char *str, char **endp)
{
    /* Casting away const is safe, since virTrimSpaces does not
     * modify string with this particular usage.  */
    char *s = (char*) str;

    if (!*endp)
        *endp = s + strlen(s);
    virTrimSpaces(s, endp);
    if (s == *endp)
        *endp = NULL;
}

/**
 * virParseNumber:
 * @str: pointer to the char pointer used
 *
 * Parse an unsigned number
 *
 * Returns the unsigned number or -1 in case of error. @str will be
 *         updated to skip the number.
 */
int
virParseNumber(const char **str)
{
    int ret = 0;
    const char *cur = *str;

    if ((*cur < '0') || (*cur > '9'))
        return (-1);

    while (c_isdigit(*cur)) {
        unsigned int c = *cur - '0';

        if ((ret > INT_MAX / 10) ||
            ((ret == INT_MAX / 10) && (c > INT_MAX % 10)))
            return (-1);
        ret = ret * 10 + c;
        cur++;
    }
    *str = cur;
    return (ret);
}


/**
 * virParseVersionString:
 * @str: const char pointer to the version string
 * @version: unsigned long pointer to output the version number
 * @allowMissing: true to treat 3 like 3.0.0, false to error out on
 * missing minor or micro
 *
 * Parse an unsigned version number from a version string. Expecting
 * 'major.minor.micro' format, ignoring an optional suffix.
 *
 * The major, minor and micro numbers are encoded into a single version number:
 *
 *   1000000 * major + 1000 * minor + micro
 *
 * Returns the 0 for success, -1 for error.
 */
int
virParseVersionString(const char *str, unsigned long *version,
                      bool allowMissing)
{
    unsigned int major, minor = 0, micro = 0;
    char *tmp;

    if (virStrToLong_ui(str, &tmp, 10, &major) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &minor) < 0)
        return -1;

    if (!allowMissing && *tmp != '.')
        return -1;

    if ((*tmp == '.') && virStrToLong_ui(tmp + 1, &tmp, 10, &micro) < 0)
        return -1;

    if (major > UINT_MAX / 1000000 || minor > 999 || micro > 999)
        return -1;

    *version = 1000000 * major + 1000 * minor + micro;

    return 0;
}

/**
 * virVasprintf
 *
 * like glibc's vasprintf but makes sure *strp == NULL on failure
 */
int
virVasprintf(char **strp, const char *fmt, va_list list)
{
    int ret;

    if ((ret = vasprintf(strp, fmt, list)) == -1)
        *strp = NULL;

    return ret;
}

/**
 * virAsprintf
 *
 * like glibc's_asprintf but makes sure *strp == NULL on failure
 */
int
virAsprintf(char **strp, const char *fmt, ...)
{
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = virVasprintf(strp, fmt, ap);
    va_end(ap);
    return ret;
}

/**
 * virStrncpy
 *
 * A safe version of strncpy.  The last parameter is the number of bytes
 * available in the destination string, *not* the number of bytes you want
 * to copy.  If the destination is not large enough to hold all n of the
 * src string bytes plus a \0, NULL is returned and no data is copied.
 * If the destination is large enough to hold the n bytes plus \0, then the
 * string is copied and a pointer to the destination string is returned.
 */
char *
virStrncpy(char *dest, const char *src, size_t n, size_t destbytes)
{
    char *ret;

    if (n > (destbytes - 1))
        return NULL;

    ret = strncpy(dest, src, n);
    /* strncpy NULL terminates iff the last character is \0.  Therefore
     * force the last byte to be \0
     */
    dest[n] = '\0';

    return ret;
}

/**
 * virStrcpy
 *
 * A safe version of strcpy.  The last parameter is the number of bytes
 * available in the destination string, *not* the number of bytes you want
 * to copy.  If the destination is not large enough to hold all n of the
 * src string bytes plus a \0, NULL is returned and no data is copied.
 * If the destination is large enough to hold the source plus \0, then the
 * string is copied and a pointer to the destination string is returned.
 */
char *
virStrcpy(char *dest, const char *src, size_t destbytes)
{
    return virStrncpy(dest, src, strlen(src), destbytes);
}

/* Compare two MAC addresses, ignoring differences in case,
 * as well as leading zeros.
 */
int
virMacAddrCompare (const char *p, const char *q)
{
    unsigned char c, d;
    do {
        while (*p == '0' && c_isxdigit (p[1]))
            ++p;
        while (*q == '0' && c_isxdigit (q[1]))
            ++q;
        c = c_tolower (*p);
        d = c_tolower (*q);

        if (c == 0 || d == 0)
            break;

        ++p;
        ++q;
    } while (c == d);

    if (UCHAR_MAX <= INT_MAX)
        return c - d;

    /* On machines where 'char' and 'int' are types of the same size, the
       difference of two 'unsigned char' values - including the sign bit -
       doesn't fit in an 'int'.  */
    return (c > d ? 1 : c < d ? -1 : 0);
}

/**
 * virParseMacAddr:
 * @str: string representation of MAC address, e.g., "0:1E:FC:E:3a:CB"
 * @addr: 6-byte MAC address
 *
 * Parse a MAC address
 *
 * Return 0 upon success, or -1 in case of error.
 */
int
virParseMacAddr(const char* str, unsigned char *addr)
{
    int i;

    errno = 0;
    for (i = 0; i < VIR_MAC_BUFLEN; i++) {
        char *end_ptr;
        unsigned long result;

        /* This is solely to avoid accepting the leading
         * space or "+" that strtoul would otherwise accept.
         */
        if (!c_isxdigit(*str))
            break;

        result = strtoul(str, &end_ptr, 16);

        if ((end_ptr - str) < 1 || 2 < (end_ptr - str) ||
            (errno != 0) ||
            (0xFF < result))
            break;

        addr[i] = (unsigned char) result;

        if ((i == 5) && (*end_ptr == '\0'))
            return 0;
        if (*end_ptr != ':')
            break;

        str = end_ptr + 1;
    }

    return -1;
}

void virFormatMacAddr(const unsigned char *addr,
                      char *str)
{
    snprintf(str, VIR_MAC_STRING_BUFLEN,
             "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[0], addr[1], addr[2],
             addr[3], addr[4], addr[5]);
    str[VIR_MAC_STRING_BUFLEN-1] = '\0';
}

void virGenerateMacAddr(const unsigned char *prefix,
                        unsigned char *addr)
{
    addr[0] = prefix[0];
    addr[1] = prefix[1];
    addr[2] = prefix[2];
    addr[3] = virRandom(256);
    addr[4] = virRandom(256);
    addr[5] = virRandom(256);
}


int virEnumFromString(const char *const*types,
                      unsigned int ntypes,
                      const char *type)
{
    unsigned int i;
    if (!type)
        return -1;

    for (i = 0 ; i < ntypes ; i++)
        if (STREQ(types[i], type))
            return i;

    return -1;
}

const char *virEnumToString(const char *const*types,
                            unsigned int ntypes,
                            int type)
{
    if (type < 0 || type >= ntypes)
        return NULL;

    return types[type];
}

/* Translates a device name of the form (regex) /^[fhv]d[a-z]+[0-9]*$/
 * into the corresponding index (e.g. sda => 0, hdz => 25, vdaa => 26)
 * Note that any trailing string of digits is simply ignored.
 * @param name The name of the device
 * @return name's index, or -1 on failure
 */
int virDiskNameToIndex(const char *name) {
    const char *ptr = NULL;
    int idx = 0;
    static char const* const drive_prefix[] = {"fd", "hd", "vd", "sd", "xvd", "ubd"};
    unsigned int i;

    for (i = 0; i < ARRAY_CARDINALITY(drive_prefix); i++) {
        if (STRPREFIX(name, drive_prefix[i])) {
            ptr = name + strlen(drive_prefix[i]);
            break;
        }
    }

    if (!ptr)
        return -1;

    for (i = 0; *ptr; i++) {
        idx = (idx + (i < 1 ? 0 : 1)) * 26;

        if (!c_islower(*ptr))
            break;

        idx += *ptr - 'a';
        ptr++;
    }

    /* Count the trailing digits.  */
    size_t n_digits = strspn(ptr, "0123456789");
    if (ptr[n_digits] != '\0')
        return -1;

    return idx;
}

char *virIndexToDiskName(int idx, const char *prefix)
{
    char *name = NULL;
    int i, k, offset;

    if (idx < 0) {
        virUtilError(VIR_ERR_INTERNAL_ERROR,
                     _("Disk index %d is negative"), idx);
        return NULL;
    }

    for (i = 0, k = idx; k >= 0; ++i, k = k / 26 - 1) { }

    offset = strlen(prefix);

    if (VIR_ALLOC_N(name, offset + i + 1)) {
        virReportOOMError();
        return NULL;
    }

    strcpy(name, prefix);
    name[offset + i] = '\0';

    for (i = i - 1, k = idx; k >= 0; --i, k = k / 26 - 1) {
        name[offset + i] = 'a' + (k % 26);
    }

    return name;
}

#ifndef AI_CANONIDN
# define AI_CANONIDN 0
#endif

/* Who knew getting a hostname could be so delicate.  In Linux (and Unices
 * in general), many things depend on "hostname" returning a value that will
 * resolve one way or another.  In the modern world where networks frequently
 * come and go this is often being hard-coded to resolve to "localhost".  If
 * it *doesn't* resolve to localhost, then we would prefer to have the FQDN.
 * That leads us to 3 possibilities:
 *
 * 1)  gethostname() returns an FQDN (not localhost) - we return the string
 *     as-is, it's all of the information we want
 * 2)  gethostname() returns "localhost" - we return localhost; doing further
 *     work to try to resolve it is pointless
 * 3)  gethostname() returns a shortened hostname - in this case, we want to
 *     try to resolve this to a fully-qualified name.  Therefore we pass it
 *     to getaddrinfo().  There are two possible responses:
 *     a)  getaddrinfo() resolves to a FQDN - return the FQDN
 *     b)  getaddrinfo() fails or resolves to localhost - in this case, the
 *         data we got from gethostname() is actually more useful than what
 *         we got from getaddrinfo().  Return the value from gethostname()
 *         and hope for the best.
 */
char *virGetHostname(virConnectPtr conn ATTRIBUTE_UNUSED)
{
    int r;
    char hostname[HOST_NAME_MAX+1], *result;
    struct addrinfo hints, *info;

    r = gethostname (hostname, sizeof(hostname));
    if (r == -1) {
        virReportSystemError(errno,
                             "%s", _("failed to determine host name"));
        return NULL;
    }
    NUL_TERMINATE(hostname);

    if (STRPREFIX(hostname, "localhost") || strchr(hostname, '.')) {
        /* in this case, gethostname returned localhost (meaning we can't
         * do any further canonicalization), or it returned an FQDN (and
         * we don't need to do any further canonicalization).  Return the
         * string as-is; it's up to callers to check whether "localhost"
         * is allowed.
         */
        result = strdup(hostname);
        goto check_and_return;
    }

    /* otherwise, it's a shortened, non-localhost, hostname.  Attempt to
     * canonicalize the hostname by running it through getaddrinfo
     */

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_CANONNAME|AI_CANONIDN;
    hints.ai_family = AF_UNSPEC;
    r = getaddrinfo(hostname, NULL, &hints, &info);
    if (r != 0) {
        VIR_WARN("getaddrinfo failed for '%s': %s",
                 hostname, gai_strerror(r));
        result = strdup(hostname);
        goto check_and_return;
    }

    /* Tell static analyzers about getaddrinfo semantics.  */
    sa_assert (info);

    if (info->ai_canonname == NULL ||
        STRPREFIX(info->ai_canonname, "localhost"))
        /* in this case, we tried to canonicalize and we ended up back with
         * localhost.  Ignore the canonicalized name and just return the
         * original hostname
         */
        result = strdup(hostname);
    else
        /* Caller frees this string. */
        result = strdup (info->ai_canonname);

    freeaddrinfo(info);

check_and_return:
    if (result == NULL)
        virReportOOMError();
    return result;
}

/* send signal to a single process */
int virKillProcess(pid_t pid, int sig)
{
    if (pid <= 1) {
        errno = ESRCH;
        return -1;
    }

#ifdef WIN32
    /* Mingw / Windows don't have many signals (AFAIK) */
    switch (sig) {
    case SIGINT:
        /* This does a Ctrl+C equiv */
        if (!GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid)) {
            errno = ESRCH;
            return -1;
        }
        break;

    case SIGTERM:
        /* Since TerminateProcess is closer to SIG_KILL, we do
         * a Ctrl+Break equiv which is more pleasant like the
         * good old unix SIGTERM/HUP
         */
        if (!GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)) {
            errno = ESRCH;
            return -1;
        }
        break;

    default:
    {
        HANDLE proc;
        proc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!proc) {
            errno = ESRCH; /* Not entirely accurate, but close enough */
            return -1;
        }

        /*
         * TerminateProcess is more or less equiv to SIG_KILL, in that
         * a process can't trap / block it
         */
        if (sig != 0 && !TerminateProcess(proc, sig)) {
            errno = ESRCH;
            return -1;
        }
        CloseHandle(proc);
    }
    }
    return 0;
#else
    return kill(pid, sig);
#endif
}


static char randomState[128];
static struct random_data randomData;
static virMutex randomLock;

int virRandomInitialize(unsigned int seed)
{
    if (virMutexInit(&randomLock) < 0)
        return -1;

    if (initstate_r(seed,
                    randomState,
                    sizeof(randomState),
                    &randomData) < 0)
        return -1;

    return 0;
}

int virRandom(int max)
{
    int32_t ret;

    virMutexLock(&randomLock);
    random_r(&randomData, &ret);
    virMutexUnlock(&randomLock);

    return (int) ((double)max * ((double)ret / (double)RAND_MAX));
}


#ifdef HAVE_GETPWUID_R
enum {
    VIR_USER_ENT_DIRECTORY,
    VIR_USER_ENT_NAME,
};

static char *virGetUserEnt(uid_t uid,
                           int field)
{
    char *strbuf;
    char *ret;
    struct passwd pwbuf;
    struct passwd *pw = NULL;
    long val = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0) {
        virReportOOMError();
        return NULL;
    }

    /*
     * From the manpage (terrifying but true):
     *
     * ERRORS
     *  0 or ENOENT or ESRCH or EBADF or EPERM or ...
     *        The given name or uid was not found.
     */
    while ((rc = getpwuid_r(uid, &pwbuf, strbuf, strbuflen, &pw)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0) {
            virReportOOMError();
            VIR_FREE(strbuf);
            return NULL;
        }
    }
    if (rc != 0 || pw == NULL) {
        virReportSystemError(rc,
                             _("Failed to find user record for uid '%u'"),
                             (unsigned int) uid);
        VIR_FREE(strbuf);
        return NULL;
    }

    if (field == VIR_USER_ENT_DIRECTORY)
        ret = strdup(pw->pw_dir);
    else
        ret = strdup(pw->pw_name);

    VIR_FREE(strbuf);
    if (!ret)
        virReportOOMError();

    return ret;
}

char *virGetUserDirectory(uid_t uid)
{
    return virGetUserEnt(uid, VIR_USER_ENT_DIRECTORY);
}

char *virGetUserName(uid_t uid)
{
    return virGetUserEnt(uid, VIR_USER_ENT_NAME);
}


int virGetUserID(const char *name,
                 uid_t *uid)
{
    char *strbuf;
    struct passwd pwbuf;
    struct passwd *pw = NULL;
    long val = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0) {
        virReportOOMError();
        return -1;
    }

    /*
     * From the manpage (terrifying but true):
     *
     * ERRORS
     *  0 or ENOENT or ESRCH or EBADF or EPERM or ...
     *        The given name or uid was not found.
     */
    while ((rc = getpwnam_r(name, &pwbuf, strbuf, strbuflen, &pw)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0) {
            virReportOOMError();
            VIR_FREE(strbuf);
            return -1;
        }
    }
    if (rc != 0 || pw == NULL) {
        virReportSystemError(rc,
                             _("Failed to find user record for name '%s'"),
                             name);
        VIR_FREE(strbuf);
        return -1;
    }

    *uid = pw->pw_uid;

    VIR_FREE(strbuf);

    return 0;
}


int virGetGroupID(const char *name,
                  gid_t *gid)
{
    char *strbuf;
    struct group grbuf;
    struct group *gr = NULL;
    long val = sysconf(_SC_GETGR_R_SIZE_MAX);
    size_t strbuflen = val;
    int rc;

    /* sysconf is a hint; if it fails, fall back to a reasonable size */
    if (val < 0)
        strbuflen = 1024;

    if (VIR_ALLOC_N(strbuf, strbuflen) < 0) {
        virReportOOMError();
        return -1;
    }

    /*
     * From the manpage (terrifying but true):
     *
     * ERRORS
     *  0 or ENOENT or ESRCH or EBADF or EPERM or ...
     *        The given name or uid was not found.
     */
    while ((rc = getgrnam_r(name, &grbuf, strbuf, strbuflen, &gr)) == ERANGE) {
        if (VIR_RESIZE_N(strbuf, strbuflen, strbuflen, strbuflen) < 0) {
            virReportOOMError();
            VIR_FREE(strbuf);
            return -1;
        }
    }
    if (rc != 0 || gr == NULL) {
        virReportSystemError(rc,
                             _("Failed to find group record for name '%s'"),
                             name);
        VIR_FREE(strbuf);
        return -1;
    }

    *gid = gr->gr_gid;

    VIR_FREE(strbuf);

    return 0;
}


/* Set the real and effective uid and gid to the given values, and call
 * initgroups so that the process has all the assumed group membership of
 * that uid. return 0 on success, -1 on failure (the original system error
 * remains in errno).
 */
int
virSetUIDGID(uid_t uid, gid_t gid)
{
    int err;

    if (gid > 0) {
        if (setregid(gid, gid) < 0) {
            virReportSystemError(err = errno,
                                 _("cannot change to '%d' group"),
                                 (unsigned int) gid);
            goto error;
        }
    }

    if (uid > 0) {
# ifdef HAVE_INITGROUPS
        struct passwd pwd, *pwd_result;
        char *buf = NULL;
        size_t bufsize;
        int rc;

        bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
        if (bufsize == -1)
            bufsize = 16384;

        if (VIR_ALLOC_N(buf, bufsize) < 0) {
            virReportOOMError();
            err = ENOMEM;
            goto error;
        }
        while ((rc = getpwuid_r(uid, &pwd, buf, bufsize,
                                &pwd_result)) == ERANGE) {
            if (VIR_RESIZE_N(buf, bufsize, bufsize, bufsize) < 0) {
                virReportOOMError();
                VIR_FREE(buf);
                err = ENOMEM;
                goto error;
            }
        }
        if (rc || !pwd_result) {
            virReportSystemError(err = rc, _("cannot getpwuid_r(%d)"),
                                 (unsigned int) uid);
            VIR_FREE(buf);
            goto error;
        }
        if (initgroups(pwd.pw_name, pwd.pw_gid) < 0) {
            virReportSystemError(err = errno,
                                 _("cannot initgroups(\"%s\", %d)"),
                                 pwd.pw_name, (unsigned int) pwd.pw_gid);
            VIR_FREE(buf);
            goto error;
        }
        VIR_FREE(buf);
# endif
        if (setreuid(uid, uid) < 0) {
            virReportSystemError(err = errno,
                                 _("cannot change to uid to '%d'"),
                                 (unsigned int) uid);
            goto error;
        }
    }
    return 0;

error:
    errno = err;
    return -1;
}

#else /* HAVE_GETPWUID_R */

char *
virGetUserDirectory(uid_t uid ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virGetUserDirectory is not available"));

    return NULL;
}

char *
virGetUserName(uid_t uid ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virGetUserName is not available"));

    return NULL;
}

int virGetUserID(const char *name ATTRIBUTE_UNUSED,
                 uid_t *uid ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virGetUserID is not available"));

    return 0;
}


int virGetGroupID(const char *name ATTRIBUTE_UNUSED,
                  gid_t *gid ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virGetGroupID is not available"));

    return 0;
}

int
virSetUIDGID(uid_t uid ATTRIBUTE_UNUSED,
             gid_t gid ATTRIBUTE_UNUSED)
{
    virUtilError(VIR_ERR_INTERNAL_ERROR,
                 "%s", _("virSetUIDGID is not available"));
    return -1;
}
#endif /* HAVE_GETPWUID_R */


#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
/* search /proc/mounts for mount point of *type; return pointer to
 * malloc'ed string of the path if found, otherwise return NULL
 * with errno set to an appropriate value.
 */
char *virFileFindMountPoint(const char *type)
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
            ret = strdup(mb.mnt_dir);
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

#if defined(UDEVADM) || defined(UDEVSETTLE)
void virFileWaitForDevices(void)
{
# ifdef UDEVADM
    const char *const settleprog[] = { UDEVADM, "settle", NULL };
# else
    const char *const settleprog[] = { UDEVSETTLE, NULL };
# endif
    int exitstatus;

    if (access(settleprog[0], X_OK) != 0)
        return;

    /*
     * NOTE: we ignore errors here; this is just to make sure that any device
     * nodes that are being created finish before we try to scan them.
     * If this fails for any reason, we still have the backup of polling for
     * 5 seconds for device nodes.
     */
    if (virRun(settleprog, &exitstatus) < 0)
    {}
}
#else
void virFileWaitForDevices(void) {}
#endif

int virBuildPathInternal(char **path, ...)
{
    char *path_component = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    va_list ap;
    int ret = 0;

    va_start(ap, path);

    path_component = va_arg(ap, char *);
    virBufferAdd(&buf, path_component, -1);

    while ((path_component = va_arg(ap, char *)) != NULL)
    {
        virBufferAddChar(&buf, '/');
        virBufferAdd(&buf, path_component, -1);
    }

    va_end(ap);

    *path = virBufferContentAndReset(&buf);
    if (*path == NULL) {
        ret = -1;
    }

    return ret;
}

/**
 * virTimestamp:
 *
 * Return an allocated string containing the current date and time,
 * followed by ": ".  Return NULL on allocation failure.
 */
char *
virTimestamp(void)
{
    struct timeval cur_time;
    struct tm time_info;
    char timestr[100];
    char *timestamp;

    gettimeofday(&cur_time, NULL);
    localtime_r(&cur_time.tv_sec, &time_info);

    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", &time_info);

    if (virAsprintf(&timestamp, "%s.%03d",
                    timestr, (int) cur_time.tv_usec / 1000) < 0) {
        return NULL;
    }

    return timestamp;
}

#define timeval_to_ms(tv)   (((tv).tv_sec * 1000ull) + ((tv).tv_usec / 1000))

/**
 * virTimeMs:
 *
 * Get current time in milliseconds.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virTimeMs(unsigned long long *ms)
{
    struct timeval now;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("cannot get time of day"));
        return -1;
    }

    *ms = timeval_to_ms(now);
    return 0;
}

#if HAVE_LIBDEVMAPPER_H
bool
virIsDevMapperDevice(const char *dev_name)
{
    struct stat buf;

    if (!stat(dev_name, &buf) &&
        S_ISBLK(buf.st_mode) &&
        dm_is_dm_major(major(buf.st_rdev)))
            return true;

    return false;
}
#else
bool virIsDevMapperDevice(const char *dev_name ATTRIBUTE_UNUSED)
{
    return false;
}
#endif

int virEmitXMLWarning(int fd,
                      const char *name,
                      const char *cmd) {
    size_t len;
    const char *prologue = "<!--\n\
WARNING: THIS IS AN AUTO-GENERATED FILE. CHANGES TO IT ARE LIKELY TO BE \n\
OVERWRITTEN AND LOST. Changes to this xml configuration should be made using:\n\
  virsh ";
    const char *epilogue = "\n\
or other application using the libvirt API.\n\
-->\n\n";

    if (fd < 0 || !name || !cmd) {
        errno = EINVAL;
        return -1;
    }

    len = strlen(prologue);
    if (safewrite(fd, prologue, len) != len)
        return -1;

    len = strlen(cmd);
    if (safewrite(fd, cmd, len) != len)
        return -1;

    if (safewrite(fd, " ", 1) != 1)
        return -1;

    len = strlen(name);
    if (safewrite(fd, name, len) != len)
        return -1;

    len = strlen(epilogue);
    if (safewrite(fd, epilogue, len) != len)
        return -1;

    return 0;
}
