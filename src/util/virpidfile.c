/*
 * virpidfile.c: manipulation of pidfiles
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

#include <config.h>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>

#include "virpidfile.h"
#include "virfile.h"
#include "viralloc.h"
#include "virutil.h"
#include "intprops.h"
#include "virlog.h"
#include "virerror.h"
#include "c-ctype.h"
#include "areadlink.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.pidfile");

char *virPidFileBuildPath(const char *dir, const char* name)
{
    char *pidfile;

    if (virAsprintf(&pidfile, "%s/%s.pid", dir, name) < 0)
        return NULL;

    return pidfile;
}


int virPidFileWritePath(const char *pidfile,
                        pid_t pid)
{
    int rc;
    int fd;
    char pidstr[INT_BUFSIZE_BOUND(pid)];

    if ((fd = open(pidfile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR)) < 0) {
        rc = -errno;
        goto cleanup;
    }

    snprintf(pidstr, sizeof(pidstr), "%lld", (long long) pid);

    if (safewrite(fd, pidstr, strlen(pidstr)) < 0) {
        rc = -errno;
        VIR_FORCE_CLOSE(fd);
        goto cleanup;
    }

    rc = 0;

 cleanup:
    if (VIR_CLOSE(fd) < 0)
        rc = -errno;

    return rc;
}


int virPidFileWrite(const char *dir,
                    const char *name,
                    pid_t pid)
{
    int rc;
    char *pidfile = NULL;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (virFileMakePath(dir) < 0) {
        rc = -errno;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileWritePath(pidfile, pid);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}


int virPidFileReadPath(const char *path,
                       pid_t *pid)
{
    int fd;
    int rc;
    ssize_t bytes;
    long long pid_value = 0;
    char pidstr[INT_BUFSIZE_BOUND(pid_value)];
    char *endptr = NULL;

    *pid = 0;

    if ((fd = open(path, O_RDONLY)) < 0) {
        rc = -errno;
        goto cleanup;
    }

    bytes = saferead(fd, pidstr, sizeof(pidstr));
    if (bytes < 0) {
        rc = -errno;
        VIR_FORCE_CLOSE(fd);
        goto cleanup;
    }
    pidstr[bytes] = '\0';

    if (virStrToLong_ll(pidstr, &endptr, 10, &pid_value) < 0 ||
        !(*endptr == '\0' || c_isspace(*endptr)) ||
        (pid_t) pid_value != pid_value) {
        rc = -1;
        goto cleanup;
    }

    *pid = pid_value;
    rc = 0;

 cleanup:
    if (VIR_CLOSE(fd) < 0)
        rc = -errno;

    return rc;
}


int virPidFileRead(const char *dir,
                   const char *name,
                   pid_t *pid)
{
    int rc;
    char *pidfile = NULL;
    *pid = 0;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileReadPath(pidfile, pid);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}



/**
 * virPidFileReadPathIfAlive:
 * @path: path to pidfile
 * @pid: variable to return pid in
 * @binpath: path of executable associated with the pidfile
 *
 * This will attempt to read a pid from @path, and store it
 * in @pid. The @pid will only be set, however, if the
 * pid in @path is running, and its executable path
 * resolves to @binpath. This adds protection against
 * recycling of previously reaped pids.
 *
 * If @binpath is NULL the check for the executable path
 * is skipped.
 *
 * Returns -errno upon error, or zero on successful
 * reading of the pidfile. If the PID was not still
 * alive, zero will be returned, but @pid will be
 * set to -1.
 */
int virPidFileReadPathIfAlive(const char *path,
                              pid_t *pid,
                              const char *binPath)
{
    int ret;
    bool isLink;
    char *procPath = NULL;
    char *procLink = NULL;
    size_t procLinkLen;
    char *resolvedBinPath = NULL;
    char *resolvedProcLink = NULL;
    const char deletedText[] = " (deleted)";
    size_t deletedTextLen = strlen(deletedText);
    pid_t retPid;

    /* only set this at the very end on success */
    *pid = -1;

    if ((ret = virPidFileReadPath(path, &retPid)) < 0)
        goto cleanup;

#ifndef WIN32
    /* Check that it's still alive.  Safe to skip this sanity check on
     * mingw, which lacks kill().  */
    if (kill(retPid, 0) < 0) {
        ret = 0;
        retPid = -1;
        goto cleanup;
    }
#endif

    if (!binPath) {
        /* we only knew the pid, and that pid is alive, so we can
         * return it.
         */
        ret = 0;
        goto cleanup;
    }

    if (virAsprintf(&procPath, "/proc/%lld/exe", (long long)retPid) < 0) {
        ret = -ENOMEM;
        goto cleanup;
    }

    if ((ret = virFileIsLink(procPath)) < 0)
        goto cleanup;
    isLink = ret;

    if (isLink && virFileLinkPointsTo(procPath, binPath)) {
        /* the link in /proc/$pid/exe is a symlink to a file
         * that has the same inode as the file at binpath.
         */
        ret = 0;
        goto cleanup;
    }

    /* Even if virFileLinkPointsTo returns a mismatch, it could be
     * that the binary was deleted/replaced after it was executed. In
     * that case the link in /proc/$pid/exe will contain
     * "$procpath (deleted)".  Read that link, remove the " (deleted)"
     * part, and see if it has the same canonicalized name as binpath.
     */
    if (!(procLink = areadlink(procPath))) {
        ret = -errno;
        goto cleanup;
    }
    procLinkLen = strlen(procLink);
    if (procLinkLen > deletedTextLen)
        procLink[procLinkLen - deletedTextLen] = 0;

    if ((ret = virFileResolveAllLinks(binPath, &resolvedBinPath)) < 0)
        goto cleanup;
    if ((ret = virFileResolveAllLinks(procLink, &resolvedProcLink)) < 0)
        goto cleanup;

    ret = STREQ(resolvedBinPath, resolvedProcLink) ? 0 : -1;

 cleanup:
    VIR_FREE(procPath);
    VIR_FREE(procLink);
    VIR_FREE(resolvedProcLink);
    VIR_FREE(resolvedBinPath);

    /* return the originally set pid of -1 unless we proclaim success */
    if (ret == 0)
        *pid = retPid;
    return ret;
}


/**
 * virPidFileReadIfAlive:
 * @dir: directory containing pidfile
 * @name: base filename of pidfile
 * @pid: variable to return pid in
 * @binpath: path of executable associated with the pidfile
 *
 * This will attempt to read a pid from the pidfile @name
 * in directory @dir, and store it in @pid. The @pid will
 * only be set, however, if the pid in @name is running,
 * and its executable path resolves to @binpath. This adds
 * protection against recycling of previously reaped pids.
 *
 * Returns -errno upon error, or zero on successful
 * reading of the pidfile. If the PID was not still
 * alive, zero will be returned, but @pid will be
 * set to -1.
 */
int virPidFileReadIfAlive(const char *dir,
                          const char *name,
                          pid_t *pid,
                          const char *binpath)
{
    int rc = 0;
    char *pidfile = NULL;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileReadPathIfAlive(pidfile, pid, binpath);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}


int virPidFileDeletePath(const char *pidfile)
{
    int rc = 0;

    if (unlink(pidfile) < 0 && errno != ENOENT)
        rc = -errno;

    return rc;
}


int virPidFileDelete(const char *dir,
                     const char *name)
{
    int rc = 0;
    char *pidfile = NULL;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileDeletePath(pidfile);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}

int virPidFileAcquirePath(const char *path,
                          bool waitForLock,
                          pid_t pid)
{
    int fd = -1;
    char pidstr[INT_BUFSIZE_BOUND(pid)];

    if (path[0] == '\0')
        return 0;

    while (1) {
        struct stat a, b;
        if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) < 0) {
            virReportSystemError(errno,
                                 _("Failed to open pid file '%s'"),
                                 path);
            return -1;
        }

        if (virSetCloseExec(fd) < 0) {
            virReportSystemError(errno,
                                 _("Failed to set close-on-exec flag '%s'"),
                                 path);
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        if (fstat(fd, &b) < 0) {
            virReportSystemError(errno,
                                 _("Unable to check status of pid file '%s'"),
                                 path);
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        if (virFileLock(fd, false, 0, 1, waitForLock) < 0) {
            virReportSystemError(errno,
                                 _("Failed to acquire pid file '%s'"),
                                 path);
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        /* Now make sure the pidfile we locked is the same
         * one that now exists on the filesystem
         */
        if (stat(path, &a) < 0) {
            char ebuf[1024] ATTRIBUTE_UNUSED;
            VIR_DEBUG("Pid file '%s' disappeared: %s",
                      path, virStrerror(errno, ebuf, sizeof(ebuf)));
            VIR_FORCE_CLOSE(fd);
            /* Someone else must be racing with us, so try again */
            continue;
        }

        if (a.st_ino == b.st_ino)
            break;

        VIR_DEBUG("Pid file '%s' was recreated", path);
        VIR_FORCE_CLOSE(fd);
        /* Someone else must be racing with us, so try again */
    }

    snprintf(pidstr, sizeof(pidstr), "%lld", (long long) pid);

    if (safewrite(fd, pidstr, strlen(pidstr)) < 0) {
        virReportSystemError(errno,
                             _("Failed to write to pid file '%s'"),
                             path);
        VIR_FORCE_CLOSE(fd);
    }

    return fd;
}


int virPidFileAcquire(const char *dir,
                      const char *name,
                      bool waitForLock,
                      pid_t pid)
{
    int rc = 0;
    char *pidfile = NULL;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileAcquirePath(pidfile, waitForLock, pid);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}


int virPidFileReleasePath(const char *path,
                          int fd)
{
    int rc = 0;
    /*
     * We need to unlink before closing the FD to avoid
     * a race, but Win32 won't let you unlink an open
     * file handle. So on that platform we do the reverse
     * and just have to live with the possible race.
     */
#ifdef WIN32
    VIR_FORCE_CLOSE(fd);
    if (unlink(path) < 0 && errno != ENOENT)
        rc = -errno;
#else
    if (unlink(path) < 0 && errno != ENOENT)
        rc = -errno;
    VIR_FORCE_CLOSE(fd);
#endif
    return rc;
}


int virPidFileRelease(const char *dir,
                      const char *name,
                      int fd)
{
    int rc = 0;
    char *pidfile = NULL;

    if (name == NULL || dir == NULL) {
        rc = -EINVAL;
        goto cleanup;
    }

    if (!(pidfile = virPidFileBuildPath(dir, name))) {
        rc = -ENOMEM;
        goto cleanup;
    }

    rc = virPidFileReleasePath(pidfile, fd);

 cleanup:
    VIR_FREE(pidfile);
    return rc;
}
