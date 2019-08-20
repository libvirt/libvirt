/*
 * virpidfile.c: manipulation of pidfiles
 *
 * Copyright (C) 2010-2012, 2014 Red Hat, Inc.
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
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.pidfile");

char *virPidFileBuildPath(const char *dir, const char* name)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s", dir);
    virBufferEscapeString(&buf, "/%s.pid", name);

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
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
    VIR_AUTOFREE(char *) pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (virFileMakePath(dir) < 0)
        return -errno;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileWritePath(pidfile, pid);
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
    VIR_AUTOFREE(char *) pidfile = NULL;

    *pid = 0;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileReadPath(pidfile, pid);
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
    size_t procLinkLen;
    const char deletedText[] = " (deleted)";
    size_t deletedTextLen = strlen(deletedText);
    pid_t retPid;
    VIR_AUTOFREE(char *) procPath = NULL;
    VIR_AUTOFREE(char *) procLink = NULL;
    VIR_AUTOFREE(char *) resolvedBinPath = NULL;
    VIR_AUTOFREE(char *) resolvedProcLink = NULL;

    /* only set this at the very end on success */
    *pid = -1;

    if ((ret = virPidFileReadPath(path, &retPid)) < 0)
        return ret;

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

    if (virAsprintf(&procPath, "/proc/%lld/exe", (long long)retPid) < 0)
        return -ENOMEM;

    if ((ret = virFileIsLink(procPath)) < 0)
        return ret;

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
    if (!(procLink = areadlink(procPath)))
        return -errno;

    procLinkLen = strlen(procLink);
    if (procLinkLen > deletedTextLen)
        procLink[procLinkLen - deletedTextLen] = 0;

    if ((ret = virFileResolveAllLinks(binPath, &resolvedBinPath)) < 0)
        return ret;
    if ((ret = virFileResolveAllLinks(procLink, &resolvedProcLink)) < 0)
        return ret;

    ret = STREQ(resolvedBinPath, resolvedProcLink) ? 0 : -1;

 cleanup:
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
    VIR_AUTOFREE(char *) pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileReadPathIfAlive(pidfile, pid, binpath);
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
    VIR_AUTOFREE(char *) pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileDeletePath(pidfile);
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

    if (ftruncate(fd, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to truncate pid file '%s'"),
                             path);
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

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
    VIR_AUTOFREE(char *) pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileAcquirePath(pidfile, waitForLock, pid);
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
    VIR_AUTOFREE(char *) pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileReleasePath(pidfile, fd);
}


int
virPidFileConstructPath(bool privileged,
                        const char *runstatedir,
                        const char *progname,
                        char **pidfile)
{
    VIR_AUTOFREE(char *) rundir = NULL;

    if (privileged) {
        /*
         * This is here just to allow calling this function with
         * statedir == NULL; of course only when !privileged.
         */
        if (!runstatedir) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No runstatedir specified"));
            return -1;
        }
        if (virAsprintf(pidfile, "%s/%s.pid", runstatedir, progname) < 0)
            return -1;
    } else {
        if (!(rundir = virGetUserRuntimeDirectory()))
            return -1;

        if (virFileMakePathWithMode(rundir, 0700) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create user runtime directory '%s'"),
                                 rundir);
            return -1;
        }

        if (virAsprintf(pidfile, "%s/%s.pid", rundir, progname) < 0)
            return -1;
    }

    return 0;
}


/**
 * virPidFileForceCleanupPath:
 *
 * Check if the pidfile is left around and clean it up whatever it
 * takes.  This doesn't raise an error.  This function must not be
 * called multiple times with the same path, be it in threads or
 * processes.  This function does not raise any errors.
 *
 * Returns 0 if the pidfile was successfully cleaned up, -1 otherwise.
 */
int
virPidFileForceCleanupPath(const char *path)
{
    pid_t pid = 0;
    int fd = -1;

    if (!virFileExists(path))
        return 0;

    if (virPidFileReadPath(path, &pid) < 0)
        return -1;

    fd = virPidFileAcquirePath(path, false, 0);
    if (fd < 0) {
        virResetLastError();

        /* Only kill the process if the pid is valid one.  0 means
         * there is somebody else doing the same pidfile cleanup
         * machinery. */
        if (pid)
            virProcessKillPainfully(pid, true);

        if (virPidFileDeletePath(path) < 0)
            return -1;
    }

    if (fd)
        virPidFileReleasePath(path, fd);

    return 0;
}
