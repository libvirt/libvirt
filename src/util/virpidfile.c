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
#include "virbuffer.h"
#include "virutil.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.pidfile");

char *virPidFileBuildPath(const char *dir, const char* name)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s", dir);
    virBufferEscapeString(&buf, "/%s.pid", name);

    return virBufferContentAndReset(&buf);
}


int virPidFileWritePath(const char *pidfile,
                        pid_t pid)
{
    int rc;
    int fd;
    char pidstr[VIR_INT64_STR_BUFLEN];

    if ((fd = open(pidfile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR)) < 0) {
        rc = -errno;
        goto cleanup;
    }

    g_snprintf(pidstr, sizeof(pidstr), "%lld", (long long) pid);

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
    g_autofree char *pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (g_mkdir_with_parents(dir, 0777) < 0)
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
    char pidstr[VIR_INT64_STR_BUFLEN];
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
        !(*endptr == '\0' || g_ascii_isspace(*endptr)) ||
        (pid_t) pid_value != pid_value) {
        rc = -EINVAL;
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
    g_autofree char *pidfile = NULL;

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
 * Returns -1 upon error, or zero on successful
 * reading of the pidfile. If the PID was not still
 * alive, zero will be returned, but @pid will be
 * set to -1.
 */
int virPidFileReadPathIfAlive(const char *path,
                              pid_t *pid,
                              const char *binPath)
{
    int rc;
    bool isLink = false;
    size_t procLinkLen;
    const char deletedText[] = " (deleted)";
    size_t deletedTextLen = strlen(deletedText);
    pid_t retPid;
    g_autofree char *procPath = NULL;
    g_autofree char *procLink = NULL;
    g_autofree char *resolvedBinPath = NULL;
    g_autofree char *resolvedProcLink = NULL;

    /* only set this at the very end on success */
    *pid = -1;

    if (virPidFileReadPath(path, &retPid) < 0)
        return -1;

#ifndef WIN32
    /* Check that it's still alive.  Safe to skip this sanity check on
     * mingw, which lacks kill().  */
    if (kill(retPid, 0) < 0) {
        *pid = -1;
        return 0;
    }
#endif

    if (!binPath) {
        /* we only knew the pid, and that pid is alive, so we can
         * return it.
         */
        *pid = retPid;
        return 0;
    }

    procPath = g_strdup_printf("/proc/%lld/exe", (long long)retPid);

    if ((rc = virFileIsLink(procPath)) < 0)
        return -1;

    if (rc == 1)
        isLink = true;

    if (isLink && virFileLinkPointsTo(procPath, binPath)) {
        /* the link in /proc/$pid/exe is a symlink to a file
         * that has the same inode as the file at binpath.
         */
        *pid = retPid;
        return 0;
    }

    /* Even if virFileLinkPointsTo returns a mismatch, it could be
     * that the binary was deleted/replaced after it was executed. In
     * that case the link in /proc/$pid/exe will contain
     * "$procpath (deleted)".  Read that link, remove the " (deleted)"
     * part, and see if it has the same canonicalized name as binpath.
     */
    if (!(procLink = g_file_read_link(procPath, NULL)))
        return -1;

    procLinkLen = strlen(procLink);
    if (procLinkLen > deletedTextLen)
        procLink[procLinkLen - deletedTextLen] = 0;

    if (virFileResolveAllLinks(binPath, &resolvedBinPath) < 0)
        return -1;
    if (virFileResolveAllLinks(procLink, &resolvedProcLink) < 0)
        return -1;

    if (STRNEQ(resolvedBinPath, resolvedProcLink))
        return -1;

    *pid = retPid;
    return 0;
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
 * Returns -1 upon error, or zero on successful
 * reading of the pidfile. If the PID was not still
 * alive, zero will be returned, but @pid will be
 * set to -1.
 */
int virPidFileReadIfAlive(const char *dir,
                          const char *name,
                          pid_t *pid,
                          const char *binpath)
{
    g_autofree char *pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -1;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -1;

    if (virPidFileReadPathIfAlive(pidfile, pid, binpath) < 0)
        return -1;

    return 0;
}

/**
 * virPidFileReadPathIfLocked:
 * @path: path to pidfile
 * @pid: variable to return pid in
 *
 * This will attempt to read a pid from @path, and store it in
 * @pid. The @pid will only be set, however, if the pid in @path
 * is running, and @path is locked by virFileLock() at byte 0
 * (which is exactly what virCommandSetPidFile() results in).
 * This adds protection against returning a stale pid.
 *
 * Returns -1 upon error, or zero on successful
 * reading of the pidfile. If @path is not locked
 * or if the PID was not still alive, zero will
 * be returned, but @pid will be set to -1.
 */
int virPidFileReadPathIfLocked(const char *path, pid_t *pid)
{
    VIR_AUTOCLOSE fd = -1;

    if ((fd = open(path, O_RDWR)) < 0)
        return -1;

    if (virFileLock(fd, false, 0, 1, false) >= 0) {
        /* The file isn't locked. PID is stale. */
        *pid = -1;
        return 0;
    }

    if (virPidFileReadPathIfAlive(path, pid, NULL) < 0)
        return -1;

    return 0;
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
    g_autofree char *pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileDeletePath(pidfile);
}

int virPidFileAcquirePathFull(const char *path,
                              bool waitForLock,
                              bool quiet,
                              pid_t pid)
{
    int fd = -1;
    char pidstr[VIR_INT64_STR_BUFLEN];

    if (path[0] == '\0')
        return 0;

    while (1) {
        struct stat a, b;
        if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) < 0) {
            if (!quiet) {
                virReportSystemError(errno,
                                     _("Failed to open pid file '%1$s'"),
                                     path);
            }
            return -1;
        }

        if (virSetCloseExec(fd) < 0) {
            if (!quiet) {
                virReportSystemError(errno,
                                     _("Failed to set close-on-exec flag '%1$s'"),
                                     path);
            }
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        if (fstat(fd, &b) < 0) {
            if (!quiet) {
                virReportSystemError(errno,
                                     _("Unable to check status of pid file '%1$s'"),
                                     path);
            }
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        if (virFileLock(fd, false, 0, 1, waitForLock) < 0) {
            if (!quiet) {
                virReportSystemError(errno,
                                     _("Failed to acquire pid file '%1$s'"),
                                     path);
            }
            VIR_FORCE_CLOSE(fd);
            return -1;
        }

        /* Now make sure the pidfile we locked is the same
         * one that now exists on the filesystem
         */
        if (stat(path, &a) < 0) {
            VIR_DEBUG("Pid file '%s' disappeared: %s",
                      path, g_strerror(errno));
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

    g_snprintf(pidstr, sizeof(pidstr), "%lld", (long long) pid);

    if (ftruncate(fd, 0) < 0) {
        if (!quiet) {
            virReportSystemError(errno,
                                 _("Failed to truncate pid file '%1$s'"),
                                 path);
        }
        VIR_FORCE_CLOSE(fd);
        return -1;
    }

    if (safewrite(fd, pidstr, strlen(pidstr)) < 0) {
        if (!quiet) {
            virReportSystemError(errno,
                                 _("Failed to write to pid file '%1$s'"),
                                 path);
        }
        VIR_FORCE_CLOSE(fd);
    }

    return fd;
}


int virPidFileAcquirePath(const char *path,
                          pid_t pid)
{
    return virPidFileAcquirePathFull(path, false, false, pid);
}


int virPidFileAcquire(const char *dir,
                      const char *name,
                      pid_t pid)
{
    g_autofree char *pidfile = NULL;

    if (name == NULL || dir == NULL)
        return -EINVAL;

    if (!(pidfile = virPidFileBuildPath(dir, name)))
        return -ENOMEM;

    return virPidFileAcquirePath(pidfile, pid);
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
    g_autofree char *pidfile = NULL;

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
    g_autofree char *rundir = NULL;

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
        *pidfile = g_strdup_printf("%s/%s.pid", runstatedir, progname);
    } else {
        rundir = virGetUserRuntimeDirectory();

        if (g_mkdir_with_parents(rundir, 0700) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create user runtime directory '%1$s'"),
                                 rundir);
            return -1;
        }

        *pidfile = g_strdup_printf("%s/%s.pid", rundir, progname);
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
virPidFileForceCleanupPathFull(const char *path, bool group)
{
    pid_t pid = 0;
    int fd = -1;

    if (!virFileExists(path))
        return 0;

    if (virPidFileReadPath(path, &pid) < 0)
        return -1;

    fd = virPidFileAcquirePathFull(path, false, true, 0);
    if (fd < 0) {
        if (pid > 1 && group)
            pid = virProcessGroupGet(pid);

        /* Only kill the process if the pid is valid one.  0 means
         * there is somebody else doing the same pidfile cleanup
         * machinery. */
        if (group)
            virProcessKillPainfullyDelay(pid, true, 0, true);
        else if (pid)
            virProcessKillPainfully(pid, true);

        if (virPidFileDeletePath(path) < 0)
            return -1;
    }

    if (fd)
        virPidFileReleasePath(path, fd);

    return 0;
}

int
virPidFileForceCleanupPath(const char *path)
{
    return virPidFileForceCleanupPathFull(path, false);
}
