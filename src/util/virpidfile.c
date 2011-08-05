/*
 * virpidfile.c: manipulation of pidfiles
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 */

#include <config.h>

#include <fcntl.h>

#include "virpidfile.h"
#include "virfile.h"
#include "memory.h"
#include "util.h"


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
    FILE *file = NULL;

    if ((fd = open(pidfile,
                   O_WRONLY | O_CREAT | O_TRUNC,
                   S_IRUSR | S_IWUSR)) < 0) {
        rc = -errno;
        goto cleanup;
    }

    if (!(file = VIR_FDOPEN(fd, "w"))) {
        rc = -errno;
        VIR_FORCE_CLOSE(fd);
        goto cleanup;
    }

    if (fprintf(file, "%d", pid) < 0) {
        rc = -errno;
        goto cleanup;
    }

    rc = 0;

cleanup:
    if (VIR_FCLOSE(file) < 0)
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
    FILE *file;
    int rc;

    *pid = 0;

    if (!(file = fopen(path, "r"))) {
        rc = -errno;
        goto cleanup;
    }

    if (fscanf(file, "%d", pid) != 1) {
        rc = -EINVAL;
        VIR_FORCE_FCLOSE(file);
        goto cleanup;
    }

    if (VIR_FCLOSE(file) < 0) {
        rc = -errno;
        goto cleanup;
    }

    rc = 0;

 cleanup:
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
