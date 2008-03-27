/*
 * storage_backend.c: internal storage driver backend contract
 *
 * Copyright (C) 2007-2008 Red Hat, Inc.
 * Copyright (C) 2007-2008 Daniel P. Berrange
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
 */

#include <config.h>

#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <dirent.h>

#if HAVE_SELINUX
#include <selinux/selinux.h>
#endif
#if WITH_STORAGE_LVM
#include "storage_backend_logical.h"
#endif
#if WITH_STORAGE_ISCSI
#include "storage_backend_iscsi.h"
#endif
#if WITH_STORAGE_DISK
#include "storage_backend_disk.h"
#endif


#include "util.h"

#include "storage_backend.h"
#include "storage_backend_fs.h"

static virStorageBackendPtr backends[] = {
    &virStorageBackendDirectory,
#if WITH_STORAGE_FS
    &virStorageBackendFileSystem,
    &virStorageBackendNetFileSystem,
#endif
#if WITH_STORAGE_LVM
    &virStorageBackendLogical,
#endif
#if WITH_STORAGE_ISCSI
    &virStorageBackendISCSI,
#endif
#if WITH_STORAGE_DISK
    &virStorageBackendDisk,
#endif
};


virStorageBackendPtr
virStorageBackendForType(int type) {
    unsigned int i;
    for (i = 0 ; i < (sizeof(backends)/sizeof(backends[0])) ; i++)
        if (backends[i]->type == type)
            return backends[i];

    virStorageReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                          _("missing backend for pool type %d"), type);
    return NULL;
}

virStorageBackendPoolOptionsPtr
virStorageBackendPoolOptionsForType(int type) {
    virStorageBackendPtr backend = virStorageBackendForType(type);
    if (backend == NULL)
        return NULL;
    return &backend->poolOptions;
}

virStorageBackendVolOptionsPtr
virStorageBackendVolOptionsForType(int type) {
    virStorageBackendPtr backend = virStorageBackendForType(type);
    if (backend == NULL)
        return NULL;
    return &backend->volOptions;
}


int
virStorageBackendFromString(const char *type) {
    if (STREQ(type, "dir"))
        return VIR_STORAGE_POOL_DIR;
#if WITH_STORAGE_FS
    if (STREQ(type, "fs"))
        return VIR_STORAGE_POOL_FS;
    if (STREQ(type, "netfs"))
        return VIR_STORAGE_POOL_NETFS;
#endif
#if WITH_STORAGE_LVM
    if (STREQ(type, "logical"))
        return VIR_STORAGE_POOL_LOGICAL;
#endif
#if WITH_STORAGE_ISCSI
    if (STREQ(type, "iscsi"))
        return VIR_STORAGE_POOL_ISCSI;
#endif
#if WITH_STORAGE_DISK
    if (STREQ(type, "disk"))
        return VIR_STORAGE_POOL_DISK;
#endif

    virStorageReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                          _("unknown storage backend type %s"), type);
    return -1;
}

const char *
virStorageBackendToString(int type) {
    switch (type) {
    case VIR_STORAGE_POOL_DIR:
        return "dir";
#if WITH_STORAGE_FS
    case VIR_STORAGE_POOL_FS:
        return "fs";
    case VIR_STORAGE_POOL_NETFS:
        return "netfs";
#endif
#if WITH_STORAGE_LVM
    case VIR_STORAGE_POOL_LOGICAL:
        return "logical";
#endif
#if WITH_STORAGE_ISCSI
    case VIR_STORAGE_POOL_ISCSI:
        return "iscsi";
#endif
#if WITH_STORAGE_DISK
    case VIR_STORAGE_POOL_DISK:
        return "disk";
#endif
    }

    virStorageReportError(NULL, VIR_ERR_INTERNAL_ERROR,
                          _("unknown storage backend type %d"), type);
    return NULL;
}


int
virStorageBackendUpdateVolInfo(virConnectPtr conn,
                               virStorageVolDefPtr vol,
                               int withCapacity)
{
    int ret, fd;

    if ((fd = open(vol->target.path, O_RDONLY)) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot open volume '%s': %s"),
                              vol->target.path, strerror(errno));
        return -1;
    }

    ret = virStorageBackendUpdateVolInfoFD(conn,
                                           vol,
                                           fd,
                                           withCapacity);

    close(fd);

    return ret;
}

int
virStorageBackendUpdateVolInfoFD(virConnectPtr conn,
                                 virStorageVolDefPtr vol,
                                 int fd,
                                 int withCapacity)
{
    struct stat sb;
#if HAVE_SELINUX
    security_context_t filecon = NULL;
#endif

    if (fstat(fd, &sb) < 0) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot stat file '%s': %s"),
                              vol->target.path, strerror(errno));
        return -1;
    }

    if (!S_ISREG(sb.st_mode) &&
        !S_ISCHR(sb.st_mode) &&
        !S_ISBLK(sb.st_mode))
        return -2;

    if (S_ISREG(sb.st_mode)) {
        vol->allocation = (unsigned long long)sb.st_blocks *
            (unsigned long long)sb.st_blksize;
        /* Regular files may be sparse, so logical size (capacity) is not same
         * as actual allocation above
         */
        if (withCapacity)
            vol->capacity = sb.st_size;
    } else {
        off_t end;
        /* XXX this is POSIX compliant, but doesn't work for for CHAR files,
         * only BLOCK. There is a Linux specific ioctl() for getting
         * size of both CHAR / BLOCK devices we should check for in
         * configure
         */
        end = lseek(fd, 0, SEEK_END);
        if (end == (off_t)-1) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot seek to end of file '%s':%s"),
                                  vol->target.path, strerror(errno));
            return -1;
        }
        vol->allocation = end;
        if (withCapacity) vol->capacity = end;
    }

    vol->target.perms.mode = sb.st_mode;
    vol->target.perms.uid = sb.st_uid;
    vol->target.perms.gid = sb.st_gid;

    free(vol->target.perms.label);
    vol->target.perms.label = NULL;

#if HAVE_SELINUX
    if (fgetfilecon(fd, &filecon) == -1) {
        if (errno != ENODATA && errno != ENOTSUP) {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("cannot get file context of %s: %s"),
                                  vol->target.path, strerror(errno));
            return -1;
        } else {
            vol->target.perms.label = NULL;
        }
    } else {
        vol->target.perms.label = strdup(filecon);
        if (vol->target.perms.label == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("context"));
            return -1;
        }
        freecon(filecon);
    }
#else
    vol->target.perms.label = NULL;
#endif

    return 0;
}

/*
 * Given a volume path directly in /dev/XXX, iterate over the
 * entries in the directory pool->def->target.path and find the
 * first symlink pointing to the volume path.
 *
 * If, the target.path is /dev/, then return the original volume
 * path.
 *
 * If no symlink is found, then return the original volume path
 *
 * Typically target.path is one of the /dev/disk/by-XXX dirs
 * with stable paths.
 */
char *
virStorageBackendStablePath(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            char *devpath)
{
    DIR *dh;
    struct dirent *dent;

    /* Short circuit if pool has no target, or if its /dev */
    if (pool->def->target.path == NULL ||
        STREQ(pool->def->target.path, "/dev") ||
        STREQ(pool->def->target.path, "/dev/"))
        return devpath;

    /* The pool is pointing somewhere like /dev/disk/by-path
     * or /dev/disk/by-id, so we need to check all symlinks in
     * the target directory and figure out which one points
     * to this device node
     */
    if ((dh = opendir(pool->def->target.path)) == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("cannot read dir %s: %s"),
                              pool->def->target.path,
                              strerror(errno));
        return NULL;
    }

    while ((dent = readdir(dh)) != NULL) {
        char *stablepath;
        if (dent->d_name[0] == '.')
            continue;

        stablepath = malloc(strlen(pool->def->target.path) +
                            1 + strlen(dent->d_name) + 1);
        if (stablepath == NULL) {
            virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("path"));
            closedir(dh);
            return NULL;
        }

        strcpy(stablepath, pool->def->target.path);
        strcat(stablepath, "/");
        strcat(stablepath, dent->d_name);

        if (virFileLinkPointsTo(stablepath, devpath)) {
            closedir(dh);
            return stablepath;
        }

        free(stablepath);
    }

    closedir(dh);

    /* Couldn't find any matching stable link so give back
     * the original non-stable dev path
     */
    return devpath;
}

/*
 * Run an external program.
 *
 * Read its output and apply a series of regexes to each line
 * When the entire set of regexes has matched consecutively
 * then run a callback passing in all the matches
 */
int
virStorageBackendRunProgRegex(virConnectPtr conn,
                              virStoragePoolObjPtr pool,
                              const char **prog,
                              int nregex,
                              const char **regex,
                              int *nvars,
                              virStorageBackendListVolRegexFunc func,
                              void *data)
{
    int child = 0, fd = -1, exitstatus, err, failed = 1;
    FILE *list = NULL;
    regex_t *reg;
    regmatch_t *vars = NULL;
    char line[1024];
    int maxReg = 0, i, j;
    int totgroups = 0, ngroup = 0, maxvars = 0;
    char **groups;

    /* Compile all regular expressions */
    if ((reg = calloc(nregex, sizeof(*reg))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY, "%s", _("regex"));
        return -1;
    }

    for (i = 0 ; i < nregex ; i++) {
        err = regcomp(&reg[i], regex[i], REG_EXTENDED);
        if (err != 0) {
            char error[100];
            regerror(err, &reg[i], error, sizeof(error));
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  _("Failed to compile regex %s"), error);
            for (j = 0 ; j <= i ; j++)
                regfree(&reg[j]);
            free(reg);
            return -1;
        }

        totgroups += nvars[i];
        if (nvars[i] > maxvars)
            maxvars = nvars[i];

    }

    /* Storage for matched variables */
    if ((groups = calloc(totgroups, sizeof(*groups))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("regex groups"));
        goto cleanup;
    }
    if ((vars = calloc(maxvars+1, sizeof(*vars))) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("regex groups"));
        goto cleanup;
    }


    /* Run the program and capture its output */
    if (virExec(conn, (char**)prog, &child, -1, &fd, NULL) < 0) {
        goto cleanup;
    }

    if ((list = fdopen(fd, "r")) == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot read fd"));
        goto cleanup;
    }

    while (fgets(line, sizeof(line), list) != NULL) {
        /* Strip trailing newline */
        int len = strlen(line);
        if (len && line[len-1] == '\n')
            line[len-1] = '\0';

        for (i = 0 ; i <= maxReg && i < nregex ; i++) {
            if (regexec(&reg[i], line, nvars[i]+1, vars, 0) == 0) {
                maxReg++;

                if (i == 0)
                    ngroup = 0;

                /* NULL terminate each captured group in the line */
                for (j = 0 ; j < nvars[i] ; j++) {
                    /* NB vars[0] is the full pattern, so we offset j by 1 */
                    line[vars[j+1].rm_eo] = '\0';
                    if ((groups[ngroup++] =
                         strdup(line + vars[j+1].rm_so)) == NULL) {
                        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                                              "%s", _("regex groups"));
                        goto cleanup;
                    }
                }

                /* We're matching on the last regex, so callback time */
                if (i == (nregex-1)) {
                    if (((*func)(conn, pool, groups, data)) < 0)
                        goto cleanup;

                    /* Release matches & restart to matching the first regex */
                    for (j = 0 ; j < totgroups ; j++) {
                        free(groups[j]);
                        groups[j] = NULL;
                    }
                    maxReg = 0;
                    ngroup = 0;
                }
            }
        }
    }

    failed = 0;

 cleanup:
    if (groups) {
        for (j = 0 ; j < totgroups ; j++)
            free(groups[j]);
        free(groups);
    }
    free(vars);

    for (i = 0 ; i < nregex ; i++)
        regfree(&reg[i]);

    free(reg);

    if (list)
        fclose(list);
    else
        close(fd);

    while ((err = waitpid(child, &exitstatus, 0) == -1) && errno == EINTR);

    /* Don't bother checking exit status if we already failed */
    if (failed)
        return -1;

    if (err == -1) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("failed to wait for command: %s"),
                              strerror(errno));
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (WEXITSTATUS(exitstatus) != 0) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("non-zero exit status from command %d"),
                                      WEXITSTATUS(exitstatus));
                return -1;
            }
        } else {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("command did not exit cleanly"));
            return -1;
        }
    }

    return 0;
}

/*
 * Run an external program and read from its standard output
 * a stream of tokens from IN_STREAM, applying FUNC to
 * each successive sequence of N_COLUMNS tokens.
 * If FUNC returns < 0, stop processing input and return -1.
 * Return -1 if N_COLUMNS == 0.
 * Return -1 upon memory allocation error.
 * If the number of input tokens is not a multiple of N_COLUMNS,
 * then the final FUNC call will specify a number smaller than N_COLUMNS.
 * If there are no input tokens (empty input), call FUNC with N_COLUMNS == 0.
 */
int
virStorageBackendRunProgNul(virConnectPtr conn,
                            virStoragePoolObjPtr pool,
                            const char **prog,
                            size_t n_columns,
                            virStorageBackendListVolNulFunc func,
                            void *data)
{
    size_t n_tok = 0;
    int child = 0, fd = -1, exitstatus;
    FILE *fp = NULL;
    char **v;
    int err = -1;
    int w_err;
    int i;

    if (n_columns == 0)
        return -1;

    if (n_columns > SIZE_MAX / sizeof *v
        || (v = malloc (n_columns * sizeof *v)) == NULL) {
        virStorageReportError(conn, VIR_ERR_NO_MEMORY,
                              "%s", _("n_columns too large"));
        return -1;
    }
    for (i = 0; i < n_columns; i++)
        v[i] = NULL;

    /* Run the program and capture its output */
    if (virExec(conn, (char**)prog, &child, -1, &fd, NULL) < 0) {
        goto cleanup;
    }

    if ((fp = fdopen(fd, "r")) == NULL) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot read fd"));
        goto cleanup;
    }

    while (1) {
        char *buf = NULL;
        size_t buf_len = 0;
        /* Be careful: even when it returns -1,
           this use of getdelim allocates memory.  */
        ssize_t tok_len = getdelim (&buf, &buf_len, 0, fp);
        v[n_tok] = buf;
        if (tok_len < 0) {
            /* Maybe EOF, maybe an error.
               If n_tok > 0, then we know it's an error.  */
            if (n_tok && func (conn, pool, n_tok, v, data) < 0)
                goto cleanup;
            break;
        }
        ++n_tok;
        if (n_tok == n_columns) {
            if (func (conn, pool, n_tok, v, data) < 0)
                goto cleanup;
            n_tok = 0;
            for (i = 0; i < n_columns; i++) {
                free (v[i]);
                v[i] = NULL;
            }
        }
    }

    if (feof (fp))
        err = 0;
    else
        virStorageReportError (conn, VIR_ERR_INTERNAL_ERROR,
                               _("read error: %s"), strerror (errno));

 cleanup:
    for (i = 0; i < n_columns; i++)
        free (v[i]);
    free (v);

    if (fp)
        fclose (fp);
    else
        close (fd);

    while ((w_err = waitpid (child, &exitstatus, 0) == -1) && errno == EINTR)
        /* empty */ ;

    /* Don't bother checking exit status if we already failed */
    if (err < 0)
        return -1;

    if (w_err == -1) {
        virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                              _("failed to wait for command: %s"),
                              strerror(errno));
        return -1;
    } else {
        if (WIFEXITED(exitstatus)) {
            if (WEXITSTATUS(exitstatus) != 0) {
                virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                      _("non-zero exit status from command %d"),
                                      WEXITSTATUS(exitstatus));
                return -1;
            }
        } else {
            virStorageReportError(conn, VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("command did not exit cleanly"));
            return -1;
        }
    }

    return 0;
}


/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
