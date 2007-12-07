/*
 * utils.c: common, generic utility functions
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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

#include "config.h"

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include "libvirt/virterror.h"
#include "internal.h"
#include "event.h"
#include "buf.h"
#include "util.h"

#define MAX_ERROR_LEN   1024

#define virLog(msg...) fprintf(stderr, msg)

static void 
ReportError(virConnectPtr conn,
                      virDomainPtr dom,
                      virNetworkPtr net,
                      int code, const char *fmt, ...) {
    va_list args;
    char errorMessage[MAX_ERROR_LEN];

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, MAX_ERROR_LEN-1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }
    __virRaiseError(conn, dom, net, VIR_FROM_NONE, code, VIR_ERR_ERROR,
                    NULL, NULL, NULL, -1, -1, "%s", errorMessage);
}

#ifndef __MINGW32__

static int virSetCloseExec(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFD)) < 0)
        return -1;
    flags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, flags)) < 0)
        return -1;
    return 0;
}

static int virSetNonBlock(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) < 0)
        return -1;
    flags |= O_NONBLOCK;
    if ((fcntl(fd, F_SETFL, flags)) < 0)
        return -1;
    return 0;
}

static int
_virExec(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd, int non_block) {
    int pid, null;
    int pipeout[2] = {-1,-1};
    int pipeerr[2] = {-1,-1};

    if ((null = open(_PATH_DEVNULL, O_RDONLY)) < 0) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot open %s : %s",
                         _PATH_DEVNULL, strerror(errno));
        goto cleanup;
    }

    if ((outfd != NULL && pipe(pipeout) < 0) ||
        (errfd != NULL && pipe(pipeerr) < 0)) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot create pipe : %s",
                         strerror(errno));
        goto cleanup;
    }

    if ((pid = fork()) < 0) {
        ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "cannot fork child process : %s",
                         strerror(errno));
        goto cleanup;
    }

    if (pid) { /* parent */
        close(null);
        if (outfd) {
            close(pipeout[1]);
            if(non_block)
                if(virSetNonBlock(pipeout[0]) == -1)
                    ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, 
                            "Failed to set non-blocking file descriptor flag");

            if(virSetCloseExec(pipeout[0]) == -1)
                ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, 
                        "Failed to set close-on-exec file descriptor flag");
            *outfd = pipeout[0];
        }
        if (errfd) {
            close(pipeerr[1]);
            if(non_block)
                if(virSetNonBlock(pipeerr[0]) == -1)
                    ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, 
                            "Failed to set non-blocking file descriptor flag");

            if(virSetCloseExec(pipeerr[0]) == -1)
                ReportError(conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, 
                        "Failed to set close-on-exec file descriptor flag");
            *errfd = pipeerr[0];
        }
        *retpid = pid;
        return 0;
    }

    /* child */

    if (pipeout[0] > 0 && close(pipeout[0]) < 0)
        _exit(1);
    if (pipeerr[0] > 0 && close(pipeerr[0]) < 0)
        _exit(1);

    if (dup2(infd >= 0 ? infd : null, STDIN_FILENO) < 0)
        _exit(1);
    if (dup2(pipeout[1] > 0 ? pipeout[1] : null, STDOUT_FILENO) < 0)
        _exit(1);
    if (dup2(pipeerr[1] > 0 ? pipeerr[1] : null, STDERR_FILENO) < 0)
        _exit(1);

    close(null);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);

    execvp(argv[0], argv);

    _exit(1);

    return 0;

 cleanup:
    if (pipeerr[0] > 0)
        close(pipeerr[0]);
    if (pipeerr[1] > 0)
        close(pipeerr[1]);
    if (pipeout[0] > 0)
        close(pipeout[0]);
    if (pipeout[1] > 0)
        close(pipeout[1]);
    if (null > 0)
        close(null);
    return -1;
}

int
virExec(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd) {

    return(_virExec(conn, argv, retpid, infd, outfd, errfd, 0));
}

int
virExecNonBlock(virConnectPtr conn,
          char **argv,
          int *retpid, int infd, int *outfd, int *errfd) {

    return(_virExec(conn, argv, retpid, infd, outfd, errfd, 1));
}

#else /* __MINGW32__ */

int
virExec(virConnectPtr conn,
        char **argv ATTRIBUTE_UNUSED,
        int *retpid ATTRIBUTE_UNUSED,
        int infd ATTRIBUTE_UNUSED,
        int *outfd ATTRIBUTE_UNUSED,
        int *errfd ATTRIBUTE_UNUSED)
{
    ReportError (conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
    return -1;
}

int
virExecNonBlock(virConnectPtr conn,
                char **argv ATTRIBUTE_UNUSED,
                int *retpid ATTRIBUTE_UNUSED,
                int infd ATTRIBUTE_UNUSED,
                int *outfd ATTRIBUTE_UNUSED,
                int *errfd ATTRIBUTE_UNUSED)
{
    ReportError (conn, NULL, NULL, VIR_ERR_INTERNAL_ERROR, __FUNCTION__);
    return -1;
}

#endif /* __MINGW32__ */

/* Like read(), but restarts after EINTR */
int saferead(int fd, void *buf, size_t count)
{
	size_t nread = 0;
	while (count > 0) { 
		int r = read(fd, buf, count);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return r;
		if (r == 0)
			return nread;
		buf = (unsigned char *)buf + r;
		count -= r;
		nread += r;
	}
	return nread;
}

/* Like write(), but restarts after EINTR */
ssize_t safewrite(int fd, const void *buf, size_t count)
{
	size_t nwritten = 0;
	while (count > 0) {
		int r = write(fd, buf, count);

		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0)
			return r;
		if (r == 0)
			return nwritten;
		buf = (unsigned char *)buf + r;
		count -= r;
		nwritten += r;
	}
	return nwritten;
}


int virFileReadAll(const char *path,
                   char *buf,
                   unsigned int buflen)
{
    FILE *fh;
    struct stat st;
    int ret = -1;

    if (!(fh = fopen(path, "r"))) {
        virLog("Failed to open file '%s': %s",
               path, strerror(errno));
        goto error;
    }

    if (fstat(fileno(fh), &st) < 0) {
        virLog("Failed to stat file '%s': %s",
               path, strerror(errno));
        goto error;
    }

    if (S_ISDIR(st.st_mode)) {
        virLog("Ignoring directory '%s'", path);
        goto error;
    }

    if (st.st_size >= (buflen-1)) {
        virLog("File '%s' is too large", path);
        goto error;
    }

    if ((ret = fread(buf, st.st_size, 1, fh)) != 1) {
        virLog("Failed to read config file '%s': %s",
               path, strerror(errno));
        goto error;
    }

    buf[st.st_size] = '\0';

    ret = 0;

 error:
    if (fh)
        fclose(fh);

    return ret;
}

int virFileMatchesNameSuffix(const char *file,
                             const char *name,
                             const char *suffix)
{
    int filelen = strlen(file);
    int namelen = strlen(name);
    int suffixlen = strlen(suffix);

    if (filelen == (namelen + suffixlen) &&
        !strncmp(file, name, namelen) &&
        !strncmp(file + namelen, suffix, suffixlen))
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

    return strcmp(str + len - suffixlen, suffix) == 0;
}

#ifndef __MINGW32__

int virFileLinkPointsTo(const char *checkLink,
                        const char *checkDest)
{
    char dest[PATH_MAX];
    char real[PATH_MAX];
    char checkReal[PATH_MAX];
    int n;

    /* read the link destination */
    if ((n = readlink(checkLink, dest, PATH_MAX)) < 0) {
        switch (errno) {
        case ENOENT:
        case ENOTDIR:
            return 0;

        case EINVAL:
            virLog("File '%s' is not a symlink",
                   checkLink);
            return 0;

        }
        virLog("Failed to read symlink '%s': %s",
               checkLink, strerror(errno));
        return 0;
    } else if (n >= PATH_MAX) {
        virLog("Symlink '%s' contents too long to fit in buffer",
               checkLink);
        return 0;
    }

    dest[n] = '\0';

    /* make absolute */
    if (dest[0] != '/') {
        char dir[PATH_MAX];
        char tmp[PATH_MAX];
        char *p;

        strncpy(dir, checkLink, PATH_MAX);
        dir[PATH_MAX-1] = '\0';

        if (!(p = strrchr(dir, '/'))) {
            virLog("Symlink path '%s' is not absolute", checkLink);
            return 0;
        }

        if (p == dir) /* handle unlikely root dir case */
            p++;

        *p = '\0';

        if (virFileBuildPath(dir, dest, NULL, tmp, PATH_MAX) < 0) {
            virLog("Path '%s/%s' is too long", dir, dest);
            return 0;
        }

        strncpy(dest, tmp, PATH_MAX);
        dest[PATH_MAX-1] = '\0';
    }

    /* canonicalize both paths */
    if (!realpath(dest, real)) {
        virLog("Failed to expand path '%s' :%s", dest, strerror(errno));
        strncpy(real, dest, PATH_MAX);
        real[PATH_MAX-1] = '\0';
    }

    if (!realpath(checkDest, checkReal)) {
        virLog("Failed to expand path '%s' :%s", checkDest, strerror(errno));
        strncpy(checkReal, checkDest, PATH_MAX);
        checkReal[PATH_MAX-1] = '\0';
    }

    /* compare */
    if (strcmp(checkReal, real) != 0) {
        virLog("Link '%s' does not point to '%s', ignoring",
               checkLink, checkReal);
        return 0;
    }

    return 1;
}

#else /* !__MINGW32__ */

/* Gnulib has an implementation of readlink which could be used
 * to implement this, but it requires LGPLv3.
 */

int
virFileLinkPointsTo (const char *checkLink ATTRIBUTE_UNUSED,
                     const char *checkDest ATTRIBUTE_UNUSED)
{
    virLog ("%s: not implemented", __FUNCTION__);
    return 0;
}

#endif /*! __MINGW32__ */

int virFileMakePath(const char *path)
{
    struct stat st;
    char parent[PATH_MAX];
    char *p;
    int err;

    if (stat(path, &st) >= 0)
        return 0;

    strncpy(parent, path, PATH_MAX);
    parent[PATH_MAX - 1] = '\0';

    if (!(p = strrchr(parent, '/')))
        return EINVAL;

    if (p == parent)
        return EPERM;

    *p = '\0';

    if ((err = virFileMakePath(parent)))
        return err;

    if (mkdir(path, 0777) < 0 && errno != EEXIST)
        return errno;

    return 0;
}

/* Build up a fully qualfiied path for a config file to be
 * associated with a persistent guest or network */
int virFileBuildPath(const char *dir,
                     const char *name,
                     const char *ext,
                     char *buf,
                     unsigned int buflen)
{
    if ((strlen(dir) + 1 + strlen(name) + (ext ? strlen(ext) : 0) + 1) >= (buflen-1))
        return -1;

    strcpy(buf, dir);
    strcat(buf, "/");
    strcat(buf, name);
    if (ext)
        strcat(buf, ext);
    return 0;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
