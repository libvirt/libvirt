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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <errno.h>
#include <libvirt/virterror.h>
#include "event.h"
#include "buf.h"
#include "util.h"

#define MAX_ERROR_LEN   1024

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
                    NULL, NULL, NULL, -1, -1, errorMessage);
}

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
