/*
 * qemu_monitor.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_monitor.h"
#include "qemu_conf.h"
#include "event.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

/* Return -1 for error, 1 to continue reading and 0 for success */
typedef int qemuMonitorHandleOutput(virDomainObjPtr vm,
                                    const char *output,
                                    int fd);

/*
 * Returns -1 for error, 0 on end-of-file, 1 for success
 */
static int
qemuMonitorReadOutput(virDomainObjPtr vm,
                      int fd,
                      char *buf,
                      size_t buflen,
                      qemuMonitorHandleOutput func,
                      const char *what,
                      int timeout)
{
    size_t got = 0;
    buf[0] = '\0';
    timeout *= 1000; /* poll wants milli seconds */

    /* Consume & discard the initial greeting */
    while (got < (buflen-1)) {
        ssize_t ret;

        ret = read(fd, buf+got, buflen-got-1);

        if (ret < 0) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN };
            if (errno == EINTR)
                continue;

            if (errno != EAGAIN) {
                virReportSystemError(NULL, errno,
                                     _("Failure while reading %s startup output"),
                                     what);
                return -1;
            }

            ret = poll(&pfd, 1, timeout);
            if (ret == 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Timed out while reading %s startup output"), what);
                return -1;
            } else if (ret == -1) {
                if (errno != EINTR) {
                    virReportSystemError(NULL, errno,
                                         _("Failure while reading %s startup output"),
                                         what);
                    return -1;
                }
            } else {
                /* Make sure we continue loop & read any further data
                   available before dealing with EOF */
                if (pfd.revents & (POLLIN | POLLHUP))
                    continue;

                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                                 _("Failure while reading %s startup output"), what);
                return -1;
            }
        } else if (ret == 0) {
            return 0;
        } else {
            got += ret;
            buf[got] = '\0';
            ret = func(vm, buf, fd);
            if (ret == -1)
                return -1;
            if (ret == 1)
                continue;
            return 1;
        }
    }

    qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("Out of space while reading %s startup output"), what);
    return -1;

}

static int
qemuMonitorCheckPrompt(virDomainObjPtr vm,
                       const char *output,
                       int fd)
{
    if (strstr(output, "(qemu) ") == NULL)
        return 1; /* keep reading */

    vm->monitor = fd;

    return 0;
}

static int
qemuMonitorOpenCommon(virDomainObjPtr vm,
                      int monfd,
                      int reconnect)
{
    char buf[1024];
    int ret;

    if (virSetCloseExec(monfd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to set monitor close-on-exec flag"));
        return -1;
    }
    if (virSetNonBlock(monfd) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         "%s", _("Unable to put monitor into non-blocking mode"));
        return -1;
    }

    if (!reconnect) {
        if (qemuMonitorReadOutput(vm, monfd,
                                  buf, sizeof(buf),
                                  qemuMonitorCheckPrompt,
                                  "monitor", 10) <= 0)
            ret = -1;
        else
            ret = 0;
    } else {
        vm->monitor = monfd;
        ret = 0;
    }

    if (ret != 0)
        return ret;

    return 0;
}

static int
qemuMonitorOpenUnix(virDomainObjPtr vm,
                    const char *monitor,
                    int reconnect)
{
    struct sockaddr_un addr;
    int monfd;
    int timeout = 3; /* In seconds */
    int ret, i = 0;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(NULL, errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Monitor path %s too big for destination"), monitor);
        goto error;
    }

    do {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));

        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        virReportSystemError(NULL, errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;

    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if (ret != 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("monitor socket did not show up."));
        goto error;
    }

    if (qemuMonitorOpenCommon(vm, monfd, reconnect) < 0)
        goto error;

    return 0;

error:
    close(monfd);
    return -1;
}

static int
qemuMonitorOpenPty(virDomainObjPtr vm,
                   const char *monitor,
                   int reconnect)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    if (qemuMonitorOpenCommon(vm, monfd, reconnect) < 0)
        goto error;

    return 0;

error:
    close(monfd);
    return -1;
}

int
qemuMonitorOpen(virDomainObjPtr vm,
                int reconnect)
{
    switch (vm->monitor_chr->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        return qemuMonitorOpenUnix(vm, vm->monitor_chr->data.nix.path,
                                   reconnect);
    case VIR_DOMAIN_CHR_TYPE_PTY:
        return qemuMonitorOpenPty(vm, vm->monitor_chr->data.file.path,
                                  reconnect);
    default:
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unable to handle monitor type: %s"),
                         virDomainChrTypeToString(vm->monitor_chr->type));
        return -1;
    }
}
