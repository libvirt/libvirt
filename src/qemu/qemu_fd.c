/*
 * qemu_fd.c: QEMU fd and fdpass passing helpers
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
 */

#include <config.h>

#include "qemu_fd.h"
#include "qemu_domain.h"

#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_QEMU
VIR_LOG_INIT("qemu.qemu_fd");

struct qemuFDPassFD {
    int fd;
    char *opaque;
};

struct _qemuFDPass {
    bool useFDSet;
    unsigned int fdSetID;
    size_t nfds;
    struct qemuFDPassFD *fds;
    char *prefix;
    char *path;

    bool passed; /* passed to qemu via monitor */
};


void
qemuFDPassFree(qemuFDPass *fdpass)
{
    size_t i;

    if (!fdpass)
        return;

    for (i = 0; i < fdpass->nfds; i++) {
        VIR_FORCE_CLOSE(fdpass->fds[i].fd);
        g_free(fdpass->fds[i].opaque);
    }

    g_free(fdpass->fds);
    g_free(fdpass->prefix);
    g_free(fdpass->path);
    g_free(fdpass);
}


/**
 * qemuFDPassNew:
 * @prefix: prefix used for naming the passed FDs
 * @dompriv: qemu domain private data
 *
 * Create a new helper object for passing FDs to QEMU. The instance created
 * via 'qemuFDPassNew' will result in the fd passed via a 'fdset' (/dev/fdset/N).
 *
 * Non-test uses must pass a valid @dompriv.
 *
 * @prefix is used as prefix for naming the fd in QEMU.
 */
qemuFDPass *
qemuFDPassNew(const char *prefix,
              void *dompriv)
{
    qemuDomainObjPrivate *priv = dompriv;
    qemuFDPass *fdpass = g_new0(qemuFDPass, 1);

    fdpass->prefix = g_strdup(prefix);
    fdpass->useFDSet = true;

    if (priv)
        fdpass->fdSetID = qemuDomainFDSetIDNew(priv);

    return fdpass;
}


/**
 * qemuFDPassNewDirect:
 * @prefix: prefix used for naming the passed FDs
 * @dompriv: qemu domain private data
 *
 * Create a new helper object for passing FDs to QEMU.
 *
 * The instance created via 'qemuFDPassNewDirect' will result in the older
 * approach of directly using FD number on the commandline and 'getfd'
 * QMP command.
 *
 * Non-test uses must pass a valid @dompriv.
 *
 * @prefix is used for naming the FD if needed and is later referenced when
 * removing the FDSet via monitor.
 */
qemuFDPass *
qemuFDPassNewDirect(const char *prefix,
                    void *dompriv G_GNUC_UNUSED)
{
    qemuFDPass *fdpass = g_new0(qemuFDPass, 1);

    fdpass->prefix = g_strdup(prefix);

    return fdpass;
}


/**
 * qemuFDPassAddFD:
 * @fdpass: The fd passing helper struct
 * @fd: File descriptor to pass
 * @suffix: Name suffix for the file descriptor name
 *
 * Adds @fd to be passed to qemu when transferring @fdpass to qemu. When @fdpass
 * is configured to use FD set mode, multiple file descriptors can be passed by
 * calling this function repeatedly.
 *
 * @suffix is used to build the name of the file descriptor by concatenating
 * it with @prefix passed to qemuFDPassNew. @suffix may be NULL, in which case
 * it's considered to be an empty string.
 *
 * Returns 0 on success, -1 on error (when attempting to pass multiple FDs) using
 * the 'direct' method.
 */
int
qemuFDPassAddFD(qemuFDPass *fdpass,
                int *fd,
                const char *suffix)
{
    struct qemuFDPassFD newfd = { .fd = *fd };

    if (newfd.fd < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid file descriptor"));
        return -1;
    }

    if (!fdpass->useFDSet &&
        fdpass->nfds >= 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("direct FD passing supports only 1 file descriptor"));
        return -1;
    }

    *fd = -1;

    newfd.opaque = g_strdup_printf("%s%s", fdpass->prefix, NULLSTR_EMPTY(suffix));

    VIR_APPEND_ELEMENT(fdpass->fds, fdpass->nfds, newfd);

    return 0;
}


/**
 * qemuFDPassTransferCommand:
 * @fdpass: The fd passing helper struct
 * @cmd: Command to pass the filedescriptors to
 *
 * Pass the fds in @fdpass to a commandline object @cmd. @fdpass may be NULL
 * in which case this is a no-op.
 */
void
qemuFDPassTransferCommand(qemuFDPass *fdpass,
                          virCommand *cmd)
{
    size_t i;

    if (!fdpass)
        return;

    for (i = 0; i < fdpass->nfds; i++) {
        virCommandPassFD(cmd, fdpass->fds[i].fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);

        if (fdpass->useFDSet) {
            g_autofree char *arg = NULL;

            arg = g_strdup_printf("set=%u,fd=%d,opaque=%s",
                                  fdpass->fdSetID,
                                  fdpass->fds[i].fd,
                                  fdpass->fds[i].opaque);

            virCommandAddArgList(cmd, "-add-fd", arg, NULL);

            fdpass->path = g_strdup_printf("/dev/fdset/%u", fdpass->fdSetID);
        } else {
            fdpass->path = g_strdup_printf("%u", fdpass->fds[i].fd);
        }

        fdpass->fds[i].fd = -1;
    }
}


/**
 * qemuFDPassTransferMonitor:
 * @fdpass: The fd passing helper struct
 * @mon: monitor object
 *
 * Pass the fds in @fdpass to qemu via the monitor. @fdpass may be NULL
 * in which case this is a no-op. Caller needs to enter the monitor context.
 */
int
qemuFDPassTransferMonitor(qemuFDPass *fdpass,
                          qemuMonitor *mon)
{
    int fdsetid = -1;
    size_t i;

    if (!fdpass)
        return 0;

    for (i = 0; i < fdpass->nfds; i++) {
        if (fdpass->useFDSet) {
            qemuMonitorAddFdInfo fdsetinfo;

            if (qemuMonitorAddFileHandleToSet(mon,
                                              fdpass->fds[i].fd,
                                              fdsetid,
                                              fdpass->fds[i].opaque,
                                              &fdsetinfo) < 0)
                return -1;

            if (fdsetid == -1) {
                fdpass->fdSetID = fdsetid = fdsetinfo.fdset;
                fdpass->path = g_strdup_printf("/dev/fdset/%u", fdsetid);
            }
        } else {
            if (qemuMonitorSendFileHandle(mon,
                                          fdpass->fds[i].opaque,
                                          fdpass->fds[i].fd) < 0)
                return -1;

            fdpass->path = g_strdup(fdpass->fds[i].opaque);
        }

        fdpass->passed = true;
    }

    return 0;
}


/**
 * qemuFDPassTransferMonitorFake:
 * @fdpass: The fd passing helper struct
 *
 * Simulate as if @fdpass was passed via monitor for callers which don't
 * actually wish to test that code path.
 */
void
qemuFDPassTransferMonitorFake(qemuFDPass *fdpass)
{

    if (!fdpass)
        return;

    if (fdpass->useFDSet) {
        fdpass->path = g_strdup_printf("/dev/fdset/monitor-fake");
    } else {
        fdpass->path = g_strdup(fdpass->fds[0].opaque);
    }
}


/**
 * qemuFDPassTransferMonitorRollback:
 * @fdpass: The fd passing helper struct
 * @mon: monitor object
 *
 * Rolls back the addition of @fdpass to @mon if it was added originally.
 */
void
qemuFDPassTransferMonitorRollback(qemuFDPass *fdpass,
                                  qemuMonitor *mon)
{
    if (!fdpass || !fdpass->passed)
        return;

    if (fdpass->useFDSet) {
        ignore_value(qemuMonitorRemoveFdset(mon, fdpass->fdSetID));
    } else {
        ignore_value(qemuMonitorCloseFileHandle(mon, fdpass->fds[0].opaque));
    }
}


/**
 * qemuFDPassGetPath:
 * @fdpass: The fd passing helper struct
 *
 * Returns the path/fd name that is used in qemu to refer to the passed FD.
 * Note that it's only valid to call this function after @fdpass was already
 * transferred to the command or monitor.
 */
const char *
qemuFDPassGetPath(qemuFDPass *fdpass)
{
    if (!fdpass)
        return NULL;

    return fdpass->path;
}
