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

    if (priv) {
        fdpass->fdSetID = qemuDomainFDSetIDNew(priv);
        fdpass->path = g_strdup_printf("/dev/fdset/%u", fdpass->fdSetID);
    } else {
        fdpass->path = g_strdup_printf("/dev/fdset/monitor-fake");
    }

    return fdpass;
}


/**
 * qemuFDPassNewPassed:
 * @fdSetID: ID of an FDset which was already passed to qemu
 *
 * Create qemuFDPass pointing to an already passed FD. Useful to use with
 * qemuFDPassTransferMonitorRollback, when restoring after restart.
 */
qemuFDPass *
qemuFDPassNewPassed(unsigned int fdSetID)
{
    qemuFDPass *fdpass = g_new0(qemuFDPass, 1);

    fdpass->fdSetID = fdSetID;
    fdpass->passed = true;

    return fdpass;
}


/**
 * qemuFDPassIsPassed:
 * @fdpass: The fd passing helper struct
 * @id: when non-NULL filled with the fdset ID
 *
 * Returns true if @fdpass was passed to qemu. In such case @id is also filled
 * with the ID of the fdset if non-NULL.
 */
bool
qemuFDPassIsPassed(qemuFDPass *fdpass,
                   unsigned *id)
{
    if (!fdpass || !fdpass->passed)
        return false;

    if (id)
        *id = fdpass->fdSetID;

    return true;
}


/**
 * qemuFDPassAddFD:
 * @fdpass: The fd passing helper struct
 * @fd: File descriptor to pass
 * @suffix: Name suffix for the file descriptor name
 *
 * Adds @fd to be passed to qemu when transferring @fdpass to qemu.
 * Multiple file descriptors can be passed by calling this function repeatedly.
 *
 * @suffix is used to build the name of the file descriptor by concatenating
 * it with @prefix passed to qemuFDPassNew. @suffix may be NULL, in which case
 * it's considered to be an empty string.
 */
void
qemuFDPassAddFD(qemuFDPass *fdpass,
                int *fd,
                const char *suffix)
{
    struct qemuFDPassFD newfd = { .fd = *fd };

    *fd = -1;

    newfd.opaque = g_strdup_printf("%s%s", fdpass->prefix, NULLSTR_EMPTY(suffix));

    VIR_APPEND_ELEMENT(fdpass->fds, fdpass->nfds, newfd);
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
        g_autofree char *arg = g_strdup_printf("set=%u,fd=%d,opaque=%s",
                                               fdpass->fdSetID,
                                               fdpass->fds[i].fd,
                                               fdpass->fds[i].opaque);

        virCommandPassFD(cmd, fdpass->fds[i].fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        fdpass->fds[i].fd = -1;
        virCommandAddArgList(cmd, "-add-fd", arg, NULL);
    }

    fdpass->passed = true;
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
    g_autoptr(qemuMonitorFdsets) fdsets = NULL;
    size_t i;

    if (!fdpass)
        return 0;

    if (qemuMonitorQueryFdsets(mon, &fdsets) < 0)
        return -1;

    for (i = 0; i < fdsets->nfdsets; i++) {
        if (fdsets->fdsets[i].id == fdpass->fdSetID) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("fdset '%1$u' is already in use by qemu"),
                           fdpass->fdSetID);
            return -1;
        }
    }

    for (i = 0; i < fdpass->nfds; i++) {
        if (qemuMonitorAddFileHandleToSet(mon,
                                          fdpass->fds[i].fd,
                                          fdpass->fdSetID,
                                          fdpass->fds[i].opaque) < 0)
            return -1;

        VIR_FORCE_CLOSE(fdpass->fds[i].fd);
        fdpass->passed = true;
    }

    return 0;
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

    ignore_value(qemuMonitorRemoveFdset(mon, fdpass->fdSetID));
}


/**
 * qemuFDPassGetPath:
 * @fdpass: The fd passing helper struct
 *
 * Returns the path/fd name that is used in qemu to refer to the passed FD.
 */
const char *
qemuFDPassGetPath(qemuFDPass *fdpass)
{
    if (!fdpass)
        return NULL;

    return fdpass->path;
}


struct _qemuFDPassDirect {
    int fd;
    char *name;

    bool passed; /* passed to qemu via monitor */
};


void
qemuFDPassDirectFree(qemuFDPassDirect *fdpass)
{

    if (!fdpass)
        return;

    VIR_FORCE_CLOSE(fdpass->fd);
    g_free(fdpass->name);
    g_free(fdpass);
}


/**
 * qemuFDPassDirectNew:
 * @name: Name of the fd (for monitor passing use-case)
 * @fd: The FD, cleared when passed.
 *
 * The qemuFDPassDirect helper returned by this helper is used to hold a FD
 * passed to qemu either directly via FD number when used on commandline or the
 * 'getfd' QMP command.
 */
qemuFDPassDirect *
qemuFDPassDirectNew(const char *name,
                    int *fd)
{
    qemuFDPassDirect *fdpass = g_new0(qemuFDPassDirect, 1);

    fdpass->name = g_strdup(name);
    fdpass->fd = *fd;
    *fd = -1;

    return fdpass;
}


/**
 * qemuFDPassDirectTransferCommand:
 * @fdpass: The fd passing helper struct
 * @cmd: Command to pass the filedescriptors to
 *
 * Pass the fds in @fdpass to a commandline object @cmd. @fdpass may be NULL
 * in which case this is a no-op.
 */
void
qemuFDPassDirectTransferCommand(qemuFDPassDirect *fdpass,
                                virCommand *cmd)
{
    if (!fdpass)
        return;

    virCommandPassFD(cmd, fdpass->fd, VIR_COMMAND_PASS_FD_CLOSE_PARENT);
    g_free(fdpass->name);
    fdpass->name = g_strdup_printf("%d", fdpass->fd);
    fdpass->fd = -1;
}


/**
 * qemuFDPassDirectTransferMonitor:
 * @fdpass: The fd passing helper struct
 * @mon: monitor object
 *
 * Pass the fds in @fdpass to qemu via the monitor. @fdpass may be NULL
 * in which case this is a no-op. Caller needs to enter the monitor context.
 */
int
qemuFDPassDirectTransferMonitor(qemuFDPassDirect *fdpass,
                                qemuMonitor *mon)
{
    if (!fdpass)
        return 0;

    if (qemuMonitorSendFileHandle(mon, fdpass->name, fdpass->fd) < 0)
        return -1;

    VIR_FORCE_CLOSE(fdpass->fd);
    fdpass->passed = true;

    return 0;
}


/**
 * qemuFDPassDirectTransferMonitorRollback:
 * @fdpass: The fd passing helper struct
 * @mon: monitor object
 *
 * Rolls back the addition of @fdpass to @mon if it was added originally.
 */
void
qemuFDPassDirectTransferMonitorRollback(qemuFDPassDirect *fdpass,
                                        qemuMonitor *mon)
{
    if (!fdpass || !fdpass->passed)
        return;

    ignore_value(qemuMonitorCloseFileHandle(mon, fdpass->name));
}


/**
 * qemuFDPassDirectGetPath:
 * @fdpass: The fd passing helper struct
 *
 * Returns the path/fd name that is used in qemu to refer to the passed FD.
 * Note that it's only valid to call this function after @fdpass was already
 * transferred to the command or monitor.
 */
const char *
qemuFDPassDirectGetPath(qemuFDPassDirect *fdpass)
{
    if (!fdpass)
        return NULL;

    return fdpass->name;
}
