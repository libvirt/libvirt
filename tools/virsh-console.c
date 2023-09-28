/*
 * virsh-console.c: A dumb serial console client
 *
 * Copyright (C) 2007-2008, 2010-2014 Red Hat, Inc.
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

#ifndef WIN32

# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <termios.h>
# include <poll.h>
# include <unistd.h>
# include <signal.h>

# include "internal.h"
# include "virsh.h"
# include "virsh-console.h"
# include "virsh-util.h"
# include "virlog.h"
# include "viralloc.h"
# include "virthread.h"
# include "virerror.h"
# include "virobject.h"

VIR_LOG_INIT("tools.virsh-console");

/*
 * Convert given character to control character.
 * Basically, we assume ASCII, and take lower 6 bits.
 */
# define CONTROL(c) ((c) ^ 0x40)

# define VIR_FROM_THIS VIR_FROM_NONE

struct virConsoleBuffer {
    size_t length;
    size_t offset;
    char *data;
};


typedef struct virConsole virConsole;
struct virConsole {
    virObjectLockable parent;

    virStreamPtr st;
    bool quit;
    virCond cond;

    int stdinWatch;
    int stdoutWatch;

    struct virConsoleBuffer streamToTerminal;
    struct virConsoleBuffer terminalToStream;

    char escapeChar;
    virError error;
};

static virClass *virConsoleClass;
static void virConsoleDispose(void *obj);

static int
virConsoleOnceInit(void)
{
    if (!VIR_CLASS_NEW(virConsole, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virConsole);

static void
virConsoleHandleSignal(int sig G_GNUC_UNUSED)
{
}


static void
virConsoleShutdown(virConsole *con,
                   bool graceful)
{
    virErrorPtr err = virGetLastError();

    if (con->error.code == VIR_ERR_OK && err)
        virCopyLastError(&con->error);

    if (con->st) {
        int rc;

        virStreamEventRemoveCallback(con->st);
        if (graceful)
            rc = virStreamFinish(con->st);
        else
            rc = virStreamAbort(con->st);

        if (rc < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cannot terminate console stream"));
        }

        g_clear_pointer(&con->st, virshStreamFree);
    }
    VIR_FREE(con->streamToTerminal.data);
    VIR_FREE(con->terminalToStream.data);
    if (con->stdinWatch != -1)
        virEventRemoveHandle(con->stdinWatch);
    if (con->stdoutWatch != -1)
        virEventRemoveHandle(con->stdoutWatch);
    con->stdinWatch = -1;
    con->stdoutWatch = -1;
    if (!con->quit) {
        con->quit = true;
        virCondSignal(&con->cond);
    }
}


static void
virConsoleDispose(void *obj)
{
    virConsole *con = obj;

    virshStreamFree(con->st);

    virCondDestroy(&con->cond);
    virResetError(&con->error);
}


static void
virConsoleEventOnStream(virStreamPtr st,
                        int events, void *opaque)
{
    virConsole *con = opaque;

    virObjectLock(con);

    /* we got late event after console was shutdown */
    if (!con->st)
        goto cleanup;

    if (events & VIR_STREAM_EVENT_READABLE) {
        size_t avail = con->streamToTerminal.length -
            con->streamToTerminal.offset;
        int got;

        if (avail < 1024) {
            VIR_REALLOC_N(con->streamToTerminal.data,
                          con->streamToTerminal.length + 1024);
            con->streamToTerminal.length += 1024;
            avail += 1024;
        }

        got = virStreamRecv(st,
                            con->streamToTerminal.data +
                            con->streamToTerminal.offset,
                            avail);
        if (got == -2)
            goto cleanup; /* blocking */
        if (got <= 0) {
            virConsoleShutdown(con, got == 0);
            goto cleanup;
        }
        con->streamToTerminal.offset += got;
        if (con->streamToTerminal.offset)
            virEventUpdateHandle(con->stdoutWatch,
                                 VIR_EVENT_HANDLE_WRITABLE);
    }

    if (events & VIR_STREAM_EVENT_WRITABLE &&
        con->terminalToStream.offset) {
        ssize_t done;
        size_t avail;
        done = virStreamSend(con->st,
                             con->terminalToStream.data,
                             con->terminalToStream.offset);
        if (done == -2)
            goto cleanup; /* blocking */
        if (done < 0) {
            virConsoleShutdown(con, false);
            goto cleanup;
        }
        memmove(con->terminalToStream.data,
                con->terminalToStream.data + done,
                con->terminalToStream.offset - done);
        con->terminalToStream.offset -= done;

        avail = con->terminalToStream.length - con->terminalToStream.offset;
        if (avail > 1024) {
            VIR_REALLOC_N(con->terminalToStream.data,
                          con->terminalToStream.offset + 1024);
            con->terminalToStream.length = con->terminalToStream.offset + 1024;
        }
    }
    if (!con->terminalToStream.offset)
        virStreamEventUpdateCallback(con->st,
                                     VIR_STREAM_EVENT_READABLE);

    if (events & VIR_STREAM_EVENT_ERROR ||
        events & VIR_STREAM_EVENT_HANGUP) {
        virConsoleShutdown(con, false);
    }

 cleanup:
    virObjectUnlock(con);
}


static void
virConsoleEventOnStdin(int watch G_GNUC_UNUSED,
                       int fd G_GNUC_UNUSED,
                       int events,
                       void *opaque)
{
    virConsole *con = opaque;

    virObjectLock(con);

    /* we got late event after console was shutdown */
    if (!con->st)
        goto cleanup;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = con->terminalToStream.length -
            con->terminalToStream.offset;
        int got;

        if (avail < 1024) {
            VIR_REALLOC_N(con->terminalToStream.data,
                          con->terminalToStream.length + 1024);
            con->terminalToStream.length += 1024;
            avail += 1024;
        }

        got = read(fd,
                   con->terminalToStream.data +
                   con->terminalToStream.offset,
                   avail);
        if (got < 0) {
            if (errno != EAGAIN) {
                virReportSystemError(errno, "%s", _("cannot read from stdin"));
                virConsoleShutdown(con, false);
            }
            goto cleanup;
        }
        if (got == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("EOF on stdin"));
            virConsoleShutdown(con, false);
            goto cleanup;
        }
        if (con->terminalToStream.data[con->terminalToStream.offset] == con->escapeChar) {
            virConsoleShutdown(con, true);
            goto cleanup;
        }

        con->terminalToStream.offset += got;
        if (con->terminalToStream.offset)
            virStreamEventUpdateCallback(con->st,
                                         VIR_STREAM_EVENT_READABLE |
                                         VIR_STREAM_EVENT_WRITABLE);
    }

    if (events & VIR_EVENT_HANDLE_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("IO error on stdin"));
        virConsoleShutdown(con, false);
        goto cleanup;
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("EOF on stdin"));
        virConsoleShutdown(con, false);
        goto cleanup;
    }

 cleanup:
    virObjectUnlock(con);
}


static void
virConsoleEventOnStdout(int watch G_GNUC_UNUSED,
                        int fd,
                        int events,
                        void *opaque)
{
    virConsole *con = opaque;

    virObjectLock(con);

    /* we got late event after console was shutdown */
    if (!con->st)
        goto cleanup;

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        con->streamToTerminal.offset) {
        ssize_t done;
        size_t avail;
        done = write(fd, /* sc_avoid_write */
                     con->streamToTerminal.data,
                     con->streamToTerminal.offset);
        if (done < 0) {
            if (errno != EAGAIN) {
                virReportSystemError(errno, "%s", _("cannot write to stdout"));
                virConsoleShutdown(con, false);
            }
            goto cleanup;
        }
        memmove(con->streamToTerminal.data,
                con->streamToTerminal.data + done,
                con->streamToTerminal.offset - done);
        con->streamToTerminal.offset -= done;

        avail = con->streamToTerminal.length - con->streamToTerminal.offset;
        if (avail > 1024) {
            VIR_REALLOC_N(con->streamToTerminal.data,
                          con->streamToTerminal.offset + 1024);
            con->streamToTerminal.length = con->streamToTerminal.offset + 1024;
        }
    }

    if (!con->streamToTerminal.offset)
        virEventUpdateHandle(con->stdoutWatch, 0);

    if (events & VIR_EVENT_HANDLE_ERROR) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("IO error stdout"));
        virConsoleShutdown(con, false);
        goto cleanup;
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("EOF on stdout"));
        virConsoleShutdown(con, false);
        goto cleanup;
    }

 cleanup:
    virObjectUnlock(con);
}


static virConsole *
virConsoleNew(void)
{
    virConsole *con;

    if (virConsoleInitialize() < 0)
        return NULL;

    if (!(con = virObjectLockableNew(virConsoleClass)))
        return NULL;

    if (virCondInit(&con->cond) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize console condition"));

        goto error;
    }

    con->stdinWatch = -1;
    con->stdoutWatch = -1;

    return con;

 error:
    virObjectUnref(con);
    return NULL;
}


static char
virshGetEscapeChar(const char *s)
{
    if (*s == '^')
        return CONTROL(g_ascii_toupper(s[1]));

    return *s;
}


int
virshRunConsole(vshControl *ctl,
                virDomainPtr dom,
                const char *dev_name,
                const bool resume_domain,
                unsigned int flags)
{
    virConsole *con = NULL;
    virshControl *priv = ctl->privData;
    int ret = -1;

    struct sigaction old_sigquit;
    struct sigaction old_sigterm;
    struct sigaction old_sigint;
    struct sigaction old_sighup;
    struct sigaction old_sigpipe;
    struct sigaction sighandler = {.sa_handler = virConsoleHandleSignal,
                                   .sa_flags = SA_SIGINFO };

    sigemptyset(&sighandler.sa_mask);

    /* Put STDIN into raw mode so that stuff typed does not echo to the screen
     * (the TTY reads will result in it being echoed back already), and also
     * ensure Ctrl-C, etc is blocked, and misc other bits */
    if (vshTTYMakeRaw(ctl, true) < 0)
        goto resettty;

    if (!(con = virConsoleNew()))
        goto resettty;

    virObjectLock(con);

    /* Trap all common signals so that we can safely restore the original
     * terminal settings on STDIN before the process exits - people don't like
     * being left with a messed up terminal ! */
    sigaction(SIGQUIT, &sighandler, &old_sigquit);
    sigaction(SIGTERM, &sighandler, &old_sigterm);
    sigaction(SIGINT,  &sighandler, &old_sigint);
    sigaction(SIGHUP,  &sighandler, &old_sighup);
    sigaction(SIGPIPE, &sighandler, &old_sigpipe);

    con->escapeChar = virshGetEscapeChar(priv->escapeChar);
    con->st = virStreamNew(virDomainGetConnect(dom),
                           VIR_STREAM_NONBLOCK);
    if (!con->st)
        goto cleanup;

    if (virDomainOpenConsole(dom, dev_name, con->st, flags) < 0)
        goto cleanup;

    virObjectRef(con);
    if ((con->stdinWatch = virEventAddHandle(STDIN_FILENO,
                                             VIR_EVENT_HANDLE_READABLE,
                                             virConsoleEventOnStdin,
                                             con,
                                             virObjectUnref)) < 0) {
        virObjectUnref(con);
        goto cleanup;
    }

    virObjectRef(con);
    if ((con->stdoutWatch = virEventAddHandle(STDOUT_FILENO,
                                              0,
                                              virConsoleEventOnStdout,
                                              con,
                                              virObjectUnref)) < 0) {
        virObjectUnref(con);
        goto cleanup;
    }

    virObjectRef(con);
    if (virStreamEventAddCallback(con->st,
                                  VIR_STREAM_EVENT_READABLE,
                                  virConsoleEventOnStream,
                                  con,
                                  virObjectUnref) < 0) {
        virObjectUnref(con);
        goto cleanup;
    }

    if (resume_domain) {
        if (virDomainResume(dom) != 0) {
            vshError(ctl, _("Failed to resume domain '%1$s'"),
                     virDomainGetName(dom));
            goto cleanup;
        }
    }

    while (!con->quit) {
        if (virCondWait(&con->cond, &con->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unable to wait on console condition"));
            goto cleanup;
        }
    }

    if (con->error.code == VIR_ERR_OK)
        ret = 0;

 cleanup:
    virConsoleShutdown(con, ret == 0);

    if (ret < 0) {
        vshResetLibvirtError();
        virSetError(&con->error);
        vshSaveLibvirtHelperError();
    }

    virObjectUnlock(con);
    virObjectUnref(con);

    /* Restore original signal handlers */
    sigaction(SIGQUIT, &old_sigquit, NULL);
    sigaction(SIGTERM, &old_sigterm, NULL);
    sigaction(SIGINT,  &old_sigint,  NULL);
    sigaction(SIGHUP,  &old_sighup,  NULL);
    sigaction(SIGPIPE, &old_sigpipe, NULL);

 resettty:
    /* Put STDIN back into the (sane?) state we found
       it in before starting */
    vshTTYRestore(ctl);

    return ret;
}

#endif /* !WIN32 */
