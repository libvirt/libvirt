/*
 * virsh-console.c: A dumb serial console client
 *
 * Copyright (C) 2007-2008, 2010-2013 Red Hat, Inc.
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
 * Authors:
 *     Daniel Berrange <berrange@redhat.com>
 */

#include <config.h>

#ifndef WIN32

# include <stdio.h>
# include <sys/types.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <termios.h>
# include <poll.h>
# include <string.h>
# include <errno.h>
# include <unistd.h>
# include <signal.h>
# include <c-ctype.h>

# include "internal.h"
# include "virsh.h"
# include "virsh-console.h"
# include "virlog.h"
# include "virfile.h"
# include "viralloc.h"
# include "virthread.h"
# include "virerror.h"

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
typedef virConsole *virConsolePtr;
struct virConsole {
    virStreamPtr st;
    bool quit;
    virMutex lock;
    virCond cond;

    int stdinWatch;
    int stdoutWatch;

    struct virConsoleBuffer streamToTerminal;
    struct virConsoleBuffer terminalToStream;

    char escapeChar;
};


static int got_signal = 0;
static void
virConsoleHandleSignal(int sig ATTRIBUTE_UNUSED)
{
    got_signal = 1;
}


static void
virConsoleShutdown(virConsolePtr con)
{
    if (con->st) {
        virStreamEventRemoveCallback(con->st);
        virStreamAbort(con->st);
        virStreamFree(con->st);
        con->st = NULL;
    }
    VIR_FREE(con->streamToTerminal.data);
    VIR_FREE(con->terminalToStream.data);
    if (con->stdinWatch != -1)
        virEventRemoveHandle(con->stdinWatch);
    if (con->stdoutWatch != -1)
        virEventRemoveHandle(con->stdoutWatch);
    con->stdinWatch = -1;
    con->stdoutWatch = -1;
    con->quit = true;
    virCondSignal(&con->cond);
}


static void
virConsoleFree(virConsolePtr con)
{
    if (!con)
        return;

    if (con->st)
        virStreamFree(con->st);
    virMutexDestroy(&con->lock);
    virCondDestroy(&con->cond);
    VIR_FREE(con);
}


static void
virConsoleEventOnStream(virStreamPtr st,
                        int events, void *opaque)
{
    virConsolePtr con = opaque;

    if (events & VIR_STREAM_EVENT_READABLE) {
        size_t avail = con->streamToTerminal.length -
            con->streamToTerminal.offset;
        int got;

        if (avail < 1024) {
            if (VIR_REALLOC_N(con->streamToTerminal.data,
                              con->streamToTerminal.length + 1024) < 0) {
                virConsoleShutdown(con);
                return;
            }
            con->streamToTerminal.length += 1024;
            avail += 1024;
        }

        got = virStreamRecv(st,
                            con->streamToTerminal.data +
                            con->streamToTerminal.offset,
                            avail);
        if (got == -2)
            return; /* blocking */
        if (got <= 0) {
            virConsoleShutdown(con);
            return;
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
            return; /* blocking */
        if (done < 0) {
            virConsoleShutdown(con);
            return;
        }
        memmove(con->terminalToStream.data,
                con->terminalToStream.data + done,
                con->terminalToStream.offset - done);
        con->terminalToStream.offset -= done;

        avail = con->terminalToStream.length - con->terminalToStream.offset;
        if (avail > 1024) {
            ignore_value(VIR_REALLOC_N(con->terminalToStream.data,
                                       con->terminalToStream.offset + 1024));
            con->terminalToStream.length = con->terminalToStream.offset + 1024;
        }
    }
    if (!con->terminalToStream.offset)
        virStreamEventUpdateCallback(con->st,
                                     VIR_STREAM_EVENT_READABLE);

    if (events & VIR_STREAM_EVENT_ERROR ||
        events & VIR_STREAM_EVENT_HANGUP) {
        virConsoleShutdown(con);
    }
}


static void
virConsoleEventOnStdin(int watch ATTRIBUTE_UNUSED,
                       int fd ATTRIBUTE_UNUSED,
                       int events,
                       void *opaque)
{
    virConsolePtr con = opaque;

    if (events & VIR_EVENT_HANDLE_READABLE) {
        size_t avail = con->terminalToStream.length -
            con->terminalToStream.offset;
        int got;

        if (avail < 1024) {
            if (VIR_REALLOC_N(con->terminalToStream.data,
                              con->terminalToStream.length + 1024) < 0) {
                virConsoleShutdown(con);
                return;
            }
            con->terminalToStream.length += 1024;
            avail += 1024;
        }

        got = read(fd,
                   con->terminalToStream.data +
                   con->terminalToStream.offset,
                   avail);
        if (got < 0) {
            if (errno != EAGAIN) {
                virConsoleShutdown(con);
            }
            return;
        }
        if (got == 0) {
            virConsoleShutdown(con);
            return;
        }
        if (con->terminalToStream.data[con->terminalToStream.offset] == con->escapeChar) {
            virConsoleShutdown(con);
            return;
        }

        con->terminalToStream.offset += got;
        if (con->terminalToStream.offset)
            virStreamEventUpdateCallback(con->st,
                                         VIR_STREAM_EVENT_READABLE |
                                         VIR_STREAM_EVENT_WRITABLE);
    }

    if (events & VIR_EVENT_HANDLE_ERROR ||
        events & VIR_EVENT_HANDLE_HANGUP) {
        virConsoleShutdown(con);
    }
}


static void
virConsoleEventOnStdout(int watch ATTRIBUTE_UNUSED,
                        int fd,
                        int events,
                        void *opaque)
{
    virConsolePtr con = opaque;

    if (events & VIR_EVENT_HANDLE_WRITABLE &&
        con->streamToTerminal.offset) {
        ssize_t done;
        size_t avail;
        done = write(fd,
                     con->streamToTerminal.data,
                     con->streamToTerminal.offset);
        if (done < 0) {
            if (errno != EAGAIN) {
                virConsoleShutdown(con);
            }
            return;
        }
        memmove(con->streamToTerminal.data,
                con->streamToTerminal.data + done,
                con->streamToTerminal.offset - done);
        con->streamToTerminal.offset -= done;

        avail = con->streamToTerminal.length - con->streamToTerminal.offset;
        if (avail > 1024) {
            ignore_value(VIR_REALLOC_N(con->streamToTerminal.data,
                                       con->streamToTerminal.offset + 1024));
            con->streamToTerminal.length = con->streamToTerminal.offset + 1024;
        }
    }

    if (!con->streamToTerminal.offset)
        virEventUpdateHandle(con->stdoutWatch, 0);

    if (events & VIR_EVENT_HANDLE_ERROR ||
        events & VIR_EVENT_HANDLE_HANGUP) {
        virConsoleShutdown(con);
    }
}


static char
vshGetEscapeChar(const char *s)
{
    if (*s == '^')
        return CONTROL(c_toupper(s[1]));

    return *s;
}


int
vshRunConsole(vshControl *ctl,
              virDomainPtr dom,
              const char *dev_name,
              unsigned int flags)
{
    virConsolePtr con = NULL;
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

    /* Trap all common signals so that we can safely restore the original
     * terminal settings on STDIN before the process exits - people don't like
     * being left with a messed up terminal ! */
    got_signal = 0;
    sigaction(SIGQUIT, &sighandler, &old_sigquit);
    sigaction(SIGTERM, &sighandler, &old_sigterm);
    sigaction(SIGINT,  &sighandler, &old_sigint);
    sigaction(SIGHUP,  &sighandler, &old_sighup);
    sigaction(SIGPIPE, &sighandler, &old_sigpipe);

    if (VIR_ALLOC(con) < 0)
        goto cleanup;

    con->escapeChar = vshGetEscapeChar(ctl->escapeChar);
    con->st = virStreamNew(virDomainGetConnect(dom),
                           VIR_STREAM_NONBLOCK);
    if (!con->st)
        goto cleanup;

    if (virDomainOpenConsole(dom, dev_name, con->st, flags) < 0)
        goto cleanup;

    if (virCondInit(&con->cond) < 0 || virMutexInit(&con->lock) < 0)
        goto cleanup;

    virMutexLock(&con->lock);

    con->stdinWatch = virEventAddHandle(STDIN_FILENO,
                                        VIR_EVENT_HANDLE_READABLE,
                                        virConsoleEventOnStdin,
                                        con,
                                        NULL);
    con->stdoutWatch = virEventAddHandle(STDOUT_FILENO,
                                         0,
                                         virConsoleEventOnStdout,
                                         con,
                                         NULL);

    virStreamEventAddCallback(con->st,
                              VIR_STREAM_EVENT_READABLE,
                              virConsoleEventOnStream,
                              con,
                              NULL);

    while (!con->quit) {
        if (virCondWait(&con->cond, &con->lock) < 0) {
            virMutexUnlock(&con->lock);
            VIR_ERROR(_("unable to wait on console condition"));
            goto cleanup;
        }
    }

    virMutexUnlock(&con->lock);

    ret = 0;

 cleanup:
    virConsoleFree(con);

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
