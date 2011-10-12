/*
 * console.c: A dumb serial console client
 *
 * Copyright (C) 2007-2008, 2010-2011 Red Hat, Inc.
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
 * Daniel Berrange <berrange@redhat.com>
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

# include "internal.h"
# include "console.h"
# include "logging.h"
# include "util.h"
# include "virfile.h"
# include "memory.h"
# include "threads.h"
# include "virterror_internal.h"

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
static void do_signal(int sig ATTRIBUTE_UNUSED) {
    got_signal = 1;
}

# ifndef HAVE_CFMAKERAW
static void
cfmakeraw (struct termios *attr)
{
    attr->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                         | INLCR | IGNCR | ICRNL | IXON);
    attr->c_oflag &= ~OPOST;
    attr->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    attr->c_cflag &= ~(CSIZE | PARENB);
    attr->c_cflag |= CS8;
}
# endif /* !HAVE_CFMAKERAW */

static void
virConsoleShutdown(virConsolePtr con)
{
    if (con->st) {
        virStreamEventRemoveCallback(con->st);
        virStreamAbort(con->st);
        virStreamFree(con->st);
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
                virReportOOMError();
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
            if (VIR_REALLOC_N(con->terminalToStream.data,
                              con->terminalToStream.offset + 1024) < 0)
            {}
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
                virReportOOMError();
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
            if (VIR_REALLOC_N(con->streamToTerminal.data,
                              con->streamToTerminal.offset + 1024) < 0)
            {}
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
        return CONTROL(s[1]);

    return *s;
}

int vshRunConsole(virDomainPtr dom,
                  const char *dev_name,
                  const char *escape_seq,
                  unsigned int flags)
{
    int ret = -1;
    struct termios ttyattr, rawattr;
    void (*old_sigquit)(int);
    void (*old_sigterm)(int);
    void (*old_sigint)(int);
    void (*old_sighup)(int);
    void (*old_sigpipe)(int);
    virConsolePtr con = NULL;

    /* Put STDIN into raw mode so that stuff typed
       does not echo to the screen (the TTY reads will
       result in it being echoed back already), and
       also ensure Ctrl-C, etc is blocked, and misc
       other bits */
    if (tcgetattr(STDIN_FILENO, &ttyattr) < 0) {
        VIR_ERROR(_("unable to get tty attributes: %s"),
                  strerror(errno));
        return -1;
    }

    rawattr = ttyattr;
    cfmakeraw(&rawattr);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawattr) < 0) {
        VIR_ERROR(_("unable to set tty attributes: %s"),
                  strerror(errno));
        goto resettty;
    }


    /* Trap all common signals so that we can safely restore
       the original terminal settings on STDIN before the
       process exits - people don't like being left with a
       messed up terminal ! */
    old_sigquit = signal(SIGQUIT, do_signal);
    old_sigterm = signal(SIGTERM, do_signal);
    old_sigint = signal(SIGINT, do_signal);
    old_sighup = signal(SIGHUP, do_signal);
    old_sigpipe = signal(SIGPIPE, do_signal);
    got_signal = 0;

    if (VIR_ALLOC(con) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    con->escapeChar = vshGetEscapeChar(escape_seq);
    con->st = virStreamNew(virDomainGetConnect(dom),
                           VIR_STREAM_NONBLOCK);
    if (!con->st)
        goto cleanup;

    if (virDomainOpenConsole(dom, dev_name, con->st, flags) < 0)
        goto cleanup;

    if (virCondInit(&con->cond) < 0 || virMutexInit(&con->lock) < 0)
        goto cleanup;

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
            VIR_ERROR(_("unable to wait on console condition"));
            goto cleanup;
        }
    }

    ret = 0;

 cleanup:

    if (con) {
        if (con->st)
            virStreamFree(con->st);
        virMutexDestroy(&con->lock);
        ignore_value(virCondDestroy(&con->cond));
        VIR_FREE(con);
    }

    /* Restore original signal handlers */
    signal(SIGPIPE, old_sigpipe);
    signal(SIGHUP, old_sighup);
    signal(SIGINT, old_sigint);
    signal(SIGTERM, old_sigterm);
    signal(SIGQUIT, old_sigquit);

resettty:
    /* Put STDIN back into the (sane?) state we found
       it in before starting */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ttyattr);

    return ret;
}

#endif /* !WIN32 */
