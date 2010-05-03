/*
 * console.c: A dumb serial console client
 *
 * Copyright (C) 2007, 2008, 2010 Red Hat, Inc.
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

# include "console.h"
# include "internal.h"
# include "logging.h"
# include "util.h"

/* ie  Ctrl-]  as per telnet */
# define CTRL_CLOSE_BRACKET '\35'

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

int vshRunConsole(const char *tty) {
    int ttyfd, ret = -1;
    struct termios ttyattr, rawattr;
    void (*old_sigquit)(int);
    void (*old_sigterm)(int);
    void (*old_sigint)(int);
    void (*old_sighup)(int);
    void (*old_sigpipe)(int);


    /* We do not want this to become the controlling TTY */
    if ((ttyfd = open(tty, O_NOCTTY | O_RDWR)) < 0) {
        VIR_ERROR(_("unable to open tty %s: %s"),
                  tty, strerror(errno));
        return -1;
    }

    /* Put STDIN into raw mode so that stuff typed
       does not echo to the screen (the TTY reads will
       result in it being echoed back already), and
       also ensure Ctrl-C, etc is blocked, and misc
       other bits */
    if (tcgetattr(STDIN_FILENO, &ttyattr) < 0) {
        VIR_ERROR(_("unable to get tty attributes: %s"),
                  strerror(errno));
        goto closetty;
    }

    rawattr = ttyattr;
    cfmakeraw(&rawattr);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &rawattr) < 0) {
        VIR_ERROR(_("unable to set tty attributes: %s"),
                  strerror(errno));
        goto closetty;
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


    /* Now lets process STDIN & tty forever.... */
    for (; !got_signal ;) {
        unsigned int i;
        struct pollfd fds[] = {
            { STDIN_FILENO, POLLIN, 0 },
            { ttyfd, POLLIN, 0 },
        };

        /* Wait for data to be available for reading on
           STDIN or the tty */
        if (poll(fds, (sizeof(fds)/sizeof(struct pollfd)), -1) < 0) {
            if (got_signal)
                goto cleanup;

            if (errno == EINTR || errno == EAGAIN)
                continue;

            VIR_ERROR(_("failure waiting for I/O: %s"), strerror(errno));
            goto cleanup;
        }

        for (i = 0 ; i < (sizeof(fds)/sizeof(struct pollfd)) ; i++) {
            if (!fds[i].revents)
                continue;

            /* Process incoming data available for read */
            if (fds[i].revents & POLLIN) {
                char buf[4096];
                int got, sent = 0, destfd;

                if ((got = read(fds[i].fd, buf, sizeof(buf))) < 0) {
                    VIR_ERROR(_("failure reading input: %s"),
                              strerror(errno));
                    goto cleanup;
                }

                /* Quit if end of file, or we got the Ctrl-] key */
                if (!got ||
                    (got == 1 &&
                     buf[0] == CTRL_CLOSE_BRACKET))
                    goto done;

                /* Data from stdin goes to the TTY,
                   data from the TTY goes to STDOUT */
                if (fds[i].fd == STDIN_FILENO)
                    destfd = ttyfd;
                else
                    destfd = STDOUT_FILENO;

                while (sent < got) {
                    int done;
                    if ((done = safewrite(destfd, buf + sent, got - sent))
                        <= 0) {
                        VIR_ERROR(_("failure writing output: %s"),
                                  strerror(errno));
                        goto cleanup;
                    }
                    sent += done;
                }
            } else { /* Any other flag from poll is an error condition */
                goto cleanup;
            }
        }
    }
 done:
    ret = 0;

 cleanup:

    /* Restore original signal handlers */
    signal(SIGQUIT, old_sigpipe);
    signal(SIGQUIT, old_sighup);
    signal(SIGQUIT, old_sigint);
    signal(SIGQUIT, old_sigterm);
    signal(SIGQUIT, old_sigquit);

    /* Put STDIN back into the (sane?) state we found
       it in before starting */
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &ttyattr);

 closetty:
    close(ttyfd);

    return ret;
}

#endif /* !WIN32 */
