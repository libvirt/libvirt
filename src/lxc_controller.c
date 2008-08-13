/*
 * Copyright IBM Corp. 2008
 *
 * lxc_controller.c: linux container process controller
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <config.h>

#ifdef WITH_LXC

#include <sys/epoll.h>
#include <unistd.h>

#include "internal.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_controller.h"


#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)

/**
 * lxcFdForward:
 * @readFd: file descriptor to read
 * @writeFd: file desriptor to write
 *
 * Reads 1 byte of data from readFd and writes to writeFd.
 *
 * Returns 0 on success, EAGAIN if returned on read, or -1 in case of error
 */
static int lxcFdForward(int readFd, int writeFd)
{
    int rc = -1;
    char buf[2];

    if (1 != (saferead(readFd, buf, 1))) {
        if (EAGAIN == errno) {
            rc = EAGAIN;
            goto cleanup;
        }

        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("read of fd %d failed: %s"), readFd, strerror(errno));
        goto cleanup;
    }

    if (1 != (safewrite(writeFd, buf, 1))) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("write to fd %d failed: %s"), writeFd, strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    return rc;
}

typedef struct _lxcTtyForwardFd_t {
    int fd;
    int active;
} lxcTtyForwardFd_t;

/**
 * lxcTtyForward:
 * @appPty: Open fd for application facing Pty
 * @contPty: Open fd for container facing Pty
 *
 * Forwards traffic between fds.  Data read from appPty will be written to contPty
 * This process loops forever.
 * This uses epoll in edge triggered mode to avoid a hard loop on POLLHUP
 * events when the user disconnects the virsh console via ctrl-]
 *
 * Returns 0 on success or -1 in case of error
 */
int lxcControllerMain(int appPty, int contPty)
{
    int rc = -1;
    int epollFd;
    struct epoll_event epollEvent;
    int numEvents;
    int numActive = 0;
    lxcTtyForwardFd_t fdArray[2];
    int timeout = -1;
    int curFdOff = 0;
    int writeFdOff = 0;

    fdArray[0].fd = appPty;
    fdArray[0].active = 0;
    fdArray[1].fd = contPty;
    fdArray[1].active = 0;

    /* create the epoll fild descriptor */
    epollFd = epoll_create(2);
    if (0 > epollFd) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_create(2) failed: %s"), strerror(errno));
        goto cleanup;
    }

    /* add the file descriptors the epoll fd */
    memset(&epollEvent, 0x00, sizeof(epollEvent));
    epollEvent.events = EPOLLIN|EPOLLET;    /* edge triggered */
    epollEvent.data.fd = appPty;
    epollEvent.data.u32 = 0;                /* fdArray position */
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, appPty, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(appPty) failed: %s"), strerror(errno));
        goto cleanup;
    }
    epollEvent.data.fd = contPty;
    epollEvent.data.u32 = 1;                /* fdArray position */
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, contPty, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(contPty) failed: %s"), strerror(errno));
        goto cleanup;
    }

    while (1) {
        /* if active fd's, return if no events, else wait forever */
        timeout = (numActive > 0) ? 0 : -1;
        numEvents = epoll_wait(epollFd, &epollEvent, 1, timeout);
        if (0 < numEvents) {
            if (epollEvent.events & EPOLLIN) {
                curFdOff = epollEvent.data.u32;
                if (!fdArray[curFdOff].active) {
                    fdArray[curFdOff].active = 1;
                    ++numActive;
                }

            } else if (epollEvent.events & EPOLLHUP) {
                DEBUG("EPOLLHUP from fd %d", epollEvent.data.fd);
                continue;
            } else {
                lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("error event %d"), epollEvent.events);
                goto cleanup;
            }

        } else if (0 == numEvents) {
            if (2 == numActive) {
                /* both fds active, toggle between the two */
                curFdOff ^= 1;
            } else {
                /* only one active, if current is active, use it, else it */
                /* must be the other one (ie. curFd just went inactive) */
                curFdOff = fdArray[curFdOff].active ? curFdOff : curFdOff ^ 1;
            }

        } else  {
            if (EINTR == errno) {
                continue;
            }

            /* error */
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("epoll_wait() failed: %s"), strerror(errno));
            goto cleanup;

        }

        if (0 < numActive) {
            writeFdOff = curFdOff ^ 1;
            rc = lxcFdForward(fdArray[curFdOff].fd, fdArray[writeFdOff].fd);

            if (EAGAIN == rc) {
                /* this fd no longer has data, set it as inactive */
                --numActive;
                fdArray[curFdOff].active = 0;
            } else if (-1 == rc) {
                goto cleanup;
            }

        }

    }

    rc = 0;

cleanup:
    close(appPty);
    close(contPty);
    close(epollFd);
    return rc;
}

#endif
