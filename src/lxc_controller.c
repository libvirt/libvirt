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
#include <sys/wait.h>
#include <sys/socket.h>
#include <unistd.h>
#include <paths.h>
#include <fcntl.h>
#include <signal.h>

#include "internal.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_controller.h"
#include "veth.h"
#include "memory.h"
#include "util.h"


#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)


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
static int lxcControllerMain(int monitor,
                             int client,
                             int appPty,
                             int contPty)
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
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, appPty, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(appPty) failed: %s"), strerror(errno));
        goto cleanup;
    }
    epollEvent.data.fd = contPty;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, contPty, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(contPty) failed: %s"), strerror(errno));
        goto cleanup;
    }

    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = monitor;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, monitor, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(contPty) failed: %s"), strerror(errno));
        goto cleanup;
    }

    epollEvent.events = EPOLLHUP;
    epollEvent.data.fd = client;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, client, &epollEvent)) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("epoll_ctl(contPty) failed: %s"), strerror(errno));
        goto cleanup;
    }

    while (1) {
        /* if active fd's, return if no events, else wait forever */
        timeout = (numActive > 0) ? 0 : -1;
        numEvents = epoll_wait(epollFd, &epollEvent, 1, timeout);
        if (numEvents > 0) {
            if (epollEvent.data.fd == monitor) {
                int fd = accept(monitor, NULL, 0);
                if (client != -1) { /* Already connected, so kick new one out */
                    close(fd);
                    continue;
                }
                client = fd;
                epollEvent.events = EPOLLHUP;
                epollEvent.data.fd = client;
                if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, client, &epollEvent)) {
                    lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("epoll_ctl(contPty) failed: %s"), strerror(errno));
                    goto cleanup;
                }
            } else if (client != -1 && epollEvent.data.fd == client) {
                if (0 > epoll_ctl(epollFd, EPOLL_CTL_DEL, client, &epollEvent)) {
                    lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("epoll_ctl(contPty) failed: %s"), strerror(errno));
                    goto cleanup;
                }
                close(client);
                client = -1;
            } else {
                if (epollEvent.events & EPOLLIN) {
                    curFdOff = epollEvent.data.fd == appPty ? 0 : 1;
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



/**
 * lxcControllerMoveInterfaces
 * @nveths: number of interfaces
 * @veths: interface names
 * @container: pid of container
 *
 * Moves network interfaces into a container's namespace
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcControllerMoveInterfaces(unsigned int nveths,
                                       char **veths,
                                       pid_t container)
{
    unsigned int i;
    for (i = 0 ; i < nveths ; i++)
        if (moveInterfaceToNetNs(veths[i], container) < 0) {
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to move interface %s to ns %d"),
                     veths[i], container);
            return -1;
        }

    return 0;
}


/**
 * lxcCleanupInterfaces:
 * @conn: pointer to connection
 * @vm: pointer to virtual machine structure
 *
 * Cleans up the container interfaces by deleting the veth device pairs.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcControllerCleanupInterfaces(unsigned int nveths,
                                          char **veths)
{
    unsigned int i;
    for (i = 0 ; i < nveths ; i++)
        if (vethDelete(veths[i]) < 0)
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to delete veth: %s"), veths[i]);
            /* will continue to try to cleanup any other interfaces */

    return 0;
}


static int
lxcControllerRun(const char *stateDir,
                 lxc_vm_def_t *def,
                 unsigned int nveths,
                 char **veths,
                 int monitor,
                 int client,
                 int appPty)
{
    int rc = -1;
    int control[2] = { -1, -1};
    int containerPty;
    char *containerPtyPath;
    pid_t container = -1;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, control) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("sockpair failed: %s"), strerror(errno));
        goto cleanup;
    }

    if (virFileOpenTty(&containerPty,
                       &containerPtyPath,
                       0) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to allocate tty: %s"), strerror(errno));
        goto cleanup;
    }

    if ((container = lxcContainerStart(def,
                                       nveths,
                                       veths,
                                       control[1],
                                       containerPtyPath)) < 0)
        goto cleanup;
    close(control[1]);
    control[1] = -1;

    if (lxcControllerMoveInterfaces(nveths, veths, container) < 0)
        goto cleanup;

    if (lxcContainerSendContinue(control[0]) < 0)
        goto cleanup;

    rc = lxcControllerMain(monitor, client, appPty, containerPty);

cleanup:
    if (control[0] != -1)
        close(control[0]);
    if (control[1] != -1)
        close(control[1]);
    VIR_FREE(containerPtyPath);
    if (containerPty != -1)
        close(containerPty);

    kill(container, SIGTERM);
    waitpid(container, NULL, 0);
    lxcControllerCleanupInterfaces(nveths, veths);
    virFileDeletePid(stateDir, def->name);
    return rc;
}


int lxcControllerStart(const char *stateDir,
                       lxc_vm_def_t *def,
                       unsigned int nveths,
                       char **veths,
                       int monitor,
                       int appPty,
                       int logfd)
{
    pid_t pid;
    int rc;
    int status, null;
    int open_max, i;
    int client;
    struct sigaction sig_action;

    if ((pid = fork()) < 0)
        return -1;

    if (pid > 0) {
        /* Original caller waits for first child to exit */
        while (1) {
            rc = waitpid(pid, &status, 0);
            if (rc < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (rc != pid) {
                fprintf(stderr,
                        _("Unexpected pid %d != %d from waitpid\n"),
                        rc, pid);
                return -1;
            }
            if (WIFEXITED(status) &&
                WEXITSTATUS(status) == 0)
                return 0;
            else {
                fprintf(stderr,
                        _("Unexpected status %d from pid %d\n"),
                        status, pid);
                return -1;
            }
        }
    }

    /* First child is running here */

    /* Clobber all libvirtd's signal handlers so they
     * don't affect us
     */
    sig_action.sa_handler = SIG_DFL;
    sig_action.sa_flags = 0;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGHUP, &sig_action, NULL);
    sigaction(SIGINT, &sig_action, NULL);
    sigaction(SIGQUIT, &sig_action, NULL);
    sigaction(SIGTERM, &sig_action, NULL);
    sigaction(SIGCHLD, &sig_action, NULL);

    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);


    /* Don't hold onto any cwd we inherit from libvirtd either */
    if (chdir("/") < 0) {
        fprintf(stderr, _("Unable to change to root dir: %s\n"),
                strerror(errno));
        _exit(-1);
    }

    if (setsid() < 0) {
        fprintf(stderr, _("Unable to become session leader: %s\n"),
                strerror(errno));
        _exit(-1);
    }

    if ((null = open(_PATH_DEVNULL, O_RDONLY)) < 0) {
        fprintf(stderr, _("Unable to open %s: %s\n"),
                _PATH_DEVNULL, strerror(errno));
        _exit(-1);
    }

    open_max = sysconf (_SC_OPEN_MAX);
    for (i = 0; i < open_max; i++)
        if (i != appPty &&
            i != monitor &&
            i != logfd &&
            i != null)
            close(i);

    if (dup2(null, STDIN_FILENO) < 0 ||
        dup2(logfd, STDOUT_FILENO) < 0 ||
        dup2(logfd, STDERR_FILENO) < 0) {
        fprintf(stderr, _("Unable to redirect stdio: %s\n"),
                strerror(errno));
        _exit(-1);
    }

    close(null);
    close(logfd);

    /* Now fork the real controller process */
    if ((pid = fork()) < 0) {
        fprintf(stderr, _("Unable to fork controller: %s\n"),
                strerror(errno));
        _exit(-1);
    }

    if (pid > 0) {
        if ((rc = virFileWritePid(stateDir, def->name, pid)) != 0) {
            fprintf(stderr, _("Unable to write pid file: %s\n"),
                    strerror(rc));
            _exit(-1);
        }
        /* First child now exits, allowing originall caller to
         * complete their waitpid & continue */
        _exit(0);
    }

    /* This is real controller running finally... */

    /* Accept initial client which is the libvirtd daemon */
    if ((client = accept(monitor, NULL, 0))) {
        fprintf(stderr, _("Failed connection from LXC driver: %s\n"),
                strerror(errno));
        _exit(-1);
    }

    /* Controlling libvirtd LXC driver now knows
       what our PID is, and is able to cleanup after
       us from now on */
    _exit(lxcControllerRun(stateDir, def, nveths, veths, monitor, client, appPty));
}


#endif
