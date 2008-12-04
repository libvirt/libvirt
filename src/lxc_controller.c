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

#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <paths.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>

#include "virterror_internal.h"
#include "logging.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "veth.h"
#include "memory.h"
#include "util.h"
#include "cgroup.h"

struct cgroup_device_policy {
    char type;
    int major;
    int minor;
};

/**
 * lxcSetContainerResources
 * @def: pointer to virtual machine structure
 *
 * Creates a cgroup for the container, moves the task inside,
 * and sets resource limits
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcSetContainerResources(virDomainDefPtr def)
{
    virCgroupPtr cgroup;
    int rc = -1;
    int i;
    struct cgroup_device_policy devices[] = {
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_CONSOLE},
        {0,   0, 0}};

    if (virCgroupHaveSupport() != 0)
        return 0; /* Not supported, so claim success */

    rc = virCgroupForDomain(def, "lxc", &cgroup);
    if (rc != 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Unable to create cgroup for %s\n"), def->name);
        return rc;
    }

    rc = virCgroupSetMemory(cgroup, def->maxmem);
    if (rc != 0)
        goto out;

    rc = virCgroupDenyAllDevices(cgroup);
    if (rc != 0)
        goto out;

    for (i = 0; devices[i].type != 0; i++) {
        struct cgroup_device_policy *dev = &devices[i];
        rc = virCgroupAllowDevice(cgroup,
                                  dev->type,
                                  dev->major,
                                  dev->minor);
        if (rc != 0)
            goto out;
    }

    rc = virCgroupAllowDeviceMajor(cgroup, 'c', LXC_DEV_MAJ_PTY);
    if (rc != 0)
        goto out;

    rc = virCgroupAddTask(cgroup, getpid());
out:
    if (rc != 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to set lxc resources: %s\n"), strerror(-rc));
        virCgroupRemove(cgroup);
    }

    virCgroupFree(&cgroup);

    return rc;
}

static char*lxcMonitorPath(virDomainDefPtr def)
{
    char *sockpath;
    if (asprintf(&sockpath, "%s/%s.sock",
                 LXC_STATE_DIR, def->name) < 0) {
        lxcError(NULL, NULL, VIR_ERR_NO_MEMORY, NULL);
        return NULL;
    }
    return sockpath;
}

static int lxcMonitorServer(const char *sockpath)
{
    int fd;
    struct sockaddr_un addr;

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to create server socket %s: %s"),
                 sockpath, strerror(errno));
        goto error;
    }

    unlink(sockpath);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path));

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to bind server socket %s: %s"),
                 sockpath, strerror(errno));
        goto error;
    }
    if (listen(fd, 30 /* backlog */ ) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to listen server socket %s: %s"),
                 sockpath, strerror(errno));
        goto error;
    }

    return fd;

error:
    if (fd != -1)
        close(fd);
    return -1;
}

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
lxcControllerRun(virDomainDefPtr def,
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

    if (lxcSetContainerResources(def) < 0)
        goto cleanup;

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

    if (container > 1) {
        kill(container, SIGTERM);
        waitpid(container, NULL, 0);
    }
    return rc;
}


int main(int argc, char *argv[])
{
    pid_t pid;
    int rc = 1;
    int client;
    char *name = NULL;
    int nveths = 0;
    char **veths = NULL;
    int monitor = -1;
    int appPty = -1;
    int bg = 0;
    virCapsPtr caps = NULL;
    virDomainDefPtr def = NULL;
    char *configFile = NULL;
    char *sockpath = NULL;
    const struct option const options[] = {
        { "background", 0, NULL, 'b' },
        { "name",   1, NULL, 'n' },
        { "veth",   1, NULL, 'v' },
        { "console", 1, NULL, 'c' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };

    while (1) {
        int c;

        c = getopt_long(argc, argv, "dn:v:m:c:h",
                       options, NULL);

        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bg = 1;
            break;

        case 'n':
            if ((name = strdup(optarg)) == NULL) {
                fprintf(stderr, "%s", strerror(errno));
                goto cleanup;
            }
            break;

        case 'v':
            if (VIR_REALLOC_N(veths, nveths+1) < 0) {
                fprintf(stderr, "cannot allocate veths %s", strerror(errno));
                goto cleanup;
            }
            if ((veths[nveths++] = strdup(optarg)) == NULL) {
                fprintf(stderr, "cannot allocate veth name %s", strerror(errno));
                goto cleanup;
            }
            break;

        case 'c':
            if (virStrToLong_i(optarg, NULL, 10, &appPty) < 0) {
                fprintf(stderr, "malformed --console argument '%s'", optarg);
                goto cleanup;
            }
            break;

        case 'h':
        case '?':
            fprintf(stderr, "\n");
            fprintf(stderr, "syntax: %s [OPTIONS]\n", argv[0]);
            fprintf(stderr, "\n");
            fprintf(stderr, "Options\n");
            fprintf(stderr, "\n");
            fprintf(stderr, "  -b, --background\n");
            fprintf(stderr, "  -n NAME, --name NAME\n");
            fprintf(stderr, "  -c FD, --console FD\n");
            fprintf(stderr, "  -v VETH, --veth VETH\n");
            fprintf(stderr, "  -h, --help\n");
            fprintf(stderr, "\n");
            goto cleanup;
        }
    }


    if (name == NULL) {
        fprintf(stderr, "%s: missing --name argument for configuration\n", argv[0]);
        goto cleanup;
    }

    if (appPty < 0) {
        fprintf(stderr, "%s: missing --console argument for container PTY\n", argv[0]);
        goto cleanup;
    }

    if (getuid() && 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    if ((caps = lxcCapsInit()) == NULL)
        goto cleanup;

    if ((configFile = virDomainConfigFile(NULL,
                                          LXC_STATE_DIR,
                                          name)) == NULL)
        goto cleanup;

    if ((def = virDomainDefParseFile(NULL, caps, configFile,
                                     VIR_DOMAIN_XML_INACTIVE)) == NULL)
        goto cleanup;

    if (def->nnets != nveths) {
        fprintf(stderr, "%s: expecting %d veths, but got %d\n",
                argv[0], def->nnets, nveths);
        goto cleanup;
    }

    if ((sockpath = lxcMonitorPath(def)) == NULL)
        goto cleanup;

    if ((monitor = lxcMonitorServer(sockpath)) < 0)
        goto cleanup;

    if (bg) {
        if ((pid = fork()) < 0)
            goto cleanup;

        if (pid > 0) {
            if ((rc = virFileWritePid(LXC_STATE_DIR, name, pid)) != 0) {
                fprintf(stderr, _("Unable to write pid file: %s\n"),
                        strerror(rc));
                _exit(1);
            }

            /* First child now exits, allowing original caller
             * (ie libvirtd's LXC driver to complete their
             * waitpid & continue */
            _exit(0);
        }

        /* Don't hold onto any cwd we inherit from libvirtd either */
        if (chdir("/") < 0) {
            fprintf(stderr, _("Unable to change to root dir: %s\n"),
                    strerror(errno));
            goto cleanup;
        }

        if (setsid() < 0) {
            fprintf(stderr, _("Unable to become session leader: %s\n"),
                    strerror(errno));
            goto cleanup;
        }
    }

    /* Accept initial client which is the libvirtd daemon */
    if ((client = accept(monitor, NULL, 0)) < 0) {
        fprintf(stderr, _("Failed connection from LXC driver: %s\n"),
                strerror(errno));
        goto cleanup;
    }

    rc = lxcControllerRun(def, nveths, veths, monitor, client, appPty);


cleanup:
    virFileDeletePid(LXC_STATE_DIR, def->name);
    lxcControllerCleanupInterfaces(nveths, veths);
    unlink(sockpath);
    VIR_FREE(sockpath);

    return rc;
}

