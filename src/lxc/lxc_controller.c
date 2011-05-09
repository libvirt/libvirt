/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
#include <sys/utsname.h>
#include <sys/personality.h>
#include <unistd.h>
#include <paths.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <sys/mount.h>
#include <locale.h>

#if HAVE_CAPNG
# include <cap-ng.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "veth.h"
#include "memory.h"
#include "util.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_LXC

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
    virCgroupPtr driver;
    virCgroupPtr cgroup;
    int rc = -1;
    int i;
    struct cgroup_device_policy devices[] = {
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_TTY},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_PTMX},
        {0,   0, 0}};

    rc = virCgroupForDriver("lxc", &driver, 1, 0);
    if (rc != 0) {
        /* Skip all if no driver cgroup is configured */
        if (rc == -ENXIO || rc == -ENOENT)
            return 0;

        virReportSystemError(-rc, "%s",
                             _("Unable to get cgroup for driver"));
        return rc;
    }

    rc = virCgroupForDomain(driver, def->name, &cgroup, 1);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to create cgroup for domain %s"),
                             def->name);
        goto cleanup;
    }

    if (def->blkio.weight) {
        rc = virCgroupSetBlkioWeight(cgroup, def->blkio.weight);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set Blkio weight for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    if (def->cputune.shares) {
        rc = virCgroupSetCpuShares(cgroup, def->cputune.shares);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set cpu shares for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    rc = virCgroupSetMemory(cgroup, def->mem.max_balloon);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to set memory limit for domain %s"),
                             def->name);
        goto cleanup;
    }

    if (def->mem.hard_limit) {
        rc = virCgroupSetMemoryHardLimit(cgroup, def->mem.hard_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set memory hard limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    if (def->mem.soft_limit) {
        rc = virCgroupSetMemorySoftLimit(cgroup, def->mem.soft_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set memory soft limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    if (def->mem.swap_hard_limit) {
        rc = virCgroupSetMemSwapHardLimit(cgroup, def->mem.swap_hard_limit);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set swap hard limit for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    rc = virCgroupDenyAllDevices(cgroup);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to deny devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    for (i = 0; devices[i].type != 0; i++) {
        struct cgroup_device_policy *dev = &devices[i];
        rc = virCgroupAllowDevice(cgroup,
                                  dev->type,
                                  dev->major,
                                  dev->minor,
                                  VIR_CGROUP_DEVICE_RWM);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %c:%d:%d for domain %s"),
                                 dev->type, dev->major, dev->minor, def->name);
            goto cleanup;
        }
    }

    rc = virCgroupAllowDeviceMajor(cgroup, 'c', LXC_DEV_MAJ_PTY,
                                   VIR_CGROUP_DEVICE_RWM);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to allow PYT devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    rc = virCgroupAddTask(cgroup, getpid());
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to add task %d to cgroup for domain %s"),
                             getpid(), def->name);
    }

cleanup:
    virCgroupFree(&driver);
    virCgroupFree(&cgroup);

    return rc;
}

static char*lxcMonitorPath(virDomainDefPtr def)
{
    char *sockpath;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    LXC_STATE_DIR, def->name) < 0)
        virReportOOMError();
    return sockpath;
}

static int lxcMonitorServer(const char *sockpath)
{
    int fd;
    struct sockaddr_un addr;

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             _("failed to create server socket '%s'"),
                             sockpath);
        goto error;
    }

    unlink(sockpath);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, sockpath) == NULL) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("Socket path %s too long for destination"), sockpath);
        goto error;
    }

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        virReportSystemError(errno,
                             _("failed to bind server socket '%s'"),
                             sockpath);
        goto error;
    }
    if (listen(fd, 30 /* backlog */ ) < 0) {
        virReportSystemError(errno,
                             _("failed to listen server socket %s"),
                             sockpath);
        goto error;
    }

    return fd;

error:
    VIR_FORCE_CLOSE(fd);
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

        virReportSystemError(errno,
                             _("read of fd %d failed"),
                             readFd);
        goto cleanup;
    }

    if (1 != (safewrite(writeFd, buf, 1))) {
        virReportSystemError(errno,
                             _("write to fd %d failed"),
                             writeFd);
        goto cleanup;
    }

    rc = 0;

cleanup:
    return rc;
}


static int lxcControllerClearCapabilities(void)
{
#if HAVE_CAPNG
    int ret;

    capng_clear(CAPNG_SELECT_BOTH);

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR,
                 _("failed to apply capabilities: %d"), ret);
        return -1;
    }
#else
    VIR_WARN("libcap-ng support not compiled in, unable to clear capabilities");
#endif
    return 0;
}

typedef struct _lxcTtyForwardFd_t {
    int fd;
    int active;
} lxcTtyForwardFd_t;

/* Return true if it is ok to ignore an accept-after-epoll syscall
   that fails with the specified errno value.  Else false.  */
static bool
ignorable_epoll_accept_errno(int errnum)
{
  return (errnum == EINVAL
          || errnum == ECONNABORTED
          || errnum == EAGAIN
          || errnum == EWOULDBLOCK);
}

static bool
lxcPidGone(pid_t container)
{
    waitpid(container, NULL, WNOHANG);

    if (kill(container, 0) < 0 &&
        errno == ESRCH)
        return true;

    return false;
}

/**
 * lxcControllerMain
 * @monitor: server socket fd to accept client requests
 * @client: initial client which is the libvirtd daemon
 * @appPty: open fd for application facing Pty
 * @contPty: open fd for container facing Pty
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
                             int contPty,
                             pid_t container)
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

    VIR_DEBUG("monitor=%d client=%d appPty=%d contPty=%d",
              monitor, client, appPty, contPty);

    /* create the epoll fild descriptor */
    epollFd = epoll_create(2);
    if (0 > epollFd) {
        virReportSystemError(errno, "%s",
                             _("epoll_create(2) failed"));
        goto cleanup;
    }

    /* add the file descriptors the epoll fd */
    memset(&epollEvent, 0x00, sizeof(epollEvent));
    epollEvent.events = EPOLLIN|EPOLLET;    /* edge triggered */
    epollEvent.data.fd = appPty;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, appPty, &epollEvent)) {
        virReportSystemError(errno, "%s",
                             _("epoll_ctl(appPty) failed"));
        goto cleanup;
    }
    epollEvent.data.fd = contPty;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, contPty, &epollEvent)) {
        virReportSystemError(errno, "%s",
                             _("epoll_ctl(contPty) failed"));
        goto cleanup;
    }

    epollEvent.events = EPOLLIN;
    epollEvent.data.fd = monitor;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, monitor, &epollEvent)) {
        virReportSystemError(errno, "%s",
                             _("epoll_ctl(monitor) failed"));
        goto cleanup;
    }

    epollEvent.events = EPOLLHUP;
    epollEvent.data.fd = client;
    if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, client, &epollEvent)) {
        virReportSystemError(errno, "%s",
                             _("epoll_ctl(client) failed"));
        goto cleanup;
    }

    while (1) {
        /* if active fd's, return if no events, else wait forever */
        timeout = (numActive > 0) ? 0 : -1;
        numEvents = epoll_wait(epollFd, &epollEvent, 1, timeout);
        if (numEvents > 0) {
            if (epollEvent.data.fd == monitor) {
                int fd = accept(monitor, NULL, 0);
                if (fd < 0) {
                    /* First reflex may be simply to declare accept failure
                       to be a fatal error.  However, accept may fail when
                       a client quits between the above epoll_wait and here.
                       That case is not fatal, but rather to be expected,
                       if not common, so ignore it.  */
                    if (ignorable_epoll_accept_errno(errno))
                        continue;
                    virReportSystemError(errno, "%s",
                                         _("accept(monitor,...) failed"));
                    goto cleanup;
                }
                if (client != -1) { /* Already connected, so kick new one out */
                    VIR_FORCE_CLOSE(fd);
                    continue;
                }
                client = fd;
                epollEvent.events = EPOLLHUP;
                epollEvent.data.fd = client;
                if (0 > epoll_ctl(epollFd, EPOLL_CTL_ADD, client, &epollEvent)) {
                    virReportSystemError(errno, "%s",
                                         _("epoll_ctl(client) failed"));
                    goto cleanup;
                }
            } else if (client != -1 && epollEvent.data.fd == client) {
                if (0 > epoll_ctl(epollFd, EPOLL_CTL_DEL, client, &epollEvent)) {
                    virReportSystemError(errno, "%s",
                                         _("epoll_ctl(client) failed"));
                    goto cleanup;
                }
                VIR_FORCE_CLOSE(client);
            } else {
                if (epollEvent.events & EPOLLIN) {
                    curFdOff = epollEvent.data.fd == appPty ? 0 : 1;
                    if (!fdArray[curFdOff].active) {
                        fdArray[curFdOff].active = 1;
                        ++numActive;
                    }
                } else if (epollEvent.events & EPOLLHUP) {
                    if (lxcPidGone(container))
                        goto cleanup;
                    curFdOff = epollEvent.data.fd == appPty ? 0 : 1;
                    if (fdArray[curFdOff].active) {
                        fdArray[curFdOff].active = 0;
                        --numActive;
                    }
                    continue;
                } else {
                    lxcError(VIR_ERR_INTERNAL_ERROR,
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
            virReportSystemError(errno, "%s",
                                 _("epoll_wait() failed"));
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
                if (lxcPidGone(container))
                    goto cleanup;
                continue;
            }

        }

    }

    rc = 0;

cleanup:
    VIR_FORCE_CLOSE(appPty);
    VIR_FORCE_CLOSE(contPty);
    VIR_FORCE_CLOSE(epollFd);
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
        if (moveInterfaceToNetNs(veths[i], container) < 0)
            return -1;

    return 0;
}


/**
 * lxcCleanupInterfaces:
 * @nveths: number of interfaces
 * @veths: interface names
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
        vethDelete(veths[i]);

    return 0;
}

static int lxcSetPersonality(virDomainDefPtr def)
{
    struct utsname utsname;
    const char *altArch;

    uname(&utsname);

    altArch = lxcContainerGetAlt32bitArch(utsname.machine);
    if (altArch &&
        STREQ(def->os.arch, altArch)) {
        if (personality(PER_LINUX32) < 0) {
            virReportSystemError(errno, _("Unable to request personality for %s on %s"),
                                 altArch, utsname.machine);
            return -1;
        }
    }
    return 0;
}

#ifndef MS_REC
# define MS_REC          16384
#endif

#ifndef MS_SLAVE
# define MS_SLAVE              (1<<19)
#endif

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
    int containerPty = -1;
    char *containerPtyPath = NULL;
    pid_t container = -1;
    virDomainFSDefPtr root;
    char *devpts = NULL;
    char *devptmx = NULL;

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, control) < 0) {
        virReportSystemError(errno, "%s",
                             _("sockpair failed"));
        goto cleanup;
    }

    root = virDomainGetRootFilesystem(def);

    if (lxcSetContainerResources(def) < 0)
        goto cleanup;

    /*
     * If doing a chroot style setup, we need to prepare
     * a private /dev/pts for the child now, which they
     * will later move into position.
     *
     * This is complex because 'virsh console' needs to
     * use /dev/pts from the host OS, and the guest OS
     * needs to use /dev/pts from the guest.
     *
     * This means that we (libvirt_lxc) need to see and
     * use both /dev/pts instances. We're running in the
     * host OS context though and don't want to expose
     * the guest OS /dev/pts there.
     *
     * Thus we call unshare(CLONE_NS) so that we can see
     * the guest's new /dev/pts, without it becoming
     * visible to the host OS. We also put the root FS
     * into slave mode, just in case it was currently
     * marked as shared
     */
    if (root) {
        VIR_DEBUG("Setting up private /dev/pts");
        if (unshare(CLONE_NEWNS) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Cannot unshare mount namespace"));
            goto cleanup;
        }

        if (mount("", "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to switch root mount into slave mode"));
            goto cleanup;
        }

        if (virAsprintf(&devpts, "%s/dev/pts", root->src) < 0 ||
            virAsprintf(&devptmx, "%s/dev/pts/ptmx", root->src) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virFileMakePath(devpts) != 0) {
            virReportSystemError(errno,
                                 _("Failed to make path %s"),
                                 devpts);
            goto cleanup;
        }

        VIR_DEBUG("Mouting 'devpts' on %s", devpts);
        if (mount("devpts", devpts, "devpts", 0,
                  "newinstance,ptmxmode=0666,mode=0620,gid=5") < 0) {
            virReportSystemError(errno,
                                 _("Failed to mount devpts on %s"),
                                 devpts);
            goto cleanup;
        }

        if (access(devptmx, R_OK) < 0) {
            VIR_WARN("Kernel does not support private devpts, using shared devpts");
            VIR_FREE(devptmx);
        }
    }

    if (devptmx) {
        VIR_DEBUG("Opening tty on private %s", devptmx);
        if (virFileOpenTtyAt(devptmx,
                             &containerPty,
                             &containerPtyPath,
                             0) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }
    } else {
        VIR_DEBUG("Opening tty on shared /dev/ptmx");
        if (virFileOpenTty(&containerPty,
                           &containerPtyPath,
                           0) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            goto cleanup;
        }
    }

    if (lxcSetPersonality(def) < 0)
        goto cleanup;

    if ((container = lxcContainerStart(def,
                                       nveths,
                                       veths,
                                       control[1],
                                       containerPtyPath)) < 0)
        goto cleanup;
    VIR_FORCE_CLOSE(control[1]);

    if (lxcControllerMoveInterfaces(nveths, veths, container) < 0)
        goto cleanup;

    if (lxcContainerSendContinue(control[0]) < 0)
        goto cleanup;

    /* Now the container is running, there's no need for us to keep
       any elevated capabilities */
    if (lxcControllerClearCapabilities() < 0)
        goto cleanup;

    rc = lxcControllerMain(monitor, client, appPty, containerPty, container);

cleanup:
    VIR_FREE(devptmx);
    VIR_FREE(devpts);
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FREE(containerPtyPath);
    VIR_FORCE_CLOSE(containerPty);

    if (container > 1) {
        int status;
        kill(container, SIGTERM);
        if (!(waitpid(container, &status, WNOHANG) == 0 &&
            WIFEXITED(status)))
            kill(container, SIGKILL);
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
    const struct option options[] = {
        { "background", 0, NULL, 'b' },
        { "name",   1, NULL, 'n' },
        { "veth",   1, NULL, 'v' },
        { "console", 1, NULL, 'c' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

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
                virReportOOMError();
                goto cleanup;
            }
            break;

        case 'v':
            if (VIR_REALLOC_N(veths, nveths+1) < 0) {
                virReportOOMError();
                goto cleanup;
            }
            if ((veths[nveths++] = strdup(optarg)) == NULL) {
                virReportOOMError();
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

    if (getuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    if ((caps = lxcCapsInit()) == NULL)
        goto cleanup;

    if ((configFile = virDomainConfigFile(LXC_STATE_DIR,
                                          name)) == NULL)
        goto cleanup;

    if ((def = virDomainDefParseFile(caps, configFile,
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
                virReportSystemError(rc,
                                     _("Unable to write pid file '%s/%s.pid'"),
                                     LXC_STATE_DIR, name);
                _exit(1);
            }

            /* First child now exits, allowing original caller
             * (ie libvirtd's LXC driver to complete their
             * waitpid & continue */
            _exit(0);
        }

        /* Don't hold onto any cwd we inherit from libvirtd either */
        if (chdir("/") < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to change to root dir"));
            goto cleanup;
        }

        if (setsid() < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to become session leader"));
            goto cleanup;
        }
    }

    /* Initialize logging */
    virLogSetFromEnv();

    /* Accept initial client which is the libvirtd daemon */
    if ((client = accept(monitor, NULL, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to accept a connection from driver"));
        goto cleanup;
    }

    rc = lxcControllerRun(def, nveths, veths, monitor, client, appPty);


cleanup:
    if (def)
        virFileDeletePid(LXC_STATE_DIR, def->name);
    lxcControllerCleanupInterfaces(nveths, veths);
    if (sockpath)
        unlink(sockpath);
    VIR_FREE(sockpath);

    return rc;
}
