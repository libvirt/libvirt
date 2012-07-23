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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
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
#include <grp.h>
#include <sys/stat.h>
#include <time.h>

#if HAVE_CAPNG
# include <cap-ng.h>
#endif

#if HAVE_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_cgroup.h"
#include "lxc_protocol.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "memory.h"
#include "util.h"
#include "virfile.h"
#include "virpidfile.h"
#include "command.h"
#include "processinfo.h"
#include "nodeinfo.h"
#include "virrandom.h"
#include "rpc/virnetserver.h"

#define VIR_FROM_THIS VIR_FROM_LXC

typedef struct _virLXCControllerConsole virLXCControllerConsole;
typedef virLXCControllerConsole *virLXCControllerConsolePtr;
struct _virLXCControllerConsole {
    int hostWatch;
    int hostFd;  /* PTY FD in the host OS */
    bool hostClosed;
    int hostEpoll;
    bool hostBlocking;

    int contWatch;
    int contFd;  /* PTY FD in the container */
    bool contClosed;
    int contEpoll;
    bool contBlocking;

    int epollWatch;
    int epollFd; /* epoll FD for dealing with EOF */

    size_t fromHostLen;
    char fromHostBuf[1024];
    size_t fromContLen;
    char fromContBuf[1024];
};

typedef struct _virLXCController virLXCController;
typedef virLXCController *virLXCControllerPtr;
struct _virLXCController {
    char *name;
    virDomainDefPtr def;

    int handshakeFd;

    pid_t initpid;

    size_t nveths;
    char **veths;

    size_t nconsoles;
    virLXCControllerConsolePtr consoles;
    char *devptmx;

    size_t nloopDevs;
    int *loopDevFds;

    virSecurityManagerPtr securityManager;

    /* Server socket */
    virNetServerPtr server;
    virNetServerClientPtr client;
    virNetServerProgramPtr prog;
    bool inShutdown;
    int timerShutdown;
};

#include "lxc_controller_dispatch.h"

static void virLXCControllerFree(virLXCControllerPtr ctrl);

static void virLXCControllerQuitTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virLXCControllerPtr ctrl = opaque;

    VIR_DEBUG("Triggering event loop quit");
    virNetServerQuit(ctrl->server);
}


static virLXCControllerPtr virLXCControllerNew(const char *name)
{
    virLXCControllerPtr ctrl = NULL;
    virCapsPtr caps = NULL;
    char *configFile = NULL;

    if (VIR_ALLOC(ctrl) < 0)
        goto no_memory;

    ctrl->timerShutdown = -1;

    if (!(ctrl->name = strdup(name)))
        goto no_memory;

    if ((caps = lxcCapsInit(NULL)) == NULL)
        goto error;

    if ((configFile = virDomainConfigFile(LXC_STATE_DIR,
                                          ctrl->name)) == NULL)
        goto error;

    if ((ctrl->def = virDomainDefParseFile(caps,
                                           configFile,
                                           1 << VIR_DOMAIN_VIRT_LXC,
                                           0)) == NULL)
        goto error;

    if ((ctrl->timerShutdown = virEventAddTimeout(-1,
                                                  virLXCControllerQuitTimer, ctrl,
                                                  NULL)) < 0)
        goto error;

cleanup:
    VIR_FREE(configFile);
    virCapabilitiesFree(caps);
    return ctrl;

no_memory:
    virReportOOMError();
error:
    virLXCControllerFree(ctrl);
    ctrl = NULL;
    goto cleanup;
}


static int virLXCControllerCloseLoopDevices(virLXCControllerPtr ctrl,
                                            bool force)
{
    size_t i;

    for (i = 0 ; i < ctrl->nloopDevs ; i++) {
        if (force) {
            VIR_FORCE_CLOSE(ctrl->loopDevFds[i]);
        } else {
            if (VIR_CLOSE(ctrl->loopDevFds[i]) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to close loop device"));
                return -1;
            }
        }
    }

    return 0;
}


static void virLXCControllerStopInit(virLXCControllerPtr ctrl)
{
    if (ctrl->initpid == 0)
        return;

    virLXCControllerCloseLoopDevices(ctrl, true);
    virPidAbort(ctrl->initpid);
    ctrl->initpid = 0;
}


static void virLXCControllerConsoleClose(virLXCControllerConsolePtr console)
{
    if (console->hostWatch != -1)
        virEventRemoveHandle(console->hostWatch);
    VIR_FORCE_CLOSE(console->hostFd);

    if (console->contWatch != -1)
        virEventRemoveHandle(console->contWatch);
    VIR_FORCE_CLOSE(console->contFd);

    if (console->epollWatch != -1)
        virEventRemoveHandle(console->epollWatch);
    VIR_FORCE_CLOSE(console->epollFd);
}


static void virLXCControllerFree(virLXCControllerPtr ctrl)
{
    size_t i;

    if (!ctrl)
        return;

    virLXCControllerStopInit(ctrl);

    virSecurityManagerFree(ctrl->securityManager);

    for (i = 0 ; i < ctrl->nveths ; i++)
        VIR_FREE(ctrl->veths[i]);
    VIR_FREE(ctrl->veths);

    for (i = 0 ; i < ctrl->nconsoles ; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));
    VIR_FREE(ctrl->consoles);

    VIR_FORCE_CLOSE(ctrl->handshakeFd);

    VIR_FREE(ctrl->devptmx);

    virDomainDefFree(ctrl->def);
    VIR_FREE(ctrl->name);

    if (ctrl->timerShutdown != -1)
        virEventRemoveTimeout(ctrl->timerShutdown);

    virNetServerFree(ctrl->server);

    VIR_FREE(ctrl);
}


static int virLXCControllerAddConsole(virLXCControllerPtr ctrl,
                                      int hostFd)
{
    if (VIR_EXPAND_N(ctrl->consoles, ctrl->nconsoles, 1) < 0) {
        virReportOOMError();
        return -1;
    }
    ctrl->consoles[ctrl->nconsoles-1].hostFd = hostFd;
    ctrl->consoles[ctrl->nconsoles-1].hostWatch = -1;

    ctrl->consoles[ctrl->nconsoles-1].contFd = -1;
    ctrl->consoles[ctrl->nconsoles-1].contWatch = -1;

    ctrl->consoles[ctrl->nconsoles-1].epollFd = -1;
    ctrl->consoles[ctrl->nconsoles-1].epollWatch = -1;
    return 0;
}


static int virLXCControllerConsoleSetNonblocking(virLXCControllerConsolePtr console)
{
    if (virSetBlocking(console->hostFd, false) < 0 ||
        virSetBlocking(console->contFd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set console file descriptor non-blocking"));
        return -1;
    }

    return 0;
}


static int virLXCControllerDaemonHandshake(virLXCControllerPtr ctrl)
{
    if (lxcContainerSendContinue(ctrl->handshakeFd) < 0) {
        virReportSystemError(errno, "%s",
                             _("error sending continue signal to daemon"));
        return -1;
    }
    VIR_FORCE_CLOSE(ctrl->handshakeFd);
    return 0;
}


static int virLXCControllerValidateNICs(virLXCControllerPtr ctrl)
{
    if (ctrl->def->nnets != ctrl->nveths) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("expecting %d veths, but got %zu"),
                       ctrl->def->nnets, ctrl->nveths);
        return -1;
    }

    return 0;
}


static int virLXCControllerValidateConsoles(virLXCControllerPtr ctrl)
{
    if (ctrl->def->nconsoles != ctrl->nconsoles) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("expecting %d consoles, but got %zu tty file handlers"),
                       ctrl->def->nconsoles, ctrl->nconsoles);
        return -1;
    }

    return 0;
}


static int virLXCControllerSetupLoopDevice(virDomainFSDefPtr fs)
{
    int lofd;
    char *loname = NULL;

    if ((lofd = virFileLoopDeviceAssociate(fs->src, &loname)) < 0)
        return -1;

    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    fs->type = VIR_DOMAIN_FS_TYPE_BLOCK;
    VIR_FREE(fs->src);
    fs->src = loname;
    loname = NULL;

    return lofd;
}


static int virLXCControllerSetupLoopDevices(virLXCControllerPtr ctrl)
{
    size_t i;
    int ret = -1;

    for (i = 0 ; i < ctrl->def->nfss ; i++) {
        int fd;

        if (ctrl->def->fss[i]->type != VIR_DOMAIN_FS_TYPE_FILE)
            continue;

        fd = virLXCControllerSetupLoopDevice(ctrl->def->fss[i]);
        if (fd < 0)
            goto cleanup;

        VIR_DEBUG("Saving loop fd %d", fd);
        if (VIR_EXPAND_N(ctrl->loopDevFds, ctrl->nloopDevs, 1) < 0) {
            VIR_FORCE_CLOSE(fd);
            virReportOOMError();
            goto cleanup;
        }
        ctrl->loopDevFds[ctrl->nloopDevs - 1] = fd;
    }

    VIR_DEBUG("Setup all loop devices");
    ret = 0;

cleanup:
    return ret;
}

#if HAVE_NUMACTL
static int virLXCControllerSetupNUMAPolicy(virLXCControllerPtr ctrl)
{
    nodemask_t mask;
    int mode = -1;
    int node = -1;
    int ret = -1;
    int i = 0;
    int maxnode = 0;
    bool warned = false;

    if (!ctrl->def->numatune.memory.nodemask)
        return 0;

    VIR_DEBUG("Setting NUMA memory policy");

    if (numa_available() < 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("Host kernel is not aware of NUMA."));
        return -1;
    }

    maxnode = numa_max_node() + 1;

    /* Convert nodemask to NUMA bitmask. */
    nodemask_zero(&mask);
    for (i = 0; i < VIR_DOMAIN_CPUMASK_LEN; i++) {
        if (ctrl->def->numatune.memory.nodemask[i]) {
            if (i > NUMA_NUM_NODES) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Host cannot support NUMA node %d"), i);
                return -1;
            }
            if (i > maxnode && !warned) {
                VIR_WARN("nodeset is out of range, there is only %d NUMA "
                         "nodes on host", maxnode);
                warned = true;
            }
            nodemask_set(&mask, i);
        }
    }

    mode = ctrl->def->numatune.memory.mode;

    if (mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT) {
        numa_set_bind_policy(1);
        numa_set_membind(&mask);
        numa_set_bind_policy(0);
    } else if (mode == VIR_DOMAIN_NUMATUNE_MEM_PREFERRED) {
        int nnodes = 0;
        for (i = 0; i < NUMA_NUM_NODES; i++) {
            if (nodemask_isset(&mask, i)) {
                node = i;
                nnodes++;
            }
        }

        if (nnodes != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("NUMA memory tuning in 'preferred' mode "
                                   "only supports single node"));
            goto cleanup;
        }

        numa_set_bind_policy(0);
        numa_set_preferred(node);
    } else if (mode == VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE) {
        numa_set_interleave_mask(&mask);
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unable to set NUMA policy %s"),
                       virDomainNumatuneMemModeTypeToString(mode));
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}
#else
static int virLXCControllerSetupNUMAPolicy(virLXCControllerPtr ctrl)
{
    if (ctrl->def->numatune.memory.nodemask) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("NUMA policy is not available on this platform"));
        return -1;
    }

    return 0;
}
#endif


/*
 * To be run while still single threaded
 */
static int virLXCControllerSetupCpuAffinity(virLXCControllerPtr ctrl)
{
    int i, hostcpus, maxcpu = CPU_SETSIZE;
    virNodeInfo nodeinfo;
    unsigned char *cpumap;
    int cpumaplen;

    VIR_DEBUG("Setting CPU affinity");

    if (nodeGetInfo(NULL, &nodeinfo) < 0)
        return -1;

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    hostcpus = VIR_NODEINFO_MAXCPUS(nodeinfo);
    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    cpumaplen = VIR_CPU_MAPLEN(maxcpu);
    if (VIR_ALLOC_N(cpumap, cpumaplen) < 0) {
        virReportOOMError();
        return -1;
    }

    if (ctrl->def->cpumask) {
        /* XXX why don't we keep 'cpumask' in the libvirt cpumap
         * format to start with ?!?! */
        for (i = 0 ; i < maxcpu && i < ctrl->def->cpumasklen ; i++)
            if (ctrl->def->cpumask[i])
                VIR_USE_CPU(cpumap, i);
    } else {
        /* You may think this is redundant, but we can't assume libvirtd
         * itself is running on all pCPUs, so we need to explicitly set
         * the spawned LXC instance to all pCPUs if no map is given in
         * its config file */
        for (i = 0 ; i < maxcpu ; i++)
            VIR_USE_CPU(cpumap, i);
    }

    /* We are pressuming we are running between fork/exec of LXC
     * so use '0' to indicate our own process ID. No threads are
     * running at this point
     */
    if (virProcessInfoSetAffinity(0, /* Self */
                                  cpumap, cpumaplen, maxcpu) < 0) {
        VIR_FREE(cpumap);
        return -1;
    }
    VIR_FREE(cpumap);

    return 0;
}


/**
 * virLXCControllerSetupResourceLimits
 * @ctrl: the controller state
 *
 * Creates a cgroup for the container, moves the task inside,
 * and sets resource limits
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerSetupResourceLimits(virLXCControllerPtr ctrl)
{

    if (virLXCControllerSetupCpuAffinity(ctrl) < 0)
        return -1;

    if (virLXCControllerSetupNUMAPolicy(ctrl) < 0)
        return -1;

    return virLXCCgroupSetup(ctrl->def);
}


static void virLXCControllerClientCloseHook(virNetServerClientPtr client)
{
    virLXCControllerPtr ctrl = virNetServerClientGetPrivateData(client);

    VIR_DEBUG("Client %p has closed", client);
    if (ctrl->client == client)
        ctrl->client = NULL;
    if (ctrl->inShutdown) {
        VIR_DEBUG("Arm timer to quit event loop");
        virEventUpdateTimeout(ctrl->timerShutdown, 0);
    }
}

static int virLXCControllerClientHook(virNetServerPtr server ATTRIBUTE_UNUSED,
                                      virNetServerClientPtr client,
                                      void *opaque)
{
    virLXCControllerPtr ctrl = opaque;
    virNetServerClientSetPrivateData(client, ctrl, NULL);
    virNetServerClientSetCloseHook(client, virLXCControllerClientCloseHook);
    VIR_DEBUG("Got new client %p", client);
    ctrl->client = client;
    return 0;
}


static int virLXCControllerSetupServer(virLXCControllerPtr ctrl)
{
    virNetServerServicePtr svc = NULL;
    char *sockpath;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    LXC_STATE_DIR, ctrl->name) < 0) {
        virReportOOMError();
        return -1;
    }

    if (!(ctrl->server = virNetServerNew(0, 0, 0, 1,
                                         -1, 0, false,
                                         NULL,
                                         virLXCControllerClientHook,
                                         ctrl)))
        goto error;

    if (!(svc = virNetServerServiceNewUNIX(sockpath,
                                           0700,
                                           0,
                                           0,
                                           false,
                                           5,
                                           NULL)))
        goto error;

    if (virNetServerAddService(ctrl->server, svc, NULL) < 0)
        goto error;
    virNetServerServiceFree(svc);
    svc = NULL;

    if (!(ctrl->prog = virNetServerProgramNew(VIR_LXC_PROTOCOL_PROGRAM,
                                              VIR_LXC_PROTOCOL_PROGRAM_VERSION,
                                              virLXCProtocolProcs,
                                              virLXCProtocolNProcs)))
        goto error;

    virNetServerUpdateServices(ctrl->server, true);
    VIR_FREE(sockpath);
    return 0;

error:
    VIR_FREE(sockpath);
    virNetServerFree(ctrl->server);
    ctrl->server = NULL;
    virNetServerServiceFree(svc);
    return -1;
}


static int lxcControllerClearCapabilities(void)
{
#if HAVE_CAPNG
    int ret;

    capng_clear(CAPNG_SELECT_BOTH);

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("failed to apply capabilities: %d"), ret);
        return -1;
    }
#else
    VIR_WARN("libcap-ng support not compiled in, unable to clear capabilities");
#endif
    return 0;
}

static bool quit = false;
static bool wantReboot = false;
static virMutex lock;


static void virLXCControllerSignalChildIO(virNetServerPtr server ATTRIBUTE_UNUSED,
                                          siginfo_t *info ATTRIBUTE_UNUSED,
                                          void *opaque)
{
    virLXCControllerPtr ctrl = opaque;
    int ret;
    int status;

    ret = waitpid(-1, &status, WNOHANG);
    if (ret == ctrl->initpid) {
        virMutexLock(&lock);
        quit = true;
        if (WIFSIGNALED(status) &&
            WTERMSIG(status) == SIGHUP)
            wantReboot = true;
        virMutexUnlock(&lock);
    }
}


static void virLXCControllerConsoleUpdateWatch(virLXCControllerConsolePtr console)
{
    int hostEvents = 0;
    int contEvents = 0;

    if (!console->hostClosed || (!console->hostBlocking && console->fromContLen)) {
        if (console->fromHostLen < sizeof(console->fromHostBuf))
            hostEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromContLen)
            hostEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }
    if (!console->contClosed || (!console->contBlocking && console->fromHostLen)) {
        if (console->fromContLen < sizeof(console->fromContBuf))
            contEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromHostLen)
            contEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }

    VIR_DEBUG("Container watch %d=%d host watch %d=%d",
              console->contWatch, contEvents,
              console->hostWatch, hostEvents);
    virEventUpdateHandle(console->contWatch, contEvents);
    virEventUpdateHandle(console->hostWatch, hostEvents);

    if (console->hostClosed) {
        int events = EPOLLIN | EPOLLET;
        if (console->hostBlocking)
            events |= EPOLLOUT;

        if (events != console->hostEpoll) {
            struct epoll_event event;
            int action = EPOLL_CTL_ADD;
            if (console->hostEpoll)
                action = EPOLL_CTL_MOD;

            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events, console->hostEpoll);

            event.events = events;
            event.data.fd = console->hostFd;
            if (epoll_ctl(console->epollFd, action, console->hostFd, &event) < 0) {
                VIR_DEBUG(":fail");
                virReportSystemError(errno, "%s",
                                     _("Unable to add epoll fd"));
                quit = true;
                goto cleanup;
            }
            console->hostEpoll = events;
            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events, console->hostEpoll);
        }
    } else if (console->hostEpoll) {
        VIR_DEBUG("Stop epoll oldContEvents=%x", console->hostEpoll);
        if (epoll_ctl(console->epollFd, EPOLL_CTL_DEL, console->hostFd, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to remove epoll fd"));
                VIR_DEBUG(":fail");
            quit = true;
            goto cleanup;
        }
        console->hostEpoll = 0;
    }

    if (console->contClosed) {
        int events = EPOLLIN | EPOLLET;
        if (console->contBlocking)
            events |= EPOLLOUT;

        if (events != console->contEpoll) {
            struct epoll_event event;
            int action = EPOLL_CTL_ADD;
            if (console->contEpoll)
                action = EPOLL_CTL_MOD;

            VIR_DEBUG("newContEvents=%x oldContEvents=%x", events, console->contEpoll);

            event.events = events;
            event.data.fd = console->contFd;
            if (epoll_ctl(console->epollFd, action, console->contFd, &event) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to add epoll fd"));
                VIR_DEBUG(":fail");
                quit = true;
                goto cleanup;
            }
            console->contEpoll = events;
            VIR_DEBUG("newHostEvents=%x oldHostEvents=%x", events, console->contEpoll);
        }
    } else if (console->contEpoll) {
        VIR_DEBUG("Stop epoll oldContEvents=%x", console->contEpoll);
        if (epoll_ctl(console->epollFd, EPOLL_CTL_DEL, console->contFd, NULL) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to remove epoll fd"));
                VIR_DEBUG(":fail");
            quit = true;
            goto cleanup;
        }
        console->contEpoll = 0;
    }
cleanup:
    return;
}


static void virLXCControllerConsoleEPoll(int watch, int fd, int events, void *opaque)
{
    virLXCControllerConsolePtr console = opaque;

    virMutexLock(&lock);
    VIR_DEBUG("IO event watch=%d fd=%d events=%d fromHost=%zu fromcont=%zu",
              watch, fd, events,
              console->fromHostLen,
              console->fromContLen);

    while (1) {
        struct epoll_event event;
        int ret;
        ret = epoll_wait(console->epollFd, &event, 1, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            virReportSystemError(errno, "%s",
                                 _("Unable to wait on epoll"));
            quit = true;
            goto cleanup;
        }

        if (ret == 0)
            break;

        VIR_DEBUG("fd=%d hostFd=%d contFd=%d hostEpoll=%x contEpoll=%x",
                  event.data.fd, console->hostFd, console->contFd,
                  console->hostEpoll, console->contEpoll);

        /* If we get HUP+dead PID, we just re-enable the main loop
         * which will see the PID has died and exit */
        if ((event.events & EPOLLIN)) {
            if (event.data.fd == console->hostFd) {
                console->hostClosed = false;
            } else {
                console->contClosed = false;
            }
            virLXCControllerConsoleUpdateWatch(console);
            break;
        }
    }

cleanup:
    virMutexUnlock(&lock);
}

static void virLXCControllerConsoleIO(int watch, int fd, int events, void *opaque)
{
    virLXCControllerConsolePtr console = opaque;

    virMutexLock(&lock);
    VIR_DEBUG("IO event watch=%d fd=%d events=%d fromHost=%zu fromcont=%zu",
              watch, fd, events,
              console->fromHostLen,
              console->fromContLen);
    if (events & VIR_EVENT_HANDLE_READABLE) {
        char *buf;
        size_t *len;
        size_t avail;
        ssize_t done;
        if (watch == console->hostWatch) {
            buf = console->fromHostBuf;
            len = &console->fromHostLen;
            avail = sizeof(console->fromHostBuf) - *len;
        } else {
            buf = console->fromContBuf;
            len = &console->fromContLen;
            avail = sizeof(console->fromContBuf) - *len;
        }
    reread:
        done = read(fd, buf + *len, avail);
        if (done == -1 && errno == EINTR)
            goto reread;
        if (done == -1 && errno != EAGAIN) {
            virReportSystemError(errno, "%s",
                                 _("Unable to read container pty"));
            goto error;
        }
        if (done > 0) {
            *len += done;
        } else {
            VIR_DEBUG("Read fd %d done %d errno %d", fd, (int)done, errno);
        }
    }

    if (events & VIR_EVENT_HANDLE_WRITABLE) {
        char *buf;
        size_t *len;
        ssize_t done;
        if (watch == console->hostWatch) {
            buf = console->fromContBuf;
            len = &console->fromContLen;
        } else {
            buf = console->fromHostBuf;
            len = &console->fromHostLen;
        }

    rewrite:
        done = write(fd, buf, *len);
        if (done == -1 && errno == EINTR)
            goto rewrite;
        if (done == -1 && errno != EAGAIN) {
            virReportSystemError(errno, "%s",
                                 _("Unable to write to container pty"));
            goto error;
        }
        if (done > 0) {
            memmove(buf, buf + done, (*len - done));
            *len -= done;
        } else {
            VIR_DEBUG("Write fd %d done %d errno %d", fd, (int)done, errno);
            if (watch == console->hostWatch)
                console->hostBlocking = true;
            else
                console->contBlocking = true;
        }
    }

    if (events & VIR_EVENT_HANDLE_HANGUP) {
        if (watch == console->hostWatch) {
            console->hostClosed = true;
        } else {
            console->contClosed = true;
        }
        VIR_DEBUG("Got EOF on %d %d", watch, fd);
    }

    virLXCControllerConsoleUpdateWatch(console);
    virMutexUnlock(&lock);
    return;

error:
    virEventRemoveHandle(console->contWatch);
    virEventRemoveHandle(console->hostWatch);
    console->contWatch = console->hostWatch = -1;
    quit = true;
    virMutexUnlock(&lock);
}


/**
 * lxcControllerMain
 * @serverFd: server socket fd to accept client requests
 * @clientFd: initial client which is the libvirtd daemon
 *
 * Processes I/O on consoles and the monitor
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerMain(virLXCControllerPtr ctrl)
{
    virErrorPtr err;
    int rc = -1;
    size_t i;

    if (virMutexInit(&lock) < 0)
        goto cleanup2;

    if (virNetServerAddSignalHandler(ctrl->server,
                                     SIGCHLD,
                                     virLXCControllerSignalChildIO,
                                     ctrl) < 0)
        goto cleanup;

    virResetLastError();

    for (i = 0 ; i < ctrl->nconsoles ; i++) {
        if ((ctrl->consoles[i].epollFd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create epoll fd"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].epollWatch = virEventAddHandle(ctrl->consoles[i].epollFd,
                                                              VIR_EVENT_HANDLE_READABLE,
                                                              virLXCControllerConsoleEPoll,
                                                              &(ctrl->consoles[i]),
                                                              NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch epoll FD"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].hostWatch = virEventAddHandle(ctrl->consoles[i].hostFd,
                                                             VIR_EVENT_HANDLE_READABLE,
                                                             virLXCControllerConsoleIO,
                                                             &(ctrl->consoles[i]),
                                                             NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch host console PTY"));
            goto cleanup;
        }

        if ((ctrl->consoles[i].contWatch = virEventAddHandle(ctrl->consoles[i].contFd,
                                                             VIR_EVENT_HANDLE_READABLE,
                                                             virLXCControllerConsoleIO,
                                                             &(ctrl->consoles[i]),
                                                             NULL)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to watch host console PTY"));
            goto cleanup;
        }
    }

    virMutexLock(&lock);
    while (!quit) {
        virMutexUnlock(&lock);
        if (virEventRunDefaultImpl() < 0)
            goto cleanup;
        virMutexLock(&lock);
    }
    virMutexUnlock(&lock);

    err = virGetLastError();
    if (!err || err->code == VIR_ERR_OK)
        rc = wantReboot ? 1 : 0;

cleanup:
    virMutexDestroy(&lock);
cleanup2:

    for (i = 0 ; i < ctrl->nconsoles ; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));

    return rc;
}



/**
 * virLXCControllerMoveInterfaces
 * @nveths: number of interfaces
 * @veths: interface names
 * @container: pid of container
 *
 * Moves network interfaces into a container's namespace
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerMoveInterfaces(virLXCControllerPtr ctrl)
{
    size_t i;

    for (i = 0 ; i < ctrl->nveths ; i++) {
        if (virNetDevSetNamespace(ctrl->veths[i], ctrl->initpid) < 0)
            return -1;
    }

    return 0;
}


/**
 * virLXCControllerDeleteInterfaces:
 * @ctrl: the LXC controller
 *
 * Cleans up the container interfaces by deleting the veth device pairs.
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerDeleteInterfaces(virLXCControllerPtr ctrl)
{
    size_t i;
    int ret = 0;

    for (i = 0 ; i < ctrl->nveths ; i++) {
        if (virNetDevVethDelete(ctrl->veths[i]) < 0)
            ret = -1;
    }

    return ret;
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

/* Create a private tty using the private devpts at PTMX, returning
 * the master in *TTYMASTER and the name of the slave, _from the
 * perspective of the guest after remounting file systems_, in
 * *TTYNAME.  Heavily borrowed from glibc, but doesn't require that
 * devpts == "/dev/pts" */
static int
lxcCreateTty(char *ptmx, int *ttymaster, char **ttyName)
{
    int ret = -1;
    int ptyno;
    int unlock = 0;

    if ((*ttymaster = open(ptmx, O_RDWR|O_NOCTTY|O_NONBLOCK)) < 0)
        goto cleanup;

    if (ioctl(*ttymaster, TIOCSPTLCK, &unlock) < 0)
        goto cleanup;

    if (ioctl(*ttymaster, TIOCGPTN, &ptyno) < 0)
        goto cleanup;

    /* If mount() succeeded at honoring newinstance, then the kernel
     * was new enough to also honor the mode=0620,gid=5 options, which
     * guarantee that the new pty already has correct permissions; so
     * while glibc has to fstat(), fchmod(), and fchown() for older
     * kernels, we can skip those steps.  ptyno shouldn't currently be
     * anything other than 0, but let's play it safe.  */
    if (virAsprintf(ttyName, "/dev/pts/%d", ptyno) < 0) {
        virReportOOMError();
        errno = ENOMEM;
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ret != 0) {
        VIR_FORCE_CLOSE(*ttymaster);
        VIR_FREE(*ttyName);
    }

    return ret;
}


static int
virLXCControllerSetupDevPTS(virLXCControllerPtr ctrl)
{
    virDomainFSDefPtr root = virDomainGetRootFilesystem(ctrl->def);
    char *mount_options = NULL;
    char *opts;
    char *devpts = NULL;
    int ret = -1;

    if (!root) {
        if (ctrl->nconsoles != 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Expected exactly one console, but got %zu"),
                           ctrl->nconsoles);
            return -1;
        }
        return 0;
    }

    VIR_DEBUG("Setting up private /dev/pts");

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
    mount_options = virSecurityManagerGetMountOptions(ctrl->securityManager,
                                                      ctrl->def);

    if (!virFileExists(root->src)) {
        virReportSystemError(errno,
                             _("root source %s does not exist"),
                             root->src);
        goto cleanup;
    }

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
        virAsprintf(&ctrl->devptmx, "%s/dev/pts/ptmx", root->src) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileMakePath(devpts) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %s"),
                             devpts);
        goto cleanup;
    }

    /* XXX should we support gid=X for X!=5 for distros which use
     * a different gid for tty?  */
    if (virAsprintf(&opts, "newinstance,ptmxmode=0666,mode=0620,gid=5%s",
                    (mount_options ? mount_options : "")) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    VIR_DEBUG("Mount devpts on %s type=tmpfs flags=%x, opts=%s",
              devpts, MS_NOSUID, opts);
    if (mount("devpts", devpts, "devpts", MS_NOSUID, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devpts on %s"),
                             devpts);
        goto cleanup;
    }

    if (access(ctrl->devptmx, R_OK) < 0) {
        VIR_WARN("Kernel does not support private devpts, using shared devpts");
        VIR_FREE(ctrl->devptmx);
    }

    ret = 0;

cleanup:
    VIR_FREE(opts);
    VIR_FREE(devpts);
    return ret;
}


static int
virLXCControllerSetupConsoles(virLXCControllerPtr ctrl,
                              char **containerTTYPaths)
{
    size_t i;

    for (i = 0 ; i < ctrl->nconsoles ; i++) {
        if (ctrl->devptmx) {
            VIR_DEBUG("Opening tty on private %s", ctrl->devptmx);
            if (lxcCreateTty(ctrl->devptmx,
                             &ctrl->consoles[i].contFd,
                             &containerTTYPaths[i]) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Failed to allocate tty"));
                return -1;
            }
        } else {
            VIR_DEBUG("Opening tty on shared /dev/ptmx");
            if (virFileOpenTty(&ctrl->consoles[i].contFd,
                               &containerTTYPaths[i],
                               0) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Failed to allocate tty"));
                return -1;
            }
        }
    }
    return 0;
}


static void
virLXCControllerEventSend(virLXCControllerPtr ctrl,
                          int procnr,
                          xdrproc_t proc,
                          void *data)
{
    virNetMessagePtr msg;

    if (!ctrl->client)
        return;

    VIR_DEBUG("Send event %d client=%p", procnr, ctrl->client);
    if (!(msg = virNetMessageNew(false)))
        goto error;

    msg->header.prog = virNetServerProgramGetID(ctrl->prog);
    msg->header.vers = virNetServerProgramGetVersion(ctrl->prog);
    msg->header.proc = procnr;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.serial = 1;
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto error;

    if (virNetMessageEncodePayload(msg, proc, data) < 0)
        goto error;

    VIR_DEBUG("Queue event %d %zu", procnr, msg->bufferLength);
    virNetServerClientSendMessage(ctrl->client, msg);

    xdr_free(proc, data);
    return;

error:
    virNetMessageFree(msg);
    xdr_free(proc, data);
}


static int
virLXCControllerEventSendExit(virLXCControllerPtr ctrl,
                              int exitstatus)
{
    virLXCProtocolExitEventMsg msg;

    VIR_DEBUG("Exit status %d", exitstatus);
    memset(&msg, 0, sizeof(msg));
    switch (exitstatus) {
    case 0:
        msg.status = VIR_LXC_PROTOCOL_EXIT_STATUS_SHUTDOWN;
        break;
    case 1:
        msg.status = VIR_LXC_PROTOCOL_EXIT_STATUS_REBOOT;
        break;
    default:
        msg.status = VIR_LXC_PROTOCOL_EXIT_STATUS_ERROR;
        break;
    }

    virLXCControllerEventSend(ctrl,
                              VIR_LXC_PROTOCOL_PROC_EXIT_EVENT,
                              (xdrproc_t)xdr_virLXCProtocolExitEventMsg,
                              (void*)&msg);

    if (ctrl->client) {
        VIR_DEBUG("Waiting for client to complete dispatch");
        ctrl->inShutdown = true;
        virNetServerClientDelayedClose(ctrl->client);
        virNetServerRun(ctrl->server);
    }
    VIR_DEBUG("Client has gone away");
    return 0;
}


static int
virLXCControllerRun(virLXCControllerPtr ctrl)
{
    int rc = -1;
    int control[2] = { -1, -1};
    int containerhandshake[2] = { -1, -1 };
    char **containerTTYPaths = NULL;
    size_t i;

    if (VIR_ALLOC_N(containerTTYPaths, ctrl->nconsoles) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, control) < 0) {
        virReportSystemError(errno, "%s",
                             _("sockpair failed"));
        goto cleanup;
    }

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, containerhandshake) < 0) {
        virReportSystemError(errno, "%s",
                             _("socketpair failed"));
        goto cleanup;
    }

    if (virLXCControllerSetupLoopDevices(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupResourceLimits(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupDevPTS(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupConsoles(ctrl, containerTTYPaths) < 0)
        goto cleanup;

    if (lxcSetPersonality(ctrl->def) < 0)
        goto cleanup;

    if ((ctrl->initpid = lxcContainerStart(ctrl->def,
                                           ctrl->securityManager,
                                           ctrl->nveths,
                                           ctrl->veths,
                                           control[1],
                                           containerhandshake[1],
                                           containerTTYPaths,
                                           ctrl->nconsoles)) < 0)
        goto cleanup;
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    if (virLXCControllerMoveInterfaces(ctrl) < 0)
        goto cleanup;

    if (lxcContainerSendContinue(control[0]) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to send container continue message"));
        goto cleanup;
    }

    if (lxcContainerWaitForContinue(containerhandshake[0]) < 0) {
        virReportSystemError(errno, "%s",
                             _("error receiving signal from container"));
        goto cleanup;
    }

    /* Now the container is fully setup... */

    /* ...we can close the loop devices... */
    if (virLXCControllerCloseLoopDevices(ctrl, false) < 0)
        goto cleanup;

    /* ...and reduce our privileges */
    if (lxcControllerClearCapabilities() < 0)
        goto cleanup;

    if (virLXCControllerDaemonHandshake(ctrl) < 0)
        goto cleanup;

    for (i = 0 ; i < ctrl->nconsoles ; i++)
        if (virLXCControllerConsoleSetNonblocking(&(ctrl->consoles[i])) < 0)
            goto cleanup;

    rc = virLXCControllerMain(ctrl);

    virLXCControllerEventSendExit(ctrl, rc);

cleanup:
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[0]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0 ; i < ctrl->nconsoles ; i++)
        VIR_FREE(containerTTYPaths[i]);
    VIR_FREE(containerTTYPaths);

    virLXCControllerStopInit(ctrl);

    return rc;
}


int main(int argc, char *argv[])
{
    pid_t pid;
    int rc = 1;
    char *name = NULL;
    size_t nveths = 0;
    char **veths = NULL;
    int handshakeFd = -1;
    int bg = 0;
    const struct option options[] = {
        { "background", 0, NULL, 'b' },
        { "name",   1, NULL, 'n' },
        { "veth",   1, NULL, 'v' },
        { "console", 1, NULL, 'c' },
        { "handshakefd", 1, NULL, 's' },
        { "security", 1, NULL, 'S' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    int *ttyFDs = NULL;
    size_t nttyFDs = 0;
    virLXCControllerPtr ctrl = NULL;
    size_t i;
    const char *securityDriver = "none";

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL ||
        virRandomInitialize(time(NULL) ^ getpid())) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize logging */
    virLogSetFromEnv();

    while (1) {
        int c;

        c = getopt_long(argc, argv, "dn:v:m:c:s:h:S:",
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
            if (VIR_REALLOC_N(ttyFDs, nttyFDs + 1) < 0) {
                virReportOOMError();
                goto cleanup;
            }
            if (virStrToLong_i(optarg, NULL, 10, &ttyFDs[nttyFDs++]) < 0) {
                fprintf(stderr, "malformed --console argument '%s'", optarg);
                goto cleanup;
            }
            break;

        case 's':
            if (virStrToLong_i(optarg, NULL, 10, &handshakeFd) < 0) {
                fprintf(stderr, "malformed --handshakefd argument '%s'",
                        optarg);
                goto cleanup;
            }
            break;

        case 'S':
            securityDriver = optarg;
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
            fprintf(stderr, "  -s FD, --handshakefd FD\n");
            fprintf(stderr, "  -S NAME, --security NAME\n");
            fprintf(stderr, "  -h, --help\n");
            fprintf(stderr, "\n");
            goto cleanup;
        }
    }

    if (name == NULL) {
        fprintf(stderr, "%s: missing --name argument for configuration\n", argv[0]);
        goto cleanup;
    }

    if (handshakeFd < 0) {
        fprintf(stderr, "%s: missing --handshake argument for container PTY\n",
                argv[0]);
        goto cleanup;
    }

    if (getuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    virEventRegisterDefaultImpl();

    if (!(ctrl = virLXCControllerNew(name)))
        goto cleanup;

    ctrl->handshakeFd = handshakeFd;

    if (!(ctrl->securityManager = virSecurityManagerNew(securityDriver,
                                                        LXC_DRIVER_NAME,
                                                        false, false, false)))
        goto cleanup;

    VIR_DEBUG("Security model %s type %s label %s imagelabel %s",
              NULLSTR(ctrl->def->seclabel.model),
              virDomainSeclabelTypeToString(ctrl->def->seclabel.type),
              NULLSTR(ctrl->def->seclabel.label),
              NULLSTR(ctrl->def->seclabel.imagelabel));

    ctrl->veths = veths;
    ctrl->nveths = nveths;

    for (i = 0 ; i < nttyFDs ; i++) {
        if (virLXCControllerAddConsole(ctrl, ttyFDs[i]) < 0)
            goto cleanup;
        ttyFDs[i] = -1;
    }

    if (virLXCControllerValidateNICs(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerValidateConsoles(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupServer(ctrl) < 0)
        goto cleanup;

    if (bg) {
        if ((pid = fork()) < 0)
            goto cleanup;

        if (pid > 0) {
            if ((rc = virPidFileWrite(LXC_STATE_DIR, name, pid)) < 0) {
                virReportSystemError(-rc,
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

    rc = virLXCControllerRun(ctrl);

cleanup:
    virPidFileDelete(LXC_STATE_DIR, name);
    virLXCControllerDeleteInterfaces(ctrl);
    for (i = 0 ; i < nttyFDs ; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);

    virLXCControllerFree(ctrl);

    return rc < 0? EXIT_FAILURE : EXIT_SUCCESS;
}
