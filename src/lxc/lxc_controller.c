/*
 * Copyright (C) 2010-2013 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
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

#if WITH_CAPNG
# include <cap-ng.h>
#endif

#include "virerror.h"
#include "virlog.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "lxc_cgroup.h"
#include "lxc_monitor_protocol.h"
#include "lxc_fuse.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "viralloc.h"
#include "virfile.h"
#include "virpidfile.h"
#include "vircommand.h"
#include "nodeinfo.h"
#include "virrandom.h"
#include "virprocess.h"
#include "virnuma.h"
#include "virdbus.h"
#include "rpc/virnetserver.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_LXC

typedef struct _virLXCControllerConsole virLXCControllerConsole;
typedef virLXCControllerConsole *virLXCControllerConsolePtr;
struct _virLXCControllerConsole {
    int hostWatch;
    int hostFd;  /* PTY FD in the host OS */
    bool hostClosed;
    int hostEpoll;

    int contWatch;
    int contFd;  /* PTY FD in the container */
    bool contClosed;
    int contEpoll;

    int epollWatch;
    int epollFd; /* epoll FD for dealing with EOF */

    size_t fromHostLen;
    char fromHostBuf[1024];
    size_t fromContLen;
    char fromContBuf[1024];

    virNetServerPtr server;
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

    size_t npassFDs;
    int *passFDs;

    size_t nconsoles;
    virLXCControllerConsolePtr consoles;
    char *devptmx;

    size_t nloopDevs;
    int *loopDevFds;

    virSecurityManagerPtr securityManager;

    /* Server socket */
    virNetServerPtr server;
    bool firstClient;
    virNetServerClientPtr client;
    virNetServerProgramPtr prog;
    bool inShutdown;
    int timerShutdown;

    virCgroupPtr cgroup;

    virLXCFusePtr fuse;
};

#include "lxc_controller_dispatch.h"

static void virLXCControllerFree(virLXCControllerPtr ctrl);
static int virLXCControllerEventSendInit(virLXCControllerPtr ctrl,
                                         pid_t initpid);

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
    virDomainXMLOptionPtr xmlopt = NULL;
    char *configFile = NULL;

    if (VIR_ALLOC(ctrl) < 0)
        goto error;

    ctrl->timerShutdown = -1;
    ctrl->firstClient = true;

    if (VIR_STRDUP(ctrl->name, name) < 0)
        goto error;

    if (!(caps = virLXCDriverCapsInit(NULL)))
        goto error;

    if (!(xmlopt = lxcDomainXMLConfInit()))
        goto error;

    if ((configFile = virDomainConfigFile(LXC_STATE_DIR,
                                          ctrl->name)) == NULL)
        goto error;

    if ((ctrl->def = virDomainDefParseFile(configFile,
                                           caps, xmlopt,
                                           1 << VIR_DOMAIN_VIRT_LXC,
                                           0)) == NULL)
        goto error;

    if ((ctrl->timerShutdown = virEventAddTimeout(-1,
                                                  virLXCControllerQuitTimer, ctrl,
                                                  NULL)) < 0)
        goto error;

cleanup:
    VIR_FREE(configFile);
    virObjectUnref(caps);
    virObjectUnref(xmlopt);
    return ctrl;

error:
    virLXCControllerFree(ctrl);
    ctrl = NULL;
    goto cleanup;
}


static int virLXCControllerCloseLoopDevices(virLXCControllerPtr ctrl)
{
    size_t i;

    for (i = 0; i < ctrl->nloopDevs; i++)
        VIR_FORCE_CLOSE(ctrl->loopDevFds[i]);

    return 0;
}


static void virLXCControllerStopInit(virLXCControllerPtr ctrl)
{
    if (ctrl->initpid == 0)
        return;

    virLXCControllerCloseLoopDevices(ctrl);
    virProcessAbort(ctrl->initpid);
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


static void
virLXCControllerFreeFuse(virLXCControllerPtr ctrl)
{
    return lxcFreeFuse(&ctrl->fuse);
}


static void virLXCControllerFree(virLXCControllerPtr ctrl)
{
    size_t i;

    if (!ctrl)
        return;

    virLXCControllerStopInit(ctrl);

    virObjectUnref(ctrl->securityManager);

    for (i = 0; i < ctrl->nveths; i++)
        VIR_FREE(ctrl->veths[i]);
    VIR_FREE(ctrl->veths);

    for (i = 0; i < ctrl->npassFDs; i++)
        VIR_FORCE_CLOSE(ctrl->passFDs[i]);
    VIR_FREE(ctrl->passFDs);

    for (i = 0; i < ctrl->nconsoles; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));
    VIR_FREE(ctrl->consoles);

    VIR_FREE(ctrl->devptmx);

    virDomainDefFree(ctrl->def);
    VIR_FREE(ctrl->name);

    if (ctrl->timerShutdown != -1)
        virEventRemoveTimeout(ctrl->timerShutdown);

    virObjectUnref(ctrl->server);
    virLXCControllerFreeFuse(ctrl);

    virCgroupFree(&ctrl->cgroup);

    /* This must always be the last thing to be closed */
    VIR_FORCE_CLOSE(ctrl->handshakeFd);
    VIR_FREE(ctrl);
}


static int virLXCControllerAddConsole(virLXCControllerPtr ctrl,
                                      int hostFd)
{
    if (VIR_EXPAND_N(ctrl->consoles, ctrl->nconsoles, 1) < 0)
        return -1;
    ctrl->consoles[ctrl->nconsoles-1].server = ctrl->server;
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
                       _("expecting %zu veths, but got %zu"),
                       ctrl->def->nnets, ctrl->nveths);
        return -1;
    }

    return 0;
}


static int virLXCControllerValidateConsoles(virLXCControllerPtr ctrl)
{
    if (ctrl->def->nconsoles != ctrl->nconsoles) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("expecting %zu consoles, but got %zu tty file handlers"),
                       ctrl->def->nconsoles, ctrl->nconsoles);
        return -1;
    }

    return 0;
}


static int virLXCControllerSetupLoopDeviceFS(virDomainFSDefPtr fs)
{
    int lofd;
    char *loname = NULL;

    if ((lofd = virFileLoopDeviceAssociate(fs->src, &loname)) < 0)
        return -1;

    VIR_DEBUG("Changing fs %s to use type=block for dev %s",
              fs->src, loname);
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


static int virLXCControllerSetupLoopDeviceDisk(virDomainDiskDefPtr disk)
{
    int lofd;
    char *loname = NULL;

    if ((lofd = virFileLoopDeviceAssociate(disk->src, &loname)) < 0)
        return -1;

    VIR_DEBUG("Changing disk %s to use type=block for dev %s",
              disk->src, loname);

    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
    VIR_FREE(disk->src);
    disk->src = loname;
    loname = NULL;

    return lofd;
}


static int virLXCControllerSetupNBDDeviceFS(virDomainFSDefPtr fs)
{
    char *dev;

    if (fs->format <= VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("An explicit disk format must be specified"));
        return -1;
    }

    if (virFileNBDDeviceAssociate(fs->src,
                                  fs->format,
                                  fs->readonly,
                                  &dev) < 0)
        return -1;

    VIR_DEBUG("Changing fs %s to use type=block for dev %s",
              fs->src, dev);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    fs->type = VIR_DOMAIN_FS_TYPE_BLOCK;
    VIR_FREE(fs->src);
    fs->src = dev;

    return 0;
}


static int virLXCControllerSetupNBDDeviceDisk(virDomainDiskDefPtr disk)
{
    char *dev;

    if (disk->format <= VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("An explicit disk format must be specified"));
        return -1;
    }

    if (virFileNBDDeviceAssociate(disk->src,
                                  disk->format,
                                  disk->readonly,
                                  &dev) < 0)
        return -1;

    VIR_DEBUG("Changing disk %s to use type=block for dev %s",
              disk->src, dev);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
    VIR_FREE(disk->src);
    disk->src = dev;

    return 0;
}


static int virLXCControllerSetupLoopDevices(virLXCControllerPtr ctrl)
{
    size_t i;
    int ret = -1;

    VIR_DEBUG("Setting up loop devices for filesystems");

    for (i = 0; i < ctrl->def->nfss; i++) {
        virDomainFSDefPtr fs = ctrl->def->fss[i];
        int fd;

        if (fs->type != VIR_DOMAIN_FS_TYPE_FILE)
            continue;

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) {
            if (fs->format == VIR_STORAGE_FILE_RAW ||
                fs->format == VIR_STORAGE_FILE_NONE)
                fs->fsdriver = VIR_DOMAIN_FS_DRIVER_TYPE_LOOP;
            else
                fs->fsdriver = VIR_DOMAIN_FS_DRIVER_TYPE_NBD;
        }

        if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_LOOP) {
            if (fs->format != VIR_STORAGE_FILE_RAW &&
                fs->format != VIR_STORAGE_FILE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("fs format %s is not supported"),
                               virStorageFileFormatTypeToString(fs->format));
                goto cleanup;
            }

            fd = virLXCControllerSetupLoopDeviceFS(fs);
            if (fd < 0)
                goto cleanup;

            VIR_DEBUG("Saving loop fd %d", fd);
            if (VIR_EXPAND_N(ctrl->loopDevFds, ctrl->nloopDevs, 1) < 0) {
                VIR_FORCE_CLOSE(fd);
                goto cleanup;
            }
            ctrl->loopDevFds[ctrl->nloopDevs - 1] = fd;
        } else if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_NBD) {
            if (virLXCControllerSetupNBDDeviceFS(fs) < 0)
                goto cleanup;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("fs driver %s is not supported"),
                           virDomainFSDriverTypeTypeToString(fs->fsdriver));
            goto cleanup;
        }
    }

    VIR_DEBUG("Setting up loop devices for disks");

    for (i = 0; i < ctrl->def->ndisks; i++) {
        virDomainDiskDefPtr disk = ctrl->def->disks[i];
        int fd;

        if (disk->type != VIR_DOMAIN_DISK_TYPE_FILE)
            continue;

        /* If no driverName is set, we prefer 'loop' for
         * dealing with raw or undefined formats, otherwise
         * we use 'nbd'.
         */
        if (STREQ_NULLABLE(disk->driverName, "loop") ||
            (!disk->driverName &&
             (disk->format == VIR_STORAGE_FILE_RAW ||
              disk->format == VIR_STORAGE_FILE_NONE))) {
            if (disk->format != VIR_STORAGE_FILE_RAW &&
                disk->format != VIR_STORAGE_FILE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk format %s is not supported"),
                               virStorageFileFormatTypeToString(disk->format));
                goto cleanup;
            }

            /* We treat 'none' as meaning 'raw' since we
             * don't want to go into the auto-probing
             * business for security reasons
             */
            fd = virLXCControllerSetupLoopDeviceDisk(disk);
            if (fd < 0)
                goto cleanup;

            VIR_DEBUG("Saving loop fd %d", fd);
            if (VIR_EXPAND_N(ctrl->loopDevFds, ctrl->nloopDevs, 1) < 0) {
                VIR_FORCE_CLOSE(fd);
                goto cleanup;
            }
            ctrl->loopDevFds[ctrl->nloopDevs - 1] = fd;
        } else if (STREQ_NULLABLE(disk->driverName, "nbd") ||
                   !disk->driverName) {
            if (disk->cachemode != VIR_DOMAIN_DISK_CACHE_DEFAULT &&
                disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Disk cache mode %s is not supported"),
                               virDomainDiskCacheTypeToString(disk->cachemode));
                goto cleanup;
            }
            if (virLXCControllerSetupNBDDeviceDisk(disk) < 0)
                goto cleanup;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk driver %s is not supported"),
                           disk->driverName);
            goto cleanup;
        }
    }

    VIR_DEBUG("Setup all loop devices");
    ret = 0;

cleanup:
    return ret;
}


/*
 * To be run while still single threaded
 */
static int virLXCControllerSetupCpuAffinity(virLXCControllerPtr ctrl)
{
    int hostcpus, maxcpu = CPU_SETSIZE;
    virBitmapPtr cpumap, cpumapToSet;

    VIR_DEBUG("Setting CPU affinity");

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    if ((hostcpus = nodeGetCPUCount()) < 0)
        return -1;

    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    cpumap = virBitmapNew(maxcpu);
    if (!cpumap)
        return -1;

    cpumapToSet = cpumap;

    if (ctrl->def->cpumask) {
        cpumapToSet = ctrl->def->cpumask;
    } else {
        /* You may think this is redundant, but we can't assume libvirtd
         * itself is running on all pCPUs, so we need to explicitly set
         * the spawned LXC instance to all pCPUs if no map is given in
         * its config file */
        virBitmapSetAll(cpumap);
    }

    /* We are presuming we are running between fork/exec of LXC
     * so use '0' to indicate our own process ID. No threads are
     * running at this point
     */
    if (virProcessSetAffinity(0 /* Self */, cpumapToSet) < 0) {
        virBitmapFree(cpumap);
        return -1;
    }
    virBitmapFree(cpumap);

    return 0;
}


static int virLXCControllerGetNumadAdvice(virLXCControllerPtr ctrl,
                                          virBitmapPtr *mask)
{
    virBitmapPtr nodemask = NULL;
    char *nodeset = NULL;
    int ret = -1;

    /* Get the advisory nodeset from numad if 'placement' of
     * either <vcpu> or <numatune> is 'auto'.
     */
    if ((ctrl->def->placement_mode ==
         VIR_DOMAIN_CPU_PLACEMENT_MODE_AUTO) ||
        (ctrl->def->numatune.memory.placement_mode ==
         VIR_NUMA_TUNE_MEM_PLACEMENT_MODE_AUTO)) {
        nodeset = virNumaGetAutoPlacementAdvice(ctrl->def->vcpus,
                                                ctrl->def->mem.cur_balloon);
        if (!nodeset)
            goto cleanup;

        VIR_DEBUG("Nodeset returned from numad: %s", nodeset);

        if (virBitmapParse(nodeset, 0, &nodemask, VIR_DOMAIN_CPUMASK_LEN) < 0)
            goto cleanup;
    }

    ret = 0;
    *mask = nodemask;

cleanup:
    VIR_FREE(nodeset);
    return ret;
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
    virBitmapPtr nodemask = NULL;
    int ret = -1;

    if (virLXCControllerGetNumadAdvice(ctrl, &nodemask) < 0 ||
        virNumaSetupMemoryPolicy(ctrl->def->numatune, nodemask) < 0)
        goto cleanup;

    if (virLXCControllerSetupCpuAffinity(ctrl) < 0)
        goto cleanup;

    if (virLXCCgroupSetup(ctrl->def, ctrl->cgroup, nodemask) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    virBitmapFree(nodemask);
    return ret;
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

static void virLXCControllerClientPrivateFree(void *data)
{
    virLXCControllerPtr ctrl = data;
    VIR_DEBUG("Got private data free %p", ctrl);
}

static void *virLXCControllerClientPrivateNew(virNetServerClientPtr client,
                                              void *opaque)
{
    virLXCControllerPtr ctrl = opaque;

    virNetServerClientSetCloseHook(client, virLXCControllerClientCloseHook);
    VIR_DEBUG("Got new client %p", client);
    ctrl->client = client;

    if (ctrl->initpid && ctrl->firstClient)
        virLXCControllerEventSendInit(ctrl, ctrl->initpid);
    ctrl->firstClient = false;

    return ctrl;
}


static int virLXCControllerSetupServer(virLXCControllerPtr ctrl)
{
    virNetServerServicePtr svc = NULL;
    char *sockpath;

    if (virAsprintf(&sockpath, "%s/%s.sock",
                    LXC_STATE_DIR, ctrl->name) < 0)
        return -1;

    if (!(ctrl->server = virNetServerNew(0, 0, 0, 1,
                                         -1, 0, false,
                                         NULL,
                                         virLXCControllerClientPrivateNew,
                                         NULL,
                                         virLXCControllerClientPrivateFree,
                                         ctrl)))
        goto error;

    if (!(svc = virNetServerServiceNewUNIX(sockpath,
                                           0700,
                                           0,
                                           0,
#if WITH_GNUTLS
                                           NULL,
#endif
                                           false,
                                           0,
                                           5)))
        goto error;

    if (virNetServerAddService(ctrl->server, svc, NULL) < 0)
        goto error;
    virObjectUnref(svc);
    svc = NULL;

    if (!(ctrl->prog = virNetServerProgramNew(VIR_LXC_MONITOR_PROGRAM,
                                              VIR_LXC_MONITOR_PROGRAM_VERSION,
                                              virLXCMonitorProcs,
                                              virLXCMonitorNProcs)))
        goto error;

    virNetServerUpdateServices(ctrl->server, true);
    VIR_FREE(sockpath);
    return 0;

error:
    VIR_FREE(sockpath);
    virObjectUnref(ctrl->server);
    ctrl->server = NULL;
    virObjectUnref(svc);
    return -1;
}


static int lxcControllerClearCapabilities(void)
{
#if WITH_CAPNG
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

static bool wantReboot = false;
static virMutex lock;


static void virLXCControllerSignalChildIO(virNetServerPtr server,
                                          siginfo_t *info ATTRIBUTE_UNUSED,
                                          void *opaque)
{
    virLXCControllerPtr ctrl = opaque;
    int ret;
    int status;

    ret = waitpid(-1, &status, WNOHANG);
    VIR_DEBUG("Got sig child %d vs %lld", ret, (unsigned long long)ctrl->initpid);
    if (ret == ctrl->initpid) {
        virNetServerQuit(server);
        virMutexLock(&lock);
        if (WIFSIGNALED(status) &&
            WTERMSIG(status) == SIGHUP) {
            VIR_DEBUG("Status indicates reboot");
            wantReboot = true;
        }
        virMutexUnlock(&lock);
    }
}


static void virLXCControllerConsoleUpdateWatch(virLXCControllerConsolePtr console)
{
    int hostEvents = 0;
    int contEvents = 0;

    /* If host console is open, then we can look to read/write */
    if (!console->hostClosed) {
        if (console->fromHostLen < sizeof(console->fromHostBuf))
            hostEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromContLen)
            hostEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }

    /* If cont console is open, then we can look to read/write */
    if (!console->contClosed) {
        if (console->fromContLen < sizeof(console->fromContBuf))
            contEvents |= VIR_EVENT_HANDLE_READABLE;
        if (console->fromHostLen)
            contEvents |= VIR_EVENT_HANDLE_WRITABLE;
    }

    VIR_DEBUG("Container watch=%d, events=%d closed=%d; host watch=%d events=%d closed=%d",
              console->contWatch, contEvents, console->contClosed,
              console->hostWatch, hostEvents, console->hostClosed);
    virEventUpdateHandle(console->contWatch, contEvents);
    virEventUpdateHandle(console->hostWatch, hostEvents);

    if (console->hostClosed) {
        /* Must setup an epoll to detect when host becomes accessible again */
        int events = EPOLLIN | EPOLLET;
        if (console->fromContLen)
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
                virNetServerQuit(console->server);
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
            virNetServerQuit(console->server);
            goto cleanup;
        }
        console->hostEpoll = 0;
    }

    if (console->contClosed) {
        /* Must setup an epoll to detect when guest becomes accessible again */
        int events = EPOLLIN | EPOLLET;
        if (console->fromHostLen)
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
                virNetServerQuit(console->server);
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
            virNetServerQuit(console->server);
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
            virNetServerQuit(console->server);
            goto cleanup;
        }

        if (ret == 0)
            break;

        VIR_DEBUG("fd=%d hostFd=%d contFd=%d hostEpoll=%x contEpoll=%x",
                  event.data.fd, console->hostFd, console->contFd,
                  console->hostEpoll, console->contEpoll);

        /* If we get HUP+dead PID, we just re-enable the main loop
         * which will see the PID has died and exit */
        if ((event.events & (EPOLLIN|EPOLLOUT))) {
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
    virNetServerQuit(console->server);
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

    for (i = 0; i < ctrl->nconsoles; i++) {
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

    virNetServerRun(ctrl->server);

    err = virGetLastError();
    if (!err || err->code == VIR_ERR_OK)
        rc = wantReboot ? 1 : 0;

cleanup:
    virMutexDestroy(&lock);
cleanup2:

    for (i = 0; i < ctrl->nconsoles; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));

    return rc;
}


static int
virLXCControllerSetupUsernsMap(virDomainIdMapEntryPtr map,
                               int num,
                               char *path)
{
    virBuffer map_value = VIR_BUFFER_INITIALIZER;
    size_t i;
    int ret = -1;

    for (i = 0; i < num; i++)
        virBufferAsprintf(&map_value, "%u %u %u\n",
                          map[i].start, map[i].target, map[i].count);

    if (virBufferError(&map_value))
        goto no_memory;

    VIR_DEBUG("Set '%s' to '%s'", path, virBufferCurrentContent(&map_value));

    if (virFileWriteStr(path, virBufferCurrentContent(&map_value), 0) < 0) {
        virReportSystemError(errno, _("unable write to %s"), path);
        goto cleanup;
    }

    ret = 0;
cleanup:
    virBufferFreeAndReset(&map_value);
    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}

/**
 * virLXCControllerSetupUserns
 *
 * Set proc files for user namespace
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerSetupUserns(virLXCControllerPtr ctrl)
{
    char *uid_map = NULL;
    char *gid_map = NULL;
    int ret = -1;

    /* User namespace is disabled for container */
    if (ctrl->def->idmap.nuidmap == 0)
        return 0;

    if (virAsprintf(&uid_map, "/proc/%d/uid_map", ctrl->initpid) < 0)
        goto cleanup;

    if (virLXCControllerSetupUsernsMap(ctrl->def->idmap.uidmap,
                                       ctrl->def->idmap.nuidmap,
                                       uid_map) < 0)
        goto cleanup;

    if (virAsprintf(&gid_map, "/proc/%d/gid_map", ctrl->initpid) < 0)
        goto cleanup;

    if (virLXCControllerSetupUsernsMap(ctrl->def->idmap.gidmap,
                                       ctrl->def->idmap.ngidmap,
                                       gid_map) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(uid_map);
    VIR_FREE(gid_map);
    return ret;
}

static int virLXCControllerSetupDev(virLXCControllerPtr ctrl)
{
    char *mount_options = NULL;
    char *opts = NULL;
    char *dev = NULL;
    int ret = -1;

    VIR_DEBUG("Setting up /dev/ for container");

    mount_options = virSecurityManagerGetMountOptions(ctrl->securityManager,
                                                      ctrl->def);

    if (virAsprintf(&dev, "/%s/%s.dev",
                    LXC_STATE_DIR, ctrl->def->name) < 0)
        goto cleanup;

    if (virFileMakePath(dev) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %s"), dev);
        goto cleanup;
    }

    /*
     * tmpfs is limited to 64kb, since we only have device nodes in there
     * and don't want to DOS the entire OS RAM usage
     */

    if (virAsprintf(&opts,
                    "mode=755,size=65536%s", mount_options) < 0)
        goto cleanup;

    VIR_DEBUG("Mount devfs on %s type=tmpfs flags=%x, opts=%s",
              dev, MS_NOSUID, opts);
    if (mount("devfs", dev, "tmpfs", MS_NOSUID, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devfs on %s type %s (%s)"),
                             dev, "tmpfs", opts);
        goto cleanup;
    }

    if (lxcContainerChown(ctrl->def, dev) < 0)
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(opts);
    VIR_FREE(mount_options);
    VIR_FREE(dev);
    return ret;
}

static int virLXCControllerPopulateDevices(virLXCControllerPtr ctrl)
{
    size_t i;
    int ret = -1;
    char *path = NULL;
    const struct {
        int maj;
        int min;
        mode_t mode;
        const char *path;
    } devs[] = {
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL, 0666, "/null" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO, 0666, "/zero" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL, 0666, "/full" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM, 0666, "/random" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM, 0666, "/urandom" },
        { LXC_DEV_MAJ_TTY, LXC_DEV_MIN_TTY, 0666, "/tty" },
    };

    if (virLXCControllerSetupDev(ctrl) < 0)
        goto cleanup;

    /* Populate /dev/ with a few important bits */
    for (i = 0; i < ARRAY_CARDINALITY(devs); i++) {
        if (virAsprintf(&path, "/%s/%s.dev/%s",
                        LXC_STATE_DIR, ctrl->def->name, devs[i].path) < 0)
            goto cleanup;

        dev_t dev = makedev(devs[i].maj, devs[i].min);
        if (mknod(path, S_IFCHR, dev) < 0 ||
            chmod(path, devs[i].mode)) {
            virReportSystemError(errno,
                                 _("Failed to make device %s"),
                                 path);
            goto cleanup;
        }

        if (lxcContainerChown(ctrl->def, path) < 0)
            goto cleanup;

        VIR_FREE(path);
    }

    ret = 0;
cleanup:
    VIR_FREE(path);
    return ret;
}


static int
virLXCControllerSetupHostdevSubsysUSB(virDomainDefPtr vmDef,
                                      virDomainHostdevDefPtr def,
                                      virSecurityManagerPtr securityDriver)
{
    int ret = -1;
    char *src = NULL;
    char *dstdir = NULL;
    char *dstfile = NULL;
    char *vroot = NULL;
    struct stat sb;
    mode_t mode;

    if (virAsprintf(&src, USB_DEVFS "/%03d/%03d",
                    def->source.subsys.u.usb.bus,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (virAsprintf(&vroot, "/%s/%s.dev/bus/usb/",
                    LXC_STATE_DIR, vmDef->name) < 0)
        goto cleanup;

    if (virAsprintf(&dstdir, "%s/%03d/", vroot,
                    def->source.subsys.u.usb.bus) < 0)
        goto cleanup;

    if (virAsprintf(&dstfile, "%s/%03d", dstdir,
                    def->source.subsys.u.usb.device) < 0)
        goto cleanup;

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), src);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("USB source %s was not a character device"),
                       src);
        goto cleanup;
    }

    mode = 0700 | S_IFCHR;

    if (virFileMakePath(dstdir) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %s"), dstdir);
        goto cleanup;
    }

    VIR_DEBUG("Creating dev %s (%d,%d)",
              dstfile, major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dstfile, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dstfile);
        goto cleanup;
    }

    if (lxcContainerChown(vmDef, dstfile) < 0)
        goto cleanup;

    if (virSecurityManagerSetHostdevLabel(securityDriver,
                                          vmDef, def, vroot) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(src);
    VIR_FREE(dstfile);
    VIR_FREE(dstdir);
    VIR_FREE(vroot);
    return ret;
}


static int
virLXCControllerSetupHostdevCapsStorage(virDomainDefPtr vmDef,
                                        virDomainHostdevDefPtr def,
                                        virSecurityManagerPtr securityDriver)
{
    char *dst = NULL;
    char *path = NULL;
    int len = 0;
    int ret = -1;
    struct stat sb;
    mode_t mode;
    char *dev = def->source.caps.u.storage.block;

    if (dev == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing storage host block path"));
        goto cleanup;
    }

    if (VIR_STRDUP(path, dev) < 0)
        goto cleanup;

    while (*(path + len) == '/')
        len++;

    if (virAsprintf(&dst, "/%s/%s.dev/%s",
                    LXC_STATE_DIR, vmDef->name,
                    strchr(path + len, '/')) < 0)
        goto cleanup;

    if (stat(dev, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"),
                             dev);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Storage source %s must be a block device"),
                       dev);
        goto cleanup;
    }

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportError(errno,
                       _("Failed to create directory for device %s"),
                       dev);
        goto cleanup;
    }

    mode = 0700 | S_IFBLK;

    VIR_DEBUG("Creating dev %s (%d,%d)", dst,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dst);
        goto cleanup;
    }

    if (lxcContainerChown(vmDef, dst) < 0)
        goto cleanup;

    def->source.caps.u.storage.block = dst;
    if (virSecurityManagerSetHostdevLabel(securityDriver, vmDef, def, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    def->source.caps.u.storage.block = dev;
    VIR_FREE(dst);
    VIR_FREE(path);
    return ret;
}


static int
virLXCControllerSetupHostdevCapsMisc(virDomainDefPtr vmDef,
                                     virDomainHostdevDefPtr def,
                                     virSecurityManagerPtr securityDriver)
{
    char *dst = NULL;
    char *path = NULL;
    int len = 0;
    int ret = -1;
    struct stat sb;
    mode_t mode;
    char *dev = def->source.caps.u.misc.chardev;

    if (dev == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Missing storage host block path"));
        goto cleanup;
    }

    if (VIR_STRDUP(path, dev) < 0)
        goto cleanup;

    while (*(path + len) == '/')
        len++;

    if (virAsprintf(&dst, "/%s/%s.dev/%s",
                    LXC_STATE_DIR, vmDef->name,
                    strchr(path + len, '/')) < 0)
        goto cleanup;

    if (stat(dev, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"),
                             dev);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Storage source %s must be a character device"),
                       dev);
        goto cleanup;
    }

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportError(errno,
                       _("Failed to create directory for device %s"),
                       dst);
        goto cleanup;
    }

    mode = 0700 | S_IFCHR;

    VIR_DEBUG("Creating dev %s (%d,%d)", dst,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dev);
        goto cleanup;
    }

    if (lxcContainerChown(vmDef, dst) < 0)
        goto cleanup;

    def->source.caps.u.misc.chardev = dst;
    if (virSecurityManagerSetHostdevLabel(securityDriver, vmDef, def, NULL) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    def->source.caps.u.misc.chardev = dev;
    VIR_FREE(dst);
    VIR_FREE(path);
    return ret;
}

static int
virLXCControllerSetupHostdevSubsys(virDomainDefPtr vmDef,
                                   virDomainHostdevDefPtr def,
                                   virSecurityManagerPtr securityDriver)
{
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return virLXCControllerSetupHostdevSubsysUSB(vmDef,
                                                     def,
                                                     securityDriver);

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %s"),
                       virDomainHostdevSubsysTypeToString(def->source.subsys.type));
        return -1;
    }
}


static int
virLXCControllerSetupHostdevCaps(virDomainDefPtr vmDef,
                                 virDomainHostdevDefPtr def,
                                 virSecurityManagerPtr securityDriver)
{
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return virLXCControllerSetupHostdevCapsStorage(vmDef,
                                                       def,
                                                       securityDriver);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return virLXCControllerSetupHostdevCapsMisc(vmDef,
                                                    def,
                                                    securityDriver);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        return 0; // case is handled in virLXCControllerMoveInterfaces

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %s"),
                       virDomainHostdevCapsTypeToString(def->source.subsys.type));
        return -1;
    }
}


static int
virLXCControllerSetupAllHostdevs(virLXCControllerPtr ctrl)
{
    size_t i;
    virDomainDefPtr vmDef = ctrl->def;
    virSecurityManagerPtr securityDriver = ctrl->securityManager;
    VIR_DEBUG("Setting up hostdevs");

    for (i = 0; i < vmDef->nhostdevs; i++) {
        virDomainHostdevDefPtr def = vmDef->hostdevs[i];
        switch (def->mode) {
        case VIR_DOMAIN_HOSTDEV_MODE_SUBSYS:
            if (virLXCControllerSetupHostdevSubsys(vmDef,
                                                   def,
                                                   securityDriver) < 0)
                return -1;
            break;
        case VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES:
            if (virLXCControllerSetupHostdevCaps(vmDef,
                                                 def,
                                                 securityDriver) < 0)
                return -1;
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported host device mode %s"),
                           virDomainHostdevModeTypeToString(def->mode));
            return -1;
        }
    }

    VIR_DEBUG("Setup all hostdevs");
    return 0;
}


static int virLXCControllerSetupDisk(virLXCControllerPtr ctrl,
                                     virDomainDiskDefPtr def,
                                     virSecurityManagerPtr securityDriver)
{
    char *dst = NULL;
    int ret = -1;
    struct stat sb;
    mode_t mode;
    char *tmpsrc = def->src;

    if (def->type != VIR_DOMAIN_DISK_TYPE_BLOCK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk for non-block device"));
        goto cleanup;
    }
    if (def->src == NULL) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk without media"));
        goto cleanup;
    }

    if (virAsprintf(&dst, "/%s/%s.dev/%s",
                    LXC_STATE_DIR, ctrl->def->name, def->dst) < 0)
        goto cleanup;

    if (stat(def->src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %s"), def->src);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk source %s must be a character/block device"),
                       def->src);
        goto cleanup;
    }

    mode = 0700;
    if (S_ISCHR(sb.st_mode))
        mode |= S_IFCHR;
    else
        mode |= S_IFBLK;

    /* Yes, the device name we're creating may not
     * actually correspond to the major:minor number
     * we're using, but we've no other option at this
     * time. Just have to hope that containerized apps
     * don't get upset that the major:minor is different
     * to that normally implied by the device name
     */
    VIR_DEBUG("Creating dev %s (%d,%d) from %s",
              dst, major(sb.st_rdev), minor(sb.st_rdev), def->src);
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %s"),
                             dst);
        goto cleanup;
    }

    if (lxcContainerChown(ctrl->def, dst) < 0)
        goto cleanup;

    /* Labelling normally operates on src, but we need
     * to actually label the dst here, so hack the config */
    def->src = dst;
    if (virSecurityManagerSetImageLabel(securityDriver, ctrl->def, def) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    def->src = tmpsrc;
    VIR_FREE(dst);
    return ret;
}

static int virLXCControllerSetupAllDisks(virLXCControllerPtr ctrl)
{
    size_t i;
    VIR_DEBUG("Setting up disks");

    for (i = 0; i < ctrl->def->ndisks; i++) {
        if (virLXCControllerSetupDisk(ctrl, ctrl->def->disks[i],
                                      ctrl->securityManager) < 0)
            return -1;
    }

    VIR_DEBUG("Setup all disks");
    return 0;
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
    virDomainDefPtr def = ctrl->def;

    for (i = 0; i < ctrl->nveths; i++) {
        if (virNetDevSetNamespace(ctrl->veths[i], ctrl->initpid) < 0)
            return -1;
    }

    for (i = 0; i < def->nhostdevs; i ++) {
        virDomainHostdevDefPtr hdev = def->hostdevs[i];

        if (hdev->mode != VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES)
            continue;

        virDomainHostdevCaps hdcaps = hdev->source.caps;

        if (hdcaps.type != VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET)
           continue;

        if (virNetDevSetNamespace(hdcaps.u.net.iface, ctrl->initpid) < 0)
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

    for (i = 0; i < ctrl->nveths; i++) {
        if (virNetDevVethDelete(ctrl->veths[i]) < 0)
            ret = -1;
    }

    return ret;
}


static int lxcSetPersonality(virDomainDefPtr def)
{
    virArch altArch;

    altArch = lxcContainerGetAlt32bitArch(virArchFromHost());
    if (altArch &&
        (def->os.arch == altArch)) {
        if (personality(PER_LINUX32) < 0) {
            virReportSystemError(errno, _("Unable to request personality for %s on %s"),
                                 virArchToString(altArch),
                                 virArchToString(virArchFromHost()));
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
lxcCreateTty(virLXCControllerPtr ctrl, int *ttymaster,
             char **ttyName, char **ttyHostPath)
{
    int ret = -1;
    int ptyno;
    int unlock = 0;

    if ((*ttymaster = open(ctrl->devptmx, O_RDWR|O_NOCTTY|O_NONBLOCK)) < 0)
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
    if ((virAsprintf(ttyName, "/dev/pts/%d", ptyno) < 0) ||
        (virAsprintf(ttyHostPath, "/%s/%s.devpts/%d", LXC_STATE_DIR,
                    ctrl->def->name, ptyno) < 0)) {
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
virLXCControllerSetupPrivateNS(void)
{
    int ret = -1;

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

    ret = 0;
cleanup:
    return ret;
}


static int
virLXCControllerSetupDevPTS(virLXCControllerPtr ctrl)
{
    char *mount_options = NULL;
    char *opts = NULL;
    char *devpts = NULL;
    int ret = -1;

    VIR_DEBUG("Setting up private /dev/pts");

    mount_options = virSecurityManagerGetMountOptions(ctrl->securityManager,
                                                      ctrl->def);

    if (virAsprintf(&devpts, "%s/%s.devpts",
                    LXC_STATE_DIR, ctrl->def->name) < 0 ||
        virAsprintf(&ctrl->devptmx, "%s/%s.devpts/ptmx",
                    LXC_STATE_DIR, ctrl->def->name) < 0)
        goto cleanup;

    if (virFileMakePath(devpts) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %s"),
                             devpts);
        goto cleanup;
    }

    /* XXX should we support gid=X for X!=5 for distros which use
     * a different gid for tty?  */
    if (virAsprintf(&opts, "newinstance,ptmxmode=0666,mode=0620,gid=5%s",
                    (mount_options ? mount_options : "")) < 0)
        goto cleanup;

    VIR_DEBUG("Mount devpts on %s type=tmpfs flags=%x, opts=%s",
              devpts, MS_NOSUID, opts);
    if (mount("devpts", devpts, "devpts", MS_NOSUID, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devpts on %s"),
                             devpts);
        goto cleanup;
    }

    if (access(ctrl->devptmx, R_OK) < 0) {
        virReportSystemError(ENOSYS, "%s",
                             _("Kernel does not support private devpts"));
        goto cleanup;
    }

    if ((lxcContainerChown(ctrl->def, ctrl->devptmx) < 0) ||
        (lxcContainerChown(ctrl->def, devpts) < 0))
         goto cleanup;

    ret = 0;

cleanup:
    VIR_FREE(opts);
    VIR_FREE(devpts);
    VIR_FREE(mount_options);
    return ret;
}


static int
virLXCControllerSetupFuse(virLXCControllerPtr ctrl)
{
    return lxcSetupFuse(&ctrl->fuse, ctrl->def);
}

static int
virLXCControllerStartFuse(virLXCControllerPtr ctrl)
{
    return lxcStartFuse(ctrl->fuse);
}

static int
virLXCControllerSetupConsoles(virLXCControllerPtr ctrl,
                              char **containerTTYPaths)
{
    size_t i;
    int ret = -1;
    char *ttyHostPath = NULL;

    for (i = 0; i < ctrl->nconsoles; i++) {
        VIR_DEBUG("Opening tty on private %s", ctrl->devptmx);
        if (lxcCreateTty(ctrl,
                         &ctrl->consoles[i].contFd,
                         &containerTTYPaths[i], &ttyHostPath) < 0) {
            virReportSystemError(errno, "%s",
                                     _("Failed to allocate tty"));
            goto cleanup;
        }

        /* Change the owner of tty device to the root user of container */
        if (lxcContainerChown(ctrl->def, ttyHostPath) < 0)
            goto cleanup;

        VIR_FREE(ttyHostPath);
    }

    ret = 0;
cleanup:
    VIR_FREE(ttyHostPath);
    return ret;
}


static void
virLXCControllerEventSend(virLXCControllerPtr ctrl,
                          int procnr,
                          xdrproc_t proc,
                          void *data)
{
    virNetMessagePtr msg;

    if (!ctrl->client) {
        VIR_WARN("Dropping event %d because libvirtd is not connected", procnr);
        return;
    }

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
    virLXCMonitorExitEventMsg msg;

    VIR_DEBUG("Exit status %d (client=%p)", exitstatus, ctrl->client);
    memset(&msg, 0, sizeof(msg));
    switch (exitstatus) {
    case 0:
        msg.status = VIR_LXC_MONITOR_EXIT_STATUS_SHUTDOWN;
        break;
    case 1:
        msg.status = VIR_LXC_MONITOR_EXIT_STATUS_REBOOT;
        break;
    default:
        msg.status = VIR_LXC_MONITOR_EXIT_STATUS_ERROR;
        break;
    }

    virLXCControllerEventSend(ctrl,
                              VIR_LXC_MONITOR_PROC_EXIT_EVENT,
                              (xdrproc_t)xdr_virLXCMonitorExitEventMsg,
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
virLXCControllerEventSendInit(virLXCControllerPtr ctrl,
                              pid_t initpid)
{
    virLXCMonitorInitEventMsg msg;

    VIR_DEBUG("Init pid %llu", (unsigned long long)initpid);
    memset(&msg, 0, sizeof(msg));
    msg.initpid = initpid;

    virLXCControllerEventSend(ctrl,
                              VIR_LXC_MONITOR_PROC_INIT_EVENT,
                              (xdrproc_t)xdr_virLXCMonitorInitEventMsg,
                              (void*)&msg);
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

    if (VIR_ALLOC_N(containerTTYPaths, ctrl->nconsoles) < 0)
        goto cleanup;

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

    if (virLXCControllerSetupPrivateNS() < 0)
        goto cleanup;

    if (virLXCControllerSetupLoopDevices(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupResourceLimits(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupDevPTS(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerPopulateDevices(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupAllDisks(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupAllHostdevs(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupFuse(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerSetupConsoles(ctrl, containerTTYPaths) < 0)
        goto cleanup;

    if (lxcSetPersonality(ctrl->def) < 0)
        goto cleanup;

    if ((ctrl->initpid = lxcContainerStart(ctrl->def,
                                           ctrl->securityManager,
                                           ctrl->nveths,
                                           ctrl->veths,
                                           ctrl->npassFDs,
                                           ctrl->passFDs,
                                           control[1],
                                           containerhandshake[1],
                                           ctrl->nconsoles,
                                           containerTTYPaths)) < 0)
        goto cleanup;
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0; i < ctrl->npassFDs; i++)
        VIR_FORCE_CLOSE(ctrl->passFDs[i]);

    if (virLXCControllerSetupUserns(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerMoveInterfaces(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerStartFuse(ctrl) < 0)
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

    /* ...and reduce our privileges */
    if (lxcControllerClearCapabilities() < 0)
        goto cleanup;

    if (virLXCControllerDaemonHandshake(ctrl) < 0)
        goto cleanup;

    for (i = 0; i < ctrl->nconsoles; i++)
        if (virLXCControllerConsoleSetNonblocking(&(ctrl->consoles[i])) < 0)
            goto cleanup;

    /* We must not hold open a dbus connection for life
     * of LXC instance, since dbus-daemon is limited to
     * only a few 100 connections by default
     */
    virDBusCloseSystemBus();

    rc = virLXCControllerMain(ctrl);

    virLXCControllerEventSendExit(ctrl, rc);

cleanup:
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[0]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0; i < ctrl->nconsoles; i++)
        VIR_FREE(containerTTYPaths[i]);
    VIR_FREE(containerTTYPaths);

    virLXCControllerStopInit(ctrl);

    return rc;
}


int main(int argc, char *argv[])
{
    pid_t pid;
    int rc = -1;
    char *name = NULL;
    size_t nveths = 0;
    char **veths = NULL;
    int handshakeFd = -1;
    bool bg = false;
    const struct option options[] = {
        { "background", 0, NULL, 'b' },
        { "name",   1, NULL, 'n' },
        { "veth",   1, NULL, 'v' },
        { "console", 1, NULL, 'c' },
        { "passfd", 1, NULL, 'p' },
        { "handshakefd", 1, NULL, 's' },
        { "security", 1, NULL, 'S' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    int *ttyFDs = NULL;
    size_t nttyFDs = 0;
    int *passFDs = NULL;
    size_t npassFDs = 0;
    virLXCControllerPtr ctrl = NULL;
    size_t i;
    const char *securityDriver = "none";

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL ||
        virThreadInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize logging */
    virLogSetFromEnv();

    while (1) {
        int c;

        c = getopt_long(argc, argv, "dn:v:p:m:c:s:h:S:",
                       options, NULL);

        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bg = true;
            break;

        case 'n':
            if (VIR_STRDUP(name, optarg) < 0)
                goto cleanup;
            break;

        case 'v':
            if (VIR_REALLOC_N(veths, nveths+1) < 0)
                goto cleanup;
            if (VIR_STRDUP(veths[nveths++], optarg) < 0)
                goto cleanup;
            break;

        case 'c':
            if (VIR_REALLOC_N(ttyFDs, nttyFDs + 1) < 0)
                goto cleanup;
            if (virStrToLong_i(optarg, NULL, 10, &ttyFDs[nttyFDs++]) < 0) {
                fprintf(stderr, "malformed --console argument '%s'", optarg);
                goto cleanup;
            }
            break;

        case 'p':
            if (VIR_REALLOC_N(passFDs, npassFDs + 1) < 0)
                goto cleanup;
            if (virStrToLong_i(optarg, NULL, 10, &passFDs[npassFDs++]) < 0) {
                fprintf(stderr, "malformed --passfd argument '%s'", optarg);
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

    if (geteuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    virEventRegisterDefaultImpl();

    virDBusSetSharedBus(false);

    if (!(ctrl = virLXCControllerNew(name)))
        goto cleanup;

    ctrl->handshakeFd = handshakeFd;

    if (!(ctrl->securityManager = virSecurityManagerNew(securityDriver,
                                                        LXC_DRIVER_NAME,
                                                        false, false, false)))
        goto cleanup;

    if (ctrl->def->seclabels) {
        VIR_DEBUG("Security model %s type %s label %s imagelabel %s",
                  NULLSTR(ctrl->def->seclabels[0]->model),
                  virDomainSeclabelTypeToString(ctrl->def->seclabels[0]->type),
                  NULLSTR(ctrl->def->seclabels[0]->label),
                  NULLSTR(ctrl->def->seclabels[0]->imagelabel));
    } else {
        VIR_DEBUG("Security model not initialized");
    }

    ctrl->veths = veths;
    ctrl->nveths = nveths;

    ctrl->passFDs = passFDs;
    ctrl->npassFDs = npassFDs;

    for (i = 0; i < nttyFDs; i++) {
        if (virLXCControllerAddConsole(ctrl, ttyFDs[i]) < 0)
            goto cleanup;
        ttyFDs[i] = -1;
    }

    if (virLXCControllerValidateNICs(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerValidateConsoles(ctrl) < 0)
        goto cleanup;

    if (!(ctrl->cgroup = virLXCCgroupCreate(ctrl->def)))
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

        /* Don't hold on to any cwd we inherit from libvirtd either */
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
    if (rc < 0) {
        virErrorPtr err = virGetLastError();
        if (err && err->message)
            fprintf(stderr, "%s\n", err->message);
        else
            fprintf(stderr, "%s\n",
                    _("Unknown failure in libvirt_lxc startup"));
    }

    virPidFileDelete(LXC_STATE_DIR, name);
    if (ctrl)
        virLXCControllerDeleteInterfaces(ctrl);
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    VIR_FREE(ttyFDs);
    for (i = 0; i < npassFDs; i++)
        VIR_FORCE_CLOSE(passFDs[i]);
    VIR_FREE(passFDs);

    virLXCControllerFree(ctrl);

    return rc < 0? EXIT_FAILURE : EXIT_SUCCESS;
}
