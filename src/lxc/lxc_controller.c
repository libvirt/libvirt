/*
 * Copyright (C) 2010-2016 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * lxc_controller.c: linux container process controller
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

#ifdef __linux__
# include <sys/sysmacros.h>
#endif

#include <sys/personality.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <sys/mount.h>
#include <grp.h>
#include <sys/stat.h>

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
#include "virgdbus.h"
#include "virpidfile.h"
#include "virhostcpu.h"
#include "virprocess.h"
#include "virnuma.h"
#include "rpc/virnetdaemon.h"
#include "virstring.h"
#include "virgettext.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_controller");

typedef struct _virLXCControllerConsole virLXCControllerConsole;
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

    virNetDaemon *daemon;
};

typedef struct _virLXCController virLXCController;
struct _virLXCController {
    char *name;
    virDomainObj *vm;
    virDomainDef *def;

    int handshakeFds[2]; /* { read FD, write FD } */

    pid_t initpid;

    size_t nnbdpids;
    pid_t *nbdpids;

    size_t nveths;
    char **veths;

    size_t nnicindexes;
    int *nicindexes;

    size_t npassFDs;
    int *passFDs;

    int *nsFDs;

    size_t nconsoles;
    virLXCControllerConsole *consoles;
    char *devptmx;

    size_t nloopDevs;
    int *loopDevFds;

    virSecurityManager *securityManager;

    virNetDaemon *daemon;
    bool firstClient;
    virNetServerClient *client;
    virNetServerProgram *prog;
    bool inShutdown;
    int timerShutdown;

    virCgroup *cgroup;

    struct virLXCFuse *fuse;
};

#include "lxc_controller_dispatch.h"

static void virLXCControllerFree(virLXCController *ctrl);
static int virLXCControllerEventSendInit(virLXCController *ctrl,
                                         pid_t initpid);

static void virLXCControllerQuitTimer(int timer G_GNUC_UNUSED, void *opaque)
{
    virLXCController *ctrl = opaque;

    VIR_DEBUG("Triggering event loop quit");
    virNetDaemonQuit(ctrl->daemon);
}


static virLXCDriver *
virLXCControllerDriverNew(void)
{
    virLXCDriver *driver = g_new0(virLXCDriver, 1);

    if (virMutexInit(&driver->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        g_free(driver);
        return NULL;
    }

    driver->caps = virLXCDriverCapsInit(NULL);
    driver->xmlopt = lxcDomainXMLConfInit(driver, NULL);

    return driver;
}


static void
virLXCControllerDriverFree(virLXCDriver *driver)
{
    if (!driver)
        return;
    virObjectUnref(driver->xmlopt);
    virObjectUnref(driver->caps);
    virMutexDestroy(&driver->lock);
    g_free(driver);
}


static virLXCController *virLXCControllerNew(const char *name)
{
    virLXCController *ctrl = g_new0(virLXCController, 1);
    virLXCDriver *driver = NULL;
    g_autofree char *configFile = NULL;

    ctrl->timerShutdown = -1;
    ctrl->firstClient = true;
    ctrl->name = g_strdup(name);
    ctrl->handshakeFds[0] = -1;
    ctrl->handshakeFds[1] = -1;

    if (!(driver = virLXCControllerDriverNew()))
        goto error;

    if ((configFile = virDomainConfigFile(LXC_STATE_DIR,
                                          ctrl->name)) == NULL)
        goto error;

    if ((ctrl->vm = virDomainObjParseFile(configFile,
                                          driver->xmlopt,
                                          0)) == NULL)
        goto error;
    ctrl->def = ctrl->vm->def;

    if ((ctrl->timerShutdown = virEventAddTimeout(-1,
                                                  virLXCControllerQuitTimer, ctrl,
                                                  NULL)) < 0)
        goto error;

 cleanup:
    virLXCControllerDriverFree(driver);
    return ctrl;

 error:
    g_clear_pointer(&ctrl, virLXCControllerFree);
    goto cleanup;
}


static int virLXCControllerCloseLoopDevices(virLXCController *ctrl)
{
    size_t i;

    for (i = 0; i < ctrl->nloopDevs; i++)
        VIR_FORCE_CLOSE(ctrl->loopDevFds[i]);

    return 0;
}


static void virLXCControllerStopInit(virLXCController *ctrl)
{
    if (ctrl->initpid == 0)
        return;

    virLXCControllerCloseLoopDevices(ctrl);
    virProcessAbort(ctrl->initpid);
    ctrl->initpid = 0;
}


static void virLXCControllerConsoleClose(virLXCControllerConsole *console)
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
virLXCControllerFreeFuse(virLXCController *ctrl)
{
    return lxcFreeFuse(&ctrl->fuse);
}


static void virLXCControllerFree(virLXCController *ctrl)
{
    size_t i;

    if (!ctrl)
        return;

    virLXCControllerStopInit(ctrl);

    virObjectUnref(ctrl->securityManager);

    for (i = 0; i < ctrl->nveths; i++)
        g_free(ctrl->veths[i]);
    g_free(ctrl->veths);
    g_free(ctrl->nicindexes);

    for (i = 0; i < ctrl->npassFDs; i++)
        VIR_FORCE_CLOSE(ctrl->passFDs[i]);
    g_free(ctrl->passFDs);

    for (i = 0; i < ctrl->nconsoles; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));
    g_free(ctrl->consoles);

    g_free(ctrl->devptmx);

    virDomainObjEndAPI(&ctrl->vm);
    g_free(ctrl->name);

    if (ctrl->timerShutdown != -1)
        virEventRemoveTimeout(ctrl->timerShutdown);

    virObjectUnref(ctrl->daemon);
    virLXCControllerFreeFuse(ctrl);

    g_free(ctrl->nbdpids);

    g_free(ctrl->nsFDs);
    virCgroupFree(ctrl->cgroup);

    /* This must always be the last thing to be closed */
    for (i = 0; i < G_N_ELEMENTS(ctrl->handshakeFds); i++)
        VIR_FORCE_CLOSE(ctrl->handshakeFds[i]);
    g_free(ctrl);
}


static int virLXCControllerAddConsole(virLXCController *ctrl,
                                      int hostFd)
{
    VIR_EXPAND_N(ctrl->consoles, ctrl->nconsoles, 1);
    ctrl->consoles[ctrl->nconsoles-1].daemon = ctrl->daemon;
    ctrl->consoles[ctrl->nconsoles-1].hostFd = hostFd;
    ctrl->consoles[ctrl->nconsoles-1].hostWatch = -1;

    ctrl->consoles[ctrl->nconsoles-1].contFd = -1;
    ctrl->consoles[ctrl->nconsoles-1].contWatch = -1;

    ctrl->consoles[ctrl->nconsoles-1].epollFd = -1;
    ctrl->consoles[ctrl->nconsoles-1].epollWatch = -1;
    return 0;
}


static int virLXCControllerConsoleSetNonblocking(virLXCControllerConsole *console)
{
    if (virSetBlocking(console->hostFd, false) < 0 ||
        virSetBlocking(console->contFd, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set console file descriptor non-blocking"));
        return -1;
    }

    return 0;
}


static int virLXCControllerDaemonHandshakeCont(virLXCController *ctrl)
{
    if (lxcContainerSendContinue(ctrl->handshakeFds[1]) < 0) {
        virReportSystemError(errno, "%s",
                             _("error sending continue signal to daemon"));
        return -1;
    }
    return 0;
}

static int virLXCControllerDaemonHandshakeWait(virLXCController *ctrl)
{
    if (lxcContainerWaitForContinue(ctrl->handshakeFds[0]) < 0) {
        virReportSystemError(errno, "%s",
                             _("error waiting for continue signal from daemon"));
        return -1;
    }
    return 0;
}

static int virLXCControllerValidateNICs(virLXCController *ctrl)
{
    if (ctrl->def->nnets != ctrl->nveths) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("expecting %1$zu veths, but got %2$zu"),
                       ctrl->def->nnets, ctrl->nveths);
        return -1;
    }

    return 0;
}


static int virLXCControllerGetNICIndexes(virLXCController *ctrl)
{
    size_t i;

    /* Gather the ifindexes of the "parent" veths for all interfaces
     * implemented with a veth pair. These will be used when calling
     * virCgroupNewMachine (and eventually the dbus method
     * CreateMachineWithNetwork). ifindexes for the child veths, and
     * for macvlan interfaces, *should not* be in this list, as they
     * will be moved into the container. Only the interfaces that will
     * remain outside the container, but are used for communication
     * with the container, should be added to the list.
     */

    VIR_DEBUG("Getting nic indexes");
    for (i = 0; i < ctrl->def->nnets; i++) {
        int nicindex = -1;
        virDomainNetType actualType = virDomainNetGetActualType(ctrl->def->nets[i]);

        switch (actualType) {
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
            if (ctrl->def->nets[i]->ifname == NULL)
                continue;
            if (virNetDevGetIndex(ctrl->def->nets[i]->ifname,
                                  &nicindex) < 0)
                return -1;
            VIR_EXPAND_N(ctrl->nicindexes, ctrl->nnicindexes, 1);
            VIR_DEBUG("Index %d for %s", nicindex,
                      ctrl->def->nets[i]->ifname);
            ctrl->nicindexes[ctrl->nnicindexes-1] = nicindex;
            break;

        case VIR_DOMAIN_NET_TYPE_DIRECT:
           break;

        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_VHOSTUSER:
        case VIR_DOMAIN_NET_TYPE_SERVER:
        case VIR_DOMAIN_NET_TYPE_CLIENT:
        case VIR_DOMAIN_NET_TYPE_MCAST:
        case VIR_DOMAIN_NET_TYPE_UDP:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_HOSTDEV:
        case VIR_DOMAIN_NET_TYPE_VDPA:
        case VIR_DOMAIN_NET_TYPE_NULL:
        case VIR_DOMAIN_NET_TYPE_VDS:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported net type %1$s"),
                           virDomainNetTypeToString(actualType));
            return -1;
        case VIR_DOMAIN_NET_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainNetType, actualType);
            return -1;
        }
    }

    return 0;
}


static int virLXCControllerValidateConsoles(virLXCController *ctrl)
{
    if (ctrl->def->nconsoles != ctrl->nconsoles) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("expecting %1$zu consoles, but got %2$zu tty file handlers"),
                       ctrl->def->nconsoles, ctrl->nconsoles);
        return -1;
    }

    return 0;
}


static int virLXCControllerSetupLoopDeviceFS(virDomainFSDef *fs)
{
    int lofd;
    char *loname = NULL;

    if ((lofd = virFileLoopDeviceAssociate(fs->src->path, &loname)) < 0)
        return -1;

    VIR_DEBUG("Changing fs %s to use type=block for dev %s",
              fs->src->path, loname);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    fs->type = VIR_DOMAIN_FS_TYPE_BLOCK;
    g_free(fs->src->path);
    fs->src->path = g_steal_pointer(&loname);

    return lofd;
}


static int virLXCControllerSetupLoopDeviceDisk(virDomainDiskDef *disk)
{
    int lofd;
    g_autofree char *loname = NULL;
    const char *src = virDomainDiskGetSource(disk);

    if ((lofd = virFileLoopDeviceAssociate(src, &loname)) < 0)
        return -1;

    VIR_DEBUG("Changing disk %s to use type=block for dev %s",
              src, loname);

    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
    virDomainDiskSetSource(disk, loname);

    return lofd;

}


static int virLXCControllerSetupNBDDeviceFS(virDomainFSDef *fs)
{
    char *dev;

    if (fs->format <= VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("An explicit disk format must be specified"));
        return -1;
    }

    if (virFileNBDDeviceAssociate(fs->src->path,
                                  virStorageFileFormatTypeToString(fs->format),
                                  fs->readonly,
                                  &dev) < 0)
        return -1;

    VIR_DEBUG("Changing fs %s to use type=block for dev %s",
              fs->src->path, dev);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    fs->type = VIR_DOMAIN_FS_TYPE_BLOCK;
    g_free(fs->src->path);
    fs->src->path = dev;

    return 0;
}


static int virLXCControllerSetupNBDDeviceDisk(virDomainDiskDef *disk)
{
    g_autofree char *dev = NULL;
    const char *src = virDomainDiskGetSource(disk);
    int format = virDomainDiskGetFormat(disk);

    if (format <= VIR_STORAGE_FILE_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("An explicit disk format must be specified"));
        return -1;
    }

    if (virFileNBDDeviceAssociate(src,
                                  virStorageFileFormatTypeToString(format),
                                  disk->src->readonly,
                                  &dev) < 0)
        return -1;

    VIR_DEBUG("Changing disk %s to use type=block for dev %s",
              src, dev);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    virDomainDiskSetType(disk, VIR_STORAGE_TYPE_BLOCK);
    virDomainDiskSetSource(disk, dev);

    return 0;
}

static int virLXCControllerAppendNBDPids(virLXCController *ctrl,
                                         const char *dev)
{
    g_autofree char *pidpath = NULL;
    g_autofree pid_t *pids = NULL;
    size_t npids = 0;
    size_t i;
    size_t loops = 0;
    pid_t pid;

    if (!STRPREFIX(dev, "/dev/"))
        return -1;

    pidpath = g_strdup_printf("/sys/devices/virtual/block/%s/pid", dev + 5);

    /* Wait for the pid file to appear */
    while (!virFileExists(pidpath)) {
        /* wait for 100ms before checking again, but don't do it for ever */
        if (errno == ENOENT && loops < 10) {
            g_usleep(100 * 1000);
            loops++;
        } else {
            virReportSystemError(errno,
                                 _("Cannot check NBD device %1$s pid"),
                                 dev + 5);
            return -1;
        }
    }

    if (virPidFileReadPath(pidpath, &pid) < 0)
        return -1;

    if (virProcessGetPids(pid, &npids, &pids) < 0)
        return -1;

    for (i = 0; i < npids; i++) {
        VIR_APPEND_ELEMENT(ctrl->nbdpids, ctrl->nnbdpids, pids[i]);
    }

    return 0;
}

static int virLXCControllerSetupLoopDevices(virLXCController *ctrl)
{
    size_t i;

    VIR_DEBUG("Setting up loop devices for filesystems");

    for (i = 0; i < ctrl->def->nfss; i++) {
        virDomainFSDef *fs = ctrl->def->fss[i];
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
                               _("fs format %1$s is not supported"),
                               virStorageFileFormatTypeToString(fs->format));
                return -1;
            }

            fd = virLXCControllerSetupLoopDeviceFS(fs);
            if (fd < 0)
                return -1;

            VIR_DEBUG("Saving loop fd %d", fd);
            VIR_EXPAND_N(ctrl->loopDevFds, ctrl->nloopDevs, 1);
            ctrl->loopDevFds[ctrl->nloopDevs - 1] = fd;
        } else if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_NBD) {
            if (virLXCControllerSetupNBDDeviceFS(fs) < 0)
                return -1;

            /* The NBD device will be cleaned up while the cgroup will end.
             * For this we need to remember the qemu-nbd pid and add it to
             * the cgroup */
            if (virLXCControllerAppendNBDPids(ctrl, fs->src->path) < 0)
                return -1;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("fs driver %1$s is not supported"),
                           virDomainFSDriverTypeToString(fs->fsdriver));
            return -1;
        }
    }

    VIR_DEBUG("Setting up loop devices for disks");

    for (i = 0; i < ctrl->def->ndisks; i++) {
        virDomainDiskDef *disk = ctrl->def->disks[i];
        int fd;
        const char *driver = virDomainDiskGetDriver(disk);
        int format = virDomainDiskGetFormat(disk);

        if (virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_FILE)
            continue;

        /* If no driverName is set, we prefer 'loop' for
         * dealing with raw or undefined formats, otherwise
         * we use 'nbd'.
         */
        if (STREQ_NULLABLE(driver, "loop") ||
            (!driver &&
             (format == VIR_STORAGE_FILE_RAW ||
              format == VIR_STORAGE_FILE_NONE))) {
            if (format != VIR_STORAGE_FILE_RAW &&
                format != VIR_STORAGE_FILE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("disk format %1$s is not supported"),
                               virStorageFileFormatTypeToString(format));
                return -1;
            }

            /* We treat 'none' as meaning 'raw' since we
             * don't want to go into the auto-probing
             * business for security reasons
             */
            fd = virLXCControllerSetupLoopDeviceDisk(disk);
            if (fd < 0)
                return -1;

            VIR_DEBUG("Saving loop fd %d", fd);
            VIR_EXPAND_N(ctrl->loopDevFds, ctrl->nloopDevs, 1);
            ctrl->loopDevFds[ctrl->nloopDevs - 1] = fd;
        } else if (!driver || STREQ(driver, "nbd")) {
            if (disk->cachemode != VIR_DOMAIN_DISK_CACHE_DEFAULT &&
                disk->cachemode != VIR_DOMAIN_DISK_CACHE_DISABLE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Disk cache mode %1$s is not supported"),
                               virDomainDiskCacheTypeToString(disk->cachemode));
                return -1;
            }
            if (virLXCControllerSetupNBDDeviceDisk(disk) < 0)
                return -1;

            /* The NBD device will be cleaned up while the cgroup will end.
             * For this we need to remember the qemu-nbd pid and add it to
             * the cgroup */
            if (virLXCControllerAppendNBDPids(ctrl, virDomainDiskGetSource(disk)) < 0)
                return -1;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk driver %1$s is not supported"),
                           driver);
            return -1;
        }
    }

    VIR_DEBUG("Setup all loop devices");

    return 0;
}


/*
 * To be run while still single threaded
 */
static int virLXCControllerSetupCpuAffinity(virLXCController *ctrl)
{
    int hostcpus, maxcpu = CPU_SETSIZE;
    g_autoptr(virBitmap) cpumap = NULL;
    virBitmap *cpumapToSet;

    VIR_DEBUG("Setting CPU affinity");

    /* setaffinity fails if you set bits for CPUs which
     * aren't present, so we have to limit ourselves */
    if ((hostcpus = virHostCPUGetCount()) < 0)
        return -1;

    if (maxcpu > hostcpus)
        maxcpu = hostcpus;

    cpumap = virBitmapNew(maxcpu);
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
    if (virProcessSetAffinity(0 /* Self */, cpumapToSet, false) < 0)
        return -1;

    return 0;
}


static int virLXCControllerGetNumadAdvice(virLXCController *ctrl,
                                          virBitmap **mask)
{
    virBitmap *nodemask = NULL;
    g_autofree char *nodeset = NULL;

    /* Get the advisory nodeset from numad if 'placement' of
     * either <vcpu> or <numatune> is 'auto'.
     */
    if (virDomainDefNeedsPlacementAdvice(ctrl->def)) {
        nodeset = virNumaGetAutoPlacementAdvice(virDomainDefGetVcpus(ctrl->def),
                                                ctrl->def->mem.cur_balloon);
        if (!nodeset)
            return -1;

        VIR_DEBUG("Nodeset returned from numad: %s", nodeset);

        if (virBitmapParse(nodeset, &nodemask, VIR_DOMAIN_CPUMASK_LEN) < 0)
            return -1;
    }

    *mask = nodemask;

    return 0;
}


/**
 * virLXCControllerSetupResourceLimits
 * @ctrl: the controller state
 *
 * Sets up the non-cgroup based resource limits that need
 * to be inherited by the child process across clone()/exec().
 * The cgroup limits are setup later
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerSetupResourceLimits(virLXCController *ctrl)
{
    g_autoptr(virBitmap) auto_nodeset = NULL;
    virBitmap *nodeset = NULL;
    virDomainNumatuneMemMode mode;

    if (virDomainNumatuneGetMode(ctrl->def->numa, -1, &mode) == 0) {
        if ((mode == VIR_DOMAIN_NUMATUNE_MEM_STRICT ||
             mode == VIR_DOMAIN_NUMATUNE_MEM_RESTRICTIVE) &&
            virCgroupControllerAvailable(VIR_CGROUP_CONTROLLER_CPUSET)) {
            /* Use virNuma* API iff necessary. Once set and child is exec()-ed,
             * there's no way for us to change it. Rely on cgroups (if available
             * and enabled in the config) rather than virNuma*. */
            VIR_DEBUG("Relying on CGroups for memory binding");
        } else {

            VIR_DEBUG("Setting up process resource limits");

            if (virLXCControllerGetNumadAdvice(ctrl, &auto_nodeset) < 0)
                return -1;

            nodeset = virDomainNumatuneGetNodeset(ctrl->def->numa, auto_nodeset, -1);

            if (virNumaSetupMemoryPolicy(mode, nodeset) < 0)
                return -1;
        }
    }

    if (virLXCControllerSetupCpuAffinity(ctrl) < 0)
        return -1;

    return 0;
}


/*
 * Creates the cgroup and sets up the various limits associated
 * with it
 */
static int virLXCControllerSetupCgroupLimits(virLXCController *ctrl)
{
    g_autoptr(virBitmap) auto_nodeset = NULL;
    virBitmap *nodeset = NULL;
    size_t i;

    VIR_DEBUG("Setting up cgroup resource limits");

    if (virLXCControllerGetNumadAdvice(ctrl, &auto_nodeset) < 0)
        return -1;

    nodeset = virDomainNumatuneGetNodeset(ctrl->def->numa, auto_nodeset, -1);

    if (!(ctrl->cgroup = virLXCCgroupCreate(ctrl->def,
                                            ctrl->initpid,
                                            ctrl->nnicindexes,
                                            ctrl->nicindexes)))
        return -1;

    if (virCgroupAddMachineProcess(ctrl->cgroup, getpid()) < 0)
        return -1;

    /* Add all qemu-nbd tasks to the cgroup */
    for (i = 0; i < ctrl->nnbdpids; i++) {
        if (virCgroupAddMachineProcess(ctrl->cgroup, ctrl->nbdpids[i]) < 0)
            return -1;
    }

    if (virLXCCgroupSetup(ctrl->def, ctrl->cgroup, nodeset) < 0)
        return -1;

    return 0;
}


static void virLXCControllerClientCloseHook(virNetServerClient *client)
{
    virLXCController *ctrl = virNetServerClientGetPrivateData(client);

    VIR_DEBUG("Client %p has closed", client);
    if (ctrl->client == client) {
        ctrl->client = NULL;
        VIR_DEBUG("Client has gone away");
    }
    if (ctrl->inShutdown) {
        VIR_DEBUG("Arm timer to quit event loop");
        virEventUpdateTimeout(ctrl->timerShutdown, 0);
    }
}

static void virLXCControllerClientPrivateFree(void *data)
{
    virLXCController *ctrl = data;
    VIR_DEBUG("Got private data free %p", ctrl);
}

static void *virLXCControllerClientPrivateNew(virNetServerClient *client,
                                              void *opaque)
{
    virLXCController *ctrl = opaque;

    virNetServerClientSetCloseHook(client, virLXCControllerClientCloseHook);
    VIR_DEBUG("Got new client %p", client);
    ctrl->client = client;

    if (ctrl->initpid && ctrl->firstClient)
        virLXCControllerEventSendInit(ctrl, ctrl->initpid);
    ctrl->firstClient = false;

    return ctrl;
}


static int virLXCControllerSetupServer(virLXCController *ctrl)
{
    virNetServer *srv = NULL;
    virNetServerService *svc = NULL;
    g_autofree char *sockpath = NULL;

    sockpath = g_strdup_printf("%s/%s.sock", LXC_STATE_DIR, ctrl->name);

    if (!(srv = virNetServerNew("LXC", 1,
                                0, 0, 0, 1,
                                0, -1, 0,
                                virLXCControllerClientPrivateNew,
                                NULL,
                                virLXCControllerClientPrivateFree,
                                ctrl)))
        goto error;

    if (virSecurityManagerSetSocketLabel(ctrl->securityManager, ctrl->def) < 0)
        goto error;

    if (!(svc = virNetServerServiceNewUNIX(sockpath,
                                           0700,
                                           0,
                                           0,
                                           NULL,
                                           false,
                                           0,
                                           5)))
        goto error;

    if (virSecurityManagerClearSocketLabel(ctrl->securityManager, ctrl->def) < 0)
        goto error;

    if (virNetServerAddService(srv, svc) < 0)
        goto error;
    g_clear_pointer(&svc, virObjectUnref);

    if (!(ctrl->prog = virNetServerProgramNew(VIR_LXC_MONITOR_PROGRAM,
                                              VIR_LXC_MONITOR_PROGRAM_VERSION,
                                              virLXCMonitorProcs,
                                              virLXCMonitorNProcs)))
        goto error;

    if (!(ctrl->daemon = virNetDaemonNew()) ||
        virNetDaemonAddServer(ctrl->daemon, srv) < 0)
        goto error;

    virNetDaemonUpdateServices(ctrl->daemon, true);
    return 0;

 error:
    virObjectUnref(srv);
    g_clear_pointer(&ctrl->daemon, virObjectUnref);
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
                       _("failed to apply capabilities: %1$d"), ret);
        return -1;
    }
#else
    VIR_WARN("libcap-ng support not compiled in, unable to clear capabilities");
#endif
    return 0;
}

static bool wantReboot;
static virMutex mutex = VIR_MUTEX_INITIALIZER;

static int
virLXCControllerEventSendExit(virLXCController *ctrl,
                              int exitstatus);

static void virLXCControllerSignalChildIO(virNetDaemon *dmn G_GNUC_UNUSED,
                                          siginfo_t *info G_GNUC_UNUSED,
                                          void *opaque)
{
    virLXCController *ctrl = opaque;
    int ret;
    int status;

    ret = waitpid(-1, &status, WNOHANG);
    VIR_DEBUG("Got sig child %d vs %lld", ret, (long long)ctrl->initpid);
    if (ret == ctrl->initpid) {
        VIR_WITH_MUTEX_LOCK_GUARD(&mutex) {
            if (WIFSIGNALED(status) &&
                WTERMSIG(status) == SIGHUP) {
                VIR_DEBUG("Status indicates reboot");
                wantReboot = true;
            }
        }
        virLXCControllerEventSendExit(ctrl, wantReboot ? 1 : 0);
    }
}


static void virLXCControllerConsoleUpdateWatch(virLXCControllerConsole *console)
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
                virNetDaemonQuit(console->daemon);
                return;
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
            virNetDaemonQuit(console->daemon);
            return;
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
                virNetDaemonQuit(console->daemon);
                return;
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
            virNetDaemonQuit(console->daemon);
            return;
        }
        console->contEpoll = 0;
    }
}


static void virLXCControllerConsoleEPoll(int watch, int fd, int events, void *opaque)
{
    virLXCControllerConsole *console = opaque;
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

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
            virNetDaemonQuit(console->daemon);
            return;
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
}

static void virLXCControllerConsoleIO(int watch, int fd, int events, void *opaque)
{
    virLXCControllerConsole *console = opaque;
    VIR_LOCK_GUARD lock = virLockGuardLock(&mutex);

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
        done = write(fd, buf, *len); /* sc_avoid_write */
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
    return;

 error:
    virEventRemoveHandle(console->contWatch);
    virEventRemoveHandle(console->hostWatch);
    console->contWatch = console->hostWatch = -1;
    virNetDaemonQuit(console->daemon);
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
static int virLXCControllerMain(virLXCController *ctrl)
{
    int rc = -1;
    size_t i;

    if (virNetDaemonAddSignalHandler(ctrl->daemon,
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

    virNetDaemonRun(ctrl->daemon);

    if (virGetLastErrorCode() == VIR_ERR_OK)
        rc = wantReboot ? 1 : 0;

 cleanup:
    for (i = 0; i < ctrl->nconsoles; i++)
        virLXCControllerConsoleClose(&(ctrl->consoles[i]));

    return rc;
}

static unsigned int
virLXCControllerLookupUsernsMap(virDomainIdMapEntry *map,
                                int num,
                                unsigned int src)
{
    size_t i;

    for (i = 0; i < num; i++) {
        if (src > map[i].start && src < map[i].start + map[i].count)
            return map[i].target + (src - map[i].start);
    }

    return src;
}

static int
virLXCControllerSetupUsernsMap(virDomainIdMapEntry *map,
                               int num,
                               char *path)
{
    g_auto(virBuffer) map_value = VIR_BUFFER_INITIALIZER;
    size_t i;

    /* The kernel supports up to 340 lines in /proc/<pid>/{g,u}id_map */
    if (num > 340) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("Too many id mappings defined."));
        return -1;
    }

    VIR_DEBUG("Set '%s' mappings to:", path);

    for (i = 0; i < num; i++) {
        VIR_DEBUG("%u %u %u", map[i].start, map[i].target, map[i].count);
        virBufferAsprintf(&map_value, "%u %u %u\n",
                          map[i].start, map[i].target, map[i].count);
    }

    if (virFileWriteStr(path, virBufferCurrentContent(&map_value), 0) < 0) {
        virReportSystemError(errno, _("unable write to %1$s"), path);
        return -1;
    }

    return 0;
}

/**
 * virLXCControllerSetupUserns
 *
 * Set proc files for user namespace
 *
 * Returns 0 on success or -1 in case of error
 */
static int virLXCControllerSetupUserns(virLXCController *ctrl)
{
    g_autofree char *uid_map = NULL;
    g_autofree char *gid_map = NULL;

    /* User namespace is disabled for container */
    if (ctrl->def->idmap.nuidmap == 0) {
        VIR_DEBUG("No uid map, skipping userns setup");
        return 0;
    }

    VIR_DEBUG("Setting up userns maps");
    uid_map = g_strdup_printf("/proc/%d/uid_map", ctrl->initpid);

    if (virLXCControllerSetupUsernsMap(ctrl->def->idmap.uidmap,
                                       ctrl->def->idmap.nuidmap,
                                       uid_map) < 0)
        return -1;

    gid_map = g_strdup_printf("/proc/%d/gid_map", ctrl->initpid);

    if (virLXCControllerSetupUsernsMap(ctrl->def->idmap.gidmap,
                                       ctrl->def->idmap.ngidmap,
                                       gid_map) < 0)
        return -1;

    return 0;
}

static int virLXCControllerSetupDev(virLXCController *ctrl)
{
    g_autofree char *mount_options = NULL;
    g_autofree char *opts = NULL;
    g_autofree char *dev = NULL;

    VIR_DEBUG("Setting up /dev/ for container");

    mount_options = virSecurityManagerGetMountOptions(ctrl->securityManager,
                                                      ctrl->def);

    dev = g_strdup_printf("/%s/%s.dev", LXC_STATE_DIR, ctrl->def->name);

    /*
     * tmpfs is limited to 64kb, since we only have device nodes in there
     * and don't want to DOS the entire OS RAM usage
     */

    opts = g_strdup_printf("mode=755,size=65536%s", mount_options);

    if (virFileSetupDev(dev, opts) < 0)
        return -1;

    if (lxcContainerChown(ctrl->def, dev) < 0)
        return -1;

    return 0;
}

static int virLXCControllerPopulateDevices(virLXCController *ctrl)
{
    size_t i;
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
        return -1;

    /* Populate /dev/ with a few important bits */
    for (i = 0; i < G_N_ELEMENTS(devs); i++) {
        g_autofree char *path = NULL;
        dev_t dev;

        path = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR, ctrl->def->name,
                               devs[i].path);

        dev = makedev(devs[i].maj, devs[i].min);
        if (mknod(path, S_IFCHR, dev) < 0 ||
            chmod(path, devs[i].mode)) {
            virReportSystemError(errno,
                                 _("Failed to make device %1$s"),
                                 path);
            return -1;
        }

        if (lxcContainerChown(ctrl->def, path) < 0)
            return -1;
    }

    return 0;
}


static int
virLXCControllerSetupTimers(virLXCController *ctrl)
{
    virDomainDef *def = ctrl->def;
    size_t i;

    /* Not sync'ed with Host clock */
    if (def->clock.offset != VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME)
        return 0;

    for (i = 0; i < def->clock.ntimers; i++) {
        virDomainTimerDef *timer = def->clock.timers[i];
        g_autofree char *path = NULL;
        const char *timer_dev = NULL;
        struct stat sb;
        dev_t dev;

        /* Check if "present" is set to "no" otherwise enable it. */
        if (timer->present == VIR_TRISTATE_BOOL_NO)
            continue;

        switch ((virDomainTimerNameType)timer->name) {
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_TSC:
        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
        case VIR_DOMAIN_TIMER_NAME_HYPERVCLOCK:
        case VIR_DOMAIN_TIMER_NAME_PIT:
        case VIR_DOMAIN_TIMER_NAME_ARMVTIMER:
        case VIR_DOMAIN_TIMER_NAME_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%1$s'"),
                           virDomainTimerNameTypeToString(timer->name));
            return -1;
        case VIR_DOMAIN_TIMER_NAME_RTC:
            timer_dev = "/dev/rtc0";
            path = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR,
                                   def->name, "/rtc");
            break;
        case VIR_DOMAIN_TIMER_NAME_HPET:
            timer_dev = "/dev/hpet";
            path = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR,
                                   ctrl->def->name, "/hpet");
            break;
        }

        if (!timer_dev)
            continue;

        if (stat(timer_dev, &sb) < 0) {
            virReportSystemError(errno, _("Unable to access %1$s"),
                                 timer_dev);
            return -1;
        }

        dev = makedev(major(sb.st_rdev), minor(sb.st_rdev));
        if (mknod(path, S_IFCHR, dev) < 0 ||
            chmod(path, sb.st_mode)) {
            virReportSystemError(errno,
                                 _("Failed to make device %1$s"),
                                 path);
            return -1;
        }

        if (lxcContainerChown(def, path) < 0)
            return -1;
    }

    return 0;
}


static int
virLXCControllerSetupHostdevSubsysUSB(virDomainDef *vmDef,
                                      virDomainHostdevDef *def,
                                      virSecurityManager *securityDriver)
{
    g_autofree char *src = NULL;
    g_autofree char *dstdir = NULL;
    g_autofree char *dstfile = NULL;
    g_autofree char *vroot = NULL;
    struct stat sb;
    mode_t mode;
    virDomainHostdevSubsysUSB *usbsrc = &def->source.subsys.u.usb;

    src = g_strdup_printf(USB_DEVFS "/%03d/%03d", usbsrc->bus, usbsrc->device);

    vroot = g_strdup_printf("/%s/%s.dev/bus/usb/", LXC_STATE_DIR, vmDef->name);

    dstdir = g_strdup_printf("%s/%03d/", vroot, usbsrc->bus);

    dstfile = g_strdup_printf("%s/%03d", dstdir, usbsrc->device);

    if (stat(src, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"), src);
        return -1;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("USB source %1$s was not a character device"),
                       src);
        return -1;
    }

    mode = 0700 | S_IFCHR;

    if (g_mkdir_with_parents(dstdir, 0777) < 0) {
        virReportSystemError(errno,
                             _("Unable to create %1$s"), dstdir);
        return -1;
    }

    VIR_DEBUG("Creating dev %s (%d,%d)",
              dstfile, major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dstfile, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %1$s"),
                             dstfile);
        return -1;
    }

    if (lxcContainerChown(vmDef, dstfile) < 0)
        return -1;

    if (virSecurityManagerSetHostdevLabel(securityDriver,
                                          vmDef, def, vroot) < 0)
        return -1;

    return 0;
}


static int
virLXCControllerSetupHostdevCapsStorage(virDomainDef *vmDef,
                                        virDomainHostdevDef *def,
                                        virSecurityManager *securityDriver)
{
    g_autofree char *dst = NULL;
    g_autofree char *path = NULL;
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

    path = g_strdup(dev);

    while (*(path + len) == '/')
        len++;

    dst = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR, vmDef->name,
                          strchr(path + len, '/'));

    if (stat(dev, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"),
                             dev);
        goto cleanup;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Storage source %1$s must be a block device"),
                       dev);
        goto cleanup;
    }

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportError(errno,
                       _("Failed to create directory for device %1$s"),
                       dev);
        goto cleanup;
    }

    mode = 0700 | S_IFBLK;

    VIR_DEBUG("Creating dev %s (%d,%d)", dst,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %1$s"),
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
    return ret;
}


static int
virLXCControllerSetupHostdevCapsMisc(virDomainDef *vmDef,
                                     virDomainHostdevDef *def,
                                     virSecurityManager *securityDriver)
{
    g_autofree char *dst = NULL;
    g_autofree char *path = NULL;
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

    path = g_strdup(dev);

    while (*(path + len) == '/')
        len++;

    dst = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR, vmDef->name,
                          strchr(path + len, '/'));

    if (stat(dev, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"),
                             dev);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Storage source %1$s must be a character device"),
                       dev);
        goto cleanup;
    }

    if (lxcContainerSetupHostdevCapsMakePath(dst) < 0) {
        virReportError(errno,
                       _("Failed to create directory for device %1$s"),
                       dst);
        goto cleanup;
    }

    mode = 0700 | S_IFCHR;

    VIR_DEBUG("Creating dev %s (%d,%d)", dst,
              major(sb.st_rdev), minor(sb.st_rdev));
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %1$s"),
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
    return ret;
}

static int
virLXCControllerSetupHostdevSubsys(virDomainDef *vmDef,
                                   virDomainHostdevDef *def,
                                   virSecurityManager *securityDriver)
{
    switch (def->source.subsys.type) {
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
        return virLXCControllerSetupHostdevSubsysUSB(vmDef,
                                                     def,
                                                     securityDriver);

    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
    case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %1$s"),
                       virDomainHostdevSubsysTypeToString(def->source.subsys.type));
        return -1;
    }
}


static int
virLXCControllerSetupHostdevCaps(virDomainDef *vmDef,
                                 virDomainHostdevDef *def,
                                 virSecurityManager *securityDriver)
{
    switch (def->source.caps.type) {
    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_STORAGE:
        return virLXCControllerSetupHostdevCapsStorage(vmDef,
                                                       def,
                                                       securityDriver);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_MISC:
        return virLXCControllerSetupHostdevCapsMisc(vmDef,
                                                    def,
                                                    securityDriver);

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET:
        return 0; /* case is handled in virLXCControllerMoveInterfaces */

    case VIR_DOMAIN_HOSTDEV_CAPS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported host device mode %1$s"),
                       virDomainHostdevCapsTypeToString(def->source.caps.type));
        return -1;
    }
}


static int
virLXCControllerSetupAllHostdevs(virLXCController *ctrl)
{
    size_t i;
    virDomainDef *vmDef = ctrl->def;
    virSecurityManager *securityDriver = ctrl->securityManager;
    VIR_DEBUG("Setting up hostdevs");

    for (i = 0; i < vmDef->nhostdevs; i++) {
        virDomainHostdevDef *def = vmDef->hostdevs[i];
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
        case VIR_DOMAIN_HOSTDEV_MODE_LAST:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported host device mode %1$s"),
                           virDomainHostdevModeTypeToString(def->mode));
            return -1;
        }
    }

    VIR_DEBUG("Setup all hostdevs");
    return 0;
}


static int virLXCControllerSetupDisk(virLXCController *ctrl,
                                     virDomainDiskDef *def,
                                     virSecurityManager *securityDriver)
{
    g_autofree char *dst = NULL;
    int ret = -1;
    struct stat sb;
    mode_t mode;
    char *tmpsrc = def->src->path;

    if (virDomainDiskGetType(def) != VIR_STORAGE_TYPE_BLOCK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk for non-block device"));
        goto cleanup;
    }
    if (!tmpsrc) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Can't setup disk without media"));
        goto cleanup;
    }

    dst = g_strdup_printf("/%s/%s.dev/%s", LXC_STATE_DIR, ctrl->def->name,
                          def->dst);

    if (stat(def->src->path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access %1$s"), tmpsrc);
        goto cleanup;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Disk source %1$s must be a character/block device"),
                       tmpsrc);
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
              dst, major(sb.st_rdev), minor(sb.st_rdev), tmpsrc);
    if (mknod(dst, mode, sb.st_rdev) < 0) {
        virReportSystemError(errno,
                             _("Unable to create device %1$s"),
                             dst);
        goto cleanup;
    }

    if (lxcContainerChown(ctrl->def, dst) < 0)
        goto cleanup;

    /* Labelling normally operates on src, but we need
     * to actually label the dst here, so hack the config */
    def->src->path = dst;
    if (virSecurityManagerSetImageLabel(securityDriver, ctrl->def, def->src,
                                        VIR_SECURITY_DOMAIN_IMAGE_LABEL_BACKING_CHAIN) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    def->src->path = tmpsrc;
    return ret;
}

static int virLXCControllerSetupAllDisks(virLXCController *ctrl)
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
static int virLXCControllerMoveInterfaces(virLXCController *ctrl)
{
    size_t i;
    virDomainDef *def = ctrl->def;

    for (i = 0; i < ctrl->nveths; i++) {
        if (virNetDevSetNamespace(ctrl->veths[i], ctrl->initpid) < 0)
            return -1;
    }

    for (i = 0; i < def->nhostdevs; i ++) {
        virDomainHostdevDef *hdev = def->hostdevs[i];
        virDomainHostdevCaps hdcaps;

        if (hdev->mode != VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES)
            continue;

        hdcaps = hdev->source.caps;

        if (hdcaps.type != VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET)
            continue;

        if (virNetDevSetNamespace(hdcaps.u.net.ifname, ctrl->initpid) < 0)
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
static int virLXCControllerDeleteInterfaces(virLXCController *ctrl)
{
    size_t i;
    int ret = 0;

    for (i = 0; i < ctrl->nveths; i++) {
        if (virNetDevVethDelete(ctrl->veths[i]) < 0)
            ret = -1;
    }

    return ret;
}


static int lxcSetPersonality(virDomainDef *def)
{
    virArch altArch;

    VIR_DEBUG("Checking for 32-bit personality");
    altArch = lxcContainerGetAlt32bitArch(virArchFromHost());
    if (altArch &&
        (def->os.arch == altArch)) {
        VIR_DEBUG("Setting personality to %s",
                  virArchToString(altArch));
        if (personality(PER_LINUX32) < 0) {
            virReportSystemError(errno, _("Unable to request personality for %1$s on %2$s"),
                                 virArchToString(altArch),
                                 virArchToString(virArchFromHost()));
            return -1;
        }
    }
    return 0;
}

/* Create a private tty using the private devpts at PTMX, returning
 * the primary in @ttyprimary and the name of the secondary, _from the
 * perspective of the guest after remounting file systems_, in
 * @ttyName.  Heavily borrowed from glibc, but doesn't require that
 * devpts == "/dev/pts" */
static int
lxcCreateTty(virLXCController *ctrl, int *ttyprimary,
             char **ttyName, char **ttyHostPath)
{
    int ret = -1;
    int ptyno;
    int unlock = 0;

    if ((*ttyprimary = open(ctrl->devptmx, O_RDWR|O_NOCTTY|O_NONBLOCK)) < 0)
        goto cleanup;

    if (ioctl(*ttyprimary, TIOCSPTLCK, &unlock) < 0)
        goto cleanup;

    if (ioctl(*ttyprimary, TIOCGPTN, &ptyno) < 0)
        goto cleanup;

    /* If mount() succeeded at honoring newinstance, then the kernel
     * was new enough to also honor the mode=0620,gid=5 options, which
     * guarantee that the new pty already has correct permissions; so
     * while glibc has to fstat(), fchmod(), and fchown() for older
     * kernels, we can skip those steps.  ptyno shouldn't currently be
     * anything other than 0, but let's play it safe.  */
    *ttyName = g_strdup_printf("/dev/pts/%d", ptyno);
    *ttyHostPath = g_strdup_printf("/%s/%s.devpts/%d", LXC_STATE_DIR, ctrl->def->name, ptyno);

    ret = 0;

 cleanup:
    if (ret != 0) {
        VIR_FORCE_CLOSE(*ttyprimary);
        g_clear_pointer(ttyName, g_free);
    }

    return ret;
}


static int
virLXCControllerSetupPrivateNS(void)
{
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
     * visible to the host OS. We also disable mount
     * propagation out of the root FS, in case it was
     * currently allowing bi-directional propagation.
     */

    return virProcessSetupPrivateMountNS();
}


static int
virLXCControllerSetupDevPTS(virLXCController *ctrl)
{
    g_autofree char *mount_options = NULL;
    g_autofree char *opts = NULL;
    g_autofree char *devpts = NULL;
    gid_t ptsgid = 5;

    VIR_DEBUG("Setting up private /dev/pts");

    mount_options = virSecurityManagerGetMountOptions(ctrl->securityManager,
                                                      ctrl->def);

    devpts = g_strdup_printf("%s/%s.devpts", LXC_STATE_DIR, ctrl->def->name);
    ctrl->devptmx = g_strdup_printf("%s/%s.devpts/ptmx", LXC_STATE_DIR, ctrl->def->name);

    if (g_mkdir_with_parents(devpts, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to make path %1$s"),
                             devpts);
        return -1;
    }

    if (ctrl->def->idmap.ngidmap)
        ptsgid = virLXCControllerLookupUsernsMap(ctrl->def->idmap.gidmap,
                                                 ctrl->def->idmap.ngidmap,
                                                 ptsgid);

    /* XXX should we support gid=X for X!=5 for distros which use
     * a different gid for tty?  */
    opts = g_strdup_printf("newinstance,ptmxmode=0666,mode=0620,gid=%u%s", ptsgid,
                           NULLSTR_EMPTY(mount_options));

    VIR_DEBUG("Mount devpts on %s type=tmpfs flags=0x%x, opts=%s",
              devpts, MS_NOSUID, opts);
    if (mount("devpts", devpts, "devpts", MS_NOSUID, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount devpts on %1$s"),
                             devpts);
        return -1;
    }

    if (access(ctrl->devptmx, R_OK) < 0) {
        virReportSystemError(ENOSYS, "%s",
                             _("Kernel does not support private devpts"));
        return -1;
    }

    if ((lxcContainerChown(ctrl->def, ctrl->devptmx) < 0) ||
        (lxcContainerChown(ctrl->def, devpts) < 0))
        return -1;

    return 0;
}


static int
virLXCControllerSetupFuse(virLXCController *ctrl)
{
    return lxcSetupFuse(&ctrl->fuse, ctrl->def);
}

static int
virLXCControllerStartFuse(virLXCController *ctrl)
{
    return lxcStartFuse(ctrl->fuse);
}

static int
virLXCControllerSetupConsoles(virLXCController *ctrl,
                              char **containerTTYPaths)
{
    size_t i;

    for (i = 0; i < ctrl->nconsoles; i++) {
        g_autofree char *ttyHostPath = NULL;

        VIR_DEBUG("Opening tty on private %s", ctrl->devptmx);
        if (lxcCreateTty(ctrl,
                         &ctrl->consoles[i].contFd,
                         &containerTTYPaths[i], &ttyHostPath) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Failed to allocate tty"));
            return -1;
        }

        /* Change the owner of tty device to the root user of container */
        if (lxcContainerChown(ctrl->def, ttyHostPath) < 0)
            return -1;
    }

    return 0;
}


static void
virLXCControllerEventSend(virLXCController *ctrl,
                          int procnr,
                          xdrproc_t proc,
                          void *data)
{
    virNetMessage *msg;

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
    if (virNetServerClientSendMessage(ctrl->client, msg) < 0)
        goto error;

    xdr_free(proc, data);
    return;

 error:
    virNetMessageFree(msg);
    xdr_free(proc, data);
}


static int
virLXCControllerEventSendExit(virLXCController *ctrl,
                              int exitstatus)
{
    virLXCMonitorExitEventMsg msg = { 0 };

    VIR_DEBUG("Exit status %d (client=%p)", exitstatus, ctrl->client);
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
    } else {
        VIR_DEBUG("Arm timer to quit event loop");
        virEventUpdateTimeout(ctrl->timerShutdown, 0);
    }
    return 0;
}


static int
virLXCControllerEventSendInit(virLXCController *ctrl,
                              pid_t initpid)
{
    virLXCMonitorInitEventMsg msg = { 0 };

    VIR_DEBUG("Init pid %lld", (long long)initpid);
    msg.initpid = initpid;

    virLXCControllerEventSend(ctrl,
                              VIR_LXC_MONITOR_PROC_INIT_EVENT,
                              (xdrproc_t)xdr_virLXCMonitorInitEventMsg,
                              (void*)&msg);
    return 0;
}


static int
virLXCControllerRun(virLXCController *ctrl)
{
    int rc = -1;
    int control[2] = { -1, -1};
    int containerhandshake[2] = { -1, -1 };
    char **containerTTYPaths = g_new0(char *, ctrl->nconsoles);
    size_t i;

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

    if (virLXCControllerSetupTimers(ctrl) < 0)
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
                                           ctrl->nsFDs,
                                           ctrl->nconsoles,
                                           containerTTYPaths)) < 0)
        goto cleanup;
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0; i < ctrl->npassFDs; i++)
        VIR_FORCE_CLOSE(ctrl->passFDs[i]);

    if (ctrl->nsFDs)
        for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
            VIR_FORCE_CLOSE(ctrl->nsFDs[i]);

    if (virLXCControllerSetupCgroupLimits(ctrl) < 0)
        goto cleanup;

    /* Allow daemon to detect CGroups. */
    if (virLXCControllerDaemonHandshakeCont(ctrl) < 0 ||
        virLXCControllerDaemonHandshakeWait(ctrl) < 0)
        goto cleanup;

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

    for (i = 0; i < ctrl->nconsoles; i++)
        if (virLXCControllerConsoleSetNonblocking(&(ctrl->consoles[i])) < 0)
            goto cleanup;

    /* Allow daemon to connect to the monitor. */
    if (virLXCControllerDaemonHandshakeCont(ctrl) < 0)
        goto cleanup;

    /* and preemptively close handshakeFds */
    for (i = 0; i < G_N_ELEMENTS(ctrl->handshakeFds); i++)
        VIR_FORCE_CLOSE(ctrl->handshakeFds[i]);

    /* We must not hold open a dbus connection for life
     * of LXC instance, since dbus-daemon is limited to
     * only a few 100 connections by default
     */
    virGDBusCloseSystemBus();

    rc = virLXCControllerMain(ctrl);

 cleanup:
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[0]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0; i < ctrl->nconsoles; i++)
        g_free(containerTTYPaths[i]);
    g_free(containerTTYPaths);

    virLXCControllerStopInit(ctrl);

    return rc;
}


static int
parseFDPair(const char *arg,
            int (*fd)[2])
{
    g_auto(GStrv) fds = NULL;

    fds = g_strsplit(arg, ":", 0);

    if (fds[0] == NULL || fds[1] == NULL || fds[2] != NULL ||
        virStrToLong_i(fds[0], NULL, 10, &(*fd)[0]) < 0 ||
        virStrToLong_i(fds[1], NULL, 10, &(*fd)[1]) < 0) {
        fprintf(stderr, "malformed --handshakefds argument '%s'",
                optarg);
        return -1;
    }

    return 0;
}


int main(int argc, char *argv[])
{
    pid_t pid;
    int rc = -1;
    const char *name = NULL;
    size_t nveths = 0;
    char **veths = NULL;
    int ns_fd[VIR_LXC_DOMAIN_NAMESPACE_LAST];
    int handshakeFds[2] = { -1, -1 };
    bool bg = false;
    const struct option options[] = {
        { "background", 0, NULL, 'b' },
        { "name",   1, NULL, 'n' },
        { "veth",   1, NULL, 'v' },
        { "console", 1, NULL, 'c' },
        { "passfd", 1, NULL, 'p' },
        { "handshakefds", 1, NULL, 's' },
        { "security", 1, NULL, 'S' },
        { "share-net", 1, NULL, 'N' },
        { "share-ipc", 1, NULL, 'I' },
        { "share-uts", 1, NULL, 'U' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    g_autofree int *ttyFDs = NULL;
    size_t nttyFDs = 0;
    g_autofree int *passFDs = NULL;
    size_t npassFDs = 0;
    virLXCController *ctrl = NULL;
    size_t i;
    const char *securityDriver = "none";

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++)
        ns_fd[i] = -1;

    if (virGettextInitialize() < 0 ||
        virErrorInitialize() < 0) {
        fprintf(stderr, _("%1$s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

    /* Initialize logging */
    if (virLogSetFromEnv() < 0)
        exit(EXIT_FAILURE);

    while (1) {
        int c;

        c = getopt_long(argc, argv, "dn:v:p:m:c:s:h:S:N:I:U:",
                        options, NULL);

        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bg = true;
            break;

        case 'n':
            name = optarg;
            break;

        case 'v':
            veths = g_renew(char *, veths, nveths+1);
            veths[nveths++] = g_strdup(optarg);
            break;

        case 'c':
            ttyFDs = g_renew(int, ttyFDs, nttyFDs + 1);
            if (virStrToLong_i(optarg, NULL, 10, &ttyFDs[nttyFDs++]) < 0) {
                fprintf(stderr, "malformed --console argument '%s'", optarg);
                goto cleanup;
            }
            break;

        case 'p':
            passFDs = g_renew(int, passFDs, npassFDs + 1);
            if (virStrToLong_i(optarg, NULL, 10, &passFDs[npassFDs++]) < 0) {
                fprintf(stderr, "malformed --passfd argument '%s'", optarg);
                goto cleanup;
            }
            break;

        case 's':
            if (parseFDPair(optarg, &handshakeFds) < 0)
                goto cleanup;
            break;

        case 'N':
            if (virStrToLong_i(optarg, NULL, 10, &ns_fd[VIR_LXC_DOMAIN_NAMESPACE_SHARENET]) < 0) {
                fprintf(stderr, "malformed --share-net argument '%s'",
                        optarg);
                goto cleanup;
            }
            break;

        case 'I':
            if (virStrToLong_i(optarg, NULL, 10, &ns_fd[VIR_LXC_DOMAIN_NAMESPACE_SHAREIPC]) < 0) {
                fprintf(stderr, "malformed --share-ipc argument '%s'",
                        optarg);
                goto cleanup;
            }
            break;

        case 'U':
            if (virStrToLong_i(optarg, NULL, 10, &ns_fd[VIR_LXC_DOMAIN_NAMESPACE_SHAREUTS]) < 0) {
                fprintf(stderr, "malformed --share-uts argument '%s'",
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
            fprintf(stderr, "  -s FD:FD, --handshakefds FD:FD (read:write)\n");
            fprintf(stderr, "  -S NAME, --security NAME\n");
            fprintf(stderr, "  -N FD, --share-net FD\n");
            fprintf(stderr, "  -I FD, --share-ipc FD\n");
            fprintf(stderr, "  -U FD, --share-uts FD\n");
            fprintf(stderr, "  -h, --help\n");
            fprintf(stderr, "\n");
            rc = 0;
            goto cleanup;
        }
    }

    if (name == NULL) {
        fprintf(stderr, "%s: missing --name argument for configuration\n", argv[0]);
        goto cleanup;
    }

    if (handshakeFds[0] < 0 || handshakeFds[1] < 0) {
        fprintf(stderr, "%s: missing --handshakefds argument for container PTY\n",
                argv[0]);
        goto cleanup;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    virEventRegisterDefaultImpl();

    virGDBusSetSharedBus(false);

    if (!(ctrl = virLXCControllerNew(name)))
        goto cleanup;

    memcpy(&ctrl->handshakeFds, &handshakeFds, sizeof(handshakeFds));

    if (!(ctrl->securityManager = virSecurityManagerNew(securityDriver,
                                                        LXC_DRIVER_NAME, 0)))
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

    for (i = 0; i < VIR_LXC_DOMAIN_NAMESPACE_LAST; i++) {
        if (ns_fd[i] != -1) {
            if (!ctrl->nsFDs) {/*allocate only once */
                size_t j = 0;
                ctrl->nsFDs = g_new0(int, VIR_LXC_DOMAIN_NAMESPACE_LAST);
                for (j = 0; j < VIR_LXC_DOMAIN_NAMESPACE_LAST; j++)
                    ctrl->nsFDs[j] = -1;
            }
            ctrl->nsFDs[i] = ns_fd[i];
        }
    }

    for (i = 0; i < nttyFDs; i++) {
        if (virLXCControllerAddConsole(ctrl, ttyFDs[i]) < 0)
            goto cleanup;
        ttyFDs[i] = -1;
    }

    if (virLXCControllerValidateNICs(ctrl) < 0)
        goto cleanup;

    if (virLXCControllerGetNICIndexes(ctrl) < 0)
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
                                     _("Unable to write pid file '%1$s/%2$s.pid'"),
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
        fprintf(stderr,
                _("Failure in libvirt_lxc startup: %1$s\n"),
                virGetLastErrorMessage());
    }

    virPidFileDelete(LXC_STATE_DIR, name);
    if (ctrl)
        virLXCControllerDeleteInterfaces(ctrl);
    for (i = 0; i < nttyFDs; i++)
        VIR_FORCE_CLOSE(ttyFDs[i]);
    for (i = 0; i < npassFDs; i++)
        VIR_FORCE_CLOSE(passFDs[i]);

    virLXCControllerFree(ctrl);

    return rc < 0? EXIT_FAILURE : EXIT_SUCCESS;
}
