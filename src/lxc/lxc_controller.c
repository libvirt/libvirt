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
#include <linux/loop.h>
#include <dirent.h>
#include <grp.h>
#include <sys/stat.h>

#if HAVE_CAPNG
# include <cap-ng.h>
#endif

#if HAVE_NUMACTL
# define NUMA_VERSION1_COMPATIBILITY 1
# include <numa.h>
#endif
#if HAVE_SELINUX
# include <selinux/selinux.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "util.h"

#include "lxc_conf.h"
#include "lxc_container.h"
#include "virnetdev.h"
#include "virnetdevveth.h"
#include "memory.h"
#include "util.h"
#include "virfile.h"
#include "virpidfile.h"
#include "command.h"
#include "processinfo.h"
#include "nodeinfo.h"

#define VIR_FROM_THIS VIR_FROM_LXC

struct cgroup_device_policy {
    char type;
    int major;
    int minor;
};


static int lxcGetLoopFD(char **dev_name)
{
    int fd = -1;
    DIR *dh = NULL;
    struct dirent *de;
    char *looppath;
    struct loop_info64 lo;

    VIR_DEBUG("Looking for loop devices in /dev");

    if (!(dh = opendir("/dev"))) {
        virReportSystemError(errno, "%s",
                             _("Unable to read /dev"));
        goto cleanup;
    }

    while ((de = readdir(dh)) != NULL) {
        if (!STRPREFIX(de->d_name, "loop"))
            continue;

        if (virAsprintf(&looppath, "/dev/%s", de->d_name) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        VIR_DEBUG("Checking up on device %s", looppath);
        if ((fd = open(looppath, O_RDWR)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to open %s"), looppath);
            goto cleanup;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &lo) < 0) {
            /* Got a free device, return the fd */
            if (errno == ENXIO)
                goto cleanup;

            VIR_FORCE_CLOSE(fd);
            virReportSystemError(errno,
                                 _("Unable to get loop status on %s"),
                                 looppath);
            goto cleanup;
        }

        /* Oh well, try the next device */
        VIR_FORCE_CLOSE(fd);
        VIR_FREE(looppath);
    }

    lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
             _("Unable to find a free loop device in /dev"));

cleanup:
    if (fd != -1) {
        VIR_DEBUG("Got free loop device %s %d", looppath, fd);
        *dev_name = looppath;
    } else {
        VIR_DEBUG("No free loop devices available");
        VIR_FREE(looppath);
    }
    if (dh)
        closedir(dh);
    return fd;
}

static int lxcSetupLoopDevice(virDomainFSDefPtr fs)
{
    int lofd = -1;
    int fsfd = -1;
    struct loop_info64 lo;
    char *loname = NULL;
    int ret = -1;

    if ((lofd = lxcGetLoopFD(&loname)) < 0)
        return -1;

    memset(&lo, 0, sizeof(lo));
    lo.lo_flags = LO_FLAGS_AUTOCLEAR;

    if ((fsfd = open(fs->src, O_RDWR)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open %s"), fs->src);
        goto cleanup;
    }

    if (ioctl(lofd, LOOP_SET_FD, fsfd) < 0) {
        virReportSystemError(errno,
                             _("Unable to attach %s to loop device"),
                             fs->src);
        goto cleanup;
    }

    if (ioctl(lofd, LOOP_SET_STATUS64, &lo) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to mark loop device as autoclear"));

        if (ioctl(lofd, LOOP_CLR_FD, 0) < 0)
            VIR_WARN("Unable to detach %s from loop device", fs->src);
        goto cleanup;
    }

    VIR_DEBUG("Attached loop device  %s %d to %s", fs->src, lofd, loname);
    /*
     * We now change it into a block device type, so that
     * the rest of container setup 'just works'
     */
    fs->type = VIR_DOMAIN_FS_TYPE_BLOCK;
    VIR_FREE(fs->src);
    fs->src = loname;
    loname = NULL;

    ret = 0;

cleanup:
    VIR_FREE(loname);
    VIR_FORCE_CLOSE(fsfd);
    if (ret == -1)
        VIR_FORCE_CLOSE(lofd);
    return lofd;
}


static int lxcSetupLoopDevices(virDomainDefPtr def, size_t *nloopDevs, int **loopDevs)
{
    size_t i;
    int ret = -1;

    for (i = 0 ; i < def->nfss ; i++) {
        int fd;

        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_FILE)
            continue;

        fd = lxcSetupLoopDevice(def->fss[i]);
        if (fd < 0)
            goto cleanup;

        VIR_DEBUG("Saving loop fd %d", fd);
        if (VIR_REALLOC_N(*loopDevs, *nloopDevs+1) < 0) {
            VIR_FORCE_CLOSE(fd);
            virReportOOMError();
            goto cleanup;
        }
        (*loopDevs)[(*nloopDevs)++] = fd;
    }

    VIR_DEBUG("Setup all loop devices");
    ret = 0;

cleanup:
    return ret;
}

#if HAVE_NUMACTL
static int lxcSetContainerNUMAPolicy(virDomainDefPtr def)
{
    nodemask_t mask;
    int mode = -1;
    int node = -1;
    int ret = -1;
    int i = 0;
    int maxnode = 0;
    bool warned = false;

    if (!def->numatune.memory.nodemask)
        return 0;

    VIR_DEBUG("Setting NUMA memory policy");

    if (numa_available() < 0) {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
                 "%s", _("Host kernel is not aware of NUMA."));
        return -1;
    }

    maxnode = numa_max_node() + 1;

    /* Convert nodemask to NUMA bitmask. */
    nodemask_zero(&mask);
    for (i = 0; i < VIR_DOMAIN_CPUMASK_LEN; i++) {
        if (def->numatune.memory.nodemask[i]) {
            if (i > NUMA_NUM_NODES) {
                lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
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

    mode = def->numatune.memory.mode;

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
            lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
                     "%s", _("NUMA memory tuning in 'preferred' mode "
                             "only supports single node"));
            goto cleanup;
        }

        numa_set_bind_policy(0);
        numa_set_preferred(node);
    } else if (mode == VIR_DOMAIN_NUMATUNE_MEM_INTERLEAVE) {
        numa_set_interleave_mask(&mask);
    } else {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
                 _("Unable to set NUMA policy %s"),
                 virDomainNumatuneMemModeTypeToString(mode));
        goto cleanup;
    }

    ret = 0;

cleanup:
    return ret;
}
#else
static int lxcSetContainerNUMAPolicy(virDomainDefPtr def)
{
    if (def->numatune.memory.nodemask) {
        lxcError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                 _("NUMA policy is not available on this platform"));
        return -1;
    }

    return 0;
}
#endif


/*
 * To be run while still single threaded
 */
static int lxcSetContainerCpuAffinity(virDomainDefPtr def)
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

    if (def->cpumask) {
        /* XXX why don't we keep 'cpumask' in the libvirt cpumap
         * format to start with ?!?! */
        for (i = 0 ; i < maxcpu && i < def->cpumasklen ; i++)
            if (def->cpumask[i])
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


static int lxcSetContainerCpuTune(virCgroupPtr cgroup, virDomainDefPtr def)
{
    int ret = -1;
    if (def->cputune.shares != 0) {
        int rc = virCgroupSetCpuShares(cgroup, def->cputune.shares);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu shares for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    if (def->cputune.quota != 0) {
        int rc = virCgroupSetCpuCfsQuota(cgroup, def->cputune.quota);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu quota for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    if (def->cputune.period != 0) {
        int rc = virCgroupSetCpuCfsPeriod(cgroup, def->cputune.period);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set io cpu period for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }
    ret = 0;
cleanup:
    return ret;
}


static int lxcSetContainerBlkioTune(virCgroupPtr cgroup, virDomainDefPtr def)
{
    int ret = -1;

    if (def->blkio.weight) {
        int rc = virCgroupSetBlkioWeight(cgroup, def->blkio.weight);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to set Blkio weight for domain %s"),
                                 def->name);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    return ret;
}


static int lxcSetContainerMemTune(virCgroupPtr cgroup, virDomainDefPtr def)
{
    int ret = -1;
    int rc;

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

    ret = 0;
cleanup:
    return ret;
}


static int lxcSetContainerDeviceACL(virCgroupPtr cgroup, virDomainDefPtr def)
{
    int ret = -1;
    int rc;
    size_t i;
    static const struct cgroup_device_policy devices[] = {
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM},
        {'c', LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_TTY},
        {'c', LXC_DEV_MAJ_TTY, LXC_DEV_MIN_PTMX},
        {0,   0, 0}};

    rc = virCgroupDenyAllDevices(cgroup);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to deny devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    for (i = 0; devices[i].type != 0; i++) {
        const struct cgroup_device_policy *dev = &devices[i];
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

    for (i = 0 ; i < def->nfss ; i++) {
        if (def->fss[i]->type != VIR_DOMAIN_FS_TYPE_BLOCK)
            continue;

        rc = virCgroupAllowDevicePath(cgroup,
                                      def->fss[i]->src,
                                      def->fss[i]->readonly ?
                                      VIR_CGROUP_DEVICE_READ :
                                      VIR_CGROUP_DEVICE_RW);
        if (rc != 0) {
            virReportSystemError(-rc,
                                 _("Unable to allow device %s for domain %s"),
                                 def->fss[i]->src, def->name);
            goto cleanup;
        }
    }

    rc = virCgroupAllowDeviceMajor(cgroup, 'c', LXC_DEV_MAJ_PTY,
                                   VIR_CGROUP_DEVICE_RWM);
    if (rc != 0) {
        virReportSystemError(-rc,
                             _("Unable to allow PTY devices for domain %s"),
                             def->name);
        goto cleanup;
    }

    ret = 0;
cleanup:
    return ret;
}


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

    if (lxcSetContainerCpuAffinity(def) < 0)
        return -1;

    if (lxcSetContainerNUMAPolicy(def) < 0)
        return -1;

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

    if (lxcSetContainerCpuTune(cgroup, def) < 0)
        goto cleanup;

    if (lxcSetContainerBlkioTune(cgroup, def) < 0)
        goto cleanup;

    if (lxcSetContainerMemTune(cgroup, def) < 0)
        goto cleanup;

    if (lxcSetContainerDeviceACL(cgroup, def) < 0)
        goto cleanup;

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

/* Return true if it is ok to ignore an accept-after-epoll syscall
   that fails with the specified errno value.  Else false.  */
static bool
ignorable_accept_errno(int errnum)
{
  return (errnum == EINVAL
          || errnum == ECONNABORTED
          || errnum == EAGAIN
          || errnum == EWOULDBLOCK);
}

static bool quit = false;
static virMutex lock;
static int sigpipe[2];

static void lxcSignalChildHandler(int signum ATTRIBUTE_UNUSED)
{
    ignore_value(write(sigpipe[1], "1", 1));
}

static void lxcSignalChildIO(int watch ATTRIBUTE_UNUSED,
                             int fd ATTRIBUTE_UNUSED,
                             int events ATTRIBUTE_UNUSED, void *opaque)
{
    char buf[1];
    int ret;
    int *container = opaque;

    ignore_value(read(sigpipe[0], buf, 1));
    ret = waitpid(-1, NULL, WNOHANG);
    if (ret == *container) {
        virMutexLock(&lock);
        quit = true;
        virMutexUnlock(&lock);
    }
}


struct lxcConsole {

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

struct lxcMonitor {
    int serverWatch;
    int serverFd;  /* Server listen socket */
    int clientWatch;
    int clientFd;  /* Current client FD (if any) */
};


static void lxcClientIO(int watch ATTRIBUTE_UNUSED, int fd, int events, void *opaque)
{
    struct lxcMonitor *monitor = opaque;
    char buf[1024];
    ssize_t ret;

    if (events & (VIR_EVENT_HANDLE_HANGUP |
                  VIR_EVENT_HANDLE_ERROR)) {
        virEventRemoveHandle(monitor->clientWatch);
        monitor->clientWatch = -1;
        return;
    }

reread:
    ret = read(fd, buf, sizeof(buf));
    if (ret == -1 && errno == EINTR)
        goto reread;
    if (ret == -1 && errno == EAGAIN)
        return;
    if (ret == -1) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to read from monitor client"));
        virMutexLock(&lock);
        quit = true;
        virMutexUnlock(&lock);
        return;
    }
    if (ret == 0) {
        VIR_DEBUG("Client %d gone", fd);
        VIR_FORCE_CLOSE(monitor->clientFd);
        virEventRemoveHandle(monitor->clientWatch);
        monitor->clientWatch = -1;
    }
}


static void lxcServerAccept(int watch ATTRIBUTE_UNUSED, int fd, int events ATTRIBUTE_UNUSED, void *opaque)
{
    struct lxcMonitor *monitor = opaque;
    int client;

    if ((client = accept(fd, NULL, NULL)) < 0) {
        /* First reflex may be simply to declare accept failure
           to be a fatal error.  However, accept may fail when
           a client quits between the above poll and here.
           That case is not fatal, but rather to be expected,
           if not common, so ignore it.  */
        if (ignorable_accept_errno(errno))
            return;
        virReportSystemError(errno, "%s",
                             _("Unable to accept monitor client"));
        virMutexLock(&lock);
        quit = true;
        virMutexUnlock(&lock);
        return;
    }
    VIR_DEBUG("New client %d (old %d)\n", client, monitor->clientFd);
    VIR_FORCE_CLOSE(monitor->clientFd);
    virEventRemoveHandle(monitor->clientWatch);

    monitor->clientFd = client;
    if ((monitor->clientWatch = virEventAddHandle(monitor->clientFd,
                                                  VIR_EVENT_HANDLE_READABLE,
                                                  lxcClientIO,
                                                  monitor,
                                                  NULL)) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to watch client socket"));
        virMutexLock(&lock);
        quit = true;
        virMutexUnlock(&lock);
        return;
    }
}

static void lxcConsoleUpdateWatch(struct lxcConsole *console)
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


static void lxcEpollIO(int watch, int fd, int events, void *opaque)
{
    struct lxcConsole *console = opaque;

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
            if (ret == EINTR)
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
            lxcConsoleUpdateWatch(console);
            break;
        }
    }

cleanup:
    virMutexUnlock(&lock);
}

static void lxcConsoleIO(int watch, int fd, int events, void *opaque)
{
    struct lxcConsole *console = opaque;

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

    lxcConsoleUpdateWatch(console);
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
 * @hostFd: open fd for application facing Pty
 * @contFd: open fd for container facing Pty
 *
 * Processes I/O on consoles and the monitor
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcControllerMain(int serverFd,
                             int clientFd,
                             int *hostFds,
                             int *contFds,
                             size_t nFds,
                             pid_t container)
{
    struct lxcConsole *consoles;
    struct lxcMonitor monitor = {
        .serverFd = serverFd,
        .clientFd = clientFd,
    };
    virErrorPtr err;
    int rc = -1;
    size_t i;

    if (virMutexInit(&lock) < 0)
        goto cleanup2;

    if (pipe2(sigpipe, O_CLOEXEC|O_NONBLOCK) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot create signal pipe"));
        goto cleanup;
    }

    if (virEventAddHandle(sigpipe[0],
                          VIR_EVENT_HANDLE_READABLE,
                          lxcSignalChildIO,
                          &container,
                          NULL) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to watch signal pipe"));
        goto cleanup;
    }

    if (signal(SIGCHLD, lxcSignalChildHandler) == SIG_ERR) {
        virReportSystemError(errno, "%s",
                             _("Cannot install signal handler"));
        goto cleanup;
    }

    VIR_DEBUG("serverFd=%d clientFd=%d",
              serverFd, clientFd);
    virResetLastError();

    if ((monitor.serverWatch = virEventAddHandle(monitor.serverFd,
                                                 VIR_EVENT_HANDLE_READABLE,
                                                 lxcServerAccept,
                                                 &monitor,
                                                 NULL)) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to watch monitor socket"));
        goto cleanup;
    }

    if (monitor.clientFd != -1 &&
        (monitor.clientWatch = virEventAddHandle(monitor.clientFd,
                                                 VIR_EVENT_HANDLE_READABLE,
                                                 lxcClientIO,
                                                 &monitor,
                                                 NULL)) < 0) {
        lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                 _("Unable to watch client socket"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(consoles, nFds) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0 ; i < nFds ; i++) {
        consoles[i].epollFd = -1;
        consoles[i].epollWatch = -1;
        consoles[i].hostWatch = -1;
        consoles[i].contWatch = -1;
    }

    for (i = 0 ; i < nFds ; i++) {
        consoles[i].hostFd = hostFds[i];
        consoles[i].contFd = contFds[i];

        if ((consoles[i].epollFd = epoll_create1(EPOLL_CLOEXEC)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create epoll fd"));
            goto cleanup;
        }

        if ((consoles[i].epollWatch = virEventAddHandle(consoles[i].epollFd,
                                                        VIR_EVENT_HANDLE_READABLE,
                                                        lxcEpollIO,
                                                        &consoles[i],
                                                        NULL)) < 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Unable to watch epoll FD"));
            goto cleanup;
        }

        if ((consoles[i].hostWatch = virEventAddHandle(consoles[i].hostFd,
                                                       VIR_EVENT_HANDLE_READABLE,
                                                       lxcConsoleIO,
                                                       &consoles[i],
                                                       NULL)) < 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
                     _("Unable to watch host console PTY"));
            goto cleanup;
        }

        if ((consoles[i].contWatch = virEventAddHandle(consoles[i].contFd,
                                                       VIR_EVENT_HANDLE_READABLE,
                                                       lxcConsoleIO,
                                                       &consoles[i],
                                                       NULL)) < 0) {
            lxcError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        rc = 0;

cleanup:
    virMutexDestroy(&lock);
    signal(SIGCHLD, SIG_DFL);
cleanup2:
    VIR_FORCE_CLOSE(monitor.serverFd);
    VIR_FORCE_CLOSE(monitor.clientFd);

    for (i = 0 ; i < nFds ; i++) {
        if (consoles[i].epollWatch != -1)
            virEventRemoveHandle(consoles[i].epollWatch);
        VIR_FORCE_CLOSE(consoles[i].epollFd);
        if (consoles[i].contWatch != -1)
            virEventRemoveHandle(consoles[i].contWatch);
        if (consoles[i].hostWatch != -1)
            virEventRemoveHandle(consoles[i].hostWatch);
    }

    VIR_FREE(consoles);
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
        if (virNetDevSetNamespace(veths[i], container) < 0)
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
        ignore_value(virNetDevVethDelete(veths[i]));

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
lxcControllerRun(virDomainDefPtr def,
                 virSecurityManagerPtr securityDriver,
                 unsigned int nveths,
                 char **veths,
                 int monitor,
                 int client,
                 int *ttyFDs,
                 size_t nttyFDs,
                 int handshakefd)
{
    int rc = -1;
    int control[2] = { -1, -1};
    int containerhandshake[2] = { -1, -1 };
    int *containerTtyFDs = NULL;
    char **containerTtyPaths = NULL;
    pid_t container = -1;
    virDomainFSDefPtr root;
    char *devpts = NULL;
    char *devptmx = NULL;
    size_t nloopDevs = 0;
    int *loopDevs = NULL;
    size_t i;

    if (VIR_ALLOC_N(containerTtyFDs, nttyFDs) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    if (VIR_ALLOC_N(containerTtyPaths, nttyFDs) < 0) {
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

    if (lxcSetupLoopDevices(def, &nloopDevs, &loopDevs) < 0)
        goto cleanup;

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
#if HAVE_SELINUX
        security_context_t con;
#else
        bool con = false;
#endif
        char *opts;
        VIR_DEBUG("Setting up private /dev/pts");

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
            virAsprintf(&devptmx, "%s/dev/pts/ptmx", root->src) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virFileMakePath(devpts) < 0) {
            virReportSystemError(errno,
                                 _("Failed to make path %s"),
                                 devpts);
            goto cleanup;
        }

#if HAVE_SELINUX
        if (getfilecon(root->src, &con) < 0 &&
            errno != ENOTSUP) {
            virReportSystemError(errno,
                                 _("Failed to query file context on %s"),
                                 root->src);
            goto cleanup;
        }
#endif
        /* XXX should we support gid=X for X!=5 for distros which use
         * a different gid for tty?  */
        if (virAsprintf(&opts, "newinstance,ptmxmode=0666,mode=0620,gid=5%s%s%s",
                        con ? ",context=\"" : "",
                        con ? (const char *)con : "",
                        con ? "\"" : "") < 0) {
            virReportOOMError();
            goto cleanup;
        }

        VIR_DEBUG("Mount devpts on %s type=tmpfs flags=%x, opts=%s",
                  devpts, MS_NOSUID, opts);
        if (mount("devpts", devpts, "devpts", MS_NOSUID, opts) < 0) {
            VIR_FREE(opts);
            virReportSystemError(errno,
                                 _("Failed to mount devpts on %s"),
                                 devpts);
            goto cleanup;
        }
        VIR_FREE(opts);

        if (access(devptmx, R_OK) < 0) {
            VIR_WARN("Kernel does not support private devpts, using shared devpts");
            VIR_FREE(devptmx);
        }
    } else {
        if (nttyFDs != 1) {
            lxcError(VIR_ERR_CONFIG_UNSUPPORTED,
                     _("Expected exactly one TTY fd, but got %zu"), nttyFDs);
            goto cleanup;
        }
    }

    for (i = 0 ; i < nttyFDs ; i++) {
        if (devptmx) {
            VIR_DEBUG("Opening tty on private %s", devptmx);
            if (lxcCreateTty(devptmx,
                             &containerTtyFDs[i],
                             &containerTtyPaths[i]) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Failed to allocate tty"));
                goto cleanup;
            }
        } else {
            VIR_DEBUG("Opening tty on shared /dev/ptmx");
            if (virFileOpenTty(&containerTtyFDs[i],
                               &containerTtyPaths[i],
                               0) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Failed to allocate tty"));
                goto cleanup;
            }
        }
    }

    if (lxcSetPersonality(def) < 0)
        goto cleanup;

    if ((container = lxcContainerStart(def,
                                       securityDriver,
                                       nveths,
                                       veths,
                                       control[1],
                                       containerhandshake[1],
                                       containerTtyPaths,
                                       nttyFDs)) < 0)
        goto cleanup;
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    if (lxcControllerMoveInterfaces(nveths, veths, container) < 0)
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

    for (i = 0 ; i < nloopDevs ; i++)
        VIR_FORCE_CLOSE(loopDevs[i]);

    /* ...and reduce our privileges */
    if (lxcControllerClearCapabilities() < 0)
        goto cleanup;

    if (lxcContainerSendContinue(handshakefd) < 0) {
        virReportSystemError(errno, "%s",
                             _("error sending continue signal to parent"));
        goto cleanup;
    }
    VIR_FORCE_CLOSE(handshakefd);

    if (virSetBlocking(monitor, false) < 0 ||
        virSetBlocking(client, false) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set file descriptor non-blocking"));
        goto cleanup;
    }
    for (i = 0 ; i < nttyFDs ; i++) {
        if (virSetBlocking(ttyFDs[i], false) < 0 ||
            virSetBlocking(containerTtyFDs[i], false) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to set file descriptor non-blocking"));
            goto cleanup;
        }
    }

    rc = lxcControllerMain(monitor, client, ttyFDs, containerTtyFDs, nttyFDs, container);
    monitor = client = -1;

cleanup:
    VIR_FREE(devptmx);
    VIR_FREE(devpts);
    VIR_FORCE_CLOSE(control[0]);
    VIR_FORCE_CLOSE(control[1]);
    VIR_FORCE_CLOSE(handshakefd);
    VIR_FORCE_CLOSE(containerhandshake[0]);
    VIR_FORCE_CLOSE(containerhandshake[1]);

    for (i = 0 ; i < nttyFDs ; i++)
        VIR_FREE(containerTtyPaths[i]);
    VIR_FREE(containerTtyPaths);
    for (i = 0 ; i < nttyFDs ; i++)
        VIR_FORCE_CLOSE(containerTtyFDs[i]);
    VIR_FREE(containerTtyFDs);

    for (i = 0 ; i < nloopDevs ; i++)
        VIR_FORCE_CLOSE(loopDevs[i]);
    VIR_FREE(loopDevs);

    virPidAbort(container);

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
    int handshakefd = -1;
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
        { "handshakefd", 1, NULL, 's' },
        { "security", 1, NULL, 'S' },
        { "help", 0, NULL, 'h' },
        { 0, 0, 0, 0 },
    };
    int *ttyFDs = NULL;
    size_t nttyFDs = 0;
    virSecurityManagerPtr securityDriver = NULL;

    if (setlocale(LC_ALL, "") == NULL ||
        bindtextdomain(PACKAGE, LOCALEDIR) == NULL ||
        textdomain(PACKAGE) == NULL) {
        fprintf(stderr, _("%s: initialization failed\n"), argv[0]);
        exit(EXIT_FAILURE);
    }

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
            if (virStrToLong_i(optarg, NULL, 10, &handshakefd) < 0) {
                fprintf(stderr, "malformed --handshakefd argument '%s'",
                        optarg);
                goto cleanup;
            }
            break;

        case 'S':
            if (!(securityDriver = virSecurityManagerNew(optarg, false, false, false))) {
                fprintf(stderr, "Cannot create security manager '%s'",
                        optarg);
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
            fprintf(stderr, "  -s FD, --handshakefd FD\n");
            fprintf(stderr, "  -S NAME, --security NAME\n");
            fprintf(stderr, "  -h, --help\n");
            fprintf(stderr, "\n");
            goto cleanup;
        }
    }

    if (securityDriver == NULL) {
        if (!(securityDriver = virSecurityManagerNew("none", false, false, false))) {
            fprintf(stderr, "%s: cannot initialize nop security manager", argv[0]);
            goto cleanup;
        }
    }


    if (name == NULL) {
        fprintf(stderr, "%s: missing --name argument for configuration\n", argv[0]);
        goto cleanup;
    }

    if (handshakefd < 0) {
        fprintf(stderr, "%s: missing --handshake argument for container PTY\n",
                argv[0]);
        goto cleanup;
    }

    if (getuid() != 0) {
        fprintf(stderr, "%s: must be run as the 'root' user\n", argv[0]);
        goto cleanup;
    }

    virEventRegisterDefaultImpl();

    if ((caps = lxcCapsInit(NULL)) == NULL)
        goto cleanup;

    if ((configFile = virDomainConfigFile(LXC_STATE_DIR,
                                          name)) == NULL)
        goto cleanup;

    if ((def = virDomainDefParseFile(caps, configFile,
                                     1 << VIR_DOMAIN_VIRT_LXC,
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

    /* Initialize logging */
    virLogSetFromEnv();

    /* Accept initial client which is the libvirtd daemon */
    if ((client = accept(monitor, NULL, 0)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to accept a connection from driver"));
        goto cleanup;
    }

    rc = lxcControllerRun(def, securityDriver,
                          nveths, veths, monitor, client,
                          ttyFDs, nttyFDs, handshakefd);

cleanup:
    if (def)
        virPidFileDelete(LXC_STATE_DIR, def->name);
    lxcControllerCleanupInterfaces(nveths, veths);
    if (sockpath)
        unlink(sockpath);
    VIR_FREE(sockpath);

    return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
