/*
 * Copyright (C) 2008-2016 Red Hat, Inc.
 * Copyright (C) 2008 IBM Corp.
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
 *
 * lxc_container.c: Performs container setup tasks
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

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
/* Yes, we want linux private one, for _syscall2() macro */
#include <linux/unistd.h>

#if WITH_CAPNG
# include <cap-ng.h>
#endif

#if WITH_BLKID
# include <blkid.h>
#endif

#if WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "virerror.h"
#include "virlog.h"
#include "lxc_container.h"
#include "viralloc.h"
#include "viruuid.h"
#include "virfile.h"
#include "vircommand.h"
#include "virnetdevip.h"
#include "virprocess.h"
#include "virstring.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_LXC

VIR_LOG_INIT("lxc.lxc_container");


/* messages between parent and container */
typedef char lxc_message_t;
#define LXC_CONTINUE_MSG 'c'

typedef struct __lxc_child_argv lxc_child_argv_t;
struct __lxc_child_argv {
    virDomainDef *config;
    virSecurityManager *securityDriver;
    size_t nveths;
    char **veths;
    int monitor;
    size_t npassFDs;
    int *passFDs;
    size_t nttyPaths;
    char **ttyPaths;
    int handshakefd;
    int *nsInheritFDs;
};

static int lxcContainerMountFSBlock(virDomainFSDef *fs,
                                    const char *srcprefix,
                                    const char *sec_mount_options);


/*
 * reboot(LINUX_REBOOT_CMD_CAD_ON) will return -EINVAL
 * in a child pid namespace if container reboot support exists.
 * Otherwise, it will either succeed or return -EPERM.
 */
G_GNUC_NORETURN static int
lxcContainerRebootChild(void *argv)
{
    int *cmd = argv;
    int ret;

    ret = reboot(*cmd);
    if (ret == -1 && errno == EINVAL)
        _exit(1);
    _exit(0);
}


static
int lxcContainerHasReboot(void)
{
    int flags = CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|
        CLONE_NEWIPC|SIGCHLD;
    int cpid;
    char *childStack;
    g_autofree char *stack = NULL;
    g_autofree char *buf = NULL;
    int cmd, v;
    int status;
    char *tmp;
    int stacksize = getpagesize() * 4;

    if (virFileReadAll("/proc/sys/kernel/ctrl-alt-del", 10, &buf) < 0)
        return -1;

    if ((tmp = strchr(buf, '\n')))
        *tmp = '\0';

    if (virStrToLong_i(buf, NULL, 10, &v) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Malformed ctrl-alt-del setting '%1$s'"), buf);
        return -1;
    }
    cmd = v ? LINUX_REBOOT_CMD_CAD_ON : LINUX_REBOOT_CMD_CAD_OFF;

    stack = g_new0(char, stacksize);

    childStack = stack + stacksize;

    cpid = clone(lxcContainerRebootChild, childStack, flags, &cmd);
    if (cpid < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to clone to check reboot support"));
        return -1;
    } else if (virProcessWait(cpid, &status, false) < 0) {
        return -1;
    }

    if (status != 1) {
        VIR_DEBUG("Containerized reboot support is missing "
                  "(kernel probably too old < 3.4)");
        return 0;
    }

    VIR_DEBUG("Containerized reboot support is available");
    return 1;
}


/**
 * lxcContainerBuildInitCmd:
 * @vmDef: pointer to vm definition structure
 *
 * Build a virCommand *for launching the container 'init' process
 *
 * Returns a virCommand *
 */
static virCommand *lxcContainerBuildInitCmd(virDomainDef *vmDef,
                                              char **ttyPaths,
                                              size_t nttyPaths)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virCommand *cmd;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    size_t i;

    /* 'container_ptys' must exclude the PTY associated with
     * the /dev/console device, hence start at 1 not 0
     */
    for (i = 1; i < nttyPaths; i++) {
        if (!STRPREFIX(ttyPaths[i], "/dev/")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Expected a /dev path for '%1$s'"),
                           ttyPaths[i]);
            return NULL;
        }
        virBufferAdd(&buf, ttyPaths[i] + 5, -1);
        virBufferAddChar(&buf, ' ');
    }
    virBufferTrimLen(&buf, 1);

    virUUIDFormat(vmDef->uuid, uuidstr);

    cmd = virCommandNew(vmDef->os.init);

    if (vmDef->os.initargv && vmDef->os.initargv[0])
        virCommandAddArgSet(cmd, (const char **)vmDef->os.initargv);

    virCommandAddEnvString(cmd, "PATH=/bin:/sbin");
    virCommandAddEnvString(cmd, "TERM=linux");
    virCommandAddEnvString(cmd, "container=lxc-libvirt");
    virCommandAddEnvString(cmd, "HOME=/");
    virCommandAddEnvPair(cmd, "container_uuid", uuidstr);
    if (nttyPaths > 1)
        virCommandAddEnvPair(cmd, "container_ttys", virBufferCurrentContent(&buf));
    virCommandAddEnvPair(cmd, "LIBVIRT_LXC_UUID", uuidstr);
    virCommandAddEnvPair(cmd, "LIBVIRT_LXC_NAME", vmDef->name);
    if (vmDef->os.cmdline)
        virCommandAddEnvPair(cmd, "LIBVIRT_LXC_CMDLINE", vmDef->os.cmdline);
    if (vmDef->os.initdir)
        virCommandSetWorkingDirectory(cmd, vmDef->os.initdir);

    for (i = 0; vmDef->os.initenv[i]; i++) {
        virCommandAddEnvPair(cmd, vmDef->os.initenv[i]->name,
                                  vmDef->os.initenv[i]->value);
    }

    return cmd;
}

/**
 * lxcContainerSetupFDs:
 * @control: control FD from parent
 * @ttyfd: FD of tty to set as the container console
 * @npassFDs: number of extra FDs
 * @passFDs: list of extra FDs
 *
 * Setup file descriptors in the container. @ttyfd is set to be
 * the container's stdin, stdout & stderr. Any FDs included in
 * @passFDs, will be dup()'d such that they start from stderr+1
 * with no gaps.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcContainerSetupFDs(int *ttyfd,
                                size_t npassFDs, int *passFDs)
{
    int rc = -1;
    int open_max;
    int fd;
    int last_fd;
    size_t i;
    size_t j;

    VIR_DEBUG("Logging from the container init will now cease "
              "as the FDs are about to be closed for exec of "
              "the container init process");

    if (dup2(*ttyfd, STDIN_FILENO) < 0) {
        virReportSystemError(errno, "%s",
                             _("dup2(stdin) failed"));
        goto cleanup;
    }

    if (dup2(*ttyfd, STDOUT_FILENO) < 0) {
        virReportSystemError(errno, "%s",
                             _("dup2(stdout) failed"));
        goto cleanup;
    }

    if (dup2(*ttyfd, STDERR_FILENO) < 0) {
        virReportSystemError(errno, "%s",
                             _("dup2(stderr) failed"));
        goto cleanup;
    }

    VIR_FORCE_CLOSE(*ttyfd);

    /* Any FDs in @passFDs need to be moved around so that
     * they are numbered, without gaps, starting from
     * STDERR_FILENO + 1
     */
    for (i = 0; i < npassFDs; i++) {
        int wantfd;

        wantfd = STDERR_FILENO + i + 1;
        VIR_DEBUG("Pass %d onto %d", passFDs[i], wantfd);

        /* If we already have desired FD number, life
         * is easy. Nothing needs renumbering */
        if (passFDs[i] == wantfd)
            continue;

        /*
         * Lets check to see if any later FDs are occupying
         * our desired FD number. If so, we must move them
         * out of the way
         */
        for (j = i + 1; j < npassFDs; j++) {
            if (passFDs[j] == wantfd) {
                int newfd = dup(passFDs[j]);

                VIR_DEBUG("Clash %zu", j);

                if (newfd < 0) {
                    virReportSystemError(errno,
                                         _("Cannot move fd %1$d out of the way"),
                                         passFDs[j]);
                    goto cleanup;
                }
                /* We're intentionally not closing the
                 * old value of passFDs[j], because we
                 * don't want later iterations of the
                 * loop to take it back. dup2() will
                 * cause it to be closed shortly anyway
                 */
                VIR_DEBUG("Moved clash onto %d", newfd);
                passFDs[j] = newfd;
            }
        }

        /* Finally we can move into our desired FD number */
        if (dup2(passFDs[i], wantfd) < 0) {
            virReportSystemError(errno,
                                 _("Cannot duplicate fd %1$d onto fd %2$d"),
                                 passFDs[i], wantfd);
            goto cleanup;
        }
        VIR_FORCE_CLOSE(passFDs[i]);
    }

    last_fd = STDERR_FILENO + npassFDs;

    /* Just in case someone forget to set FD_CLOEXEC, explicitly
     * close all remaining FDs before executing the container */
    open_max = sysconf(_SC_OPEN_MAX);
    if (open_max < 0) {
        virReportSystemError(errno, "%s",
                             _("sysconf(_SC_OPEN_MAX) failed"));
        goto cleanup;
    }

    for (fd = last_fd + 1; fd < open_max; fd++) {
        int tmpfd = fd;
        VIR_MASS_CLOSE(tmpfd);
    }

    rc = 0;

 cleanup:
    VIR_DEBUG("rc=%d", rc);
    return rc;
}

/**
 * lxcContainerSendContinue:
 * @control: control FD to child
 *
 * Sends the continue message via the socket pair stored in the vm
 * structure.
 *
 * Returns 0 on success or -1 in case of error
 */
int lxcContainerSendContinue(int control)
{
    lxc_message_t msg = LXC_CONTINUE_MSG;
    int writeCount = 0;

    VIR_DEBUG("Send continue on fd %d", control);
    writeCount = safewrite(control, &msg, sizeof(msg));
    if (writeCount != sizeof(msg))
        return -1;

    return 0;
}

/**
 * lxcContainerWaitForContinue:
 * @control: Control FD from parent
 *
 * This function will wait for the container continue message from the
 * parent process.  It will send this message on the socket pair stored in
 * the vm structure once it has completed the post clone container setup.
 *
 * Returns 0 on success or -1 in case of error
 */
int lxcContainerWaitForContinue(int control)
{
    lxc_message_t msg;
    int readLen;

    VIR_DEBUG("Wait continue on fd %d", control);
    readLen = saferead(control, &msg, sizeof(msg));
    VIR_DEBUG("Got continue on fd %d %d", control, readLen);
    if (readLen != sizeof(msg)) {
        if (readLen >= 0)
            errno = EIO;
        return -1;
    }
    if (msg != LXC_CONTINUE_MSG) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}


/**
 * lxcContainerSetID:
 *
 * This function calls setuid and setgid to create proper
 * cred for tasks running in container.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcContainerSetID(virDomainDef *def)
{
    /* Only call virSetUIDGID when user namespace is enabled
     * for this container. And user namespace is only enabled
     * when nuidmap&ngidmap is not zero */

    if (!def->idmap.nuidmap)
        return 0;

    VIR_DEBUG("Setting UID/GID to 0/0");
    if (virSetUIDGID(0, 0, NULL, 0) < 0) {
        virReportSystemError(errno, "%s",
                             _("setuid or setgid failed"));
        return -1;
    }

    return 0;
}


static virDomainNetDef *
lxcContainerGetNetDef(virDomainDef *vmDef, const char *devName)
{
    size_t i;
    virDomainNetDef *netDef;

    for (i = 0; i < vmDef->nnets; i++) {
        netDef = vmDef->nets[i];
        if (STREQ_NULLABLE(netDef->ifname_guest_actual, devName))
            return netDef;
    }

    return NULL;
}

/**
 * lxcContainerRenameAndEnableInterfaces:
 * @nveths: number of interfaces
 * @veths: interface names
 *
 * This function will rename the interfaces to ethN
 * with id ascending order from zero and enable the
 * renamed interfaces for this container.
 *
 * Returns 0 on success or nonzero in case of error
 */
static int
lxcContainerRenameAndEnableInterfaces(virDomainDef *vmDef,
                                      size_t nveths,
                                      char **veths)
{
    size_t i;
    const char *newname;
    virDomainNetDef *netDef;
    bool privNet = vmDef->features[VIR_DOMAIN_FEATURE_PRIVNET] ==
                   VIR_TRISTATE_SWITCH_ON;

    for (i = 0; i < nveths; i++) {
        if (!(netDef = lxcContainerGetNetDef(vmDef, veths[i])))
            return -1;

        newname = netDef->ifname_guest;
        if (!newname) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing device name for container-side veth"));
            return -1;
        }

        VIR_DEBUG("Renaming %s to %s", veths[i], newname);
        if (virNetDevSetName(veths[i], newname) < 0)
            return -1;

        /* Only enable this device if there is a reason to do so (either
         * at least one IP was specified, or link state was set to up in
         * the config)
         */
        if (netDef->guestIP.nips ||
            netDef->linkstate == VIR_DOMAIN_NET_INTERFACE_LINK_STATE_UP) {
            VIR_DEBUG("Enabling %s", newname);
            if (virNetDevSetOnline(newname, true) < 0)
                return -1;
        }

        /* set IP addresses and routes */
        if (virNetDevIPInfoAddToDev(newname, &netDef->guestIP) < 0)
            return -1;
    }

    /* enable lo device only if there were other net devices */
    if ((veths || privNet) &&
        virNetDevSetOnline("lo", true) < 0)
        return -1;

    return 0;
}


/*_syscall2(int, pivot_root, char *, newroot, const char *, oldroot)*/
extern int pivot_root(const char * new_root, const char * put_old);

static int lxcContainerUnmountSubtree(const char *prefix,
                                      bool isOldRootFS)
{
    g_auto(GStrv) mounts = NULL;
    size_t nmounts = 0;
    size_t i;
    int saveErrno;
    const char *failedUmount = NULL;

    VIR_DEBUG("Unmount subtree from %s", prefix);

    if (virFileGetMountReverseSubtree("/proc/mounts", prefix,
                                      &mounts, &nmounts) < 0)
        return -1;
    for (i = 0; i < nmounts; i++) {
        VIR_DEBUG("Umount %s", mounts[i]);
        if (umount(mounts[i]) < 0) {
            failedUmount = mounts[i];
            saveErrno = errno;
            VIR_WARN("Failed to unmount '%s', trying to detach subtree '%s': %s",
                     failedUmount, mounts[nmounts-1],
                     g_strerror(errno));
            break;
        }
    }

    if (failedUmount) {
        /* This detaches the subtree */
        if (umount2(mounts[nmounts-1], MNT_DETACH) < 0) {
            virReportSystemError(saveErrno,
                                 _("Failed to unmount '%1$s' and could not detach subtree '%2$s'"),
                                 failedUmount, mounts[nmounts-1]);
            return -1;
        }
        /* This unmounts the tmpfs on which the old root filesystem was hosted */
        if (isOldRootFS &&
            umount(mounts[nmounts-1]) < 0) {
            virReportSystemError(saveErrno,
                                 _("Failed to unmount '%1$s' and could not unmount old root '%2$s'"),
                                 failedUmount, mounts[nmounts-1]);
            return -1;
        }
    }

    return 0;
}

static int lxcContainerResolveSymlinks(virDomainFSDef *fs, bool gentle)
{
    char *newroot;

    if (!fs->src || !fs->src->path || fs->symlinksResolved)
        return 0;

    if (access(fs->src->path, F_OK)) {
        if (gentle) {
            /* Just ignore the error for the while, we'll try again later */
            VIR_DEBUG("Skipped unaccessible '%s'", fs->src->path);
            return 0;
        } else {
            virReportSystemError(errno,
                                 _("Failed to access '%1$s'"), fs->src->path);
            return -1;
        }
    }

    VIR_DEBUG("Resolving '%s'", fs->src->path);
    if (virFileResolveAllLinks(fs->src->path, &newroot) < 0) {
        if (gentle) {
            VIR_DEBUG("Skipped non-resolvable '%s'", fs->src->path);
            return 0;
        } else {
            virReportSystemError(errno,
                                 _("Failed to resolve symlink at %1$s"),
                                 fs->src->path);
        }
        return -1;
    }

    /* Mark it resolved to skip it the next time */
    fs->symlinksResolved = true;

    VIR_DEBUG("Resolved '%s' to %s", fs->src->path, newroot);

    g_free(fs->src->path);
    fs->src->path = newroot;

    return 0;
}

static int lxcContainerPrepareRoot(virDomainDef *def,
                                   virDomainFSDef *root,
                                   const char *sec_mount_options)
{
    g_autofree char *dst = NULL;
    char *tmp;

    VIR_DEBUG("Prepare root %d", root->type);

    if (root->type == VIR_DOMAIN_FS_TYPE_MOUNT)
        return 0;

    if (root->type == VIR_DOMAIN_FS_TYPE_FILE) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unexpected root filesystem without loop device"));
        return -1;
    }

    if (root->type != VIR_DOMAIN_FS_TYPE_BLOCK) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported root filesystem type %1$s"),
                       virDomainFSTypeToString(root->type));
        return -1;
    }

    if (lxcContainerResolveSymlinks(root, false) < 0)
        return -1;

    dst = g_strdup_printf("%s/%s.root", LXC_STATE_DIR, def->name);

    tmp = root->dst;
    root->dst = dst;

    if (lxcContainerMountFSBlock(root, "", sec_mount_options) < 0) {
        root->dst = tmp;
        return -1;
    }

    root->dst = tmp;
    root->type = VIR_DOMAIN_FS_TYPE_MOUNT;
    g_free(root->src->path);
    root->src->path = g_steal_pointer(&dst);

    return 0;
}

static int lxcContainerPivotRoot(virDomainFSDef *root)
{
    g_autofree char *oldroot = NULL;
    g_autofree char *newroot = NULL;

    VIR_DEBUG("Pivot via %s", root->src->path);

    /* root->parent must be private, so make / private. */
    if (mount("", "/", "none", MS_PRIVATE|MS_REC, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to make root private"));
        return -1;
    }

    oldroot = g_strdup_printf("%s/.oldroot", root->src->path);

    if (g_mkdir_with_parents(oldroot, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to create %1$s"),
                             oldroot);
        return -1;
    }

    /* Create a tmpfs root since old and new roots must be
     * on separate filesystems */
    if (mount("tmprootfs", oldroot, "tmpfs", 0, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount empty tmpfs at %1$s"),
                             oldroot);
        return -1;
    }

    /* Create a directory called 'new' in tmpfs */
    newroot = g_strdup_printf("%s/new", oldroot);

    if (g_mkdir_with_parents(newroot, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to create %1$s"),
                             newroot);
        return -1;
    }

    /* ... and mount our root onto it */
    if (mount(root->src->path, newroot, "none", MS_BIND|MS_REC, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to bind %1$s to new root %2$s"),
                             root->src->path, newroot);
        return -1;
    }

    if (root->readonly) {
        if (mount(root->src->path, newroot, "none", MS_BIND|MS_REC|MS_RDONLY|MS_REMOUNT, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to make new root %1$s readonly"),
                                 root->src->path);
            return -1;
        }
    }

    /* Now we chdir into the tmpfs, then pivot into the
     * root->src bind-mounted onto '/new' */
    if (chdir(newroot) < 0) {
        virReportSystemError(errno,
                             _("Failed to chdir into %1$s"), newroot);
        return -1;
    }

    /* The old root directory will live at /.oldroot after
     * this and will soon be unmounted completely */
    if (pivot_root(".", ".oldroot") < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to pivot root"));
        return -1;
    }

    /* CWD is undefined after pivot_root, so go to / */
    if (chdir("/") < 0)
        return -1;

    return 0;
}


typedef struct {
    const char *src;
    const char *dst;
    const char *type;
    int mflags;
    bool skipUserNS;
    bool skipUnmounted;
    bool skipNoNetns;
} virLXCBasicMountInfo;

static const virLXCBasicMountInfo lxcBasicMounts[] = {
    { "proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, false, false, false },
    { "/proc/sys", "/proc/sys", "none", MS_BIND|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, false, false, false },
    { "/.oldroot/proc/sys/net/ipv4", "/proc/sys/net/ipv4", "none", MS_BIND, false, false, true },
    { "/.oldroot/proc/sys/net/ipv6", "/proc/sys/net/ipv6", "none", MS_BIND, false, false, true },
    { "sysfs", "/sys", "sysfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, false, false, false },
    { "securityfs", "/sys/kernel/security", "securityfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, true, true, false },
#if WITH_SELINUX
    { SELINUX_MOUNT, SELINUX_MOUNT, "selinuxfs", MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, true, true, false },
#endif
};


bool lxcIsBasicMountLocation(const char *path)
{
    size_t i;

    for (i = 0; i < G_N_ELEMENTS(lxcBasicMounts); i++) {
        if (STREQ(path, lxcBasicMounts[i].dst))
            return true;
    }

    return false;
}


static int lxcContainerSetReadOnly(void)
{
    FILE *procmnt;
    struct mntent mntent;
    char mntbuf[1024];
    g_auto(GStrv) mounts = NULL;
    size_t nmounts = 0;
    size_t i;

    if (!(procmnt = setmntent("/proc/mounts", "r"))) {
        virReportSystemError(errno, "%s",
                             _("Failed to read /proc/mounts"));
        return -1;
    }

    while (getmntent_r(procmnt, &mntent, mntbuf, sizeof(mntbuf)) != NULL) {
        char *tmp;
        if (STREQ(mntent.mnt_dir, "/") ||
            STREQ(mntent.mnt_dir, "/.oldroot") ||
            STRPREFIX(mntent.mnt_dir, "/.oldroot/") ||
            lxcIsBasicMountLocation(mntent.mnt_dir))
            continue;

        tmp = g_strdup(mntent.mnt_dir);

        VIR_APPEND_ELEMENT(mounts, nmounts, tmp);
    }

    endmntent(procmnt);

    if (!mounts)
        return 0;

    qsort(mounts, nmounts, sizeof(mounts[0]), virStringSortRevCompare);

    /* turn 'mounts' into a proper GStrv */
    VIR_EXPAND_N(mounts, nmounts, 1);
    nmounts--;

    for (i = 0; i < nmounts; i++) {
        VIR_DEBUG("Bind readonly %s", mounts[i]);
        if (mount(mounts[i], mounts[i], "none", MS_BIND|MS_REC|MS_RDONLY|MS_REMOUNT, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to make mount %1$s readonly"),
                                 mounts[i]);
            return -1;
        }
    }

    return 0;
}


static int lxcContainerMountBasicFS(bool userns_enabled,
                                    bool netns_disabled)
{
    size_t i;
    int mnt_mflags;

    VIR_DEBUG("Mounting basic filesystems");

    for (i = 0; i < G_N_ELEMENTS(lxcBasicMounts); i++) {
        g_autofree char *mnt_src = NULL;
        bool bindOverReadonly;
        virLXCBasicMountInfo const *mnt = &lxcBasicMounts[i];

        /* When enable userns but disable netns, kernel will
         * forbid us doing a new fresh mount for sysfs.
         * So we had to do a bind mount for sysfs instead.
         */
        if (userns_enabled && netns_disabled &&
            STREQ(mnt->src, "sysfs")) {
            mnt_src = g_strdup("/sys");
            mnt_mflags = MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY|MS_BIND;
        } else {
            mnt_src = g_strdup(mnt->src);
            mnt_mflags = mnt->mflags;
        }

        VIR_DEBUG("Processing %s -> %s",
                  mnt_src, mnt->dst);

        if (mnt->skipUnmounted) {
            int ret;
            g_autofree char *hostdir = g_strdup_printf("/.oldroot%s",
                                                       mnt->dst);

            ret = virFileIsMountPoint(hostdir);
            if (ret < 0)
                return -1;

            if (ret == 0) {
                VIR_DEBUG("Skipping '%s' which isn't mounted in host",
                          mnt->dst);
                continue;
            }
        }

        if (mnt->skipUserNS && userns_enabled) {
            VIR_DEBUG("Skipping due to user ns enablement");
            continue;
        }

        /* Skip mounts with missing source without shouting: it may be a
         * missing folder in /proc due to the absence of a kernel feature */
        if (STRPREFIX(mnt_src, "/") && !virFileExists(mnt_src)) {
            VIR_DEBUG("Skipping due to missing source: %s", mnt_src);
            continue;
        }

        if (mnt->skipNoNetns && netns_disabled) {
            VIR_DEBUG("Skipping due to absence of network namespace");
            continue;
        }

        if (g_mkdir_with_parents(mnt->dst, 0777) < 0) {
            virReportSystemError(errno,
                                 _("Failed to mkdir %1$s"),
                                 mnt->dst);
            return -1;
        }

        /*
         * We can't immediately set the MS_RDONLY flag when mounting filesystems
         * because (in at least some kernel versions) this will propagate back
         * to the original mount in the host OS, turning it readonly too. Thus
         * we mount the filesystem in read-write mode initially, and then do a
         * separate read-only bind mount on top of that.
         */
        bindOverReadonly = !!(mnt_mflags & MS_RDONLY);

        VIR_DEBUG("Mount %s on %s type=%s flags=0x%x",
                  mnt_src, mnt->dst, mnt->type, mnt_mflags & ~MS_RDONLY);
        if (mount(mnt_src, mnt->dst, mnt->type, mnt_mflags & ~MS_RDONLY, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to mount %1$s on %2$s type %3$s flags=0x%4$x"),
                                 mnt_src, mnt->dst, NULLSTR(mnt->type),
                                 mnt_mflags & ~MS_RDONLY);
            return -1;
        }

        if (bindOverReadonly &&
            mount(mnt_src, mnt->dst, "none",
                  MS_BIND|MS_REMOUNT|mnt_mflags|MS_RDONLY, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to re-mount %1$s on %2$s flags=0x%3$x"),
                                 mnt_src, mnt->dst,
                                 MS_BIND|MS_REMOUNT|MS_RDONLY);
            return -1;
        }
    }

    return 0;
}

#if WITH_FUSE
static int lxcContainerMountProcFuse(virDomainDef *def,
                                     const char *stateDir)
{
    g_autofree char *meminfo_path = NULL;

    VIR_DEBUG("Mount /proc/meminfo stateDir=%s", stateDir);

    meminfo_path = g_strdup_printf("/.oldroot/%s/%s.fuse/meminfo",
                                   stateDir,
                                   def->name);

    if (mount(meminfo_path, "/proc/meminfo",
              NULL, MS_BIND, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %1$s on /proc/meminfo"),
                             meminfo_path);
        return -1;
    }

    return 0;
}
#else
static int lxcContainerMountProcFuse(virDomainDef *def G_GNUC_UNUSED,
                                     const char *stateDir G_GNUC_UNUSED)
{
    return 0;
}
#endif

static int lxcContainerMountFSDev(virDomainDef *def,
                                  const char *stateDir)
{
    g_autofree char *path = NULL;
    int flags = def->idmap.nuidmap ? MS_BIND : MS_MOVE;

    VIR_DEBUG("Mount /dev/ stateDir=%s", stateDir);

    path = g_strdup_printf("/.oldroot/%s/%s.dev", stateDir, def->name);

    if (g_mkdir_with_parents("/dev", 0777) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot create /dev"));
        return -1;
    }

    VIR_DEBUG("Trying to %s %s to /dev", def->idmap.nuidmap ?
              "bind" : "move", path);

    if (mount(path, "/dev", "none", flags, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %1$s on /dev"),
                             path);
        return -1;
    }

    return 0;
}

static int lxcContainerMountFSDevPTS(virDomainDef *def,
                                     const char *stateDir)
{
    g_autofree char *path = NULL;
    int flags = def->idmap.nuidmap ? MS_BIND : MS_MOVE;

    VIR_DEBUG("Mount /dev/pts stateDir=%s", stateDir);

    path = g_strdup_printf("/.oldroot/%s/%s.devpts", stateDir, def->name);

    if (g_mkdir_with_parents("/dev/pts", 0777) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot create /dev/pts"));
        return -1;
    }

    VIR_DEBUG("Trying to %s %s to /dev/pts", def->idmap.nuidmap ?
              "bind" : "move", path);

    if (mount(path, "/dev/pts", "none", flags, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %1$s on /dev/pts"),
                             path);
        return -1;
    }

    return 0;
}

static int lxcContainerSetupDevices(char **ttyPaths, size_t nttyPaths)
{
    size_t i;
    const struct {
        const char *src;
        const char *dst;
    } links[] = {
        { "/proc/self/fd/0", "/dev/stdin" },
        { "/proc/self/fd/1", "/dev/stdout" },
        { "/proc/self/fd/2", "/dev/stderr" },
        { "/proc/self/fd", "/dev/fd" },
    };

    for (i = 0; i < G_N_ELEMENTS(links); i++) {
        if (symlink(links[i].src, links[i].dst) < 0) {
            virReportSystemError(errno,
                                 _("Failed to symlink device %1$s to %2$s"),
                                 links[i].dst, links[i].src);
            return -1;
        }
    }

    /* We have private devpts capability, so bind that */
    if (virFileBindMountDevice("/dev/pts/ptmx", "/dev/ptmx") < 0)
        return -1;

    for (i = 0; i < nttyPaths; i++) {
        g_autofree char *tty = g_strdup_printf("/dev/tty%zu", i + 1);

        if (virFileBindMountDevice(ttyPaths[i], tty) < 0)
            return -1;

        if (i == 0 &&
            virFileBindMountDevice(ttyPaths[i], "/dev/console") < 0)
            return -1;
    }
    return 0;
}


static int lxcContainerMountFSBind(virDomainFSDef *fs,
                                   const char *srcprefix)
{
    g_autofree char *src = NULL;
    struct stat st;

    VIR_DEBUG("src=%s dst=%s", fs->src->path, fs->dst);

    src = g_strdup_printf("%s%s", srcprefix, fs->src->path);

    if (stat(fs->dst, &st) < 0) {
        if (errno != ENOENT) {
            virReportSystemError(errno, _("Unable to stat bind target %1$s"),
                                 fs->dst);
            return -1;
        }
        /* ENOENT => create the target dir or file */
        if (stat(src, &st) < 0) {
            virReportSystemError(errno, _("Unable to stat bind source %1$s"),
                                 src);
            return -1;
        }
        if (S_ISDIR(st.st_mode)) {
            if (g_mkdir_with_parents(fs->dst, 0777) < 0) {
                virReportSystemError(errno,
                                     _("Failed to create %1$s"),
                                     fs->dst);
                return -1;
            }
        } else {
            /* Create Empty file for target mount point */
            int fd = open(fs->dst, O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK, 0666);
            if (fd < 0) {
                if (errno != EEXIST) {
                    virReportSystemError(errno,
                                         _("Failed to create bind target %1$s"),
                                         fs->dst);
                    return -1;
                }
            }
            if (VIR_CLOSE(fd) < 0) {
                virReportSystemError(errno,
                                     _("Failed to close bind target %1$s"),
                                     fs->dst);
                return -1;
            }
        }
    }

    if (mount(src, fs->dst, "none", MS_BIND, NULL) < 0) {
        virReportSystemError(errno,
                             _("Failed to bind mount directory %1$s to %2$s"),
                             src, fs->dst);
        return -1;
    }

    if (fs->readonly) {
        VIR_DEBUG("Binding %s readonly", fs->dst);
        if (mount(src, fs->dst, "none", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to make directory %1$s readonly"),
                                 fs->dst);
        }
    }

    return 0;
}


#ifdef WITH_BLKID
static int
lxcContainerMountDetectFilesystem(const char *src, char **type)
{
    int fd;
    int ret = -1;
    int rc;
    const char *data = NULL;
    blkid_probe blkid = NULL;

    *type = NULL;

    if ((fd = open(src, O_RDONLY)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open filesystem %1$s"), src);
        return -1;
    }

    if (!(blkid = blkid_new_probe())) {
        virReportSystemError(errno, "%s",
                             _("Unable to create blkid library handle"));
        goto cleanup;
    }
    if (blkid_probe_set_device(blkid, fd, 0, 0) < 0) {
        virReportSystemError(EINVAL,
                             _("Unable to associate device %1$s with blkid library"),
                             src);
        goto cleanup;
    }

    blkid_probe_enable_superblocks(blkid, 1);

    blkid_probe_set_superblocks_flags(blkid, BLKID_SUBLKS_TYPE);

    rc = blkid_do_safeprobe(blkid);
    if (rc != 0) {
        if (rc == 1) /* Nothing found, return success with *type == NULL */
            goto done;

        if (rc == -2) {
            virReportSystemError(EINVAL,
                                 _("Too many filesystems detected for %1$s"),
                                 src);
        } else {
            virReportSystemError(errno,
                                 _("Unable to detect filesystem for %1$s"),
                                 src);
        }
        goto cleanup;
    }

    if (blkid_probe_lookup_value(blkid, "TYPE", &data, NULL) < 0) {
        virReportSystemError(ENOENT,
                             _("Unable to find filesystem type for %1$s"),
                             src);
        goto cleanup;
    }

    *type = g_strdup(data);

 done:
    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    if (blkid)
        blkid_free_probe(blkid);
    return ret;
}
#else /* ! WITH_BLKID */
static int
lxcContainerMountDetectFilesystem(const char *src G_GNUC_UNUSED,
                                  char **type)
{
    /* No libblkid, so just return success with no detected type */
    *type = NULL;
    return 0;
}
#endif /* ! WITH_BLKID */

/*
 * This function attempts to do automatic detection of filesystem
 * type following the same rules as the util-linux 'mount' binary.
 *
 * The main difference is that we don't (currently) try to use
 * libblkid to detect the format first. We go straight to using
 * /etc/filesystems, and then /proc/filesystems
 */
static int lxcContainerMountFSBlockAuto(virDomainFSDef *fs,
                                        int fsflags,
                                        const char *src,
                                        const char *srcprefix,
                                        const char *sec_mount_options)
{
    FILE *fp = NULL;
    int ret = -1;
    bool tryProc = false;
    bool gotStar = false;
    g_autofree char *fslist = NULL;
    const char *type;

    VIR_DEBUG("src=%s dst=%s srcprefix=%s", src, fs->dst, srcprefix);

    /* First time around we use /etc/filesystems */
 retry:
    g_free(fslist);
    fslist = g_strdup_printf("%s%s", srcprefix,
                             tryProc ? "/proc/filesystems" : "/etc/filesystems");

    VIR_DEBUG("Open fslist %s", fslist);
    if (!(fp = fopen(fslist, "r"))) {
        /* If /etc/filesystems does not exist, then we need to retry
         * with /proc/filesystems next
         */
        if (errno == ENOENT &&
            !tryProc) {
            tryProc = true;
            goto retry;
        }

        virReportSystemError(errno,
                             _("Unable to read %1$s"),
                             fslist);
        goto cleanup;
    }

    while (!feof(fp)) {
        g_autofree char *line = NULL;
        size_t n;
        if (getline(&line, &n, fp) <= 0) {
            if (feof(fp))
                break;

            goto cleanup;
        }

        if (strstr(line, "nodev"))
            continue;

        type = strchr(line, '\n');
        if (type)
            line[type-line] = '\0';

        type = line;
        virSkipSpaces(&type);

        /*
         * /etc/filesystems is only allowed to contain '*' on the last line
         */
        if (gotStar && !tryProc) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s has unexpected '*' before last line"),
                           fslist);
            goto cleanup;
        }

        /* An '*' on the last line in /etc/filesystems
         * means try /proc/filesystems next. We don't
         * jump immediately though, since we need to see
         * if any more lines follow
         */
        if (!tryProc &&
            STREQ(type, "*"))
            gotStar = true;

        VIR_DEBUG("Trying mount '%s' on '%s' with '%s' opts '%s'",
                  src, fs->dst, type, sec_mount_options);
        if (mount(src, fs->dst, type, fsflags, sec_mount_options) < 0) {
            /* These errnos indicate a bogus filesystem type for
             * the image we have, so skip to the next type
             */
            if (errno == EINVAL || errno == ENODEV)
                continue;

            virReportSystemError(errno,
                                 _("Failed to mount device %1$s to %2$s"),
                                 src, fs->dst);
            goto cleanup;
        }

        ret = 0;
        break;
    }

    /* We've got to the end of /etc/filesystems and saw
     * a '*', so we must try /proc/filesystems next
     */
    if (ret != 0 &&
        !tryProc &&
        gotStar) {
        tryProc = true;
        VIR_FORCE_FCLOSE(fp);
        goto retry;
    }

    if (ret != 0) {
        virReportSystemError(ENODEV,
                             _("Failed to mount device %1$s to %2$s, unable to detect filesystem"),
                             src, fs->dst);
    }

    VIR_DEBUG("Done mounting filesystem ret=%d tryProc=%d", ret, tryProc);

 cleanup:
    VIR_FORCE_FCLOSE(fp);
    return ret;
}


/*
 * Mount a block device 'src' on fs->dst, automatically
 * probing for filesystem type
 */
static int lxcContainerMountFSBlockHelper(virDomainFSDef *fs,
                                          const char *src,
                                          const char *srcprefix,
                                          const char *sec_mount_options)
{
    int fsflags = 0;
    g_autofree char *format = NULL;

    if (fs->readonly)
        fsflags |= MS_RDONLY;

    if (g_mkdir_with_parents(fs->dst, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to create %1$s"),
                             fs->dst);
        return -1;
    }

    if (lxcContainerMountDetectFilesystem(src, &format) < 0)
        return -1;

    if (format) {
        VIR_DEBUG("Mount '%s' on '%s' with detected format '%s' opts '%s'",
                  src, fs->dst, format, sec_mount_options);
        if (mount(src, fs->dst, format, fsflags, sec_mount_options) < 0) {
            virReportSystemError(errno,
                                 _("Failed to mount device %1$s to %2$s as %3$s"),
                                 src, fs->dst, format);
            return -1;
        }
        return 0;
    } else {
        return lxcContainerMountFSBlockAuto(fs, fsflags, src, srcprefix, sec_mount_options);
    }
}


static int lxcContainerMountFSBlock(virDomainFSDef *fs,
                                    const char *srcprefix,
                                    const char *sec_mount_options)
{
    g_autofree char *src = NULL;
    int ret = -1;

    VIR_DEBUG("src=%s dst=%s", fs->src->path, fs->dst);

    src = g_strdup_printf("%s%s", srcprefix, fs->src->path);

    ret = lxcContainerMountFSBlockHelper(fs, src, srcprefix, sec_mount_options);

    VIR_DEBUG("Done mounting filesystem ret=%d", ret);

    return ret;
}


static int lxcContainerMountFSTmpfs(virDomainFSDef *fs,
                                    char *sec_mount_options)
{
    g_autofree char *data = NULL;

    VIR_DEBUG("usage=%lld sec=%s", fs->usage, sec_mount_options);

    data = g_strdup_printf("size=%lld%s", fs->usage, sec_mount_options);

    if (g_mkdir_with_parents(fs->dst, 0777) < 0) {
        virReportSystemError(errno,
                             _("Failed to create %1$s"),
                             fs->dst);
        return -1;
    }

    if (mount("tmpfs", fs->dst, "tmpfs", MS_NOSUID|MS_NODEV, data) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount directory %1$s as tmpfs"),
                             fs->dst);
        return -1;
    }

    if (fs->readonly) {
        VIR_DEBUG("Binding %s readonly", fs->dst);
        if (mount(fs->dst, fs->dst, "none", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) < 0) {
            virReportSystemError(errno,
                                 _("Failed to make directory %1$s readonly"),
                                 fs->dst);
            return -1;
        }
    }

    return 0;
}


static int lxcContainerMountFS(virDomainFSDef *fs,
                               char *sec_mount_options)
{
    switch (fs->type) {
    case VIR_DOMAIN_FS_TYPE_MOUNT:
        if (lxcContainerMountFSBind(fs, "/.oldroot") < 0)
            return -1;
        break;
    case VIR_DOMAIN_FS_TYPE_BLOCK:
        if (lxcContainerMountFSBlock(fs, "/.oldroot", sec_mount_options) < 0)
            return -1;
        break;
    case VIR_DOMAIN_FS_TYPE_RAM:
        if (lxcContainerMountFSTmpfs(fs, sec_mount_options) < 0)
            return -1;
        break;
    case VIR_DOMAIN_FS_TYPE_BIND:
        if (lxcContainerMountFSBind(fs, "") < 0)
            return -1;
        break;
    case VIR_DOMAIN_FS_TYPE_FILE:
        /* We do actually support this, but the lxc controller
         * should have associated the file with a loopback
         * device and changed this to TYPE_BLOCK for us */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected filesystem type %1$s"),
                       virDomainFSTypeToString(fs->type));
        return -1;
    case VIR_DOMAIN_FS_TYPE_TEMPLATE:
    case VIR_DOMAIN_FS_TYPE_VOLUME:
    case VIR_DOMAIN_FS_TYPE_LAST:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Cannot mount filesystem type %1$s"),
                       virDomainFSTypeToString(fs->type));
        return -1;
    }
    return 0;
}


static int lxcContainerMountAllFS(virDomainDef *vmDef,
                                  char *sec_mount_options)
{
    size_t i;
    VIR_DEBUG("Mounting all non-root filesystems");

    /* Pull in rest of container's mounts */
    for (i = 0; i < vmDef->nfss; i++) {
        if (STREQ(vmDef->fss[i]->dst, "/"))
            continue;

        VIR_DEBUG("Mounting '%s' -> '%s'", NULLSTR(vmDef->fss[i]->src->path),
                  vmDef->fss[i]->dst);

        if (lxcContainerResolveSymlinks(vmDef->fss[i], false) < 0)
            return -1;

        if (!(vmDef->fss[i]->src->path &&
              STRPREFIX(vmDef->fss[i]->src->path, vmDef->fss[i]->dst)) &&
            lxcContainerUnmountSubtree(vmDef->fss[i]->dst, false) < 0)
            return -1;

        if (lxcContainerMountFS(vmDef->fss[i], sec_mount_options) < 0)
            return -1;
    }

    VIR_DEBUG("Mounted all non-root filesystems");
    return 0;
}


int lxcContainerSetupHostdevCapsMakePath(const char *dev)
{
    g_autofree char *dir = NULL;
    char *tmp;

    dir = g_strdup(dev);

    if ((tmp = strrchr(dir, '/'))) {
        *tmp = '\0';
        if (g_mkdir_with_parents(dir, 0777) < 0) {
            virReportSystemError(errno,
                                 _("Failed to create directory for '%1$s' dev '%2$s'"),
                                 dir, dev);
            return -1;
        }
    }

    return 0;
}


static int lxcContainerUnmountForSharedRoot(const char *stateDir,
                                            const char *domain)
{
    g_autofree char *tmp = NULL;

#if WITH_SELINUX
    /* Some versions of Linux kernel don't let you overmount
     * the selinux filesystem, so make sure we kill it first
     */
    if (lxcContainerUnmountSubtree(SELINUX_MOUNT, false) < 0)
        return -1;
#endif

    /* These filesystems are created by libvirt temporarily, they
     * shouldn't appear in container. */
    tmp = g_strdup_printf("%s/%s.dev", stateDir, domain);

    if (lxcContainerUnmountSubtree(tmp, false) < 0)
        return -1;

    g_free(tmp);
    tmp = g_strdup_printf("%s/%s.devpts", stateDir, domain);

    if (lxcContainerUnmountSubtree(tmp, false) < 0)
        return -1;

#if WITH_FUSE
    g_free(tmp);
    tmp = g_strdup_printf("%s/%s.fuse", stateDir, domain);

    if (lxcContainerUnmountSubtree(tmp, false) < 0)
        return -1;
#endif

    /* If we have the root source being '/', then we need to
     * get rid of any existing stuff under /proc, /sys & /tmp.
     * We need new namespace aware versions of those. We must
     * do /proc last otherwise we won't find /proc/mounts :-) */
    if (lxcContainerUnmountSubtree("/sys", false) < 0 ||
        lxcContainerUnmountSubtree("/dev", false) < 0 ||
        lxcContainerUnmountSubtree("/proc", false) < 0)
        return -1;

    return 0;
}


static bool
lxcNeedNetworkNamespace(virDomainDef *def)
{
    size_t i;
    if (def->nets != NULL)
        return true;
    if (def->features[VIR_DOMAIN_FEATURE_PRIVNET] == VIR_TRISTATE_SWITCH_ON)
        return true;
    for (i = 0; i < def->nhostdevs; i++) {
        if (def->hostdevs[i]->mode == VIR_DOMAIN_HOSTDEV_MODE_CAPABILITIES &&
            def->hostdevs[i]->source.caps.type == VIR_DOMAIN_HOSTDEV_CAPS_TYPE_NET)
            return true;
    }
    return false;
}


/* Got a FS mapped to /, we're going the pivot_root
 * approach to do a better-chroot-than-chroot
 * this is based on this thread https://lkml.org/lkml/2008/3/5/29
 */
static int lxcContainerSetupPivotRoot(virDomainDef *vmDef,
                                      virDomainFSDef *root,
                                      char **ttyPaths,
                                      size_t nttyPaths,
                                      virSecurityManager *securityDriver)
{
    g_autoptr(virCgroup) cgroup = NULL;
    g_autofree char *sec_mount_options = NULL;
    g_autofree char *stateDir = NULL;

    VIR_DEBUG("Setup pivot root");

    if (!(sec_mount_options = virSecurityManagerGetMountOptions(securityDriver, vmDef)))
        return -1;

    /* Before pivoting we need to identify any
     * cgroups controllers that are mounted */
    if (virCgroupNewSelf(&cgroup) < 0)
        return -1;

    if (virFileResolveAllLinks(LXC_STATE_DIR, &stateDir) < 0)
        return -1;

    /* Ensure the root filesystem is mounted */
    if (lxcContainerPrepareRoot(vmDef, root, sec_mount_options) < 0)
        return -1;

    /* Gives us a private root, leaving all parent OS mounts on /.oldroot */
    if (lxcContainerPivotRoot(root) < 0)
        return -1;

    /* FIXME: we should find a way to unmount these mounts for container
     * even user namespace is enabled. */
    if (STREQ(root->src->path, "/") && (!vmDef->idmap.nuidmap) &&
        lxcContainerUnmountForSharedRoot(stateDir, vmDef->name) < 0)
        return -1;

    /* Mounts the core /proc, /sys, etc filesystems */
    if (lxcContainerMountBasicFS(vmDef->idmap.nuidmap,
                                 !lxcNeedNetworkNamespace(vmDef)) < 0)
        return -1;

    /* Ensure entire root filesystem (except /.oldroot) is readonly */
    if (root->readonly &&
        lxcContainerSetReadOnly() < 0)
        return -1;

    /* Mounts /proc/meminfo etc sysinfo */
    if (lxcContainerMountProcFuse(vmDef, stateDir) < 0)
        return -1;

    /* Now we can re-mount the cgroups controllers in the
     * same configuration as before */
    if (virCgroupBindMount(cgroup, "/.oldroot/", sec_mount_options) < 0)
        return -1;

    /* Mounts /dev */
    if (lxcContainerMountFSDev(vmDef, stateDir) < 0)
        return -1;

    /* Mounts /dev/pts */
    if (lxcContainerMountFSDevPTS(vmDef, stateDir) < 0)
        return -1;

    /* Setup device nodes in /dev/ */
    if (lxcContainerSetupDevices(ttyPaths, nttyPaths) < 0)
        return -1;

    /* Sets up any non-root mounts from guest config */
    if (lxcContainerMountAllFS(vmDef, sec_mount_options) < 0)
        return -1;

   /* Gets rid of all remaining mounts from host OS, including /.oldroot itself */
    if (lxcContainerUnmountSubtree("/.oldroot", true) < 0)
        return -1;

    return 0;
}

static int lxcContainerResolveAllSymlinks(virDomainDef *vmDef)
{
    size_t i;

    VIR_DEBUG("Resolving symlinks");

    for (i = 0; i < vmDef->nfss; i++) {
        virDomainFSDef *fs = vmDef->fss[i];
        /* In the first pass, be gentle as some files may
           depend on other filesystems to be mounted */
        if (lxcContainerResolveSymlinks(fs, true) < 0)
            return -1;
    }
    VIR_DEBUG("Resolved all filesystem symlinks");

    return 0;
}

/*
 * This is running as the 'init' process inside the container.
 * It removes some capabilities that could be dangerous to
 * host system, since they are not currently "containerized"
 */
#if WITH_CAPNG

static int lxcContainerDropCapabilities(virDomainDef *def,
                                        bool keepReboot)
{
    int ret;
    size_t i;
    int policy = def->features[VIR_DOMAIN_FEATURE_CAPABILITIES];

    /* Maps virDomainProcessCapsFeature to CAPS_* */
    static int capsMapping[] = {CAP_AUDIT_CONTROL,
                                CAP_AUDIT_WRITE,
                                CAP_BLOCK_SUSPEND,
                                CAP_CHOWN,
                                CAP_DAC_OVERRIDE,
                                CAP_DAC_READ_SEARCH,
                                CAP_FOWNER,
                                CAP_FSETID,
                                CAP_IPC_LOCK,
                                CAP_IPC_OWNER,
                                CAP_KILL,
                                CAP_LEASE,
                                CAP_LINUX_IMMUTABLE,
                                CAP_MAC_ADMIN,
                                CAP_MAC_OVERRIDE,
                                CAP_MKNOD,
                                CAP_NET_ADMIN,
                                CAP_NET_BIND_SERVICE,
                                CAP_NET_BROADCAST,
                                CAP_NET_RAW,
                                CAP_SETGID,
                                CAP_SETFCAP,
                                CAP_SETPCAP,
                                CAP_SETUID,
                                CAP_SYS_ADMIN,
                                CAP_SYS_BOOT,
                                CAP_SYS_CHROOT,
                                CAP_SYS_MODULE,
                                CAP_SYS_NICE,
                                CAP_SYS_PACCT,
                                CAP_SYS_PTRACE,
                                CAP_SYS_RAWIO,
                                CAP_SYS_RESOURCE,
                                CAP_SYS_TIME,
                                CAP_SYS_TTY_CONFIG,
                                CAP_SYSLOG,
                                CAP_WAKE_ALARM};

    /* Init the internal state of capng */
    if ((ret = capng_get_caps_process()) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to get current process capabilities: %1$d"),
                       ret);
        return -1;
    }

    /* Make sure we drop everything if required by the user */
    if (policy == VIR_DOMAIN_CAPABILITIES_POLICY_DENY)
        capng_clear(CAPNG_SELECT_BOTH);

    /* Apply all single capabilities changes */
    for (i = 0; i < VIR_DOMAIN_PROCES_CAPS_FEATURE_LAST; i++) {
        bool toDrop = false;
        int state = def->caps_features[i];

        if (!cap_valid(capsMapping[i]))
            continue;

        switch ((virDomainCapabilitiesPolicy) policy) {

        case VIR_DOMAIN_CAPABILITIES_POLICY_DENY:
            if (state == VIR_TRISTATE_SWITCH_ON &&
                    (ret = capng_update(CAPNG_ADD,
                                        CAPNG_EFFECTIVE | CAPNG_PERMITTED |
                                        CAPNG_INHERITABLE | CAPNG_BOUNDING_SET,
                                        capsMapping[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to add capability %1$s: %2$d"),
                               virDomainProcessCapsFeatureTypeToString(i), ret);
                return -1;
            }
            break;

        case VIR_DOMAIN_CAPABILITIES_POLICY_DEFAULT:
            switch (i) {
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_SYS_BOOT: /* No use of reboot */
                toDrop = !keepReboot && (state != VIR_TRISTATE_SWITCH_ON);
                break;
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_SYS_MODULE: /* No kernel module loading */
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_SYS_TIME: /* No changing the clock */
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_MKNOD: /* No creating device nodes */
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_AUDIT_CONTROL: /* No messing with auditing status */
            case VIR_DOMAIN_PROCES_CAPS_FEATURE_MAC_ADMIN: /* No messing with LSM config */
                toDrop = (state != VIR_TRISTATE_SWITCH_ON);
                break;
            default: /* User specified capabilities to drop */
                toDrop = (state == VIR_TRISTATE_SWITCH_OFF);
            }
            G_GNUC_FALLTHROUGH;

        case VIR_DOMAIN_CAPABILITIES_POLICY_ALLOW:
            if (policy == VIR_DOMAIN_CAPABILITIES_POLICY_ALLOW)
                toDrop = state == VIR_TRISTATE_SWITCH_OFF;

            if (toDrop && (ret = capng_update(CAPNG_DROP,
                                              CAPNG_EFFECTIVE | CAPNG_PERMITTED |
                                              CAPNG_INHERITABLE | CAPNG_BOUNDING_SET,
                                              capsMapping[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to remove capability %1$s: %2$d"),
                               virDomainProcessCapsFeatureTypeToString(i), ret);
                return -1;
            }
            break;

        case VIR_DOMAIN_CAPABILITIES_POLICY_LAST:
        default:
            virReportEnumRangeError(virDomainCapabilitiesPolicy, policy);
            return -1;
        }
    }

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to apply capabilities: %1$d"), ret);
        return -1;
    }

    /* We do not need to call capng_lock() in this case. The bounding
     * set restriction will prevent them reacquiring sys_boot/module/time,
     * etc which is all that matters for the container. Once inside the
     * container it is fine for SECURE_NOROOT / SECURE_NO_SETUID_FIXUP to
     * be unmasked  - they can never escape the bounding set. */

    return 0;
}
#else
static int lxcContainerDropCapabilities(virDomainDef *def G_GNUC_UNUSED,
                                        bool keepReboot G_GNUC_UNUSED)
{
    VIR_WARN("libcap-ng support not compiled in, unable to clear capabilities");
    return 0;
}
#endif


/**
 * lxcAttach_ns:
 * @ns_fd: array of namespaces to attach
 */
static int lxcAttachNS(int *ns_fd)
{
    if (ns_fd &&
        virProcessSetNamespaces((size_t)VIR_LXC_DOMAIN_NAMESPACE_LAST,
                                ns_fd) < 0)
        return -1;
    return 0;
}

/**
 * lxcContainerSetUserGroup:
 * @cmd: command to update
 * @vmDef: domain definition for the container
 * @ttyPath: guest path to the tty
 *
 * Set the command UID and GID. As this function attempts at
 * converting the user/group name into uid/gid, it needs to
 * be called after the pivot root is done.
 *
 * The owner of the tty is also changed to the given user.
 */
static int lxcContainerSetUserGroup(virCommand *cmd,
                                    virDomainDef *vmDef,
                                    const char *ttyPath)
{
    uid_t uid;
    gid_t gid;

    if (vmDef->os.inituser) {
        if (virGetUserID(vmDef->os.inituser, &uid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("User %1$s doesn't exist"),
                           vmDef->os.inituser);
            return -1;
        }
        virCommandSetUID(cmd, uid);

        /* Change the newly created tty owner to the inituid for
         * shells to have job control. */
        if (chown(ttyPath, uid, -1) < 0) {
            virReportSystemError(errno,
                                 _("Failed to change ownership of tty %1$s"),
                                 ttyPath);
            return -1;
        }
    }

    if (vmDef->os.initgroup) {
        if (virGetGroupID(vmDef->os.initgroup, &gid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, _("Group %1$s doesn't exist"),
                           vmDef->os.initgroup);
            return -1;
        }
        virCommandSetGID(cmd, gid);
    }

    return 0;
}

static const char hostname_validchars[] =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-";

static int lxcContainerSetHostname(virDomainDef *def)
{
    g_autofree char *name = NULL;
    const char *hostname = NULL;

    /* Filter the VM name to get a valid hostname */
    name = g_strdup(def->name);

    /* RFC 1123 allows 0-9 digits as a first character in hostname */
    virStringFilterChars(name, hostname_validchars);
    hostname = name;
    if (strlen(name) > 0 && name[0] == '-')
        hostname = name + 1;

    if (sethostname(hostname, strlen(hostname)) < 0) {
        virReportSystemError(errno, "%s", _("Failed to set hostname"));
        return -1;
    }

    return 0;
}

/**
 * lxcContainerChild:
 * @data: pointer to container arguments
 *
 * This function is run in the process clone()'d in lxcStartContainer.
 * Perform a number of container setup tasks:
 *     Setup container file system
 *     mount container /proc
 * Then exec's the container init
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcContainerChild(void *data)
{
    lxc_child_argv_t *argv = data;
    virDomainDef *vmDef = argv->config;
    int ttyfd = -1;
    int ret = -1;
    g_autofree char *ttyPath = NULL;
    virDomainFSDef *root;
    g_autoptr(virCommand) cmd = NULL;
    int hasReboot;
    g_autofree gid_t *groups = NULL;
    int ngroups;

    if (NULL == vmDef) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("lxcChild() passed invalid vm definition"));
        goto cleanup;
    }

    if (lxcAttachNS(argv->nsInheritFDs) < 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("failed to attach the namespace"));
        return -1;
    }

    /* Wait for controller to finish setup tasks, including
     * things like move of network interfaces, uid/gid mapping
     */
    if (lxcContainerWaitForContinue(argv->monitor) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to read the container continue message"));
        goto cleanup;
    }
    VIR_DEBUG("Received container continue message");

    if ((hasReboot = lxcContainerHasReboot()) < 0)
        goto cleanup;

    cmd = lxcContainerBuildInitCmd(vmDef,
                                   argv->ttyPaths,
                                   argv->nttyPaths);
    virCommandWriteArgLog(cmd, 1);

    if (lxcContainerSetID(vmDef) < 0)
        goto cleanup;

    root = virDomainGetFilesystemForTarget(vmDef, "/");

    if (argv->nttyPaths) {
        const char *tty = argv->ttyPaths[0];
        if (STRPREFIX(tty, "/dev/pts/"))
            tty += strlen("/dev/pts/");
        ttyPath = g_strdup_printf("%s/%s.devpts/%s", LXC_STATE_DIR, vmDef->name,
                                  tty);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("At least one tty is required"));
        goto cleanup;
    }

    VIR_DEBUG("Container TTY path: %s", ttyPath);

    ttyfd = open(ttyPath, O_RDWR);
    if (ttyfd < 0) {
        virReportSystemError(errno,
                             _("Failed to open tty %1$s"),
                             ttyPath);
        goto cleanup;
    }

    if (lxcContainerResolveAllSymlinks(vmDef) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up pivot");
    if (lxcContainerSetupPivotRoot(vmDef, root,
                                   argv->ttyPaths, argv->nttyPaths,
                                   argv->securityDriver) < 0)
        goto cleanup;

    if (!virFileExists(vmDef->os.init)) {
        virReportSystemError(errno,
                             _("cannot find init path '%1$s' relative to container root"),
                             vmDef->os.init);
        goto cleanup;
    }

    if (lxcContainerSetUserGroup(cmd, vmDef, argv->ttyPaths[0]) < 0)
        goto cleanup;

    /* rename and enable interfaces */
    if (lxcContainerRenameAndEnableInterfaces(vmDef,
                                              argv->nveths,
                                              argv->veths) < 0) {
        goto cleanup;
    }

    if (lxcContainerSetHostname(vmDef) < 0)
        goto cleanup;


    /* drop a set of root capabilities */
    if (lxcContainerDropCapabilities(vmDef, !!hasReboot) < 0)
        goto cleanup;

    if (lxcContainerSendContinue(argv->handshakefd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to send continue signal to controller"));
        goto cleanup;
    }

    VIR_DEBUG("Setting up security labeling");
    if (virSecurityManagerSetProcessLabel(argv->securityDriver, vmDef) < 0)
        goto cleanup;

    VIR_DEBUG("Setting up inherited FDs");
    VIR_FORCE_CLOSE(argv->handshakefd);
    VIR_FORCE_CLOSE(argv->monitor);
    if (lxcContainerSetupFDs(&ttyfd,
                             argv->npassFDs, argv->passFDs) < 0)
        goto cleanup;

    /* Make init process of the container the leader of the new session.
     * That is needed when checkpointing container.
     */
    if (setsid() < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to become session leader"));
        goto cleanup;
    }

    /* TODO is it safe to call it here or should this call be moved in
     * front of the clone() as otherwise there might be a risk for a
     * deadlock */
    if ((ngroups = virGetGroupList(virCommandGetUID(cmd), virCommandGetGID(cmd),
                                   &groups)) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(ttyfd);
    VIR_FORCE_CLOSE(argv->monitor);
    VIR_FORCE_CLOSE(argv->handshakefd);

    if (ret == 0) {
        VIR_DEBUG("Executing init binary");
        /* this function will only return if an error occurred */
        ret = virCommandExec(cmd, groups, ngroups);
    }

    if (ret != 0) {
        VIR_DEBUG("Tearing down container");
        fprintf(stderr,
                _("Failure in libvirt_lxc startup: %1$s\n"),
                virGetLastErrorMessage());
    }

    return ret;
}

static int userns_required(virDomainDef *def)
{
    return def->idmap.uidmap && def->idmap.gidmap;
}

virArch lxcContainerGetAlt32bitArch(virArch arch)
{
    /* Any Linux 64bit arch which has a 32bit
     * personality available should be listed here */
    if (arch == VIR_ARCH_X86_64)
        return VIR_ARCH_I686;
    if (arch == VIR_ARCH_S390X)
        return VIR_ARCH_S390;
    if (arch == VIR_ARCH_PPC64)
        return VIR_ARCH_PPC;
    if (arch == VIR_ARCH_PARISC64)
        return VIR_ARCH_PARISC;
    if (arch == VIR_ARCH_SPARC64)
        return VIR_ARCH_SPARC;
    if (arch == VIR_ARCH_MIPS64)
        return VIR_ARCH_MIPS;
    if (arch == VIR_ARCH_MIPS64EL)
        return VIR_ARCH_MIPSEL;
    if (arch == VIR_ARCH_AARCH64)
        return VIR_ARCH_ARMV7L;

    return VIR_ARCH_NONE;
}


/**
 * lxcContainerStart:
 * @def: pointer to virtual machine structure
 * @nveths: number of interfaces
 * @veths: interface names
 * @control: control FD to the container
 * @ttyPath: path of tty to set as the container console
 *
 * Starts a container process by calling clone() with the namespace flags
 *
 * Returns PID of container on success or -1 in case of error
 */
int lxcContainerStart(virDomainDef *def,
                      virSecurityManager *securityDriver,
                      size_t nveths,
                      char **veths,
                      size_t npassFDs,
                      int *passFDs,
                      int control,
                      int handshakefd,
                      int *nsInheritFDs,
                      size_t nttyPaths,
                      char **ttyPaths)
{
    pid_t pid;
    int cflags;
    int stacksize = getpagesize() * 16;
    char *stack = NULL;
    char *stacktop;
    int ret = -1;
    lxc_child_argv_t args = {
        .config = def,
        .securityDriver = securityDriver,
        .nveths = nveths,
        .veths = veths,
        .npassFDs = npassFDs,
        .passFDs = passFDs,
        .monitor = control,
        .nttyPaths = nttyPaths,
        .ttyPaths = ttyPaths,
        .handshakefd = handshakefd,
        .nsInheritFDs = nsInheritFDs,
    };

    /* allocate a stack for the container */
    stack = mmap(NULL, stacksize, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN | MAP_STACK,
                 -1, 0);
    if (stack == MAP_FAILED) {
        virReportSystemError(errno, "%s",
                             _("Unable to allocate stack"));
        return -1;
    }

    stacktop = stack + stacksize;

    cflags = CLONE_NEWPID|CLONE_NEWNS|SIGCHLD;

    if (userns_required(def)) {
        if (virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_USER) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Kernel doesn't support user namespace"));
            goto cleanup;
        }
        VIR_DEBUG("Enable user namespace");
        cflags |= CLONE_NEWUSER;
    }
    if (!nsInheritFDs || nsInheritFDs[VIR_LXC_DOMAIN_NAMESPACE_SHARENET] == -1) {
        if (lxcNeedNetworkNamespace(def)) {
            VIR_DEBUG("Enable network namespaces");
            cflags |= CLONE_NEWNET;
        }
    } else {
        if (lxcNeedNetworkNamespace(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Config asks for inherit net namespace as well as private network interfaces"));
            goto cleanup;
        }
        VIR_DEBUG("Inheriting a net namespace");
    }

    if (!nsInheritFDs || nsInheritFDs[VIR_LXC_DOMAIN_NAMESPACE_SHAREIPC] == -1) {
        cflags |= CLONE_NEWIPC;
    } else {
        VIR_DEBUG("Inheriting an IPC namespace");
    }

    if (!nsInheritFDs || nsInheritFDs[VIR_LXC_DOMAIN_NAMESPACE_SHAREUTS] == -1) {
        cflags |= CLONE_NEWUTS;
    } else {
        VIR_DEBUG("Inheriting a UTS namespace");
    }

    VIR_DEBUG("Cloning container init process");
    pid = clone(lxcContainerChild, stacktop, cflags, &args);
    VIR_DEBUG("clone() completed, new container PID is %d", pid);

    if (pid < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to run clone container"));
        goto cleanup;
    }

    ret = pid;
 cleanup:
    if (munmap(stack, stacksize) < 0)
        VIR_WARN("Unable to munmap() stack: %s", g_strerror(errno));

    return ret;
}

int lxcContainerChown(virDomainDef *def, const char *path)
{
    uid_t uid;
    gid_t gid;

    if (!def->idmap.uidmap)
        return 0;

    uid = def->idmap.uidmap[0].target;
    gid = def->idmap.gidmap[0].target;

    if (chown(path, uid, gid) < 0) {
        virReportSystemError(errno,
                             _("Failed to change owner of %1$s to %2$u:%3$u"),
                             path, uid, gid);
        return -1;
    }

    return 0;
}
