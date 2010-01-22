/*
 * Copyright IBM Corp. 2008
 * Copyright Red Hat 2008-2009
 *
 * lxc_container.c: file description
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
 *  Daniel P. Berrange <berrange@redhat.com>
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

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mntent.h>

/* Yes, we want linux private one, for _syscall2() macro */
#include <linux/unistd.h>

/* For MS_MOVE */
#include <linux/fs.h>

#if HAVE_CAPNG
#include <cap-ng.h>
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "lxc_container.h"
#include "util.h"
#include "memory.h"
#include "veth.h"

#define VIR_FROM_THIS VIR_FROM_LXC

/*
 * GLibc headers are behind the kernel, so we define these
 * constants if they're not present already.
 */

#ifndef CLONE_NEWPID
#define CLONE_NEWPID  0x20000000
#endif
#ifndef CLONE_NEWUTS
#define CLONE_NEWUTS  0x04000000
#endif
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif
#ifndef CLONE_NEWIPC
#define CLONE_NEWIPC  0x08000000
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET  0x40000000 /* New network namespace */
#endif

/* messages between parent and container */
typedef char lxc_message_t;
#define LXC_CONTINUE_MSG 'c'

typedef struct __lxc_child_argv lxc_child_argv_t;
struct __lxc_child_argv {
    virDomainDefPtr config;
    unsigned int nveths;
    char **veths;
    int monitor;
    char *ttyPath;
};


/**
 * lxcContainerExecInit:
 * @vmDef: pointer to vm definition structure
 *
 * Exec the container init string. The container init will replace then
 * be running in the current process
 *
 * Does not return
 */
static int lxcContainerExecInit(virDomainDefPtr vmDef)
{
    const char *const argv[] = {
        vmDef->os.init,
        NULL,
    };

    return execve(argv[0], (char **)argv, NULL);
}

/**
 * lxcContainerSetStdio:
 * @control: control FD from parent
 * @ttyfd: FD of tty to set as the container console
 *
 * Sets the given tty as the primary conosole for the container as well as
 * stdout, stdin and stderr.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcContainerSetStdio(int control, int ttyfd)
{
    int rc = -1;
    int open_max, i;

    if (setsid() < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("setsid failed"));
        goto cleanup;
    }

    if (ioctl(ttyfd, TIOCSCTTY, NULL) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("ioctl(TIOCSTTY) failed"));
        goto cleanup;
    }

    /* Just in case someone forget to set FD_CLOEXEC, explicitly
     * close all FDs before executing the container */
    open_max = sysconf (_SC_OPEN_MAX);
    for (i = 0; i < open_max; i++)
        if (i != ttyfd && i != control)
            close(i);

    if (dup2(ttyfd, 0) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("dup2(stdin) failed"));
        goto cleanup;
    }

    if (dup2(ttyfd, 1) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("dup2(stdout) failed"));
        goto cleanup;
    }

    if (dup2(ttyfd, 2) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("dup2(stderr) failed"));
        goto cleanup;
    }

    rc = 0;

cleanup:
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
    int rc = -1;
    lxc_message_t msg = LXC_CONTINUE_MSG;
    int writeCount = 0;

    writeCount = safewrite(control, &msg, sizeof(msg));
    if (writeCount != sizeof(msg)) {
        virReportSystemError(NULL, errno, "%s",
                             _("Unable to send container continue message"));
        goto error_out;
    }

    rc = 0;

error_out:
    return rc;
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
static int lxcContainerWaitForContinue(int control)
{
    lxc_message_t msg;
    int readLen;

    readLen = saferead(control, &msg, sizeof(msg));
    if (readLen != sizeof(msg) ||
        msg != LXC_CONTINUE_MSG) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to read the container continue message"));
        return -1;
    }
    close(control);

    DEBUG0("Received container continue message");

    return 0;
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
static int lxcContainerRenameAndEnableInterfaces(unsigned int nveths,
                                                 char **veths)
{
    int rc = 0;
    unsigned int i;
    char *newname = NULL;

    for (i = 0 ; i < nveths ; i++) {
        rc = virAsprintf(&newname, "eth%d", i);
        if (rc < 0)
            goto error_out;

        DEBUG("Renaming %s to %s", veths[i], newname);
        rc = setInterfaceName(veths[i], newname);
        if (0 != rc)
            goto error_out;

        DEBUG("Enabling %s", newname);
        rc =  vethInterfaceUpOrDown(newname, 1);
        if (0 != rc)
            goto error_out;
        VIR_FREE(newname);
    }

    /* enable lo device only if there were other net devices */
    if (veths)
        rc = vethInterfaceUpOrDown("lo", 1);

error_out:
    VIR_FREE(newname);
    return rc;
}


//_syscall2(int, pivot_root, char *, newroot, const char *, oldroot)
extern int pivot_root(const char * new_root,const char * put_old);

static int lxcContainerChildMountSort(const void *a, const void *b)
{
  const char **sa = (const char**)a;
  const char **sb = (const char**)b;

  /* Delibrately reversed args - we need to unmount deepest
     children first */
  return strcmp(*sb, *sa);
}

#ifndef MS_REC
#define MS_REC          16384
#endif

#ifndef MNT_DETACH
#define MNT_DETACH      0x00000002
#endif

#ifndef MS_PRIVATE
#define MS_PRIVATE              (1<<18)
#endif

#ifndef MS_SLAVE
#define MS_SLAVE                (1<<19)
#endif

static int lxcContainerPivotRoot(virDomainFSDefPtr root)
{
    int rc, ret;
    char *oldroot = NULL, *newroot = NULL;

    ret = -1;

    /* root->parent must be private, so make / private. */
    if (mount("", "/", NULL, MS_PRIVATE|MS_REC, NULL) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to make root private"));
        goto err;
    }

    if (virAsprintf(&oldroot, "%s/.oldroot", root->src) < 0) {
        virReportOOMError(NULL);
        goto err;
    }

    if ((rc = virFileMakePath(oldroot)) != 0) {
        virReportSystemError(NULL, rc,
                             _("Failed to create %s"),
                             oldroot);
        goto err;
    }

    /* Create a tmpfs root since old and new roots must be
     * on separate filesystems */
    if (mount("tmprootfs", oldroot, "tmpfs", 0, NULL) < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to mount empty tmpfs at %s"),
                             oldroot);
        goto err;
    }

    /* Create a directory called 'new' in tmpfs */
    if (virAsprintf(&newroot, "%s/new", oldroot) < 0) {
        virReportOOMError(NULL);
        goto err;
    }

    if ((rc = virFileMakePath(newroot)) != 0) {
        virReportSystemError(NULL, rc,
                             _("Failed to create %s"),
                             newroot);
        goto err;
    }

    /* ... and mount our root onto it */
    if (mount(root->src, newroot, NULL, MS_BIND|MS_REC, NULL) < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to bind new root %s into tmpfs"),
                             root->src);
        goto err;
    }

    /* Now we chroot into the tmpfs, then pivot into the
     * root->src bind-mounted onto '/new' */
    if (chdir(newroot) < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to chroot into %s"), newroot);
        goto err;
    }

    /* The old root directory will live at /.oldroot after
     * this and will soon be unmounted completely */
    if (pivot_root(".", ".oldroot") < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to pivot root"));
        goto err;
    }

    /* CWD is undefined after pivot_root, so go to / */
    if (chdir("/") < 0)
        goto err;

    ret = 0;

err:
    VIR_FREE(oldroot);
    VIR_FREE(newroot);

    return ret;
}


static int lxcContainerMountBasicFS(virDomainFSDefPtr root)
{
    const struct {
        const char *src;
        const char *dst;
        const char *type;
    } mnts[] = {
        { "/dev", "/dev", "tmpfs" },
        { "/proc", "/proc", "proc" },
        { "/sys", "/sys", "sysfs" },
#if WITH_SELINUX
        { "none", "/selinux", "selinuxfs" },
#endif
    };
    int i, rc = -1;
    char *devpts;

    if (virAsprintf(&devpts, "/.oldroot%s/dev/pts", root->src) < 0) {
        virReportOOMError(NULL);
        return rc;
    }

    for (i = 0 ; i < ARRAY_CARDINALITY(mnts) ; i++) {
        if (virFileMakePath(mnts[i].dst) != 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to mkdir %s"),
                                 mnts[i].src);
            goto cleanup;
        }
        if (mount(mnts[i].src, mnts[i].dst, mnts[i].type, 0, NULL) < 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to mount %s on %s"),
                                 mnts[i].type, mnts[i].type);
            goto cleanup;
        }
    }

    if ((rc = virFileMakePath("/dev/pts") != 0)) {
        virReportSystemError(NULL, rc, "%s",
                             _("Cannot create /dev/pts"));
        goto cleanup;
    }

    VIR_DEBUG("Trying to move %s to %s", devpts, "/dev/pts");
    if ((rc = mount(devpts, "/dev/pts", NULL, MS_MOVE, NULL)) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to mount /dev/pts in container"));
        goto cleanup;
    }

    rc = 0;

 cleanup:
    VIR_FREE(devpts);

    return rc;
}

static int lxcContainerPopulateDevices(void)
{
    int i;
    const struct {
        int maj;
        int min;
        mode_t mode;
        const char *path;
    } devs[] = {
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_NULL, 0666, "/dev/null" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_ZERO, 0666, "/dev/zero" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_FULL, 0666, "/dev/full" },
        { LXC_DEV_MAJ_TTY, LXC_DEV_MIN_CONSOLE, 0600, "/dev/console" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_RANDOM, 0666, "/dev/random" },
        { LXC_DEV_MAJ_MEMORY, LXC_DEV_MIN_URANDOM, 0666, "/dev/urandom" },
    };

    /* Populate /dev/ with a few important bits */
    for (i = 0 ; i < ARRAY_CARDINALITY(devs) ; i++) {
        dev_t dev = makedev(devs[i].maj, devs[i].min);
        if (mknod(devs[i].path, S_IFCHR, dev) < 0 ||
            chmod(devs[i].path, devs[i].mode)) {
            virReportSystemError(NULL, errno,
                                 _("Failed to make device %s"),
                                 devs[i].path);
            return -1;
        }
    }

    if (access("/dev/pts/ptmx", W_OK) == 0) {
        if (symlink("/dev/pts/ptmx", "/dev/ptmx") < 0) {
            virReportSystemError(NULL, errno, "%s",
                                 _("Failed to create symlink /dev/ptmx to /dev/pts/ptmx"));
            return -1;
        }
    } else {
        dev_t dev = makedev(LXC_DEV_MAJ_TTY, LXC_DEV_MIN_PTMX);
        if (mknod("/dev/ptmx", S_IFCHR, dev) < 0 ||
            chmod("/dev/ptmx", 0666)) {
            virReportSystemError(NULL, errno, "%s",
                                 _("Failed to make device /dev/ptmx"));
            return -1;
        }
    }


    return 0;
}


static int lxcContainerMountNewFS(virDomainDefPtr vmDef)
{
    int i;

    /* Pull in rest of container's mounts */
    for (i = 0 ; i < vmDef->nfss ; i++) {
        char *src;
        if (STREQ(vmDef->fss[i]->dst, "/"))
            continue;
        // XXX fix
        if (vmDef->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
            continue;

        if (virAsprintf(&src, "/.oldroot/%s", vmDef->fss[i]->src) < 0) {
            virReportOOMError(NULL);
            return -1;
        }

        if (virFileMakePath(vmDef->fss[i]->dst) != 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to create %s"),
                                 vmDef->fss[i]->dst);
            VIR_FREE(src);
            return -1;
        }
        if (mount(src, vmDef->fss[i]->dst, NULL, MS_BIND, NULL) < 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to mount %s at %s"),
                                 src, vmDef->fss[i]->dst);
            VIR_FREE(src);
            return -1;
        }
        VIR_FREE(src);
    }

    return 0;
}


static int lxcContainerUnmountOldFS(void)
{
    struct mntent mntent;
    char **mounts = NULL;
    int nmounts = 0;
    FILE *procmnt;
    int i;
    char mntbuf[1024];

    if (!(procmnt = setmntent("/proc/mounts", "r"))) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to read /proc/mounts"));
        return -1;
    }
    while (getmntent_r(procmnt, &mntent, mntbuf, sizeof(mntbuf)) != NULL) {
        VIR_DEBUG("Got %s", mntent.mnt_dir);
        if (!STRPREFIX(mntent.mnt_dir, "/.oldroot"))
            continue;

        if (VIR_REALLOC_N(mounts, nmounts+1) < 0) {
            endmntent(procmnt);
            virReportOOMError(NULL);
            return -1;
        }
        if (!(mounts[nmounts++] = strdup(mntent.mnt_dir))) {
            endmntent(procmnt);
            virReportOOMError(NULL);
            return -1;
        }
    }
    endmntent(procmnt);

    if (mounts)
        qsort(mounts, nmounts, sizeof(mounts[0]),
              lxcContainerChildMountSort);

    for (i = 0 ; i < nmounts ; i++) {
        VIR_DEBUG("Umount %s", mounts[i]);
        if (umount(mounts[i]) < 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to unmount '%s'"),
                                 mounts[i]);
            return -1;
        }
        VIR_FREE(mounts[i]);
    }
    VIR_FREE(mounts);

    return 0;
}


/* Got a FS mapped to /, we're going the pivot_root
 * approach to do a better-chroot-than-chroot
 * this is based on this thread http://lkml.org/lkml/2008/3/5/29
 */
static int lxcContainerSetupPivotRoot(virDomainDefPtr vmDef,
                                      virDomainFSDefPtr root)
{
    /* Gives us a private root, leaving all parent OS mounts on /.oldroot */
    if (lxcContainerPivotRoot(root) < 0)
        return -1;

    /* Mounts the core /proc, /sys, /dev, /dev/pts filesystems */
    if (lxcContainerMountBasicFS(root) < 0)
        return -1;

    /* Populates device nodes in /dev/ */
    if (lxcContainerPopulateDevices() < 0)
        return -1;

    /* Sets up any non-root mounts from guest config */
    if (lxcContainerMountNewFS(vmDef) < 0)
        return -1;

    /* Gets rid of all remaining mounts from host OS, including /.oldroot itself */
    if (lxcContainerUnmountOldFS() < 0)
        return -1;

    return 0;
}

/* Nothing mapped to /, we're using the main root,
   but with extra stuff mapped in */
static int lxcContainerSetupExtraMounts(virDomainDefPtr vmDef)
{
    int i;

    if (mount("", "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to make / slave"));
        return -1;
    }
    for (i = 0 ; i < vmDef->nfss ; i++) {
        // XXX fix to support other mount types
        if (vmDef->fss[i]->type != VIR_DOMAIN_FS_TYPE_MOUNT)
            continue;

        if (mount(vmDef->fss[i]->src,
                  vmDef->fss[i]->dst,
                  NULL,
                  MS_BIND,
                  NULL) < 0) {
            virReportSystemError(NULL, errno,
                                 _("Failed to mount %s at %s"),
                                 vmDef->fss[i]->src,
                                 vmDef->fss[i]->dst);
            return -1;
        }
    }

    /* mount /proc */
    if (mount("lxcproc", "/proc", "proc", 0, NULL) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to mount /proc"));
        return -1;
    }

    return 0;
}

static int lxcContainerSetupMounts(virDomainDefPtr vmDef,
                                   virDomainFSDefPtr root)
{
    if (root)
        return lxcContainerSetupPivotRoot(vmDef, root);
    else
        return lxcContainerSetupExtraMounts(vmDef);
}


/*
 * This is running as the 'init' process insid the container.
 * It removes some capabilities that could be dangerous to
 * host system, since they are not currently "containerized"
 */
static int lxcContainerDropCapabilities(void)
{
#if HAVE_CAPNG
    int ret;

    capng_get_caps_process();

    if ((ret = capng_updatev(CAPNG_DROP,
                             CAPNG_EFFECTIVE | CAPNG_PERMITTED |
                             CAPNG_INHERITABLE | CAPNG_BOUNDING_SET,
                             CAP_SYS_BOOT, /* No use of reboot */
                             CAP_SYS_MODULE, /* No kernel module loading */
                             CAP_SYS_TIME, /* No changing the clock */
                             CAP_AUDIT_CONTROL, /* No messing with auditing status */
                             CAP_MAC_ADMIN, /* No messing with LSM config */
                             -1 /* sentinal */)) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to remove capabilities: %d"), ret);
        return -1;
    }

    if ((ret = capng_apply(CAPNG_SELECT_BOTH)) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to apply capabilities: %d"), ret);
        return -1;
    }

    /* We do not need to call capng_lock() in this case. The bounding
     * set restriction will prevent them reacquiring sys_boot/module/time,
     * etc which is all that matters for the container. Once inside the
     * container it is fine for SECURE_NOROOT / SECURE_NO_SETUID_FIXUP to
     * be unmasked  - they can never escape the bounding set. */

#else
    VIR_WARN0(_("libcap-ng support not compiled in, unable to clear capabilities"));
#endif
    return 0;
}


/**
 * lxcContainerChild:
 * @data: pointer to container arguments
 *
 * This function is run in the process clone()'d in lxcStartContainer.
 * Perform a number of container setup tasks:
 *     Setup container file system
 *     mount container /proca
 * Then exec's the container init
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcContainerChild( void *data )
{
    lxc_child_argv_t *argv = data;
    virDomainDefPtr vmDef = argv->config;
    int ttyfd;
    char *ttyPath;
    virDomainFSDefPtr root;

    if (NULL == vmDef) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 "%s", _("lxcChild() passed invalid vm definition"));
        return -1;
    }

    root = virDomainGetRootFilesystem(vmDef);

    if (root) {
        if (virAsprintf(&ttyPath, "%s%s", root->src, argv->ttyPath) < 0) {
            virReportOOMError(NULL);
            return -1;
        }
    } else {
        if (!(ttyPath = strdup(argv->ttyPath))) {
            virReportOOMError(NULL);
            return -1;
        }
    }

    ttyfd = open(ttyPath, O_RDWR|O_NOCTTY);
    if (ttyfd < 0) {
        virReportSystemError(NULL, errno,
                             _("Failed to open tty %s"),
                             ttyPath);
        VIR_FREE(ttyPath);
        return -1;
    }
    VIR_FREE(ttyPath);

    if (lxcContainerSetStdio(argv->monitor, ttyfd) < 0) {
        close(ttyfd);
        return -1;
    }
    close(ttyfd);

    if (lxcContainerSetupMounts(vmDef, root) < 0)
        return -1;

    /* Wait for interface devices to show up */
    if (lxcContainerWaitForContinue(argv->monitor) < 0)
        return -1;

    /* rename and enable interfaces */
    if (lxcContainerRenameAndEnableInterfaces(argv->nveths,
                                              argv->veths) < 0)
        return -1;

    /* drop a set of root capabilities */
    if (lxcContainerDropCapabilities() < 0)
        return -1;

    /* this function will only return if an error occured */
    return lxcContainerExecInit(vmDef);
}

static int userns_supported(void)
{
    return lxcContainerAvailable(LXC_CONTAINER_FEATURE_USER) == 0;
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
int lxcContainerStart(virDomainDefPtr def,
                      unsigned int nveths,
                      char **veths,
                      int control,
                      char *ttyPath)
{
    pid_t pid;
    int flags;
    int stacksize = getpagesize() * 4;
    char *stack, *stacktop;
    lxc_child_argv_t args = { def, nveths, veths, control, ttyPath };

    /* allocate a stack for the container */
    if (VIR_ALLOC_N(stack, stacksize) < 0) {
        virReportOOMError(NULL);
        return -1;
    }
    stacktop = stack + stacksize;

    flags = CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|CLONE_NEWIPC|SIGCHLD;

    if (userns_supported())
        flags |= CLONE_NEWUSER;

    if (def->nets != NULL)
        flags |= CLONE_NEWNET;

    pid = clone(lxcContainerChild, stacktop, flags, &args);
    VIR_FREE(stack);
    DEBUG("clone() returned, %d", pid);

    if (pid < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("Failed to run clone container"));
        return -1;
    }

    return pid;
}

static int lxcContainerDummyChild(void *argv ATTRIBUTE_UNUSED)
{
    _exit(0);
}

int lxcContainerAvailable(int features)
{
    int flags = CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUTS|
        CLONE_NEWIPC|SIGCHLD;
    int cpid;
    char *childStack;
    char *stack;
    int childStatus;

    if (features & LXC_CONTAINER_FEATURE_USER)
        flags |= CLONE_NEWUSER;

    if (features & LXC_CONTAINER_FEATURE_NET)
        flags |= CLONE_NEWNET;

    if (VIR_ALLOC_N(stack, getpagesize() * 4) < 0) {
        DEBUG0("Unable to allocate stack");
        return -1;
    }

    childStack = stack + (getpagesize() * 4);

    cpid = clone(lxcContainerDummyChild, childStack, flags, NULL);
    VIR_FREE(stack);
    if (cpid < 0) {
        char ebuf[1024];
        DEBUG("clone call returned %s, container support is not enabled",
              virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    } else {
        waitpid(cpid, &childStatus, 0);
    }

    return 0;
}
