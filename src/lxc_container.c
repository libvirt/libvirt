/*
 * Copyright IBM Corp. 2008
 *
 * lxc_container.c: file description
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

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

#include "lxc_container.h"
#include "util.h"
#include "memory.h"
#include "veth.h"

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt, __VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

/**
 * lxcExecContainerInit:
 * @vmDef: Ptr to vm definition structure
 *
 * Exec the container init string.  The container init will replace then
 * be running in the current process
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcExecContainerInit(const lxc_vm_def_t *vmDef)
{
    int rc = -1;
    char* execString;
    size_t execStringLen = strlen(vmDef->init) + 1 + 5;

    if (VIR_ALLOC_N(execString, execStringLen) < 0) {
        lxcError(NULL, NULL, VIR_ERR_NO_MEMORY,
                 _("failed to calloc memory for init string: %s"),
                 strerror(errno));
        goto error_out;
    }

    strcpy(execString, "exec ");
    strcat(execString, vmDef->init);

    execl("/bin/sh", "sh", "-c", execString, (char*)NULL);
    lxcError(NULL, NULL, VIR_ERR_NO_MEMORY,
             _("execl failed to exec init: %s"), strerror(errno));

error_out:
    exit(rc);
}

/**
 * lxcSetContainerStdio:
 * @ttyName: Name of tty to set as the container console
 *
 * Sets the given tty as the primary conosole for the container as well as
 * stdout, stdin and stderr.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcSetContainerStdio(const char *ttyPath)
{
    int rc = -1;
    int ttyfd;
    int open_max, i;

    if (setsid() < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("setsid failed: %s"), strerror(errno));
        goto error_out;
    }

    ttyfd = open(ttyPath, O_RDWR|O_NOCTTY);
    if (ttyfd < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("open(%s) failed: %s"), ttyPath, strerror(errno));
        goto error_out;
    }

    if (ioctl(ttyfd, TIOCSCTTY, NULL) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("ioctl(TIOCSTTY) failed: %s"), strerror(errno));
        goto cleanup;
    }

    /* Just in case someone forget to set FD_CLOEXEC, explicitly
     * close all FDs before executing the container */
    open_max = sysconf (_SC_OPEN_MAX);
    for (i = 0; i < open_max; i++)
        if (i != ttyfd)
            close(i);

    if (dup2(ttyfd, 0) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("dup2(stdin) failed: %s"), strerror(errno));
        goto cleanup;
    }

    if (dup2(ttyfd, 1) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("dup2(stdout) failed: %s"), strerror(errno));
        goto cleanup;
    }

    if (dup2(ttyfd, 2) < 0) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("dup2(stderr) failed: %s"), strerror(errno));
        goto cleanup;
    }

    rc = 0;

cleanup:
    close(ttyfd);

error_out:
    return rc;
}

/**
 * lxcExecWithTty:
 * @vm: Ptr to vm structure
 *
 * Sets container console and stdio and then execs container init
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcExecWithTty(lxc_vm_def_t *vmDef, char *ttyPath)
{
    int rc = -1;

    if(lxcSetContainerStdio(ttyPath) < 0) {
        goto exit_with_error;
    }

    lxcExecContainerInit(vmDef);

exit_with_error:
    exit(rc);
}

/**
 * lxcWaitForContinue:
 * @monitor: monitor FD from parent
 *
 * This function will wait for the container continue message from the
 * parent process.  It will send this message on the socket pair stored in
 * the vm structure once it has completed the post clone container setup.
 *
 * Returns 0 on success or -1 in case of error
 */
static int lxcWaitForContinue(int monitor)
{
    lxc_message_t msg;
    int readLen;

    readLen = saferead(monitor, &msg, sizeof(msg));
    if (readLen != sizeof(msg) ||
        msg != LXC_CONTINUE_MSG) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("Failed to read the container continue message: %s"),
                 strerror(errno));
        return -1;
    }

    DEBUG0("Received container continue message");

    return 0;
}

/**
 * lxcEnableInterfaces:
 * @vm: Pointer to vm structure
 *
 * This function will enable the interfaces for this container.
 *
 * Returns 0 on success or nonzero in case of error
 */
static int lxcEnableInterfaces(const lxc_vm_def_t *def)
{
    int rc = 0;
    const lxc_net_def_t *net;

    for (net = def->nets; net; net = net->next) {
        DEBUG("Enabling %s", net->containerVeth);
        rc =  vethInterfaceUpOrDown(net->containerVeth, 1);
        if (0 != rc) {
            goto error_out;
        }
    }

    /* enable lo device only if there were other net devices */
    if (def->nets)
        rc = vethInterfaceUpOrDown("lo", 1);

error_out:
    return rc;
}

/**
 * lxcChild:
 * @argv: Pointer to container arguments
 *
 * This function is run in the process clone()'d in lxcStartContainer.
 * Perform a number of container setup tasks:
 *     Setup container file system
 *     mount container /proca
 * Then exec's the container init
 *
 * Returns 0 on success or -1 in case of error
 */
int lxcChild( void *data )
{
    int rc = -1;
    lxc_child_argv_t *argv = data;
    lxc_vm_def_t *vmDef = argv->config;
    lxc_mount_t *curMount;
    int i;

    if (NULL == vmDef) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("lxcChild() passed invalid vm definition"));
        goto cleanup;
    }

    /* handle the bind mounts first before doing anything else that may */
    /* then access those mounted dirs */
    curMount = vmDef->mounts;
    for (i = 0; curMount; curMount = curMount->next) {
        rc = mount(curMount->source,
                   curMount->target,
                   NULL,
                   MS_BIND,
                   NULL);
        if (0 != rc) {
            lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                     _("failed to mount %s at %s for container: %s"),
                     curMount->source, curMount->target, strerror(errno));
            goto cleanup;
        }
    }

    /* mount /proc */
    rc = mount("lxcproc", "/proc", "proc", 0, NULL);
    if (0 != rc) {
        lxcError(NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                 _("failed to mount /proc for container: %s"),
                 strerror(errno));
        goto cleanup;
    }

    /* Wait for interface devices to show up */
    if (0 != (rc = lxcWaitForContinue(argv->monitor))) {
        goto cleanup;
    }

    /* enable interfaces */
    if (0 != (rc = lxcEnableInterfaces(vmDef))) {
        goto cleanup;
    }

    rc = lxcExecWithTty(vmDef, argv->ttyPath);
    /* this function will only return if an error occured */

cleanup:
    return rc;
}

#endif /* WITH_LXC */
