/*
 * Copyright (C) 2010-2014 Red Hat, Inc.
 * Copyright IBM Corp. 2008
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
 *
 * Authors:
 *     David L. Leskovec <dlesko at linux.vnet.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/wait.h>

#include "virnetdevveth.h"
#include "viralloc.h"
#include "virlog.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "virutil.h"
#include "virnetdev.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevveth");

/* Functions */

virMutex virNetDevVethCreateMutex;

static int virNetDevVethCreateMutexOnceInit(void)
{
    if (virMutexInit(&virNetDevVethCreateMutex) < 0) {
        virReportSystemError(errno, "%s", _("unable to init mutex"));
        return -1;
    }
    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetDevVethCreateMutex);

static int virNetDevVethExists(int devNum)
{
    int ret;
    char *path = NULL;
    if (virAsprintf(&path, "/sys/class/net/vnet%d/", devNum) < 0)
        return -1;
    ret = virFileExists(path) ? 1 : 0;
    VIR_DEBUG("Checked dev vnet%d usage: %d", devNum, ret);
    VIR_FREE(path);
    return ret;
}

/**
 * virNetDevVethGetFreeNum:
 * @startDev: device number to start at (x in vethx)
 *
 * Looks in /sys/class/net/ to find the first available veth device
 * name.
 *
 * Returns non-negative device number on success or -1 in case of error
 */
static int virNetDevVethGetFreeNum(int startDev)
{
    int devNum;

#define MAX_DEV_NUM 65536

    for (devNum = startDev; devNum < MAX_DEV_NUM; devNum++) {
        int ret = virNetDevVethExists(devNum);
        if (ret < 0)
            return -1;
        if (ret == 0)
            return devNum;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("No free veth devices available"));
    return -1;
}

/**
 * virNetDevVethCreate:
 * @veth1: pointer to name for parent end of veth pair
 * @veth2: pointer to return name for container end of veth pair
 *
 * Creates a veth device pair using the ip command:
 * ip link add veth1 type veth peer name veth2
 * If veth1 points to NULL on entry, it will be a valid interface on
 * return.  veth2 should point to NULL on entry.
 *
 * NOTE: If veth1 and veth2 names are not specified, ip will auto assign
 *       names.  There seems to be two problems here -
 *       1) There doesn't seem to be a way to determine the names of the
 *          devices that it creates.  They show up in ip link show and
 *          under /sys/class/net/ however there is no guarantee that they
 *          are the devices that this process just created.
 *       2) Once one of the veth devices is moved to another namespace, it
 *          is no longer visible in the parent namespace.  This seems to
 *          confuse the name assignment causing it to fail with File exists.
 *       Because of these issues, this function currently allocates names
 *       prior to using the ip command, and returns any allocated names
 *       to the caller.
 *
 * Returns 0 on success or -1 in case of error
 */
int virNetDevVethCreate(char** veth1, char** veth2)
{
    int ret = -1;
    char *veth1auto = NULL;
    char *veth2auto = NULL;
    int vethNum = 0;
    virCommandPtr cmd = NULL;
    size_t i;

    /*
     * We might race with other containers, but this is reasonably
     * unlikely, so don't do too many retries for device creation
     */
    if (virNetDevVethCreateMutexInitialize() < 0)
        return -1;

    virMutexLock(&virNetDevVethCreateMutex);
#define MAX_VETH_RETRIES 10

    for (i = 0; i < MAX_VETH_RETRIES; i++) {
        int status;
        if (!*veth1) {
            int veth1num;
            if ((veth1num = virNetDevVethGetFreeNum(vethNum)) < 0)
                goto cleanup;

            if (virAsprintf(&veth1auto, "vnet%d", veth1num) < 0)
                goto cleanup;
            vethNum = veth1num + 1;
        }
        if (!*veth2) {
            int veth2num;
            if ((veth2num = virNetDevVethGetFreeNum(vethNum)) < 0)
                goto cleanup;

            if (virAsprintf(&veth2auto, "vnet%d", veth2num) < 0)
                goto cleanup;
            vethNum = veth2num + 1;
        }

        cmd = virCommandNew("ip");
        virCommandAddArgList(cmd, "link", "add",
                             *veth1 ? *veth1 : veth1auto,
                             "type", "veth", "peer", "name",
                             *veth2 ? *veth2 : veth2auto,
                             NULL);

        if (virCommandRun(cmd, &status) < 0)
            goto cleanup;

        if (status == 0) {
            if (veth1auto) {
                *veth1 = veth1auto;
                veth1auto = NULL;
            }
            if (veth2auto) {
                *veth2 = veth2auto;
                veth2auto = NULL;
            }
            VIR_DEBUG("Create Host: %s guest: %s", *veth1, *veth2);
            ret = 0;
            goto cleanup;
        }

        VIR_DEBUG("Failed to create veth host: %s guest: %s: %d",
                  *veth1 ? *veth1 : veth1auto,
                  *veth2 ? *veth2 : veth2auto,
                  status);
        VIR_FREE(veth1auto);
        VIR_FREE(veth2auto);
        virCommandFree(cmd);
        cmd = NULL;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Failed to allocate free veth pair after %d attempts"),
                   MAX_VETH_RETRIES);

 cleanup:
    virMutexUnlock(&virNetDevVethCreateMutex);
    virCommandFree(cmd);
    VIR_FREE(veth1auto);
    VIR_FREE(veth2auto);
    return ret;
}

/**
 * virNetDevVethDelete:
 * @veth: name for one end of veth pair
 *
 * This will delete both veth devices in a pair.  Only one end needs to
 * be specified.  The ip command will identify and delete the other veth
 * device as well.
 * ip link del veth
 *
 * Returns 0 on success or -1 in case of error
 */
int virNetDevVethDelete(const char *veth)
{
    virCommandPtr cmd = virCommandNewArgList("ip", "link", "del", veth, NULL);
    int status;
    int ret = -1;

    if (virCommandRun(cmd, &status) < 0)
        goto cleanup;

    if (status != 0) {
        if (!virNetDevExists(veth)) {
            VIR_DEBUG("Device %s already deleted (by kernel namespace cleanup)", veth);
            ret = 0;
            goto cleanup;
        }
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to delete veth device %s"), veth);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}
