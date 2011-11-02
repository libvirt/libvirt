/*
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     David L. Leskovec <dlesko at linux.vnet.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/wait.h>

#include "virnetdevveth.h"
#include "memory.h"
#include "logging.h"
#include "command.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virNetDevvError(code, ...)                                  \
    virReportErrorHelper(VIR_FROM_NONE, code, __FILE__,             \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/* Functions */
/**
 * virNetDevVethGetFreeName:
 * @veth: pointer to store returned name for veth device
 * @startDev: device number to start at (x in vethx)
 *
 * Looks in /sys/class/net/ to find the first available veth device
 * name.
 *
 * Returns non-negative device number on success or -1 in case of error
 */
static int virNetDevVethGetFreeName(char **veth, int startDev)
{
    int devNum = startDev-1;
    char *path = NULL;

    VIR_DEBUG("Find free from veth%d", startDev);
    do {
        VIR_FREE(path);
        ++devNum;
        if (virAsprintf(&path, "/sys/class/net/veth%d/", devNum) < 0) {
            virReportOOMError();
            return -1;
        }
        VIR_DEBUG("Probe %s", path);
    } while (virFileExists(path));
    VIR_FREE(path);

    if (virAsprintf(veth, "veth%d", devNum) < 0) {
        virReportOOMError();
        return -1;
    }

    return devNum;
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
    int rc = -1;
    const char *argv[] = {
        "ip", "link", "add", NULL, "type", "veth", "peer", "name", NULL, NULL
    };
    int vethDev = 0;
    bool veth1_alloc = false;
    bool veth2_alloc = false;

    VIR_DEBUG("Host: %s guest: %s", NULLSTR(*veth1), NULLSTR(*veth2));

    if (*veth1 == NULL) {
        if ((vethDev = virNetDevVethGetFreeName(veth1, vethDev)) < 0)
            goto cleanup;
        VIR_DEBUG("Assigned host: %s", *veth1);
        veth1_alloc = true;
        vethDev++;
    }
    argv[3] = *veth1;

    while (*veth2 == NULL) {
        if ((vethDev = virNetDevVethGetFreeName(veth2, vethDev)) < 0) {
            if (veth1_alloc)
                VIR_FREE(*veth1);
            goto cleanup;
        }

        /* Just make sure they didn't accidentally get same name */
        if (STREQ(*veth1, *veth2)) {
            vethDev++;
            VIR_FREE(*veth2);
            continue;
        }

        VIR_DEBUG("Assigned guest: %s", *veth2);
        veth2_alloc = true;
    }
    argv[8] = *veth2;

    VIR_DEBUG("Create Host: %s guest: %s", *veth1, *veth2);
    if (virRun(argv, NULL) < 0) {
        if (veth1_alloc)
            VIR_FREE(*veth1);
        if (veth2_alloc)
            VIR_FREE(*veth2);
        goto cleanup;
    }

    rc = 0;

cleanup:
    return rc;
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
    int rc;
    const char *argv[] = {"ip", "link", "del", veth, NULL};
    int cmdResult = 0;

    VIR_DEBUG("veth: %s", veth);

    rc = virRun(argv, &cmdResult);

    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        /*
         * Prevent overwriting an error log which may be set
         * where an actual failure occurs.
         */
        VIR_DEBUG("Failed to delete '%s' (%d)",
                  veth, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    return rc;
}
