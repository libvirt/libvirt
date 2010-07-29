/*
 * veth.c: Tools for managing veth pairs
 *
 * Copyright (C) 2010 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * See COPYING.LIB for the License of this software
 *
 * Authors:
 *  David L. Leskovec <dlesko at linux.vnet.ibm.com>
 */

#include <config.h>

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "veth.h"
#include "internal.h"
#include "logging.h"
#include "memory.h"
#include "util.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_LXC

#define vethError(code, ...)                                  \
    virReportErrorHelper(NULL, VIR_FROM_LXC, code, __FILE__,  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/* Functions */
/**
 * getFreeVethName:
 * @veth: name for veth device (NULL to find first open)
 * @maxLen: max length of veth name
 * @startDev: device number to start at (x in vethx)
 *
 * Looks in /sys/class/net/ to find the first available veth device
 * name.
 *
 * Returns 0 on success or -1 in case of error
 */
static int getFreeVethName(char *veth, int maxLen, int startDev)
{
    int rc = -1;
    int devNum = startDev-1;
    char path[PATH_MAX];

    do {
        ++devNum;
        snprintf(path, PATH_MAX, "/sys/class/net/veth%d/", devNum);
    } while (virFileExists(path));

    snprintf(veth, maxLen, "veth%d", devNum);

    rc = devNum;

    return rc;
}

/**
 * vethCreate:
 * @veth1: name for one end of veth pair
 * @veth1MaxLen: max length of veth1 name
 * @veth2: name for one end of veth pair
 * @veth2MaxLen: max length of veth1 name
 *
 * Creates a veth device pair using the ip command:
 * ip link add veth1 type veth peer name veth2
 * NOTE: If veth1 and veth2 names are not specified, ip will auto assign
 *       names.  There seems to be two problems here -
 *       1) There doesn't seem to be a way to determine the names of the
 *          devices that it creates.  They show up in ip link show and
 *          under /sys/class/net/ however there is no guarantee that they
 *          are the devices that this process just created.
 *       2) Once one of the veth devices is moved to another namespace, it
 *          is no longer visible in the parent namespace.  This seems to
 *          confuse the name assignment causing it to fail with File exists.
 *       Because of these issues, this function currently forces the caller
 *       to fully specify the veth device names.
 *
 * Returns 0 on success or -1 in case of error
 */
int vethCreate(char* veth1, int veth1MaxLen,
               char* veth2, int veth2MaxLen)
{
    int rc;
    const char *argv[] = {
        "ip", "link", "add", veth1, "type", "veth", "peer", "name", veth2, NULL
    };
    int cmdResult = 0;
    int vethDev = 0;

    DEBUG("veth1: %s veth2: %s", veth1, veth2);

    while ((1 > strlen(veth1)) || STREQ(veth1, veth2)) {
        vethDev = getFreeVethName(veth1, veth1MaxLen, 0);
        ++vethDev;
        DEBUG("Assigned veth1: %s", veth1);
    }

    while ((1 > strlen(veth2)) || STREQ(veth1, veth2)) {
        vethDev = getFreeVethName(veth2, veth2MaxLen, vethDev);
        ++vethDev;
        DEBUG("Assigned veth2: %s", veth2);
    }

    DEBUG("veth1: %s veth2: %s", veth1, veth2);
    rc = virRun(argv, &cmdResult);

    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        vethError(VIR_ERR_INTERNAL_ERROR,
                  _("Failed to create veth device pair '%s', '%s': %d"),
                  veth1, veth2, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    return rc;
}

/**
 * vethDelete:
 * @veth: name for one end of veth pair
 *
 * This will delete both veth devices in a pair.  Only one end needs to
 * be specified.  The ip command will identify and delete the other veth
 * device as well.
 * ip link del veth
 *
 * Returns 0 on success or -1 in case of error
 */
int vethDelete(const char *veth)
{
    int rc;
    const char *argv[] = {"ip", "link", "del", veth, NULL};
    int cmdResult = 0;

    DEBUG("veth: %s", veth);

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

/**
 * vethInterfaceUpOrDown:
 * @veth: name of veth device
 * @upOrDown: 0 => down, 1 => up
 *
 * Enables a veth device using the ifconfig command.  A NULL inetAddress
 * will cause it to be left off the command line.
 *
 * Returns 0 on success or -1 in case of error
 */
int vethInterfaceUpOrDown(const char* veth, int upOrDown)
{
    int rc;
    const char *argv[] = {"ifconfig", veth, NULL, NULL};
    int cmdResult = 0;

    if (0 == upOrDown)
        argv[2] = "down";
    else
        argv[2] = "up";

    rc = virRun(argv, &cmdResult);

    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        if (0 == upOrDown)
            /*
             * Prevent overwriting an error log which may be set
             * where an actual failure occurs.
             */
            VIR_DEBUG("Failed to disable '%s' (%d)",
                      veth, WEXITSTATUS(cmdResult));
        else
            vethError(VIR_ERR_INTERNAL_ERROR,
                      _("Failed to enable '%s' (%d)"),
                      veth, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    return rc;
}

/**
 * moveInterfaceToNetNs:
 * @iface: name of device
 * @pidInNs: PID of process in target net namespace
 *
 * Moves the given device into the target net namespace specified by the given
 * pid using this command:
 *     ip link set @iface netns @pidInNs
 *
 * Returns 0 on success or -1 in case of error
 */
int moveInterfaceToNetNs(const char* iface, int pidInNs)
{
    int rc;
    char *pid = NULL;
    const char *argv[] = {
        "ip", "link", "set", iface, "netns", NULL, NULL
    };
    int cmdResult = 0;

    if (virAsprintf(&pid, "%d", pidInNs) == -1) {
        virReportOOMError();
        return -1;
    }

    argv[5] = pid;
    rc = virRun(argv, &cmdResult);
    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        vethError(VIR_ERR_INTERNAL_ERROR,
                  _("Failed to move '%s' into NS(pid=%d) (%d)"),
                  iface, pidInNs, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    VIR_FREE(pid);
    return rc;
}

/**
 * setMacAddr
 * @iface: name of device
 * @macaddr: MAC address to be assigned
 *
 * Changes the MAC address of the given device with the
 * given address using this command:
 *     ip link set @iface address @macaddr
 *
 * Returns 0 on success or -1 in case of error
 */
int setMacAddr(const char* iface, const char* macaddr)
{
    int rc;
    const char *argv[] = {
        "ip", "link", "set", iface, "address", macaddr, NULL
    };
    int cmdResult = 0;

    rc = virRun(argv, &cmdResult);
    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        vethError(VIR_ERR_INTERNAL_ERROR,
                  _("Failed to set '%s' to '%s' (%d)"),
                  macaddr, iface, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    return rc;
}

/**
 * setInterfaceName
 * @iface: name of device
 * @new: new name of @iface
 *
 * Changes the name of the given device with the
 * given new name using this command:
 *     ip link set @iface name @new
 *
 * Returns 0 on success or -1 in case of error
 */
int setInterfaceName(const char* iface, const char* new)
{
    int rc;
    const char *argv[] = {
        "ip", "link", "set", iface, "name", new, NULL
    };
    int cmdResult = 0;

    rc = virRun(argv, &cmdResult);
    if (rc != 0 ||
        (WIFEXITED(cmdResult) && WEXITSTATUS(cmdResult) != 0)) {
        vethError(VIR_ERR_INTERNAL_ERROR,
                  _("Failed to set '%s' to '%s' (%d)"),
                  new, iface, WEXITSTATUS(cmdResult));
        rc = -1;
    }

    return rc;
}
