/*
 * virccw.c: helper APIs for managing host CCW devices
 *
 * Copyright (C) 2022 IBM Corporation
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

#include "virccw.h"

#include <dirent.h>

#include "virerror.h"
#include "virfile.h"
#include "virstring.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_NONE


bool
virCCWDeviceAddressIsValid(virCCWDeviceAddress *addr)
{
    return addr->cssid <= VIR_CCW_DEVICE_MAX_CSSID &&
           addr->ssid <= VIR_CCW_DEVICE_MAX_SSID &&
           addr->devno <= VIR_CCW_DEVICE_MAX_DEVNO;
}

bool
virCCWDeviceAddressEqual(virCCWDeviceAddress *addr1,
                         virCCWDeviceAddress *addr2)
{
    if (addr1->cssid == addr2->cssid &&
        addr1->ssid == addr2->ssid &&
        addr1->devno == addr2->devno) {
        return true;
    }
    return false;
}

char*
virCCWDeviceAddressAsString(virCCWDeviceAddress *addr)
{
    return g_strdup_printf(VIR_CCW_DEVICE_ADDRESS_FMT, addr->cssid, addr->ssid, addr->devno);
}

virCCWDeviceAddress *
virCCWDeviceAddressFromString(const char *address)
{
    g_autofree virCCWDeviceAddress *ccw = NULL;

    ccw = g_new0(virCCWDeviceAddress, 1);

    if (virCCWDeviceAddressParseFromString(address,
                                           &ccw->cssid,
                                           &ccw->ssid,
                                           &ccw->devno) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse CCW address '%1$s'"),
                       address);
        return NULL;
    }

    return g_steal_pointer(&ccw);
}

int
virCCWDeviceAddressIncrement(virCCWDeviceAddress *addr)
{
    virCCWDeviceAddress ccwaddr = *addr;

    /* We are not touching subchannel sets and channel subsystems */
    if (++ccwaddr.devno > VIR_CCW_DEVICE_MAX_DEVNO)
        return -1;

    *addr = ccwaddr;
    return 0;
}

int
virCCWDeviceAddressParseFromString(const char *address,
                                   unsigned int *cssid,
                                   unsigned int *ssid,
                                   unsigned int *devno)
{
    char *p;

    if (address == NULL || virStrToLong_ui(address, &p, 16, cssid) < 0 ||
        p == NULL || virStrToLong_ui(p + 1, &p, 16, ssid) < 0 ||
        p == NULL || virStrToLong_ui(p + 1, &p, 16, devno) < 0) {
        return -1;
    }

    return 0;
}

void
virCCWGroupMemberTypeFree(virCCWGroupMemberType *member)
{
    if (!member)
        return;

    VIR_FREE(member->ref);
    VIR_FREE(member->device);
    VIR_FREE(member);
}

static char *
virCCWGroupDeviceDevNodeName(const char *nodedev_prefix,
                             const char *sysfs_path)
{
    g_autofree char *node_name = NULL;
    size_t i;

    node_name = g_path_get_basename(sysfs_path);

    for (i = 0; i < strlen(node_name); i++) {
        if (!(g_ascii_isalnum(*(node_name + i))))
            *(node_name + i) = '_';
    }

    return g_strdup_printf("%s_%s", nodedev_prefix, node_name);
}

/**
 * virCCWGroupDeviceGetMembers:
 * @sysfs_path: sysfs path to a group device
 * @members:    Where to add the found group members
 * @nmembers:   Number of found group members
 *
 * The sysfs path is searched for links with a name prefix "cdev".
 * These links point the ccw device sysfs entry which is a member
 * of the ccw group.
 *
 * Returns: -1 on error (invalid sysfs_path or group has no members)
 *           0 on success
 */
int
virCCWGroupDeviceGetMembers(const char *sysfs_path,
                            virCCWGroupMemberType ***members,
                            size_t *nmembers)
{
    virCCWGroupMemberType *member = NULL;
    g_autofree char *ccwdevpath = NULL;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int direrr;

    if (virDirOpenIfExists(&dir, sysfs_path) <= 0)
        return -1;

    while ((direrr = virDirRead(dir, &entry, NULL)) > 0) {
        if (g_str_has_prefix(entry->d_name, "cdev")) {
            /* found a cdev reference */
            g_autofree char *cdevpath = NULL;
            cdevpath = g_build_filename(sysfs_path, entry->d_name, NULL);

            if (virFileIsLink(cdevpath) != 1)
                continue;

            if (virFileResolveLink(cdevpath, &ccwdevpath) < 0)
                continue;

            if (!virFileExists(ccwdevpath))
                continue;

            member = g_new0(virCCWGroupMemberType, 1);

            member->ref = g_strdup(entry->d_name);
            member->device = virCCWGroupDeviceDevNodeName("ccw", ccwdevpath);

            VIR_APPEND_ELEMENT(*members, *nmembers, member);
        }
    }

    /* Groups without a member must not exist */
    if (*nmembers == 0)
        return -1;

    return 0;
}

void
virCCWGroupTypeQethFree(virCCWGroupTypeQeth *qeth)
{
    if (!qeth)
        return;

    VIR_FREE(qeth->card_type);
    VIR_FREE(qeth->chpid);
}

char *
virCCWDeviceGetGroupDev(const char *sysfs_path)
{
    g_autofree char *ccwgroup_path = NULL;
    g_autofree char *group_dev_path = NULL;

    group_dev_path = g_build_filename(sysfs_path, "group_device", NULL);

    if (!virFileExists(group_dev_path))
        return NULL;

    if (virFileIsLink(group_dev_path) != 1)
        return NULL;

    if (virFileResolveLink(group_dev_path, &ccwgroup_path) < 0)
        return NULL;

    if (!virFileExists(ccwgroup_path))
        return NULL;

    return virCCWGroupDeviceDevNodeName("ccwgroup", ccwgroup_path);
}
