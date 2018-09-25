/*
 * vircgroupv2.c: methods for cgroups v2 backend
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#ifdef __linux__
# include <mntent.h>
#endif /* __linux__ */

#include "internal.h"

#define __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__
#include "vircgrouppriv.h"
#undef __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__

#include "vircgroup.h"
#include "vircgroupbackend.h"
#include "vircgroupv2.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virsystemd.h"

VIR_LOG_INIT("util.cgroup");

#define VIR_FROM_THIS VIR_FROM_CGROUP

VIR_ENUM_DECL(virCgroupV2Controller);
VIR_ENUM_IMPL(virCgroupV2Controller, VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "io", "net_cls", "perf_event", "name=systemd");

#ifdef __linux__

/* We're looking for one 'cgroup2' fs mount which has some
 * controllers enabled. */
static bool
virCgroupV2Available(void)
{
    bool ret = false;
    FILE *mounts = NULL;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];

    if (!(mounts = fopen("/proc/mounts", "r")))
        return false;

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        VIR_AUTOFREE(char *) contFile = NULL;
        VIR_AUTOFREE(char *) contStr = NULL;

        if (STRNEQ(entry.mnt_type, "cgroup2"))
            continue;

        /* Systemd uses cgroup v2 for process tracking but no controller is
         * available. We should consider this configuration as cgroup v2 is
         * not available. */
        if (virAsprintf(&contFile, "%s/cgroup.controllers", entry.mnt_dir) < 0)
            goto cleanup;

        if (virFileReadAll(contFile, 1024 * 1024, &contStr) < 0)
            goto cleanup;

        if (STREQ(contStr, ""))
            continue;

        ret = true;
        break;
    }

 cleanup:
    VIR_FORCE_FCLOSE(mounts);
    return ret;
}


static bool
virCgroupV2ValidateMachineGroup(virCgroupPtr group,
                                const char *name ATTRIBUTE_UNUSED,
                                const char *drivername,
                                const char *machinename)
{
    VIR_AUTOFREE(char *) partmachinename = NULL;
    VIR_AUTOFREE(char *) scopename = NULL;
    char *tmp;

    if (virAsprintf(&partmachinename, "%s.libvirt-%s", machinename,
                    drivername) < 0) {
        return false;
    }

    if (virCgroupPartitionEscape(&partmachinename) < 0)
        return false;

    if (!(scopename = virSystemdMakeScopeName(machinename, drivername,
                                              false))) {
        return false;
    }

    if (virCgroupPartitionEscape(&scopename) < 0)
        return false;

    if (!(tmp = strrchr(group->unified.placement, '/')))
        return false;
    tmp++;

    if (STRNEQ(tmp, partmachinename) &&
        STRNEQ(tmp, scopename)) {
        VIR_DEBUG("Name '%s' for unified does not match '%s' or '%s'",
                  tmp, partmachinename, scopename);
        return false;
    }

    return true;
}


static int
virCgroupV2CopyMounts(virCgroupPtr group,
                      virCgroupPtr parent)
{
    return VIR_STRDUP(group->unified.mountPoint, parent->unified.mountPoint);
}


static int
virCgroupV2CopyPlacement(virCgroupPtr group,
                         const char *path,
                         virCgroupPtr parent)
{
    if (path[0] == '/') {
        if (VIR_STRDUP(group->unified.placement, path) < 0)
            return -1;
    } else {
        /*
         * parent == "/" + path="" => "/"
         * parent == "/libvirt.service" + path == "" => "/libvirt.service"
         * parent == "/libvirt.service" + path == "foo" => "/libvirt.service/foo"
         */
        if (virAsprintf(&group->unified.placement, "%s%s%s",
                        parent->unified.placement,
                        (STREQ(parent->unified.placement, "/") ||
                         STREQ(path, "") ? "" : "/"),
                        path) < 0)
            return -1;
    }

    return 0;
}


static int
virCgroupV2DetectMounts(virCgroupPtr group,
                        const char *mntType,
                        const char *mntOpts ATTRIBUTE_UNUSED,
                        const char *mntDir)
{
    if (STRNEQ(mntType, "cgroup2"))
        return 0;

    VIR_FREE(group->unified.mountPoint);

    return VIR_STRDUP(group->unified.mountPoint, mntDir);
}


static int
virCgroupV2DetectPlacement(virCgroupPtr group,
                           const char *path,
                           const char *controllers ATTRIBUTE_UNUSED,
                           const char *selfpath)
{
    if (group->unified.placement)
        return 0;

    /*
     * selfpath == "/" + path="" -> "/"
     * selfpath == "/libvirt.service" + path == "" -> "/libvirt.service"
     * selfpath == "/libvirt.service" + path == "foo" -> "/libvirt.service/foo"
     */
    if (virAsprintf(&group->unified.placement,
                    "%s%s%s", selfpath,
                    (STREQ(selfpath, "/") ||
                     STREQ(path, "") ? "" : "/"),
                    path) < 0)
        return -1;

    return 0;
}


static int
virCgroupV2ValidatePlacement(virCgroupPtr group,
                             pid_t pid ATTRIBUTE_UNUSED)
{
    if (!group->unified.placement) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find placement for v2 controller"));
        return -1;
    }

    return 0;
}


static char *
virCgroupV2StealPlacement(virCgroupPtr group)
{
    char *ret;

    VIR_STEAL_PTR(ret, group->unified.placement);

    return ret;
}


static int
virCgroupV2ParseControllersFile(virCgroupPtr group)
{
    int rc;
    VIR_AUTOFREE(char *) contStr = NULL;
    VIR_AUTOFREE(char *) contFile = NULL;
    char **contList = NULL;
    char **tmp;

    if (virAsprintf(&contFile, "%s/cgroup.controllers",
                    group->unified.mountPoint) < 0)
        return -1;

    rc = virFileReadAll(contFile, 1024 * 1024, &contStr);
    if (rc < 0) {
        virReportSystemError(errno, _("Unable to read from '%s'"), contFile);
        return -1;
    }

    virTrimSpaces(contStr, NULL);

    contList = virStringSplit(contStr, " ", 20);
    if (!contList)
        return -1;

    tmp = contList;

    while (*tmp) {
        int type = virCgroupV2ControllerTypeFromString(*tmp);

        if (type >= 0)
            group->unified.controllers |= 1 << type;

        tmp++;
    }

    virStringListFree(contList);

    return 0;
}


static int
virCgroupV2DetectControllers(virCgroupPtr group,
                             int controllers)
{
    size_t i;

    if (virCgroupV2ParseControllersFile(group) < 0)
        return -1;

    /* In cgroup v2 there is no cpuacct controller, the cpu.stat file always
     * exists with usage stats. */
    group->unified.controllers |= 1 << VIR_CGROUP_CONTROLLER_CPUACCT;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++)
        VIR_DEBUG("Controller '%s' present=%s",
                  virCgroupV2ControllerTypeToString(i),
                  (group->unified.controllers & 1 << i) ? "yes" : "no");

    if (controllers >= 0)
        return controllers & group->unified.controllers;
    else
        return group->unified.controllers;
}


virCgroupBackend virCgroupV2Backend = {
    .type = VIR_CGROUP_BACKEND_TYPE_V2,

    .available = virCgroupV2Available,
    .validateMachineGroup = virCgroupV2ValidateMachineGroup,
    .copyMounts = virCgroupV2CopyMounts,
    .copyPlacement = virCgroupV2CopyPlacement,
    .detectMounts = virCgroupV2DetectMounts,
    .detectPlacement = virCgroupV2DetectPlacement,
    .validatePlacement = virCgroupV2ValidatePlacement,
    .stealPlacement = virCgroupV2StealPlacement,
    .detectControllers = virCgroupV2DetectControllers,
};


void
virCgroupV2Register(void)
{
    virCgroupBackendRegister(&virCgroupV2Backend);
}

#else /* !__linux__ */

void
virCgroupV2Register(void)
{
    VIR_INFO("Control groups not supported on this platform");
}

#endif /* !__linux__ */
