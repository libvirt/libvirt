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
# include <sys/mount.h>
#endif /* __linux__ */

#include "internal.h"

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "viralloc.h"
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
VIR_ENUM_IMPL(virCgroupV2Controller,
              VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "io", "net_cls", "perf_event", "name=systemd",
);

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

    if (STREQ(tmp, "/emulator")) {
        *tmp = '\0';

        if (!(tmp = strrchr(group->unified.placement, '/')))
            return false;
    }
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
virCgroupV2ParseControllersFile(virCgroupPtr group,
                                virCgroupPtr parent)
{
    int rc;
    VIR_AUTOFREE(char *) contStr = NULL;
    VIR_AUTOFREE(char *) contFile = NULL;
    char **contList = NULL;
    char **tmp;

    if (parent) {
        if (virAsprintf(&contFile, "%s%s/cgroup.subtree_control",
                        parent->unified.mountPoint,
                        NULLSTR_EMPTY(parent->unified.placement)) < 0)
            return -1;
    } else {
        if (virAsprintf(&contFile, "%s%s/cgroup.controllers",
                        group->unified.mountPoint,
                        NULLSTR_EMPTY(group->unified.placement)) < 0)
            return -1;
    }

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
                             int controllers,
                             virCgroupPtr parent)
{
    size_t i;

    if (virCgroupV2ParseControllersFile(group, parent) < 0)
        return -1;

    /* In cgroup v2 there is no cpuacct controller, the cpu.stat file always
     * exists with usage stats. */
    group->unified.controllers |= 1 << VIR_CGROUP_CONTROLLER_CPUACCT;

    if (controllers >= 0)
        group->unified.controllers &= controllers;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++)
        VIR_DEBUG("Controller '%s' present=%s",
                  virCgroupV2ControllerTypeToString(i),
                  (group->unified.controllers & 1 << i) ? "yes" : "no");

    return group->unified.controllers;
}


static bool
virCgroupV2HasController(virCgroupPtr group,
                         int controller)
{
    return group->unified.controllers & (1 << controller);
}


static int
virCgroupV2GetAnyController(virCgroupPtr group)
{
    /* The least significant bit is position 1. */
    return ffs(group->unified.controllers) - 1;
}


static int
virCgroupV2PathOfController(virCgroupPtr group,
                            int controller,
                            const char *key,
                            char **path)
{
    if (!virCgroupV2HasController(group, controller)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v2 controller '%s' is not available"),
                       virCgroupV2ControllerTypeToString(controller));
        return -1;
    }

    if (virAsprintf(path, "%s%s/%s",
                    group->unified.mountPoint,
                    group->unified.placement,
                    NULLSTR_EMPTY(key)) < 0)
        return -1;

    return 0;
}


/**
 * virCgroupV2EnableController:
 *
 * Returns: -1 on fatal error
 *          -2 if we failed to write into cgroup.subtree_control
 *          0 on success
 */
static int
virCgroupV2EnableController(virCgroupPtr group,
                            virCgroupPtr parent,
                            int controller,
                            bool report)
{
    VIR_AUTOFREE(char *) val = NULL;
    VIR_AUTOFREE(char *) path = NULL;

    if (virAsprintf(&val, "+%s",
                    virCgroupV2ControllerTypeToString(controller)) < 0) {
        return -1;
    }

    if (virCgroupPathOfController(parent, controller,
                                  "cgroup.subtree_control", &path) < 0) {
        return -1;
    }

    if (virFileWriteStr(path, val, 0) < 0) {
        if (report) {
            virReportSystemError(errno,
                                 _("Failed to enable controller '%s' for '%s'"),
                                 val, path);
        }
        return -2;
    }

    group->unified.controllers |= 1 << controller;

    return 0;
}


static int
virCgroupV2MakeGroup(virCgroupPtr parent,
                     virCgroupPtr group,
                     bool create,
                     unsigned int flags)
{
    VIR_AUTOFREE(char *) path = NULL;
    int controller;

    if (flags & VIR_CGROUP_SYSTEMD) {
        VIR_DEBUG("Running with systemd so we should not create cgroups ourselves.");
        return 0;
    }

    VIR_DEBUG("Make group %s", group->path);

    controller = virCgroupV2GetAnyController(group);
    if (virCgroupV2PathOfController(group, controller, "", &path) < 0)
        return -1;

    VIR_DEBUG("Make controller %s", path);

    if (!virFileExists(path) &&
        (!create || (mkdir(path, 0755) < 0 && errno != EEXIST))) {
        virReportSystemError(errno, _("Failed to create v2 cgroup '%s'"),
                             group->path);
        return -1;
    }

    if (create) {
        if (flags & VIR_CGROUP_THREAD) {
            if (virCgroupSetValueStr(group, controller,
                                     "cgroup.type", "threaded") < 0) {
                return -1;
            }

            if (virCgroupV2HasController(parent, VIR_CGROUP_CONTROLLER_CPU) &&
                virCgroupV2EnableController(group, parent,
                                            VIR_CGROUP_CONTROLLER_CPU,
                                            true) < 0) {
                return -1;
            }

            if (virCgroupV2HasController(parent, VIR_CGROUP_CONTROLLER_CPUSET) &&
                virCgroupV2EnableController(group, parent,
                                            VIR_CGROUP_CONTROLLER_CPUSET,
                                            true) < 0) {
                return -1;
            }
        } else {
            size_t i;
            for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
                int rc;

                if (!virCgroupV2HasController(parent, i))
                    continue;

                /* Controllers that are implicitly enabled if available. */
                if (i == VIR_CGROUP_CONTROLLER_CPUACCT)
                    continue;

                rc = virCgroupV2EnableController(group, parent, i, false);
                if (rc < 0) {
                    if (rc == -2) {
                        virResetLastError();
                        VIR_DEBUG("failed to enable '%s' controller, skipping",
                                  virCgroupV2ControllerTypeToString(i));
                        group->unified.controllers &= ~(1 << i);
                        continue;
                    }
                    return -1;
                }
            }
        }
    }

    return 0;
}


static int
virCgroupV2Remove(virCgroupPtr group)
{
    VIR_AUTOFREE(char *) grppath = NULL;
    int controller;

    /* Don't delete the root group, if we accidentally
       ended up in it for some reason */
    if (STREQ(group->unified.placement, "/"))
        return 0;

    controller = virCgroupV2GetAnyController(group);
    if (virCgroupV2PathOfController(group, controller, "", &grppath) < 0)
        return 0;

    return virCgroupRemoveRecursively(grppath);
}


static int
virCgroupV2AddTask(virCgroupPtr group,
                   pid_t pid,
                   unsigned int flags)
{
    int controller = virCgroupV2GetAnyController(group);

    if (flags & VIR_CGROUP_TASK_THREAD)
        return virCgroupSetValueI64(group, controller, "cgroup.threads", pid);
    else
        return virCgroupSetValueI64(group, controller, "cgroup.procs", pid);
}


static int
virCgroupV2HasEmptyTasks(virCgroupPtr cgroup,
                         int controller)
{
    int ret = -1;
    VIR_AUTOFREE(char *) content = NULL;

    ret = virCgroupGetValueStr(cgroup, controller, "cgroup.procs", &content);

    if (ret == 0 && content[0] == '\0')
        ret = 1;

    return ret;
}


static int
virCgroupV2KillRecursive(virCgroupPtr group,
                         int signum,
                         virHashTablePtr pids)
{
    int controller = virCgroupV2GetAnyController(group);

    if (controller < 0)
        return -1;

    return virCgroupKillRecursiveInternal(group, signum, pids, controller,
                                          "cgroup.threads", false);
}


static int
virCgroupV2BindMount(virCgroupPtr group,
                     const char *oldroot,
                     const char *mountopts)
{
    VIR_AUTOFREE(char *) opts = NULL;
    VIR_AUTOFREE(char *) src = NULL;

    VIR_DEBUG("Mounting cgroups at '%s'", group->unified.mountPoint);

    if (virFileMakePath(group->unified.mountPoint) < 0) {
        virReportSystemError(errno, _("Unable to create directory %s"),
                             group->unified.mountPoint);
        return -1;
    }

    if (virAsprintf(&opts, "mode=755,size=65536%s", mountopts) < 0)
        return -1;

    if (virAsprintf(&src, "%s%s", oldroot, group->unified.mountPoint) < 0)
        return -1;

    if (mount(src, group->unified.mountPoint, "none", MS_BIND, NULL) < 0) {
        virReportSystemError(errno, _("Failed to bind cgroup '%s' on '%s'"),
                             src, group->unified.mountPoint);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetOwner(virCgroupPtr cgroup,
                    uid_t uid,
                    gid_t gid,
                    int controllers ATTRIBUTE_UNUSED)
{
    VIR_AUTOFREE(char *) base = NULL;

    if (virAsprintf(&base, "%s%s", cgroup->unified.mountPoint,
                    cgroup->unified.placement) < 0) {
        return -1;
    }

    if (virFileChownFiles(base, uid, gid) < 0)
        return -1;

    if (chown(base, uid, gid) < 0) {
        virReportSystemError(errno, _("cannot chown '%s' to (%u, %u)"),
                             base, uid, gid);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetBlkioWeight(virCgroupPtr group,
                          unsigned int weight)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    const char *format = "%u";

    if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "io.bfq.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        VIR_FREE(path);
        format = "default %u";

        if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                        "io.weight", &path) < 0) {
            return -1;
        }
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio weight is valid only for bfq or cfq scheduler"));
        return -1;
    }

    if (virAsprintf(&value, format, weight) < 0)
        return -1;

    return virCgroupSetValueRaw(path, value);
}


static int
virCgroupV2GetBlkioWeight(virCgroupPtr group,
                          unsigned int *weight)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    char *tmp;

    if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "io.bfq.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        VIR_FREE(path);

        if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                        "io.weight", &path) < 0) {
            return -1;
        }
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio weight is valid only for bfq or cfq scheduler"));
        return -1;
    }

    if (virCgroupGetValueRaw(path, &value) < 0)
        return -1;

    if ((tmp = strstr(value, "default "))) {
        tmp += strlen("default ");
    } else {
        tmp = value;
    }

    if (virStrToLong_ui(tmp, &tmp, 10, weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       tmp);
        return -1;
    }

    return 0;
}


static int
virCgroupV2GetBlkioIoServiced(virCgroupPtr group,
                              long long *bytes_read,
                              long long *bytes_write,
                              long long *requests_read,
                              long long *requests_write)
{
    long long stats_val;
    VIR_AUTOFREE(char *) str1 = NULL;
    char *p1;
    size_t i;

    const char *value_names[] = {
        "rbytes=",
        "wbytes=",
        "rios=",
        "wios=",
    };
    long long *value_ptrs[] = {
        bytes_read,
        bytes_write,
        requests_read,
        requests_write
    };

    *bytes_read = 0;
    *bytes_write = 0;
    *requests_read = 0;
    *requests_write = 0;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.stat", &str1) < 0) {
        return -1;
    }

    /* sum up all entries of the same kind, from all devices */
    for (i = 0; i < ARRAY_CARDINALITY(value_names); i++) {
        p1 = str1;

        while ((p1 = strstr(p1, value_names[i]))) {
            p1 += strlen(value_names[i]);
            if (virStrToLong_ll(p1, &p1, 10, &stats_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse byte '%s' stat '%s'"),
                               value_names[i], p1);
                return -1;
            }

            if (stats_val < 0 ||
                (stats_val > 0 && *value_ptrs[i] > (LLONG_MAX - stats_val))) {
                virReportError(VIR_ERR_OVERFLOW,
                               _("Sum of byte '%s' stat overflows"),
                               value_names[i]);
                return -1;
            }
            *value_ptrs[i] += stats_val;
        }
    }

    return 0;
}


static int
virCgroupV2GetBlkioIoDeviceServiced(virCgroupPtr group,
                                    const char *path,
                                    long long *bytes_read,
                                    long long *bytes_write,
                                    long long *requests_read,
                                    long long *requests_write)
{
    VIR_AUTOFREE(char *) str1 = NULL;
    VIR_AUTOFREE(char *) str2 = NULL;
    char *p1;
    size_t i;

    const char *value_names[] = {
        "rbytes=",
        "wbytes=",
        "rios=",
        "wios=",
    };
    long long *value_ptrs[] = {
        bytes_read,
        bytes_write,
        requests_read,
        requests_write
    };

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.stat", &str1) < 0) {
        return -1;
    }

    if (!(str2 = virCgroupGetBlockDevString(path)))
        return -1;

    if (!(p1 = strstr(str1, str2))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find byte stats for block device '%s'"),
                       str2);
        return -1;
    }

    for (i = 0; i < ARRAY_CARDINALITY(value_names); i++) {
        if (!(p1 = strstr(p1, value_names[i]))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find byte '%s' stats for block device '%s'"),
                           value_names[i], str2);
            return -1;
        }

        p1 += strlen(value_names[i]);
        if (virStrToLong_ll(p1, &p1, 10, value_ptrs[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse '%s' stat '%s'"),
                           value_names[i], p1);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWeight(virCgroupPtr group,
                                const char *devPath,
                                unsigned int weight)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(devPath)))
        return -1;

    if (virAsprintf(&str, "%s%d", blkstr, weight) < 0)
        return -1;

    if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "io.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio device weight is valid only for cfq scheduler"));
        return -1;
    }

    return virCgroupSetValueRaw(path, str);
}


static int
virCgroupV2GetBlkioDeviceWeight(virCgroupPtr group,
                                const char *devPath,
                                unsigned int *weight)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    char *tmp;

    if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "io.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio device weight is valid only for cfq scheduler"));
        return -1;
    }

    if (virCgroupGetValueRaw(path, &value) < 0)
        return -1;

    if (virCgroupGetValueForBlkDev(value, devPath, &str) < 0)
        return -1;

    if (!str) {
        *weight = 0;
    } else if (virStrToLong_ui(str, &tmp, 10, weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceReadIops(virCgroupPtr group,
                                  const char *path,
                                  unsigned int riops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (riops == 0) {
        if (virAsprintf(&str, "%sriops=max", blkstr) < 0)
            return -1;
    } else {
        if (virAsprintf(&str, "%sriops=%u", blkstr, riops) < 0)
            return -1;
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceReadIops(virCgroupPtr group,
                                  const char *path,
                                  unsigned int *riops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    const char *name = "riops=";
    char *tmp;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.max",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *riops = 0;
    } else {
        if (!(tmp = strstr(str, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find '%s' limit for block device '%s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STREQLEN(tmp, "max", 3)) {
            *riops = 0;
        } else if (virStrToLong_ui(tmp, &tmp, 10, riops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWriteIops(virCgroupPtr group,
                                   const char *path,
                                   unsigned int wiops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (wiops == 0) {
        if (virAsprintf(&str, "%swiops=max", blkstr) < 0)
            return -1;
    } else {
        if (virAsprintf(&str, "%swiops=%u", blkstr, wiops) < 0)
            return -1;
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceWriteIops(virCgroupPtr group,
                                   const char *path,
                                   unsigned int *wiops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    const char *name = "wiops=";
    char *tmp;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.max",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *wiops = 0;
    } else {
        if (!(tmp = strstr(str, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find '%s' limit for block device '%s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STREQLEN(tmp, "max", 3)) {
            *wiops = 0;
        } else if (virStrToLong_ui(tmp, &tmp, 10, wiops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceReadBps(virCgroupPtr group,
                                 const char *path,
                                 unsigned long long rbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (rbps == 0) {
        if (virAsprintf(&str, "%srbps=max", blkstr) < 0)
            return -1;
    } else {
        if (virAsprintf(&str, "%srbps=%llu", blkstr, rbps) < 0)
            return -1;
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceReadBps(virCgroupPtr group,
                                 const char *path,
                                 unsigned long long *rbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    const char *name = "rbps=";
    char *tmp;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.max",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *rbps = 0;
    } else {
        if (!(tmp = strstr(str, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find '%s' limit for block device '%s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STREQLEN(tmp, "max", 3)) {
            *rbps = 0;
        } else if (virStrToLong_ull(tmp, &tmp, 10, rbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWriteBps(virCgroupPtr group,
                                  const char *path,
                                  unsigned long long wbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (wbps == 0) {
        if (virAsprintf(&str, "%swbps=max", blkstr) < 0)
            return -1;
    } else {
        if (virAsprintf(&str, "%swbps=%llu", blkstr, wbps) < 0)
            return -1;
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceWriteBps(virCgroupPtr group,
                                  const char *path,
                                  unsigned long long *wbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) value = NULL;
    const char *name = "wbps=";
    char *tmp;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "io.max",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *wbps = 0;
    } else {
        if (!(tmp = strstr(str, name))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find '%s' limit for block device '%s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STREQLEN(tmp, "max", 3)) {
            *wbps = 0;
        } else if (virStrToLong_ull(tmp, &tmp, 10, wbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetMemory(virCgroupPtr group,
                     unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb) {
        return virCgroupSetValueStr(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.max",
                                    "max");
    } else {
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.max",
                                    kb << 10);
    }
}


static int
virCgroupV2GetMemoryStat(virCgroupPtr group,
                         unsigned long long *cache,
                         unsigned long long *activeAnon,
                         unsigned long long *inactiveAnon,
                         unsigned long long *activeFile,
                         unsigned long long *inactiveFile,
                         unsigned long long *unevictable)
{
    VIR_AUTOFREE(char *) stat = NULL;
    char *line = NULL;
    unsigned long long cacheVal = 0;
    unsigned long long activeAnonVal = 0;
    unsigned long long inactiveAnonVal = 0;
    unsigned long long activeFileVal = 0;
    unsigned long long inactiveFileVal = 0;
    unsigned long long unevictableVal = 0;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.stat",
                             &stat) < 0) {
        return -1;
    }

    line = stat;

    while (*line) {
        char *newLine = strchr(line, '\n');
        char *valueStr = strchr(line, ' ');
        unsigned long long value;

        if (newLine)
            *newLine = '\0';

        if (!valueStr) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Cannot parse 'memory.stat' cgroup file."));
            return -1;
        }
        *valueStr = '\0';

        if (virStrToLong_ull(valueStr + 1, NULL, 10, &value) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%s' as an integer"),
                           valueStr + 1);
            return -1;
        }

        if (STREQ(line, "file"))
            cacheVal = value >> 10;
        else if (STREQ(line, "active_anon"))
            activeAnonVal = value >> 10;
        else if (STREQ(line, "inactive_anon"))
            inactiveAnonVal = value >> 10;
        else if (STREQ(line, "active_file"))
            activeFileVal = value >> 10;
        else if (STREQ(line, "inactive_file"))
            inactiveFileVal = value >> 10;
        else if (STREQ(line, "unevictable"))
            unevictableVal = value >> 10;

        if (newLine)
            line = newLine + 1;
        else
            break;
    }

    *cache = cacheVal;
    *activeAnon = activeAnonVal;
    *inactiveAnon = inactiveAnonVal;
    *activeFile = activeFileVal;
    *inactiveFile = inactiveFileVal;
    *unevictable = unevictableVal;

    return 0;
}


static int
virCgroupV2GetMemoryUsage(virCgroupPtr group,
                          unsigned long *kb)
{
    unsigned long long usage_in_bytes;
    int ret = virCgroupGetValueU64(group,
                                   VIR_CGROUP_CONTROLLER_MEMORY,
                                   "memory.current", &usage_in_bytes);
    if (ret == 0)
        *kb = (unsigned long) usage_in_bytes >> 10;
    return ret;
}


static int
virCgroupV2SetMemoryHardLimit(virCgroupPtr group,
                              unsigned long long kb)
{
    return virCgroupV2SetMemory(group, kb);
}


static int
virCgroupV2GetMemoryHardLimit(virCgroupPtr group,
                              unsigned long long *kb)
{
    VIR_AUTOFREE(char *) value = NULL;
    unsigned long long max;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.max", &value) < 0) {
        return -1;
    }

    if (STREQ(value, "max")) {
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 0;
    }

    if (virStrToLong_ull(value, NULL, 10, &max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."),
                       value);
        return -1;
    }

    *kb = max >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2SetMemorySoftLimit(virCgroupPtr group,
                              unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb) {
        return virCgroupSetValueStr(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.high",
                                    "max");
    } else {
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.high",
                                    kb << 10);
    }
}


static int
virCgroupV2GetMemorySoftLimit(virCgroupPtr group,
                              unsigned long long *kb)
{
    VIR_AUTOFREE(char *) value = NULL;
    unsigned long long high;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.high", &value) < 0)
        return -1;

    if (STREQ(value, "max")) {
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 0;
    }

    if (virStrToLong_ull(value, NULL, 10, &high) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."),
                       value);
        return -1;
    }

    *kb = high >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2SetMemSwapHardLimit(virCgroupPtr group,
                               unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb) {
        return virCgroupSetValueStr(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.swap.max",
                                    "max");
    } else {
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.swap.max",
                                    kb << 10);
    }
}


static int
virCgroupV2GetMemSwapHardLimit(virCgroupPtr group,
                               unsigned long long *kb)
{
    VIR_AUTOFREE(char *) value = NULL;
    unsigned long long max;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.swap.max", &value) < 0) {
        return -1;
    }

    if (STREQ(value, "max")) {
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
        return 0;
    }

    if (virStrToLong_ull(value, NULL, 10, &max) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."),
                       value);
        return -1;
    }

    *kb = max >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2GetMemSwapUsage(virCgroupPtr group,
                           unsigned long long *kb)
{
    unsigned long long usage_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.swap.current", &usage_in_bytes);
    if (ret == 0)
        *kb = (unsigned long) usage_in_bytes >> 10;
    return ret;
}


static int
virCgroupV2SetCpuShares(virCgroupPtr group,
                        unsigned long long shares)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.weight", shares);
}


static int
virCgroupV2GetCpuShares(virCgroupPtr group,
                        unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.weight", shares);
}


static int
virCgroupV2SetCpuCfsPeriod(virCgroupPtr group,
                           unsigned long long cfs_period)
{
    VIR_AUTOFREE(char *) value = NULL;
    VIR_AUTOFREE(char *) str = NULL;
    char *tmp;

    /* The cfs_period should be greater or equal than 1ms, and less or equal
     * than 1s.
     */
    if (cfs_period < 1000 || cfs_period > 1000000) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_period '%llu' must be in range (1000, 1000000)"),
                       cfs_period);
        return -1;
    }

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                             "cpu.max", &str) < 0) {
        return -1;
    }

    if (!(tmp = strchr(str, ' '))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid 'cpu.max' data."));
        return -1;
    }
    *tmp = '\0';

    if (virAsprintf(&value, "%s %llu", str, cfs_period) < 0)
        return -1;

    return virCgroupSetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.max", value);
}


static int
virCgroupV2GetCpuCfsPeriod(virCgroupPtr group,
                           unsigned long long *cfs_period)
{
    VIR_AUTOFREE(char *) str = NULL;
    char *tmp;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                             "cpu.max", &str) < 0) {
        return -1;
    }

    if (!(tmp = strchr(str, ' '))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid 'cpu.max' data."));
        return -1;
    }

    if (virStrToLong_ull(tmp, &tmp, 10, cfs_period) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' from cpu.max."), str);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetCpuCfsQuota(virCgroupPtr group,
                          long long cfs_quota)
{
    /* The cfs_quota should be greater or equal than 1ms */
    if (cfs_quota >= 0 &&
        (cfs_quota < 1000 ||
         cfs_quota > ULLONG_MAX / 1000)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_quota '%lld' must be in range (1000, %llu)"),
                       cfs_quota, ULLONG_MAX / 1000);
        return -1;
    }

    if (cfs_quota == ULLONG_MAX / 1000) {
        return virCgroupSetValueStr(group,
                                    VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.max", "max");
    }

    return virCgroupSetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.max", cfs_quota);
}


static int
virCgroupV2GetCpuCfsQuota(virCgroupPtr group,
                          long long *cfs_quota)
{
    VIR_AUTOFREE(char *) str = NULL;
    char *tmp;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                             "cpu.max", &str) < 0) {
        return -1;
    }

    if (STREQLEN(str, "max", 3)) {
        *cfs_quota = ULLONG_MAX / 1000;
        return 0;
    }

    if (virStrToLong_ll(str, &tmp, 10, cfs_quota) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' from cpu.max."), str);
        return -1;
    }

    return 0;
}


static bool
virCgroupV2SupportsCpuBW(virCgroupPtr cgroup)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (virCgroupV2PathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.max", &path) < 0) {
        virResetLastError();
        return false;
    }

    return virFileExists(path);
}


static int
virCgroupV2GetCpuacctUsage(virCgroupPtr group,
                           unsigned long long *usage)
{
    VIR_AUTOFREE(char *) str = NULL;
    char *tmp;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpu.stat", &str) < 0) {
        return -1;
    }

    if (!(tmp = strstr(str, "usage_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu usage stat '%s'"), str);
        return -1;
    }
    tmp += strlen("usage_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, usage) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."), tmp);
        return -1;
    }

    *usage *= 1000;

    return 0;
}


static int
virCgroupV2GetCpuacctStat(virCgroupPtr group,
                          unsigned long long *user,
                          unsigned long long *sys)
{
    VIR_AUTOFREE(char *) str = NULL;
    char *tmp;
    unsigned long long userVal = 0;
    unsigned long long sysVal = 0;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpu.stat", &str) < 0) {
        return -1;
    }

    if (!(tmp = strstr(str, "user_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu user stat '%s'"), str);
        return -1;
    }
    tmp += strlen("user_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, &userVal) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."), tmp);
        return -1;
    }

    if (!(tmp = strstr(str, "system_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu sys stat '%s'"), str);
        return -1;
    }
    tmp += strlen("system_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, &sysVal) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%s' as number."), tmp);
        return -1;
    }

    *user = userVal * 1000;
    *sys = sysVal * 1000;

    return 0;
}


static int
virCgroupV2SetCpusetMems(virCgroupPtr group,
                         const char *mems)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV2GetCpusetMems(virCgroupPtr group,
                         char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV2SetCpusetMemoryMigrate(virCgroupPtr group ATTRIBUTE_UNUSED,
                                  bool migrate ATTRIBUTE_UNUSED)
{
    return 0;
}


static int
virCgroupV2GetCpusetMemoryMigrate(virCgroupPtr group ATTRIBUTE_UNUSED,
                                  bool *migrate)
{
    *migrate = true;
    return 0;
}


static int
virCgroupV2SetCpusetCpus(virCgroupPtr group,
                         const char *cpus)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


static int
virCgroupV2GetCpusetCpus(virCgroupPtr group,
                         char **cpus)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
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
    .hasController = virCgroupV2HasController,
    .getAnyController = virCgroupV2GetAnyController,
    .pathOfController = virCgroupV2PathOfController,
    .makeGroup = virCgroupV2MakeGroup,
    .remove = virCgroupV2Remove,
    .addTask = virCgroupV2AddTask,
    .hasEmptyTasks = virCgroupV2HasEmptyTasks,
    .killRecursive = virCgroupV2KillRecursive,
    .bindMount = virCgroupV2BindMount,
    .setOwner = virCgroupV2SetOwner,

    .setBlkioWeight = virCgroupV2SetBlkioWeight,
    .getBlkioWeight = virCgroupV2GetBlkioWeight,
    .getBlkioIoServiced = virCgroupV2GetBlkioIoServiced,
    .getBlkioIoDeviceServiced = virCgroupV2GetBlkioIoDeviceServiced,
    .setBlkioDeviceWeight = virCgroupV2SetBlkioDeviceWeight,
    .getBlkioDeviceWeight = virCgroupV2GetBlkioDeviceWeight,
    .setBlkioDeviceReadIops = virCgroupV2SetBlkioDeviceReadIops,
    .getBlkioDeviceReadIops = virCgroupV2GetBlkioDeviceReadIops,
    .setBlkioDeviceWriteIops = virCgroupV2SetBlkioDeviceWriteIops,
    .getBlkioDeviceWriteIops = virCgroupV2GetBlkioDeviceWriteIops,
    .setBlkioDeviceReadBps = virCgroupV2SetBlkioDeviceReadBps,
    .getBlkioDeviceReadBps = virCgroupV2GetBlkioDeviceReadBps,
    .setBlkioDeviceWriteBps = virCgroupV2SetBlkioDeviceWriteBps,
    .getBlkioDeviceWriteBps = virCgroupV2GetBlkioDeviceWriteBps,

    .setMemory = virCgroupV2SetMemory,
    .getMemoryStat = virCgroupV2GetMemoryStat,
    .getMemoryUsage = virCgroupV2GetMemoryUsage,
    .setMemoryHardLimit = virCgroupV2SetMemoryHardLimit,
    .getMemoryHardLimit = virCgroupV2GetMemoryHardLimit,
    .setMemorySoftLimit = virCgroupV2SetMemorySoftLimit,
    .getMemorySoftLimit = virCgroupV2GetMemorySoftLimit,
    .setMemSwapHardLimit = virCgroupV2SetMemSwapHardLimit,
    .getMemSwapHardLimit = virCgroupV2GetMemSwapHardLimit,
    .getMemSwapUsage = virCgroupV2GetMemSwapUsage,

    .setCpuShares = virCgroupV2SetCpuShares,
    .getCpuShares = virCgroupV2GetCpuShares,
    .setCpuCfsPeriod = virCgroupV2SetCpuCfsPeriod,
    .getCpuCfsPeriod = virCgroupV2GetCpuCfsPeriod,
    .setCpuCfsQuota = virCgroupV2SetCpuCfsQuota,
    .getCpuCfsQuota = virCgroupV2GetCpuCfsQuota,
    .supportsCpuBW = virCgroupV2SupportsCpuBW,

    .getCpuacctUsage = virCgroupV2GetCpuacctUsage,
    .getCpuacctStat = virCgroupV2GetCpuacctStat,

    .setCpusetMems = virCgroupV2SetCpusetMems,
    .getCpusetMems = virCgroupV2GetCpusetMems,
    .setCpusetMemoryMigrate = virCgroupV2SetCpusetMemoryMigrate,
    .getCpusetMemoryMigrate = virCgroupV2GetCpusetMemoryMigrate,
    .setCpusetCpus = virCgroupV2SetCpusetCpus,
    .getCpusetCpus = virCgroupV2GetCpusetCpus,
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
