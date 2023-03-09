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

#include <unistd.h>
#ifdef __linux__
# include <mntent.h>
# include <sys/mount.h>
#endif /* __linux__ */

#include "internal.h"

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "viralloc.h"
#include "virbpf.h"
#include "vircgroup.h"
#include "vircgroupbackend.h"
#include "vircgroupv2.h"
#include "vircgroupv2devices.h"
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
        g_autofree char *contFile = NULL;
        g_autofree char *contStr = NULL;

        if (STRNEQ(entry.mnt_type, "cgroup2"))
            continue;

        /* Systemd uses cgroup v2 for process tracking but no controller is
         * available. We should consider this configuration as cgroup v2 is
         * not available. */
        contFile = g_strdup_printf("%s/cgroup.controllers", entry.mnt_dir);

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
virCgroupV2ValidateMachineGroup(virCgroup *group,
                                const char *name G_GNUC_UNUSED,
                                const char *drivername,
                                const char *machinename)
{
    g_autofree char *partmachinename = NULL;
    g_autofree char *scopename = NULL;
    char *tmp;

    partmachinename = g_strdup_printf("%s.libvirt-%s", machinename, drivername);

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
virCgroupV2CopyMounts(virCgroup *group,
                      virCgroup *parent)
{
    group->unified.mountPoint = g_strdup(parent->unified.mountPoint);
    return 0;
}


static int
virCgroupV2CopyPlacement(virCgroup *group,
                         const char *path,
                         virCgroup *parent)
{
    bool delim = STREQ(parent->unified.placement, "/") || STREQ(path, "");

    VIR_DEBUG("group=%p path=%s parent=%p", group, path, parent);

    /*
     * parent == "/" + path="" => "/"
     * parent == "/libvirt.service" + path == "" => "/libvirt.service"
     * parent == "/libvirt.service" + path == "foo" => "/libvirt.service/foo"
     */
    group->unified.placement = g_strdup_printf("%s%s%s",
                                               parent->unified.placement,
                                               delim ? "" : "/",
                                               path);

    return 0;
}


static int
virCgroupV2DetectMounts(virCgroup *group,
                        const char *mntType,
                        const char *mntOpts G_GNUC_UNUSED,
                        const char *mntDir)
{
    if (STRNEQ(mntType, "cgroup2"))
        return 0;

    VIR_FREE(group->unified.mountPoint);

    group->unified.mountPoint = g_strdup(mntDir);
    return 0;
}


static int
virCgroupV2DetectPlacement(virCgroup *group,
                           const char *path,
                           const char *controllers,
                           const char *selfpath)
{
    g_autofree char *placement = g_strdup(selfpath);
    char *tmp = NULL;

    if (group->unified.placement)
        return 0;

    VIR_DEBUG("group=%p path=%s controllers=%s selfpath=%s",
              group, path, controllers, selfpath);

    /* controllers == "" indicates the cgroupv2 controller path */
    if (STRNEQ(controllers, ""))
        return 0;

    /* Running VM will have the main thread placed in emulator cgroup
     * but we need to get the main cgroup. */
    tmp = g_strrstr(placement, "/emulator");
    if (tmp)
        *tmp = '\0';

    /* On systemd we create a nested cgroup for some cgroup tasks
     * but the placement should point to the root cgroup. */
    tmp = g_strrstr(placement, "/libvirt");
    if (tmp)
        *tmp = '\0';

    /*
     * selfpath == "/" + path="" -> "/"
     * selfpath == "/libvirt.service" + path == "" -> "/libvirt.service"
     * selfpath == "/libvirt.service" + path == "foo" -> "/libvirt.service/foo"
     */
    group->unified.placement = g_strdup_printf("%s%s%s", placement,
                                               (STREQ(selfpath, "/") || STREQ(path, "") ? "" : "/"), path);

    return 0;
}


static int
virCgroupV2SetPlacement(virCgroup *group,
                        const char *path)
{
    group->unified.placement = g_strdup(path);

    return 0;
}


static int
virCgroupV2ValidatePlacement(virCgroup *group,
                             pid_t pid G_GNUC_UNUSED)
{
    if (!group->unified.placement) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find placement for v2 controller"));
        return -1;
    }

    return 0;
}


static char *
virCgroupV2StealPlacement(virCgroup *group)
{
    return g_steal_pointer(&group->unified.placement);
}


static int
virCgroupV2ParseControllersFile(virCgroup *group,
                                virCgroup *parent)
{
    int rc;
    g_autofree char *contStr = NULL;
    g_autofree char *contFile = NULL;
    g_auto(GStrv) contList = NULL;
    char **tmp;

    if (parent) {
        contFile = g_strdup_printf("%s%s/cgroup.controllers",
                                   parent->unified.mountPoint,
                                   NULLSTR_EMPTY(parent->unified.placement));
    } else {
        contFile = g_strdup_printf("%s%s/cgroup.controllers",
                                   group->unified.mountPoint,
                                   NULLSTR_EMPTY(group->unified.placement));
    }

    rc = virFileReadAll(contFile, 1024 * 1024, &contStr);
    if (rc < 0) {
        virReportSystemError(errno, _("Unable to read from '%1$s'"), contFile);
        return -1;
    }

    virTrimSpaces(contStr, NULL);

    contList = g_strsplit(contStr, " ", 20);
    if (!contList)
        return -1;

    tmp = contList;

    while (*tmp) {
        int type = virCgroupV2ControllerTypeFromString(*tmp);

        if (type >= 0)
            group->unified.controllers |= 1 << type;

        tmp++;
    }

    return 0;
}


static int
virCgroupV2DetectControllers(virCgroup *group,
                             int controllers,
                             virCgroup *parent,
                             int detected)
{
    size_t i;

    if (virCgroupV2ParseControllersFile(group, parent) < 0)
        return -1;

    /* In cgroup v2 there is no cpuacct controller, the cpu.stat file always
     * exists with usage stats. */
    group->unified.controllers |= 1 << VIR_CGROUP_CONTROLLER_CPUACCT;

    if (virCgroupV2DevicesAvailable(group))
        group->unified.controllers |= 1 << VIR_CGROUP_CONTROLLER_DEVICES;

    if (controllers >= 0)
        group->unified.controllers &= controllers;

    group->unified.controllers &= ~detected;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++)
        VIR_DEBUG("Controller '%s' present=%s",
                  virCgroupV2ControllerTypeToString(i),
                  (group->unified.controllers & 1 << i) ? "yes" : "no");

    return group->unified.controllers;
}


static bool
virCgroupV2HasController(virCgroup *group,
                         int controller)
{
    return group->unified.controllers & (1 << controller);
}


static int
virCgroupV2GetAnyController(virCgroup *group)
{
    /* The least significant bit is position 1. */
    return __builtin_ffs(group->unified.controllers) - 1;
}


static int
virCgroupV2PathOfController(virCgroup *group,
                            int controller,
                            const char *key,
                            char **path)
{
    if (!virCgroupV2HasController(group, controller)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v2 controller '%1$s' is not available"),
                       virCgroupV2ControllerTypeToString(controller));
        return -1;
    }

    *path = g_strdup_printf("%s%s/%s", group->unified.mountPoint,
                            group->unified.placement, NULLSTR_EMPTY(key));

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
virCgroupV2EnableController(virCgroup *group,
                            virCgroup *parent,
                            int controller,
                            bool report)
{
    g_autofree char *val = NULL;
    g_autofree char *path = NULL;

    val = g_strdup_printf("+%s", virCgroupV2ControllerTypeToString(controller));

    if (virCgroupPathOfController(parent, controller,
                                  "cgroup.subtree_control", &path) < 0) {
        return -1;
    }

    if (virFileWriteStr(path, val, 0) < 0) {
        if (report) {
            virReportSystemError(errno,
                                 _("Failed to enable controller '%1$s' for '%2$s'"),
                                 val, path);
        }
        return -2;
    }

    group->unified.controllers |= 1 << controller;

    return 0;
}


static int
virCgroupV2AddTask(virCgroup *group,
                   pid_t pid,
                   unsigned int flags);


static int
virCgroupV2MakeGroup(virCgroup *parent,
                     virCgroup *group,
                     bool create,
                     pid_t pid,
                     unsigned int flags)
{
    g_autofree char *path = NULL;
    int controller;

    if (flags & VIR_CGROUP_SYSTEMD) {
        VIR_DEBUG("Running with systemd so we should not create cgroups ourselves.");
        return 0;
    }

    controller = virCgroupV2GetAnyController(group);
    if (virCgroupV2PathOfController(group, controller, "", &path) < 0)
        return -1;

    VIR_DEBUG("Make controller %s", path);

    if (!virFileExists(path) &&
        (!create || (mkdir(path, 0755) < 0 && errno != EEXIST))) {
        virReportSystemError(errno, _("Failed to create v2 cgroup '%1$s'"),
                             path);
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

            if (pid > 0) {
                if (virCgroupV2AddTask(group, pid, VIR_CGROUP_TASK_PROCESS) < 0)
                    return -1;
            }

            for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
                int rc;

                if (!virCgroupV2HasController(parent, i))
                    continue;

                /* Controllers that are implicitly enabled if available. */
                if (i == VIR_CGROUP_CONTROLLER_CPUACCT ||
                    i == VIR_CGROUP_CONTROLLER_DEVICES) {
                    continue;
                }

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


static bool
virCgroupV2Exists(virCgroup *group)
{
    g_autofree char *path = NULL;
    int controller;

    controller = virCgroupV2GetAnyController(group);
    if (virCgroupV2PathOfController(group, controller, "", &path) < 0)
        return false;

    return virFileExists(path);
}


static int
virCgroupV2Remove(virCgroup *group)
{
    g_autofree char *grppath = NULL;
    virCgroup *parent = virCgroupGetNested(group);
    int controller;

    /* Don't delete the root group, if we accidentally
       ended up in it for some reason */
    if (STREQ(group->unified.placement, "/"))
        return 0;

    controller = virCgroupV2GetAnyController(group);
    if (virCgroupV2PathOfController(group, controller, "", &grppath) < 0)
        return 0;

    if (virCgroupV2DevicesCloseProg(parent) < 0)
        return -1;

    return virCgroupRemoveRecursively(grppath);
}


static int
virCgroupV2AddTask(virCgroup *group,
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
virCgroupV2HasEmptyTasks(virCgroup *cgroup,
                         int controller)
{
    int ret = -1;
    g_autofree char *content = NULL;

    ret = virCgroupGetValueStr(cgroup, controller, "cgroup.threads", &content);

    if (ret == 0 && content[0] == '\0')
        ret = 1;

    return ret;
}


static int
virCgroupV2KillRecursive(virCgroup *group,
                         int signum,
                         GHashTable *pids)
{
    return virCgroupKillRecursiveInternal(group, signum, pids,
                                          "cgroup.threads", false);
}


static int
virCgroupV2BindMount(virCgroup *group,
                     const char *oldroot,
                     const char *mountopts G_GNUC_UNUSED)
{
    g_autofree char *src = NULL;

    VIR_DEBUG("Mounting cgroups at '%s'", group->unified.mountPoint);

    if (g_mkdir_with_parents(group->unified.mountPoint, 0777) < 0) {
        virReportSystemError(errno, _("Unable to create directory %1$s"),
                             group->unified.mountPoint);
        return -1;
    }

    src = g_strdup_printf("%s%s", oldroot, group->unified.mountPoint);

    if (mount(src, group->unified.mountPoint, "none", MS_BIND, NULL) < 0) {
        virReportSystemError(errno, _("Failed to bind cgroup '%1$s' on '%2$s'"),
                             src, group->unified.mountPoint);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetOwner(virCgroup *cgroup,
                    uid_t uid,
                    gid_t gid,
                    int controllers G_GNUC_UNUSED)
{
    g_autofree char *base = NULL;

    base = g_strdup_printf("%s%s", cgroup->unified.mountPoint,
                           cgroup->unified.placement);

    if (virFileChownFiles(base, uid, gid) < 0)
        return -1;

    if (chown(base, uid, gid) < 0) {
        virReportSystemError(errno, _("cannot chown '%1$s' to (%2$u, %3$u)"),
                             base, uid, gid);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetBlkioWeight(virCgroup *group,
                          unsigned int weight)
{
    g_autofree char *path = NULL;
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

    if (group->unitName) {
        GVariant *value = g_variant_new("t", weight);

        return virCgroupSetValueDBus(group->unitName, "IOWeight", value);
    } else {
        g_autofree char *value = g_strdup_printf(format, weight);

        return virCgroupSetValueRaw(path, value);
    }
}


static int
virCgroupV2GetBlkioWeight(virCgroup *group,
                          unsigned int *weight)
{
    g_autofree char *path = NULL;
    g_autofree char *value = NULL;
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
                       _("Unable to parse '%1$s' as an integer"),
                       tmp);
        return -1;
    }

    return 0;
}


static int
virCgroupV2GetBlkioIoServiced(virCgroup *group,
                              long long *bytes_read,
                              long long *bytes_write,
                              long long *requests_read,
                              long long *requests_write)
{
    long long stats_val;
    g_autofree char *str1 = NULL;
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
    for (i = 0; i < G_N_ELEMENTS(value_names); i++) {
        p1 = str1;

        while ((p1 = strstr(p1, value_names[i]))) {
            p1 += strlen(value_names[i]);
            if (virStrToLong_ll(p1, &p1, 10, &stats_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse byte '%1$s' stat '%2$s'"),
                               value_names[i], p1);
                return -1;
            }

            if (stats_val < 0 ||
                (stats_val > 0 && *value_ptrs[i] > (LLONG_MAX - stats_val))) {
                virReportError(VIR_ERR_OVERFLOW,
                               _("Sum of byte '%1$s' stat overflows"),
                               value_names[i]);
                return -1;
            }
            *value_ptrs[i] += stats_val;
        }
    }

    return 0;
}


static int
virCgroupV2GetBlkioIoDeviceServiced(virCgroup *group,
                                    const char *path,
                                    long long *bytes_read,
                                    long long *bytes_write,
                                    long long *requests_read,
                                    long long *requests_write)
{
    g_autofree char *str1 = NULL;
    g_autofree char *str2 = NULL;
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
                       _("Cannot find byte stats for block device '%1$s'"),
                       str2);
        return -1;
    }

    for (i = 0; i < G_N_ELEMENTS(value_names); i++) {
        if (!(p1 = strstr(p1, value_names[i]))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find byte '%1$s' stats for block device '%2$s'"),
                           value_names[i], str2);
            return -1;
        }

        p1 += strlen(value_names[i]);
        if (virStrToLong_ll(p1, &p1, 10, value_ptrs[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse '%1$s' stat '%2$s'"),
                           value_names[i], p1);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWeight(virCgroup *group,
                                const char *devPath,
                                unsigned int weight)
{
    g_autofree char *path = NULL;

    if (virCgroupV2PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "io.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio device weight is valid only for cfq scheduler"));
        return -1;
    }

    if (group->unitName) {
        GVariant *value = NULL;

        value = g_variant_new_parsed("[(%s, uint64 %u)]", path, weight);

        return virCgroupSetValueDBus(group->unitName, "IODeviceWeight", value);
    } else {
        g_autofree char *str = NULL;
        g_autofree char *blkstr = NULL;

        if (!(blkstr = virCgroupGetBlockDevString(devPath)))
            return -1;

        str = g_strdup_printf("%s%d", blkstr, weight);

        return virCgroupSetValueRaw(path, str);
    }
}


static int
virCgroupV2GetBlkioDeviceWeight(virCgroup *group,
                                const char *devPath,
                                unsigned int *weight)
{
    g_autofree char *path = NULL;
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
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
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceReadIops(virCgroup *group,
                                  const char *path,
                                  unsigned int riops)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (riops == 0) {
        str = g_strdup_printf("%sriops=max", blkstr);
    } else {
        str = g_strdup_printf("%sriops=%u", blkstr, riops);
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceReadIops(virCgroup *group,
                                  const char *path,
                                  unsigned int *riops)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
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
                           _("Unable to find '%1$s' limit for block device '%2$s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STRPREFIX(tmp, "max")) {
            *riops = 0;
        } else if (virStrToLong_ui(tmp, &tmp, 10, riops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%1$s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWriteIops(virCgroup *group,
                                   const char *path,
                                   unsigned int wiops)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (wiops == 0) {
        str = g_strdup_printf("%swiops=max", blkstr);
    } else {
        str = g_strdup_printf("%swiops=%u", blkstr, wiops);
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceWriteIops(virCgroup *group,
                                   const char *path,
                                   unsigned int *wiops)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
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
                           _("Unable to find '%1$s' limit for block device '%2$s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STRPREFIX(tmp, "max")) {
            *wiops = 0;
        } else if (virStrToLong_ui(tmp, &tmp, 10, wiops) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%1$s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceReadBps(virCgroup *group,
                                 const char *path,
                                 unsigned long long rbps)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (rbps == 0) {
        str = g_strdup_printf("%srbps=max", blkstr);
    } else {
        str = g_strdup_printf("%srbps=%llu", blkstr, rbps);
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceReadBps(virCgroup *group,
                                 const char *path,
                                 unsigned long long *rbps)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
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
                           _("Unable to find '%1$s' limit for block device '%2$s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STRPREFIX(tmp, "max")) {
            *rbps = 0;
        } else if (virStrToLong_ull(tmp, &tmp, 10, rbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%1$s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetBlkioDeviceWriteBps(virCgroup *group,
                                  const char *path,
                                  unsigned long long wbps)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (wbps == 0) {
        str = g_strdup_printf("%swbps=max", blkstr);
    } else {
        str = g_strdup_printf("%swbps=%llu", blkstr, wbps);
    }

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "io.max",
                                str);
}


static int
virCgroupV2GetBlkioDeviceWriteBps(virCgroup *group,
                                  const char *path,
                                  unsigned long long *wbps)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
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
                           _("Unable to find '%1$s' limit for block device '%2$s'"),
                           name, path);
            return -1;
        }
        tmp += strlen(name);

        if (STRPREFIX(tmp, "max")) {
            *wbps = 0;
        } else if (virStrToLong_ull(tmp, &tmp, 10, wbps) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to parse '%1$s' as an integer"),
                           str);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2SetMemory(virCgroup *group,
                     unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
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
virCgroupV2GetMemoryStat(virCgroup *group,
                         unsigned long long *cache,
                         unsigned long long *activeAnon,
                         unsigned long long *inactiveAnon,
                         unsigned long long *activeFile,
                         unsigned long long *inactiveFile,
                         unsigned long long *unevictable)
{
    g_autofree char *stat = NULL;
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
                           _("Unable to parse '%1$s' as an integer"),
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
virCgroupV2GetMemoryUsage(virCgroup *group,
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
virCgroupV2SetMemoryHardLimit(virCgroup *group,
                              unsigned long long kb)
{
    return virCgroupV2SetMemory(group, kb);
}


static int
virCgroupV2GetMemoryHardLimit(virCgroup *group,
                              unsigned long long *kb)
{
    g_autofree char *value = NULL;
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
                       _("Failed to parse value '%1$s' as number."),
                       value);
        return -1;
    }

    *kb = max >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2SetMemorySoftLimit(virCgroup *group,
                              unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
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
virCgroupV2GetMemorySoftLimit(virCgroup *group,
                              unsigned long long *kb)
{
    g_autofree char *value = NULL;
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
                       _("Failed to parse value '%1$s' as number."),
                       value);
        return -1;
    }

    *kb = high >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2SetMemSwapHardLimit(virCgroup *group,
                               unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
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
virCgroupV2GetMemSwapHardLimit(virCgroup *group,
                               unsigned long long *kb)
{
    g_autofree char *value = NULL;
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
                       _("Failed to parse value '%1$s' as number."),
                       value);
        return -1;
    }

    *kb = max >> 10;
    if (*kb >= VIR_DOMAIN_MEMORY_PARAM_UNLIMITED)
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV2GetMemSwapUsage(virCgroup *group,
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
virCgroupV2SetCpuShares(virCgroup *group,
                        unsigned long long shares)
{
    if (shares < VIR_CGROUPV2_WEIGHT_MIN ||
        shares > VIR_CGROUPV2_WEIGHT_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("shares '%1$llu' must be in range [%2$llu, %3$llu]"),
                       shares,
                       VIR_CGROUPV2_WEIGHT_MIN,
                       VIR_CGROUPV2_WEIGHT_MAX);
        return -1;
    }

    if (group->unitName) {
        GVariant *value = g_variant_new("t", shares);

        return virCgroupSetValueDBus(group->unitName, "CPUWeight", value);
    } else {
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.weight", shares);
    }
}


static int
virCgroupV2GetCpuShares(virCgroup *group,
                        unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.weight", shares);
}


static int
virCgroupV2SetCpuCfsPeriod(virCgroup *group,
                           unsigned long long cfs_period)
{
    g_autofree char *value = NULL;
    g_autofree char *str = NULL;
    char *tmp;

    if (cfs_period < VIR_CGROUP_CPU_PERIOD_MIN ||
        cfs_period > VIR_CGROUP_CPU_PERIOD_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_period '%1$llu' must be in range (%2$llu, %3$llu)"),
                       VIR_CGROUP_CPU_PERIOD_MIN,
                       VIR_CGROUP_CPU_PERIOD_MAX,
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

    value = g_strdup_printf("%s %llu", str, cfs_period);

    return virCgroupSetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.max", value);
}


static int
virCgroupV2GetCpuCfsPeriod(virCgroup *group,
                           unsigned long long *cfs_period)
{
    g_autofree char *str = NULL;
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
                       _("Failed to parse value '%1$s' from cpu.max."), str);
        return -1;
    }

    return 0;
}


static int
virCgroupV2SetCpuCfsQuota(virCgroup *group,
                          long long cfs_quota)
{
    if (cfs_quota >= 0 &&
        (cfs_quota < VIR_CGROUP_CPU_QUOTA_MIN ||
         cfs_quota > VIR_CGROUP_CPU_QUOTA_MAX)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_quota '%1$lld' must be in range (%2$llu, %3$llu)"),
                       cfs_quota,
                       VIR_CGROUP_CPU_QUOTA_MIN,
                       VIR_CGROUP_CPU_QUOTA_MAX);
        return -1;
    }

    if (cfs_quota < 0 || cfs_quota == VIR_CGROUP_CPU_QUOTA_MAX) {
        return virCgroupSetValueStr(group,
                                    VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.max", "max");
    }

    return virCgroupSetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.max", cfs_quota);
}


static int
virCgroupV2GetCpuCfsQuota(virCgroup *group,
                          long long *cfs_quota)
{
    g_autofree char *str = NULL;
    char *tmp;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPU,
                             "cpu.max", &str) < 0) {
        return -1;
    }

    if (STRPREFIX(str, "max")) {
        *cfs_quota = VIR_CGROUP_CPU_QUOTA_MAX;
        return 0;
    }

    if (virStrToLong_ll(str, &tmp, 10, cfs_quota) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%1$s' from cpu.max."), str);
        return -1;
    }

    return 0;
}


static bool
virCgroupV2SupportsCpuBW(virCgroup *cgroup)
{
    g_autofree char *path = NULL;

    if (virCgroupV2PathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.max", &path) < 0) {
        virResetLastError();
        return false;
    }

    return virFileExists(path);
}


static int
virCgroupV2GetCpuacctUsage(virCgroup *group,
                           unsigned long long *usage)
{
    g_autofree char *str = NULL;
    char *tmp;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpu.stat", &str) < 0) {
        return -1;
    }

    if (!(tmp = strstr(str, "usage_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu usage stat '%1$s'"), str);
        return -1;
    }
    tmp += strlen("usage_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, usage) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%1$s' as number."), tmp);
        return -1;
    }

    *usage *= 1000;

    return 0;
}


static int
virCgroupV2GetCpuacctStat(virCgroup *group,
                          unsigned long long *user,
                          unsigned long long *sys)
{
    g_autofree char *str = NULL;
    char *tmp;
    unsigned long long userVal = 0;
    unsigned long long sysVal = 0;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpu.stat", &str) < 0) {
        return -1;
    }

    if (!(tmp = strstr(str, "user_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu user stat '%1$s'"), str);
        return -1;
    }
    tmp += strlen("user_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, &userVal) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%1$s' as number."), tmp);
        return -1;
    }

    if (!(tmp = strstr(str, "system_usec "))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot parse cpu sys stat '%1$s'"), str);
        return -1;
    }
    tmp += strlen("system_usec ");

    if (virStrToLong_ull(tmp, &tmp, 10, &sysVal) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse value '%1$s' as number."), tmp);
        return -1;
    }

    *user = userVal * 1000;
    *sys = sysVal * 1000;

    return 0;
}


static int
virCgroupV2SetCpusetMems(virCgroup *group,
                         const char *mems)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV2GetCpusetMems(virCgroup *group,
                         char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV2SetCpusetMemoryMigrate(virCgroup *group G_GNUC_UNUSED,
                                  bool migrate G_GNUC_UNUSED)
{
    return 0;
}


static int
virCgroupV2GetCpusetMemoryMigrate(virCgroup *group G_GNUC_UNUSED,
                                  bool *migrate)
{
    *migrate = true;
    return 0;
}


static int
virCgroupV2SetCpusetCpus(virCgroup *group,
                         const char *cpus)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


static int
virCgroupV2GetCpusetCpus(virCgroup *group,
                         char **cpus)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


static int
virCgroupV2AllowDevice(virCgroup *group,
                       char type,
                       int major,
                       int minor,
                       int perms)
{
    uint64_t key = virCgroupV2DevicesGetKey(major, minor);
    uint32_t val = virCgroupV2DevicesGetPerms(perms, type);
    int rc;

    if (virCgroupV2DevicesPrepareProg(group) < 0)
        return -1;

    rc = virBPFLookupElem(group->unified.devices.mapfd, &key, NULL);

    if (virBPFUpdateElem(group->unified.devices.mapfd, &key, &val) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to update device in BPF cgroup map"));
        return -1;
    }

    if (rc < 0)
        group->unified.devices.count++;

    return 0;
}


static int
virCgroupV2DenyDevice(virCgroup *group,
                      char type,
                      int major,
                      int minor,
                      int perms)
{
    uint64_t key = virCgroupV2DevicesGetKey(major, minor);
    uint32_t newval = virCgroupV2DevicesGetPerms(perms, type);
    uint32_t val = 0;

    if (virCgroupV2DevicesPrepareProg(group) < 0)
        return -1;

    if (group->unified.devices.count <= 0 ||
        virBPFLookupElem(group->unified.devices.mapfd, &key, &val) < 0) {
        VIR_DEBUG("nothing to do, device is not allowed");
        return 0;
    }

    val = val & ~newval;

    if (val == 0) {
        if (virBPFDeleteElem(group->unified.devices.mapfd, &key) < 0) {
            virReportSystemError(errno, "%s",
                                 _("failed to remove device from BPF cgroup map"));
            return -1;
        }
        group->unified.devices.count--;
    } else {
        if (virBPFUpdateElem(group->unified.devices.mapfd, &key, &val) < 0) {
            virReportSystemError(errno, "%s",
                                 _("failed to update device in BPF cgroup map"));
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV2AllowAllDevices(virCgroup *group,
                           int perms)
{
    if (virCgroupV2DevicesPrepareProg(group) < 0)
        return -1;

    if (group->unified.devices.count > 0 &&
        perms == VIR_CGROUP_DEVICE_RWM &&
        virCgroupV2DevicesCreateProg(group) < 0) {
        return -1;
    }

    return virCgroupV2AllowDevice(group, 'a', -1, -1, perms);
}


static int
virCgroupV2DenyAllDevices(virCgroup *group)
{
    if (virCgroupV2DevicesDetectProg(group) < 0)
        return -1;

    return virCgroupV2DevicesCreateProg(group);
}


virCgroupBackend virCgroupV2Backend = {
    .type = VIR_CGROUP_BACKEND_TYPE_V2,

    .available = virCgroupV2Available,
    .validateMachineGroup = virCgroupV2ValidateMachineGroup,
    .copyMounts = virCgroupV2CopyMounts,
    .copyPlacement = virCgroupV2CopyPlacement,
    .detectMounts = virCgroupV2DetectMounts,
    .detectPlacement = virCgroupV2DetectPlacement,
    .setPlacement = virCgroupV2SetPlacement,
    .validatePlacement = virCgroupV2ValidatePlacement,
    .stealPlacement = virCgroupV2StealPlacement,
    .detectControllers = virCgroupV2DetectControllers,
    .hasController = virCgroupV2HasController,
    .getAnyController = virCgroupV2GetAnyController,
    .pathOfController = virCgroupV2PathOfController,
    .makeGroup = virCgroupV2MakeGroup,
    .exists = virCgroupV2Exists,
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

    .allowDevice = virCgroupV2AllowDevice,
    .denyDevice = virCgroupV2DenyDevice,
    .allowAllDevices = virCgroupV2AllowAllDevices,
    .denyAllDevices = virCgroupV2DenyAllDevices,

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
