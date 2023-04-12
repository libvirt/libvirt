/*
 * vircgroupv1.c: methods for cgroups v1 backend
 *
 * Copyright (C) 2010-2015,2018 Red Hat, Inc.
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
 */
#include <config.h>

#include <unistd.h>
#ifdef __linux__
# include <mntent.h>
# include <sys/stat.h>
# include <sys/mount.h>
#endif /* __linux__ */

#include "internal.h"

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "vircgroup.h"
#include "vircgroupbackend.h"
#include "vircgroupv1.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virsystemd.h"
#include "virerror.h"
#include "viralloc.h"
#include "virthread.h"

VIR_LOG_INIT("util.cgroup");

#define VIR_FROM_THIS VIR_FROM_CGROUP


VIR_ENUM_DECL(virCgroupV1Controller);
VIR_ENUM_IMPL(virCgroupV1Controller,
              VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "blkio", "net_cls", "perf_event",
              "name=systemd",
);


#ifdef __linux__

/* We're looking for at least one 'cgroup' fs mount,
 * which is *not* a named mount. */
static bool
virCgroupV1Available(void)
{
    bool ret = false;
    FILE *mounts = NULL;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];

    if (!virFileExists("/proc/cgroups"))
        return false;

    if (!(mounts = fopen("/proc/mounts", "r")))
        return false;

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        if (STREQ(entry.mnt_type, "cgroup") && !strstr(entry.mnt_opts, "name=")) {
            ret = true;
            break;
        }
    }

    VIR_FORCE_FCLOSE(mounts);
    return ret;
}


static bool
virCgroupV1ValidateMachineGroup(virCgroup *group,
                                const char *name,
                                const char *drivername,
                                const char *machinename)
{
    size_t i;
    g_autofree char *partname = NULL;
    g_autofree char *scopename_old = NULL;
    g_autofree char *scopename_new = NULL;
    g_autofree char *partmachinename = NULL;

    partname = g_strdup_printf("%s.libvirt-%s", name, drivername);

    if (virCgroupPartitionEscape(&partname) < 0)
        return false;

    partmachinename = g_strdup_printf("%s.libvirt-%s",
                                      machinename, drivername);

    if (virCgroupPartitionEscape(&partmachinename) < 0)
        return false;

    if (!(scopename_old = virSystemdMakeScopeName(name, drivername, true)))
        return false;

    if (!(scopename_new = virSystemdMakeScopeName(machinename,
                                                  drivername, false)))
        return false;

    if (virCgroupPartitionEscape(&scopename_old) < 0)
        return false;

    if (virCgroupPartitionEscape(&scopename_new) < 0)
        return false;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        char *tmp;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        if (!group->legacy[i].placement)
            continue;

        tmp = strrchr(group->legacy[i].placement, '/');
        if (!tmp)
            return false;

        if (i == VIR_CGROUP_CONTROLLER_CPU ||
            i == VIR_CGROUP_CONTROLLER_CPUACCT ||
            i == VIR_CGROUP_CONTROLLER_CPUSET) {
            if (STREQ(tmp, "/emulator"))
                *tmp = '\0';
            tmp = strrchr(group->legacy[i].placement, '/');
            if (!tmp)
                return false;
        }

        tmp++;

        if (STRNEQ(tmp, name) &&
            STRNEQ(tmp, machinename) &&
            STRNEQ(tmp, partname) &&
            STRNEQ(tmp, partmachinename) &&
            STRNEQ(tmp, scopename_old) &&
            STRNEQ(tmp, scopename_new)) {
            VIR_DEBUG("Name '%s' for controller '%s' does not match "
                      "'%s', '%s', '%s', '%s' or '%s'",
                      tmp, virCgroupV1ControllerTypeToString(i),
                      name, machinename, partname,
                      scopename_old, scopename_new);
            return false;
        }
    }

    return true;
}


static int
virCgroupV1CopyMounts(virCgroup *group,
                      virCgroup *parent)
{
    size_t i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!parent->legacy[i].mountPoint)
            continue;

        group->legacy[i].mountPoint = g_strdup(parent->legacy[i].mountPoint);

        group->legacy[i].linkPoint = g_strdup(parent->legacy[i].linkPoint);
    }
    return 0;
}


static int
virCgroupV1CopyPlacement(virCgroup *group,
                         const char *path,
                         virCgroup *parent)
{
    size_t i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        bool delim;

        if (!group->legacy[i].mountPoint)
            continue;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        delim = STREQ(parent->legacy[i].placement, "/") || STREQ(path, "");
        /*
         * parent == "/" + path="" => "/"
         * parent == "/libvirt.service" + path == "" => "/libvirt.service"
         * parent == "/libvirt.service" + path == "foo" => "/libvirt.service/foo"
         */
        group->legacy[i].placement = g_strdup_printf("%s%s%s",
                                                     parent->legacy[i].placement,
                                                     delim ? "" : "/",
                                                     path);
    }

    return 0;
}


static int
virCgroupV1ResolveMountLink(const char *mntDir,
                            const char *typeStr,
                            virCgroupV1Controller *controller)
{
    g_autofree char *linkSrc = NULL;
    g_autofree char *tmp = NULL;
    char *dirName;
    GStatBuf sb;

    tmp = g_strdup(mntDir);

    dirName = strrchr(tmp, '/');
    if (!dirName) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing '/' separator in cgroup mount '%1$s'"), tmp);
        return -1;
    }

    if (!strchr(dirName + 1, ','))
        return 0;

    *dirName = '\0';
    linkSrc = g_strdup_printf("%s/%s", tmp, typeStr);
    *dirName = '/';

    if (g_lstat(linkSrc, &sb) < 0) {
        if (errno == ENOENT) {
            VIR_WARN("Controller %s co-mounted at %s is missing symlink at %s",
                     typeStr, tmp, linkSrc);
        } else {
            virReportSystemError(errno, _("Cannot stat %1$s"), linkSrc);
            return -1;
        }
    } else {
        if (!S_ISLNK(sb.st_mode)) {
            VIR_WARN("Expecting a symlink at %s for controller %s",
                     linkSrc, typeStr);
        } else {
            controller->linkPoint = g_steal_pointer(&linkSrc);
        }
    }

    return 0;
}


static bool
virCgroupV1MountOptsMatchController(const char *mntOpts,
                                    const char *typeStr)
{
    const char *tmp = mntOpts;
    int typeLen = strlen(typeStr);

    while (tmp) {
        const char *next = strchr(tmp, ',');
        int len;
        if (next) {
            len = next - tmp;
            next++;
        } else {
            len = strlen(tmp);
        }

        if (typeLen == len && STREQLEN(typeStr, tmp, len))
            return true;

        tmp = next;
    }

    return false;
}


static int
virCgroupV1DetectMounts(virCgroup *group,
                        const char *mntType,
                        const char *mntOpts,
                        const char *mntDir)
{
    size_t i;

    if (STRNEQ(mntType, "cgroup"))
        return 0;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        const char *typestr = virCgroupV1ControllerTypeToString(i);

        if (virCgroupV1MountOptsMatchController(mntOpts, typestr)) {
            /* Note that the lines in /proc/mounts have the same
             * order than the mount operations, and that there may
             * be duplicates due to bind mounts. This means
             * that the same mount point may be processed more than
             * once. We need to save the results of the last one,
             * and we need to be careful to release the memory used
             * by previous processing. */
            virCgroupV1Controller *controller = &group->legacy[i];

            VIR_FREE(controller->mountPoint);
            VIR_FREE(controller->linkPoint);
            controller->mountPoint = g_strdup(mntDir);

            /* If it is a co-mount it has a filename like "cpu,cpuacct"
             * and we must identify the symlink path */
            if (virCgroupV1ResolveMountLink(mntDir, typestr, controller) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virCgroupV1DetectPlacement(virCgroup *group,
                           const char *path,
                           const char *controllers,
                           const char *selfpath)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        const char *typestr = virCgroupV1ControllerTypeToString(i);
        g_autofree char* placement = NULL;
        char *tmp = NULL;

        if (!virCgroupV1MountOptsMatchController(controllers, typestr))
            continue;

        if (!group->legacy[i].mountPoint)
            continue;

        if (group->legacy[i].placement)
            continue;

        /* On systemd we create a nested cgroup for some cgroup tasks
         * but the placement should point to the root cgroup. */
        placement = g_strdup(selfpath);
        tmp = g_strrstr(placement, "/libvirt");
        if (tmp)
            *tmp = '\0';

        /*
         * selfpath == "/" + path="" -> "/"
         * selfpath == "/libvirt.service" + path == "" -> "/libvirt.service"
         * selfpath == "/libvirt.service" + path == "foo" -> "/libvirt.service/foo"
         */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD) {
            group->legacy[i].placement = g_strdup(placement);
        } else {
            bool delim = STREQ(placement, "/") || STREQ(path, "");

            group->legacy[i].placement = g_strdup_printf("%s%s%s", placement,
                                                         delim ? "" : "/",
                                                         path);
        }
    }

    return 0;
}


static int
virCgroupV1SetPlacement(virCgroup *group,
                        const char *path)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        group->legacy[i].placement = g_strdup(path);
    }

    return 0;
}


static int
virCgroupV1ValidatePlacement(virCgroup *group,
                             pid_t pid)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (!group->legacy[i].placement) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find placement for v1 controller %1$s"),
                           virCgroupV1ControllerTypeToString(i));
            return -1;
        }

        VIR_DEBUG("Detected mount/mapping %zu:%s at %s in %s for pid %lld",
                  i,
                  virCgroupV1ControllerTypeToString(i),
                  group->legacy[i].mountPoint,
                  group->legacy[i].placement,
                  (long long) pid);
    }

    return 0;
}


static char *
virCgroupV1StealPlacement(virCgroup *group)
{
    return g_steal_pointer(&group->legacy[VIR_CGROUP_CONTROLLER_SYSTEMD].placement);
}


static int
virCgroupV1DetectControllers(virCgroup *group,
                             int controllers,
                             virCgroup *parent G_GNUC_UNUSED,
                             int detected)
{
    size_t i;
    size_t j;

    if (controllers >= 0) {
        VIR_DEBUG("Filtering controllers %d", controllers);
        /* First mark requested but non-existing controllers to be ignored */
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            if (((1 << i) & controllers)) {
                int type = 1 << i;
                if (type & detected) {
                    VIR_FREE(group->legacy[i].mountPoint);
                    VIR_FREE(group->legacy[i].placement);
                }
                /* Remove non-existent controllers  */
                if (!group->legacy[i].mountPoint) {
                    VIR_DEBUG("Requested controller '%s' not mounted, ignoring",
                              virCgroupV1ControllerTypeToString(i));
                    controllers &= ~(1 << i);
                }
            }
        }
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            VIR_DEBUG("Controller '%s' wanted=%s, mount='%s'",
                      virCgroupV1ControllerTypeToString(i),
                      (1 << i) & controllers ? "yes" : "no",
                      NULLSTR(group->legacy[i].mountPoint));
            if (!((1 << i) & controllers) &&
                group->legacy[i].mountPoint) {
                /* Check whether a request to disable a controller
                 * clashes with co-mounting of controllers */
                for (j = 0; j < VIR_CGROUP_CONTROLLER_LAST; j++) {
                    if (j == i)
                        continue;
                    if (!((1 << j) & controllers))
                        continue;

                    if (STREQ_NULLABLE(group->legacy[i].mountPoint,
                                       group->legacy[j].mountPoint)) {
                        virReportSystemError(EINVAL,
                                             _("V1 controller '%1$s' is not wanted, but '%2$s' is co-mounted"),
                                             virCgroupV1ControllerTypeToString(i),
                                             virCgroupV1ControllerTypeToString(j));
                        return -1;
                    }
                }
                VIR_FREE(group->legacy[i].mountPoint);
                VIR_FREE(group->legacy[i].placement);
            }
        }
    } else {
        VIR_DEBUG("Auto-detecting controllers");
        controllers = 0;
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            int type = 1 << i;
            if (type & detected) {
                VIR_FREE(group->legacy[i].mountPoint);
                VIR_FREE(group->legacy[i].placement);
            }
            VIR_DEBUG("Controller '%s' present=%s",
                      virCgroupV1ControllerTypeToString(i),
                      group->legacy[i].mountPoint ? "yes" : "no");
            if (group->legacy[i].mountPoint == NULL)
                continue;
            controllers |= (1 << i);
        }
    }

    return controllers;
}


static bool
virCgroupV1HasController(virCgroup *group,
                         int controller)
{
    return group->legacy[controller].mountPoint != NULL;
}


static int
virCgroupV1GetAnyController(virCgroup *group)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Reject any controller with a placement
         * of '/' to avoid doing bad stuff to the root
         * cgroup
         */
        if (group->legacy[i].mountPoint &&
            group->legacy[i].placement &&
            STRNEQ(group->legacy[i].placement, "/")) {
            return i;
        }
    }

    return -1;
}


static int
virCgroupV1PathOfController(virCgroup *group,
                            int controller,
                            const char *key,
                            char **path)
{
    if (group->legacy[controller].mountPoint == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v1 controller '%1$s' is not mounted"),
                       virCgroupV1ControllerTypeToString(controller));
        return -1;
    }

    if (group->legacy[controller].placement == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v1 controller '%1$s' is not enabled for group"),
                       virCgroupV1ControllerTypeToString(controller));
        return -1;
    }

    *path = g_strdup_printf("%s%s/%s", group->legacy[controller].mountPoint,
                            group->legacy[controller].placement, NULLSTR_EMPTY(key));

    return 0;
}


static int
virCgroupV1CpuSetInherit(virCgroup *parent,
                         virCgroup *group)
{
    size_t i;
    const char *inherit_values[] = {
        "cpuset.cpus",
        "cpuset.mems",
        "cpuset.memory_migrate",
    };

    VIR_DEBUG("Setting up inheritance %s -> %s",
              parent->legacy[VIR_CGROUP_CONTROLLER_CPUSET].placement,
              group->legacy[VIR_CGROUP_CONTROLLER_CPUSET].placement);
    for (i = 0; i < G_N_ELEMENTS(inherit_values); i++) {
        g_autofree char *value = NULL;

        if (virCgroupGetValueStr(parent,
                                 VIR_CGROUP_CONTROLLER_CPUSET,
                                 inherit_values[i],
                                 &value) < 0)
            return -1;

        VIR_DEBUG("Inherit %s = %s", inherit_values[i], value);

        if (virCgroupSetValueStr(group,
                                 VIR_CGROUP_CONTROLLER_CPUSET,
                                 inherit_values[i],
                                 value) < 0)
            return -1;
    }

    return 0;
}


static int
virCgroupV1SetMemoryUseHierarchy(virCgroup *group)
{
    unsigned long long value;
    const char *filename = "memory.use_hierarchy";

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             filename, &value) < 0)
        return -1;

    /* Setting twice causes error, so if already enabled, skip setting */
    if (value == 1)
        return 0;

    if (virCgroupSetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             filename, 1) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1MakeGroup(virCgroup *parent,
                     virCgroup *group,
                     bool create,
                     pid_t pid G_GNUC_UNUSED,
                     unsigned int flags)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        g_autofree char *path = NULL;

        /* We must never mkdir() in systemd's hierarchy */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD) {
            VIR_DEBUG("Not creating systemd controller group");
            continue;
        }

        /* Skip over controllers that aren't mounted */
        if (!group->legacy[i].mountPoint) {
            VIR_DEBUG("Skipping unmounted controller %s",
                      virCgroupV1ControllerTypeToString(i));
            continue;
        }

        if (virCgroupV1PathOfController(group, i, "", &path) < 0)
            return -1;

        VIR_DEBUG("Make controller %s", path);
        if (!virFileExists(path)) {
            if (!create ||
                mkdir(path, 0755) < 0) {
                if (errno == EEXIST)
                    continue;
                /* With a kernel that doesn't support multi-level directory
                 * for blkio controller, libvirt will fail and disable all
                 * other controllers even though they are available. So
                 * treat blkio as unmounted if mkdir fails. */
                if (i == VIR_CGROUP_CONTROLLER_BLKIO) {
                    VIR_DEBUG("Ignoring mkdir failure with blkio controller. Kernel probably too old");
                    VIR_FREE(group->legacy[i].mountPoint);
                    continue;
                } else {
                    virReportSystemError(errno,
                                         _("Failed to create v1 controller %1$s for group"),
                                         virCgroupV1ControllerTypeToString(i));
                    return -1;
                }
            }
            if (i == VIR_CGROUP_CONTROLLER_CPUSET &&
                group->legacy[i].mountPoint != NULL &&
                virCgroupV1CpuSetInherit(parent, group) < 0) {
                return -1;
            }
            /*
             * Note that virCgroupV1SetMemoryUseHierarchy should always be
             * called prior to creating subcgroups and attaching tasks.
             */
            if ((flags & VIR_CGROUP_MEM_HIERACHY) &&
                i == VIR_CGROUP_CONTROLLER_MEMORY &&
                group->legacy[i].mountPoint != NULL &&
                virCgroupV1SetMemoryUseHierarchy(group) < 0) {
                return -1;
            }
        }
    }

    VIR_DEBUG("Done making controllers for group");
    return 0;
}


static bool
virCgroupV1Exists(virCgroup *group)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        g_autofree char *path = NULL;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        if (!group->legacy[i].mountPoint)
            continue;

        if (virCgroupV1PathOfController(group, i, "", &path) < 0)
            return false;

        if (!virFileExists(path)) {
            return false;
        }
    }

    return true;
}


static int
virCgroupV1Remove(virCgroup *group)
{
    int rc = 0;
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        g_autofree char *grppath = NULL;

        /* Skip over controllers not mounted */
        if (!group->legacy[i].mountPoint)
            continue;

        /* We must never rmdir() in systemd's hierarchy */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        /* Don't delete the root group, if we accidentally
           ended up in it for some reason */
        if (STREQ(group->legacy[i].placement, "/"))
            continue;

        if (virCgroupV1PathOfController(group,
                                        i,
                                        NULL,
                                        &grppath) != 0)
            continue;

        VIR_DEBUG("Removing cgroup %s and all child cgroups", grppath);
        rc = virCgroupRemoveRecursively(grppath);
    }

    return rc;
}


static int
virCgroupV1AddTask(virCgroup *group,
                   pid_t pid,
                   unsigned int flags)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Skip over controllers not mounted */
        if (!group->legacy[i].mountPoint)
            continue;

        /* We must never add tasks in systemd's hierarchy
         * unless we're intentionally trying to move a
         * task into a systemd machine scope */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD &&
            !(flags & VIR_CGROUP_TASK_SYSTEMD))
            continue;

        if (virCgroupSetValueI64(group, i, "tasks", pid) < 0)
            return -1;
    }

    return 0;
}


static int
virCgroupV1HasEmptyTasks(virCgroup *cgroup,
                         int controller)
{
    int ret = -1;
    g_autofree char *content = NULL;

    if (!cgroup)
        return -1;

    ret = virCgroupGetValueStr(cgroup, controller, "tasks", &content);

    if (ret == 0 && content[0] == '\0')
        ret = 1;

    return ret;
}


static int
virCgroupV1KillRecursive(virCgroup *group,
                         int signum,
                         GHashTable *pids)
{
    return virCgroupKillRecursiveInternal(group, signum, pids,
                                          "tasks", false);
}


static char *
virCgroupV1IdentifyRoot(virCgroup *group)
{
    char *ret = NULL;
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        char *tmp;
        if (!group->legacy[i].mountPoint)
            continue;
        if (!(tmp = strrchr(group->legacy[i].mountPoint, '/'))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find directory separator in %1$s"),
                           group->legacy[i].mountPoint);
            return NULL;
        }

        ret = g_strndup(group->legacy[i].mountPoint,
                        tmp - group->legacy[i].mountPoint);
        return ret;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Could not find any mounted v1 controllers"));
    return NULL;
}


static int
virCgroupV1BindMount(virCgroup *group,
                     const char *oldroot,
                     const char *mountopts)
{
    size_t i;
    g_autofree char *opts = NULL;
    g_autofree char *root = NULL;

    if (!(root = virCgroupV1IdentifyRoot(group)))
        return -1;

    VIR_DEBUG("Mounting cgroups at '%s'", root);

    if (g_mkdir_with_parents(root, 0777) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directory %1$s"),
                             root);
        return -1;
    }

    opts = g_strdup_printf("mode=755,size=65536%s", mountopts);

    if (mount("tmpfs", root, "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %1$s on %2$s type %3$s"),
                             "tmpfs", root, "tmpfs");
        return -1;
    }

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (!virFileExists(group->legacy[i].mountPoint)) {
            g_autofree char *src = NULL;
            src = g_strdup_printf("%s%s", oldroot, group->legacy[i].mountPoint);

            VIR_DEBUG("Create mount point '%s'",
                      group->legacy[i].mountPoint);
            if (g_mkdir_with_parents(group->legacy[i].mountPoint, 0777) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create directory %1$s"),
                                     group->legacy[i].mountPoint);
                return -1;
            }

            if (mount(src, group->legacy[i].mountPoint, "none", MS_BIND,
                      NULL) < 0) {
                virReportSystemError(errno,
                                     _("Failed to bind cgroup '%1$s' on '%2$s'"),
                                     src, group->legacy[i].mountPoint);
                return -1;
            }
        }

        if (group->legacy[i].linkPoint) {
            VIR_DEBUG("Link mount point '%s' to '%s'",
                      group->legacy[i].mountPoint,
                      group->legacy[i].linkPoint);
            if (symlink(group->legacy[i].mountPoint,
                        group->legacy[i].linkPoint) < 0) {
                virReportSystemError(errno,
                                     _("Unable to symlink directory %1$s to %2$s"),
                                     group->legacy[i].mountPoint,
                                     group->legacy[i].linkPoint);
                return -1;
            }
        }
    }

    return 0;
}


static int
virCgroupV1SetOwner(virCgroup *cgroup,
                    uid_t uid,
                    gid_t gid,
                    int controllers)
{
    size_t i;
    int direrr;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        g_autofree char *base = NULL;
        struct dirent *de;
        g_autoptr(DIR) dh = NULL;

        if (!((1 << i) & controllers))
            continue;

        if (!cgroup->legacy[i].mountPoint)
            continue;

        base = g_strdup_printf("%s%s", cgroup->legacy[i].mountPoint,
                               cgroup->legacy[i].placement);

        if (virDirOpen(&dh, base) < 0)
            return -1;

        while ((direrr = virDirRead(dh, &de, base)) > 0) {
            g_autofree char *entry = NULL;

            entry = g_strdup_printf("%s/%s", base, de->d_name);

            if (chown(entry, uid, gid) < 0) {
                virReportSystemError(errno,
                                     _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                     entry, uid, gid);
                return -1;
            }
        }
        if (direrr < 0)
            return -1;

        if (chown(base, uid, gid) < 0) {
            virReportSystemError(errno,
                                 _("cannot chown '%1$s' to (%2$u, %3$u)"),
                                 base, uid, gid);
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV1SetBlkioWeight(virCgroup *group,
                          unsigned int weight)
{
    g_autofree char *path = NULL;

    if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "blkio.bfq.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        VIR_FREE(path);

        if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                        "blkio.weight", &path) < 0) {
            return -1;
        }
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio device weight is valid only for bfq or cfq scheduler"));
        return -1;
    }

    if (group->unitName) {
        GVariant *value = g_variant_new("t", weight);

        return virCgroupSetValueDBus(group->unitName, "BlockIOWeight", value);
    } else {
        g_autofree char *value = g_strdup_printf("%u", weight);

        return virCgroupSetValueRaw(path, value);
    }
}


static int
virCgroupV1GetBlkioWeight(virCgroup *group,
                          unsigned int *weight)
{
    g_autofree char *path = NULL;
    g_autofree char *value = NULL;

    if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "blkio.bfq.weight", &path) < 0) {
        return -1;
    }

    if (!virFileExists(path)) {
        VIR_FREE(path);

        if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                        "blkio.weight", &path) < 0) {
            return -1;
        }
    }

    if (!virFileExists(path)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("blkio device weight is valid only for bfq or cfq scheduler"));
        return -1;
    }

    if (virCgroupGetValueRaw(path, &value) < 0)
        return -1;

    if (virStrToLong_ui(value, NULL, 10, weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       value);
        return -1;
    }

    return 0;
}



static int
virCgroupV1GetBlkioIoServicedOne(virCgroup *group,
                                 const char *field,
                                 const char *devpath,
                                 long long *dataRead,
                                 long long *dataWrite)
{
    g_autofree char *serviced = NULL;
    g_autofree char *filterWrite = NULL;
    g_autofree char *filterRead = NULL;
    unsigned long long tmpval;
    char *tmp;
    size_t len;

    *dataRead = 0;
    *dataWrite = 0;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_BLKIO, field, &serviced) < 0)
        return -1;

    if (devpath) {
        g_autofree char *devstr = NULL;

        if (!(devstr = virCgroupGetBlockDevString(devpath)))
            return -1;

        filterWrite = g_strdup_printf("%sWrite ", devstr);
        filterRead = g_strdup_printf("%sRead ", devstr);

        if (!strstr(serviced, filterWrite) ||
            !strstr(serviced, filterRead)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find blkio cgroup stats (%1$s) for block device '%2$s' (%3$s)"),
                           field, devstr, devpath);
            return -1;
        }
    } else {
        filterWrite = g_strdup("Write ");
        filterRead = g_strdup("Read ");
    }

    len = strlen(filterRead);

    for (tmp = strstr(serviced, filterRead); tmp; tmp = strstr(tmp, filterRead)) {
        char *cur = tmp;
        tmp += len;

        VIR_DEBUG("filter='%s' line='%.*s'", filterRead, (int) (strchr(tmp, '\n') - tmp), tmp);

        if (virStrToLong_ullp(tmp, &tmp, 10, &tmpval) < 0) {
            char *eol;

            if ((eol = strchr(cur, '\n')))
                *eol = '\0';

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse blkio cgroup (%1$s) entry '%2$s'"),
                           field, cur);
            return -1;
        }

        if (tmpval + *dataRead > LLONG_MAX) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("overflow in sum of statistic for blkio cgroup (%1$s) field '%2$s'"),
                           field, filterRead);
            return -1;
        }

        *dataRead += tmpval;
    }

    len = strlen(filterWrite);

    for (tmp = strstr(serviced, filterWrite); tmp; tmp = strstr(tmp, filterWrite)) {
        char *cur = tmp;
        tmp += len;

        VIR_DEBUG("filter='%s' line='%.*s'", filterWrite, (int) (strchr(cur, '\n') - cur), cur);

        if (virStrToLong_ullp(tmp, &tmp, 10, &tmpval) < 0) {
            char *eol;

            if ((eol = strchr(cur, '\n')))
                *eol = '\0';

            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse blkio cgroup ('%1$s') entry '%2$s'"),
                           field, cur);
            return -1;
        }

        if (tmpval + *dataWrite > LLONG_MAX) {
            virReportError(VIR_ERR_OVERFLOW,
                           _("overflow in sum of statistic for blkio cgroup (%1$s) field '%2$s'"),
                           field, filterWrite);
            return -1;
        }

        *dataWrite += tmpval;
    }

    return 0;
}


static int
virCgroupV1GetBlkioIoServicedInternal(virCgroup *group,
                                      const char *devpath,
                                      long long *bytes_read,
                                      long long *bytes_write,
                                      long long *requests_read,
                                      long long *requests_write)
{
    if (virCgroupV1GetBlkioIoServicedOne(group, "blkio.throttle.io_service_bytes",
                                         devpath, bytes_read, bytes_write) < 0)
        return -1;

    if (virCgroupV1GetBlkioIoServicedOne(group, "blkio.throttle.io_serviced",
                                         devpath, requests_read, requests_write) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1GetBlkioIoServiced(virCgroup *group,
                              long long *bytes_read,
                              long long *bytes_write,
                              long long *requests_read,
                              long long *requests_write)
{
    return virCgroupV1GetBlkioIoServicedInternal(group, NULL,
                                                 bytes_read, bytes_write,
                                                 requests_read, requests_write);
}


static int
virCgroupV1GetBlkioIoDeviceServiced(virCgroup *group,
                                    const char *path,
                                    long long *bytes_read,
                                    long long *bytes_write,
                                    long long *requests_read,
                                    long long *requests_write)
{
    return virCgroupV1GetBlkioIoServicedInternal(group, path,
                                                 bytes_read, bytes_write,
                                                 requests_read, requests_write);
}


static int
virCgroupV1SetBlkioDeviceWeight(virCgroup *group,
                                const char *devPath,
                                unsigned int weight)
{
    g_autofree char *path = NULL;

    if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "blkio.weight_device", &path) < 0) {
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

        return virCgroupSetValueDBus(group->unitName, "BlockIODeviceWeight", value);
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
virCgroupV1GetBlkioDeviceWeight(virCgroup *group,
                                const char *devPath,
                                unsigned int *weight)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;
    g_autofree char *path = NULL;

    if (virCgroupV1PathOfController(group, VIR_CGROUP_CONTROLLER_BLKIO,
                                    "blkio.weight_device", &path) < 0) {
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
    } else if (virStrToLong_ui(str, NULL, 10, weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceReadIops(virCgroup *group,
                                  const char *path,
                                  unsigned int riops)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    str = g_strdup_printf("%s%u", blkstr, riops);

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.read_iops_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceReadIops(virCgroup *group,
                                  const char *path,
                                  unsigned int *riops)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.read_iops_device",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *riops = 0;
    } else if (virStrToLong_ui(str, NULL, 10, riops) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceWriteIops(virCgroup *group,
                                   const char *path,
                                   unsigned int wiops)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    str = g_strdup_printf("%s%u", blkstr, wiops);

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.write_iops_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceWriteIops(virCgroup *group,
                                   const char *path,
                                   unsigned int *wiops)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.write_iops_device",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *wiops = 0;
    } else if (virStrToLong_ui(str, NULL, 10, wiops) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceReadBps(virCgroup *group,
                                 const char *path,
                                 unsigned long long rbps)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    str = g_strdup_printf("%s%llu", blkstr, rbps);

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.read_bps_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceReadBps(virCgroup *group,
                                 const char *path,
                                 unsigned long long *rbps)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.read_bps_device",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *rbps = 0;
    } else if (virStrToLong_ull(str, NULL, 10, rbps) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceWriteBps(virCgroup *group,
                                  const char *path,
                                  unsigned long long wbps)
{
    g_autofree char *str = NULL;
    g_autofree char *blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    str = g_strdup_printf("%s%llu", blkstr, wbps);

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.write_bps_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceWriteBps(virCgroup *group,
                                  const char *path,
                                  unsigned long long *wbps)
{
    g_autofree char *str = NULL;
    g_autofree char *value = NULL;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.write_bps_device",
                             &value) < 0) {
        return -1;
    }

    if (virCgroupGetValueForBlkDev(value, path, &str) < 0)
        return -1;

    if (!str) {
        *wbps = 0;
    } else if (virStrToLong_ull(str, NULL, 10, wbps) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


/*
 * Retrieve the "memory.limit_in_bytes" value from the memory controller
 * root dir. This value cannot be modified by userspace and therefore
 * is the maximum limit value supported by cgroups on the local system.
 * Returns this value scaled to KB or falls back to the original
 * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED. Either way, remember the return
 * value to avoid unnecessary cgroup filesystem access.
 */
static unsigned long long int virCgroupV1MemoryUnlimitedKB;
static virOnceControl virCgroupV1MemoryOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
virCgroupV1MemoryOnceInit(void)
{
    g_autoptr(virCgroup) group = NULL;
    unsigned long long int mem_unlimited = 0ULL;

    if (virCgroupNew("/", -1, &group) < 0)
        return;

    if (!virCgroupV1HasController(group, VIR_CGROUP_CONTROLLER_MEMORY))
        return;

    ignore_value(virCgroupGetValueU64(group,
                                      VIR_CGROUP_CONTROLLER_MEMORY,
                                      "memory.limit_in_bytes",
                                      &mem_unlimited));

    virCgroupV1MemoryUnlimitedKB = mem_unlimited >> 10;
}

static unsigned long long int
virCgroupV1GetMemoryUnlimitedKB(void)
{
    if (virOnce(&virCgroupV1MemoryOnce, virCgroupV1MemoryOnceInit) < 0)
        VIR_DEBUG("Init failed, will fall back to defaults.");

    if (virCgroupV1MemoryUnlimitedKB)
        return virCgroupV1MemoryUnlimitedKB;
    else
        return VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
}


static int
virCgroupV1SetMemory(virCgroup *group,
                     unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb)
        return virCgroupSetValueI64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.limit_in_bytes",
                                    -1);
    else
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.limit_in_bytes",
                                    kb << 10);
}


static int
virCgroupV1GetMemoryStat(virCgroup *group,
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

        if (virStrToLong_ull(valueStr + 1, NULL, 10, &value) < 0)
            return -1;

        if (STREQ(line, "cache"))
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
virCgroupV1GetMemoryUsage(virCgroup *group,
                          unsigned long *kb)
{
    long long unsigned int usage_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.usage_in_bytes", &usage_in_bytes);
    if (ret == 0)
        *kb = (unsigned long) usage_in_bytes >> 10;
    return ret;
}


static int
virCgroupV1SetMemoryHardLimit(virCgroup *group,
                              unsigned long long kb)
{
    return virCgroupV1SetMemory(group, kb);
}


static int
virCgroupV1GetMemoryHardLimit(virCgroup *group,
                              unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupV1GetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV1SetMemorySoftLimit(virCgroup *group,
                              unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb)
        return virCgroupSetValueI64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.soft_limit_in_bytes",
                                    -1);
    else
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.soft_limit_in_bytes",
                                    kb << 10);
}


static int
virCgroupV1GetMemorySoftLimit(virCgroup *group,
                              unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.soft_limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupV1GetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV1SetMemSwapHardLimit(virCgroup *group,
                               unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%1$llu' must be less than %2$llu"),
                       kb, maxkb);
        return -1;
    }

    if (kb == maxkb)
        return virCgroupSetValueI64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.memsw.limit_in_bytes",
                                    -1);
    else
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_MEMORY,
                                    "memory.memsw.limit_in_bytes",
                                    kb << 10);
}


static int
virCgroupV1GetMemSwapHardLimit(virCgroup *group,
                               unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.memsw.limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupV1GetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


static int
virCgroupV1GetMemSwapUsage(virCgroup *group,
                           unsigned long long *kb)
{
    long long unsigned int usage_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.memsw.usage_in_bytes", &usage_in_bytes);
    if (ret == 0)
        *kb = usage_in_bytes >> 10;
    return ret;
}


static int
virCgroupV1AllowDevice(virCgroup *group,
                       char type,
                       int major,
                       int minor,
                       int perms)
{
    g_autofree char *devstr = NULL;
    g_autofree char *majorstr = NULL;
    g_autofree char *minorstr = NULL;

    if (major < 0)
        majorstr = g_strdup("*");
    else
        majorstr = g_strdup_printf("%i", major);

    if (minor < 0)
        minorstr = g_strdup("*");
    else
        minorstr = g_strdup_printf("%i", minor);

    devstr = g_strdup_printf("%c %s:%s %s", type, majorstr, minorstr,
                             virCgroupGetDevicePermsString(perms));

    if (virCgroupSetValueStr(group,
                             VIR_CGROUP_CONTROLLER_DEVICES,
                             "devices.allow",
                             devstr) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1DenyDevice(virCgroup *group,
                      char type,
                      int major,
                      int minor,
                      int perms)
{
    g_autofree char *devstr = NULL;
    g_autofree char *majorstr = NULL;
    g_autofree char *minorstr = NULL;

    if (major < 0)
        majorstr = g_strdup("*");
    else
        majorstr = g_strdup_printf("%i", major);

    if (minor < 0)
        minorstr = g_strdup("*");
    else
        minorstr = g_strdup_printf("%i", minor);

    devstr = g_strdup_printf("%c %s:%s %s", type, majorstr, minorstr,
                             virCgroupGetDevicePermsString(perms));

    if (virCgroupSetValueStr(group,
                             VIR_CGROUP_CONTROLLER_DEVICES,
                             "devices.deny",
                             devstr) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1AllowAllDevices(virCgroup *group,
                           int perms)
{
    if (virCgroupV1AllowDevice(group, 'b', -1, -1, perms) < 0)
        return -1;

    if (virCgroupV1AllowDevice(group, 'c', -1, -1, perms) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1DenyAllDevices(virCgroup *group)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_DEVICES,
                                "devices.deny",
                                "a");
}


static int
virCgroupV1SetCpuShares(virCgroup *group,
                        unsigned long long shares)
{
    if (shares < VIR_CGROUP_CPU_SHARES_MIN ||
        shares > VIR_CGROUP_CPU_SHARES_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("shares '%1$llu' must be in range [%2$llu, %3$llu]"),
                       shares,
                       VIR_CGROUP_CPU_SHARES_MIN,
                       VIR_CGROUP_CPU_SHARES_MAX);
        return -1;
    }

    if (group->unitName) {
        GVariant *value = g_variant_new("t", shares);

        return virCgroupSetValueDBus(group->unitName, "CPUShares", value);
    } else {
        return virCgroupSetValueU64(group,
                                    VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.shares", shares);
    }
}


static int
virCgroupV1GetCpuShares(virCgroup *group,
                        unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}


static int
virCgroupV1SetCpuCfsPeriod(virCgroup *group,
                           unsigned long long cfs_period)
{
    if (cfs_period < VIR_CGROUP_CPU_PERIOD_MIN ||
        cfs_period > VIR_CGROUP_CPU_PERIOD_MAX) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_period '%1$llu' must be in range (%2$llu, %3$llu)"),
                       cfs_period,
                       VIR_CGROUP_CPU_PERIOD_MIN,
                       VIR_CGROUP_CPU_PERIOD_MAX);
        return -1;
    }

    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_period_us", cfs_period);
}


static int
virCgroupV1GetCpuCfsPeriod(virCgroup *group,
                           unsigned long long *cfs_period)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_period_us", cfs_period);
}


static int
virCgroupV1SetCpuCfsQuota(virCgroup *group,
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

    return virCgroupSetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}


static int
virCgroupV1GetCpuCfsQuota(virCgroup *group,
                          long long *cfs_quota)
{
    return virCgroupGetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}


static bool
virCgroupV1SupportsCpuBW(virCgroup *cgroup)
{
    g_autofree char *path = NULL;

    if (!cgroup)
        return false;

    if (virCgroupV1PathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                    "cpu.cfs_period_us", &path) < 0) {
        virResetLastError();
        return false;
    }

    return virFileExists(path);
}


static int
virCgroupV1GetCpuacctUsage(virCgroup *group,
                           unsigned long long *usage)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage", usage);
}


static int
virCgroupV1GetCpuacctPercpuUsage(virCgroup *group,
                                 char **usage)
{
    return virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage_percpu", usage);
}


static int
virCgroupV1GetCpuacctStat(virCgroup *group,
                          unsigned long long *user,
                          unsigned long long *sys)
{
    g_autofree char *str = NULL;
    char *p;
    static double scale = -1.0;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpuacct.stat", &str) < 0)
        return -1;

    if (!(p = STRSKIP(str, "user ")) ||
        virStrToLong_ull(p, &p, 10, user) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse user stat '%1$s'"),
                       p);
        return -1;
    }
    if (!(p = STRSKIP(p, "\nsystem ")) ||
        virStrToLong_ull(p, NULL, 10, sys) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse sys stat '%1$s'"),
                       p);
        return -1;
    }
    /* times reported are in system ticks (generally 100 Hz), but that
     * rate can theoretically vary between machines.  Scale things
     * into approximate nanoseconds.  */
    if (scale < 0) {
        long ticks_per_sec = sysconf(_SC_CLK_TCK);
        if (ticks_per_sec == -1) {
            virReportSystemError(errno, "%s",
                                 _("Cannot determine system clock HZ"));
            return -1;
        }
        scale = 1000000000.0 / ticks_per_sec;
    }
    *user *= scale;
    *sys *= scale;

    return 0;
}


static int
virCgroupV1SetFreezerState(virCgroup *group,
                           const char *state)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


static int
virCgroupV1GetFreezerState(virCgroup *group,
                           char **state)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


static int
virCgroupV1SetCpusetMems(virCgroup *group,
                         const char *mems)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV1GetCpusetMems(virCgroup *group,
                         char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV1SetCpusetMemoryMigrate(virCgroup *group,
                                  bool migrate)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.memory_migrate",
                                migrate ? "1" : "0");
}


static int
virCgroupV1GetCpusetMemoryMigrate(virCgroup *group,
                                  bool *migrate)
{
    unsigned long long value = 0;
    int ret = virCgroupGetValueU64(group,
                                   VIR_CGROUP_CONTROLLER_CPUSET,
                                   "cpuset.memory_migrate",
                                   &value);
    *migrate = !!value;
    return ret;
}


static int
virCgroupV1SetCpusetCpus(virCgroup *group,
                         const char *cpus)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


static int
virCgroupV1GetCpusetCpus(virCgroup *group,
                         char **cpus)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


virCgroupBackend virCgroupV1Backend = {
    .type = VIR_CGROUP_BACKEND_TYPE_V1,

    .available = virCgroupV1Available,
    .validateMachineGroup = virCgroupV1ValidateMachineGroup,
    .copyMounts = virCgroupV1CopyMounts,
    .copyPlacement = virCgroupV1CopyPlacement,
    .detectMounts = virCgroupV1DetectMounts,
    .detectPlacement = virCgroupV1DetectPlacement,
    .setPlacement = virCgroupV1SetPlacement,
    .validatePlacement = virCgroupV1ValidatePlacement,
    .stealPlacement = virCgroupV1StealPlacement,
    .detectControllers = virCgroupV1DetectControllers,
    .hasController = virCgroupV1HasController,
    .getAnyController = virCgroupV1GetAnyController,
    .pathOfController = virCgroupV1PathOfController,
    .makeGroup = virCgroupV1MakeGroup,
    .exists = virCgroupV1Exists,
    .remove = virCgroupV1Remove,
    .addTask = virCgroupV1AddTask,
    .hasEmptyTasks = virCgroupV1HasEmptyTasks,
    .killRecursive = virCgroupV1KillRecursive,
    .bindMount = virCgroupV1BindMount,
    .setOwner = virCgroupV1SetOwner,

    .setBlkioWeight = virCgroupV1SetBlkioWeight,
    .getBlkioWeight = virCgroupV1GetBlkioWeight,
    .getBlkioIoServiced = virCgroupV1GetBlkioIoServiced,
    .getBlkioIoDeviceServiced = virCgroupV1GetBlkioIoDeviceServiced,
    .setBlkioDeviceWeight = virCgroupV1SetBlkioDeviceWeight,
    .getBlkioDeviceWeight = virCgroupV1GetBlkioDeviceWeight,
    .setBlkioDeviceReadIops = virCgroupV1SetBlkioDeviceReadIops,
    .getBlkioDeviceReadIops = virCgroupV1GetBlkioDeviceReadIops,
    .setBlkioDeviceWriteIops = virCgroupV1SetBlkioDeviceWriteIops,
    .getBlkioDeviceWriteIops = virCgroupV1GetBlkioDeviceWriteIops,
    .setBlkioDeviceReadBps = virCgroupV1SetBlkioDeviceReadBps,
    .getBlkioDeviceReadBps = virCgroupV1GetBlkioDeviceReadBps,
    .setBlkioDeviceWriteBps = virCgroupV1SetBlkioDeviceWriteBps,
    .getBlkioDeviceWriteBps = virCgroupV1GetBlkioDeviceWriteBps,

    .setMemory = virCgroupV1SetMemory,
    .getMemoryStat = virCgroupV1GetMemoryStat,
    .getMemoryUsage = virCgroupV1GetMemoryUsage,
    .setMemoryHardLimit = virCgroupV1SetMemoryHardLimit,
    .getMemoryHardLimit = virCgroupV1GetMemoryHardLimit,
    .setMemorySoftLimit = virCgroupV1SetMemorySoftLimit,
    .getMemorySoftLimit = virCgroupV1GetMemorySoftLimit,
    .setMemSwapHardLimit = virCgroupV1SetMemSwapHardLimit,
    .getMemSwapHardLimit = virCgroupV1GetMemSwapHardLimit,
    .getMemSwapUsage = virCgroupV1GetMemSwapUsage,

    .allowDevice = virCgroupV1AllowDevice,
    .denyDevice = virCgroupV1DenyDevice,
    .allowAllDevices = virCgroupV1AllowAllDevices,
    .denyAllDevices = virCgroupV1DenyAllDevices,

    .setCpuShares = virCgroupV1SetCpuShares,
    .getCpuShares = virCgroupV1GetCpuShares,
    .setCpuCfsPeriod = virCgroupV1SetCpuCfsPeriod,
    .getCpuCfsPeriod = virCgroupV1GetCpuCfsPeriod,
    .setCpuCfsQuota = virCgroupV1SetCpuCfsQuota,
    .getCpuCfsQuota = virCgroupV1GetCpuCfsQuota,
    .supportsCpuBW = virCgroupV1SupportsCpuBW,

    .getCpuacctUsage = virCgroupV1GetCpuacctUsage,
    .getCpuacctPercpuUsage = virCgroupV1GetCpuacctPercpuUsage,
    .getCpuacctStat = virCgroupV1GetCpuacctStat,

    .setFreezerState = virCgroupV1SetFreezerState,
    .getFreezerState = virCgroupV1GetFreezerState,

    .setCpusetMems = virCgroupV1SetCpusetMems,
    .getCpusetMems = virCgroupV1GetCpusetMems,
    .setCpusetMemoryMigrate = virCgroupV1SetCpusetMemoryMigrate,
    .getCpusetMemoryMigrate = virCgroupV1GetCpusetMemoryMigrate,
    .setCpusetCpus = virCgroupV1SetCpusetCpus,
    .getCpusetCpus = virCgroupV1GetCpusetCpus,
};


void
virCgroupV1Register(void)
{
    virCgroupBackendRegister(&virCgroupV1Backend);
}

#else /* !__linux__ */

void
virCgroupV1Register(void)
{
    VIR_INFO("Control groups not supported on this platform");
}

#endif /* !__linux__ */
