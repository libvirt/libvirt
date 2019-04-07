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

VIR_LOG_INIT("util.cgroup");

#define VIR_FROM_THIS VIR_FROM_CGROUP


VIR_ENUM_DECL(virCgroupV1Controller);
VIR_ENUM_IMPL(virCgroupV1Controller, VIR_CGROUP_CONTROLLER_LAST,
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
virCgroupV1ValidateMachineGroup(virCgroupPtr group,
                                const char *name,
                                const char *drivername,
                                const char *machinename)
{
    size_t i;
    VIR_AUTOFREE(char *) partname = NULL;
    VIR_AUTOFREE(char *) scopename_old = NULL;
    VIR_AUTOFREE(char *) scopename_new = NULL;
    VIR_AUTOFREE(char *) partmachinename = NULL;

    if (virAsprintf(&partname, "%s.libvirt-%s",
                    name, drivername) < 0)
        return false;

    if (virCgroupPartitionEscape(&partname) < 0)
        return false;

    if (virAsprintf(&partmachinename, "%s.libvirt-%s",
                    machinename, drivername) < 0 ||
        virCgroupPartitionEscape(&partmachinename) < 0)
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
virCgroupV1CopyMounts(virCgroupPtr group,
                      virCgroupPtr parent)
{
    size_t i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!parent->legacy[i].mountPoint)
            continue;

        if (VIR_STRDUP(group->legacy[i].mountPoint,
                       parent->legacy[i].mountPoint) < 0)
            return -1;

        if (VIR_STRDUP(group->legacy[i].linkPoint,
                       parent->legacy[i].linkPoint) < 0)
            return -1;
    }
    return 0;
}


static int
virCgroupV1CopyPlacement(virCgroupPtr group,
                         const char *path,
                         virCgroupPtr parent)
{
    size_t i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        if (path[0] == '/') {
            if (VIR_STRDUP(group->legacy[i].placement, path) < 0)
                return -1;
        } else {
            /*
             * parent == "/" + path="" => "/"
             * parent == "/libvirt.service" + path == "" => "/libvirt.service"
             * parent == "/libvirt.service" + path == "foo" => "/libvirt.service/foo"
             */
            if (virAsprintf(&group->legacy[i].placement,
                            "%s%s%s",
                            parent->legacy[i].placement,
                            (STREQ(parent->legacy[i].placement, "/") ||
                             STREQ(path, "") ? "" : "/"),
                            path) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virCgroupV1ResolveMountLink(const char *mntDir,
                            const char *typeStr,
                            virCgroupV1ControllerPtr controller)
{
    VIR_AUTOFREE(char *) linkSrc = NULL;
    VIR_AUTOFREE(char *) tmp = NULL;
    char *dirName;
    struct stat sb;

    if (VIR_STRDUP(tmp, mntDir) < 0)
        return -1;

    dirName = strrchr(tmp, '/');
    if (!dirName) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Missing '/' separator in cgroup mount '%s'"), tmp);
        return -1;
    }

    if (!strchr(dirName + 1, ','))
        return 0;

    *dirName = '\0';
    if (virAsprintf(&linkSrc, "%s/%s", tmp, typeStr) < 0)
        return -1;
    *dirName = '/';

    if (lstat(linkSrc, &sb) < 0) {
        if (errno == ENOENT) {
            VIR_WARN("Controller %s co-mounted at %s is missing symlink at %s",
                     typeStr, tmp, linkSrc);
        } else {
            virReportSystemError(errno, _("Cannot stat %s"), linkSrc);
            return -1;
        }
    } else {
        if (!S_ISLNK(sb.st_mode)) {
            VIR_WARN("Expecting a symlink at %s for controller %s",
                     linkSrc, typeStr);
        } else {
            VIR_STEAL_PTR(controller->linkPoint, linkSrc);
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
virCgroupV1DetectMounts(virCgroupPtr group,
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
            virCgroupV1ControllerPtr controller = &group->legacy[i];

            VIR_FREE(controller->mountPoint);
            VIR_FREE(controller->linkPoint);
            if (VIR_STRDUP(controller->mountPoint, mntDir) < 0)
                return -1;

            /* If it is a co-mount it has a filename like "cpu,cpuacct"
             * and we must identify the symlink path */
            if (virCgroupV1ResolveMountLink(mntDir, typestr, controller) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virCgroupV1DetectPlacement(virCgroupPtr group,
                           const char *path,
                           const char *controllers,
                           const char *selfpath)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        const char *typestr = virCgroupV1ControllerTypeToString(i);

        if (virCgroupV1MountOptsMatchController(controllers, typestr) &&
            group->legacy[i].mountPoint != NULL &&
            group->legacy[i].placement == NULL) {
            /*
             * selfpath == "/" + path="" -> "/"
             * selfpath == "/libvirt.service" + path == "" -> "/libvirt.service"
             * selfpath == "/libvirt.service" + path == "foo" -> "/libvirt.service/foo"
             */
            if (i == VIR_CGROUP_CONTROLLER_SYSTEMD) {
                if (VIR_STRDUP(group->legacy[i].placement,
                               selfpath) < 0)
                    return -1;
            } else {
                if (virAsprintf(&group->legacy[i].placement,
                                "%s%s%s", selfpath,
                                (STREQ(selfpath, "/") ||
                                 STREQ(path, "") ? "" : "/"),
                                path) < 0)
                    return -1;
            }
        }
    }

    return 0;
}


static int
virCgroupV1ValidatePlacement(virCgroupPtr group,
                             pid_t pid)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (!group->legacy[i].placement) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find placement for v1 controller %s at %s"),
                           virCgroupV1ControllerTypeToString(i),
                           group->legacy[i].placement);
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
virCgroupV1StealPlacement(virCgroupPtr group)
{
    char *ret = NULL;

    VIR_STEAL_PTR(ret, group->legacy[VIR_CGROUP_CONTROLLER_SYSTEMD].placement);

    return ret;
}


static int
virCgroupV1DetectControllers(virCgroupPtr group,
                             int controllers)
{
    size_t i;
    size_t j;

    if (controllers >= 0) {
        VIR_DEBUG("Filtering controllers %d", controllers);
        /* First mark requested but non-existing controllers to be ignored */
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            if (((1 << i) & controllers)) {
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
                                             _("V1 controller '%s' is not wanted, but '%s' is co-mounted"),
                                             virCgroupV1ControllerTypeToString(i),
                                             virCgroupV1ControllerTypeToString(j));
                        return -1;
                    }
                }
                VIR_FREE(group->legacy[i].mountPoint);
            }
        }
    } else {
        VIR_DEBUG("Auto-detecting controllers");
        controllers = 0;
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
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
virCgroupV1HasController(virCgroupPtr group,
                         int controller)
{
    return group->legacy[controller].mountPoint != NULL;
}


static int
virCgroupV1GetAnyController(virCgroupPtr group)
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
virCgroupV1PathOfController(virCgroupPtr group,
                            int controller,
                            const char *key,
                            char **path)
{
    if (group->legacy[controller].mountPoint == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v1 controller '%s' is not mounted"),
                       virCgroupV1ControllerTypeToString(controller));
        return -1;
    }

    if (group->legacy[controller].placement == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("v1 controller '%s' is not enabled for group"),
                       virCgroupV1ControllerTypeToString(controller));
        return -1;
    }

    if (virAsprintf(path, "%s%s/%s",
                    group->legacy[controller].mountPoint,
                    group->legacy[controller].placement,
                    NULLSTR_EMPTY(key)) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1CpuSetInherit(virCgroupPtr parent,
                         virCgroupPtr group)
{
    size_t i;
    const char *inherit_values[] = {
        "cpuset.cpus",
        "cpuset.mems",
        "cpuset.memory_migrate",
    };

    VIR_DEBUG("Setting up inheritance %s -> %s", parent->path, group->path);
    for (i = 0; i < ARRAY_CARDINALITY(inherit_values); i++) {
        VIR_AUTOFREE(char *) value = NULL;

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
virCgroupV1SetMemoryUseHierarchy(virCgroupPtr group)
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

    VIR_DEBUG("Setting up %s/%s", group->path, filename);
    if (virCgroupSetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             filename, 1) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1MakeGroup(virCgroupPtr parent,
                     virCgroupPtr group,
                     bool create,
                     unsigned int flags)
{
    size_t i;

    VIR_DEBUG("Make group %s", group->path);
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        VIR_AUTOFREE(char *) path = NULL;

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
                                         _("Failed to create v1 controller %s for group"),
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


static int
virCgroupV1Remove(virCgroupPtr group)
{
    int rc = 0;
    size_t i;

    VIR_DEBUG("Removing cgroup %s", group->path);
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        VIR_AUTOFREE(char *) grppath = NULL;

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
    VIR_DEBUG("Done removing cgroup %s", group->path);

    return rc;
}


static int
virCgroupV1AddTask(virCgroupPtr group,
                   pid_t pid,
                   unsigned int flags)
{
    int ret = -1;
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
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


static int
virCgroupV1HasEmptyTasks(virCgroupPtr cgroup,
                         int controller)
{
    int ret = -1;
    VIR_AUTOFREE(char *) content = NULL;

    if (!cgroup)
        return -1;

    ret = virCgroupGetValueStr(cgroup, controller, "tasks", &content);

    if (ret == 0 && content[0] == '\0')
        ret = 1;

    return ret;
}


static int
virCgroupV1KillRecursive(virCgroupPtr group,
                         int signum,
                         virHashTablePtr pids)
{
    int controller = virCgroupV1GetAnyController(group);

    if (controller < 0)
        return -1;

    return virCgroupKillRecursiveInternal(group, signum, pids, controller,
                                          "tasks", false);
}


static char *
virCgroupV1IdentifyRoot(virCgroupPtr group)
{
    char *ret = NULL;
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        char *tmp;
        if (!group->legacy[i].mountPoint)
            continue;
        if (!(tmp = strrchr(group->legacy[i].mountPoint, '/'))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find directory separator in %s"),
                           group->legacy[i].mountPoint);
            return NULL;
        }

        if (VIR_STRNDUP(ret, group->legacy[i].mountPoint,
                        tmp - group->legacy[i].mountPoint) < 0)
            return NULL;
        return ret;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Could not find any mounted v1 controllers"));
    return NULL;
}


static int
virCgroupV1BindMount(virCgroupPtr group,
                     const char *oldroot,
                     const char *mountopts)
{
    size_t i;
    VIR_AUTOFREE(char *) opts = NULL;
    VIR_AUTOFREE(char *) root = NULL;

    if (!(root = virCgroupV1IdentifyRoot(group)))
        return -1;

    VIR_DEBUG("Mounting cgroups at '%s'", root);

    if (virFileMakePath(root) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directory %s"),
                             root);
        return -1;
    }

    if (virAsprintf(&opts,
                    "mode=755,size=65536%s", mountopts) < 0)
        return -1;

    if (mount("tmpfs", root, "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %s on %s type %s"),
                             "tmpfs", root, "tmpfs");
        return -1;
    }

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->legacy[i].mountPoint)
            continue;

        if (!virFileExists(group->legacy[i].mountPoint)) {
            VIR_AUTOFREE(char *) src = NULL;
            if (virAsprintf(&src, "%s%s",
                            oldroot,
                            group->legacy[i].mountPoint) < 0)
                return -1;

            VIR_DEBUG("Create mount point '%s'",
                      group->legacy[i].mountPoint);
            if (virFileMakePath(group->legacy[i].mountPoint) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create directory %s"),
                                     group->legacy[i].mountPoint);
                return -1;
            }

            if (mount(src, group->legacy[i].mountPoint, "none", MS_BIND,
                      NULL) < 0) {
                virReportSystemError(errno,
                                     _("Failed to bind cgroup '%s' on '%s'"),
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
                                     _("Unable to symlink directory %s to %s"),
                                     group->legacy[i].mountPoint,
                                     group->legacy[i].linkPoint);
                return -1;
            }
        }
    }

    return 0;
}


static int
virCgroupV1SetOwner(virCgroupPtr cgroup,
                    uid_t uid,
                    gid_t gid,
                    int controllers)
{
    int ret = -1;
    size_t i;
    DIR *dh = NULL;
    int direrr;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        VIR_AUTOFREE(char *) base = NULL;
        struct dirent *de;

        if (!((1 << i) & controllers))
            continue;

        if (!cgroup->legacy[i].mountPoint)
            continue;

        if (virAsprintf(&base, "%s%s", cgroup->legacy[i].mountPoint,
                        cgroup->legacy[i].placement) < 0)
            goto cleanup;

        if (virDirOpen(&dh, base) < 0)
            goto cleanup;

        while ((direrr = virDirRead(dh, &de, base)) > 0) {
            VIR_AUTOFREE(char *) entry = NULL;

            if (virAsprintf(&entry, "%s/%s", base, de->d_name) < 0)
                goto cleanup;

            if (chown(entry, uid, gid) < 0) {
                virReportSystemError(errno,
                                     _("cannot chown '%s' to (%u, %u)"),
                                     entry, uid, gid);
                goto cleanup;
            }
        }
        if (direrr < 0)
            goto cleanup;

        if (chown(base, uid, gid) < 0) {
            virReportSystemError(errno,
                                 _("cannot chown '%s' to (%u, %u)"),
                                 base, uid, gid);
            goto cleanup;
        }

        VIR_DIR_CLOSE(dh);
    }

    ret = 0;

 cleanup:
    VIR_DIR_CLOSE(dh);
    return ret;
}


static int
virCgroupV1SetBlkioWeight(virCgroupPtr group,
                          unsigned int weight)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.weight",
                                weight);
}


static int
virCgroupV1GetBlkioWeight(virCgroupPtr group,
                          unsigned int *weight)
{
    unsigned long long tmp;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_BLKIO,
                               "blkio.weight", &tmp);
    if (ret == 0)
        *weight = tmp;
    return ret;
}


static int
virCgroupV1GetBlkioIoServiced(virCgroupPtr group,
                              long long *bytes_read,
                              long long *bytes_write,
                              long long *requests_read,
                              long long *requests_write)
{
    long long stats_val;
    VIR_AUTOFREE(char *) str1 = NULL;
    VIR_AUTOFREE(char *) str2 = NULL;
    char *p1 = NULL;
    char *p2 = NULL;
    size_t i;

    const char *value_names[] = {
        "Read ",
        "Write "
    };
    long long *bytes_ptrs[] = {
        bytes_read,
        bytes_write
    };
    long long *requests_ptrs[] = {
        requests_read,
        requests_write
    };

    *bytes_read = 0;
    *bytes_write = 0;
    *requests_read = 0;
    *requests_write = 0;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.io_service_bytes", &str1) < 0)
        return -1;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.io_serviced", &str2) < 0)
        return -1;

    /* sum up all entries of the same kind, from all devices */
    for (i = 0; i < ARRAY_CARDINALITY(value_names); i++) {
        p1 = str1;
        p2 = str2;

        while ((p1 = strstr(p1, value_names[i]))) {
            p1 += strlen(value_names[i]);
            if (virStrToLong_ll(p1, &p1, 10, &stats_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse byte %sstat '%s'"),
                               value_names[i],
                               p1);
                return -1;
            }

            if (stats_val < 0 ||
                (stats_val > 0 && *bytes_ptrs[i] > (LLONG_MAX - stats_val)))
            {
                virReportError(VIR_ERR_OVERFLOW,
                               _("Sum of byte %sstat overflows"),
                               value_names[i]);
                return -1;
            }
            *bytes_ptrs[i] += stats_val;
        }

        while ((p2 = strstr(p2, value_names[i]))) {
            p2 += strlen(value_names[i]);
            if (virStrToLong_ll(p2, &p2, 10, &stats_val) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot parse %srequest stat '%s'"),
                               value_names[i],
                               p2);
                return -1;
            }

            if (stats_val < 0 ||
                (stats_val > 0 && *requests_ptrs[i] > (LLONG_MAX - stats_val)))
            {
                virReportError(VIR_ERR_OVERFLOW,
                               _("Sum of %srequest stat overflows"),
                               value_names[i]);
                return -1;
            }
            *requests_ptrs[i] += stats_val;
        }
    }

    return 0;
}


static int
virCgroupV1GetBlkioIoDeviceServiced(virCgroupPtr group,
                                    const char *path,
                                    long long *bytes_read,
                                    long long *bytes_write,
                                    long long *requests_read,
                                    long long *requests_write)
{
    VIR_AUTOFREE(char *) str1 = NULL;
    VIR_AUTOFREE(char *) str2 = NULL;
    VIR_AUTOFREE(char *) str3 = NULL;
    char *p1 = NULL;
    char *p2 = NULL;
    size_t i;

    const char *value_names[] = {
        "Read ",
        "Write "
    };
    long long *bytes_ptrs[] = {
        bytes_read,
        bytes_write
    };
    long long *requests_ptrs[] = {
        requests_read,
        requests_write
    };

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.io_service_bytes", &str1) < 0)
        return -1;

    if (virCgroupGetValueStr(group,
                             VIR_CGROUP_CONTROLLER_BLKIO,
                             "blkio.throttle.io_serviced", &str2) < 0)
        return -1;

    if (!(str3 = virCgroupGetBlockDevString(path)))
        return -1;

    if (!(p1 = strstr(str1, str3))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find byte stats for block device '%s'"),
                       str3);
        return -1;
    }

    if (!(p2 = strstr(str2, str3))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot find request stats for block device '%s'"),
                       str3);
        return -1;
    }

    for (i = 0; i < ARRAY_CARDINALITY(value_names); i++) {
        if (!(p1 = strstr(p1, value_names[i]))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find byte %sstats for block device '%s'"),
                           value_names[i], str3);
            return -1;
        }

        if (virStrToLong_ll(p1 + strlen(value_names[i]), &p1, 10, bytes_ptrs[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse %sstat '%s'"),
                           value_names[i], p1 + strlen(value_names[i]));
            return -1;
        }

        if (!(p2 = strstr(p2, value_names[i]))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot find request %sstats for block device '%s'"),
                           value_names[i], str3);
            return -1;
        }

        if (virStrToLong_ll(p2 + strlen(value_names[i]), &p2, 10, requests_ptrs[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot parse %sstat '%s'"),
                           value_names[i], p2 + strlen(value_names[i]));
            return -1;
        }
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceWeight(virCgroupPtr group,
                                const char *path,
                                unsigned int weight)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (virAsprintf(&str, "%s%d", blkstr, weight) < 0)
        return -1;

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.weight_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceWeight(virCgroupPtr group,
                                const char *path,
                                unsigned int *weight)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (virCgroupGetValueForBlkDev(group,
                                   VIR_CGROUP_CONTROLLER_BLKIO,
                                   "blkio.weight_device",
                                   path,
                                   &str) < 0)
        return -1;

    if (!str) {
        *weight = 0;
    } else if (virStrToLong_ui(str, NULL, 10, weight) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceReadIops(virCgroupPtr group,
                                  const char *path,
                                  unsigned int riops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (virAsprintf(&str, "%s%u", blkstr, riops) < 0)
        return -1;

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.read_iops_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceReadIops(virCgroupPtr group,
                                  const char *path,
                                  unsigned int *riops)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (virCgroupGetValueForBlkDev(group,
                                   VIR_CGROUP_CONTROLLER_BLKIO,
                                   "blkio.throttle.read_iops_device",
                                   path,
                                   &str) < 0)
        return -1;

    if (!str) {
        *riops = 0;
    } else if (virStrToLong_ui(str, NULL, 10, riops) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceWriteIops(virCgroupPtr group,
                                   const char *path,
                                   unsigned int wiops)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (virAsprintf(&str, "%s%u", blkstr, wiops) < 0)
        return -1;

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.write_iops_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceWriteIops(virCgroupPtr group,
                                   const char *path,
                                   unsigned int *wiops)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (virCgroupGetValueForBlkDev(group,
                                   VIR_CGROUP_CONTROLLER_BLKIO,
                                   "blkio.throttle.write_iops_device",
                                   path,
                                   &str) < 0)
        return -1;

    if (!str) {
        *wiops = 0;
    } else if (virStrToLong_ui(str, NULL, 10, wiops) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceReadBps(virCgroupPtr group,
                                 const char *path,
                                 unsigned long long rbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (virAsprintf(&str, "%s%llu", blkstr, rbps) < 0)
        return -1;

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.read_bps_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceReadBps(virCgroupPtr group,
                                 const char *path,
                                 unsigned long long *rbps)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (virCgroupGetValueForBlkDev(group,
                                   VIR_CGROUP_CONTROLLER_BLKIO,
                                   "blkio.throttle.read_bps_device",
                                   path,
                                   &str) < 0)
        return -1;

    if (!str) {
        *rbps = 0;
    } else if (virStrToLong_ull(str, NULL, 10, rbps) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       str);
        return -1;
    }

    return 0;
}


static int
virCgroupV1SetBlkioDeviceWriteBps(virCgroupPtr group,
                                  const char *path,
                                  unsigned long long wbps)
{
    VIR_AUTOFREE(char *) str = NULL;
    VIR_AUTOFREE(char *) blkstr = NULL;

    if (!(blkstr = virCgroupGetBlockDevString(path)))
        return -1;

    if (virAsprintf(&str, "%s%llu", blkstr, wbps) < 0)
        return -1;

    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.throttle.write_bps_device",
                                str);
}


static int
virCgroupV1GetBlkioDeviceWriteBps(virCgroupPtr group,
                                  const char *path,
                                  unsigned long long *wbps)
{
    VIR_AUTOFREE(char *) str = NULL;

    if (virCgroupGetValueForBlkDev(group,
                                   VIR_CGROUP_CONTROLLER_BLKIO,
                                   "blkio.throttle.write_bps_device",
                                   path,
                                   &str) < 0)
        return -1;

    if (!str) {
        *wbps = 0;
    } else if (virStrToLong_ull(str, NULL, 10, wbps) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
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
    virCgroupPtr group;
    unsigned long long int mem_unlimited = 0ULL;

    if (virCgroupNew(-1, "/", NULL, -1, &group) < 0)
        goto cleanup;

    if (!virCgroupV1HasController(group, VIR_CGROUP_CONTROLLER_MEMORY))
        goto cleanup;

    ignore_value(virCgroupGetValueU64(group,
                                      VIR_CGROUP_CONTROLLER_MEMORY,
                                      "memory.limit_in_bytes",
                                      &mem_unlimited));
 cleanup:
    virCgroupFree(&group);
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
virCgroupV1SetMemory(virCgroupPtr group,
                     unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
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
virCgroupV1GetMemoryStat(virCgroupPtr group,
                         unsigned long long *cache,
                         unsigned long long *activeAnon,
                         unsigned long long *inactiveAnon,
                         unsigned long long *activeFile,
                         unsigned long long *inactiveFile,
                         unsigned long long *unevictable)
{
    int ret = -1;
    char *stat = NULL;
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
            goto cleanup;
        }
        *valueStr = '\0';

        if (virStrToLong_ull(valueStr + 1, NULL, 10, &value) < 0)
            goto cleanup;

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

    ret = 0;

 cleanup:
    VIR_FREE(stat);
    return ret;
}


static int
virCgroupV1GetMemoryUsage(virCgroupPtr group,
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
virCgroupV1SetMemoryHardLimit(virCgroupPtr group,
                              unsigned long long kb)
{
    return virCgroupV1SetMemory(group, kb);
}


static int
virCgroupV1GetMemoryHardLimit(virCgroupPtr group,
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
virCgroupV1SetMemorySoftLimit(virCgroupPtr group,
                              unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
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
virCgroupV1GetMemorySoftLimit(virCgroupPtr group,
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
virCgroupV1SetMemSwapHardLimit(virCgroupPtr group,
                               unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Memory '%llu' must be less than %llu"),
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
virCgroupV1GetMemSwapHardLimit(virCgroupPtr group,
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
virCgroupV1GetMemSwapUsage(virCgroupPtr group,
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
virCgroupV1AllowDevice(virCgroupPtr group,
                       char type,
                       int major,
                       int minor,
                       int perms)
{
    VIR_AUTOFREE(char *) devstr = NULL;
    VIR_AUTOFREE(char *) majorstr = NULL;
    VIR_AUTOFREE(char *) minorstr = NULL;

    if ((major < 0 && VIR_STRDUP(majorstr, "*") < 0) ||
        (major >= 0 && virAsprintf(&majorstr, "%i", major) < 0))
        return -1;

    if ((minor < 0 && VIR_STRDUP(minorstr, "*") < 0) ||
        (minor >= 0 && virAsprintf(&minorstr, "%i", minor) < 0))
        return -1;

    if (virAsprintf(&devstr, "%c %s:%s %s", type, majorstr, minorstr,
                    virCgroupGetDevicePermsString(perms)) < 0)
        return -1;

    if (virCgroupSetValueStr(group,
                             VIR_CGROUP_CONTROLLER_DEVICES,
                             "devices.allow",
                             devstr) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1DenyDevice(virCgroupPtr group,
                      char type,
                      int major,
                      int minor,
                      int perms)
{
    VIR_AUTOFREE(char *) devstr = NULL;
    VIR_AUTOFREE(char *) majorstr = NULL;
    VIR_AUTOFREE(char *) minorstr = NULL;

    if ((major < 0 && VIR_STRDUP(majorstr, "*") < 0) ||
        (major >= 0 && virAsprintf(&majorstr, "%i", major) < 0))
        return -1;

    if ((minor < 0 && VIR_STRDUP(minorstr, "*") < 0) ||
        (minor >= 0 && virAsprintf(&minorstr, "%i", minor) < 0))
        return -1;

    if (virAsprintf(&devstr, "%c %s:%s %s", type, majorstr, minorstr,
                    virCgroupGetDevicePermsString(perms)) < 0)
        return -1;

    if (virCgroupSetValueStr(group,
                             VIR_CGROUP_CONTROLLER_DEVICES,
                             "devices.deny",
                             devstr) < 0)
        return -1;

    return 0;
}


static int
virCgroupV1AllowAllDevices(virCgroupPtr group,
                           int perms)
{
    int ret = -1;

    if (virCgroupV1AllowDevice(group, 'b', -1, -1, perms) < 0)
        goto cleanup;

    if (virCgroupV1AllowDevice(group, 'c', -1, -1, perms) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


static int
virCgroupV1DenyAllDevices(virCgroupPtr group)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_DEVICES,
                                "devices.deny",
                                "a");
}


static int
virCgroupV1SetCpuShares(virCgroupPtr group,
                        unsigned long long shares)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}


static int
virCgroupV1GetCpuShares(virCgroupPtr group,
                        unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}


static int
virCgroupV1SetCpuCfsPeriod(virCgroupPtr group,
                           unsigned long long cfs_period)
{
    /* The cfs_period should be greater or equal than 1ms, and less or equal
     * than 1s.
     */
    if (cfs_period < 1000 || cfs_period > 1000000) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("cfs_period '%llu' must be in range (1000, 1000000)"),
                       cfs_period);
        return -1;
    }

    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_period_us", cfs_period);
}


static int
virCgroupV1GetCpuCfsPeriod(virCgroupPtr group,
                           unsigned long long *cfs_period)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_period_us", cfs_period);
}


static int
virCgroupV1SetCpuCfsQuota(virCgroupPtr group,
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

    return virCgroupSetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}


static int
virCgroupV1GetCpuCfsQuota(virCgroupPtr group,
                          long long *cfs_quota)
{
    return virCgroupGetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}


static bool
virCgroupV1SupportsCpuBW(virCgroupPtr cgroup)
{
    VIR_AUTOFREE(char *) path = NULL;

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
virCgroupV1GetCpuacctUsage(virCgroupPtr group,
                           unsigned long long *usage)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage", usage);
}


static int
virCgroupV1GetCpuacctPercpuUsage(virCgroupPtr group,
                                 char **usage)
{
    return virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage_percpu", usage);
}


static int
virCgroupV1GetCpuacctStat(virCgroupPtr group,
                          unsigned long long *user,
                          unsigned long long *sys)
{
    VIR_AUTOFREE(char *) str = NULL;
    char *p;
    static double scale = -1.0;

    if (virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                             "cpuacct.stat", &str) < 0)
        return -1;

    if (!(p = STRSKIP(str, "user ")) ||
        virStrToLong_ull(p, &p, 10, user) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse user stat '%s'"),
                       p);
        return -1;
    }
    if (!(p = STRSKIP(p, "\nsystem ")) ||
        virStrToLong_ull(p, NULL, 10, sys) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Cannot parse sys stat '%s'"),
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
virCgroupV1SetFreezerState(virCgroupPtr group,
                           const char *state)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


static int
virCgroupV1GetFreezerState(virCgroupPtr group,
                           char **state)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


static int
virCgroupV1SetCpusetMems(virCgroupPtr group,
                         const char *mems)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV1GetCpusetMems(virCgroupPtr group,
                         char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


static int
virCgroupV1SetCpusetMemoryMigrate(virCgroupPtr group,
                                  bool migrate)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.memory_migrate",
                                migrate ? "1" : "0");
}


static int
virCgroupV1GetCpusetMemoryMigrate(virCgroupPtr group,
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
virCgroupV1SetCpusetCpus(virCgroupPtr group,
                         const char *cpus)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


static int
virCgroupV1GetCpusetCpus(virCgroupPtr group,
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
    .validatePlacement = virCgroupV1ValidatePlacement,
    .stealPlacement = virCgroupV1StealPlacement,
    .detectControllers = virCgroupV1DetectControllers,
    .hasController = virCgroupV1HasController,
    .getAnyController = virCgroupV1GetAnyController,
    .pathOfController = virCgroupV1PathOfController,
    .makeGroup = virCgroupV1MakeGroup,
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
