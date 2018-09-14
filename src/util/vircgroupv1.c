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

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# include <mntent.h>
#endif
#include <sys/stat.h>

#include "internal.h"

#define __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__
#include "vircgrouppriv.h"
#undef __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__

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
              "name=systemd");


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

        if (!group->controllers[i].placement)
            continue;

        tmp = strrchr(group->controllers[i].placement, '/');
        if (!tmp)
            return false;

        if (i == VIR_CGROUP_CONTROLLER_CPU ||
            i == VIR_CGROUP_CONTROLLER_CPUACCT ||
            i == VIR_CGROUP_CONTROLLER_CPUSET) {
            if (STREQ(tmp, "/emulator"))
                *tmp = '\0';
            tmp = strrchr(group->controllers[i].placement, '/');
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
        if (!parent->controllers[i].mountPoint)
            continue;

        if (VIR_STRDUP(group->controllers[i].mountPoint,
                       parent->controllers[i].mountPoint) < 0)
            return -1;

        if (VIR_STRDUP(group->controllers[i].linkPoint,
                       parent->controllers[i].linkPoint) < 0)
            return -1;
    }
    return 0;
}


static int
virCgroupV1ResolveMountLink(const char *mntDir,
                            const char *typeStr,
                            virCgroupControllerPtr controller)
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
            virCgroupControllerPtr controller = &group->controllers[i];

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
            group->controllers[i].mountPoint != NULL &&
            group->controllers[i].placement == NULL) {
            /*
             * selfpath == "/" + path="" -> "/"
             * selfpath == "/libvirt.service" + path == "" -> "/libvirt.service"
             * selfpath == "/libvirt.service" + path == "foo" -> "/libvirt.service/foo"
             */
            if (i == VIR_CGROUP_CONTROLLER_SYSTEMD) {
                if (VIR_STRDUP(group->controllers[i].placement,
                               selfpath) < 0)
                    return -1;
            } else {
                if (virAsprintf(&group->controllers[i].placement,
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


virCgroupBackend virCgroupV1Backend = {
    .type = VIR_CGROUP_BACKEND_TYPE_V1,

    .available = virCgroupV1Available,
    .validateMachineGroup = virCgroupV1ValidateMachineGroup,
    .copyMounts = virCgroupV1CopyMounts,
    .detectMounts = virCgroupV1DetectMounts,
    .detectPlacement = virCgroupV1DetectPlacement,
};


void
virCgroupV1Register(void)
{
    virCgroupBackendRegister(&virCgroupV1Backend);
}
