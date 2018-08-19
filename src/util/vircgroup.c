/*
 * vircgroup.c: methods for managing control cgroups
 *
 * Copyright (C) 2010-2015 Red Hat, Inc.
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
 *  Dan Smith <danms@us.ibm.com>
 */
#include <config.h>

#include <stdio.h>
#if defined HAVE_MNTENT_H && defined HAVE_SYS_MOUNT_H \
    && defined HAVE_GETMNTENT_R
# include <mntent.h>
# include <sys/mount.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#ifdef MAJOR_IN_MKDEV
# include <sys/mkdev.h>
#elif MAJOR_IN_SYSMACROS
# include <sys/sysmacros.h>
#endif

#include <sys/types.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>

#define __VIR_CGROUP_ALLOW_INCLUDE_PRIV_H__
#include "vircgrouppriv.h"

#include "virutil.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virhash.h"
#include "virhashcode.h"
#include "virstring.h"
#include "virsystemd.h"
#include "virtypedparam.h"
#include "virhostcpu.h"
#include "virthread.h"

VIR_LOG_INIT("util.cgroup");

#define CGROUP_MAX_VAL 512

#define VIR_FROM_THIS VIR_FROM_CGROUP

#define CGROUP_NB_TOTAL_CPU_STAT_PARAM 3
#define CGROUP_NB_PER_CPU_STAT_PARAM   1

#if defined(__linux__) && defined(HAVE_GETMNTENT_R) && \
    defined(_DIRENT_HAVE_D_TYPE) && defined(_SC_CLK_TCK)
# define VIR_CGROUP_SUPPORTED
#endif

VIR_ENUM_IMPL(virCgroupController, VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "blkio", "net_cls", "perf_event",
              "name=systemd");

typedef enum {
    VIR_CGROUP_NONE = 0, /* create subdir under each cgroup if possible. */
    VIR_CGROUP_MEM_HIERACHY = 1 << 0, /* call virCgroupSetMemoryUseHierarchy
                                       * before creating subcgroups and
                                       * attaching tasks
                                       */
} virCgroupFlags;


/**
 * virCgroupGetDevicePermsString:
 *
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits
 *
 * Returns string corresponding to the appropriate bits set.
 */
const char *
virCgroupGetDevicePermsString(int perms)
{
    if (perms & VIR_CGROUP_DEVICE_READ) {
        if (perms & VIR_CGROUP_DEVICE_WRITE) {
            if (perms & VIR_CGROUP_DEVICE_MKNOD)
                return "rwm";
            else
                return "rw";
        } else {
            if (perms & VIR_CGROUP_DEVICE_MKNOD)
                return "rm";
            else
                return "r";
        }
    } else {
        if (perms & VIR_CGROUP_DEVICE_WRITE) {
            if (perms & VIR_CGROUP_DEVICE_MKNOD)
                return "wm";
            else
                return "w";
        } else {
            if (perms & VIR_CGROUP_DEVICE_MKNOD)
                return "m";
            else
                return "";
        }
    }
}


#ifdef VIR_CGROUP_SUPPORTED
bool
virCgroupAvailable(void)
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
        /* We're looking for at least one 'cgroup' fs mount,
         * which is *not* a named mount. */
        if (STREQ(entry.mnt_type, "cgroup") &&
            !strstr(entry.mnt_opts, "name=")) {
            ret = true;
            break;
        }
    }

    VIR_FORCE_FCLOSE(mounts);
    return ret;
}


static int
virCgroupPartitionNeedsEscaping(const char *path)
{
    FILE *fp = NULL;
    int ret = 0;
    VIR_AUTOFREE(char *) line = NULL;
    size_t buflen;

    /* If it starts with 'cgroup.' or a '_' of any
     * of the controller names from /proc/cgroups,
     * then we must prefix a '_'
     */
    if (STRPREFIX(path, "cgroup."))
        return 1;

    if (path[0] == '_' ||
        path[0] == '.')
        return 1;

    if (!(fp = fopen("/proc/cgroups", "r"))) {
        /* The API contract is that we return ENXIO
         * if cgroups are not available on a host */
        if (errno == ENOENT)
            errno = ENXIO;
        virReportSystemError(errno, "%s",
                             _("Cannot open /proc/cgroups"));
        return -1;
    }

    /*
     * Data looks like this:
     * #subsys_name hierarchy num_cgroups enabled
     * cpuset  2 4  1
     * cpu     3 48 1
     * cpuacct 3 48 1
     * memory  4 4  1
     * devices 5 4  1
     * freezer 6 4  1
     * net_cls 7 1  1
     */
    while (getline(&line, &buflen, fp) > 0) {
        char *tmp;
        size_t len;

        if (STRPREFIX(line, "#subsys_name"))
            continue;

        tmp = strchrnul(line, ' ');
        *tmp = '\0';
        len = tmp - line;

        if (STRPREFIX(path, line) &&
            path[len] == '.') {
            ret = 1;
            goto cleanup;
        }
    }

    if (ferror(fp)) {
        virReportSystemError(errno, "%s",
                             _("Error while reading /proc/cgroups"));
        goto cleanup;
    }

 cleanup:
    VIR_FORCE_FCLOSE(fp);
    return ret;
}


static int
virCgroupPartitionEscape(char **path)
{
    int rc;
    char *newstr = NULL;

    if ((rc = virCgroupPartitionNeedsEscaping(*path)) <= 0)
        return rc;

    if (virAsprintf(&newstr, "_%s", *path) < 0)
        return -1;

    VIR_FREE(*path);
    *path = newstr;

    return 0;
}


static bool
virCgroupValidateMachineGroup(virCgroupPtr group,
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
                      tmp, virCgroupControllerTypeToString(i),
                      name, machinename, partname,
                      scopename_old, scopename_new);
            return false;
        }
    }

    return true;
}


static int
virCgroupCopyMounts(virCgroupPtr group,
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
virCgroupResolveMountLink(const char *mntDir,
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
virCgroupMountOptsMatchController(const char *mntOpts,
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


/*
 * Process /proc/mounts figuring out what controllers are
 * mounted and where
 */
int
virCgroupDetectMountsFromFile(virCgroupPtr group,
                              const char *path,
                              bool checkLinks)
{
    size_t i;
    FILE *mounts = NULL;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];
    int ret = -1;

    mounts = fopen(path, "r");
    if (mounts == NULL) {
        virReportSystemError(errno, _("Unable to open %s"), path);
        return -1;
    }

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        if (STRNEQ(entry.mnt_type, "cgroup"))
            continue;

        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            const char *typestr = virCgroupControllerTypeToString(i);

            if (virCgroupMountOptsMatchController(entry.mnt_opts, typestr)) {
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
                if (VIR_STRDUP(controller->mountPoint, entry.mnt_dir) < 0)
                    goto cleanup;

                /* If it is a co-mount it has a filename like "cpu,cpuacct"
                 * and we must identify the symlink path */
                if (checkLinks &&
                    virCgroupResolveMountLink(entry.mnt_dir, typestr,
                                              controller) < 0) {
                    goto cleanup;
                }
            }
        }
    }

    ret = 0;
 cleanup:
    VIR_FORCE_FCLOSE(mounts);
    return ret;
}

static int
virCgroupDetectMounts(virCgroupPtr group)
{
    return virCgroupDetectMountsFromFile(group, "/proc/mounts", true);
}


static int
virCgroupCopyPlacement(virCgroupPtr group,
                       const char *path,
                       virCgroupPtr parent)
{
    size_t i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->controllers[i].mountPoint)
            continue;

        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        if (path[0] == '/') {
            if (VIR_STRDUP(group->controllers[i].placement, path) < 0)
                return -1;
        } else {
            /*
             * parent == "/" + path="" => "/"
             * parent == "/libvirt.service" + path == "" => "/libvirt.service"
             * parent == "/libvirt.service" + path == "foo" => "/libvirt.service/foo"
             */
            if (virAsprintf(&group->controllers[i].placement,
                            "%s%s%s",
                            parent->controllers[i].placement,
                            (STREQ(parent->controllers[i].placement, "/") ||
                             STREQ(path, "") ? "" : "/"),
                            path) < 0)
                return -1;
        }
    }

    return 0;
}


/*
 * virCgroupDetectPlacement:
 * @group: the group to process
 * @path: the relative path to append, not starting with '/'
 *
 * Process /proc/self/cgroup figuring out what cgroup
 * sub-path the current process is assigned to. ie not
 * necessarily in the root. The contents of this file
 * looks like
 *
 * 9:perf_event:/
 * 8:blkio:/
 * 7:net_cls:/
 * 6:freezer:/
 * 5:devices:/
 * 4:memory:/
 * 3:cpuacct,cpu:/
 * 2:cpuset:/
 * 1:name=systemd:/user/berrange/2
 *
 * It then appends @path to each detected path.
 */
static int
virCgroupDetectPlacement(virCgroupPtr group,
                         pid_t pid,
                         const char *path)
{
    size_t i;
    FILE *mapping  = NULL;
    char line[1024];
    int ret = -1;
    VIR_AUTOFREE(char *) procfile = NULL;

    VIR_DEBUG("Detecting placement for pid %lld path %s",
              (long long) pid, path);
    if (pid == -1) {
        if (VIR_STRDUP(procfile, "/proc/self/cgroup") < 0)
            goto cleanup;
    } else {
        if (virAsprintf(&procfile, "/proc/%lld/cgroup",
                        (long long) pid) < 0)
            goto cleanup;
    }

    mapping = fopen(procfile, "r");
    if (mapping == NULL) {
        virReportSystemError(errno,
                             _("Unable to open '%s'"),
                             procfile);
        goto cleanup;
    }

    while (fgets(line, sizeof(line), mapping) != NULL) {
        char *controllers = strchr(line, ':');
        char *selfpath = controllers ? strchr(controllers + 1, ':') : NULL;
        char *nl = selfpath ? strchr(selfpath, '\n') : NULL;

        if (!controllers || !selfpath)
            continue;

        if (nl)
            *nl = '\0';

        *selfpath = '\0';
        controllers++;
        selfpath++;

        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            const char *typestr = virCgroupControllerTypeToString(i);

            if (virCgroupMountOptsMatchController(controllers, typestr) &&
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
                        goto cleanup;
                } else {
                    if (virAsprintf(&group->controllers[i].placement,
                                    "%s%s%s", selfpath,
                                    (STREQ(selfpath, "/") ||
                                     STREQ(path, "") ? "" : "/"),
                                    path) < 0)
                        goto cleanup;
                }
            }
        }
    }

    ret = 0;

 cleanup:
    VIR_FORCE_FCLOSE(mapping);
    return ret;
}


static int
virCgroupValidatePlacement(virCgroupPtr group,
                           pid_t pid)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->controllers[i].mountPoint)
            continue;

        if (!group->controllers[i].placement) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find placement for controller %s at %s"),
                           virCgroupControllerTypeToString(i),
                           group->controllers[i].placement);
            return -1;
        }

        VIR_DEBUG("Detected mount/mapping %zu:%s at %s in %s for pid %lld",
                  i,
                  virCgroupControllerTypeToString(i),
                  group->controllers[i].mountPoint,
                  group->controllers[i].placement,
                  (long long) pid);
    }

    return 0;
}


static int
virCgroupDetectControllers(virCgroupPtr group,
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
                if (!group->controllers[i].mountPoint) {
                    VIR_DEBUG("Requested controller '%s' not mounted, ignoring",
                              virCgroupControllerTypeToString(i));
                    controllers &= ~(1 << i);
                }
            }
        }
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            VIR_DEBUG("Controller '%s' wanted=%s, mount='%s'",
                      virCgroupControllerTypeToString(i),
                      (1 << i) & controllers ? "yes" : "no",
                      NULLSTR(group->controllers[i].mountPoint));
            if (!((1 << i) & controllers) &&
                group->controllers[i].mountPoint) {
                /* Check whether a request to disable a controller
                 * clashes with co-mounting of controllers */
                for (j = 0; j < VIR_CGROUP_CONTROLLER_LAST; j++) {
                    if (j == i)
                        continue;
                    if (!((1 << j) & controllers))
                        continue;

                    if (STREQ_NULLABLE(group->controllers[i].mountPoint,
                                       group->controllers[j].mountPoint)) {
                        virReportSystemError(EINVAL,
                                             _("Controller '%s' is not wanted, but '%s' is co-mounted"),
                                             virCgroupControllerTypeToString(i),
                                             virCgroupControllerTypeToString(j));
                        return -1;
                    }
                }
                VIR_FREE(group->controllers[i].mountPoint);
            }
        }
    } else {
        VIR_DEBUG("Auto-detecting controllers");
        controllers = 0;
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            VIR_DEBUG("Controller '%s' present=%s",
                      virCgroupControllerTypeToString(i),
                      group->controllers[i].mountPoint ? "yes" : "no");
            if (group->controllers[i].mountPoint == NULL)
                continue;
            controllers |= (1 << i);
        }
    }

    return controllers;
}


static int
virCgroupDetect(virCgroupPtr group,
                pid_t pid,
                int controllers,
                const char *path,
                virCgroupPtr parent)
{
    int rc;

    VIR_DEBUG("group=%p controllers=%d path=%s parent=%p",
              group, controllers, path, parent);

    if (parent) {
        if (virCgroupCopyMounts(group, parent) < 0)
            return -1;
    } else {
        if (virCgroupDetectMounts(group) < 0)
            return -1;
    }

    rc = virCgroupDetectControllers(group, controllers);
    if (rc < 0)
        return -1;

    /* Check that at least 1 controller is available */
    if (rc == 0) {
        virReportSystemError(ENXIO, "%s",
                             _("At least one cgroup controller is required"));
        return -1;
    }

    /* In some cases we can copy part of the placement info
     * based on the parent cgroup...
     */
    if ((parent || path[0] == '/') &&
        virCgroupCopyPlacement(group, path, parent) < 0)
        return -1;

    /* ... but use /proc/cgroups to fill in the rest */
    if (virCgroupDetectPlacement(group, pid, path) < 0)
        return -1;

    /* Check that for every mounted controller, we found our placement */
    if (virCgroupValidatePlacement(group, pid) < 0)
        return -1;

    return 0;
}


static char *
virCgroupGetBlockDevString(const char *path)
{
    char *ret = NULL;
    struct stat sb;

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Path '%s' is not accessible"),
                             path);
        return NULL;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportSystemError(EINVAL,
                             _("Path '%s' must be a block device"),
                             path);
        return NULL;
    }

    /* Automatically append space after the string since all callers
     * use it anyway */
    if (virAsprintf(&ret, "%d:%d ", major(sb.st_rdev), minor(sb.st_rdev)) < 0)
        return NULL;

    return ret;
}


static int
virCgroupSetValueStr(virCgroupPtr group,
                     int controller,
                     const char *key,
                     const char *value)
{
    VIR_AUTOFREE(char *) keypath = NULL;
    char *tmp = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    VIR_DEBUG("Set value '%s' to '%s'", keypath, value);
    if (virFileWriteStr(keypath, value, 0) < 0) {
        if (errno == EINVAL &&
            (tmp = strrchr(keypath, '/'))) {
            virReportSystemError(errno,
                                 _("Invalid value '%s' for '%s'"),
                                 value, tmp + 1);
            return -1;
        }
        virReportSystemError(errno,
                             _("Unable to write to '%s'"), keypath);
        return -1;
    }

    return 0;
}


static int
virCgroupGetValueStr(virCgroupPtr group,
                     int controller,
                     const char *key,
                     char **value)
{
    VIR_AUTOFREE(char *) keypath = NULL;
    int rc;

    *value = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    VIR_DEBUG("Get value %s", keypath);

    if ((rc = virFileReadAll(keypath, 1024*1024, value)) < 0) {
        virReportSystemError(errno,
                             _("Unable to read from '%s'"), keypath);
        return -1;
    }

    /* Terminated with '\n' has sometimes harmful effects to the caller */
    if (rc > 0 && (*value)[rc - 1] == '\n')
        (*value)[rc - 1] = '\0';

    return 0;
}


static int
virCgroupGetValueForBlkDev(virCgroupPtr group,
                           int controller,
                           const char *key,
                           const char *path,
                           char **value)
{
    VIR_AUTOFREE(char *) prefix = NULL;
    VIR_AUTOFREE(char *) str = NULL;
    char **lines = NULL;
    int ret = -1;

    if (virCgroupGetValueStr(group, controller, key, &str) < 0)
        goto error;

    if (!(prefix = virCgroupGetBlockDevString(path)))
        goto error;

    if (!(lines = virStringSplit(str, "\n", -1)))
        goto error;

    if (VIR_STRDUP(*value, virStringListGetFirstWithPrefix(lines, prefix)) < 0)
        goto error;

    ret = 0;
 error:
    virStringListFree(lines);
    return ret;
}


static int
virCgroupSetValueU64(virCgroupPtr group,
                     int controller,
                     const char *key,
                     unsigned long long int value)
{
    VIR_AUTOFREE(char *) strval = NULL;

    if (virAsprintf(&strval, "%llu", value) < 0)
        return -1;

    return virCgroupSetValueStr(group, controller, key, strval);
}


static int
virCgroupSetValueI64(virCgroupPtr group,
                     int controller,
                     const char *key,
                     long long int value)
{
    VIR_AUTOFREE(char *) strval = NULL;

    if (virAsprintf(&strval, "%lld", value) < 0)
        return -1;

    return virCgroupSetValueStr(group, controller, key, strval);
}


static int
virCgroupGetValueI64(virCgroupPtr group,
                     int controller,
                     const char *key,
                     long long int *value)
{
    VIR_AUTOFREE(char *) strval = NULL;

    if (virCgroupGetValueStr(group, controller, key, &strval) < 0)
        return -1;

    if (virStrToLong_ll(strval, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       strval);
        return -1;
    }

    return 0;
}


static int
virCgroupGetValueU64(virCgroupPtr group,
                     int controller,
                     const char *key,
                     unsigned long long int *value)
{
    VIR_AUTOFREE(char *) strval = NULL;

    if (virCgroupGetValueStr(group, controller, key, &strval) < 0)
        return -1;

    if (virStrToLong_ull(strval, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%s' as an integer"),
                       strval);
        return -1;
    }

    return 0;
}


static int
virCgroupCpuSetInherit(virCgroupPtr parent, virCgroupPtr group)
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
virCgroupSetMemoryUseHierarchy(virCgroupPtr group)
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
virCgroupMakeGroup(virCgroupPtr parent,
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
        if (!group->controllers[i].mountPoint) {
            VIR_DEBUG("Skipping unmounted controller %s",
                      virCgroupControllerTypeToString(i));
            continue;
        }

        if (virCgroupPathOfController(group, i, "", &path) < 0)
            goto error;

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
                    VIR_FREE(group->controllers[i].mountPoint);
                    continue;
                } else {
                    virReportSystemError(errno,
                                         _("Failed to create controller %s for group"),
                                         virCgroupControllerTypeToString(i));
                    goto error;
                }
            }
            if (i == VIR_CGROUP_CONTROLLER_CPUSET &&
                group->controllers[i].mountPoint != NULL &&
                virCgroupCpuSetInherit(parent, group) < 0) {
                goto error;
            }
            /*
             * Note that virCgroupSetMemoryUseHierarchy should always be
             * called prior to creating subcgroups and attaching tasks.
             */
            if ((flags & VIR_CGROUP_MEM_HIERACHY) &&
                i == VIR_CGROUP_CONTROLLER_MEMORY &&
                group->controllers[i].mountPoint != NULL &&
                virCgroupSetMemoryUseHierarchy(group) < 0) {
                goto error;
            }
        }
    }

    VIR_DEBUG("Done making controllers for group");
    return 0;

 error:
    virCgroupRemove(group);
    return -1;
}


/**
 * virCgroupNew:
 * @path: path for the new group
 * @parent: parent group, or NULL
 * @controllers: bitmask of controllers to activate
 *
 * Create a new cgroup storing it in @group.
 *
 * If @path starts with a '/' it is treated as an
 * absolute path, and @parent is ignored. Otherwise
 * it is treated as being relative to @parent. If
 * @parent is NULL, then the placement of the current
 * process is used.
 *
 * Returns 0 on success, -1 on error
 */
static int
virCgroupNew(pid_t pid,
             const char *path,
             virCgroupPtr parent,
             int controllers,
             virCgroupPtr *group)
{
    VIR_DEBUG("pid=%lld path=%s parent=%p controllers=%d group=%p",
              (long long) pid, path, parent, controllers, group);
    *group = NULL;

    if (VIR_ALLOC((*group)) < 0)
        goto error;

    if (path[0] == '/' || !parent) {
        if (VIR_STRDUP((*group)->path, path) < 0)
            goto error;
    } else {
        if (virAsprintf(&(*group)->path, "%s%s%s",
                        parent->path,
                        STREQ(parent->path, "") ? "" : "/",
                        path) < 0)
            goto error;
    }

    if (virCgroupDetect(*group, pid, controllers, path, parent) < 0)
        goto error;

    return 0;

 error:
    virCgroupFree(group);
    *group = NULL;

    return -1;
}


static int
virCgroupAddTaskInternal(virCgroupPtr group, pid_t pid, bool withSystemd)
{
    int ret = -1;
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Skip over controllers not mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        /* We must never add tasks in systemd's hierarchy
         * unless we're intentionally trying to move a
         * task into a systemd machine scope */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD && !withSystemd)
            continue;

        if (virCgroupSetValueI64(group, i, "tasks", pid) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

/**
 * virCgroupAddTask:
 *
 * @group: The cgroup to add a task to
 * @pid: The pid of the task to add
 *
 * Will add the task to all controllers, except the
 * systemd unit controller.
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupAddTask(virCgroupPtr group, pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid, false);
}

/**
 * virCgroupAddMachineTask:
 *
 * @group: The cgroup to add a task to
 * @pid: The pid of the task to add
 *
 * Will add the task to all controllers, including the
 * systemd unit controller.
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupAddMachineTask(virCgroupPtr group, pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid, true);
}


static int
virCgroupSetPartitionSuffix(const char *path, char **res)
{
    char **tokens;
    size_t i;
    int ret = -1;

    if (!(tokens = virStringSplit(path, "/", 0)))
        return ret;

    for (i = 0; tokens[i] != NULL; i++) {
        /* Whitelist the 3 top level fixed dirs
         * NB i == 0 is "", since we have leading '/'
         */
        if (i == 1 &&
            (STREQ(tokens[i], "machine") ||
             STREQ(tokens[i], "system") ||
             STREQ(tokens[i], "user"))) {
            continue;
        }
        /* If there is no suffix set already, then
         * add ".partition"
         */
        if (STRNEQ(tokens[i], "") &&
            !strchr(tokens[i], '.')) {
            if (VIR_REALLOC_N(tokens[i],
                              strlen(tokens[i]) + strlen(".partition") + 1) < 0)
                goto cleanup;
            strcat(tokens[i], ".partition");
        }

        if (virCgroupPartitionEscape(&(tokens[i])) < 0)
            goto cleanup;
    }

    if (!(*res = virStringListJoin((const char **)tokens, "/")))
        goto cleanup;

    ret = 0;

 cleanup:
    virStringListFree(tokens);
    return ret;
}


/**
 * virCgroupNewPartition:
 * @path: path for the partition
 * @create: true to create the cgroup tree
 * @controllers: mask of controllers to create
 *
 * Creates a new cgroup to represent the resource
 * partition path identified by @path.
 *
 * Returns 0 on success, -1 on failure
 */
int
virCgroupNewPartition(const char *path,
                      bool create,
                      int controllers,
                      virCgroupPtr *group)
{
    int ret = -1;
    VIR_AUTOFREE(char *) parentPath = NULL;
    VIR_AUTOFREE(char *) newPath = NULL;
    virCgroupPtr parent = NULL;
    VIR_DEBUG("path=%s create=%d controllers=%x",
              path, create, controllers);

    if (path[0] != '/') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Partition path '%s' must start with '/'"),
                       path);
        return -1;
    }

    if (virCgroupSetPartitionSuffix(path, &newPath) < 0)
        goto cleanup;

    if (virCgroupNew(-1, newPath, NULL, controllers, group) < 0)
        goto cleanup;

    if (STRNEQ(newPath, "/")) {
        char *tmp;
        if (VIR_STRDUP(parentPath, newPath) < 0)
            goto cleanup;

        tmp = strrchr(parentPath, '/');
        tmp++;
        *tmp = '\0';

        if (virCgroupNew(-1, parentPath, NULL, controllers, &parent) < 0)
            goto cleanup;

        if (virCgroupMakeGroup(parent, *group, create, VIR_CGROUP_NONE) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    if (ret != 0)
        virCgroupFree(group);
    virCgroupFree(&parent);
    return ret;
}


/**
* virCgroupNewSelf:
*
* @group: Pointer to returned virCgroupPtr
*
* Obtain a cgroup representing the config of the
* current process
*
* Returns 0 on success, or -1 on error
*/
int
virCgroupNewSelf(virCgroupPtr *group)
{
    return virCgroupNewDetect(-1, -1, group);
}


/**
 * virCgroupNewDomainPartition:
 *
 * @partition: partition holding the domain
 * @driver: name of the driver
 * @name: name of the domain
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success, or -1 on error
 */
int
virCgroupNewDomainPartition(virCgroupPtr partition,
                            const char *driver,
                            const char *name,
                            bool create,
                            virCgroupPtr *group)
{
    VIR_AUTOFREE(char *)grpname = NULL;

    if (virAsprintf(&grpname, "%s.libvirt-%s",
                    name, driver) < 0)
        return -1;

    if (virCgroupPartitionEscape(&grpname) < 0)
        return -1;

    if (virCgroupNew(-1, grpname, partition, -1, group) < 0)
        return -1;

    /*
     * Create a cgroup with memory.use_hierarchy enabled to
     * surely account memory usage of lxc with ns subsystem
     * enabled. (To be exact, memory and ns subsystems are
     * enabled at the same time.)
     *
     * The reason why doing it here, not a upper group, say
     * a group for driver, is to avoid overhead to track
     * cumulative usage that we don't need.
     */
    if (virCgroupMakeGroup(partition, *group, create,
                           VIR_CGROUP_MEM_HIERACHY) < 0) {
        virCgroupFree(group);
        return -1;
    }

    return 0;
}


/**
 * virCgroupNewThread:
 *
 * @domain: group for the domain
 * @name: enum to generate the name for the new thread
 * @id: id of the vcpu or iothread
 * @create: true to create if not already existing
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success, or -1 on error
 */
int
virCgroupNewThread(virCgroupPtr domain,
                   virCgroupThreadName nameval,
                   int id,
                   bool create,
                   virCgroupPtr *group)
{
    VIR_AUTOFREE(char *) name = NULL;
    int controllers;

    switch (nameval) {
    case VIR_CGROUP_THREAD_VCPU:
        if (virAsprintf(&name, "vcpu%d", id) < 0)
            return -1;
        break;
    case VIR_CGROUP_THREAD_EMULATOR:
        if (VIR_STRDUP(name, "emulator") < 0)
            return -1;
        break;
    case VIR_CGROUP_THREAD_IOTHREAD:
        if (virAsprintf(&name, "iothread%d", id) < 0)
            return -1;
        break;
    case VIR_CGROUP_THREAD_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected name value %d"), nameval);
        return -1;
    }

    controllers = ((1 << VIR_CGROUP_CONTROLLER_CPU) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUSET));

    if (virCgroupNew(-1, name, domain, controllers, group) < 0)
        return -1;

    if (virCgroupMakeGroup(domain, *group, create, VIR_CGROUP_NONE) < 0) {
        virCgroupFree(group);
        return -1;
    }

    return 0;
}


int
virCgroupNewDetect(pid_t pid,
                   int controllers,
                   virCgroupPtr *group)
{
    return virCgroupNew(pid, "", NULL, controllers, group);
}


/*
 * Returns 0 on success (but @group may be NULL), -1 on fatal error
 */
int
virCgroupNewDetectMachine(const char *name,
                          const char *drivername,
                          pid_t pid,
                          int controllers,
                          char *machinename,
                          virCgroupPtr *group)
{
    if (virCgroupNewDetect(pid, controllers, group) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;
        return -1;
    }

    if (!virCgroupValidateMachineGroup(*group, name, drivername, machinename)) {
        VIR_DEBUG("Failed to validate machine name for '%s' driver '%s'",
                  name, drivername);
        virCgroupFree(group);
        return 0;
    }

    return 0;
}


static int
virCgroupEnableMissingControllers(char *path,
                                  pid_t pidleader,
                                  int controllers,
                                  virCgroupPtr *group)
{
    virCgroupPtr parent = NULL;
    char *offset = path;
    int ret = -1;

    if (virCgroupNew(pidleader,
                     "",
                     NULL,
                     controllers,
                     &parent) < 0)
        return ret;

    for (;;) {
        virCgroupPtr tmp;
        char *t = strchr(offset + 1, '/');
        if (t)
            *t = '\0';

        if (virCgroupNew(pidleader,
                         path,
                         parent,
                         controllers,
                         &tmp) < 0)
            goto cleanup;

        if (virCgroupMakeGroup(parent, tmp, true, VIR_CGROUP_NONE) < 0) {
            virCgroupFree(&tmp);
            goto cleanup;
        }
        if (t) {
            *t = '/';
            offset = t;
            virCgroupFree(&parent);
            parent = tmp;
        } else {
            *group = tmp;
            break;
        }
    }

    ret = 0;
 cleanup:
    virCgroupFree(&parent);
    return ret;
}


/*
 * Returns 0 on success, -1 on fatal error, -2 on systemd not available
 */
static int
virCgroupNewMachineSystemd(const char *name,
                           const char *drivername,
                           const unsigned char *uuid,
                           const char *rootdir,
                           pid_t pidleader,
                           bool isContainer,
                           size_t nnicindexes,
                           int *nicindexes,
                           const char *partition,
                           int controllers,
                           virCgroupPtr *group)
{
    int rv;
    virCgroupPtr init;
    VIR_AUTOFREE(char *) path = NULL;

    VIR_DEBUG("Trying to setup machine '%s' via systemd", name);
    if ((rv = virSystemdCreateMachine(name,
                                      drivername,
                                      uuid,
                                      rootdir,
                                      pidleader,
                                      isContainer,
                                      nnicindexes,
                                      nicindexes,
                                      partition)) < 0)
        return rv;

    if (controllers != -1)
        controllers |= (1 << VIR_CGROUP_CONTROLLER_SYSTEMD);

    VIR_DEBUG("Detecting systemd placement");
    if (virCgroupNewDetect(pidleader,
                           controllers,
                           &init) < 0)
        return -1;

    path = init->controllers[VIR_CGROUP_CONTROLLER_SYSTEMD].placement;
    init->controllers[VIR_CGROUP_CONTROLLER_SYSTEMD].placement = NULL;
    virCgroupFree(&init);

    if (!path || STREQ(path, "/") || path[0] != '/') {
        VIR_DEBUG("Systemd didn't setup its controller");
        return -2;
    }

    if (virCgroupEnableMissingControllers(path, pidleader,
                                          controllers, group) < 0) {
        return -1;
    }

    if (virCgroupAddTask(*group, pidleader) < 0) {
        virErrorPtr saved = virSaveLastError();
        virCgroupRemove(*group);
        virCgroupFree(group);
        if (saved) {
            virSetError(saved);
            virFreeError(saved);
        }
    }

    return 0;
}


/*
 * Returns 0 on success, -1 on fatal error
 */
int virCgroupTerminateMachine(const char *name)
{
    return virSystemdTerminateMachine(name);
}


static int
virCgroupNewMachineManual(const char *name,
                          const char *drivername,
                          pid_t pidleader,
                          const char *partition,
                          int controllers,
                          virCgroupPtr *group)
{
    virCgroupPtr parent = NULL;
    int ret = -1;

    VIR_DEBUG("Fallback to non-systemd setup");
    if (virCgroupNewPartition(partition,
                              STREQ(partition, "/machine"),
                              controllers,
                              &parent) < 0) {
        if (virCgroupNewIgnoreError())
            goto done;

        goto cleanup;
    }

    if (virCgroupNewDomainPartition(parent,
                                    drivername,
                                    name,
                                    true,
                                    group) < 0)
        goto cleanup;

    if (virCgroupAddTask(*group, pidleader) < 0) {
        virErrorPtr saved = virSaveLastError();
        virCgroupRemove(*group);
        virCgroupFree(group);
        if (saved) {
            virSetError(saved);
            virFreeError(saved);
        }
    }

 done:
    ret = 0;

 cleanup:
    virCgroupFree(&parent);
    return ret;
}


int
virCgroupNewMachine(const char *name,
                    const char *drivername,
                    const unsigned char *uuid,
                    const char *rootdir,
                    pid_t pidleader,
                    bool isContainer,
                    size_t nnicindexes,
                    int *nicindexes,
                    const char *partition,
                    int controllers,
                    virCgroupPtr *group)
{
    int rv;

    *group = NULL;

    if ((rv = virCgroupNewMachineSystemd(name,
                                         drivername,
                                         uuid,
                                         rootdir,
                                         pidleader,
                                         isContainer,
                                         nnicindexes,
                                         nicindexes,
                                         partition,
                                         controllers,
                                         group)) == 0)
        return 0;

    if (rv == -1)
        return -1;

    return virCgroupNewMachineManual(name,
                                     drivername,
                                     pidleader,
                                     partition,
                                     controllers,
                                     group);
}


bool
virCgroupNewIgnoreError(void)
{
    if (virLastErrorIsSystemErrno(ENXIO) ||
        virLastErrorIsSystemErrno(EPERM) ||
        virLastErrorIsSystemErrno(EACCES)) {
        virResetLastError();
        VIR_DEBUG("No cgroups present/configured/accessible, ignoring error");
        return true;
    }
    return false;
}


/**
 * virCgroupFree:
 *
 * @group: The group structure to free
 */
void
virCgroupFree(virCgroupPtr *group)
{
    size_t i;

    if (*group == NULL)
        return;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        VIR_FREE((*group)->controllers[i].mountPoint);
        VIR_FREE((*group)->controllers[i].linkPoint);
        VIR_FREE((*group)->controllers[i].placement);
    }

    VIR_FREE((*group)->path);
    VIR_FREE(*group);
}


/**
 * virCgroupHasController: query whether a cgroup controller is present
 *
 * @cgroup: The group structure to be queried, or NULL
 * @controller: cgroup subsystem id
 *
 * Returns true if a cgroup controller is mounted and is associated
 * with this cgroup object.
 */
bool
virCgroupHasController(virCgroupPtr cgroup, int controller)
{
    if (!cgroup)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;
    return cgroup->controllers[controller].mountPoint != NULL;
}


int
virCgroupPathOfController(virCgroupPtr group,
                          unsigned int controller,
                          const char *key,
                          char **path)
{
    if (controller >= VIR_CGROUP_CONTROLLER_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid controller id '%d'"), controller);
        return -1;
    }

    if (group->controllers[controller].mountPoint == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Controller '%s' is not mounted"),
                       virCgroupControllerTypeToString(controller));
        return -1;
    }

    if (group->controllers[controller].placement == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Controller '%s' is not enabled for group"),
                       virCgroupControllerTypeToString(controller));
        return -1;
    }

    if (virAsprintf(path, "%s%s/%s",
                    group->controllers[controller].mountPoint,
                    group->controllers[controller].placement,
                    key ? key : "") < 0)
        return -1;

    return 0;
}


/**
 * virCgroupGetBlkioIoServiced:
 *
 * @group: The cgroup to get throughput for
 * @bytes_read: Pointer to returned bytes read
 * @bytes_write: Pointer to returned bytes written
 * @requests_read: Pointer to returned read io ops
 * @requests_write: Pointer to returned write io ops
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioIoServiced(virCgroupPtr group,
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


/**
 * virCgroupGetBlkioIoDeviceServiced:
 *
 * @group: The cgroup to get throughput for
 * @path: The device to get throughput for
 * @bytes_read: Pointer to returned bytes read
 * @bytes_write: Pointer to returned bytes written
 * @requests_read: Pointer to returned read io ops
 * @requests_write: Pointer to returned write io ops
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioIoDeviceServiced(virCgroupPtr group,
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


/**
 * virCgroupSetBlkioWeight:
 *
 * @group: The cgroup to change io weight for
 * @weight: The Weight for this cgroup
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioWeight(virCgroupPtr group, unsigned int weight)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_BLKIO,
                                "blkio.weight",
                                weight);
}


/**
 * virCgroupGetBlkioWeight:
 *
 * @group: The cgroup to get weight for
 * @Weight: Pointer to returned weight
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioWeight(virCgroupPtr group, unsigned int *weight)
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

/**
 * virCgroupSetBlkioDeviceReadIops:
 * @group: The cgroup to change block io setting for
 * @path: The path of device
 * @riops: The new device read iops throttle, or 0 to clear
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioDeviceReadIops(virCgroupPtr group,
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


/**
 * virCgroupSetBlkioDeviceWriteIops:
 * @group: The cgroup to change block io setting for
 * @path: The path of device
 * @wiops: The new device write iops throttle, or 0 to clear
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioDeviceWriteIops(virCgroupPtr group,
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


/**
 * virCgroupSetBlkioDeviceReadBps:
 * @group: The cgroup to change block io setting for
 * @path: The path of device
 * @rbps: The new device read bps throttle, or 0 to clear
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioDeviceReadBps(virCgroupPtr group,
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

/**
 * virCgroupSetBlkioDeviceWriteBps:
 * @group: The cgroup to change block io setting for
 * @path: The path of device
 * @wbps: The new device write bps throttle, or 0 to clear
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioDeviceWriteBps(virCgroupPtr group,
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


/**
 * virCgroupSetBlkioDeviceWeight:
 * @group: The cgroup to change block io setting for
 * @path: The path of device
 * @weight: The new device weight (100-1000),
 * (10-1000) after kernel 2.6.39, or 0 to clear
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupSetBlkioDeviceWeight(virCgroupPtr group,
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

/**
 * virCgroupGetBlkioDeviceReadIops:
 * @group: The cgroup to gather block io setting for
 * @path: The path of device
 * @riops: Returned device read iops throttle, 0 if there is none
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioDeviceReadIops(virCgroupPtr group,
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

/**
 * virCgroupGetBlkioDeviceWriteIops:
 * @group: The cgroup to gather block io setting for
 * @path: The path of device
 * @wiops: Returned device write iops throttle, 0 if there is none
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioDeviceWriteIops(virCgroupPtr group,
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

/**
 * virCgroupGetBlkioDeviceReadBps:
 * @group: The cgroup to gather block io setting for
 * @path: The path of device
 * @rbps: Returned device read bps throttle, 0 if there is none
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioDeviceReadBps(virCgroupPtr group,
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

/**
 * virCgroupGetBlkioDeviceWriteBps:
 * @group: The cgroup to gather block io setting for
 * @path: The path of device
 * @wbps: Returned device write bps throttle, 0 if there is none
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioDeviceWriteBps(virCgroupPtr group,
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

/**
 * virCgroupGetBlkioDeviceWeight:
 * @group: The cgroup to gather block io setting for
 * @path: The path of device
 * @weight: Returned device weight, 0 if there is none
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetBlkioDeviceWeight(virCgroupPtr group,
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


/*
 * Retrieve the "memory.limit_in_bytes" value from the memory controller
 * root dir. This value cannot be modified by userspace and therefore
 * is the maximum limit value supported by cgroups on the local system.
 * Returns this value scaled to KB or falls back to the original
 * VIR_DOMAIN_MEMORY_PARAM_UNLIMITED. Either way, remember the return
 * value to avoid unnecessary cgroup filesystem access.
 */
static unsigned long long int virCgroupMemoryUnlimitedKB;
static virOnceControl virCgroupMemoryOnce = VIR_ONCE_CONTROL_INITIALIZER;

static void
virCgroupMemoryOnceInit(void)
{
    virCgroupPtr group;
    unsigned long long int mem_unlimited = 0ULL;

    if (virCgroupNew(-1, "/", NULL, -1, &group) < 0)
        goto cleanup;

    if (!virCgroupHasController(group, VIR_CGROUP_CONTROLLER_MEMORY))
        goto cleanup;

    ignore_value(virCgroupGetValueU64(group,
                                      VIR_CGROUP_CONTROLLER_MEMORY,
                                      "memory.limit_in_bytes",
                                      &mem_unlimited));
 cleanup:
    virCgroupFree(&group);
    virCgroupMemoryUnlimitedKB = mem_unlimited >> 10;
}

static unsigned long long int
virCgroupGetMemoryUnlimitedKB(void)
{
    if (virOnce(&virCgroupMemoryOnce, virCgroupMemoryOnceInit) < 0)
        VIR_DEBUG("Init failed, will fall back to defaults.");

    if (virCgroupMemoryUnlimitedKB)
        return virCgroupMemoryUnlimitedKB;
    else
        return VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;
}


/**
 * virCgroupSetMemory:
 *
 * @group: The cgroup to change memory for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupSetMemory(virCgroupPtr group, unsigned long long kb)
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


/**
 * virCgroupGetMemoryStat:
 *
 * @group: The cgroup to change memory for
 * @cache: page cache memory in KiB
 * @activeAnon: anonymous and swap cache memory in KiB
 * @inactiveAnon: anonymous and swap cache memory in KiB
 * @activeFile: file-backed memory in KiB
 * @inactiveFile: file-backed memory in KiB
 * @unevictable: memory that cannot be reclaimed KiB
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupGetMemoryStat(virCgroupPtr group,
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

    while (line) {
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


/**
 * virCgroupGetMemoryUsage:
 *
 * @group: The cgroup to change memory for
 * @kb: Pointer to returned used memory in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupGetMemoryUsage(virCgroupPtr group, unsigned long *kb)
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


/**
 * virCgroupSetMemoryHardLimit:
 *
 * @group: The cgroup to change memory hard limit for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupSetMemoryHardLimit(virCgroupPtr group, unsigned long long kb)
{
    return virCgroupSetMemory(group, kb);
}


/**
 * virCgroupGetMemoryHardLimit:
 *
 * @group: The cgroup to get the memory hard limit for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupGetMemoryHardLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupGetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


/**
 * virCgroupSetMemorySoftLimit:
 *
 * @group: The cgroup to change memory soft limit for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupSetMemorySoftLimit(virCgroupPtr group, unsigned long long kb)
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


/**
 * virCgroupGetMemorySoftLimit:
 *
 * @group: The cgroup to get the memory soft limit for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupGetMemorySoftLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.soft_limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupGetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


/**
 * virCgroupSetMemSwapHardLimit:
 *
 * @group: The cgroup to change mem+swap hard limit for
 * @kb: The mem+swap amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupSetMemSwapHardLimit(virCgroupPtr group, unsigned long long kb)
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


/**
 * virCgroupGetMemSwapHardLimit:
 *
 * @group: The cgroup to get mem+swap hard limit for
 * @kb: The mem+swap amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupGetMemSwapHardLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;

    if (virCgroupGetValueU64(group,
                             VIR_CGROUP_CONTROLLER_MEMORY,
                             "memory.memsw.limit_in_bytes", &limit_in_bytes) < 0)
        return -1;

    *kb = limit_in_bytes >> 10;
    if (*kb >= virCgroupGetMemoryUnlimitedKB())
        *kb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    return 0;
}


/**
 * virCgroupGetMemSwapUsage:
 *
 * @group: The cgroup to get mem+swap usage for
 * @kb: The mem+swap amount in kilobytes
 *
 * Returns: 0 on success
 */
int
virCgroupGetMemSwapUsage(virCgroupPtr group, unsigned long long *kb)
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


/**
 * virCgroupSetCpusetMems:
 *
 * @group: The cgroup to set cpuset.mems for
 * @mems: the numa nodes to set
 *
 * Returns: 0 on success
 */
int
virCgroupSetCpusetMems(virCgroupPtr group, const char *mems)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


/**
 * virCgroupGetCpusetMems:
 *
 * @group: The cgroup to get cpuset.mems for
 * @mems: the numa nodes to get
 *
 * Returns: 0 on success
 */
int
virCgroupGetCpusetMems(virCgroupPtr group, char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}


/**
 * virCgroupSetCpusetMemoryMigrate:
 *
 * @group: The cgroup to set cpuset.memory_migrate for
 * @migrate: Whether to migrate the memory on change or not
 *
 * Returns: 0 on success
 */
int
virCgroupSetCpusetMemoryMigrate(virCgroupPtr group, bool migrate)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.memory_migrate",
                                migrate ? "1" : "0");
}


/**
 * virCgroupGetCpusetMemoryMigrate:
 *
 * @group: The cgroup to get cpuset.memory_migrate for
 * @migrate: Migration setting
 *
 * Returns: 0 on success
 */
int
virCgroupGetCpusetMemoryMigrate(virCgroupPtr group, bool *migrate)
{
    unsigned long long value = 0;
    int ret = virCgroupGetValueU64(group,
                                   VIR_CGROUP_CONTROLLER_CPUSET,
                                   "cpuset.memory_migrate",
                                   &value);
    *migrate = !!value;
    return ret;
}


/**
 * virCgroupSetCpusetCpus:
 *
 * @group: The cgroup to set cpuset.cpus for
 * @cpus: the cpus to set
 *
 * Returns: 0 on success
 */
int
virCgroupSetCpusetCpus(virCgroupPtr group, const char *cpus)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


/**
 * virCgroupGetCpusetCpus:
 *
 * @group: The cgroup to get cpuset.cpus for
 * @cpus: the cpus to get
 *
 * Returns: 0 on success
 */
int
virCgroupGetCpusetCpus(virCgroupPtr group, char **cpus)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.cpus",
                                cpus);
}


/**
 * virCgroupDenyAllDevices:
 *
 * @group: The cgroup to deny all permissions, for all devices
 *
 * Returns: 0 on success
 */
int
virCgroupDenyAllDevices(virCgroupPtr group)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_DEVICES,
                                "devices.deny",
                                "a");
}

/**
 * virCgroupAllowAllDevices:
 *
 * Allows the permissiong for all devices by setting lines similar
 * to these ones (obviously the 'm' permission is an example):
 *
 * 'b *:* m'
 * 'c *:* m'
 *
 * @group: The cgroup to allow devices for
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 *
 * Returns: 0 on success
 */
int
virCgroupAllowAllDevices(virCgroupPtr group, int perms)
{
    int ret = -1;

    if (virCgroupAllowDevice(group, 'b', -1, -1, perms) < 0)
        goto cleanup;

    if (virCgroupAllowDevice(group, 'c', -1, -1, perms) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    return ret;
}


/**
 * virCgroupAllowDevice:
 *
 * @group: The cgroup to allow a device for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device, a negative value means '*'
 * @minor: The minor number of the device, a negative value means '*'
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 *
 * Returns: 0 on success
 */
int
virCgroupAllowDevice(virCgroupPtr group, char type, int major, int minor,
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


/**
 * virCgroupAllowDevicePath:
 *
 * @group: The cgroup to allow the device for
 * @path: the device to allow
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 * @ignoreEacces: Ignore lack of permission (mostly for NFS mounts)
 *
 * Queries the type of device and its major/minor number, and
 * adds that to the cgroup ACL
 *
 * Returns: 0 on success, 1 if path exists but is not a device or is not
 * accesible, or * -1 on error
 */
int
virCgroupAllowDevicePath(virCgroupPtr group,
                         const char *path,
                         int perms,
                         bool ignoreEacces)
{
    struct stat sb;

    if (stat(path, &sb) < 0) {
        if (errno == EACCES && ignoreEacces)
            return 1;

        virReportSystemError(errno,
                             _("Path '%s' is not accessible"),
                             path);
        return -1;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    return virCgroupAllowDevice(group,
                                S_ISCHR(sb.st_mode) ? 'c' : 'b',
                                major(sb.st_rdev),
                                minor(sb.st_rdev),
                                perms);
}


/**
 * virCgroupDenyDevice:
 *
 * @group: The cgroup to deny a device for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device, a negative value means '*'
 * @minor: The minor number of the device, a negative value means '*'
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to deny
 *
 * Returns: 0 on success
 */
int
virCgroupDenyDevice(virCgroupPtr group, char type, int major, int minor,
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


/**
 * virCgroupDenyDevicePath:
 *
 * @group: The cgroup to deny the device for
 * @path: the device to deny
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 * @ignoreEacces: Ignore lack of permission (mostly for NFS mounts)
 *
 * Queries the type of device and its major/minor number, and
 * removes it from the cgroup ACL
 *
 * Returns: 0 on success, 1 if path exists but is not a device or is not
 * accessible, or -1 on error.
 */
int
virCgroupDenyDevicePath(virCgroupPtr group,
                        const char *path,
                        int perms,
                        bool ignoreEacces)
{
    struct stat sb;

    if (stat(path, &sb) < 0) {
        if (errno == EACCES && ignoreEacces)
            return 1;

        virReportSystemError(errno,
                             _("Path '%s' is not accessible"),
                             path);
        return -1;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    return virCgroupDenyDevice(group,
                               S_ISCHR(sb.st_mode) ? 'c' : 'b',
                               major(sb.st_rdev),
                               minor(sb.st_rdev),
                               perms);
}


/* This function gets the sums of cpu time consumed by all vcpus.
 * For example, if there are 4 physical cpus, and 2 vcpus in a domain,
 * then for each vcpu, the cpuacct.usage_percpu looks like this:
 *   t0 t1 t2 t3
 * and we have 2 groups of such data:
 *   v\p   0   1   2   3
 *   0   t00 t01 t02 t03
 *   1   t10 t11 t12 t13
 * for each pcpu, the sum is cpu time consumed by all vcpus.
 *   s0 = t00 + t10
 *   s1 = t01 + t11
 *   s2 = t02 + t12
 *   s3 = t03 + t13
 */
static int
virCgroupGetPercpuVcpuSum(virCgroupPtr group,
                          virBitmapPtr guestvcpus,
                          unsigned long long *sum_cpu_time,
                          size_t nsum,
                          virBitmapPtr cpumap)
{
    int ret = -1;
    ssize_t i = -1;
    virCgroupPtr group_vcpu = NULL;

    while ((i = virBitmapNextSetBit(guestvcpus, i)) >= 0) {
        VIR_AUTOFREE(char *) buf = NULL;
        char *pos;
        unsigned long long tmp;
        ssize_t j;

        if (virCgroupNewThread(group, VIR_CGROUP_THREAD_VCPU, i,
                               false, &group_vcpu) < 0)
            goto cleanup;

        if (virCgroupGetCpuacctPercpuUsage(group_vcpu, &buf) < 0)
            goto cleanup;

        pos = buf;
        for (j = virBitmapNextSetBit(cpumap, -1);
             j >= 0 && j < nsum;
             j = virBitmapNextSetBit(cpumap, j)) {
            if (virStrToLong_ull(pos, &pos, 10, &tmp) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cpuacct parse error"));
                goto cleanup;
            }
            sum_cpu_time[j] += tmp;
        }

        virCgroupFree(&group_vcpu);
    }

    ret = 0;
 cleanup:
    virCgroupFree(&group_vcpu);
    return ret;
}


/**
 * virCgroupGetPercpuStats:
 * @cgroup: cgroup data structure
 * @params: typed parameter array where data is returned
 * @nparams: cardinality of @params
 * @start_cpu: offset of physical CPU to get data for
 * @ncpus: number of physical CPUs to get data for
 * @nvcpupids: number of vCPU threads for a domain (actual number of vcpus)
 *
 * This function is the worker that retrieves data in the appropriate format
 * for the terribly designed 'virDomainGetCPUStats' API. Sharing semantics with
 * the API, this function has two modes of operation depending on magic settings
 * of the input arguments. Please refer to docs of 'virDomainGetCPUStats' for
 * the usage patterns of the similarly named arguments.
 *
 * @nvcpupids determines the count of active vcpu threads for the vm. If the
 * threads could not be detected the percpu data is skipped.
 *
 * Please DON'T use this function anywhere else.
 */
int
virCgroupGetPercpuStats(virCgroupPtr group,
                        virTypedParameterPtr params,
                        unsigned int nparams,
                        int start_cpu,
                        unsigned int ncpus,
                        virBitmapPtr guestvcpus)
{
    int ret = -1;
    size_t i;
    int need_cpus, total_cpus;
    char *pos;
    VIR_AUTOFREE(char *) buf = NULL;
    VIR_AUTOFREE(unsigned long long *) sum_cpu_time = NULL;
    virTypedParameterPtr ent;
    int param_idx;
    unsigned long long cpu_time;
    virBitmapPtr cpumap = NULL;

    /* return the number of supported params */
    if (nparams == 0 && ncpus != 0) {
        if (!guestvcpus)
            return CGROUP_NB_PER_CPU_STAT_PARAM;
        else
            return CGROUP_NB_PER_CPU_STAT_PARAM + 1;
    }

    /* To parse account file, we need to know how many cpus are present.  */
    if (!(cpumap = virHostCPUGetPresentBitmap()))
        return -1;

    total_cpus = virBitmapSize(cpumap);

    /* return total number of cpus */
    if (ncpus == 0) {
        ret = total_cpus;
        goto cleanup;
    }

    if (start_cpu >= total_cpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("start_cpu %d larger than maximum of %d"),
                       start_cpu, total_cpus - 1);
        goto cleanup;
    }

    /* we get percpu cputime accounting info. */
    if (virCgroupGetCpuacctPercpuUsage(group, &buf))
        goto cleanup;
    pos = buf;

    /* return percpu cputime in index 0 */
    param_idx = 0;

    /* number of cpus to compute */
    need_cpus = MIN(total_cpus, start_cpu + ncpus);

    for (i = 0; i < need_cpus; i++) {
        if (!virBitmapIsBitSet(cpumap, i)) {
            cpu_time = 0;
        } else if (virStrToLong_ull(pos, &pos, 10, &cpu_time) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("cpuacct parse error"));
            goto cleanup;
        }
        if (i < start_cpu)
            continue;
        ent = &params[(i - start_cpu) * nparams + param_idx];
        if (virTypedParameterAssign(ent, VIR_DOMAIN_CPU_STATS_CPUTIME,
                                    VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
            goto cleanup;
    }

    /* return percpu vcputime in index 1 */
    param_idx = 1;

    if (guestvcpus && param_idx < nparams) {
        if (VIR_ALLOC_N(sum_cpu_time, need_cpus) < 0)
            goto cleanup;
        if (virCgroupGetPercpuVcpuSum(group, guestvcpus, sum_cpu_time,
                                      need_cpus, cpumap) < 0)
            goto cleanup;

        for (i = start_cpu; i < need_cpus; i++) {
            if (virTypedParameterAssign(&params[(i - start_cpu) * nparams +
                                                param_idx],
                                        VIR_DOMAIN_CPU_STATS_VCPUTIME,
                                        VIR_TYPED_PARAM_ULLONG,
                                        sum_cpu_time[i]) < 0)
                goto cleanup;
        }

        param_idx++;
    }

    ret = param_idx;

 cleanup:
    virBitmapFree(cpumap);
    return ret;
}


int
virCgroupGetDomainTotalCpuStats(virCgroupPtr group,
                                virTypedParameterPtr params,
                                int nparams)
{
    unsigned long long cpu_time;
    int ret;

    if (nparams == 0) /* return supported number of params */
        return CGROUP_NB_TOTAL_CPU_STAT_PARAM;
    /* entry 0 is cputime */
    ret = virCgroupGetCpuacctUsage(group, &cpu_time);
    if (ret < 0) {
        virReportSystemError(-ret, "%s", _("unable to get cpu account"));
        return -1;
    }

    if (virTypedParameterAssign(&params[0], VIR_DOMAIN_CPU_STATS_CPUTIME,
                                VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
        return -1;

    if (nparams > 1) {
        unsigned long long user;
        unsigned long long sys;

        ret = virCgroupGetCpuacctStat(group, &user, &sys);
        if (ret < 0) {
            virReportSystemError(-ret, "%s", _("unable to get cpu account"));
            return -1;
        }

        if (virTypedParameterAssign(&params[1],
                                    VIR_DOMAIN_CPU_STATS_USERTIME,
                                    VIR_TYPED_PARAM_ULLONG, user) < 0)
            return -1;
        if (nparams > 2 &&
            virTypedParameterAssign(&params[2],
                                    VIR_DOMAIN_CPU_STATS_SYSTEMTIME,
                                    VIR_TYPED_PARAM_ULLONG, sys) < 0)
            return -1;

        if (nparams > CGROUP_NB_TOTAL_CPU_STAT_PARAM)
            nparams = CGROUP_NB_TOTAL_CPU_STAT_PARAM;
    }

    return nparams;
}


int
virCgroupSetCpuShares(virCgroupPtr group, unsigned long long shares)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}


int
virCgroupGetCpuShares(virCgroupPtr group, unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}


/**
 * virCgroupSetCpuCfsPeriod:
 *
 * @group: The cgroup to change cpu.cfs_period_us for
 * @cfs_period: The bandwidth period in usecs
 *
 * Returns: 0 on success
 */
int
virCgroupSetCpuCfsPeriod(virCgroupPtr group, unsigned long long cfs_period)
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


/**
 * virCgroupGetCpuCfsPeriod:
 *
 * @group: The cgroup to get cpu.cfs_period_us for
 * @cfs_period: Pointer to the returned bandwidth period in usecs
 *
 * Returns: 0 on success
 */
int
virCgroupGetCpuCfsPeriod(virCgroupPtr group, unsigned long long *cfs_period)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_period_us", cfs_period);
}


/**
 * virCgroupSetCpuCfsQuota:
 *
 * @group: The cgroup to change cpu.cfs_quota_us for
 * @cfs_quota: the cpu bandwidth (in usecs) that this tg will be allowed to
 *             consume over period
 *
 * Returns: 0 on success
 */
int
virCgroupSetCpuCfsQuota(virCgroupPtr group, long long cfs_quota)
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


int
virCgroupGetCpuacctPercpuUsage(virCgroupPtr group, char **usage)
{
    return virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage_percpu", usage);
}


static int
virCgroupRemoveRecursively(char *grppath)
{
    DIR *grpdir;
    struct dirent *ent;
    int rc = 0;
    int direrr;

    if (virDirOpenQuiet(&grpdir, grppath) < 0) {
        if (errno == ENOENT)
            return 0;
        rc = -errno;
        VIR_ERROR(_("Unable to open %s (%d)"), grppath, errno);
        return rc;
    }

    /* This is best-effort cleanup: we want to log failures with just
     * VIR_ERROR instead of normal virReportError */
    while ((direrr = virDirRead(grpdir, &ent, NULL)) > 0) {
        VIR_AUTOFREE(char *) path = NULL;

        if (ent->d_type != DT_DIR) continue;

        if (virAsprintf(&path, "%s/%s", grppath, ent->d_name) == -1) {
            rc = -ENOMEM;
            break;
        }
        rc = virCgroupRemoveRecursively(path);
        if (rc != 0)
            break;
    }
    if (direrr < 0) {
        rc = -errno;
        VIR_ERROR(_("Failed to readdir for %s (%d)"), grppath, errno);
    }

    VIR_DIR_CLOSE(grpdir);

    VIR_DEBUG("Removing cgroup %s", grppath);
    if (rmdir(grppath) != 0 && errno != ENOENT) {
        rc = -errno;
        VIR_ERROR(_("Unable to remove %s (%d)"), grppath, errno);
    }

    return rc;
}


/**
 * virCgroupRemove:
 *
 * @group: The group to be removed
 *
 * It first removes all child groups recursively
 * in depth first order and then removes @group
 * because the presence of the child groups
 * prevents removing @group.
 *
 * Returns: 0 on success
 */
int
virCgroupRemove(virCgroupPtr group)
{
    int rc = 0;
    size_t i;

    VIR_DEBUG("Removing cgroup %s", group->path);
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        VIR_AUTOFREE(char *) grppath = NULL;

        /* Skip over controllers not mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        /* We must never rmdir() in systemd's hierarchy */
        if (i == VIR_CGROUP_CONTROLLER_SYSTEMD)
            continue;

        /* Don't delete the root group, if we accidentally
           ended up in it for some reason */
        if (STREQ(group->controllers[i].placement, "/"))
            continue;

        if (virCgroupPathOfController(group,
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
virCgroupPathOfAnyController(virCgroupPtr group,
                             const char *name,
                             char **keypath)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Reject any controller with a placement
         * of '/' to avoid doing bad stuff to the root
         * cgroup
         */
        if (group->controllers[i].mountPoint &&
            group->controllers[i].placement &&
            STRNEQ(group->controllers[i].placement, "/")) {
            return virCgroupPathOfController(group, i, name, keypath);
        }
    }

    virReportSystemError(ENOSYS, "%s",
                         _("No controllers are mounted"));
    return -1;
}


/*
 * Returns 1 if some PIDs are killed, 0 if none are killed, or -1 on error
 */
static int
virCgroupKillInternal(virCgroupPtr group, int signum, virHashTablePtr pids)
{
    int ret = -1;
    bool killedAny = false;
    VIR_AUTOFREE(char *) keypath = NULL;
    bool done = false;
    FILE *fp = NULL;
    VIR_DEBUG("group=%p path=%s signum=%d pids=%p",
              group, group->path, signum, pids);

    if (virCgroupPathOfAnyController(group, "tasks", &keypath) < 0)
        return -1;

    /* PIDs may be forking as we kill them, so loop
     * until there are no new PIDs found
     */
    while (!done) {
        done = true;
        if (!(fp = fopen(keypath, "r"))) {
            if (errno == ENOENT) {
                VIR_DEBUG("No file %s, assuming done", keypath);
                killedAny = false;
                goto done;
            }

            virReportSystemError(errno,
                                 _("Failed to read %s"),
                                 keypath);
            goto cleanup;
        } else {
            while (!feof(fp)) {
                long pid_value;
                if (fscanf(fp, "%ld", &pid_value) != 1) {
                    if (feof(fp))
                        break;
                    virReportSystemError(errno,
                                         _("Failed to read %s"),
                                         keypath);
                    goto cleanup;
                }
                if (virHashLookup(pids, (void*)pid_value))
                    continue;

                VIR_DEBUG("pid=%ld", pid_value);
                /* Cgroups is a Linux concept, so this cast is safe.  */
                if (kill((pid_t)pid_value, signum) < 0) {
                    if (errno != ESRCH) {
                        virReportSystemError(errno,
                                             _("Failed to kill process %ld"),
                                             pid_value);
                        goto cleanup;
                    }
                    /* Leave RC == 0 since we didn't kill one */
                } else {
                    killedAny = true;
                    done = false;
                }

                ignore_value(virHashAddEntry(pids, (void*)pid_value, (void*)1));
            }
            VIR_FORCE_FCLOSE(fp);
        }
    }

 done:
    ret = killedAny ? 1 : 0;

 cleanup:
    VIR_FORCE_FCLOSE(fp);

    return ret;
}


static uint32_t
virCgroupPidCode(const void *name, uint32_t seed)
{
    long pid_value = (long)(intptr_t)name;
    return virHashCodeGen(&pid_value, sizeof(pid_value), seed);
}


static bool
virCgroupPidEqual(const void *namea, const void *nameb)
{
    return namea == nameb;
}


static void *
virCgroupPidCopy(const void *name)
{
    return (void*)name;
}


static int
virCgroupKillRecursiveInternal(virCgroupPtr group,
                               int signum,
                               virHashTablePtr pids,
                               bool dormdir)
{
    int ret = -1;
    int rc;
    bool killedAny = false;
    VIR_AUTOFREE(char *) keypath = NULL;
    DIR *dp = NULL;
    virCgroupPtr subgroup = NULL;
    struct dirent *ent;
    int direrr;
    VIR_DEBUG("group=%p path=%s signum=%d pids=%p",
              group, group->path, signum, pids);

    if (virCgroupPathOfAnyController(group, "", &keypath) < 0)
        return -1;

    if ((rc = virCgroupKillInternal(group, signum, pids)) < 0)
        goto cleanup;
    if (rc == 1)
        killedAny = true;

    VIR_DEBUG("Iterate over children of %s (killedAny=%d)", keypath, killedAny);
    if ((rc = virDirOpenIfExists(&dp, keypath)) < 0)
        goto cleanup;

    if (rc == 0) {
        VIR_DEBUG("Path %s does not exist, assuming done", keypath);
        killedAny = false;
        goto done;
    }

    while ((direrr = virDirRead(dp, &ent, keypath)) > 0) {
        if (ent->d_type != DT_DIR)
            continue;

        VIR_DEBUG("Process subdir %s", ent->d_name);

        if (virCgroupNew(-1, ent->d_name, group, -1, &subgroup) < 0)
            goto cleanup;

        if ((rc = virCgroupKillRecursiveInternal(subgroup, signum, pids,
                                                 true)) < 0)
            goto cleanup;
        if (rc == 1)
            killedAny = true;

        if (dormdir)
            virCgroupRemove(subgroup);

        virCgroupFree(&subgroup);
    }
    if (direrr < 0)
        goto cleanup;

 done:
    ret = killedAny ? 1 : 0;

 cleanup:
    virCgroupFree(&subgroup);
    VIR_DIR_CLOSE(dp);
    return ret;
}


int
virCgroupKillRecursive(virCgroupPtr group, int signum)
{
    int ret;
    VIR_DEBUG("group=%p path=%s signum=%d", group, group->path, signum);
    virHashTablePtr pids = virHashCreateFull(100,
                                             NULL,
                                             virCgroupPidCode,
                                             virCgroupPidEqual,
                                             virCgroupPidCopy,
                                             NULL);

    ret = virCgroupKillRecursiveInternal(group, signum, pids, false);

    virHashFree(pids);

    return ret;
}


int
virCgroupKillPainfully(virCgroupPtr group)
{
    size_t i;
    int ret;
    VIR_DEBUG("cgroup=%p path=%s", group, group->path);
    for (i = 0; i < 15; i++) {
        int signum;
        if (i == 0)
            signum = SIGTERM;
        else if (i == 8)
            signum = SIGKILL;
        else
            signum = 0; /* Just check for existence */

        ret = virCgroupKillRecursive(group, signum);
        VIR_DEBUG("Iteration %zu rc=%d", i, ret);
        /* If ret == -1 we hit error, if 0 we ran out of PIDs */
        if (ret <= 0)
            break;

        usleep(200 * 1000);
    }
    VIR_DEBUG("Complete %d", ret);
    return ret;
}


static char *
virCgroupIdentifyRoot(virCgroupPtr group)
{
    char *ret = NULL;
    size_t i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        char *tmp;
        if (!group->controllers[i].mountPoint)
            continue;
        if (!(tmp = strrchr(group->controllers[i].mountPoint, '/'))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Could not find directory separator in %s"),
                           group->controllers[i].mountPoint);
            return NULL;
        }

        if (VIR_STRNDUP(ret, group->controllers[i].mountPoint,
                        tmp - group->controllers[i].mountPoint) < 0)
            return NULL;
        return ret;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Could not find any mounted controllers"));
    return NULL;
}


/**
 * virCgroupGetCpuCfsQuota:
 *
 * @group: The cgroup to get cpu.cfs_quota_us for
 * @cfs_quota: Pointer to the returned cpu bandwidth (in usecs) that this tg
 *             will be allowed to consume over period
 *
 * Returns: 0 on success
 */
int
virCgroupGetCpuCfsQuota(virCgroupPtr group, long long *cfs_quota)
{
    return virCgroupGetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}


int
virCgroupGetCpuacctUsage(virCgroupPtr group, unsigned long long *usage)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage", usage);
}


int
virCgroupGetCpuacctStat(virCgroupPtr group, unsigned long long *user,
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


int
virCgroupSetFreezerState(virCgroupPtr group, const char *state)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


int
virCgroupGetFreezerState(virCgroupPtr group, char **state)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


int
virCgroupBindMount(virCgroupPtr group, const char *oldroot,
                   const char *mountopts)
{
    size_t i;
    VIR_AUTOFREE(char *) opts = NULL;
    VIR_AUTOFREE(char *) root = NULL;

    if (!(root = virCgroupIdentifyRoot(group)))
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
        if (!group->controllers[i].mountPoint)
            continue;

        if (!virFileExists(group->controllers[i].mountPoint)) {
            VIR_AUTOFREE(char *) src = NULL;
            if (virAsprintf(&src, "%s%s",
                            oldroot,
                            group->controllers[i].mountPoint) < 0)
                return -1;

            VIR_DEBUG("Create mount point '%s'",
                      group->controllers[i].mountPoint);
            if (virFileMakePath(group->controllers[i].mountPoint) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create directory %s"),
                                     group->controllers[i].mountPoint);
                return -1;
            }

            if (mount(src, group->controllers[i].mountPoint, "none", MS_BIND,
                      NULL) < 0) {
                virReportSystemError(errno,
                                     _("Failed to bind cgroup '%s' on '%s'"),
                                     src, group->controllers[i].mountPoint);
                return -1;
            }
        }

        if (group->controllers[i].linkPoint) {
            VIR_DEBUG("Link mount point '%s' to '%s'",
                      group->controllers[i].mountPoint,
                      group->controllers[i].linkPoint);
            if (symlink(group->controllers[i].mountPoint,
                        group->controllers[i].linkPoint) < 0) {
                virReportSystemError(errno,
                                     _("Unable to symlink directory %s to %s"),
                                     group->controllers[i].mountPoint,
                                     group->controllers[i].linkPoint);
                return -1;
            }
        }
    }

    return 0;
}


int virCgroupSetOwner(virCgroupPtr cgroup,
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

        if (!cgroup->controllers[i].mountPoint)
            continue;

        if (virAsprintf(&base, "%s%s", cgroup->controllers[i].mountPoint,
                        cgroup->controllers[i].placement) < 0)
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


/**
 * virCgroupSupportsCpuBW():
 * Check whether the host supports CFS bandwidth.
 *
 * Return true when CFS bandwidth is supported,
 * false when CFS bandwidth is not supported.
 */
bool
virCgroupSupportsCpuBW(virCgroupPtr cgroup)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (!cgroup)
        return false;

    if (virCgroupPathOfController(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                                  "cpu.cfs_period_us", &path) < 0) {
        virResetLastError();
        return false;
    }

    return virFileExists(path);
}

int
virCgroupHasEmptyTasks(virCgroupPtr cgroup, int controller)
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

bool
virCgroupControllerAvailable(int controller)
{
    virCgroupPtr cgroup;
    bool ret = false;

    if (virCgroupNewSelf(&cgroup) < 0)
        return ret;

    ret = virCgroupHasController(cgroup, controller);
    virCgroupFree(&cgroup);
    return ret;
}

#else /* !VIR_CGROUP_SUPPORTED */

bool
virCgroupAvailable(void)
{
    return false;
}


int
virCgroupDetectMountsFromFile(virCgroupPtr group ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED,
                              bool checkLinks ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewPartition(const char *path ATTRIBUTE_UNUSED,
                      bool create ATTRIBUTE_UNUSED,
                      int controllers ATTRIBUTE_UNUSED,
                      virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewSelf(virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDomainPartition(virCgroupPtr partition ATTRIBUTE_UNUSED,
                            const char *driver ATTRIBUTE_UNUSED,
                            const char *name ATTRIBUTE_UNUSED,
                            bool create ATTRIBUTE_UNUSED,
                            virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewThread(virCgroupPtr domain ATTRIBUTE_UNUSED,
                   virCgroupThreadName nameval ATTRIBUTE_UNUSED,
                   int id ATTRIBUTE_UNUSED,
                   bool create ATTRIBUTE_UNUSED,
                   virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDetect(pid_t pid ATTRIBUTE_UNUSED,
                   int controllers ATTRIBUTE_UNUSED,
                   virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDetectMachine(const char *name ATTRIBUTE_UNUSED,
                          const char *drivername ATTRIBUTE_UNUSED,
                          pid_t pid ATTRIBUTE_UNUSED,
                          int controllers ATTRIBUTE_UNUSED,
                          char *machinename ATTRIBUTE_UNUSED,
                          virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int virCgroupTerminateMachine(const char *name ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewMachine(const char *name ATTRIBUTE_UNUSED,
                    const char *drivername ATTRIBUTE_UNUSED,
                    const unsigned char *uuid ATTRIBUTE_UNUSED,
                    const char *rootdir ATTRIBUTE_UNUSED,
                    pid_t pidleader ATTRIBUTE_UNUSED,
                    bool isContainer ATTRIBUTE_UNUSED,
                    size_t nnicindexes ATTRIBUTE_UNUSED,
                    int *nicindexes ATTRIBUTE_UNUSED,
                    const char *partition ATTRIBUTE_UNUSED,
                    int controllers ATTRIBUTE_UNUSED,
                    virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


bool
virCgroupNewIgnoreError(void)
{
    VIR_DEBUG("No cgroups present/configured/accessible, ignoring error");
    return true;
}


void
virCgroupFree(virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
}


bool
virCgroupHasController(virCgroupPtr cgroup ATTRIBUTE_UNUSED,
                       int controller ATTRIBUTE_UNUSED)
{
    return false;
}


int
virCgroupPathOfController(virCgroupPtr group ATTRIBUTE_UNUSED,
                          unsigned int controller ATTRIBUTE_UNUSED,
                          const char *key ATTRIBUTE_UNUSED,
                          char **path ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddTask(virCgroupPtr group ATTRIBUTE_UNUSED,
                 pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddMachineTask(virCgroupPtr group ATTRIBUTE_UNUSED,
                        pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioIoServiced(virCgroupPtr group ATTRIBUTE_UNUSED,
                            long long *bytes_read ATTRIBUTE_UNUSED,
                            long long *bytes_write ATTRIBUTE_UNUSED,
                            long long *requests_read ATTRIBUTE_UNUSED,
                            long long *requests_write ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioIoDeviceServiced(virCgroupPtr group ATTRIBUTE_UNUSED,
                                  const char *path ATTRIBUTE_UNUSED,
                                  long long *bytes_read ATTRIBUTE_UNUSED,
                                  long long *bytes_write ATTRIBUTE_UNUSED,
                                  long long *requests_read ATTRIBUTE_UNUSED,
                                  long long *requests_write ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetBlkioWeight(virCgroupPtr group ATTRIBUTE_UNUSED,
                        unsigned int weight ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioWeight(virCgroupPtr group ATTRIBUTE_UNUSED,
                        unsigned int *weight ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetBlkioDeviceWeight(virCgroupPtr group ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED,
                              unsigned int weight ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetBlkioDeviceReadIops(virCgroupPtr group ATTRIBUTE_UNUSED,
                                const char *path ATTRIBUTE_UNUSED,
                                unsigned int riops ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetBlkioDeviceWriteIops(virCgroupPtr group ATTRIBUTE_UNUSED,
                                 const char *path ATTRIBUTE_UNUSED,
                                 unsigned int wiops ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetBlkioDeviceReadBps(virCgroupPtr group ATTRIBUTE_UNUSED,
                               const char *path ATTRIBUTE_UNUSED,
                               unsigned long long rbps ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetBlkioDeviceWriteBps(virCgroupPtr group ATTRIBUTE_UNUSED,
                                const char *path ATTRIBUTE_UNUSED,
                                unsigned long long wbps ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupGetBlkioDeviceWeight(virCgroupPtr group ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED,
                              unsigned int *weight ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupGetBlkioDeviceReadIops(virCgroupPtr group ATTRIBUTE_UNUSED,
                                const char *path ATTRIBUTE_UNUSED,
                                unsigned int *riops ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupGetBlkioDeviceWriteIops(virCgroupPtr group ATTRIBUTE_UNUSED,
                                 const char *path ATTRIBUTE_UNUSED,
                                 unsigned int *wiops ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupGetBlkioDeviceReadBps(virCgroupPtr group ATTRIBUTE_UNUSED,
                               const char *path ATTRIBUTE_UNUSED,
                               unsigned long long *rbps ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupGetBlkioDeviceWriteBps(virCgroupPtr group ATTRIBUTE_UNUSED,
                                const char *path ATTRIBUTE_UNUSED,
                                unsigned long long *wbps ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetMemory(virCgroupPtr group ATTRIBUTE_UNUSED,
                   unsigned long long kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryStat(virCgroupPtr group ATTRIBUTE_UNUSED,
                       unsigned long long *cache ATTRIBUTE_UNUSED,
                       unsigned long long *activeAnon ATTRIBUTE_UNUSED,
                       unsigned long long *inactiveAnon ATTRIBUTE_UNUSED,
                       unsigned long long *activeFile ATTRIBUTE_UNUSED,
                       unsigned long long *inactiveFile ATTRIBUTE_UNUSED,
                       unsigned long long *unevictable ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryUsage(virCgroupPtr group ATTRIBUTE_UNUSED,
                        unsigned long *kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemoryHardLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                            unsigned long long kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryHardLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                            unsigned long long *kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemorySoftLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                            unsigned long long kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemorySoftLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                            unsigned long long *kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemSwapHardLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                             unsigned long long kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemSwapHardLimit(virCgroupPtr group ATTRIBUTE_UNUSED,
                             unsigned long long *kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemSwapUsage(virCgroupPtr group ATTRIBUTE_UNUSED,
                         unsigned long long *kb ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetMems(virCgroupPtr group ATTRIBUTE_UNUSED,
                       const char *mems ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetMems(virCgroupPtr group ATTRIBUTE_UNUSED,
                       char **mems ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetMemoryMigrate(virCgroupPtr group ATTRIBUTE_UNUSED,
                                bool migrate ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetMemoryMigrate(virCgroupPtr group ATTRIBUTE_UNUSED,
                                bool *migrate ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetCpus(virCgroupPtr group ATTRIBUTE_UNUSED,
                       const char *cpus ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetCpus(virCgroupPtr group ATTRIBUTE_UNUSED,
                       char **cpus ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupAllowAllDevices(virCgroupPtr group ATTRIBUTE_UNUSED,
                         int perms ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupDenyAllDevices(virCgroupPtr group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAllowDevice(virCgroupPtr group ATTRIBUTE_UNUSED,
                     char type ATTRIBUTE_UNUSED,
                     int major ATTRIBUTE_UNUSED,
                     int minor ATTRIBUTE_UNUSED,
                     int perms ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAllowDevicePath(virCgroupPtr group ATTRIBUTE_UNUSED,
                         const char *path ATTRIBUTE_UNUSED,
                         int perms ATTRIBUTE_UNUSED,
                         bool ignoreEaccess ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupDenyDevice(virCgroupPtr group ATTRIBUTE_UNUSED,
                    char type ATTRIBUTE_UNUSED,
                    int major ATTRIBUTE_UNUSED,
                    int minor ATTRIBUTE_UNUSED,
                    int perms ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupDenyDevicePath(virCgroupPtr group ATTRIBUTE_UNUSED,
                        const char *path ATTRIBUTE_UNUSED,
                        int perms ATTRIBUTE_UNUSED,
                        bool ignoreEacces ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuShares(virCgroupPtr group ATTRIBUTE_UNUSED,
                      unsigned long long shares ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuShares(virCgroupPtr group ATTRIBUTE_UNUSED,
                      unsigned long long *shares ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuCfsPeriod(virCgroupPtr group ATTRIBUTE_UNUSED,
                         unsigned long long cfs_period ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuCfsPeriod(virCgroupPtr group ATTRIBUTE_UNUSED,
                         unsigned long long *cfs_period ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuCfsQuota(virCgroupPtr group ATTRIBUTE_UNUSED,
                        long long cfs_quota ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupRemove(virCgroupPtr group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupKillRecursive(virCgroupPtr group ATTRIBUTE_UNUSED,
                       int signum ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupKillPainfully(virCgroupPtr group ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuCfsQuota(virCgroupPtr group ATTRIBUTE_UNUSED,
                        long long *cfs_quota ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctUsage(virCgroupPtr group ATTRIBUTE_UNUSED,
                         unsigned long long *usage ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctPercpuUsage(virCgroupPtr group ATTRIBUTE_UNUSED,
                               char **usage ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctStat(virCgroupPtr group ATTRIBUTE_UNUSED,
                        unsigned long long *user ATTRIBUTE_UNUSED,
                        unsigned long long *sys ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetDomainTotalCpuStats(virCgroupPtr group ATTRIBUTE_UNUSED,
                                virTypedParameterPtr params ATTRIBUTE_UNUSED,
                                int nparams ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetFreezerState(virCgroupPtr group ATTRIBUTE_UNUSED,
                         const char *state ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetFreezerState(virCgroupPtr group ATTRIBUTE_UNUSED,
                         char **state ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupBindMount(virCgroupPtr group ATTRIBUTE_UNUSED,
                   const char *oldroot ATTRIBUTE_UNUSED,
                   const char *mountopts ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


bool
virCgroupSupportsCpuBW(virCgroupPtr cgroup ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("Control groups not supported on this platform");
    return false;
}


int
virCgroupGetPercpuStats(virCgroupPtr group ATTRIBUTE_UNUSED,
                        virTypedParameterPtr params ATTRIBUTE_UNUSED,
                        unsigned int nparams ATTRIBUTE_UNUSED,
                        int start_cpu ATTRIBUTE_UNUSED,
                        unsigned int ncpus ATTRIBUTE_UNUSED,
                        virBitmapPtr guestvcpus ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetOwner(virCgroupPtr cgroup ATTRIBUTE_UNUSED,
                  uid_t uid ATTRIBUTE_UNUSED,
                  gid_t gid ATTRIBUTE_UNUSED,
                  int controllers ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupHasEmptyTasks(virCgroupPtr cgroup ATTRIBUTE_UNUSED,
                       int controller ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

bool
virCgroupControllerAvailable(int controller ATTRIBUTE_UNUSED)
{
    return false;
}
#endif /* !VIR_CGROUP_SUPPORTED */


int
virCgroupDelThread(virCgroupPtr cgroup,
                   virCgroupThreadName nameval,
                   int idx)
{
    virCgroupPtr new_cgroup = NULL;

    if (cgroup) {
        if (virCgroupNewThread(cgroup, nameval, idx, false, &new_cgroup) < 0)
            return -1;

        /* Remove the offlined cgroup */
        virCgroupRemove(new_cgroup);
        virCgroupFree(&new_cgroup);
    }

    return 0;
}
