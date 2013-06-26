/*
 * vircgroup.c: methods for managing control cgroups
 *
 * Copyright (C) 2010-2013 Red Hat, Inc.
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
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# include <mntent.h>
#endif
#if defined HAVE_SYS_MOUNT_H
# include <sys/mount.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <dirent.h>

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

#define CGROUP_MAX_VAL 512

#define VIR_FROM_THIS VIR_FROM_CGROUP

VIR_ENUM_IMPL(virCgroupController, VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "blkio", "net_cls", "perf_event");

typedef enum {
    VIR_CGROUP_NONE = 0, /* create subdir under each cgroup if possible. */
    VIR_CGROUP_MEM_HIERACHY = 1 << 0, /* call virCgroupSetMemoryUseHierarchy
                                       * before creating subcgroups and
                                       * attaching tasks
                                       */
} virCgroupFlags;

/**
 * virCgroupFree:
 *
 * @group: The group structure to free
 */
void virCgroupFree(virCgroupPtr *group)
{
    int i;

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
bool virCgroupHasController(virCgroupPtr cgroup, int controller)
{
    if (!cgroup)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;
    return cgroup->controllers[controller].mountPoint != NULL;
}

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int virCgroupCopyMounts(virCgroupPtr group,
                               virCgroupPtr parent)
{
    int i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!parent->controllers[i].mountPoint)
            continue;

        if (VIR_STRDUP_QUIET(group->controllers[i].mountPoint,
                             parent->controllers[i].mountPoint) < 0)
            return -ENOMEM;

        if (VIR_STRDUP_QUIET(group->controllers[i].linkPoint,
                             parent->controllers[i].linkPoint) < 0)
            return -ENOMEM;
    }
    return 0;
}

/*
 * Process /proc/mounts figuring out what controllers are
 * mounted and where
 */
static int virCgroupDetectMounts(virCgroupPtr group)
{
    int i;
    FILE *mounts = NULL;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];

    mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL) {
        VIR_ERROR(_("Unable to open /proc/mounts"));
        return -ENOENT;
    }

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        if (STRNEQ(entry.mnt_type, "cgroup"))
            continue;

        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            const char *typestr = virCgroupControllerTypeToString(i);
            int typelen = strlen(typestr);
            char *tmp = entry.mnt_opts;
            while (tmp) {
                char *next = strchr(tmp, ',');
                int len;
                if (next) {
                    len = next-tmp;
                    next++;
                } else {
                    len = strlen(tmp);
                }
                /* NB, the same controller can appear >1 time in mount list
                 * due to bind mounts from one location to another. Pick the
                 * first entry only
                 */
                if (typelen == len && STREQLEN(typestr, tmp, len) &&
                    !group->controllers[i].mountPoint) {
                    char *linksrc;
                    struct stat sb;
                    char *tmp2;

                    if (VIR_STRDUP_QUIET(group->controllers[i].mountPoint,
                                         entry.mnt_dir) < 0)
                        goto error;

                    tmp2 = strrchr(entry.mnt_dir, '/');
                    if (!tmp2) {
                        errno = EINVAL;
                        goto error;
                    }
                    *tmp2 = '\0';
                    /* If it is a co-mount it has a filename like "cpu,cpuacct"
                     * and we must identify the symlink path */
                    if (strchr(tmp2 + 1, ',')) {
                        if (virAsprintf(&linksrc, "%s/%s",
                                        entry.mnt_dir, typestr) < 0)
                            goto error;
                        *tmp2 = '/';

                        if (lstat(linksrc, &sb) < 0) {
                            if (errno == ENOENT) {
                                VIR_WARN("Controller %s co-mounted at %s is missing symlink at %s",
                                         typestr, entry.mnt_dir, linksrc);
                                VIR_FREE(linksrc);
                            } else {
                                goto error;
                            }
                        } else {
                            if (!S_ISLNK(sb.st_mode)) {
                                VIR_WARN("Expecting a symlink at %s for controller %s",
                                         linksrc, typestr);
                            } else {
                                group->controllers[i].linkPoint = linksrc;
                            }
                        }
                    }
                }
                tmp = next;
            }
        }
    }

    VIR_FORCE_FCLOSE(mounts);

    return 0;

error:
    VIR_FORCE_FCLOSE(mounts);
    return -errno;
}


static int virCgroupCopyPlacement(virCgroupPtr group,
                                  const char *path,
                                  virCgroupPtr parent)
{
    int i;
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->controllers[i].mountPoint)
            continue;

        if (path[0] == '/') {
            if (VIR_STRDUP_QUIET(group->controllers[i].placement, path) < 0)
                return -ENOMEM;
        } else {
            /*
             * parent=="/" + path="" => "/"
             * parent=="/libvirt.service" + path=="" => "/libvirt.service"
             * parent=="/libvirt.service" + path=="foo" => "/libvirt.service/foo"
             */
            if (virAsprintf(&group->controllers[i].placement,
                            "%s%s%s",
                            parent->controllers[i].placement,
                            (STREQ(parent->controllers[i].placement, "/") ||
                             STREQ(path, "") ? "" : "/"),
                            path) < 0)
                return -ENOMEM;
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
static int virCgroupDetectPlacement(virCgroupPtr group,
                                    const char *path)
{
    int i;
    FILE *mapping  = NULL;
    char line[1024];

    mapping = fopen("/proc/self/cgroup", "r");
    if (mapping == NULL) {
        VIR_ERROR(_("Unable to open /proc/self/cgroup"));
        return -ENOENT;
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
            int typelen = strlen(typestr);
            char *tmp = controllers;
            while (tmp) {
                char *next = strchr(tmp, ',');
                int len;
                if (next) {
                    len = next - tmp;
                    next++;
                } else {
                    len = strlen(tmp);
                }

                /*
                 * selfpath=="/" + path="" -> "/"
                 * selfpath=="/libvirt.service" + path="" -> "/libvirt.service"
                 * selfpath=="/libvirt.service" + path="foo" -> "/libvirt.service/foo"
                 */
                if (typelen == len && STREQLEN(typestr, tmp, len)) {
                    if (virAsprintf(&group->controllers[i].placement,
                                    "%s%s%s", selfpath,
                                    (STREQ(selfpath, "/") ||
                                     STREQ(path, "") ? "" : "/"),
                                    path) < 0)
                        goto no_memory;
                }

                tmp = next;
            }
        }
    }

    VIR_FORCE_FCLOSE(mapping);

    return 0;

no_memory:
    VIR_FORCE_FCLOSE(mapping);
    return -ENOMEM;

}

static int virCgroupDetect(virCgroupPtr group,
                           int controllers,
                           const char *path,
                           virCgroupPtr parent)
{
    int rc;
    int i;
    int j;
    VIR_DEBUG("group=%p controllers=%d path=%s parent=%p",
              group, controllers, path, parent);

    if (parent)
        rc = virCgroupCopyMounts(group, parent);
    else
        rc = virCgroupDetectMounts(group);
    if (rc < 0) {
        VIR_ERROR(_("Failed to detect mounts for %s"), group->path);
        return rc;
    }

    if (controllers >= 0) {
        VIR_DEBUG("Filtering controllers %d", controllers);
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            VIR_DEBUG("Controller '%s' wanted=%s, mount='%s'",
                      virCgroupControllerTypeToString(i),
                      (1 << i) & controllers ? "yes" : "no",
                      NULLSTR(group->controllers[i].mountPoint));
            if (((1 << i) & controllers)) {
                /* Remove non-existent controllers  */
                if (!group->controllers[i].mountPoint) {
                    VIR_DEBUG("Requested controller '%s' not mounted, ignoring",
                              virCgroupControllerTypeToString(i));
                    controllers &= ~(1 << i);
                }
            } else {
                /* Check whether a request to disable a controller
                 * clashes with co-mounting of controllers */
                for (j = 0; j < VIR_CGROUP_CONTROLLER_LAST; j++) {
                    if (j == i)
                        continue;
                    if (!((1 << j) & controllers))
                        continue;

                    if (STREQ_NULLABLE(group->controllers[i].mountPoint,
                                       group->controllers[j].mountPoint)) {
                        VIR_DEBUG("Controller '%s' is not wanted, but '%s' is co-mounted",
                                  virCgroupControllerTypeToString(i),
                                  virCgroupControllerTypeToString(j));
                        return -EINVAL;
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

    /* Check that at least 1 controller is available */
    if (!controllers) {
        VIR_DEBUG("No controllers set");
        return -ENXIO;
    }

    if (parent || path[0] == '/')
        rc = virCgroupCopyPlacement(group, path, parent);
    else
        rc = virCgroupDetectPlacement(group, path);

    if (rc == 0) {
        /* Check that for every mounted controller, we found our placement */
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            if (!group->controllers[i].mountPoint)
                continue;

            if (!group->controllers[i].placement) {
                VIR_ERROR(_("Could not find placement for controller %s at %s"),
                          virCgroupControllerTypeToString(i),
                          group->controllers[i].placement);
                rc = -ENOENT;
                break;
            }

            VIR_DEBUG("Detected mount/mapping %i:%s at %s in %s", i,
                      virCgroupControllerTypeToString(i),
                      group->controllers[i].mountPoint,
                      group->controllers[i].placement);
        }
    } else {
        VIR_ERROR(_("Failed to detect mapping for %s"), group->path);
    }

    return rc;
}
#endif


int virCgroupPathOfController(virCgroupPtr group,
                              int controller,
                              const char *key,
                              char **path)
{
    if (controller == -1) {
        int i;
        for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
            if (group->controllers[i].mountPoint &&
                group->controllers[i].placement) {
                controller = i;
                break;
            }
        }
    }
    if (controller == -1)
        return -ENOSYS;

    if (group->controllers[controller].mountPoint == NULL)
        return -ENOENT;

    if (group->controllers[controller].placement == NULL)
        return -ENOENT;

    if (virAsprintf(path, "%s%s/%s",
                    group->controllers[controller].mountPoint,
                    group->controllers[controller].placement,
                    key ? key : "") == -1)
        return -ENOMEM;

    return 0;
}


static int virCgroupSetValueStr(virCgroupPtr group,
                                int controller,
                                const char *key,
                                const char *value)
{
    int rc = 0;
    char *keypath = NULL;

    rc = virCgroupPathOfController(group, controller, key, &keypath);
    if (rc != 0)
        return rc;

    VIR_DEBUG("Set value '%s' to '%s'", keypath, value);
    rc = virFileWriteStr(keypath, value, 0);
    if (rc < 0) {
        rc = -errno;
        VIR_DEBUG("Failed to write value '%s': %m", value);
    } else {
        rc = 0;
    }

    VIR_FREE(keypath);

    return rc;
}

static int virCgroupGetValueStr(virCgroupPtr group,
                                int controller,
                                const char *key,
                                char **value)
{
    int rc;
    char *keypath = NULL;

    *value = NULL;

    rc = virCgroupPathOfController(group, controller, key, &keypath);
    if (rc != 0) {
        VIR_DEBUG("No path of %s, %s", group->path, key);
        return rc;
    }

    VIR_DEBUG("Get value %s", keypath);

    rc = virFileReadAll(keypath, 1024*1024, value);
    if (rc < 0) {
        rc = -errno;
        VIR_DEBUG("Failed to read %s: %m\n", keypath);
    } else {
        /* Terminated with '\n' has sometimes harmful effects to the caller */
        if (rc > 0 && (*value)[rc - 1] == '\n')
            (*value)[rc - 1] = '\0';

        rc = 0;
    }

    VIR_FREE(keypath);

    return rc;
}

static int virCgroupSetValueU64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                unsigned long long int value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%llu", value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, controller, key, strval);

    VIR_FREE(strval);

    return rc;
}



static int virCgroupSetValueI64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                long long int value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%lld", value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, controller, key, strval);

    VIR_FREE(strval);

    return rc;
}

static int virCgroupGetValueI64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                long long int *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, controller, key, &strval);
    if (rc != 0)
        goto out;

    if (virStrToLong_ll(strval, NULL, 10, value) < 0)
        rc = -EINVAL;
out:
    VIR_FREE(strval);

    return rc;
}

static int virCgroupGetValueU64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                unsigned long long int *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, controller, key, &strval);
    if (rc != 0)
        goto out;

    if (virStrToLong_ull(strval, NULL, 10, value) < 0)
        rc = -EINVAL;
out:
    VIR_FREE(strval);

    return rc;
}


#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int virCgroupCpuSetInherit(virCgroupPtr parent, virCgroupPtr group)
{
    int i;
    int rc = 0;
    const char *inherit_values[] = {
        "cpuset.cpus",
        "cpuset.mems",
    };

    VIR_DEBUG("Setting up inheritance %s -> %s", parent->path, group->path);
    for (i = 0; i < ARRAY_CARDINALITY(inherit_values); i++) {
        char *value;

        rc = virCgroupGetValueStr(parent,
                                  VIR_CGROUP_CONTROLLER_CPUSET,
                                  inherit_values[i],
                                  &value);
        if (rc != 0) {
            VIR_ERROR(_("Failed to get %s %d"), inherit_values[i], rc);
            break;
        }

        VIR_DEBUG("Inherit %s = %s", inherit_values[i], value);

        rc = virCgroupSetValueStr(group,
                                  VIR_CGROUP_CONTROLLER_CPUSET,
                                  inherit_values[i],
                                  value);
        VIR_FREE(value);

        if (rc != 0) {
            VIR_ERROR(_("Failed to set %s %d"), inherit_values[i], rc);
            break;
        }
    }

    return rc;
}

static int virCgroupSetMemoryUseHierarchy(virCgroupPtr group)
{
    int rc = 0;
    unsigned long long value;
    const char *filename = "memory.use_hierarchy";

    rc = virCgroupGetValueU64(group,
                              VIR_CGROUP_CONTROLLER_MEMORY,
                              filename, &value);
    if (rc != 0) {
        VIR_ERROR(_("Failed to read %s/%s (%d)"), group->path, filename, rc);
        return rc;
    }

    /* Setting twice causes error, so if already enabled, skip setting */
    if (value == 1)
        return 0;

    VIR_DEBUG("Setting up %s/%s", group->path, filename);
    rc = virCgroupSetValueU64(group,
                              VIR_CGROUP_CONTROLLER_MEMORY,
                              filename, 1);

    if (rc != 0) {
        VIR_ERROR(_("Failed to set %s/%s (%d)"), group->path, filename, rc);
    }

    return rc;
}

static int virCgroupMakeGroup(virCgroupPtr parent,
                              virCgroupPtr group,
                              bool create,
                              unsigned int flags)
{
    int i;
    int rc = 0;

    VIR_DEBUG("Make group %s", group->path);
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        char *path = NULL;

        /* Skip over controllers that aren't mounted */
        if (!group->controllers[i].mountPoint) {
            VIR_DEBUG("Skipping unmounted controller %s",
                      virCgroupControllerTypeToString(i));
            continue;
        }

        rc = virCgroupPathOfController(group, i, "", &path);
        if (rc < 0) {
            VIR_DEBUG("Failed to find path of controller %s",
                      virCgroupControllerTypeToString(i));
            return rc;
        }
        /* As of Feb 2011, clang can't see that the above function
         * call did not modify group. */
        sa_assert(group->controllers[i].mountPoint);

        VIR_DEBUG("Make controller %s", path);
        if (access(path, F_OK) != 0) {
            if (!create ||
                mkdir(path, 0755) < 0) {
                /* With a kernel that doesn't support multi-level directory
                 * for blkio controller, libvirt will fail and disable all
                 * other controllers even though they are available. So
                 * treat blkio as unmounted if mkdir fails. */
                if (i == VIR_CGROUP_CONTROLLER_BLKIO) {
                    VIR_DEBUG("Ignoring mkdir failure with blkio controller. Kernel probably too old");
                    rc = 0;
                    VIR_FREE(group->controllers[i].mountPoint);
                    VIR_FREE(path);
                    continue;
                } else {
                    VIR_DEBUG("Failed to create controller %s for group",
                              virCgroupControllerTypeToString(i));
                    rc = -errno;
                    VIR_FREE(path);
                    break;
                }
            }
            if (group->controllers[VIR_CGROUP_CONTROLLER_CPUSET].mountPoint != NULL &&
                (i == VIR_CGROUP_CONTROLLER_CPUSET ||
                 STREQ(group->controllers[i].mountPoint, group->controllers[VIR_CGROUP_CONTROLLER_CPUSET].mountPoint))) {
                rc = virCgroupCpuSetInherit(parent, group);
                if (rc != 0) {
                    VIR_FREE(path);
                    break;
                }
            }
            /*
             * Note that virCgroupSetMemoryUseHierarchy should always be
             * called prior to creating subcgroups and attaching tasks.
             */
            if ((flags & VIR_CGROUP_MEM_HIERACHY) &&
                (group->controllers[VIR_CGROUP_CONTROLLER_MEMORY].mountPoint != NULL) &&
                (i == VIR_CGROUP_CONTROLLER_MEMORY ||
                 STREQ(group->controllers[i].mountPoint, group->controllers[VIR_CGROUP_CONTROLLER_MEMORY].mountPoint))) {
                rc = virCgroupSetMemoryUseHierarchy(group);
                if (rc != 0) {
                    VIR_FREE(path);
                    break;
                }
            }
        }

        VIR_FREE(path);
    }

    VIR_DEBUG("Done making controllers for group");
    return rc;
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
 */
static int virCgroupNew(const char *path,
                        virCgroupPtr parent,
                        int controllers,
                        virCgroupPtr *group)
{
    int rc = 0;
    char *typpath = NULL;

    VIR_DEBUG("parent=%p path=%s controllers=%d",
              parent, path, controllers);
    *group = NULL;

    if (VIR_ALLOC((*group)) != 0) {
        rc = -ENOMEM;
        goto err;
    }

    if (path[0] == '/' || !parent) {
        if (VIR_STRDUP_QUIET((*group)->path, path) < 0) {
            rc = -ENOMEM;
            goto err;
        }
    } else {
        if (virAsprintf(&(*group)->path, "%s%s%s",
                        parent->path,
                        STREQ(parent->path, "") ? "" : "/",
                        path) < 0) {
            rc = -ENOMEM;
            goto err;
        }
    }

    rc = virCgroupDetect(*group, controllers, path, parent);
    if (rc < 0)
        goto err;

    return rc;
err:
    virCgroupFree(group);
    *group = NULL;

    VIR_FREE(typpath);

    return rc;
}

static int virCgroupAppRoot(virCgroupPtr *group,
                            bool create,
                            int controllers)
{
    virCgroupPtr selfgrp = NULL;
    int rc;

    rc = virCgroupNewSelf(&selfgrp);

    if (rc != 0)
        return rc;

    rc = virCgroupNew("libvirt", selfgrp, controllers, group);
    if (rc != 0)
        goto cleanup;

    rc = virCgroupMakeGroup(selfgrp, *group, create, VIR_CGROUP_NONE);

cleanup:
    virCgroupFree(&selfgrp);
    return rc;
}
#endif

#if defined _DIRENT_HAVE_D_TYPE
int virCgroupRemoveRecursively(char *grppath)
{
    DIR *grpdir;
    struct dirent *ent;
    int rc = 0;

    grpdir = opendir(grppath);
    if (grpdir == NULL) {
        if (errno == ENOENT)
            return 0;
        rc = -errno;
        VIR_ERROR(_("Unable to open %s (%d)"), grppath, errno);
        return rc;
    }

    for (;;) {
        char *path;

        errno = 0;
        ent = readdir(grpdir);
        if (ent == NULL) {
            if ((rc = -errno))
                VIR_ERROR(_("Failed to readdir for %s (%d)"), grppath, errno);
            break;
        }

        if (ent->d_name[0] == '.') continue;
        if (ent->d_type != DT_DIR) continue;

        if (virAsprintf(&path, "%s/%s", grppath, ent->d_name) == -1) {
            rc = -ENOMEM;
            break;
        }
        rc = virCgroupRemoveRecursively(path);
        VIR_FREE(path);
        if (rc != 0)
            break;
    }
    closedir(grpdir);

    VIR_DEBUG("Removing cgroup %s", grppath);
    if (rmdir(grppath) != 0 && errno != ENOENT) {
        rc = -errno;
        VIR_ERROR(_("Unable to remove %s (%d)"), grppath, errno);
    }

    return rc;
}
#else
int virCgroupRemoveRecursively(char *grppath ATTRIBUTE_UNUSED)
{
    /* Claim no support */
    return -ENXIO;
}
#endif

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
int virCgroupRemove(virCgroupPtr group)
{
    int rc = 0;
    int i;
    char *grppath = NULL;

    VIR_DEBUG("Removing cgroup %s", group->path);
    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Skip over controllers not mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        if (virCgroupPathOfController(group,
                                      i,
                                      NULL,
                                      &grppath) != 0)
            continue;

        VIR_DEBUG("Removing cgroup %s and all child cgroups", grppath);
        rc = virCgroupRemoveRecursively(grppath);
        VIR_FREE(grppath);
    }
    VIR_DEBUG("Done removing cgroup %s", group->path);

    return rc;
}


/**
 * virCgroupAddTask:
 *
 * @group: The cgroup to add a task to
 * @pid: The pid of the task to add
 *
 * Returns: 0 on success
 */
int virCgroupAddTask(virCgroupPtr group, pid_t pid)
{
    int rc = 0;
    int i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        /* Skip over controllers not mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        rc = virCgroupSetValueU64(group, i, "tasks", (unsigned long long)pid);
        if (rc != 0)
            break;
    }

    return rc;
}

/**
 * virCgroupAddTaskController:
 *
 * @group: The cgroup to add a task to
 * @pid: The pid of the task to add
 * @controller: The cgroup controller to be operated on
 *
 * Returns: 0 on success or -errno on failure
 */
int virCgroupAddTaskController(virCgroupPtr group, pid_t pid, int controller)
{
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return -EINVAL;

    if (!group->controllers[controller].mountPoint)
        return -EINVAL;

    return virCgroupSetValueU64(group, controller, "tasks",
                                (unsigned long long)pid);
}


static int virCgroupAddTaskStrController(virCgroupPtr group,
                                        const char *pidstr,
                                        int controller)
{
    char *str = NULL, *cur = NULL, *next = NULL;
    unsigned long long p = 0;
    int rc = 0;
    char *endp;

    if (VIR_STRDUP_QUIET(str, pidstr) < 0)
        return -ENOMEM;

    cur = str;
    while (*cur != '\0') {
        rc = virStrToLong_ull(cur, &endp, 10, &p);
        if (rc != 0)
            goto cleanup;

        rc = virCgroupAddTaskController(group, p, controller);
        /* A thread that exits between when we first read the source
         * tasks and now is not fatal.  */
        if (rc == -ESRCH)
            rc = 0;
        else if (rc != 0)
            goto cleanup;

        next = strchr(cur, '\n');
        if (next) {
            cur = next + 1;
            *next = '\0';
        } else {
            break;
        }
    }

cleanup:
    VIR_FREE(str);
    return rc;
}

/**
 * virCgroupMoveTask:
 *
 * @src_group: The source cgroup where all tasks are removed from
 * @dest_group: The destination where all tasks are added to
 * @controller: The cgroup controller to be operated on
 *
 * Returns: 0 on success or -errno on failure
 */
int virCgroupMoveTask(virCgroupPtr src_group, virCgroupPtr dest_group)
{
    int rc = 0;
    char *content = NULL;
    int i;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!src_group->controllers[i].mountPoint ||
            !dest_group->controllers[i].mountPoint)
            continue;

        /* New threads are created in the same group as their parent;
         * but if a thread is created after we first read we aren't
         * aware that it needs to move.  Therefore, we must iterate
         * until content is empty.  */
        while (1) {
            VIR_FREE(content);
            rc = virCgroupGetValueStr(src_group, i, "tasks", &content);
            if (rc != 0)
                return rc;
            if (!*content)
                break;

            rc = virCgroupAddTaskStrController(dest_group, content, i);
            if (rc != 0)
                goto cleanup;
        }
    }

cleanup:
    VIR_FREE(content);
    return rc;
}


#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int virCgroupPartitionNeedsEscaping(const char *path)
{
    FILE *fp = NULL;
    int ret = 0;
    char *line = NULL;
    size_t len;

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
        return -errno;
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
    while (getline(&line, &len, fp) > 0) {
        if (STRPREFIX(line, "#subsys_name")) {
            VIR_FREE(line);
            continue;
        }
        char *tmp = strchr(line, ' ');
        if (tmp)
            *tmp = '\0';
        len = tmp - line;

        if (STRPREFIX(path, line) &&
            path[len] == '.') {
            ret = 1;
            VIR_FREE(line);
            goto cleanup;
        }
        VIR_FREE(line);
    }

    if (ferror(fp)) {
        ret = -EIO;
        goto cleanup;
    }

cleanup:
    VIR_FORCE_FCLOSE(fp);
    return ret;
}

static int virCgroupPartitionEscape(char **path)
{
    size_t len = strlen(*path) + 1;
    int rc;
    char escape = '_';

    if ((rc = virCgroupPartitionNeedsEscaping(*path)) <= 0)
        return rc;

    if (VIR_INSERT_ELEMENT(*path, 0, len, escape) < 0)
        return -ENOMEM;

    return 0;
}

static int virCgroupSetPartitionSuffix(const char *path, char **res)
{
    char **tokens = virStringSplit(path, "/", 0);
    size_t i;
    int ret = -1;

    if (!tokens)
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
                              strlen(tokens[i]) + strlen(".partition") + 1) < 0) {
                ret = -ENOMEM;
                virReportOOMError();
                goto cleanup;
            }
            strcat(tokens[i], ".partition");
        }

        ret = virCgroupPartitionEscape(&(tokens[i]));
        if (ret < 0) {
            if (ret == -ENOMEM)
                virReportOOMError();
            goto cleanup;
        }
    }

    if (!(*res = virStringJoin((const char **)tokens, "/"))) {
        ret = -ENOMEM;
        goto cleanup;
    }

    ret = 0;

cleanup:
    virStringFreeList(tokens);
    return ret;
}

/**
 * virCgroupNewPartition:
 * @path: path for the partition
 * @create: true to create the cgroup tree
 * @controllers: mask of controllers to create
 *
 * Creates a new cgroup to represent the resource
 * partition path identified by @name.
 *
 * Returns 0 on success, -errno on failure
 */
int virCgroupNewPartition(const char *path,
                          bool create,
                          int controllers,
                          virCgroupPtr *group)
{
    int rc;
    char *parentPath = NULL;
    virCgroupPtr parent = NULL;
    char *newpath;
    VIR_DEBUG("path=%s create=%d controllers=%x",
              path, create, controllers);

    if (path[0] != '/')
        return -EINVAL;

    /* XXX convert all cgroups APIs to use error report
     * APIs instead of returning errno */
    rc = virCgroupSetPartitionSuffix(path, &newpath);
    if (rc < 0) {
        virResetLastError();
        goto cleanup;
    }

    rc = virCgroupNew(newpath, NULL, controllers, group);
    if (rc != 0)
        goto cleanup;

    if (STRNEQ(newpath, "/")) {
        char *tmp;
        if (VIR_STRDUP_QUIET(parentPath, newpath) < 0) {
            rc = -ENOMEM;
            goto cleanup;
        }

        tmp = strrchr(parentPath, '/');
        tmp++;
        *tmp = '\0';

        rc = virCgroupNew(parentPath, NULL, controllers, &parent);
        if (rc != 0)
            goto cleanup;

        rc = virCgroupMakeGroup(parent, *group, create, VIR_CGROUP_NONE);
        if (rc != 0) {
            virCgroupRemove(*group);
            goto cleanup;
        }
    }

cleanup:
    if (rc != 0)
        virCgroupFree(group);
    virCgroupFree(&parent);
    VIR_FREE(parentPath);
    return rc;
}
#else
int virCgroupNewPartition(const char *path ATTRIBUTE_UNUSED,
                          bool create ATTRIBUTE_UNUSED,
                          int controllers ATTRIBUTE_UNUSED,
                          virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    /* Claim no support */
    return -ENXIO;
}
#endif

/**
 * virCgroupNewDriver:
 *
 * @name: name of this driver (e.g., xen, qemu, lxc)
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewDriver(const char *name,
                       bool create,
                       int controllers,
                       virCgroupPtr *group)
{
    int rc;
    virCgroupPtr rootgrp = NULL;

    rc = virCgroupAppRoot(&rootgrp,
                          create, controllers);
    if (rc != 0)
        goto out;

    rc = virCgroupNew(name, rootgrp, -1, group);
    if (rc == 0) {
        rc = virCgroupMakeGroup(rootgrp, *group, create, VIR_CGROUP_NONE);
        if (rc != 0) {
            virCgroupRemove(*group);
            virCgroupFree(group);
        }
    }
out:
    virCgroupFree(&rootgrp);

    return rc;
}
#else
int virCgroupNewDriver(const char *name ATTRIBUTE_UNUSED,
                       bool create ATTRIBUTE_UNUSED,
                       int controllers ATTRIBUTE_UNUSED,
                       virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    /* Claim no support */
    return -ENXIO;
}
#endif

/**
* virCgroupNewSelf:
*
* @group: Pointer to returned virCgroupPtr
*
* Obtain a cgroup representing the config of the
* current process
*
* Returns 0 on success
*/
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewSelf(virCgroupPtr *group)
{
    return virCgroupNew("", NULL, -1, group);
}
#else
int virCgroupNewSelf(virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}
#endif

/**
 * virCgroupNewDomainDriver:
 *
 * @driver: group for driver owning the domain
 * @name: name of the domain
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewDomainDriver(virCgroupPtr driver,
                             const char *name,
                             bool create,
                             virCgroupPtr *group)
{
    int rc;

    rc = virCgroupNew(name, driver, -1, group);

    if (rc == 0) {
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
        rc = virCgroupMakeGroup(driver, *group, create, VIR_CGROUP_MEM_HIERACHY);
        if (rc != 0) {
            virCgroupRemove(*group);
            virCgroupFree(group);
        }
    }

    return rc;
}
#else
int virCgroupNewDomainDriver(virCgroupPtr driver ATTRIBUTE_UNUSED,
                             const char *name ATTRIBUTE_UNUSED,
                             bool create ATTRIBUTE_UNUSED,
                             virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}
#endif

/**
 * virCgroupNewDomainPartition:
 *
 * @partition: partition holding the domain
 * @driver: name of the driver
 * @name: name of the domain
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewDomainPartition(virCgroupPtr partition,
                                const char *driver,
                                const char *name,
                                bool create,
                                virCgroupPtr *group)
{
    int rc;
    char *grpname = NULL;

    if (virAsprintf(&grpname, "%s.libvirt-%s",
                    name, driver) < 0)
        return -ENOMEM;

    if ((rc = virCgroupPartitionEscape(&grpname)) < 0)
        return rc;

    rc = virCgroupNew(grpname, partition, -1, group);

    if (rc == 0) {
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
        rc = virCgroupMakeGroup(partition, *group, create, VIR_CGROUP_MEM_HIERACHY);
        if (rc != 0) {
            virCgroupRemove(*group);
            virCgroupFree(group);
        }
    }

    VIR_FREE(grpname);
    return rc;
}
#else
int virCgroupNewDomainPartition(virCgroupPtr partition ATTRIBUTE_UNUSED,
                                const char *driver ATTRIBUTE_UNUSED,
                                const char *name ATTRIBUTE_UNUSED,
                                bool create ATTRIBUTE_UNUSED,
                                virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}
#endif

/**
 * virCgroupNewVcpu:
 *
 * @domain: group for the domain
 * @vcpuid: id of the vcpu
 * @create: true to create if not already existing
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewVcpu(virCgroupPtr domain,
                     int vcpuid,
                     bool create,
                     virCgroupPtr *group)
{
    int rc;
    char *name;
    int controllers;

    if (virAsprintf(&name, "vcpu%d", vcpuid) < 0)
        return -ENOMEM;

    controllers = ((1 << VIR_CGROUP_CONTROLLER_CPU) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUSET));

    rc = virCgroupNew(name, domain, controllers, group);
    VIR_FREE(name);

    if (rc == 0) {
        rc = virCgroupMakeGroup(domain, *group, create, VIR_CGROUP_NONE);
        if (rc != 0) {
            virCgroupRemove(*group);
            virCgroupFree(group);
        }
    }

    return rc;
}
#else
int virCgroupNewVcpu(virCgroupPtr domain ATTRIBUTE_UNUSED,
                     int vcpuid ATTRIBUTE_UNUSED,
                     bool create ATTRIBUTE_UNUSED,
                     virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}
#endif

/**
 * virCgroupNewEmulator:
 *
 * @domain: group for the domain
 * @create: true to create if not already existing
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns: 0 on success or -errno on failure
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupNewEmulator(virCgroupPtr domain,
                         bool create,
                         virCgroupPtr *group)
{
    int rc;
    int controllers;

    controllers = ((1 << VIR_CGROUP_CONTROLLER_CPU) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUSET));

    rc = virCgroupNew("emulator", domain, controllers, group);

    if (rc == 0) {
        rc = virCgroupMakeGroup(domain, *group, create, VIR_CGROUP_NONE);
        if (rc != 0) {
            virCgroupRemove(*group);
            virCgroupFree(group);
        }
    }

    return rc;
}
#else
int virCgroupNewEmulator(virCgroupPtr domain ATTRIBUTE_UNUSED,
                         bool create ATTRIBUTE_UNUSED,
                         virCgroupPtr *group ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}

#endif
/**
 * virCgroupSetBlkioWeight:
 *
 * @group: The cgroup to change io weight for
 * @weight: The Weight for this cgroup
 *
 * Returns: 0 on success
 */
int virCgroupSetBlkioWeight(virCgroupPtr group, unsigned int weight)
{
    if (weight > 1000 || weight < 100)
        return -EINVAL;

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
 * Returns: 0 on success
 */
int virCgroupGetBlkioWeight(virCgroupPtr group, unsigned int *weight)
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
 * virCgroupSetBlkioDeviceWeight:
 *
 * @group: The cgroup to change io device weight device for
 * @path: The device with a weight to alter
 * @weight: The new device weight (100-1000), or 0 to clear
 *
 * device_weight is treated as a write-only parameter, so
 * there isn't a getter counterpart.
 *
 * Returns: 0 on success, -errno on failure
 */
#if defined(major) && defined(minor)
int virCgroupSetBlkioDeviceWeight(virCgroupPtr group,
                                  const char *path,
                                  unsigned int weight)
{
    char *str;
    struct stat sb;
    int ret;

    if (weight && (weight > 1000 || weight < 100))
        return -EINVAL;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISBLK(sb.st_mode))
        return -EINVAL;

    if (virAsprintf(&str, "%d:%d %d", major(sb.st_rdev), minor(sb.st_rdev),
                    weight) < 0)
        return -errno;

    ret = virCgroupSetValueStr(group,
                               VIR_CGROUP_CONTROLLER_BLKIO,
                               "blkio.weight_device",
                               str);
    VIR_FREE(str);
    return ret;
}
#else
int
virCgroupSetBlkioDeviceWeight(virCgroupPtr group ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED,
                              unsigned int weight ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif

/**
 * virCgroupSetMemory:
 *
 * @group: The cgroup to change memory for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupSetMemory(virCgroupPtr group, unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb)
        return -EINVAL;
    else if (kb == maxkb)
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
 * virCgroupGetMemoryUsage:
 *
 * @group: The cgroup to change memory for
 * @kb: Pointer to returned used memory in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupGetMemoryUsage(virCgroupPtr group, unsigned long *kb)
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
int virCgroupSetMemoryHardLimit(virCgroupPtr group, unsigned long long kb)
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
int virCgroupGetMemoryHardLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.limit_in_bytes", &limit_in_bytes);
    if (ret == 0)
        *kb = limit_in_bytes >> 10;
    return ret;
}

/**
 * virCgroupSetMemorySoftLimit:
 *
 * @group: The cgroup to change memory soft limit for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupSetMemorySoftLimit(virCgroupPtr group, unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb)
        return -EINVAL;
    else if (kb == maxkb)
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
int virCgroupGetMemorySoftLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.soft_limit_in_bytes", &limit_in_bytes);
    if (ret == 0)
        *kb = limit_in_bytes >> 10;
    return ret;
}

/**
 * virCgroupSetMemSwapHardLimit:
 *
 * @group: The cgroup to change mem+swap hard limit for
 * @kb: The mem+swap amount in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupSetMemSwapHardLimit(virCgroupPtr group, unsigned long long kb)
{
    unsigned long long maxkb = VIR_DOMAIN_MEMORY_PARAM_UNLIMITED;

    if (kb > maxkb)
        return -EINVAL;
    else if (kb == maxkb)
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
int virCgroupGetMemSwapHardLimit(virCgroupPtr group, unsigned long long *kb)
{
    long long unsigned int limit_in_bytes;
    int ret;
    ret = virCgroupGetValueU64(group,
                               VIR_CGROUP_CONTROLLER_MEMORY,
                               "memory.memsw.limit_in_bytes", &limit_in_bytes);
    if (ret == 0)
        *kb = limit_in_bytes >> 10;
    return ret;
}

/**
 * virCgroupGetMemSwapUsage:
 *
 * @group: The cgroup to get mem+swap usage for
 * @kb: The mem+swap amount in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupGetMemSwapUsage(virCgroupPtr group, unsigned long long *kb)
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
int virCgroupSetCpusetMems(virCgroupPtr group, const char *mems)
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
int virCgroupGetCpusetMems(virCgroupPtr group, char **mems)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_CPUSET,
                                "cpuset.mems",
                                mems);
}

/**
 * virCgroupSetCpusetCpus:
 *
 * @group: The cgroup to set cpuset.cpus for
 * @cpus: the cpus to set
 *
 * Retuens: 0 on success
 */
int virCgroupSetCpusetCpus(virCgroupPtr group, const char *cpus)
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
 * Retuens: 0 on success
 */
int virCgroupGetCpusetCpus(virCgroupPtr group, char **cpus)
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
int virCgroupDenyAllDevices(virCgroupPtr group)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_DEVICES,
                                "devices.deny",
                                "a");
}

/**
 * virCgroupAllowDevice:
 *
 * @group: The cgroup to allow a device for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device
 * @minor: The minor number of the device
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 *
 * Returns: 0 on success
 */
int virCgroupAllowDevice(virCgroupPtr group, char type, int major, int minor,
                         int perms)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:%i %s%s%s", type, major, minor,
                    perms & VIR_CGROUP_DEVICE_READ ? "r" : "",
                    perms & VIR_CGROUP_DEVICE_WRITE ? "w" : "",
                    perms & VIR_CGROUP_DEVICE_MKNOD ? "m" : "") == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
                              VIR_CGROUP_CONTROLLER_DEVICES,
                              "devices.allow",
                              devstr);
out:
    VIR_FREE(devstr);

    return rc;
}

/**
 * virCgroupAllowDeviceMajor:
 *
 * @group: The cgroup to allow an entire device major type for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device type
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 *
 * Returns: 0 on success
 */
int virCgroupAllowDeviceMajor(virCgroupPtr group, char type, int major,
                              int perms)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:* %s%s%s", type, major,
                    perms & VIR_CGROUP_DEVICE_READ ? "r" : "",
                    perms & VIR_CGROUP_DEVICE_WRITE ? "w" : "",
                    perms & VIR_CGROUP_DEVICE_MKNOD ? "m" : "") == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
                              VIR_CGROUP_CONTROLLER_DEVICES,
                              "devices.allow",
                              devstr);
 out:
    VIR_FREE(devstr);

    return rc;
}

/**
 * virCgroupAllowDevicePath:
 *
 * @group: The cgroup to allow the device for
 * @path: the device to allow
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to allow
 *
 * Queries the type of device and its major/minor number, and
 * adds that to the cgroup ACL
 *
 * Returns: 0 on success, 1 if path exists but is not a device, or
 * negative errno value on failure
 */
#if defined(major) && defined(minor)
int virCgroupAllowDevicePath(virCgroupPtr group, const char *path, int perms)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    return virCgroupAllowDevice(group,
                                S_ISCHR(sb.st_mode) ? 'c' : 'b',
                                major(sb.st_rdev),
                                minor(sb.st_rdev),
                                perms);
}
#else
int virCgroupAllowDevicePath(virCgroupPtr group ATTRIBUTE_UNUSED,
                             const char *path ATTRIBUTE_UNUSED,
                             int perms ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif


/**
 * virCgroupDenyDevice:
 *
 * @group: The cgroup to deny a device for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device
 * @minor: The minor number of the device
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to deny
 *
 * Returns: 0 on success
 */
int virCgroupDenyDevice(virCgroupPtr group, char type, int major, int minor,
                        int perms)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:%i %s%s%s", type, major, minor,
                    perms & VIR_CGROUP_DEVICE_READ ? "r" : "",
                    perms & VIR_CGROUP_DEVICE_WRITE ? "w" : "",
                    perms & VIR_CGROUP_DEVICE_MKNOD ? "m" : "") == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
                              VIR_CGROUP_CONTROLLER_DEVICES,
                              "devices.deny",
                              devstr);
out:
    VIR_FREE(devstr);

    return rc;
}

/**
 * virCgroupDenyDeviceMajor:
 *
 * @group: The cgroup to deny an entire device major type for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device type
 * @perms: Bitwise or of VIR_CGROUP_DEVICE permission bits to deny
 *
 * Returns: 0 on success
 */
int virCgroupDenyDeviceMajor(virCgroupPtr group, char type, int major,
                             int perms)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:* %s%s%s", type, major,
                    perms & VIR_CGROUP_DEVICE_READ ? "r" : "",
                    perms & VIR_CGROUP_DEVICE_WRITE ? "w" : "",
                    perms & VIR_CGROUP_DEVICE_MKNOD ? "m" : "") == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
                              VIR_CGROUP_CONTROLLER_DEVICES,
                              "devices.deny",
                              devstr);
 out:
    VIR_FREE(devstr);

    return rc;
}

#if defined(major) && defined(minor)
int virCgroupDenyDevicePath(virCgroupPtr group, const char *path, int perms)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    return virCgroupDenyDevice(group,
                               S_ISCHR(sb.st_mode) ? 'c' : 'b',
                               major(sb.st_rdev),
                               minor(sb.st_rdev),
                               perms);
}
#else
int virCgroupDenyDevicePath(virCgroupPtr group ATTRIBUTE_UNUSED,
                            const char *path ATTRIBUTE_UNUSED,
                            int perms ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif

int virCgroupSetCpuShares(virCgroupPtr group, unsigned long long shares)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", shares);
}

int virCgroupGetCpuShares(virCgroupPtr group, unsigned long long *shares)
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
int virCgroupSetCpuCfsPeriod(virCgroupPtr group, unsigned long long cfs_period)
{
    /* The cfs_period shoule be greater or equal than 1ms, and less or equal
     * than 1s.
     */
    if (cfs_period < 1000 || cfs_period > 1000000)
        return -EINVAL;

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
int virCgroupGetCpuCfsPeriod(virCgroupPtr group, unsigned long long *cfs_period)
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
int virCgroupSetCpuCfsQuota(virCgroupPtr group, long long cfs_quota)
{
    if (cfs_quota >= 0) {
        /* The cfs_quota shoule be greater or equal than 1ms */
        if (cfs_quota < 1000)
            return -EINVAL;

        /* check overflow */
        if (cfs_quota > ULLONG_MAX / 1000)
            return -EINVAL;
    }

    return virCgroupSetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
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
int virCgroupGetCpuCfsQuota(virCgroupPtr group, long long *cfs_quota)
{
    return virCgroupGetValueI64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.cfs_quota_us", cfs_quota);
}

int virCgroupGetCpuacctUsage(virCgroupPtr group, unsigned long long *usage)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage", usage);
}

int virCgroupGetCpuacctPercpuUsage(virCgroupPtr group, char **usage)
{
    return virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage_percpu", usage);
}

#ifdef _SC_CLK_TCK
int virCgroupGetCpuacctStat(virCgroupPtr group, unsigned long long *user,
                            unsigned long long *sys)
{
    char *str;
    char *p;
    int ret;
    static double scale = -1.0;

    if ((ret = virCgroupGetValueStr(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                                    "cpuacct.stat", &str)) < 0)
        return ret;
    if (!(p = STRSKIP(str, "user ")) ||
        virStrToLong_ull(p, &p, 10, user) < 0 ||
        !(p = STRSKIP(p, "\nsystem ")) ||
        virStrToLong_ull(p, NULL, 10, sys) < 0) {
        ret = -EINVAL;
        goto cleanup;
    }
    /* times reported are in system ticks (generally 100 Hz), but that
     * rate can theoretically vary between machines.  Scale things
     * into approximate nanoseconds.  */
    if (scale < 0) {
        long ticks_per_sec = sysconf(_SC_CLK_TCK);
        if (ticks_per_sec == -1) {
            ret = -errno;
            goto cleanup;
        }
        scale = 1000000000.0 / ticks_per_sec;
    }
    *user *= scale;
    *sys *= scale;

    ret = 0;
cleanup:
    VIR_FREE(str);
    return ret;
}
#else
int virCgroupGetCpuacctStat(virCgroupPtr group ATTRIBUTE_UNUSED,
                            unsigned long long *user ATTRIBUTE_UNUSED,
                            unsigned long long *sys ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif

int virCgroupSetFreezerState(virCgroupPtr group, const char *state)
{
    return virCgroupSetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}

int virCgroupGetFreezerState(virCgroupPtr group, char **state)
{
    return virCgroupGetValueStr(group,
                                VIR_CGROUP_CONTROLLER_FREEZER,
                                "freezer.state", state);
}


#if defined HAVE_KILL && defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
static int virCgroupKillInternal(virCgroupPtr group, int signum, virHashTablePtr pids)
{
    int rc;
    bool killedAny = false;
    char *keypath = NULL;
    bool done = false;
    FILE *fp = NULL;
    VIR_DEBUG("group=%p path=%s signum=%d pids=%p",
              group, group->path, signum, pids);

    rc = virCgroupPathOfController(group, -1, "tasks", &keypath);
    if (rc != 0) {
        VIR_DEBUG("No path of %s, tasks", group->path);
        return rc;
    }

    /* PIDs may be forking as we kill them, so loop
     * until there are no new PIDs found
     */
    while (!done) {
        done = true;
        if (!(fp = fopen(keypath, "r"))) {
            rc = -errno;
            VIR_DEBUG("Failed to read %s: %m\n", keypath);
            goto cleanup;
        } else {
            while (!feof(fp)) {
                unsigned long pid_value;
                if (fscanf(fp, "%lu", &pid_value) != 1) {
                    if (feof(fp))
                        break;
                    rc = -errno;
                    VIR_DEBUG("Failed to read %s: %m\n", keypath);
                    goto cleanup;
                }
                if (virHashLookup(pids, (void*)pid_value))
                    continue;

                VIR_DEBUG("pid=%lu", pid_value);
                /* Cgroups is a Linux concept, so this cast is safe.  */
                if (kill((pid_t)pid_value, signum) < 0) {
                    if (errno != ESRCH) {
                        rc = -errno;
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

    rc = killedAny ? 1 : 0;

cleanup:
    VIR_FREE(keypath);
    VIR_FORCE_FCLOSE(fp);

    return rc;
}


static uint32_t virCgroupPidCode(const void *name, uint32_t seed)
{
    unsigned long pid_value = (unsigned long)(intptr_t)name;
    return virHashCodeGen(&pid_value, sizeof(pid_value), seed);
}
static bool virCgroupPidEqual(const void *namea, const void *nameb)
{
    return namea == nameb;
}
static void *virCgroupPidCopy(const void *name)
{
    return (void*)name;
}

/*
 * Returns
 *   < 0 : errno that occurred
 *     0 : no PIDs killed
 *     1 : at least one PID killed
 */
int virCgroupKill(virCgroupPtr group, int signum)
{
    VIR_DEBUG("group=%p path=%s signum=%d", group, group->path, signum);
    int rc;
    /* The 'tasks' file in cgroups can contain duplicated
     * pids, so we use a hash to track which we've already
     * killed.
     */
    virHashTablePtr pids = virHashCreateFull(100,
                                             NULL,
                                             virCgroupPidCode,
                                             virCgroupPidEqual,
                                             virCgroupPidCopy,
                                             NULL);

    rc = virCgroupKillInternal(group, signum, pids);

    virHashFree(pids);

    return rc;
}


static int virCgroupKillRecursiveInternal(virCgroupPtr group, int signum, virHashTablePtr pids, bool dormdir)
{
    int rc;
    int killedAny = 0;
    char *keypath = NULL;
    DIR *dp;
    virCgroupPtr subgroup = NULL;
    struct dirent *ent;
    VIR_DEBUG("group=%p path=%s signum=%d pids=%p", group, group->path, signum, pids);

    rc = virCgroupPathOfController(group, -1, "", &keypath);
    if (rc != 0) {
        VIR_DEBUG("No path of %s, tasks", group->path);
        return rc;
    }

    if ((rc = virCgroupKillInternal(group, signum, pids)) != 0)
        return rc;

    VIR_DEBUG("Iterate over children of %s", keypath);
    if (!(dp = opendir(keypath))) {
        rc = -errno;
        return rc;
    }

    while ((ent = readdir(dp))) {
        if (STREQ(ent->d_name, "."))
            continue;
        if (STREQ(ent->d_name, ".."))
            continue;
        if (ent->d_type != DT_DIR)
            continue;

        VIR_DEBUG("Process subdir %s", ent->d_name);

        if ((rc = virCgroupNew(ent->d_name, group, -1, &subgroup)) != 0)
            goto cleanup;

        if ((rc = virCgroupKillRecursiveInternal(subgroup, signum, pids, true)) < 0)
            goto cleanup;
        if (rc == 1)
            killedAny = 1;

        if (dormdir)
            virCgroupRemove(subgroup);

        virCgroupFree(&subgroup);
    }

    rc = killedAny;

cleanup:
    virCgroupFree(&subgroup);
    closedir(dp);

    return rc;
}

int virCgroupKillRecursive(virCgroupPtr group, int signum)
{
    int rc;
    VIR_DEBUG("group=%p path=%s signum=%d", group, group->path, signum);
    virHashTablePtr pids = virHashCreateFull(100,
                                             NULL,
                                             virCgroupPidCode,
                                             virCgroupPidEqual,
                                             virCgroupPidCopy,
                                             NULL);

    rc = virCgroupKillRecursiveInternal(group, signum, pids, false);

    virHashFree(pids);

    return rc;
}


int virCgroupKillPainfully(virCgroupPtr group)
{
    int i;
    int rc;
    VIR_DEBUG("cgroup=%p path=%s", group, group->path);
    for (i = 0; i < 15; i++) {
        int signum;
        if (i == 0)
            signum = SIGTERM;
        else if (i == 8)
            signum = SIGKILL;
        else
            signum = 0; /* Just check for existence */

        rc = virCgroupKillRecursive(group, signum);
        VIR_DEBUG("Iteration %d rc=%d", i, rc);
        /* If rc == -1 we hit error, if 0 we ran out of PIDs */
        if (rc <= 0)
            break;

        usleep(200 * 1000);
    }
    VIR_DEBUG("Complete %d", rc);
    return rc;
}

#else /* !(HAVE_KILL, HAVE_MNTENT_H, HAVE_GETMNTENT_R) */
int virCgroupKill(virCgroupPtr group ATTRIBUTE_UNUSED,
                  int signum ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
int virCgroupKillRecursive(virCgroupPtr group ATTRIBUTE_UNUSED,
                           int signum ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}

int virCgroupKillPainfully(virCgroupPtr group ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif /* HAVE_KILL, HAVE_MNTENT_H, HAVE_GETMNTENT_R */

#ifdef __linux__
static char *virCgroupIdentifyRoot(virCgroupPtr group)
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

        ignore_value(VIR_STRNDUP_QUIET(ret, group->controllers[i].mountPoint,
                                       tmp - group->controllers[i].mountPoint));
        return ret;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Could not find any mounted controllers"));
    return NULL;
}


int virCgroupIsolateMount(virCgroupPtr group, const char *oldroot,
                          const char *mountopts)
{
    int ret = -1;
    size_t i;
    char *opts = NULL;
    char *root = NULL;

    if (!(root = virCgroupIdentifyRoot(group)))
        return -1;

    VIR_DEBUG("Mounting cgroups at '%s'", root);

    if (virFileMakePath(root) < 0) {
        virReportSystemError(errno,
                             _("Unable to create directory %s"),
                             root);
        goto cleanup;
    }

    if (virAsprintf(&opts,
                    "mode=755,size=65536%s", mountopts) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (mount("tmpfs", root, "tmpfs", MS_NOSUID|MS_NODEV|MS_NOEXEC, opts) < 0) {
        virReportSystemError(errno,
                             _("Failed to mount %s on %s type %s"),
                             "tmpfs", root, "tmpfs");
        goto cleanup;
    }

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        if (!group->controllers[i].mountPoint)
            continue;

        if (!virFileExists(group->controllers[i].mountPoint)) {
            char *src;
            if (virAsprintf(&src, "%s%s%s",
                            oldroot,
                            group->controllers[i].mountPoint,
                            group->controllers[i].placement) < 0) {
                virReportOOMError();
                goto cleanup;
            }

            VIR_DEBUG("Create mount point '%s'", group->controllers[i].mountPoint);
            if (virFileMakePath(group->controllers[i].mountPoint) < 0) {
                virReportSystemError(errno,
                                     _("Unable to create directory %s"),
                                     group->controllers[i].mountPoint);
                VIR_FREE(src);
                goto cleanup;
            }

            if (mount(src, group->controllers[i].mountPoint, NULL, MS_BIND, NULL) < 0) {
                virReportSystemError(errno,
                                     _("Failed to bind cgroup '%s' on '%s'"),
                                     src, group->controllers[i].mountPoint);
            VIR_FREE(src);
                goto cleanup;
            }

            VIR_FREE(src);
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
    ret = 0;

cleanup:
    VIR_FREE(root);
    VIR_FREE(opts);
    return ret;
}
#else /* __linux__ */
int virCgroupIsolateMount(virCgroupPtr group ATTRIBUTE_UNUSED,
                          const char *oldroot ATTRIBUTE_UNUSED,
                          const char *mountopts ATTRIBUTE_UNUSED)
{
    return -ENOSYS;
}
#endif /* __linux__ */
