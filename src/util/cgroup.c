/*
 * cgroup.c: Tools for managing cgroups
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
 * Copyright IBM Corp. 2008
 *
 * See COPYING.LIB for the License of this software
 *
 * Authors:
 *  Dan Smith <danms@us.ibm.com>
 */
#include <config.h>

#include <stdio.h>
#include <stdint.h>
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
# include <mntent.h>
#endif
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <libgen.h>
#include <dirent.h>

#include "internal.h"
#include "util.h"
#include "memory.h"
#include "cgroup.h"
#include "logging.h"
#include "virfile.h"
#include "virhash.h"
#include "virhashcode.h"

#define CGROUP_MAX_VAL 512

VIR_ENUM_IMPL(virCgroupController, VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "blkio");

struct virCgroupController {
    int type;
    char *mountPoint;
    char *placement;
};

struct virCgroup {
    char *path;

    struct virCgroupController controllers[VIR_CGROUP_CONTROLLER_LAST];
};

typedef enum {
    VIR_CGROUP_NONE = 0, /* create subdir under each cgroup if possible. */
    VIR_CGROUP_MEM_HIERACHY = 1 << 0, /* call virCgroupSetMemoryUseHierarchy
                                       * before creating subcgroups and
                                       * attaching tasks
                                       */
    VIR_CGROUP_VCPU = 1 << 1, /* create subdir only under the cgroup cpu,
                               * cpuacct and cpuset if possible. */
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

    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        VIR_FREE((*group)->controllers[i].mountPoint);
        VIR_FREE((*group)->controllers[i].placement);
    }

    VIR_FREE((*group)->path);
    VIR_FREE(*group);
}

/**
 * virCgroupMounted: query whether a cgroup subsystem is mounted or not
 *
 * @cgroup: The group structure to be queried
 * @controller: cgroup subsystem id
 *
 * Returns true if a cgroup is subsystem is mounted.
 */
bool virCgroupMounted(virCgroupPtr cgroup, int controller)
{
    return cgroup->controllers[controller].mountPoint != NULL;
}

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
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

        for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
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
                    !group->controllers[i].mountPoint &&
                    !(group->controllers[i].mountPoint = strdup(entry.mnt_dir)))
                    goto no_memory;
                tmp = next;
            }
        }
    }

    VIR_FORCE_FCLOSE(mounts);

    return 0;

no_memory:
    VIR_FORCE_FCLOSE(mounts);
    return -ENOMEM;
}


/*
 * Process /proc/self/cgroup figuring out what cgroup
 * sub-path the current process is assigned to. ie not
 * neccessarily in the root
 */
static int virCgroupDetectPlacement(virCgroupPtr group)
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
        char *path = controllers ? strchr(controllers+1, ':') : NULL;
        char *nl = path ? strchr(path, '\n') : NULL;

        if (!controllers || !path)
            continue;

        if (nl)
            *nl = '\0';

        *path = '\0';
        controllers++;
        path++;

        for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
            const char *typestr = virCgroupControllerTypeToString(i);
            int typelen = strlen(typestr);
            char *tmp = controllers;
            while (tmp) {
                char *next = strchr(tmp, ',');
                int len;
                if (next) {
                    len = next-tmp;
                    next++;
                } else {
                    len = strlen(tmp);
                }
                if (typelen == len && STREQLEN(typestr, tmp, len) &&
                    !(group->controllers[i].placement = strdup(STREQ(path, "/") ? "" : path)))
                    goto no_memory;

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

static int virCgroupDetect(virCgroupPtr group)
{
    int any = 0;
    int rc;
    int i;

    rc = virCgroupDetectMounts(group);
    if (rc < 0) {
        VIR_ERROR(_("Failed to detect mounts for %s"), group->path);
        return rc;
    }

    /* Check that at least 1 controller is available */
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (group->controllers[i].mountPoint != NULL)
            any = 1;
    }
    if (!any)
        return -ENXIO;


    rc = virCgroupDetectPlacement(group);

    if (rc == 0) {
        /* Check that for every mounted controller, we found our placement */
        for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
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
        for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
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

    if (virAsprintf(path, "%s%s%s/%s",
                    group->controllers[controller].mountPoint,
                    group->controllers[controller].placement,
                    STREQ(group->path, "/") ? "" : group->path,
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

    rc = virFileReadAll(keypath, 1024, value);
    if (rc < 0) {
        rc = -errno;
        VIR_DEBUG("Failed to read %s: %m\n", keypath);
    } else {
        /* Terminated with '\n' has sometimes harmful effects to the caller */
        if ((*value)[rc - 1] == '\n')
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
    for (i = 0; i < ARRAY_CARDINALITY(inherit_values) ; i++) {
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

static int virCgroupMakeGroup(virCgroupPtr parent, virCgroupPtr group,
                              int create, unsigned int flags)
{
    int i;
    int rc = 0;

    VIR_DEBUG("Make group %s", group->path);
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        char *path = NULL;

        /* Skip over controllers that aren't mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        /* We need to control cpu bandwidth for each vcpu now */
        if ((flags & VIR_CGROUP_VCPU) && (i != VIR_CGROUP_CONTROLLER_CPU)) {
            /* treat it as unmounted and we can use virCgroupAddTask */
            VIR_FREE(group->controllers[i].mountPoint);
            continue;
        }

        rc = virCgroupPathOfController(group, i, "", &path);
        if (rc < 0)
            return rc;
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
                    rc = 0;
                    VIR_FREE(group->controllers[i].mountPoint);
                    VIR_FREE(path);
                    continue;
                } else {
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

    return rc;
}


static int virCgroupNew(const char *path,
                        virCgroupPtr *group)
{
    int rc = 0;
    char *typpath = NULL;

    VIR_DEBUG("New group %s", path);
    *group = NULL;

    if (VIR_ALLOC((*group)) != 0) {
        rc = -ENOMEM;
        goto err;
    }

    if (!((*group)->path = strdup(path))) {
        rc = -ENOMEM;
        goto err;
    }

    rc = virCgroupDetect(*group);
    if (rc < 0)
        goto err;

    return rc;
err:
    virCgroupFree(group);
    *group = NULL;

    VIR_FREE(typpath);

    return rc;
}

static int virCgroupAppRoot(int privileged,
                            virCgroupPtr *group,
                            int create)
{
    virCgroupPtr rootgrp = NULL;
    int rc;

    rc = virCgroupNew("/", &rootgrp);
    if (rc != 0)
        return rc;

    if (privileged) {
        rc = virCgroupNew("/libvirt", group);
    } else {
        char *rootname;
        char *username;
        username = virGetUserName(getuid());
        if (!username) {
            rc = -ENOMEM;
            goto cleanup;
        }
        rc = virAsprintf(&rootname, "/libvirt-%s", username);
        VIR_FREE(username);
        if (rc < 0) {
            rc = -ENOMEM;
            goto cleanup;
        }

        rc = virCgroupNew(rootname, group);
        VIR_FREE(rootname);
    }
    if (rc != 0)
        goto cleanup;

    rc = virCgroupMakeGroup(rootgrp, *group, create, VIR_CGROUP_NONE);

cleanup:
    virCgroupFree(&rootgrp);
    return rc;
}
#endif

#if defined _DIRENT_HAVE_D_TYPE
static int virCgroupRemoveRecursively(char *grppath)
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
static int virCgroupRemoveRecursively(char *grppath ATTRIBUTE_UNUSED)
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

    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
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

    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
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
 * virCgroupForDriver:
 *
 * @name: name of this driver (e.g., xen, qemu, lxc)
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupForDriver(const char *name,
                       virCgroupPtr *group,
                       int privileged,
                       int create)
{
    int rc;
    char *path = NULL;
    virCgroupPtr rootgrp = NULL;

    rc = virCgroupAppRoot(privileged, &rootgrp, create);
    if (rc != 0)
        goto out;

    if (virAsprintf(&path, "%s/%s", rootgrp->path, name) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupNew(path, group);
    VIR_FREE(path);

    if (rc == 0) {
        rc = virCgroupMakeGroup(rootgrp, *group, create, VIR_CGROUP_NONE);
        if (rc != 0)
            virCgroupFree(group);
    }

out:
    virCgroupFree(&rootgrp);

    return rc;
}
#else
int virCgroupForDriver(const char *name ATTRIBUTE_UNUSED,
                       virCgroupPtr *group ATTRIBUTE_UNUSED,
                       int privileged ATTRIBUTE_UNUSED,
                       int create ATTRIBUTE_UNUSED)
{
    /* Claim no support */
    return -ENXIO;
}
#endif


/**
 * virCgroupForDomain:
 *
 * @driver: group for driver owning the domain
 * @name: name of the domain
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupForDomain(virCgroupPtr driver,
                       const char *name,
                       virCgroupPtr *group,
                       int create)
{
    int rc;
    char *path;

    if (driver == NULL)
        return -EINVAL;

    if (virAsprintf(&path, "%s/%s", driver->path, name) < 0)
        return -ENOMEM;

    rc = virCgroupNew(path, group);
    VIR_FREE(path);

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
        if (rc != 0)
            virCgroupFree(group);
    }

    return rc;
}
#else
int virCgroupForDomain(virCgroupPtr driver ATTRIBUTE_UNUSED,
                       const char *name ATTRIBUTE_UNUSED,
                       virCgroupPtr *group ATTRIBUTE_UNUSED,
                       int create ATTRIBUTE_UNUSED)
{
    return -ENXIO;
}
#endif

/**
 * virCgroupForVcpu:
 *
 * @driver: group for the domain
 * @vcpuid: id of the vcpu
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
int virCgroupForVcpu(virCgroupPtr driver,
                     int vcpuid,
                     virCgroupPtr *group,
                     int create)
{
    int rc;
    char *path;

    if (driver == NULL)
        return -EINVAL;

    if (virAsprintf(&path, "%s/vcpu%d", driver->path, vcpuid) < 0)
        return -ENOMEM;

    rc = virCgroupNew(path, group);
    VIR_FREE(path);

    if (rc == 0) {
        rc = virCgroupMakeGroup(driver, *group, create, VIR_CGROUP_VCPU);
        if (rc != 0)
            virCgroupFree(group);
    }

    return rc;
}
#else
int virCgroupForVcpu(virCgroupPtr driver ATTRIBUTE_UNUSED,
                     int vcpuid ATTRIBUTE_UNUSED,
                     virCgroupPtr *group ATTRIBUTE_UNUSED,
                     int create ATTRIBUTE_UNUSED)
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
    int killedAny = 0;
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
                    killedAny = 1;
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
        char *subpath;

        if (STREQ(ent->d_name, "."))
            continue;
        if (STREQ(ent->d_name, ".."))
            continue;
        if (ent->d_type != DT_DIR)
            continue;

        VIR_DEBUG("Process subdir %s", ent->d_name);
        if (virAsprintf(&subpath, "%s/%s", group->path, ent->d_name) < 0) {
            rc = -ENOMEM;
            goto cleanup;
        }

        if ((rc = virCgroupNew(subpath, &subgroup)) != 0)
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
    for (i = 0 ; i < 15 ; i++) {
        int signum;
        if (i == 0)
            signum = SIGTERM;
        else if (i == 8)
            signum = SIGKILL;
        else
            signum = 0; /* Just check for existance */

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
