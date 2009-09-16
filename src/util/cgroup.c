/*
 * cgroup.c: Tools for managing cgroups
 *
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
#include <inttypes.h>
#include <mntent.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libgen.h>

#include "internal.h"
#include "util.h"
#include "memory.h"
#include "cgroup.h"
#include "logging.h"

#define CGROUP_MAX_VAL 512

VIR_ENUM_IMPL(virCgroupController, VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices");

struct virCgroupController {
    int type;
    char *mountPoint;
    char *placement;
};

struct virCgroup {
    char *path;

    struct virCgroupController controllers[VIR_CGROUP_CONTROLLER_LAST];
};

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
        VIR_ERROR0("Unable to open /proc/mounts");
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
                if (typelen == len && STREQLEN(typestr, tmp, len) &&
                    !(group->controllers[i].mountPoint = strdup(entry.mnt_dir)))
                    goto no_memory;
                tmp = next;
            }
        }
    }

    fclose(mounts);

    return 0;

no_memory:
    if (mounts)
        fclose(mounts);
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
        VIR_ERROR0("Unable to open /proc/self/cgroup");
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

    fclose(mapping);

    return 0;

no_memory:
    return -ENOMEM;

}

static int virCgroupDetect(virCgroupPtr group)
{
    int any = 0;
    int rc;
    int i;

    rc = virCgroupDetectMounts(group);
    if (rc < 0) {
        VIR_ERROR("Failed to detect mounts for %s", group->path);
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
                VIR_ERROR("Could not find placement for controller %s at %s",
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
        VIR_ERROR("Failed to detect mapping for %s", group->path);
    }

    return rc;
}


static int virCgroupPathOfController(virCgroupPtr group,
                                     int controller,
                                     const char *key,
                                     char **path)
{
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

    VIR_DEBUG("Set value %s", keypath);
    rc = virFileWriteStr(keypath, value);
    if (rc < 0) {
        DEBUG("Failed to write value '%s': %m", value);
        rc = -errno;
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
        DEBUG("No path of %s, %s", group->path, key);
        return rc;
    }

    VIR_DEBUG("Get value %s", keypath);

    rc = virFileReadAll(keypath, 1024, value);
    if (rc < 0) {
        DEBUG("Failed to read %s: %m\n", keypath);
        rc = -errno;
    } else {
        rc = 0;
    }

    VIR_FREE(keypath);

    return rc;
}

static int virCgroupSetValueU64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                uint64_t value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%" PRIu64, value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, controller, key, strval);

    VIR_FREE(strval);

    return rc;
}


#if 0
/* This is included for completeness, but not yet used */

static int virCgroupSetValueI64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                int64_t value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%" PRIi64, value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, controller, key, strval);

    VIR_FREE(strval);

    return rc;
}

static int virCgroupGetValueI64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                int64_t *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, controller, key, &strval);
    if (rc != 0)
        goto out;

    if (sscanf(strval, "%" SCNi64, value) != 1)
        rc = -EINVAL;
out:
    VIR_FREE(strval);

    return rc;
}
#endif

static int virCgroupGetValueU64(virCgroupPtr group,
                                int controller,
                                const char *key,
                                uint64_t *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, controller, key, &strval);
    if (rc != 0)
        goto out;

    if (sscanf(strval, "%" SCNu64, value) != 1)
        rc = -EINVAL;
out:
    VIR_FREE(strval);

    return rc;
}


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
            VIR_ERROR("Failed to get %s %d", inherit_values[i], rc);
            break;
        }

        VIR_DEBUG("Inherit %s = %s", inherit_values[i], value);

        rc = virCgroupSetValueStr(group,
                                  VIR_CGROUP_CONTROLLER_CPUSET,
                                  inherit_values[i],
                                  value);

        if (rc != 0) {
            VIR_ERROR("Failed to set %s %d", inherit_values[i], rc);
            break;
        }
    }

    return rc;
}

static int virCgroupMakeGroup(virCgroupPtr parent, virCgroupPtr group)
{
    int i;
    int rc = 0;

    VIR_DEBUG("Make group %s", group->path);
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        char *path = NULL;

        /* Skip over controllers that aren't mounted */
        if (!group->controllers[i].mountPoint)
            continue;

        rc = virCgroupPathOfController(group, i, "", &path);
        if (rc < 0)
            return rc;

        VIR_DEBUG("Make controller %s", path);
        if (access(path, F_OK) != 0) {
            if (mkdir(path, 0755) < 0) {
                rc = -errno;
                VIR_FREE(path);
                break;
            }
            if (group->controllers[VIR_CGROUP_CONTROLLER_CPUSET].mountPoint != NULL &&
                (i == VIR_CGROUP_CONTROLLER_CPUSET ||
                 STREQ(group->controllers[i].mountPoint, group->controllers[VIR_CGROUP_CONTROLLER_CPUSET].mountPoint))) {
                rc = virCgroupCpuSetInherit(parent, group);
                if (rc != 0)
                    break;
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
                            virCgroupPtr *group)
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
        username = virGetUserName(NULL, getuid());
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

    rc = virCgroupMakeGroup(rootgrp, *group);

cleanup:
    virCgroupFree(&rootgrp);
    return rc;
}


/**
 * virCgroupRemove:
 *
 * @group: The group to be removed
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

        DEBUG("Removing cgroup %s", grppath);
        if (rmdir(grppath) != 0 && errno != ENOENT) {
            rc = -errno;
        }
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
int virCgroupForDriver(const char *name,
                       virCgroupPtr *group,
                       int privileged,
                       int create)
{
    int rc;
    char *path = NULL;
    virCgroupPtr rootgrp = NULL;

    rc = virCgroupAppRoot(privileged, &rootgrp);
    if (rc != 0)
        goto out;

    if (virAsprintf(&path, "%s/%s", rootgrp->path, name) < 0) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupNew(path, group);
    VIR_FREE(path);

    if (rc == 0 &&
        create) {
        rc = virCgroupMakeGroup(rootgrp, *group);
        if (rc != 0)
            virCgroupFree(group);
    }

out:
    virCgroupFree(&rootgrp);

    return rc;
}


/**
 * virCgroupForDomain:
 *
 * @driver: group for driver owning the domain
 * @name: name of the domain
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
int virCgroupForDomain(virCgroupPtr driver,
                       const char *name,
                       virCgroupPtr *group,
                       int create)
{
    int rc;
    char *path;

    if (virAsprintf(&path, "%s/%s", driver->path, name) < 0)
        return -ENOMEM;

    rc = virCgroupNew(path, group);
    VIR_FREE(path);

    if (rc == 0 &&
        create) {
        rc = virCgroupMakeGroup(driver, *group);
        if (rc != 0)
            virCgroupFree(group);
    }

    return rc;
}

/**
 * virCgroupSetMemory:
 *
 * @group: The cgroup to change memory for
 * @kb: The memory amount in kilobytes
 *
 * Returns: 0 on success
 */
int virCgroupSetMemory(virCgroupPtr group, unsigned long kb)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_MEMORY,
                                "memory.limit_in_bytes",
                                kb << 10);
}

/**
 * virCgroupDenyAllDevices:
 *
 * @group: The cgroup to deny devices for
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
 *
 * Returns: 0 on success
 */
int virCgroupAllowDevice(virCgroupPtr group, char type, int major, int minor)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:%i rwm", type, major, minor) == -1) {
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
 *
 * Returns: 0 on success
 */
int virCgroupAllowDeviceMajor(virCgroupPtr group, char type, int major)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:* rwm", type, major) == -1) {
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
 *
 * Queries the type of device and its major/minor number, and
 * adds that to the cgroup ACL
 *
 * Returns: 0 on success
 */
int virCgroupAllowDevicePath(virCgroupPtr group, const char *path)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return -EINVAL;

    return virCgroupAllowDevice(group,
                                S_ISCHR(sb.st_mode) ? 'c' : 'b',
                                major(sb.st_rdev),
                                minor(sb.st_rdev));
}

/**
 * virCgroupDenyDevice:
 *
 * @group: The cgroup to deny a device for
 * @type: The device type (i.e., 'c' or 'b')
 * @major: The major number of the device
 * @minor: The minor number of the device
 *
 * Returns: 0 on success
 */
int virCgroupDenyDevice(virCgroupPtr group, char type, int major, int minor)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:%i rwm", type, major, minor) == -1) {
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
 *
 * Returns: 0 on success
 */
int virCgroupDenyDeviceMajor(virCgroupPtr group, char type, int major)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:* rwm", type, major) == -1) {
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

int virCgroupDenyDevicePath(virCgroupPtr group, const char *path)
{
    struct stat sb;

    if (stat(path, &sb) < 0)
        return -errno;

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return -EINVAL;

    return virCgroupDenyDevice(group,
                               S_ISCHR(sb.st_mode) ? 'c' : 'b',
                               major(sb.st_rdev),
                               minor(sb.st_rdev));
}

int virCgroupSetCpuShares(virCgroupPtr group, unsigned long long shares)
{
    return virCgroupSetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", (uint64_t)shares);
}

int virCgroupGetCpuShares(virCgroupPtr group, unsigned long long *shares)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPU,
                                "cpu.shares", (uint64_t *)shares);
}

int virCgroupGetCpuacctUsage(virCgroupPtr group, unsigned long long *usage)
{
    return virCgroupGetValueU64(group,
                                VIR_CGROUP_CONTROLLER_CPUACCT,
                                "cpuacct.usage", (uint64_t *)usage);
}
