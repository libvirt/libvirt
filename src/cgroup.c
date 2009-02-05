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

struct virCgroup {
    char *path;
};

const char *supported_controllers[] = {
    "memory",
    "devices",
    NULL
};

/**
 * virCgroupFree:
 *
 * @group: The group structure to free
 */
void virCgroupFree(virCgroupPtr *group)
{
    if (*group != NULL) {
        VIR_FREE((*group)->path);
        VIR_FREE(*group);
    }
}

static virCgroupPtr virCgroupGetMount(const char *controller)
{
    FILE *mounts;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];
    virCgroupPtr root = NULL;

    if (VIR_ALLOC(root) != 0)
        return NULL;

    mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL) {
        DEBUG0("Unable to open /proc/mounts: %m");
        goto err;
    }

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        if (STREQ(entry.mnt_type, "cgroup") &&
            (strstr(entry.mnt_opts, controller))) {
            root->path = strdup(entry.mnt_dir);
            break;
        }
    }

    DEBUG("Mount for %s is %s\n", controller, root->path);

    if (root->path == NULL) {
        DEBUG0("Did not find cgroup mount");
        goto err;
    }

    fclose(mounts);

    return root;
err:
    virCgroupFree(&root);

    return NULL;
}

/**
 * virCgroupHaveSupport:
 *
 * Returns 0 if support is present, negative if not
 */
int virCgroupHaveSupport(void)
{
    virCgroupPtr root;
    int i;

    for (i = 0; supported_controllers[i] != NULL; i++) {
        root = virCgroupGetMount(supported_controllers[i]);
        if (root == NULL)
            return -1;
        virCgroupFree(&root);
    }

    return 0;
}

static int virCgroupPathOfGroup(const char *group,
                                const char *controller,
                                char **path)
{
    virCgroupPtr root = NULL;
    int rc = 0;

    root = virCgroupGetMount(controller);
    if (root == NULL) {
        rc = -ENOTDIR;
        goto out;
    }

    if (virAsprintf(path, "%s/%s", root->path, group) == -1)
        rc = -ENOMEM;
out:
    virCgroupFree(&root);

    return rc;
}

static int virCgroupPathOf(const char *grppath,
                           const char *key,
                           char **path)
{
    virCgroupPtr root;
    int rc = 0;
    char *controller = NULL;

    if (strchr(key, '.') == NULL)
        return -EINVAL;

    if (sscanf(key, "%a[^.]", &controller) != 1)
        return -EINVAL;

    root = virCgroupGetMount(controller);
    if (root == NULL) {
        rc = -ENOTDIR;
        goto out;
    }

    if (virAsprintf(path, "%s/%s/%s", root->path, grppath, key) == -1)
        rc = -ENOMEM;
out:
    virCgroupFree(&root);
    VIR_FREE(controller);

    return rc;
}

static int virCgroupSetValueStr(virCgroupPtr group,
                                const char *key,
                                const char *value)
{
    int fd = -1;
    int rc = 0;
    char *keypath = NULL;

    rc = virCgroupPathOf(group->path, key, &keypath);
    if (rc != 0)
        return rc;

    fd = open(keypath, O_WRONLY);
    if (fd < 0) {
        DEBUG("Unable to open %s: %m", keypath);
        rc = -ENOENT;
        goto out;
    }

    DEBUG("Writing '%s' to '%s'", value, keypath);

    rc = safewrite(fd, value, strlen(value));
    if (rc < 0) {
        DEBUG("Failed to write value '%s': %m", value);
        rc = -errno;
        goto out;
    } else if (rc != strlen(value)) {
        DEBUG("Short write of value '%s'", value);
        rc = -ENOSPC;
        goto out;
    }

    rc = 0;
out:
    VIR_FREE(keypath);
    close(fd);

    return rc;
}

static int virCgroupSetValueU64(virCgroupPtr group,
                                const char *key,
                                uint64_t value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%" PRIu64, value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, key, strval);

    VIR_FREE(strval);

    return rc;
}

static int virCgroupGetValueStr(virCgroupPtr group,
                                const char *key,
                                char **value)
{
    int fd = -1;
    int rc;
    char *keypath = NULL;
    char buf[CGROUP_MAX_VAL];

    memset(buf, 0, sizeof(buf));

    rc = virCgroupPathOf(group->path, key, &keypath);
    if (rc != 0) {
        DEBUG("No path of %s, %s", group->path, key);
        return rc;
    }

    fd = open(keypath, O_RDONLY);
    if (fd < 0) {
        DEBUG("Unable to open %s: %m", keypath);
        rc = -ENOENT;
        goto out;
    }

    rc = saferead(fd, buf, sizeof(buf));
    if (rc < 0) {
        DEBUG("Failed to read %s: %m\n", keypath);
        rc = -errno;
        goto out;
    } else if (rc == 0) {
        DEBUG("Short read of %s\n", keypath);
        rc = -EIO;
        goto out;
    }

    *value = strdup(buf);
    if (*value == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    rc = 0;
out:
    VIR_FREE(keypath);
    close(fd);

    return rc;
}

#if 0
/* This is included for completeness, but not yet used */

static int virCgroupSetValueI64(virCgroupPtr group,
                                const char *key,
                                int64_t value)
{
    char *strval = NULL;
    int rc;

    if (virAsprintf(&strval, "%" PRIi64, value) == -1)
        return -ENOMEM;

    rc = virCgroupSetValueStr(group, key, strval);

    VIR_FREE(strval);

    return rc;
}

static int virCgroupGetValueI64(virCgroupPtr group,
                                const char *key,
                                int64_t *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, key, &strval);
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
                                const char *key,
                                uint64_t *value)
{
    char *strval = NULL;
    int rc = 0;

    rc = virCgroupGetValueStr(group, key, &strval);
    if (rc != 0)
        goto out;

    if (sscanf(strval, "%" SCNu64, value) != 1)
        rc = -EINVAL;
out:
    VIR_FREE(strval);

    return rc;
}

static int _virCgroupInherit(const char *path,
                             const char *key)
{
    int rc = 0;
    int fd = -1;
    char buf[CGROUP_MAX_VAL];
    char *keypath = NULL;
    char *pkeypath = NULL;

    memset(buf, 0, sizeof(buf));

    if (virAsprintf(&keypath, "%s/%s", path, key) == -1) {
        rc = -ENOMEM;
        goto out;
    }

    if (access(keypath, F_OK) != 0) {
        DEBUG("Group %s has no key %s\n", path, key);
        goto out;
    }

    if (virAsprintf(&pkeypath, "%s/../%s", path, key) == -1) {
        rc = -ENOMEM;
        VIR_FREE(keypath);
        goto out;
    }

    fd = open(pkeypath, O_RDONLY);
    if (fd < 0) {
        rc = -errno;
        goto out;
    }

    if (saferead(fd, buf, sizeof(buf)) <= 0) {
        rc = -errno;
        goto out;
    }

    close(fd);

    fd = open(keypath, O_WRONLY);
    if (fd < 0) {
        rc = -errno;
        goto out;
    }

    if (safewrite(fd, buf, strlen(buf)) != strlen(buf)) {
        rc = -errno;
        goto out;
    }

out:
    VIR_FREE(keypath);
    VIR_FREE(pkeypath);
    close(fd);

    return rc;
}

static int virCgroupInherit(const char *grppath)
{
    int i;
    int rc = 0;
    const char *inherit_values[] = {
        "cpuset.cpus",
        "cpuset.mems",
        NULL
    };

    for (i = 0; inherit_values[i] != NULL; i++) {
        const char *key = inherit_values[i];

        rc = _virCgroupInherit(grppath, key);
        if (rc != 0) {
            DEBUG("inherit of %s failed\n", key);
            break;
        }
    }

    return rc;
}

static int virCgroupMakeGroup(const char *name)
{
    int i;
    int rc = 0;

    for (i = 0; supported_controllers[i] != NULL; i++) {
        char *path = NULL;
        virCgroupPtr root;

        root = virCgroupGetMount(supported_controllers[i]);
        if (root == NULL)
            continue;

        rc = virCgroupPathOfGroup(name, supported_controllers[i], &path);
        if (rc != 0) {
            virCgroupFree(&root);
            break;
        }

        virCgroupFree(&root);

        if (access(path, F_OK) != 0) {
            if (mkdir(path, 0655) < 0) {
                rc = -errno;
                VIR_FREE(path);
                break;
            }
            virCgroupInherit(path);
        }

        VIR_FREE(path);
    }

    return rc;
}

static int virCgroupRoot(virCgroupPtr *root)
{
    int rc = 0;
    char *grppath = NULL;

    if (VIR_ALLOC((*root)) != 0) {
        rc = -ENOMEM;
        goto out;
    }

    (*root)->path = strdup("libvirt");
    if ((*root)->path == NULL) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupMakeGroup((*root)->path);
out:
    if (rc != 0)
        virCgroupFree(root);
    VIR_FREE(grppath);

    return rc;
}

static int virCgroupNew(virCgroupPtr *parent,
                        const char *group,
                        virCgroupPtr *newgroup)
{
    int rc = 0;
    char *typpath = NULL;

    *newgroup = NULL;

    if (*parent == NULL) {
        rc = virCgroupRoot(parent);
        if (rc != 0)
            goto err;
    }

    if (VIR_ALLOC((*newgroup)) != 0) {
        rc = -ENOMEM;
        goto err;
    }

    rc = virAsprintf(&((*newgroup)->path),
                     "%s/%s",
                     (*parent)->path,
                     group);
    if (rc == -1) {
        rc = -ENOMEM;
        goto err;
    }

    rc = 0;

    return rc;
err:
    virCgroupFree(newgroup);
    *newgroup = NULL;

    VIR_FREE(typpath);

    return rc;
}

static int virCgroupOpen(virCgroupPtr parent,
                         const char *group,
                         virCgroupPtr *newgroup)
{
    int rc = 0;
    char *grppath = NULL;
    bool free_parent = (parent == NULL);

    rc = virCgroupNew(&parent, group, newgroup);
    if (rc != 0)
        goto err;

    if (free_parent)
        virCgroupFree(&parent);

    rc = virCgroupPathOfGroup((*newgroup)->path,
                              supported_controllers[0],
                              &grppath);
    if (rc != 0)
        goto err;

    if (access(grppath, F_OK) != 0) {
        rc = -ENOENT;
        goto err;
    }

    return rc;
err:
    virCgroupFree(newgroup);
    *newgroup = NULL;

    return rc;
}

static int virCgroupCreate(virCgroupPtr parent,
                           const char *group,
                           virCgroupPtr *newgroup)
{
    int rc = 0;
    bool free_parent = (parent == NULL);

    rc = virCgroupNew(&parent, group, newgroup);
    if (rc != 0) {
        DEBUG0("Unable to allocate new virCgroup structure");
        goto err;
    }

    rc = virCgroupMakeGroup((*newgroup)->path);
    if (rc != 0)
        goto err;

    if (free_parent)
        virCgroupFree(&parent);

    return rc;
err:
    virCgroupFree(newgroup);
    *newgroup = NULL;

    if (free_parent)
        virCgroupFree(&parent);

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

    for (i = 0; supported_controllers[i] != NULL; i++) {
        if (virCgroupPathOfGroup(group->path,
                                 supported_controllers[i],
                                 &grppath) != 0)
            continue;

        if (rmdir(grppath) != 0)
            rc = -errno;

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
    int fd = -1;
    int i;
    char *grppath = NULL;
    char *taskpath = NULL;
    char *pidstr = NULL;

    for (i = 0; supported_controllers[i] != NULL; i++) {
        rc = virCgroupPathOfGroup(group->path,
                                  supported_controllers[i],
                                  &grppath);
        if (rc != 0)
            goto done;

        if (virAsprintf(&taskpath, "%s/tasks", grppath) == -1) {
            rc = -ENOMEM;
            goto done;
        }

        fd = open(taskpath, O_WRONLY);
        if (fd < 0) {
            rc = -errno;
            goto done;
        }

        if (virAsprintf(&pidstr, "%lu", (unsigned long)pid) == -1) {
            rc = -ENOMEM;
            goto done;
        }

        if (safewrite(fd, pidstr, strlen(pidstr)) <= 0) {
            rc = -errno;
            goto done;
        }

    done:
        VIR_FREE(grppath);
        VIR_FREE(taskpath);
        VIR_FREE(pidstr);
        close(fd);

        if (rc != 0)
            break;
    }

    return rc;
}

/**
 * virCgroupForDomain:
 *
 * @def: Domain definition to create cgroup for
 * @driverName: Classification of this domain type (e.g., xen, qemu, lxc)
 * @group: Pointer to returned virCgroupPtr
 *
 * Returns 0 on success
 */
int virCgroupForDomain(virDomainDefPtr def,
                       const char *driverName,
                       virCgroupPtr *group)
{
    int rc;
    virCgroupPtr typegrp = NULL;

    rc = virCgroupOpen(NULL, driverName, &typegrp);
    if (rc == -ENOENT) {
        rc = virCgroupCreate(NULL, driverName, &typegrp);
        if (rc != 0)
            goto out;
    } else if (rc != 0)
        goto out;

    rc = virCgroupOpen(typegrp, def->name, group);
    if (rc == -ENOENT)
        rc = virCgroupCreate(typegrp, def->name, group);
out:
    virCgroupFree(&typegrp);

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
int virCgroupAllowDevice(virCgroupPtr group,
                         char type,
                         int major,
                         int minor)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:%i rwm", type, major, minor) == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
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
int virCgroupAllowDeviceMajor(virCgroupPtr group,
                              char type,
                              int major)
{
    int rc;
    char *devstr = NULL;

    if (virAsprintf(&devstr, "%c %i:* rwm", type, major) == -1) {
        rc = -ENOMEM;
        goto out;
    }

    rc = virCgroupSetValueStr(group,
                              "devices.allow",
                              devstr);
 out:
    VIR_FREE(devstr);

    return rc;
}

int virCgroupSetCpuShares(virCgroupPtr group, unsigned long shares)
{
    return virCgroupSetValueU64(group, "cpu.shares", (uint64_t)shares);
}

int virCgroupGetCpuShares(virCgroupPtr group, unsigned long *shares)
{
    return virCgroupGetValueU64(group, "cpu.shares", (uint64_t *)shares);
}
