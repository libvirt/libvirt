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
 */
#include <config.h>

#ifdef __linux__
# include <mntent.h>
# include <sys/mount.h>
# include <fcntl.h>
# include <sys/stat.h>

# ifdef MAJOR_IN_MKDEV
#  include <sys/mkdev.h>
# elif MAJOR_IN_SYSMACROS
#  include <sys/sysmacros.h>
# endif

# include <sys/types.h>
# include <signal.h>
# include <dirent.h>
# include <unistd.h>
#endif /* __linux__ */

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "virutil.h"
#include "viralloc.h"
#include "vircgroupbackend.h"
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

#define VIR_FROM_THIS VIR_FROM_CGROUP

#define CGROUP_NB_TOTAL_CPU_STAT_PARAM 3
#define CGROUP_NB_PER_CPU_STAT_PARAM   1

VIR_ENUM_IMPL(virCgroupController,
              VIR_CGROUP_CONTROLLER_LAST,
              "cpu", "cpuacct", "cpuset", "memory", "devices",
              "freezer", "blkio", "net_cls", "perf_event",
              "name=systemd",
);


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


#ifdef __linux__
bool
virCgroupAvailable(void)
{
    size_t i;
    virCgroupBackendPtr *backends = virCgroupBackendGetAll();

    if (!backends)
        return false;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (backends[i] && backends[i]->available())
            return true;
    }

    return false;
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


int
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


/*
 * Process /proc/mounts figuring out what controllers are
 * mounted and where
 */
static int
virCgroupDetectMounts(virCgroupPtr group)
{
    FILE *mounts = NULL;
    struct mntent entry;
    char buf[CGROUP_MAX_VAL];
    int ret = -1;
    size_t i;

    mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL) {
        virReportSystemError(errno, "%s", _("Unable to open /proc/mounts"));
        return -1;
    }

    while (getmntent_r(mounts, &entry, buf, sizeof(buf)) != NULL) {
        for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
            if (group->backends[i] &&
                group->backends[i]->detectMounts(group,
                                                 entry.mnt_type,
                                                 entry.mnt_opts,
                                                 entry.mnt_dir) < 0) {
                goto cleanup;
            }
        }
    }

    ret = 0;
 cleanup:
    VIR_FORCE_FCLOSE(mounts);
    return ret;
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
        size_t i;
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

        for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
            if (group->backends[i] &&
                group->backends[i]->detectPlacement(group, path, controllers,
                                                    selfpath) < 0) {
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    VIR_FORCE_FCLOSE(mapping);
    return ret;
}


static int
virCgroupDetect(virCgroupPtr group,
                pid_t pid,
                int controllers,
                const char *path,
                virCgroupPtr parent)
{
    size_t i;
    bool backendAvailable = false;
    int controllersAvailable = 0;
    virCgroupBackendPtr *backends = virCgroupBackendGetAll();

    VIR_DEBUG("group=%p controllers=%d path=%s parent=%p",
              group, controllers, path, parent);

    if (!backends)
        return -1;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (backends[i] && backends[i]->available()) {
            group->backends[i] = backends[i];
            backendAvailable = true;
        }
    }

    if (!backendAvailable) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no cgroup backend available"));
        return -1;
    }

    if (parent) {
        for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
            if (group->backends[i] &&
                group->backends[i]->copyMounts(group, parent) < 0) {
                return -1;
            }
        }
    } else {
        if (virCgroupDetectMounts(group) < 0)
            return -1;
    }

    /* In some cases we can copy part of the placement info
     * based on the parent cgroup...
     */
    if (parent || path[0] == '/') {
        for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
            if (group->backends[i] &&
                group->backends[i]->copyPlacement(group, path, parent) < 0) {
                return -1;
            }
        }
    }

    /* ... but use /proc/cgroups to fill in the rest */
    if (virCgroupDetectPlacement(group, pid, path) < 0)
        return -1;

    /* Check that for every mounted controller, we found our placement */
    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->validatePlacement(group, pid) < 0) {
            return -1;
        }
    }

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i]) {
            int rc = group->backends[i]->detectControllers(group, controllers);
            if (rc < 0)
                return -1;
            controllersAvailable |= rc;
        }
    }

    /* Check that at least 1 controller is available */
    if (controllersAvailable == 0) {
        virReportSystemError(ENXIO, "%s",
                             _("At least one cgroup controller is required"));
        return -1;
    }

    return 0;
}


char *
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


int
virCgroupSetValueRaw(const char *path,
                     const char *value)
{
    char *tmp;

    VIR_DEBUG("Set value '%s' to '%s'", path, value);
    if (virFileWriteStr(path, value, 0) < 0) {
        if (errno == EINVAL &&
            (tmp = strrchr(path, '/'))) {
            virReportSystemError(errno,
                                 _("Invalid value '%s' for '%s'"),
                                 value, tmp + 1);
            return -1;
        }
        virReportSystemError(errno,
                             _("Unable to write to '%s'"), path);
        return -1;
    }

    return 0;
}


int
virCgroupGetValueRaw(const char *path,
                     char **value)
{
    int rc;

    *value = NULL;

    VIR_DEBUG("Get value %s", path);

    if ((rc = virFileReadAll(path, 1024*1024, value)) < 0) {
        virReportSystemError(errno,
                             _("Unable to read from '%s'"), path);
        return -1;
    }

    /* Terminated with '\n' has sometimes harmful effects to the caller */
    if (rc > 0 && (*value)[rc - 1] == '\n')
        (*value)[rc - 1] = '\0';

    return 0;
}


int
virCgroupSetValueStr(virCgroupPtr group,
                     int controller,
                     const char *key,
                     const char *value)
{
    VIR_AUTOFREE(char *) keypath = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    return virCgroupSetValueRaw(keypath, value);
}


int
virCgroupGetValueStr(virCgroupPtr group,
                     int controller,
                     const char *key,
                     char **value)
{
    VIR_AUTOFREE(char *) keypath = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    return virCgroupGetValueRaw(keypath, value);
}


int
virCgroupGetValueForBlkDev(const char *str,
                           const char *path,
                           char **value)
{
    VIR_AUTOFREE(char *) prefix = NULL;
    char **lines = NULL;
    int ret = -1;

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


int
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


int
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


int
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


int
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
virCgroupMakeGroup(virCgroupPtr parent,
                   virCgroupPtr group,
                   bool create,
                   unsigned int flags)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->makeGroup(parent, group, create, flags) < 0) {
            virCgroupRemove(group);
            return -1;
        }
    }

    return 0;
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
int
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
virCgroupAddTaskInternal(virCgroupPtr group,
                         pid_t pid,
                         unsigned int flags)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->addTask(group, pid, flags) < 0) {
            return -1;
        }
    }

    return 0;
}


/**
 * virCgroupAddProcess:
 *
 * @group: The cgroup to add a process to
 * @pid: The pid of the process to add
 *
 * Will add the process to all controllers, except the
 * systemd unit controller.
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupAddProcess(virCgroupPtr group, pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid, VIR_CGROUP_TASK_PROCESS);
}

/**
 * virCgroupAddMachineProcess:
 *
 * @group: The cgroup to add a process to
 * @pid: The pid of the process to add
 *
 * Will add the process to all controllers, including the
 * systemd unit controller.
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupAddMachineProcess(virCgroupPtr group, pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid,
                                    VIR_CGROUP_TASK_PROCESS |
                                    VIR_CGROUP_TASK_SYSTEMD);
}

/**
 * virCgroupAddThread:
 *
 * @group: The cgroup to add a thread to
 * @pid: The pid of the thread to add
 *
 * Will add the thread to all controllers, except the
 * systemd unit controller.
 *
 * Returns: 0 on success, -1 on error
 */
int
virCgroupAddThread(virCgroupPtr group,
                   pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid, VIR_CGROUP_TASK_THREAD);
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

    if (virCgroupMakeGroup(domain, *group, create, VIR_CGROUP_THREAD) < 0) {
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
    size_t i;

    if (virCgroupNewDetect(pid, controllers, group) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;
        return -1;
    }

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if ((*group)->backends[i] &&
            !(*group)->backends[i]->validateMachineGroup(*group, name,
                                                         drivername,
                                                         machinename)) {
            VIR_DEBUG("Failed to validate machine name for '%s' driver '%s'",
                      name, drivername);
            virCgroupFree(group);
            return 0;
        }
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
                     "/",
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

        if (virCgroupMakeGroup(parent, tmp, true, VIR_CGROUP_SYSTEMD) < 0) {
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
                           unsigned int maxthreads,
                           virCgroupPtr *group)
{
    int rv;
    virCgroupPtr init;
    VIR_AUTOFREE(char *) path = NULL;
    size_t i;

    VIR_DEBUG("Trying to setup machine '%s' via systemd", name);
    if ((rv = virSystemdCreateMachine(name,
                                      drivername,
                                      uuid,
                                      rootdir,
                                      pidleader,
                                      isContainer,
                                      nnicindexes,
                                      nicindexes,
                                      partition,
                                      maxthreads)) < 0)
        return rv;

    if (controllers != -1)
        controllers |= (1 << VIR_CGROUP_CONTROLLER_SYSTEMD);

    VIR_DEBUG("Detecting systemd placement");
    if (virCgroupNewDetect(pidleader,
                           controllers,
                           &init) < 0)
        return -1;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (init->backends[i] &&
            (path = init->backends[i]->stealPlacement(init))) {
            break;
        }
    }
    virCgroupFree(&init);

    if (!path || STREQ(path, "/") || path[0] != '/') {
        VIR_DEBUG("Systemd didn't setup its controller");
        return -2;
    }

    if (virCgroupEnableMissingControllers(path, pidleader,
                                          controllers, group) < 0) {
        return -1;
    }

    if (virCgroupAddProcess(*group, pidleader) < 0) {
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

    if (virCgroupAddProcess(*group, pidleader) < 0) {
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
                    unsigned int maxthreads,
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
                                         maxthreads,
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
    size_t i;

    if (!cgroup)
        return false;
    if (controller < 0 || controller >= VIR_CGROUP_CONTROLLER_LAST)
        return false;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (cgroup->backends[i] &&
            cgroup->backends[i]->hasController(cgroup, controller)) {
            return true;
        }
    }

    return false;
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

    VIR_CGROUP_BACKEND_CALL(group, controller, pathOfController, -1,
                            controller, key, path);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioIoServiced, -1,
                            bytes_read, bytes_write,
                            requests_read, requests_write);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioIoDeviceServiced, -1,
                            path, bytes_read, bytes_write,
                            requests_read, requests_write);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioWeight, -1, weight);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioWeight, -1, weight);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioDeviceReadIops, -1, path, riops);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioDeviceWriteIops, -1, path, wiops);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioDeviceReadBps, -1, path, rbps);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioDeviceWriteBps, -1, path, wbps);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            setBlkioDeviceWeight, -1, path, weight);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioDeviceReadIops, -1, path, riops);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioDeviceWriteIops, -1, path, wiops);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioDeviceReadBps, -1, path, rbps);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioDeviceWriteBps, -1, path, wbps);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_BLKIO,
                            getBlkioDeviceWeight, -1, path, weight);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            setMemory, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemoryStat, -1, cache,
                            activeAnon, inactiveAnon,
                            activeFile, inactiveFile,
                            unevictable);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemoryUsage, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            setMemoryHardLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemoryHardLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            setMemorySoftLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemorySoftLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            setMemSwapHardLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemSwapHardLimit, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_MEMORY,
                            getMemSwapUsage, -1, kb);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            setCpusetMems, -1, mems);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            getCpusetMems, -1, mems);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            setCpusetMemoryMigrate, -1, migrate);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            getCpusetMemoryMigrate, -1, migrate);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            setCpusetCpus, -1, cpus);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUSET,
                            getCpusetCpus, -1, cpus);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            denyAllDevices, -1);
}

/**
 * virCgroupAllowAllDevices:
 *
 * Allows the permission for all devices by setting lines similar
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            allowAllDevices, -1, perms);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            allowDevice, -1, type, major, minor, perms);
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
 * accessible, or * -1 on error
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

    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            allowDevice, -1,
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            denyDevice, -1, type, major, minor, perms);
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

    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_DEVICES,
                            denyDevice, -1,
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
            int idx = (i - start_cpu) * nparams + param_idx;
            if (virTypedParameterAssign(&params[idx],
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            setCpuShares, -1, shares);
}


int
virCgroupGetCpuShares(virCgroupPtr group, unsigned long long *shares)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            getCpuShares, -1, shares);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            setCpuCfsPeriod, -1, cfs_period);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            getCpuCfsPeriod, -1, cfs_period);
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            setCpuCfsQuota, -1, cfs_quota);
}


int
virCgroupGetCpuacctPercpuUsage(virCgroupPtr group, char **usage)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctPercpuUsage, -1, usage);
}


int
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
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i]) {
            int rc = group->backends[i]->remove(group);
            if (rc < 0)
                return rc;
        }
    }

    return 0;
}


/*
 * Returns 1 if some PIDs are killed, 0 if none are killed, or -1 on error
 */
static int
virCgroupKillInternal(virCgroupPtr group,
                      int signum,
                      virHashTablePtr pids,
                      int controller,
                      const char *taskFile)
{
    int ret = -1;
    bool killedAny = false;
    VIR_AUTOFREE(char *) keypath = NULL;
    bool done = false;
    FILE *fp = NULL;
    VIR_DEBUG("group=%p path=%s signum=%d pids=%p",
              group, group->path, signum, pids);

    if (virCgroupPathOfController(group, controller, taskFile, &keypath) < 0)
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


int
virCgroupKillRecursiveInternal(virCgroupPtr group,
                               int signum,
                               virHashTablePtr pids,
                               int controller,
                               const char *taskFile,
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

    if (virCgroupPathOfController(group, controller, "", &keypath) < 0)
        return -1;

    if ((rc = virCgroupKillInternal(group, signum, pids,
                                    controller, taskFile)) < 0) {
        goto cleanup;
    }
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
                                                 controller, taskFile, true)) < 0)
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
    int ret = 0;
    int rc;
    size_t i;
    bool backendAvailable = false;
    virCgroupBackendPtr *backends = virCgroupBackendGetAll();
    virHashTablePtr pids = virHashCreateFull(100,
                                             NULL,
                                             virCgroupPidCode,
                                             virCgroupPidEqual,
                                             virCgroupPidCopy,
                                             NULL);

    VIR_DEBUG("group=%p path=%s signum=%d", group, group->path, signum);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (backends && backends[i] && backends[i]->available()) {
            backendAvailable = true;
            rc = backends[i]->killRecursive(group, signum, pids);
            if (rc < 0) {
                ret = -1;
                goto cleanup;
            }
            if (rc > 0)
                ret = rc;
        }
    }

    if (!backends || !backendAvailable) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no cgroup backend available"));
        goto cleanup;
    }

 cleanup:
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
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            getCpuCfsQuota, -1, cfs_quota);
}


int
virCgroupGetCpuacctUsage(virCgroupPtr group, unsigned long long *usage)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctUsage, -1, usage);
}


int
virCgroupGetCpuacctStat(virCgroupPtr group, unsigned long long *user,
                        unsigned long long *sys)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctStat, -1, user, sys);
}


int
virCgroupSetFreezerState(virCgroupPtr group, const char *state)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_FREEZER,
                            setFreezerState, -1, state);
}


int
virCgroupGetFreezerState(virCgroupPtr group, char **state)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_FREEZER,
                            getFreezerState, -1, state);
}


int
virCgroupBindMount(virCgroupPtr group, const char *oldroot,
                   const char *mountopts)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->bindMount(group, oldroot, mountopts) < 0) {
            return -1;
        }
    }

    return 0;
}


int virCgroupSetOwner(virCgroupPtr cgroup,
                      uid_t uid,
                      gid_t gid,
                      int controllers)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (cgroup->backends[i] &&
            cgroup->backends[i]->setOwner(cgroup, uid, gid, controllers) < 0) {
            return -1;
        }
    }

    return 0;
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
    VIR_CGROUP_BACKEND_CALL(cgroup, VIR_CGROUP_CONTROLLER_CPU,
                            supportsCpuBW, false);
}

int
virCgroupHasEmptyTasks(virCgroupPtr cgroup, int controller)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (cgroup->backends[i]) {
            int rc = cgroup->backends[i]->hasEmptyTasks(cgroup, controller);
            if (rc <= 0)
                return rc;
        }
    }

    return 1;
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

#else /* !__linux__ */

bool
virCgroupAvailable(void)
{
    return false;
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
                    unsigned int maxthreads ATTRIBUTE_UNUSED,
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
virCgroupAddProcess(virCgroupPtr group ATTRIBUTE_UNUSED,
                    pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddMachineProcess(virCgroupPtr group ATTRIBUTE_UNUSED,
                           pid_t pid ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddThread(virCgroupPtr group ATTRIBUTE_UNUSED,
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
#endif /* !__linux__ */


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
        VIR_FREE((*group)->legacy[i].mountPoint);
        VIR_FREE((*group)->legacy[i].linkPoint);
        VIR_FREE((*group)->legacy[i].placement);
    }

    VIR_FREE((*group)->unified.mountPoint);
    VIR_FREE((*group)->unified.placement);

    VIR_FREE((*group)->path);
    VIR_FREE(*group);
}


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
