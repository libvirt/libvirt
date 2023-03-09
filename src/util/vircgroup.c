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
# include <sys/sysmacros.h>
# include <sys/types.h>
# include <signal.h>
# include <dirent.h>
# include <unistd.h>
#endif /* __linux__ */

#define LIBVIRT_VIRCGROUPPRIV_H_ALLOW
#include "vircgrouppriv.h"

#include "viralloc.h"
#include "vircgroupbackend.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virgdbus.h"
#include "virstring.h"
#include "virsystemd.h"
#include "virtypedparam.h"
#include "virhostcpu.h"

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
    virCgroupBackend **backends = virCgroupBackendGetAll();

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
    g_autofree char *line = NULL;
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

        tmp = strchr(line, ' ');
        if (tmp) {
            *tmp = '\0';
            len = tmp - line;
        } else {
            len = strlen(line);
        }

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

    newstr = g_strdup_printf("_%s", *path);

    VIR_FREE(*path);
    *path = newstr;

    return 0;
}


static int
virCgroupSetBackends(virCgroup *group)
{
    virCgroupBackend **backends = virCgroupBackendGetAll();
    bool backendAvailable = false;
    size_t i;

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

    return 0;
}


static int
virCgroupCopyMounts(virCgroup *group,
                    virCgroup *parent)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->copyMounts(group, parent) < 0) {
            return -1;
        }
    }

    return 0;
}


/*
 * Process /proc/mounts figuring out what controllers are
 * mounted and where
 */
static int
virCgroupDetectMounts(virCgroup *group)
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


static int
virCgroupCopyPlacement(virCgroup *group,
                      const char *path,
                      virCgroup *parent)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->copyPlacement(group, path, parent) < 0) {
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
virCgroupDetectPlacement(virCgroup *group,
                         pid_t pid,
                         const char *path)
{
    FILE *mapping  = NULL;
    char line[1024];
    int ret = -1;
    g_autofree char *procfile = NULL;

    VIR_DEBUG("Detecting placement for pid %lld path %s",
              (long long) pid, path);
    if (pid == -1) {
        procfile = g_strdup("/proc/self/cgroup");
    } else {
        procfile = g_strdup_printf("/proc/%lld/cgroup", (long long)pid);
    }

    mapping = fopen(procfile, "r");
    if (mapping == NULL) {
        virReportSystemError(errno,
                             _("Unable to open '%1$s'"),
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
virCgroupSetPlacement(virCgroup *group,
                      const char *path)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->setPlacement(group, path) < 0) {
            return -1;
        }
    }

    return 0;
}


static int
virCgroupValidatePlacement(virCgroup *group,
                           pid_t pid)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->validatePlacement(group, pid) < 0) {
            return -1;
        }
    }

    return 0;
}


static int
virCgroupDetectControllers(virCgroup *group,
                           int controllers,
                           virCgroup *parent)
{
    size_t i;
    int controllersAvailable = 0;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        int rc;

        if (!group->backends[i])
            continue;

        rc = group->backends[i]->detectControllers(group, controllers, parent,
                                                   controllersAvailable);
        if (rc < 0)
            return -1;
        controllersAvailable |= rc;
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
    struct stat sb;

    if (stat(path, &sb) < 0) {
        virReportSystemError(errno,
                             _("Path '%1$s' is not accessible"),
                             path);
        return NULL;
    }

    if (!S_ISBLK(sb.st_mode)) {
        virReportSystemError(EINVAL,
                             _("Path '%1$s' must be a block device"),
                             path);
        return NULL;
    }

    /* Automatically append space after the string since all callers
     * use it anyway */
    return g_strdup_printf("%d:%d ", major(sb.st_rdev), minor(sb.st_rdev));
}


int
virCgroupSetValueDBus(const char *unitName,
                      const char *key,
                      GVariant *value)
{
    GDBusConnection *conn;
    g_autoptr(GVariant) message = NULL;
    GVariantBuilder builder;
    GVariant *props = NULL;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(sv)"));
    g_variant_builder_add(&builder, "(sv)", key, value);
    props = g_variant_builder_end(&builder);

    message = g_variant_new("(sb@a(sv))", unitName, true, props);

    if (!(conn = virGDBusGetSystemBus()))
        return -1;

    return virGDBusCallMethod(conn,
                              NULL,
                              NULL,
                              NULL,
                              "org.freedesktop.systemd1",
                              "/org/freedesktop/systemd1",
                              "org.freedesktop.systemd1.Manager",
                              "SetUnitProperties",
                              message);
}


int
virCgroupSetValueRaw(const char *path,
                     const char *value)
{
    char *tmp;

    VIR_DEBUG("Set path '%s' to value '%s'", path, value);
    if (virFileWriteStr(path, value, 0) < 0) {
        if (errno == EINVAL &&
            (tmp = strrchr(path, '/'))) {
            virReportSystemError(errno,
                                 _("Invalid value '%1$s' for '%2$s'"),
                                 value, tmp + 1);
            return -1;
        }
        virReportSystemError(errno,
                             _("Unable to write to '%1$s'"), path);
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
                             _("Unable to read from '%1$s'"), path);
        return -1;
    }

    /* Terminated with '\n' has sometimes harmful effects to the caller */
    if (rc > 0 && (*value)[rc - 1] == '\n')
        (*value)[rc - 1] = '\0';

    return 0;
}


int
virCgroupSetValueStr(virCgroup *group,
                     int controller,
                     const char *key,
                     const char *value)
{
    g_autofree char *keypath = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    return virCgroupSetValueRaw(keypath, value);
}


int
virCgroupGetValueStr(virCgroup *group,
                     int controller,
                     const char *key,
                     char **value)
{
    g_autofree char *keypath = NULL;

    if (virCgroupPathOfController(group, controller, key, &keypath) < 0)
        return -1;

    return virCgroupGetValueRaw(keypath, value);
}


int
virCgroupGetValueForBlkDev(const char *str,
                           const char *path,
                           char **value)
{
    g_autofree char *prefix = NULL;
    g_auto(GStrv) lines = NULL;
    GStrv tmp;

    if (!(prefix = virCgroupGetBlockDevString(path)))
        return -1;

    if (!(lines = g_strsplit(str, "\n", -1)))
        return -1;

    for (tmp = lines; *tmp; tmp++) {
        if ((*value = g_strdup(STRSKIP(*tmp, prefix))))
            break;
    }

    return 0;
}


int
virCgroupSetValueU64(virCgroup *group,
                     int controller,
                     const char *key,
                     unsigned long long int value)
{
    g_autofree char *strval = NULL;

    strval = g_strdup_printf("%llu", value);

    return virCgroupSetValueStr(group, controller, key, strval);
}


int
virCgroupSetValueI64(virCgroup *group,
                     int controller,
                     const char *key,
                     long long int value)
{
    g_autofree char *strval = NULL;

    strval = g_strdup_printf("%lld", value);

    return virCgroupSetValueStr(group, controller, key, strval);
}


int
virCgroupGetValueI64(virCgroup *group,
                     int controller,
                     const char *key,
                     long long int *value)
{
    g_autofree char *strval = NULL;

    if (virCgroupGetValueStr(group, controller, key, &strval) < 0)
        return -1;

    if (virStrToLong_ll(strval, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       strval);
        return -1;
    }

    return 0;
}


int
virCgroupGetValueU64(virCgroup *group,
                     int controller,
                     const char *key,
                     unsigned long long int *value)
{
    g_autofree char *strval = NULL;

    if (virCgroupGetValueStr(group, controller, key, &strval) < 0)
        return -1;

    if (virStrToLong_ull(strval, NULL, 10, value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to parse '%1$s' as an integer"),
                       strval);
        return -1;
    }

    return 0;
}


static int
virCgroupMakeGroup(virCgroup *parent,
                   virCgroup *group,
                   bool create,
                   pid_t pid,
                   unsigned int flags)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            group->backends[i]->makeGroup(parent, group, create, pid, flags) < 0) {
            virCgroupRemove(group);
            return -1;
        }
    }

    return 0;
}


static bool
virCgroupExists(virCgroup *group)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (group->backends[i] &&
            !group->backends[i]->exists(group)) {
            return false;
        }
    }

    return true;
}


/**
 * virCgroupNew:
 * @path: path for the new group
 * @controllers: bitmask of controllers to activate
 *
 * Create a new cgroup storing it in @group.
 *
 * Returns 0 on success, -1 on error
 */
int
virCgroupNew(const char *path,
             int controllers,
             virCgroup **group)
{
    g_autoptr(virCgroup) newGroup = NULL;

    VIR_DEBUG("path=%s controllers=%d group=%p",
              path, controllers, group);

    *group = NULL;
    newGroup = g_new0(virCgroup, 1);

    if (virCgroupSetBackends(newGroup) < 0)
        return -1;

    if (virCgroupDetectMounts(newGroup) < 0)
        return -1;

    if (virCgroupSetPlacement(newGroup, path) < 0)
        return -1;

    /* ... but use /proc/cgroups to fill in the rest */
    if (virCgroupDetectPlacement(newGroup, -1, path) < 0)
        return -1;

    /* Check that for every mounted controller, we found our placement */
    if (virCgroupValidatePlacement(newGroup, -1) < 0)
        return -1;

    if (virCgroupDetectControllers(newGroup, controllers, NULL) < 0)
        return -1;

    *group = g_steal_pointer(&newGroup);
    return 0;
}


static int
virCgroupAddTaskInternal(virCgroup *group,
                         pid_t pid,
                         unsigned int flags)
{
    size_t i;
    virCgroup *parent = virCgroupGetNested(group);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (parent->backends[i] &&
            parent->backends[i]->addTask(parent, pid, flags) < 0) {
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
virCgroupAddProcess(virCgroup *group, pid_t pid)
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
virCgroupAddMachineProcess(virCgroup *group, pid_t pid)
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
virCgroupAddThread(virCgroup *group,
                   pid_t pid)
{
    return virCgroupAddTaskInternal(group, pid, VIR_CGROUP_TASK_THREAD);
}


static int
virCgroupSetPartitionSuffix(const char *path, char **res)
{
    g_auto(GStrv) tokens = NULL;
    size_t i;

    if (!(tokens = g_strsplit(path, "/", 0)))
        return -1;

    for (i = 0; tokens[i] != NULL; i++) {
        /* Special case the 3 top level fixed dirs
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
            g_autofree char *oldtoken = tokens[i];
            tokens[i] = g_strdup_printf("%s.partition", oldtoken);
        }

        if (virCgroupPartitionEscape(&(tokens[i])) < 0)
            return -1;
    }

    if (!(*res = g_strjoinv("/", tokens)))
        return -1;

    return 0;
}


static int
virCgroupNewFromParent(virCgroup *parent,
                       const char *path,
                       int controllers,
                       virCgroup **group)
{
    g_autoptr(virCgroup) new = g_new0(virCgroup, 1);

    VIR_DEBUG("parent=%p path=%s controllers=%d group=%p",
              parent, path, controllers, group);

    if (virCgroupSetBackends(new) < 0)
        return -1;

    if (virCgroupCopyMounts(new, parent) < 0)
        return -1;

    if (virCgroupCopyPlacement(new, path, parent) < 0)
        return -1;

    if (virCgroupDetectPlacement(new, -1, path) < 0)
        return -1;

    if (virCgroupValidatePlacement(new, -1) < 0)
        return -1;

    if (virCgroupDetectControllers(new, controllers, parent) < 0)
        return -1;

    *group = g_steal_pointer(&new);
    return 0;
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
                      virCgroup **group)
{
    g_autofree char *newPath = NULL;
    g_autoptr(virCgroup) parent = NULL;
    g_autoptr(virCgroup) newGroup = NULL;
    char *partition = NULL;

    VIR_DEBUG("path=%s create=%d controllers=%x",
              path, create, controllers);

    *group = NULL;

    if (!g_path_is_absolute(path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Partition path '%1$s' must start with '/'"),
                       path);
        return -1;
    }

    if (virCgroupSetPartitionSuffix(path, &newPath) < 0)
        return -1;

    if (STRNEQ(newPath, "/")) {
        char *tmp;
        const char *parentPath;

        tmp = strrchr(newPath, '/');
        *tmp = '\0';

        if (tmp == newPath) {
            parentPath = "/";
        } else {
            parentPath = newPath;
        }

        if (virCgroupNew(parentPath, controllers, &parent) < 0)
            return -1;

        partition = tmp + 1;
    } else {
        partition = newPath;
    }

    if (virCgroupNewFromParent(parent, partition, controllers, &newGroup) < 0)
        return -1;

    if (parent) {
        if (virCgroupMakeGroup(parent, newGroup, create, -1, VIR_CGROUP_NONE) < 0)
            return -1;
    }

    *group = g_steal_pointer(&newGroup);
    return 0;
}


static int
virCgroupNewNested(virCgroup *parent,
                   int controllers,
                   bool create,
                   pid_t pid,
                   virCgroup **nested)
{
    g_autoptr(virCgroup) new = NULL;

    if (virCgroupNewFromParent(parent, "libvirt", controllers, &new) < 0)
        return -1;

    if (create) {
        if (virCgroupMakeGroup(parent, new, create, pid, VIR_CGROUP_NONE) < 0)
            return -1;
    }

    *nested = g_steal_pointer(&new);
    return 0;
}


/**
* virCgroupNewSelf:
*
* @group: Pointer to returned virCgroup *
*
* Obtain a cgroup representing the config of the
* current process
*
* Returns 0 on success, or -1 on error
*/
int
virCgroupNewSelf(virCgroup **group)
{
    g_autoptr(virCgroup) newGroup = NULL;
    g_autoptr(virCgroup) nested = NULL;

    if (virCgroupNewDetect(-1, -1, &newGroup) < 0)
        return -1;

    if (virCgroupNewNested(newGroup, -1, false, -1, &nested) < 0)
        return -1;

    if (virCgroupExists(nested))
        newGroup->nested = g_steal_pointer(&nested);

    *group = g_steal_pointer(&newGroup);
    return 0;
}


/**
 * virCgroupNewDomainPartition:
 *
 * @partition: partition holding the domain
 * @driver: name of the driver
 * @name: name of the domain
 * @group: Pointer to returned virCgroup *
 *
 * Returns 0 on success, or -1 on error
 */
int
virCgroupNewDomainPartition(virCgroup *partition,
                            const char *driver,
                            const char *name,
                            virCgroup **group)
{
    g_autofree char *grpname = NULL;
    g_autoptr(virCgroup) newGroup = NULL;

    grpname = g_strdup_printf("%s.libvirt-%s", name, driver);

    if (virCgroupPartitionEscape(&grpname) < 0)
        return -1;

    if (virCgroupNewFromParent(partition, grpname, -1, &newGroup) < 0)
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
    if (virCgroupMakeGroup(partition, newGroup, true, -1,
                           VIR_CGROUP_MEM_HIERACHY) < 0) {
        return -1;
    }

    *group = g_steal_pointer(&newGroup);
    return 0;
}


/**
 * virCgroupNewThread:
 *
 * @domain: group for the domain
 * @name: enum to generate the name for the new thread
 * @id: id of the vcpu or iothread
 * @create: true to create if not already existing
 * @group: Pointer to returned virCgroup *
 *
 * Returns 0 on success, or -1 on error
 */
int
virCgroupNewThread(virCgroup *domain,
                   virCgroupThreadName nameval,
                   int id,
                   bool create,
                   virCgroup **group)
{
    g_autofree char *name = NULL;
    g_autoptr(virCgroup) newGroup = NULL;
    virCgroup *parent = NULL;
    int controllers;

    *group = NULL;

    switch (nameval) {
    case VIR_CGROUP_THREAD_VCPU:
        name = g_strdup_printf("vcpu%d", id);
        break;
    case VIR_CGROUP_THREAD_EMULATOR:
        name = g_strdup("emulator");
        break;
    case VIR_CGROUP_THREAD_IOTHREAD:
        name = g_strdup_printf("iothread%d", id);
        break;
    case VIR_CGROUP_THREAD_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected name value %1$d"), nameval);
        return -1;
    }

    controllers = ((1 << VIR_CGROUP_CONTROLLER_CPU) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUACCT) |
                   (1 << VIR_CGROUP_CONTROLLER_CPUSET));

    parent = virCgroupGetNested(domain);

    if (virCgroupNewFromParent(parent, name, controllers, &newGroup) < 0)
        return -1;

    if (virCgroupMakeGroup(parent, newGroup, create, -1, VIR_CGROUP_THREAD) < 0)
        return -1;

    *group = g_steal_pointer(&newGroup);
    return 0;
}


int
virCgroupNewDetect(pid_t pid,
                   int controllers,
                   virCgroup **group)
{
    g_autoptr(virCgroup) new = g_new0(virCgroup, 1);

    VIR_DEBUG("pid=%lld controllers=%d group=%p",
              (long long) pid, controllers, group);

    if (virCgroupSetBackends(new) < 0)
        return -1;

    if (virCgroupDetectMounts(new) < 0)
        return -1;

    if (virCgroupDetectPlacement(new, pid, "") < 0)
        return -1;

    if (virCgroupValidatePlacement(new, pid) < 0)
        return -1;

    if (virCgroupDetectControllers(new, controllers, NULL) < 0)
        return -1;

    *group = g_steal_pointer(&new);
    return 0;
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
                          virCgroup **group)
{
    size_t i;
    g_autoptr(virCgroup) newGroup = NULL;
    g_autoptr(virCgroup) nested = NULL;

    *group = NULL;

    if (virCgroupNewDetect(pid, controllers, &newGroup) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;
        return -1;
    }

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (newGroup->backends[i] &&
            !newGroup->backends[i]->validateMachineGroup(newGroup, name,
                                                         drivername,
                                                         machinename)) {
            VIR_DEBUG("Failed to validate machine name for '%s' driver '%s'",
                      name, drivername);
            return 0;
        }
    }

    newGroup->unitName = virSystemdGetMachineUnitByPID(pid);
    if (virSystemdHasMachined() == 0 && !newGroup->unitName)
        return -1;

    if (virCgroupNewNested(newGroup, controllers, false, -1, &nested) < 0)
        return -1;

    if (virCgroupExists(nested))
        newGroup->nested = g_steal_pointer(&nested);

    *group = g_steal_pointer(&newGroup);
    return 0;
}


static int
virCgroupEnableMissingControllers(char *path,
                                  int controllers,
                                  virCgroup **group)
{
    g_autoptr(virCgroup) parent = NULL;
    g_auto(GStrv) tokens = g_strsplit(path, "/", 0);
    size_t i;

    if (virCgroupNew("/", controllers, &parent) < 0)
        return -1;

    /* Skip the first token as it is empty string. */
    for (i = 1; tokens[i]; i++) {
        g_autoptr(virCgroup) tmp = NULL;

        if (virCgroupNewFromParent(parent,
                                   tokens[i],
                                   controllers,
                                   &tmp) < 0)
            return -1;

        if (virCgroupMakeGroup(parent, tmp, true, -1, VIR_CGROUP_SYSTEMD) < 0)
            return -1;

        virCgroupFree(parent);
        parent = g_steal_pointer(&tmp);
    }

    *group = g_steal_pointer(&parent);
    return 0;
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
                           virCgroup **group)
{
    int rv;
    g_autoptr(virCgroup) init = NULL;
    g_autoptr(virCgroup) newGroup = NULL;
    g_autoptr(virCgroup) nested = NULL;
    g_autofree char *path = NULL;
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

    if (!path || STREQ(path, "/") || !g_path_is_absolute(path)) {
        VIR_DEBUG("Systemd didn't setup its controller, path=%s",
                  NULLSTR(path));
        return -2;
    }

    if (virCgroupEnableMissingControllers(path, controllers, &newGroup) < 0)
        return -1;

    newGroup->unitName = virSystemdGetMachineUnitByPID(pidleader);
    if (!newGroup->unitName)
        return -1;

    if (virCgroupNewNested(newGroup, controllers, true, pidleader, &nested) < 0)
        return -1;

    newGroup->nested = g_steal_pointer(&nested);

    if (virCgroupAddProcess(newGroup, pidleader) < 0) {
        virErrorPtr saved;

        virErrorPreserveLast(&saved);
        virCgroupRemove(newGroup);
        virErrorRestore(&saved);
        return 0;
    }

    *group = g_steal_pointer(&newGroup);
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
                          virCgroup **group)
{
    g_autoptr(virCgroup) parent = NULL;
    g_autoptr(virCgroup) newGroup = NULL;

    VIR_DEBUG("Fallback to non-systemd setup");
    if (virCgroupNewPartition(partition,
                              STREQ(partition, "/machine"),
                              controllers,
                              &parent) < 0) {
        if (virCgroupNewIgnoreError())
            return 0;

        return -1;
    }

    if (virCgroupNewDomainPartition(parent,
                                    drivername,
                                    name,
                                    &newGroup) < 0)
        return -1;

    if (virCgroupAddProcess(newGroup, pidleader) < 0) {
        virErrorPtr saved;

        virErrorPreserveLast(&saved);
        virCgroupRemove(newGroup);
        virErrorRestore(&saved);
    }

    *group = g_steal_pointer(&newGroup);
    return 0;
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
                    virCgroup **group)
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
virCgroupHasController(virCgroup *cgroup, int controller)
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


static int
virCgroupGetAnyController(virCgroup *cgroup)
{
    size_t i;

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (!cgroup->backends[i])
            continue;

        return cgroup->backends[i]->getAnyController(cgroup);
    }

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Unable to get any controller"));
    return -1;
}


int
virCgroupPathOfController(virCgroup *group,
                          unsigned int controller,
                          const char *key,
                          char **path)
{
    if (controller >= VIR_CGROUP_CONTROLLER_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid controller id '%1$d'"), controller);
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
virCgroupGetBlkioIoServiced(virCgroup *group,
                            long long *bytes_read,
                            long long *bytes_write,
                            long long *requests_read,
                            long long *requests_write)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
virCgroupGetBlkioIoDeviceServiced(virCgroup *group,
                                  const char *path,
                                  long long *bytes_read,
                                  long long *bytes_write,
                                  long long *requests_read,
                                  long long *requests_write)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
virCgroupSetBlkioWeight(virCgroup *group, unsigned int weight)
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
virCgroupGetBlkioWeight(virCgroup *group, unsigned int *weight)
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
static int
virCgroupSetBlkioDeviceReadIops(virCgroup *group,
                                const char *path,
                                unsigned int riops)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupSetBlkioDeviceWriteIops(virCgroup *group,
                                 const char *path,
                                 unsigned int wiops)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupSetBlkioDeviceReadBps(virCgroup *group,
                               const char *path,
                               unsigned long long rbps)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupSetBlkioDeviceWriteBps(virCgroup *group,
                                const char *path,
                                unsigned long long wbps)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupSetBlkioDeviceWeight(virCgroup *group,
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
static int
virCgroupGetBlkioDeviceReadIops(virCgroup *group,
                                const char *path,
                                unsigned int *riops)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupGetBlkioDeviceWriteIops(virCgroup *group,
                                 const char *path,
                                 unsigned int *wiops)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupGetBlkioDeviceReadBps(virCgroup *group,
                               const char *path,
                               unsigned long long *rbps)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupGetBlkioDeviceWriteBps(virCgroup *group,
                                const char *path,
                                unsigned long long *wbps)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_BLKIO,
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
static int
virCgroupGetBlkioDeviceWeight(virCgroup *group,
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
virCgroupSetMemory(virCgroup *group, unsigned long long kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemoryStat(virCgroup *group,
                       unsigned long long *cache,
                       unsigned long long *activeAnon,
                       unsigned long long *inactiveAnon,
                       unsigned long long *activeFile,
                       unsigned long long *inactiveFile,
                       unsigned long long *unevictable)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemoryUsage(virCgroup *group, unsigned long *kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupSetMemoryHardLimit(virCgroup *group, unsigned long long kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemoryHardLimit(virCgroup *group, unsigned long long *kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupSetMemorySoftLimit(virCgroup *group, unsigned long long kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemorySoftLimit(virCgroup *group, unsigned long long *kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupSetMemSwapHardLimit(virCgroup *group, unsigned long long kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemSwapHardLimit(virCgroup *group, unsigned long long *kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupGetMemSwapUsage(virCgroup *group, unsigned long long *kb)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_MEMORY,
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
virCgroupSetCpusetMems(virCgroup *group, const char *mems)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupGetCpusetMems(virCgroup *group, char **mems)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupSetCpusetMemoryMigrate(virCgroup *group, bool migrate)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupGetCpusetMemoryMigrate(virCgroup *group, bool *migrate)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupSetCpusetCpus(virCgroup *group, const char *cpus)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupGetCpusetCpus(virCgroup *group, char **cpus)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUSET,
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
virCgroupDenyAllDevices(virCgroup *group)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupAllowAllDevices(virCgroup *group, int perms)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupAllowDevice(virCgroup *group, char type, int major, int minor,
                     int perms)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupAllowDevicePath(virCgroup *group,
                         const char *path,
                         int perms,
                         bool ignoreEacces)
{
    struct stat sb;
    virCgroup *parent = virCgroupGetNested(group);

    if (stat(path, &sb) < 0) {
        if (errno == EACCES && ignoreEacces)
            return 1;

        virReportSystemError(errno,
                             _("Path '%1$s' is not accessible"),
                             path);
        return -1;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupDenyDevice(virCgroup *group, char type, int major, int minor,
                    int perms)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupDenyDevicePath(virCgroup *group,
                        const char *path,
                        int perms,
                        bool ignoreEacces)
{
    struct stat sb;
    virCgroup *parent = virCgroupGetNested(group);

    if (stat(path, &sb) < 0) {
        if (errno == EACCES && ignoreEacces)
            return 1;

        virReportSystemError(errno,
                             _("Path '%1$s' is not accessible"),
                             path);
        return -1;
    }

    if (!S_ISCHR(sb.st_mode) && !S_ISBLK(sb.st_mode))
        return 1;

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_DEVICES,
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
virCgroupGetPercpuVcpuSum(virCgroup *group,
                          virBitmap *guestvcpus,
                          unsigned long long *sum_cpu_time,
                          size_t nsum,
                          virBitmap *cpumap)
{
    ssize_t i = -1;

    while ((i = virBitmapNextSetBit(guestvcpus, i)) >= 0) {
        g_autofree char *buf = NULL;
        g_autoptr(virCgroup) group_vcpu = NULL;
        char *pos;
        unsigned long long tmp;
        ssize_t j;

        if (virCgroupNewThread(group, VIR_CGROUP_THREAD_VCPU, i,
                               false, &group_vcpu) < 0)
            return -1;

        if (virCgroupGetCpuacctPercpuUsage(group_vcpu, &buf) < 0)
            return -1;

        pos = buf;
        for (j = virBitmapNextSetBit(cpumap, -1);
             j >= 0 && j < nsum;
             j = virBitmapNextSetBit(cpumap, j)) {
            if (virStrToLong_ull(pos, &pos, 10, &tmp) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cpuacct parse error"));
                return -1;
            }
            sum_cpu_time[j] += tmp;
        }
    }

    return 0;
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
virCgroupGetPercpuStats(virCgroup *group,
                        virTypedParameterPtr params,
                        unsigned int nparams,
                        int start_cpu,
                        unsigned int ncpus,
                        virBitmap *guestvcpus)
{
    size_t i;
    int need_cpus, total_cpus;
    char *pos;
    g_autofree char *buf = NULL;
    g_autofree unsigned long long *sum_cpu_time = NULL;
    virTypedParameterPtr ent;
    int param_idx;
    unsigned long long cpu_time;
    g_autoptr(virBitmap) cpumap = NULL;

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
    if (ncpus == 0)
        return total_cpus;

    if (start_cpu >= total_cpus) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("start_cpu %1$d larger than maximum of %2$d"),
                       start_cpu, total_cpus - 1);
        return -1;
    }

    /* we get percpu cputime accounting info. */
    if (virCgroupGetCpuacctPercpuUsage(group, &buf))
        return -1;
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
            return -1;
        }
        if (i < start_cpu)
            continue;
        ent = &params[(i - start_cpu) * nparams + param_idx];
        if (virTypedParameterAssign(ent, VIR_DOMAIN_CPU_STATS_CPUTIME,
                                    VIR_TYPED_PARAM_ULLONG, cpu_time) < 0)
            return -1;
    }

    /* return percpu vcputime in index 1 */
    param_idx = 1;

    if (guestvcpus && param_idx < nparams) {
        sum_cpu_time = g_new0(unsigned long long, need_cpus);
        if (virCgroupGetPercpuVcpuSum(group, guestvcpus, sum_cpu_time,
                                      need_cpus, cpumap) < 0)
            return -1;

        for (i = start_cpu; i < need_cpus; i++) {
            int idx = (i - start_cpu) * nparams + param_idx;
            if (virTypedParameterAssign(&params[idx],
                                        VIR_DOMAIN_CPU_STATS_VCPUTIME,
                                        VIR_TYPED_PARAM_ULLONG,
                                        sum_cpu_time[i]) < 0)
                return -1;
        }

        param_idx++;
    }

    return param_idx;
}


int
virCgroupGetDomainTotalCpuStats(virCgroup *group,
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
virCgroupSetCpuShares(virCgroup *group, unsigned long long shares)
{
    VIR_CGROUP_BACKEND_CALL(group, VIR_CGROUP_CONTROLLER_CPU,
                            setCpuShares, -1, shares);
}


int
virCgroupGetCpuShares(virCgroup *group, unsigned long long *shares)
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
virCgroupSetCpuCfsPeriod(virCgroup *group, unsigned long long cfs_period)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPU,
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
virCgroupGetCpuCfsPeriod(virCgroup *group, unsigned long long *cfs_period)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPU,
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
virCgroupSetCpuCfsQuota(virCgroup *group, long long cfs_quota)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPU,
                            setCpuCfsQuota, -1, cfs_quota);
}


int
virCgroupGetCpuacctPercpuUsage(virCgroup *group, char **usage)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctPercpuUsage, -1, usage);
}


int
virCgroupRemoveRecursively(char *grppath)
{
    g_autoptr(DIR) grpdir = NULL;
    struct dirent *ent;
    int rc = 0;
    int direrr;

    if (virDirOpenQuiet(&grpdir, grppath) < 0) {
        if (errno == ENOENT)
            return 0;
        rc = -errno;
        VIR_ERROR(_("Unable to open %1$s (%2$d)"), grppath, errno);
        return rc;
    }

    /* This is best-effort cleanup: we want to log failures with just
     * VIR_ERROR instead of normal virReportError */
    while ((direrr = virDirRead(grpdir, &ent, NULL)) > 0) {
        g_autofree char *path = NULL;

        if (ent->d_type != DT_DIR) continue;

        path = g_strdup_printf("%s/%s", grppath, ent->d_name);

        rc = virCgroupRemoveRecursively(path);
        if (rc != 0)
            break;
    }
    if (direrr < 0) {
        rc = -errno;
        VIR_ERROR(_("Failed to readdir for %1$s (%2$d)"), grppath, errno);
    }

    VIR_DEBUG("Removing cgroup %s", grppath);
    if (rmdir(grppath) != 0 && errno != ENOENT) {
        rc = -errno;
        VIR_ERROR(_("Unable to remove %1$s (%2$d)"), grppath, errno);
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
virCgroupRemove(virCgroup *group)
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
virCgroupKillInternal(virCgroup *group,
                      int signum,
                      GHashTable *pids,
                      int controller,
                      const char *taskFile)
{
    int ret = -1;
    bool killedAny = false;
    g_autofree char *keypath = NULL;
    bool done = false;
    FILE *fp = NULL;
    VIR_DEBUG("group=%p signum=%d pids=%p",
              group, signum, pids);

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
                                 _("Failed to read %1$s"),
                                 keypath);
            goto cleanup;
        } else {
            while (!feof(fp)) {
                g_autofree long long *pid_value = g_new0(long long, 1);

                if (fscanf(fp, "%lld", pid_value) != 1) {
                    if (feof(fp))
                        break;
                    virReportSystemError(errno,
                                         _("Failed to read %1$s"),
                                         keypath);
                    goto cleanup;
                }

                if (g_hash_table_lookup(pids, pid_value))
                    continue;

                VIR_DEBUG("pid=%lld", *pid_value);
                /* Cgroups is a Linux concept, so this cast is safe.  */
                if (kill((pid_t)*pid_value, signum) < 0) {
                    if (errno != ESRCH) {
                        virReportSystemError(errno,
                                             _("Failed to kill process %1$lld"),
                                             *pid_value);
                        goto cleanup;
                    }
                    /* Leave RC == 0 since we didn't kill one */
                } else {
                    killedAny = true;
                    done = false;
                }

                g_hash_table_add(pids, g_steal_pointer(&pid_value));
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


int
virCgroupKillRecursiveInternal(virCgroup *group,
                               int signum,
                               GHashTable *pids,
                               const char *taskFile,
                               bool dormdir)
{
    int rc;
    int controller;
    bool killedAny = false;
    g_autofree char *keypath = NULL;
    g_autoptr(DIR) dp = NULL;
    struct dirent *ent;
    int direrr;
    VIR_DEBUG("group=%p signum=%d pids=%p taskFile=%s dormdir=%d",
              group, signum, pids, taskFile, dormdir);

    if ((controller = virCgroupGetAnyController(group)) < 0)
        return -1;

    if (virCgroupPathOfController(group, controller, "", &keypath) < 0)
        return -1;

    if ((rc = virCgroupKillInternal(group, signum, pids,
                                    controller, taskFile)) < 0) {
        return -1;
    }
    if (rc == 1)
        killedAny = true;

    VIR_DEBUG("Iterate over children of %s (killedAny=%d)", keypath, killedAny);
    if ((rc = virDirOpenIfExists(&dp, keypath)) < 0)
        return -1;

    if (rc == 0) {
        VIR_DEBUG("Path %s does not exist, assuming done", keypath);
        return 0;
    }

    while ((direrr = virDirRead(dp, &ent, keypath)) > 0) {
        g_autoptr(virCgroup) subgroup = NULL;

        if (ent->d_type != DT_DIR)
            continue;

        VIR_DEBUG("Process subdir %s", ent->d_name);

        if (virCgroupNewFromParent(group, ent->d_name, -1, &subgroup) < 0)
            return -1;

        if ((rc = virCgroupKillRecursiveInternal(subgroup, signum, pids,
                                                 taskFile, true)) < 0)
            return -1;
        if (rc == 1)
            killedAny = true;

        if (dormdir)
            virCgroupRemove(subgroup);
    }
    if (direrr < 0)
        return -1;

    return killedAny ? 1 : 0;
}


int
virCgroupKillRecursive(virCgroup *group, int signum)
{
    int rc;
    bool success = false;
    size_t i;
    bool backendAvailable = false;
    virCgroupBackend **backends = virCgroupBackendGetAll();
    g_autoptr(GHashTable) pids = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);

    VIR_DEBUG("group=%p signum=%d", group, signum);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (backends && backends[i] && backends[i]->available()) {
            backendAvailable = true;
            if ((rc = backends[i]->killRecursive(group, signum, pids)) < 0)
                return -1;

            if (rc > 0)
                success = true;
        }
    }

    if (success)
        return 1;

    if (!backends || !backendAvailable) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("no cgroup backend available"));
        return -1;
    }

    return 0;
}


int
virCgroupKillPainfully(virCgroup *group)
{
    size_t i;
    int ret;
    VIR_DEBUG("cgroup=%p", group);
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

        g_usleep(200 * 1000);
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
virCgroupGetCpuCfsQuota(virCgroup *group, long long *cfs_quota)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPU,
                            getCpuCfsQuota, -1, cfs_quota);
}


int
virCgroupGetCpuacctUsage(virCgroup *group, unsigned long long *usage)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctUsage, -1, usage);
}


int
virCgroupGetCpuacctStat(virCgroup *group, unsigned long long *user,
                        unsigned long long *sys)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPUACCT,
                            getCpuacctStat, -1, user, sys);
}


int
virCgroupSetFreezerState(virCgroup *group, const char *state)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_FREEZER,
                            setFreezerState, -1, state);
}


int
virCgroupGetFreezerState(virCgroup *group, char **state)
{
    virCgroup *parent = virCgroupGetNested(group);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_FREEZER,
                            getFreezerState, -1, state);
}


int
virCgroupBindMount(virCgroup *group, const char *oldroot,
                   const char *mountopts)
{
    size_t i;
    virCgroup *parent = virCgroupGetNested(group);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (parent->backends[i] &&
            parent->backends[i]->bindMount(parent, oldroot, mountopts) < 0) {
            return -1;
        }
    }

    return 0;
}


int virCgroupSetOwner(virCgroup *cgroup,
                      uid_t uid,
                      gid_t gid,
                      int controllers)
{
    size_t i;
    virCgroup *parent = virCgroupGetNested(cgroup);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (parent->backends[i] &&
            parent->backends[i]->setOwner(parent, uid, gid, controllers) < 0) {
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
virCgroupSupportsCpuBW(virCgroup *cgroup)
{
    virCgroup *parent = virCgroupGetNested(cgroup);

    VIR_CGROUP_BACKEND_CALL(parent, VIR_CGROUP_CONTROLLER_CPU,
                            supportsCpuBW, false);
}

int
virCgroupHasEmptyTasks(virCgroup *cgroup, int controller)
{
    size_t i;
    virCgroup *parent = virCgroupGetNested(cgroup);

    for (i = 0; i < VIR_CGROUP_BACKEND_TYPE_LAST; i++) {
        if (parent->backends[i]) {
            int rc = parent->backends[i]->hasEmptyTasks(parent, controller);
            if (rc <= 0)
                return rc;
        }
    }

    return 1;
}

bool
virCgroupControllerAvailable(int controller)
{
    g_autoptr(virCgroup) cgroup = NULL;

    /* Don't use virCgroupNewSelf() - we might be running in a slice that
     * doesn't have @controller but the domain (for which we will later use
     * virCgroupHasController()) might have it. */
    if (virCgroupNew("/", -1, &cgroup) < 0)
        return false;

    return virCgroupHasController(cgroup, controller);
}


/**
 * virCgroupGetInode:
 *
 * @cgroup: the cgroup to get inode for
 *
 * Get the @cgroup inode and return its value to the caller.
 *
 * Returns inode on success, -1 on error with error message reported.
 */
int
virCgroupGetInode(virCgroup *cgroup)
{
    struct stat st;
    int controller = virCgroupGetAnyController(cgroup);
    g_autofree char *path = NULL;

    if (controller < 0)
        return -1;

    if (virCgroupPathOfController(cgroup, controller, "", &path) < 0)
        return -1;

    if (stat(path, &st) < 0) {
        virReportSystemError(errno, _("failed to get stat for '%1$s'"), path);
        return -1;
    }

    return st.st_ino;
}

#else /* !__linux__ */

bool
virCgroupAvailable(void)
{
    return false;
}


int
virCgroupNewPartition(const char *path G_GNUC_UNUSED,
                      bool create G_GNUC_UNUSED,
                      int controllers G_GNUC_UNUSED,
                      virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNew(const char *path G_GNUC_UNUSED,
             int controllers G_GNUC_UNUSED,
             virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewSelf(virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDomainPartition(virCgroup *partition G_GNUC_UNUSED,
                            const char *driver G_GNUC_UNUSED,
                            const char *name G_GNUC_UNUSED,
                            virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewThread(virCgroup *domain G_GNUC_UNUSED,
                   virCgroupThreadName nameval G_GNUC_UNUSED,
                   int id G_GNUC_UNUSED,
                   bool create G_GNUC_UNUSED,
                   virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDetect(pid_t pid G_GNUC_UNUSED,
                   int controllers G_GNUC_UNUSED,
                   virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewDetectMachine(const char *name G_GNUC_UNUSED,
                          const char *drivername G_GNUC_UNUSED,
                          pid_t pid G_GNUC_UNUSED,
                          int controllers G_GNUC_UNUSED,
                          char *machinename G_GNUC_UNUSED,
                          virCgroup **group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int virCgroupTerminateMachine(const char *name G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupNewMachine(const char *name G_GNUC_UNUSED,
                    const char *drivername G_GNUC_UNUSED,
                    const unsigned char *uuid G_GNUC_UNUSED,
                    const char *rootdir G_GNUC_UNUSED,
                    pid_t pidleader G_GNUC_UNUSED,
                    bool isContainer G_GNUC_UNUSED,
                    size_t nnicindexes G_GNUC_UNUSED,
                    int *nicindexes G_GNUC_UNUSED,
                    const char *partition G_GNUC_UNUSED,
                    int controllers G_GNUC_UNUSED,
                    unsigned int maxthreads G_GNUC_UNUSED,
                    virCgroup **group G_GNUC_UNUSED)
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
virCgroupHasController(virCgroup *cgroup G_GNUC_UNUSED,
                       int controller G_GNUC_UNUSED)
{
    return false;
}


int
virCgroupPathOfController(virCgroup *group G_GNUC_UNUSED,
                          unsigned int controller G_GNUC_UNUSED,
                          const char *key G_GNUC_UNUSED,
                          char **path G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddProcess(virCgroup *group G_GNUC_UNUSED,
                    pid_t pid G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddMachineProcess(virCgroup *group G_GNUC_UNUSED,
                           pid_t pid G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAddThread(virCgroup *group G_GNUC_UNUSED,
                   pid_t pid G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioIoServiced(virCgroup *group G_GNUC_UNUSED,
                            long long *bytes_read G_GNUC_UNUSED,
                            long long *bytes_write G_GNUC_UNUSED,
                            long long *requests_read G_GNUC_UNUSED,
                            long long *requests_write G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioIoDeviceServiced(virCgroup *group G_GNUC_UNUSED,
                                  const char *path G_GNUC_UNUSED,
                                  long long *bytes_read G_GNUC_UNUSED,
                                  long long *bytes_write G_GNUC_UNUSED,
                                  long long *requests_read G_GNUC_UNUSED,
                                  long long *requests_write G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetBlkioWeight(virCgroup *group G_GNUC_UNUSED,
                        unsigned int weight G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetBlkioWeight(virCgroup *group G_GNUC_UNUSED,
                        unsigned int *weight G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


static int
virCgroupSetBlkioDeviceWeight(virCgroup *group G_GNUC_UNUSED,
                              const char *path G_GNUC_UNUSED,
                              unsigned int weight G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupSetBlkioDeviceReadIops(virCgroup *group G_GNUC_UNUSED,
                                const char *path G_GNUC_UNUSED,
                                unsigned int riops G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupSetBlkioDeviceWriteIops(virCgroup *group G_GNUC_UNUSED,
                                 const char *path G_GNUC_UNUSED,
                                 unsigned int wiops G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupSetBlkioDeviceReadBps(virCgroup *group G_GNUC_UNUSED,
                               const char *path G_GNUC_UNUSED,
                               unsigned long long rbps G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupSetBlkioDeviceWriteBps(virCgroup *group G_GNUC_UNUSED,
                                const char *path G_GNUC_UNUSED,
                                unsigned long long wbps G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupGetBlkioDeviceWeight(virCgroup *group G_GNUC_UNUSED,
                              const char *path G_GNUC_UNUSED,
                              unsigned int *weight G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupGetBlkioDeviceReadIops(virCgroup *group G_GNUC_UNUSED,
                                const char *path G_GNUC_UNUSED,
                                unsigned int *riops G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupGetBlkioDeviceWriteIops(virCgroup *group G_GNUC_UNUSED,
                                 const char *path G_GNUC_UNUSED,
                                 unsigned int *wiops G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupGetBlkioDeviceReadBps(virCgroup *group G_GNUC_UNUSED,
                               const char *path G_GNUC_UNUSED,
                               unsigned long long *rbps G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

static int
virCgroupGetBlkioDeviceWriteBps(virCgroup *group G_GNUC_UNUSED,
                                const char *path G_GNUC_UNUSED,
                                unsigned long long *wbps G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupSetMemory(virCgroup *group G_GNUC_UNUSED,
                   unsigned long long kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryStat(virCgroup *group G_GNUC_UNUSED,
                       unsigned long long *cache G_GNUC_UNUSED,
                       unsigned long long *activeAnon G_GNUC_UNUSED,
                       unsigned long long *inactiveAnon G_GNUC_UNUSED,
                       unsigned long long *activeFile G_GNUC_UNUSED,
                       unsigned long long *inactiveFile G_GNUC_UNUSED,
                       unsigned long long *unevictable G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryUsage(virCgroup *group G_GNUC_UNUSED,
                        unsigned long *kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemoryHardLimit(virCgroup *group G_GNUC_UNUSED,
                            unsigned long long kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemoryHardLimit(virCgroup *group G_GNUC_UNUSED,
                            unsigned long long *kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemorySoftLimit(virCgroup *group G_GNUC_UNUSED,
                            unsigned long long kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemorySoftLimit(virCgroup *group G_GNUC_UNUSED,
                            unsigned long long *kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetMemSwapHardLimit(virCgroup *group G_GNUC_UNUSED,
                             unsigned long long kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemSwapHardLimit(virCgroup *group G_GNUC_UNUSED,
                             unsigned long long *kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetMemSwapUsage(virCgroup *group G_GNUC_UNUSED,
                         unsigned long long *kb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetMems(virCgroup *group G_GNUC_UNUSED,
                       const char *mems G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetMems(virCgroup *group G_GNUC_UNUSED,
                       char **mems G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetMemoryMigrate(virCgroup *group G_GNUC_UNUSED,
                                bool migrate G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetMemoryMigrate(virCgroup *group G_GNUC_UNUSED,
                                bool *migrate G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpusetCpus(virCgroup *group G_GNUC_UNUSED,
                       const char *cpus G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpusetCpus(virCgroup *group G_GNUC_UNUSED,
                       char **cpus G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupAllowAllDevices(virCgroup *group G_GNUC_UNUSED,
                         int perms G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupDenyAllDevices(virCgroup *group G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAllowDevice(virCgroup *group G_GNUC_UNUSED,
                     char type G_GNUC_UNUSED,
                     int major G_GNUC_UNUSED,
                     int minor G_GNUC_UNUSED,
                     int perms G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupAllowDevicePath(virCgroup *group G_GNUC_UNUSED,
                         const char *path G_GNUC_UNUSED,
                         int perms G_GNUC_UNUSED,
                         bool ignoreEaccess G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupDenyDevice(virCgroup *group G_GNUC_UNUSED,
                    char type G_GNUC_UNUSED,
                    int major G_GNUC_UNUSED,
                    int minor G_GNUC_UNUSED,
                    int perms G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupDenyDevicePath(virCgroup *group G_GNUC_UNUSED,
                        const char *path G_GNUC_UNUSED,
                        int perms G_GNUC_UNUSED,
                        bool ignoreEacces G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuShares(virCgroup *group G_GNUC_UNUSED,
                      unsigned long long shares G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuShares(virCgroup *group G_GNUC_UNUSED,
                      unsigned long long *shares G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuCfsPeriod(virCgroup *group G_GNUC_UNUSED,
                         unsigned long long cfs_period G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuCfsPeriod(virCgroup *group G_GNUC_UNUSED,
                         unsigned long long *cfs_period G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetCpuCfsQuota(virCgroup *group G_GNUC_UNUSED,
                        long long cfs_quota G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupRemove(virCgroup *group G_GNUC_UNUSED)
{
    virReportSystemError(ENXIO, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupKillRecursive(virCgroup *group G_GNUC_UNUSED,
                       int signum G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupKillPainfully(virCgroup *group G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuCfsQuota(virCgroup *group G_GNUC_UNUSED,
                        long long *cfs_quota G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctUsage(virCgroup *group G_GNUC_UNUSED,
                         unsigned long long *usage G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctPercpuUsage(virCgroup *group G_GNUC_UNUSED,
                               char **usage G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetCpuacctStat(virCgroup *group G_GNUC_UNUSED,
                        unsigned long long *user G_GNUC_UNUSED,
                        unsigned long long *sys G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetDomainTotalCpuStats(virCgroup *group G_GNUC_UNUSED,
                                virTypedParameterPtr params G_GNUC_UNUSED,
                                int nparams G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetFreezerState(virCgroup *group G_GNUC_UNUSED,
                         const char *state G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupGetFreezerState(virCgroup *group G_GNUC_UNUSED,
                         char **state G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupBindMount(virCgroup *group G_GNUC_UNUSED,
                   const char *oldroot G_GNUC_UNUSED,
                   const char *mountopts G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


bool
virCgroupSupportsCpuBW(virCgroup *cgroup G_GNUC_UNUSED)
{
    VIR_DEBUG("Control groups not supported on this platform");
    return false;
}


int
virCgroupGetPercpuStats(virCgroup *group G_GNUC_UNUSED,
                        virTypedParameterPtr params G_GNUC_UNUSED,
                        unsigned int nparams G_GNUC_UNUSED,
                        int start_cpu G_GNUC_UNUSED,
                        unsigned int ncpus G_GNUC_UNUSED,
                        virBitmap *guestvcpus G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}


int
virCgroupSetOwner(virCgroup *cgroup G_GNUC_UNUSED,
                  uid_t uid G_GNUC_UNUSED,
                  gid_t gid G_GNUC_UNUSED,
                  int controllers G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

int
virCgroupHasEmptyTasks(virCgroup *cgroup G_GNUC_UNUSED,
                       int controller G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}

bool
virCgroupControllerAvailable(int controller G_GNUC_UNUSED)
{
    return false;
}

int
virCgroupGetInode(virCgroup *cgroup G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("Control groups not supported on this platform"));
    return -1;
}
#endif /* !__linux__ */


/**
 * virCgroupFree:
 *
 * @group: The group structure to free
 */
void
virCgroupFree(virCgroup *group)
{
    size_t i;

    if (group == NULL)
        return;

    for (i = 0; i < VIR_CGROUP_CONTROLLER_LAST; i++) {
        g_free(group->legacy[i].mountPoint);
        g_free(group->legacy[i].linkPoint);
        g_free(group->legacy[i].placement);
    }

    g_free(group->unified.mountPoint);
    g_free(group->unified.placement);
    g_free(group->unitName);

    virCgroupFree(group->nested);

    g_free(group);
}


int
virCgroupDelThread(virCgroup *cgroup,
                   virCgroupThreadName nameval,
                   int idx)
{
    g_autoptr(virCgroup) new_cgroup = NULL;
    virCgroup *parent = NULL;

    if (cgroup) {
        parent = virCgroupGetNested(cgroup);

        if (virCgroupNewThread(parent, nameval, idx, false, &new_cgroup) < 0)
            return -1;

        /* Remove the offlined cgroup */
        virCgroupRemove(new_cgroup);
    }

    return 0;
}


/**
 * Calls virCgroupSetBlkioDeviceWeight() to set up blkio device weight,
 * then retrieves the actual value set by the kernel with
 * virCgroupGetBlkioDeviceWeight() in the same @weight pointer.
 */
int
virCgroupSetupBlkioDeviceWeight(virCgroup *cgroup, const char *path,
                                unsigned int *weight)
{
    if (virCgroupSetBlkioDeviceWeight(cgroup, path, *weight) < 0 ||
        virCgroupGetBlkioDeviceWeight(cgroup, path, weight) < 0)
        return -1;

    return 0;
}


/**
 * Calls virCgroupSetBlkioDeviceReadIops() to set up blkio device riops,
 * then retrieves the actual value set by the kernel with
 * virCgroupGetBlkioDeviceReadIops() in the same @riops pointer.
 */
int
virCgroupSetupBlkioDeviceReadIops(virCgroup *cgroup, const char *path,
                                  unsigned int *riops)
{
    if (virCgroupSetBlkioDeviceReadIops(cgroup, path, *riops) < 0 ||
        virCgroupGetBlkioDeviceReadIops(cgroup, path, riops) < 0)
        return -1;

    return 0;
}


/**
 * Calls virCgroupSetBlkioDeviceWriteIops() to set up blkio device wiops,
 * then retrieves the actual value set by the kernel with
 * virCgroupGetBlkioDeviceWriteIops() in the same @wiops pointer.
 */
int
virCgroupSetupBlkioDeviceWriteIops(virCgroup *cgroup, const char *path,
                                   unsigned int *wiops)
{
    if (virCgroupSetBlkioDeviceWriteIops(cgroup, path, *wiops) < 0 ||
        virCgroupGetBlkioDeviceWriteIops(cgroup, path, wiops) < 0)
        return -1;

    return 0;
}


/**
 * Calls virCgroupSetBlkioDeviceReadBps() to set up blkio device rbps,
 * then retrieves the actual value set by the kernel with
 * virCgroupGetBlkioDeviceReadBps() in the same @rbps pointer.
 */
int
virCgroupSetupBlkioDeviceReadBps(virCgroup *cgroup, const char *path,
                                 unsigned long long *rbps)
{
    if (virCgroupSetBlkioDeviceReadBps(cgroup, path, *rbps) < 0 ||
        virCgroupGetBlkioDeviceReadBps(cgroup, path, rbps) < 0)
        return -1;

    return 0;
}


/**
 * Calls virCgroupSetBlkioDeviceWriteBps() to set up blkio device wbps,
 * then retrieves the actual value set by the kernel with
 * virCgroupGetBlkioDeviceWriteBps() in the same @wbps pointer.
 */
int
virCgroupSetupBlkioDeviceWriteBps(virCgroup *cgroup, const char *path,
                                  unsigned long long *wbps)
{
    if (virCgroupSetBlkioDeviceWriteBps(cgroup, path, *wbps) < 0 ||
        virCgroupGetBlkioDeviceWriteBps(cgroup, path, wbps) < 0)
        return -1;

    return 0;
}


int
virCgroupSetupCpusetCpus(virCgroup *cgroup, virBitmap *cpumask)
{
    g_autofree char *new_cpus = NULL;

    if (!(new_cpus = virBitmapFormat(cpumask)))
        return -1;

    if (virCgroupSetCpusetCpus(cgroup, new_cpus) < 0)
        return -1;

    return 0;
}


int
virCgroupSetupCpuPeriodQuota(virCgroup *cgroup,
                             unsigned long long period,
                             long long quota)
{
    unsigned long long old_period;

    if (period == 0 && quota == 0)
        return 0;

    if (period) {
        /* get old period, and we can rollback if set quota failed */
        if (virCgroupGetCpuCfsPeriod(cgroup, &old_period) < 0)
            return -1;

        if (virCgroupSetCpuCfsPeriod(cgroup, period) < 0)
            return -1;
    }

    if (quota &&
        virCgroupSetCpuCfsQuota(cgroup, quota) < 0)
        goto error;

    return 0;

 error:
    if (period) {
        virErrorPtr saved;

        virErrorPreserveLast(&saved);
        ignore_value(virCgroupSetCpuCfsPeriod(cgroup, old_period));
        virErrorRestore(&saved);
    }

    return -1;
}


int
virCgroupGetCpuPeriodQuota(virCgroup *cgroup, unsigned long long *period,
                           long long *quota)
{
    if (virCgroupGetCpuCfsPeriod(cgroup, period) < 0)
        return -1;

    if (virCgroupGetCpuCfsQuota(cgroup, quota) < 0)
        return -1;

    return 0;
}
