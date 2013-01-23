/*
 * qemu_conf.c: QEMU configuration management
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "virerror.h"
#include "qemu_conf.h"
#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "qemu_bridge_filter.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virconf.h"
#include "virutil.h"
#include "viralloc.h"
#include "datatypes.h"
#include "virxml.h"
#include "nodeinfo.h"
#include "virlog.h"
#include "cpu/cpu.h"
#include "domain_nwfilter.h"
#include "virfile.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

struct _qemuDriverCloseDef {
    virConnectPtr conn;
    qemuDriverCloseCallback cb;
};

void qemuDriverLock(virQEMUDriverPtr driver)
{
    virMutexLock(&driver->lock);
}
void qemuDriverUnlock(virQEMUDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}


int qemuLoadDriverConfig(virQEMUDriverPtr driver,
                         const char *filename) {
    virConfPtr conf = NULL;
    virConfValuePtr p;
    char *user = NULL;
    char *group = NULL;
    int ret = -1;
    int i;

    /* Setup critical defaults */
    driver->securityDefaultConfined = true;
    driver->securityRequireConfined = false;
    driver->dynamicOwnership = 1;
    driver->clearEmulatorCapabilities = 1;

    if (!(driver->vncListen = strdup("127.0.0.1")))
        goto no_memory;

    driver->remotePortMin = QEMU_REMOTE_PORT_MIN;
    driver->remotePortMax = QEMU_REMOTE_PORT_MAX;

    if (!(driver->vncTLSx509certdir = strdup(SYSCONFDIR "/pki/libvirt-vnc")))
        goto no_memory;

    if (!(driver->spiceListen = strdup("127.0.0.1")))
        goto no_memory;

    if (!(driver->spiceTLSx509certdir
          = strdup(SYSCONFDIR "/pki/libvirt-spice")))
        goto no_memory;

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
    /* For privileged driver, try and find hugepage mount automatically.
     * Non-privileged driver requires admin to create a dir for the
     * user, chown it, and then let user configure it manually */
    if (driver->privileged &&
        !(driver->hugetlbfs_mount = virFileFindMountPoint("hugetlbfs"))) {
        if (errno != ENOENT) {
            virReportSystemError(errno, "%s",
                                 _("unable to find hugetlbfs mountpoint"));
            goto cleanup;
        }
    }
#endif

    if (!(driver->lockManager = virLockManagerPluginNew("nop",
                                                        "qemu",
                                                        driver->configBaseDir,
                                                        0)))
        goto cleanup;

    driver->keepAliveInterval = 5;
    driver->keepAliveCount = 5;
    driver->seccompSandbox = -1;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        ret = 0;
        goto cleanup;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        goto cleanup;

#define CHECK_TYPE(name,typ)                          \
    if (p && p->type != (typ)) {                      \
        virReportError(VIR_ERR_INTERNAL_ERROR,        \
                       "%s: %s: expected type " #typ, \
                       filename, (name));             \
        goto cleanup;                                 \
    }

#define GET_VALUE_LONG(NAME, VAR)     \
    p = virConfGetValue(conf, NAME);  \
    CHECK_TYPE(NAME, VIR_CONF_LONG);  \
    if (p)                            \
        VAR = p->l;

#define GET_VALUE_STR(NAME, VAR)           \
    p = virConfGetValue(conf, NAME);       \
    CHECK_TYPE(NAME, VIR_CONF_STRING);     \
    if (p && p->str) {                     \
        VIR_FREE(VAR);                     \
        if (!(VAR = strdup(p->str)))       \
            goto no_memory;                \
    }

    GET_VALUE_LONG("vnc_auto_unix_socket", driver->vncAutoUnixSocket);
    GET_VALUE_LONG("vnc_tls", driver->vncTLS);
    GET_VALUE_LONG("vnc_tls_x509_verify", driver->vncTLSx509verify);
    GET_VALUE_STR("vnc_tls_x509_cert_dir", driver->vncTLSx509certdir);
    GET_VALUE_STR("vnc_listen", driver->vncListen);
    GET_VALUE_STR("vnc_password", driver->vncPassword);
    GET_VALUE_LONG("vnc_sasl", driver->vncSASL);
    GET_VALUE_STR("vnc_sasl_dir", driver->vncSASLdir);
    GET_VALUE_LONG("vnc_allow_host_audio", driver->vncAllowHostAudio);

    p = virConfGetValue(conf, "security_driver");
    if (p && p->type == VIR_CONF_LIST) {
        size_t len;
        virConfValuePtr pp;

        /* Calc length and check items */
        for (len = 0, pp = p->list; pp; len++, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("security_driver must be a list of strings"));
                goto cleanup;
            }
        }

        if (VIR_ALLOC_N(driver->securityDriverNames, len + 1) < 0)
            goto no_memory;

        for (i = 0, pp = p->list; pp; i++, pp = pp->next) {
            if (!(driver->securityDriverNames[i] = strdup(pp->str)))
                goto no_memory;
        }
        driver->securityDriverNames[len] = NULL;
    } else {
        CHECK_TYPE("security_driver", VIR_CONF_STRING);
        if (p && p->str) {
            if (VIR_ALLOC_N(driver->securityDriverNames, 2) < 0 ||
                !(driver->securityDriverNames[0] = strdup(p->str)))
                goto no_memory;

            driver->securityDriverNames[1] = NULL;
        }
    }

    GET_VALUE_LONG("security_default_confined", driver->securityDefaultConfined);
    GET_VALUE_LONG("security_require_confined", driver->securityRequireConfined);

    GET_VALUE_LONG("spice_tls", driver->spiceTLS);
    GET_VALUE_STR("spice_tls_x509_cert_dir", driver->spiceTLSx509certdir);
    GET_VALUE_STR("spice_listen", driver->spiceListen);
    GET_VALUE_STR("spice_password", driver->spicePassword);


    GET_VALUE_LONG("remote_display_port_min", driver->remotePortMin);
    if (driver->remotePortMin < QEMU_REMOTE_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5900, e.g. localhost:1
         * for port 5901) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: remote_display_port_min: port must be greater "
                         "than or equal to %d"),
                        filename, QEMU_REMOTE_PORT_MIN);
        goto cleanup;
    }

    GET_VALUE_LONG("remote_display_port_max", driver->remotePortMax);
    if (driver->remotePortMax > QEMU_REMOTE_PORT_MAX ||
        driver->remotePortMax < driver->remotePortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_max: port must be between "
                          "the minimal port and %d"),
                       filename, QEMU_REMOTE_PORT_MAX);
        goto cleanup;
    }

    if (driver->remotePortMin > driver->remotePortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_min: min port must not be "
                          "greater than max port"), filename);
        goto cleanup;
    }

    p = virConfGetValue(conf, "user");
    CHECK_TYPE("user", VIR_CONF_STRING);
    if (!(user = strdup(p && p->str ? p->str : QEMU_USER)))
        goto no_memory;

    if (virGetUserID(user, &driver->user) < 0)
        goto cleanup;

    p = virConfGetValue(conf, "group");
    CHECK_TYPE("group", VIR_CONF_STRING);
    if (!(group = strdup(p && p->str ? p->str : QEMU_GROUP)))
        goto no_memory;

    if (virGetGroupID(group, &driver->group) < 0)
        goto cleanup;

    GET_VALUE_LONG("dynamic_ownership", driver->dynamicOwnership);

    p = virConfGetValue(conf, "cgroup_controllers");
    CHECK_TYPE("cgroup_controllers", VIR_CONF_LIST);
    if (p) {
        virConfValuePtr pp;
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            int ctl;
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("cgroup_controllers must be a "
                                 "list of strings"));
                goto cleanup;
            }

            if ((ctl = virCgroupControllerTypeFromString(pp->str)) < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown cgroup controller '%s'"), pp->str);
                goto cleanup;
            }
            driver->cgroupControllers |= (1 << ctl);
        }
    } else {
        driver->cgroupControllers =
            (1 << VIR_CGROUP_CONTROLLER_CPU) |
            (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
            (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
            (1 << VIR_CGROUP_CONTROLLER_BLKIO) |
            (1 << VIR_CGROUP_CONTROLLER_CPUSET) |
            (1 << VIR_CGROUP_CONTROLLER_CPUACCT);
    }
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (driver->cgroupControllers & (1 << i)) {
            VIR_INFO("Configured cgroup controller '%s'",
                     virCgroupControllerTypeToString(i));
        }
    }

    p = virConfGetValue(conf, "cgroup_device_acl");
    CHECK_TYPE("cgroup_device_acl", VIR_CONF_LIST);
    if (p) {
        int len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(driver->cgroupDeviceACL, 1+len) < 0)
            goto no_memory;

        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("cgroup_device_acl must be a "
                                 "list of strings"));
                goto cleanup;
            }
            if (!(driver->cgroupDeviceACL[i] = strdup(pp->str)))
                goto no_memory;
        }
        driver->cgroupDeviceACL[i] = NULL;
    }

    GET_VALUE_STR("save_image_format", driver->saveImageFormat);
    GET_VALUE_STR("dump_image_format", driver->dumpImageFormat);
    GET_VALUE_STR("auto_dump_path", driver->autoDumpPath);
    GET_VALUE_LONG("auto_dump_bypass_cache", driver->autoDumpBypassCache);
    GET_VALUE_LONG("auto_start_bypass_cache", driver->autoStartBypassCache);

    GET_VALUE_STR("hugetlbfs_mount", driver->hugetlbfs_mount);

    p = virConfGetValue(conf, "mac_filter");
    CHECK_TYPE("mac_filter", VIR_CONF_LONG);
    if (p && p->l) {
        driver->macFilter = p->l;
        if (!(driver->ebtables = ebtablesContextNew("qemu"))) {
            driver->macFilter = 0;
            virReportSystemError(errno,
                                 _("failed to enable mac filter in '%s'"),
                                 __FILE__);
            goto cleanup;
        }

        if ((errno = networkDisableAllFrames(driver))) {
            virReportSystemError(errno,
                         _("failed to add rule to drop all frames in '%s'"),
                                 __FILE__);
            goto cleanup;
        }
    }

    GET_VALUE_LONG("relaxed_acs_check", driver->relaxedACS);
    GET_VALUE_LONG("clear_emulator_capabilities", driver->clearEmulatorCapabilities);
    GET_VALUE_LONG("allow_disk_format_probing", driver->allowDiskFormatProbing);
    GET_VALUE_LONG("set_process_name", driver->setProcessName);
    GET_VALUE_LONG("max_processes", driver->maxProcesses);
    GET_VALUE_LONG("max_files", driver->maxFiles);

    p = virConfGetValue(conf, "lock_manager");
    CHECK_TYPE("lock_manager", VIR_CONF_STRING);
    if (p && p->str) {
        virLockManagerPluginUnref(driver->lockManager);
        if (!(driver->lockManager =
              virLockManagerPluginNew(p->str, "qemu", driver->configBaseDir, 0)))
            VIR_ERROR(_("Failed to load lock manager %s"), p->str);
    }

    GET_VALUE_LONG("max_queued", driver->max_queued);
    GET_VALUE_LONG("keepalive_interval", driver->keepAliveInterval);
    GET_VALUE_LONG("keepalive_count", driver->keepAliveCount);
    GET_VALUE_LONG("seccomp_sandbox", driver->seccompSandbox);

    ret = 0;

cleanup:
    VIR_FREE(user);
    VIR_FREE(group);
    virConfFree(conf);
    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}
#undef GET_VALUE_LONG
#undef GET_VALUE_STRING

static void
qemuDriverCloseCallbackFree(void *payload,
                            const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}

int
qemuDriverCloseCallbackInit(virQEMUDriverPtr driver)
{
    driver->closeCallbacks = virHashCreate(5, qemuDriverCloseCallbackFree);
    if (!driver->closeCallbacks)
        return -1;

    return 0;
}

void
qemuDriverCloseCallbackShutdown(virQEMUDriverPtr driver)
{
    virHashFree(driver->closeCallbacks);
}

int
qemuDriverCloseCallbackSet(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virConnectPtr conn,
                           qemuDriverCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p, cb=%p",
              vm->def->name, uuidstr, conn, cb);

    closeDef = virHashLookup(driver->closeCallbacks, uuidstr);
    if (closeDef) {
        if (closeDef->conn != conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Close callback for domain %s already registered"
                             " with another connection %p"),
                           vm->def->name, closeDef->conn);
            return -1;
        }
        if (closeDef->cb && closeDef->cb != cb) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Another close callback is already defined for"
                             " domain %s"), vm->def->name);
            return -1;
        }

        closeDef->cb = cb;
    } else {
        if (VIR_ALLOC(closeDef) < 0) {
            virReportOOMError();
            return -1;
        }

        closeDef->conn = conn;
        closeDef->cb = cb;
        if (virHashAddEntry(driver->closeCallbacks, uuidstr, closeDef) < 0) {
            VIR_FREE(closeDef);
            return -1;
        }
    }
    return 0;
}

int
qemuDriverCloseCallbackUnset(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             qemuDriverCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, cb=%p",
              vm->def->name, uuidstr, cb);

    closeDef = virHashLookup(driver->closeCallbacks, uuidstr);
    if (!closeDef)
        return -1;

    if (closeDef->cb && closeDef->cb != cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Trying to remove mismatching close callback for"
                         " domain %s"), vm->def->name);
        return -1;
    }

    return virHashRemoveEntry(driver->closeCallbacks, uuidstr);
}

qemuDriverCloseCallback
qemuDriverCloseCallbackGet(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    qemuDriverCloseCallback cb = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p",
              vm->def->name, uuidstr, conn);

    closeDef = virHashLookup(driver->closeCallbacks, uuidstr);
    if (closeDef && (!conn || closeDef->conn == conn))
        cb = closeDef->cb;

    VIR_DEBUG("cb=%p", cb);
    return cb;
}

struct qemuDriverCloseCallbackData {
    virQEMUDriverPtr driver;
    virConnectPtr conn;
};

static void
qemuDriverCloseCallbackRun(void *payload,
                           const void *name,
                           void *opaque)
{
    struct qemuDriverCloseCallbackData *data = opaque;
    qemuDriverCloseDefPtr closeDef = payload;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr dom;

    VIR_DEBUG("conn=%p, thisconn=%p, uuid=%s, cb=%p",
              closeDef->conn, data->conn, (const char *)name, closeDef->cb);

    if (data->conn != closeDef->conn || !closeDef->cb)
        return;

    if (virUUIDParse(name, uuid) < 0) {
        VIR_WARN("Failed to parse %s", (const char *)name);
        return;
    }
    /* We need to reformat uuidstr, because closeDef->cb
     * might cause the current hash entry to be removed,
     * which means 'name' will have been free()d
     */
    virUUIDFormat(uuid, uuidstr);

    if (!(dom = virDomainFindByUUID(&data->driver->domains, uuid))) {
        VIR_DEBUG("No domain object with UUID %s", uuidstr);
        return;
    }

    dom = closeDef->cb(data->driver, dom, data->conn);
    if (dom)
        virObjectUnlock(dom);

    virHashRemoveEntry(data->driver->closeCallbacks, uuidstr);
}

void
qemuDriverCloseCallbackRunAll(virQEMUDriverPtr driver,
                              virConnectPtr conn)
{
    struct qemuDriverCloseCallbackData data = {
        driver, conn
    };
    VIR_DEBUG("conn=%p", conn);

    virHashForEach(driver->closeCallbacks, qemuDriverCloseCallbackRun, &data);
}

/* Construct the hash key for sharedDisks as "major:minor" */
char *
qemuGetSharedDiskKey(const char *disk_path)
{
    int maj, min;
    char *key = NULL;
    int rc;

    if ((rc = virGetDeviceID(disk_path, &maj, &min)) < 0) {
        virReportSystemError(-rc,
                             _("Unable to get minor number of device '%s'"),
                             disk_path);
        return NULL;
    }

    if (virAsprintf(&key, "%d:%d", maj, min) < 0) {
        virReportOOMError();
        return NULL;
    }

    return key;
}

/* Increase ref count if the entry already exists, otherwise
 * add a new entry.
 */
int
qemuAddSharedDisk(virHashTablePtr sharedDisks,
                  const char *disk_path)
{
    size_t *ref = NULL;
    char *key = NULL;

    if (!(key = qemuGetSharedDiskKey(disk_path)))
        return -1;

    if ((ref = virHashLookup(sharedDisks, key))) {
        if (virHashUpdateEntry(sharedDisks, key, ++ref) < 0) {
             VIR_FREE(key);
             return -1;
        }
    } else {
        if (virHashAddEntry(sharedDisks, key, (void *)0x1)) {
            VIR_FREE(key);
            return -1;
        }
    }

    VIR_FREE(key);
    return 0;
}

/* Decrease the ref count if the entry already exists, otherwise
 * remove the entry.
 */
int
qemuRemoveSharedDisk(virHashTablePtr sharedDisks,
                     const char *disk_path)
{
    size_t *ref = NULL;
    char *key = NULL;

    if (!(key = qemuGetSharedDiskKey(disk_path)))
        return -1;

    if (!(ref = virHashLookup(sharedDisks, key))) {
        VIR_FREE(key);
        return -1;
    }

    if (ref != (void *)0x1) {
        if (virHashUpdateEntry(sharedDisks, key, --ref) < 0) {
             VIR_FREE(key);
             return -1;
        }
    } else {
        if (virHashRemoveEntry(sharedDisks, key) < 0) {
            VIR_FREE(key);
            return -1;
        }
    }

    VIR_FREE(key);
    return 0;
}
