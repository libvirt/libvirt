/*
 * qemu_conf.c: QEMU configuration management
 *
 * Copyright (C) 2006-2013 Red Hat, Inc.
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
#include "virstring.h"
#include "viratomic.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

typedef struct _qemuDriverCloseDef qemuDriverCloseDef;
typedef qemuDriverCloseDef *qemuDriverCloseDefPtr;
struct _qemuDriverCloseDef {
    virConnectPtr conn;
    virQEMUCloseCallback cb;
};

struct _virQEMUCloseCallbacks {
    virObjectLockable parent;

    /* UUID string to qemuDriverCloseDef mapping */
    virHashTablePtr list;
};


static virClassPtr virQEMUDriverConfigClass;
static virClassPtr virQEMUCloseCallbacksClass;
static void virQEMUDriverConfigDispose(void *obj);
static void virQEMUCloseCallbacksDispose(void *obj);

static int virQEMUConfigOnceInit(void)
{
    virQEMUDriverConfigClass = virClassNew(virClassForObject(),
                                           "virQEMUDriverConfig",
                                           sizeof(virQEMUDriverConfig),
                                           virQEMUDriverConfigDispose);

    virQEMUCloseCallbacksClass = virClassNew(virClassForObjectLockable(),
                                             "virQEMUCloseCallbacks",
                                             sizeof(virQEMUCloseCallbacks),
                                             virQEMUCloseCallbacksDispose);

    if (!virQEMUDriverConfigClass || !virQEMUCloseCallbacksClass)
        return -1;
    else
        return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUConfig)


static void
qemuDriverLock(virQEMUDriverPtr driver)
{
    virMutexLock(&driver->lock);
}
static void
qemuDriverUnlock(virQEMUDriverPtr driver)
{
    virMutexUnlock(&driver->lock);
}


virQEMUDriverConfigPtr virQEMUDriverConfigNew(bool privileged)
{
    virQEMUDriverConfigPtr cfg;

    if (virQEMUConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virQEMUDriverConfigClass)))
        return NULL;

    cfg->privileged = privileged;
    cfg->uri = privileged ? "qemu:///system" : "qemu:///session";

    if (privileged) {
        if (virGetUserID(QEMU_USER, &cfg->user) < 0)
            goto error;
        if (virGetGroupID(QEMU_GROUP, &cfg->group) < 0)
            goto error;
    } else {
        cfg->user = (uid_t)-1;
        cfg->group = (gid_t)-1;
    }
    cfg->dynamicOwnership = privileged;

    cfg->cgroupControllers =
        (1 << VIR_CGROUP_CONTROLLER_CPU) |
        (1 << VIR_CGROUP_CONTROLLER_DEVICES) |
        (1 << VIR_CGROUP_CONTROLLER_MEMORY) |
        (1 << VIR_CGROUP_CONTROLLER_BLKIO) |
        (1 << VIR_CGROUP_CONTROLLER_CPUSET) |
        (1 << VIR_CGROUP_CONTROLLER_CPUACCT);


    if (privileged) {
        if (virAsprintf(&cfg->logDir,
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto no_memory;

        if ((cfg->configBaseDir = strdup(SYSCONFDIR "/libvirt")) == NULL)
            goto no_memory;

        if (virAsprintf(&cfg->stateDir,
                      "%s/run/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto no_memory;

        if (virAsprintf(&cfg->libDir,
                      "%s/lib/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto no_memory;

        if (virAsprintf(&cfg->cacheDir,
                      "%s/cache/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->saveDir,
                      "%s/lib/libvirt/qemu/save", LOCALSTATEDIR) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->snapshotDir,
                        "%s/lib/libvirt/qemu/snapshot", LOCALSTATEDIR) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->autoDumpPath,
                        "%s/lib/libvirt/qemu/dump", LOCALSTATEDIR) < 0)
            goto no_memory;
    } else {
        char *rundir;
        char *cachedir;

        cachedir = virGetUserCacheDirectory();
        if (!cachedir)
            goto error;

        if (virAsprintf(&cfg->logDir,
                        "%s/qemu/log", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto no_memory;
        }
        if (virAsprintf(&cfg->cacheDir, "%s/qemu/cache", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto no_memory;
        }
        VIR_FREE(cachedir);

        rundir = virGetUserRuntimeDirectory();
        if (!rundir)
            goto error;
        if (virAsprintf(&cfg->stateDir, "%s/qemu/run", rundir) < 0) {
            VIR_FREE(rundir);
            goto no_memory;
        }
        VIR_FREE(rundir);

        if (!(cfg->configBaseDir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(&cfg->libDir, "%s/qemu/lib", cfg->configBaseDir) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->saveDir, "%s/qemu/save", cfg->configBaseDir) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->snapshotDir, "%s/qemu/snapshot", cfg->configBaseDir) < 0)
            goto no_memory;
        if (virAsprintf(&cfg->autoDumpPath, "%s/qemu/dump", cfg->configBaseDir) < 0)
            goto no_memory;
    }

    if (virAsprintf(&cfg->configDir, "%s/qemu", cfg->configBaseDir) < 0)
        goto no_memory;
    if (virAsprintf(&cfg->autostartDir, "%s/qemu/autostart", cfg->configBaseDir) < 0)
        goto no_memory;


    if (!(cfg->vncListen = strdup("127.0.0.1")))
        goto no_memory;

    if (!(cfg->vncTLSx509certdir
          = strdup(SYSCONFDIR "/pki/libvirt-vnc")))
        goto no_memory;

    if (!(cfg->spiceListen = strdup("127.0.0.1")))
        goto no_memory;

    if (!(cfg->spiceTLSx509certdir
          = strdup(SYSCONFDIR "/pki/libvirt-spice")))
        goto no_memory;

    cfg->remotePortMin = QEMU_REMOTE_PORT_MIN;
    cfg->remotePortMax = QEMU_REMOTE_PORT_MAX;

#if defined HAVE_MNTENT_H && defined HAVE_GETMNTENT_R
    /* For privileged driver, try and find hugepage mount automatically.
     * Non-privileged driver requires admin to create a dir for the
     * user, chown it, and then let user configure it manually */
    if (privileged &&
        !(cfg->hugetlbfsMount = virFileFindMountPoint("hugetlbfs"))) {
        if (errno != ENOENT) {
            virReportSystemError(errno, "%s",
                                 _("unable to find hugetlbfs mountpoint"));
            goto error;
        }
    }
#endif

    cfg->clearEmulatorCapabilities = true;

    cfg->securityDefaultConfined = true;
    cfg->securityRequireConfined = false;

    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;
    cfg->seccompSandbox = -1;

    return cfg;

no_memory:
    virReportOOMError();
error:
    virObjectUnref(cfg);
    return NULL;
}


static void virQEMUDriverConfigDispose(void *obj)
{
    virQEMUDriverConfigPtr cfg = obj;


    virStringFreeList(cfg->cgroupDeviceACL);

    VIR_FREE(cfg->configBaseDir);
    VIR_FREE(cfg->configDir);
    VIR_FREE(cfg->autostartDir);
    VIR_FREE(cfg->logDir);
    VIR_FREE(cfg->stateDir);

    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->cacheDir);
    VIR_FREE(cfg->saveDir);
    VIR_FREE(cfg->snapshotDir);

    VIR_FREE(cfg->vncTLSx509certdir);
    VIR_FREE(cfg->vncListen);
    VIR_FREE(cfg->vncPassword);
    VIR_FREE(cfg->vncSASLdir);

    VIR_FREE(cfg->spiceTLSx509certdir);
    VIR_FREE(cfg->spiceListen);
    VIR_FREE(cfg->spicePassword);

    VIR_FREE(cfg->hugetlbfsMount);
    VIR_FREE(cfg->hugepagePath);

    VIR_FREE(cfg->saveImageFormat);
    VIR_FREE(cfg->dumpImageFormat);
    VIR_FREE(cfg->autoDumpPath);

    virStringFreeList(cfg->securityDriverNames);

    VIR_FREE(cfg->lockManagerName);
}


int virQEMUDriverConfigLoadFile(virQEMUDriverConfigPtr cfg,
                                const char *filename)
{
    virConfPtr conf = NULL;
    virConfValuePtr p;
    int ret = -1;
    int i;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        return 0;
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

#define GET_VALUE_BOOL(NAME, VAR)     \
    p = virConfGetValue(conf, NAME);  \
    CHECK_TYPE(NAME, VIR_CONF_LONG);  \
    if (p)                            \
        VAR = p->l != 0;

#define GET_VALUE_STR(NAME, VAR)           \
    p = virConfGetValue(conf, NAME);       \
    CHECK_TYPE(NAME, VIR_CONF_STRING);     \
    if (p && p->str) {                     \
        VIR_FREE(VAR);                     \
        if (!(VAR = strdup(p->str)))       \
            goto no_memory;                \
    }

    GET_VALUE_BOOL("vnc_auto_unix_socket", cfg->vncAutoUnixSocket);
    GET_VALUE_BOOL("vnc_tls", cfg->vncTLS);
    GET_VALUE_BOOL("vnc_tls_x509_verify", cfg->vncTLSx509verify);
    GET_VALUE_STR("vnc_tls_x509_cert_dir", cfg->vncTLSx509certdir);
    GET_VALUE_STR("vnc_listen", cfg->vncListen);
    GET_VALUE_STR("vnc_password", cfg->vncPassword);
    GET_VALUE_BOOL("vnc_sasl", cfg->vncSASL);
    GET_VALUE_STR("vnc_sasl_dir", cfg->vncSASLdir);
    GET_VALUE_BOOL("vnc_allow_host_audio", cfg->vncAllowHostAudio);

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

        if (VIR_ALLOC_N(cfg->securityDriverNames, len + 1) < 0)
            goto no_memory;

        for (i = 0, pp = p->list; pp; i++, pp = pp->next) {
            if (!(cfg->securityDriverNames[i] = strdup(pp->str)))
                goto no_memory;
        }
        cfg->securityDriverNames[len] = NULL;
    } else {
        CHECK_TYPE("security_driver", VIR_CONF_STRING);
        if (p && p->str) {
            if (VIR_ALLOC_N(cfg->securityDriverNames, 2) < 0 ||
                !(cfg->securityDriverNames[0] = strdup(p->str)))
                goto no_memory;

            cfg->securityDriverNames[1] = NULL;
        }
    }

    GET_VALUE_BOOL("security_default_confined", cfg->securityDefaultConfined);
    GET_VALUE_BOOL("security_require_confined", cfg->securityRequireConfined);

    GET_VALUE_BOOL("spice_tls", cfg->spiceTLS);
    GET_VALUE_STR("spice_tls_x509_cert_dir", cfg->spiceTLSx509certdir);
    GET_VALUE_STR("spice_listen", cfg->spiceListen);
    GET_VALUE_STR("spice_password", cfg->spicePassword);


    GET_VALUE_LONG("remote_display_port_min", cfg->remotePortMin);
    if (cfg->remotePortMin < QEMU_REMOTE_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5900, e.g. localhost:1
         * for port 5901) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: remote_display_port_min: port must be greater "
                         "than or equal to %d"),
                        filename, QEMU_REMOTE_PORT_MIN);
        goto cleanup;
    }

    GET_VALUE_LONG("remote_display_port_max", cfg->remotePortMax);
    if (cfg->remotePortMax > QEMU_REMOTE_PORT_MAX ||
        cfg->remotePortMax < cfg->remotePortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_max: port must be between "
                          "the minimal port and %d"),
                       filename, QEMU_REMOTE_PORT_MAX);
        goto cleanup;
    }

    if (cfg->remotePortMin > cfg->remotePortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_min: min port must not be "
                          "greater than max port"), filename);
        goto cleanup;
    }

    p = virConfGetValue(conf, "user");
    CHECK_TYPE("user", VIR_CONF_STRING);
    if (p && p->str &&
        virGetUserID(p->str, &cfg->user) < 0)
        goto cleanup;

    p = virConfGetValue(conf, "group");
    CHECK_TYPE("group", VIR_CONF_STRING);
    if (p && p->str &&
        virGetGroupID(p->str, &cfg->group) < 0)
        goto cleanup;

    GET_VALUE_BOOL("dynamic_ownership", cfg->dynamicOwnership);

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
            cfg->cgroupControllers |= (1 << ctl);
        }
    }
    for (i = 0 ; i < VIR_CGROUP_CONTROLLER_LAST ; i++) {
        if (cfg->cgroupControllers & (1 << i)) {
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
        if (VIR_ALLOC_N(cfg->cgroupDeviceACL, 1+len) < 0)
            goto no_memory;

        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("cgroup_device_acl must be a "
                                 "list of strings"));
                goto cleanup;
            }
            if (!(cfg->cgroupDeviceACL[i] = strdup(pp->str)))
                goto no_memory;
        }
        cfg->cgroupDeviceACL[i] = NULL;
    }

    GET_VALUE_STR("save_image_format", cfg->saveImageFormat);
    GET_VALUE_STR("dump_image_format", cfg->dumpImageFormat);
    GET_VALUE_STR("auto_dump_path", cfg->autoDumpPath);
    GET_VALUE_BOOL("auto_dump_bypass_cache", cfg->autoDumpBypassCache);
    GET_VALUE_BOOL("auto_start_bypass_cache", cfg->autoStartBypassCache);

    GET_VALUE_STR("hugetlbfs_mount", cfg->hugetlbfsMount);

    GET_VALUE_BOOL("mac_filter", cfg->macFilter);

    GET_VALUE_BOOL("relaxed_acs_check", cfg->relaxedACS);
    GET_VALUE_BOOL("clear_emulator_capabilities", cfg->clearEmulatorCapabilities);
    GET_VALUE_BOOL("allow_disk_format_probing", cfg->allowDiskFormatProbing);
    GET_VALUE_BOOL("set_process_name", cfg->setProcessName);
    GET_VALUE_LONG("max_processes", cfg->maxProcesses);
    GET_VALUE_LONG("max_files", cfg->maxFiles);

    GET_VALUE_STR("lock_manager", cfg->lockManagerName);

    GET_VALUE_LONG("max_queued", cfg->maxQueuedJobs);

    GET_VALUE_LONG("keepalive_interval", cfg->keepAliveInterval);
    GET_VALUE_LONG("keepalive_count", cfg->keepAliveCount);

    GET_VALUE_LONG("seccomp_sandbox", cfg->seccompSandbox);

    ret = 0;

cleanup:
    virConfFree(conf);
    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}
#undef GET_VALUE_BOOL
#undef GET_VALUE_LONG
#undef GET_VALUE_STRING

virQEMUDriverConfigPtr virQEMUDriverGetConfig(virQEMUDriverPtr driver)
{
    virQEMUDriverConfigPtr conf;
    qemuDriverLock(driver);
    conf = virObjectRef(driver->config);
    qemuDriverUnlock(driver);
    return conf;
}

virDomainXMLConfPtr
virQEMUDriverCreateXMLConf(void)
{
    return virDomainXMLConfNew(&virQEMUDriverPrivateDataCallbacks,
                               &virQEMUDriverDomainXMLNamespace);
}


virCapsPtr virQEMUDriverCreateCapabilities(virQEMUDriverPtr driver)
{
    size_t i;
    virCapsPtr caps;
    virSecurityManagerPtr *sec_managers = NULL;
    /* Security driver data */
    const char *doi, *model;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    /* Basic host arch / guest machine capabilities */
    if (!(caps = virQEMUCapsInit(driver->qemuCapsCache)))
        goto no_memory;

    if (cfg->allowDiskFormatProbing) {
        caps->defaultDiskDriverName = NULL;
        caps->defaultDiskDriverType = VIR_STORAGE_FILE_AUTO;
    } else {
        caps->defaultDiskDriverName = "qemu";
        caps->defaultDiskDriverType = VIR_STORAGE_FILE_RAW;
    }

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto error;
    }

    /* access sec drivers and create a sec model for each one */
    if (!(sec_managers = virSecurityManagerGetNested(driver->securityManager)))
        goto error;

    /* calculate length */
    for (i = 0; sec_managers[i]; i++)
        ;
    caps->host.nsecModels = i;

    if (VIR_ALLOC_N(caps->host.secModels, caps->host.nsecModels) < 0)
        goto no_memory;

    for (i = 0; sec_managers[i]; i++) {
        doi = virSecurityManagerGetDOI(sec_managers[i]);
        model = virSecurityManagerGetModel(sec_managers[i]);
        if (!(caps->host.secModels[i].model = strdup(model)))
            goto no_memory;
        if (!(caps->host.secModels[i].doi = strdup(doi)))
            goto no_memory;
        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    }
    VIR_FREE(sec_managers);

    virObjectUnref(cfg);
    return caps;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(sec_managers);
    virObjectUnref(caps);
    virObjectUnref(cfg);
    return NULL;
}


/**
 * virQEMUDriverGetCapabilities:
 *
 * Get a reference to the virCapsPtr instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virCapsPtr instance or NULL
 */
virCapsPtr virQEMUDriverGetCapabilities(virQEMUDriverPtr driver,
                                        bool refresh)
{
    virCapsPtr ret = NULL;
    if (refresh) {
        virCapsPtr caps = NULL;
        if ((caps = virQEMUDriverCreateCapabilities(driver)) == NULL)
            return NULL;

        qemuDriverLock(driver);
        virObjectUnref(driver->caps);
        driver->caps = caps;
    } else {
        qemuDriverLock(driver);
    }

    ret = virObjectRef(driver->caps);
    qemuDriverUnlock(driver);
    return ret;
}


static void
virQEMUCloseCallbacksFreeData(void *payload,
                              const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}

virQEMUCloseCallbacksPtr
virQEMUCloseCallbacksNew(void)
{
    virQEMUCloseCallbacksPtr closeCallbacks;

    if (virQEMUConfigInitialize() < 0)
        return NULL;

    if (!(closeCallbacks = virObjectLockableNew(virQEMUCloseCallbacksClass)))
        return NULL;

    closeCallbacks->list = virHashCreate(5, virQEMUCloseCallbacksFreeData);
    if (!closeCallbacks->list) {
        virObjectUnref(closeCallbacks);
        return NULL;
    }

    return closeCallbacks;
}

static void
virQEMUCloseCallbacksDispose(void *obj)
{
    virQEMUCloseCallbacksPtr closeCallbacks = obj;

    virHashFree(closeCallbacks->list);
}

int
virQEMUCloseCallbacksSet(virQEMUCloseCallbacksPtr closeCallbacks,
                         virDomainObjPtr vm,
                         virConnectPtr conn,
                         virQEMUCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    int ret = -1;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p, cb=%p",
              vm->def->name, uuidstr, conn, cb);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (closeDef) {
        if (closeDef->conn != conn) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Close callback for domain %s already registered"
                             " with another connection %p"),
                           vm->def->name, closeDef->conn);
            goto cleanup;
        }
        if (closeDef->cb && closeDef->cb != cb) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Another close callback is already defined for"
                             " domain %s"), vm->def->name);
            goto cleanup;
        }

        closeDef->cb = cb;
    } else {
        if (VIR_ALLOC(closeDef) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        closeDef->conn = conn;
        closeDef->cb = cb;
        if (virHashAddEntry(closeCallbacks->list, uuidstr, closeDef) < 0) {
            VIR_FREE(closeDef);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    virObjectUnlock(closeCallbacks);
    return ret;
}

int
virQEMUCloseCallbacksUnset(virQEMUCloseCallbacksPtr closeCallbacks,
                           virDomainObjPtr vm,
                           virQEMUCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    int ret = -1;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, cb=%p",
              vm->def->name, uuidstr, cb);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (!closeDef)
        goto cleanup;

    if (closeDef->cb && closeDef->cb != cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Trying to remove mismatching close callback for"
                         " domain %s"), vm->def->name);
        goto cleanup;
    }

    ret = virHashRemoveEntry(closeCallbacks->list, uuidstr);
cleanup:
    virObjectUnlock(closeCallbacks);
    return ret;
}

virQEMUCloseCallback
virQEMUCloseCallbacksGet(virQEMUCloseCallbacksPtr closeCallbacks,
                         virDomainObjPtr vm,
                         virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    virQEMUCloseCallback cb = NULL;

    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p",
              vm->def->name, uuidstr, conn);

    virObjectLock(closeCallbacks);

    closeDef = virHashLookup(closeCallbacks->list, uuidstr);
    if (closeDef && (!conn || closeDef->conn == conn))
        cb = closeDef->cb;

    virObjectUnlock(closeCallbacks);

    VIR_DEBUG("cb=%p", cb);
    return cb;
}


typedef struct _virQEMUCloseCallbacksListEntry virQEMUCloseCallbacksListEntry;
typedef virQEMUCloseCallbacksListEntry *virQEMUCloseCallbacksListEntryPtr;
struct _virQEMUCloseCallbacksListEntry {
    unsigned char uuid[VIR_UUID_BUFLEN];
    virQEMUCloseCallback callback;
};


typedef struct _virQEMUCloseCallbacksList virQEMUCloseCallbacksList;
typedef virQEMUCloseCallbacksList *virQEMUCloseCallbacksListPtr;
struct _virQEMUCloseCallbacksList {
    size_t nentries;
    virQEMUCloseCallbacksListEntryPtr entries;
};


struct virQEMUCloseCallbacksData {
    virConnectPtr conn;
    virQEMUCloseCallbacksListPtr list;
    bool oom;
};


static void
virQEMUCloseCallbacksGetOne(void *payload,
                            const void *key,
                            void *opaque)
{
    struct virQEMUCloseCallbacksData *data = opaque;
    qemuDriverCloseDefPtr closeDef = payload;
    const char *uuidstr = key;
    unsigned char uuid[VIR_UUID_BUFLEN];

    if (virUUIDParse(uuidstr, uuid) < 0)
        return;

    VIR_DEBUG("conn=%p, thisconn=%p, uuid=%s, cb=%p",
              closeDef->conn, data->conn, uuidstr, closeDef->cb);

    if (data->conn != closeDef->conn || !closeDef->cb)
        return;

    if (VIR_EXPAND_N(data->list->entries,
                     data->list->nentries, 1) < 0) {
        data->oom = true;
        return;
    }

    memcpy(data->list->entries[data->list->nentries - 1].uuid,
           uuid, VIR_UUID_BUFLEN);
    data->list->entries[data->list->nentries - 1].callback = closeDef->cb;
}


static virQEMUCloseCallbacksListPtr
virQEMUCloseCallbacksGetForConn(virQEMUCloseCallbacksPtr closeCallbacks,
                                virConnectPtr conn)
{
    virQEMUCloseCallbacksListPtr list = NULL;
    struct virQEMUCloseCallbacksData data;

    if (VIR_ALLOC(list) < 0) {
        virReportOOMError();
        return NULL;
    }

    data.conn = conn;
    data.list = list;
    data.oom = false;

    virHashForEach(closeCallbacks->list, virQEMUCloseCallbacksGetOne, &data);

    if (data.oom) {
        VIR_FREE(list->entries);
        VIR_FREE(list);
        virReportOOMError();
        return NULL;
    }

    return list;
}


void
virQEMUCloseCallbacksRun(virQEMUCloseCallbacksPtr closeCallbacks,
                         virConnectPtr conn,
                         virQEMUDriverPtr driver)
{
    virQEMUCloseCallbacksListPtr list;
    size_t i;

    VIR_DEBUG("conn=%p", conn);

    /* We must not hold the lock while running the callbacks,
     * so first we obtain the list of callbacks, then remove
     * them all from the hash. At that point we can release
     * the lock and run the callbacks safely. */

    virObjectLock(closeCallbacks);
    list = virQEMUCloseCallbacksGetForConn(closeCallbacks, conn);
    if (!list)
        return;

    for (i = 0 ; i < list->nentries ; i++) {
        virHashRemoveEntry(closeCallbacks->list,
                           list->entries[i].uuid);
    }
    virObjectUnlock(closeCallbacks);

    for (i = 0 ; i < list->nentries ; i++) {
        virDomainObjPtr vm;

        if (!(vm = virDomainObjListFindByUUID(driver->domains,
                                              list->entries[i].uuid))) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(list->entries[i].uuid, uuidstr);
            VIR_DEBUG("No domain object with UUID %s", uuidstr);
            continue;
        }

        vm = list->entries[i].callback(driver, vm, conn);
        if (vm)
            virObjectUnlock(vm);
    }
    VIR_FREE(list->entries);
    VIR_FREE(list);
}

struct _qemuSharedDiskEntry {
    size_t ref;
    char **domains; /* array of domain names */
};

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

/* Check if a shared disk's setting conflicts with the conf
 * used by other domain(s). Currently only checks the sgio
 * setting. Note that this should only be called for disk with
 * block source.
 *
 * Returns 0 if no conflicts, otherwise returns -1.
 */
static int
qemuCheckSharedDisk(virHashTablePtr sharedDisks,
                    virDomainDiskDefPtr disk)
{
    char *sysfs_path = NULL;
    char *key = NULL;
    int val;
    int ret = 0;

    /* The only conflicts between shared disk we care about now
     * is sgio setting, which is only valid for device='lun'.
     */
    if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN)
        return 0;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(disk->src, NULL))) {
        ret = -1;
        goto cleanup;
    }

    /* It can't be conflict if unpriv_sgio is not supported
     * by kernel.
     */
    if (!virFileExists(sysfs_path))
        goto cleanup;

    if (!(key = qemuGetSharedDiskKey(disk->src))) {
        ret = -1;
        goto cleanup;
    }

    /* It can't be conflict if no other domain is
     * is sharing it.
     */
    if (!(virHashLookup(sharedDisks, key)))
        goto cleanup;

    if (virGetDeviceUnprivSGIO(disk->src, NULL, &val) < 0) {
        ret = -1;
        goto cleanup;
    }

    if ((val == 0 &&
         (disk->sgio == VIR_DOMAIN_DISK_SGIO_FILTERED ||
          disk->sgio == VIR_DOMAIN_DISK_SGIO_DEFAULT)) ||
        (val == 1 &&
         disk->sgio == VIR_DOMAIN_DISK_SGIO_UNFILTERED))
        goto cleanup;

    virReportError(VIR_ERR_OPERATION_INVALID,
                   _("sgio of shared disk '%s' conflicts with other "
                     "active domains"), disk->src);
    ret = -1;

cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(key);
    return ret;
}

bool
qemuSharedDiskEntryDomainExists(qemuSharedDiskEntryPtr entry,
                                const char *name,
                                int *idx)
{
    size_t i;

    for (i = 0; i < entry->ref; i++) {
        if (STREQ(entry->domains[i], name)) {
            if (idx)
                *idx = i;
            return true;
        }
    }

    return false;
}

void
qemuSharedDiskEntryFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    qemuSharedDiskEntryPtr entry = payload;
    size_t i;

    if (!entry)
        return;

    for (i = 0; i < entry->ref; i++) {
        VIR_FREE(entry->domains[i]);
    }
    VIR_FREE(entry->domains);
    VIR_FREE(entry);
}

static qemuSharedDiskEntryPtr
qemuSharedDiskEntryCopy(const qemuSharedDiskEntryPtr entry)
{
    qemuSharedDiskEntryPtr ret = NULL;
    size_t i;

    if (VIR_ALLOC(ret) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (VIR_ALLOC_N(ret->domains, entry->ref) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0; i < entry->ref; i++) {
        if (!(ret->domains[i] = strdup(entry->domains[i]))) {
            virReportOOMError();
            goto cleanup;
        }
        ret->ref++;
    }

    return ret;

cleanup:
    qemuSharedDiskEntryFree(ret, NULL);
    return NULL;
}

/* qemuAddSharedDisk:
 * @driver: Pointer to qemu driver struct
 * @disk: The disk def
 * @name: The domain name
 *
 * Increase ref count and add the domain name into the list which
 * records all the domains that use the shared disk if the entry
 * already exists, otherwise add a new entry.
 */
int
qemuAddSharedDisk(virQEMUDriverPtr driver,
                  virDomainDiskDefPtr disk,
                  const char *name)
{
    qemuSharedDiskEntry *entry = NULL;
    qemuSharedDiskEntry *new_entry = NULL;
    char *key = NULL;
    int ret = -1;

    /* Currently the only conflicts we have to care about
     * for the shared disk is "sgio" setting, which is only
     * valid for block disk.
     */
    if (disk->type != VIR_DOMAIN_DISK_TYPE_BLOCK ||
        !disk->shared || !disk->src)
        return 0;

    qemuDriverLock(driver);
    if (qemuCheckSharedDisk(driver->sharedDisks, disk) < 0)
        goto cleanup;

    if (!(key = qemuGetSharedDiskKey(disk->src)))
        goto cleanup;

    if ((entry = virHashLookup(driver->sharedDisks, key))) {
        /* Nothing to do if the shared disk is already recorded
         * in the table.
         */
        if (qemuSharedDiskEntryDomainExists(entry, name, NULL)) {
            ret = 0;
            goto cleanup;
        }

        if (!(new_entry = qemuSharedDiskEntryCopy(entry)))
            goto cleanup;

        if ((VIR_EXPAND_N(new_entry->domains, new_entry->ref, 1) < 0) ||
            !(new_entry->domains[new_entry->ref - 1] = strdup(name))) {
            qemuSharedDiskEntryFree(new_entry, NULL);
            virReportOOMError();
            goto cleanup;
        }

        if (virHashUpdateEntry(driver->sharedDisks, key, new_entry) < 0) {
            qemuSharedDiskEntryFree(new_entry, NULL);
            goto cleanup;
        }
    } else {
        if ((VIR_ALLOC(entry) < 0) ||
            (VIR_ALLOC_N(entry->domains, 1) < 0) ||
            !(entry->domains[0] = strdup(name))) {
            qemuSharedDiskEntryFree(entry, NULL);
            virReportOOMError();
            goto cleanup;
        }

        entry->ref = 1;

        if (virHashAddEntry(driver->sharedDisks, key, entry))
            goto cleanup;
    }

    ret = 0;
cleanup:
    qemuDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}

/* qemuRemoveSharedDisk:
 * @driver: Pointer to qemu driver struct
 * @disk: The disk def
 * @name: The domain name
 *
 * Decrease ref count and remove the domain name from the list which
 * records all the domains that use the shared disk if ref is not 1,
 * otherwise remove the entry.
 */
int
qemuRemoveSharedDisk(virQEMUDriverPtr driver,
                     virDomainDiskDefPtr disk,
                     const char *name)
{
    qemuSharedDiskEntryPtr entry = NULL;
    qemuSharedDiskEntryPtr new_entry = NULL;
    char *key = NULL;
    int ret = -1;
    int idx;

    if (disk->type != VIR_DOMAIN_DISK_TYPE_BLOCK ||
        !disk->shared || !disk->src)
        return 0;

    qemuDriverLock(driver);
    if (!(key = qemuGetSharedDiskKey(disk->src)))
        goto cleanup;

    if (!(entry = virHashLookup(driver->sharedDisks, key)))
        goto cleanup;

    /* Nothing to do if the shared disk is not recored in
     * the table.
     */
    if (!qemuSharedDiskEntryDomainExists(entry, name, &idx)) {
        ret = 0;
        goto cleanup;
    }

    if (entry->ref != 1) {
        if (!(new_entry = qemuSharedDiskEntryCopy(entry)))
            goto cleanup;

        if (idx != new_entry->ref - 1)
            memmove(&new_entry->domains[idx],
                    &new_entry->domains[idx + 1],
                    sizeof(*new_entry->domains) * (new_entry->ref - idx - 1));

        VIR_SHRINK_N(new_entry->domains, new_entry->ref, 1);

        if (virHashUpdateEntry(driver->sharedDisks, key, new_entry) < 0){
            qemuSharedDiskEntryFree(new_entry, NULL);
            goto cleanup;
        }
    } else {
        if (virHashRemoveEntry(driver->sharedDisks, key) < 0)
            goto cleanup;
    }

    ret = 0;
cleanup:
    qemuDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}


int qemuDriverAllocateID(virQEMUDriverPtr driver)
{
    return virAtomicIntInc(&driver->nextvmid);
}
