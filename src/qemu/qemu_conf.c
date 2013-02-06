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

static virClassPtr virQEMUDriverConfigClass;
static void virQEMUDriverConfigDispose(void *obj);

static int virQEMUConfigOnceInit(void)
{
    if (!(virQEMUDriverConfigClass = virClassNew(virClassForObject(),
                                                 "virQEMUDriverConfig",
                                                 sizeof(virQEMUDriverConfig),
                                                 virQEMUDriverConfigDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUConfig)


struct _qemuDriverCloseDef {
    virConnectPtr conn;
    qemuDriverCloseCallback cb;
};

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
        cfg->user = 0;
        cfg->group = 0;
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


virCapsPtr virQEMUDriverCreateCapabilities(virQEMUDriverPtr driver)
{
    size_t i;
    virCapsPtr caps;
    virSecurityManagerPtr *sec_managers = NULL;
    /* Security driver data */
    const char *doi, *model;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);

    /* Basic host arch / guest machine capabilities */
    if (!(caps = virQEMUCapsInit(driver->qemuCapsCache))) {
        virReportOOMError();
        virObjectUnref(cfg);
        return NULL;
    }

    if (cfg->allowDiskFormatProbing) {
        caps->defaultDiskDriverName = NULL;
        caps->defaultDiskDriverType = VIR_STORAGE_FILE_AUTO;
    } else {
        caps->defaultDiskDriverName = "qemu";
        caps->defaultDiskDriverType = VIR_STORAGE_FILE_RAW;
    }

    qemuDomainSetPrivateDataHooks(caps);
    qemuDomainSetNamespaceHooks(caps);

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        goto err_exit;
    }

    /* access sec drivers and create a sec model for each one */
    sec_managers = virSecurityManagerGetNested(driver->securityManager);
    if (sec_managers == NULL) {
        goto err_exit;
    }

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
err_exit:
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
    int ret = -1;

    qemuDriverLock(driver);
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
        if (virHashAddEntry(driver->closeCallbacks, uuidstr, closeDef) < 0) {
            VIR_FREE(closeDef);
            goto cleanup;
        }
    }

    ret = 0;
cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

int
qemuDriverCloseCallbackUnset(virQEMUDriverPtr driver,
                             virDomainObjPtr vm,
                             qemuDriverCloseCallback cb)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    int ret = -1;

    qemuDriverLock(driver);
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, cb=%p",
              vm->def->name, uuidstr, cb);

    closeDef = virHashLookup(driver->closeCallbacks, uuidstr);
    if (!closeDef)
        goto cleanup;

    if (closeDef->cb && closeDef->cb != cb) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Trying to remove mismatching close callback for"
                         " domain %s"), vm->def->name);
        goto cleanup;
    }

    ret = virHashRemoveEntry(driver->closeCallbacks, uuidstr);
cleanup:
    qemuDriverUnlock(driver);
    return ret;
}

qemuDriverCloseCallback
qemuDriverCloseCallbackGet(virQEMUDriverPtr driver,
                           virDomainObjPtr vm,
                           virConnectPtr conn)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    qemuDriverCloseDefPtr closeDef;
    qemuDriverCloseCallback cb = NULL;

    qemuDriverLock(driver);
    virUUIDFormat(vm->def->uuid, uuidstr);
    VIR_DEBUG("vm=%s, uuid=%s, conn=%p",
              vm->def->name, uuidstr, conn);

    closeDef = virHashLookup(driver->closeCallbacks, uuidstr);
    if (closeDef && (!conn || closeDef->conn == conn))
        cb = closeDef->cb;

    VIR_DEBUG("cb=%p", cb);
    qemuDriverUnlock(driver);
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

    if (!(dom = virDomainObjListFindByUUID(data->driver->domains, uuid))) {
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
    qemuDriverLock(driver);
    virHashForEach(driver->closeCallbacks, qemuDriverCloseCallbackRun, &data);
    qemuDriverUnlock(driver);
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
qemuAddSharedDisk(virQEMUDriverPtr driver,
                  const char *disk_path)
{
    size_t *ref = NULL;
    char *key = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    if (!(key = qemuGetSharedDiskKey(disk_path)))
        goto cleanup;

    if ((ref = virHashLookup(driver->sharedDisks, key))) {
        if (virHashUpdateEntry(driver->sharedDisks, key, ++ref) < 0)
             goto cleanup;
    } else {
        if (virHashAddEntry(driver->sharedDisks, key, (void *)0x1))
            goto cleanup;
    }

    ret = 0;
cleanup:
    qemuDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}

/* Decrease the ref count if the entry already exists, otherwise
 * remove the entry.
 */
int
qemuRemoveSharedDisk(virQEMUDriverPtr driver,
                     const char *disk_path)
{
    size_t *ref = NULL;
    char *key = NULL;
    int ret = -1;

    qemuDriverLock(driver);
    if (!(key = qemuGetSharedDiskKey(disk_path)))
        goto cleanup;

    if (!(ref = virHashLookup(driver->sharedDisks, key)))
        goto cleanup;

    if (ref != (void *)0x1) {
        if (virHashUpdateEntry(driver->sharedDisks, key, --ref) < 0)
            goto cleanup;
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
