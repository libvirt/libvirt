/*
 * qemu_conf.c: QEMU configuration management
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
#include "viruuid.h"
#include "virbuffer.h"
#include "virconf.h"
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
#include "storage_conf.h"
#include "configmake.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_conf");

static virClassPtr virQEMUDriverConfigClass;
static void virQEMUDriverConfigDispose(void *obj);

static int virQEMUConfigOnceInit(void)
{
    virQEMUDriverConfigClass = virClassNew(virClassForObject(),
                                           "virQEMUDriverConfig",
                                           sizeof(virQEMUDriverConfig),
                                           virQEMUDriverConfigDispose);

    if (!virQEMUDriverConfigClass)
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

void qemuDomainCmdlineDefFree(qemuDomainCmdlineDefPtr def)
{
    size_t i;

    if (!def)
        return;

    for (i = 0; i < def->num_args; i++)
        VIR_FREE(def->args[i]);
    for (i = 0; i < def->num_env; i++) {
        VIR_FREE(def->env_name[i]);
        VIR_FREE(def->env_value[i]);
    }
    VIR_FREE(def->args);
    VIR_FREE(def->env_name);
    VIR_FREE(def->env_value);
    VIR_FREE(def);
}


static int ATTRIBUTE_UNUSED
virQEMUDriverConfigLoaderNVRAMParse(virQEMUDriverConfigPtr cfg,
                                    const char *list)
{
    int ret = -1;
    char **token;
    size_t i, j;

    if (!(token = virStringSplit(list, ":", 0)))
        goto cleanup;

    for (i = 0; token[i]; i += 2) {
        if (!token[i] || !token[i + 1] ||
            STREQ(token[i], "") || STREQ(token[i + 1], "")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid --with-loader-nvram list: %s"),
                           list);
            goto cleanup;
        }
    }

    if (i) {
        if (VIR_ALLOC_N(cfg->loader, i / 2) < 0 ||
            VIR_ALLOC_N(cfg->nvram, i / 2) < 0)
            goto cleanup;
        cfg->nloader = i / 2;

        for (j = 0; j < i / 2; j++) {
            if (VIR_STRDUP(cfg->loader[j], token[2 * j]) < 0 ||
                VIR_STRDUP(cfg->nvram[j], token[2 * j + 1]) < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virStringFreeList(token);
    return ret;
}


#define VIR_QEMU_OVMF_LOADER_PATH "/usr/share/OVMF/OVMF_CODE.fd"
#define VIR_QEMU_OVMF_NVRAM_PATH "/usr/share/OVMF/OVMF_VARS.fd"
#define VIR_QEMU_AAVMF_LOADER_PATH "/usr/share/AAVMF/AAVMF_CODE.fd"
#define VIR_QEMU_AAVMF_NVRAM_PATH "/usr/share/AAVMF/AAVMF_VARS.fd"

virQEMUDriverConfigPtr virQEMUDriverConfigNew(bool privileged)
{
    virQEMUDriverConfigPtr cfg;

    if (virQEMUConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virQEMUDriverConfigClass)))
        return NULL;

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

    cfg->cgroupControllers = -1; /* -1 == auto-detect */

    if (privileged) {
        if (virAsprintf(&cfg->logDir,
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto error;

        if (VIR_STRDUP(cfg->configBaseDir, SYSCONFDIR "/libvirt") < 0)
            goto error;

        if (virAsprintf(&cfg->stateDir,
                      "%s/run/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto error;

        if (virAsprintf(&cfg->cacheDir,
                      "%s/cache/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto error;

        if (virAsprintf(&cfg->libDir,
                      "%s/lib/libvirt/qemu", LOCALSTATEDIR) < 0)
            goto error;
        if (virAsprintf(&cfg->saveDir, "%s/save", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->snapshotDir, "%s/snapshot", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->autoDumpPath, "%s/dump", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/channel/target", cfg->libDir) < 0)
            goto error;
        if (virAsprintf(&cfg->nvramDir, "%s/nvram", cfg->libDir) < 0)
            goto error;
    } else {
        char *rundir;
        char *cachedir;

        cachedir = virGetUserCacheDirectory();
        if (!cachedir)
            goto error;

        if (virAsprintf(&cfg->logDir,
                        "%s/qemu/log", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto error;
        }
        if (virAsprintf(&cfg->cacheDir, "%s/qemu/cache", cachedir) < 0) {
            VIR_FREE(cachedir);
            goto error;
        }
        VIR_FREE(cachedir);

        rundir = virGetUserRuntimeDirectory();
        if (!rundir)
            goto error;
        if (virAsprintf(&cfg->stateDir, "%s/qemu/run", rundir) < 0) {
            VIR_FREE(rundir);
            goto error;
        }
        VIR_FREE(rundir);

        if (!(cfg->configBaseDir = virGetUserConfigDirectory()))
            goto error;

        if (virAsprintf(&cfg->libDir, "%s/qemu/lib", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->saveDir, "%s/qemu/save", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->snapshotDir, "%s/qemu/snapshot", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->autoDumpPath, "%s/qemu/dump", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/qemu/channel/target", cfg->configBaseDir) < 0)
            goto error;
        if (virAsprintf(&cfg->nvramDir,
                        "%s/qemu/nvram", cfg->configBaseDir) < 0)
            goto error;
    }

    if (virAsprintf(&cfg->configDir, "%s/qemu", cfg->configBaseDir) < 0)
        goto error;
    if (virAsprintf(&cfg->autostartDir, "%s/qemu/autostart", cfg->configBaseDir) < 0)
        goto error;


    if (VIR_STRDUP(cfg->vncListen, "127.0.0.1") < 0)
        goto error;

    if (VIR_STRDUP(cfg->vncTLSx509certdir, SYSCONFDIR "/pki/libvirt-vnc") < 0)
        goto error;

    if (VIR_STRDUP(cfg->spiceListen, "127.0.0.1") < 0)
        goto error;

    if (VIR_STRDUP(cfg->spiceTLSx509certdir,
                   SYSCONFDIR "/pki/libvirt-spice") < 0)
        goto error;

    cfg->remotePortMin = QEMU_REMOTE_PORT_MIN;
    cfg->remotePortMax = QEMU_REMOTE_PORT_MAX;

    cfg->webSocketPortMin = QEMU_WEBSOCKET_PORT_MIN;
    cfg->webSocketPortMax = QEMU_WEBSOCKET_PORT_MAX;

    cfg->migrationPortMin = QEMU_MIGRATION_PORT_MIN;
    cfg->migrationPortMax = QEMU_MIGRATION_PORT_MAX;

    /* For privileged driver, try and find hugetlbfs mounts automatically.
     * Non-privileged driver requires admin to create a dir for the
     * user, chown it, and then let user configure it manually. */
    if (privileged &&
        virFileFindHugeTLBFS(&cfg->hugetlbfs, &cfg->nhugetlbfs) < 0) {
        /* This however is not implemented on all platforms. */
        virErrorPtr err = virGetLastError();
        if (err && err->code != VIR_ERR_NO_SUPPORT)
            goto error;
    }

    if (VIR_STRDUP(cfg->bridgeHelperName, QEMU_BRIDGE_HELPER) < 0)
        goto error;

    cfg->clearEmulatorCapabilities = true;

    cfg->securityDefaultConfined = true;
    cfg->securityRequireConfined = false;

    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;
    cfg->seccompSandbox = -1;

    cfg->logTimestamp = true;

#ifdef DEFAULT_LOADER_NVRAM
    if (virQEMUDriverConfigLoaderNVRAMParse(cfg, DEFAULT_LOADER_NVRAM) < 0)
        goto error;

#else

    if (VIR_ALLOC_N(cfg->loader, 2) < 0 ||
        VIR_ALLOC_N(cfg->nvram, 2) < 0)
        goto error;
    cfg->nloader = 2;

    if (VIR_STRDUP(cfg->loader[0], VIR_QEMU_AAVMF_LOADER_PATH) < 0 ||
        VIR_STRDUP(cfg->nvram[0], VIR_QEMU_AAVMF_NVRAM_PATH) < 0  ||
        VIR_STRDUP(cfg->loader[1], VIR_QEMU_OVMF_LOADER_PATH) < 0 ||
        VIR_STRDUP(cfg->nvram[1], VIR_QEMU_OVMF_NVRAM_PATH) < 0)
        goto error;
#endif

    return cfg;

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
    VIR_FREE(cfg->channelTargetDir);
    VIR_FREE(cfg->nvramDir);

    VIR_FREE(cfg->vncTLSx509certdir);
    VIR_FREE(cfg->vncListen);
    VIR_FREE(cfg->vncPassword);
    VIR_FREE(cfg->vncSASLdir);

    VIR_FREE(cfg->spiceTLSx509certdir);
    VIR_FREE(cfg->spiceListen);
    VIR_FREE(cfg->spicePassword);
    VIR_FREE(cfg->spiceSASLdir);

    while (cfg->nhugetlbfs) {
        cfg->nhugetlbfs--;
        VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
    }
    VIR_FREE(cfg->hugetlbfs);
    VIR_FREE(cfg->bridgeHelperName);

    VIR_FREE(cfg->saveImageFormat);
    VIR_FREE(cfg->dumpImageFormat);
    VIR_FREE(cfg->autoDumpPath);

    virStringFreeList(cfg->securityDriverNames);

    VIR_FREE(cfg->lockManagerName);

    while (cfg->nloader) {
        VIR_FREE(cfg->loader[cfg->nloader - 1]);
        VIR_FREE(cfg->nvram[cfg->nloader - 1]);
        cfg->nloader--;
    }
    VIR_FREE(cfg->loader);
    VIR_FREE(cfg->nvram);
}


static int
virQEMUDriverConfigHugeTLBFSInit(virHugeTLBFSPtr hugetlbfs,
                                 const char *path,
                                 bool deflt)
{
    int ret = -1;

    if (VIR_STRDUP(hugetlbfs->mnt_dir, path) < 0)
        goto cleanup;

    if (virFileGetHugepageSize(path, &hugetlbfs->size) < 0)
        goto cleanup;

    hugetlbfs->deflt = deflt;
    ret = 0;
 cleanup:
    return ret;
}


static int
virQEMUDriverConfigNVRAMParse(const char *str,
                              char **loader,
                              char **nvram)
{
    int ret = -1;
    char **token;

    if (!(token = virStringSplit(str, ":", 0)))
        goto cleanup;

    if (token[0]) {
        virSkipSpaces((const char **) &token[0]);
        if (token[1])
            virSkipSpaces((const char **) &token[1]);
    }

    /* Exactly two tokens are expected */
    if (!token[0] || !token[1] || token[2] ||
        STREQ(token[0], "") || STREQ(token[1], "")) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("Invalid nvram format: '%s'"),
                       str);
        goto cleanup;
    }

    if (VIR_STRDUP(*loader, token[0]) < 0 ||
        VIR_STRDUP(*nvram, token[1]) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virStringFreeList(token);
    return ret;
}


int virQEMUDriverConfigLoadFile(virQEMUDriverConfigPtr cfg,
                                const char *filename)
{
    virConfPtr conf = NULL;
    virConfValuePtr p;
    int ret = -1;
    size_t i;
    char *stdioHandler = NULL;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        goto cleanup;

#define CHECK_TYPE(name, typ)                         \
    if (p && p->type != (typ)) {                      \
        virReportError(VIR_ERR_INTERNAL_ERROR,        \
                       "%s: %s: expected type " #typ, \
                       filename, (name));             \
        goto cleanup;                                 \
    }

#define CHECK_TYPE_ALT(name, type1, type2)                      \
    if (p && (p->type != (type1) && p->type != (type2))) {      \
        virReportError(VIR_ERR_INTERNAL_ERROR,                  \
                       "%s: %s: expected type " #type1,         \
                       filename, (name));                       \
        goto cleanup;                                           \
    }

#define GET_VALUE_LONG(NAME, VAR)                               \
    p = virConfGetValue(conf, NAME);                            \
    CHECK_TYPE_ALT(NAME, VIR_CONF_LONG, VIR_CONF_ULONG);        \
    if (p)                                                      \
        VAR = p->l;

#define GET_VALUE_ULONG(NAME, VAR)    \
    p = virConfGetValue(conf, NAME);  \
    CHECK_TYPE(NAME, VIR_CONF_ULONG); \
    if (p)                            \
        VAR = p->l;

#define GET_VALUE_BOOL(NAME, VAR)     \
    p = virConfGetValue(conf, NAME);  \
    CHECK_TYPE(NAME, VIR_CONF_ULONG); \
    if (p)                            \
        VAR = p->l != 0;

#define GET_VALUE_STR(NAME, VAR)           \
    p = virConfGetValue(conf, NAME);       \
    CHECK_TYPE(NAME, VIR_CONF_STRING);     \
    if (p && p->str) {                     \
        VIR_FREE(VAR);                     \
        if (VIR_STRDUP(VAR, p->str) < 0)   \
            goto cleanup;                  \
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
    GET_VALUE_BOOL("nographics_allow_host_audio", cfg->nogfxAllowHostAudio);

    p = virConfGetValue(conf, "security_driver");
    if (p && p->type == VIR_CONF_LIST) {
        size_t len, j;
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
            goto cleanup;

        for (i = 0, pp = p->list; pp; i++, pp = pp->next) {
            for (j = 0; j < i; j++) {
                if (STREQ(pp->str, cfg->securityDriverNames[j])) {
                    virReportError(VIR_ERR_CONF_SYNTAX,
                                   _("Duplicate security driver %s"), pp->str);
                    goto cleanup;
                }
            }
            if (VIR_STRDUP(cfg->securityDriverNames[i], pp->str) < 0)
                goto cleanup;
        }
        cfg->securityDriverNames[len] = NULL;
    } else {
        CHECK_TYPE("security_driver", VIR_CONF_STRING);
        if (p && p->str) {
            if (VIR_ALLOC_N(cfg->securityDriverNames, 2) < 0)
                goto cleanup;
            if (VIR_STRDUP(cfg->securityDriverNames[0], p->str) < 0)
                goto cleanup;

            cfg->securityDriverNames[1] = NULL;
        }
    }

    GET_VALUE_BOOL("security_default_confined", cfg->securityDefaultConfined);
    GET_VALUE_BOOL("security_require_confined", cfg->securityRequireConfined);

    GET_VALUE_BOOL("spice_tls", cfg->spiceTLS);
    GET_VALUE_STR("spice_tls_x509_cert_dir", cfg->spiceTLSx509certdir);
    GET_VALUE_BOOL("spice_sasl", cfg->spiceSASL);
    GET_VALUE_STR("spice_sasl_dir", cfg->spiceSASLdir);
    GET_VALUE_STR("spice_listen", cfg->spiceListen);
    GET_VALUE_STR("spice_password", cfg->spicePassword);


    GET_VALUE_ULONG("remote_websocket_port_min", cfg->webSocketPortMin);
    if (cfg->webSocketPortMin < QEMU_WEBSOCKET_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5700, e.g. localhost:1
         * for port 5701) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: remote_websocket_port_min: port must be greater "
                         "than or equal to %d"),
                        filename, QEMU_WEBSOCKET_PORT_MIN);
        goto cleanup;
    }

    GET_VALUE_ULONG("remote_websocket_port_max", cfg->webSocketPortMax);
    if (cfg->webSocketPortMax > QEMU_WEBSOCKET_PORT_MAX ||
        cfg->webSocketPortMax < cfg->webSocketPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_websocket_port_max: port must be between "
                          "the minimal port and %d"),
                       filename, QEMU_WEBSOCKET_PORT_MAX);
        goto cleanup;
    }

    if (cfg->webSocketPortMin > cfg->webSocketPortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_websocket_port_min: min port must not be "
                          "greater than max port"), filename);
        goto cleanup;
    }

    GET_VALUE_ULONG("remote_display_port_min", cfg->remotePortMin);
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

    GET_VALUE_ULONG("remote_display_port_max", cfg->remotePortMax);
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

    GET_VALUE_ULONG("migration_port_min", cfg->migrationPortMin);
    if (cfg->migrationPortMin <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: migration_port_min: port must be greater than 0"),
                        filename);
        goto cleanup;
    }

    GET_VALUE_ULONG("migration_port_max", cfg->migrationPortMax);
    if (cfg->migrationPortMax > 65535 ||
        cfg->migrationPortMax < cfg->migrationPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: migration_port_max: port must be between "
                          "the minimal port %d and 65535"),
                       filename, cfg->migrationPortMin);
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
        cfg->cgroupControllers = 0;
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

    p = virConfGetValue(conf, "cgroup_device_acl");
    CHECK_TYPE("cgroup_device_acl", VIR_CONF_LIST);
    if (p) {
        int len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(cfg->cgroupDeviceACL, 1+len) < 0)
            goto cleanup;

        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("cgroup_device_acl must be a "
                                 "list of strings"));
                goto cleanup;
            }
            if (VIR_STRDUP(cfg->cgroupDeviceACL[i], pp->str) < 0)
                goto cleanup;
        }
        cfg->cgroupDeviceACL[i] = NULL;
    }

    GET_VALUE_STR("save_image_format", cfg->saveImageFormat);
    GET_VALUE_STR("dump_image_format", cfg->dumpImageFormat);
    GET_VALUE_STR("snapshot_image_format", cfg->snapshotImageFormat);

    GET_VALUE_STR("auto_dump_path", cfg->autoDumpPath);
    GET_VALUE_BOOL("auto_dump_bypass_cache", cfg->autoDumpBypassCache);
    GET_VALUE_BOOL("auto_start_bypass_cache", cfg->autoStartBypassCache);

    /* Some crazy backcompat. Back in the old days, this was just a pure
     * string. We must continue supporting it. These days however, this may be
     * an array of strings. */
    p = virConfGetValue(conf, "hugetlbfs_mount");
    if (p) {
        /* There already might be something autodetected. Avoid leaking it. */
        while (cfg->nhugetlbfs) {
            cfg->nhugetlbfs--;
            VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
        }
        VIR_FREE(cfg->hugetlbfs);

        if (p->type == VIR_CONF_LIST) {
            size_t len = 0;
            virConfValuePtr pp = p->list;

            /* Calc length and check items */
            while (pp) {
                if (pp->type != VIR_CONF_STRING) {
                    virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                                   _("hugetlbfs_mount must be a list of strings"));
                    goto cleanup;
                }
                len++;
                pp = pp->next;
            }

            if (len && VIR_ALLOC_N(cfg->hugetlbfs, len) < 0)
                goto cleanup;
            cfg->nhugetlbfs = len;

            pp = p->list;
            len = 0;
            while (pp) {
                if (virQEMUDriverConfigHugeTLBFSInit(&cfg->hugetlbfs[len],
                                                     pp->str, !len) < 0)
                    goto cleanup;
                len++;
                pp = pp->next;
            }
        } else {
            CHECK_TYPE("hugetlbfs_mount", VIR_CONF_STRING);
            if (STRNEQ(p->str, "")) {
                if (VIR_ALLOC_N(cfg->hugetlbfs, 1) < 0)
                    goto cleanup;
                cfg->nhugetlbfs = 1;
                if (virQEMUDriverConfigHugeTLBFSInit(&cfg->hugetlbfs[0],
                                                     p->str, true) < 0)
                    goto cleanup;
            }
        }
    }

    GET_VALUE_STR("bridge_helper", cfg->bridgeHelperName);

    GET_VALUE_BOOL("mac_filter", cfg->macFilter);

    GET_VALUE_BOOL("relaxed_acs_check", cfg->relaxedACS);
    GET_VALUE_BOOL("clear_emulator_capabilities", cfg->clearEmulatorCapabilities);
    GET_VALUE_BOOL("allow_disk_format_probing", cfg->allowDiskFormatProbing);
    GET_VALUE_BOOL("set_process_name", cfg->setProcessName);
    GET_VALUE_ULONG("max_processes", cfg->maxProcesses);
    GET_VALUE_ULONG("max_files", cfg->maxFiles);

    GET_VALUE_STR("lock_manager", cfg->lockManagerName);
    GET_VALUE_STR("stdio_handler", stdioHandler);
    if (stdioHandler) {
        if (STREQ(stdioHandler, "logd")) {
            cfg->stdioLogD = true;
        } else if (STREQ(stdioHandler, "file")) {
            cfg->stdioLogD = false;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown stdio handler %s"),
                           stdioHandler);
            VIR_FREE(stdioHandler);
            goto cleanup;
        }
        VIR_FREE(stdioHandler);
    } else {
        cfg->stdioLogD = true;
    }

    GET_VALUE_ULONG("max_queued", cfg->maxQueuedJobs);

    GET_VALUE_LONG("keepalive_interval", cfg->keepAliveInterval);
    GET_VALUE_ULONG("keepalive_count", cfg->keepAliveCount);

    GET_VALUE_LONG("seccomp_sandbox", cfg->seccompSandbox);

    GET_VALUE_STR("migration_host", cfg->migrateHost);
    virStringStripIPv6Brackets(cfg->migrateHost);
    if (cfg->migrateHost &&
        (STRPREFIX(cfg->migrateHost, "localhost") ||
         virSocketAddrIsNumericLocalhost(cfg->migrateHost))) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migration_host must not be the address of"
                         " the local machine: %s"),
                       cfg->migrateHost);
        goto cleanup;
    }

    GET_VALUE_STR("migration_address", cfg->migrationAddress);
    virStringStripIPv6Brackets(cfg->migrationAddress);
    if (cfg->migrationAddress &&
        (STRPREFIX(cfg->migrationAddress, "localhost") ||
         virSocketAddrIsNumericLocalhost(cfg->migrationAddress))) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migration_address must not be the address of"
                         " the local machine: %s"),
                       cfg->migrationAddress);
        goto cleanup;
    }

    GET_VALUE_BOOL("log_timestamp", cfg->logTimestamp);

    if ((p = virConfGetValue(conf, "nvram"))) {
        size_t len;
        virConfValuePtr pp;

        CHECK_TYPE("nvram", VIR_CONF_LIST);

        while (cfg->nloader) {
            VIR_FREE(cfg->loader[cfg->nloader - 1]);
            VIR_FREE(cfg->nvram[cfg->nloader - 1]);
            cfg->nloader--;
        }
        VIR_FREE(cfg->loader);
        VIR_FREE(cfg->nvram);

        /* Calc length and check items */
        for (len = 0, pp = p->list; pp; len++, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                virReportError(VIR_ERR_CONF_SYNTAX, "%s",
                               _("nvram must be a list of strings"));
                goto cleanup;
            }
        }

        if (len &&
            (VIR_ALLOC_N(cfg->loader, len) < 0 ||
             VIR_ALLOC_N(cfg->nvram, len) < 0))
            goto cleanup;
        cfg->nloader = len;

        for (i = 0, pp = p->list; pp; i++, pp = pp->next) {
            if (virQEMUDriverConfigNVRAMParse(pp->str,
                                              &cfg->loader[i],
                                              &cfg->nvram[i]) < 0)
                goto cleanup;
        }
    }

    ret = 0;

 cleanup:
    virConfFree(conf);
    return ret;
}
#undef GET_VALUE_LONG
#undef GET_VALUE_ULONG
#undef GET_VALUE_BOOL
#undef GET_VALUE_STR

virQEMUDriverConfigPtr virQEMUDriverGetConfig(virQEMUDriverPtr driver)
{
    virQEMUDriverConfigPtr conf;
    qemuDriverLock(driver);
    conf = virObjectRef(driver->config);
    qemuDriverUnlock(driver);
    return conf;
}

bool
virQEMUDriverIsPrivileged(virQEMUDriverPtr driver)
{
    return driver->privileged;
}

virDomainXMLOptionPtr
virQEMUDriverCreateXMLConf(virQEMUDriverPtr driver)
{
    virQEMUDriverDomainDefParserConfig.priv = driver;
    return virDomainXMLOptionNew(&virQEMUDriverDomainDefParserConfig,
                                 &virQEMUDriverPrivateDataCallbacks,
                                 &virQEMUDriverDomainXMLNamespace);
}


virCapsPtr virQEMUDriverCreateCapabilities(virQEMUDriverPtr driver)
{
    size_t i, j;
    virCapsPtr caps;
    virSecurityManagerPtr *sec_managers = NULL;
    /* Security driver data */
    const char *doi, *model, *lbl, *type;
    virQEMUDriverConfigPtr cfg = virQEMUDriverGetConfig(driver);
    const int virtTypes[] = {VIR_DOMAIN_VIRT_KVM,
                             VIR_DOMAIN_VIRT_QEMU,};

    /* Basic host arch / guest machine capabilities */
    if (!(caps = virQEMUCapsInit(driver->qemuCapsCache)))
        goto error;

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
        goto error;

    for (i = 0; sec_managers[i]; i++) {
        virCapsHostSecModelPtr sm = &caps->host.secModels[i];
        doi = virSecurityManagerGetDOI(sec_managers[i]);
        model = virSecurityManagerGetModel(sec_managers[i]);
        if (VIR_STRDUP(sm->model, model) < 0 ||
            VIR_STRDUP(sm->doi, doi) < 0)
            goto error;

        for (j = 0; j < ARRAY_CARDINALITY(virtTypes); j++) {
            lbl = virSecurityManagerGetBaseLabel(sec_managers[i], virtTypes[j]);
            type = virDomainVirtTypeToString(virtTypes[j]);
            if (lbl &&
                virCapabilitiesHostSecModelAddBaseLabel(sm, type, lbl) < 0)
                goto error;
        }

        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    }
    VIR_FREE(sec_managers);

    virObjectUnref(cfg);
    return caps;

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

    if (driver->caps->nguests == 0 && !refresh) {
        VIR_DEBUG("Capabilities didn't detect any guests. Forcing a "
            "refresh.");
        qemuDriverUnlock(driver);
        return virQEMUDriverGetCapabilities(driver, true);
    }

    ret = virObjectRef(driver->caps);
    qemuDriverUnlock(driver);
    return ret;
}

struct _qemuSharedDeviceEntry {
    size_t ref;
    char **domains; /* array of domain names */
};

/* Construct the hash key for sharedDevices as "major:minor" */
char *
qemuGetSharedDeviceKey(const char *device_path)
{
    int maj, min;
    char *key = NULL;
    int rc;

    if ((rc = virGetDeviceID(device_path, &maj, &min)) < 0) {
        virReportSystemError(-rc,
                             _("Unable to get minor number of device '%s'"),
                             device_path);
        return NULL;
    }

    if (virAsprintf(&key, "%d:%d", maj, min) < 0)
        return NULL;

    return key;
}

/*
 * Make necessary checks for the need to check and for the current setting
 * of the 'unpriv_sgio' value for the device_path passed.
 *
 * Returns:
 *  0 - Success
 * -1 - Some failure which would already have been messaged
 * -2 - Mismatch with the "shared" sgio setting - needs to be messaged
 *      by caller since it has context of which type of disk resource is
 *      being used and in the future the hostdev information.
 */
static int
qemuCheckUnprivSGIO(virHashTablePtr sharedDevices,
                    const char *device_path,
                    int sgio)
{
    char *sysfs_path = NULL;
    char *key = NULL;
    int val;
    int ret = -1;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(device_path, NULL)))
        goto cleanup;

    /* It can't be conflict if unpriv_sgio is not supported by kernel. */
    if (!virFileExists(sysfs_path)) {
        ret = 0;
        goto cleanup;
    }

    if (!(key = qemuGetSharedDeviceKey(device_path)))
        goto cleanup;

    /* It can't be conflict if no other domain is sharing it. */
    if (!(virHashLookup(sharedDevices, key))) {
        ret = 0;
        goto cleanup;
    }

    if (virGetDeviceUnprivSGIO(device_path, NULL, &val) < 0)
        goto cleanup;

    /* Error message on failure needs to be handled in caller
     * since there is more specific knowledge of device
     */
    if (!((val == 0 &&
           (sgio == VIR_DOMAIN_DEVICE_SGIO_FILTERED ||
            sgio == VIR_DOMAIN_DEVICE_SGIO_DEFAULT)) ||
          (val == 1 &&
           sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED))) {
        ret = -2;
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(sysfs_path);
    VIR_FREE(key);
    return ret;
}


/* Check if a shared device's setting conflicts with the conf
 * used by other domain(s). Currently only checks the sgio
 * setting. Note that this should only be called for disk with
 * block source if the device type is disk.
 *
 * Returns 0 if no conflicts, otherwise returns -1.
 */
static int
qemuCheckSharedDisk(virHashTablePtr sharedDevices,
                    virDomainDiskDefPtr disk)
{
    int ret;

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN)
        return 0;

    if ((ret = qemuCheckUnprivSGIO(sharedDevices, disk->src->path,
                                   disk->sgio)) < 0) {
        if (ret == -2) {
            if (virDomainDiskGetType(disk) == VIR_STORAGE_TYPE_VOLUME) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("sgio of shared disk 'pool=%s' 'volume=%s' "
                                 "conflicts with other active domains"),
                               disk->src->srcpool->pool,
                               disk->src->srcpool->volume);
            } else {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("sgio of shared disk '%s' conflicts with "
                                 "other active domains"),
                               disk->src->path);
            }
        }
        return -1;
    }

    return 0;
}


bool
qemuSharedDeviceEntryDomainExists(qemuSharedDeviceEntryPtr entry,
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
qemuSharedDeviceEntryFree(void *payload, const void *name ATTRIBUTE_UNUSED)
{
    qemuSharedDeviceEntryPtr entry = payload;
    size_t i;

    if (!entry)
        return;

    for (i = 0; i < entry->ref; i++)
        VIR_FREE(entry->domains[i]);
    VIR_FREE(entry->domains);
    VIR_FREE(entry);
}


static int
qemuSharedDeviceEntryInsert(virQEMUDriverPtr driver,
                            const char *key,
                            const char *name)
{
    qemuSharedDeviceEntry *entry = NULL;

    if ((entry = virHashLookup(driver->sharedDevices, key))) {
        /* Nothing to do if the shared scsi host device is already
         * recorded in the table.
         */
        if (!qemuSharedDeviceEntryDomainExists(entry, name, NULL)) {
            if (VIR_EXPAND_N(entry->domains, entry->ref, 1) < 0 ||
                VIR_STRDUP(entry->domains[entry->ref - 1], name) < 0) {
                /* entry is owned by the hash table here */
                entry = NULL;
                goto error;
            }
        }
    } else {
        if (VIR_ALLOC(entry) < 0 ||
            VIR_ALLOC_N(entry->domains, 1) < 0 ||
            VIR_STRDUP(entry->domains[0], name) < 0)
            goto error;

        entry->ref = 1;

        if (virHashAddEntry(driver->sharedDevices, key, entry))
            goto error;
    }

    return 0;

 error:
    qemuSharedDeviceEntryFree(entry, NULL);
    return -1;
}


/* qemuAddSharedDisk:
 * @driver: Pointer to qemu driver struct
 * @src: disk source
 * @name: The domain name
 *
 * Increase ref count and add the domain name into the list which
 * records all the domains that use the shared device if the entry
 * already exists, otherwise add a new entry.
 */
static int
qemuAddSharedDisk(virQEMUDriverPtr driver,
                  virDomainDiskDefPtr disk,
                  const char *name)
{
    char *key = NULL;
    int ret = -1;

    if (!disk->src->shared || !virDomainDiskSourceIsBlockType(disk->src, false))
        return 0;

    qemuDriverLock(driver);

    if (qemuCheckSharedDisk(driver->sharedDevices, disk) < 0)
        goto cleanup;

    if (!(key = qemuGetSharedDeviceKey(virDomainDiskGetSource(disk))))
        goto cleanup;

    if (qemuSharedDeviceEntryInsert(driver, key, name) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    qemuDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}


static bool
qemuIsSharedHostdev(virDomainHostdevDefPtr hostdev)
{
    return (hostdev->shareable &&
        (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
         hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI &&
         hostdev->source.subsys.u.scsi.protocol !=
         VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI));
}


static char *
qemuGetHostdevPath(virDomainHostdevDefPtr hostdev)
{
    virDomainHostdevSubsysSCSIPtr scsisrc = &hostdev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIHostPtr scsihostsrc = &scsisrc->u.host;
    char *dev_name = NULL;
    char *dev_path = NULL;

    if (!(dev_name = virSCSIDeviceGetDevName(NULL,
                                             scsihostsrc->adapter,
                                             scsihostsrc->bus,
                                             scsihostsrc->target,
                                             scsihostsrc->unit)))
        goto cleanup;

    ignore_value(virAsprintf(&dev_path, "/dev/%s", dev_name));

 cleanup:
    VIR_FREE(dev_name);
    return dev_path;
}


static int
qemuAddSharedHostdev(virQEMUDriverPtr driver,
                     virDomainHostdevDefPtr hostdev,
                     const char *name)
{
    char *dev_path = NULL;
    char *key = NULL;
    int ret = -1;

    if (!qemuIsSharedHostdev(hostdev))
        return 0;

    if (!(dev_path = qemuGetHostdevPath(hostdev)))
        goto cleanup;

    if (!(key = qemuGetSharedDeviceKey(dev_path)))
        goto cleanup;

    qemuDriverLock(driver);
    ret = qemuSharedDeviceEntryInsert(driver, key, name);
    qemuDriverUnlock(driver);

 cleanup:
    VIR_FREE(dev_path);
    VIR_FREE(key);
    return ret;
}


static int
qemuSharedDeviceEntryRemove(virQEMUDriverPtr driver,
                            const char *key,
                            const char *name)
{
    qemuSharedDeviceEntryPtr entry = NULL;
    int idx;

    if (!(entry = virHashLookup(driver->sharedDevices, key)))
        return -1;

    /* Nothing to do if the shared disk is not recored in the table. */
    if (!qemuSharedDeviceEntryDomainExists(entry, name, &idx))
        return 0;

    if (entry->ref != 1)
        VIR_DELETE_ELEMENT(entry->domains, idx, entry->ref);
    else
        ignore_value(virHashRemoveEntry(driver->sharedDevices, key));

    return 0;
}


/* qemuAddSharedDevice:
 * @driver: Pointer to qemu driver struct
 * @dev: The device def
 * @name: The domain name
 *
 * Increase ref count and add the domain name into the list which
 * records all the domains that use the shared device if the entry
 * already exists, otherwise add a new entry.
 */
int
qemuAddSharedDevice(virQEMUDriverPtr driver,
                    virDomainDeviceDefPtr dev,
                    const char *name)
{
    /* Currently the only conflicts we have to care about for
     * the shared disk and shared host device is "sgio" setting,
     * which is only valid for block disk and scsi host device.
     */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK)
        return qemuAddSharedDisk(driver, dev->data.disk, name);
    else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV)
        return qemuAddSharedHostdev(driver, dev->data.hostdev, name);
    else
        return 0;
}


int
qemuRemoveSharedDisk(virQEMUDriverPtr driver,
                     virDomainDiskDefPtr disk,
                     const char *name)
{
    char *key = NULL;
    int ret = -1;

    if (!disk->src->shared || !virDomainDiskSourceIsBlockType(disk->src, false))
        return 0;

    qemuDriverLock(driver);

    if (!(key = qemuGetSharedDeviceKey(virDomainDiskGetSource(disk))))
        goto cleanup;

    if (qemuSharedDeviceEntryRemove(driver, key, name) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    qemuDriverUnlock(driver);
    VIR_FREE(key);
    return ret;
}


static int
qemuRemoveSharedHostdev(virQEMUDriverPtr driver,
                        virDomainHostdevDefPtr hostdev,
                        const char *name)
{
    char *dev_path = NULL;
    char *key = NULL;
    int ret = -1;

    if (!qemuIsSharedHostdev(hostdev))
        return 0;

    if (!(dev_path = qemuGetHostdevPath(hostdev)))
        goto cleanup;

    if (!(key = qemuGetSharedDeviceKey(dev_path)))
        goto cleanup;

    qemuDriverLock(driver);
    ret = qemuSharedDeviceEntryRemove(driver, key, name);
    qemuDriverUnlock(driver);

 cleanup:
    VIR_FREE(dev_path);
    VIR_FREE(key);
    return ret;
}


/* qemuRemoveSharedDevice:
 * @driver: Pointer to qemu driver struct
 * @device: The device def
 * @name: The domain name
 *
 * Decrease ref count and remove the domain name from the list which
 * records all the domains that use the shared device if ref is not
 * 1, otherwise remove the entry.
 */
int
qemuRemoveSharedDevice(virQEMUDriverPtr driver,
                       virDomainDeviceDefPtr dev,
                       const char *name)
{
    if (dev->type == VIR_DOMAIN_DEVICE_DISK)
        return qemuRemoveSharedDisk(driver, dev->data.disk, name);
    else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV)
        return qemuRemoveSharedHostdev(driver, dev->data.hostdev, name);
    else
        return 0;
}


int
qemuSetUnprivSGIO(virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    char *sysfs_path = NULL;
    const char *path = NULL;
    int val = -1;
    int ret = -1;

    /* "sgio" is only valid for block disk; cdrom
     * and floopy disk can have empty source.
     */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        disk = dev->data.disk;

        if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN ||
            !virDomainDiskSourceIsBlockType(disk->src, false))
            return 0;

        path = virDomainDiskGetSource(disk);
    } else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV) {
        hostdev = dev->data.hostdev;

        if (!qemuIsSharedHostdev(hostdev))
            return 0;

        if (hostdev->source.subsys.u.scsi.sgio) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("'sgio' is not supported for SCSI "
                             "generic device yet "));
            goto cleanup;
        }

        return 0;
    } else {
        return 0;
    }

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(path, NULL)))
        goto cleanup;

    /* By default, filter the SG_IO commands, i.e. set unpriv_sgio to 0.  */
    val = (disk->sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED);

    /* Do not do anything if unpriv_sgio is not supported by the kernel and the
     * whitelist is enabled.  But if requesting unfiltered access, always call
     * virSetDeviceUnprivSGIO, to report an error for unsupported unpriv_sgio.
     */
    if ((virFileExists(sysfs_path) || val == 1) &&
        virSetDeviceUnprivSGIO(path, NULL, val) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(sysfs_path);
    return ret;
}

int qemuDriverAllocateID(virQEMUDriverPtr driver)
{
    return virAtomicIntInc(&driver->lastvmid);
}


int
qemuTranslateSnapshotDiskSourcePool(virConnectPtr conn ATTRIBUTE_UNUSED,
                                    virDomainSnapshotDiskDefPtr def)
{
    if (def->src->type != VIR_STORAGE_TYPE_VOLUME)
        return 0;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Snapshots are not yet supported with 'pool' volumes"));
    return -1;
}

char *
qemuGetHugepagePath(virHugeTLBFSPtr hugepage)
{
    char *ret;

    if (virAsprintf(&ret, "%s/libvirt/qemu", hugepage->mnt_dir) < 0)
        return NULL;

    return ret;
}

char *
qemuGetDefaultHugepath(virHugeTLBFSPtr hugetlbfs,
                       size_t nhugetlbfs)
{
    size_t i;

    for (i = 0; i < nhugetlbfs; i++)
        if (hugetlbfs[i].deflt)
            break;

    if (i == nhugetlbfs)
        i = 0;

    return qemuGetHugepagePath(&hugetlbfs[i]);
}
