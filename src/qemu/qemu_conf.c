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
#include "qemu_capabilities.h"
#include "qemu_domain.h"
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

/* These are only defaults, they can be changed now in qemu.conf and
 * explicitly specified port is checked against these two (makes
 * sense to limit the values).
 *
 * This limitation is mentioned in qemu.conf, so bear in mind that the
 * configuration file should reflect any changes made to these values.
 */
#define QEMU_REMOTE_PORT_MIN 5900
#define QEMU_REMOTE_PORT_MAX 65535

#define QEMU_WEBSOCKET_PORT_MIN 5700
#define QEMU_WEBSOCKET_PORT_MAX 65535

#define QEMU_MIGRATION_PORT_MIN 49152
#define QEMU_MIGRATION_PORT_MAX 49215

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


#define VIR_QEMU_OVMF_LOADER_PATH "/usr/share/OVMF/OVMF_CODE.fd"
#define VIR_QEMU_OVMF_NVRAM_PATH "/usr/share/OVMF/OVMF_VARS.fd"
#define VIR_QEMU_OVMF_SEC_LOADER_PATH "/usr/share/OVMF/OVMF_CODE.secboot.fd"
#define VIR_QEMU_OVMF_SEC_NVRAM_PATH "/usr/share/OVMF/OVMF_VARS.fd"
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

    /* Set the default directory to find TLS X.509 certificates.
     * This will then be used as a fallback if the service specific
     * directory doesn't exist (although we don't check if this exists).
     */
    if (VIR_STRDUP(cfg->defaultTLSx509certdir,
                   SYSCONFDIR "/pki/qemu") < 0)
        goto error;

    if (VIR_STRDUP(cfg->vncListen, "127.0.0.1") < 0)
        goto error;

    if (VIR_STRDUP(cfg->spiceListen, "127.0.0.1") < 0)
        goto error;

    /*
     * If a "SYSCONFDIR" + "pki/libvirt-<val>" exists, then assume someone
     * has created a val specific area to place service specific certificates.
     *
     * If the service specific directory doesn't exist, 'assume' that the
     * user has created and populated the "SYSCONFDIR" + "pki/libvirt-default".
     */
#define SET_TLS_X509_CERT_DEFAULT(val)                                 \
    do {                                                               \
        if (virFileExists(SYSCONFDIR "/pki/libvirt-"#val)) {           \
            if (VIR_STRDUP(cfg->val ## TLSx509certdir,                 \
                           SYSCONFDIR "/pki/libvirt-"#val) < 0)        \
                goto error;                                            \
        } else {                                                       \
            if (VIR_STRDUP(cfg->val ## TLSx509certdir,                 \
                           cfg->defaultTLSx509certdir) < 0)            \
                goto error;                                            \
        }                                                              \
    } while (false);

    SET_TLS_X509_CERT_DEFAULT(vnc);
    SET_TLS_X509_CERT_DEFAULT(spice);
    SET_TLS_X509_CERT_DEFAULT(chardev);

#undef SET_TLS_X509_CERT_DEFAULT

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
    cfg->glusterDebugLevel = 4;
    cfg->stdioLogD = true;

    if (!(cfg->namespaces = virBitmapNew(QEMU_DOMAIN_NS_LAST)))
        goto error;

#if defined(__linux__)
    if (privileged &&
        virProcessNamespaceAvailable(VIR_PROCESS_NAMESPACE_MNT) == 0 &&
        virBitmapSetBit(cfg->namespaces, QEMU_DOMAIN_NS_MOUNT) < 0)
        goto error;
#endif /* defined(__linux__) */

#ifdef DEFAULT_LOADER_NVRAM
    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0)
        goto error;

#else
    if (VIR_ALLOC_N(cfg->firmwares, 3) < 0)
        goto error;
    cfg->nfirmwares = 3;
    if (VIR_ALLOC(cfg->firmwares[0]) < 0 || VIR_ALLOC(cfg->firmwares[1]) < 0 ||
        VIR_ALLOC(cfg->firmwares[2]) < 0)
        goto error;

    if (VIR_STRDUP(cfg->firmwares[0]->name, VIR_QEMU_AAVMF_LOADER_PATH) < 0 ||
        VIR_STRDUP(cfg->firmwares[0]->nvram, VIR_QEMU_AAVMF_NVRAM_PATH) < 0  ||
        VIR_STRDUP(cfg->firmwares[1]->name, VIR_QEMU_OVMF_LOADER_PATH) < 0 ||
        VIR_STRDUP(cfg->firmwares[1]->nvram, VIR_QEMU_OVMF_NVRAM_PATH) < 0 ||
        VIR_STRDUP(cfg->firmwares[2]->name, VIR_QEMU_OVMF_SEC_LOADER_PATH) < 0 ||
        VIR_STRDUP(cfg->firmwares[2]->nvram, VIR_QEMU_OVMF_SEC_NVRAM_PATH) < 0)
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

    virBitmapFree(cfg->namespaces);

    virStringListFree(cfg->cgroupDeviceACL);

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

    VIR_FREE(cfg->defaultTLSx509certdir);
    VIR_FREE(cfg->defaultTLSx509secretUUID);

    VIR_FREE(cfg->vncTLSx509certdir);
    VIR_FREE(cfg->vncListen);
    VIR_FREE(cfg->vncPassword);
    VIR_FREE(cfg->vncSASLdir);

    VIR_FREE(cfg->spiceTLSx509certdir);
    VIR_FREE(cfg->spiceListen);
    VIR_FREE(cfg->spicePassword);
    VIR_FREE(cfg->spiceSASLdir);

    VIR_FREE(cfg->chardevTLSx509certdir);
    VIR_FREE(cfg->chardevTLSx509secretUUID);

    while (cfg->nhugetlbfs) {
        cfg->nhugetlbfs--;
        VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
    }
    VIR_FREE(cfg->hugetlbfs);
    VIR_FREE(cfg->bridgeHelperName);

    VIR_FREE(cfg->saveImageFormat);
    VIR_FREE(cfg->dumpImageFormat);
    VIR_FREE(cfg->autoDumpPath);

    virStringListFree(cfg->securityDriverNames);

    VIR_FREE(cfg->lockManagerName);

    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);
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


int virQEMUDriverConfigLoadFile(virQEMUDriverConfigPtr cfg,
                                const char *filename)
{
    virConfPtr conf = NULL;
    int ret = -1;
    int rv;
    size_t i, j;
    char *stdioHandler = NULL;
    char *user = NULL, *group = NULL;
    char **controllers = NULL;
    char **hugetlbfs = NULL;
    char **nvram = NULL;
    char *corestr = NULL;
    char **namespaces = NULL;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        goto cleanup;

    if (virConfGetValueString(conf, "default_tls_x509_cert_dir", &cfg->defaultTLSx509certdir) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "default_tls_x509_verify", &cfg->defaultTLSx509verify) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "default_tls_x509_secret_uuid",
                              &cfg->defaultTLSx509secretUUID) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "vnc_auto_unix_socket", &cfg->vncAutoUnixSocket) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "vnc_tls", &cfg->vncTLS) < 0)
        goto cleanup;
    if ((rv = virConfGetValueBool(conf, "vnc_tls_x509_verify", &cfg->vncTLSx509verify)) < 0)
        goto cleanup;
    if (rv == 0)
        cfg->vncTLSx509verify = cfg->defaultTLSx509verify;
    if (virConfGetValueString(conf, "vnc_tls_x509_cert_dir", &cfg->vncTLSx509certdir) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "vnc_listen", &cfg->vncListen) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "vnc_password", &cfg->vncPassword) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "vnc_sasl", &cfg->vncSASL) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "vnc_sasl_dir", &cfg->vncSASLdir) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "vnc_allow_host_audio", &cfg->vncAllowHostAudio) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "nographics_allow_host_audio", &cfg->nogfxAllowHostAudio) < 0)
        goto cleanup;


    if (virConfGetValueStringList(conf, "security_driver", true, &cfg->securityDriverNames) < 0)
        goto cleanup;

    for (i = 0; cfg->securityDriverNames && cfg->securityDriverNames[i] != NULL; i++) {
        for (j = i + 1; cfg->securityDriverNames[j] != NULL; j++) {
            if (STREQ(cfg->securityDriverNames[i],
                      cfg->securityDriverNames[j])) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Duplicate security driver %s"),
                               cfg->securityDriverNames[i]);
                goto cleanup;
            }
        }
    }

    if (virConfGetValueBool(conf, "security_default_confined", &cfg->securityDefaultConfined) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "security_require_confined", &cfg->securityRequireConfined) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "spice_tls", &cfg->spiceTLS) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "spice_tls_x509_cert_dir", &cfg->spiceTLSx509certdir) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "spice_sasl", &cfg->spiceSASL) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "spice_sasl_dir", &cfg->spiceSASLdir) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "spice_listen", &cfg->spiceListen) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "spice_password", &cfg->spicePassword) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "spice_auto_unix_socket", &cfg->spiceAutoUnixSocket) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "chardev_tls", &cfg->chardevTLS) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "chardev_tls_x509_cert_dir", &cfg->chardevTLSx509certdir) < 0)
        goto cleanup;
    if ((rv = virConfGetValueBool(conf, "chardev_tls_x509_verify", &cfg->chardevTLSx509verify)) < 0)
        goto cleanup;
    if (rv == 0)
        cfg->chardevTLSx509verify = cfg->defaultTLSx509verify;
    if (virConfGetValueString(conf, "chardev_tls_x509_secret_uuid",
                              &cfg->chardevTLSx509secretUUID) < 0)
        goto cleanup;
    if (!cfg->chardevTLSx509secretUUID && cfg->defaultTLSx509secretUUID) {
        if (VIR_STRDUP(cfg->chardevTLSx509secretUUID,
                       cfg->defaultTLSx509secretUUID) < 0)
            goto cleanup;
    }

    if (virConfGetValueUInt(conf, "remote_websocket_port_min", &cfg->webSocketPortMin) < 0)
        goto cleanup;
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

    if (virConfGetValueUInt(conf, "remote_websocket_port_max", &cfg->webSocketPortMax) < 0)
        goto cleanup;
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

    if (virConfGetValueUInt(conf, "remote_display_port_min", &cfg->remotePortMin) < 0)
        goto cleanup;
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

    if (virConfGetValueUInt(conf, "remote_display_port_max", &cfg->remotePortMax) < 0)
        goto cleanup;
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

    if (virConfGetValueUInt(conf, "migration_port_min", &cfg->migrationPortMin) < 0)
        goto cleanup;
    if (cfg->migrationPortMin <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: migration_port_min: port must be greater than 0"),
                        filename);
        goto cleanup;
    }

    if (virConfGetValueUInt(conf, "migration_port_max", &cfg->migrationPortMax) < 0)
        goto cleanup;
    if (cfg->migrationPortMax > 65535 ||
        cfg->migrationPortMax < cfg->migrationPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: migration_port_max: port must be between "
                          "the minimal port %d and 65535"),
                       filename, cfg->migrationPortMin);
        goto cleanup;
    }

    if (virConfGetValueString(conf, "user", &user) < 0)
        goto cleanup;
    if (user && virGetUserID(user, &cfg->user) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "group", &group) < 0)
        goto cleanup;
    if (group && virGetGroupID(group, &cfg->group) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "dynamic_ownership", &cfg->dynamicOwnership) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf,  "cgroup_controllers", false,
                                  &controllers) < 0)
        goto cleanup;

    if (controllers) {
        cfg-> cgroupControllers = 0;
        for (i = 0; controllers[i] != NULL; i++) {
            int ctl;
            if ((ctl = virCgroupControllerTypeFromString(controllers[i])) < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown cgroup controller '%s'"),
                               controllers[i]);
                goto cleanup;
            }
            cfg->cgroupControllers |= (1 << ctl);
        }
    }

    if (virConfGetValueStringList(conf,  "cgroup_device_acl", false,
                                  &cfg->cgroupDeviceACL) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "save_image_format", &cfg->saveImageFormat) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "dump_image_format", &cfg->dumpImageFormat) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "snapshot_image_format", &cfg->snapshotImageFormat) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "auto_dump_path", &cfg->autoDumpPath) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "auto_dump_bypass_cache", &cfg->autoDumpBypassCache) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "auto_start_bypass_cache", &cfg->autoStartBypassCache) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "hugetlbfs_mount", true,
                                  &hugetlbfs) < 0)
        goto cleanup;
    if (hugetlbfs) {
        /* There already might be something autodetected. Avoid leaking it. */
        while (cfg->nhugetlbfs) {
            cfg->nhugetlbfs--;
            VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
        }
        VIR_FREE(cfg->hugetlbfs);

        cfg->nhugetlbfs = virStringListLength((const char *const *)hugetlbfs);
        if (hugetlbfs[0] &&
            VIR_ALLOC_N(cfg->hugetlbfs, cfg->nhugetlbfs) < 0)
            goto cleanup;

        for (i = 0; hugetlbfs[i] != NULL; i++) {
            if (virQEMUDriverConfigHugeTLBFSInit(&cfg->hugetlbfs[i],
                                                 hugetlbfs[i], i != 0) < 0)
                goto cleanup;
        }
    }

    if (virConfGetValueString(conf, "bridge_helper", &cfg->bridgeHelperName) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "mac_filter", &cfg->macFilter) < 0)
        goto cleanup;

    if (virConfGetValueBool(conf, "relaxed_acs_check", &cfg->relaxedACS) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "clear_emulator_capabilities", &cfg->clearEmulatorCapabilities) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "allow_disk_format_probing", &cfg->allowDiskFormatProbing) < 0)
        goto cleanup;
    if (virConfGetValueBool(conf, "set_process_name", &cfg->setProcessName) < 0)
        goto cleanup;
    if (virConfGetValueUInt(conf, "max_processes", &cfg->maxProcesses) < 0)
        goto cleanup;
    if (virConfGetValueUInt(conf, "max_files", &cfg->maxFiles) < 0)
        goto cleanup;

    if (virConfGetValueType(conf, "max_core") == VIR_CONF_STRING) {
        if (virConfGetValueString(conf, "max_core", &corestr) < 0)
            goto cleanup;
        if (STREQ(corestr, "unlimited")) {
            cfg->maxCore = ULLONG_MAX;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown core size '%s'"),
                           corestr);
            goto cleanup;
        }
    } else if (virConfGetValueULLong(conf, "max_core", &cfg->maxCore) < 0) {
        goto cleanup;
    }

    if (virConfGetValueBool(conf, "dump_guest_core", &cfg->dumpGuestCore) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "lock_manager", &cfg->lockManagerName) < 0)
        goto cleanup;
    if (virConfGetValueString(conf, "stdio_handler", &stdioHandler) < 0)
        goto cleanup;
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
    }

    if (virConfGetValueUInt(conf, "max_queued", &cfg->maxQueuedJobs) < 0)
        goto cleanup;

    if (virConfGetValueInt(conf, "keepalive_interval", &cfg->keepAliveInterval) < 0)
        goto cleanup;
    if (virConfGetValueUInt(conf, "keepalive_count", &cfg->keepAliveCount) < 0)
        goto cleanup;

    if (virConfGetValueInt(conf, "seccomp_sandbox", &cfg->seccompSandbox) < 0)
        goto cleanup;

    if (virConfGetValueString(conf, "migration_host", &cfg->migrateHost) < 0)
        goto cleanup;
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

    if (virConfGetValueString(conf, "migration_address", &cfg->migrationAddress) < 0)
        goto cleanup;
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

    if (virConfGetValueBool(conf, "log_timestamp", &cfg->logTimestamp) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "nvram", false, &nvram) < 0)
        goto cleanup;
    if (nvram) {
        virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

        cfg->nfirmwares = virStringListLength((const char *const *)nvram);
        if (nvram[0] && VIR_ALLOC_N(cfg->firmwares, cfg->nfirmwares) < 0)
            goto cleanup;

        for (i = 0; nvram[i] != NULL; i++) {
            if (VIR_ALLOC(cfg->firmwares[i]) < 0)
                goto cleanup;
            if (virFirmwareParse(nvram[i], cfg->firmwares[i]) < 0)
                goto cleanup;
        }
    }
    if (virConfGetValueUInt(conf, "gluster_debug_level", &cfg->glusterDebugLevel) < 0)
        goto cleanup;

    if (virConfGetValueStringList(conf, "namespaces", false, &namespaces) < 0)
        goto cleanup;

    if (namespaces) {
        virBitmapClearAll(cfg->namespaces);

        for (i = 0; namespaces[i]; i++) {
            int ns = qemuDomainNamespaceTypeFromString(namespaces[i]);

            if (ns < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown namespace: %s"),
                               namespaces[i]);
                goto cleanup;
            }

            if (virBitmapSetBit(cfg->namespaces, ns) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to enable namespace: %s"),
                               namespaces[i]);
                goto cleanup;
            }
        }
    }

    ret = 0;

 cleanup:
    virStringListFree(controllers);
    virStringListFree(hugetlbfs);
    virStringListFree(nvram);
    VIR_FREE(corestr);
    VIR_FREE(user);
    VIR_FREE(group);
    virConfFree(conf);
    return ret;
}

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

    if (virStorageSourceIsEmpty(disk->src) ||
        !disk->src->shared ||
        !virStorageSourceIsBlockLocal(disk->src))
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
            (virHostdevIsSCSIDevice(hostdev) &&
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

    if (virStorageSourceIsEmpty(disk->src) ||
        !disk->src->shared ||
        !virStorageSourceIsBlockLocal(disk->src))
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
            !virStorageSourceIsBlockLocal(disk->src))
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
qemuGetBaseHugepagePath(virHugeTLBFSPtr hugepage)
{
    char *ret;

    if (virAsprintf(&ret, "%s/libvirt/qemu", hugepage->mnt_dir) < 0)
        return NULL;

    return ret;
}


char *
qemuGetDomainHugepagePath(const virDomainDef *def,
                          virHugeTLBFSPtr hugepage)
{
    char *base = qemuGetBaseHugepagePath(hugepage);
    char *domPath = virDomainObjGetShortName(def);
    char *ret = NULL;

    if (base && domPath)
        ignore_value(virAsprintf(&ret, "%s/%s", base, domPath));
    VIR_FREE(domPath);
    VIR_FREE(base);
    return ret;
}


/**
 * qemuGetDomainDefaultHugepath:
 * @def: domain definition
 * @hugetlbfs: array of configured hugepages
 * @nhugetlbfs: number of item in the array
 *
 * Callers must ensure that @hugetlbfs contains at least one entry.
 *
 * Returns 0 on success, -1 otherwise.
 * */
char *
qemuGetDomainDefaultHugepath(const virDomainDef *def,
                             virHugeTLBFSPtr hugetlbfs,
                             size_t nhugetlbfs)
{
    size_t i;

    for (i = 0; i < nhugetlbfs; i++)
        if (hugetlbfs[i].deflt)
            break;

    if (i == nhugetlbfs)
        i = 0;

    return qemuGetDomainHugepagePath(def, &hugetlbfs[i]);
}


/**
 * qemuGetDomainHupageMemPath: Construct HP enabled memory backend path
 *
 * If no specific hugepage size is requested (@pagesize is zero)
 * the default hugepage size is used).
 * The resulting path is stored at @memPath.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
int
qemuGetDomainHupageMemPath(const virDomainDef *def,
                           virQEMUDriverConfigPtr cfg,
                           unsigned long long pagesize,
                           char **memPath)
{
    size_t i = 0;

    if (!cfg->nhugetlbfs) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("hugetlbfs filesystem is not mounted "
                               "or disabled by administrator config"));
        return -1;
    }

    if (!pagesize) {
        if (!(*memPath = qemuGetDomainDefaultHugepath(def,
                                                      cfg->hugetlbfs,
                                                      cfg->nhugetlbfs)))
            return -1;
    } else {
        for (i = 0; i < cfg->nhugetlbfs; i++) {
            if (cfg->hugetlbfs[i].size == pagesize)
                break;
        }

        if (i == cfg->nhugetlbfs) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to find any usable hugetlbfs "
                             "mount for %llu KiB"),
                           pagesize);
            return -1;
        }

        if (!(*memPath = qemuGetDomainHugepagePath(def, &cfg->hugetlbfs[i])))
            return -1;
    }

    return 0;
}
