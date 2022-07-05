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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "virerror.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_firmware.h"
#include "qemu_namespace.h"
#include "qemu_security.h"
#include "viruuid.h"
#include "virconf.h"
#include "viralloc.h"
#include "virxml.h"
#include "virlog.h"
#include "cpu/cpu.h"
#include "domain_driver.h"
#include "virfile.h"
#include "virstring.h"
#include "virutil.h"
#include "configmake.h"
#include "security/security_util.h"

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

VIR_ENUM_IMPL(virQEMUSchedCore,
              QEMU_SCHED_CORE_LAST,
              "none",
              "vcpus",
              "emulator",
              "full");


static virClass *virQEMUDriverConfigClass;
static void virQEMUDriverConfigDispose(void *obj);

static int virQEMUConfigOnceInit(void)
{
    if (!VIR_CLASS_NEW(virQEMUDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUConfig);


#ifndef DEFAULT_LOADER_NVRAM
# define DEFAULT_LOADER_NVRAM \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd:" \
    "/usr/share/OVMF/OVMF_CODE.secboot.fd:/usr/share/OVMF/OVMF_VARS.fd:" \
    "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd:" \
    "/usr/share/AAVMF/AAVMF32_CODE.fd:/usr/share/AAVMF/AAVMF32_VARS.fd"
#endif


#define QEMU_BRIDGE_HELPER "qemu-bridge-helper"
#define QEMU_PR_HELPER "qemu-pr-helper"
#define QEMU_DBUS_DAEMON "dbus-daemon"


virQEMUDriverConfig *virQEMUDriverConfigNew(bool privileged,
                                            const char *root)
{
    g_autoptr(virQEMUDriverConfig) cfg = NULL;

    if (virQEMUConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virQEMUDriverConfigClass)))
        return NULL;

    if (root) {
        cfg->uri = g_strdup_printf("qemu:///embed?root=%s", root);
    } else {
        cfg->uri = g_strdup(privileged ? "qemu:///system" : "qemu:///session");
    }

    if (privileged) {
        if (virGetUserID(QEMU_USER, &cfg->user) < 0)
            return NULL;
        if (virGetGroupID(QEMU_GROUP, &cfg->group) < 0)
            return NULL;
    } else {
        cfg->user = (uid_t)-1;
        cfg->group = (gid_t)-1;
    }
    cfg->dynamicOwnership = privileged;

    if (privileged)
        cfg->rememberOwner = virSecurityXATTRNamespaceDefined();
    else
        cfg->rememberOwner = false;

    cfg->cgroupControllers = -1; /* -1 == auto-detect */

    if (root != NULL) {
        cfg->logDir = g_strdup_printf("%s/log/qemu", root);
        cfg->swtpmLogDir = g_strdup_printf("%s/log/swtpm", root);
        cfg->configBaseDir = g_strdup_printf("%s/etc", root);
        cfg->stateDir = g_strdup_printf("%s/run/qemu", root);
        cfg->swtpmStateDir = g_strdup_printf("%s/run/swtpm", root);
        cfg->channelTargetDir = g_strdup_printf("%s/channel", cfg->stateDir);
        cfg->cacheDir = g_strdup_printf("%s/cache/qemu", root);
        cfg->libDir = g_strdup_printf("%s/lib/qemu", root);
        cfg->swtpmStorageDir = g_strdup_printf("%s/lib/swtpm", root);

        cfg->saveDir = g_strdup_printf("%s/save", cfg->libDir);
        cfg->snapshotDir = g_strdup_printf("%s/snapshot", cfg->libDir);
        cfg->checkpointDir = g_strdup_printf("%s/checkpoint", cfg->libDir);
        cfg->autoDumpPath = g_strdup_printf("%s/dump", cfg->libDir);
        cfg->nvramDir = g_strdup_printf("%s/nvram", cfg->libDir);
        cfg->memoryBackingDir = g_strdup_printf("%s/ram", cfg->libDir);
    } else if (privileged) {
        cfg->logDir = g_strdup_printf("%s/log/libvirt/qemu", LOCALSTATEDIR);

        cfg->swtpmLogDir = g_strdup_printf("%s/log/swtpm/libvirt/qemu",
                                           LOCALSTATEDIR);

        cfg->configBaseDir = g_strdup(SYSCONFDIR "/libvirt");

        cfg->stateDir = g_strdup_printf("%s/libvirt/qemu", RUNSTATEDIR);
        cfg->swtpmStateDir = g_strdup_printf("%s/libvirt/qemu/swtpm", RUNSTATEDIR);
        cfg->channelTargetDir = g_strdup_printf("%s/channel", cfg->stateDir);

        cfg->cacheDir = g_strdup_printf("%s/cache/libvirt/qemu", LOCALSTATEDIR);

        cfg->libDir = g_strdup_printf("%s/lib/libvirt/qemu", LOCALSTATEDIR);
        cfg->saveDir = g_strdup_printf("%s/save", cfg->libDir);
        cfg->snapshotDir = g_strdup_printf("%s/snapshot", cfg->libDir);
        cfg->checkpointDir = g_strdup_printf("%s/checkpoint", cfg->libDir);
        cfg->autoDumpPath = g_strdup_printf("%s/dump", cfg->libDir);
        cfg->nvramDir = g_strdup_printf("%s/nvram", cfg->libDir);
        cfg->memoryBackingDir = g_strdup_printf("%s/ram", cfg->libDir);
        cfg->swtpmStorageDir = g_strdup_printf("%s/lib/libvirt/swtpm",
                                               LOCALSTATEDIR);
    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cachedir = NULL;

        cachedir = virGetUserCacheDirectory();

        cfg->logDir = g_strdup_printf("%s/qemu/log", cachedir);
        cfg->swtpmLogDir = g_strdup_printf("%s/qemu/log", cachedir);
        cfg->cacheDir = g_strdup_printf("%s/qemu/cache", cachedir);

        rundir = virGetUserRuntimeDirectory();
        cfg->stateDir = g_strdup_printf("%s/qemu/run", rundir);
        cfg->swtpmStateDir = g_strdup_printf("%s/swtpm", cfg->stateDir);
        cfg->channelTargetDir = g_strdup_printf("%s/channel", cfg->stateDir);

        cfg->configBaseDir = virGetUserConfigDirectory();

        cfg->libDir = g_strdup_printf("%s/qemu/lib", cfg->configBaseDir);
        cfg->saveDir = g_strdup_printf("%s/qemu/save", cfg->configBaseDir);
        cfg->snapshotDir = g_strdup_printf("%s/qemu/snapshot", cfg->configBaseDir);
        cfg->checkpointDir = g_strdup_printf("%s/qemu/checkpoint",
                                             cfg->configBaseDir);
        cfg->autoDumpPath = g_strdup_printf("%s/qemu/dump", cfg->configBaseDir);
        cfg->nvramDir = g_strdup_printf("%s/qemu/nvram", cfg->configBaseDir);
        cfg->memoryBackingDir = g_strdup_printf("%s/qemu/ram", cfg->configBaseDir);
        cfg->swtpmStorageDir = g_strdup_printf("%s/qemu/swtpm",
                                               cfg->configBaseDir);
    }

    if (privileged) {
        if (!virDoesUserExist("tss") ||
            virGetUserID("tss", &cfg->swtpm_user) < 0)
            cfg->swtpm_user = 0; /* fall back to root */
        if (!virDoesGroupExist("tss") ||
            virGetGroupID("tss", &cfg->swtpm_group) < 0)
            cfg->swtpm_group = 0; /* fall back to root */
    } else {
        cfg->swtpm_user = (uid_t)-1;
        cfg->swtpm_group = (gid_t)-1;
    }

    cfg->configDir = g_strdup_printf("%s/qemu", cfg->configBaseDir);
    cfg->autostartDir = g_strdup_printf("%s/qemu/autostart", cfg->configBaseDir);
    cfg->slirpStateDir = g_strdup_printf("%s/slirp", cfg->stateDir);
    cfg->passtStateDir = g_strdup_printf("%s/passt", cfg->stateDir);
    cfg->dbusStateDir = g_strdup_printf("%s/dbus", cfg->stateDir);

    /* Set the default directory to find TLS X.509 certificates.
     * This will then be used as a fallback if the service specific
     * directory doesn't exist (although we don't check if this exists).
     */
    if (root == NULL) {
        cfg->defaultTLSx509certdir = g_strdup(SYSCONFDIR "/pki/qemu");
    } else {
        cfg->defaultTLSx509certdir = g_strdup_printf("%s/etc/pki/qemu", root);
    }

    cfg->vncListen = g_strdup(VIR_LOOPBACK_IPV4_ADDR);
    cfg->spiceListen = g_strdup(VIR_LOOPBACK_IPV4_ADDR);

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
        if (virGetLastErrorCode() != VIR_ERR_NO_SUPPORT)
            return NULL;
    }

    cfg->bridgeHelperName = g_strdup(QEMU_BRIDGE_HELPER);
    cfg->prHelperName = g_strdup(QEMU_PR_HELPER);
    cfg->slirpHelperName = g_strdup(QEMU_SLIRP_HELPER);
    cfg->dbusDaemonName = g_strdup(QEMU_DBUS_DAEMON);

    cfg->securityDefaultConfined = true;
    cfg->securityRequireConfined = false;

    cfg->keepAliveInterval = 5;
    cfg->keepAliveCount = 5;
    cfg->seccompSandbox = -1;

    cfg->logTimestamp = true;
    cfg->glusterDebugLevel = 4;
    cfg->stdioLogD = true;

    cfg->namespaces = virBitmapNew(QEMU_DOMAIN_NS_LAST);

    if (privileged &&
        qemuDomainNamespaceAvailable(QEMU_DOMAIN_NS_MOUNT) &&
        virBitmapSetBit(cfg->namespaces, QEMU_DOMAIN_NS_MOUNT) < 0)
        return NULL;

    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0)
        return NULL;

    cfg->deprecationBehavior = g_strdup("none");

    return g_steal_pointer(&cfg);
}


static void virQEMUDriverConfigDispose(void *obj)
{
    virQEMUDriverConfig *cfg = obj;

    virBitmapFree(cfg->namespaces);

    g_strfreev(cfg->cgroupDeviceACL);
    g_free(cfg->uri);

    g_free(cfg->configBaseDir);
    g_free(cfg->configDir);
    g_free(cfg->autostartDir);
    g_free(cfg->logDir);
    g_free(cfg->swtpmLogDir);
    g_free(cfg->stateDir);
    g_free(cfg->swtpmStateDir);
    g_free(cfg->slirpStateDir);
    g_free(cfg->passtStateDir);
    g_free(cfg->dbusStateDir);

    g_free(cfg->libDir);
    g_free(cfg->cacheDir);
    g_free(cfg->saveDir);
    g_free(cfg->snapshotDir);
    g_free(cfg->checkpointDir);
    g_free(cfg->channelTargetDir);
    g_free(cfg->nvramDir);

    g_free(cfg->defaultTLSx509certdir);
    g_free(cfg->defaultTLSx509secretUUID);

    g_free(cfg->vncTLSx509certdir);
    g_free(cfg->vncTLSx509secretUUID);
    g_free(cfg->vncListen);
    g_free(cfg->vncPassword);
    g_free(cfg->vncSASLdir);

    g_free(cfg->spiceTLSx509certdir);
    g_free(cfg->spiceListen);
    g_free(cfg->spicePassword);
    g_free(cfg->spiceSASLdir);

    g_free(cfg->chardevTLSx509certdir);
    g_free(cfg->chardevTLSx509secretUUID);

    g_free(cfg->vxhsTLSx509certdir);
    g_free(cfg->vxhsTLSx509secretUUID);

    g_free(cfg->nbdTLSx509certdir);
    g_free(cfg->nbdTLSx509secretUUID);

    g_free(cfg->migrateTLSx509certdir);
    g_free(cfg->migrateTLSx509secretUUID);

    g_free(cfg->backupTLSx509certdir);
    g_free(cfg->backupTLSx509secretUUID);

    while (cfg->nhugetlbfs) {
        cfg->nhugetlbfs--;
        g_free(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
    }
    g_free(cfg->hugetlbfs);
    g_free(cfg->bridgeHelperName);
    g_free(cfg->prHelperName);
    g_free(cfg->slirpHelperName);
    g_free(cfg->dbusDaemonName);

    g_free(cfg->saveImageFormat);
    g_free(cfg->dumpImageFormat);
    g_free(cfg->snapshotImageFormat);
    g_free(cfg->autoDumpPath);

    g_strfreev(cfg->securityDriverNames);

    g_free(cfg->lockManagerName);

    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

    g_free(cfg->memoryBackingDir);
    g_free(cfg->swtpmStorageDir);

    g_strfreev(cfg->capabilityfilters);

    g_free(cfg->deprecationBehavior);
}


static int
virQEMUDriverConfigHugeTLBFSInit(virHugeTLBFS *hugetlbfs,
                                 const char *path,
                                 bool deflt)
{
    hugetlbfs->mnt_dir = g_strdup(path);
    if (virFileGetHugepageSize(path, &hugetlbfs->size) < 0)
        return -1;

    hugetlbfs->deflt = deflt;
    return 0;
}


static int
virQEMUDriverConfigLoadDefaultTLSEntry(virQEMUDriverConfig *cfg,
                                       virConf *conf)
{
    int rv;

    if ((rv = virConfGetValueString(conf, "default_tls_x509_cert_dir", &cfg->defaultTLSx509certdir)) < 0)
        return -1;
    cfg->defaultTLSx509certdirPresent = (rv == 1);
    if ((rv = virConfGetValueBool(conf, "default_tls_x509_verify", &cfg->defaultTLSx509verify)) < 0)
        return -1;
    if (rv == 1)
        cfg->defaultTLSx509verifyPresent = true;
    if (virConfGetValueString(conf, "default_tls_x509_secret_uuid",
                              &cfg->defaultTLSx509secretUUID) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadVNCEntry(virQEMUDriverConfig *cfg,
                                virConf *conf)
{
    int rv;

    if (virConfGetValueBool(conf, "vnc_auto_unix_socket", &cfg->vncAutoUnixSocket) < 0)
        return -1;
    if (virConfGetValueBool(conf, "vnc_tls", &cfg->vncTLS) < 0)
        return -1;
    if ((rv = virConfGetValueBool(conf, "vnc_tls_x509_verify", &cfg->vncTLSx509verify)) < 0)
        return -1;
    if (rv == 1)
        cfg->vncTLSx509verifyPresent = true;
    if (virConfGetValueString(conf, "vnc_tls_x509_cert_dir", &cfg->vncTLSx509certdir) < 0)
        return -1;
    if (virConfGetValueString(conf, "vnc_tls_x509_secret_uuid", &cfg->vncTLSx509secretUUID) < 0)
        return -1;
    if (virConfGetValueString(conf, "vnc_listen", &cfg->vncListen) < 0)
        return -1;
    if (virConfGetValueString(conf, "vnc_password", &cfg->vncPassword) < 0)
        return -1;
    if (virConfGetValueBool(conf, "vnc_sasl", &cfg->vncSASL) < 0)
        return -1;
    if (virConfGetValueString(conf, "vnc_sasl_dir", &cfg->vncSASLdir) < 0)
        return -1;
    if (virConfGetValueBool(conf, "vnc_allow_host_audio", &cfg->vncAllowHostAudio) < 0)
        return -1;

    if (cfg->vncPassword &&
        strlen(cfg->vncPassword) > 8) {
        VIR_WARN("VNC password is %zu characters long, only 8 permitted, truncating",
                 strlen(cfg->vncPassword));
        cfg->vncPassword[8] = '\0';
    }
    return 0;
}


static int
virQEMUDriverConfigLoadNographicsEntry(virQEMUDriverConfig *cfg,
                                       virConf *conf)
{
    return virConfGetValueBool(conf, "nographics_allow_host_audio", &cfg->nogfxAllowHostAudio);
}


static int
virQEMUDriverConfigLoadSPICEEntry(virQEMUDriverConfig *cfg,
                                  virConf *conf)
{
    if (virConfGetValueBool(conf, "spice_tls", &cfg->spiceTLS) < 0)
        return -1;
    if (virConfGetValueString(conf, "spice_tls_x509_cert_dir", &cfg->spiceTLSx509certdir) < 0)
        return -1;
    if (virConfGetValueBool(conf, "spice_sasl", &cfg->spiceSASL) < 0)
        return -1;
    if (virConfGetValueString(conf, "spice_sasl_dir", &cfg->spiceSASLdir) < 0)
        return -1;
    if (virConfGetValueString(conf, "spice_listen", &cfg->spiceListen) < 0)
        return -1;
    if (virConfGetValueString(conf, "spice_password", &cfg->spicePassword) < 0)
        return -1;
    if (virConfGetValueBool(conf, "spice_auto_unix_socket", &cfg->spiceAutoUnixSocket) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadSpecificTLSEntry(virQEMUDriverConfig *cfg,
                                        virConf *conf)
{
    int rv;

    if (virConfGetValueBool(conf, "vxhs_tls", &cfg->vxhsTLS) < 0)
        return -1;
    if (virConfGetValueBool(conf, "nbd_tls", &cfg->nbdTLS) < 0)
        return -1;
    if (virConfGetValueBool(conf, "chardev_tls", &cfg->chardevTLS) < 0)
        return -1;
    if (virConfGetValueBool(conf, "migrate_tls_force", &cfg->migrateTLSForce) < 0)
        return -1;

#define GET_CONFIG_TLS_CERTINFO_COMMON(val) \
    do { \
        if (virConfGetValueString(conf, #val "_tls_x509_cert_dir", \
                                  &cfg->val## TLSx509certdir) < 0) \
            return -1; \
        if (virConfGetValueString(conf, \
                                  #val "_tls_x509_secret_uuid", \
                                  &cfg->val## TLSx509secretUUID) < 0) \
            return -1; \
    } while (0)

#define GET_CONFIG_TLS_CERTINFO_SERVER(val) \
    do { \
        if ((rv = virConfGetValueBool(conf, #val "_tls_x509_verify", \
                                      &cfg->val## TLSx509verify)) < 0) \
            return -1; \
        if (rv == 1) \
            cfg->val## TLSx509verifyPresent = true; \
    } while (0)

    GET_CONFIG_TLS_CERTINFO_COMMON(chardev);
    GET_CONFIG_TLS_CERTINFO_SERVER(chardev);

    GET_CONFIG_TLS_CERTINFO_COMMON(migrate);
    GET_CONFIG_TLS_CERTINFO_SERVER(migrate);

    GET_CONFIG_TLS_CERTINFO_COMMON(backup);
    GET_CONFIG_TLS_CERTINFO_SERVER(backup);

    GET_CONFIG_TLS_CERTINFO_COMMON(vxhs);

    GET_CONFIG_TLS_CERTINFO_COMMON(nbd);

#undef GET_CONFIG_TLS_CERTINFO_COMMON
#undef GET_CONFIG_TLS_CERTINFO_SERVER
    return 0;
}


static int
virQEMUDriverConfigLoadRemoteDisplayEntry(virQEMUDriverConfig *cfg,
                                          virConf *conf,
                                          const char *filename)
{
    if (virConfGetValueUInt(conf, "remote_websocket_port_min", &cfg->webSocketPortMin) < 0)
        return -1;
    if (cfg->webSocketPortMin < QEMU_WEBSOCKET_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5700, e.g. localhost:1
         * for port 5701) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s: remote_websocket_port_min: port must be greater than or equal to %2$d"),
                        filename, QEMU_WEBSOCKET_PORT_MIN);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_websocket_port_max", &cfg->webSocketPortMax) < 0)
        return -1;
    if (cfg->webSocketPortMax > QEMU_WEBSOCKET_PORT_MAX ||
        cfg->webSocketPortMax < cfg->webSocketPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%1$s: remote_websocket_port_max: port must be between the minimal port and %2$d"),
                       filename, QEMU_WEBSOCKET_PORT_MAX);
        return -1;
    }

    if (cfg->webSocketPortMin > cfg->webSocketPortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%1$s: remote_websocket_port_min: min port must not be greater than max port"),
                        filename);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_display_port_min", &cfg->remotePortMin) < 0)
        return -1;
    if (cfg->remotePortMin < QEMU_REMOTE_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5900, e.g. localhost:1
         * for port 5901) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s: remote_display_port_min: port must be greater than or equal to %2$d"),
                        filename, QEMU_REMOTE_PORT_MIN);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_display_port_max", &cfg->remotePortMax) < 0)
        return -1;
    if (cfg->remotePortMax > QEMU_REMOTE_PORT_MAX ||
        cfg->remotePortMax < cfg->remotePortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%1$s: remote_display_port_max: port must be between the minimal port and %2$d"),
                       filename, QEMU_REMOTE_PORT_MAX);
        return -1;
    }

    if (cfg->remotePortMin > cfg->remotePortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%1$s: remote_display_port_min: min port must not be greater than max port"),
                        filename);
        return -1;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadSaveEntry(virQEMUDriverConfig *cfg,
                                 virConf *conf)
{
    if (virConfGetValueString(conf, "save_image_format", &cfg->saveImageFormat) < 0)
        return -1;
    if (virConfGetValueString(conf, "dump_image_format", &cfg->dumpImageFormat) < 0)
        return -1;
    if (virConfGetValueString(conf, "snapshot_image_format", &cfg->snapshotImageFormat) < 0)
        return -1;
    if (virConfGetValueString(conf, "auto_dump_path", &cfg->autoDumpPath) < 0)
        return -1;
    if (virConfGetValueBool(conf, "auto_dump_bypass_cache", &cfg->autoDumpBypassCache) < 0)
        return -1;
    if (virConfGetValueBool(conf, "auto_start_bypass_cache", &cfg->autoStartBypassCache) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadProcessEntry(virQEMUDriverConfig *cfg,
                                    virConf *conf)
{
    g_auto(GStrv) hugetlbfs = NULL;
    g_autofree char *stdioHandler = NULL;
    g_autofree char *corestr = NULL;
    g_autofree char *schedCore = NULL;
    size_t i;

    if (virConfGetValueStringList(conf, "hugetlbfs_mount", true,
                                  &hugetlbfs) < 0)
        return -1;
    if (hugetlbfs) {
        /* There already might be something autodetected. Avoid leaking it. */
        while (cfg->nhugetlbfs) {
            cfg->nhugetlbfs--;
            VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
        }
        VIR_FREE(cfg->hugetlbfs);

        cfg->nhugetlbfs = g_strv_length(hugetlbfs);
        if (hugetlbfs[0])
            cfg->hugetlbfs = g_new0(virHugeTLBFS, cfg->nhugetlbfs);

        for (i = 0; hugetlbfs[i] != NULL; i++) {
            if (virQEMUDriverConfigHugeTLBFSInit(&cfg->hugetlbfs[i],
                                                 hugetlbfs[i], i != 0) < 0)
                return -1;
        }
    }

    if (virConfGetValueString(conf, "bridge_helper", &cfg->bridgeHelperName) < 0)
        return -1;

    if (virConfGetValueString(conf, "pr_helper", &cfg->prHelperName) < 0)
        return -1;

    if (virConfGetValueString(conf, "slirp_helper", &cfg->slirpHelperName) < 0)
        return -1;

    if (virConfGetValueString(conf, "dbus_daemon", &cfg->dbusDaemonName) < 0)
        return -1;

    if (virConfGetValueBool(conf, "set_process_name", &cfg->setProcessName) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_processes", &cfg->maxProcesses) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_files", &cfg->maxFiles) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "max_threads_per_process", &cfg->maxThreadsPerProc) < 0)
        return -1;

    if (virConfGetValueType(conf, "max_core") == VIR_CONF_STRING) {
        if (virConfGetValueString(conf, "max_core", &corestr) < 0)
            return -1;
        if (STREQ(corestr, "unlimited")) {
            cfg->maxCore = ULLONG_MAX;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown core size '%1$s'"),
                           corestr);
            return -1;
        }
    } else if (virConfGetValueULLong(conf, "max_core", &cfg->maxCore) < 0) {
        return -1;
    }

    if (virConfGetValueBool(conf, "dump_guest_core", &cfg->dumpGuestCore) < 0)
        return -1;
    if (virConfGetValueString(conf, "stdio_handler", &stdioHandler) < 0)
        return -1;
    if (stdioHandler) {
        if (STREQ(stdioHandler, "logd")) {
            cfg->stdioLogD = true;
        } else if (STREQ(stdioHandler, "file")) {
            cfg->stdioLogD = false;
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown stdio handler %1$s"),
                           stdioHandler);
            return -1;
        }
    }

    if (virConfGetValueString(conf, "sched_core", &schedCore) < 0)
        return -1;
    if (schedCore) {
        int val = virQEMUSchedCoreTypeFromString(schedCore);

        if (val < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown sched_core value %1$s"),
                           schedCore);
            return -1;
        }

        if (val != QEMU_SCHED_CORE_NONE) {
            int rv = virProcessSchedCoreAvailable();

            if (rv < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to detect SCHED_CORE"));
                return -1;
            } else if (rv == 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SCHED_CORE not supported by kernel"));
                return -1;
            }
        }

        cfg->schedCore = val;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadDeviceEntry(virQEMUDriverConfig *cfg,
                                   virConf *conf)
{
    bool tmp;
    int rv;

    if (virConfGetValueBool(conf, "mac_filter", &cfg->macFilter) < 0)
        return -1;

    if (virConfGetValueBool(conf, "relaxed_acs_check", &cfg->relaxedACS) < 0)
        return -1;
    if (virConfGetValueString(conf, "lock_manager", &cfg->lockManagerName) < 0)
        return -1;
    if ((rv = virConfGetValueBool(conf, "allow_disk_format_probing", &tmp)) < 0)
        return -1;
    if (rv == 1 && tmp) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("allow_disk_format_probing is no longer supported"));
        return -1;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadRPCEntry(virQEMUDriverConfig *cfg,
                                virConf *conf)
{
    if (virConfGetValueUInt(conf, "max_queued", &cfg->maxQueuedJobs) < 0)
        return -1;
    if (virConfGetValueInt(conf, "keepalive_interval", &cfg->keepAliveInterval) < 0)
        return -1;
    if (virConfGetValueUInt(conf, "keepalive_count", &cfg->keepAliveCount) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadNetworkEntry(virQEMUDriverConfig *cfg,
                                    virConf *conf,
                                    const char *filename)
{
    if (virConfGetValueUInt(conf, "migration_port_min", &cfg->migrationPortMin) < 0)
        return -1;
    if (cfg->migrationPortMin <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s: migration_port_min: port must be greater than 0"),
                        filename);
        return -1;
    }

    if (virConfGetValueUInt(conf, "migration_port_max", &cfg->migrationPortMax) < 0)
        return -1;
    if (cfg->migrationPortMax > 65535 ||
        cfg->migrationPortMax < cfg->migrationPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%1$s: migration_port_max: port must be between the minimal port %2$d and 65535"),
                       filename, cfg->migrationPortMin);
        return -1;
    }

    if (virConfGetValueString(conf, "migration_host", &cfg->migrateHost) < 0)
        return -1;
    virStringStripIPv6Brackets(cfg->migrateHost);
    if (cfg->migrateHost &&
        (STRPREFIX(cfg->migrateHost, "localhost") ||
         virSocketAddrIsNumericLocalhost(cfg->migrateHost))) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migration_host must not be the address of the local machine: %1$s"),
                       cfg->migrateHost);
        return -1;
    }

    if (virConfGetValueString(conf, "migration_address", &cfg->migrationAddress) < 0)
        return -1;
    virStringStripIPv6Brackets(cfg->migrationAddress);
    if (cfg->migrationAddress &&
        (STRPREFIX(cfg->migrationAddress, "localhost") ||
         virSocketAddrIsNumericLocalhost(cfg->migrationAddress))) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migration_address must not be the address of the local machine: %1$s"),
                       cfg->migrationAddress);
        return -1;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadLogEntry(virQEMUDriverConfig *cfg,
                                virConf *conf)
{
    return virConfGetValueBool(conf, "log_timestamp", &cfg->logTimestamp);
}


static int
virQEMUDriverConfigLoadNVRAMEntry(virQEMUDriverConfig *cfg,
                                  virConf *conf,
                                  bool privileged)
{
    g_auto(GStrv) nvram = NULL;
    size_t i;

    if (virConfGetValueStringList(conf, "nvram", false, &nvram) < 0)
        return -1;
    if (nvram) {
        g_auto(GStrv) fwList = NULL;

        virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);
        cfg->firmwares = NULL;
        cfg->nfirmwares = 0;

        if (qemuFirmwareFetchConfigs(&fwList, privileged) < 0)
            return -1;

        if (fwList) {
            VIR_WARN("Obsolete nvram variable is set while firmware metadata "
                     "files found. Note that the nvram config file variable is "
                     "going to be ignored.");
            return 0;
        }

        cfg->nfirmwares = g_strv_length(nvram);
        cfg->firmwares = g_new0(virFirmware *, cfg->nfirmwares);

        for (i = 0; nvram[i] != NULL; i++) {
            cfg->firmwares[i] = g_new0(virFirmware, 1);
            if (virFirmwareParse(nvram[i], cfg->firmwares[i]) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virQEMUDriverConfigLoadDebugEntry(virQEMUDriverConfig *cfg,
                                  virConf *conf)
{
    if (virConfGetValueUInt(conf, "gluster_debug_level", &cfg->glusterDebugLevel) < 0)
        return -1;
    if (virConfGetValueBool(conf, "virtiofsd_debug", &cfg->virtiofsdDebug) < 0)
        return -1;
    if (virConfGetValueString(conf, "deprecation_behavior", &cfg->deprecationBehavior) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadSecurityEntry(virQEMUDriverConfig *cfg,
                                     virConf *conf,
                                     bool privileged)
{
    g_auto(GStrv) controllers = NULL;
    g_auto(GStrv) namespaces = NULL;
    g_autofree char *user = NULL;
    g_autofree char *group = NULL;
    size_t i, j;

    if (virConfGetValueStringList(conf, "security_driver", true, &cfg->securityDriverNames) < 0)
        return -1;

    for (i = 0; cfg->securityDriverNames && cfg->securityDriverNames[i] != NULL; i++) {
        for (j = i + 1; cfg->securityDriverNames[j] != NULL; j++) {
            if (STREQ(cfg->securityDriverNames[i],
                      cfg->securityDriverNames[j])) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Duplicate security driver %1$s"),
                               cfg->securityDriverNames[i]);
                return -1;
            }
        }
    }

    if (virConfGetValueBool(conf, "security_default_confined", &cfg->securityDefaultConfined) < 0)
        return -1;
    if (virConfGetValueBool(conf, "security_require_confined", &cfg->securityRequireConfined) < 0)
        return -1;

    if (virConfGetValueString(conf, "user", &user) < 0)
        return -1;
    if (user && virGetUserID(user, &cfg->user) < 0)
        return -1;

    if (virConfGetValueString(conf, "group", &group) < 0)
        return -1;
    if (group && virGetGroupID(group, &cfg->group) < 0)
        return -1;

    if (virConfGetValueBool(conf, "dynamic_ownership", &cfg->dynamicOwnership) < 0)
        return -1;

    if (virConfGetValueBool(conf, "remember_owner", &cfg->rememberOwner) < 0)
        return -1;

    if (virConfGetValueStringList(conf, "cgroup_controllers", false,
                                  &controllers) < 0)
        return -1;

    if (controllers) {
        cfg->cgroupControllers = 0;
        for (i = 0; controllers[i] != NULL; i++) {
            int ctl;
            if ((ctl = virCgroupControllerTypeFromString(controllers[i])) < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown cgroup controller '%1$s'"),
                               controllers[i]);
                return -1;
            }
            cfg->cgroupControllers |= (1 << ctl);
        }
    }

    if (virConfGetValueStringList(conf, "cgroup_device_acl", false,
                                  &cfg->cgroupDeviceACL) < 0)
        return -1;

    if (virConfGetValueInt(conf, "seccomp_sandbox", &cfg->seccompSandbox) < 0)
        return -1;

    if (virConfGetValueStringList(conf, "namespaces", false, &namespaces) < 0)
        return -1;

    if (namespaces) {
        virBitmapClearAll(cfg->namespaces);

        for (i = 0; namespaces[i]; i++) {
            int ns = qemuDomainNamespaceTypeFromString(namespaces[i]);

            if (ns < 0) {
                virReportError(VIR_ERR_CONF_SYNTAX,
                               _("Unknown namespace: %1$s"),
                               namespaces[i]);
                return -1;
            }

            if (!privileged) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("cannot use namespaces in session mode"));
                return -1;
            }

            if (!qemuDomainNamespaceAvailable(ns)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("%1$s namespace is not available"),
                               namespaces[i]);
                return -1;
            }

            if (virBitmapSetBit(cfg->namespaces, ns) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to enable namespace: %1$s"),
                               namespaces[i]);
                return -1;
            }
        }
    }

    return 0;
}


static int
virQEMUDriverConfigLoadMemoryEntry(virQEMUDriverConfig *cfg,
                                   virConf *conf)
{
    g_autofree char *dir = NULL;
    int rc;

    if ((rc = virConfGetValueString(conf, "memory_backing_dir", &dir)) < 0)
        return -1;

    if (rc > 0) {
        VIR_FREE(cfg->memoryBackingDir);
        cfg->memoryBackingDir = g_strdup_printf("%s/libvirt/qemu", dir);
    }

    return 0;
}


static int
virQEMUDriverConfigLoadSWTPMEntry(virQEMUDriverConfig *cfg,
                                  virConf *conf)
{
    g_autofree char *swtpm_user = NULL;
    g_autofree char *swtpm_group = NULL;

    if (virConfGetValueString(conf, "swtpm_user", &swtpm_user) < 0)
        return -1;
    if (swtpm_user && virGetUserID(swtpm_user, &cfg->swtpm_user) < 0)
        return -1;

    if (virConfGetValueString(conf, "swtpm_group", &swtpm_group) < 0)
        return -1;
    if (swtpm_group && virGetGroupID(swtpm_group, &cfg->swtpm_group) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadCapsFiltersEntry(virQEMUDriverConfig *cfg,
                                        virConf *conf)
{
    if (virConfGetValueStringList(conf, "capability_filters", false,
                                  &cfg->capabilityfilters) < 0)
        return -1;

    return 0;
}


int virQEMUDriverConfigLoadFile(virQEMUDriverConfig *cfg,
                                const char *filename,
                                bool privileged)
{
    g_autoptr(virConf) conf = NULL;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access(filename, R_OK) == -1) {
        VIR_INFO("Could not read qemu config file %s", filename);
        return 0;
    }

    if (!(conf = virConfReadFile(filename, 0)))
        return -1;

    if (virQEMUDriverConfigLoadDefaultTLSEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadVNCEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadNographicsEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadSPICEEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadSpecificTLSEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadRemoteDisplayEntry(cfg, conf, filename) < 0)
        return -1;

    if (virQEMUDriverConfigLoadSaveEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadProcessEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadDeviceEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadRPCEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadNetworkEntry(cfg, conf, filename) < 0)
        return -1;

    if (virQEMUDriverConfigLoadLogEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadNVRAMEntry(cfg, conf, privileged) < 0)
        return -1;

    if (virQEMUDriverConfigLoadDebugEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadSecurityEntry(cfg, conf, privileged) < 0)
        return -1;

    if (virQEMUDriverConfigLoadMemoryEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadSWTPMEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadCapsFiltersEntry(cfg, conf) < 0)
        return -1;

    return 0;
}


/**
 * @cfg: Recently read config values
 *
 * Validate the recently read configuration values.
 *
 * Returns 0 on success, -1 on failure
 */
int
virQEMUDriverConfigValidate(virQEMUDriverConfig *cfg)
{
    if (cfg->defaultTLSx509certdirPresent) {
        if (!virFileExists(cfg->defaultTLSx509certdir)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("default_tls_x509_cert_dir directory '%1$s' does not exist"),
                           cfg->defaultTLSx509certdir);
            return -1;
        }
    }

    if (cfg->vncTLSx509certdir &&
        !virFileExists(cfg->vncTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("vnc_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->vncTLSx509certdir);
        return -1;
    }

    if (cfg->spiceTLSx509certdir &&
        !virFileExists(cfg->spiceTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("spice_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->spiceTLSx509certdir);
        return -1;
    }

    if (cfg->chardevTLSx509certdir &&
        !virFileExists(cfg->chardevTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("chardev_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->chardevTLSx509certdir);
        return -1;
    }

    if (cfg->migrateTLSx509certdir &&
        !virFileExists(cfg->migrateTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migrate_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->migrateTLSx509certdir);
        return -1;
    }

    if (cfg->backupTLSx509certdir &&
        !virFileExists(cfg->backupTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("backup_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->backupTLSx509certdir);
        return -1;
    }

    if (cfg->vxhsTLSx509certdir &&
        !virFileExists(cfg->vxhsTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("vxhs_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->vxhsTLSx509certdir);
        return -1;
    }

    if (cfg->nbdTLSx509certdir &&
        !virFileExists(cfg->nbdTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("nbd_tls_x509_cert_dir directory '%1$s' does not exist"),
                       cfg->nbdTLSx509certdir);
        return -1;
    }

    return 0;
}


int
virQEMUDriverConfigSetDefaults(virQEMUDriverConfig *cfg)
{
#define SET_TLS_SECRET_UUID_DEFAULT(val) \
    do { \
        if (!cfg->val## TLSx509certdir && \
            !cfg->val## TLSx509secretUUID && \
            cfg->defaultTLSx509secretUUID) { \
            cfg->val## TLSx509secretUUID = g_strdup(cfg->defaultTLSx509secretUUID); \
        } \
    } while (0)

    SET_TLS_SECRET_UUID_DEFAULT(vnc);
    SET_TLS_SECRET_UUID_DEFAULT(chardev);
    SET_TLS_SECRET_UUID_DEFAULT(migrate);
    SET_TLS_SECRET_UUID_DEFAULT(backup);
    SET_TLS_SECRET_UUID_DEFAULT(vxhs);
    SET_TLS_SECRET_UUID_DEFAULT(nbd);

#undef SET_TLS_SECRET_UUID_DEFAULT

    /*
     * If a "SYSCONFDIR" + "pki/libvirt-<val>" exists, then assume someone
     * has created a val specific area to place service specific certificates.
     *
     * If the service specific directory doesn't exist, 'assume' that the
     * user has created and populated the "SYSCONFDIR" + "pki/libvirt-default".
     */
#define SET_TLS_X509_CERT_DEFAULT(val) \
    do { \
        if (cfg->val ## TLSx509certdir) \
            break; \
        if (virFileExists(SYSCONFDIR "/pki/libvirt-"#val)) { \
            cfg->val ## TLSx509certdir = g_strdup(SYSCONFDIR "/pki/libvirt-"#val); \
        } else { \
            cfg->val ## TLSx509certdir = g_strdup(cfg->defaultTLSx509certdir); \
        } \
    } while (0)

    SET_TLS_X509_CERT_DEFAULT(vnc);
    SET_TLS_X509_CERT_DEFAULT(spice);
    SET_TLS_X509_CERT_DEFAULT(chardev);
    SET_TLS_X509_CERT_DEFAULT(migrate);
    SET_TLS_X509_CERT_DEFAULT(backup);
    SET_TLS_X509_CERT_DEFAULT(vxhs);
    SET_TLS_X509_CERT_DEFAULT(nbd);

#undef SET_TLS_X509_CERT_DEFAULT

#define SET_TLS_VERIFY_DEFAULT(val, defaultverify) \
    do { \
        if (!cfg->val## TLSx509verifyPresent) {\
            if (cfg->defaultTLSx509verifyPresent) \
                cfg->val## TLSx509verify = cfg->defaultTLSx509verify; \
            else \
                cfg->val## TLSx509verify = defaultverify;\
        }\
    } while (0)

    SET_TLS_VERIFY_DEFAULT(vnc, false);
    SET_TLS_VERIFY_DEFAULT(chardev, true);
    SET_TLS_VERIFY_DEFAULT(migrate, true);
    SET_TLS_VERIFY_DEFAULT(backup, true);

#undef SET_TLS_VERIFY_DEFAULT

    return 0;
}


virQEMUDriverConfig *virQEMUDriverGetConfig(virQEMUDriver *driver)
{
    VIR_LOCK_GUARD lock = virLockGuardLock(&driver->lock);

    return virObjectRef(driver->config);
}

virDomainXMLOption *
virQEMUDriverCreateXMLConf(virQEMUDriver *driver,
                           const char *defsecmodel)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virDomainXMLOption *ret = NULL;

    virQEMUDriverDomainDefParserConfig.priv = driver;
    virQEMUDriverDomainDefParserConfig.defSecModel = defsecmodel;
    virQEMUDriverDomainJobConfig.maxQueuedJobs = cfg->maxQueuedJobs;

    ret = virDomainXMLOptionNew(&virQEMUDriverDomainDefParserConfig,
                                &virQEMUDriverPrivateDataCallbacks,
                                &virQEMUDriverDomainXMLNamespace,
                                &virQEMUDriverDomainABIStability,
                                &virQEMUDriverDomainSaveCookie,
                                &virQEMUDriverDomainJobConfig);

    virDomainXMLOptionSetCloseCallbackAlloc(ret, virCloseCallbacksDomainAlloc);

    return ret;
}


virCPUDef *
virQEMUDriverGetHostCPU(virQEMUDriver *driver)
{
    virCPUDef *hostcpu = NULL;

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        if (!driver->hostcpu)
            driver->hostcpu = virCPUProbeHost(virArchFromHost());
        hostcpu = driver->hostcpu;
    }

    if (hostcpu)
        virCPUDefRef(hostcpu);

    return hostcpu;
}


virCaps *virQEMUDriverCreateCapabilities(virQEMUDriver *driver)
{
    size_t i, j;
    g_autoptr(virCaps) caps = NULL;
    g_autofree virSecurityManager **sec_managers = NULL;
    /* Security driver data */
    const char *doi, *model, *lbl, *type;
    const int virtTypes[] = {VIR_DOMAIN_VIRT_KVM,
                             VIR_DOMAIN_VIRT_QEMU,};

    /* Basic host arch / guest machine capabilities */
    if (!(caps = virQEMUCapsInit(driver->qemuCapsCache)))
        return NULL;

    if (virGetHostUUID(caps->host.host_uuid)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot get the host uuid"));
        return NULL;
    }

    /* access sec drivers and create a sec model for each one */
    if (!(sec_managers = qemuSecurityGetNested(driver->securityManager)))
        return NULL;

    /* calculate length */
    for (i = 0; sec_managers[i]; i++)
        ;
    caps->host.nsecModels = i;

    caps->host.secModels = g_new0(virCapsHostSecModel, caps->host.nsecModels);

    for (i = 0; sec_managers[i]; i++) {
        virCapsHostSecModel *sm = &caps->host.secModels[i];
        doi = qemuSecurityGetDOI(sec_managers[i]);
        model = qemuSecurityGetModel(sec_managers[i]);
        sm->model = g_strdup(model);
        sm->doi = g_strdup(doi);

        for (j = 0; j < G_N_ELEMENTS(virtTypes); j++) {
            lbl = qemuSecurityGetBaseLabel(sec_managers[i], virtTypes[j]);
            type = virDomainVirtTypeToString(virtTypes[j]);
            if (lbl &&
                virCapabilitiesHostSecModelAddBaseLabel(sm, type, lbl) < 0)
                return NULL;
        }

        VIR_DEBUG("Initialized caps for security driver \"%s\" with "
                  "DOI \"%s\"", model, doi);
    }

    caps->host.numa = virCapabilitiesHostNUMANewHost();
    caps->host.cpu = virQEMUDriverGetHostCPU(driver);
    return g_steal_pointer(&caps);
}


/**
 * virQEMUDriverGetCapabilities:
 *
 * Get a reference to the virCaps *instance for the
 * driver. If @refresh is true, the capabilities will be
 * rebuilt first
 *
 * The caller must release the reference with virObjectUnref
 *
 * Returns: a reference to a virCaps *instance or NULL
 */
virCaps *virQEMUDriverGetCapabilities(virQEMUDriver *driver,
                                      bool refresh)
{
    if (refresh) {
        virCaps *caps = NULL;
        if ((caps = virQEMUDriverCreateCapabilities(driver)) == NULL)
            return NULL;

        VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
            virObjectUnref(driver->caps);
            driver->caps = caps;
            return virObjectRef(driver->caps);
        }
    }

    VIR_WITH_MUTEX_LOCK_GUARD(&driver->lock) {
        if (driver->caps && driver->caps->nguests > 0)
            return virObjectRef(driver->caps);
    }

    VIR_DEBUG("Capabilities didn't detect any guests. Forcing a refresh.");
    return virQEMUDriverGetCapabilities(driver, true);
}


/**
 * virQEMUDriverGetDomainCapabilities:
 *
 * Get a reference to the virDomainCaps *instance. The caller
 * must release the reference with virObjetUnref().
 *
 * Returns: a reference to a virDomainCaps *instance or NULL
 */
virDomainCaps *
virQEMUDriverGetDomainCapabilities(virQEMUDriver *driver,
                                   virQEMUCaps *qemuCaps,
                                   const char *machine,
                                   virArch arch,
                                   virDomainVirtType virttype)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    g_autoptr(virDomainCaps) domCaps = NULL;
    const char *path = virQEMUCapsGetBinary(qemuCaps);

    if (!virQEMUCapsIsArchSupported(qemuCaps, arch)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Emulator '%1$s' does not support arch '%2$s'"),
                       path, virArchToString(arch));
        return NULL;
    }

    if (!virQEMUCapsIsVirtTypeSupported(qemuCaps, virttype)) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Emulator '%1$s' does not support virt type '%2$s'"),
                       path, virDomainVirtTypeToString(virttype));
        return NULL;
    }

    if (!virQEMUCapsIsMachineSupported(qemuCaps, virttype, machine)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Emulator '%1$s' does not support machine type '%2$s'"),
                       path, NULLSTR(machine));
        return NULL;
    }

    if (!(domCaps = virDomainCapsNew(path, machine, arch, virttype)))
        return NULL;

    if (virQEMUCapsFillDomainCaps(qemuCaps, driver->hostarch,
                                  domCaps, driver->privileged,
                                  cfg->firmwares,
                                  cfg->nfirmwares) < 0)
        return NULL;

    return g_steal_pointer(&domCaps);
}


int qemuDriverAllocateID(virQEMUDriver *driver)
{
    return g_atomic_int_add(&driver->lastvmid, 1) + 1;
}


int
qemuTranslateSnapshotDiskSourcePool(virDomainSnapshotDiskDef *def)
{
    if (def->src->type != VIR_STORAGE_TYPE_VOLUME)
        return 0;

    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Snapshots are not yet supported with 'pool' volumes"));
    return -1;
}

char *
qemuGetBaseHugepagePath(virQEMUDriver *driver,
                        virHugeTLBFS *hugepage)
{
    const char *root = driver->embeddedRoot;

    if (root && !STRPREFIX(hugepage->mnt_dir, root)) {
        g_autofree char * hash = virDomainDriverGenerateRootHash("qemu", root);
        return g_strdup_printf("%s/libvirt/%s", hugepage->mnt_dir, hash);
    }

    return g_strdup_printf("%s/libvirt/qemu", hugepage->mnt_dir);
}


char *
qemuGetDomainHugepagePath(virQEMUDriver *driver,
                          const virDomainDef *def,
                          virHugeTLBFS *hugepage)
{
    g_autofree char *base = qemuGetBaseHugepagePath(driver, hugepage);
    g_autofree char *domPath = virDomainDefGetShortName(def);

    if (!base || !domPath)
        return NULL;

    return g_strdup_printf("%s/%s", base, domPath);
}


/**
 * qemuGetDomainHupageMemPath: Construct HP enabled memory backend path
 *
 * The resulting path is stored at @memPath.
 *
 * Returns 0 on success,
 *        -1 otherwise.
 */
int
qemuGetDomainHupageMemPath(virQEMUDriver *driver,
                           const virDomainDef *def,
                           unsigned long long pagesize,
                           char **memPath)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    size_t i = 0;

    if (!cfg->nhugetlbfs) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("hugetlbfs filesystem is not mounted or disabled by administrator config"));
        return -1;
    }

    for (i = 0; i < cfg->nhugetlbfs; i++) {
        if (cfg->hugetlbfs[i].size == pagesize)
            break;
    }

    if (i == cfg->nhugetlbfs) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find any usable hugetlbfs mount for %1$llu KiB"),
                       pagesize);
        return -1;
    }

    if (!(*memPath = qemuGetDomainHugepagePath(driver, def, &cfg->hugetlbfs[i])))
        return -1;

    return 0;
}


int
qemuGetMemoryBackingDomainPath(virQEMUDriver *driver,
                               const virDomainDef *def,
                               char **path)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    const char *root = driver->embeddedRoot;
    g_autofree char *shortName = NULL;

    if (!(shortName = virDomainDefGetShortName(def)))
        return -1;

    if (root && !STRPREFIX(cfg->memoryBackingDir, root)) {
        g_autofree char * hash = virDomainDriverGenerateRootHash("qemu", root);
        *path = g_strdup_printf("%s/%s-%s", cfg->memoryBackingDir, hash, shortName);
    } else {
        *path = g_strdup_printf("%s/%s", cfg->memoryBackingDir, shortName);
    }

    return 0;
}


/**
 * qemuGetMemoryBackingPath:
 * @driver: the qemu driver
 * @def: domain definition
 * @alias: memory object alias
 * @memPath: constructed path
 *
 * Constructs path to memory backing dir and stores it at @memPath.
 *
 * Returns: 0 on success,
 *          -1 otherwise (with error reported).
 */
int
qemuGetMemoryBackingPath(virQEMUDriver *driver,
                         const virDomainDef *def,
                         const char *alias,
                         char **memPath)
{
    g_autofree char *domainPath = NULL;

    if (!alias) {
        /* This should never happen (TM) */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("memory device alias is not assigned"));
        return -1;
    }

    if (qemuGetMemoryBackingDomainPath(driver, def, &domainPath) < 0)
        return -1;

    *memPath = g_strdup_printf("%s/%s", domainPath, alias);
    return 0;
}


int
qemuHugepageMakeBasedir(virQEMUDriver *driver,
                        virHugeTLBFS *hugepage)
{

    g_autofree char *hugepagePath = NULL;

    hugepagePath = qemuGetBaseHugepagePath(driver, hugepage);

    if (!hugepagePath)
        return -1;

    if (g_mkdir_with_parents(hugepagePath, 0777) < 0) {
        virReportSystemError(errno,
                             _("unable to create hugepage path %1$s"),
                             hugepagePath);
        return -1;
    }

    if (driver->privileged &&
        virFileUpdatePerm(hugepage->mnt_dir, 0, S_IXGRP | S_IXOTH) < 0)
        return -1;

    return 0;
}


/*
 * qemuGetNbdkitCaps:
 * @driver: the qemu driver
 *
 * Gets the capabilities for Nbdkit for the specified driver. These can be used
 * to determine whether a particular disk source can be served by nbdkit or
 * not.
 *
 * Returns: a reference to qemuNbdkitCaps or NULL
 */
qemuNbdkitCaps*
qemuGetNbdkitCaps(virQEMUDriver *driver)
{
    g_autofree char *nbdkitBinary = virFindFileInPath("nbdkit");

    if (!nbdkitBinary)
        return NULL;

    return virFileCacheLookup(driver->nbdkitCapsCache, nbdkitBinary);
}
