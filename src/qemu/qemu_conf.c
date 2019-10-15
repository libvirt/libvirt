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
#include <sys/wait.h>
#include <arpa/inet.h>

#include "virerror.h"
#include "qemu_conf.h"
#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_security.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "virconf.h"
#include "viralloc.h"
#include "datatypes.h"
#include "virxml.h"
#include "virlog.h"
#include "cpu/cpu.h"
#include "domain_nwfilter.h"
#include "virfile.h"
#include "virsocketaddr.h"
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
    if (!VIR_CLASS_NEW(virQEMUDriverConfig, virClassForObject()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virQEMUConfig);


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

#ifndef DEFAULT_LOADER_NVRAM
# define DEFAULT_LOADER_NVRAM \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd:" \
    "/usr/share/OVMF/OVMF_CODE.secboot.fd:/usr/share/OVMF/OVMF_VARS.fd:" \
    "/usr/share/AAVMF/AAVMF_CODE.fd:/usr/share/AAVMF/AAVMF_VARS.fd:" \
    "/usr/share/AAVMF/AAVMF32_CODE.fd:/usr/share/AAVMF/AAVMF32_VARS.fd"
#endif


virQEMUDriverConfigPtr virQEMUDriverConfigNew(bool privileged)
{
    g_autoptr(virQEMUDriverConfig) cfg = NULL;

    if (virQEMUConfigInitialize() < 0)
        return NULL;

    if (!(cfg = virObjectNew(virQEMUDriverConfigClass)))
        return NULL;

    cfg->uri = privileged ? "qemu:///system" : "qemu:///session";

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
    cfg->rememberOwner = privileged;

    cfg->cgroupControllers = -1; /* -1 == auto-detect */

    if (privileged) {
        if (virAsprintf(&cfg->logDir,
                        "%s/log/libvirt/qemu", LOCALSTATEDIR) < 0)
            return NULL;

        if (virAsprintf(&cfg->swtpmLogDir,
                        "%s/log/swtpm/libvirt/qemu", LOCALSTATEDIR) < 0)
            return NULL;

        if (VIR_STRDUP(cfg->configBaseDir, SYSCONFDIR "/libvirt") < 0)
            return NULL;

        if (virAsprintf(&cfg->stateDir,
                      "%s/libvirt/qemu", RUNSTATEDIR) < 0)
            return NULL;

        if (virAsprintf(&cfg->swtpmStateDir,
                       "%s/libvirt/qemu/swtpm", RUNSTATEDIR) < 0)
            return NULL;

        if (virAsprintf(&cfg->cacheDir,
                      "%s/cache/libvirt/qemu", LOCALSTATEDIR) < 0)
            return NULL;

        if (virAsprintf(&cfg->libDir,
                      "%s/lib/libvirt/qemu", LOCALSTATEDIR) < 0)
            return NULL;
        if (virAsprintf(&cfg->saveDir, "%s/save", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->snapshotDir, "%s/snapshot", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->checkpointDir, "%s/checkpoint", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->autoDumpPath, "%s/dump", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/channel/target", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->nvramDir, "%s/nvram", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->memoryBackingDir, "%s/ram", cfg->libDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->swtpmStorageDir, "%s/lib/libvirt/swtpm",
                        LOCALSTATEDIR) < 0)
            return NULL;
        if (!virDoesUserExist("tss") ||
            virGetUserID("tss", &cfg->swtpm_user) < 0)
            cfg->swtpm_user = 0; /* fall back to root */
        if (!virDoesGroupExist("tss") ||
            virGetGroupID("tss", &cfg->swtpm_group) < 0)
            cfg->swtpm_group = 0; /* fall back to root */
    } else {
        g_autofree char *rundir = NULL;
        g_autofree char *cachedir = NULL;

        cachedir = virGetUserCacheDirectory();
        if (!cachedir)
            return NULL;

        if (virAsprintf(&cfg->logDir, "%s/qemu/log", cachedir) < 0)
            return NULL;
        if (virAsprintf(&cfg->swtpmLogDir, "%s/qemu/log", cachedir) < 0)
            return NULL;
        if (virAsprintf(&cfg->cacheDir, "%s/qemu/cache", cachedir) < 0)
            return NULL;

        rundir = virGetUserRuntimeDirectory();
        if (!rundir)
            return NULL;
        if (virAsprintf(&cfg->stateDir, "%s/qemu/run", rundir) < 0)
            return NULL;

        if (virAsprintf(&cfg->swtpmStateDir, "%s/swtpm", cfg->stateDir) < 0)
            return NULL;

        if (!(cfg->configBaseDir = virGetUserConfigDirectory()))
            return NULL;

        if (virAsprintf(&cfg->libDir, "%s/qemu/lib", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->saveDir, "%s/qemu/save", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->snapshotDir, "%s/qemu/snapshot", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->checkpointDir, "%s/qemu/checkpoint", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->autoDumpPath, "%s/qemu/dump", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->channelTargetDir,
                        "%s/qemu/channel/target", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->nvramDir,
                        "%s/qemu/nvram", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->memoryBackingDir, "%s/qemu/ram", cfg->configBaseDir) < 0)
            return NULL;
        if (virAsprintf(&cfg->swtpmStorageDir, "%s/qemu/swtpm", cfg->configBaseDir) < 0)
            return NULL;
        cfg->swtpm_user = (uid_t)-1;
        cfg->swtpm_group = (gid_t)-1;
    }

    if (virAsprintf(&cfg->configDir, "%s/qemu", cfg->configBaseDir) < 0)
        return NULL;
    if (virAsprintf(&cfg->autostartDir, "%s/qemu/autostart", cfg->configBaseDir) < 0)
        return NULL;
    if (virAsprintf(&cfg->slirpStateDir, "%s/slirp", cfg->stateDir) < 0)
        return NULL;

    /* Set the default directory to find TLS X.509 certificates.
     * This will then be used as a fallback if the service specific
     * directory doesn't exist (although we don't check if this exists).
     */
    if (VIR_STRDUP(cfg->defaultTLSx509certdir,
                   SYSCONFDIR "/pki/qemu") < 0)
        return NULL;

    if (VIR_STRDUP(cfg->vncListen, VIR_LOOPBACK_IPV4_ADDR) < 0)
        return NULL;

    if (VIR_STRDUP(cfg->spiceListen, VIR_LOOPBACK_IPV4_ADDR) < 0)
        return NULL;

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

    if (VIR_STRDUP(cfg->bridgeHelperName, QEMU_BRIDGE_HELPER) < 0 ||
        VIR_STRDUP(cfg->prHelperName, QEMU_PR_HELPER) < 0 ||
        VIR_STRDUP(cfg->slirpHelperName, QEMU_SLIRP_HELPER) < 0)
        return NULL;

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
        return NULL;

    if (privileged &&
        qemuDomainNamespaceAvailable(QEMU_DOMAIN_NS_MOUNT) &&
        virBitmapSetBit(cfg->namespaces, QEMU_DOMAIN_NS_MOUNT) < 0)
        return NULL;

    if (virFirmwareParseList(DEFAULT_LOADER_NVRAM,
                             &cfg->firmwares,
                             &cfg->nfirmwares) < 0)
        return NULL;

    VIR_RETURN_PTR(cfg);
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
    VIR_FREE(cfg->swtpmLogDir);
    VIR_FREE(cfg->stateDir);
    VIR_FREE(cfg->swtpmStateDir);
    VIR_FREE(cfg->slirpStateDir);

    VIR_FREE(cfg->libDir);
    VIR_FREE(cfg->cacheDir);
    VIR_FREE(cfg->saveDir);
    VIR_FREE(cfg->snapshotDir);
    VIR_FREE(cfg->checkpointDir);
    VIR_FREE(cfg->channelTargetDir);
    VIR_FREE(cfg->nvramDir);

    VIR_FREE(cfg->defaultTLSx509certdir);
    VIR_FREE(cfg->defaultTLSx509secretUUID);

    VIR_FREE(cfg->vncTLSx509certdir);
    VIR_FREE(cfg->vncTLSx509secretUUID);
    VIR_FREE(cfg->vncListen);
    VIR_FREE(cfg->vncPassword);
    VIR_FREE(cfg->vncSASLdir);

    VIR_FREE(cfg->spiceTLSx509certdir);
    VIR_FREE(cfg->spiceListen);
    VIR_FREE(cfg->spicePassword);
    VIR_FREE(cfg->spiceSASLdir);

    VIR_FREE(cfg->chardevTLSx509certdir);
    VIR_FREE(cfg->chardevTLSx509secretUUID);

    VIR_FREE(cfg->vxhsTLSx509certdir);
    VIR_FREE(cfg->nbdTLSx509certdir);

    VIR_FREE(cfg->migrateTLSx509certdir);
    VIR_FREE(cfg->migrateTLSx509secretUUID);

    while (cfg->nhugetlbfs) {
        cfg->nhugetlbfs--;
        VIR_FREE(cfg->hugetlbfs[cfg->nhugetlbfs].mnt_dir);
    }
    VIR_FREE(cfg->hugetlbfs);
    VIR_FREE(cfg->bridgeHelperName);
    VIR_FREE(cfg->prHelperName);
    VIR_FREE(cfg->slirpHelperName);

    VIR_FREE(cfg->saveImageFormat);
    VIR_FREE(cfg->dumpImageFormat);
    VIR_FREE(cfg->snapshotImageFormat);
    VIR_FREE(cfg->autoDumpPath);

    virStringListFree(cfg->securityDriverNames);

    VIR_FREE(cfg->lockManagerName);

    virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

    VIR_FREE(cfg->memoryBackingDir);
    VIR_FREE(cfg->swtpmStorageDir);

    virStringListFree(cfg->capabilityfilters);
}


static int
virQEMUDriverConfigHugeTLBFSInit(virHugeTLBFSPtr hugetlbfs,
                                 const char *path,
                                 bool deflt)
{
    if (VIR_STRDUP(hugetlbfs->mnt_dir, path) < 0 ||
        virFileGetHugepageSize(path, &hugetlbfs->size) < 0) {
        return -1;
    }

    hugetlbfs->deflt = deflt;
    return 0;
}


static int
virQEMUDriverConfigLoadDefaultTLSEntry(virQEMUDriverConfigPtr cfg,
                                       virConfPtr conf)
{
    int rv;

    if ((rv = virConfGetValueString(conf, "default_tls_x509_cert_dir", &cfg->defaultTLSx509certdir)) < 0)
        return -1;
    cfg->defaultTLSx509certdirPresent = (rv == 1);
    if (virConfGetValueBool(conf, "default_tls_x509_verify", &cfg->defaultTLSx509verify) < 0)
        return -1;
    if (virConfGetValueString(conf, "default_tls_x509_secret_uuid",
                              &cfg->defaultTLSx509secretUUID) < 0)
        return -1;

    return 0;
}


static int
virQEMUDriverConfigLoadVNCEntry(virQEMUDriverConfigPtr cfg,
                                virConfPtr conf)
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

    return 0;
}


static int
virQEMUDriverConfigLoadNographicsEntry(virQEMUDriverConfigPtr cfg,
                                       virConfPtr conf)
{
    return virConfGetValueBool(conf, "nographics_allow_host_audio", &cfg->nogfxAllowHostAudio);
}


static int
virQEMUDriverConfigLoadSPICEEntry(virQEMUDriverConfigPtr cfg,
                                  virConfPtr conf)
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
virQEMUDriverConfigLoadSpecificTLSEntry(virQEMUDriverConfigPtr cfg,
                                        virConfPtr conf)
{
    int rv;

    if (virConfGetValueBool(conf, "vxhs_tls", &cfg->vxhsTLS) < 0)
        return -1;
    if (virConfGetValueString(conf, "vxhs_tls_x509_cert_dir", &cfg->vxhsTLSx509certdir) < 0)
        return -1;
    if (virConfGetValueBool(conf, "nbd_tls", &cfg->nbdTLS) < 0)
        return -1;
    if (virConfGetValueString(conf, "nbd_tls_x509_cert_dir", &cfg->nbdTLSx509certdir) < 0)
        return -1;

#define GET_CONFIG_TLS_CERTINFO(val) \
    do { \
        if ((rv = virConfGetValueBool(conf, #val "_tls_x509_verify", \
                                      &cfg->val## TLSx509verify)) < 0) \
            return -1; \
        if (rv == 1) \
            cfg->val## TLSx509verifyPresent = true; \
        if (virConfGetValueString(conf, #val "_tls_x509_cert_dir", \
                                  &cfg->val## TLSx509certdir) < 0) \
            return -1; \
        if (virConfGetValueString(conf, \
                                  #val "_tls_x509_secret_uuid", \
                                  &cfg->val## TLSx509secretUUID) < 0) \
            return -1; \
    } while (0)

    if (virConfGetValueBool(conf, "chardev_tls", &cfg->chardevTLS) < 0)
        return -1;
    GET_CONFIG_TLS_CERTINFO(chardev);

    GET_CONFIG_TLS_CERTINFO(migrate);

#undef GET_CONFIG_TLS_CERTINFO
    return 0;
}


static int
virQEMUDriverConfigLoadRemoteDisplayEntry(virQEMUDriverConfigPtr cfg,
                                          virConfPtr conf,
                                          const char *filename)
{
    if (virConfGetValueUInt(conf, "remote_websocket_port_min", &cfg->webSocketPortMin) < 0)
        return -1;
    if (cfg->webSocketPortMin < QEMU_WEBSOCKET_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5700, e.g. localhost:1
         * for port 5701) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: remote_websocket_port_min: port must be greater "
                         "than or equal to %d"),
                        filename, QEMU_WEBSOCKET_PORT_MIN);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_websocket_port_max", &cfg->webSocketPortMax) < 0)
        return -1;
    if (cfg->webSocketPortMax > QEMU_WEBSOCKET_PORT_MAX ||
        cfg->webSocketPortMax < cfg->webSocketPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_websocket_port_max: port must be between "
                          "the minimal port and %d"),
                       filename, QEMU_WEBSOCKET_PORT_MAX);
        return -1;
    }

    if (cfg->webSocketPortMin > cfg->webSocketPortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_websocket_port_min: min port must not be "
                          "greater than max port"), filename);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_display_port_min", &cfg->remotePortMin) < 0)
        return -1;
    if (cfg->remotePortMin < QEMU_REMOTE_PORT_MIN) {
        /* if the port is too low, we can't get the display name
         * to tell to vnc (usually subtract 5900, e.g. localhost:1
         * for port 5901) */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: remote_display_port_min: port must be greater "
                         "than or equal to %d"),
                        filename, QEMU_REMOTE_PORT_MIN);
        return -1;
    }

    if (virConfGetValueUInt(conf, "remote_display_port_max", &cfg->remotePortMax) < 0)
        return -1;
    if (cfg->remotePortMax > QEMU_REMOTE_PORT_MAX ||
        cfg->remotePortMax < cfg->remotePortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_max: port must be between "
                          "the minimal port and %d"),
                       filename, QEMU_REMOTE_PORT_MAX);
        return -1;
    }

    if (cfg->remotePortMin > cfg->remotePortMax) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: remote_display_port_min: min port must not be "
                          "greater than max port"), filename);
        return -1;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadSaveEntry(virQEMUDriverConfigPtr cfg,
                                 virConfPtr conf)
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
virQEMUDriverConfigLoadProcessEntry(virQEMUDriverConfigPtr cfg,
                                    virConfPtr conf)
{
    VIR_AUTOSTRINGLIST hugetlbfs = NULL;
    g_autofree char *stdioHandler = NULL;
    g_autofree char *corestr = NULL;
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

        cfg->nhugetlbfs = virStringListLength((const char *const *)hugetlbfs);
        if (hugetlbfs[0] &&
            VIR_ALLOC_N(cfg->hugetlbfs, cfg->nhugetlbfs) < 0)
            return -1;

        for (i = 0; hugetlbfs[i] != NULL; i++) {
            if (virQEMUDriverConfigHugeTLBFSInit(&cfg->hugetlbfs[i],
                                                 hugetlbfs[i], i != 0) < 0)
                return -1;
        }
    }

    if (virConfGetValueBool(conf, "clear_emulator_capabilities", &cfg->clearEmulatorCapabilities) < 0)
        return -1;
    if (virConfGetValueString(conf, "bridge_helper", &cfg->bridgeHelperName) < 0)
        return -1;

    if (virConfGetValueString(conf, "pr_helper", &cfg->prHelperName) < 0)
        return -1;

    if (virConfGetValueString(conf, "slirp_helper", &cfg->slirpHelperName) < 0)
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
                           _("Unknown core size '%s'"),
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
                           _("Unknown stdio handler %s"),
                           stdioHandler);
            return -1;
        }
    }

    return 0;
}


static int
virQEMUDriverConfigLoadDeviceEntry(virQEMUDriverConfigPtr cfg,
                                   virConfPtr conf)
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
virQEMUDriverConfigLoadRPCEntry(virQEMUDriverConfigPtr cfg,
                                virConfPtr conf)
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
virQEMUDriverConfigLoadNetworkEntry(virQEMUDriverConfigPtr cfg,
                                    virConfPtr conf,
                                    const char *filename)
{
    if (virConfGetValueUInt(conf, "migration_port_min", &cfg->migrationPortMin) < 0)
        return -1;
    if (cfg->migrationPortMin <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s: migration_port_min: port must be greater than 0"),
                        filename);
        return -1;
    }

    if (virConfGetValueUInt(conf, "migration_port_max", &cfg->migrationPortMax) < 0)
        return -1;
    if (cfg->migrationPortMax > 65535 ||
        cfg->migrationPortMax < cfg->migrationPortMin) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                        _("%s: migration_port_max: port must be between "
                          "the minimal port %d and 65535"),
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
                       _("migration_host must not be the address of"
                         " the local machine: %s"),
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
                       _("migration_address must not be the address of"
                         " the local machine: %s"),
                       cfg->migrationAddress);
        return -1;
    }

    return 0;
}


static int
virQEMUDriverConfigLoadLogEntry(virQEMUDriverConfigPtr cfg,
                                virConfPtr conf)
{
    return virConfGetValueBool(conf, "log_timestamp", &cfg->logTimestamp);
}


static int
virQEMUDriverConfigLoadNVRAMEntry(virQEMUDriverConfigPtr cfg,
                                  virConfPtr conf)
{
    VIR_AUTOSTRINGLIST nvram = NULL;
    size_t i;

    if (virConfGetValueStringList(conf, "nvram", false, &nvram) < 0)
        return -1;
    if (nvram) {
        virFirmwareFreeList(cfg->firmwares, cfg->nfirmwares);

        cfg->nfirmwares = virStringListLength((const char *const *)nvram);
        if (nvram[0] && VIR_ALLOC_N(cfg->firmwares, cfg->nfirmwares) < 0)
            return -1;

        for (i = 0; nvram[i] != NULL; i++) {
            if (VIR_ALLOC(cfg->firmwares[i]) < 0)
                return -1;
            if (virFirmwareParse(nvram[i], cfg->firmwares[i]) < 0)
                return -1;
        }
    }

    return 0;
}


static int
virQEMUDriverConfigLoadGlusterDebugEntry(virQEMUDriverConfigPtr cfg,
                                         virConfPtr conf)
{
    return virConfGetValueUInt(conf, "gluster_debug_level", &cfg->glusterDebugLevel);
}


static int
virQEMUDriverConfigLoadSecurityEntry(virQEMUDriverConfigPtr cfg,
                                     virConfPtr conf,
                                     bool privileged)
{
    VIR_AUTOSTRINGLIST controllers = NULL;
    VIR_AUTOSTRINGLIST namespaces = NULL;
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
                               _("Duplicate security driver %s"),
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
                               _("Unknown cgroup controller '%s'"),
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
                               _("Unknown namespace: %s"),
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
                               _("%s namespace is not available"),
                               namespaces[i]);
                return -1;
            }

            if (virBitmapSetBit(cfg->namespaces, ns) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unable to enable namespace: %s"),
                               namespaces[i]);
                return -1;
            }
        }
    }

    return 0;
}


static int
virQEMUDriverConfigLoadMemoryEntry(virQEMUDriverConfigPtr cfg,
                                   virConfPtr conf)
{
    return virConfGetValueString(conf, "memory_backing_dir", &cfg->memoryBackingDir);
}


static int
virQEMUDriverConfigLoadSWTPMEntry(virQEMUDriverConfigPtr cfg,
                                  virConfPtr conf)
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
virQEMUDriverConfigLoadCapsFiltersEntry(virQEMUDriverConfigPtr cfg,
                                        virConfPtr conf)
{
    if (virConfGetValueStringList(conf, "capability_filters", false,
                                  &cfg->capabilityfilters) < 0)
        return -1;

    return 0;
}


int virQEMUDriverConfigLoadFile(virQEMUDriverConfigPtr cfg,
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

    if (virQEMUDriverConfigLoadNVRAMEntry(cfg, conf) < 0)
        return -1;

    if (virQEMUDriverConfigLoadGlusterDebugEntry(cfg, conf) < 0)
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
virQEMUDriverConfigValidate(virQEMUDriverConfigPtr cfg)
{
    if (cfg->defaultTLSx509certdirPresent) {
        if (!virFileExists(cfg->defaultTLSx509certdir)) {
            virReportError(VIR_ERR_CONF_SYNTAX,
                           _("default_tls_x509_cert_dir directory '%s' "
                             "does not exist"),
                           cfg->defaultTLSx509certdir);
            return -1;
        }
    }

    if (cfg->vncTLSx509certdir &&
        !virFileExists(cfg->vncTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("vnc_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->vncTLSx509certdir);
        return -1;
    }

    if (cfg->spiceTLSx509certdir &&
        !virFileExists(cfg->spiceTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("spice_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->spiceTLSx509certdir);
        return -1;
    }

    if (cfg->chardevTLSx509certdir &&
        !virFileExists(cfg->chardevTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("chardev_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->chardevTLSx509certdir);
        return -1;
    }

    if (cfg->migrateTLSx509certdir &&
        !virFileExists(cfg->migrateTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("migrate_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->migrateTLSx509certdir);
        return -1;
    }

    if (cfg->vxhsTLSx509certdir &&
        !virFileExists(cfg->vxhsTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("vxhs_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->vxhsTLSx509certdir);
        return -1;
    }

    if (cfg->nbdTLSx509certdir &&
        !virFileExists(cfg->nbdTLSx509certdir)) {
        virReportError(VIR_ERR_CONF_SYNTAX,
                       _("nbd_tls_x509_cert_dir directory '%s' does not exist"),
                       cfg->nbdTLSx509certdir);
        return -1;
    }

    return 0;
}


int
virQEMUDriverConfigSetDefaults(virQEMUDriverConfigPtr cfg)
{
#define SET_TLS_SECRET_UUID_DEFAULT(val) \
    do { \
        if (!cfg->val## TLSx509certdir && \
            !cfg->val## TLSx509secretUUID && \
            cfg->defaultTLSx509secretUUID) { \
            if (VIR_STRDUP(cfg->val## TLSx509secretUUID, \
                           cfg->defaultTLSx509secretUUID) < 0) { \
                return -1; \
            } \
        } \
    } while (0)

    SET_TLS_SECRET_UUID_DEFAULT(vnc);
    SET_TLS_SECRET_UUID_DEFAULT(chardev);
    SET_TLS_SECRET_UUID_DEFAULT(migrate);

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
            if (VIR_STRDUP(cfg->val ## TLSx509certdir, \
                           SYSCONFDIR "/pki/libvirt-"#val) < 0) { \
                return -1; \
            } \
        } else { \
            if (VIR_STRDUP(cfg->val ## TLSx509certdir, \
                           cfg->defaultTLSx509certdir) < 0) { \
                return -1; \
            } \
        } \
    } while (0)

    SET_TLS_X509_CERT_DEFAULT(vnc);
    SET_TLS_X509_CERT_DEFAULT(spice);
    SET_TLS_X509_CERT_DEFAULT(chardev);
    SET_TLS_X509_CERT_DEFAULT(migrate);
    SET_TLS_X509_CERT_DEFAULT(vxhs);
    SET_TLS_X509_CERT_DEFAULT(nbd);

#undef SET_TLS_X509_CERT_DEFAULT

#define SET_TLS_VERIFY_DEFAULT(val) \
    do { \
        if (!cfg->val## TLSx509verifyPresent) \
            cfg->val## TLSx509verify = cfg->defaultTLSx509verify; \
    } while (0)

    SET_TLS_VERIFY_DEFAULT(vnc);
    SET_TLS_VERIFY_DEFAULT(chardev);
    SET_TLS_VERIFY_DEFAULT(migrate);

#undef SET_TLS_VERIFY_DEFAULT

    return 0;
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
                                 &virQEMUDriverDomainXMLNamespace,
                                 &virQEMUDriverDomainABIStability,
                                 &virQEMUDriverDomainSaveCookie);
}


virCapsPtr virQEMUDriverCreateCapabilities(virQEMUDriverPtr driver)
{
    size_t i, j;
    g_autoptr(virCaps) caps = NULL;
    g_autofree virSecurityManagerPtr *sec_managers = NULL;
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

    if (VIR_ALLOC_N(caps->host.secModels, caps->host.nsecModels) < 0)
        return NULL;

    for (i = 0; sec_managers[i]; i++) {
        virCapsHostSecModelPtr sm = &caps->host.secModels[i];
        doi = qemuSecurityGetDOI(sec_managers[i]);
        model = qemuSecurityGetModel(sec_managers[i]);
        if (VIR_STRDUP(sm->model, model) < 0 ||
            VIR_STRDUP(sm->doi, doi) < 0)
            return NULL;

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

    VIR_RETURN_PTR(caps);
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


struct virQEMUDriverSearchDomcapsData {
    const char *path;
    const char *machine;
    virArch arch;
    virDomainVirtType virttype;
};


static int
virQEMUDriverSearchDomcaps(const void *payload,
                           const void *name G_GNUC_UNUSED,
                           const void *opaque)
{
    virDomainCapsPtr domCaps = (virDomainCapsPtr) payload;
    struct virQEMUDriverSearchDomcapsData *data = (struct virQEMUDriverSearchDomcapsData *) opaque;

    if (STREQ_NULLABLE(data->path, domCaps->path) &&
        STREQ_NULLABLE(data->machine, domCaps->machine) &&
        data->arch == domCaps->arch &&
        data->virttype == domCaps->virttype)
        return 1;

    return 0;
}

/**
 * virQEMUDriverGetDomainCapabilities:
 *
 * Get a reference to the virDomainCapsPtr instance from the virQEMUCapsPtr
 * domCapsCache. If there's no domcaps in the cache, create a new instance,
 * add it to the cache, and return a reference.
 *
 * The caller must release the reference with virObjetUnref
 *
 * Returns: a reference to a virDomainCapsPtr instance or NULL
 */
virDomainCapsPtr
virQEMUDriverGetDomainCapabilities(virQEMUDriverPtr driver,
                                   virQEMUCapsPtr qemuCaps,
                                   const char *machine,
                                   virArch arch,
                                   virDomainVirtType virttype)
{
    g_autoptr(virDomainCaps) domCaps = NULL;
    g_autoptr(virCaps) caps = NULL;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virHashTablePtr domCapsCache = virQEMUCapsGetDomainCapsCache(qemuCaps);
    struct virQEMUDriverSearchDomcapsData data = {
        .path = virQEMUCapsGetBinary(qemuCaps),
        .machine = machine,
        .arch = arch,
        .virttype = virttype,
    };

    if (!(caps = virQEMUDriverGetCapabilities(driver, false)))
        return NULL;

    domCaps = virHashSearch(domCapsCache,
                            virQEMUDriverSearchDomcaps, &data, NULL);
    if (!domCaps) {
        /* hash miss, build new domcaps */
        if (!(domCaps = virDomainCapsNew(data.path, data.machine,
                                         data.arch, data.virttype)))
            return NULL;

        if (virQEMUCapsFillDomainCaps(caps, domCaps, qemuCaps,
                                      driver->privileged,
                                      cfg->firmwares, cfg->nfirmwares) < 0)
            return NULL;

        if (virHashAddEntry(domCapsCache, machine, domCaps) < 0)
            return NULL;
    }

    virObjectRef(domCaps);
    VIR_RETURN_PTR(domCaps);
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
    g_autofree char *sysfs_path = NULL;
    g_autofree char *key = NULL;
    int val;

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(device_path, NULL)))
        return -1;

    /* It can't be conflict if unpriv_sgio is not supported by kernel. */
    if (!virFileExists(sysfs_path))
        return 0;

    if (!(key = qemuGetSharedDeviceKey(device_path)))
        return -1;

    /* It can't be conflict if no other domain is sharing it. */
    if (!(virHashLookup(sharedDevices, key)))
        return 0;

    if (virGetDeviceUnprivSGIO(device_path, NULL, &val) < 0)
        return -1;

    /* Error message on failure needs to be handled in caller
     * since there is more specific knowledge of device
     */
    if (!((val == 0 &&
           (sgio == VIR_DOMAIN_DEVICE_SGIO_FILTERED ||
            sgio == VIR_DOMAIN_DEVICE_SGIO_DEFAULT)) ||
          (val == 1 &&
           sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED))) {
        return -2;
    }

    return 0;
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
qemuSharedDeviceEntryFree(void *payload, const void *name G_GNUC_UNUSED)
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

        if (virHashAddEntry(driver->sharedDevices, key, entry) < 0)
            goto error;
    }

    return 0;

 error:
    qemuSharedDeviceEntryFree(entry, NULL);
    return -1;
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

    if (entry->ref != 1) {
        VIR_FREE(entry->domains[idx]);
        VIR_DELETE_ELEMENT(entry->domains, idx, entry->ref);
    } else {
        ignore_value(virHashRemoveEntry(driver->sharedDevices, key));
    }

    return 0;
}


static int
qemuSharedDiskAddRemoveInternal(virQEMUDriverPtr driver,
                                virDomainDiskDefPtr disk,
                                const char *name,
                                bool addDisk)
{
    g_autofree char *key = NULL;
    int ret = -1;

    if (virStorageSourceIsEmpty(disk->src) ||
        !disk->src->shared ||
        !virStorageSourceIsBlockLocal(disk->src))
        return 0;

    qemuDriverLock(driver);

    if (!(key = qemuGetSharedDeviceKey(virDomainDiskGetSource(disk))))
        goto cleanup;

    if (addDisk) {
        if (qemuCheckSharedDisk(driver->sharedDevices, disk) < 0)
            goto cleanup;

        if (qemuSharedDeviceEntryInsert(driver, key, name) < 0)
            goto cleanup;
    } else {
        if (qemuSharedDeviceEntryRemove(driver, key, name) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    qemuDriverUnlock(driver);
    return ret;
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
int
qemuAddSharedDisk(virQEMUDriverPtr driver,
                  virDomainDiskDefPtr disk,
                  const char *name)
{
    return qemuSharedDiskAddRemoveInternal(driver, disk, name, true);
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
    g_autofree char *dev_name = NULL;
    char *dev_path = NULL;

    if (!(dev_name = virSCSIDeviceGetDevName(NULL,
                                             scsihostsrc->adapter,
                                             scsihostsrc->bus,
                                             scsihostsrc->target,
                                             scsihostsrc->unit)))
        return NULL;

    ignore_value(virAsprintf(&dev_path, "/dev/%s", dev_name));
    return dev_path;
}


static int
qemuSharedHostdevAddRemoveInternal(virQEMUDriverPtr driver,
                                   virDomainHostdevDefPtr hostdev,
                                   const char *name,
                                   bool addDevice)
{
    g_autofree char *dev_path = NULL;
    g_autofree char *key = NULL;
    int ret = -1;

    if (!qemuIsSharedHostdev(hostdev))
        return 0;

    if (!(dev_path = qemuGetHostdevPath(hostdev)) ||
        !(key = qemuGetSharedDeviceKey(dev_path)))
        return -1;

    qemuDriverLock(driver);

    if (addDevice)
        ret = qemuSharedDeviceEntryInsert(driver, key, name);
    else
        ret = qemuSharedDeviceEntryRemove(driver, key, name);

    qemuDriverUnlock(driver);

    return ret;
}

static int
qemuSharedDeviceAddRemoveInternal(virQEMUDriverPtr driver,
                                  virDomainDeviceDefPtr dev,
                                  const char *name,
                                  bool addDevice)
{
    /* Currently the only conflicts we have to care about for
     * the shared disk and shared host device is "sgio" setting,
     * which is only valid for block disk and scsi host device.
     */
    if (dev->type == VIR_DOMAIN_DEVICE_DISK)
        return qemuSharedDiskAddRemoveInternal(driver, dev->data.disk,
                                               name, addDevice);
    else if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV)
        return qemuSharedHostdevAddRemoveInternal(driver, dev->data.hostdev,
                                                  name, addDevice);
    else
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
    return qemuSharedDeviceAddRemoveInternal(driver, dev, name, true);
}


int
qemuRemoveSharedDisk(virQEMUDriverPtr driver,
                     virDomainDiskDefPtr disk,
                     const char *name)
{
    return qemuSharedDiskAddRemoveInternal(driver, disk, name, false);
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
    return qemuSharedDeviceAddRemoveInternal(driver, dev, name, false);
}


int
qemuSetUnprivSGIO(virDomainDeviceDefPtr dev)
{
    virDomainDiskDefPtr disk = NULL;
    virDomainHostdevDefPtr hostdev = NULL;
    g_autofree char *sysfs_path = NULL;
    const char *path = NULL;
    int val = -1;

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
            return -1;
        }

        return 0;
    } else {
        return 0;
    }

    if (!(sysfs_path = virGetUnprivSGIOSysfsPath(path, NULL)))
        return -1;

    /* By default, filter the SG_IO commands, i.e. set unpriv_sgio to 0.  */
    val = (disk->sgio == VIR_DOMAIN_DEVICE_SGIO_UNFILTERED);

    /* Do not do anything if unpriv_sgio is not supported by the kernel and the
     * whitelist is enabled.  But if requesting unfiltered access, always call
     * virSetDeviceUnprivSGIO, to report an error for unsupported unpriv_sgio.
     */
    if ((virFileExists(sysfs_path) || val == 1) &&
        virSetDeviceUnprivSGIO(path, NULL, val) < 0)
        return -1;

    return 0;
}

int qemuDriverAllocateID(virQEMUDriverPtr driver)
{
    return virAtomicIntInc(&driver->lastvmid);
}


int
qemuTranslateSnapshotDiskSourcePool(virDomainSnapshotDiskDefPtr def)
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
    g_autofree char *base = qemuGetBaseHugepagePath(hugepage);
    g_autofree char *domPath = virDomainDefGetShortName(def);
    char *ret = NULL;

    if (base && domPath)
        ignore_value(virAsprintf(&ret, "%s/%s", base, domPath));
    return ret;
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

    return 0;
}


int
qemuGetMemoryBackingBasePath(virQEMUDriverConfigPtr cfg,
                             char **path)
{
    return virAsprintf(path, "%s/libvirt/qemu", cfg->memoryBackingDir);
}


int
qemuGetMemoryBackingDomainPath(const virDomainDef *def,
                               virQEMUDriverConfigPtr cfg,
                               char **path)
{
    g_autofree char *shortName = NULL;
    g_autofree char *base = NULL;

    if (!(shortName = virDomainDefGetShortName(def)) ||
        qemuGetMemoryBackingBasePath(cfg, &base) < 0 ||
        virAsprintf(path, "%s/%s", base, shortName) < 0)
        return -1;

    return 0;
}


/**
 * qemuGetMemoryBackingPath:
 * @def: domain definition
 * @cfg: the driver config
 * @alias: memory object alias
 * @memPath: constructed path
 *
 * Constructs path to memory backing dir and stores it at @memPath.
 *
 * Returns: 0 on success,
 *          -1 otherwise (with error reported).
 */
int
qemuGetMemoryBackingPath(const virDomainDef *def,
                         virQEMUDriverConfigPtr cfg,
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

    if (qemuGetMemoryBackingDomainPath(def, cfg, &domainPath) < 0 ||
        virAsprintf(memPath, "%s/%s", domainPath, alias) < 0)
        return -1;

    return 0;
}
