/*
 * qemu_conf.h: QEMU configuration management
 *
 * Copyright (C) 2006-2007, 2009-2013 Red Hat, Inc.
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

#pragma once

#include <unistd.h>

#include "virebtables.h"
#include "internal.h"
#include "domain_conf.h"
#include "checkpoint_conf.h"
#include "snapshot_conf.h"
#include "domain_event.h"
#include "virthread.h"
#include "security/security_manager.h"
#include "cpu_conf.h"
#include "virportallocator.h"
#include "virthreadpool.h"
#include "locking/lock_manager.h"
#include "qemu_capabilities.h"
#include "qemu_nbdkit.h"
#include "virclosecallbacks.h"
#include "virhostdev.h"
#include "virfile.h"
#include "virfilecache.h"
#include "virfirmware.h"

#define QEMU_DRIVER_NAME "QEMU"

typedef enum {
    QEMU_SCHED_CORE_NONE = 0,
    QEMU_SCHED_CORE_VCPUS,
    QEMU_SCHED_CORE_EMULATOR,
    QEMU_SCHED_CORE_FULL,

    QEMU_SCHED_CORE_LAST
} virQEMUSchedCore;

VIR_ENUM_DECL(virQEMUSchedCore);

typedef struct _virQEMUDriver virQEMUDriver;

typedef struct _virQEMUDriverConfig virQEMUDriverConfig;

/* Main driver config. The data in these object
 * instances is immutable, so can be accessed
 * without locking. Threads must, however, hold
 * a valid reference on the object to prevent it
 * being released while they use it.
 *
 * eg
 *  g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
 *
 *  ...do stuff with 'cfg'..
 */
struct _virQEMUDriverConfig {
    virObject parent;

    char *uri;

    uid_t user;
    gid_t group;
    bool dynamicOwnership;

    virBitmap *namespaces;
    bool rememberOwner;

    int cgroupControllers;
    char **cgroupDeviceACL;

    /* These five directories are ones libvirtd uses (so must be root:root
     * to avoid security risk from QEMU processes */
    char *configBaseDir;
    char *configDir;
    char *autostartDir;
    char *logDir;
    char *swtpmLogDir;
    char *stateDir;
    char *swtpmStateDir;
    char *slirpStateDir;
    char *passtStateDir;
    char *dbusStateDir;
    /* These two directories are ones QEMU processes use (so must match
     * the QEMU user/group */
    char *libDir;
    char *cacheDir;
    char *saveDir;
    char *snapshotDir;
    char *checkpointDir;
    char *channelTargetDir;
    char *nvramDir;
    char *swtpmStorageDir;

    char *defaultTLSx509certdir;
    bool defaultTLSx509certdirPresent;
    bool defaultTLSx509verify;
    bool defaultTLSx509verifyPresent;
    char *defaultTLSx509secretUUID;

    bool vncAutoUnixSocket;
    bool vncTLS;
    bool vncTLSx509verify;
    bool vncTLSx509verifyPresent;
    bool vncSASL;
    char *vncTLSx509certdir;
    char *vncTLSx509secretUUID;
    char *vncListen;
    char *vncPassword;
    char *vncSASLdir;

    bool spiceTLS;
    char *spiceTLSx509certdir;
    bool spiceSASL;
    char *spiceSASLdir;
    char *spiceListen;
    char *spicePassword;
    bool spiceAutoUnixSocket;

    bool chardevTLS;
    char *chardevTLSx509certdir;
    bool chardevTLSx509verify;
    bool chardevTLSx509verifyPresent;
    char *chardevTLSx509secretUUID;

    char *migrateTLSx509certdir;
    bool migrateTLSx509verify;
    bool migrateTLSx509verifyPresent;
    char *migrateTLSx509secretUUID;
    bool migrateTLSForce;

    char *backupTLSx509certdir;
    bool backupTLSx509verify;
    bool backupTLSx509verifyPresent;
    char *backupTLSx509secretUUID;

    bool vxhsTLS;
    char *vxhsTLSx509certdir;
    char *vxhsTLSx509secretUUID;

    bool nbdTLS;
    char *nbdTLSx509certdir;
    char *nbdTLSx509secretUUID;

    unsigned int remotePortMin;
    unsigned int remotePortMax;

    unsigned int webSocketPortMin;
    unsigned int webSocketPortMax;

    virHugeTLBFS *hugetlbfs;
    size_t nhugetlbfs;

    char *bridgeHelperName;
    char *prHelperName;
    char *slirpHelperName;
    char *dbusDaemonName;

    bool macFilter;

    bool relaxedACS;
    bool vncAllowHostAudio;
    bool nogfxAllowHostAudio;
    bool setProcessName;

    unsigned int maxProcesses;
    unsigned int maxFiles;
    unsigned int maxThreadsPerProc;
    unsigned long long maxCore;
    bool dumpGuestCore;

    unsigned int maxQueuedJobs;

    char **securityDriverNames;
    bool securityDefaultConfined;
    bool securityRequireConfined;

    char *saveImageFormat;
    char *dumpImageFormat;
    char *snapshotImageFormat;

    char *autoDumpPath;
    bool autoDumpBypassCache;
    bool autoStartBypassCache;

    char *lockManagerName;

    int keepAliveInterval;
    unsigned int keepAliveCount;

    int seccompSandbox;

    char *migrateHost;
    /* The default for -incoming */
    char *migrationAddress;
    unsigned int migrationPortMin;
    unsigned int migrationPortMax;

    bool logTimestamp;
    bool stdioLogD;

    virFirmware **firmwares;
    size_t nfirmwares;
    unsigned int glusterDebugLevel;
    bool virtiofsdDebug;

    char *memoryBackingDir;

    uid_t swtpm_user;
    gid_t swtpm_group;

    char **capabilityfilters;

    char *deprecationBehavior;

    virQEMUSchedCore schedCore;
};

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virQEMUDriverConfig, virObjectUnref);


/* Main driver state */
struct _virQEMUDriver {
    virMutex lock;

    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    virQEMUDriverConfig *config;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    /* Immutable pointer, self-locking APIs */
    virThreadPool *workerPool;

    /* Atomic increment only */
    int lastvmid;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable values */
    bool privileged;
    char *embeddedRoot;
    bool hostFips; /* FIPS mode is enabled on the host */

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjList *domains;

    /* Immutable pointer */
    char *qemuImgBinary;

    /* Immutable pointer, lockless APIs. Pointless abstraction */
    ebtablesContext *ebtables;

    /* Require lock to get a reference on the object,
     * lockless access thereafter
     */
    virCaps *caps;

    /* Lazy initialized on first use, immutable thereafter.
     * Require lock to get the pointer & do optional initialization
     */
    virCPUDef *hostcpu;

    /* Immutable value */
    virArch hostarch;

    /* Immutable pointer, Immutable object */
    virDomainXMLOption *xmlopt;

    /* Immutable pointer, self-locking APIs */
    virFileCache *qemuCapsCache;

    /* Immutable pointer, self-locking APIs */
    virObjectEventState *domainEventState;

    /* Immutable pointer. self-locking APIs */
    virSecurityManager *securityManager;

    virHostdevManager *hostdevMgr;

    /* Immutable pointer, immutable object */
    virPortAllocatorRange *remotePorts;

    /* Immutable pointer, immutable object */
    virPortAllocatorRange *webSocketPorts;

    /* Immutable pointer, immutable object */
    virPortAllocatorRange *migrationPorts;

    /* Immutable pointer, lockless APIs */
    virSysinfoDef *hostsysinfo;

    /* Immutable pointer. lockless access */
    virLockManagerPlugin *lockManager;

    /* Immutable pointer, self-locking APIs */
    virHashAtomic *migrationErrors;

    /* Immutable pointer, self-locking APIs */
    virFileCache *nbdkitCapsCache;
};

virQEMUDriverConfig *virQEMUDriverConfigNew(bool privileged,
                                              const char *root);

int virQEMUDriverConfigLoadFile(virQEMUDriverConfig *cfg,
                                const char *filename,
                                bool privileged);

int
virQEMUDriverConfigValidate(virQEMUDriverConfig *cfg);

int
virQEMUDriverConfigSetDefaults(virQEMUDriverConfig *cfg);

virQEMUDriverConfig *virQEMUDriverGetConfig(virQEMUDriver *driver);

virCPUDef *virQEMUDriverGetHostCPU(virQEMUDriver *driver);
virCaps *virQEMUDriverCreateCapabilities(virQEMUDriver *driver);
virCaps *virQEMUDriverGetCapabilities(virQEMUDriver *driver,
                                        bool refresh);

virDomainCaps *
virQEMUDriverGetDomainCapabilities(virQEMUDriver *driver,
                                   virQEMUCaps *qemuCaps,
                                   const char *machine,
                                   virArch arch,
                                   virDomainVirtType virttype);

int qemuDriverAllocateID(virQEMUDriver *driver);
virDomainXMLOption *virQEMUDriverCreateXMLConf(virQEMUDriver *driver,
                                                 const char *defsecmodel);

int qemuTranslateSnapshotDiskSourcePool(virDomainSnapshotDiskDef *def);

char * qemuGetBaseHugepagePath(virQEMUDriver *driver,
                               virHugeTLBFS *hugepage);
char * qemuGetDomainHugepagePath(virQEMUDriver *driver,
                                 const virDomainDef *def,
                                 virHugeTLBFS *hugepage);

int qemuGetDomainHupageMemPath(virQEMUDriver *driver,
                               const virDomainDef *def,
                               unsigned long long pagesize,
                               char **memPath);

int qemuGetMemoryBackingDomainPath(virQEMUDriver *driver,
                                   const virDomainDef *def,
                                   char **path);
int qemuGetMemoryBackingPath(virQEMUDriver *driver,
                             const virDomainDef *def,
                             const char *alias,
                             char **memPath);

int qemuHugepageMakeBasedir(virQEMUDriver *driver,
                            virHugeTLBFS *hugepage);

qemuNbdkitCaps* qemuGetNbdkitCaps(virQEMUDriver *driver);
