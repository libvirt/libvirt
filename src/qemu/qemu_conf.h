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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMUD_CONF_H
# define __QEMUD_CONF_H

# include <unistd.h>

# include "virebtables.h"
# include "internal.h"
# include "capabilities.h"
# include "network_conf.h"
# include "domain_conf.h"
# include "snapshot_conf.h"
# include "domain_event.h"
# include "virthread.h"
# include "security/security_manager.h"
# include "virpci.h"
# include "virusb.h"
# include "virscsi.h"
# include "cpu_conf.h"
# include "driver.h"
# include "virportallocator.h"
# include "vircommand.h"
# include "virthreadpool.h"
# include "locking/lock_manager.h"
# include "qemu_capabilities.h"
# include "virclosecallbacks.h"
# include "virhostdev.h"
# include "virfile.h"
# include "virfirmware.h"

# ifdef CPU_SETSIZE /* Linux */
#  define QEMUD_CPUMASK_LEN CPU_SETSIZE
# elif defined(_SC_NPROCESSORS_CONF) /* Cygwin */
#  define QEMUD_CPUMASK_LEN (sysconf(_SC_NPROCESSORS_CONF))
# else
#  error "Port me"
# endif

# define QEMU_DRIVER_NAME "QEMU"

typedef struct _virQEMUDriver virQEMUDriver;
typedef virQEMUDriver *virQEMUDriverPtr;

typedef struct _virQEMUDriverConfig virQEMUDriverConfig;
typedef virQEMUDriverConfig *virQEMUDriverConfigPtr;

/* Main driver config. The data in these object
 * instances is immutable, so can be accessed
 * without locking. Threads must, however, hold
 * a valid reference on the object to prevent it
 * being released while they use it.
 *
 * eg
 *  qemuDriverLock(driver);
 *  virQEMUDriverConfigPtr cfg = virObjectRef(driver->config);
 *  qemuDriverUnlock(driver);
 *
 *  ...do stuff with 'cfg'..
 *
 *  virObjectUnref(cfg);
 */
struct _virQEMUDriverConfig {
    virObject parent;

    const char *uri;

    uid_t user;
    gid_t group;
    bool dynamicOwnership;

    virBitmapPtr namespaces;

    int cgroupControllers;
    char **cgroupDeviceACL;

    /* These five directories are ones libvirtd uses (so must be root:root
     * to avoid security risk from QEMU processes */
    char *configBaseDir;
    char *configDir;
    char *autostartDir;
    char *logDir;
    char *stateDir;
    /* These two directories are ones QEMU processes use (so must match
     * the QEMU user/group */
    char *libDir;
    char *cacheDir;
    char *saveDir;
    char *snapshotDir;
    char *channelTargetDir;
    char *nvramDir;

    char *defaultTLSx509certdir;
    bool defaultTLSx509verify;
    char *defaultTLSx509secretUUID;

    bool vncAutoUnixSocket;
    bool vncTLS;
    bool vncTLSx509verify;
    bool vncSASL;
    char *vncTLSx509certdir;
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
    char *chardevTLSx509secretUUID;

    unsigned int remotePortMin;
    unsigned int remotePortMax;

    unsigned int webSocketPortMin;
    unsigned int webSocketPortMax;

    virHugeTLBFSPtr hugetlbfs;
    size_t nhugetlbfs;

    char *bridgeHelperName;

    bool macFilter;

    bool relaxedACS;
    bool vncAllowHostAudio;
    bool nogfxAllowHostAudio;
    bool clearEmulatorCapabilities;
    bool allowDiskFormatProbing;
    bool setProcessName;

    unsigned int maxProcesses;
    unsigned int maxFiles;
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

    virFirmwarePtr *firmwares;
    size_t nfirmwares;
    unsigned int glusterDebugLevel;

    char *memoryBackingDir;
};

/* Main driver state */
struct _virQEMUDriver {
    virMutex lock;

    /* Require lock to get reference on 'config',
     * then lockless thereafter */
    virQEMUDriverConfigPtr config;

    /* Immutable pointer, self-locking APIs */
    virThreadPoolPtr workerPool;

    /* Atomic increment only */
    int lastvmid;

    /* Atomic inc/dec only */
    unsigned int nactive;

    /* Immutable value */
    bool privileged;

    /* Immutable pointers. Caller must provide locking */
    virStateInhibitCallback inhibitCallback;
    void *inhibitOpaque;

    /* Immutable pointer, self-locking APIs */
    virDomainObjListPtr domains;

    /* Immutable pointer */
    char *qemuImgBinary;

    /* Immutable pointer, lockless APIs. Pointless abstraction */
    ebtablesContext *ebtables;

    /* Require lock to get a reference on the object,
     * lockless access thereafter
     */
    virCapsPtr caps;

    /* Immutable pointer, Immutable object */
    virDomainXMLOptionPtr xmlopt;

    /* Immutable pointer, self-locking APIs */
    virQEMUCapsCachePtr qemuCapsCache;

    /* Immutable pointer, self-locking APIs */
    virObjectEventStatePtr domainEventState;

    /* Immutable pointer. self-locking APIs */
    virSecurityManagerPtr securityManager;

    virHostdevManagerPtr hostdevMgr;

    /* Immutable pointer. Unsafe APIs. XXX */
    virHashTablePtr sharedDevices;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorPtr remotePorts;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorPtr webSocketPorts;

    /* Immutable pointer, self-locking APIs */
    virPortAllocatorPtr migrationPorts;

    /* Immutable pointer, lockless APIs*/
    virSysinfoDefPtr hostsysinfo;

    /* Immutable pointer. lockless access */
    virLockManagerPluginPtr lockManager;

    /* Immutable pointer, self-clocking APIs */
    virCloseCallbacksPtr closeCallbacks;

    /* Immutable pointer, self-locking APIs */
    virHashAtomicPtr migrationErrors;
};

typedef struct _qemuDomainCmdlineDef qemuDomainCmdlineDef;
typedef qemuDomainCmdlineDef *qemuDomainCmdlineDefPtr;
struct _qemuDomainCmdlineDef {
    size_t num_args;
    char **args;

    unsigned int num_env;
    char **env_name;
    char **env_value;
};



void qemuDomainCmdlineDefFree(qemuDomainCmdlineDefPtr def);

virQEMUDriverConfigPtr virQEMUDriverConfigNew(bool privileged);

int virQEMUDriverConfigLoadFile(virQEMUDriverConfigPtr cfg,
                                const char *filename,
                                bool privileged);

virQEMUDriverConfigPtr virQEMUDriverGetConfig(virQEMUDriverPtr driver);
bool virQEMUDriverIsPrivileged(virQEMUDriverPtr driver);

virCapsPtr virQEMUDriverCreateCapabilities(virQEMUDriverPtr driver);
virCapsPtr virQEMUDriverGetCapabilities(virQEMUDriverPtr driver,
                                        bool refresh);

typedef struct _qemuSharedDeviceEntry qemuSharedDeviceEntry;
typedef qemuSharedDeviceEntry *qemuSharedDeviceEntryPtr;

bool qemuSharedDeviceEntryDomainExists(qemuSharedDeviceEntryPtr entry,
                                       const char *name,
                                       int *idx)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

char *qemuGetSharedDeviceKey(const char *disk_path)
    ATTRIBUTE_NONNULL(1);

void qemuSharedDeviceEntryFree(void *payload, const void *name);

int qemuAddSharedDevice(virQEMUDriverPtr driver,
                        virDomainDeviceDefPtr dev,
                        const char *name)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuRemoveSharedDevice(virQEMUDriverPtr driver,
                           virDomainDeviceDefPtr dev,
                           const char *name)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuRemoveSharedDisk(virQEMUDriverPtr driver,
                         virDomainDiskDefPtr disk,
                         const char *name)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuSetUnprivSGIO(virDomainDeviceDefPtr dev);

int qemuDriverAllocateID(virQEMUDriverPtr driver);
virDomainXMLOptionPtr virQEMUDriverCreateXMLConf(virQEMUDriverPtr driver);

int qemuTranslateSnapshotDiskSourcePool(virConnectPtr conn,
                                        virDomainSnapshotDiskDefPtr def);

char * qemuGetBaseHugepagePath(virHugeTLBFSPtr hugepage);
char * qemuGetDomainHugepagePath(const virDomainDef *def,
                                 virHugeTLBFSPtr hugepage);
char * qemuGetDomainDefaultHugepath(const virDomainDef *def,
                                    virHugeTLBFSPtr hugetlbfs,
                                    size_t nhugetlbfs);

int qemuGetDomainHupageMemPath(const virDomainDef *def,
                               virQEMUDriverConfigPtr cfg,
                               unsigned long long pagesize,
                               char **memPath);
#endif /* __QEMUD_CONF_H */
