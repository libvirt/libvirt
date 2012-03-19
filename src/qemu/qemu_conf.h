/*
 * qemu_conf.h: QEMU configuration management
 *
 * Copyright (C) 2006-2007, 2009-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __QEMUD_CONF_H
# define __QEMUD_CONF_H

# include <config.h>

# include "ebtables.h"
# include "internal.h"
# include "capabilities.h"
# include "network_conf.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "threads.h"
# include "security/security_manager.h"
# include "cgroup.h"
# include "pci.h"
# include "hostusb.h"
# include "cpu_conf.h"
# include "driver.h"
# include "bitmap.h"
# include "command.h"
# include "threadpool.h"
# include "locking/lock_manager.h"

# define QEMUD_CPUMASK_LEN CPU_SETSIZE

typedef struct _qemuDriverCloseDef qemuDriverCloseDef;
typedef qemuDriverCloseDef *qemuDriverCloseDefPtr;

/* Main driver state */
struct qemud_driver {
    virMutex lock;

    virThreadPoolPtr workerPool;

    int privileged;

    uid_t user;
    gid_t group;
    int dynamicOwnership;

    unsigned int qemuVersion;
    int nextvmid;

    virCgroupPtr cgroup;
    int cgroupControllers;
    char **cgroupDeviceACL;

    virDomainObjList domains;

    /* These four directories are ones libvirtd uses (so must be root:root
     * to avoid security risk from QEMU processes */
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
    char *qemuImgBinary;
    unsigned int vncAutoUnixSocket : 1;
    unsigned int vncTLS : 1;
    unsigned int vncTLSx509verify : 1;
    unsigned int vncSASL : 1;
    char *vncTLSx509certdir;
    char *vncListen;
    char *vncPassword;
    char *vncSASLdir;
    unsigned int spiceTLS : 1;
    char *spiceTLSx509certdir;
    char *spiceListen;
    char *spicePassword;
    char *hugetlbfs_mount;
    char *hugepage_path;

    unsigned int macFilter : 1;
    ebtablesContext *ebtables;

    unsigned int relaxedACS : 1;
    unsigned int vncAllowHostAudio : 1;
    unsigned int clearEmulatorCapabilities : 1;
    unsigned int allowDiskFormatProbing : 1;
    unsigned int setProcessName : 1;

    int maxProcesses;
    int maxFiles;

    int max_queued;

    virCapsPtr caps;

    virDomainEventStatePtr domainEventState;

    char *securityDriverName;
    bool securityDefaultConfined;
    bool securityRequireConfined;
    virSecurityManagerPtr securityManager;

    char *saveImageFormat;
    char *dumpImageFormat;

    char *autoDumpPath;
    bool autoDumpBypassCache;

    bool autoStartBypassCache;

    pciDeviceList *activePciHostdevs;
    usbDeviceList *activeUsbHostdevs;

    /* The devices which is are not in use by the host or any guest. */
    pciDeviceList *inactivePciHostdevs;

    virBitmapPtr reservedVNCPorts;

    virSysinfoDefPtr hostsysinfo;

    virLockManagerPluginPtr lockManager;

    /* Mapping of 'char *uuidstr' -> qemuDriverCloseDefPtr of domains
     * which want a specific cleanup to be done when a connection is
     * closed. Such cleanup may be to automatically destroy the
     * domain or abort a particular job running on it.
     */
    virHashTablePtr closeCallbacks;

    int keepAliveInterval;
    unsigned int keepAliveCount;
};

typedef struct _qemuDomainCmdlineDef qemuDomainCmdlineDef;
typedef qemuDomainCmdlineDef *qemuDomainCmdlineDefPtr;
struct _qemuDomainCmdlineDef {
    unsigned int num_args;
    char **args;

    unsigned int num_env;
    char **env_name;
    char **env_value;
};

/* Port numbers used for KVM migration. */
# define QEMUD_MIGRATION_FIRST_PORT 49152
# define QEMUD_MIGRATION_NUM_PORTS 64

# define qemuReportError(code, ...)                                      \
    virReportErrorHelper(VIR_FROM_QEMU, code, __FILE__,                  \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


void qemuDriverLock(struct qemud_driver *driver);
void qemuDriverUnlock(struct qemud_driver *driver);
int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename);

struct qemuDomainDiskInfo {
    bool removable;
    bool locked;
    bool tray_open;
    int io_status;
};

typedef virDomainObjPtr (*qemuDriverCloseCallback)(struct qemud_driver *driver,
                                                   virDomainObjPtr vm,
                                                   virConnectPtr conn);
int qemuDriverCloseCallbackInit(struct qemud_driver *driver);
void qemuDriverCloseCallbackShutdown(struct qemud_driver *driver);
int qemuDriverCloseCallbackSet(struct qemud_driver *driver,
                               virDomainObjPtr vm,
                               virConnectPtr conn,
                               qemuDriverCloseCallback cb);
int qemuDriverCloseCallbackUnset(struct qemud_driver *driver,
                                 virDomainObjPtr vm,
                                 qemuDriverCloseCallback cb);
qemuDriverCloseCallback qemuDriverCloseCallbackGet(struct qemud_driver *driver,
                                                   virDomainObjPtr vm,
                                                   virConnectPtr conn);
void qemuDriverCloseCallbackRunAll(struct qemud_driver *driver,
                                   virConnectPtr conn);

#endif /* __QEMUD_CONF_H */
