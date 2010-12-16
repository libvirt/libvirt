/*
 * qemu_conf.h: QEMU configuration management
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
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
# include <stdbool.h>

# include "ebtables.h"
# include "internal.h"
# include "bridge.h"
# include "capabilities.h"
# include "network_conf.h"
# include "domain_conf.h"
# include "domain_event.h"
# include "threads.h"
# include "security/security_driver.h"
# include "cgroup.h"
# include "pci.h"
# include "cpu_conf.h"
# include "driver.h"
# include "bitmap.h"
# include "macvtap.h"
# include "command.h"
# include "threadpool.h"

# define QEMUD_CPUMASK_LEN CPU_SETSIZE


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

    brControl *brctl;
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

    virCapsPtr caps;

    /* An array of callbacks */
    virDomainEventCallbackListPtr domainEventCallbacks;
    virDomainEventQueuePtr domainEventQueue;
    int domainEventTimer;
    int domainEventDispatching;

    char *securityDriverName;
    virSecurityDriverPtr securityDriver;
    virSecurityDriverPtr securityPrimaryDriver;
    virSecurityDriverPtr securitySecondaryDriver;

    char *saveImageFormat;
    char *dumpImageFormat;

    char *autoDumpPath;

    pciDeviceList *activePciHostdevs;

    virBitmapPtr reservedVNCPorts;

    virSysinfoDefPtr hostsysinfo;
};

typedef struct _qemuDomainPCIAddressSet qemuDomainPCIAddressSet;
typedef qemuDomainPCIAddressSet *qemuDomainPCIAddressSetPtr;

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

/* Config type for XML import/export conversions */
# define QEMU_CONFIG_FORMAT_ARGV "qemu-argv"

# define QEMU_DRIVE_HOST_PREFIX "drive-"
# define QEMU_VIRTIO_SERIAL_PREFIX "virtio-serial"
# define QEMU_FSDEV_HOST_PREFIX "fsdev-"

# define qemuReportError(code, ...)                                      \
    virReportErrorHelper(NULL, VIR_FROM_QEMU, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


int qemudLoadDriverConfig(struct qemud_driver *driver,
                          const char *filename);

virCommandPtr qemudBuildCommandLine     (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         virDomainDefPtr def,
                                         virDomainChrDefPtr monitor_chr,
                                         bool monitor_json,
                                         unsigned long long qemuCmdFlags,
                                         const char *migrateFrom,
                                         virDomainSnapshotObjPtr current_snapshot,
                                         enum virVMOperationType vmop)
    ATTRIBUTE_NONNULL(1);

/* With vlan == -1, use netdev syntax, else old hostnet */
char * qemuBuildHostNetStr(virDomainNetDefPtr net,
                           char type_sep,
                           int vlan,
                           const char *tapfd,
                           const char *vhostfd);

/* Legacy, pre device support */
char * qemuBuildNicStr(virDomainNetDefPtr net,
                       const char *prefix,
                       int vlan);

/* Current, best practice */
char * qemuBuildNicDevStr(virDomainNetDefPtr net,
                          int vlan);

char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk,
                               unsigned long long qemudCmdFlags);

/* Both legacy & current support */
char *qemuBuildDriveStr(virDomainDiskDefPtr disk,
                        int bootable,
                        unsigned long long qemuCmdFlags);
char *qemuBuildFSStr(virDomainFSDefPtr fs,
                     unsigned long long qemuCmdFlags);

/* Current, best practice */
char * qemuBuildDriveDevStr(virDomainDiskDefPtr disk);
char * qemuBuildFSDevStr(virDomainFSDefPtr fs);
/* Current, best practice */
char * qemuBuildControllerDevStr(virDomainControllerDefPtr def);

char * qemuBuildWatchdogDevStr(virDomainWatchdogDefPtr dev);

char * qemuBuildMemballoonDevStr(virDomainMemballoonDefPtr dev);

char * qemuBuildUSBInputDevStr(virDomainInputDefPtr dev);

char * qemuBuildSoundDevStr(virDomainSoundDefPtr sound);

/* Legacy, pre device support */
char * qemuBuildPCIHostdevPCIDevStr(virDomainHostdevDefPtr dev);
/* Current, best practice */
char * qemuBuildPCIHostdevDevStr(virDomainHostdevDefPtr dev,
                                 const char *configfd);

int qemudOpenPCIConfig(virDomainHostdevDefPtr dev);

/* Current, best practice */
char * qemuBuildChrChardevStr(virDomainChrDefPtr dev);
/* Legacy, pre device support */
char * qemuBuildChrArgStr(virDomainChrDefPtr dev, const char *prefix);

char * qemuBuildVirtioSerialPortDevStr(virDomainChrDefPtr dev);

/* Legacy, pre device support */
char * qemuBuildUSBHostdevUsbDevStr(virDomainHostdevDefPtr dev);
/* Current, best practice */
char * qemuBuildUSBHostdevDevStr(virDomainHostdevDefPtr dev);



int         qemudNetworkIfaceConnect    (virConnectPtr conn,
                                         struct qemud_driver *driver,
                                         virDomainNetDefPtr net,
                                         unsigned long long qemuCmdFlags)
    ATTRIBUTE_NONNULL(1);

int
qemudOpenVhostNet(virDomainNetDefPtr net,
                  unsigned long long qemuCmdFlags);

int qemudPhysIfaceConnect(virConnectPtr conn,
                          struct qemud_driver *driver,
                          virDomainNetDefPtr net,
                          unsigned long long qemuCmdFlags,
                          const unsigned char *vmuuid,
                          enum virVMOperationType vmop);

int         qemudCanonicalizeMachine    (struct qemud_driver *driver,
                                         virDomainDefPtr def);

virDomainDefPtr qemuParseCommandLine(virCapsPtr caps,
                                     const char **progenv,
                                     const char **progargv);
virDomainDefPtr qemuParseCommandLineString(virCapsPtr caps,
                                           const char *args);

qemuDomainPCIAddressSetPtr qemuDomainPCIAddressSetCreate(virDomainDefPtr def);
int qemuDomainPCIAddressReserveSlot(qemuDomainPCIAddressSetPtr addrs,
                                    int slot);
int qemuDomainPCIAddressReserveAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev);
int qemuDomainPCIAddressSetNextAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev);
int qemuDomainPCIAddressEnsureAddr(qemuDomainPCIAddressSetPtr addrs,
                                   virDomainDeviceInfoPtr dev);
int qemuDomainPCIAddressReleaseAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev);

void qemuDomainPCIAddressSetFree(qemuDomainPCIAddressSetPtr addrs);
int  qemuAssignDevicePCISlots(virDomainDefPtr def, qemuDomainPCIAddressSetPtr addrs);

int qemuDomainNetVLAN(virDomainNetDefPtr def);
int qemuAssignDeviceNetAlias(virDomainDefPtr def, virDomainNetDefPtr net, int idx);
int qemuAssignDeviceDiskAlias(virDomainDiskDefPtr def, unsigned long long qemuCmdFlags);
int qemuAssignDeviceHostdevAlias(virDomainDefPtr def, virDomainHostdevDefPtr net, int idx);
int qemuAssignDeviceControllerAlias(virDomainControllerDefPtr controller);

int
qemuParseKeywords(const char *str,
                  char ***retkeywords,
                  char ***retvalues,
                  int allowEmptyValue);


#endif /* __QEMUD_CONF_H */
