/*
 * qemu_command.h: QEMU command generation
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

#ifndef __QEMU_COMMAND_H__
# define __QEMU_COMMAND_H__

# include "domain_conf.h"
# include "command.h"
# include "capabilities.h"
# include "qemu_conf.h"
# include "qemu_domain.h"

/* Config type for XML import/export conversions */
# define QEMU_CONFIG_FORMAT_ARGV "qemu-argv"

# define QEMU_DRIVE_HOST_PREFIX "drive-"
# define QEMU_VIRTIO_SERIAL_PREFIX "virtio-serial"
# define QEMU_FSDEV_HOST_PREFIX "fsdev-"

virCommandPtr qemuBuildCommandLine(virConnectPtr conn,
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
                               unsigned long long qemuCmdFlags);

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

int qemuOpenPCIConfig(virDomainHostdevDefPtr dev);

/* Current, best practice */
char * qemuBuildChrChardevStr(virDomainChrDefPtr dev);
/* Legacy, pre device support */
char * qemuBuildChrArgStr(virDomainChrDefPtr dev, const char *prefix);

char * qemuBuildVirtioSerialPortDevStr(virDomainChrDefPtr dev);

/* Legacy, pre device support */
char * qemuBuildUSBHostdevUsbDevStr(virDomainHostdevDefPtr dev);
/* Current, best practice */
char * qemuBuildUSBHostdevDevStr(virDomainHostdevDefPtr dev);



int qemuNetworkIfaceConnect(virConnectPtr conn,
                            struct qemud_driver *driver,
                            virDomainNetDefPtr net,
                            unsigned long long qemCmdFlags)
    ATTRIBUTE_NONNULL(1);

int qemuOpenVhostNet(virDomainNetDefPtr net,
                     unsigned long long qemuCmdFlags);

int qemuPhysIfaceConnect(virConnectPtr conn,
                         struct qemud_driver *driver,
                         virDomainNetDefPtr net,
                         unsigned long long qemuCmdFlags,
                         const unsigned char *vmuuid,
                         enum virVMOperationType vmop);

int qemudCanonicalizeMachine(struct qemud_driver *driver,
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


#endif /* __QEMU_COMMAND_H__*/
