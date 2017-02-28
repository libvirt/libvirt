/*
 * qemu_command.h: QEMU command generation
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
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

#ifndef __QEMU_COMMAND_H__
# define __QEMU_COMMAND_H__

# include "domain_addr.h"
# include "domain_conf.h"
# include "vircommand.h"
# include "capabilities.h"
# include "qemu_conf.h"
# include "qemu_domain.h"
# include "qemu_domain_address.h"
# include "qemu_capabilities.h"
# include "logging/log_manager.h"

/* Config type for XML import/export conversions */
# define QEMU_CONFIG_FORMAT_ARGV "qemu-argv"

# define QEMU_FSDEV_HOST_PREFIX "fsdev-"

# define QEMU_BLOCK_IOTUNE_MAX 1000000000000000LL

VIR_ENUM_DECL(qemuVideo)

virCommandPtr qemuBuildCommandLine(virQEMUDriverPtr driver,
                                   virLogManagerPtr logManager,
                                   virDomainDefPtr def,
                                   virDomainChrSourceDefPtr monitor_chr,
                                   bool monitor_json,
                                   virQEMUCapsPtr qemuCaps,
                                   const char *migrateURI,
                                   virDomainSnapshotObjPtr snapshot,
                                   virNetDevVPortProfileOp vmop,
                                   bool standalone,
                                   bool enableFips,
                                   virBitmapPtr nodeset,
                                   size_t *nnicindexes,
                                   int **nicindexes,
                                   const char *domainLibDir,
                                   bool chardevStdioLogd)
    ATTRIBUTE_NONNULL(15);


/* Generate the object properties for a secret */
int qemuBuildSecretInfoProps(qemuDomainSecretInfoPtr secinfo,
                             virJSONValuePtr *propsret);

/* Generate the object properties for a tls-creds-x509 */
int qemuBuildTLSx509BackendProps(const char *tlspath,
                                 bool isListen,
                                 bool verifypeer,
                                 const char *secalias,
                                 virQEMUCapsPtr qemuCaps,
                                 virJSONValuePtr *propsret);

/* Generate '-device' string for chardev device */
int
qemuBuildChrDeviceStr(char **deviceStr,
                      const virDomainDef *vmdef,
                      virDomainChrDefPtr chr,
                      virQEMUCapsPtr qemuCaps);

/* With vlan == -1, use netdev syntax, else old hostnet */
char *qemuBuildHostNetStr(virDomainNetDefPtr net,
                          virQEMUDriverPtr driver,
                          char type_sep,
                          int vlan,
                          char **tapfd,
                          size_t tapfdSize,
                          char **vhostfd,
                          size_t vhostfdSize);

/* Legacy, pre device support */
char *qemuBuildNicStr(virDomainNetDefPtr net,
                      const char *prefix,
                      int vlan);

/* Current, best practice */
char *qemuBuildNicDevStr(virDomainDefPtr def,
                         virDomainNetDefPtr net,
                         int vlan,
                         unsigned int bootindex,
                         size_t vhostfdSize,
                         virQEMUCapsPtr qemuCaps);

char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk);

/* Both legacy & current support */
char *qemuBuildDriveStr(virDomainDiskDefPtr disk,
                        virQEMUDriverConfigPtr cfg,
                        bool bootable,
                        virQEMUCapsPtr qemuCaps);

/* Current, best practice */
char *qemuBuildDriveDevStr(const virDomainDef *def,
                           virDomainDiskDefPtr disk,
                           unsigned int bootindex,
                           virQEMUCapsPtr qemuCaps);

/* Current, best practice */
int qemuBuildControllerDevStr(const virDomainDef *domainDef,
                              virDomainControllerDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              char **devstr,
                              int *nusbcontroller);

int qemuBuildMemoryBackendStr(virJSONValuePtr *backendProps,
                              const char **backendType,
                              virQEMUDriverConfigPtr cfg,
                              virQEMUCapsPtr qemuCaps,
                              virDomainDefPtr def,
                              virDomainMemoryDefPtr mem,
                              virBitmapPtr autoNodeset,
                              bool force);

char *qemuBuildMemoryDeviceStr(virDomainMemoryDefPtr mem);

/* Current, best practice */
char *qemuBuildPCIHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDefPtr dev,
                                unsigned int bootIndex,
                                const char *configfd,
                                virQEMUCapsPtr qemuCaps);

char *qemuBuildRNGDevStr(const virDomainDef *def,
                         virDomainRNGDefPtr dev,
                         virQEMUCapsPtr qemuCaps);
int qemuBuildRNGBackendProps(virDomainRNGDefPtr rng,
                             virQEMUCapsPtr qemuCaps,
                             const char **type,
                             virJSONValuePtr *props);

int qemuOpenPCIConfig(virDomainHostdevDefPtr dev);

/* Current, best practice */
char *qemuBuildUSBHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDefPtr dev,
                                virQEMUCapsPtr qemuCaps);

char *qemuBuildSCSIHostdevDrvStr(virDomainHostdevDefPtr dev);

char *qemuBuildSCSIHostdevDevStr(const virDomainDef *def,
                                 virDomainHostdevDefPtr dev,
                                 virQEMUCapsPtr qemuCaps);
char *
qemuBuildSCSIVHostHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDefPtr dev,
                                virQEMUCapsPtr qemuCaps,
                                char *vhostfdName);

char *
qemuBuildHostdevMediatedDevStr(const virDomainDef *def,
                               virDomainHostdevDefPtr dev,
                               virQEMUCapsPtr qemuCaps);

char *qemuBuildRedirdevDevStr(const virDomainDef *def,
                              virDomainRedirdevDefPtr dev,
                              virQEMUCapsPtr qemuCaps);

int qemuNetworkPrepareDevices(virDomainDefPtr def);

int qemuGetDriveSourceString(virStorageSourcePtr src,
                             qemuDomainSecretInfoPtr secinfo,
                             char **source);

int qemuCheckDiskConfig(virDomainDiskDefPtr disk);

bool
qemuCheckFips(void);

bool qemuCheckCCWS390AddressSupport(const virDomainDef *def,
                                    virDomainDeviceInfo info,
                                    virQEMUCapsPtr qemuCaps,
                                    const char *devicename);

virJSONValuePtr qemuBuildHotpluggableCPUProps(const virDomainVcpuDef *vcpu)
    ATTRIBUTE_NONNULL(1);

virJSONValuePtr qemuBuildShmemBackendMemProps(virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1);

char *qemuBuildShmemDevStr(virDomainDefPtr def,
                           virDomainShmemDefPtr shmem,
                           virQEMUCapsPtr qemuCaps)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);



#endif /* __QEMU_COMMAND_H__*/
