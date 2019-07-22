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
 */

#pragma once

#include "domain_addr.h"
#include "domain_conf.h"
#include "vircommand.h"
#include "virenum.h"
#include "capabilities.h"
#include "qemu_block.h"
#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"
#include "qemu_capabilities.h"
#include "logging/log_manager.h"

/* Config type for XML import/export conversions */
#define QEMU_CONFIG_FORMAT_ARGV "qemu-argv"

#define QEMU_FSDEV_HOST_PREFIX "fsdev-"

#define QEMU_BLOCK_IOTUNE_MAX 1000000000000000LL

VIR_ENUM_DECL(qemuVideo);

virCommandPtr qemuBuildCommandLine(virQEMUDriverPtr driver,
                                   virLogManagerPtr logManager,
                                   virSecurityManagerPtr secManager,
                                   virDomainObjPtr vm,
                                   const char *migrateURI,
                                   virDomainMomentObjPtr snapshot,
                                   virNetDevVPortProfileOp vmop,
                                   bool standalone,
                                   bool enableFips,
                                   size_t *nnicindexes,
                                   int **nicindexes);

/* Generate the object properties for pr-manager */
virJSONValuePtr qemuBuildPRManagerInfoProps(virStorageSourcePtr src);
virJSONValuePtr qemuBuildPRManagedManagerInfoProps(qemuDomainObjPrivatePtr priv);

/* Generate the object properties for a secret */
int qemuBuildSecretInfoProps(qemuDomainSecretInfoPtr secinfo,
                             virJSONValuePtr *propsret);

/* Generate the object properties for a tls-creds-x509 */
int qemuBuildTLSx509BackendProps(const char *tlspath,
                                 bool isListen,
                                 bool verifypeer,
                                 const char *alias,
                                 const char *secalias,
                                 virQEMUCapsPtr qemuCaps,
                                 virJSONValuePtr *propsret);

/* Open a UNIX socket for chardev FD passing */
int
qemuOpenChrChardevUNIXSocket(const virDomainChrSourceDef *dev);

/* Generate '-device' string for chardev device */
int
qemuBuildChrDeviceStr(char **deviceStr,
                      const virDomainDef *vmdef,
                      virDomainChrDefPtr chr,
                      virQEMUCapsPtr qemuCaps);

char *qemuBuildHostNetStr(virDomainNetDefPtr net,
                          virQEMUDriverPtr driver,
                          char **tapfd,
                          size_t tapfdSize,
                          char **vhostfd,
                          size_t vhostfdSize);

/* Current, best practice */
char *qemuBuildNicDevStr(virDomainDefPtr def,
                         virDomainNetDefPtr net,
                         unsigned int bootindex,
                         size_t vhostfdSize,
                         virQEMUCapsPtr qemuCaps);

char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk);
bool qemuDiskBusNeedsDriveArg(int bus);

qemuBlockStorageSourceAttachDataPtr
qemuBuildStorageSourceAttachPrepareDrive(virDomainDiskDefPtr disk,
                                         virQEMUCapsPtr qemuCaps);
int
qemuBuildStorageSourceAttachPrepareCommon(virStorageSourcePtr src,
                                          qemuBlockStorageSourceAttachDataPtr data,
                                          virQEMUCapsPtr qemuCaps);


qemuBlockStorageSourceChainDataPtr
qemuBuildStorageSourceChainAttachPrepareDrive(virDomainDiskDefPtr disk,
                                              virQEMUCapsPtr qemuCaps);


qemuBlockStorageSourceChainDataPtr
qemuBuildStorageSourceChainAttachPrepareBlockdev(virStorageSourcePtr top,
                                                 virQEMUCapsPtr qemuCaps);

qemuBlockStorageSourceChainDataPtr
qemuBuildStorageSourceChainAttachPrepareBlockdevTop(virStorageSourcePtr top,
                                                    virQEMUCapsPtr qemuCaps);

char
*qemuBuildDiskDeviceStr(const virDomainDef *def,
                        virDomainDiskDefPtr disk,
                        unsigned int bootindex,
                        virQEMUCapsPtr qemuCaps);

/* Current, best practice */
int qemuBuildControllerDevStr(const virDomainDef *domainDef,
                              virDomainControllerDefPtr def,
                              virQEMUCapsPtr qemuCaps,
                              char **devstr);

int qemuBuildMemoryBackendProps(virJSONValuePtr *backendProps,
                                const char *alias,
                                virQEMUDriverConfigPtr cfg,
                                qemuDomainObjPrivatePtr priv,
                                virDomainDefPtr def,
                                virDomainMemoryDefPtr mem,
                                bool force);

char *qemuBuildMemoryDeviceStr(virDomainMemoryDefPtr mem,
                               qemuDomainObjPrivatePtr priv);

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
                             virJSONValuePtr *props);

int qemuOpenPCIConfig(virDomainHostdevDefPtr dev);

/* Current, best practice */
char *qemuBuildUSBHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDefPtr dev,
                                virQEMUCapsPtr qemuCaps);

char *qemuBuildSCSIHostdevDrvStr(virDomainHostdevDefPtr dev,
                                 virQEMUCapsPtr qemuCaps);

char *qemuBuildSCSIHostdevDevStr(const virDomainDef *def,
                                 virDomainHostdevDefPtr dev);
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

char *qemuBuildZPCIDevStr(virDomainDeviceInfoPtr dev);

int qemuNetworkPrepareDevices(virDomainDefPtr def);

int qemuGetDriveSourceString(virStorageSourcePtr src,
                             qemuDomainSecretInfoPtr secinfo,
                             char **source);

bool
qemuDiskConfigBlkdeviotuneEnabled(virDomainDiskDefPtr disk);

int qemuCheckDiskConfig(virDomainDiskDefPtr disk,
                        virQEMUCapsPtr qemuCaps);

bool
qemuCheckFips(void);

virJSONValuePtr qemuBuildHotpluggableCPUProps(const virDomainVcpuDef *vcpu)
    ATTRIBUTE_NONNULL(1);

virJSONValuePtr qemuBuildShmemBackendMemProps(virDomainShmemDefPtr shmem)
    ATTRIBUTE_NONNULL(1);

char *qemuBuildShmemDevStr(virDomainDefPtr def,
                           virDomainShmemDefPtr shmem,
                           virQEMUCapsPtr qemuCaps)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

char *qemuBuildWatchdogDevStr(const virDomainDef *def,
                              virDomainWatchdogDefPtr dev,
                              virQEMUCapsPtr qemuCaps);

int qemuBuildInputDevStr(char **devstr,
                         const virDomainDef *def,
                         virDomainInputDefPtr input,
                         virQEMUCapsPtr qemuCaps)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

char *
qemuBuildVsockDevStr(virDomainDefPtr def,
                     virDomainVsockDefPtr vsock,
                     virQEMUCapsPtr qemuCaps,
                     const char *fdprefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

/* this function is exported so that tests can mock the FDs */
int
qemuBuildTPMOpenBackendFDs(const char *tpmdev,
                           const char *cancel_path,
                           int *tpmfd,
                           int *cancelfd)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);
