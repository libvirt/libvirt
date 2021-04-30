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
VIR_ENUM_DECL(qemuSoundCodec);

typedef enum {
    QEMU_BUILD_COMMANDLINE_VALIDATE_KEEP_JSON = 1 << 0,
} qemuBuildCommandLineFlags;

virCommand *qemuBuildCommandLine(virQEMUDriver *driver,
                                   virLogManager *logManager,
                                   virSecurityManager *secManager,
                                   virDomainObj *vm,
                                   const char *migrateURI,
                                   virDomainMomentObj *snapshot,
                                   virNetDevVPortProfileOp vmop,
                                   bool standalone,
                                   bool enableFips,
                                   size_t *nnicindexes,
                                   int **nicindexes,
                                   unsigned int flags);

/* Generate the object properties for pr-manager */
virJSONValue *qemuBuildPRManagerInfoProps(virStorageSource *src);
virJSONValue *qemuBuildPRManagedManagerInfoProps(qemuDomainObjPrivate *priv);

virJSONValue *qemuBuildDBusVMStateInfoProps(virQEMUDriver *driver,
                                              virDomainObj *vm);

/* Generate the object properties for a secret */
int qemuBuildSecretInfoProps(qemuDomainSecretInfo *secinfo,
                             virJSONValue **propsret);

/* Generate the object properties for a tls-creds-x509 */
int qemuBuildTLSx509BackendProps(const char *tlspath,
                                 bool isListen,
                                 bool verifypeer,
                                 const char *alias,
                                 const char *secalias,
                                 virQEMUCaps *qemuCaps,
                                 virJSONValue **propsret);

/* Open a UNIX socket for chardev FD passing */
int
qemuOpenChrChardevUNIXSocket(const virDomainChrSourceDef *dev) G_GNUC_NO_INLINE;

/* Generate '-device' string for chardev device */
int
qemuBuildChrDeviceStr(char **deviceStr,
                      const virDomainDef *vmdef,
                      virDomainChrDef *chr,
                      virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildChannelGuestfwdNetdevProps(virDomainChrDef *chr);

virJSONValue *qemuBuildHostNetStr(virDomainNetDef *net,
                                    char **tapfd,
                                    size_t tapfdSize,
                                    char **vhostfd,
                                    size_t vhostfdSize,
                                    const char *slirpfd,
                                    const char *vdpadev);

/* Current, best practice */
char *qemuBuildNicDevStr(virDomainDef *def,
                         virDomainNetDef *net,
                         unsigned int bootindex,
                         size_t vhostfdSize,
                         virQEMUCaps *qemuCaps);

char *qemuDeviceDriveHostAlias(virDomainDiskDef *disk);
bool qemuDiskBusIsSD(int bus);

qemuBlockStorageSourceAttachData *
qemuBuildStorageSourceAttachPrepareDrive(virDomainDiskDef *disk,
                                         virQEMUCaps *qemuCaps);

qemuBlockStorageSourceAttachData *
qemuBuildStorageSourceAttachPrepareChardev(virDomainDiskDef *disk);

int
qemuBuildStorageSourceAttachPrepareCommon(virStorageSource *src,
                                          qemuBlockStorageSourceAttachData *data,
                                          virQEMUCaps *qemuCaps);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareDrive(virDomainDiskDef *disk,
                                              virQEMUCaps *qemuCaps);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareChardev(virDomainDiskDef *disk);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdev(virStorageSource *top,
                                                 virQEMUCaps *qemuCaps);

qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdevTop(virStorageSource *top,
                                                    virStorageSource *backingStore,
                                                    virQEMUCaps *qemuCaps);

char
*qemuBuildDiskDeviceStr(const virDomainDef *def,
                        virDomainDiskDef *disk,
                        virQEMUCaps *qemuCaps);

/* Current, best practice */
int qemuBuildControllerDevStr(const virDomainDef *domainDef,
                              virDomainControllerDef *def,
                              virQEMUCaps *qemuCaps,
                              char **devstr);

int qemuBuildMemoryBackendProps(virJSONValue **backendProps,
                                const char *alias,
                                virQEMUDriverConfig *cfg,
                                qemuDomainObjPrivate *priv,
                                const virDomainDef *def,
                                const virDomainMemoryDef *mem,
                                bool force,
                                bool systemMemory);

char *
qemuBuildMemoryDeviceStr(const virDomainDef *def,
                         virDomainMemoryDef *mem,
                         virQEMUCaps *qemuCaps);

/* Current, best practice */
char *qemuBuildPCIHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDef *dev,
                                unsigned int bootIndex,
                                virQEMUCaps *qemuCaps);

char *qemuBuildRNGDevStr(const virDomainDef *def,
                         virDomainRNGDef *dev,
                         virQEMUCaps *qemuCaps);
int qemuBuildRNGBackendProps(virDomainRNGDef *rng,
                             virJSONValue **props);

/* Current, best practice */
char *qemuBuildUSBHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDef *dev,
                                virQEMUCaps *qemuCaps);

char *qemuBuildSCSIHostdevDevStr(const virDomainDef *def,
                                 virDomainHostdevDef *dev,
                                 const char *backendAlias);

qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIAttachPrepare(virDomainHostdevDef *hostdev,
                                  const char **backendAlias,
                                  virQEMUCaps *qemuCaps);
qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIDetachPrepare(virDomainHostdevDef *hostdev,
                                  virQEMUCaps *qemuCaps);

char *
qemuBuildSCSIVHostHostdevDevStr(const virDomainDef *def,
                                virDomainHostdevDef *dev,
                                virQEMUCaps *qemuCaps,
                                char *vhostfdName);

char *
qemuBuildHostdevMediatedDevStr(const virDomainDef *def,
                               virDomainHostdevDef *dev,
                               virQEMUCaps *qemuCaps);

char *qemuBuildRedirdevDevStr(const virDomainDef *def,
                              virDomainRedirdevDef *dev,
                              virQEMUCaps *qemuCaps);

char *qemuBuildZPCIDevStr(virDomainDeviceInfo *dev);

int qemuNetworkPrepareDevices(virDomainDef *def);

int qemuGetDriveSourceString(virStorageSource *src,
                             qemuDomainSecretInfo *secinfo,
                             char **source);

bool
qemuDiskConfigBlkdeviotuneEnabled(virDomainDiskDef *disk);


bool
qemuCheckFips(virDomainObj *vm);

virJSONValue *qemuBuildHotpluggableCPUProps(const virDomainVcpuDef *vcpu)
    ATTRIBUTE_NONNULL(1);

virJSONValue *qemuBuildShmemBackendMemProps(virDomainShmemDef *shmem)
    ATTRIBUTE_NONNULL(1);

char *qemuBuildShmemDevStr(virDomainDef *def,
                           virDomainShmemDef *shmem,
                           virQEMUCaps *qemuCaps)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

char *qemuBuildWatchdogDevStr(const virDomainDef *def,
                              virDomainWatchdogDef *dev,
                              virQEMUCaps *qemuCaps);

int qemuBuildInputDevStr(char **devstr,
                         const virDomainDef *def,
                         virDomainInputDef *input,
                         virQEMUCaps *qemuCaps)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4);

char *
qemuBuildVsockDevStr(virDomainDef *def,
                     virDomainVsockDef *vsock,
                     virQEMUCaps *qemuCaps,
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
    ATTRIBUTE_NONNULL(4) G_GNUC_NO_INLINE;
