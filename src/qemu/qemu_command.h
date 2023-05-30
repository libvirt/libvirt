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

#include "domain_conf.h"
#include "virbitmap.h"
#include "vircommand.h"
#include "virenum.h"
#include "qemu_block.h"
#include "qemu_conf.h"
#include "qemu_domain.h"
#include "qemu_capabilities.h"

/* Config type for XML import/export conversions */
#define QEMU_CONFIG_FORMAT_ARGV "qemu-argv"

#define QEMU_FSDEV_HOST_PREFIX "fsdev-"

#define QEMU_BLOCK_IOTUNE_MAX 1000000000000000LL

VIR_ENUM_DECL(qemuVideo);
VIR_ENUM_DECL(qemuSoundCodec);

virCommand *qemuBuildCommandLine(virDomainObj *vm,
                                 const char *migrateURI,
                                 virDomainMomentObj *snapshot,
                                 virNetDevVPortProfileOp vmop,
                                 size_t *nnicindexes,
                                 int **nicindexes);

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
                                 virJSONValue **propsret);

/* Open a UNIX socket for chardev FD passing */
int
qemuOpenChrChardevUNIXSocket(const virDomainChrSourceDef *dev) G_NO_INLINE;

virJSONValue *
qemuBuildChrDeviceProps(const virDomainDef *vmdef,
                        virDomainChrDef *chr,
                        virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildChannelGuestfwdNetdevProps(virDomainChrDef *chr);

virJSONValue *
qemuBuildHostNetProps(virDomainObj *vm,
                      virDomainNetDef *net);

int
qemuBuildInterfaceConnect(virDomainObj *vm,
                          virDomainNetDef *net,
                          virNetDevVPortProfileOp vmop);

/* Current, best practice */
virJSONValue *
qemuBuildNicDevProps(virDomainDef *def,
                     virDomainNetDef *net,
                     virQEMUCaps *qemuCaps);

char *qemuDeviceDriveHostAlias(virDomainDiskDef *disk);
bool qemuDiskBusIsSD(int bus);

int
qemuBuildStorageSourceAttachPrepareCommon(virStorageSource *src,
                                          qemuBlockStorageSourceAttachData *data);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareDrive(virDomainDiskDef *disk);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareChardev(virDomainDiskDef *disk);


qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdev(virStorageSource *top);

qemuBlockStorageSourceChainData *
qemuBuildStorageSourceChainAttachPrepareBlockdevTop(virStorageSource *top,
                                                    virStorageSource *backingStore);

virJSONValue *
qemuBuildDiskDeviceProps(const virDomainDef *def,
                         virDomainDiskDef *disk,
                         virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildVHostUserFsDevProps(virDomainFSDef *fs,
                             const virDomainDef *def,
                             const char *chardev_alias,
                             qemuDomainObjPrivate *priv);

/* Current, best practice */
int
qemuBuildControllerDevProps(const virDomainDef *domainDef,
                            virDomainControllerDef *def,
                            virQEMUCaps *qemuCaps,
                            virJSONValue **devprops);

int qemuBuildMemoryBackendProps(virJSONValue **backendProps,
                                const char *alias,
                                virQEMUDriverConfig *cfg,
                                qemuDomainObjPrivate *priv,
                                const virDomainDef *def,
                                const virDomainMemoryDef *mem,
                                bool force,
                                bool systemMemory,
                                virBitmap **nodemaskRet);

virJSONValue *
qemuBuildMemoryDeviceProps(virQEMUDriverConfig *cfg,
                           qemuDomainObjPrivate *priv,
                           const virDomainDef *def,
                           const virDomainMemoryDef *mem);

int
qemuBuildThreadContextProps(virJSONValue **tcProps,
                            virJSONValue **memProps,
                            const virDomainDef *def,
                            qemuDomainObjPrivate *priv,
                            virBitmap *nodemask);

/* Current, best practice */
virJSONValue *
qemuBuildPCIHostdevDevProps(const virDomainDef *def,
                            virDomainHostdevDef *dev);

virJSONValue *
qemuBuildRNGDevProps(const virDomainDef *def,
                     virDomainRNGDef *dev,
                     virQEMUCaps *qemuCaps);
int qemuBuildRNGBackendProps(virDomainRNGDef *rng,
                             virJSONValue **props);

/* Current, best practice */
virJSONValue *
qemuBuildUSBHostdevDevProps(const virDomainDef *def,
                            virDomainHostdevDef *dev,
                            virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildSCSIHostdevDevProps(const virDomainDef *def,
                             virDomainHostdevDef *dev,
                             const char *backendAlias);

qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIAttachPrepare(virDomainHostdevDef *hostdev,
                                  const char **backendAlias,
                                  virQEMUCaps *qemuCaps);
qemuBlockStorageSourceAttachData *
qemuBuildHostdevSCSIDetachPrepare(virDomainHostdevDef *hostdev,
                                  virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildSCSIVHostHostdevDevProps(const virDomainDef *def,
                                  virDomainHostdevDef *dev,
                                  virQEMUCaps *qemuCaps,
                                  char *vhostfdName);

virJSONValue *
qemuBuildHostdevMediatedDevProps(const virDomainDef *def,
                                 virDomainHostdevDef *dev);

virJSONValue *
qemuBuildRedirdevDevProps(const virDomainDef *def,
                          virDomainRedirdevDef *dev);

virJSONValue *
qemuBuildZPCIDevProps(virDomainDeviceInfo *dev);

int qemuNetworkPrepareDevices(virDomainDef *def);

bool
qemuDiskConfigBlkdeviotuneEnabled(const virDomainDiskDef *disk);

virJSONValue *qemuBuildHotpluggableCPUProps(const virDomainVcpuDef *vcpu)
    ATTRIBUTE_NONNULL(1);

virJSONValue *qemuBuildShmemBackendMemProps(virDomainShmemDef *shmem)
    ATTRIBUTE_NONNULL(1);

virJSONValue *
qemuBuildShmemDevProps(virDomainDef *def,
                       virDomainShmemDef *shmem);

virJSONValue *
qemuBuildWatchdogDevProps(const virDomainDef *def,
                          virDomainWatchdogDef *dev);

virJSONValue *
qemuBuildInputVirtioDevProps(const virDomainDef *def,
                             virDomainInputDef *dev,
                             virQEMUCaps *qemuCaps);

virJSONValue *
qemuBuildInputUSBDevProps(const virDomainDef *def,
                          virDomainInputDef *dev);

virJSONValue *
qemuBuildVsockDevProps(virDomainDef *def,
                       virDomainVsockDef *vsock,
                       virQEMUCaps *qemuCaps,
                       const char *fdprefix);

/* this function is exported so that tests can mock the FDs */
int
qemuBuildTPMOpenBackendFDs(const char *tpmdev,
                           int *tpmfd,
                           int *cancelfd)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) G_NO_INLINE;

const char * qemuAudioDriverTypeToString(virDomainAudioType type);
virDomainAudioType qemuAudioDriverTypeFromString(const char *str);
int qemuVDPAConnect(const char *devicepath) G_NO_INLINE;
