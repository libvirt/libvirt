/*
 * qemu_hotplug.h: QEMU device hotplug management
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "qemu_conf.h"
#include "qemu_domain.h"

int qemuDomainChangeEjectableMedia(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainDiskDef *disk,
                                   virStorageSource *newsrc,
                                   bool force);

void qemuDomainDelTLSObjects(virDomainObj *vm,
                             virDomainAsyncJob asyncJob,
                             const char *secAlias,
                             const char *tlsAlias);

int qemuDomainAddTLSObjects(virDomainObj *vm,
                            virDomainAsyncJob asyncJob,
                            virJSONValue **secProps,
                            virJSONValue **tlsProps);

int qemuDomainGetTLSObjects(qemuDomainSecretInfo *secinfo,
                            const char *tlsCertdir,
                            bool tlsListen,
                            bool tlsVerify,
                            const char *alias,
                            virJSONValue **tlsProps,
                            virJSONValue **secProps);

int qemuDomainAttachControllerDevice(virDomainObj *vm,
                                     virDomainControllerDef *controller);
int qemuDomainAttachDeviceDiskLive(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainDeviceDef *dev);

int qemuDomainAttachDiskGeneric(virDomainObj *vm,
                                virDomainDiskDef *disk,
                                virDomainAsyncJob asyncJob);

int qemuDomainAttachNetDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainNetDef *net);
int qemuDomainAttachRedirdevDevice(virQEMUDriver *driver,
                                   virDomainObj *vm,
                                   virDomainRedirdevDef *hostdev);
int qemuDomainAttachHostDevice(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainHostdevDef *hostdev);
int qemuDomainAttachShmemDevice(virDomainObj *vm,
                                virDomainShmemDef *shmem);
int qemuDomainAttachWatchdog(virDomainObj *vm,
                             virDomainWatchdogDef *watchdog);
int qemuDomainFindGraphicsIndex(virDomainDef *def,
                                virDomainGraphicsDef *dev);
int qemuDomainAttachMemory(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainMemoryDef *mem);
int qemuDomainChangeGraphics(virQEMUDriver *driver,
                             virDomainObj *vm,
                             virDomainGraphicsDef *dev);
int qemuDomainChangeGraphicsPasswords(virDomainObj *vm,
                                      int type,
                                      virDomainGraphicsAuthDef *auth,
                                      const char *defaultPasswd,
                                      int asyncJob);
int qemuDomainChangeNet(virQEMUDriver *driver,
                        virDomainObj *vm,
                        virDomainDeviceDef *dev);
int qemuDomainChangeNetLinkState(virDomainObj *vm,
                                 virDomainNetDef *dev,
                                 int linkstate);

int qemuDomainAttachInputDevice(virDomainObj *vm,
                                virDomainInputDef *input);

int qemuDomainAttachVsockDevice(virDomainObj *vm,
                                virDomainVsockDef *vsock);
int
qemuDomainAttachFSDevice(virQEMUDriver *driver,
                         virDomainObj *vm,
                         virDomainFSDef *fs);

int qemuDomainAttachLease(virQEMUDriver *driver,
                          virDomainObj *vm,
                          virDomainLeaseDef *lease);
int qemuDomainAttachChrDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainDeviceDef *dev);
int qemuDomainAttachRNGDevice(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainRNGDef *rng);

int qemuDomainDetachDeviceLive(virDomainObj *vm,
                               virDomainDeviceDef *match,
                               virQEMUDriver *driver,
                               bool async);

void qemuDomainRemoveVcpuAlias(virDomainObj *vm,
                               const char *alias);

int
qemuDomainChrInsert(virDomainDef *vmdef,
                    virDomainChrDef *chr);
virDomainChrDef *
qemuDomainChrRemove(virDomainDef *vmdef,
                    virDomainChrDef *chr);

int qemuDomainRemoveDevice(virQEMUDriver *driver,
                           virDomainObj *vm,
                           virDomainDeviceDef *dev);

bool qemuDomainSignalDeviceRemoval(virDomainObj *vm,
                                   const char *devAlias,
                                   qemuDomainUnpluggingDeviceStatus status);

int qemuDomainSetVcpusInternal(virQEMUDriver *driver,
                               virDomainObj *vm,
                               virDomainDef *def,
                               virDomainDef *persistentDef,
                               unsigned int nvcpus,
                               bool hotpluggable);

int qemuDomainSetVcpuInternal(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virDomainDef *def,
                              virDomainDef *persistentDef,
                              virBitmap *vcpus,
                              bool state);

unsigned long long qemuDomainGetUnplugTimeout(virDomainObj *vm) G_NO_INLINE;

int qemuHotplugAttachDBusVMState(virQEMUDriver *driver,
                                 virDomainObj *vm,
                                 virDomainAsyncJob asyncJob);

int qemuHotplugRemoveDBusVMState(virDomainObj *vm,
                                 virDomainAsyncJob asyncJob);

int qemuDomainChangeMemoryRequestedSize(virDomainObj *vm,
                                        const char *alias,
                                        unsigned long long requestedsize);
