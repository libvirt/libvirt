/*
 * qemu_alias.h: QEMU alias manipulation
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

#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"

int qemuAssignDeviceChrAlias(virDomainDef *def,
                             virDomainChrDef *chr,
                             ssize_t idx);

void qemuAssignDeviceControllerAlias(virDomainDef *domainDef,
                                     virDomainControllerDef *controller);

int qemuAssignDeviceDiskAlias(virDomainDef *def,
                              virDomainDiskDef *disk);

void qemuAssignDeviceHostdevAlias(virDomainDef *def,
                                  char **alias,
                                  int idx);

void qemuAssignDeviceNetAlias(virDomainDef *def,
                              virDomainNetDef *net,
                              int idx);

void
qemuAssignDeviceFSAlias(virDomainDef *def,
                        virDomainFSDef *fss);

void qemuAssignDeviceRedirdevAlias(virDomainDef *def,
                                   virDomainRedirdevDef *redirdev,
                                   int idx);

void qemuAssignDeviceRNGAlias(virDomainDef *def,
                              virDomainRNGDef *rng);

int qemuAssignDeviceMemoryAlias(virDomainDef *def,
                                virDomainMemoryDef *mems);

void qemuAssignDeviceShmemAlias(virDomainDef *def,
                                virDomainShmemDef *shmem,
                                int idx);

void
qemuAssignDeviceWatchdogAlias(virDomainDef *def,
                              virDomainWatchdogDef *watchdog,
                              int idx);

void qemuAssignDeviceInputAlias(virDomainDef *def,
                                virDomainInputDef *input,
                                int idx);

void qemuAssignDeviceVsockAlias(virDomainVsockDef *vsock);

int qemuAssignDeviceAliases(virDomainDef *def);

int qemuDomainDeviceAliasIndex(const virDomainDeviceInfo *info,
                               const char *prefix);

char *qemuAliasDiskDriveFromDisk(const virDomainDiskDef *disk);

const char *qemuAliasDiskDriveSkipPrefix(const char *dev_name);

char *qemuAliasFromHostdev(const virDomainHostdevDef *hostdev);

char *qemuDomainGetMasterKeyAlias(void);

char *qemuAliasForSecret(const char *parentalias,
                         const char *obj,
                         size_t secret_idx);

char *qemuAliasTLSObjFromSrcAlias(const char *srcAlias)
    ATTRIBUTE_NONNULL(1);

char *qemuAliasChardevFromDevAlias(const char *devAlias)
    ATTRIBUTE_NONNULL(1);

const char *qemuDomainGetManagedPRAlias(void);

char *qemuDomainGetUnmanagedPRAlias(const char *parentalias);

const char *qemuDomainGetDBusVMStateAlias(void);

char *qemuDomainGetVhostUserChrAlias(const char *devalias);
