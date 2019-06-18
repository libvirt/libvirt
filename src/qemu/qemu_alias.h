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

#include "domain_conf.h"

#include "qemu_capabilities.h"
#include "qemu_domain.h"
#include "qemu_domain_address.h"

int qemuAssignDeviceChrAlias(virDomainDefPtr def,
                             virDomainChrDefPtr chr,
                             ssize_t idx);

int qemuAssignDeviceControllerAlias(virDomainDefPtr domainDef,
                                    virQEMUCapsPtr qemuCaps,
                                    virDomainControllerDefPtr controller);

int qemuAssignDeviceDiskAlias(virDomainDefPtr def,
                              virDomainDiskDefPtr disk,
                              virQEMUCapsPtr qemuCaps);

int qemuAssignDeviceHostdevAlias(virDomainDefPtr def,
                                 char **alias,
                                 int idx);

int qemuAssignDeviceNetAlias(virDomainDefPtr def,
                             virDomainNetDefPtr net,
                             int idx);

int qemuAssignDeviceRedirdevAlias(virDomainDefPtr def,
                                  virDomainRedirdevDefPtr redirdev,
                                  int idx);

int qemuAssignDeviceRNGAlias(virDomainDefPtr def,
                             virDomainRNGDefPtr rng);

int qemuAssignDeviceMemoryAlias(virDomainDefPtr def,
                                virDomainMemoryDefPtr mems,
                                bool oldAlias);

int qemuAssignDeviceShmemAlias(virDomainDefPtr def,
                               virDomainShmemDefPtr shmem,
                               int idx);

int qemuAssignDeviceWatchdogAlias(virDomainWatchdogDefPtr watchdog);

int qemuAssignDeviceInputAlias(virDomainDefPtr def,
                               virDomainInputDefPtr input,
                               int idx);

int qemuAssignDeviceVsockAlias(virDomainVsockDefPtr vsock);

int qemuAssignDeviceAliases(virDomainDefPtr def, virQEMUCapsPtr qemuCaps);

int qemuDomainDeviceAliasIndex(const virDomainDeviceInfo *info,
                               const char *prefix);

char *qemuAliasDiskDriveFromDisk(const virDomainDiskDef *disk);

const char *qemuAliasDiskDriveSkipPrefix(const char *dev_name);

char *qemuAliasFromHostdev(const virDomainHostdevDef *hostdev);

char *qemuDomainGetMasterKeyAlias(void);

char *qemuDomainGetSecretAESAlias(const char *srcalias,
                                  bool isLuks);

char *qemuAliasTLSObjFromSrcAlias(const char *srcAlias)
    ATTRIBUTE_NONNULL(1);

char *qemuAliasChardevFromDevAlias(const char *devAlias)
    ATTRIBUTE_NONNULL(1);

const char *qemuDomainGetManagedPRAlias(void);

char *qemuDomainGetUnmanagedPRAlias(const char *parentalias);
