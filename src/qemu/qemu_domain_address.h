/*
 * qemu_domain_address.h: QEMU domain address
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

#include "qemu_conf.h"
#include "qemu_capabilities.h"

int qemuDomainGetSCSIControllerModel(const virDomainDef *def,
                                     const virDomainControllerDef *cont,
                                     virQEMUCaps *qemuCaps);

int qemuDomainSetSCSIControllerModel(const virDomainDef *def,
                                     virDomainControllerDef *cont,
                                     virQEMUCaps *qemuCaps);

int qemuDomainFindSCSIControllerModel(const virDomainDef *def,
                                      virDomainDeviceInfo *info);

int qemuDomainAssignAddresses(virDomainDef *def,
                              virQEMUCaps *qemuCaps,
                              virQEMUDriver *driver,
                              virDomainObj *obj,
                              bool newDomain)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);

int qemuDomainEnsurePCIAddress(virDomainObj *obj,
                               virDomainDeviceDef *dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainFillDeviceIsolationGroup(virDomainDef *def,
                                       virDomainDeviceDef *dev)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void qemuDomainReleaseDeviceAddress(virDomainObj *vm,
                                    virDomainDeviceInfo *info);

int qemuDomainAssignMemoryDeviceSlot(virDomainObj *vm,
                                     virDomainMemoryDef *mem);

void qemuDomainReleaseMemoryDeviceSlot(virDomainObj *vm,
                                       virDomainMemoryDef *mem);

int qemuDomainEnsureVirtioAddress(bool *releaseAddr,
                                  virDomainObj *vm,
                                  virDomainDeviceDef *dev);
