/*
 * qemu_extdevice.h: QEMU external devices support
 *
 * Copyright (C) 2018 IBM Corporation
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

int qemuExtDeviceLogCommand(virQEMUDriver *driver,
                            virDomainObj *vm,
                            virCommand *cmd,
                            const char *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    G_GNUC_WARN_UNUSED_RESULT;

int
qemuExtDevicesInitPaths(virQEMUDriver *driver,
                        virDomainDef *def)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int qemuExtDevicesPrepareDomain(virQEMUDriver *driver,
                                virDomainObj *vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

int qemuExtDevicesPrepareHost(virQEMUDriver *driver,
                              virDomainObj *vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuExtDevicesCleanupHost(virQEMUDriver *driver,
                               virDomainDef *def,
                               virDomainUndefineFlagsValues flags,
                               bool outgoingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuExtDevicesStart(virQEMUDriver *driver,
                        virDomainObj *vm,
                        bool incomingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    G_GNUC_WARN_UNUSED_RESULT;

void qemuExtDevicesStop(virQEMUDriver *driver,
                        virDomainObj *vm,
                        bool outgoingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool qemuExtDevicesHasDevice(virDomainDef *def);

int qemuExtDevicesSetupCgroup(virQEMUDriver *driver,
                              virDomainObj *vm,
                              virCgroup *cgroup);
