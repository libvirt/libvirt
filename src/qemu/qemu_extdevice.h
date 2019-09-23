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

int qemuExtDeviceLogCommand(virQEMUDriverPtr driver,
                            virDomainObjPtr vm,
                            virCommandPtr cmd,
                            const char *info)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;

int qemuExtDevicesPrepareDomain(virQEMUDriverPtr driver,
                                virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;

int qemuExtDevicesPrepareHost(virQEMUDriverPtr driver,
                              virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;

void qemuExtDevicesCleanupHost(virQEMUDriverPtr driver,
                               virDomainDefPtr def)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int qemuExtDevicesStart(virQEMUDriverPtr driver,
                        virDomainObjPtr vm,
                        bool incomingMigration)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2)
    ATTRIBUTE_RETURN_CHECK;

void qemuExtDevicesStop(virQEMUDriverPtr driver,
                        virDomainObjPtr vm)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool qemuExtDevicesHasDevice(virDomainDefPtr def);

int qemuExtDevicesSetupCgroup(virQEMUDriverPtr driver,
                              virDomainDefPtr def,
                              virCgroupPtr cgroup);
