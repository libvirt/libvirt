/*
 * qemu_validate.h: QEMU general validation functions
 *
 * Copyright IBM Corp, 2020
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

int
qemuValidateDomainDef(const virDomainDef *def,
                      void *opaque,
                      void *parseOpaque);

int
qemuValidateDomainDeviceDefDisk(const virDomainDiskDef *disk,
                                const virDomainDef *def,
                                virQEMUCaps *qemuCaps);

int
qemuValidateDomainDeviceDef(const virDomainDeviceDef *dev,
                            const virDomainDef *def,
                            void *opaque,
                            void *parseOpaque);

int
qemuValidateLifecycleAction(virDomainLifecycleAction onPoweroff,
                            virDomainLifecycleAction onReboot,
                            virDomainLifecycleAction onCrash);
