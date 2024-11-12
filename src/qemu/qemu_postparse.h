/*
 * qemu_postparse.h: QEMU domain PostParse functions
 *
 * Copyright (C) 2006-2024 Red Hat, Inc.
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

#include "virconftypes.h"

int
qemuDomainDeviceDiskDefPostParse(virDomainDiskDef *disk,
                                 unsigned int parseFlags);

int
qemuDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                             const virDomainDef *def,
                             unsigned int parseFlags,
                             void *opaque,
                             void *parseOpaque);

int
qemuDomainDefPostParseBasic(virDomainDef *def,
                            void *opaque);

int
qemuDomainDefPostParse(virDomainDef *def,
                       unsigned int parseFlags,
                       void *opaque,
                       void *parseOpaque);

int
qemuDomainPostParseDataAlloc(const virDomainDef *def,
                             unsigned int parseFlags,
                             void *opaque,
                             void **parseOpaque);

void
qemuDomainPostParseDataFree(void *parseOpaque);
