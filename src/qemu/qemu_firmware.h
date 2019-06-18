/*
 * qemu_firmware.h: QEMU firmware
 *
 * Copyright (C) 2019 Red Hat, Inc.
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
#include "qemu_conf.h"
#include "virautoclean.h"
#include "virarch.h"

typedef struct _qemuFirmware qemuFirmware;
typedef qemuFirmware *qemuFirmwarePtr;

void
qemuFirmwareFree(qemuFirmwarePtr fw);

VIR_DEFINE_AUTOPTR_FUNC(qemuFirmware, qemuFirmwareFree);

qemuFirmwarePtr
qemuFirmwareParse(const char *path);

char *
qemuFirmwareFormat(qemuFirmwarePtr fw);

int
qemuFirmwareFetchConfigs(char ***firmwares,
                         bool privileged);

int
qemuFirmwareFillDomain(virQEMUDriverPtr driver,
                       virDomainObjPtr vm,
                       unsigned int flags);

int
qemuFirmwareGetSupported(const char *machine,
                         virArch arch,
                         bool privileged,
                         uint64_t *supported,
                         bool *secure);

verify(VIR_DOMAIN_OS_DEF_FIRMWARE_LAST <= 64);
