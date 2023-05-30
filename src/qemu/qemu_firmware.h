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
#include "virarch.h"
#include "virfirmware.h"

typedef struct _qemuFirmware qemuFirmware;

void
qemuFirmwareFree(qemuFirmware *fw);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuFirmware, qemuFirmwareFree);

qemuFirmware *
qemuFirmwareParse(const char *path);

char *
qemuFirmwareFormat(qemuFirmware *fw);

int
qemuFirmwareFetchConfigs(char ***firmwares,
                         bool privileged);

int
qemuFirmwareFillDomain(virQEMUDriver *driver,
                       virDomainDef *def,
                       bool abiUpdate);

int
qemuFirmwareGetSupported(const char *machine,
                         virArch arch,
                         bool privileged,
                         uint64_t *supported,
                         bool *secure,
                         virFirmware ***fws,
                         size_t *nfws);

G_STATIC_ASSERT(VIR_DOMAIN_OS_DEF_FIRMWARE_LAST <= 64);
