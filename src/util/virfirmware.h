/*
 * virfirmware.h: Declaration of firmware object and supporting functions
 *
 * Copyright (C) 2016 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

#include "internal.h"

typedef struct _virFirmware virFirmware;
typedef virFirmware *virFirmwarePtr;

struct _virFirmware {
    char *name;
    char *nvram;
};


void
virFirmwareFree(virFirmwarePtr firmware);

VIR_DEFINE_AUTOPTR_FUNC(virFirmware, virFirmwareFree);

void
virFirmwareFreeList(virFirmwarePtr *firmwares, size_t nfirmwares);

int
virFirmwareParse(const char *str, virFirmwarePtr firmware)
    ATTRIBUTE_NONNULL(2);

int
virFirmwareParseList(const char *list,
                     virFirmwarePtr **firmwares,
                     size_t *nfirmwares)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
