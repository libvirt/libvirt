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
struct _virFirmware {
    char *name;
    char *nvram;
};


void
virFirmwareFree(virFirmware *firmware);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virFirmware, virFirmwareFree);

void
virFirmwareFreeList(virFirmware **firmwares, size_t nfirmwares);

int
virFirmwareParse(const char *str, virFirmware *firmware)
    ATTRIBUTE_NONNULL(2);

int
virFirmwareParseList(const char *list,
                     virFirmware ***firmwares,
                     size_t *nfirmwares)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3);
