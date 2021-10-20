/*
 * virpcivpd.h: helper APIs for working with the PCI/PCIe VPD capability
 *
 * Copyright (C) 2021 Canonical Ltd.
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

typedef struct virPCIVPDResourceCustom virPCIVPDResourceCustom;
struct virPCIVPDResourceCustom {
    char idx;
    char *value;
};

typedef struct virPCIVPDResourceRO virPCIVPDResourceRO;
struct virPCIVPDResourceRO {
    char *part_number;
    char *change_level;
    char *manufacture_id;
    char *serial_number;
    GPtrArray *vendor_specific;
};

typedef struct virPCIVPDResourceRW virPCIVPDResourceRW;
struct virPCIVPDResourceRW {
    char *asset_tag;
    GPtrArray *vendor_specific;
    GPtrArray *system_specific;
};

typedef struct virPCIVPDResource virPCIVPDResource;
struct virPCIVPDResource {
    char *name;
    virPCIVPDResourceRO *ro;
    virPCIVPDResourceRW *rw;
};


virPCIVPDResource *virPCIVPDParse(int vpdFileFd);
void virPCIVPDResourceFree(virPCIVPDResource *res);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIVPDResource, virPCIVPDResourceFree);

virPCIVPDResourceRO *virPCIVPDResourceRONew(void);
void virPCIVPDResourceROFree(virPCIVPDResourceRO *ro);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIVPDResourceRO, virPCIVPDResourceROFree);

virPCIVPDResourceRW *virPCIVPDResourceRWNew(void);
void virPCIVPDResourceRWFree(virPCIVPDResourceRW *rw);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIVPDResourceRW, virPCIVPDResourceRWFree);

bool
virPCIVPDResourceUpdateKeyword(virPCIVPDResource *res, const bool readOnly,
                               const char *const keyword, const char *const value);

void virPCIVPDResourceCustomFree(virPCIVPDResourceCustom *custom);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virPCIVPDResourceCustom, virPCIVPDResourceCustomFree);
