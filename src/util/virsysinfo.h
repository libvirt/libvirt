/*
 * virsysinfo.h: get SMBIOS/sysinfo information from the host
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
 * Copyright (C) 2010 Daniel Veillard
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
#include "virbuffer.h"
#include "virenum.h"

typedef enum {
    VIR_SYSINFO_SMBIOS,
    VIR_SYSINFO_FWCFG,

    VIR_SYSINFO_LAST
} virSysinfoType;

typedef struct _virSysinfoProcessorDef virSysinfoProcessorDef;
struct _virSysinfoProcessorDef {
    char *processor_socket_destination;
    char *processor_type;
    char *processor_family;
    char *processor_manufacturer;
    char *processor_signature;
    char *processor_version;
    char *processor_external_clock;
    char *processor_max_speed;
    char *processor_status;
    char *processor_serial_number;
    char *processor_part_number;
};

typedef struct _virSysinfoMemoryDef virSysinfoMemoryDef;
struct _virSysinfoMemoryDef {
    char *memory_size;
    char *memory_form_factor;
    char *memory_locator;
    char *memory_bank_locator;
    char *memory_type;
    char *memory_type_detail;
    char *memory_speed;
    char *memory_manufacturer;
    char *memory_serial_number;
    char *memory_part_number;
};

typedef struct _virSysinfoBIOSDef virSysinfoBIOSDef;
struct _virSysinfoBIOSDef {
    char *vendor;
    char *version;
    char *date;
    char *release;
};

typedef struct _virSysinfoSystemDef virSysinfoSystemDef;
struct _virSysinfoSystemDef {
    char *manufacturer;
    char *product;
    char *version;
    char *serial;
    char *uuid;
    char *sku;
    char *family;
};

typedef struct _virSysinfoBaseBoardDef virSysinfoBaseBoardDef;
struct _virSysinfoBaseBoardDef {
    char *manufacturer;
    char *product;
    char *version;
    char *serial;
    char *asset;
    char *location;
    /* XXX board type */
};

typedef struct _virSysinfoChassisDef virSysinfoChassisDef;
struct _virSysinfoChassisDef {
    char *manufacturer;
    char *version;
    char *serial;
    char *asset;
    char *sku;
};

typedef struct _virSysinfoOEMStringsDef virSysinfoOEMStringsDef;
struct _virSysinfoOEMStringsDef {
    size_t nvalues;
    char **values;
};

typedef struct _virSysinfoFWCfgDef virSysinfoFWCfgDef;
struct _virSysinfoFWCfgDef {
    char *name;
    char *value;
    char *file;
};

typedef struct _virSysinfoDef virSysinfoDef;
struct _virSysinfoDef {
    virSysinfoType type;

    /* The following members are valid for type == VIR_SYSINFO_SMBIOS */
    virSysinfoBIOSDef *bios;
    virSysinfoSystemDef *system;

    size_t nbaseBoard;
    virSysinfoBaseBoardDef *baseBoard;

    virSysinfoChassisDef *chassis;

    size_t nprocessor;
    virSysinfoProcessorDef *processor;

    size_t nmemory;
    virSysinfoMemoryDef *memory;

    virSysinfoOEMStringsDef *oemStrings;

    /* The following members are valid for type == VIR_SYSINFO_FWCFG */
    size_t nfw_cfgs;
    virSysinfoFWCfgDef *fw_cfgs;
};

virSysinfoDef *virSysinfoRead(void);

void virSysinfoBIOSDefFree(virSysinfoBIOSDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSysinfoBIOSDef, virSysinfoBIOSDefFree);
void virSysinfoSystemDefFree(virSysinfoSystemDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSysinfoSystemDef, virSysinfoSystemDefFree);
void virSysinfoBaseBoardDefClear(virSysinfoBaseBoardDef *def);
void virSysinfoChassisDefFree(virSysinfoChassisDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSysinfoChassisDef, virSysinfoChassisDefFree);
void virSysinfoOEMStringsDefFree(virSysinfoOEMStringsDef *def);
void virSysinfoDefFree(virSysinfoDef *def);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virSysinfoDef, virSysinfoDefFree);

int virSysinfoFormat(virBuffer *buf, virSysinfoDef *def)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virSysinfoIsEqual(virSysinfoDef *src,
                       virSysinfoDef *dst);

VIR_ENUM_DECL(virSysinfo);
