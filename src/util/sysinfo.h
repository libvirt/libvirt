/*
 * sysinfo.h: structure and entry points for sysinfo support
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel Veillard <veillard@redhat.com>
 */

#ifndef __VIR_SYSINFOS_H__
# define __VIR_SYSINFOS_H__

# include "internal.h"
# include "util.h"

enum virSysinfoType {
    VIR_SYSINFO_SMBIOS,

    VIR_SYSINFO_LAST
};

typedef struct _virSysinfoDef virSysinfoDef;
typedef virSysinfoDef *virSysinfoDefPtr;
struct _virSysinfoDef {
    int type;

    char *bios_vendor;
    char *bios_version;
    char *bios_date;
    char *bios_release;

    char *system_manufacturer;
    char *system_product;
    char *system_version;
    char *system_serial;
    char *system_uuid;
    char *system_sku;
    char *system_family;
};

virSysinfoDefPtr virSysinfoRead(void);

void virSysinfoDefFree(virSysinfoDefPtr def);

char *virSysinfoFormat(virSysinfoDefPtr def, const char *prefix)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

bool virSysinfoIsEqual(virSysinfoDefPtr src,
                       virSysinfoDefPtr dst);

VIR_ENUM_DECL(virSysinfo)

#endif /* __VIR_SYSINFOS_H__ */
