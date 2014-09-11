/*
 * xen_xl_disk_i.h - common header for disk spec parser
 *
 * Copyright (C) 2011      Citrix Ltd.
 * Author Ian Jackson <ian.jackson@eu.citrix.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#ifndef __VIR_XEN_XL_DISK_I_H__
# define __VIR_XEN_XL_DISK_I_H__

# include "virconf.h"
# include "domain_conf.h"


typedef struct {
    int err;
    void *scanner;
    YY_BUFFER_STATE buf;
    virDomainDiskDefPtr disk;
    int access_set;
    int had_depr_prefix;
    const char *spec;
} xenXLDiskParserContext;

void xenXLDiskParserError(xenXLDiskParserContext *dpc,
                          const char *erroneous,
                          const char *message);

#endif /* __VIR_XEN_XL_DISK_I_H__ */
