/*
 * xen_common.h: Parsing and formatting functions for config common
 *
 * Copyright (C) 2014 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 * Author: Jim Fehlig <jfehlig@suse.com>
 */

#ifndef __VIR_XEN_COMMON_H__
# define __VIR_XEN_COMMON_H__

# include "internal.h"
# include "virconf.h"
# include "domain_conf.h"

int xenConfigGetString(virConfPtr conf,
                       const char *name,
                       const char **value,
                       const char *def);

int xenConfigGetBool(virConfPtr conf, const char *name, int *value, int def);

int xenConfigSetInt(virConfPtr conf, const char *name, long long value);

int xenConfigSetString(virConfPtr conf, const char *setting, const char *value);

int xenConfigGetULong(virConfPtr conf,
                      const char *name,
                      unsigned long *value,
                      unsigned long def);

int
xenConfigCopyString(virConfPtr conf,
                    const char *name,
                    char **value);

int xenConfigCopyStringOpt(virConfPtr conf,
                           const char *name,
                           char **value);

int xenParseConfigCommon(virConfPtr conf,
                         virDomainDefPtr def,
                         virCapsPtr caps);

int xenFormatConfigCommon(virConfPtr conf,
                          virDomainDefPtr def,
                          virConnectPtr conn);


int xenDomainDefAddImplicitInputDevice(virDomainDefPtr def);

#endif /* __VIR_XEN_COMMON_H__ */
