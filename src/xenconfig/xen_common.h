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
 */

#ifndef LIBVIRT_XEN_COMMON_H
# define LIBVIRT_XEN_COMMON_H

# include "internal.h"
# include "virconf.h"
# include "domain_conf.h"

# define XEN_CONFIG_FORMAT_XL    "xen-xl"
# define XEN_CONFIG_FORMAT_XM    "xen-xm"
# define XEN_CONFIG_FORMAT_SEXPR "xen-sxpr"

int xenConfigGetString(virConfPtr conf,
                       const char *name,
                       char **value,
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
                         virCapsPtr caps,
                         const char *nativeFormat,
                         virDomainXMLOptionPtr xmlopt);

int xenFormatConfigCommon(virConfPtr conf,
                          virDomainDefPtr def,
                          virConnectPtr conn,
                          const char *nativeFormat);

char *xenMakeIPList(virNetDevIPInfoPtr guestIP);

int xenDomainDefAddImplicitInputDevice(virDomainDefPtr def);

#endif /* LIBVIRT_XEN_COMMON_H */
