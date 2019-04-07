/*
 * xen_sxpr.h: Xen SEXPR parsing functions
 *
 * Copyright (C) 2006-2008, 2010, 2012 Red Hat, Inc.
 * Copyright (C) 2011 Univention GmbH
 * Copyright (C) 2005,2006
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

#ifndef LIBVIRT_XEN_SXPR_H
# define LIBVIRT_XEN_SXPR_H

# include "internal.h"
# include "virconf.h"
# include "domain_conf.h"
# include "virsexpr.h"

/* helper functions to get the dom id from a sexpr */
int xenGetDomIdFromSxprString(const char *sexpr, int *id);
int xenGetDomIdFromSxpr(const struct sexpr *root, int *id);

virDomainDefPtr xenParseSxprString(const char *sexpr,
                                   char *tty,
                                   int vncport,
                                   virCapsPtr caps,
                                   virDomainXMLOptionPtr xmlopt);

virDomainDefPtr xenParseSxpr(const struct sexpr *root,
                             const char *cpus,
                             char *tty,
                             int vncport,
                             virCapsPtr caps,
                             virDomainXMLOptionPtr xmlopt);

int xenParseSxprSound(virDomainDefPtr def, const char *str);

virDomainChrDefPtr xenParseSxprChar(const char *value, const char *tty);

int xenParseSxprVifRate(const char *rate, unsigned long long *kbytes_per_sec);

int xenFormatSxprDisk(virDomainDiskDefPtr def, virBufferPtr buf, int hvm,
                      int isAttach);

int xenFormatSxprNet(virConnectPtr conn,
                     virDomainNetDefPtr def, virBufferPtr buf, int hvm,
                     int isAttach);

int xenFormatSxprOnePCI(virDomainHostdevDefPtr def, virBufferPtr buf,
                        int detach);

int xenFormatSxprChr(virDomainChrDefPtr def, virBufferPtr buf);
int xenFormatSxprSound(virDomainDefPtr def, virBufferPtr buf);

char * xenFormatSxpr(virConnectPtr conn, virDomainDefPtr def);

#endif /* LIBVIRT_XEN_SXPR_H */
