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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Anthony Liguori <aliguori@us.ibm.com>
 * Author: Daniel Veillard <veillard@redhat.com>
 * Author: Markus Groß <gross@univention.de>
 */

#ifndef __VIR_XEN_SXPR_H__
# define __VIR_XEN_SXPR_H__

# include "internal.h"
# include "conf.h"
# include "domain_conf.h"
# include "sexpr.h"

typedef enum {
    XEND_CONFIG_VERSION_3_0_2 = 1,
    XEND_CONFIG_VERSION_3_0_3 = 2,
    XEND_CONFIG_VERSION_3_0_4 = 3,
    XEND_CONFIG_VERSION_3_1_0 = 4,
} xenConfigVersionEnum;

/* helper functions to get the dom id from a sexpr */
int xenGetDomIdFromSxprString(const char *sexpr, int xendConfigVersion);
int xenGetDomIdFromSxpr(const struct sexpr *root, int xendConfigVersion);

virDomainDefPtr xenParseSxprString(const char *sexpr, int xendConfigVersion,
                                   char *tty, int vncport);

virDomainDefPtr xenParseSxpr(const struct sexpr *root, int xendConfigVersion,
                             const char *cpus, char *tty, int vncport);

int xenParseSxprSound(virDomainDefPtr def, const char *str);

virDomainChrDefPtr xenParseSxprChar(const char *value, const char *tty);

int xenFormatSxprDisk(virDomainDiskDefPtr def, virBufferPtr buf, int hvm,
                      int xendConfigVersion, int isAttach);

int xenFormatSxprNet(virConnectPtr conn,
                     virDomainNetDefPtr def, virBufferPtr buf, int hvm,
                     int xendConfigVersion, int isAttach);

int xenFormatSxprOnePCI(virDomainHostdevDefPtr def, virBufferPtr buf,
                        int detach);

int xenFormatSxprChr(virDomainChrDefPtr def, virBufferPtr buf);
int xenFormatSxprSound(virDomainDefPtr def, virBufferPtr buf);

char * xenFormatSxpr(virConnectPtr conn, virDomainDefPtr def,
                     int xendConfigVersion);

#endif /* __VIR_XEN_SXPR_H__ */
