/*
 * nwfilter_ipaddrmap.h: IP address map for mapping interfaces to their
 *                       detected/expected IP addresses
 *
 * Copyright (C) 2010, 2012 IBM Corp.
 *
 * Author:
 *     Stefan Berger <stefanb@linux.vnet.ibm.com>
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
 */

#ifndef __VIR_NWFILTER_IPADDRMAP_H
# define __VIR_NWFILTER_IPADDRMAP_H

int virNWFilterIPAddrMapInit(void);
void virNWFilterIPAddrMapShutdown(void);

int virNWFilterIPAddrMapAddIPAddr(const char *ifname, char *addr);
int virNWFilterIPAddrMapDelIPAddr(const char *ifname,
                                  const char *ipaddr);
virNWFilterVarValuePtr virNWFilterIPAddrMapGetIPAddr(const char *ifname);

#endif /* __VIR_NWFILTER_IPADDRMAP_H */
