/*
 * Copyright (C) 2010 IBM Corporation
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef __UTIL_MACVTAP_H__
#define __UTIL_MACVTAP_H__

#include <config.h>

#if defined(WITH_MACVTAP)

#include "internal.h"

int openMacvtapTap(virConnectPtr conn,
                   const char *ifname,
                   const unsigned char *macaddress,
                   const char *linkdev,
                   int mode,
                   char **res_ifname,
                   int vnet_hdr);

void delMacvtap(const char *ifname);

#endif /* WITH_MACVTAP */

#define MACVTAP_MODE_PRIVATE_STR  "private"
#define MACVTAP_MODE_VEPA_STR     "vepa"
#define MACVTAP_MODE_BRIDGE_STR   "bridge"


#endif /* __UTIL_MACVTAP_H__ */
