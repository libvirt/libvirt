
/*
 * esx_util.h: utility methods for the VMware ESX driver
 *
 * Copyright (C) 2009 Matthias Bolte <matthias.bolte@googlemail.com>
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
 */

#ifndef __ESX_UTIL_H__
#define __ESX_UTIL_H__

#include <libxml/tree.h>

#include "internal.h"
#include "conf.h"

char *esxUtil_RequestUsername(virConnectAuthPtr auth,
                              const char *default_username,
                              const char *server);

char *esxUtil_RequestPassword(virConnectAuthPtr auth, const char *username,
                              const char *server);

int esxUtil_ParseQuery(virConnectPtr conn, char **transport, char **vcenter,
                       int *noVerify);

int esxUtil_ParseVirtualMachineIDString(const char *id_string, int *id);

int esxUtil_ResolveHostname(virConnectPtr conn, const char *hostname,
                            char *ip_address, size_t ip_address_length);

int esxUtil_GetConfigString(virConnectPtr conn, virConfPtr conf,
                            const char *name, char **string, int optional);

int esxUtil_GetConfigUUID(virConnectPtr conn, virConfPtr conf, const char *name,
                          unsigned char *uuid, int optional);

int esxUtil_GetConfigLong(virConnectPtr conn, virConfPtr conf, const char *name,
                          long long *number, long long default_, int optional);

int esxUtil_GetConfigBoolean(virConnectPtr conn, virConfPtr conf,
                             const char *name, int *boolean, int default_,
                             int optional);

int esxUtil_EqualSuffix(const char *string, const char* suffix);

#endif /* __ESX_UTIL_H__ */
