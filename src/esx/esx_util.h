
/*
 * esx_util.h: utility functions for the VMware ESX driver
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
# define __ESX_UTIL_H__

# include <libxml/uri.h>

# include "internal.h"
# include "conf.h"

int esxUtil_ParseQuery(xmlURIPtr uri, char **transport, char **vCenter,
                       int *noVerify, int *autoAnswer);

int esxUtil_ParseVirtualMachineIDString(const char *id_string, int *id);

int esxUtil_ParseDatastoreRelatedPath(const char *datastoreRelatedPath,
                                      char **datastoreName,
                                      char **directoryName, char **fileName);

int esxUtil_ResolveHostname(const char *hostname,
                            char *ipAddress, size_t ipAddress_length);

int esxUtil_GetConfigString(virConfPtr conf, const char *name, char **string,
                            int optional);

int esxUtil_GetConfigUUID(virConfPtr conf, const char *name,
                          unsigned char *uuid, int optional);

int esxUtil_GetConfigLong(virConfPtr conf, const char *name, long long *number,
                          long long default_, int optional);

int esxUtil_GetConfigBoolean(virConfPtr conf, const char *name, int *boolean_,
                             int default_, int optional);

#endif /* __ESX_UTIL_H__ */
