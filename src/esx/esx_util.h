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

# include <netdb.h>
# include "internal.h"
# include "viruri.h"

typedef struct _esxUtil_ParsedUri esxUtil_ParsedUri;

struct _esxUtil_ParsedUri {
    char *transport;
    char *vCenter;
    bool noVerify;
    bool autoAnswer;
    bool proxy;
    int proxy_type;
    char *proxy_hostname;
    int proxy_port;
    char *path;
};

int esxUtil_ParseUri(esxUtil_ParsedUri **parsedUri, virURIPtr uri);

void esxUtil_FreeParsedUri(esxUtil_ParsedUri **parsedUri);

int esxUtil_ParseVirtualMachineIDString(const char *id_string, int *id);

int esxUtil_ParseDatastorePath(const char *datastorePath, char **datastoreName,
                               char **directoryName, char **directoryAndFileName);

int esxUtil_ResolveHostname(const char *hostname,
                            char *ipAddress, size_t ipAddress_length);

int esxUtil_ReformatUuid(const char *input, char *output);

char *esxUtil_EscapeBase64(const char *string);

void esxUtil_ReplaceSpecialWindowsPathChars(char *string);

char *esxUtil_EscapeDatastoreItem(const char *string);

char *esxUtil_EscapeForXml(const char *string);

#endif /* __ESX_UTIL_H__ */
