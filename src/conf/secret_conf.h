/*
 * secret_conf.h: internal <secret> XML handling API
 *
 * Copyright (C) 2009-2010, 2013-2014, 2016 Red Hat, Inc.
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

#ifndef LIBVIRT_SECRET_CONF_H
# define LIBVIRT_SECRET_CONF_H

# include "internal.h"
# include "virutil.h"

typedef struct _virSecretDef virSecretDef;
typedef virSecretDef *virSecretDefPtr;
struct _virSecretDef {
    bool isephemeral;
    bool isprivate;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *description;          /* May be NULL */
    int usage_type;  /* virSecretUsageType */
    char *usage_id; /* May be NULL */
};

void virSecretDefFree(virSecretDefPtr def);
virSecretDefPtr virSecretDefParseString(const char *xml);
virSecretDefPtr virSecretDefParseFile(const char *filename);
char *virSecretDefFormat(const virSecretDef *def);

# define VIR_CONNECT_LIST_SECRETS_FILTERS_EPHEMERAL \
                (VIR_CONNECT_LIST_SECRETS_EPHEMERAL     | \
                 VIR_CONNECT_LIST_SECRETS_NO_EPHEMERAL)

# define VIR_CONNECT_LIST_SECRETS_FILTERS_PRIVATE \
                (VIR_CONNECT_LIST_SECRETS_PRIVATE     | \
                 VIR_CONNECT_LIST_SECRETS_NO_PRIVATE)

# define VIR_CONNECT_LIST_SECRETS_FILTERS_ALL \
                (VIR_CONNECT_LIST_SECRETS_FILTERS_EPHEMERAL  | \
                 VIR_CONNECT_LIST_SECRETS_FILTERS_PRIVATE)

#endif /* LIBVIRT_SECRET_CONF_H */
