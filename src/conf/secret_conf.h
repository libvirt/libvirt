/*
 * secret_conf.h: internal <secret> XML handling API
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Red Hat Author: Miloslav Trmač <mitr@redhat.com>
 */

#ifndef __VIR_SECRET_CONF_H__
# define __VIR_SECRET_CONF_H__

# include "internal.h"
# include "util.h"

VIR_ENUM_DECL(virSecretUsageType)

typedef struct _virSecretDef virSecretDef;
typedef virSecretDef *virSecretDefPtr;
struct _virSecretDef {
    unsigned ephemeral : 1;
    unsigned private : 1;
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *description;          /* May be NULL */
    int usage_type;
    union {
        char *volume;               /* May be NULL */
        char *ceph;
    } usage;
};

void virSecretDefFree(virSecretDefPtr def);
virSecretDefPtr virSecretDefParseString(const char *xml);
virSecretDefPtr virSecretDefParseFile(const char *filename);
char *virSecretDefFormat(const virSecretDefPtr def);

#endif
