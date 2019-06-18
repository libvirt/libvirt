/*
 * virsecret.h: secret utility functions
 *
 * Copyright (C) 2016 Red Hat, Inc.
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

#pragma once

#include "internal.h"

#include "virutil.h"
#include "virxml.h"
#include "virenum.h"

VIR_ENUM_DECL(virSecretUsage);

typedef enum {
    VIR_SECRET_LOOKUP_TYPE_NONE,
    VIR_SECRET_LOOKUP_TYPE_UUID,
    VIR_SECRET_LOOKUP_TYPE_USAGE,

    VIR_SECRET_LOOKUP_TYPE_LAST
} virSecretLookupType;

typedef struct _virSecretLookupTypeDef virSecretLookupTypeDef;
typedef virSecretLookupTypeDef *virSecretLookupTypeDefPtr;
struct _virSecretLookupTypeDef {
    int type;   /* virSecretLookupType */
    union {
        unsigned char uuid[VIR_UUID_BUFLEN];
        char *usage;
    } u;

};

void virSecretLookupDefClear(virSecretLookupTypeDefPtr def);
int virSecretLookupDefCopy(virSecretLookupTypeDefPtr dst,
                           const virSecretLookupTypeDef *src);
int virSecretLookupParseSecret(xmlNodePtr secretnode,
                               virSecretLookupTypeDefPtr def);
void virSecretLookupFormatSecret(virBufferPtr buf,
                                 const char *secrettype,
                                 virSecretLookupTypeDefPtr def);
