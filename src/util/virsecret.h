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
struct _virSecretLookupTypeDef {
    int type;   /* virSecretLookupType */
    union {
        unsigned char uuid[VIR_UUID_BUFLEN];
        char *usage;
    } u;

};

void virSecretLookupDefClear(virSecretLookupTypeDef *def);
void virSecretLookupDefCopy(virSecretLookupTypeDef *dst,
                            const virSecretLookupTypeDef *src);
int virSecretLookupParseSecret(xmlNodePtr secretnode,
                               virSecretLookupTypeDef *def);
void virSecretLookupFormatSecret(virBuffer *buf,
                                 const char *secrettype,
                                 virSecretLookupTypeDef *def);

int virSecretGetSecretString(virConnectPtr conn,
                             virSecretLookupTypeDef *seclookupdef,
                             virSecretUsageType secretUsageType,
                             uint8_t **ret_secret,
                             size_t *ret_secret_size)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_NONNULL(5) G_GNUC_WARN_UNUSED_RESULT;
