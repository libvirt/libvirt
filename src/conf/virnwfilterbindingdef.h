/*
 * virnwfilterbindingdef.h: network filter binding XML processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
#include "virmacaddr.h"
#include "virhash.h"
#include "virbuffer.h"
#include "virxml.h"

typedef struct _virNWFilterBindingDef virNWFilterBindingDef;
struct _virNWFilterBindingDef {
    char *ownername;
    unsigned char owneruuid[VIR_UUID_BUFLEN];
    char *portdevname;
    char *linkdevname;
    virMacAddr mac;
    char *filter;
    GHashTable *filterparams;
};


void
virNWFilterBindingDefFree(virNWFilterBindingDef *binding);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNWFilterBindingDef, virNWFilterBindingDefFree);

virNWFilterBindingDef *
virNWFilterBindingDefCopy(virNWFilterBindingDef *src);

virNWFilterBindingDef *
virNWFilterBindingDefParseXML(xmlXPathContextPtr ctxt);

virNWFilterBindingDef *
virNWFilterBindingDefParse(const char *xmlStr,
                           const char *filename,
                           unsigned int flags);

char *
virNWFilterBindingDefFormat(const virNWFilterBindingDef *def);

int
virNWFilterBindingDefFormatBuf(virBuffer *buf,
                               const virNWFilterBindingDef *def);
