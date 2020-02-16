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
typedef virNWFilterBindingDef *virNWFilterBindingDefPtr;

struct _virNWFilterBindingDef {
    char *ownername;
    unsigned char owneruuid[VIR_UUID_BUFLEN];
    char *portdevname;
    char *linkdevname;
    virMacAddr mac;
    char *filter;
    virHashTablePtr filterparams;
};


void
virNWFilterBindingDefFree(virNWFilterBindingDefPtr binding);
virNWFilterBindingDefPtr
virNWFilterBindingDefCopy(virNWFilterBindingDefPtr src);

virNWFilterBindingDefPtr
virNWFilterBindingDefParseNode(xmlDocPtr xml,
                               xmlNodePtr root);

virNWFilterBindingDefPtr
virNWFilterBindingDefParseString(const char *xml);

virNWFilterBindingDefPtr
virNWFilterBindingDefParseFile(const char *filename);

char *
virNWFilterBindingDefFormat(const virNWFilterBindingDef *def);

int
virNWFilterBindingDefFormatBuf(virBufferPtr buf,
                               const virNWFilterBindingDef *def);
