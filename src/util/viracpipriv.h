/*
 * viracpipriv.h: Functions for testing virAcpi APIs
 *
 * Copyright (C) 2023 Red Hat, Inc.
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

#ifndef LIBVIRT_VIRACPIPRIV_H_ALLOW
# error "viracpipriv.h may only be included by viracpi.c or test suites"
#endif /* LIBVIRT_VIRACPIPRIV_H_ALLOW */

#pragma once

#include <inttypes.h>

#include "internal.h"
#include "virenum.h"

typedef enum {
    VIR_IORT_NODE_TYPE_ITS_GROUP = 0,
    VIR_IORT_NODE_TYPE_NAMED_COMPONENT,
    VIR_IORT_NODE_TYPE_ROOT_COMPLEX,
    VIR_IORT_NODE_TYPE_SMMUV1_OR_SMMUV2,
    VIR_IORT_NODE_TYPE_SMMUV3,
    VIR_IORT_NODE_TYPE_PMCG,
    VIR_IORT_NODE_TYPE_MEMORY_RANGE,
    VIR_IORT_NODE_TYPE_LAST,
} virIORTNodeType;

VIR_ENUM_DECL(virIORTNodeType);

typedef struct virIORTNodeHeader virIORTNodeHeader;
struct virIORTNodeHeader {
    uint8_t type; /* One of virIORTNodeType */
    uint16_t len;
    uint8_t revision;
    uint32_t identifier;
    uint32_t nmappings;
    uint32_t reference_id;
} ATTRIBUTE_PACKED;

ssize_t
virAcpiParseIORT(virIORTNodeHeader **nodesRet,
                 const char *filename);
