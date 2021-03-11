/*
 * Copyright (C) 2009-2012 Red Hat, Inc.
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

#pragma once

#include "internal.h"
#include "virnetdevvportprofile.h"
#include "virbuffer.h"
#include "virxml.h"

typedef enum {
    /* generate random defaults for interfaceID/interfaceID
     * when appropriate
     */
    VIR_VPORT_XML_GENERATE_MISSING_DEFAULTS = (1<<0),
    /* fail if any attribute required for the specified
     * type is missing
     */
    VIR_VPORT_XML_REQUIRE_ALL_ATTRIBUTES    = (1<<1),
    /* fail if no type is specified */
    VIR_VPORT_XML_REQUIRE_TYPE              = (1<<2),
} virNetDevVPortXMLFlags;

virNetDevVPortProfile *
virNetDevVPortProfileParse(xmlNodePtr node, unsigned int flags);

int
virNetDevVPortProfileFormat(const virNetDevVPortProfile *virtPort,
                            virBuffer *buf);
