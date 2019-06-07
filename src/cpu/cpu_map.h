/*
 * cpu_map.h: internal functions for handling CPU mapping configuration
 *
 * Copyright (C) 2009 Red Hat, Inc.
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

#include "virxml.h"

typedef int
(*cpuMapLoadCallback)  (xmlXPathContextPtr ctxt,
                        const char *name,
                        void *data);

int
cpuMapLoad(const char *arch,
           cpuMapLoadCallback vendorCB,
           cpuMapLoadCallback featureCB,
           cpuMapLoadCallback modelCB,
           void *data);
