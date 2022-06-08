/*
 * esx_private.h: private driver struct for the VMware ESX driver
 *
 * Copyright (C) 2009-2011 Matthias Bolte <matthias.bolte@googlemail.com>
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
#include "capabilities.h"
#include "esx_vi.h"

typedef struct _esxPrivate {
    esxVI_Context *primary; /* points to host or vCenter */
    esxVI_Context *host;
    esxVI_Context *vCenter;
    esxUtil_ParsedUri *parsedUri;
    virCaps *caps;
    virDomainXMLOption *xmlopt;
    int32_t maxVcpus;
    esxVI_Boolean supportsVMotion;
    esxVI_Boolean supportsLongMode; /* aka x86_64 */
    esxVI_Boolean supportsScreenshot;
    int32_t usedCpuTimeCounterId;
} esxPrivate;
