/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
#include "virnetdevbandwidth.h"
#include "virbuffer.h"
#include "virxml.h"
#include "domain_conf.h"
#include "network_conf.h"

int virNetDevBandwidthParse(virNetDevBandwidth **bandwidth,
                            unsigned int *class_id,
                            xmlNodePtr node,
                            bool allowFloor)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetDevBandwidthFormat(const virNetDevBandwidth *def,
                             unsigned int class_id,
                             virBuffer *buf);

void virDomainClearNetBandwidth(virDomainDef *def)
    ATTRIBUTE_NONNULL(1);

bool virNetDevSupportsBandwidth(virDomainNetType type);
bool virNetDevBandwidthHasFloor(const virNetDevBandwidth *b);
bool virNetDevBandwidthSupportsFloor(virNetworkForwardType type);
