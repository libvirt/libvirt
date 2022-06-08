/*
 * bridge_driver.h: core driver methods for managing networks
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
#include "virdnsmasq.h"
#include "virnetworkobj.h"

virNetworkXMLOption *
networkDnsmasqCreateXMLConf(void);

int
networkRegister(void);

int
networkDnsmasqConfContents(virNetworkObj *obj,
                           const char *pidfile,
                           char **configstr,
                           char **hostsfilestr,
                           dnsmasqContext *dctx,
                           dnsmasqCaps *caps);
