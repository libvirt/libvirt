/*
 * nwfilter_ebiptables_driver.h: ebtables/iptables driver support
 *
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Stefan Berger
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

#include "nwfilter_tech_driver.h"

#define MAX_CHAINNAME_LENGTH  32 /* see linux/netfilter_bridge/ebtables.h */

extern virNWFilterTechDriver ebiptables_driver;

#define EBIPTABLES_DRIVER_ID "ebiptables"

#define IPTABLES_MAX_COMMENT_LENGTH  256
