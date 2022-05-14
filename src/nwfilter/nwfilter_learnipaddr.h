/*
 * nwfilter_learnipaddr.h: support for learning IP address used by a VM
 *                         on an interface
 *
 * Copyright (C) 2012-2013 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corp.
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
#include "virnwfilterbindingdef.h"
#include <net/if.h>

enum howDetect {
  DETECT_DHCP = 1,
  DETECT_STATIC = 2,
};

int virNWFilterLearnIPAddress(virNWFilterTechDriver *techdriver,
                              virNWFilterBindingDef *binding,
                              int ifindex,
                              virNWFilterDriverState *driver,
                              int howDetect);

bool virNWFilterHasLearnReq(int ifindex);
int virNWFilterTerminateLearnReq(const char *ifname);

int virNWFilterLockIface(const char *ifname) G_GNUC_WARN_UNUSED_RESULT;
void virNWFilterUnlockIface(const char *ifname);

int virNWFilterLearnInit(void);
void virNWFilterLearnShutdown(void);
void virNWFilterLearnThreadsTerminate(bool allowNewThreads);
