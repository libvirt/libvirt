/*
 * nwfilter_gentech_driver.h: generic technology driver include file
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#include "virnwfilterobj.h"
#include "virnwfilterbindingdef.h"

int virNWFilterTechDriversInit(bool privileged);
void virNWFilterTechDriversShutdown(void);

enum instCase {
    INSTANTIATE_ALWAYS,
    INSTANTIATE_FOLLOW_NEWFILTER,
};


int virNWFilterInstantiateFilter(virNWFilterDriverState *driver,
                                 virNWFilterBindingDef *binding);

int virNWFilterInstantiateFilterLate(virNWFilterDriverState *driver,
                                     virNWFilterBindingDef *binding,
                                     int ifindex);

int virNWFilterTeardownFilter(virNWFilterBindingDef *binding);

int virNWFilterBuildAll(virNWFilterDriverState *driver,
                        bool newFilters);
