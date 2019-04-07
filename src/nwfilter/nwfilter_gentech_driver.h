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

#ifndef LIBVIRT_NWFILTER_GENTECH_DRIVER_H
# define LIBVIRT_NWFILTER_GENTECH_DRIVER_H

# include "virnwfilterobj.h"
# include "virnwfilterbindingdef.h"
# include "nwfilter_tech_driver.h"

virNWFilterTechDriverPtr virNWFilterTechDriverForName(const char *name);

int virNWFilterTechDriversInit(bool privileged);
void virNWFilterTechDriversShutdown(void);

enum instCase {
    INSTANTIATE_ALWAYS,
    INSTANTIATE_FOLLOW_NEWFILTER,
};


int virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                                 virNWFilterBindingDefPtr binding);
int virNWFilterUpdateInstantiateFilter(virNWFilterDriverStatePtr driver,
                                       virNWFilterBindingDefPtr binding,
                                       bool *skipIface);

int virNWFilterInstantiateFilterLate(virNWFilterDriverStatePtr driver,
                                     virNWFilterBindingDefPtr binding,
                                     int ifindex);

int virNWFilterTeardownFilter(virNWFilterBindingDefPtr binding);

virHashTablePtr virNWFilterCreateVarHashmap(const char *macaddr,
                                            const virNWFilterVarValue *value);

int virNWFilterBuildAll(virNWFilterDriverStatePtr driver,
                        bool newFilters);

#endif /* LIBVIRT_NWFILTER_GENTECH_DRIVER_H */
