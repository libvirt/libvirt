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
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef __NWFILTER_GENTECH_DRIVER_H
# define __NWFILTER_GENTECH_DRIVER_H

# include "virnwfilterobj.h"
# include "nwfilter_tech_driver.h"

virNWFilterTechDriverPtr virNWFilterTechDriverForName(const char *name);

int virNWFilterTechDriversInit(bool privileged);
void virNWFilterTechDriversShutdown(void);

enum instCase {
    INSTANTIATE_ALWAYS,
    INSTANTIATE_FOLLOW_NEWFILTER,
};


int virNWFilterInstantiateFilter(virNWFilterDriverStatePtr driver,
                                 const unsigned char *vmuuid,
                                 const virDomainNetDef *net);
int virNWFilterUpdateInstantiateFilter(virNWFilterDriverStatePtr driver,
                                       const unsigned char *vmuuid,
                                       const virDomainNetDef *net,
                                       bool *skipIface);

int virNWFilterInstantiateFilterLate(virNWFilterDriverStatePtr driver,
                                     const unsigned char *vmuuid,
                                     const char *ifname,
                                     int ifindex,
                                     const char *linkdev,
                                     const virMacAddr *macaddr,
                                     const char *filtername,
                                     virNWFilterHashTablePtr filterparams);

int virNWFilterTeardownFilter(const virDomainNetDef *net);

virNWFilterHashTablePtr virNWFilterCreateVarHashmap(char *macaddr,
                                       const virNWFilterVarValue *value);

int virNWFilterDomainFWUpdateCB(virDomainObjPtr vm,
                                void *data);

#endif
