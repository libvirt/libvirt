/*
 * nwfilter_gentech_driver.h: generic technology driver include file
 *
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */
#ifndef __NWFILTER_GENTECH_DRIVER_H
# define __NWFILTER_GENTECH_DRIVER_H

virNWFilterTechDriverPtr virNWFilterTechDriverForName(const char *name);

int virNWFilterRuleInstAddData(virNWFilterRuleInstPtr res,
                               void *data);

void virNWFilterTechDriversInit(bool privileged);
void virNWFilterTechDriversShutdown(void);

enum instCase {
    INSTANTIATE_ALWAYS,
    INSTANTIATE_FOLLOW_NEWFILTER,
};


int virNWFilterInstantiateFilter(virConnectPtr conn,
                                 const unsigned char *vmuuid,
                                 const virDomainNetDefPtr net);
int virNWFilterUpdateInstantiateFilter(virConnectPtr conn,
                                       const unsigned char *vmuuid,
                                       const virDomainNetDefPtr net,
                                       bool *skipIface);

int virNWFilterInstantiateFilterLate(const unsigned char *vmuuid,
                                     const char *ifname,
                                     int ifindex,
                                     const char *linkdev,
                                     enum virDomainNetType nettype,
                                     const unsigned char *macaddr,
                                     const char *filtername,
                                     virNWFilterHashTablePtr filterparams,
                                     virNWFilterDriverStatePtr driver);

int virNWFilterTeardownFilter(const virDomainNetDefPtr net);

virNWFilterHashTablePtr virNWFilterCreateVarHashmap(char *macaddr,
                                       const virNWFilterVarValuePtr);

void virNWFilterDomainFWUpdateCB(void *payload,
                                 const void *name,
                                 void *data);

#endif
