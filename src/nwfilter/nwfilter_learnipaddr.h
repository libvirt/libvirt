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
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef __NWFILTER_LEARNIPADDR_H
# define __NWFILTER_LEARNIPADDR_H

# include "conf/nwfilter_params.h"
# include "nwfilter_tech_driver.h"
# include <net/if.h>

enum howDetect {
  DETECT_DHCP = 1,
  DETECT_STATIC = 2,
};

typedef struct _virNWFilterIPAddrLearnReq virNWFilterIPAddrLearnReq;
typedef virNWFilterIPAddrLearnReq *virNWFilterIPAddrLearnReqPtr;
struct _virNWFilterIPAddrLearnReq {
    virNWFilterTechDriverPtr techdriver;
    char ifname[IF_NAMESIZE];
    int ifindex;
    char linkdev[IF_NAMESIZE];
    virMacAddr macaddr;
    char *filtername;
    virNWFilterHashTablePtr filterparams;
    virNWFilterDriverStatePtr driver;
    enum howDetect howDetect;

    int status;
    volatile bool terminate;
};

int virNWFilterLearnIPAddress(virNWFilterTechDriverPtr techdriver,
                              const char *ifname,
                              int ifindex,
                              const char *linkdev,
                              const virMacAddr *macaddr,
                              const char *filtername,
                              virNWFilterHashTablePtr filterparams,
                              virNWFilterDriverStatePtr driver,
                              enum howDetect howDetect);

virNWFilterIPAddrLearnReqPtr virNWFilterLookupLearnReq(int ifindex);
int virNWFilterTerminateLearnReq(const char *ifname);

int virNWFilterLockIface(const char *ifname) ATTRIBUTE_RETURN_CHECK;
void virNWFilterUnlockIface(const char *ifname);

int virNWFilterLearnInit(void);
void virNWFilterLearnShutdown(void);
void virNWFilterLearnThreadsTerminate(bool allowNewThreads);

#endif /* __NWFILTER_LEARNIPADDR_H */
