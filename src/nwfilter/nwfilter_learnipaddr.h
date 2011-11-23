/*
 * nwfilter_learnipaddr.h: support for learning IP address used by a VM
 *                         on an interface
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

#ifndef __NWFILTER_LEARNIPADDR_H
# define __NWFILTER_LEARNIPADDR_H

# include "conf/nwfilter_params.h"

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
    enum virDomainNetType nettype;
    unsigned char macaddr[VIR_MAC_BUFLEN];
    char *filtername;
    virNWFilterHashTablePtr filterparams;
    virNWFilterDriverStatePtr driver;
    enum howDetect howDetect;

    int status;
    pthread_t thread;
    volatile bool terminate;
};

int virNWFilterLearnIPAddress(virNWFilterTechDriverPtr techdriver,
                              const char *ifname,
                              int ifindex,
                              const char *linkdev,
                              enum virDomainNetType nettype,
                              const unsigned char *macaddr,
                              const char *filtername,
                              virNWFilterHashTablePtr filterparams,
                              virNWFilterDriverStatePtr driver,
                              enum howDetect howDetect);

virNWFilterIPAddrLearnReqPtr virNWFilterLookupLearnReq(int ifindex);
int virNWFilterTerminateLearnReq(const char *ifname);

int virNWFilterDelIpAddrForIfname(const char *ifname, const char *ipaddr);
virNWFilterVarValuePtr virNWFilterGetIpAddrForIfname(const char *ifname);

int virNWFilterLockIface(const char *ifname) ATTRIBUTE_RETURN_CHECK;
void virNWFilterUnlockIface(const char *ifname);

int virNWFilterLearnInit(void);
void virNWFilterLearnShutdown(void);
void virNWFilterLearnThreadsTerminate(bool allowNewThreads);

#endif /* __NWFILTER_LEARNIPADDR_H */
