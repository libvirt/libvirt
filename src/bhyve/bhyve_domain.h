/*
 * bhyve_domain.h: bhyve domain private state headers
 *
 * Copyright (C) 2014 Roman Bogorodskiy
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
 * Author: Roman Bogorodskiy
 */

#ifndef __BHYVE_DOMAIN_H__
# define __BHYVE_DOMAIN_H__

# include "domain_addr.h"
# include "domain_conf.h"

# include "bhyve_monitor.h"

typedef struct _bhyveDomainObjPrivate bhyveDomainObjPrivate;
typedef bhyveDomainObjPrivate *bhyveDomainObjPrivatePtr;
struct _bhyveDomainObjPrivate {
    virDomainPCIAddressSetPtr pciaddrs;
    bool persistentAddrs;

    bhyveMonitorPtr mon;
};

virDomainXMLOptionPtr virBhyveDriverCreateXMLConf(bhyveConnPtr);

extern virDomainXMLPrivateDataCallbacks virBhyveDriverPrivateDataCallbacks;
extern virDomainDefParserConfig virBhyveDriverDomainDefParserConfig;

#endif /* __BHYVE_DOMAIN_H__ */
