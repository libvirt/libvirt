/*
 * jailhouse_driver.c: Implementation of driver for Jailhouse hypervisor
 *
 * Copyright (C) 2020 Prakhar Bansal
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

#include <config.h>

#include "jailhouse_driver.h"
#include "virtypedparam.h"
#include "virerror.h"
#include "virstring.h"
#include "viralloc.h"
#include "domain_conf.h"
#include "virfile.h"
#include "datatypes.h"
#include "vircommand.h"
#include <string.h>

#define UNUSED(x) (void)(x)

static virDrvOpenStatus
jailhouseConnectOpen(virConnectPtr conn,
                     virConnectAuthPtr auth,
                     virConfPtr conf,
                     unsigned int flags)
{
    UNUSED(conn);
    UNUSED(auth);
    UNUSED(conf);
    UNUSED(flags);
    return 0;
}

static int
jailhouseConnectClose(virConnectPtr conn)
{
    UNUSED(conn);
    return 0;
}

static const char *
jailhouseConnectGetType(virConnectPtr conn)
{
    UNUSED(conn);
    return NULL;

}

static char *
jailhouseConnectGetHostname(virConnectPtr conn)
{
    UNUSED(conn);
    return NULL;
}

static int
jailhouseNodeGetInfo(virConnectPtr conn,
                     virNodeInfoPtr info)
{
    UNUSED(conn);
    UNUSED(info);
    return -1;
}

static int
jailhouseConnectListDomains(virConnectPtr conn,
                            int *ids,
                            int maxids)
{
    UNUSED(conn);
    UNUSED(ids);
    UNUSED(maxids);
    return -1;
}

static int
jailhouseConnectNumOfDomains(virConnectPtr conn)
{
    UNUSED(conn);
    return -1;
}

static int
jailhouseConnectListAllDomains(virConnectPtr conn,
                               virDomainPtr **domain,
                               unsigned int flags)
{
    UNUSED(conn);
    UNUSED(domain);
    UNUSED(flags);
    return -1;
}

static virDomainPtr
jailhouseDomainLookupByID(virConnectPtr conn,
                          int id)
{
    UNUSED(conn);
    UNUSED(id);
    return NULL;
}

static virDomainPtr
jailhouseDomainLookupByName(virConnectPtr conn,
                            const char *name)
{
    UNUSED(conn);
    UNUSED(name);
    return NULL;
}

static virDomainPtr
jailhouseDomainLookupByUUID(virConnectPtr conn,
                            const unsigned char *uuid)
{
    UNUSED(conn);
    UNUSED(uuid);
    return NULL;
}

static int
jailhouseDomainCreate(virDomainPtr domain)
{
    UNUSED(domain);
    return -1;

}

static int
jailhouseDomainShutdown(virDomainPtr domain)
{
    UNUSED(domain);
    return -1;
}


static int
jailhouseDomainDestroy(virDomainPtr domain)
{
    UNUSED(domain);
    return -1;
}

static int
jailhouseDomainGetInfo(virDomainPtr domain,
                       virDomainInfoPtr info)
{
    UNUSED(domain);
    UNUSED(info);
    return -1;
}

static int
jailhouseDomainGetState(virDomainPtr domain,
                        int *state,
                        int *reason,
                        unsigned int flags)
{
    UNUSED(domain);
    UNUSED(state);
    UNUSED(reason);
    UNUSED(flags);
    return -1;
}

static char *
jailhouseDomainGetXMLDesc(virDomainPtr domain,
                          unsigned int flags)
{
    UNUSED(domain);
    UNUSED(flags);
    return NULL;
}

static virHypervisorDriver jailhouseHypervisorDriver = {
    .name = "JAILHOUSE",
    .connectOpen = jailhouseConnectOpen, /* 6.3.0 */
    .connectClose = jailhouseConnectClose, /* 6.3.0 */
    .connectListDomains = jailhouseConnectListDomains, /* 6.3.0 */
    .connectNumOfDomains = jailhouseConnectNumOfDomains, /* 6.3.0 */
    .connectListAllDomains = jailhouseConnectListAllDomains, /* 6.3.0 */
    .domainLookupByID = jailhouseDomainLookupByID, /* 6.3.0 */
    .domainLookupByUUID = jailhouseDomainLookupByUUID, /* 6.3.0 */
    .domainLookupByName = jailhouseDomainLookupByName, /* 6.3.0 */
    .domainGetXMLDesc = jailhouseDomainGetXMLDesc, /* 6.3.0 */
    .domainCreate = jailhouseDomainCreate, /* 6.3.0 */
    .connectGetType = jailhouseConnectGetType, /* 6.3.0 */
    .connectGetHostname = jailhouseConnectGetHostname, /* 6.3.0 */
    .nodeGetInfo = jailhouseNodeGetInfo, /* 6.3.0 */
    .domainShutdown = jailhouseDomainShutdown, /* 6.3.0 */
    .domainDestroy = jailhouseDomainDestroy, /* 6.3.0 */
    .domainGetInfo = jailhouseDomainGetInfo, /* 6.3.0 */
    .domainGetState = jailhouseDomainGetState, /* 6.3.0 */
};

static virConnectDriver jailhouseConnectDriver = {
    .hypervisorDriver = &jailhouseHypervisorDriver,
};

int
jailhouseRegister(void)
{
    return virRegisterConnectDriver(&jailhouseConnectDriver, false);
}
