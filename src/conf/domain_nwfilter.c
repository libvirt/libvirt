/*
 * domain_nwfilter.c:
 *
 * Copyright (C) 2014 Red Hat, Inc.
 * Copyright (C) 2010 IBM Corporation
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

#include <config.h>

#include "internal.h"

#include "datatypes.h"
#include "domain_conf.h"
#include "domain_nwfilter.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

static virDomainConfNWFilterDriverPtr nwfilterDriver;

void
virDomainConfNWFilterRegister(virDomainConfNWFilterDriverPtr driver)
{
    nwfilterDriver = driver;
}

int
virDomainConfNWFilterInstantiate(const char *vmname,
                                 const unsigned char *vmuuid,
                                 virDomainNetDefPtr net)
{
    if (nwfilterDriver != NULL)
        return nwfilterDriver->instantiateFilter(vmname, vmuuid, net);

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                   _("No network filter driver available"));
    return -1;
}

void
virDomainConfNWFilterTeardown(virDomainNetDefPtr net)
{
    if (nwfilterDriver != NULL)
        nwfilterDriver->teardownFilter(net);
}

void
virDomainConfVMNWFilterTeardown(virDomainObjPtr vm)
{
    size_t i;

    if (nwfilterDriver != NULL) {
        for (i = 0; i < vm->def->nnets; i++)
            virDomainConfNWFilterTeardown(vm->def->nets[i]);
    }
}
