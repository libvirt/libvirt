/*
 * domain_nwfilter.c:
 *
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#include <config.h>

#include "internal.h"

#include "datatypes.h"
#include "domain_conf.h"
#include "domain_nwfilter.h"

static virDomainConfNWFilterDriverPtr nwfilterDriver;

void
virDomainConfNWFilterRegister(virDomainConfNWFilterDriverPtr driver) {
    nwfilterDriver = driver;
}

int
virDomainConfNWFilterInstantiate(virConnectPtr conn,
                                 const unsigned char *vmuuid,
                                 virDomainNetDefPtr net) {
    if (nwfilterDriver != NULL)
        return nwfilterDriver->instantiateFilter(conn, vmuuid, net);
    /* driver module not available -- don't indicate failure */
    return 0;
}

void
virDomainConfNWFilterTeardown(virDomainNetDefPtr net) {
    if (nwfilterDriver != NULL)
        nwfilterDriver->teardownFilter(net);
}

void
virDomainConfVMNWFilterTeardown(virDomainObjPtr vm) {
    int i;

    if (nwfilterDriver != NULL) {
        for (i = 0; i < vm->def->nnets; i++)
            virDomainConfNWFilterTeardown(vm->def->nets[i]);
    }
}
