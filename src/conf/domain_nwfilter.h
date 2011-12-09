/*
 * domain_nwfilter.h:
 *
 * Copyright (C) 2010 IBM Corporation
 * Copyright (C) 2010 Red Hat, Inc.
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
#ifndef DOMAIN_NWFILTER_H
# define DOMAIN_NWFILTER_H

typedef int (*virDomainConfInstantiateNWFilter)(virConnectPtr conn,
                                                const unsigned char *vmuuid,
                                                virDomainNetDefPtr net);
typedef void (*virDomainConfTeardownNWFilter)(virDomainNetDefPtr net);

typedef struct {
    virDomainConfInstantiateNWFilter instantiateFilter;
    virDomainConfTeardownNWFilter    teardownFilter;
} virDomainConfNWFilterDriver;
typedef virDomainConfNWFilterDriver *virDomainConfNWFilterDriverPtr;

void virDomainConfNWFilterRegister(virDomainConfNWFilterDriverPtr driver);

int virDomainConfNWFilterInstantiate(virConnectPtr conn,
                                     const unsigned char *vmuuid,
                                     virDomainNetDefPtr net);
void virDomainConfNWFilterTeardown(virDomainNetDefPtr net);
void virDomainConfVMNWFilterTeardown(virDomainObjPtr vm);

#endif /* DOMAIN_NWFILTER_H */
