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
#include "virnwfilterbindingdef.h"
#include "virerror.h"
#include "viralloc.h"
#include "virstring.h"
#include "virlog.h"


VIR_LOG_INIT("conf.domain_nwfilter");

#define VIR_FROM_THIS VIR_FROM_NWFILTER

static virNWFilterBindingDefPtr
virNWFilterBindingDefForNet(const char *vmname,
                            const unsigned char *vmuuid,
                            virDomainNetDefPtr net)
{
    virNWFilterBindingDefPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    if (VIR_STRDUP(ret->ownername, vmname) < 0)
        goto error;

    memcpy(ret->owneruuid, vmuuid, sizeof(ret->owneruuid));

    if (VIR_STRDUP(ret->portdevname, net->ifname) < 0)
        goto error;

    if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT &&
        VIR_STRDUP(ret->linkdevname, net->data.direct.linkdev) < 0)
        goto error;

    ret->mac = net->mac;

    if (VIR_STRDUP(ret->filter, net->filter) < 0)
        goto error;

    if (!(ret->filterparams = virNWFilterHashTableCreate(0)))
        goto error;

    if (net->filterparams &&
        virNWFilterHashTablePutAll(net->filterparams, ret->filterparams) < 0)
        goto error;

    return ret;

 error:
    virNWFilterBindingDefFree(ret);
    return NULL;
}


int
virDomainConfNWFilterInstantiate(const char *vmname,
                                 const unsigned char *vmuuid,
                                 virDomainNetDefPtr net,
                                 bool ignoreExists)
{
    virConnectPtr conn = virGetConnectNWFilter();
    virNWFilterBindingDefPtr def = NULL;
    virNWFilterBindingPtr binding = NULL;
    char *xml = NULL;
    int ret = -1;

    VIR_DEBUG("vmname=%s portdev=%s filter=%s ignoreExists=%d",
              vmname, NULLSTR(net->ifname), NULLSTR(net->filter), ignoreExists);

    if (!conn)
        goto cleanup;

    if (ignoreExists) {
        binding = virNWFilterBindingLookupByPortDev(conn, net->ifname);
        if (binding) {
            ret = 0;
            goto cleanup;
        }
    }

    if (!(def = virNWFilterBindingDefForNet(vmname, vmuuid, net)))
        goto cleanup;

    if (!(xml = virNWFilterBindingDefFormat(def)))
        goto cleanup;

    if (!(binding = virNWFilterBindingCreateXML(conn, xml, 0)))
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(xml);
    virNWFilterBindingDefFree(def);
    virObjectUnref(binding);
    virObjectUnref(conn);
    return ret;
}


static void
virDomainConfNWFilterTeardownImpl(virConnectPtr conn,
                                  virDomainNetDefPtr net)
{
    virNWFilterBindingPtr binding;

    if (!net->ifname)
        return;

    binding = virNWFilterBindingLookupByPortDev(conn, net->ifname);
    if (!binding)
        return;

    virNWFilterBindingDelete(binding);

    virObjectUnref(binding);
}


void
virDomainConfNWFilterTeardown(virDomainNetDefPtr net)
{
    virConnectPtr conn = virGetConnectNWFilter();

    if (!conn)
        return;

    virDomainConfNWFilterTeardownImpl(conn, net);

    virObjectUnref(conn);
}

void
virDomainConfVMNWFilterTeardown(virDomainObjPtr vm)
{
    size_t i;
    virConnectPtr conn = virGetConnectNWFilter();

    if (!conn)
        return;


    for (i = 0; i < vm->def->nnets; i++)
        virDomainConfNWFilterTeardownImpl(conn, vm->def->nets[i]);

    virObjectUnref(conn);
}
