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
 */

#include <config.h>

#include "internal.h"

#include "datatypes.h"
#include "domain_conf.h"
#include "domain_nwfilter.h"
#include "virnwfilterbindingdef.h"
#include "viralloc.h"
#include "virlog.h"


VIR_LOG_INIT("conf.domain_nwfilter");

#define VIR_FROM_THIS VIR_FROM_NWFILTER

static virNWFilterBindingDef *
virNWFilterBindingDefForNet(const char *vmname,
                            const unsigned char *vmuuid,
                            virDomainNetDef *net)
{
    g_autoptr(virNWFilterBindingDef) ret = g_new0(virNWFilterBindingDef, 1);

    ret->ownername = g_strdup(vmname);

    memcpy(ret->owneruuid, vmuuid, sizeof(ret->owneruuid));

    ret->portdevname = g_strdup(net->ifname);

    if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT)
        ret->linkdevname = g_strdup(net->data.direct.linkdev);

    ret->mac = net->mac;

    ret->filter = g_strdup(net->filter);

    ret->filterparams = virHashNew(virNWFilterVarValueHashFree);

    if (net->filterparams &&
        virNWFilterHashTablePutAll(net->filterparams, ret->filterparams) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


int
virDomainConfNWFilterInstantiate(const char *vmname,
                                 const unsigned char *vmuuid,
                                 virDomainNetDef *net,
                                 bool ignoreExists)
{
    virConnectPtr conn = virGetConnectNWFilter();
    virNWFilterBindingDef *def = NULL;
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
                                  virDomainNetDef *net)
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
virDomainConfNWFilterTeardown(virDomainNetDef *net)
{
    virConnectPtr conn;

    if (!net->filter)
        return;

    if (!(conn = virGetConnectNWFilter()))
        return;

    virDomainConfNWFilterTeardownImpl(conn, net);

    virObjectUnref(conn);
}

void
virDomainConfVMNWFilterTeardown(virDomainObj *vm)
{
    size_t i;
    virConnectPtr conn = NULL;

    for (i = 0; i < vm->def->nnets; i++) {
        virDomainNetDef *net = vm->def->nets[i];

        if (!net->filter)
            continue;

        if (!conn && !(conn = virGetConnectNWFilter()))
            return;

        virDomainConfNWFilterTeardownImpl(conn, net);
    }

    virObjectUnref(conn);
}
