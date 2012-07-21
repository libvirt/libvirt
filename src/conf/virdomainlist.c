/**
 * virdomainlist.c: Helpers for listing and filtering domains.
 *
 * Copyright (C) 2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Peter Krempa <pkrempa@redhat.com>
 */

#include <config.h>

#include "virdomainlist.h"

#include "internal.h"
#include "virhash.h"
#include "domain_conf.h"
#include "memory.h"
#include "datatypes.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

struct virDomainListData {
    virConnectPtr conn;
    virDomainPtr *domains;
    unsigned int flags;
    int ndomains;
    bool error;
};

#define MATCH(FLAG) (data->flags & (FLAG))
static void
virDomainListPopulate(void *payload,
                      const void *name ATTRIBUTE_UNUSED,
                      void *opaque)
{
    struct virDomainListData *data = opaque;
    virDomainObjPtr vm = payload;
    virDomainPtr dom;

    if (data->error)
        return;

    virDomainObjLock(vm);
    /* check if the domain matches the filter */

    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) &&
           virDomainObjIsActive(vm)) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE) &&
           !virDomainObjIsActive(vm))))
        goto cleanup;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT) &&
           vm->persistent) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) &&
           !vm->persistent)))
        goto cleanup;

    /* filter by domain state */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_STATE)) {
        int st = virDomainObjGetState(vm, NULL);
        if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
               st == VIR_DOMAIN_RUNNING) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
               st == VIR_DOMAIN_PAUSED) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
               st == VIR_DOMAIN_SHUTOFF) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
               (st != VIR_DOMAIN_RUNNING &&
                st != VIR_DOMAIN_PAUSED &&
                st != VIR_DOMAIN_SHUTOFF))))
            goto cleanup;
    }

    /* filter by existence of managed save state */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_MANAGEDSAVE) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) &&
           vm->hasManagedSave) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) &&
           !vm->hasManagedSave)))
            goto cleanup;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) && vm->autostart) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART) && !vm->autostart)))
        goto cleanup;

    /* filter by snapshot existence */
    if (MATCH(VIR_CONNECT_LIST_FILTERS_SNAPSHOT)) {
        int nsnap = virDomainSnapshotObjListNum(&vm->snapshots, NULL, 0);
        if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) && nsnap > 0) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) && nsnap <= 0)))
            goto cleanup;
    }

    /* just count the machines */
    if (!data->domains) {
        data->ndomains++;
        return;
    }

    if (!(dom = virGetDomain(data->conn, vm->def->name, vm->def->uuid))) {
        data->error = true;
        goto cleanup;
    }

    dom->id = vm->def->id;

    data->domains[data->ndomains++] = dom;

cleanup:
    virDomainObjUnlock(vm);
    return;
}
#undef MATCH

int
virDomainList(virConnectPtr conn,
              virHashTablePtr domobjs,
              virDomainPtr **domains,
              unsigned int flags)
{
    int ret = -1;
    int i;

    struct virDomainListData data = { conn, NULL, flags, 0, false };

    if (domains) {
        if (VIR_ALLOC_N(data.domains, virHashSize(domobjs) + 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    }

    virHashForEach(domobjs, virDomainListPopulate, &data);

    if (data.error)
        goto cleanup;

    if (data.domains) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.domains, data.ndomains + 1));
        *domains = data.domains;
        data.domains = NULL;
    }

    ret = data.ndomains;

cleanup:
    if (data.domains) {
        int count = virHashSize(domobjs);
        for (i = 0; i < count; i++) {
            if (data.domains[i])
                virDomainFree(data.domains[i]);
        }
    }

    VIR_FREE(data.domains);
    return ret;
}

int
virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                       virDomainSnapshotObjPtr from,
                       virDomainPtr dom,
                       virDomainSnapshotPtr **snaps,
                       unsigned int flags)
{
    int count = virDomainSnapshotObjListNum(snapshots, from, flags);
    virDomainSnapshotPtr *list;
    char **names;
    int ret = -1;
    int i;

    if (!snaps)
        return count;
    if (VIR_ALLOC_N(names, count) < 0 ||
        VIR_ALLOC_N(list, count + 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virDomainSnapshotObjListGetNames(snapshots, from, names, count,
                                         flags) < 0)
        goto cleanup;
    for (i = 0; i < count; i++)
        if ((list[i] = virGetDomainSnapshot(dom, names[i])) == NULL)
            goto cleanup;

    ret = count;
    *snaps = list;

cleanup:
    for (i = 0; i < count; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);
    if (ret < 0 && list) {
        for (i = 0; i < count; i++)
            if (list[i])
                virDomainSnapshotFree(list[i]);
        VIR_FREE(list);
    }
    return ret;
}
