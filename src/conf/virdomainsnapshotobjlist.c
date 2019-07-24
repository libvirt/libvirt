/*
 * virdomainsnapshotobjlist.c: handle a tree of snapshot objects
 *                  (derived from snapshot_conf.c)
 *
 * Copyright (C) 2006-2019 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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
#include "virdomainsnapshotobjlist.h"
#include "snapshot_conf.h"
#include "virlog.h"
#include "virerror.h"
#include "datatypes.h"
#include "virstring.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.virdomainsnapshotobjlist");

struct _virDomainSnapshotObjList {
    virDomainMomentObjListPtr base;
};


virDomainMomentObjPtr
virDomainSnapshotAssignDef(virDomainSnapshotObjListPtr snapshots,
                           virDomainSnapshotDefPtr def)
{
    return virDomainMomentAssignDef(snapshots->base, &def->parent);
}


static bool
virDomainSnapshotFilter(virDomainMomentObjPtr obj,
                        unsigned int flags)
{
    virDomainSnapshotDefPtr def = virDomainSnapshotObjGetDef(obj);

    /* Caller has already sanitized flags and performed filtering on
     * DESCENDANTS and LEAVES. */
    if (flags & VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS) {
        if (!(flags & VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE) &&
            def->state == VIR_DOMAIN_SNAPSHOT_SHUTOFF)
            return false;
        if (!(flags & VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY) &&
            def->state == VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)
            return false;
        if (!(flags & VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE) &&
            def->state != VIR_DOMAIN_SNAPSHOT_SHUTOFF &&
            def->state != VIR_DOMAIN_SNAPSHOT_DISK_SNAPSHOT)
            return false;
    }

    if ((flags & VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL) &&
        virDomainSnapshotIsExternal(obj))
        return false;
    if ((flags & VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL) &&
        !virDomainSnapshotIsExternal(obj))
        return false;

    return true;
}


virDomainSnapshotObjListPtr
virDomainSnapshotObjListNew(void)
{
    virDomainSnapshotObjListPtr snapshots;

    if (VIR_ALLOC(snapshots) < 0)
        return NULL;
    snapshots->base = virDomainMomentObjListNew();
    if (!snapshots->base) {
        VIR_FREE(snapshots);
        return NULL;
    }
    return snapshots;
}


void
virDomainSnapshotObjListFree(virDomainSnapshotObjListPtr snapshots)
{
    if (!snapshots)
        return;
    virDomainMomentObjListFree(snapshots->base);
    VIR_FREE(snapshots);
}


int
virDomainSnapshotObjListGetNames(virDomainSnapshotObjListPtr snapshots,
                                 virDomainMomentObjPtr from,
                                 char **const names,
                                 int maxnames,
                                 unsigned int flags)
{
    /* Convert public flags into common flags */
    unsigned int moment_flags = 0;
    struct { int snap_flag; int moment_flag; } map[] = {
        { VIR_DOMAIN_SNAPSHOT_LIST_ROOTS,
          VIR_DOMAIN_MOMENT_LIST_ROOTS, },
        { VIR_DOMAIN_SNAPSHOT_LIST_TOPOLOGICAL,
          VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL, },
        { VIR_DOMAIN_SNAPSHOT_LIST_LEAVES,
          VIR_DOMAIN_MOMENT_LIST_LEAVES, },
        { VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES,
          VIR_DOMAIN_MOMENT_LIST_NO_LEAVES, },
        { VIR_DOMAIN_SNAPSHOT_LIST_METADATA,
          VIR_DOMAIN_MOMENT_LIST_METADATA, },
        { VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA,
          VIR_DOMAIN_MOMENT_LIST_NO_METADATA, },
    };
    size_t i;

    for (i = 0; i < ARRAY_CARDINALITY(map); i++) {
        if (flags & map[i].snap_flag) {
            flags &= ~map[i].snap_flag;
            moment_flags |= map[i].moment_flag;
        }
    }

    /* For ease of coding the visitor, it is easier to zero each group
     * where all of the bits are set.  */
    if ((flags & VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES)
        flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES;
    if ((flags & VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS)
        flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS;
    if ((flags & VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION) ==
        VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)
        flags &= ~VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION;
    return virDomainMomentObjListGetNames(snapshots->base, from, names,
                                          maxnames, moment_flags,
                                          virDomainSnapshotFilter, flags);
}


int
virDomainSnapshotObjListNum(virDomainSnapshotObjListPtr snapshots,
                            virDomainMomentObjPtr from,
                            unsigned int flags)
{
    return virDomainSnapshotObjListGetNames(snapshots, from, NULL, 0, flags);
}


virDomainMomentObjPtr
virDomainSnapshotFindByName(virDomainSnapshotObjListPtr snapshots,
                            const char *name)
{
    return virDomainMomentFindByName(snapshots->base, name);
}


/* Return the current snapshot, or NULL */
virDomainMomentObjPtr
virDomainSnapshotGetCurrent(virDomainSnapshotObjListPtr snapshots)
{
    return virDomainMomentGetCurrent(snapshots->base);
}


/* Return the current snapshot's name, or NULL */
const char *
virDomainSnapshotGetCurrentName(virDomainSnapshotObjListPtr snapshots)
{
    return virDomainMomentGetCurrentName(snapshots->base);
}


/* Update the current snapshot, using NULL if no current remains */
void
virDomainSnapshotSetCurrent(virDomainSnapshotObjListPtr snapshots,
                            virDomainMomentObjPtr snapshot)
{
    virDomainMomentSetCurrent(snapshots->base, snapshot);
}


/* Remove snapshot from the list; return true if it was current */
bool
virDomainSnapshotObjListRemove(virDomainSnapshotObjListPtr snapshots,
                               virDomainMomentObjPtr snapshot)
{
    return virDomainMomentObjListRemove(snapshots->base, snapshot);
}


/* Remove all snapshots tracked in the list */
void
virDomainSnapshotObjListRemoveAll(virDomainSnapshotObjListPtr snapshots)
{
    return virDomainMomentObjListRemoveAll(snapshots->base);
}


int
virDomainSnapshotForEach(virDomainSnapshotObjListPtr snapshots,
                         virHashIterator iter,
                         void *data)
{
    return virDomainMomentForEach(snapshots->base, iter, data);
}


/* Populate parent link of a given snapshot. */
void
virDomainSnapshotLinkParent(virDomainSnapshotObjListPtr snapshots,
                            virDomainMomentObjPtr snap)
{
    return virDomainMomentLinkParent(snapshots->base, snap);
}


/* Populate parent link and child count of all snapshots, with all
 * assigned defs having relations starting as 0/NULL. Return 0 on
 * success, -1 if a parent is missing or if a circular relationship
 * was requested. */
int
virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots)
{
    return virDomainMomentUpdateRelations(snapshots->base);
}


int
virDomainSnapshotCheckCycles(virDomainSnapshotObjListPtr snapshots,
                             virDomainSnapshotDefPtr def,
                             const char *domname)
{
    return virDomainMomentCheckCycles(snapshots->base, &def->parent, domname);
}


int
virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                       virDomainMomentObjPtr from,
                       virDomainPtr dom,
                       virDomainSnapshotPtr **snaps,
                       unsigned int flags)
{
    int count = virDomainSnapshotObjListNum(snapshots, from, flags);
    virDomainSnapshotPtr *list = NULL;
    char **names;
    int ret = -1;
    size_t i;

    if (!snaps || count < 0)
        return count;
    if (VIR_ALLOC_N(names, count) < 0 ||
        VIR_ALLOC_N(list, count + 1) < 0)
        goto cleanup;

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
            virObjectUnref(list[i]);
        VIR_FREE(list);
    }
    return ret;
}
