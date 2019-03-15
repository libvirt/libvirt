/*
 * virdomainsnapshotobj.c: handle snapshot objects
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
#include "virdomainsnapshotobj.h"
#include "snapshot_conf.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.virdomainsnapshotobj");

/* Run iter(data) on all direct children of snapshot, while ignoring all
 * other entries in snapshots.  Return the number of children
 * visited.  No particular ordering is guaranteed.  */
int
virDomainSnapshotForEachChild(virDomainSnapshotObjPtr snapshot,
                              virHashIterator iter,
                              void *data)
{
    virDomainSnapshotObjPtr child = snapshot->first_child;

    while (child) {
        virDomainSnapshotObjPtr next = child->sibling;
        (iter)(child, child->def->name, data);
        child = next;
    }

    return snapshot->nchildren;
}

struct snapshot_act_on_descendant {
    int number;
    virHashIterator iter;
    void *data;
};

static int
virDomainSnapshotActOnDescendant(void *payload,
                                 const void *name,
                                 void *data)
{
    virDomainSnapshotObjPtr obj = payload;
    struct snapshot_act_on_descendant *curr = data;

    (curr->iter)(payload, name, curr->data);
    curr->number += 1 + virDomainSnapshotForEachDescendant(obj,
                                                           curr->iter,
                                                           curr->data);
    return 0;
}

/* Run iter(data) on all descendants of snapshot, while ignoring all
 * other entries in snapshots.  Return the number of descendants
 * visited.  The visit is guaranteed to be topological, but no
 * particular order between siblings is guaranteed.  */
int
virDomainSnapshotForEachDescendant(virDomainSnapshotObjPtr snapshot,
                                   virHashIterator iter,
                                   void *data)
{
    struct snapshot_act_on_descendant act;

    act.number = 0;
    act.iter = iter;
    act.data = data;
    virDomainSnapshotForEachChild(snapshot,
                                  virDomainSnapshotActOnDescendant, &act);

    return act.number;
}


/* Prepare to reparent or delete snapshot, by removing it from its
 * current listed parent.  Note that when bulk removing all children
 * of a parent, it is faster to just 0 the count rather than calling
 * this function on each child.  */
void
virDomainSnapshotDropParent(virDomainSnapshotObjPtr snapshot)
{
    virDomainSnapshotObjPtr prev = NULL;
    virDomainSnapshotObjPtr curr = NULL;

    snapshot->parent->nchildren--;
    curr = snapshot->parent->first_child;
    while (curr != snapshot) {
        if (!curr) {
            VIR_WARN("inconsistent snapshot relations");
            return;
        }
        prev = curr;
        curr = curr->sibling;
    }
    if (prev)
        prev->sibling = snapshot->sibling;
    else
        snapshot->parent->first_child = snapshot->sibling;
    snapshot->parent = NULL;
    snapshot->sibling = NULL;
}
