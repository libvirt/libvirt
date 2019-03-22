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
#include "virdomainsnapshotobjlist.h"
#include "virlog.h"
#include "virerror.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_SNAPSHOT

VIR_LOG_INIT("conf.virdomainsnapshotobj");

/* Run iter(data) on all direct children of moment, while ignoring all
 * other entries in moments.  Return the number of children
 * visited.  No particular ordering is guaranteed.  */
int
virDomainMomentForEachChild(virDomainMomentObjPtr moment,
                            virHashIterator iter,
                            void *data)
{
    virDomainMomentObjPtr child = moment->first_child;

    while (child) {
        virDomainMomentObjPtr next = child->sibling;
        (iter)(child, child->def->name, data);
        child = next;
    }

    return moment->nchildren;
}

struct moment_act_on_descendant {
    int number;
    virHashIterator iter;
    void *data;
};

static int
virDomainMomentActOnDescendant(void *payload,
                               const void *name,
                               void *data)
{
    virDomainMomentObjPtr obj = payload;
    struct moment_act_on_descendant *curr = data;

    (curr->iter)(payload, name, curr->data);
    curr->number += 1 + virDomainMomentForEachDescendant(obj,
                                                           curr->iter,
                                                           curr->data);
    return 0;
}

/* Run iter(data) on all descendants of moment, while ignoring all
 * other entries in moments.  Return the number of descendants
 * visited.  The visit is guaranteed to be topological, but no
 * particular order between siblings is guaranteed.  */
int
virDomainMomentForEachDescendant(virDomainMomentObjPtr moment,
                                 virHashIterator iter,
                                 void *data)
{
    struct moment_act_on_descendant act;

    act.number = 0;
    act.iter = iter;
    act.data = data;
    virDomainMomentForEachChild(moment,
                                virDomainMomentActOnDescendant, &act);

    return act.number;
}


/* Prepare to reparent or delete moment, by removing it from its
 * current listed parent.  Note that when bulk removing all children
 * of a parent, it is faster to just 0 the count rather than calling
 * this function on each child.  */
void
virDomainMomentDropParent(virDomainMomentObjPtr moment)
{
    virDomainMomentObjPtr prev = NULL;
    virDomainMomentObjPtr curr = NULL;

    moment->parent->nchildren--;
    curr = moment->parent->first_child;
    while (curr != moment) {
        if (!curr) {
            VIR_WARN("inconsistent snapshot relations");
            return;
        }
        prev = curr;
        curr = curr->sibling;
    }
    if (prev)
        prev->sibling = moment->sibling;
    else
        moment->parent->first_child = moment->sibling;
    moment->parent = NULL;
    moment->sibling = NULL;
}


/* Update @moment to no longer have children. */
void
virDomainMomentDropChildren(virDomainMomentObjPtr moment)
{
    moment->nchildren = 0;
    moment->first_child = NULL;
}


/* Add @moment to @parent's list of children. */
void
virDomainMomentSetParent(virDomainMomentObjPtr moment,
                         virDomainMomentObjPtr parent)
{
    moment->parent = parent;
    parent->nchildren++;
    moment->sibling = parent->first_child;
    parent->first_child = moment;
}


/* Take all children of @from and convert them into children of @to. */
void
virDomainMomentMoveChildren(virDomainMomentObjPtr from,
                            virDomainMomentObjPtr to)
{
    virDomainMomentObjPtr child;
    virDomainMomentObjPtr last;

    if (!from->first_child)
        return;
    for (child = from->first_child; child; child = child->sibling) {
        child->parent = to;
        if (!child->sibling)
            last = child;
    }
    to->nchildren += from->nchildren;
    last->sibling = to->first_child;
    to->first_child = from->first_child;
    from->nchildren = 0;
    from->first_child = NULL;
}
