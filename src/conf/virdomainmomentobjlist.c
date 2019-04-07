/*
 * virdomainmomentobjlist.c: handle snapshot/checkpoint objects
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
#include "virdomainmomentobjlist.h"
#include "virlog.h"
#include "virerror.h"
#include "virstring.h"
#include "moment_conf.h"

/* FIXME: using virObject would allow us to not need this */
#include "snapshot_conf.h"
#include "virdomainsnapshotobjlist.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.virdomainmomentobjlist");

/* Opaque struct */
struct _virDomainMomentObjList {
    /* name string -> virDomainMomentObj  mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objs;

    virDomainMomentObj metaroot; /* Special parent of all root moments */
    virDomainMomentObjPtr current; /* The current moment, if any */
};


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
            VIR_WARN("inconsistent moment relations");
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
    virDomainMomentObjPtr child = from->first_child;

    if (!from->nchildren)
        return;
    while (child) {
        child->parent = to;
        if (!child->sibling) {
            child->sibling = to->first_child;
            break;
        }
        child = child->sibling;
    }
    to->nchildren += from->nchildren;
    to->first_child = from->first_child;
    from->nchildren = 0;
    from->first_child = NULL;
}


static virDomainMomentObjPtr
virDomainMomentObjNew(void)
{
    virDomainMomentObjPtr moment;

    if (VIR_ALLOC(moment) < 0)
        return NULL;

    VIR_DEBUG("obj=%p", moment);

    return moment;
}


static void
virDomainMomentObjFree(virDomainMomentObjPtr moment)
{
    if (!moment)
        return;

    VIR_DEBUG("obj=%p", moment);

    /* FIXME: Make this polymorphic by inheriting from virObject */
    virDomainSnapshotDefFree(virDomainSnapshotObjGetDef(moment));
    VIR_FREE(moment);
}


/* Add def to the list and return a matching object, or NULL on error */
virDomainMomentObjPtr
virDomainMomentAssignDef(virDomainMomentObjListPtr moments,
                         virDomainMomentDefPtr def)
{
    virDomainMomentObjPtr moment;

    if (virHashLookup(moments->objs, def->name) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain moment %s already exists"),
                       def->name);
        return NULL;
    }

    if (!(moment = virDomainMomentObjNew()))
        return NULL;

    if (virHashAddEntry(moments->objs, def->name, moment) < 0) {
        VIR_FREE(moment);
        return NULL;
    }
    moment->def = def;

    return moment;
}


static void
virDomainMomentObjListDataFree(void *payload,
                               const void *name ATTRIBUTE_UNUSED)
{
    virDomainMomentObjPtr obj = payload;

    virDomainMomentObjFree(obj);
}


virDomainMomentObjListPtr
virDomainMomentObjListNew(void)
{
    virDomainMomentObjListPtr moments;

    if (VIR_ALLOC(moments) < 0)
        return NULL;
    moments->objs = virHashCreate(50, virDomainMomentObjListDataFree);
    if (!moments->objs) {
        VIR_FREE(moments);
        return NULL;
    }
    return moments;
}

void
virDomainMomentObjListFree(virDomainMomentObjListPtr moments)
{
    if (!moments)
        return;
    virHashFree(moments->objs);
    VIR_FREE(moments);
}


/* Struct and callback for collecting a list of names of moments that
 * meet a particular filter. */
struct virDomainMomentNameData {
    char **const names;
    int maxnames;
    unsigned int flags;
    int count;
    bool error;
    virDomainMomentObjListFilter filter;
    unsigned int filter_flags;
};


static int virDomainMomentObjListCopyNames(void *payload,
                                           const void *name ATTRIBUTE_UNUSED,
                                           void *opaque)
{
    virDomainMomentObjPtr obj = payload;
    struct virDomainMomentNameData *data = opaque;

    if (data->error)
        return 0;
    /* Caller already sanitized flags.  Filtering on DESCENDANTS was
     * done by choice of iteration in the caller.  */
    if ((data->flags & VIR_DOMAIN_MOMENT_LIST_LEAVES) && obj->nchildren)
        return 0;
    if ((data->flags & VIR_DOMAIN_MOMENT_LIST_NO_LEAVES) && !obj->nchildren)
        return 0;

    if (!data->filter(obj, data->filter_flags))
        return 0;

    if (data->names && data->count < data->maxnames &&
        VIR_STRDUP(data->names[data->count], obj->def->name) < 0) {
        data->error = true;
        return 0;
    }
    data->count++;
    return 0;
}


int
virDomainMomentObjListGetNames(virDomainMomentObjListPtr moments,
                               virDomainMomentObjPtr from,
                               char **const names,
                               int maxnames,
                               unsigned int flags,
                               virDomainMomentObjListFilter filter,
                               unsigned int filter_flags)
{
    struct virDomainMomentNameData data = { names, maxnames, flags, 0,
                                            false, filter, filter_flags };
    size_t i;

    virCheckFlags(VIR_DOMAIN_MOMENT_FILTERS_ALL, -1);
    if (!from) {
        /* LIST_ROOTS and LIST_DESCENDANTS have the same bit value,
         * but opposite semantics.  Toggle here to get the correct
         * traversal on the metaroot.  */
        flags ^= VIR_DOMAIN_MOMENT_LIST_ROOTS;
        from = &moments->metaroot;
    }

    /* We handle LIST_ROOT/LIST_DESCENDANTS and LIST_TOPOLOGICAL directly,
     * mask those bits out to determine when we must use the filter callback. */
    data.flags &= ~(VIR_DOMAIN_MOMENT_LIST_DESCENDANTS |
                    VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL);

    /* If this common code is being used, we assume that all moments
     * have metadata, and thus can handle METADATA up front as an
     * all-or-none filter.  XXX This might not always be true, if we
     * add the ability to track qcow2 internal snapshots without the
     * use of metadata, in which case this check should move into the
     * filter callback.  */
    if ((data.flags & VIR_DOMAIN_MOMENT_FILTERS_METADATA) ==
        VIR_DOMAIN_MOMENT_LIST_NO_METADATA)
        return 0;
    data.flags &= ~VIR_DOMAIN_MOMENT_FILTERS_METADATA;

    if (flags & VIR_DOMAIN_MOMENT_LIST_DESCENDANTS) {
        /* We could just always do a topological visit; but it is
         * possible to optimize for less stack usage and time when a
         * simpler full hashtable visit or counter will do. */
        if (from->def || (names &&
                          (flags & VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL)))
            virDomainMomentForEachDescendant(from,
                                             virDomainMomentObjListCopyNames,
                                             &data);
        else if (names || data.flags || filter_flags)
            virHashForEach(moments->objs, virDomainMomentObjListCopyNames,
                           &data);
        else
            data.count = virHashSize(moments->objs);
    } else if (names || data.flags || filter_flags) {
        virDomainMomentForEachChild(from,
                                    virDomainMomentObjListCopyNames, &data);
    } else {
        data.count = from->nchildren;
    }

    if (data.error) {
        for (i = 0; i < data.count; i++)
            VIR_FREE(names[i]);
        return -1;
    }

    return data.count;
}


virDomainMomentObjPtr
virDomainMomentFindByName(virDomainMomentObjListPtr moments,
                          const char *name)
{
    return name ? virHashLookup(moments->objs, name) : &moments->metaroot;
}


/* Return the current moment, or NULL */
virDomainMomentObjPtr
virDomainMomentGetCurrent(virDomainMomentObjListPtr moments)
{
    return moments->current;
}


/* Return the current moment's name, or NULL */
const char *
virDomainMomentGetCurrentName(virDomainMomentObjListPtr moments)
{
    if (moments->current)
        return moments->current->def->name;
    return NULL;
}


/* Update the current moment, using NULL if no current remains */
void
virDomainMomentSetCurrent(virDomainMomentObjListPtr moments,
                          virDomainMomentObjPtr moment)
{
    moments->current = moment;
}


/* Return the number of moments in the list */
int
virDomainMomentObjListSize(virDomainMomentObjListPtr moments)
{
    return virHashSize(moments->objs);
}


/* Remove moment from the list; return true if it was current */
bool
virDomainMomentObjListRemove(virDomainMomentObjListPtr moments,
                             virDomainMomentObjPtr moment)
{
    bool ret = moments->current == moment;

    virHashRemoveEntry(moments->objs, moment->def->name);
    if (ret)
        moments->current = NULL;
    return ret;
}


/* Remove all moments tracked in the list */
void
virDomainMomentObjListRemoveAll(virDomainMomentObjListPtr moments)
{
    virHashRemoveAll(moments->objs);
    virDomainMomentDropChildren(&moments->metaroot);
}


/* Call iter on each member of the list, in unspecified order */
int
virDomainMomentForEach(virDomainMomentObjListPtr moments,
                       virHashIterator iter,
                       void *data)
{
    return virHashForEach(moments->objs, iter, data);
}


/* Struct and callback function used as a hash table callback; each call
 * inspects the pre-existing moment->def->parent field, and adjusts
 * the moment->parent field as well as the parent's child fields to
 * wire up the hierarchical relations for the given moment.  The error
 * indicator gets set if a parent is missing or a requested parent would
 * cause a circular parent chain.  */
struct moment_set_relation {
    virDomainMomentObjListPtr moments;
    int err;
};
static int
virDomainMomentSetRelations(void *payload,
                            const void *name ATTRIBUTE_UNUSED,
                            void *data)
{
    virDomainMomentObjPtr obj = payload;
    struct moment_set_relation *curr = data;
    virDomainMomentObjPtr tmp;
    virDomainMomentObjPtr parent;

    parent = virDomainMomentFindByName(curr->moments, obj->def->parent);
    if (!parent) {
        curr->err = -1;
        parent = &curr->moments->metaroot;
        VIR_WARN("moment %s lacks parent", obj->def->name);
    } else {
        tmp = parent;
        while (tmp && tmp->def) {
            if (tmp == obj) {
                curr->err = -1;
                parent = &curr->moments->metaroot;
                VIR_WARN("moment %s in circular chain", obj->def->name);
                break;
            }
            tmp = tmp->parent;
        }
    }
    virDomainMomentSetParent(obj, parent);
    return 0;
}


/* Populate parent link and child count of all moments, with all
 * assigned defs having relations starting as 0/NULL. Return 0 on
 * success, -1 if a parent is missing or if a circular relationship
 * was requested. */
int
virDomainMomentUpdateRelations(virDomainMomentObjListPtr moments)
{
    struct moment_set_relation act = { moments, 0 };

    virDomainMomentDropChildren(&moments->metaroot);
    virHashForEach(moments->objs, virDomainMomentSetRelations, &act);
    if (act.err)
        moments->current = NULL;
    return act.err;
}
