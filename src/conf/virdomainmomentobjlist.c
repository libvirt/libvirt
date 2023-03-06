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
#include "moment_conf.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.virdomainmomentobjlist");

/* Opaque struct */
struct _virDomainMomentObjList {
    /* name string -> virDomainMomentObj  mapping
     * for O(1), lockless lookup-by-name */
    GHashTable *objs;

    virDomainMomentObj metaroot; /* Special parent of all root moments */
    virDomainMomentObj *current; /* The current moment, if any */
};


/* Run iter(data) on all direct children of moment, while ignoring all
 * other entries in moments.  Return the number of children
 * visited.  No particular ordering is guaranteed.  */
int
virDomainMomentForEachChild(virDomainMomentObj *moment,
                            virHashIterator iter,
                            void *data)
{
    virDomainMomentObj *child = moment->first_child;

    while (child) {
        virDomainMomentObj *next = child->sibling;
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
                               const char *name,
                               void *data)
{
    virDomainMomentObj *obj = payload;
    struct moment_act_on_descendant *curr = data;
    virDomainMomentObj tmp = *obj;

    /* Careful: curr->iter can delete obj, hence the need for tmp */
    (curr->iter)(payload, name, curr->data);
    curr->number += 1 + virDomainMomentForEachDescendant(&tmp,
                                                         curr->iter,
                                                         curr->data);
    return 0;
}

/* Run iter(data) on all descendants of moment, while ignoring all
 * other entries in moments.  Return the number of descendants
 * visited.  The visit is guaranteed to be topological, but no
 * particular order between siblings is guaranteed.  */
int
virDomainMomentForEachDescendant(virDomainMomentObj *moment,
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
virDomainMomentDropParent(virDomainMomentObj *moment)
{
    virDomainMomentObj *prev = NULL;
    virDomainMomentObj *curr = NULL;

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
        prev->sibling = g_steal_pointer(&moment->sibling);
    else
        moment->parent->first_child = g_steal_pointer(&moment->sibling);
    moment->parent = NULL;
}


/* Update @moment to no longer have children. */
void
virDomainMomentDropChildren(virDomainMomentObj *moment)
{
    moment->nchildren = 0;
    moment->first_child = NULL;
}


/* Add @moment to @parent's list of children. */
static void
virDomainMomentSetParent(virDomainMomentObj *moment,
                         virDomainMomentObj *parent)
{
    moment->parent = parent;
    parent->nchildren++;
    moment->sibling = parent->first_child;
    parent->first_child = moment;
}


/* Add @moment to the appropriate parent's list of children. The
 * caller must ensure that moment->def->parent_name is either NULL
 * (for a new root) or set to an existing moment already in the
 * list. */
void
virDomainMomentLinkParent(virDomainMomentObjList *moments,
                          virDomainMomentObj *moment)
{
    virDomainMomentObj *parent;

    parent = virDomainMomentFindByName(moments, moment->def->parent_name);
    if (!parent) {
        parent = &moments->metaroot;
        if (moment->def->parent_name)
            VIR_WARN("moment %s lacks parent %s", moment->def->name,
                     moment->def->parent_name);
    }
    virDomainMomentSetParent(moment, parent);
}


/* Take all children of @from and convert them into children of @to. */
void
virDomainMomentMoveChildren(virDomainMomentObj *from,
                            virDomainMomentObj *to)
{
    virDomainMomentObj *child = from->first_child;

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
    to->first_child = g_steal_pointer(&from->first_child);
    from->nchildren = 0;
}


virDomainMomentObj *
virDomainMomentObjNew(void)
{
    virDomainMomentObj *moment;

    moment = g_new0(virDomainMomentObj, 1);

    VIR_DEBUG("obj=%p", moment);

    return moment;
}


void
virDomainMomentObjFree(virDomainMomentObj *moment)
{
    if (!moment)
        return;

    VIR_DEBUG("obj=%p", moment);

    virObjectUnref(moment->def);
    g_free(moment);
}


/* Add def to the list and return a matching object, or NULL on error */
virDomainMomentObj *
virDomainMomentAssignDef(virDomainMomentObjList *moments,
                         virDomainMomentDef *def)
{
    virDomainMomentObj *moment;

    if (virHashLookup(moments->objs, def->name) != NULL) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("domain moment %1$s already exists"),
                       def->name);
        return NULL;
    }

    moment = virDomainMomentObjNew();
    moment->def = def;
    g_hash_table_insert(moments->objs, g_strdup(def->name), moment);

    return moment;
}


static void
virDomainMomentObjListDataFree(void *payload)
{
    virDomainMomentObj *obj = payload;

    virDomainMomentObjFree(obj);
}


virDomainMomentObjList *
virDomainMomentObjListNew(void)
{
    virDomainMomentObjList *moments;

    moments = g_new0(virDomainMomentObjList, 1);
    moments->objs = virHashNew(virDomainMomentObjListDataFree);
    return moments;
}

void
virDomainMomentObjListFree(virDomainMomentObjList *moments)
{
    if (!moments)
        return;
    g_clear_pointer(&moments->objs, g_hash_table_unref);
    g_free(moments);
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
                                           const char *name G_GNUC_UNUSED,
                                           void *opaque)
{
    virDomainMomentObj *obj = payload;
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

    if (data->names && data->count < data->maxnames)
        data->names[data->count] = g_strdup(obj->def->name);
    data->count++;
    return 0;
}


int
virDomainMomentObjListGetNames(virDomainMomentObjList *moments,
                               virDomainMomentObj *from,
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


virDomainMomentObj *
virDomainMomentFindByName(virDomainMomentObjList *moments,
                          const char *name)
{
    if (name)
        return virHashLookup(moments->objs, name);
    return NULL;
}


/* Return the current moment, or NULL */
virDomainMomentObj *
virDomainMomentGetCurrent(virDomainMomentObjList *moments)
{
    return moments->current;
}


/* Return the current moment's name, or NULL */
const char *
virDomainMomentGetCurrentName(virDomainMomentObjList *moments)
{
    if (moments->current)
        return moments->current->def->name;
    return NULL;
}


/* Update the current moment, using NULL if no current remains */
void
virDomainMomentSetCurrent(virDomainMomentObjList *moments,
                          virDomainMomentObj *moment)
{
    moments->current = moment;
}


/* Return the number of moments in the list */
int
virDomainMomentObjListSize(virDomainMomentObjList *moments)
{
    return virHashSize(moments->objs);
}


/* Remove moment from the list; return true if it was current */
bool
virDomainMomentObjListRemove(virDomainMomentObjList *moments,
                             virDomainMomentObj *moment)
{
    bool ret = moments->current == moment;

    virHashRemoveEntry(moments->objs, moment->def->name);
    if (ret)
        moments->current = NULL;
    return ret;
}


/* Remove all moments tracked in the list */
void
virDomainMomentObjListRemoveAll(virDomainMomentObjList *moments)
{
    virHashRemoveAll(moments->objs);
    virDomainMomentDropChildren(&moments->metaroot);
}


/* Call iter on each member of the list, in unspecified order */
int
virDomainMomentForEach(virDomainMomentObjList *moments,
                       virHashIterator iter,
                       void *data)
{
    return virHashForEachSafe(moments->objs, iter, data);
}


/* Struct and callback function used as a hash table callback; each call
 * inspects the pre-existing moment->def->parent_name field, and adjusts
 * the moment->parent field as well as the parent's child fields to
 * wire up the hierarchical relations for the given moment.  The error
 * indicator gets set if a parent is missing or a requested parent would
 * cause a circular parent chain.  */
struct moment_set_relation {
    virDomainMomentObjList *moments;
    int err;
};
static int
virDomainMomentSetRelations(void *payload,
                            const char *name G_GNUC_UNUSED,
                            void *data)
{
    virDomainMomentObj *obj = payload;
    struct moment_set_relation *curr = data;
    virDomainMomentObj *tmp;
    virDomainMomentObj *parent;

    parent = virDomainMomentFindByName(curr->moments, obj->def->parent_name);
    if (!parent) {
        parent = &curr->moments->metaroot;
        if (obj->def->parent_name) {
            curr->err = -1;
            VIR_WARN("moment %s lacks parent %s", obj->def->name,
                     obj->def->parent_name);
        }
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
virDomainMomentUpdateRelations(virDomainMomentObjList *moments)
{
    struct moment_set_relation act = { moments, 0 };

    virDomainMomentDropChildren(&moments->metaroot);
    virHashForEach(moments->objs, virDomainMomentSetRelations, &act);
    if (act.err)
        moments->current = NULL;
    return act.err;
}


/* Check that inserting def into list would not create any impossible
 * parent-child relationships (cycles or missing parents).  Return 0
 * on success, or report an error on behalf of domname before
 * returning -1. */
int
virDomainMomentCheckCycles(virDomainMomentObjList *list,
                           virDomainMomentDef *def,
                           const char *domname)
{
    virDomainMomentObj *other;

    if (def->parent_name) {
        if (STREQ(def->name, def->parent_name)) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("cannot set moment %1$s as its own parent"),
                           def->name);
            return -1;
        }
        other = virDomainMomentFindByName(list, def->parent_name);
        if (!other) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("parent %1$s for moment %2$s not found"),
                           def->parent_name, def->name);
            return -1;
        }
        while (other->def->parent_name) {
            if (STREQ(other->def->parent_name, def->name)) {
                virReportError(VIR_ERR_INVALID_ARG,
                               _("parent %1$s would create cycle to %2$s"),
                               other->def->name, def->name);
                return -1;
            }
            other = virDomainMomentFindByName(list, other->def->parent_name);
            if (!other) {
                VIR_WARN("moments are inconsistent for domain %s",
                         domname);
                break;
            }
        }
    }
    return 0;
}

/* If there is exactly one leaf node, return that node. */
virDomainMomentObj *
virDomainMomentFindLeaf(virDomainMomentObjList *list)
{
    virDomainMomentObj *moment = &list->metaroot;

    if (moment->nchildren != 1)
        return NULL;
    while (moment->nchildren == 1)
        moment = moment->first_child;
    if (moment->nchildren == 0)
        return moment;
    return NULL;
}


/* Check if @moment is descendant of @ancestor. */
bool
virDomainMomentIsAncestor(virDomainMomentObj *moment,
                          virDomainMomentObj *ancestor)
{
    if (moment == ancestor)
        return false;

    for (moment = moment->parent; moment; moment = moment->parent) {
        if (moment == ancestor)
            return true;
    }

    return false;
}
