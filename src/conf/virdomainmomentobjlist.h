/*
 * virdomainmomentobjlist.h: handle a tree of moment objects
 *                  (derived from snapshot_conf.h)
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

#pragma once

#include "internal.h"
#include "virconftypes.h"
#include "virhash.h"

/* Filter that returns true if a given moment matches the filter flags */
typedef bool (*virDomainMomentObjListFilter)(virDomainMomentObj *obj,
                                             unsigned int flags);

/* Struct that allows tracing hierarchical relationships between
 * multiple virDomainMoment objects. The opaque type
 * virDomainMomentObjList then maintains both a hash of these structs
 * (for quick lookup by name) and a metaroot (which is the parent of
 * all user-visible roots), so that all other objects always have a
 * valid parent object; the tree structure is currently maintained via
 * a linked list. */
struct _virDomainMomentObj {
    /* Public field */
    virDomainMomentDef *def; /* non-NULL except for metaroot */

    /* Private fields, use accessors instead */
    virDomainMomentObj *parent; /* non-NULL except for metaroot, before
                                     virDomainMomentUpdateRelations, or
                                     after virDomainMomentDropParent */
    virDomainMomentObj *sibling; /* NULL if last child of parent */
    size_t nchildren;
    virDomainMomentObj *first_child; /* NULL if no children */
};

virDomainMomentObj *
virDomainMomentObjNew(void);

void
virDomainMomentObjFree(virDomainMomentObj *moment);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virDomainMomentObj, virDomainMomentObjFree);

int
virDomainMomentForEachChild(virDomainMomentObj *moment,
                            virHashIterator iter,
                            void *data);
int
virDomainMomentForEachDescendant(virDomainMomentObj *moment,
                                 virHashIterator iter,
                                 void *data);
void
virDomainMomentDropParent(virDomainMomentObj *moment);
void
virDomainMomentDropChildren(virDomainMomentObj *moment);
void
virDomainMomentMoveChildren(virDomainMomentObj *from,
                            virDomainMomentObj *to);
void
virDomainMomentLinkParent(virDomainMomentObjList *moments,
                          virDomainMomentObj *moment);

virDomainMomentObjList *
virDomainMomentObjListNew(void);
void
virDomainMomentObjListFree(virDomainMomentObjList *moments);

virDomainMomentObj *
virDomainMomentAssignDef(virDomainMomentObjList *moments,
                         virDomainMomentDef *def);

/* Various enum bits that map to public API filters. Note that the
 * values of the internal bits are not the same as the public ones for
 * snapshot, however, this list should be kept in sync with the public
 * ones for checkpoint. */
typedef enum {
    VIR_DOMAIN_MOMENT_LIST_ROOTS       = (1 << 0),
    VIR_DOMAIN_MOMENT_LIST_DESCENDANTS = (1 << 0),
    VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL = (1 << 1),
    VIR_DOMAIN_MOMENT_LIST_LEAVES      = (1 << 2),
    VIR_DOMAIN_MOMENT_LIST_NO_LEAVES   = (1 << 3),
    VIR_DOMAIN_MOMENT_LIST_METADATA    = (1 << 4),
    VIR_DOMAIN_MOMENT_LIST_NO_METADATA = (1 << 5),
} virDomainMomentFilters;

#define VIR_DOMAIN_MOMENT_FILTERS_METADATA \
               (VIR_DOMAIN_MOMENT_LIST_METADATA | \
                VIR_DOMAIN_MOMENT_LIST_NO_METADATA)

#define VIR_DOMAIN_MOMENT_FILTERS_LEAVES \
               (VIR_DOMAIN_MOMENT_LIST_LEAVES | \
                VIR_DOMAIN_MOMENT_LIST_NO_LEAVES)

#define VIR_DOMAIN_MOMENT_FILTERS_ALL \
               (VIR_DOMAIN_MOMENT_LIST_ROOTS | \
                VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL | \
                VIR_DOMAIN_MOMENT_FILTERS_METADATA | \
                VIR_DOMAIN_MOMENT_FILTERS_LEAVES)

int
virDomainMomentObjListGetNames(virDomainMomentObjList *moments,
                               virDomainMomentObj *from,
                               char **const names,
                               int maxnames,
                               unsigned int moment_flags,
                               virDomainMomentObjListFilter filter,
                               unsigned int filter_flags);
virDomainMomentObj *
virDomainMomentFindByName(virDomainMomentObjList *moments,
                          const char *name);
int
virDomainMomentObjListSize(virDomainMomentObjList *moments);

virDomainMomentObj *
virDomainMomentGetCurrent(virDomainMomentObjList *moments);
const char *
virDomainMomentGetCurrentName(virDomainMomentObjList *moments);
void
virDomainMomentSetCurrent(virDomainMomentObjList *moments,
                          virDomainMomentObj *moment);

bool
virDomainMomentObjListRemove(virDomainMomentObjList *moments,
                             virDomainMomentObj *moment);
void
virDomainMomentObjListRemoveAll(virDomainMomentObjList *moments);

int
virDomainMomentForEach(virDomainMomentObjList *moments,
                       virHashIterator iter,
                       void *data);

int
virDomainMomentUpdateRelations(virDomainMomentObjList *moments);

int
virDomainMomentCheckCycles(virDomainMomentObjList *list,
                           virDomainMomentDef *def,
                           const char *domname);

virDomainMomentObj *
virDomainMomentFindLeaf(virDomainMomentObjList *list);

bool
virDomainMomentIsAncestor(virDomainMomentObj *moment,
                          virDomainMomentObj *ancestor);
