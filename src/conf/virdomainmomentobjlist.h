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
typedef bool (*virDomainMomentObjListFilter)(virDomainMomentObjPtr obj,
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
    virDomainMomentDefPtr def; /* non-NULL except for metaroot */

    /* Private fields, use accessors instead */
    virDomainMomentObjPtr parent; /* non-NULL except for metaroot, before
                                     virDomainMomentUpdateRelations, or
                                     after virDomainMomentDropParent */
    virDomainMomentObjPtr sibling; /* NULL if last child of parent */
    size_t nchildren;
    virDomainMomentObjPtr first_child; /* NULL if no children */
};

int virDomainMomentForEachChild(virDomainMomentObjPtr moment,
                                virHashIterator iter,
                                void *data);
int virDomainMomentForEachDescendant(virDomainMomentObjPtr moment,
                                     virHashIterator iter,
                                     void *data);
void virDomainMomentDropParent(virDomainMomentObjPtr moment);
void virDomainMomentDropChildren(virDomainMomentObjPtr moment);
void virDomainMomentMoveChildren(virDomainMomentObjPtr from,
                                 virDomainMomentObjPtr to);
void virDomainMomentSetParent(virDomainMomentObjPtr moment,
                              virDomainMomentObjPtr parent);

virDomainMomentObjListPtr virDomainMomentObjListNew(void);
void virDomainMomentObjListFree(virDomainMomentObjListPtr moments);

virDomainMomentObjPtr virDomainMomentAssignDef(virDomainMomentObjListPtr moments,
                                               virDomainMomentDefPtr def);

/* Various enum bits that map to public API filters. Note that the
 * values of the internal bits are not necessarily the same as the
 * public ones. */
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

int virDomainMomentObjListGetNames(virDomainMomentObjListPtr moments,
                                   virDomainMomentObjPtr from,
                                   char **const names,
                                   int maxnames,
                                   unsigned int moment_flags,
                                   virDomainMomentObjListFilter filter,
                                   unsigned int filter_flags);
virDomainMomentObjPtr virDomainMomentFindByName(virDomainMomentObjListPtr moments,
                                                const char *name);
int virDomainMomentObjListSize(virDomainMomentObjListPtr moments);
virDomainMomentObjPtr virDomainMomentGetCurrent(virDomainMomentObjListPtr moments);
const char *virDomainMomentGetCurrentName(virDomainMomentObjListPtr moments);
void virDomainMomentSetCurrent(virDomainMomentObjListPtr moments,
                               virDomainMomentObjPtr moment);
bool virDomainMomentObjListRemove(virDomainMomentObjListPtr moments,
                                  virDomainMomentObjPtr moment);
void virDomainMomentObjListRemoveAll(virDomainMomentObjListPtr moments);
int virDomainMomentForEach(virDomainMomentObjListPtr moments,
                           virHashIterator iter,
                           void *data);
int virDomainMomentUpdateRelations(virDomainMomentObjListPtr moments);
int virDomainMomentCheckCycles(virDomainMomentObjListPtr list,
                               virDomainMomentDefPtr def,
                               const char *domname);
