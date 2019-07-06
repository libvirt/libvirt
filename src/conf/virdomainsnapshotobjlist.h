/*
 * virdomainsnapshotobjlist.h: handle a tree of snapshot objects
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
#include "virdomainmomentobjlist.h"
#include "virbuffer.h"

virDomainSnapshotObjListPtr virDomainSnapshotObjListNew(void);
void virDomainSnapshotObjListFree(virDomainSnapshotObjListPtr snapshots);

virDomainMomentObjPtr virDomainSnapshotAssignDef(virDomainSnapshotObjListPtr snapshots,
                                                 virDomainSnapshotDefPtr def);

int virDomainSnapshotObjListGetNames(virDomainSnapshotObjListPtr snapshots,
                                     virDomainMomentObjPtr from,
                                     char **const names, int maxnames,
                                     unsigned int flags);
int virDomainSnapshotObjListNum(virDomainSnapshotObjListPtr snapshots,
                                virDomainMomentObjPtr from,
                                unsigned int flags);
virDomainMomentObjPtr virDomainSnapshotFindByName(virDomainSnapshotObjListPtr snapshots,
                                                  const char *name);
virDomainMomentObjPtr virDomainSnapshotGetCurrent(virDomainSnapshotObjListPtr snapshots);
const char *virDomainSnapshotGetCurrentName(virDomainSnapshotObjListPtr snapshots);
void virDomainSnapshotSetCurrent(virDomainSnapshotObjListPtr snapshots,
                                 virDomainMomentObjPtr snapshot);
bool virDomainSnapshotObjListRemove(virDomainSnapshotObjListPtr snapshots,
                                    virDomainMomentObjPtr snapshot);
void virDomainSnapshotObjListRemoveAll(virDomainSnapshotObjListPtr snapshots);
int virDomainSnapshotForEach(virDomainSnapshotObjListPtr snapshots,
                             virHashIterator iter,
                             void *data);
int virDomainSnapshotUpdateRelations(virDomainSnapshotObjListPtr snapshots);
int virDomainSnapshotCheckCycles(virDomainSnapshotObjListPtr snapshots,
                                 virDomainSnapshotDefPtr def,
                                 const char *domname);

#define VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA \
               (VIR_DOMAIN_SNAPSHOT_LIST_METADATA     | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_METADATA)

#define VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES \
               (VIR_DOMAIN_SNAPSHOT_LIST_LEAVES       | \
                VIR_DOMAIN_SNAPSHOT_LIST_NO_LEAVES)

#define VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS \
               (VIR_DOMAIN_SNAPSHOT_LIST_INACTIVE     | \
                VIR_DOMAIN_SNAPSHOT_LIST_ACTIVE       | \
                VIR_DOMAIN_SNAPSHOT_LIST_DISK_ONLY)

#define VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION \
               (VIR_DOMAIN_SNAPSHOT_LIST_INTERNAL     | \
                VIR_DOMAIN_SNAPSHOT_LIST_EXTERNAL)

#define VIR_DOMAIN_SNAPSHOT_FILTERS_ALL \
               (VIR_DOMAIN_SNAPSHOT_FILTERS_METADATA  | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LEAVES    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_STATUS    | \
                VIR_DOMAIN_SNAPSHOT_FILTERS_LOCATION)

int virDomainListSnapshots(virDomainSnapshotObjListPtr snapshots,
                           virDomainMomentObjPtr from,
                           virDomainPtr dom,
                           virDomainSnapshotPtr **snaps,
                           unsigned int flags);

/* Access the snapshot-specific definition from a given list member. */
static inline virDomainSnapshotDefPtr
virDomainSnapshotObjGetDef(virDomainMomentObjPtr obj)
{
    return (virDomainSnapshotDefPtr) obj->def;
}
