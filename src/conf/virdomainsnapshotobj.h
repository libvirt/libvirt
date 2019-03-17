/*
 * virdomainsnapshotobj.h: handle snapshot objects
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

#ifndef LIBVIRT_VIRDOMAINSNAPSHOTOBJ_H
# define LIBVIRT_VIRDOMAINSNAPSHOTOBJ_H

# include "internal.h"
# include "virconftypes.h"
# include "virhash.h"

struct _virDomainSnapshotObj {
    virDomainSnapshotDefPtr def; /* non-NULL except for metaroot */

    virDomainSnapshotObjPtr parent; /* non-NULL except for metaroot, before
                                       virDomainSnapshotUpdateRelations, or
                                       after virDomainSnapshotDropParent */
    virDomainSnapshotObjPtr sibling; /* NULL if last child of parent */
    size_t nchildren;
    virDomainSnapshotObjPtr first_child; /* NULL if no children */
};


int virDomainSnapshotForEachChild(virDomainSnapshotObjPtr snapshot,
                                  virHashIterator iter,
                                  void *data);
int virDomainSnapshotForEachDescendant(virDomainSnapshotObjPtr snapshot,
                                       virHashIterator iter,
                                       void *data);
void virDomainSnapshotDropParent(virDomainSnapshotObjPtr snapshot);
void virDomainSnapshotDropChildren(virDomainSnapshotObjPtr snapshot);
void virDomainSnapshotMoveChildren(virDomainSnapshotObjPtr from,
                                   virDomainSnapshotObjPtr to);
void virDomainSnapshotSetParent(virDomainSnapshotObjPtr snapshot,
                                virDomainSnapshotObjPtr parent);

#endif /* LIBVIRT_VIRDOMAINSNAPSHOTOBJ_H */
