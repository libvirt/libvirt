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

struct _virDomainMomentObj {
    virDomainMomentDefPtr def; /* non-NULL except for metaroot */

    virDomainMomentObjPtr parent; /* non-NULL except for metaroot, before
                                     virDomainSnapshotUpdateRelations, or
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

#endif /* LIBVIRT_VIRDOMAINSNAPSHOTOBJ_H */
