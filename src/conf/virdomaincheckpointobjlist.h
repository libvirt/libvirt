/*
 * virdomaincheckpointobjlist.h: handle a tree of checkpoint objects
 *                  (derived from virdomainsnapshotobjlist.h)
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

virDomainCheckpointObjListPtr
virDomainCheckpointObjListNew(void);

void
virDomainCheckpointObjListFree(virDomainCheckpointObjListPtr checkpoints);

virDomainMomentObjPtr
virDomainCheckpointAssignDef(virDomainCheckpointObjListPtr checkpoints,
                             virDomainCheckpointDefPtr def);

virDomainMomentObjPtr
virDomainCheckpointFindByName(virDomainCheckpointObjListPtr checkpoints,
                              const char *name);

virDomainMomentObjPtr
virDomainCheckpointGetCurrent(virDomainCheckpointObjListPtr checkpoints);

const char *
virDomainCheckpointGetCurrentName(virDomainCheckpointObjListPtr checkpoints);

void
virDomainCheckpointSetCurrent(virDomainCheckpointObjListPtr checkpoints,
                              virDomainMomentObjPtr checkpoint);

bool
virDomainCheckpointObjListRemove(virDomainCheckpointObjListPtr checkpoints,
                                 virDomainMomentObjPtr checkpoint);

void
virDomainCheckpointObjListRemoveAll(virDomainCheckpointObjListPtr checkpoints);

int
virDomainCheckpointForEach(virDomainCheckpointObjListPtr checkpoints,
                           virHashIterator iter,
                           void *data);

void
virDomainCheckpointLinkParent(virDomainCheckpointObjListPtr checkpoints,
                              virDomainMomentObjPtr chk);

int
virDomainCheckpointUpdateRelations(virDomainCheckpointObjListPtr checkpoints,
                                   virDomainMomentObjPtr *leaf);

int
virDomainCheckpointCheckCycles(virDomainCheckpointObjListPtr checkpoints,
                               virDomainCheckpointDefPtr def,
                               const char *domname);

#define VIR_DOMAIN_CHECKPOINT_FILTERS_LEAVES \
               (VIR_DOMAIN_CHECKPOINT_LIST_LEAVES       | \
                VIR_DOMAIN_CHECKPOINT_LIST_NO_LEAVES)

#define VIR_DOMAIN_CHECKPOINT_FILTERS_ALL \
               (VIR_DOMAIN_CHECKPOINT_FILTERS_LEAVES)

int
virDomainListCheckpoints(virDomainCheckpointObjListPtr checkpoints,
                         virDomainMomentObjPtr from,
                         virDomainPtr dom,
                         virDomainCheckpointPtr **objs,
                         unsigned int flags);

static inline virDomainCheckpointDefPtr
virDomainCheckpointObjGetDef(virDomainMomentObjPtr obj)
{
    return (virDomainCheckpointDefPtr) obj->def;
}
