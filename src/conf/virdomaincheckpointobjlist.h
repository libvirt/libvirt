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

virDomainCheckpointObjList *
virDomainCheckpointObjListNew(void);

void
virDomainCheckpointObjListFree(virDomainCheckpointObjList *checkpoints);

virDomainMomentObj *
virDomainCheckpointAssignDef(virDomainCheckpointObjList *checkpoints,
                             virDomainCheckpointDef *def);

virDomainMomentObj *
virDomainCheckpointFindByName(virDomainCheckpointObjList *checkpoints,
                              const char *name);

virDomainMomentObj *
virDomainCheckpointGetCurrent(virDomainCheckpointObjList *checkpoints);

const char *
virDomainCheckpointGetCurrentName(virDomainCheckpointObjList *checkpoints);

void
virDomainCheckpointSetCurrent(virDomainCheckpointObjList *checkpoints,
                              virDomainMomentObj *checkpoint);

bool
virDomainCheckpointObjListRemove(virDomainCheckpointObjList *checkpoints,
                                 virDomainMomentObj *checkpoint);

void
virDomainCheckpointObjListRemoveAll(virDomainCheckpointObjList *checkpoints);

int
virDomainCheckpointForEach(virDomainCheckpointObjList *checkpoints,
                           virHashIterator iter,
                           void *data);

void
virDomainCheckpointLinkParent(virDomainCheckpointObjList *checkpoints,
                              virDomainMomentObj *chk);

int
virDomainCheckpointUpdateRelations(virDomainCheckpointObjList *checkpoints,
                                   virDomainMomentObj **leaf);

int
virDomainCheckpointCheckCycles(virDomainCheckpointObjList *checkpoints,
                               virDomainCheckpointDef *def,
                               const char *domname);

#define VIR_DOMAIN_CHECKPOINT_FILTERS_LEAVES \
               (VIR_DOMAIN_CHECKPOINT_LIST_LEAVES       | \
                VIR_DOMAIN_CHECKPOINT_LIST_NO_LEAVES)

#define VIR_DOMAIN_CHECKPOINT_FILTERS_ALL \
               (VIR_DOMAIN_CHECKPOINT_FILTERS_LEAVES)

int
virDomainListCheckpoints(virDomainCheckpointObjList *checkpoints,
                         virDomainMomentObj *from,
                         virDomainPtr dom,
                         virDomainCheckpointPtr **objs,
                         unsigned int flags);

static inline virDomainCheckpointDef *
virDomainCheckpointObjGetDef(virDomainMomentObj *obj)
{
    return (virDomainCheckpointDef *) obj->def;
}
