/*
 * virdomaincheckpointobjlist.c: handle a tree of checkpoint objects
 *                  (derived from virdomainsnapshotobjlist.c)
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
#include "virdomaincheckpointobjlist.h"
#include "checkpoint_conf.h"
#include "virlog.h"
#include "virerror.h"
#include "datatypes.h"
#include "viralloc.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN_CHECKPOINT

VIR_LOG_INIT("conf.virdomaincheckpointobjlist");

struct _virDomainCheckpointObjList {
    virDomainMomentObjList *base;
};

virDomainMomentObj *
virDomainCheckpointAssignDef(virDomainCheckpointObjList *checkpoints,
                             virDomainCheckpointDef *def)
{
    return virDomainMomentAssignDef(checkpoints->base, &def->parent);
}


static bool
virDomainCheckpointFilter(virDomainMomentObj *obj G_GNUC_UNUSED,
                          unsigned int flags)
{
    /* For now, we have no further filters than what the common code handles. */
    virCheckFlags(0, false);
    return true;
}


virDomainCheckpointObjList *
virDomainCheckpointObjListNew(void)
{
    virDomainCheckpointObjList *checkpoints;

    checkpoints = g_new0(virDomainCheckpointObjList, 1);
    checkpoints->base = virDomainMomentObjListNew();
    if (!checkpoints->base) {
        VIR_FREE(checkpoints);
        return NULL;
    }
    return checkpoints;
}


void
virDomainCheckpointObjListFree(virDomainCheckpointObjList *checkpoints)
{
    if (!checkpoints)
        return;
    virDomainMomentObjListFree(checkpoints->base);
    g_free(checkpoints);
}


static int
virDomainCheckpointObjListGetNames(virDomainCheckpointObjList *checkpoints,
                                   virDomainMomentObj *from,
                                   char **const names,
                                   int maxnames,
                                   unsigned int flags)
{
    /* We intentionally chose our public flags to match the common flags */
    G_STATIC_ASSERT(VIR_DOMAIN_CHECKPOINT_LIST_ROOTS ==
           (int) VIR_DOMAIN_MOMENT_LIST_ROOTS);
    G_STATIC_ASSERT(VIR_DOMAIN_CHECKPOINT_LIST_TOPOLOGICAL ==
           (int) VIR_DOMAIN_MOMENT_LIST_TOPOLOGICAL);
    G_STATIC_ASSERT(VIR_DOMAIN_CHECKPOINT_LIST_LEAVES ==
           (int) VIR_DOMAIN_MOMENT_LIST_LEAVES);
    G_STATIC_ASSERT(VIR_DOMAIN_CHECKPOINT_LIST_NO_LEAVES ==
           (int) VIR_DOMAIN_MOMENT_LIST_NO_LEAVES);

    return virDomainMomentObjListGetNames(checkpoints->base, from, names,
                                          maxnames, flags,
                                          virDomainCheckpointFilter, 0);
}


virDomainMomentObj *
virDomainCheckpointFindByName(virDomainCheckpointObjList *checkpoints,
                              const char *name)
{
    return virDomainMomentFindByName(checkpoints->base, name);
}


/* Return the current checkpoint, or NULL */
virDomainMomentObj *
virDomainCheckpointGetCurrent(virDomainCheckpointObjList *checkpoints)
{
    return virDomainMomentGetCurrent(checkpoints->base);
}


/* Return the current checkpoint's name, or NULL */
const char *
virDomainCheckpointGetCurrentName(virDomainCheckpointObjList *checkpoints)
{
    return virDomainMomentGetCurrentName(checkpoints->base);
}


/* Update the current checkpoint, using NULL if no current remains */
void
virDomainCheckpointSetCurrent(virDomainCheckpointObjList *checkpoints,
                              virDomainMomentObj *checkpoint)
{
    virDomainMomentSetCurrent(checkpoints->base, checkpoint);
}


/* Remove checkpoint from the list; return true if it was current */
bool
virDomainCheckpointObjListRemove(virDomainCheckpointObjList *checkpoints,
                                 virDomainMomentObj *checkpoint)
{
    return virDomainMomentObjListRemove(checkpoints->base, checkpoint);
}


/* Remove all checkpoints tracked in the list */
void
virDomainCheckpointObjListRemoveAll(virDomainCheckpointObjList *checkpoints)
{
    return virDomainMomentObjListRemoveAll(checkpoints->base);
}


int
virDomainCheckpointForEach(virDomainCheckpointObjList *checkpoints,
                           virHashIterator iter,
                           void *data)
{
    return virDomainMomentForEach(checkpoints->base, iter, data);
}


/* Populate parent link of a given checkpoint. */
void
virDomainCheckpointLinkParent(virDomainCheckpointObjList *checkpoints,
                              virDomainMomentObj *chk)
{
    return virDomainMomentLinkParent(checkpoints->base, chk);
}


/* Populate parent link and child count of all checkpoints, with all
 * assigned defs having relations starting as 0/NULL. Return 0 on
 * success, -1 if a parent is missing or if a circular relationship
 * was requested. Set leaf to the end of the chain, if there is
 * exactly one such leaf. */
int
virDomainCheckpointUpdateRelations(virDomainCheckpointObjList *checkpoints,
                                   virDomainMomentObj **leaf)
{
    int ret = virDomainMomentUpdateRelations(checkpoints->base);

    if (ret == 0)
        *leaf = virDomainMomentFindLeaf(checkpoints->base);
    return ret;
}


int
virDomainCheckpointCheckCycles(virDomainCheckpointObjList *checkpoints,
                               virDomainCheckpointDef *def,
                               const char *domname)
{
    return virDomainMomentCheckCycles(checkpoints->base, &def->parent, domname);
}


int
virDomainListCheckpoints(virDomainCheckpointObjList *checkpoints,
                         virDomainMomentObj *from,
                         virDomainPtr dom,
                         virDomainCheckpointPtr **chks,
                         unsigned int flags)
{
    int count = virDomainCheckpointObjListGetNames(checkpoints, from, NULL,
                                                   0, flags);
    virDomainCheckpointPtr *list = NULL;
    char **names;
    int ret = -1;
    size_t i;

    if (!chks || count < 0)
        return count;

    names = g_new0(char *, count);
    list = g_new0(virDomainCheckpointPtr, count + 1);

    if (virDomainCheckpointObjListGetNames(checkpoints, from, names, count,
                                           flags) < 0)
        goto cleanup;
    for (i = 0; i < count; i++)
        if ((list[i] = virGetDomainCheckpoint(dom, names[i])) == NULL)
            goto cleanup;

    ret = count;
    *chks = list;

 cleanup:
    for (i = 0; i < count; i++)
        VIR_FREE(names[i]);
    VIR_FREE(names);
    if (ret < 0 && list) {
        for (i = 0; i < count; i++)
            virObjectUnref(list[i]);
        VIR_FREE(list);
    }
    return ret;
}
