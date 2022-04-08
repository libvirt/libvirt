/*
 * virnwfilterobj.h: network filter object processing
 *                  (derived from nwfilter_conf.h)
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

#include "nwfilter_conf.h"
#include "virnwfilterbindingobjlist.h"

typedef struct _virNWFilterObj virNWFilterObj;

typedef struct _virNWFilterObjList virNWFilterObjList;

typedef struct _virNWFilterDriverState virNWFilterDriverState;
struct _virNWFilterDriverState {
    bool privileged;

    /* pid file FD, ensures two copies of the driver can't use the same root */
    int lockFD;

    virNWFilterObjList *nwfilters;

    virNWFilterBindingObjList *bindings;

    char *stateDir;
    char *configDir;
    char *bindingDir;

    /* Recursive. Hold for filter changes, instantiation or deletion */
    virMutex updateLock;
    bool updateLockInitialized;
};

virNWFilterDef *
virNWFilterObjGetDef(virNWFilterObj *obj);

virNWFilterDef *
virNWFilterObjGetNewDef(virNWFilterObj *obj);

bool
virNWFilterObjWantRemoved(virNWFilterObj *obj);

virNWFilterObjList *
virNWFilterObjListNew(void);

void
virNWFilterObjListFree(virNWFilterObjList *nwfilters);

void
virNWFilterObjListRemove(virNWFilterObjList *nwfilters,
                         virNWFilterObj *obj);

virNWFilterObj *
virNWFilterObjListFindByUUID(virNWFilterObjList *nwfilters,
                             const unsigned char *uuid);

virNWFilterObj *
virNWFilterObjListFindByName(virNWFilterObjList *nwfilters,
                             const char *name);

virNWFilterObj *
virNWFilterObjListFindInstantiateFilter(virNWFilterObjList *nwfilters,
                                        const char *filtername);

virNWFilterObj *
virNWFilterObjListAssignDef(virNWFilterObjList *nwfilters,
                            virNWFilterDef *def);

int
virNWFilterObjTestUnassignDef(virNWFilterObj *obj);

typedef bool
(*virNWFilterObjListFilter)(virConnectPtr conn,
                            virNWFilterDef *def);

int
virNWFilterObjListNumOfNWFilters(virNWFilterObjList *nwfilters,
                                 virConnectPtr conn,
                                 virNWFilterObjListFilter filter);

int
virNWFilterObjListGetNames(virNWFilterObjList *nwfilters,
                           virConnectPtr conn,
                           virNWFilterObjListFilter filter,
                           char **const names,
                           int maxnames);

int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjList *nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter filter);

int
virNWFilterObjListLoadAllConfigs(virNWFilterObjList *nwfilters,
                                 const char *configDir);

void
virNWFilterObjLock(virNWFilterObj *obj);

void
virNWFilterObjUnlock(virNWFilterObj *obj);
