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

#ifndef LIBVIRT_VIRNWFILTEROBJ_H
# define LIBVIRT_VIRNWFILTEROBJ_H

# include "internal.h"

# include "nwfilter_conf.h"
# include "virnwfilterbindingobjlist.h"

typedef struct _virNWFilterObj virNWFilterObj;
typedef virNWFilterObj *virNWFilterObjPtr;

typedef struct _virNWFilterObjList virNWFilterObjList;
typedef virNWFilterObjList *virNWFilterObjListPtr;

typedef struct _virNWFilterDriverState virNWFilterDriverState;
typedef virNWFilterDriverState *virNWFilterDriverStatePtr;
struct _virNWFilterDriverState {
    virMutex lock;
    bool privileged;

    virNWFilterObjListPtr nwfilters;

    virNWFilterBindingObjListPtr bindings;

    char *configDir;
    char *bindingDir;
};

virNWFilterDefPtr
virNWFilterObjGetDef(virNWFilterObjPtr obj);

virNWFilterDefPtr
virNWFilterObjGetNewDef(virNWFilterObjPtr obj);

bool
virNWFilterObjWantRemoved(virNWFilterObjPtr obj);

virNWFilterObjListPtr
virNWFilterObjListNew(void);

void
virNWFilterObjListFree(virNWFilterObjListPtr nwfilters);

void
virNWFilterObjListRemove(virNWFilterObjListPtr nwfilters,
                         virNWFilterObjPtr obj);

virNWFilterObjPtr
virNWFilterObjListFindByUUID(virNWFilterObjListPtr nwfilters,
                             const unsigned char *uuid);

virNWFilterObjPtr
virNWFilterObjListFindByName(virNWFilterObjListPtr nwfilters,
                             const char *name);

virNWFilterObjPtr
virNWFilterObjListFindInstantiateFilter(virNWFilterObjListPtr nwfilters,
                                        const char *filtername);

virNWFilterObjPtr
virNWFilterObjListAssignDef(virNWFilterObjListPtr nwfilters,
                            virNWFilterDefPtr def);

int
virNWFilterObjTestUnassignDef(virNWFilterObjPtr obj);

typedef bool
(*virNWFilterObjListFilter)(virConnectPtr conn,
                            virNWFilterDefPtr def);

int
virNWFilterObjListNumOfNWFilters(virNWFilterObjListPtr nwfilters,
                                 virConnectPtr conn,
                                 virNWFilterObjListFilter filter);

int
virNWFilterObjListGetNames(virNWFilterObjListPtr nwfilters,
                           virConnectPtr conn,
                           virNWFilterObjListFilter filter,
                           char **const names,
                           int maxnames);

int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjListPtr nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter filter);

int
virNWFilterObjListLoadAllConfigs(virNWFilterObjListPtr nwfilters,
                                 const char *configDir);

void
virNWFilterObjLock(virNWFilterObjPtr obj);

void
virNWFilterObjUnlock(virNWFilterObjPtr obj);

#endif /* LIBVIRT_VIRNWFILTEROBJ_H */
