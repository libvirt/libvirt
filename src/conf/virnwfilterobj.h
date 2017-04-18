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
#ifndef VIRNWFILTEROBJ_H
# define VIRNWFILTEROBJ_H

# include "internal.h"

# include "nwfilter_conf.h"

typedef struct _virNWFilterObj virNWFilterObj;
typedef virNWFilterObj *virNWFilterObjPtr;

typedef struct _virNWFilterObjList virNWFilterObjList;
typedef virNWFilterObjList *virNWFilterObjListPtr;
struct _virNWFilterObjList {
    size_t count;
    virNWFilterObjPtr *objs;
};


typedef struct _virNWFilterDriverState virNWFilterDriverState;
typedef virNWFilterDriverState *virNWFilterDriverStatePtr;
struct _virNWFilterDriverState {
    virMutex lock;
    bool privileged;

    virNWFilterObjList nwfilters;

    char *configDir;
    bool watchingFirewallD;
};

virNWFilterDefPtr
virNWFilterObjGetDef(virNWFilterObjPtr obj);

virNWFilterDefPtr
virNWFilterObjGetNewDef(virNWFilterObjPtr obj);

bool
virNWFilterObjWantRemoved(virNWFilterObjPtr obj);

void
virNWFilterObjListFree(virNWFilterObjListPtr nwfilters);

void
virNWFilterObjRemove(virNWFilterObjListPtr nwfilters,
                     virNWFilterObjPtr obj);

virNWFilterObjPtr
virNWFilterObjFindByUUID(virNWFilterObjListPtr nwfilters,
                         const unsigned char *uuid);

virNWFilterObjPtr
virNWFilterObjFindByName(virNWFilterObjListPtr nwfilters,
                         const char *name);

virNWFilterObjPtr
virNWFilterObjAssignDef(virNWFilterObjListPtr nwfilters,
                        virNWFilterDefPtr def);

int
virNWFilterObjTestUnassignDef(virNWFilterObjPtr obj);

typedef bool
(*virNWFilterObjListFilter)(virConnectPtr conn,
                            virNWFilterDefPtr def);

int
virNWFilterObjNumOfNWFilters(virNWFilterObjListPtr nwfilters,
                             virConnectPtr conn,
                             virNWFilterObjListFilter aclfilter);

int
virNWFilterObjGetNames(virNWFilterObjListPtr nwfilters,
                       virConnectPtr conn,
                       virNWFilterObjListFilter aclfilter,
                       char **const names,
                       int maxnames);

int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjListPtr nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter aclfilter);

int
virNWFilterObjLoadAllConfigs(virNWFilterObjListPtr nwfilters,
                             const char *configDir);

void
virNWFilterObjLock(virNWFilterObjPtr obj);

void
virNWFilterObjUnlock(virNWFilterObjPtr obj);

#endif /* VIRNWFILTEROBJ_H */
