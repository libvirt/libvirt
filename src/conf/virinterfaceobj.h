/*
 * virinterfaceobj.h: interface object handling entry points
 *                    (derived from interface_conf.h)
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

#ifndef __VIRINTERFACEOBJ_H__
# define __VIRINTERFACEOBJ_H__

# include "internal.h"

typedef struct _virInterfaceObj virInterfaceObj;
typedef virInterfaceObj *virInterfaceObjPtr;
struct _virInterfaceObj {
    virMutex lock;

    bool active;           /* true if interface is active (up) */
    virInterfaceDefPtr def; /* The interface definition */
};

typedef struct _virInterfaceObjList virInterfaceObjList;
typedef virInterfaceObjList *virInterfaceObjListPtr;
struct _virInterfaceObjList {
    size_t count;
    virInterfaceObjPtr *objs;
};

static inline bool
virInterfaceObjIsActive(const virInterfaceObj *iface)
{
    return iface->active;
}

int
virInterfaceObjFindByMACString(virInterfaceObjListPtr interfaces,
                               const char *mac,
                               virInterfaceObjPtr *matches, int maxmatches);

virInterfaceObjPtr
virInterfaceObjFindByName(virInterfaceObjListPtr interfaces,
                          const char *name);

void
virInterfaceObjFree(virInterfaceObjPtr iface);

void
virInterfaceObjListFree(virInterfaceObjListPtr vms);

int
virInterfaceObjListClone(virInterfaceObjListPtr src,
                         virInterfaceObjListPtr dest);

virInterfaceObjPtr
virInterfaceObjAssignDef(virInterfaceObjListPtr interfaces,
                         virInterfaceDefPtr def);

void
virInterfaceObjRemove(virInterfaceObjListPtr interfaces,
                      virInterfaceObjPtr iface);

void
virInterfaceObjLock(virInterfaceObjPtr obj);

void
virInterfaceObjUnlock(virInterfaceObjPtr obj);

typedef bool
(*virInterfaceObjListFilter)(virConnectPtr conn,
                             virInterfaceDefPtr def);

int
virInterfaceObjNumOfInterfaces(virInterfaceObjListPtr interfaces,
                               bool wantActive);

int
virInterfaceObjGetNames(virInterfaceObjListPtr interfaces,
                        bool wantActive,
                        char **const names,
                        int maxnames);

#endif /* __VIRINTERFACEOBJ_H__ */
