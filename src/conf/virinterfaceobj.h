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

#ifndef LIBVIRT_VIRINTERFACEOBJ_H
# define LIBVIRT_VIRINTERFACEOBJ_H

# include "internal.h"

typedef struct _virInterfaceObj virInterfaceObj;
typedef virInterfaceObj *virInterfaceObjPtr;

typedef struct _virInterfaceObjList virInterfaceObjList;
typedef virInterfaceObjList *virInterfaceObjListPtr;

void
virInterfaceObjEndAPI(virInterfaceObjPtr *obj);

virInterfaceDefPtr
virInterfaceObjGetDef(virInterfaceObjPtr obj);

bool
virInterfaceObjIsActive(virInterfaceObjPtr obj);

void
virInterfaceObjSetActive(virInterfaceObjPtr obj,
                         bool active);

virInterfaceObjListPtr
virInterfaceObjListNew(void);

int
virInterfaceObjListFindByMACString(virInterfaceObjListPtr interfaces,
                                   const char *mac,
                                   char **const matches,
                                   int maxmatches);

virInterfaceObjPtr
virInterfaceObjListFindByName(virInterfaceObjListPtr interfaces,
                              const char *name);

void
virInterfaceObjFree(virInterfaceObjPtr obj);

virInterfaceObjListPtr
virInterfaceObjListClone(virInterfaceObjListPtr interfaces);

virInterfaceObjPtr
virInterfaceObjListAssignDef(virInterfaceObjListPtr interfaces,
                             virInterfaceDefPtr def);

void
virInterfaceObjListRemove(virInterfaceObjListPtr interfaces,
                          virInterfaceObjPtr obj);

typedef bool
(*virInterfaceObjListFilter)(virConnectPtr conn,
                             virInterfaceDefPtr def);

int
virInterfaceObjListNumOfInterfaces(virInterfaceObjListPtr interfaces,
                                   bool wantActive);

int
virInterfaceObjListGetNames(virInterfaceObjListPtr interfaces,
                            bool wantActive,
                            char **const names,
                            int maxnames);

int
virInterfaceObjListExport(virConnectPtr conn,
                          virInterfaceObjListPtr ifaceobjs,
                          virInterfacePtr **ifaces,
                          virInterfaceObjListFilter filter,
                          unsigned int flags);

#endif /* LIBVIRT_VIRINTERFACEOBJ_H */
