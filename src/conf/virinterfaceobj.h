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

#pragma once

#include "internal.h"

typedef struct _virInterfaceObj virInterfaceObj;

typedef struct _virInterfaceObjList virInterfaceObjList;

void
virInterfaceObjEndAPI(virInterfaceObj **obj);

virInterfaceDef *
virInterfaceObjGetDef(virInterfaceObj *obj);

bool
virInterfaceObjIsActive(virInterfaceObj *obj);

void
virInterfaceObjSetActive(virInterfaceObj *obj,
                         bool active);

virInterfaceObjList *
virInterfaceObjListNew(void);

int
virInterfaceObjListFindByMACString(virInterfaceObjList *interfaces,
                                   const char *mac,
                                   char **const matches,
                                   int maxmatches);

virInterfaceObj *
virInterfaceObjListFindByName(virInterfaceObjList *interfaces,
                              const char *name);

void
virInterfaceObjFree(virInterfaceObj *obj);

virInterfaceObjList *
virInterfaceObjListClone(virInterfaceObjList *interfaces);

virInterfaceObj *
virInterfaceObjListAssignDef(virInterfaceObjList *interfaces,
                             virInterfaceDef **def);

void
virInterfaceObjListRemove(virInterfaceObjList *interfaces,
                          virInterfaceObj *obj);

typedef bool
(*virInterfaceObjListFilter)(virConnectPtr conn,
                             virInterfaceDef *def);

int
virInterfaceObjListNumOfInterfaces(virInterfaceObjList *interfaces,
                                   bool wantActive);

int
virInterfaceObjListGetNames(virInterfaceObjList *interfaces,
                            bool wantActive,
                            char **const names,
                            int maxnames);

int
virInterfaceObjListExport(virConnectPtr conn,
                          virInterfaceObjList *ifaceobjs,
                          virInterfacePtr **ifaces,
                          virInterfaceObjListFilter filter,
                          unsigned int flags);
