/*
 * virnwfilterbindingobjlist.h: nwfilter binding object list utilities
 *
 * Copyright (C) 2018 Red Hat, Inc.
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

#include "virnwfilterbindingobj.h"

typedef struct _virNWFilterBindingObjList virNWFilterBindingObjList;

virNWFilterBindingObjList *
virNWFilterBindingObjListNew(void);

virNWFilterBindingObj *
virNWFilterBindingObjListFindByPortDev(virNWFilterBindingObjList *bindings,
                                       const char *name);

virNWFilterBindingObj *
virNWFilterBindingObjListAdd(virNWFilterBindingObjList *bindings,
                             virNWFilterBindingDef *def);

void
virNWFilterBindingObjListRemove(virNWFilterBindingObjList *bindings,
                                virNWFilterBindingObj *binding);

int
virNWFilterBindingObjListLoadAllConfigs(virNWFilterBindingObjList *bindings,
                                        const char *configDir);


typedef int (*virNWFilterBindingObjListIterator)(virNWFilterBindingObj *binding,
                                                 void *opaque);

int
virNWFilterBindingObjListForEach(virNWFilterBindingObjList *bindings,
                                 virNWFilterBindingObjListIterator callback,
                                 void *opaque);

typedef bool (*virNWFilterBindingObjListACLFilter)(virConnectPtr conn,
                                                   virNWFilterBindingDef *def);

int
virNWFilterBindingObjListExport(virNWFilterBindingObjList *bindings,
                                virConnectPtr conn,
                                virNWFilterBindingPtr **bindinglist,
                                virNWFilterBindingObjListACLFilter filter);
