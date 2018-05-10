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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NWFILTER_BINDING_OBJ_LIST_H__
# define __VIR_NWFILTER_BINDING_OBJ_LIST_H__

# include "virnwfilterbindingobj.h"

typedef struct _virNWFilterBindingObjList virNWFilterBindingObjList;
typedef virNWFilterBindingObjList *virNWFilterBindingObjListPtr;

virNWFilterBindingObjListPtr
virNWFilterBindingObjListNew(void);

virNWFilterBindingObjPtr
virNWFilterBindingObjListFindByPortDev(virNWFilterBindingObjListPtr bindings,
                                       const char *name);

virNWFilterBindingObjPtr
virNWFilterBindingObjListAdd(virNWFilterBindingObjListPtr bindings,
                             virNWFilterBindingDefPtr def);

void
virNWFilterBindingObjListRemove(virNWFilterBindingObjListPtr bindings,
                                virNWFilterBindingObjPtr binding);

int
virNWFilterBindingObjListLoadAllConfigs(virNWFilterBindingObjListPtr bindings,
                                        const char *configDir);


typedef int (*virNWFilterBindingObjListIterator)(virNWFilterBindingObjPtr binding,
                                                 void *opaque);

int
virNWFilterBindingObjListForEach(virNWFilterBindingObjListPtr bindings,
                                 virNWFilterBindingObjListIterator callback,
                                 void *opaque);

typedef bool (*virNWFilterBindingObjListACLFilter)(virConnectPtr conn,
                                                   virNWFilterBindingDefPtr def);

int
virNWFilterBindingObjListExport(virNWFilterBindingObjListPtr bindings,
                                virConnectPtr conn,
                                virNWFilterBindingPtr **bindinglist,
                                virNWFilterBindingObjListACLFilter filter);


#endif /* __VIR_NWFILTER_BINDING_OBJ_LIST_H__ */
