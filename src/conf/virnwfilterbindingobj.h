/*
 * virnwfilterbindingobj.h: network filter binding object processing
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
 */

#pragma once

#include "internal.h"
#include "virnwfilterbindingdef.h"
#include "virobject.h"

typedef struct _virNWFilterBindingObj virNWFilterBindingObj;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNWFilterBindingObj, virObjectUnref);

virNWFilterBindingObj *
virNWFilterBindingObjNew(void);

virNWFilterBindingDef *
virNWFilterBindingObjGetDef(virNWFilterBindingObj *obj);

void
virNWFilterBindingObjSetDef(virNWFilterBindingObj *obj,
                            virNWFilterBindingDef *def);

virNWFilterBindingDef *
virNWFilterBindingObjStealDef(virNWFilterBindingObj *obj);

bool
virNWFilterBindingObjGetRemoving(virNWFilterBindingObj *obj);

void
virNWFilterBindingObjSetRemoving(virNWFilterBindingObj *obj,
                                 bool removing);

void
virNWFilterBindingObjEndAPI(virNWFilterBindingObj **obj);

char *
virNWFilterBindingObjConfigFile(const char *dir,
                                const char *name);

int
virNWFilterBindingObjSave(const virNWFilterBindingObj *obj,
                          const char *statusDir);

int
virNWFilterBindingObjDelete(const virNWFilterBindingObj *obj,
                            const char *statusDir);

virNWFilterBindingObj *
virNWFilterBindingObjParse(const char *filename);

char *
virNWFilterBindingObjFormat(const virNWFilterBindingObj *obj);
