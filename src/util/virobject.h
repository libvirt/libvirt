/*
 * virobject.h: libvirt reference counted object
 *
 * Copyright (C) 2012-2014 Red Hat, Inc.
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
#include "virthread.h"

#include <glib-object.h>

typedef struct _virClass virClass;
typedef virClass *virClassPtr;

typedef struct _virObject virObject;
typedef virObject *virObjectPtr;

typedef struct _virObjectLockable virObjectLockable;
typedef virObjectLockable *virObjectLockablePtr;

typedef struct _virObjectRWLockable virObjectRWLockable;
typedef virObjectRWLockable *virObjectRWLockablePtr;

typedef void (*virObjectDisposeCallback)(void *obj);

#define VIR_TYPE_OBJECT vir_object_get_type()
G_DECLARE_DERIVABLE_TYPE(virObject, vir_object, VIR, OBJECT, GObject);

struct _virObjectClass {
    GObjectClass parent;
};

struct _virObjectLockable {
    virObject parent;
    virMutex lock;
};

struct _virObjectRWLockable {
    virObject parent;
    virRWLock lock;
};

virClassPtr virClassForObject(void);
virClassPtr virClassForObjectLockable(void);
virClassPtr virClassForObjectRWLockable(void);

#ifndef VIR_PARENT_REQUIRED
# define VIR_PARENT_REQUIRED ATTRIBUTE_NONNULL(1)
#endif

/* Assign the class description nameClass to represent struct @name
 * (which must have an object-based 'parent' member at offset 0), and
 * with parent class @prnt. nameDispose must exist as either a
 * function or as a macro defined to NULL.
 */
#define VIR_CLASS_NEW(name, prnt) \
    (G_STATIC_ASSERT_EXPR(offsetof(name, parent) == 0), \
     (name##Class = virClassNew(prnt, #name, sizeof(name),\
                                sizeof(((name *)NULL)->parent), \
                                name##Dispose)))

virClassPtr
virClassNew(virClassPtr parent,
            const char *name,
            size_t objectSize,
            size_t parentSize,
            virObjectDisposeCallback dispose)
    VIR_PARENT_REQUIRED ATTRIBUTE_NONNULL(2);

const char *
virClassName(virClassPtr klass)
    ATTRIBUTE_NONNULL(1);

bool
virClassIsDerivedFrom(virClassPtr klass,
                      virClassPtr parent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void *
virObjectNew(virClassPtr klass)
    ATTRIBUTE_NONNULL(1);

void
virObjectUnref(void *obj);

void *
virObjectRef(void *obj);

bool
virObjectIsClass(void *obj,
                 virClassPtr klass)
    ATTRIBUTE_NONNULL(2);

void
virObjectFreeCallback(void *opaque);

void
virObjectFreeHashData(void *opaque);

void *
virObjectLockableNew(virClassPtr klass)
    ATTRIBUTE_NONNULL(1);

void *
virObjectRWLockableNew(virClassPtr klass)
    ATTRIBUTE_NONNULL(1);

void
virObjectLock(void *lockableobj)
    ATTRIBUTE_NONNULL(1);

void
virObjectRWLockRead(void *lockableobj)
    ATTRIBUTE_NONNULL(1);

void
virObjectRWLockWrite(void *lockableobj)
    ATTRIBUTE_NONNULL(1);

void
virObjectUnlock(void *lockableobj)
    ATTRIBUTE_NONNULL(1);

void
virObjectRWUnlock(void *lockableobj)
    ATTRIBUTE_NONNULL(1);

void
virObjectListFree(void *list);

void
virObjectListFreeCount(void *list,
                       size_t count);
