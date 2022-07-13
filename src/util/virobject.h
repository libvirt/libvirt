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

typedef struct _virObject virObject;

typedef struct _virObjectLockable virObjectLockable;

typedef struct _virObjectRWLockable virObjectRWLockable;

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

virClass *virClassForObject(void);
virClass *virClassForObjectLockable(void);
virClass *virClassForObjectRWLockable(void);

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

virClass *
virClassNew(virClass *parent,
            const char *name,
            size_t objectSize,
            size_t parentSize,
            virObjectDisposeCallback dispose)
    VIR_PARENT_REQUIRED ATTRIBUTE_NONNULL(2);

const char *
virClassName(virClass *klass)
    ATTRIBUTE_NONNULL(1);

bool
virClassIsDerivedFrom(virClass *klass,
                      virClass *parent)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

void *
virObjectNew(virClass *klass)
    ATTRIBUTE_NONNULL(1);

void
virObjectUnref(void *obj);

void *
virObjectRef(void *obj);

bool
virObjectIsClass(void *obj,
                 virClass *klass)
    ATTRIBUTE_NONNULL(2);

void *
virObjectLockableNew(virClass *klass)
    ATTRIBUTE_NONNULL(1);

void *
virObjectRWLockableNew(virClass *klass)
    ATTRIBUTE_NONNULL(1);

virLockGuard
virObjectLockGuard(void *lockableobj)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

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

#define VIR_WITH_OBJECT_LOCK_GUARD_(o, name) \
    for (g_auto(virLockGuard) name = virObjectLockGuard(o); name.mutex; \
         name.mutex = (virLockGuardUnlock(&name), NULL))

/**
 * VIR_WITH_OBJECT_LOCK_GUARD:
 *
 * This macro defines a lock scope such that entering the scope takes the lock
 * and leaving the scope releases the lock. Return statements are allowed
 * within the scope and release the lock. Break and continue statements leave
 * the scope early and release the lock.
 *
 *     virObjectLockable *lockable = ...;
 *
 *     VIR_WITH_OBJECT_LOCK_GUARD(lockable) {
 *         // `lockable` is locked, and released automatically on scope exit
 *         ...
 *     }
 */
#define VIR_WITH_OBJECT_LOCK_GUARD(o) \
    VIR_WITH_OBJECT_LOCK_GUARD_(o, CONCAT(var, __COUNTER__))
