/*
 * virobject.c: libvirt reference counted object
 *
 * Copyright (C) 2012 Red Hat, Inc.
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

#include <config.h>

#include "virobject.h"
#include "threads.h"
#include "memory.h"
#include "viratomic.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_NONE

static unsigned int magicCounter = 0xCAFE0000;

struct _virClass {
    unsigned int magic;
    const char *name;
    size_t objectSize;

    virObjectDisposeCallback dispose;
};


/**
 * virClassNew:
 * @name: the class name
 * @objectSize: total size of the object struct
 * @dispose: callback to run to free object fields
 *
 * Register a new object class with @name. The @objectSize
 * should give the total size of the object struct, which
 * is expected to have a 'virObject object;' field as its
 * first member. When the last reference on the object is
 * released, the @dispose callback will be invoked to free
 * memory of the object fields
 *
 * Returns a new class instance
 */
virClassPtr virClassNew(const char *name,
                        size_t objectSize,
                        virObjectDisposeCallback dispose)
{
    virClassPtr klass;

    if (VIR_ALLOC(klass) < 0)
        goto no_memory;

    if (!(klass->name = strdup(name)))
        goto no_memory;
    klass->magic = virAtomicIntInc(&magicCounter);
    klass->objectSize = objectSize;
    klass->dispose = dispose;

    return klass;

no_memory:
    VIR_FREE(klass);
    virReportOOMError();
    return NULL;
}


/**
 * virObjectNew:
 * @klass: the klass of object to create
 *
 * Allocates a new object of type @klass. The returned
 * object will be an instance of "virObjectPtr", which
 * can be cast to the struct associated with @klass.
 *
 * The initial reference count of the object will be 1.
 *
 * Returns the new object
 */
void *virObjectNew(virClassPtr klass)
{
    virObjectPtr obj = NULL;
    char *somebytes;

    if (VIR_ALLOC_N(somebytes, klass->objectSize) < 0) {
        virReportOOMError();
        return NULL;
    }
    obj = (virObjectPtr)somebytes;

    obj->magic = klass->magic;
    obj->klass = klass;
    virAtomicIntSet(&obj->refs, 1);

    PROBE(OBJECT_NEW, "obj=%p classname=%s", obj, obj->klass->name);

    return obj;
}


/**
 * virObjectUnref:
 * @anyobj: any instance of virObjectPtr
 *
 * Decrement the reference count on @anyobj and if
 * it hits zero, runs the "dispose" callback associated
 * with the object class and frees @anyobj.
 *
 * Returns true if the remaining reference count is
 * non-zero, false if the object was disposed of
 */
bool virObjectUnref(void *anyobj)
{
    virObjectPtr obj = anyobj;

    if (!obj)
        return false;

    bool lastRef = virAtomicIntDecAndTest(&obj->refs);
    PROBE(OBJECT_UNREF, "obj=%p", obj);
    if (lastRef) {
        PROBE(OBJECT_DISPOSE, "obj=%p", obj);
        if (obj->klass->dispose)
            obj->klass->dispose(obj);

        /* Clear & poison object */
        memset(obj, 0, obj->klass->objectSize);
        obj->magic = 0xDEADBEEF;
        obj->klass = (void*)0xDEADBEEF;
        VIR_FREE(obj);
    }

    return !lastRef;
}


/**
 * virObjectRef:
 * @anyobj: any instance of virObjectPtr
 *
 * Increment the reference count on @anyobj and return
 * the same pointer
 *
 * Returns @anyobj
 */
void *virObjectRef(void *anyobj)
{
    virObjectPtr obj = anyobj;

    if (!obj)
        return NULL;
    virAtomicIntInc(&obj->refs);
    PROBE(OBJECT_REF, "obj=%p", obj);
    return anyobj;
}


/**
 * virObjectIsClass:
 * @anyobj: any instance of virObjectPtr
 * @klass: the class to check
 *
 * Checks whether @anyobj is an instance of
 * @klass
 *
 * Returns true if @anyobj is an instance of @klass
 */
bool virObjectIsClass(void *anyobj,
                      virClassPtr klass)
{
    virObjectPtr obj = anyobj;
    return obj != NULL && (obj->magic == klass->magic) && (obj->klass == klass);
}


/**
 * virClassName:
 * @klass: the object class
 *
 * Returns the name of @klass
 */
const char *virClassName(virClassPtr klass)
{
    return klass->name;
}


/**
 * virObjectFreeCallback:
 * @opaque: a pointer to a virObject instance
 *
 * Provides identical functionality to virObjectUnref,
 * but with the signature matching the virFreeCallback
 * typedef.
 */
void virObjectFreeCallback(void *opaque)
{
    virObjectUnref(opaque);
}
