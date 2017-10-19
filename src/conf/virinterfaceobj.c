/*
 * virinterfaceobj.c: interface object handling
 *                    (derived from interface_conf.c)
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

#include <config.h>

#include "datatypes.h"
#include "interface_conf.h"

#include "viralloc.h"
#include "virerror.h"
#include "virinterfaceobj.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_LOG_INIT("conf.virinterfaceobj");

struct _virInterfaceObj {
    virObjectLockable parent;

    bool active;           /* true if interface is active (up) */
    virInterfaceDefPtr def; /* The interface definition */
};

struct _virInterfaceObjList {
    virObjectRWLockable parent;

    size_t count;
    virInterfaceObjPtr *objs;
};

/* virInterfaceObj manipulation */

static virClassPtr virInterfaceObjClass;
static virClassPtr virInterfaceObjListClass;
static void virInterfaceObjDispose(void *obj);
static void virInterfaceObjListDispose(void *obj);

static int
virInterfaceObjOnceInit(void)
{
    if (!(virInterfaceObjClass = virClassNew(virClassForObjectLockable(),
                                             "virInterfaceObj",
                                             sizeof(virInterfaceObj),
                                             virInterfaceObjDispose)))
        return -1;

    if (!(virInterfaceObjListClass = virClassNew(virClassForObjectRWLockable(),
                                                 "virInterfaceObjList",
                                                 sizeof(virInterfaceObjList),
                                                 virInterfaceObjListDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virInterfaceObj)


static void
virInterfaceObjDispose(void *opaque)
{
    virInterfaceObjPtr obj = opaque;

    virInterfaceDefFree(obj->def);
}


static virInterfaceObjPtr
virInterfaceObjNew(void)
{
    virInterfaceObjPtr obj;

    if (virInterfaceObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virInterfaceObjClass)))
        return NULL;

    virObjectLock(obj);

    return obj;
}


void
virInterfaceObjEndAPI(virInterfaceObjPtr *obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    virObjectUnref(*obj);
    *obj = NULL;
}


virInterfaceDefPtr
virInterfaceObjGetDef(virInterfaceObjPtr obj)
{
    return obj->def;
}


bool
virInterfaceObjIsActive(virInterfaceObjPtr obj)
{
    return obj->active;
}


void
virInterfaceObjSetActive(virInterfaceObjPtr obj,
                         bool active)
{
    obj->active = active;
}


/* virInterfaceObjList manipulation */
virInterfaceObjListPtr
virInterfaceObjListNew(void)
{
    virInterfaceObjListPtr interfaces;

    if (virInterfaceObjInitialize() < 0)
        return NULL;

    if (!(interfaces = virObjectRWLockableNew(virInterfaceObjListClass)))
        return NULL;

    return interfaces;
}


int
virInterfaceObjListFindByMACString(virInterfaceObjListPtr interfaces,
                                   const char *mac,
                                   char **const matches,
                                   int maxmatches)
{
    size_t i;
    int matchct = 0;

    virObjectRWLockRead(interfaces);
    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virObjectLock(obj);
        def = obj->def;
        if (STRCASEEQ(def->mac, mac)) {
            if (matchct < maxmatches) {
                if (VIR_STRDUP(matches[matchct], def->name) < 0) {
                    virObjectUnlock(obj);
                    goto error;
                }
                matchct++;
            }
        }
        virObjectUnlock(obj);
    }
    virObjectRWUnlock(interfaces);
    return matchct;

 error:
    while (--matchct >= 0)
        VIR_FREE(matches[matchct]);
    virObjectRWUnlock(interfaces);

    return -1;
}


virInterfaceObjPtr
virInterfaceObjListFindByName(virInterfaceObjListPtr interfaces,
                              const char *name)
{
    size_t i;

    virObjectRWLockRead(interfaces);
    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virObjectLock(obj);
        def = obj->def;
        if (STREQ(def->name, name)) {
            virObjectRWUnlock(interfaces);
            return virObjectRef(obj);
        }
        virObjectUnlock(obj);
    }
    virObjectRWUnlock(interfaces);

    return NULL;
}


void
virInterfaceObjListDispose(void *obj)
{
    size_t i;
    virInterfaceObjListPtr interfaces = obj;

    for (i = 0; i < interfaces->count; i++)
        virObjectUnref(interfaces->objs[i]);
    VIR_FREE(interfaces->objs);
}


virInterfaceObjListPtr
virInterfaceObjListClone(virInterfaceObjListPtr interfaces)
{
    size_t i;
    unsigned int cnt;
    virInterfaceObjListPtr dest;

    if (!interfaces)
        return NULL;

    if (!(dest = virInterfaceObjListNew()))
        return NULL;

    virObjectRWLockRead(interfaces);
    cnt = interfaces->count;
    for (i = 0; i < cnt; i++) {
        virInterfaceObjPtr srcobj = interfaces->objs[i];
        virInterfaceDefPtr backup;
        virInterfaceObjPtr obj;
        char *xml = virInterfaceDefFormat(srcobj->def);

        if (!xml)
            goto error;

        if (!(backup = virInterfaceDefParseString(xml))) {
            VIR_FREE(xml);
            goto error;
        }

        VIR_FREE(xml);
        if (!(obj = virInterfaceObjListAssignDef(dest, backup)))
            goto error;
        virInterfaceObjEndAPI(&obj);
    }
    virObjectRWUnlock(interfaces);

    return dest;

 error:
    virObjectUnref(dest);
    virObjectRWUnlock(interfaces);
    return NULL;
}


virInterfaceObjPtr
virInterfaceObjListAssignDef(virInterfaceObjListPtr interfaces,
                             virInterfaceDefPtr def)
{
    virInterfaceObjPtr obj;

    if ((obj = virInterfaceObjListFindByName(interfaces, def->name))) {
        virInterfaceDefFree(obj->def);
        obj->def = def;

        return obj;
    }

    if (!(obj = virInterfaceObjNew()))
        return NULL;

    virObjectRWLockWrite(interfaces);
    if (VIR_APPEND_ELEMENT_COPY(interfaces->objs,
                                interfaces->count, obj) < 0) {
        virInterfaceObjEndAPI(&obj);
        virObjectRWUnlock(interfaces);
        return NULL;
    }
    obj->def = def;
    virObjectRWUnlock(interfaces);
    return virObjectRef(obj);
}


void
virInterfaceObjListRemove(virInterfaceObjListPtr interfaces,
                          virInterfaceObjPtr obj)
{
    size_t i;

    virObjectUnlock(obj);
    virObjectRWLockWrite(interfaces);
    for (i = 0; i < interfaces->count; i++) {
        virObjectLock(interfaces->objs[i]);
        if (interfaces->objs[i] == obj) {
            virObjectUnlock(interfaces->objs[i]);
            virObjectUnref(interfaces->objs[i]);

            VIR_DELETE_ELEMENT(interfaces->objs, i, interfaces->count);
            break;
        }
        virObjectUnlock(interfaces->objs[i]);
    }
    virObjectRWUnlock(interfaces);
}


int
virInterfaceObjListNumOfInterfaces(virInterfaceObjListPtr interfaces,
                                   bool wantActive)
{
    size_t i;
    int ninterfaces = 0;

    virObjectRWLockRead(interfaces);
    for (i = 0; (i < interfaces->count); i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virObjectLock(obj);
        if (wantActive == virInterfaceObjIsActive(obj))
            ninterfaces++;
        virObjectUnlock(obj);
    }
    virObjectRWUnlock(interfaces);

    return ninterfaces;
}


int
virInterfaceObjListGetNames(virInterfaceObjListPtr interfaces,
                            bool wantActive,
                            char **const names,
                            int maxnames)
{
    int nnames = 0;
    size_t i;

    virObjectRWLockRead(interfaces);
    for (i = 0; i < interfaces->count && nnames < maxnames; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virObjectLock(obj);
        def = obj->def;
        if (wantActive == virInterfaceObjIsActive(obj)) {
            if (VIR_STRDUP(names[nnames], def->name) < 0) {
                virObjectUnlock(obj);
                goto failure;
            }
            nnames++;
        }
        virObjectUnlock(obj);
    }
    virObjectRWUnlock(interfaces);

    return nnames;

 failure:
    while (--nnames >= 0)
        VIR_FREE(names[nnames]);

    return -1;
}
