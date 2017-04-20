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
    virMutex lock;

    bool active;           /* true if interface is active (up) */
    virInterfaceDefPtr def; /* The interface definition */
};

struct _virInterfaceObjList {
    size_t count;
    virInterfaceObjPtr *objs;
};

/* virInterfaceObj manipulation */

static virInterfaceObjPtr
virInterfaceObjNew(void)
{
    virInterfaceObjPtr obj;

    if (VIR_ALLOC(obj) < 0)
        return NULL;

    if (virMutexInit(&obj->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(obj);
        return NULL;
    }

    virInterfaceObjLock(obj);

    return obj;
}


void
virInterfaceObjLock(virInterfaceObjPtr obj)
{
    virMutexLock(&obj->lock);
}


void
virInterfaceObjUnlock(virInterfaceObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}


void
virInterfaceObjFree(virInterfaceObjPtr obj)
{
    if (!obj)
        return;

    virInterfaceDefFree(obj->def);
    virMutexDestroy(&obj->lock);
    VIR_FREE(obj);
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

    if (VIR_ALLOC(interfaces) < 0)
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

    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virInterfaceObjLock(obj);
        def = obj->def;
        if (STRCASEEQ(def->mac, mac)) {
            if (matchct < maxmatches) {
                if (VIR_STRDUP(matches[matchct], def->name) < 0) {
                    virInterfaceObjUnlock(obj);
                    goto error;
                }
                matchct++;
            }
        }
        virInterfaceObjUnlock(obj);
    }
    return matchct;

 error:
    while (--matchct >= 0)
        VIR_FREE(matches[matchct]);

    return -1;
}


virInterfaceObjPtr
virInterfaceObjListFindByName(virInterfaceObjListPtr interfaces,
                              const char *name)
{
    size_t i;

    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virInterfaceObjLock(obj);
        def = obj->def;
        if (STREQ(def->name, name))
            return obj;
        virInterfaceObjUnlock(obj);
    }

    return NULL;
}


void
virInterfaceObjListFree(virInterfaceObjListPtr interfaces)
{
    size_t i;

    for (i = 0; i < interfaces->count; i++)
        virInterfaceObjFree(interfaces->objs[i]);
    VIR_FREE(interfaces->objs);
    VIR_FREE(interfaces);
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
        virInterfaceObjUnlock(obj); /* locked by virInterfaceObjListAssignDef */
    }

    return dest;

 error:
    virInterfaceObjListFree(dest);
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

    if (VIR_APPEND_ELEMENT_COPY(interfaces->objs,
                                interfaces->count, obj) < 0) {
        virInterfaceObjUnlock(obj);
        virInterfaceObjFree(obj);
        return NULL;
    }

    obj->def = def;
    return obj;

}


void
virInterfaceObjListRemove(virInterfaceObjListPtr interfaces,
                          virInterfaceObjPtr obj)
{
    size_t i;

    virInterfaceObjUnlock(obj);
    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjLock(interfaces->objs[i]);
        if (interfaces->objs[i] == obj) {
            virInterfaceObjUnlock(interfaces->objs[i]);
            virInterfaceObjFree(interfaces->objs[i]);

            VIR_DELETE_ELEMENT(interfaces->objs, i, interfaces->count);
            break;
        }
        virInterfaceObjUnlock(interfaces->objs[i]);
    }
}


int
virInterfaceObjListNumOfInterfaces(virInterfaceObjListPtr interfaces,
                                   bool wantActive)
{
    size_t i;
    int ninterfaces = 0;

    for (i = 0; (i < interfaces->count); i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceObjLock(obj);
        if (wantActive == virInterfaceObjIsActive(obj))
            ninterfaces++;
        virInterfaceObjUnlock(obj);
    }

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

    for (i = 0; i < interfaces->count && nnames < maxnames; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virInterfaceObjLock(obj);
        def = obj->def;
        if (wantActive == virInterfaceObjIsActive(obj)) {
            if (VIR_STRDUP(names[nnames], def->name) < 0) {
                virInterfaceObjUnlock(obj);
                goto failure;
            }
            nnames++;
        }
        virInterfaceObjUnlock(obj);
    }

    return nnames;

 failure:
    while (--nnames >= 0)
        VIR_FREE(names[nnames]);

    return -1;
}
