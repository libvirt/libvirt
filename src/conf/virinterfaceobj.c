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



/* virInterfaceObj manipulation */

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


/* virInterfaceObjList manipulation */
int
virInterfaceObjFindByMACString(virInterfaceObjListPtr interfaces,
                               const char *mac,
                               virInterfaceObjPtr *matches, int maxmatches)
{
    size_t i;
    unsigned int matchct = 0;

    for (i = 0; i < interfaces->count; i++) {
        virInterfaceObjPtr obj = interfaces->objs[i];
        virInterfaceDefPtr def;

        virInterfaceObjLock(obj);
        def = obj->def;
        if (STRCASEEQ(def->mac, mac)) {
            matchct++;
            if (matchct <= maxmatches) {
                matches[matchct - 1] = obj;
                /* keep the lock if we're returning object to caller */
                /* it is the caller's responsibility to unlock *all* matches */
                continue;
            }
        }
        virInterfaceObjUnlock(obj);

    }
    return matchct;
}


virInterfaceObjPtr
virInterfaceObjFindByName(virInterfaceObjListPtr interfaces,
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
    interfaces->count = 0;
}


int
virInterfaceObjListClone(virInterfaceObjListPtr src,
                         virInterfaceObjListPtr dest)
{
    int ret = -1;
    size_t i;
    unsigned int cnt;

    if (!src || !dest)
        goto cleanup;

    virInterfaceObjListFree(dest); /* start with an empty list */
    cnt = src->count;
    for (i = 0; i < cnt; i++) {
        virInterfaceObjPtr srcobj = src->objs[i];
        virInterfaceDefPtr backup;
        virInterfaceObjPtr obj;
        char *xml = virInterfaceDefFormat(srcobj->def);

        if (!xml)
            goto cleanup;

        if ((backup = virInterfaceDefParseString(xml)) == NULL) {
            VIR_FREE(xml);
            goto cleanup;
        }

        VIR_FREE(xml);
        if ((obj = virInterfaceObjAssignDef(dest, backup)) == NULL)
            goto cleanup;
        virInterfaceObjUnlock(obj); /* locked by virInterfaceObjAssignDef */
    }

    ret = cnt;
 cleanup:
    if ((ret < 0) && dest)
       virInterfaceObjListFree(dest);
    return ret;
}


virInterfaceObjPtr
virInterfaceObjAssignDef(virInterfaceObjListPtr interfaces,
                         virInterfaceDefPtr def)
{
    virInterfaceObjPtr obj;

    if ((obj = virInterfaceObjFindByName(interfaces, def->name))) {
        virInterfaceDefFree(obj->def);
        obj->def = def;

        return obj;
    }

    if (VIR_ALLOC(obj) < 0)
        return NULL;
    if (virMutexInit(&obj->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(obj);
        return NULL;
    }
    virInterfaceObjLock(obj);

    if (VIR_APPEND_ELEMENT_COPY(interfaces->objs,
                                interfaces->count, obj) < 0) {
        virInterfaceObjFree(obj);
        return NULL;
    }

    obj->def = def;
    return obj;

}


void
virInterfaceObjRemove(virInterfaceObjListPtr interfaces,
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
virInterfaceObjNumOfInterfaces(virInterfaceObjListPtr interfaces,
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
virInterfaceObjGetNames(virInterfaceObjListPtr interfaces,
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
