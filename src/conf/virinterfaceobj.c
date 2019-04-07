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
#include "virhash.h"
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

    /* name string -> virInterfaceObj  mapping
     * for O(1), lockless lookup-by-name */
    virHashTable *objsName;
};

/* virInterfaceObj manipulation */

static virClassPtr virInterfaceObjClass;
static virClassPtr virInterfaceObjListClass;
static void virInterfaceObjDispose(void *obj);
static void virInterfaceObjListDispose(void *obj);

static int
virInterfaceObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virInterfaceObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virInterfaceObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virInterfaceObj);


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

    if (!(interfaces->objsName = virHashCreate(10, virObjectFreeHashData))) {
        virObjectUnref(interfaces);
        return NULL;
    }

    return interfaces;
}


struct _virInterfaceObjFindMACData {
    const char *matchStr;
    bool error;
    int nnames;
    int maxnames;
    char **const names;
};

static int
virInterfaceObjListFindByMACStringCb(void *payload,
                                     const void *name ATTRIBUTE_UNUSED,
                                     void *opaque)
{
    virInterfaceObjPtr obj = payload;
    struct _virInterfaceObjFindMACData *data = opaque;

    if (data->error)
        return 0;

    if (data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (STRCASEEQ(obj->def->mac, data->matchStr)) {
        if (VIR_STRDUP(data->names[data->nnames], obj->def->name) < 0) {
            data->error = true;
            goto cleanup;
        }
        data->nnames++;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListFindByMACString(virInterfaceObjListPtr interfaces,
                                   const char *mac,
                                   char **const matches,
                                   int maxmatches)
{
    struct _virInterfaceObjFindMACData data = { .matchStr = mac,
                                                .error = false,
                                                .nnames = 0,
                                                .maxnames = maxmatches,
                                                .names = matches };

    virObjectRWLockRead(interfaces);
    virHashForEach(interfaces->objsName, virInterfaceObjListFindByMACStringCb,
                   &data);
    virObjectRWUnlock(interfaces);

    if (data.error)
        goto error;

    return data.nnames;

 error:
    while (--data.nnames >= 0)
        VIR_FREE(data.names[data.nnames]);

    return -1;
}


static virInterfaceObjPtr
virInterfaceObjListFindByNameLocked(virInterfaceObjListPtr interfaces,
                                    const char *name)
{
    return virObjectRef(virHashLookup(interfaces->objsName, name));
}


virInterfaceObjPtr
virInterfaceObjListFindByName(virInterfaceObjListPtr interfaces,
                              const char *name)
{
    virInterfaceObjPtr obj;
    virObjectRWLockRead(interfaces);
    obj = virInterfaceObjListFindByNameLocked(interfaces, name);
    virObjectRWUnlock(interfaces);
    if (obj)
        virObjectLock(obj);

    return obj;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virInterfaceObjMatch(virInterfaceObjPtr obj,
                     unsigned int flags)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_INTERFACES_ACTIVE) &&
           virInterfaceObjIsActive(obj)) ||
          (MATCH(VIR_CONNECT_LIST_INTERFACES_INACTIVE) &&
           !virInterfaceObjIsActive(obj))))
        return false;

    return true;
}
#undef MATCH


typedef struct _virInterfaceObjListExportData virInterfaceObjListExportData;
typedef virInterfaceObjListExportData *virInterfaceObjListExportDataPtr;
struct _virInterfaceObjListExportData {
    virConnectPtr conn;
    virInterfacePtr *ifaces;
    virInterfaceObjListFilter filter;
    unsigned int flags;
    int nifaces;
    bool error;
};

static int
virInterfaceObjListExportCallback(void *payload,
                                  const void *name ATTRIBUTE_UNUSED,
                                  void *opaque)
{
    virInterfaceObjListExportDataPtr data = opaque;
    virInterfaceObjPtr obj = payload;
    virInterfacePtr iface = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;

    if (!virInterfaceObjMatch(obj, data->flags))
        goto cleanup;

    if (!data->ifaces) {
        data->nifaces++;
        goto cleanup;
    }

    if (!(iface = virGetInterface(data->conn, obj->def->name, obj->def->mac))) {
        data->error = true;
        goto cleanup;
    }

    data->ifaces[data->nifaces++] = iface;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListExport(virConnectPtr conn,
                          virInterfaceObjListPtr ifaceobjs,
                          virInterfacePtr **ifaces,
                          virInterfaceObjListFilter filter,
                          unsigned int flags)
{
    int ret = -1;
    virInterfaceObjListExportData data = {
        .conn = conn, .ifaces = NULL, .filter = filter, .flags = flags,
        .nifaces = 0, .error = false };

    virObjectRWLockRead(ifaceobjs);
    if (ifaces && VIR_ALLOC_N(data.ifaces,
                              virHashSize(ifaceobjs->objsName) + 1) < 0)
        goto cleanup;

    virHashForEach(ifaceobjs->objsName, virInterfaceObjListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.ifaces) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.ifaces, data.nifaces + 1));
        *ifaces = data.ifaces;
        data.ifaces = NULL;
    }

    ret = data.nifaces;
 cleanup:
    virObjectRWUnlock(ifaceobjs);
    while (data.ifaces && data.nifaces)
        virObjectUnref(data.ifaces[--data.nifaces]);

    VIR_FREE(data.ifaces);
    return ret;
}


void
virInterfaceObjListDispose(void *obj)
{
    virInterfaceObjListPtr interfaces = obj;

    virHashFree(interfaces->objsName);
}


struct _virInterfaceObjListCloneData {
    bool error;
    virInterfaceObjListPtr dest;
};

static int
virInterfaceObjListCloneCb(void *payload,
                           const void *name ATTRIBUTE_UNUSED,
                           void *opaque)
{
    virInterfaceObjPtr srcObj = payload;
    struct _virInterfaceObjListCloneData *data = opaque;
    char *xml = NULL;
    virInterfaceDefPtr backup = NULL;
    virInterfaceObjPtr obj;

    if (data->error)
        return 0;

    virObjectLock(srcObj);

    if (!(xml = virInterfaceDefFormat(srcObj->def)))
        goto error;

    if (!(backup = virInterfaceDefParseString(xml)))
        goto error;
    VIR_FREE(xml);

    if (!(obj = virInterfaceObjListAssignDef(data->dest, backup)))
        goto error;
    virInterfaceObjEndAPI(&obj);

    virObjectUnlock(srcObj);
    return 0;

 error:
    data->error = true;
    VIR_FREE(xml);
    virInterfaceDefFree(backup);
    virObjectUnlock(srcObj);
    return 0;
}


virInterfaceObjListPtr
virInterfaceObjListClone(virInterfaceObjListPtr interfaces)
{
    struct _virInterfaceObjListCloneData data = { .error = false,
                                                  .dest = NULL };

    if (!interfaces)
        return NULL;

    if (!(data.dest = virInterfaceObjListNew()))
        return NULL;

    virObjectRWLockRead(interfaces);
    virHashForEach(interfaces->objsName, virInterfaceObjListCloneCb, &data);
    virObjectRWUnlock(interfaces);

    if (data.error)
        goto error;

    return data.dest;

 error:
    virObjectUnref(data.dest);
    return NULL;
}


virInterfaceObjPtr
virInterfaceObjListAssignDef(virInterfaceObjListPtr interfaces,
                             virInterfaceDefPtr def)
{
    virInterfaceObjPtr obj;

    virObjectRWLockWrite(interfaces);
    if ((obj = virInterfaceObjListFindByNameLocked(interfaces, def->name))) {
        virInterfaceDefFree(obj->def);
    } else {
        if (!(obj = virInterfaceObjNew()))
            goto error;

        if (virHashAddEntry(interfaces->objsName, def->name, obj) < 0)
            goto error;
        virObjectRef(obj);
    }

    obj->def = def;
    virObjectRWUnlock(interfaces);

    return obj;

 error:
    virInterfaceObjEndAPI(&obj);
    virObjectRWUnlock(interfaces);
    return NULL;
}


void
virInterfaceObjListRemove(virInterfaceObjListPtr interfaces,
                          virInterfaceObjPtr obj)
{
    if (!obj)
        return;

    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(interfaces);
    virObjectLock(obj);
    virHashRemoveEntry(interfaces->objsName, obj->def->name);
    virObjectUnlock(obj);
    virObjectUnref(obj);
    virObjectRWUnlock(interfaces);
}


struct _virInterfaceObjNumOfInterfacesData {
    bool wantActive;
    int count;
};

static int
virInterfaceObjListNumOfInterfacesCb(void *payload,
                                     const void *name ATTRIBUTE_UNUSED,
                                     void *opaque)
{
    virInterfaceObjPtr obj = payload;
    struct _virInterfaceObjNumOfInterfacesData *data = opaque;

    virObjectLock(obj);

    if (data->wantActive == virInterfaceObjIsActive(obj))
        data->count++;

    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListNumOfInterfaces(virInterfaceObjListPtr interfaces,
                                   bool wantActive)
{
    struct _virInterfaceObjNumOfInterfacesData data = {
        .wantActive = wantActive, .count = 0 };

    virObjectRWLockRead(interfaces);
    virHashForEach(interfaces->objsName, virInterfaceObjListNumOfInterfacesCb,
                   &data);
    virObjectRWUnlock(interfaces);

    return data.count;
}


struct _virInterfaceObjGetNamesData {
    bool wantActive;
    bool error;
    int nnames;
    int maxnames;
    char **const names;
};

static int
virInterfaceObjListGetNamesCb(void *payload,
                              const void *name ATTRIBUTE_UNUSED,
                              void *opaque)
{
    virInterfaceObjPtr obj = payload;
    struct _virInterfaceObjGetNamesData *data = opaque;

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (data->wantActive != virInterfaceObjIsActive(obj))
        goto cleanup;

    if (VIR_STRDUP(data->names[data->nnames], obj->def->name) < 0) {
        data->error = true;
        goto cleanup;
    }

    data->nnames++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListGetNames(virInterfaceObjListPtr interfaces,
                            bool wantActive,
                            char **const names,
                            int maxnames)
{
    struct _virInterfaceObjGetNamesData data = {
        .wantActive = wantActive, .error = false, .nnames = 0,
        .maxnames = maxnames,  .names = names };

    virObjectRWLockRead(interfaces);
    virHashForEach(interfaces->objsName, virInterfaceObjListGetNamesCb, &data);
    virObjectRWUnlock(interfaces);

    if (data.error)
        goto error;

    return data.nnames;

 error:
    while (--data.nnames >= 0)
        VIR_FREE(data.names[data.nnames]);

    return -1;
}
