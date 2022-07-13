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

#define VIR_FROM_THIS VIR_FROM_INTERFACE

VIR_LOG_INIT("conf.virinterfaceobj");

struct _virInterfaceObj {
    virObjectLockable parent;

    bool active;           /* true if interface is active (up) */
    virInterfaceDef *def; /* The interface definition */
};

struct _virInterfaceObjList {
    virObjectRWLockable parent;

    /* name string -> virInterfaceObj  mapping
     * for O(1), lookup-by-name */
    GHashTable *objsName;
};

/* virInterfaceObj manipulation */

static virClass *virInterfaceObjClass;
static virClass *virInterfaceObjListClass;
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
    virInterfaceObj *obj = opaque;

    virInterfaceDefFree(obj->def);
}


static virInterfaceObj *
virInterfaceObjNew(void)
{
    virInterfaceObj *obj;

    if (virInterfaceObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virInterfaceObjClass)))
        return NULL;

    virObjectLock(obj);

    return obj;
}


void
virInterfaceObjEndAPI(virInterfaceObj **obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    g_clear_pointer(obj, virObjectUnref);
}


virInterfaceDef *
virInterfaceObjGetDef(virInterfaceObj *obj)
{
    return obj->def;
}


bool
virInterfaceObjIsActive(virInterfaceObj *obj)
{
    return obj->active;
}


void
virInterfaceObjSetActive(virInterfaceObj *obj,
                         bool active)
{
    obj->active = active;
}


/* virInterfaceObjList manipulation */
virInterfaceObjList *
virInterfaceObjListNew(void)
{
    virInterfaceObjList *interfaces;

    if (virInterfaceObjInitialize() < 0)
        return NULL;

    if (!(interfaces = virObjectRWLockableNew(virInterfaceObjListClass)))
        return NULL;

    interfaces->objsName = virHashNew(virObjectUnref);

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
                                     const char *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virInterfaceObj *obj = payload;
    struct _virInterfaceObjFindMACData *data = opaque;

    if (data->error)
        return 0;

    if (data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (STRCASEEQ(obj->def->mac, data->matchStr)) {
        data->names[data->nnames] = g_strdup(obj->def->name);
        data->nnames++;
    }

    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListFindByMACString(virInterfaceObjList *interfaces,
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


static virInterfaceObj *
virInterfaceObjListFindByNameLocked(virInterfaceObjList *interfaces,
                                    const char *name)
{
    return virObjectRef(virHashLookup(interfaces->objsName, name));
}


virInterfaceObj *
virInterfaceObjListFindByName(virInterfaceObjList *interfaces,
                              const char *name)
{
    virInterfaceObj *obj;
    virObjectRWLockRead(interfaces);
    obj = virInterfaceObjListFindByNameLocked(interfaces, name);
    virObjectRWUnlock(interfaces);
    if (obj)
        virObjectLock(obj);

    return obj;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virInterfaceObjMatch(virInterfaceObj *obj,
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
                                  const char *name G_GNUC_UNUSED,
                                  void *opaque)
{
    virInterfaceObjListExportData *data = opaque;
    virInterfaceObj *obj = payload;
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
                          virInterfaceObjList *ifaceobjs,
                          virInterfacePtr **ifaces,
                          virInterfaceObjListFilter filter,
                          unsigned int flags)
{
    int ret = -1;
    virInterfaceObjListExportData data = {
        .conn = conn, .ifaces = NULL, .filter = filter, .flags = flags,
        .nifaces = 0, .error = false };

    virObjectRWLockRead(ifaceobjs);
    if (ifaces)
        data.ifaces = g_new0(virInterfacePtr, virHashSize(ifaceobjs->objsName) + 1);

    virHashForEach(ifaceobjs->objsName, virInterfaceObjListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.ifaces) {
        /* trim the array to the final size */
        VIR_REALLOC_N(data.ifaces, data.nifaces + 1);
        *ifaces = g_steal_pointer(&data.ifaces);
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
    virInterfaceObjList *interfaces = obj;

    g_clear_pointer(&interfaces->objsName, g_hash_table_unref);
}


struct _virInterfaceObjListCloneData {
    bool error;
    virInterfaceObjList *dest;
};

static int
virInterfaceObjListCloneCb(void *payload,
                           const char *name G_GNUC_UNUSED,
                           void *opaque)
{
    virInterfaceObj *srcObj = payload;
    struct _virInterfaceObjListCloneData *data = opaque;
    char *xml = NULL;
    g_autoptr(virInterfaceDef) backup = NULL;
    virInterfaceObj *obj;

    if (data->error)
        return 0;

    virObjectLock(srcObj);

    if (!(xml = virInterfaceDefFormat(srcObj->def)))
        goto error;

    if (!(backup = virInterfaceDefParseString(xml, 0)))
        goto error;
    VIR_FREE(xml);

    if (!(obj = virInterfaceObjListAssignDef(data->dest, &backup)))
        goto error;
    virInterfaceObjEndAPI(&obj);

    virObjectUnlock(srcObj);
    return 0;

 error:
    data->error = true;
    VIR_FREE(xml);
    virObjectUnlock(srcObj);
    return 0;
}


virInterfaceObjList *
virInterfaceObjListClone(virInterfaceObjList *interfaces)
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


/**
 * virInterfaceObjListAssignDef:
 * @interfaces: virInterface object list
 * @def: new definition
 *
 * Assigns new definition to either an existing or newly created
 * virInterface object. Upon successful return the virInterface
 * object is the owner of @def and callers should use
 * virInterfaceObjGetDef() if they need to access the definition
 * as @def is set to NULL.
 *
 * Returns: a virInterface object instance on success, or
 *          NULL on error.
 */
virInterfaceObj *
virInterfaceObjListAssignDef(virInterfaceObjList *interfaces,
                             virInterfaceDef **def)
{
    virInterfaceObj *obj;

    virObjectRWLockWrite(interfaces);
    if ((obj = virInterfaceObjListFindByNameLocked(interfaces, (*def)->name))) {
        virInterfaceDefFree(obj->def);
    } else {
        if (!(obj = virInterfaceObjNew()))
            goto error;

        if (virHashAddEntry(interfaces->objsName, (*def)->name, obj) < 0)
            goto error;
        virObjectRef(obj);
    }

    obj->def = g_steal_pointer(def);
    virObjectRWUnlock(interfaces);

    return obj;

 error:
    virInterfaceObjEndAPI(&obj);
    virObjectRWUnlock(interfaces);
    return NULL;
}


void
virInterfaceObjListRemove(virInterfaceObjList *interfaces,
                          virInterfaceObj *obj)
{
    if (!obj)
        return;

    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(interfaces);
    virObjectLock(obj);
    virHashRemoveEntry(interfaces->objsName, obj->def->name);
    virInterfaceObjEndAPI(&obj);
    virObjectRWUnlock(interfaces);
}


struct _virInterfaceObjNumOfInterfacesData {
    bool wantActive;
    int count;
};

static int
virInterfaceObjListNumOfInterfacesCb(void *payload,
                                     const char *name G_GNUC_UNUSED,
                                     void *opaque)
{
    virInterfaceObj *obj = payload;
    struct _virInterfaceObjNumOfInterfacesData *data = opaque;

    virObjectLock(obj);

    if (data->wantActive == virInterfaceObjIsActive(obj))
        data->count++;

    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListNumOfInterfaces(virInterfaceObjList *interfaces,
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
                              const char *name G_GNUC_UNUSED,
                              void *opaque)
{
    virInterfaceObj *obj = payload;
    struct _virInterfaceObjGetNamesData *data = opaque;

    if (data->error)
        return 0;

    if (data->maxnames >= 0 && data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (data->wantActive != virInterfaceObjIsActive(obj))
        goto cleanup;

    data->names[data->nnames] = g_strdup(obj->def->name);

    data->nnames++;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virInterfaceObjListGetNames(virInterfaceObjList *interfaces,
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
