/*
 * virnwfilterbindingobjlist.c: nwfilter binding object list utilities
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
 */

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "virnwfilterbindingobjlist.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("conf.virnwfilterbindingobjlist");

static virClass *virNWFilterBindingObjListClass;
static void virNWFilterBindingObjListDispose(void *obj);

struct _virNWFilterBindingObjList {
    virObjectRWLockable parent;

    /* port dev name -> virNWFilterBindingObj  mapping
     * for O(1), lookup-by-port dev */
    GHashTable *objs;
};


static int virNWFilterBindingObjListOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNWFilterBindingObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNWFilterBindingObjList);


virNWFilterBindingObjList *
virNWFilterBindingObjListNew(void)
{
    virNWFilterBindingObjList *bindings;

    if (virNWFilterBindingObjListInitialize() < 0)
        return NULL;

    if (!(bindings = virObjectRWLockableNew(virNWFilterBindingObjListClass)))
        return NULL;

    bindings->objs = virHashNew(virObjectUnref);

    return bindings;
}


static void
virNWFilterBindingObjListDispose(void *obj)
{
    virNWFilterBindingObjList *bindings = obj;

    g_clear_pointer(&bindings->objs, g_hash_table_unref);
}


static virNWFilterBindingObj *
virNWFilterBindingObjListFindByPortDevLocked(virNWFilterBindingObjList *bindings,
                                             const char *name)
{
    virNWFilterBindingObj *obj;

    obj = virHashLookup(bindings->objs, name);
    if (obj) {
        virObjectRef(obj);
        virObjectLock(obj);
    }
    return obj;
}


/**
 * @bindings: NWFilterBinding object list
 * @name: Name to search the bindings->objs table
 *
 * Lookup the @name in the bindings->objs hash table and return a
 * locked and ref counted binding object if found. Caller is expected
 * to use the virNWFilterBindingObjEndAPI when done with the object.
 */
virNWFilterBindingObj *
virNWFilterBindingObjListFindByPortDev(virNWFilterBindingObjList *bindings,
                                       const char *name)
{
    virNWFilterBindingObj *obj;

    virObjectRWLockRead(bindings);
    obj = virNWFilterBindingObjListFindByPortDevLocked(bindings, name);
    virObjectRWUnlock(bindings);

    if (obj && virNWFilterBindingObjGetRemoving(obj))
        virNWFilterBindingObjEndAPI(&obj);

    return obj;
}


/**
 * @bindings: NWFilterBinding object list pointer
 * @binding: NWFilterBinding object to be added
 *
 * Upon entry @binding should have at least 1 ref and be locked.
 *
 * Add the @binding into the @bindings->objs hash
 * tables. Once successfully added into a table, increase the
 * reference count since upon removal in virHashRemoveEntry
 * the virObjectUnref will be called since the hash tables were
 * configured to call virObjectUnref when the object is
 * removed from the hash table.
 *
 * Returns 0 on success with 2 references and locked
 *        -1 on failure with 1 reference and locked
 */
static int
virNWFilterBindingObjListAddObjLocked(virNWFilterBindingObjList *bindings,
                                      virNWFilterBindingObj *binding)
{
    virNWFilterBindingDef *def = virNWFilterBindingObjGetDef(binding);
    if (virHashAddEntry(bindings->objs, def->portdevname, binding) < 0)
        return -1;
    virObjectRef(binding);

    return 0;
}


/*
 * virNWFilterBindingObjListAddLocked:
 *
 * The returned @binding from this function will be locked and ref
 * counted. The caller is expected to use virNWFilterBindingObjEndAPI
 * when it completes usage.
 */
static virNWFilterBindingObj *
virNWFilterBindingObjListAddLocked(virNWFilterBindingObjList *bindings,
                                   virNWFilterBindingDef *def)
{
    virNWFilterBindingObj *binding;
    bool stealDef = false;

    /* See if a binding with matching portdev already exists */
    binding = virNWFilterBindingObjListFindByPortDevLocked(bindings, def->portdevname);
    if (binding) {
        if (virNWFilterBindingObjGetRemoving(binding)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("binding '%1$s' is already being removed"),
                           def->portdevname);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("binding '%1$s' already exists"),
                           def->portdevname);
        }
        goto error;
    }

    if (!(binding = virNWFilterBindingObjNew()))
        goto error;

    virNWFilterBindingObjSetDef(binding, def);
    stealDef = true;

    if (virNWFilterBindingObjListAddObjLocked(bindings, binding) < 0)
        goto error;

    return binding;

 error:
    if (stealDef)
        virNWFilterBindingObjStealDef(binding);
    virNWFilterBindingObjEndAPI(&binding);
    return NULL;
}


virNWFilterBindingObj *
virNWFilterBindingObjListAdd(virNWFilterBindingObjList *bindings,
                             virNWFilterBindingDef *def)
{
    virNWFilterBindingObj *ret;

    virObjectRWLockWrite(bindings);
    ret = virNWFilterBindingObjListAddLocked(bindings, def);
    virObjectRWUnlock(bindings);
    return ret;
}


/* The caller must hold lock on 'bindings' in addition to 'virNWFilterBindingObjListRemove'
 * requirements
 *
 * Can be used to remove current element while iterating with
 * virNWFilterBindingObjListForEach
 */
static void
virNWFilterBindingObjListRemoveLocked(virNWFilterBindingObjList *bindings,
                                      virNWFilterBindingObj *binding)
{
    virNWFilterBindingDef *def = virNWFilterBindingObjGetDef(binding);
    virHashRemoveEntry(bindings->objs, def->portdevname);
}


/**
 * @bindings: Pointer to the binding object list
 * @binding: NWFilterBinding pointer from either after Add or FindBy* API where the
 *       @binding was successfully added to the bindings->objs
 *       hash tables that now would need to be removed.
 *
 * The caller must hold a lock on the driver owning 'bindings',
 * and must also have locked and ref counted 'binding', to ensure
 * no one else is either waiting for 'binding' or still using it.
 *
 * When this function returns, @binding will be removed from the hash
 * tables and returned with lock and refcnt that was present upon entry.
 */
void
virNWFilterBindingObjListRemove(virNWFilterBindingObjList *bindings,
                                virNWFilterBindingObj *binding)
{
    virNWFilterBindingObjSetRemoving(binding, true);
    virObjectRef(binding);
    virObjectUnlock(binding);
    virObjectRWLockWrite(bindings);
    virObjectLock(binding);
    virNWFilterBindingObjListRemoveLocked(bindings, binding);
    virObjectUnref(binding);
    virObjectRWUnlock(bindings);
}


static virNWFilterBindingObj *
virNWFilterBindingObjListLoadStatus(virNWFilterBindingObjList *bindings,
                                    const char *statusDir,
                                    const char *name)
{
    char *statusFile = NULL;
    virNWFilterBindingObj *obj = NULL;
    virNWFilterBindingDef *def;

    if ((statusFile = virNWFilterBindingObjConfigFile(statusDir, name)) == NULL)
        goto error;

    if (!(obj = virNWFilterBindingObjParse(statusFile)))
        goto error;

    def = virNWFilterBindingObjGetDef(obj);
    if (virHashLookup(bindings->objs, def->portdevname) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected binding %1$s already exists"),
                       def->portdevname);
        goto error;
    }

    if (virNWFilterBindingObjListAddObjLocked(bindings, obj) < 0)
        goto error;

    VIR_FREE(statusFile);
    return obj;

 error:
    virNWFilterBindingObjEndAPI(&obj);
    VIR_FREE(statusFile);
    return NULL;
}


int
virNWFilterBindingObjListLoadAllConfigs(virNWFilterBindingObjList *bindings,
                                        const char *configDir)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    VIR_INFO("Scanning for configs in %s", configDir);

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    virObjectRWLockWrite(bindings);

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNWFilterBindingObj *binding;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading config file '%s.xml'", entry->d_name);
        binding = virNWFilterBindingObjListLoadStatus(bindings,
                                                      configDir,
                                                      entry->d_name);
        if (binding)
            virNWFilterBindingObjEndAPI(&binding);
        else
            VIR_ERROR(_("Failed to load config for binding '%1$s'"), entry->d_name);
    }

    virObjectRWUnlock(bindings);
    return ret;
}


struct virNWFilterBindingListIterData {
    virNWFilterBindingObjListIterator callback;
    void *opaque;
    int ret;
};


static int
virNWFilterBindingObjListHelper(void *payload,
                                const char *name G_GNUC_UNUSED,
                                void *opaque)
{
    struct virNWFilterBindingListIterData *data = opaque;

    if (data->callback(payload, data->opaque) < 0)
        data->ret = -1;
    return 0;
}


int
virNWFilterBindingObjListForEach(virNWFilterBindingObjList *bindings,
                                 virNWFilterBindingObjListIterator callback,
                                 void *opaque)
{
    struct virNWFilterBindingListIterData data = {
        callback, opaque, 0,
    };
    virObjectRWLockRead(bindings);
    virHashForEachSafe(bindings->objs, virNWFilterBindingObjListHelper, &data);
    virObjectRWUnlock(bindings);
    return data.ret;
}


struct virNWFilterBindingListData {
    virNWFilterBindingObj **bindings;
    size_t nbindings;
};


static int
virNWFilterBindingObjListCollectIterator(void *payload,
                                         const char *name G_GNUC_UNUSED,
                                         void *opaque)
{
    struct virNWFilterBindingListData *data = opaque;

    data->bindings[data->nbindings++] = virObjectRef(payload);
    return 0;
}


static void
virNWFilterBindingObjListFilter(virNWFilterBindingObj ***list,
                                size_t *nbindings,
                                virConnectPtr conn,
                                virNWFilterBindingObjListACLFilter filter)
{
    size_t i = 0;

    while (i < *nbindings) {
        virNWFilterBindingObj *binding = (*list)[i];
        virNWFilterBindingDef *def;

        virObjectLock(binding);

        def = virNWFilterBindingObjGetDef(binding);
        /* do not list the object if:
         * 1) it's being removed.
         * 2) connection does not have ACL to see it
         * 3) it doesn't match the filter
         */
        if (virNWFilterBindingObjGetRemoving(binding) ||
            (filter && !filter(conn, def))) {
            virNWFilterBindingObjEndAPI(&binding);
            VIR_DELETE_ELEMENT(*list, i, *nbindings);
            continue;
        }

        virObjectUnlock(binding);
        i++;
    }
}


static int
virNWFilterBindingObjListCollect(virNWFilterBindingObjList *domlist,
                                 virConnectPtr conn,
                                 virNWFilterBindingObj ***bindings,
                                 size_t *nbindings,
                                 virNWFilterBindingObjListACLFilter filter)
{
    struct virNWFilterBindingListData data = { NULL, 0 };

    virObjectRWLockRead(domlist);
    data.bindings = g_new0(virNWFilterBindingObj *, virHashSize(domlist->objs));

    virHashForEach(domlist->objs, virNWFilterBindingObjListCollectIterator, &data);
    virObjectRWUnlock(domlist);

    virNWFilterBindingObjListFilter(&data.bindings, &data.nbindings, conn, filter);

    *nbindings = data.nbindings;
    *bindings = data.bindings;

    return 0;
}


int
virNWFilterBindingObjListExport(virNWFilterBindingObjList *bindings,
                                virConnectPtr conn,
                                virNWFilterBindingPtr **bindinglist,
                                virNWFilterBindingObjListACLFilter filter)
{
    virNWFilterBindingObj **bindingobjs = NULL;
    size_t nbindings = 0;
    size_t i;
    int ret = -1;

    if (virNWFilterBindingObjListCollect(bindings, conn, &bindingobjs,
                                         &nbindings, filter) < 0)
        return -1;

    if (bindinglist) {
        *bindinglist = g_new0(virNWFilterBindingPtr, nbindings + 1);

        for (i = 0; i < nbindings; i++) {
            virNWFilterBindingObj *binding = bindingobjs[i];
            virNWFilterBindingDef *def = virNWFilterBindingObjGetDef(binding);

            virObjectLock(binding);
            (*bindinglist)[i] = virGetNWFilterBinding(conn, def->portdevname,
                                                      def->filter);
            virObjectUnlock(binding);

            if (!(*bindinglist)[i])
                goto cleanup;
        }
    }

    ret = nbindings;

 cleanup:
    virObjectListFreeCount(bindingobjs, nbindings);
    if (ret < 0) {
        virObjectListFreeCount(*bindinglist, nbindings);
        *bindinglist = NULL;
    }
    return ret;
}
