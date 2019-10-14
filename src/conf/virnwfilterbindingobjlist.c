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

static virClassPtr virNWFilterBindingObjListClass;
static void virNWFilterBindingObjListDispose(void *obj);

struct _virNWFilterBindingObjList {
    virObjectRWLockable parent;

    /* port dev name -> virNWFilterBindingObj  mapping
     * for O(1), lockless lookup-by-port dev */
    virHashTable *objs;
};


static int virNWFilterBindingObjListOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNWFilterBindingObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNWFilterBindingObjList);


virNWFilterBindingObjListPtr
virNWFilterBindingObjListNew(void)
{
    virNWFilterBindingObjListPtr bindings;

    if (virNWFilterBindingObjListInitialize() < 0)
        return NULL;

    if (!(bindings = virObjectRWLockableNew(virNWFilterBindingObjListClass)))
        return NULL;

    if (!(bindings->objs = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(bindings);
        return NULL;
    }

    return bindings;
}


static void
virNWFilterBindingObjListDispose(void *obj)
{
    virNWFilterBindingObjListPtr bindings = obj;

    virHashFree(bindings->objs);
}


static virNWFilterBindingObjPtr
virNWFilterBindingObjListFindByPortDevLocked(virNWFilterBindingObjListPtr bindings,
                                             const char *name)
{
    virNWFilterBindingObjPtr obj;

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
virNWFilterBindingObjPtr
virNWFilterBindingObjListFindByPortDev(virNWFilterBindingObjListPtr bindings,
                                       const char *name)
{
    virNWFilterBindingObjPtr obj;

    virObjectRWLockRead(bindings);
    obj = virNWFilterBindingObjListFindByPortDevLocked(bindings, name);
    virObjectRWUnlock(bindings);

    if (obj && virNWFilterBindingObjGetRemoving(obj)) {
        virObjectUnlock(obj);
        virObjectUnref(obj);
        obj = NULL;
    }

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
 * configured to call virObjectFreeHashData when the object is
 * removed from the hash table.
 *
 * Returns 0 on success with 2 references and locked
 *        -1 on failure with 1 reference and locked
 */
static int
virNWFilterBindingObjListAddObjLocked(virNWFilterBindingObjListPtr bindings,
                                      virNWFilterBindingObjPtr binding)
{
    virNWFilterBindingDefPtr def = virNWFilterBindingObjGetDef(binding);
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
static virNWFilterBindingObjPtr
virNWFilterBindingObjListAddLocked(virNWFilterBindingObjListPtr bindings,
                                   virNWFilterBindingDefPtr def)
{
    virNWFilterBindingObjPtr binding;
    bool stealDef = false;

    /* See if a binding with matching portdev already exists */
    binding = virNWFilterBindingObjListFindByPortDevLocked(bindings, def->portdevname);
    if (binding) {
        if (virNWFilterBindingObjGetRemoving(binding)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("binding '%s' is already being removed"),
                           def->portdevname);
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("binding '%s' already exists"),
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


virNWFilterBindingObjPtr
virNWFilterBindingObjListAdd(virNWFilterBindingObjListPtr bindings,
                             virNWFilterBindingDefPtr def)
{
    virNWFilterBindingObjPtr ret;

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
virNWFilterBindingObjListRemoveLocked(virNWFilterBindingObjListPtr bindings,
                                      virNWFilterBindingObjPtr binding)
{
    virNWFilterBindingDefPtr def = virNWFilterBindingObjGetDef(binding);
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
virNWFilterBindingObjListRemove(virNWFilterBindingObjListPtr bindings,
                                virNWFilterBindingObjPtr binding)
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


static virNWFilterBindingObjPtr
virNWFilterBindingObjListLoadStatus(virNWFilterBindingObjListPtr bindings,
                                    const char *statusDir,
                                    const char *name)
{
    char *statusFile = NULL;
    virNWFilterBindingObjPtr obj = NULL;
    virNWFilterBindingDefPtr def;

    if ((statusFile = virNWFilterBindingObjConfigFile(statusDir, name)) == NULL)
        goto error;

    if (!(obj = virNWFilterBindingObjParseFile(statusFile)))
        goto error;

    def = virNWFilterBindingObjGetDef(obj);
    if (virHashLookup(bindings->objs, def->portdevname) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected binding %s already exists"),
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
virNWFilterBindingObjListLoadAllConfigs(virNWFilterBindingObjListPtr bindings,
                                        const char *configDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    VIR_INFO("Scanning for configs in %s", configDir);

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    virObjectRWLockWrite(bindings);

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNWFilterBindingObjPtr binding;

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
            VIR_ERROR(_("Failed to load config for binding '%s'"), entry->d_name);
    }

    VIR_DIR_CLOSE(dir);
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
                                const void *name G_GNUC_UNUSED,
                                void *opaque)
{
    struct virNWFilterBindingListIterData *data = opaque;

    if (data->callback(payload, data->opaque) < 0)
        data->ret = -1;
    return 0;
}


int
virNWFilterBindingObjListForEach(virNWFilterBindingObjListPtr bindings,
                                 virNWFilterBindingObjListIterator callback,
                                 void *opaque)
{
    struct virNWFilterBindingListIterData data = {
        callback, opaque, 0,
    };
    virObjectRWLockRead(bindings);
    virHashForEach(bindings->objs, virNWFilterBindingObjListHelper, &data);
    virObjectRWUnlock(bindings);
    return data.ret;
}


struct virNWFilterBindingListData {
    virNWFilterBindingObjPtr *bindings;
    size_t nbindings;
};


static int
virNWFilterBindingObjListCollectIterator(void *payload,
                                         const void *name G_GNUC_UNUSED,
                                         void *opaque)
{
    struct virNWFilterBindingListData *data = opaque;

    data->bindings[data->nbindings++] = virObjectRef(payload);
    return 0;
}


static void
virNWFilterBindingObjListFilter(virNWFilterBindingObjPtr **list,
                                size_t *nbindings,
                                virConnectPtr conn,
                                virNWFilterBindingObjListACLFilter filter)
{
    size_t i = 0;

    while (i < *nbindings) {
        virNWFilterBindingObjPtr binding = (*list)[i];
        virNWFilterBindingDefPtr def;

        virObjectLock(binding);

        def = virNWFilterBindingObjGetDef(binding);
        /* do not list the object if:
         * 1) it's being removed.
         * 2) connection does not have ACL to see it
         * 3) it doesn't match the filter
         */
        if (virNWFilterBindingObjGetRemoving(binding) ||
            (filter && !filter(conn, def))) {
            virObjectUnlock(binding);
            virObjectUnref(binding);
            VIR_DELETE_ELEMENT(*list, i, *nbindings);
            continue;
        }

        virObjectUnlock(binding);
        i++;
    }
}


static int
virNWFilterBindingObjListCollect(virNWFilterBindingObjListPtr domlist,
                                 virConnectPtr conn,
                                 virNWFilterBindingObjPtr **bindings,
                                 size_t *nbindings,
                                 virNWFilterBindingObjListACLFilter filter)
{
    struct virNWFilterBindingListData data = { NULL, 0 };

    virObjectRWLockRead(domlist);
    sa_assert(domlist->objs);
    if (VIR_ALLOC_N(data.bindings, virHashSize(domlist->objs)) < 0) {
        virObjectRWUnlock(domlist);
        return -1;
    }

    virHashForEach(domlist->objs, virNWFilterBindingObjListCollectIterator, &data);
    virObjectRWUnlock(domlist);

    virNWFilterBindingObjListFilter(&data.bindings, &data.nbindings, conn, filter);

    *nbindings = data.nbindings;
    *bindings = data.bindings;

    return 0;
}


int
virNWFilterBindingObjListExport(virNWFilterBindingObjListPtr bindings,
                                virConnectPtr conn,
                                virNWFilterBindingPtr **bindinglist,
                                virNWFilterBindingObjListACLFilter filter)
{
    virNWFilterBindingObjPtr *bindingobjs = NULL;
    size_t nbindings = 0;
    size_t i;
    int ret = -1;

    if (virNWFilterBindingObjListCollect(bindings, conn, &bindingobjs,
                                         &nbindings, filter) < 0)
        return -1;

    if (bindinglist) {
        if (VIR_ALLOC_N(*bindinglist, nbindings + 1) < 0)
            goto cleanup;

        for (i = 0; i < nbindings; i++) {
            virNWFilterBindingObjPtr binding = bindingobjs[i];
            virNWFilterBindingDefPtr def = virNWFilterBindingObjGetDef(binding);

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
