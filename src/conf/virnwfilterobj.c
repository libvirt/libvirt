/*
 * virnwfilterobj.c: network filter object processing
 *                   (derived from nwfilter_conf.c)
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
#include <dirent.h>

#include "datatypes.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virlog.h"
#include "virnwfilterobj.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NWFILTER

VIR_LOG_INIT("conf.virnwfilterobj");

struct _virNWFilterObj {
    virMutex lock;

    bool wantRemoved;

    virNWFilterDef *def;
    virNWFilterDef *newDef;
};

struct _virNWFilterObjList {
    /* uuid string -> virNWFilterObj  mapping
     * for O(1), lookup-by-uuid */
    GHashTable *objs;

    /* name -> virNWFilterObj mapping for O(1),
     * lookup-by-name */
    GHashTable *objsName;
};

static virNWFilterObj *
virNWFilterObjNew(void)
{
    virNWFilterObj *obj;

    obj = g_new0(virNWFilterObj, 1);

    if (virMutexInitRecursive(&obj->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(obj);
        return NULL;
    }

    virNWFilterObjLock(obj);
    return obj;
}


virNWFilterDef *
virNWFilterObjGetDef(virNWFilterObj *obj)
{
    return obj->def;
}


virNWFilterDef *
virNWFilterObjGetNewDef(virNWFilterObj *obj)
{
    return obj->newDef;
}


bool
virNWFilterObjWantRemoved(virNWFilterObj *obj)
{
    return obj->wantRemoved;
}


static void
virNWFilterObjFree(virNWFilterObj *obj)
{
    if (!obj)
        return;

    virNWFilterDefFree(obj->def);
    virNWFilterDefFree(obj->newDef);

    virMutexDestroy(&obj->lock);

    g_free(obj);
}


void
virNWFilterObjListFree(virNWFilterObjList *nwfilters)
{
    if (!nwfilters)
        return;

    g_hash_table_unref(nwfilters->objs);
    g_hash_table_unref(nwfilters->objsName);
    g_free(nwfilters);
}


virNWFilterObjList *
virNWFilterObjListNew(void)
{
    virNWFilterObjList *nwfilters = g_new0(virNWFilterObjList, 1);

    /* virNWFilterObj is not ref counted, so we rely fact that
     * an instance will always exist in both hash tables, or
     * neither hash table. Thus we only need to have a destroy
     * callback for one of the two hash tables.
     */
    nwfilters->objs = virHashNew((GDestroyNotify)virNWFilterObjFree);
    nwfilters->objsName = virHashNew(NULL);

    return nwfilters;
}


void
virNWFilterObjListRemove(virNWFilterObjList *nwfilters,
                         virNWFilterObj *obj)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(obj->def->uuid, uuidstr);

    virNWFilterObjUnlock(obj);

    g_hash_table_remove(nwfilters->objsName, obj->def->name);
    g_hash_table_remove(nwfilters->objs, uuidstr);
}


virNWFilterObj *
virNWFilterObjListFindByUUID(virNWFilterObjList *nwfilters,
                             const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virNWFilterObj *obj;

    virUUIDFormat(uuid, uuidstr);

    obj = g_hash_table_lookup(nwfilters->objs, uuidstr);
    if (obj)
        virNWFilterObjLock(obj);

    return obj;
}


virNWFilterObj *
virNWFilterObjListFindByName(virNWFilterObjList *nwfilters,
                             const char *name)
{
    virNWFilterObj *obj;

    obj = g_hash_table_lookup(nwfilters->objsName, name);
    if (obj)
        virNWFilterObjLock(obj);

    return obj;
}


virNWFilterObj *
virNWFilterObjListFindInstantiateFilter(virNWFilterObjList *nwfilters,
                                        const char *filtername)
{
    virNWFilterObj *obj;

    if (!(obj = virNWFilterObjListFindByName(nwfilters, filtername))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("referenced filter '%1$s' is missing"), filtername);
        return NULL;
    }

    if (virNWFilterObjWantRemoved(obj)) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Filter '%1$s' is in use."), filtername);
        virNWFilterObjUnlock(obj);
        return NULL;
    }

    return obj;
}


static int
_virNWFilterObjListDefLoopDetect(virNWFilterObjList *nwfilters,
                                 virNWFilterDef *def,
                                 const char *filtername)
{
    int rc = 0;
    size_t i;
    virNWFilterEntry *entry;
    virNWFilterObj *obj;

    if (!def)
        return 0;

    for (i = 0; i < def->nentries; i++) {
        entry = def->filterEntries[i];
        if (entry->include) {

            if (STREQ(filtername, entry->include->filterref)) {
                rc = -1;
                break;
            }

            obj = virNWFilterObjListFindByName(nwfilters,
                                               entry->include->filterref);
            if (obj) {
                rc = _virNWFilterObjListDefLoopDetect(nwfilters, obj->def,
                                                      filtername);
                virNWFilterObjUnlock(obj);
                if (rc < 0)
                    break;
            }
        }
    }

    return rc;
}


/*
 * virNWFilterObjListDefLoopDetect:
 * @nwfilters : the nwfilters to search
 * @def : the filter definition that may add a loop and is to be tested
 *
 * Detect a loop introduced through the filters being able to
 * reference each other.
 *
 * Returns 0 in case no loop was detected, -1 otherwise.
 */
static int
virNWFilterObjListDefLoopDetect(virNWFilterObjList *nwfilters,
                                virNWFilterDef *def)
{
    return _virNWFilterObjListDefLoopDetect(nwfilters, def, def->name);
}


int
virNWFilterObjTestUnassignDef(virNWFilterObj *obj)
{
    int rc = 0;

    obj->wantRemoved = true;
    /* trigger the update on VMs referencing the filter */
    if (virNWFilterTriggerRebuild() < 0)
        rc = -1;

    obj->wantRemoved = false;

    return rc;
}


static bool
virNWFilterDefEqual(const virNWFilterDef *def1,
                    virNWFilterDef *def2)
{
    g_autofree char *xml1 = NULL;
    g_autofree char *xml2 = NULL;

    if (!(xml1 = virNWFilterDefFormat(def1)) ||
        !(xml2 = virNWFilterDefFormat(def2)))
        return false;

    return STREQ(xml1, xml2);
}


virNWFilterObj *
virNWFilterObjListAssignDef(virNWFilterObjList *nwfilters,
                            virNWFilterDef *def)
{
    virNWFilterObj *obj;
    virNWFilterDef *objdef;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if ((obj = virNWFilterObjListFindByUUID(nwfilters, def->uuid))) {
        objdef = obj->def;

        if (STRNEQ(def->name, objdef->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("filter with same UUID but different name ('%1$s') already exists"),
                           objdef->name);
            virNWFilterObjUnlock(obj);
            return NULL;
        }
        virNWFilterObjUnlock(obj);
    } else {
        if ((obj = virNWFilterObjListFindByName(nwfilters, def->name))) {
            objdef = obj->def;
            virUUIDFormat(objdef->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("filter '%1$s' already exists with uuid %2$s"),
                           def->name, uuidstr);
            virNWFilterObjUnlock(obj);
            return NULL;
        }
    }

    if (virNWFilterObjListDefLoopDetect(nwfilters, def) < 0) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       "%s", _("filter would introduce a loop"));
        return NULL;
    }


    if ((obj = virNWFilterObjListFindByName(nwfilters, def->name))) {

        objdef = obj->def;
        if (virNWFilterDefEqual(def, objdef)) {
            virNWFilterDefFree(objdef);
            obj->def = def;
            return obj;
        }

        obj->newDef = def;
        /* trigger the update on VMs referencing the filter */
        if (virNWFilterTriggerRebuild() < 0) {
            obj->newDef = NULL;
            virNWFilterObjUnlock(obj);
            return NULL;
        }

        virNWFilterDefFree(objdef);
        obj->def = def;
        obj->newDef = NULL;
        return obj;
    }

    if (!(obj = virNWFilterObjNew()))
        return NULL;

    virUUIDFormat(def->uuid, uuidstr);

    g_hash_table_insert(nwfilters->objs, g_strdup(uuidstr), obj);
    g_hash_table_insert(nwfilters->objsName, g_strdup(def->name), obj);

    obj->def = def;

    return obj;
}


struct virNWFilterObjListData {
    virNWFilterObjListFilter filter;
    virConnectPtr conn;
    int count;
};


static void
virNWFilterObjListCount(void *key G_GNUC_UNUSED,
                        void *payload,
                        void *opaque)
{
    virNWFilterObj *obj = payload;
    struct virNWFilterObjListData *data = opaque;
    VIR_LOCK_GUARD lock = virLockGuardLock(&obj->lock);

    if (data->filter(data->conn, obj->def))
        data->count++;
}


int
virNWFilterObjListNumOfNWFilters(virNWFilterObjList *nwfilters,
                                 virConnectPtr conn,
                                 virNWFilterObjListFilter filter)
{
    struct virNWFilterObjListData data = { filter, conn, 0 };

    g_hash_table_foreach(nwfilters->objs,
                         virNWFilterObjListCount,
                         &data);
    return data.count;
}


struct virNWFilterNameData {
    virNWFilterObjListFilter filter;
    virConnectPtr conn;
    int numnames;
    int maxnames;
    char **const names;
};


static void
virNWFilterObjListCopyNames(void *key G_GNUC_UNUSED,
                            void *payload,
                            void *opaque)
{
    virNWFilterObj *obj = payload;
    struct virNWFilterNameData *data = opaque;
    VIR_LOCK_GUARD lock = virLockGuardLock(&obj->lock);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        return;

    if (data->numnames < data->maxnames) {
        data->names[data->numnames] = g_strdup(obj->def->name);
        data->numnames++;
    }
}

int
virNWFilterObjListGetNames(virNWFilterObjList *nwfilters,
                           virConnectPtr conn,
                           virNWFilterObjListFilter filter,
                           char **const names,
                           int maxnames)
{
    struct virNWFilterNameData data =
        { filter, conn, 0, maxnames, names };

    g_hash_table_foreach(nwfilters->objs,
                         virNWFilterObjListCopyNames,
                         &data);

    return data.numnames;
}


struct virNWFilterListData {
    virNWFilterObj **filters;
    size_t nfilters;
};


static void
virNWFilterObjListCollectIterator(void *key G_GNUC_UNUSED,
                                  void *payload,
                                  void *opaque)
{
    struct virNWFilterListData *data = opaque;
    virNWFilterObj *obj = payload;

    virNWFilterObjLock(obj);
    data->filters[data->nfilters++] = obj;
}


static void
virNWFilterObjListFilterApply(virNWFilterObj ***list,
                              size_t *nfilters,
                              virConnectPtr conn,
                              virNWFilterObjListFilter filter)
{
    size_t i = 0;

    while (i < *nfilters) {
        virNWFilterObj *obj = (*list)[i];

        if (filter && !filter(conn, obj->def)) {
            VIR_DELETE_ELEMENT(*list, i, *nfilters);
            virNWFilterObjUnlock(obj);
            continue;
        }

        i++;
    }
}


static int
virNWFilterObjListCollect(virNWFilterObjList *nwfilters,
                          virConnectPtr conn,
                          virNWFilterObj ***filters,
                          size_t *nfilters,
                          virNWFilterObjListFilter filter)
{
    struct virNWFilterListData data = { NULL, 0 };

    data.filters = g_new0(virNWFilterObj *,
                          g_hash_table_size(nwfilters->objs));

    g_hash_table_foreach(nwfilters->objs,
                         virNWFilterObjListCollectIterator,
                         &data);

    virNWFilterObjListFilterApply(&data.filters, &data.nfilters, conn, filter);

    *nfilters = data.nfilters;
    *filters = data.filters;

    return 0;
}


int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjList *nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter filter)
{
    virNWFilterPtr *tmp_filters = NULL;
    virNWFilterObj **objs = NULL;
    size_t nfilters = 0;
    size_t i;
    int ret = -1;

    if (virNWFilterObjListCollect(nwfilters, conn, &objs, &nfilters, filter) < 0)
        return -1;

    if (!filters) {
        ret = nfilters;
        goto cleanup;
    }

    tmp_filters = g_new0(virNWFilterPtr, nfilters + 1);

    for (i = 0; i < nfilters; i++) {
        tmp_filters[i] = virGetNWFilter(conn, objs[i]->def->name, objs[i]->def->uuid);

        if (!tmp_filters[i])
            goto cleanup;
    }

    *filters = g_steal_pointer(&tmp_filters);
    ret = nfilters;

 cleanup:
    if (tmp_filters) {
        for (i = 0; i < nfilters; i++)
            virObjectUnref(tmp_filters[i]);
    }
    VIR_FREE(tmp_filters);
    for (i = 0; i < nfilters; i++)
        virNWFilterObjUnlock(objs[i]);
    return ret;
}


static virNWFilterObj *
virNWFilterObjListLoadConfig(virNWFilterObjList *nwfilters,
                             const char *configDir,
                             const char *name)
{
    virNWFilterDef *def = NULL;
    virNWFilterObj *obj;
    g_autofree char *configFile = NULL;

    if (!(configFile = virFileBuildPath(configDir, name, ".xml")))
        goto error;

    if (!(def = virNWFilterDefParse(NULL, configFile, 0)))
        goto error;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("network filter config filename '%1$s' does not match name '%2$s'"),
                       configFile, def->name);
        goto error;
    }

    /* We generated a UUID, make it permanent by saving the config to disk */
    if (!def->uuid_specified &&
        virNWFilterSaveConfig(configDir, def) < 0)
        goto error;

    if (!(obj = virNWFilterObjListAssignDef(nwfilters, def)))
        goto error;

    return obj;

 error:
    virNWFilterDefFree(def);
    return NULL;
}


int
virNWFilterObjListLoadAllConfigs(virNWFilterObjList *nwfilters,
                                 const char *configDir)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNWFilterObj *obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        obj = virNWFilterObjListLoadConfig(nwfilters, configDir, entry->d_name);
        if (obj)
            virNWFilterObjUnlock(obj);
    }

    return ret;
}


void
virNWFilterObjLock(virNWFilterObj *obj)
{
    virMutexLock(&obj->lock);
}


void
virNWFilterObjUnlock(virNWFilterObj *obj)
{
    virMutexUnlock(&obj->lock);
}
