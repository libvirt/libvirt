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
    size_t count;
    virNWFilterObj **objs;
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
    size_t i;
    for (i = 0; i < nwfilters->count; i++)
        virNWFilterObjFree(nwfilters->objs[i]);
    g_free(nwfilters->objs);
    g_free(nwfilters);
}


virNWFilterObjList *
virNWFilterObjListNew(void)
{
    return g_new0(virNWFilterObjList, 1);
}


void
virNWFilterObjListRemove(virNWFilterObjList *nwfilters,
                         virNWFilterObj *obj)
{
    size_t i;

    virNWFilterObjUnlock(obj);

    for (i = 0; i < nwfilters->count; i++) {
        virNWFilterObjLock(nwfilters->objs[i]);
        if (nwfilters->objs[i] == obj) {
            virNWFilterObjUnlock(nwfilters->objs[i]);
            virNWFilterObjFree(nwfilters->objs[i]);

            VIR_DELETE_ELEMENT(nwfilters->objs, i, nwfilters->count);
            break;
        }
        virNWFilterObjUnlock(nwfilters->objs[i]);
    }
}


virNWFilterObj *
virNWFilterObjListFindByUUID(virNWFilterObjList *nwfilters,
                             const unsigned char *uuid)
{
    size_t i;
    virNWFilterObj *obj;
    virNWFilterDef *def;

    for (i = 0; i < nwfilters->count; i++) {
        obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (!memcmp(def->uuid, uuid, VIR_UUID_BUFLEN))
            return obj;
        virNWFilterObjUnlock(obj);
    }

    return NULL;
}


virNWFilterObj *
virNWFilterObjListFindByName(virNWFilterObjList *nwfilters,
                             const char *name)
{
    size_t i;
    virNWFilterObj *obj;
    virNWFilterDef *def;

    for (i = 0; i < nwfilters->count; i++) {
        obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (STREQ_NULLABLE(def->name, name))
            return obj;
        virNWFilterObjUnlock(obj);
    }

    return NULL;
}


virNWFilterObj *
virNWFilterObjListFindInstantiateFilter(virNWFilterObjList *nwfilters,
                                        const char *filtername)
{
    virNWFilterObj *obj;

    if (!(obj = virNWFilterObjListFindByName(nwfilters, filtername))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("referenced filter '%s' is missing"), filtername);
        return NULL;
    }

    if (virNWFilterObjWantRemoved(obj)) {
        virReportError(VIR_ERR_NO_NWFILTER,
                       _("Filter '%s' is in use."), filtername);
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
    bool ret = false;
    char *xml1 = NULL;
    char *xml2 = NULL;

    if (!(xml1 = virNWFilterDefFormat(def1)) ||
        !(xml2 = virNWFilterDefFormat(def2)))
        goto cleanup;

    ret = STREQ(xml1, xml2);

 cleanup:
    VIR_FREE(xml1);
    VIR_FREE(xml2);

    return ret;
}


virNWFilterObj *
virNWFilterObjListAssignDef(virNWFilterObjList *nwfilters,
                            virNWFilterDef *def)
{
    virNWFilterObj *obj;
    virNWFilterDef *objdef;

    if ((obj = virNWFilterObjListFindByUUID(nwfilters, def->uuid))) {
        objdef = obj->def;

        if (STRNEQ(def->name, objdef->name)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("filter with same UUID but different name "
                             "('%s') already exists"),
                           objdef->name);
            virNWFilterObjUnlock(obj);
            return NULL;
        }
        virNWFilterObjUnlock(obj);
    } else {
        if ((obj = virNWFilterObjListFindByName(nwfilters, def->name))) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            objdef = obj->def;
            virUUIDFormat(objdef->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("filter '%s' already exists with uuid %s"),
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

    VIR_APPEND_ELEMENT_COPY(nwfilters->objs, nwfilters->count, obj);

    obj->def = def;

    return obj;
}


int
virNWFilterObjListNumOfNWFilters(virNWFilterObjList *nwfilters,
                                 virConnectPtr conn,
                                 virNWFilterObjListFilter filter)
{
    size_t i;
    int nfilters = 0;

    for (i = 0; i < nwfilters->count; i++) {
        virNWFilterObj *obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        if (!filter || filter(conn, obj->def))
            nfilters++;
        virNWFilterObjUnlock(obj);
    }

    return nfilters;
}


int
virNWFilterObjListGetNames(virNWFilterObjList *nwfilters,
                           virConnectPtr conn,
                           virNWFilterObjListFilter filter,
                           char **const names,
                           int maxnames)
{
    int nnames = 0;
    size_t i;
    virNWFilterDef *def;

    for (i = 0; i < nwfilters->count && nnames < maxnames; i++) {
        virNWFilterObj *obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (!filter || filter(conn, def)) {
            names[nnames] = g_strdup(def->name);
            nnames++;
        }
        virNWFilterObjUnlock(obj);
    }

    return nnames;
}


int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjList *nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter filter)
{
    virNWFilterPtr *tmp_filters = NULL;
    int nfilters = 0;
    virNWFilterPtr nwfilter = NULL;
    virNWFilterObj *obj = NULL;
    virNWFilterDef *def;
    size_t i;
    int ret = -1;

    if (!filters) {
        ret = nwfilters->count;
        goto cleanup;
    }

    tmp_filters = g_new0(virNWFilterPtr, nwfilters->count + 1);

    for (i = 0; i < nwfilters->count; i++) {
        obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (!filter || filter(conn, def)) {
            if (!(nwfilter = virGetNWFilter(conn, def->name, def->uuid))) {
                virNWFilterObjUnlock(obj);
                goto cleanup;
            }
            tmp_filters[nfilters++] = nwfilter;
        }
        virNWFilterObjUnlock(obj);
    }

    *filters = g_steal_pointer(&tmp_filters);
    ret = nfilters;

 cleanup:
    if (tmp_filters) {
        for (i = 0; i < nfilters; i ++)
            virObjectUnref(tmp_filters[i]);
    }
    VIR_FREE(tmp_filters);

    return ret;
}


static virNWFilterObj *
virNWFilterObjListLoadConfig(virNWFilterObjList *nwfilters,
                             const char *configDir,
                             const char *name)
{
    virNWFilterDef *def = NULL;
    virNWFilterObj *obj;
    char *configFile = NULL;

    if (!(configFile = virFileBuildPath(configDir, name, ".xml")))
        goto error;

    if (!(def = virNWFilterDefParseFile(configFile)))
        goto error;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("network filter config filename '%s' "
                         "does not match name '%s'"),
                       configFile, def->name);
        goto error;
    }

    /* We generated a UUID, make it permanent by saving the config to disk */
    if (!def->uuid_specified &&
        virNWFilterSaveConfig(configDir, def) < 0)
        goto error;

    if (!(obj = virNWFilterObjListAssignDef(nwfilters, def)))
        goto error;

    VIR_FREE(configFile);
    return obj;

 error:
    VIR_FREE(configFile);
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
