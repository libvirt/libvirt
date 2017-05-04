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

    virNWFilterDefPtr def;
    virNWFilterDefPtr newDef;
};

struct _virNWFilterObjList {
    size_t count;
    virNWFilterObjPtr *objs;
};


static virNWFilterObjPtr
virNWFilterObjNew(void)
{
    virNWFilterObjPtr obj;

    if (VIR_ALLOC(obj) < 0)
        return NULL;

    if (virMutexInitRecursive(&obj->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(obj);
        return NULL;
    }

    virNWFilterObjLock(obj);
    return obj;
}


virNWFilterDefPtr
virNWFilterObjGetDef(virNWFilterObjPtr obj)
{
    return obj->def;
}


virNWFilterDefPtr
virNWFilterObjGetNewDef(virNWFilterObjPtr obj)
{
    return obj->newDef;
}


bool
virNWFilterObjWantRemoved(virNWFilterObjPtr obj)
{
    return obj->wantRemoved;
}


static void
virNWFilterObjFree(virNWFilterObjPtr obj)
{
    if (!obj)
        return;

    virNWFilterDefFree(obj->def);
    virNWFilterDefFree(obj->newDef);

    virMutexDestroy(&obj->lock);

    VIR_FREE(obj);
}


void
virNWFilterObjListFree(virNWFilterObjListPtr nwfilters)
{
    size_t i;
    for (i = 0; i < nwfilters->count; i++)
        virNWFilterObjFree(nwfilters->objs[i]);
    VIR_FREE(nwfilters->objs);
    VIR_FREE(nwfilters);
}


virNWFilterObjListPtr
virNWFilterObjListNew(void)
{
    virNWFilterObjListPtr nwfilters;

    if (VIR_ALLOC(nwfilters) < 0)
        return NULL;
    return nwfilters;
}


void
virNWFilterObjListRemove(virNWFilterObjListPtr nwfilters,
                         virNWFilterObjPtr obj)
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


virNWFilterObjPtr
virNWFilterObjListFindByUUID(virNWFilterObjListPtr nwfilters,
                             const unsigned char *uuid)
{
    size_t i;
    virNWFilterObjPtr obj;
    virNWFilterDefPtr def;

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


virNWFilterObjPtr
virNWFilterObjListFindByName(virNWFilterObjListPtr nwfilters,
                             const char *name)
{
    size_t i;
    virNWFilterObjPtr obj;
    virNWFilterDefPtr def;

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


static int
_virNWFilterObjListDefLoopDetect(virNWFilterObjListPtr nwfilters,
                                 virNWFilterDefPtr def,
                                 const char *filtername)
{
    int rc = 0;
    size_t i;
    virNWFilterEntryPtr entry;
    virNWFilterObjPtr obj;

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
virNWFilterObjListDefLoopDetect(virNWFilterObjListPtr nwfilters,
                                virNWFilterDefPtr def)
{
    return _virNWFilterObjListDefLoopDetect(nwfilters, def, def->name);
}


int
virNWFilterObjTestUnassignDef(virNWFilterObjPtr obj)
{
    int rc = 0;

    obj->wantRemoved = true;
    /* trigger the update on VMs referencing the filter */
    if (virNWFilterTriggerVMFilterRebuild())
        rc = -1;

    obj->wantRemoved = false;

    return rc;
}


static bool
virNWFilterDefEqual(const virNWFilterDef *def1,
                    virNWFilterDefPtr def2,
                    bool cmpUUIDs)
{
    bool ret = false;
    unsigned char rem_uuid[VIR_UUID_BUFLEN];
    char *xml1, *xml2 = NULL;

    if (!cmpUUIDs) {
        /* make sure the UUIDs are equal */
        memcpy(rem_uuid, def2->uuid, sizeof(rem_uuid));
        memcpy(def2->uuid, def1->uuid, sizeof(def2->uuid));
    }

    if (!(xml1 = virNWFilterDefFormat(def1)) ||
        !(xml2 = virNWFilterDefFormat(def2)))
        goto cleanup;

    ret = STREQ(xml1, xml2);

 cleanup:
    if (!cmpUUIDs)
        memcpy(def2->uuid, rem_uuid, sizeof(rem_uuid));

    VIR_FREE(xml1);
    VIR_FREE(xml2);

    return ret;
}


virNWFilterObjPtr
virNWFilterObjListAssignDef(virNWFilterObjListPtr nwfilters,
                            virNWFilterDefPtr def)
{
    virNWFilterObjPtr obj;
    virNWFilterDefPtr objdef;

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
        if (virNWFilterDefEqual(def, objdef, false)) {
            virNWFilterDefFree(objdef);
            obj->def = def;
            return obj;
        }

        obj->newDef = def;
        /* trigger the update on VMs referencing the filter */
        if (virNWFilterTriggerVMFilterRebuild()) {
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

    if (VIR_APPEND_ELEMENT_COPY(nwfilters->objs,
                                nwfilters->count, obj) < 0) {
        virNWFilterObjUnlock(obj);
        virNWFilterObjFree(obj);
        return NULL;
    }
    obj->def = def;

    return obj;
}


int
virNWFilterObjListNumOfNWFilters(virNWFilterObjListPtr nwfilters,
                                 virConnectPtr conn,
                                 virNWFilterObjListFilter aclfilter)
{
    size_t i;
    int nfilters = 0;

    for (i = 0; i < nwfilters->count; i++) {
        virNWFilterObjPtr obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        if (!aclfilter || aclfilter(conn, obj->def))
            nfilters++;
        virNWFilterObjUnlock(obj);
    }

    return nfilters;
}


int
virNWFilterObjListGetNames(virNWFilterObjListPtr nwfilters,
                           virConnectPtr conn,
                           virNWFilterObjListFilter aclfilter,
                           char **const names,
                           int maxnames)
{
    int nnames = 0;
    size_t i;
    virNWFilterDefPtr def;

    for (i = 0; i < nwfilters->count && nnames < maxnames; i++) {
        virNWFilterObjPtr obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (!aclfilter || aclfilter(conn, def)) {
            if (VIR_STRDUP(names[nnames], def->name) < 0) {
                virNWFilterObjUnlock(obj);
                goto failure;
            }
            nnames++;
        }
        virNWFilterObjUnlock(obj);
    }

    return nnames;

 failure:
    while (--nnames >= 0)
        VIR_FREE(names[nnames]);

    return -1;
}


int
virNWFilterObjListExport(virConnectPtr conn,
                         virNWFilterObjListPtr nwfilters,
                         virNWFilterPtr **filters,
                         virNWFilterObjListFilter aclfilter)
{
    virNWFilterPtr *tmp_filters = NULL;
    int nfilters = 0;
    virNWFilterPtr filter = NULL;
    virNWFilterObjPtr obj = NULL;
    virNWFilterDefPtr def;
    size_t i;
    int ret = -1;

    if (!filters) {
        ret = nwfilters->count;
        goto cleanup;
    }

    if (VIR_ALLOC_N(tmp_filters, nwfilters->count + 1) < 0)
        goto cleanup;

    for (i = 0; i < nwfilters->count; i++) {
        obj = nwfilters->objs[i];
        virNWFilterObjLock(obj);
        def = obj->def;
        if (!aclfilter || aclfilter(conn, def)) {
            if (!(filter = virGetNWFilter(conn, def->name, def->uuid))) {
                virNWFilterObjUnlock(obj);
                goto cleanup;
            }
            tmp_filters[nfilters++] = filter;
        }
        virNWFilterObjUnlock(obj);
    }

    *filters = tmp_filters;
    tmp_filters = NULL;
    ret = nfilters;

 cleanup:
    if (tmp_filters) {
        for (i = 0; i < nfilters; i ++)
            virObjectUnref(tmp_filters[i]);
    }
    VIR_FREE(tmp_filters);

    return ret;
}


static virNWFilterObjPtr
virNWFilterObjListLoadConfig(virNWFilterObjListPtr nwfilters,
                             const char *configDir,
                             const char *name)
{
    virNWFilterDefPtr def = NULL;
    virNWFilterObjPtr obj;
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

    if (!(obj = virNWFilterObjListAssignDef(nwfilters, def)))
        goto error;

    /* We generated a UUID, make it permanent by saving the config to disk */
    if (!def->uuid_specified &&
        virNWFilterSaveConfig(configDir, def) < 0)
        goto error;

    VIR_FREE(configFile);
    return obj;

 error:
    VIR_FREE(configFile);
    virNWFilterDefFree(def);
    return NULL;
}


int
virNWFilterObjListLoadAllConfigs(virNWFilterObjListPtr nwfilters,
                                 const char *configDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNWFilterObjPtr obj;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        obj = virNWFilterObjListLoadConfig(nwfilters, configDir, entry->d_name);
        if (obj)
            virNWFilterObjUnlock(obj);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


void
virNWFilterObjLock(virNWFilterObjPtr obj)
{
    virMutexLock(&obj->lock);
}


void
virNWFilterObjUnlock(virNWFilterObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}
