/*
 * virdomainobjlist.c: domain objects list utilities
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
 * Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "snapshot_conf.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.virdomainobjlist");

static virClassPtr virDomainObjListClass;
static void virDomainObjListDispose(void *obj);


struct _virDomainObjList {
    virObjectRWLockable parent;

    /* uuid string -> virDomainObj  mapping
     * for O(1), lockless lookup-by-uuid */
    virHashTable *objs;

    /* name -> virDomainObj mapping for O(1),
     * lockless lookup-by-name */
    virHashTable *objsName;
};


static int virDomainObjListOnceInit(void)
{
    if (!(virDomainObjListClass = virClassNew(virClassForObjectRWLockable(),
                                              "virDomainObjList",
                                              sizeof(virDomainObjList),
                                              virDomainObjListDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainObjList)

virDomainObjListPtr virDomainObjListNew(void)
{
    virDomainObjListPtr doms;

    if (virDomainObjListInitialize() < 0)
        return NULL;

    if (!(doms = virObjectRWLockableNew(virDomainObjListClass)))
        return NULL;

    if (!(doms->objs = virHashCreate(50, virObjectFreeHashData)) ||
        !(doms->objsName = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(doms);
        return NULL;
    }

    return doms;
}


static void virDomainObjListDispose(void *obj)
{
    virDomainObjListPtr doms = obj;

    virHashFree(doms->objs);
    virHashFree(doms->objsName);
}


static int virDomainObjListSearchID(const void *payload,
                                    const void *name ATTRIBUTE_UNUSED,
                                    const void *data)
{
    virDomainObjPtr obj = (virDomainObjPtr)payload;
    const int *id = data;
    int want = 0;

    virObjectLock(obj);
    if (virDomainObjIsActive(obj) &&
        obj->def->id == *id)
        want = 1;
    virObjectUnlock(obj);
    return want;
}

static virDomainObjPtr
virDomainObjListFindByIDInternal(virDomainObjListPtr doms,
                                 int id,
                                 bool ref)
{
    virDomainObjPtr obj;
    virObjectRWLockRead(doms);
    obj = virHashSearch(doms->objs, virDomainObjListSearchID, &id, NULL);
    if (ref) {
        virObjectRef(obj);
        virObjectUnlock(doms);
    }
    if (obj) {
        virObjectLock(obj);
        if (obj->removing) {
            virObjectUnlock(obj);
            if (ref)
                virObjectUnref(obj);
            obj = NULL;
        }
    }
    if (!ref)
        virObjectUnlock(doms);
    return obj;
}

virDomainObjPtr
virDomainObjListFindByID(virDomainObjListPtr doms,
                         int id)
{
    return virDomainObjListFindByIDInternal(doms, id, false);
}

virDomainObjPtr
virDomainObjListFindByIDRef(virDomainObjListPtr doms,
                            int id)
{
    return virDomainObjListFindByIDInternal(doms, id, true);
}

static virDomainObjPtr
virDomainObjListFindByUUIDInternal(virDomainObjListPtr doms,
                                   const unsigned char *uuid,
                                   bool ref)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr obj;

    virObjectRWLockRead(doms);
    virUUIDFormat(uuid, uuidstr);

    obj = virHashLookup(doms->objs, uuidstr);
    if (ref) {
        virObjectRef(obj);
        virObjectUnlock(doms);
    }
    if (obj) {
        virObjectLock(obj);
        if (obj->removing) {
            virObjectUnlock(obj);
            if (ref)
                virObjectUnref(obj);
            obj = NULL;
        }
    }
    if (!ref)
        virObjectUnlock(doms);
    return obj;
}


virDomainObjPtr
virDomainObjListFindByUUID(virDomainObjListPtr doms,
                           const unsigned char *uuid)
{
    return virDomainObjListFindByUUIDInternal(doms, uuid, false);
}


virDomainObjPtr
virDomainObjListFindByUUIDRef(virDomainObjListPtr doms,
                              const unsigned char *uuid)
{
    return virDomainObjListFindByUUIDInternal(doms, uuid, true);
}


virDomainObjPtr virDomainObjListFindByName(virDomainObjListPtr doms,
                                           const char *name)
{
    virDomainObjPtr obj;

    virObjectRWLockRead(doms);
    obj = virHashLookup(doms->objsName, name);
    virObjectRef(obj);
    virObjectUnlock(doms);
    if (obj) {
        virObjectLock(obj);
        if (obj->removing) {
            virObjectUnlock(obj);
            virObjectUnref(obj);
            obj = NULL;
        }
    }
    return obj;
}


/*
 * virDomainObjListAddLocked:
 *
 * If flags & VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE then
 * this will refuse updating an existing def if the
 * current def is Live
 *
 * If flags & VIR_DOMAIN_OBJ_LIST_ADD_LIVE then
 * the @def being added is assumed to represent a
 * live config, not a future inactive config
 *
 */
static virDomainObjPtr
virDomainObjListAddLocked(virDomainObjListPtr doms,
                          virDomainDefPtr def,
                          virDomainXMLOptionPtr xmlopt,
                          unsigned int flags,
                          virDomainDefPtr *oldDef)
{
    virDomainObjPtr vm;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (oldDef)
        *oldDef = NULL;

    virUUIDFormat(def->uuid, uuidstr);

    /* See if a VM with matching UUID already exists */
    if ((vm = virHashLookup(doms->objs, uuidstr))) {
        virObjectLock(vm);
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%s' is already defined with uuid %s"),
                           vm->def->name, uuidstr);
            goto error;
        }

        if (flags & VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE) {
            /* UUID & name match, but if VM is already active, refuse it */
            if (virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("domain '%s' is already active"),
                               vm->def->name);
                goto error;
            }
            if (!vm->persistent) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("domain '%s' is already being started"),
                               vm->def->name);
                goto error;
            }
        }

        virDomainObjAssignDef(vm,
                              def,
                              !!(flags & VIR_DOMAIN_OBJ_LIST_ADD_LIVE),
                              oldDef);
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        if ((vm = virHashLookup(doms->objsName, def->name))) {
            virObjectLock(vm);
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto error;
        }

        if (!(vm = virDomainObjNew(xmlopt)))
            goto cleanup;
        vm->def = def;

        virUUIDFormat(def->uuid, uuidstr);
        if (virHashAddEntry(doms->objs, uuidstr, vm) < 0) {
            virObjectUnref(vm);
            return NULL;
        }

        if (virHashAddEntry(doms->objsName, def->name, vm) < 0) {
            virHashRemoveEntry(doms->objs, uuidstr);
            return NULL;
        }

        /* Since domain is in two hash tables, increment the
         * reference counter */
        virObjectRef(vm);
    }
 cleanup:
    return vm;

 error:
    virObjectUnlock(vm);
    vm = NULL;
    goto cleanup;
}


virDomainObjPtr virDomainObjListAdd(virDomainObjListPtr doms,
                                    virDomainDefPtr def,
                                    virDomainXMLOptionPtr xmlopt,
                                    unsigned int flags,
                                    virDomainDefPtr *oldDef)
{
    virDomainObjPtr ret;

    virObjectLock(doms);
    ret = virDomainObjListAddLocked(doms, def, xmlopt, flags, oldDef);
    virObjectUnlock(doms);
    return ret;
}


/*
 * The caller must hold a lock on the driver owning 'doms',
 * and must also have locked 'dom', to ensure no one else
 * is either waiting for 'dom' or still using it
 */
void virDomainObjListRemove(virDomainObjListPtr doms,
                            virDomainObjPtr dom)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    dom->removing = true;
    virUUIDFormat(dom->def->uuid, uuidstr);
    virObjectRef(dom);
    virObjectUnlock(dom);

    virObjectLock(doms);
    virObjectLock(dom);
    virHashRemoveEntry(doms->objs, uuidstr);
    virHashRemoveEntry(doms->objsName, dom->def->name);
    virObjectUnlock(dom);
    virObjectUnref(dom);
    virObjectUnlock(doms);
}


/**
 * virDomainObjListRename:
 *
 * The caller must hold a lock on dom. Callbacks should not
 * sleep/wait otherwise operations on all domains will be blocked
 * as the callback is called with domains lock hold. Domain lock
 * is dropped/reacquired during this operation thus domain
 * consistency must not rely on this lock solely.
 */
int
virDomainObjListRename(virDomainObjListPtr doms,
                       virDomainObjPtr dom,
                       const char *new_name,
                       unsigned int flags,
                       virDomainObjListRenameCallback callback,
                       void *opaque)
{
    int ret = -1;
    char *old_name = NULL;
    int rc;

    if (STREQ(dom->def->name, new_name)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Can't rename domain to itself"));
        return ret;
    }

    if (VIR_STRDUP(old_name, dom->def->name) < 0)
        return ret;

    /* doms and dom locks must be attained in right order thus relock dom. */
    /* dom reference is touched for the benefit of those callers that
     * hold a lock on dom but not refcount it. */
    virObjectRef(dom);
    virObjectUnlock(dom);
    virObjectLock(doms);
    virObjectLock(dom);
    virObjectUnref(dom);

    if (virHashLookup(doms->objsName, new_name) != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain with name '%s' already exists"),
                       new_name);
        goto cleanup;
    }

    if (virHashAddEntry(doms->objsName, new_name, dom) < 0)
        goto cleanup;

    /* Okay, this is crazy. virHashAddEntry() does not increment
     * the refcounter of @dom, but virHashRemoveEntry() does
     * decrement it. We need to work around it. */
    virObjectRef(dom);

    rc = callback(dom, new_name, flags, opaque);
    virHashRemoveEntry(doms->objsName, rc < 0 ? new_name : old_name);
    if (rc < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virObjectUnlock(doms);
    VIR_FREE(old_name);
    return ret;
}

/* The caller must hold lock on 'doms' in addition to 'virDomainObjListRemove'
 * requirements
 *
 * Can be used to remove current element while iterating with
 * virDomainObjListForEach
 */
void virDomainObjListRemoveLocked(virDomainObjListPtr doms,
                                  virDomainObjPtr dom)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(dom->def->uuid, uuidstr);

    virHashRemoveEntry(doms->objs, uuidstr);
    virHashRemoveEntry(doms->objsName, dom->def->name);
    virObjectUnlock(dom);
}


static virDomainObjPtr
virDomainObjListLoadConfig(virDomainObjListPtr doms,
                           virCapsPtr caps,
                           virDomainXMLOptionPtr xmlopt,
                           const char *configDir,
                           const char *autostartDir,
                           const char *name,
                           virDomainLoadConfigNotify notify,
                           void *opaque)
{
    char *configFile = NULL, *autostartLink = NULL;
    virDomainDefPtr def = NULL;
    virDomainObjPtr dom;
    int autostart;
    virDomainDefPtr oldDef = NULL;

    if ((configFile = virDomainConfigFile(configDir, name)) == NULL)
        goto error;
    if (!(def = virDomainDefParseFile(configFile, caps, xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto error;

    if ((autostartLink = virDomainConfigFile(autostartDir, name)) == NULL)
        goto error;

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        goto error;

    if (!(dom = virDomainObjListAddLocked(doms, def, xmlopt, 0, &oldDef)))
        goto error;

    dom->autostart = autostart;

    if (notify)
        (*notify)(dom, oldDef == NULL, opaque);

    virDomainDefFree(oldDef);
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    return dom;

 error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virDomainDefFree(def);
    return NULL;
}


static virDomainObjPtr
virDomainObjListLoadStatus(virDomainObjListPtr doms,
                           const char *statusDir,
                           const char *name,
                           virCapsPtr caps,
                           virDomainXMLOptionPtr xmlopt,
                           virDomainLoadConfigNotify notify,
                           void *opaque)
{
    char *statusFile = NULL;
    virDomainObjPtr obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if ((statusFile = virDomainConfigFile(statusDir, name)) == NULL)
        goto error;

    if (!(obj = virDomainObjParseFile(statusFile, caps, xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_OSTYPE_CHECKS |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)))
        goto error;

    virUUIDFormat(obj->def->uuid, uuidstr);

    if (virHashLookup(doms->objs, uuidstr) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain %s already exists"),
                       obj->def->name);
        goto error;
    }

    if (virHashAddEntry(doms->objs, uuidstr, obj) < 0)
        goto error;

    if (virHashAddEntry(doms->objsName, obj->def->name, obj) < 0) {
        virHashRemoveEntry(doms->objs, uuidstr);
        goto error;
    }

    /* Since domain is in two hash tables, increment the
     * reference counter */
    virObjectRef(obj);

    if (notify)
        (*notify)(obj, 1, opaque);

    VIR_FREE(statusFile);
    return obj;

 error:
    virObjectUnref(obj);
    VIR_FREE(statusFile);
    return NULL;
}


int
virDomainObjListLoadAllConfigs(virDomainObjListPtr doms,
                               const char *configDir,
                               const char *autostartDir,
                               int liveStatus,
                               virCapsPtr caps,
                               virDomainXMLOptionPtr xmlopt,
                               virDomainLoadConfigNotify notify,
                               void *opaque)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    VIR_INFO("Scanning for configs in %s", configDir);

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    virObjectLock(doms);

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virDomainObjPtr dom;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading config file '%s.xml'", entry->d_name);
        if (liveStatus)
            dom = virDomainObjListLoadStatus(doms,
                                             configDir,
                                             entry->d_name,
                                             caps,
                                             xmlopt,
                                             notify,
                                             opaque);
        else
            dom = virDomainObjListLoadConfig(doms,
                                             caps,
                                             xmlopt,
                                             configDir,
                                             autostartDir,
                                             entry->d_name,
                                             notify,
                                             opaque);
        if (dom) {
            if (!liveStatus)
                dom->persistent = 1;
            virObjectUnlock(dom);
        }
    }

    VIR_DIR_CLOSE(dir);
    virObjectUnlock(doms);
    return ret;
}


struct virDomainObjListData {
    virDomainObjListACLFilter filter;
    virConnectPtr conn;
    bool active;
    int count;
};


static int
virDomainObjListCount(void *payload,
                      const void *name ATTRIBUTE_UNUSED,
                      void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virDomainObjListData *data = opaque;
    virObjectLock(obj);
    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;
    if (virDomainObjIsActive(obj)) {
        if (data->active)
            data->count++;
    } else {
        if (!data->active)
            data->count++;
    }
 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virDomainObjListNumOfDomains(virDomainObjListPtr doms,
                             bool active,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virDomainObjListData data = { filter, conn, active, 0 };
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListCount, &data);
    virObjectUnlock(doms);
    return data.count;
}


struct virDomainIDData {
    virDomainObjListACLFilter filter;
    virConnectPtr conn;
    int numids;
    int maxids;
    int *ids;
};


static int
virDomainObjListCopyActiveIDs(void *payload,
                              const void *name ATTRIBUTE_UNUSED,
                              void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virDomainIDData *data = opaque;
    virObjectLock(obj);
    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;
    if (virDomainObjIsActive(obj) && data->numids < data->maxids)
        data->ids[data->numids++] = obj->def->id;
 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virDomainObjListGetActiveIDs(virDomainObjListPtr doms,
                             int *ids,
                             int maxids,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virDomainIDData data = { filter, conn,
                                    0, maxids, ids };
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListCopyActiveIDs, &data);
    virObjectUnlock(doms);
    return data.numids;
}


struct virDomainNameData {
    virDomainObjListACLFilter filter;
    virConnectPtr conn;
    int oom;
    int numnames;
    int maxnames;
    char **const names;
};


static int
virDomainObjListCopyInactiveNames(void *payload,
                                  const void *name ATTRIBUTE_UNUSED,
                                  void *opaque)
{
    virDomainObjPtr obj = payload;
    struct virDomainNameData *data = opaque;

    if (data->oom)
        return 0;

    virObjectLock(obj);
    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;
    if (!virDomainObjIsActive(obj) && data->numnames < data->maxnames) {
        if (VIR_STRDUP(data->names[data->numnames], obj->def->name) < 0)
            data->oom = 1;
        else
            data->numnames++;
    }
 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virDomainObjListGetInactiveNames(virDomainObjListPtr doms,
                                 char **const names,
                                 int maxnames,
                                 virDomainObjListACLFilter filter,
                                 virConnectPtr conn)
{
    struct virDomainNameData data = { filter, conn,
                                      0, 0, maxnames, names };
    size_t i;
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListCopyInactiveNames, &data);
    virObjectUnlock(doms);
    if (data.oom) {
        for (i = 0; i < data.numnames; i++)
            VIR_FREE(data.names[i]);
        return -1;
    }

    return data.numnames;
}


struct virDomainListIterData {
    virDomainObjListIterator callback;
    void *opaque;
    int ret;
};


static int
virDomainObjListHelper(void *payload,
                       const void *name ATTRIBUTE_UNUSED,
                       void *opaque)
{
    struct virDomainListIterData *data = opaque;

    if (data->callback(payload, data->opaque) < 0)
        data->ret = -1;
    return 0;
}


int
virDomainObjListForEach(virDomainObjListPtr doms,
                        virDomainObjListIterator callback,
                        void *opaque)
{
    struct virDomainListIterData data = {
        callback, opaque, 0,
    };
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListHelper, &data);
    virObjectUnlock(doms);
    return data.ret;
}


#define MATCH(FLAG) (filter & (FLAG))
static bool
virDomainObjMatchFilter(virDomainObjPtr vm,
                        unsigned int filter)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_ACTIVE) &&
           virDomainObjIsActive(vm)) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_INACTIVE) &&
           !virDomainObjIsActive(vm))))
        return false;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_PERSISTENT) &&
           vm->persistent) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_TRANSIENT) &&
           !vm->persistent)))
        return false;

    /* filter by domain state */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_STATE)) {
        int st = virDomainObjGetState(vm, NULL);
        if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_RUNNING) &&
               st == VIR_DOMAIN_RUNNING) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_PAUSED) &&
               st == VIR_DOMAIN_PAUSED) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_SHUTOFF) &&
               st == VIR_DOMAIN_SHUTOFF) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_OTHER) &&
               (st != VIR_DOMAIN_RUNNING &&
                st != VIR_DOMAIN_PAUSED &&
                st != VIR_DOMAIN_SHUTOFF))))
            return false;
    }

    /* filter by existence of managed save state */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_MANAGEDSAVE) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_MANAGEDSAVE) &&
           vm->hasManagedSave) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_MANAGEDSAVE) &&
           !vm->hasManagedSave)))
        return false;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_DOMAINS_AUTOSTART) && vm->autostart) ||
          (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_AUTOSTART) && !vm->autostart)))
        return false;

    /* filter by snapshot existence */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_SNAPSHOT)) {
        int nsnap = virDomainSnapshotObjListNum(vm->snapshots, NULL, 0);
        if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_SNAPSHOT) && nsnap > 0) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_SNAPSHOT) && nsnap <= 0)))
            return false;
    }

    return true;
}
#undef MATCH


struct virDomainListData {
    virDomainObjPtr *vms;
    size_t nvms;
};


static int
virDomainObjListCollectIterator(void *payload,
                                const void *name ATTRIBUTE_UNUSED,
                                void *opaque)
{
    struct virDomainListData *data = opaque;

    data->vms[data->nvms++] = virObjectRef(payload);
    return 0;
}


static void
virDomainObjListFilter(virDomainObjPtr **list,
                       size_t *nvms,
                       virConnectPtr conn,
                       virDomainObjListACLFilter filter,
                       unsigned int flags)
{
    size_t i = 0;

    while (i < *nvms) {
        virDomainObjPtr vm = (*list)[i];

        virObjectLock(vm);

        /* do not list the object if:
         * 1) it's being removed.
         * 2) connection does not have ACL to see it
         * 3) it doesn't match the filter
         */
        if (vm->removing ||
            (filter && !filter(conn, vm->def)) ||
            !virDomainObjMatchFilter(vm, flags)) {
            virObjectUnlock(vm);
            virObjectUnref(vm);
            VIR_DELETE_ELEMENT(*list, i, *nvms);
            continue;
        }

        virObjectUnlock(vm);
        i++;
    }
}


int
virDomainObjListCollect(virDomainObjListPtr domlist,
                        virConnectPtr conn,
                        virDomainObjPtr **vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags)
{
    struct virDomainListData data = { NULL, 0 };

    virObjectRWLockRead(domlist);
    sa_assert(domlist->objs);
    if (VIR_ALLOC_N(data.vms, virHashSize(domlist->objs)) < 0) {
        virObjectUnlock(domlist);
        return -1;
    }

    virHashForEach(domlist->objs, virDomainObjListCollectIterator, &data);
    virObjectUnlock(domlist);

    virDomainObjListFilter(&data.vms, &data.nvms, conn, filter, flags);

    *nvms = data.nvms;
    *vms = data.vms;

    return 0;
}


int
virDomainObjListConvert(virDomainObjListPtr domlist,
                        virConnectPtr conn,
                        virDomainPtr *doms,
                        size_t ndoms,
                        virDomainObjPtr **vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags,
                        bool skip_missing)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObjPtr vm;
    size_t i;

    *nvms = 0;
    *vms = NULL;

    virObjectRWLockRead(domlist);
    for (i = 0; i < ndoms; i++) {
        virDomainPtr dom = doms[i];

        virUUIDFormat(dom->uuid, uuidstr);

        if (!(vm = virHashLookup(domlist->objs, uuidstr))) {
            if (skip_missing)
                continue;

            virObjectUnlock(domlist);
            virReportError(VIR_ERR_NO_DOMAIN,
                           _("no domain with matching uuid '%s' (%s)"),
                           uuidstr, dom->name);
            goto error;
        }

        virObjectRef(vm);

        if (VIR_APPEND_ELEMENT(*vms, *nvms, vm) < 0) {
            virObjectUnlock(domlist);
            virObjectUnref(vm);
            goto error;
        }
    }
    virObjectUnlock(domlist);

    sa_assert(*vms);
    virDomainObjListFilter(vms, nvms, conn, filter, flags);

    return 0;

 error:
    virObjectListFreeCount(*vms, *nvms);
    *vms = NULL;
    *nvms = 0;

    return -1;
}


int
virDomainObjListExport(virDomainObjListPtr domlist,
                       virConnectPtr conn,
                       virDomainPtr **domains,
                       virDomainObjListACLFilter filter,
                       unsigned int flags)
{
    virDomainObjPtr *vms = NULL;
    virDomainPtr *doms = NULL;
    size_t nvms = 0;
    size_t i;
    int ret = -1;

    if (virDomainObjListCollect(domlist, conn, &vms, &nvms, filter, flags) < 0)
        return -1;

    if (domains) {
        if (VIR_ALLOC_N(doms, nvms + 1) < 0)
            goto cleanup;

        for (i = 0; i < nvms; i++) {
            virDomainObjPtr vm = vms[i];

            virObjectLock(vm);
            doms[i] = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);
            virObjectUnlock(vm);

            if (!doms[i])
                goto cleanup;
        }

        *domains = doms;
        doms = NULL;
    }

    ret = nvms;

 cleanup:
    virObjectListFree(doms);
    virObjectListFreeCount(vms, nvms);
    return ret;
}
