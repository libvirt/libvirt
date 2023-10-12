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
 */

#include <config.h>

#include "internal.h"
#include "datatypes.h"
#include "virdomainobjlist.h"
#include "viralloc.h"
#include "virfile.h"
#include "virlog.h"
#include "virstring.h"
#include "virdomainsnapshotobjlist.h"
#include "virdomaincheckpointobjlist.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.virdomainobjlist");

static virClass *virDomainObjListClass;
static void virDomainObjListDispose(void *obj);


struct _virDomainObjList {
    virObjectRWLockable parent;

    /* uuid string -> virDomainObj  mapping
     * for O(1), lookup-by-uuid */
    GHashTable *objs;

    /* name -> virDomainObj mapping for O(1),
     * lookup-by-name */
    GHashTable *objsName;
};


static int virDomainObjListOnceInit(void)
{
    if (!VIR_CLASS_NEW(virDomainObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virDomainObjList);

virDomainObjList *virDomainObjListNew(void)
{
    virDomainObjList *doms;

    if (virDomainObjListInitialize() < 0)
        return NULL;

    if (!(doms = virObjectRWLockableNew(virDomainObjListClass)))
        return NULL;

    doms->objs = virHashNew(virObjectUnref);
    doms->objsName = virHashNew(virObjectUnref);
    return doms;
}


static void virDomainObjListDispose(void *obj)
{
    virDomainObjList *doms = obj;

    g_clear_pointer(&doms->objs, g_hash_table_unref);
    g_clear_pointer(&doms->objsName, g_hash_table_unref);
}


static int virDomainObjListSearchID(const void *payload,
                                    const char *name G_GNUC_UNUSED,
                                    const void *data)
{
    virDomainObj *obj = (virDomainObj *)payload;
    const int *id = data;
    int want = 0;

    virObjectLock(obj);
    if (virDomainObjIsActive(obj) &&
        obj->def->id == *id)
        want = 1;
    virObjectUnlock(obj);
    return want;
}


virDomainObj *
virDomainObjListFindByID(virDomainObjList *doms,
                         int id)
{
    virDomainObj *obj;

    virObjectRWLockRead(doms);
    obj = virHashSearch(doms->objs, virDomainObjListSearchID, &id, NULL);
    virObjectRef(obj);
    virObjectRWUnlock(doms);
    if (obj) {
        virObjectLock(obj);
        if (obj->removing)
            virDomainObjEndAPI(&obj);
    }

    return obj;
}


static virDomainObj *
virDomainObjListFindByUUIDLocked(virDomainObjList *doms,
                                 const unsigned char *uuid)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObj *obj;

    virUUIDFormat(uuid, uuidstr);
    obj = virHashLookup(doms->objs, uuidstr);
    if (obj) {
        virObjectRef(obj);
        virObjectLock(obj);
    }
    return obj;
}


/**
 * @doms: Domain object list
 * @uuid: UUID to search the doms->objs table
 *
 * Lookup the @uuid in the doms->objs hash table and return a
 * locked and ref counted domain object if found. Caller is
 * expected to use the virDomainObjEndAPI when done with the object.
 */
virDomainObj *
virDomainObjListFindByUUID(virDomainObjList *doms,
                           const unsigned char *uuid)
{
    virDomainObj *obj;

    virObjectRWLockRead(doms);
    obj = virDomainObjListFindByUUIDLocked(doms, uuid);
    virObjectRWUnlock(doms);

    if (obj && obj->removing)
        virDomainObjEndAPI(&obj);

    return obj;
}


static virDomainObj *
virDomainObjListFindByNameLocked(virDomainObjList *doms,
                                 const char *name)
{
    virDomainObj *obj;

    obj = virHashLookup(doms->objsName, name);
    if (obj) {
        virObjectRef(obj);
        virObjectLock(obj);
    }
    return obj;
}


/**
 * @doms: Domain object list
 * @name: Name to search the doms->objsName table
 *
 * Lookup the @name in the doms->objsName hash table and return a
 * locked and ref counted domain object if found. Caller is expected
 * to use the virDomainObjEndAPI when done with the object.
 */
virDomainObj *
virDomainObjListFindByName(virDomainObjList *doms,
                           const char *name)
{
    virDomainObj *obj;

    virObjectRWLockRead(doms);
    obj = virDomainObjListFindByNameLocked(doms, name);
    virObjectRWUnlock(doms);

    if (obj && obj->removing)
        virDomainObjEndAPI(&obj);

    return obj;
}


/**
 * @doms: Domain object list pointer
 * @vm: Domain object to be added
 *
 * Upon entry @vm should have at least 1 ref and be locked.
 *
 * Add the @vm into the @doms->objs and @doms->objsName hash
 * tables. Once successfully added into a table, increase the
 * reference count since upon removal in virHashRemoveEntry
 * the virObjectUnref will be called since the hash tables were
 * configured to call virObjectUnref when the object is
 * removed from the hash table.
 *
 * Returns 0 on success with 3 references and locked
 *        -1 on failure with 1 reference and locked
 */
static int
virDomainObjListAddObjLocked(virDomainObjList *doms,
                             virDomainObj *vm)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(vm->def->uuid, uuidstr);
    if (virHashAddEntry(doms->objs, uuidstr, vm) < 0)
        return -1;
    virObjectRef(vm);

    if (virHashAddEntry(doms->objsName, vm->def->name, vm) < 0) {
        virHashRemoveEntry(doms->objs, uuidstr);
        return -1;
    }
    virObjectRef(vm);

    return 0;
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
 * Upon successful return the virDomain object is the owner of
 * @def and callers should use @vm->def if they need to access
 * the definition as @def is set to NULL.
 *
 * The returned @vm from this function will be locked and ref
 * counted. The caller is expected to use virDomainObjEndAPI
 * when it completes usage.
 */
static virDomainObj *
virDomainObjListAddLocked(virDomainObjList *doms,
                          virDomainDef **def,
                          virDomainXMLOption *xmlopt,
                          unsigned int flags,
                          virDomainDef **oldDef)
{
    virDomainObj *vm;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if (oldDef)
        *oldDef = NULL;

    /* See if a VM with matching UUID already exists */
    if ((vm = virDomainObjListFindByUUIDLocked(doms, (*def)->uuid))) {
        if (vm->removing) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%1$s' is already being removed"),
                           vm->def->name);
            goto error;
        } else if (STRNEQ(vm->def->name, (*def)->name)) {
            /* UUID matches, but if names don't match, refuse it */
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%1$s' is already defined with uuid %2$s"),
                           vm->def->name, uuidstr);
            goto error;
        }

        if (flags & VIR_DOMAIN_OBJ_LIST_ADD_CHECK_LIVE) {
            /* UUID & name match, but if VM is already active, refuse it */
            if (virDomainObjIsActive(vm)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("domain '%1$s' is already active"),
                               vm->def->name);
                goto error;
            }
            if (!vm->persistent) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("domain '%1$s' is already being started"),
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
        if ((vm = virDomainObjListFindByNameLocked(doms, (*def)->name))) {
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("domain '%1$s' already exists with uuid %2$s"),
                           (*def)->name, uuidstr);
            goto error;
        }

        if (!(vm = virDomainObjNew(xmlopt)))
            goto error;
        vm->def = g_steal_pointer(def);

        if (virDomainObjListAddObjLocked(doms, vm) < 0) {
            *def = g_steal_pointer(&vm->def);
            goto error;
        }
    }

    return vm;

 error:
    virDomainObjEndAPI(&vm);
    return NULL;
}


virDomainObj *
virDomainObjListAdd(virDomainObjList *doms,
                    virDomainDef **def,
                    virDomainXMLOption *xmlopt,
                    unsigned int flags,
                    virDomainDef **oldDef)
{
    virDomainObj *ret;

    virObjectRWLockWrite(doms);
    ret = virDomainObjListAddLocked(doms, def, xmlopt, flags, oldDef);
    virObjectRWUnlock(doms);
    return ret;
}


/* The caller must hold lock on 'doms' in addition to 'virDomainObjListRemove'
 * requirements
 *
 * Can be used to remove current element while iterating with
 * virDomainObjListForEach
 */
void
virDomainObjListRemoveLocked(virDomainObjList *doms,
                             virDomainObj *dom)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(dom->def->uuid, uuidstr);

    virHashRemoveEntry(doms->objs, uuidstr);
    virHashRemoveEntry(doms->objsName, dom->def->name);
}


/**
 * @doms: Pointer to the domain object list
 * @dom: Domain pointer from either after Add or FindBy* API where the
 *       @dom was successfully added to both the doms->objs and ->objsName
 *       hash tables that now would need to be removed.
 *
 * The caller must hold a lock on the driver owning 'doms',
 * and must also have locked and ref counted 'dom', to ensure
 * no one else is either waiting for 'dom' or still using it.
 *
 * When this function returns, @dom will be removed from the hash
 * tables and returned with lock and refcnt that was present upon entry.
 */
void
virDomainObjListRemove(virDomainObjList *doms,
                       virDomainObj *dom)
{
    dom->removing = true;
    virObjectRef(dom);
    virObjectUnlock(dom);
    virObjectRWLockWrite(doms);
    virObjectLock(dom);
    virDomainObjListRemoveLocked(doms, dom);
    virObjectUnref(dom);
    virObjectRWUnlock(doms);
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
virDomainObjListRename(virDomainObjList *doms,
                       virDomainObj *dom,
                       const char *new_name,
                       unsigned int flags,
                       virDomainObjListRenameCallback callback,
                       void *opaque)
{
    int ret = -1;
    g_autofree char *old_name = NULL;
    int rc;

    if (STREQ(dom->def->name, new_name)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Can't rename domain to itself"));
        return ret;
    }

    old_name = g_strdup(dom->def->name);

    /* doms and dom locks must be attained in right order thus relock dom. */
    /* dom reference is touched for the benefit of those callers that
     * hold a lock on dom but not refcount it. */
    virObjectRef(dom);
    virObjectUnlock(dom);
    virObjectRWLockWrite(doms);
    virObjectLock(dom);
    virObjectUnref(dom);

    if (virHashLookup(doms->objsName, new_name) != NULL) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("domain with name '%1$s' already exists"),
                       new_name);
        goto cleanup;
    }

    if (virHashAddEntry(doms->objsName, new_name, dom) < 0)
        goto cleanup;

    /* Increment the refcnt for @new_name. We're about to remove
     * the @old_name which will cause the refcnt to be decremented
     * via the virObjectUnref call made during the virObjectUnref
     * as a result of removing something from the object list hash
     * table as set up during virDomainObjListNew. */
    virObjectRef(dom);

    rc = callback(dom, new_name, flags, opaque);
    virHashRemoveEntry(doms->objsName, rc < 0 ? new_name : old_name);
    if (rc < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virObjectRWUnlock(doms);
    return ret;
}


static virDomainObj *
virDomainObjListLoadConfig(virDomainObjList *doms,
                           virDomainXMLOption *xmlopt,
                           const char *configDir,
                           const char *autostartDir,
                           const char *name,
                           virDomainLoadConfigNotify notify,
                           void *opaque)
{
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;
    g_autoptr(virDomainDef) def = NULL;
    virDomainObj *dom;
    int autostart;
    g_autoptr(virDomainDef) oldDef = NULL;

    if ((configFile = virDomainConfigFile(configDir, name)) == NULL)
        return NULL;
    if (!(def = virDomainDefParseFile(configFile, xmlopt, NULL,
                                      VIR_DOMAIN_DEF_PARSE_INACTIVE |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                      VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL)))
        return NULL;

    if ((autostartLink = virDomainConfigFile(autostartDir, name)) == NULL)
        return NULL;

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        return NULL;

    if (!(dom = virDomainObjListAddLocked(doms, &def, xmlopt, 0, &oldDef)))
        return NULL;

    dom->autostart = autostart;

    if (notify)
        (*notify)(dom, oldDef == NULL, opaque);

    return dom;
}


static virDomainObj *
virDomainObjListLoadStatus(virDomainObjList *doms,
                           const char *statusDir,
                           const char *name,
                           virDomainXMLOption *xmlopt,
                           virDomainLoadConfigNotify notify,
                           void *opaque)
{
    g_autofree char *statusFile = NULL;
    virDomainObj *obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    if ((statusFile = virDomainConfigFile(statusDir, name)) == NULL)
        goto error;

    if (!(obj = virDomainObjParseFile(statusFile, xmlopt,
                                      VIR_DOMAIN_DEF_PARSE_STATUS |
                                      VIR_DOMAIN_DEF_PARSE_ACTUAL_NET |
                                      VIR_DOMAIN_DEF_PARSE_PCI_ORIG_STATES |
                                      VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE |
                                      VIR_DOMAIN_DEF_PARSE_ALLOW_POST_PARSE_FAIL |
                                      VIR_DOMAIN_DEF_PARSE_VOLUME_TRANSLATED)))
        goto error;

    virUUIDFormat(obj->def->uuid, uuidstr);

    if (virHashLookup(doms->objs, uuidstr) != NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected domain %1$s already exists"),
                       obj->def->name);
        goto error;
    }

    if (virDomainObjListAddObjLocked(doms, obj) < 0)
        goto error;

    if (notify)
        (*notify)(obj, 1, opaque);

    return obj;

 error:
    virDomainObjEndAPI(&obj);
    return NULL;
}


int
virDomainObjListLoadAllConfigs(virDomainObjList *doms,
                               const char *configDir,
                               const char *autostartDir,
                               bool liveStatus,
                               virDomainXMLOption *xmlopt,
                               virDomainLoadConfigNotify notify,
                               void *opaque)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    VIR_INFO("Scanning for configs in %s", configDir);

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    virObjectRWLockWrite(doms);

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virDomainObj *dom;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        VIR_INFO("Loading config file '%s.xml'", entry->d_name);
        if (liveStatus)
            dom = virDomainObjListLoadStatus(doms,
                                             configDir,
                                             entry->d_name,
                                             xmlopt,
                                             notify,
                                             opaque);
        else
            dom = virDomainObjListLoadConfig(doms,
                                             xmlopt,
                                             configDir,
                                             autostartDir,
                                             entry->d_name,
                                             notify,
                                             opaque);
        if (dom) {
            if (!liveStatus)
                dom->persistent = 1;
            virDomainObjEndAPI(&dom);
        } else {
            VIR_ERROR(_("Failed to load config for domain '%1$s'"), entry->d_name);
        }
    }

    virObjectRWUnlock(doms);
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
                      const char *name G_GNUC_UNUSED,
                      void *opaque)
{
    virDomainObj *obj = payload;
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
virDomainObjListNumOfDomains(virDomainObjList *doms,
                             bool active,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virDomainObjListData data = { filter, conn, active, 0 };
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListCount, &data);
    virObjectRWUnlock(doms);
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
                              const char *name G_GNUC_UNUSED,
                              void *opaque)
{
    virDomainObj *obj = payload;
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
virDomainObjListGetActiveIDs(virDomainObjList *doms,
                             int *ids,
                             int maxids,
                             virDomainObjListACLFilter filter,
                             virConnectPtr conn)
{
    struct virDomainIDData data = { filter, conn,
                                    0, maxids, ids };
    virObjectRWLockRead(doms);
    virHashForEach(doms->objs, virDomainObjListCopyActiveIDs, &data);
    virObjectRWUnlock(doms);
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
                                  const char *name G_GNUC_UNUSED,
                                  void *opaque)
{
    virDomainObj *obj = payload;
    struct virDomainNameData *data = opaque;

    if (data->oom)
        return 0;

    virObjectLock(obj);
    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;
    if (!virDomainObjIsActive(obj) && data->numnames < data->maxnames) {
        data->names[data->numnames] = g_strdup(obj->def->name);
        data->numnames++;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virDomainObjListGetInactiveNames(virDomainObjList *doms,
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
    virObjectRWUnlock(doms);
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
                       const char *name G_GNUC_UNUSED,
                       void *opaque)
{
    struct virDomainListIterData *data = opaque;

    if (data->callback(payload, data->opaque) < 0)
        data->ret = -1;
    return 0;
}


/**
 * virDomainObjListForEach:
 * @doms: Pointer to the domain object list
 * @modify: Whether to lock @doms for modify operation
 * @callback: callback to run over each domain on the list
 * @opaque: opaque data to pass to @callback
 *
 * For every domain on the list (@doms) run @callback on it. If
 * @callback fails (i.e. returns a negative value), the iteration
 * carries still on until all domains are visited. Moreover, if
 * @callback wants to modify the list of domains (@doms) then
 * @modify must be set to true.
 *
 * Returns: 0 on success,
 *         -1 otherwise.
 */
int
virDomainObjListForEach(virDomainObjList *doms,
                        bool modify,
                        virDomainObjListIterator callback,
                        void *opaque)
{
    struct virDomainListIterData data = {
        callback, opaque, 0,
    };

    if (modify)
        virObjectRWLockWrite(doms);
    else
        virObjectRWLockRead(doms);
    virHashForEachSafe(doms->objs, virDomainObjListHelper, &data);
    virObjectRWUnlock(doms);
    return data.ret;
}


#define MATCH(FLAG) (filter & (FLAG))
static bool
virDomainObjMatchFilter(virDomainObj *vm,
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

    /* filter by checkpoint existence */
    if (MATCH(VIR_CONNECT_LIST_DOMAINS_FILTERS_CHECKPOINT)) {
        int nchk = virDomainListCheckpoints(vm->checkpoints, NULL, NULL,
                                            NULL, 0);
        if (!((MATCH(VIR_CONNECT_LIST_DOMAINS_HAS_CHECKPOINT) && nchk > 0) ||
              (MATCH(VIR_CONNECT_LIST_DOMAINS_NO_CHECKPOINT) && nchk <= 0)))
            return false;
    }

    return true;
}
#undef MATCH


struct virDomainListData {
    virDomainObj **vms;
    size_t nvms;
};


static int
virDomainObjListCollectIterator(void *payload,
                                const char *name G_GNUC_UNUSED,
                                void *opaque)
{
    struct virDomainListData *data = opaque;

    data->vms[data->nvms++] = virObjectRef(payload);
    return 0;
}


void
virDomainObjListCollectAll(virDomainObjList *domlist,
                           virDomainObj ***vms,
                           size_t *nvms)
{
    struct virDomainListData data = { NULL, 0 };

    virObjectRWLockRead(domlist);
    data.vms = g_new0(virDomainObj *, virHashSize(domlist->objs));

    virHashForEach(domlist->objs, virDomainObjListCollectIterator, &data);
    virObjectRWUnlock(domlist);

    *nvms = data.nvms;
    *vms = data.vms;
}


static void
virDomainObjListFilter(virDomainObj ***list,
                       size_t *nvms,
                       virConnectPtr conn,
                       virDomainObjListACLFilter filter,
                       unsigned int flags)
{
    size_t i = 0;

    while (i < *nvms) {
        virDomainObj *vm = (*list)[i];

        virObjectLock(vm);

        /* do not list the object if:
         * 1) it's being removed.
         * 2) connection does not have ACL to see it
         * 3) it doesn't match the filter
         */
        if (vm->removing ||
            (filter && !filter(conn, vm->def)) ||
            !virDomainObjMatchFilter(vm, flags)) {
            virDomainObjEndAPI(&vm);
            VIR_DELETE_ELEMENT(*list, i, *nvms);
            continue;
        }

        virObjectUnlock(vm);
        i++;
    }
}


void
virDomainObjListCollect(virDomainObjList *domlist,
                        virConnectPtr conn,
                        virDomainObj ***vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags)
{
    virDomainObjListCollectAll(domlist, vms, nvms);
    virDomainObjListFilter(vms, nvms, conn, filter, flags);
}


int
virDomainObjListConvert(virDomainObjList *domlist,
                        virConnectPtr conn,
                        virDomainPtr *doms,
                        size_t ndoms,
                        virDomainObj ***vms,
                        size_t *nvms,
                        virDomainObjListACLFilter filter,
                        unsigned int flags,
                        bool skip_missing)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virDomainObj *vm;
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

            virObjectRWUnlock(domlist);
            virReportError(VIR_ERR_NO_DOMAIN,
                           _("no domain with matching uuid '%1$s' (%2$s)"),
                           uuidstr, dom->name);
            goto error;
        }

        virObjectRef(vm);

        VIR_APPEND_ELEMENT(*vms, *nvms, vm);
    }
    virObjectRWUnlock(domlist);

    virDomainObjListFilter(vms, nvms, conn, filter, flags);

    return 0;

 error:
    virObjectListFreeCount(*vms, *nvms);
    *vms = NULL;
    *nvms = 0;

    return -1;
}


int
virDomainObjListExport(virDomainObjList *domlist,
                       virConnectPtr conn,
                       virDomainPtr **domains,
                       virDomainObjListACLFilter filter,
                       unsigned int flags)
{
    virDomainObj **vms = NULL;
    virDomainPtr *doms = NULL;
    size_t nvms = 0;
    size_t i;
    int ret = -1;

    virDomainObjListCollect(domlist, conn, &vms, &nvms, filter, flags);

    if (domains) {
        doms = g_new0(virDomainPtr, nvms + 1);

        for (i = 0; i < nvms; i++) {
            virDomainObj *vm = vms[i];

            virObjectLock(vm);
            doms[i] = virGetDomain(conn, vm->def->name, vm->def->uuid, vm->def->id);
            virObjectUnlock(vm);

            if (!doms[i])
                goto cleanup;
        }

        *domains = g_steal_pointer(&doms);
    }

    ret = nvms;

 cleanup:
    virObjectListFree(doms);
    virObjectListFreeCount(vms, nvms);
    return ret;
}
