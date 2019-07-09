/*
 * virnetworkobj.c: handle network objects
 *                  (derived from network_conf.c)
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
#include "virnetworkobj.h"

#include "viralloc.h"
#include "virerror.h"
#include "virfile.h"
#include "virhash.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_LOG_INIT("conf.virnetworkobj");

/* Currently, /sbin/tc implementation allows up to 16 bits for
 * minor class size. But the initial bitmap doesn't have to be
 * that big. */
#define INIT_CLASS_ID_BITMAP_SIZE (1<<4)

struct _virNetworkObj {
    virObjectLockable parent;

    pid_t dnsmasqPid;
    pid_t radvdPid;
    bool active;
    bool autostart;
    bool persistent;

    virNetworkDefPtr def; /* The current definition */
    virNetworkDefPtr newDef; /* New definition to activate at shutdown */

    virBitmapPtr classIdMap; /* bitmap of class IDs for QoS */
    unsigned long long floor_sum; /* sum of all 'floor'-s of attached NICs */

    unsigned int taint;

    /* Immutable pointer, self locking APIs */
    virMacMapPtr macmap;

    virHashTablePtr ports; /* uuid -> virNetworkPortDefPtr */
};

struct _virNetworkObjList {
    virObjectRWLockable parent;

    virHashTablePtr objs;
};

static virClassPtr virNetworkObjClass;
static virClassPtr virNetworkObjListClass;
static void virNetworkObjDispose(void *obj);
static void virNetworkObjListDispose(void *obj);

static int
virNetworkObjOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetworkObj, virClassForObjectLockable()))
        return -1;

    if (!VIR_CLASS_NEW(virNetworkObjList, virClassForObjectRWLockable()))
        return -1;

    return 0;
}


VIR_ONCE_GLOBAL_INIT(virNetworkObj);

static int
virNetworkObjLoadAllPorts(virNetworkObjPtr net,
                          const char *stateDir);


static void
virNetworkObjPortFree(void *val, const void *key ATTRIBUTE_UNUSED)
{
    virNetworkPortDefFree(val);
}

virNetworkObjPtr
virNetworkObjNew(void)
{
    virNetworkObjPtr obj;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virNetworkObjClass)))
        return NULL;

    if (!(obj->classIdMap = virBitmapNew(INIT_CLASS_ID_BITMAP_SIZE)))
        goto error;

    /* The first three class IDs are already taken */
    if (virBitmapSetBitExpand(obj->classIdMap, 0) < 0 ||
        virBitmapSetBitExpand(obj->classIdMap, 1) < 0 ||
        virBitmapSetBitExpand(obj->classIdMap, 2) < 0)
        goto error;

    if (!(obj->ports = virHashCreate(10,
                                     virNetworkObjPortFree)))
        goto error;

    virObjectLock(obj);

    return obj;

 error:
    virObjectUnref(obj);
    return NULL;
}


void
virNetworkObjEndAPI(virNetworkObjPtr *obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    virObjectUnref(*obj);
    *obj = NULL;
}


virNetworkDefPtr
virNetworkObjGetDef(virNetworkObjPtr obj)
{
    return obj->def;
}


void
virNetworkObjSetDef(virNetworkObjPtr obj,
                    virNetworkDefPtr def)
{
    obj->def = def;
}


virNetworkDefPtr
virNetworkObjGetNewDef(virNetworkObjPtr obj)
{
    return obj->newDef;
}


bool
virNetworkObjIsActive(virNetworkObjPtr obj)
{
    return obj->active;
}


void
virNetworkObjSetActive(virNetworkObjPtr obj,
                       bool active)
{
    obj->active = active;
}


bool
virNetworkObjIsPersistent(virNetworkObjPtr obj)
{
    return obj->persistent;
}


bool
virNetworkObjIsAutostart(virNetworkObjPtr obj)
{
    return obj->autostart;
}


void
virNetworkObjSetAutostart(virNetworkObjPtr obj,
                          bool autostart)
{
    obj->autostart = autostart;
}


pid_t
virNetworkObjGetDnsmasqPid(virNetworkObjPtr obj)
{
    return obj->dnsmasqPid;
}


void
virNetworkObjSetDnsmasqPid(virNetworkObjPtr obj,
                           pid_t dnsmasqPid)
{
    obj->dnsmasqPid = dnsmasqPid;
}


pid_t
virNetworkObjGetRadvdPid(virNetworkObjPtr obj)
{
    return obj->radvdPid;
}


void
virNetworkObjSetRadvdPid(virNetworkObjPtr obj,
                         pid_t radvdPid)
{
    obj->radvdPid = radvdPid;
}


virBitmapPtr
virNetworkObjGetClassIdMap(virNetworkObjPtr obj)
{
    return obj->classIdMap;
}


virMacMapPtr
virNetworkObjGetMacMap(virNetworkObjPtr obj)
{
    return obj->macmap;
}


unsigned long long
virNetworkObjGetFloorSum(virNetworkObjPtr obj)
{
    return obj->floor_sum;
}


void
virNetworkObjSetFloorSum(virNetworkObjPtr obj,
                         unsigned long long floor_sum)
{
    obj->floor_sum = floor_sum;
}


void
virNetworkObjSetMacMap(virNetworkObjPtr obj,
                       virMacMapPtr macmap)
{
    obj->macmap = macmap;
}


void
virNetworkObjUnrefMacMap(virNetworkObjPtr obj)
{
    virObjectUnref(obj->macmap);
    obj->macmap = NULL;
}


int
virNetworkObjMacMgrAdd(virNetworkObjPtr obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac)
{
    char macStr[VIR_MAC_STRING_BUFLEN];
    char *file = NULL;
    int ret = -1;

    if (!obj->macmap)
        return 0;

    virMacAddrFormat(mac, macStr);

    if (!(file = virMacMapFileName(dnsmasqStateDir, obj->def->bridge)))
        goto cleanup;

    if (virMacMapAdd(obj->macmap, domain, macStr) < 0)
        goto cleanup;

    if (virMacMapWriteFile(obj->macmap, file) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(file);
    return ret;
}


int
virNetworkObjMacMgrDel(virNetworkObjPtr obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac)
{
    char macStr[VIR_MAC_STRING_BUFLEN];
    char *file = NULL;
    int ret = -1;

    if (!obj->macmap)
        return 0;

    virMacAddrFormat(mac, macStr);

    if (!(file = virMacMapFileName(dnsmasqStateDir, obj->def->bridge)))
        goto cleanup;

    if (virMacMapRemove(obj->macmap, domain, macStr) < 0)
        goto cleanup;

    if (virMacMapWriteFile(obj->macmap, file) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(file);
    return ret;
}


virNetworkObjListPtr
virNetworkObjListNew(void)
{
    virNetworkObjListPtr nets;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(nets = virObjectRWLockableNew(virNetworkObjListClass)))
        return NULL;

    if (!(nets->objs = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(nets);
        return NULL;
    }

    return nets;
}


static virNetworkObjPtr
virNetworkObjFindByUUIDLocked(virNetworkObjListPtr nets,
                              const unsigned char *uuid)
{
    virNetworkObjPtr obj = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    obj = virHashLookup(nets->objs, uuidstr);
    if (obj)
        virObjectRef(obj);
    return obj;
}


/**
 * virNetworkObjFindByUUID:
 * @nets: list of network objects
 * @uuid: network uuid to find
 *
 * This functions locks @nets and find network object which
 * corresponds to @uuid.
 *
 * Returns: locked and ref'd network object.
 */
virNetworkObjPtr
virNetworkObjFindByUUID(virNetworkObjListPtr nets,
                        const unsigned char *uuid)
{
    virNetworkObjPtr obj;

    virObjectRWLockRead(nets);
    obj = virNetworkObjFindByUUIDLocked(nets, uuid);
    virObjectRWUnlock(nets);
    if (obj)
        virObjectLock(obj);
    return obj;
}


static int
virNetworkObjSearchName(const void *payload,
                        const void *name ATTRIBUTE_UNUSED,
                        const void *data)
{
    virNetworkObjPtr obj = (virNetworkObjPtr) payload;
    int want = 0;

    virObjectLock(obj);
    if (STREQ(obj->def->name, (const char *)data))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNetworkObjPtr
virNetworkObjFindByNameLocked(virNetworkObjListPtr nets,
                              const char *name)
{
    virNetworkObjPtr obj = NULL;

    obj = virHashSearch(nets->objs, virNetworkObjSearchName, name, NULL);
    if (obj)
        virObjectRef(obj);
    return obj;
}


/**
 * virNetworkObjFindByName:
 * @nets: list of network objects
 * @name: network name to find
 *
 * This functions locks @nets and find network object which
 * corresponds to @name.
 *
 * Returns: locked and ref'd network object.
 */
virNetworkObjPtr
virNetworkObjFindByName(virNetworkObjListPtr nets,
                        const char *name)
{
    virNetworkObjPtr obj;

    virObjectRWLockRead(nets);
    obj = virNetworkObjFindByNameLocked(nets, name);
    virObjectRWUnlock(nets);
    if (obj)
        virObjectLock(obj);
    return obj;
}


bool
virNetworkObjTaint(virNetworkObjPtr obj,
                   virNetworkTaintFlags taint)
{
    unsigned int flag = (1 << taint);

    if (obj->taint & flag)
        return false;

    obj->taint |= flag;
    return true;
}


static void
virNetworkObjDispose(void *opaque)
{
    virNetworkObjPtr obj = opaque;

    virHashFree(obj->ports);
    virNetworkDefFree(obj->def);
    virNetworkDefFree(obj->newDef);
    virBitmapFree(obj->classIdMap);
    virObjectUnref(obj->macmap);
}


static void
virNetworkObjListDispose(void *opaque)
{
    virNetworkObjListPtr nets = opaque;

    virHashFree(nets->objs);
}


/*
 * virNetworkObjUpdateAssignDef:
 * @network: the network object to update
 * @def: the new NetworkDef (will be consumed by this function)
 * @live: is this new def the "live" version, or the "persistent" version
 *
 * Replace the appropriate copy of the given network's def or newDef
 * with def. Use "live" and current state of the network to determine
 * which to replace and what to do with the old defs. When a non-live
 * def is set, indicate that the network is now persistent.
 *
 * NB: a persistent network can be made transient by calling with:
 * virNetworkObjAssignDef(network, NULL, false) (i.e. set the
 * persistent def to NULL)
 *
 */
void
virNetworkObjUpdateAssignDef(virNetworkObjPtr obj,
                             virNetworkDefPtr def,
                             bool live)
{
    if (live) {
        /* before setting new live def, save (into newDef) any
         * existing persistent (!live) def to be restored when the
         * network is destroyed, unless there is one already saved.
         */
        if (obj->persistent && !obj->newDef)
            obj->newDef = obj->def;
        else
            virNetworkDefFree(obj->def);
        obj->def = def;
    } else { /* !live */
        virNetworkDefFree(obj->newDef);
        if (virNetworkObjIsActive(obj)) {
            /* save new configuration to be restored on network
             * shutdown, leaving current live def alone
             */
            obj->newDef = def;
        } else { /* !live and !active */
            if (obj->def && !obj->persistent) {
                /* network isn't (yet) marked active or persistent,
                 * but already has a "live" def set. This means we are
                 * currently setting the persistent def as a part of
                 * the process of starting the network, so we need to
                 * preserve the "not yet live" def in network->def.
                 */
                obj->newDef = def;
            } else {
                /* either there is no live def set, or this network
                 * was already set as persistent, so the proper thing
                 * is to overwrite network->def.
                 */
                obj->newDef = NULL;
                virNetworkDefFree(obj->def);
                obj->def = def;
            }
        }
        obj->persistent = !!def;
    }
}


/*
 * If flags & VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE then this will
 * refuse updating an existing def if the current def is live
 *
 * If flags & VIR_NETWORK_OBJ_LIST_ADD_LIVE then the @def being
 * added is assumed to represent a live config, not a future
 * inactive config
 *
 * If flags is zero, network is considered as inactive and persistent.
 */
static virNetworkObjPtr
virNetworkObjAssignDefLocked(virNetworkObjListPtr nets,
                             virNetworkDefPtr def,
                             unsigned int flags)
{
    virNetworkObjPtr obj;
    virNetworkObjPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    /* See if a network with matching UUID already exists */
    if ((obj = virNetworkObjFindByUUIDLocked(nets, def->uuid))) {
        virObjectLock(obj);
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(obj->def->name, def->name)) {
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' is already defined with uuid %s"),
                           obj->def->name, uuidstr);
            goto cleanup;
        }

        if (flags & VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE) {
            /* UUID & name match, but if network is already active, refuse it */
            if (virNetworkObjIsActive(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("network is already active as '%s'"),
                               obj->def->name);
                goto cleanup;
            }
        }

        virNetworkObjUpdateAssignDef(obj, def,
                                     !!(flags & VIR_NETWORK_OBJ_LIST_ADD_LIVE));
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        if ((obj = virNetworkObjFindByNameLocked(nets, def->name))) {
            virObjectLock(obj);
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto cleanup;
        }

        if (!(obj = virNetworkObjNew()))
              goto cleanup;

        virUUIDFormat(def->uuid, uuidstr);
        if (virHashAddEntry(nets->objs, uuidstr, obj) < 0)
            goto cleanup;
        virObjectRef(obj);

        obj->def = def;
        obj->persistent = !(flags & VIR_NETWORK_OBJ_LIST_ADD_LIVE);
    }

    VIR_STEAL_PTR(ret, obj);

 cleanup:
    virNetworkObjEndAPI(&obj);
    return ret;
}


/*
 * virNetworkObjAssignDef:
 * @nets: list of all networks
 * @def: the new NetworkDef (will be consumed by this function iff successful)
 * @flags: bitwise-OR of VIR_NETWORK_OBJ_LIST_ADD_* flags
 *
 * Either replace the appropriate copy of the NetworkDef with name
 * matching def->name or, if not found, create a new NetworkObj with
 * def. For an existing network, use "live" and current state of the
 * network to determine which to replace.
 *
 * Look at virNetworkObjAssignDefLocked() for @flags description.
 *
 * Returns NULL on error, virNetworkObjPtr on success.
 */
virNetworkObjPtr
virNetworkObjAssignDef(virNetworkObjListPtr nets,
                       virNetworkDefPtr def,
                       unsigned int flags)
{
    virNetworkObjPtr obj;

    virObjectRWLockWrite(nets);
    obj = virNetworkObjAssignDefLocked(nets, def, flags);
    virObjectRWUnlock(nets);
    return obj;
}


/*
 * virNetworkObjSetDefTransient:
 * @network: network object pointer
 * @live: if true, run this operation even for an inactive network.
 *   this allows freely updated network->def with runtime defaults
 *   before starting the network, which will be discarded on network
 *   shutdown. Any cleanup paths need to be sure to handle newDef if
 *   the network is never started.
 *
 * Mark the active network config as transient. Ensures live-only update
 * operations do not persist past network destroy.
 *
 * Returns 0 on success, -1 on failure
 */
int
virNetworkObjSetDefTransient(virNetworkObjPtr obj,
                             bool live)
{
    if (!virNetworkObjIsActive(obj) && !live)
        return 0;

    if (!obj->persistent || obj->newDef)
        return 0;

    obj->newDef = virNetworkDefCopy(obj->def, VIR_NETWORK_XML_INACTIVE);
    return obj->newDef ? 0 : -1;
}


/* virNetworkObjUnsetDefTransient:
 *
 * This *undoes* what virNetworkObjSetDefTransient did.
 */
void
virNetworkObjUnsetDefTransient(virNetworkObjPtr obj)
{
    if (obj->newDef) {
        virNetworkDefFree(obj->def);
        obj->def = obj->newDef;
        obj->newDef = NULL;
    }
}


/*
 * virNetworkObjGetPersistentDef:
 * @network: network object pointer
 *
 * Return the persistent network configuration. If network is transient,
 * return the running config.
 *
 * Returns NULL on error, virNetworkDefPtr on success.
 */
virNetworkDefPtr
virNetworkObjGetPersistentDef(virNetworkObjPtr obj)
{
    if (obj->newDef)
        return obj->newDef;
    else
        return obj->def;
}


/*
 * virNetworkObjReplacePersistentDef:
 * @network: network object pointer
 * @def: new virNetworkDef to replace current persistent config
 *
 * Replace the "persistent" network configuration with the given new
 * virNetworkDef. This pays attention to whether or not the network
 * is active.
 *
 * Returns -1 on error, 0 on success
 */
int
virNetworkObjReplacePersistentDef(virNetworkObjPtr obj,
                                  virNetworkDefPtr def)
{
    if (virNetworkObjIsActive(obj)) {
        virNetworkDefFree(obj->newDef);
        obj->newDef = def;
    } else {
        virNetworkDefFree(obj->def);
        obj->def = def;
    }
    return 0;
}


/*
 * virNetworkObjConfigChangeSetup:
 *
 * 1) checks whether network state is consistent with the requested
 *    type of modification.
 *
 * 3) make sure there are separate "def" and "newDef" copies of
 *    networkDef if appropriate.
 *
 * Returns 0 on success, -1 on error.
 */
static int
virNetworkObjConfigChangeSetup(virNetworkObjPtr obj,
                               unsigned int flags)
{
    bool isActive;
    int ret = -1;

    isActive = virNetworkObjIsActive(obj);

    if (!isActive && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("network is not running"));
        goto cleanup;
    }

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        if (!obj->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot change persistent config of a "
                             "transient network"));
            goto cleanup;
        }
        /* this should already have been done by the driver, but do it
         * anyway just in case.
         */
        if (isActive && (virNetworkObjSetDefTransient(obj, false) < 0))
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


void
virNetworkObjRemoveInactive(virNetworkObjListPtr nets,
                            virNetworkObjPtr obj)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(obj->def->uuid, uuidstr);
    virObjectRef(obj);
    virObjectUnlock(obj);
    virObjectRWLockWrite(nets);
    virObjectLock(obj);
    virHashRemoveEntry(nets->objs, uuidstr);
    virObjectRWUnlock(nets);
    virObjectUnref(obj);
}


static char *
virNetworkObjFormat(virNetworkObjPtr obj,
                    unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *classIdStr = virBitmapFormat(obj->classIdMap);
    size_t i;

    if (!classIdStr)
        goto error;

    virBufferAddLit(&buf, "<networkstatus>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<class_id bitmap='%s'/>\n", classIdStr);
    virBufferAsprintf(&buf, "<floor sum='%llu'/>\n", obj->floor_sum);
    VIR_FREE(classIdStr);

    for (i = 0; i < VIR_NETWORK_TAINT_LAST; i++) {
        if (obj->taint & (1 << i))
            virBufferAsprintf(&buf, "<taint flag='%s'/>\n",
                              virNetworkTaintTypeToString(i));
    }

    if (virNetworkDefFormatBuf(&buf, obj->def, flags) < 0)
        goto error;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</networkstatus>");

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
virNetworkObjSaveStatus(const char *statusDir,
                        virNetworkObjPtr obj)
{
    int ret = -1;
    int flags = 0;
    char *xml;

    if (!(xml = virNetworkObjFormat(obj, flags)))
        goto cleanup;

    if (virNetworkSaveXML(statusDir, obj->def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


static virNetworkObjPtr
virNetworkLoadState(virNetworkObjListPtr nets,
                    const char *stateDir,
                    const char *name)
{
    char *configFile = NULL;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr obj = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL, *nodes = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virBitmapPtr classIdMap = NULL;
    unsigned long long floor_sum_val = 0;
    unsigned int taint = 0;
    int n;
    size_t i;


    if ((configFile = virNetworkConfigFile(stateDir, name)) == NULL)
        goto error;

    if (!(xml = virXMLParseCtxt(configFile, NULL, _("(network status)"), &ctxt)))
        goto error;

    if (!(node = virXPathNode("//network", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any 'network' element in status file"));
        goto error;
    }

    /* parse the definition first */
    ctxt->node = node;
    if (!(def = virNetworkDefParseXML(ctxt)))
        goto error;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network config filename '%s'"
                         " does not match network name '%s'"),
                       configFile, def->name);
        goto error;
    }

    /* now parse possible status data */
    node = xmlDocGetRootElement(xml);
    if (virXMLNodeNameEqual(node, "networkstatus")) {
        /* Newer network status file. Contains useful
         * info which are not to be found in bare config XML */
        char *classIdStr = NULL;
        char *floor_sum = NULL;

        ctxt->node = node;
        if ((classIdStr = virXPathString("string(./class_id[1]/@bitmap)",
                                         ctxt))) {
            if (!(classIdMap = virBitmapParseUnlimited(classIdStr))) {
                VIR_FREE(classIdStr);
                goto error;
            }
        }
        VIR_FREE(classIdStr);

        floor_sum = virXPathString("string(./floor[1]/@sum)", ctxt);
        if (floor_sum &&
            virStrToLong_ull(floor_sum, NULL, 10, &floor_sum_val) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Malformed 'floor_sum' attribute: %s"),
                           floor_sum);
            VIR_FREE(floor_sum);
            goto error;
        }
        VIR_FREE(floor_sum);

        if ((n = virXPathNodeSet("./taint", ctxt, &nodes)) < 0)
            goto error;

        for (i = 0; i < n; i++) {
            char *str = virXMLPropString(nodes[i], "flag");
            if (str) {
                int flag = virNetworkTaintTypeFromString(str);
                if (flag < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("Unknown taint flag %s"), str);
                    VIR_FREE(str);
                    goto error;
                }
                VIR_FREE(str);
                /* Compute taint mask here. The network object does not
                 * exist yet, so we can't use virNetworkObjtTaint. */
                taint |= (1 << flag);
            }
        }
        VIR_FREE(nodes);
    }

    /* create the object */
    if (!(obj = virNetworkObjAssignDef(nets, def,
                                       VIR_NETWORK_OBJ_LIST_ADD_LIVE)))
        goto error;
    /* do not put any "goto error" below this comment */

    /* assign status data stored in the network object */
    if (classIdMap) {
        virBitmapFree(obj->classIdMap);
        obj->classIdMap = classIdMap;
    }

    if (floor_sum_val > 0)
        obj->floor_sum = floor_sum_val;

    obj->taint = taint;
    obj->active = true; /* network with a state file is by definition active */

 cleanup:
    VIR_FREE(configFile);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return obj;

 error:
    VIR_FREE(nodes);
    virBitmapFree(classIdMap);
    virNetworkDefFree(def);
    goto cleanup;
}


static virNetworkObjPtr
virNetworkLoadConfig(virNetworkObjListPtr nets,
                     const char *configDir,
                     const char *autostartDir,
                     const char *name)
{
    char *configFile = NULL, *autostartLink = NULL;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr obj;
    int autostart;

    if ((configFile = virNetworkConfigFile(configDir, name)) == NULL)
        goto error;
    if ((autostartLink = virNetworkConfigFile(autostartDir, name)) == NULL)
        goto error;

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        goto error;

    if (!(def = virNetworkDefParseFile(configFile)))
        goto error;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network config filename '%s'"
                         " does not match network name '%s'"),
                       configFile, def->name);
        goto error;
    }

    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        if (!def->mac_specified) {
            virNetworkSetBridgeMacAddr(def);
            virNetworkSaveConfig(configDir, def);
        }
        break;

    case VIR_NETWORK_FORWARD_BRIDGE:
    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        /* Throw away MAC address for other forward types,
         * which could have been generated by older libvirt RPMs */
        def->mac_specified = false;
        break;

    case VIR_NETWORK_FORWARD_LAST:
    default:
        virReportEnumRangeError(virNetworkForwardType, def->forward.type);
        goto error;
    }

    if (!(obj = virNetworkObjAssignDef(nets, def, 0)))
        goto error;

    obj->autostart = (autostart == 1);

    VIR_FREE(configFile);
    VIR_FREE(autostartLink);

    return obj;

 error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virNetworkDefFree(def);
    return NULL;
}


int
virNetworkObjLoadAllState(virNetworkObjListPtr nets,
                          const char *stateDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virNetworkObjPtr obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        obj = virNetworkLoadState(nets, stateDir, entry->d_name);

        if (obj &&
            virNetworkObjLoadAllPorts(obj, stateDir) < 0) {
            virNetworkObjEndAPI(&obj);
            goto cleanup;
        }
        virNetworkObjEndAPI(&obj);
    }

 cleanup:
    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virNetworkObjLoadAllConfigs(virNetworkObjListPtr nets,
                            const char *configDir,
                            const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNetworkObjPtr obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        obj = virNetworkLoadConfig(nets,
                                   configDir,
                                   autostartDir,
                                   entry->d_name);
        virNetworkObjEndAPI(&obj);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virNetworkObjDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virNetworkObjPtr obj)
{
    char *configFile = NULL;
    char *autostartLink = NULL;
    int ret = -1;

    if (!(configFile = virNetworkConfigFile(configDir, obj->def->name)))
        goto error;
    if (!(autostartLink = virNetworkConfigFile(autostartDir, obj->def->name)))
        goto error;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);
    obj->autostart = false;

    if (unlink(configFile) < 0) {
        virReportSystemError(errno,
                             _("cannot remove config file '%s'"),
                             configFile);
        goto error;
    }

    ret = 0;

 error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    return ret;
}


struct virNetworkObjBridgeInUseHelperData {
    const char *bridge;
    const char *skipname;
};

static int
virNetworkObjBridgeInUseHelper(const void *payload,
                               const void *name ATTRIBUTE_UNUSED,
                               const void *opaque)
{
    int ret;
    virNetworkObjPtr obj = (virNetworkObjPtr) payload;
    const struct virNetworkObjBridgeInUseHelperData *data = opaque;

    virObjectLock(obj);
    if (data->skipname &&
        ((obj->def && STREQ(obj->def->name, data->skipname)) ||
         (obj->newDef && STREQ(obj->newDef->name, data->skipname))))
        ret = 0;
    else if ((obj->def && obj->def->bridge &&
              STREQ(obj->def->bridge, data->bridge)) ||
             (obj->newDef && obj->newDef->bridge &&
              STREQ(obj->newDef->bridge, data->bridge)))
        ret = 1;
    else
        ret = 0;
    virObjectUnlock(obj);
    return ret;
}


bool
virNetworkObjBridgeInUse(virNetworkObjListPtr nets,
                         const char *bridge,
                         const char *skipname)
{
    virNetworkObjPtr obj;
    struct virNetworkObjBridgeInUseHelperData data = {bridge, skipname};

    virObjectRWLockRead(nets);
    obj = virHashSearch(nets->objs, virNetworkObjBridgeInUseHelper, &data, NULL);
    virObjectRWUnlock(nets);

    return obj != NULL;
}


/*
 * virNetworkObjUpdate:
 *
 * Apply the supplied update to the given virNetworkObj. Except for
 * @network pointing to an actual network object rather than the
 * opaque virNetworkPtr, parameters are identical to the public API
 * virNetworkUpdate.
 *
 * The original virNetworkDefs are copied, and all modifications made
 * to these copies. The originals are replaced with the copies only
 * after success has been guaranteed.
 *
 * Returns: -1 on error, 0 on success.
 */
int
virNetworkObjUpdate(virNetworkObjPtr obj,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    unsigned int flags)  /* virNetworkUpdateFlags */
{
    int ret = -1;
    virNetworkDefPtr livedef = NULL, configdef = NULL;

    /* normalize config data, and check for common invalid requests. */
    if (virNetworkObjConfigChangeSetup(obj, flags) < 0)
       goto cleanup;

    if (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE) {
        virNetworkDefPtr checkdef;

        /* work on a copy of the def */
        if (!(livedef = virNetworkDefCopy(obj->def, 0)))
            goto cleanup;
        if (virNetworkDefUpdateSection(livedef, command, section,
                                       parentIndex, xml, flags) < 0) {
            goto cleanup;
        }
        /* run a final format/parse cycle to make sure we didn't
         * add anything illegal to the def
         */
        if (!(checkdef = virNetworkDefCopy(livedef, 0)))
            goto cleanup;
        virNetworkDefFree(checkdef);
    }

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        virNetworkDefPtr checkdef;

        /* work on a copy of the def */
        if (!(configdef = virNetworkDefCopy(virNetworkObjGetPersistentDef(obj),
                                            VIR_NETWORK_XML_INACTIVE))) {
            goto cleanup;
        }
        if (virNetworkDefUpdateSection(configdef, command, section,
                                       parentIndex, xml, flags) < 0) {
            goto cleanup;
        }
        if (!(checkdef = virNetworkDefCopy(configdef,
                                           VIR_NETWORK_XML_INACTIVE))) {
            goto cleanup;
        }
        virNetworkDefFree(checkdef);
    }

    if (configdef) {
        /* successfully modified copy, now replace original */
        if (virNetworkObjReplacePersistentDef(obj, configdef) < 0)
           goto cleanup;
        configdef = NULL;
    }
    if (livedef) {
        /* successfully modified copy, now replace original */
        virNetworkDefFree(obj->def);
        obj->def = livedef;
        livedef = NULL;
    }

    ret = 0;
 cleanup:
    virNetworkDefFree(livedef);
    virNetworkDefFree(configdef);
    return ret;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virNetworkObjMatch(virNetworkObjPtr obj,
                   unsigned int flags)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE) &&
           virNetworkObjIsActive(obj)) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_INACTIVE) &&
           !virNetworkObjIsActive(obj))))
        return false;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_PERSISTENT) &&
           obj->persistent) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_TRANSIENT) &&
           !obj->persistent)))
        return false;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_AUTOSTART) &&
           obj->autostart) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART) &&
           !obj->autostart)))
        return false;

    return true;
}
#undef MATCH


typedef struct _virNetworkObjListExportData virNetworkObjListExportData;
typedef virNetworkObjListExportData *virNetworkObjListExportDataPtr;
struct _virNetworkObjListExportData {
    virConnectPtr conn;
    virNetworkPtr *nets;
    virNetworkObjListFilter filter;
    unsigned int flags;
    int nnets;
    bool error;
};

static int
virNetworkObjListExportCallback(void *payload,
                                const void *name ATTRIBUTE_UNUSED,
                                void *opaque)
{
    virNetworkObjListExportDataPtr data = opaque;
    virNetworkObjPtr obj = payload;
    virNetworkPtr net = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;

    if (!virNetworkObjMatch(obj, data->flags))
        goto cleanup;

    if (!data->nets) {
        data->nnets++;
        goto cleanup;
    }

    if (!(net = virGetNetwork(data->conn, obj->def->name, obj->def->uuid))) {
        data->error = true;
        goto cleanup;
    }

    data->nets[data->nnets++] = net;

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virNetworkObjListExport(virConnectPtr conn,
                        virNetworkObjListPtr netobjs,
                        virNetworkPtr **nets,
                        virNetworkObjListFilter filter,
                        unsigned int flags)
{
    int ret = -1;
    virNetworkObjListExportData data = {
        .conn = conn, .nets = NULL, .filter = filter, .flags = flags,
        .nnets = 0, .error = false };

    virObjectRWLockRead(netobjs);
    if (nets && VIR_ALLOC_N(data.nets, virHashSize(netobjs->objs) + 1) < 0)
        goto cleanup;

    virHashForEach(netobjs->objs, virNetworkObjListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.nets) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.nets, data.nnets + 1));
        *nets = data.nets;
        data.nets = NULL;
    }

    ret = data.nnets;
 cleanup:
    virObjectRWUnlock(netobjs);
    while (data.nets && data.nnets)
        virObjectUnref(data.nets[--data.nnets]);

    VIR_FREE(data.nets);
    return ret;
}


struct virNetworkObjListForEachHelperData {
    virNetworkObjListIterator callback;
    void *opaque;
    int ret;
};

static int
virNetworkObjListForEachHelper(void *payload,
                               const void *name ATTRIBUTE_UNUSED,
                               void *opaque)
{
    struct virNetworkObjListForEachHelperData *data = opaque;

    if (data->callback(payload, data->opaque) < 0)
        data->ret = -1;
    return 0;
}


/**
 * virNetworkObjListForEach:
 * @nets: a list of network objects
 * @callback: function to call over each of object in the list
 * @opaque: pointer to pass to the @callback
 *
 * Function iterates over the list of network objects and calls
 * passed callback over each one of them. You should avoid
 * calling those virNetworkObjList APIs, which lock the list
 * again in favor of their virNetworkObj*Locked variants.
 *
 * Returns: 0 on success, -1 otherwise.
 */
int
virNetworkObjListForEach(virNetworkObjListPtr nets,
                         virNetworkObjListIterator callback,
                         void *opaque)
{
    struct virNetworkObjListForEachHelperData data = {
        .callback = callback, .opaque = opaque, .ret = 0};
    virObjectRWLockRead(nets);
    virHashForEach(nets->objs, virNetworkObjListForEachHelper, &data);
    virObjectRWUnlock(nets);
    return data.ret;
}


struct virNetworkObjListGetHelperData {
    virConnectPtr conn;
    virNetworkObjListFilter filter;
    char **names;
    int nnames;
    int maxnames;
    bool active;
    bool error;
};

static int
virNetworkObjListGetHelper(void *payload,
                           const void *name ATTRIBUTE_UNUSED,
                           void *opaque)
{
    struct virNetworkObjListGetHelperData *data = opaque;
    virNetworkObjPtr obj = payload;

    if (data->error)
        return 0;

    if (data->maxnames >= 0 &&
        data->nnames == data->maxnames)
        return 0;

    virObjectLock(obj);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;

    if ((data->active && virNetworkObjIsActive(obj)) ||
        (!data->active && !virNetworkObjIsActive(obj))) {
        if (data->names &&
            VIR_STRDUP(data->names[data->nnames], obj->def->name) < 0) {
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
virNetworkObjListGetNames(virNetworkObjListPtr nets,
                          bool active,
                          char **names,
                          int maxnames,
                          virNetworkObjListFilter filter,
                          virConnectPtr conn)
{
    int ret = -1;

    struct virNetworkObjListGetHelperData data = {
        .conn = conn, .filter = filter, .names = names, .nnames = 0,
        .maxnames = maxnames, .active = active, .error = false};

    virObjectRWLockRead(nets);
    virHashForEach(nets->objs, virNetworkObjListGetHelper, &data);
    virObjectRWUnlock(nets);

    if (data.error)
        goto cleanup;

    ret = data.nnames;
 cleanup:
    if (ret < 0) {
        while (data.nnames)
            VIR_FREE(data.names[--data.nnames]);
    }
    return ret;
}


int
virNetworkObjListNumOfNetworks(virNetworkObjListPtr nets,
                               bool active,
                               virNetworkObjListFilter filter,
                               virConnectPtr conn)
{
    struct virNetworkObjListGetHelperData data = {
        .conn = conn, .filter = filter, .names = NULL, .nnames = 0,
        .maxnames = -1, .active = active, .error = false};

    virObjectRWLockRead(nets);
    virHashForEach(nets->objs, virNetworkObjListGetHelper, &data);
    virObjectRWUnlock(nets);

    return data.nnames;
}


struct virNetworkObjListPruneHelperData {
    unsigned int flags;
};

static int
virNetworkObjListPruneHelper(const void *payload,
                             const void *name ATTRIBUTE_UNUSED,
                             const void *opaque)
{
    const struct virNetworkObjListPruneHelperData *data = opaque;
    virNetworkObjPtr obj = (virNetworkObjPtr) payload;
    int want = 0;

    virObjectLock(obj);
    want = virNetworkObjMatch(obj, data->flags);
    virObjectUnlock(obj);
    return want;
}


/**
 * virNetworkObjListPrune:
 * @nets: a list of network objects
 * @flags: bitwise-OR of virConnectListAllNetworksFlags
 *
 * Iterate over list of network objects and remove the desired
 * ones from it.
 */
void
virNetworkObjListPrune(virNetworkObjListPtr nets,
                       unsigned int flags)
{
    struct virNetworkObjListPruneHelperData data = {flags};

    virObjectRWLockWrite(nets);
    virHashRemoveSet(nets->objs, virNetworkObjListPruneHelper, &data);
    virObjectRWUnlock(nets);
}


char *
virNetworkObjGetPortStatusDir(virNetworkObjPtr net,
                              const char *stateDir)
{
    char *ret;
    ignore_value(virAsprintf(&ret, "%s/%s/ports", stateDir, net->def->name));
    return ret;
}

int
virNetworkObjAddPort(virNetworkObjPtr net,
                     virNetworkPortDefPtr portdef,
                     const char *stateDir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    VIR_AUTOFREE(char *) dir = NULL;

    virUUIDFormat(portdef->uuid, uuidstr);

    if (virHashLookup(net->ports, uuidstr)) {
        virReportError(VIR_ERR_NETWORK_PORT_EXIST,
                       _("Network port with UUID %s already exists"),
                       uuidstr);
        return -1;
    }

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        return -1;

    if (virHashAddEntry(net->ports, uuidstr, portdef) < 0)
        return -1;

    if (virNetworkPortDefSaveStatus(portdef, dir) < 0) {
        virHashRemoveEntry(net->ports, uuidstr);
        return -1;
    }

    return 0;
}


virNetworkPortDefPtr
virNetworkObjLookupPort(virNetworkObjPtr net,
                        const unsigned char *uuid)
{
    virNetworkPortDefPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    if (!(ret = virHashLookup(net->ports, uuidstr))) {
        virReportError(VIR_ERR_NO_NETWORK_PORT,
                       _("Network port with UUID %s does not exist"),
                       uuidstr);
        goto cleanup;
    }

 cleanup:
    return ret;
}


int
virNetworkObjDeletePort(virNetworkObjPtr net,
                        const unsigned char *uuid,
                        const char *stateDir)
{
    int ret = -1;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *dir = NULL;
    virNetworkPortDefPtr portdef;

    virUUIDFormat(uuid, uuidstr);

    if (!(portdef = virHashLookup(net->ports, uuidstr))) {
        virReportError(VIR_ERR_NO_NETWORK_PORT,
                       _("Network port with UUID %s does not exist"),
                       uuidstr);
        goto cleanup;
    }

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        goto cleanup;

    if (virNetworkPortDefDeleteStatus(portdef, dir) < 0)
        goto cleanup;

    if (virHashRemoveEntry(net->ports, uuidstr) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(dir);
    return ret;
}


int
virNetworkObjDeleteAllPorts(virNetworkObjPtr net,
                            const char *stateDir)
{
    VIR_AUTOFREE(char *) dir = NULL;
    DIR *dh = NULL;
    struct dirent *de;
    int rc;
    int ret = -1;

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        goto cleanup;

    if ((rc = virDirOpenIfExists(&dh, dir)) <= 0) {
        ret = rc;
        goto cleanup;
    }

    while ((rc = virDirRead(dh, &de, dir)) > 0) {
        char *file = NULL;

        if (!virStringStripSuffix(de->d_name, ".xml"))
            continue;

        if (virAsprintf(&file, "%s/%s.xml", dir, de->d_name) < 0)
            goto cleanup;

        if (unlink(file) < 0 && errno != ENOENT)
            VIR_WARN("Unable to delete %s", file);

        VIR_FREE(file);
    }

    virHashRemoveAll(net->ports);

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dh);
    return ret;
}


typedef struct _virNetworkObjPortListExportData virNetworkObjPortListExportData;
typedef virNetworkObjPortListExportData *virNetworkObjPortListExportDataPtr;
struct _virNetworkObjPortListExportData {
    virNetworkPtr net;
    virNetworkDefPtr def;
    virNetworkPortPtr *ports;
    virNetworkPortListFilter filter;
    int nports;
    bool error;
};

static int
virNetworkObjPortListExportCallback(void *payload,
                                    const void *name ATTRIBUTE_UNUSED,
                                    void *opaque)
{
    virNetworkObjPortListExportDataPtr data = opaque;
    virNetworkPortDefPtr def = payload;
    virNetworkPortPtr port;

    if (data->error)
        return 0;

    if (data->filter &&
        !data->filter(data->net->conn, data->def, def))
        goto cleanup;

    if (!data->ports) {
        data->nports++;
        goto cleanup;
    }

    if (!(port = virGetNetworkPort(data->net, def->uuid))) {
        data->error = true;
        goto cleanup;
    }

    data->ports[data->nports++] = port;

 cleanup:
    return 0;
}


int
virNetworkObjPortListExport(virNetworkPtr net,
                            virNetworkObjPtr obj,
                            virNetworkPortPtr **ports,
                            virNetworkPortListFilter filter)
{
    virNetworkObjPortListExportData data = {
        net, obj->def, NULL, filter, 0, false,
    };
    int ret = -1;

    if (ports) {
        *ports = NULL;

        if (VIR_ALLOC_N(data.ports, virHashSize(obj->ports) + 1) < 0)
            goto cleanup;
    }

    virHashForEach(obj->ports, virNetworkObjPortListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.ports) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(data.ports, data.nports + 1));
        *ports = data.ports;
        data.ports = NULL;
    }

    ret = data.nports;
 cleanup:
    while (data.ports && data.nports)
        virObjectUnref(data.ports[--data.nports]);

    VIR_FREE(data.ports);
    return ret;
}


static int
virNetworkObjLoadAllPorts(virNetworkObjPtr net,
                          const char *stateDir)
{
    VIR_AUTOFREE(char *) dir = NULL;
    DIR *dh = NULL;
    struct dirent *de;
    int ret = -1;
    int rc;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    virNetworkPortDefPtr portdef = NULL;

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        goto cleanup;

    if ((rc = virDirOpenIfExists(&dh, dir)) <= 0) {
        ret = rc;
        goto cleanup;
    }

    while ((rc = virDirRead(dh, &de, dir)) > 0) {
        char *file = NULL;

        if (!virStringStripSuffix(de->d_name, ".xml"))
            continue;

        if (virAsprintf(&file, "%s/%s.xml", dir, de->d_name) < 0)
            goto cleanup;

        portdef = virNetworkPortDefParseFile(file);
        VIR_FREE(file);
        file = NULL;

        if (!portdef) {
            VIR_WARN("Cannot parse port %s", file);
            continue;
        }

        virUUIDFormat(portdef->uuid, uuidstr);
        if (virHashAddEntry(net->ports, uuidstr, portdef) < 0)
            goto cleanup;

        portdef = NULL;
    }

    ret = 0;
 cleanup:
    VIR_DIR_CLOSE(dh);
    virNetworkPortDefFree(portdef);
    return ret;
}
