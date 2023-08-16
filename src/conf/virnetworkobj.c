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
    bool active;
    bool autostart;
    bool persistent;

    virNetworkDef *def; /* The current definition */
    virNetworkDef *newDef; /* New definition to activate at shutdown */

    virBitmap *classIdMap; /* bitmap of class IDs for QoS */
    unsigned long long floor_sum; /* sum of all 'floor'-s of attached NICs */

    unsigned int taint;

    /* Immutable pointer, self locking APIs */
    virMacMap *macmap;

    GHashTable *ports; /* uuid -> virNetworkPortDef **/
};

struct _virNetworkObjList {
    virObjectRWLockable parent;

    GHashTable *objs;
};

static virClass *virNetworkObjClass;
static virClass *virNetworkObjListClass;
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
virNetworkObjLoadAllPorts(virNetworkObj *net,
                          const char *stateDir);


static void
virNetworkObjPortFree(void *val)
{
    virNetworkPortDefFree(val);
}

virNetworkObj *
virNetworkObjNew(void)
{
    virNetworkObj *obj;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(obj = virObjectLockableNew(virNetworkObjClass)))
        return NULL;

    obj->classIdMap = virBitmapNew(INIT_CLASS_ID_BITMAP_SIZE);

    /* The first three class IDs are already taken. */
    ignore_value(virBitmapSetBit(obj->classIdMap, 0));
    ignore_value(virBitmapSetBit(obj->classIdMap, 1));
    ignore_value(virBitmapSetBit(obj->classIdMap, 2));

    obj->ports = virHashNew(virNetworkObjPortFree);
    obj->dnsmasqPid = (pid_t)-1;

    virObjectLock(obj);

    return obj;
}


void
virNetworkObjEndAPI(virNetworkObj **obj)
{
    if (!*obj)
        return;

    virObjectUnlock(*obj);
    g_clear_pointer(obj, virObjectUnref);
}


virNetworkDef *
virNetworkObjGetDef(virNetworkObj *obj)
{
    return obj->def;
}


void
virNetworkObjSetDef(virNetworkObj *obj,
                    virNetworkDef *def)
{
    obj->def = def;
}


virNetworkDef *
virNetworkObjGetNewDef(virNetworkObj *obj)
{
    return obj->newDef;
}


bool
virNetworkObjIsActive(virNetworkObj *obj)
{
    return obj->active;
}


void
virNetworkObjSetActive(virNetworkObj *obj,
                       bool active)
{
    obj->active = active;
}


bool
virNetworkObjIsPersistent(virNetworkObj *obj)
{
    return obj->persistent;
}


bool
virNetworkObjIsAutostart(virNetworkObj *obj)
{
    return obj->autostart;
}


void
virNetworkObjSetAutostart(virNetworkObj *obj,
                          bool autostart)
{
    obj->autostart = autostart;
}


pid_t
virNetworkObjGetDnsmasqPid(virNetworkObj *obj)
{
    return obj->dnsmasqPid;
}


void
virNetworkObjSetDnsmasqPid(virNetworkObj *obj,
                           pid_t dnsmasqPid)
{
    obj->dnsmasqPid = dnsmasqPid;
}


virBitmap *
virNetworkObjGetClassIdMap(virNetworkObj *obj)
{
    return obj->classIdMap;
}


virMacMap *
virNetworkObjGetMacMap(virNetworkObj *obj)
{
    return obj->macmap;
}


unsigned long long
virNetworkObjGetFloorSum(virNetworkObj *obj)
{
    return obj->floor_sum;
}


void
virNetworkObjSetFloorSum(virNetworkObj *obj,
                         unsigned long long floor_sum)
{
    obj->floor_sum = floor_sum;
}


void
virNetworkObjSetMacMap(virNetworkObj *obj,
                       virMacMap **macmap)
{
    obj->macmap = g_steal_pointer(macmap);
}


void
virNetworkObjUnrefMacMap(virNetworkObj *obj)
{
    g_clear_pointer(&obj->macmap, virObjectUnref);
}


int
virNetworkObjMacMgrAdd(virNetworkObj *obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac)
{
    char macStr[VIR_MAC_STRING_BUFLEN];
    g_autofree char *file = NULL;

    if (!obj->macmap)
        return 0;

    virMacAddrFormat(mac, macStr);

    if (!(file = virMacMapFileName(dnsmasqStateDir, obj->def->bridge)))
        return -1;

    if (virMacMapAdd(obj->macmap, domain, macStr) < 0)
        return -1;

    if (virMacMapWriteFile(obj->macmap, file) < 0)
        return -1;

    return 0;
}


int
virNetworkObjMacMgrDel(virNetworkObj *obj,
                       const char *dnsmasqStateDir,
                       const char *domain,
                       const virMacAddr *mac)
{
    char macStr[VIR_MAC_STRING_BUFLEN];
    g_autofree char *file = NULL;

    if (!obj->macmap)
        return 0;

    virMacAddrFormat(mac, macStr);

    if (!(file = virMacMapFileName(dnsmasqStateDir, obj->def->bridge)))
        return -1;

    if (virMacMapRemove(obj->macmap, domain, macStr) < 0)
        return -1;

    if (virMacMapWriteFile(obj->macmap, file) < 0)
        return -1;

    return 0;
}


virNetworkObjList *
virNetworkObjListNew(void)
{
    virNetworkObjList *nets;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(nets = virObjectRWLockableNew(virNetworkObjListClass)))
        return NULL;

    nets->objs = virHashNew(virObjectUnref);

    return nets;
}


static virNetworkObj *
virNetworkObjFindByUUIDLocked(virNetworkObjList *nets,
                              const unsigned char *uuid)
{
    virNetworkObj *obj = NULL;
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
virNetworkObj *
virNetworkObjFindByUUID(virNetworkObjList *nets,
                        const unsigned char *uuid)
{
    virNetworkObj *obj;

    virObjectRWLockRead(nets);
    obj = virNetworkObjFindByUUIDLocked(nets, uuid);
    virObjectRWUnlock(nets);
    if (obj)
        virObjectLock(obj);
    return obj;
}


static int
virNetworkObjSearchName(const void *payload,
                        const char *name G_GNUC_UNUSED,
                        const void *data)
{
    virNetworkObj *obj = (virNetworkObj *) payload;
    int want = 0;

    virObjectLock(obj);
    if (STREQ(obj->def->name, (const char *)data))
        want = 1;
    virObjectUnlock(obj);
    return want;
}


static virNetworkObj *
virNetworkObjFindByNameLocked(virNetworkObjList *nets,
                              const char *name)
{
    virNetworkObj *obj = NULL;

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
virNetworkObj *
virNetworkObjFindByName(virNetworkObjList *nets,
                        const char *name)
{
    virNetworkObj *obj;

    virObjectRWLockRead(nets);
    obj = virNetworkObjFindByNameLocked(nets, name);
    virObjectRWUnlock(nets);
    if (obj)
        virObjectLock(obj);
    return obj;
}


bool
virNetworkObjTaint(virNetworkObj *obj,
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
    virNetworkObj *obj = opaque;

    g_clear_pointer(&obj->ports, g_hash_table_unref);
    virNetworkDefFree(obj->def);
    virNetworkDefFree(obj->newDef);
    virBitmapFree(obj->classIdMap);
    virObjectUnref(obj->macmap);
}


static void
virNetworkObjListDispose(void *opaque)
{
    virNetworkObjList *nets = opaque;

    g_clear_pointer(&nets->objs, g_hash_table_unref);
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
virNetworkObjUpdateAssignDef(virNetworkObj *obj,
                             virNetworkDef *def,
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
static virNetworkObj *
virNetworkObjAssignDefLocked(virNetworkObjList *nets,
                             virNetworkDef *def,
                             unsigned int flags)
{
    virNetworkObj *obj;
    virNetworkObj *ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    /* See if a network with matching UUID already exists */
    if ((obj = virNetworkObjFindByUUIDLocked(nets, def->uuid))) {
        virObjectLock(obj);
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(obj->def->name, def->name)) {
            virUUIDFormat(obj->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%1$s' is already defined with uuid %2$s"),
                           obj->def->name, uuidstr);
            goto cleanup;
        }

        if (flags & VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE) {
            /* UUID & name match, but if network is already active, refuse it */
            if (virNetworkObjIsActive(obj)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("network is already active as '%1$s'"),
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
                           _("network '%1$s' already exists with uuid %2$s"),
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

    ret = g_steal_pointer(&obj);

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
 * Returns NULL on error, virNetworkObj *on success.
 */
virNetworkObj *
virNetworkObjAssignDef(virNetworkObjList *nets,
                       virNetworkDef *def,
                       unsigned int flags)
{
    virNetworkObj *obj;

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
virNetworkObjSetDefTransient(virNetworkObj *obj,
                             bool live,
                             virNetworkXMLOption *xmlopt)
{
    if (!virNetworkObjIsActive(obj) && !live)
        return 0;

    if (!obj->persistent || obj->newDef)
        return 0;

    obj->newDef = virNetworkDefCopy(obj->def,
                                    xmlopt,
                                    VIR_NETWORK_XML_INACTIVE);
    return obj->newDef ? 0 : -1;
}


/* virNetworkObjUnsetDefTransient:
 *
 * This *undoes* what virNetworkObjSetDefTransient did.
 */
void
virNetworkObjUnsetDefTransient(virNetworkObj *obj)
{
    if (obj->newDef) {
        virNetworkDefFree(obj->def);
        obj->def = g_steal_pointer(&obj->newDef);
    }
}


/*
 * virNetworkObjGetPersistentDef:
 * @network: network object pointer
 *
 * Return the persistent network configuration. If network is transient,
 * return the running config.
 *
 * Returns NULL on error, virNetworkDef *on success.
 */
virNetworkDef *
virNetworkObjGetPersistentDef(virNetworkObj *obj)
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
virNetworkObjReplacePersistentDef(virNetworkObj *obj,
                                  virNetworkDef *def)
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
virNetworkObjConfigChangeSetup(virNetworkObj *obj,
                               unsigned int flags)
{
    bool isActive;

    isActive = virNetworkObjIsActive(obj);

    if (!isActive && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("network is not running"));
        return -1;
    }

    if ((flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) &&
         !obj->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot change persistent config of a transient network"));
            return -1;
    }

    return 0;
}


void
virNetworkObjRemoveInactive(virNetworkObjList *nets,
                            virNetworkObj *obj)
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
virNetworkObjFormat(virNetworkObj *obj,
                    virNetworkXMLOption *xmlopt,
                    unsigned int flags)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    char *classIdStr = virBitmapFormat(obj->classIdMap);
    size_t i;

    if (!classIdStr)
        return NULL;

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

    if (virNetworkDefFormatBuf(&buf, obj->def, xmlopt, flags) < 0)
        return NULL;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</networkstatus>");

    return virBufferContentAndReset(&buf);
}


int
virNetworkObjSaveStatus(const char *statusDir,
                        virNetworkObj *obj,
                        virNetworkXMLOption *xmlopt)
{
    int flags = 0;
    g_autofree char *xml = NULL;

    if (!(xml = virNetworkObjFormat(obj, xmlopt, flags)))
        return -1;

    if (virNetworkSaveXML(statusDir, obj->def, xml))
        return -1;

    return 0;
}


static virNetworkObj *
virNetworkLoadState(virNetworkObjList *nets,
                    const char *stateDir,
                    const char *name,
                    virNetworkXMLOption *xmlopt)
{
    g_autofree char *configFile = NULL;
    g_autoptr(virNetworkDef) def = NULL;
    virNetworkObj *obj = NULL;
    g_autoptr(xmlDoc) xml = NULL;
    xmlNodePtr node = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;
    g_autoptr(virBitmap) classIdMap = NULL;
    unsigned long long floor_sum_val = 0;
    unsigned int taint = 0;
    int n;
    size_t i;


    if ((configFile = virNetworkConfigFile(stateDir, name)) == NULL)
        return NULL;

    if (!(xml = virXMLParseFileCtxt(configFile, &ctxt)))
        return NULL;

    if (!(node = virXPathNode("//network", ctxt))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Could not find any 'network' element in status file"));
        return NULL;
    }

    /* parse the definition first */
    ctxt->node = node;
    if (!(def = virNetworkDefParseXML(ctxt, xmlopt)))
        return NULL;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network config filename '%1$s' does not match network name '%2$s'"),
                       configFile, def->name);
        return NULL;
    }

    /* now parse possible status data */
    node = xmlDocGetRootElement(xml);
    if (virXMLNodeNameEqual(node, "networkstatus")) {
        /* Newer network status file. Contains useful
         * info which are not to be found in bare config XML */
        g_autofree char *classIdStr = NULL;
        g_autofree char *floor_sum = NULL;
        g_autofree xmlNodePtr *nodes = NULL;

        ctxt->node = node;
        if ((classIdStr = virXPathString("string(./class_id[1]/@bitmap)",
                                         ctxt))) {
            if (!(classIdMap = virBitmapParseUnlimited(classIdStr)))
                return NULL;
        }

        floor_sum = virXPathString("string(./floor[1]/@sum)", ctxt);
        if (floor_sum &&
            virStrToLong_ull(floor_sum, NULL, 10, &floor_sum_val) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Malformed 'floor_sum' attribute: %1$s"),
                           floor_sum);
            return NULL;
        }

        if ((n = virXPathNodeSet("./taint", ctxt, &nodes)) < 0)
            return NULL;

        for (i = 0; i < n; i++) {
            g_autofree char *str = virXMLPropString(nodes[i], "flag");
            if (str) {
                int flag = virNetworkTaintTypeFromString(str);
                if (flag < 0) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("Unknown taint flag %1$s"), str);
                    return NULL;
                }
                /* Compute taint mask here. The network object does not
                 * exist yet, so we can't use virNetworkObjtTaint. */
                taint |= (1 << flag);
            }
        }
    }

    /* create the object */
    if (!(obj = virNetworkObjAssignDef(nets, def, VIR_NETWORK_OBJ_LIST_ADD_LIVE)))
        return NULL;

    def = NULL;

    /* assign status data stored in the network object */
    if (classIdMap) {
        virBitmapFree(obj->classIdMap);
        obj->classIdMap = g_steal_pointer(&classIdMap);
    }

    if (floor_sum_val > 0)
        obj->floor_sum = floor_sum_val;

    obj->taint = taint;
    obj->active = true; /* network with a state file is by definition active */

    return obj;
}


static virNetworkObj *
virNetworkLoadConfig(virNetworkObjList *nets,
                     const char *configDir,
                     const char *autostartDir,
                     const char *name,
                     virNetworkXMLOption *xmlopt)
{
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;
    g_autoptr(virNetworkDef) def = NULL;
    virNetworkObj *obj;
    bool saveConfig = false;
    int autostart;

    if ((configFile = virNetworkConfigFile(configDir, name)) == NULL)
        return NULL;
    if ((autostartLink = virNetworkConfigFile(autostartDir, name)) == NULL)
        return NULL;

    if ((autostart = virFileLinkPointsTo(autostartLink, configFile)) < 0)
        return NULL;

    if (!(def = virNetworkDefParse(NULL, configFile, xmlopt, false)))
        return NULL;

    if (STRNEQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network config filename '%1$s' does not match network name '%2$s'"),
                       configFile, def->name);
        return NULL;
    }

    switch ((virNetworkForwardType) def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_OPEN:
        if (!def->mac_specified) {
            virNetworkSetBridgeMacAddr(def);
            /* We just generated a new MAC address, and we need to persist
             * the configuration to disk to avoid the network getting a
             * different one the next time the daemon is started */
            saveConfig = true;
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
        return NULL;
    }

    /* The network didn't have a UUID so we generated a new one, and
     * we need to persist the configuration to disk to avoid the network
     * getting a different one the next time the daemon is started */
    if (!def->uuid_specified)
        saveConfig = true;

    if (saveConfig &&
        virNetworkSaveConfig(configDir, def, xmlopt) < 0) {
        return NULL;
    }

    if (!(obj = virNetworkObjAssignDef(nets, def, 0)))
        return NULL;

    def = NULL;

    obj->autostart = (autostart == 1);

    return obj;
}


int
virNetworkObjLoadAllState(virNetworkObjList *nets,
                          const char *stateDir,
                          virNetworkXMLOption *xmlopt)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virNetworkObj *obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        obj = virNetworkLoadState(nets, stateDir, entry->d_name, xmlopt);

        if (obj &&
            virNetworkObjLoadAllPorts(obj, stateDir) < 0) {
            virNetworkObjEndAPI(&obj);
            return -1;
        }
        virNetworkObjEndAPI(&obj);
    }

    return ret;
}


int
virNetworkObjLoadAllConfigs(virNetworkObjList *nets,
                            const char *configDir,
                            const char *autostartDir,
                            virNetworkXMLOption *xmlopt)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, configDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, configDir)) > 0) {
        virNetworkObj *obj;

        if (!virStringStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        obj = virNetworkLoadConfig(nets,
                                   configDir,
                                   autostartDir,
                                   entry->d_name,
                                   xmlopt);
        virNetworkObjEndAPI(&obj);
    }

    return ret;
}


int
virNetworkObjDeleteConfig(const char *configDir,
                          const char *autostartDir,
                          virNetworkObj *obj)
{
    g_autofree char *configFile = NULL;
    g_autofree char *autostartLink = NULL;

    if (!(configFile = virNetworkConfigFile(configDir, obj->def->name)))
        return -1;
    if (!(autostartLink = virNetworkConfigFile(autostartDir, obj->def->name)))
        return -1;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);
    obj->autostart = false;

    if (unlink(configFile) < 0) {
        virReportSystemError(errno,
                             _("cannot remove config file '%1$s'"),
                             configFile);
        return -1;
    }

    return 0;
}


struct virNetworkObjBridgeInUseHelperData {
    const char *bridge;
    const char *skipname;
};

static int
virNetworkObjBridgeInUseHelper(const void *payload,
                               const char *name G_GNUC_UNUSED,
                               const void *opaque)
{
    int ret;
    virNetworkObj *obj = (virNetworkObj *) payload;
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
virNetworkObjBridgeInUse(virNetworkObjList *nets,
                         const char *bridge,
                         const char *skipname)
{
    virNetworkObj *obj;
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
virNetworkObjUpdate(virNetworkObj *obj,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    virNetworkXMLOption *xmlopt,
                    unsigned int flags)  /* virNetworkUpdateFlags */
{
    g_autoptr(virNetworkDef) livedef = NULL;
    g_autoptr(virNetworkDef) configdef = NULL;

    /* normalize config data, and check for common invalid requests. */
    if (virNetworkObjConfigChangeSetup(obj, flags) < 0)
        return -1;

    if (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE) {
        g_autoptr(virNetworkDef) checkdef = NULL;

        /* work on a copy of the def */
        if (!(livedef = virNetworkDefCopy(obj->def, xmlopt, 0)))
            return -1;

        if (virNetworkDefUpdateSection(livedef, command, section,
                                       parentIndex, xml, flags) < 0) {
            return -1;
        }
        /* run a final format/parse cycle to make sure we didn't
         * add anything illegal to the def
         */
        if (!(checkdef = virNetworkDefCopy(livedef, xmlopt, 0)))
            return -1;
    }

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        g_autoptr(virNetworkDef) checkdef = NULL;

        /* work on a copy of the def */
        if (!(configdef = virNetworkDefCopy(virNetworkObjGetPersistentDef(obj),
                                            xmlopt,
                                            VIR_NETWORK_XML_INACTIVE))) {
            return -1;
        }
        if (virNetworkDefUpdateSection(configdef, command, section,
                                       parentIndex, xml, flags) < 0) {
            return -1;
        }
        if (!(checkdef = virNetworkDefCopy(configdef,
                                           xmlopt,
                                           VIR_NETWORK_XML_INACTIVE))) {
            return -1;
        }
    }

    if (configdef) {
        /* successfully modified copy, now replace original */
        if (virNetworkObjReplacePersistentDef(obj, configdef) < 0)
            return -1;

        configdef = NULL;
    }
    if (livedef) {
        /* successfully modified copy, now replace original */
        virNetworkDefFree(obj->def);
        obj->def = g_steal_pointer(&livedef);
    }

    return 0;
}


#define MATCH(FLAG) (flags & (FLAG))
static bool
virNetworkObjMatch(virNetworkObj *obj,
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
                                const char *name G_GNUC_UNUSED,
                                void *opaque)
{
    virNetworkObjListExportData *data = opaque;
    virNetworkObj *obj = payload;
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
                        virNetworkObjList *netobjs,
                        virNetworkPtr **nets,
                        virNetworkObjListFilter filter,
                        unsigned int flags)
{
    int ret = -1;
    virNetworkObjListExportData data = {
        .conn = conn, .nets = NULL, .filter = filter, .flags = flags,
        .nnets = 0, .error = false };

    virObjectRWLockRead(netobjs);
    if (nets)
        data.nets = g_new0(virNetworkPtr, virHashSize(netobjs->objs) + 1);

    virHashForEach(netobjs->objs, virNetworkObjListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.nets) {
        /* trim the array to the final size */
        VIR_REALLOC_N(data.nets, data.nnets + 1);
        *nets = g_steal_pointer(&data.nets);
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
                               const char *name G_GNUC_UNUSED,
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
virNetworkObjListForEach(virNetworkObjList *nets,
                         virNetworkObjListIterator callback,
                         void *opaque)
{
    struct virNetworkObjListForEachHelperData data = {
        .callback = callback, .opaque = opaque, .ret = 0};
    virObjectRWLockRead(nets);
    virHashForEachSafe(nets->objs, virNetworkObjListForEachHelper, &data);
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
                           const char *name G_GNUC_UNUSED,
                           void *opaque)
{
    struct virNetworkObjListGetHelperData *data = opaque;
    virNetworkObj *obj = payload;

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
        if (data->names)
            data->names[data->nnames] = g_strdup(obj->def->name);
        data->nnames++;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virNetworkObjListGetNames(virNetworkObjList *nets,
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
virNetworkObjListNumOfNetworks(virNetworkObjList *nets,
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
                             const char *name G_GNUC_UNUSED,
                             const void *opaque)
{
    const struct virNetworkObjListPruneHelperData *data = opaque;
    virNetworkObj *obj = (virNetworkObj *) payload;
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
virNetworkObjListPrune(virNetworkObjList *nets,
                       unsigned int flags)
{
    struct virNetworkObjListPruneHelperData data = {flags};

    virObjectRWLockWrite(nets);
    virHashRemoveSet(nets->objs, virNetworkObjListPruneHelper, &data);
    virObjectRWUnlock(nets);
}


char *
virNetworkObjGetPortStatusDir(virNetworkObj *net,
                              const char *stateDir)
{
    return g_strdup_printf("%s/%s/ports", stateDir, net->def->name);
}

int
virNetworkObjAddPort(virNetworkObj *net,
                     virNetworkPortDef *portdef,
                     const char *stateDir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *dir = NULL;

    virUUIDFormat(portdef->uuid, uuidstr);

    if (virHashLookup(net->ports, uuidstr)) {
        virReportError(VIR_ERR_NETWORK_PORT_EXIST,
                       _("Network port with UUID %1$s already exists"),
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


virNetworkPortDef *
virNetworkObjLookupPort(virNetworkObj *net,
                        const unsigned char *uuid)
{
    virNetworkPortDef *ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    if (!(ret = virHashLookup(net->ports, uuidstr))) {
        virReportError(VIR_ERR_NO_NETWORK_PORT,
                       _("Network port with UUID %1$s does not exist"),
                       uuidstr);
        return NULL;
    }

    return ret;
}


int
virNetworkObjDeletePort(virNetworkObj *net,
                        const unsigned char *uuid,
                        const char *stateDir)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *dir = NULL;
    virNetworkPortDef *portdef;

    virUUIDFormat(uuid, uuidstr);

    if (!(portdef = virHashLookup(net->ports, uuidstr))) {
        virReportError(VIR_ERR_NO_NETWORK_PORT,
                       _("Network port with UUID %1$s does not exist"),
                       uuidstr);
        return -1;
    }

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        return -1;

    if (virNetworkPortDefDeleteStatus(portdef, dir) < 0)
        return -1;

    if (virHashRemoveEntry(net->ports, uuidstr) < 0)
        return -1;

    return 0;
}


int
virNetworkObjDeleteAllPorts(virNetworkObj *net,
                            const char *stateDir)
{
    g_autofree char *dir = NULL;
    g_autoptr(DIR) dh = NULL;
    struct dirent *de;
    int rc;

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        return -1;

    if ((rc = virDirOpenIfExists(&dh, dir)) <= 0)
        return rc;

    while ((rc = virDirRead(dh, &de, dir)) > 0) {
        char *file = NULL;

        if (!virStringStripSuffix(de->d_name, ".xml"))
            continue;

        file = g_strdup_printf("%s/%s.xml", dir, de->d_name);

        if (unlink(file) < 0 && errno != ENOENT)
            VIR_WARN("Unable to delete %s", file);

        VIR_FREE(file);
    }

    virHashRemoveAll(net->ports);
    return 0;
}


typedef struct _virNetworkObjPortListExportData virNetworkObjPortListExportData;
struct _virNetworkObjPortListExportData {
    virNetworkPtr net;
    virNetworkDef *def;
    virNetworkPortPtr *ports;
    virNetworkPortListFilter filter;
    int nports;
    bool error;
};

static int
virNetworkObjPortListExportCallback(void *payload,
                                    const char *name G_GNUC_UNUSED,
                                    void *opaque)
{
    virNetworkObjPortListExportData *data = opaque;
    virNetworkPortDef *def = payload;
    virNetworkPortPtr port;

    if (data->error)
        return 0;

    if (data->filter &&
        !data->filter(data->net->conn, data->def, def))
        return 0;

    if (!data->ports) {
        data->nports++;
        return 0;
    }

    if (!(port = virGetNetworkPort(data->net, def->uuid))) {
        data->error = true;
        return 0;
    }

    data->ports[data->nports++] = port;

    return 0;
}


int
virNetworkObjPortListExport(virNetworkPtr net,
                            virNetworkObj *obj,
                            virNetworkPortPtr **ports,
                            virNetworkPortListFilter filter)
{
    virNetworkObjPortListExportData data = {
        net, obj->def, NULL, filter, 0, false,
    };
    int ret = -1;

    if (ports) {
        *ports = NULL;

        data.ports = g_new0(virNetworkPortPtr, virHashSize(obj->ports) + 1);
    }

    virHashForEach(obj->ports, virNetworkObjPortListExportCallback, &data);

    if (data.error)
        goto cleanup;

    if (data.ports) {
        /* trim the array to the final size */
        VIR_REALLOC_N(data.ports, data.nports + 1);
        *ports = g_steal_pointer(&data.ports);
    }

    ret = data.nports;
 cleanup:
    while (data.ports && data.nports)
        virObjectUnref(data.ports[--data.nports]);

    VIR_FREE(data.ports);
    return ret;
}


typedef struct _virNetworkObjPortListForEachData virNetworkObjPortListForEachData;
struct _virNetworkObjPortListForEachData {
    virNetworkPortListIter iter;
    void *opaque;
    bool err;
};

static int
virNetworkObjPortForEachCallback(void *payload,
                                 const char *name G_GNUC_UNUSED,
                                 void *opaque)
{
    virNetworkObjPortListForEachData *data = opaque;

    if (!data->iter(payload, data->opaque))
        data->err = true;

    return 0;
}

int
virNetworkObjPortForEach(virNetworkObj *obj,
                         virNetworkPortListIter iter,
                         void *opaque)
{
    virNetworkObjPortListForEachData data = { iter, opaque, false };
    virHashForEachSafe(obj->ports, virNetworkObjPortForEachCallback, &data);
    if (data.err)
        return -1;
    return 0;
}


static int
virNetworkObjLoadAllPorts(virNetworkObj *net,
                          const char *stateDir)
{
    g_autofree char *dir = NULL;
    g_autoptr(DIR) dh = NULL;
    struct dirent *de;
    int rc;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    g_autoptr(virNetworkPortDef) portdef = NULL;

    if (!(dir = virNetworkObjGetPortStatusDir(net, stateDir)))
        return -1;

    if ((rc = virDirOpenIfExists(&dh, dir)) <= 0)
        return rc;

    while ((rc = virDirRead(dh, &de, dir)) > 0) {
        g_autofree char *file = NULL;

        if (!virStringStripSuffix(de->d_name, ".xml"))
            continue;

        file = g_strdup_printf("%s/%s.xml", dir, de->d_name);

        portdef = virNetworkPortDefParse(NULL, file, 0);
        if (!portdef) {
            VIR_WARN("Cannot parse port %s", file);
            continue;
        }

        virUUIDFormat(portdef->uuid, uuidstr);
        if (virHashAddEntry(net->ports, uuidstr, portdef) < 0)
            return -1;

        portdef = NULL;
    }

    return 0;
}


/**
 * virNetworkObjUpdateModificationImpact:
 *
 * @obj: network object
 * @flags: flags to update the modification impact on
 *
 * Resolves virNetworkUpdateFlags in @flags so that they correctly
 * apply to the actual state of @obj. @flags may be modified after call to this
 * function.
 *
 * Returns 0 on success if @flags point to a valid combination for @obj or -1 on
 * error.
 */
int
virNetworkObjUpdateModificationImpact(virNetworkObj *obj,
                                      unsigned int *flags)
{
    bool isActive = virNetworkObjIsActive(obj);

    if ((*flags & (VIR_NETWORK_UPDATE_AFFECT_LIVE | VIR_NETWORK_UPDATE_AFFECT_CONFIG)) ==
        VIR_NETWORK_UPDATE_AFFECT_CURRENT) {
        if (isActive)
            *flags |= VIR_NETWORK_UPDATE_AFFECT_LIVE;
        else
            *flags |= VIR_NETWORK_UPDATE_AFFECT_CONFIG;
    }

    if (virNetworkObjConfigChangeSetup(obj, *flags) < 0)
        return -1;

    return 0;
}


/**
 * virNetworkObjGetDefs:
 *
 * @net: network object
 * @flags: for virNetworkUpdateFlags
 * @liveDef: Set the pointer to the live definition of @net.
 * @persDef: Set the pointer to the config definition of @net.
 *
 * Helper function to resolve @flags and retrieve correct network pointer
 * objects. This function should be used only when the network driver
 * creates net->newDef once the network has started.
 *
 * If @liveDef or @persDef are set it implies that @flags request modification
 * thereof.
 *
 * Returns 0 on success and sets @liveDef and @persDef; -1 if @flags are
 * inappropriate.
 */
static int
virNetworkObjGetDefs(virNetworkObj *net,
                    unsigned int flags,
                    virNetworkDef **liveDef,
                    virNetworkDef **persDef)
{
    if (liveDef)
        *liveDef = NULL;

    if (persDef)
        *persDef = NULL;

    if (virNetworkObjUpdateModificationImpact(net, &flags) < 0)
        return -1;

    if (virNetworkObjIsActive(net)) {
        if (liveDef && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE))
            *liveDef = net->def;

        if (persDef && (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG))
            *persDef = net->newDef;
    } else {
        if (persDef)
            *persDef = net->def;
    }

    return 0;
}


/**
 * virNetworkObjGetOneDefState:
 *
 * @net: Network object
 * @flags: for virNetworkUpdateFlags
 * @live: set to true if live config was returned (may be omitted)
 *
 * Helper function to resolve @flags and return the correct network pointer
 * object. This function returns one of @net->def or @net->persistentDef
 * according to @flags. @live is set to true if the live net config will be
 * returned. This helper should be used only in APIs that guarantee
 * that @flags contains exactly one of VIR_NETWORK_UPDATE_AFFECT_LIVE or
 * VIR_NETWORK_UPDATE_AFFECT_CONFIG and not both.
 *
 * Returns the correct definition pointer or NULL on error.
 */
static virNetworkDef *
virNetworkObjGetOneDefState(virNetworkObj *net,
                           unsigned int flags,
                           bool *live)
{
    if (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE &&
        flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        virReportInvalidArg(flags, "%s",
                            _("Flags 'VIR_NETWORK_UPDATE_AFFECT_LIVE' and 'VIR_NETWORK_UPDATE_AFFECT_CONFIG' are mutually exclusive"));
        return NULL;
    }

    if (virNetworkObjUpdateModificationImpact(net, &flags) < 0)
        return NULL;

    if (live)
        *live = flags & VIR_NETWORK_UPDATE_AFFECT_LIVE;

    if (virNetworkObjIsActive(net) && flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG)
        return net->newDef;

    return net->def;
}


/**
 * virNetworkObjGetOneDef:
 *
 * @net: Network object
 * @flags: for virNetworkUpdateFlags
 *
 * Helper function to resolve @flags and return the correct network pointer
 * object. This function returns one of @net->def or @net->persistentDef
 * according to @flags. This helper should be used only in APIs that guarantee
 * that @flags contains exactly one of VIR_NETWORK_UPDATE_AFFECT_LIVE or
 * VIR_NETWORK_UPDATE_AFFECT_CONFIG and not both.
 *
 * Returns the correct definition pointer or NULL on error.
 */
static virNetworkDef *
virNetworkObjGetOneDef(virNetworkObj *net,
                      unsigned int flags)
{
    return virNetworkObjGetOneDefState(net, flags, NULL);
}


char *
virNetworkObjGetMetadata(virNetworkObj *net,
                        int type,
                        const char *uri,
                        unsigned int flags)
{
    virNetworkDef *def;
    char *ret = NULL;

    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG, NULL);

    if (type >= VIR_NETWORK_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%1$d'"), type);
        return NULL;
    }

    if (!(def = virNetworkObjGetOneDef(net, flags)))
        return NULL;

    switch ((virNetworkMetadataType) type) {
    case VIR_NETWORK_METADATA_DESCRIPTION:
        ret = g_strdup(def->description);
        break;

    case VIR_NETWORK_METADATA_TITLE:
        ret = g_strdup(def->title);
        break;

    case VIR_NETWORK_METADATA_ELEMENT:
        if (!def->metadata)
            break;

        if (virXMLExtractNamespaceXML(def->metadata, uri, &ret) < 0)
            return NULL;
        break;

    case VIR_NETWORK_METADATA_LAST:
        break;
    }

    if (!ret)
        virReportError(VIR_ERR_NO_NETWORK_METADATA, "%s",
                       _("Requested metadata element is not present"));

    return ret;
}


static int
virNetworkDefSetMetadata(virNetworkDef *def,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri)
{
    g_autoptr(xmlDoc) doc = NULL;
    xmlNodePtr old;
    g_autoptr(xmlNode) new = NULL;

    if (type >= VIR_NETWORK_METADATA_LAST) {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unknown metadata type '%1$d'"), type);
        return -1;
    }

    switch ((virNetworkMetadataType) type) {
    case VIR_NETWORK_METADATA_DESCRIPTION:
        g_clear_pointer(&def->description, g_free);

        if (STRNEQ_NULLABLE(metadata, ""))
            def->description = g_strdup(metadata);
        break;

    case VIR_NETWORK_METADATA_TITLE:
        g_clear_pointer(&def->title, g_free);

        if (STRNEQ_NULLABLE(metadata, ""))
            def->title = g_strdup(metadata);
        break;

    case VIR_NETWORK_METADATA_ELEMENT:
        if (metadata) {

            /* parse and modify the xml from the user */
            if (!(doc = virXMLParseStringCtxt(metadata, _("(metadata_xml)"), NULL)))
                return -1;

            if (virXMLInjectNamespace(doc->children, uri, key) < 0)
                return -1;

            /* create the root node if needed */
            if (!def->metadata)
                def->metadata = virXMLNewNode(NULL, "metadata");

            if (!(new = xmlCopyNode(doc->children, 1))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Failed to copy XML node"));
                return -1;
            }
        }

        /* remove possible other nodes sharing the namespace */
        while ((old = virXMLFindChildNodeByNs(def->metadata, uri))) {
            xmlUnlinkNode(old);
            xmlFreeNode(old);
        }

        if (new) {
            if (!(xmlAddChild(def->metadata, new))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("failed to add metadata to XML document"));
                return -1;
            }
            new = NULL;
        }
        break;

    case VIR_NETWORK_METADATA_LAST:
        break;
    }

    return 0;
}


int
virNetworkObjSetMetadata(virNetworkObj *net,
                        int type,
                        const char *metadata,
                        const char *key,
                        const char *uri,
                        virNetworkXMLOption *xmlopt,
                        const char *stateDir,
                        const char *configDir,
                        unsigned int flags)
{
    virNetworkDef *def;
    virNetworkDef *persistentDef;

    virCheckFlags(VIR_NETWORK_UPDATE_AFFECT_LIVE |
                  VIR_NETWORK_UPDATE_AFFECT_CONFIG, -1);

    if (virNetworkObjGetDefs(net, flags, &def, &persistentDef) < 0)
        return -1;

    if (def) {
        if (virNetworkDefSetMetadata(def, type, metadata, key, uri) < 0)
            return -1;

        if (virNetworkObjSaveStatus(stateDir, net, xmlopt) < 0)
            return -1;
    }

    if (persistentDef) {
        if (virNetworkDefSetMetadata(persistentDef, type, metadata, key,
                                    uri) < 0)
            return -1;

        if (virNetworkSaveConfig(configDir, persistentDef, xmlopt) < 0)
            return -1;
    }

    return 0;
}
