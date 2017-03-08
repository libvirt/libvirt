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

/* currently, /sbin/tc implementation allows up to 16 bits for minor class size */
#define CLASS_ID_BITMAP_SIZE (1<<16)

struct _virNetworkObjList {
    virObjectLockable parent;

    virHashTablePtr objs;
};

static virClassPtr virNetworkObjClass;
static virClassPtr virNetworkObjListClass;
static void virNetworkObjDispose(void *obj);
static void virNetworkObjListDispose(void *obj);

static int
virNetworkObjOnceInit(void)
{
    if (!(virNetworkObjClass = virClassNew(virClassForObjectLockable(),
                                           "virNetworkObj",
                                           sizeof(virNetworkObj),
                                           virNetworkObjDispose)))
        return -1;

    if (!(virNetworkObjListClass = virClassNew(virClassForObjectLockable(),
                                               "virNetworkObjList",
                                               sizeof(virNetworkObjList),
                                               virNetworkObjListDispose)))
        return -1;
    return 0;
}


VIR_ONCE_GLOBAL_INIT(virNetworkObj)

virNetworkObjPtr
virNetworkObjNew(void)
{
    virNetworkObjPtr net;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(net = virObjectLockableNew(virNetworkObjClass)))
        return NULL;

    if (!(net->class_id = virBitmapNew(CLASS_ID_BITMAP_SIZE)))
        goto error;

    /* The first three class IDs are already taken */
    ignore_value(virBitmapSetBit(net->class_id, 0));
    ignore_value(virBitmapSetBit(net->class_id, 1));
    ignore_value(virBitmapSetBit(net->class_id, 2));

    return net;

 error:
    virObjectUnref(net);
    return NULL;
}


void
virNetworkObjEndAPI(virNetworkObjPtr *net)
{
    if (!*net)
        return;

    virObjectUnlock(*net);
    virObjectUnref(*net);
    *net = NULL;
}


virNetworkObjListPtr
virNetworkObjListNew(void)
{
    virNetworkObjListPtr nets;

    if (virNetworkObjInitialize() < 0)
        return NULL;

    if (!(nets = virObjectLockableNew(virNetworkObjListClass)))
        return NULL;

    if (!(nets->objs = virHashCreate(50, virObjectFreeHashData))) {
        virObjectUnref(nets);
        return NULL;
    }

    return nets;
}


/**
 * virNetworkObjFindByUUIDLocked:
 * @nets: list of network objects
 * @uuid: network uuid to find
 *
 * This functions requires @nets to be locked already!
 *
 * Returns: not locked, but ref'd network object.
 */
virNetworkObjPtr
virNetworkObjFindByUUIDLocked(virNetworkObjListPtr nets,
                              const unsigned char *uuid)
{
    virNetworkObjPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(uuid, uuidstr);

    ret = virHashLookup(nets->objs, uuidstr);
    if (ret)
        virObjectRef(ret);
    return ret;
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
    virNetworkObjPtr ret;

    virObjectLock(nets);
    ret = virNetworkObjFindByUUIDLocked(nets, uuid);
    virObjectUnlock(nets);
    if (ret)
        virObjectLock(ret);
    return ret;
}


static int
virNetworkObjSearchName(const void *payload,
                        const void *name ATTRIBUTE_UNUSED,
                        const void *data)
{
    virNetworkObjPtr net = (virNetworkObjPtr) payload;
    int want = 0;

    virObjectLock(net);
    if (STREQ(net->def->name, (const char *)data))
        want = 1;
    virObjectUnlock(net);
    return want;
}


/*
 * virNetworkObjFindByNameLocked:
 * @nets: list of network objects
 * @name: network name to find
 *
 * This functions requires @nets to be locked already!
 *
 * Returns: not locked, but ref'd network object.
 */
virNetworkObjPtr
virNetworkObjFindByNameLocked(virNetworkObjListPtr nets,
                              const char *name)
{
    virNetworkObjPtr ret = NULL;

    ret = virHashSearch(nets->objs, virNetworkObjSearchName, name);
    if (ret)
        virObjectRef(ret);
    return ret;
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
    virNetworkObjPtr ret;

    virObjectLock(nets);
    ret = virNetworkObjFindByNameLocked(nets, name);
    virObjectUnlock(nets);
    if (ret)
        virObjectLock(ret);
    return ret;
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
virNetworkObjDispose(void *obj)
{
    virNetworkObjPtr net = obj;

    virNetworkDefFree(net->def);
    virNetworkDefFree(net->newDef);
    virBitmapFree(net->class_id);
    virObjectUnref(net->macmap);
}


static void
virNetworkObjListDispose(void *obj)
{
    virNetworkObjListPtr nets = obj;

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
virNetworkObjUpdateAssignDef(virNetworkObjPtr network,
                             virNetworkDefPtr def,
                             bool live)
{
    if (live) {
        /* before setting new live def, save (into newDef) any
         * existing persistent (!live) def to be restored when the
         * network is destroyed, unless there is one already saved.
         */
        if (network->persistent && !network->newDef)
            network->newDef = network->def;
        else
            virNetworkDefFree(network->def);
        network->def = def;
    } else { /* !live */
        virNetworkDefFree(network->newDef);
        if (virNetworkObjIsActive(network)) {
            /* save new configuration to be restored on network
             * shutdown, leaving current live def alone
             */
            network->newDef = def;
        } else { /* !live and !active */
            if (network->def && !network->persistent) {
                /* network isn't (yet) marked active or persistent,
                 * but already has a "live" def set. This means we are
                 * currently setting the persistent def as a part of
                 * the process of starting the network, so we need to
                 * preserve the "not yet live" def in network->def.
                 */
                network->newDef = def;
            } else {
                /* either there is no live def set, or this network
                 * was already set as persistent, so the proper thing
                 * is to overwrite network->def.
                 */
                network->newDef = NULL;
                virNetworkDefFree(network->def);
                network->def = def;
            }
        }
        network->persistent = !!def;
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
virNetworkAssignDefLocked(virNetworkObjListPtr nets,
                          virNetworkDefPtr def,
                          unsigned int flags)
{
    virNetworkObjPtr network;
    virNetworkObjPtr ret = NULL;
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    /* See if a network with matching UUID already exists */
    if ((network = virNetworkObjFindByUUIDLocked(nets, def->uuid))) {
        virObjectLock(network);
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(network->def->name, def->name)) {
            virUUIDFormat(network->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' is already defined with uuid %s"),
                           network->def->name, uuidstr);
            goto cleanup;
        }

        if (flags & VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE) {
            /* UUID & name match, but if network is already active, refuse it */
            if (virNetworkObjIsActive(network)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("network is already active as '%s'"),
                               network->def->name);
                goto cleanup;
            }
        }

        virNetworkObjUpdateAssignDef(network,
                                     def,
                                     !!(flags & VIR_NETWORK_OBJ_LIST_ADD_LIVE));
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        if ((network = virNetworkObjFindByNameLocked(nets, def->name))) {
            virObjectLock(network);
            virUUIDFormat(network->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto cleanup;
        }

        if (!(network = virNetworkObjNew()))
              goto cleanup;

        virObjectLock(network);

        virUUIDFormat(def->uuid, uuidstr);
        if (virHashAddEntry(nets->objs, uuidstr, network) < 0)
            goto cleanup;

        network->def = def;
        network->persistent = !(flags & VIR_NETWORK_OBJ_LIST_ADD_LIVE);
        virObjectRef(network);
    }

    ret = network;
    network = NULL;

 cleanup:
    virNetworkObjEndAPI(&network);
    return ret;
}


/*
 * virNetworkAssignDef:
 * @nets: list of all networks
 * @def: the new NetworkDef (will be consumed by this function iff successful)
 * @flags: bitwise-OR of VIR_NETWORK_OBJ_LIST_ADD_* flags
 *
 * Either replace the appropriate copy of the NetworkDef with name
 * matching def->name or, if not found, create a new NetworkObj with
 * def. For an existing network, use "live" and current state of the
 * network to determine which to replace.
 *
 * Look at virNetworkAssignDefLocked() for @flags description.
 *
 * Returns NULL on error, virNetworkObjPtr on success.
 */
virNetworkObjPtr
virNetworkAssignDef(virNetworkObjListPtr nets,
                    virNetworkDefPtr def,
                    unsigned int flags)
{
    virNetworkObjPtr network;

    virObjectLock(nets);
    network = virNetworkAssignDefLocked(nets, def, flags);
    virObjectUnlock(nets);
    return network;
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
virNetworkObjSetDefTransient(virNetworkObjPtr network,
                             bool live)
{
    if (!virNetworkObjIsActive(network) && !live)
        return 0;

    if (!network->persistent || network->newDef)
        return 0;

    network->newDef = virNetworkDefCopy(network->def, VIR_NETWORK_XML_INACTIVE);
    return network->newDef ? 0 : -1;
}


/* virNetworkObjUnsetDefTransient:
 *
 * This *undoes* what virNetworkObjSetDefTransient did.
 */
void
virNetworkObjUnsetDefTransient(virNetworkObjPtr network)
{
    if (network->newDef) {
        virNetworkDefFree(network->def);
        network->def = network->newDef;
        network->newDef = NULL;
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
virNetworkObjGetPersistentDef(virNetworkObjPtr network)
{
    if (network->newDef)
        return network->newDef;
    else
        return network->def;
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
virNetworkObjReplacePersistentDef(virNetworkObjPtr network,
                                  virNetworkDefPtr def)
{
    if (virNetworkObjIsActive(network)) {
        virNetworkDefFree(network->newDef);
        network->newDef = def;
    } else {
        virNetworkDefFree(network->def);
        network->def = def;
    }
    return 0;
}


/*
 * virNetworkConfigChangeSetup:
 *
 * 1) checks whether network state is consistent with the requested
 *    type of modification.
 *
 * 3) make sure there are separate "def" and "newDef" copies of
 *    networkDef if appropriate.
 *
 * Returns 0 on success, -1 on error.
 */
int
virNetworkConfigChangeSetup(virNetworkObjPtr network,
                            unsigned int flags)
{
    bool isActive;
    int ret = -1;

    isActive = virNetworkObjIsActive(network);

    if (!isActive && (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("network is not running"));
        goto cleanup;
    }

    if (flags & VIR_NETWORK_UPDATE_AFFECT_CONFIG) {
        if (!network->persistent) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("cannot change persistent config of a "
                             "transient network"));
            goto cleanup;
        }
        /* this should already have been done by the driver, but do it
         * anyway just in case.
         */
        if (isActive && (virNetworkObjSetDefTransient(network, false) < 0))
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


void
virNetworkRemoveInactive(virNetworkObjListPtr nets,
                         virNetworkObjPtr net)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];

    virUUIDFormat(net->def->uuid, uuidstr);
    virObjectRef(net);
    virObjectUnlock(net);
    virObjectLock(nets);
    virObjectLock(net);
    virHashRemoveEntry(nets->objs, uuidstr);
    virObjectUnlock(nets);
    virObjectUnref(net);
}


static char *
virNetworkObjFormat(virNetworkObjPtr net,
                    unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *class_id = virBitmapFormat(net->class_id);
    size_t i;

    if (!class_id)
        goto error;

    virBufferAddLit(&buf, "<networkstatus>\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferAsprintf(&buf, "<class_id bitmap='%s'/>\n", class_id);
    virBufferAsprintf(&buf, "<floor sum='%llu'/>\n", net->floor_sum);
    VIR_FREE(class_id);

    for (i = 0; i < VIR_NETWORK_TAINT_LAST; i++) {
        if (net->taint & (1 << i))
            virBufferAsprintf(&buf, "<taint flag='%s'/>\n",
                              virNetworkTaintTypeToString(i));
    }

    if (virNetworkDefFormatBuf(&buf, net->def, flags) < 0)
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
virNetworkSaveStatus(const char *statusDir,
                     virNetworkObjPtr network)
{
    int ret = -1;
    int flags = 0;
    char *xml;

    if (!(xml = virNetworkObjFormat(network, flags)))
        goto cleanup;

    if (virNetworkSaveXML(statusDir, network->def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


virNetworkObjPtr
virNetworkLoadState(virNetworkObjListPtr nets,
                    const char *stateDir,
                    const char *name)
{
    char *configFile = NULL;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr net = NULL;
    xmlDocPtr xml = NULL;
    xmlNodePtr node = NULL, *nodes = NULL;
    xmlXPathContextPtr ctxt = NULL;
    virBitmapPtr class_id_map = NULL;
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
    if (xmlStrEqual(node->name, BAD_CAST "networkstatus")) {
        /* Newer network status file. Contains useful
         * info which are not to be found in bare config XML */
        char *class_id = NULL;
        char *floor_sum = NULL;

        ctxt->node = node;
        if ((class_id = virXPathString("string(./class_id[1]/@bitmap)", ctxt))) {
            if (virBitmapParse(class_id, &class_id_map,
                               CLASS_ID_BITMAP_SIZE) < 0) {
                VIR_FREE(class_id);
                goto error;
            }
        }
        VIR_FREE(class_id);

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
    if (!(net = virNetworkAssignDef(nets, def, VIR_NETWORK_OBJ_LIST_ADD_LIVE)))
        goto error;
    /* do not put any "goto error" below this comment */

    /* assign status data stored in the network object */
    if (class_id_map) {
        virBitmapFree(net->class_id);
        net->class_id = class_id_map;
    }

    if (floor_sum_val > 0)
        net->floor_sum = floor_sum_val;

    net->taint = taint;
    net->active = 1; /* any network with a state file is by definition active */

 cleanup:
    VIR_FREE(configFile);
    xmlFreeDoc(xml);
    xmlXPathFreeContext(ctxt);
    return net;

 error:
    VIR_FREE(nodes);
    virBitmapFree(class_id_map);
    virNetworkDefFree(def);
    goto cleanup;
}


virNetworkObjPtr
virNetworkLoadConfig(virNetworkObjListPtr nets,
                     const char *configDir,
                     const char *autostartDir,
                     const char *name)
{
    char *configFile = NULL, *autostartLink = NULL;
    virNetworkDefPtr def = NULL;
    virNetworkObjPtr net;
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

    if (def->forward.type == VIR_NETWORK_FORWARD_NONE ||
        def->forward.type == VIR_NETWORK_FORWARD_NAT ||
        def->forward.type == VIR_NETWORK_FORWARD_ROUTE ||
        def->forward.type == VIR_NETWORK_FORWARD_OPEN) {

        if (!def->mac_specified) {
            virNetworkSetBridgeMacAddr(def);
            virNetworkSaveConfig(configDir, def);
        }
    } else {
        /* Throw away MAC address for other forward types,
         * which could have been generated by older libvirt RPMs */
        def->mac_specified = false;
    }

    if (!(net = virNetworkAssignDef(nets, def, 0)))
        goto error;

    net->autostart = autostart;

    VIR_FREE(configFile);
    VIR_FREE(autostartLink);

    return net;

 error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virNetworkDefFree(def);
    return NULL;
}


int
virNetworkLoadAllState(virNetworkObjListPtr nets,
                       const char *stateDir)
{
    DIR *dir;
    struct dirent *entry;
    int ret = -1;
    int rc;

    if ((rc = virDirOpenIfExists(&dir, stateDir)) <= 0)
        return rc;

    while ((ret = virDirRead(dir, &entry, stateDir)) > 0) {
        virNetworkObjPtr net;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        net = virNetworkLoadState(nets, stateDir, entry->d_name);
        virNetworkObjEndAPI(&net);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virNetworkLoadAllConfigs(virNetworkObjListPtr nets,
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
        virNetworkObjPtr net;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        net = virNetworkLoadConfig(nets,
                                   configDir,
                                   autostartDir,
                                   entry->d_name);
        virNetworkObjEndAPI(&net);
    }

    VIR_DIR_CLOSE(dir);
    return ret;
}


int
virNetworkDeleteConfig(const char *configDir,
                       const char *autostartDir,
                       virNetworkObjPtr net)
{
    char *configFile = NULL;
    char *autostartLink = NULL;
    int ret = -1;

    if ((configFile = virNetworkConfigFile(configDir, net->def->name)) == NULL)
        goto error;
    if ((autostartLink = virNetworkConfigFile(autostartDir, net->def->name)) == NULL)
        goto error;

    /* Not fatal if this doesn't work */
    unlink(autostartLink);
    net->autostart = 0;

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


struct virNetworkBridgeInUseHelperData {
    const char *bridge;
    const char *skipname;
};

static int
virNetworkBridgeInUseHelper(const void *payload,
                            const void *name ATTRIBUTE_UNUSED,
                            const void *opaque)
{
    int ret;
    virNetworkObjPtr net = (virNetworkObjPtr) payload;
    const struct virNetworkBridgeInUseHelperData *data = opaque;

    virObjectLock(net);
    if (data->skipname &&
        ((net->def && STREQ(net->def->name, data->skipname)) ||
         (net->newDef && STREQ(net->newDef->name, data->skipname))))
        ret = 0;
    else if ((net->def && net->def->bridge &&
              STREQ(net->def->bridge, data->bridge)) ||
             (net->newDef && net->newDef->bridge &&
              STREQ(net->newDef->bridge, data->bridge)))
        ret = 1;
    else
        ret = 0;
    virObjectUnlock(net);
    return ret;
}


int
virNetworkBridgeInUse(virNetworkObjListPtr nets,
                      const char *bridge,
                      const char *skipname)
{
    virNetworkObjPtr obj;
    struct virNetworkBridgeInUseHelperData data = {bridge, skipname};

    virObjectLock(nets);
    obj = virHashSearch(nets->objs, virNetworkBridgeInUseHelper, &data);
    virObjectUnlock(nets);

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
virNetworkObjUpdate(virNetworkObjPtr network,
                    unsigned int command, /* virNetworkUpdateCommand */
                    unsigned int section, /* virNetworkUpdateSection */
                    int parentIndex,
                    const char *xml,
                    unsigned int flags)  /* virNetworkUpdateFlags */
{
    int ret = -1;
    virNetworkDefPtr livedef = NULL, configdef = NULL;

    /* normalize config data, and check for common invalid requests. */
    if (virNetworkConfigChangeSetup(network, flags) < 0)
       goto cleanup;

    if (flags & VIR_NETWORK_UPDATE_AFFECT_LIVE) {
        virNetworkDefPtr checkdef;

        /* work on a copy of the def */
        if (!(livedef = virNetworkDefCopy(network->def, 0)))
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
        if (!(configdef = virNetworkDefCopy(virNetworkObjGetPersistentDef(network),
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
        if (virNetworkObjReplacePersistentDef(network, configdef) < 0)
           goto cleanup;
        configdef = NULL;
    }
    if (livedef) {
        /* successfully modified copy, now replace original */
        virNetworkDefFree(network->def);
        network->def = livedef;
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
virNetworkMatch(virNetworkObjPtr netobj,
                unsigned int flags)
{
    /* filter by active state */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_ACTIVE) &&
           virNetworkObjIsActive(netobj)) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_INACTIVE) &&
           !virNetworkObjIsActive(netobj))))
        return false;

    /* filter by persistence */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_PERSISTENT) &&
           netobj->persistent) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_TRANSIENT) &&
           !netobj->persistent)))
        return false;

    /* filter by autostart option */
    if (MATCH(VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART) &&
        !((MATCH(VIR_CONNECT_LIST_NETWORKS_AUTOSTART) &&
           netobj->autostart) ||
          (MATCH(VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART) &&
           !netobj->autostart)))
        return false;

    return true;
}
#undef MATCH


struct virNetworkObjListData {
    virConnectPtr conn;
    virNetworkPtr *nets;
    virNetworkObjListFilter filter;
    unsigned int flags;
    int nnets;
    bool error;
};

static int
virNetworkObjListPopulate(void *payload,
                          const void *name ATTRIBUTE_UNUSED,
                          void *opaque)
{
    struct virNetworkObjListData *data = opaque;
    virNetworkObjPtr obj = payload;
    virNetworkPtr net = NULL;

    if (data->error)
        return 0;

    virObjectLock(obj);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;

    if (!virNetworkMatch(obj, data->flags))
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
    struct virNetworkObjListData data = { conn, NULL, filter, flags, 0, false};

    virObjectLock(netobjs);
    if (nets && VIR_ALLOC_N(data.nets, virHashSize(netobjs->objs) + 1) < 0)
        goto cleanup;

    virHashForEach(netobjs->objs, virNetworkObjListPopulate, &data);

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
    virObjectUnlock(netobjs);
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
    struct virNetworkObjListForEachHelperData data = {callback, opaque, 0};
    virObjectLock(nets);
    virHashForEach(nets->objs, virNetworkObjListForEachHelper, &data);
    virObjectUnlock(nets);
    return data.ret;
}


struct virNetworkObjListGetHelperData {
    virConnectPtr conn;
    virNetworkObjListFilter filter;
    char **names;
    int nnames;
    bool active;
    int got;
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

    if (data->nnames >= 0 &&
        data->got == data->nnames)
        return 0;

    virObjectLock(obj);

    if (data->filter &&
        !data->filter(data->conn, obj->def))
        goto cleanup;

    if ((data->active && virNetworkObjIsActive(obj)) ||
        (!data->active && !virNetworkObjIsActive(obj))) {
        if (data->names &&
            VIR_STRDUP(data->names[data->got], obj->def->name) < 0) {
            data->error = true;
            goto cleanup;
        }
        data->got++;
    }

 cleanup:
    virObjectUnlock(obj);
    return 0;
}


int
virNetworkObjListGetNames(virNetworkObjListPtr nets,
                          bool active,
                          char **names,
                          int nnames,
                          virNetworkObjListFilter filter,
                          virConnectPtr conn)
{
    int ret = -1;

    struct virNetworkObjListGetHelperData data = {
        conn, filter, names, nnames, active, 0, false};

    virObjectLock(nets);
    virHashForEach(nets->objs, virNetworkObjListGetHelper, &data);
    virObjectUnlock(nets);

    if (data.error)
        goto cleanup;

    ret = data.got;
 cleanup:
    if (ret < 0) {
        while (data.got)
            VIR_FREE(data.names[--data.got]);
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
        conn, filter, NULL, -1, active, 0, false};

    virObjectLock(nets);
    virHashForEach(nets->objs, virNetworkObjListGetHelper, &data);
    virObjectUnlock(nets);

    return data.got;
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
    want = virNetworkMatch(obj, data->flags);
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

    virObjectLock(nets);
    virHashRemoveSet(nets->objs, virNetworkObjListPruneHelper, &data);
    virObjectUnlock(nets);
}
