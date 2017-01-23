/*
 * network_conf.c: network XML handling
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006-2008 Daniel P. Berrange
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

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>

#include "virerror.h"
#include "datatypes.h"
#include "network_conf.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "viralloc.h"
#include "virxml.h"
#include "viruuid.h"
#include "virbuffer.h"
#include "c-ctype.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NETWORK
/* currently, /sbin/tc implementation allows up to 16 bits for minor class size */
#define CLASS_ID_BITMAP_SIZE (1<<16)

struct _virNetworkObjList {
    virObjectLockable parent;

    virHashTablePtr objs;
};

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route", "open",
              "bridge", "private", "vepa", "passthrough",
              "hostdev")

VIR_ENUM_IMPL(virNetworkBridgeMACTableManager,
              VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LAST,
              "default", "kernel", "libvirt")

VIR_ENUM_DECL(virNetworkForwardHostdevDevice)
VIR_ENUM_IMPL(virNetworkForwardHostdevDevice,
              VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST,
              "none", "pci", "netdev")

VIR_ENUM_IMPL(virNetworkForwardDriverName,
              VIR_NETWORK_FORWARD_DRIVER_NAME_LAST,
              "default",
              "kvm",
              "vfio")

VIR_ENUM_IMPL(virNetworkTaint, VIR_NETWORK_TAINT_LAST,
              "hook-script");

static virClassPtr virNetworkObjClass;
static virClassPtr virNetworkObjListClass;
static void virNetworkObjDispose(void *obj);
static void virNetworkObjListDispose(void *obj);

static int virNetworkObjOnceInit(void)
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

virNetworkObjListPtr virNetworkObjListNew(void)
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
virPortGroupDefClear(virPortGroupDefPtr def)
{
    VIR_FREE(def->name);
    VIR_FREE(def->virtPortProfile);
    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    def->bandwidth = NULL;
}

static void
virNetworkForwardIfDefClear(virNetworkForwardIfDefPtr def)
{
    if (def->type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV)
        VIR_FREE(def->device.dev);
}

static void
virNetworkForwardPfDefClear(virNetworkForwardPfDefPtr def)
{
    VIR_FREE(def->dev);
}

static void
virNetworkDHCPHostDefClear(virNetworkDHCPHostDefPtr def)
{
    VIR_FREE(def->mac);
    VIR_FREE(def->id);
    VIR_FREE(def->name);
}

static void
virNetworkIPDefClear(virNetworkIPDefPtr def)
{
    VIR_FREE(def->family);
    VIR_FREE(def->ranges);

    while (def->nhosts)
        virNetworkDHCPHostDefClear(&def->hosts[--def->nhosts]);

    VIR_FREE(def->hosts);
    VIR_FREE(def->tftproot);
    VIR_FREE(def->bootfile);
}

static void
virNetworkDNSTxtDefClear(virNetworkDNSTxtDefPtr def)
{
    VIR_FREE(def->name);
    VIR_FREE(def->value);
}

static void
virNetworkDNSHostDefClear(virNetworkDNSHostDefPtr def)
{
    while (def->nnames)
        VIR_FREE(def->names[--def->nnames]);
    VIR_FREE(def->names);
}

static void
virNetworkDNSSrvDefClear(virNetworkDNSSrvDefPtr def)
{
    VIR_FREE(def->domain);
    VIR_FREE(def->service);
    VIR_FREE(def->protocol);
    VIR_FREE(def->target);
}


static void
virNetworkDNSForwarderClear(virNetworkDNSForwarderPtr def)
{
    VIR_FREE(def->domain);
}


static void
virNetworkDNSDefClear(virNetworkDNSDefPtr def)
{
    if (def->forwarders) {
        while (def->nfwds)
            virNetworkDNSForwarderClear(&def->forwarders[--def->nfwds]);
        VIR_FREE(def->forwarders);
    }
    if (def->txts) {
        while (def->ntxts)
            virNetworkDNSTxtDefClear(&def->txts[--def->ntxts]);
        VIR_FREE(def->txts);
    }
    if (def->hosts) {
        while (def->nhosts)
            virNetworkDNSHostDefClear(&def->hosts[--def->nhosts]);
        VIR_FREE(def->hosts);
    }
    if (def->srvs) {
        while (def->nsrvs)
            virNetworkDNSSrvDefClear(&def->srvs[--def->nsrvs]);
        VIR_FREE(def->srvs);
    }
}

static void
virNetworkForwardDefClear(virNetworkForwardDefPtr def)
{
    size_t i;

    for (i = 0; i < def->npfs && def->pfs; i++)
        virNetworkForwardPfDefClear(&def->pfs[i]);
    VIR_FREE(def->pfs);

    for (i = 0; i < def->nifs && def->ifs; i++)
        virNetworkForwardIfDefClear(&def->ifs[i]);
    VIR_FREE(def->ifs);
    def->nifs = def->npfs = 0;
}

void
virNetworkDefFree(virNetworkDefPtr def)
{
    size_t i;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->bridge);
    VIR_FREE(def->domain);

    virNetworkForwardDefClear(&def->forward);

    for (i = 0; i < def->nips && def->ips; i++)
        virNetworkIPDefClear(&def->ips[i]);
    VIR_FREE(def->ips);

    for (i = 0; i < def->nroutes && def->routes; i++)
        virNetDevIPRouteFree(def->routes[i]);
    VIR_FREE(def->routes);

    for (i = 0; i < def->nPortGroups && def->portGroups; i++)
        virPortGroupDefClear(&def->portGroups[i]);
    VIR_FREE(def->portGroups);

    virNetworkDNSDefClear(&def->dns);

    VIR_FREE(def->virtPortProfile);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);

    xmlFreeNode(def->metadata);

    VIR_FREE(def);
}

static void
virNetworkObjDispose(void *obj)
{
    virNetworkObjPtr net = obj;

    virNetworkDefFree(net->def);
    virNetworkDefFree(net->newDef);
    virBitmapFree(net->class_id);
}

static void
virNetworkObjListDispose(void *obj)
{
    virNetworkObjListPtr nets = obj;

    virHashFree(nets->objs);
}

/*
 * virNetworkObjAssignDef:
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
virNetworkObjAssignDef(virNetworkObjPtr network,
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

        virNetworkObjAssignDef(network,
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
virNetworkObjSetDefTransient(virNetworkObjPtr network, bool live)
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
 * virNetworkDefCopy:
 * @def: NetworkDef to copy
 * @flags: VIR_NETWORK_XML_INACTIVE if appropriate
 *
 * make a deep copy of the given NetworkDef
 *
 * Returns a new NetworkDef on success, or NULL on failure.
 */
virNetworkDefPtr
virNetworkDefCopy(virNetworkDefPtr def, unsigned int flags)
{
    char *xml = NULL;
    virNetworkDefPtr newDef = NULL;

    if (!def) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("NULL NetworkDef"));
        return NULL;
    }

    /* deep copy with a format/parse cycle */
    if (!(xml = virNetworkDefFormat(def, flags)))
        goto cleanup;
    newDef = virNetworkDefParseString(xml);
 cleanup:
    VIR_FREE(xml);
    return newDef;
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
virNetworkConfigChangeSetup(virNetworkObjPtr network, unsigned int flags)
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

void virNetworkRemoveInactive(virNetworkObjListPtr nets,
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

/* return ips[index], or NULL if there aren't enough ips */
virNetworkIPDefPtr
virNetworkDefGetIPByIndex(const virNetworkDef *def,
                          int family, size_t n)
{
    size_t i;

    if (!def->ips || n >= def->nips)
        return NULL;

    if (family == AF_UNSPEC)
        return &def->ips[n];

    /* find the nth ip of type "family" */
    for (i = 0; i < def->nips; i++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->ips[i].address, family)
            && (n-- <= 0)) {
            return &def->ips[i];
        }
    }
    /* failed to find enough of the right family */
    return NULL;
}

/* return routes[index], or NULL if there aren't enough routes */
virNetDevIPRoutePtr
virNetworkDefGetRouteByIndex(const virNetworkDef *def,
                             int family, size_t n)
{
    size_t i;

    if (!def->routes || n >= def->nroutes)
        return NULL;

    if (family == AF_UNSPEC)
        return def->routes[n];

    /* find the nth route of type "family" */
    for (i = 0; i < def->nroutes; i++) {
        virSocketAddrPtr addr = virNetDevIPRouteGetAddress(def->routes[i]);
        if (VIR_SOCKET_ADDR_IS_FAMILY(addr, family)
            && (n-- <= 0)) {
            return def->routes[i];
        }
    }

    /* failed to find enough of the right family */
    return NULL;
}

/* return number of 1 bits in netmask for the network's ipAddress,
 * or -1 on error
 */
int virNetworkIPDefPrefix(const virNetworkIPDef *def)
{
    return virSocketAddrGetIPPrefix(&def->address,
                                    &def->netmask,
                                    def->prefix);
}

/* Fill in a virSocketAddr with the proper netmask for this
 * definition, based on either the definition's netmask, or its
 * prefix. Return -1 on error (and set the netmask family to AF_UNSPEC)
 */
int virNetworkIPDefNetmask(const virNetworkIPDef *def,
                           virSocketAddrPtr netmask)
{
    if (VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
        *netmask = def->netmask;
        return 0;
    }

    return virSocketAddrPrefixToNetmask(virNetworkIPDefPrefix(def), netmask,
                                        VIR_SOCKET_ADDR_FAMILY(&def->address));
}


static int
virSocketAddrRangeParseXML(const char *networkName,
                           virNetworkIPDefPtr ipdef,
                           xmlNodePtr node,
                           virSocketAddrRangePtr range)
{


    char *start = NULL, *end = NULL;
    int ret = -1;

    if (!(start = virXMLPropString(node, "start"))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing 'start' attribute in dhcp range for network '%s'"),
                       networkName);
        goto cleanup;
    }
    if (virSocketAddrParse(&range->start, start, AF_UNSPEC) < 0)
        goto cleanup;

    if (!(end = virXMLPropString(node, "end"))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing 'end' attribute in dhcp range for network '%s'"),
                       networkName);
        goto cleanup;
    }
    if (virSocketAddrParse(&range->end, end, AF_UNSPEC) < 0)
        goto cleanup;

    /* do a sanity check of the range */
    if (virSocketAddrGetRange(&range->start, &range->end, &ipdef->address,
                              virNetworkIPDefPrefix(ipdef)) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(start);
    VIR_FREE(end);
    return ret;
}

static int
virNetworkDHCPHostDefParseXML(const char *networkName,
                              virNetworkIPDefPtr def,
                              xmlNodePtr node,
                              virNetworkDHCPHostDefPtr host,
                              bool partialOkay)
{
    char *mac = NULL, *name = NULL, *ip = NULL, *id = NULL;
    virMacAddr addr;
    virSocketAddr inaddr;
    int ret = -1;

    mac = virXMLPropString(node, "mac");
    if (mac != NULL) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid to specify MAC address '%s' "
                             "in network '%s' IPv6 static host definition"),
                           mac, networkName);
            goto cleanup;
        }
        if (virMacAddrParse(mac, &addr) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Cannot parse MAC address '%s' in network '%s'"),
                           mac, networkName);
            goto cleanup;
        }
        if (virMacAddrIsMulticast(&addr)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("expected unicast mac address, found "
                             "multicast '%s' in network '%s'"),
                           (const char *)mac, networkName);
            goto cleanup;
        }
    }

    id = virXMLPropString(node, "id");
    if (id) {
        char *cp = id + strspn(id, "0123456789abcdefABCDEF:");
        if (*cp) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid character '%c' in id '%s' of network '%s'"),
                           *cp, id, networkName);
            goto cleanup;
        }
    }

    name = virXMLPropString(node, "name");
    if (name && (!c_isalpha(name[0]))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Cannot use host name '%s' in network '%s'"),
                       name, networkName);
        goto cleanup;
    }

    ip = virXMLPropString(node, "ip");
    if (ip && (virSocketAddrParse(&inaddr, ip, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid IP address in static host definition "
                         "for network '%s'"),
                       networkName);
        goto cleanup;
    }

    if (partialOkay) {
        /* for search/match, you just need one of the three */
        if (!(mac || name || ip)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("At least one of name, mac, or ip attribute "
                             "must be specified for static host definition "
                             "in network '%s' "),
                           networkName);
            goto cleanup;
        }
    } else {
        /* normal usage - you need at least name (IPv6) or one of MAC
         * address or name (IPv4)
         */
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            if (!(id || name)) {
                virReportError(VIR_ERR_XML_ERROR,
                           _("Static host definition in IPv6 network '%s' "
                             "must have id or name attribute"),
                           networkName);
                goto cleanup;
            }
        } else if (!(mac || name)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Static host definition in IPv4 network '%s' "
                             "must have mac or name attribute"),
                           networkName);
            goto cleanup;
        }
        if (!ip) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Missing IP address in static host definition "
                             "for network '%s'"),
                           networkName);
            goto cleanup;
        }
    }

    host->mac = mac;
    mac = NULL;
    host->id = id;
    id = NULL;
    host->name = name;
    name = NULL;
    if (ip)
        host->ip = inaddr;
    ret = 0;

 cleanup:
    VIR_FREE(mac);
    VIR_FREE(id);
    VIR_FREE(name);
    VIR_FREE(ip);
    return ret;
}

static int
virNetworkDHCPDefParseXML(const char *networkName,
                          xmlNodePtr node,
                          virNetworkIPDefPtr def)
{
    int ret = -1;
    xmlNodePtr cur;
    virSocketAddrRange range;
    virNetworkDHCPHostDef host;

    memset(&range, 0, sizeof(range));
    memset(&host, 0, sizeof(host));

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "range")) {

            if (virSocketAddrRangeParseXML(networkName, def, cur, &range) < 0)
                goto cleanup;
            if (VIR_APPEND_ELEMENT(def->ranges, def->nranges, range) < 0)
                goto cleanup;

        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "host")) {

            if (virNetworkDHCPHostDefParseXML(networkName, def, cur,
                                              &host, false) < 0)
                goto cleanup;
            if (VIR_APPEND_ELEMENT(def->hosts, def->nhosts, host) < 0)
                goto cleanup;

        } else if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) &&
                   cur->type == XML_ELEMENT_NODE &&
                   xmlStrEqual(cur->name, BAD_CAST "bootp")) {
            char *file;
            char *server;
            virSocketAddr inaddr;
            memset(&inaddr, 0, sizeof(inaddr));

            if (!(file = virXMLPropString(cur, "file"))) {
                cur = cur->next;
                continue;
            }
            server = virXMLPropString(cur, "server");

            if (server &&
                virSocketAddrParse(&inaddr, server, AF_UNSPEC) < 0) {
                VIR_FREE(file);
                VIR_FREE(server);
                goto cleanup;
            }

            def->bootfile = file;
            def->bootserver = inaddr;
            VIR_FREE(server);
        }

        cur = cur->next;
    }

    ret = 0;
 cleanup:
    virNetworkDHCPHostDefClear(&host);
    return ret;
}

static int
virNetworkDNSHostDefParseXML(const char *networkName,
                             xmlNodePtr node,
                             virNetworkDNSHostDefPtr def,
                             bool partialOkay)
{
    xmlNodePtr cur;
    char *ip;

    if (!(ip = virXMLPropString(node, "ip")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing IP address in network '%s' DNS HOST record"),
                       networkName);
        goto error;
    }

    if (ip && (virSocketAddrParse(&def->ip, ip, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Invalid IP address in network '%s' DNS HOST record"),
                       networkName);
        VIR_FREE(ip);
        goto error;
    }
    VIR_FREE(ip);

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "hostname")) {
              if (cur->children != NULL) {
                  char *name = (char *) xmlNodeGetContent(cur);

                  if (!name) {
                      virReportError(VIR_ERR_XML_DETAIL,
                                     _("Missing hostname in network '%s' DNS HOST record"),
                                     networkName);
                      goto error;
                  }
                  if (VIR_APPEND_ELEMENT(def->names, def->nnames, name) < 0) {
                      VIR_FREE(name);
                      goto error;
                  }
              }
        }
        cur = cur->next;
    }
    if (def->nnames == 0 && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing hostname in network '%s' DNS HOST record"),
                       networkName);
        goto error;
    }

    if (!VIR_SOCKET_ADDR_VALID(&def->ip) && def->nnames == 0) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing ip and hostname in network '%s' DNS HOST record"),
                       networkName);
        goto error;
    }

    return 0;

 error:
    virNetworkDNSHostDefClear(def);
    return -1;
}

/* This includes all characters used in the names of current
 * /etc/services and /etc/protocols files (on Fedora 20), except ".",
 * which we can't allow because it would conflict with the use of "."
 * as a field separator in the SRV record, there appears to be no way
 * to escape it in, and the protocols/services that use "." in the
 * name are obscure and unlikely to be used anyway.
 */
#define PROTOCOL_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
    "-+/"

#define SERVICE_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" \
    "_-+/*"

static int
virNetworkDNSSrvDefParseXML(const char *networkName,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt,
                            virNetworkDNSSrvDefPtr def,
                            bool partialOkay)
{
    int ret;
    xmlNodePtr save_ctxt = ctxt->node;

    ctxt->node = node;

    if (!(def->service = virXMLPropString(node, "service")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required service attribute in DNS SRV record "
                         "of network '%s'"), networkName);
        goto error;
    }
    if (def->service) {
        if (strlen(def->service) > DNS_RECORD_LENGTH_SRV) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("service attribute '%s' in network '%s' is too long, "
                             "limit is %d bytes"),
                           def->service, networkName, DNS_RECORD_LENGTH_SRV);
            goto error;
        }
        if (strspn(def->service, SERVICE_CHARS) < strlen(def->service)) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("invalid character in service attribute '%s' "
                             "in DNS SRV record of network '%s'"),
                           def->service, networkName);
            goto error;
        }
    }

    if (!(def->protocol = virXMLPropString(node, "protocol")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required protocol attribute "
                         "in DNS SRV record '%s' of network '%s'"),
                       def->service, networkName);
        goto error;
    }
    if (def->protocol &&
        strspn(def->protocol, PROTOCOL_CHARS) < strlen(def->protocol)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid character in protocol attribute '%s' "
                         "in DNS SRV record of network '%s'"),
                       def->protocol, networkName);
        goto error;
    }

    /* Following attributes are optional */
    def->domain = virXMLPropString(node, "domain");
    def->target = virXMLPropString(node, "target");

    ret = virXPathUInt("string(./@port)", ctxt, &def->port);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV port attribute not permitted without "
                         "target for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && (def->port < 1 || def->port > 65535))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid DNS SRV port attribute "
                         "for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }

    ret = virXPathUInt("string(./@priority)", ctxt, &def->priority);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV priority attribute not permitted without "
                         "target for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && def->priority > 65535)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Invalid DNS SRV priority attribute "
                         "for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }

    ret = virXPathUInt("string(./@weight)", ctxt, &def->weight);
    if (ret >= 0 && !def->target) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("DNS SRV weight attribute not permitted without "
                         "target for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }
    if (ret == -2 || (ret >= 0 && def->weight > 65535)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("invalid DNS SRV weight attribute "
                         "for service '%s' in network '%s'"),
                       def->service, networkName);
        goto error;
    }

    ctxt->node = save_ctxt;
    return 0;

 error:
    virNetworkDNSSrvDefClear(def);
    ctxt->node = save_ctxt;
    return -1;
}

static int
virNetworkDNSTxtDefParseXML(const char *networkName,
                            xmlNodePtr node,
                            virNetworkDNSTxtDefPtr def,
                            bool partialOkay)
{
    const char *bad = " ,";

    if (!(def->name = virXMLPropString(node, "name"))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required name attribute in DNS TXT record "
                         "of network %s"), networkName);
        goto error;
    }
    if (strcspn(def->name, bad) != strlen(def->name)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("prohibited character in DNS TXT record "
                         "name '%s' of network %s"), def->name, networkName);
        goto error;
    }
    if (!(def->value = virXMLPropString(node, "value")) && !partialOkay) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("missing required value attribute in DNS TXT record "
                         "named '%s' of network %s"), def->name, networkName);
        goto error;
    }

    if (!(def->name || def->value)) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing required name or value "
                         "in DNS TXT record of network %s"), networkName);
        goto error;
    }
    return 0;

 error:
    virNetworkDNSTxtDefClear(def);
    return -1;
}

static int
virNetworkDNSDefParseXML(const char *networkName,
                         xmlNodePtr node,
                         xmlXPathContextPtr ctxt,
                         virNetworkDNSDefPtr def)
{
    xmlNodePtr *hostNodes = NULL;
    xmlNodePtr *srvNodes = NULL;
    xmlNodePtr *txtNodes = NULL;
    xmlNodePtr *fwdNodes = NULL;
    char *forwardPlainNames = NULL;
    char *enable = NULL;
    int nhosts, nsrvs, ntxts, nfwds;
    size_t i;
    int ret = -1;
    xmlNodePtr save = ctxt->node;

    ctxt->node = node;

    enable = virXPathString("string(./@enable)", ctxt);
    if (enable) {
        def->enable = virTristateBoolTypeFromString(enable);
        if (def->enable <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid dns enable setting '%s' "
                             "in network '%s'"),
                           enable, networkName);
            goto cleanup;
        }
    }

    forwardPlainNames = virXPathString("string(./@forwardPlainNames)", ctxt);
    if (forwardPlainNames) {
        def->forwardPlainNames = virTristateBoolTypeFromString(forwardPlainNames);
        if (def->forwardPlainNames <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid dns forwardPlainNames setting '%s' "
                             "in network '%s'"),
                           forwardPlainNames, networkName);
            goto cleanup;
        }
    }

    nfwds = virXPathNodeSet("./forwarder", ctxt, &fwdNodes);
    if (nfwds < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <forwarder> element found in <dns> of network %s"),
                       networkName);
        goto cleanup;
    }
    if (nfwds > 0) {
        if (VIR_ALLOC_N(def->forwarders, nfwds) < 0)
            goto cleanup;

        for (i = 0; i < nfwds; i++) {
            char *addr = virXMLPropString(fwdNodes[i], "addr");

            if (addr && virSocketAddrParse(&def->forwarders[i].addr,
                                           addr, AF_UNSPEC) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Invalid forwarder IP address '%s' "
                                 "in network '%s'"),
                               addr, networkName);
                VIR_FREE(addr);
                goto cleanup;
            }
            def->forwarders[i].domain = virXMLPropString(fwdNodes[i], "domain");
            if (!(addr || def->forwarders[i].domain)) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("Invalid forwarder element, must contain "
                                 "at least one of addr or domain"));
                goto cleanup;
            }
            VIR_FREE(addr);
            def->nfwds++;
        }
    }

    nhosts = virXPathNodeSet("./host", ctxt, &hostNodes);
    if (nhosts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <host> element found in <dns> of network %s"),
                       networkName);
        goto cleanup;
    }
    if (nhosts > 0) {
        if (VIR_ALLOC_N(def->hosts, nhosts) < 0)
            goto cleanup;

        for (i = 0; i < nhosts; i++) {
            if (virNetworkDNSHostDefParseXML(networkName, hostNodes[i],
                                             &def->hosts[def->nhosts], false) < 0) {
                goto cleanup;
            }
            def->nhosts++;
        }
    }

    nsrvs = virXPathNodeSet("./srv", ctxt, &srvNodes);
    if (nsrvs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <srv> element found in <dns> of network %s"),
                       networkName);
        goto cleanup;
    }
    if (nsrvs > 0) {
        if (VIR_ALLOC_N(def->srvs, nsrvs) < 0)
            goto cleanup;

        for (i = 0; i < nsrvs; i++) {
            if (virNetworkDNSSrvDefParseXML(networkName, srvNodes[i], ctxt,
                                            &def->srvs[def->nsrvs], false) < 0) {
                goto cleanup;
            }
            def->nsrvs++;
        }
    }

    ntxts = virXPathNodeSet("./txt", ctxt, &txtNodes);
    if (ntxts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <txt> element found in <dns> of network %s"),
                       networkName);
        goto cleanup;
    }
    if (ntxts > 0) {
        if (VIR_ALLOC_N(def->txts, ntxts) < 0)
            goto cleanup;

        for (i = 0; i < ntxts; i++) {
            if (virNetworkDNSTxtDefParseXML(networkName, txtNodes[i],
                                            &def->txts[def->ntxts], false) < 0) {
                goto cleanup;
            }
            def->ntxts++;
        }
    }

    if (def->enable == VIR_TRISTATE_BOOL_NO &&
        (nfwds || nhosts || nsrvs || ntxts)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Extra data in disabled network '%s'"),
                       networkName);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(enable);
    VIR_FREE(forwardPlainNames);
    VIR_FREE(fwdNodes);
    VIR_FREE(hostNodes);
    VIR_FREE(srvNodes);
    VIR_FREE(txtNodes);
    ctxt->node = save;
    return ret;
}

static int
virNetworkIPDefParseXML(const char *networkName,
                        xmlNodePtr node,
                        xmlXPathContextPtr ctxt,
                        virNetworkIPDefPtr def)
{
    /*
     * virNetworkIPDef object is already allocated as part of an array.
     * On failure clear it out, but don't free it.
     */

    xmlNodePtr save;
    xmlNodePtr dhcp;
    char *address = NULL, *netmask = NULL;
    unsigned long prefix = 0;
    int prefixRc;
    int result = -1;
    char *localPtr = NULL;

    save = ctxt->node;
    ctxt->node = node;

    /* grab raw data from XML */
    def->family = virXPathString("string(./@family)", ctxt);

    address = virXPathString("string(./@address)", ctxt);
    if (!address) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Missing required address attribute in network '%s'"),
                       networkName);
        goto cleanup;
    }
    if (virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid address '%s' in network '%s'"),
                       address, networkName);
        goto cleanup;
    }

    netmask = virXPathString("string(./@netmask)", ctxt);
    if (netmask &&
        (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid netmask '%s' in network '%s'"),
                       netmask, networkName);
        goto cleanup;
    }

    prefixRc = virXPathULong("string(./@prefix)", ctxt, &prefix);
    if (prefixRc == -2) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid ULong value specified for prefix in definition of network '%s'"),
                       networkName);
        goto cleanup;
    }
    if (prefixRc < 0)
        def->prefix = 0;
    else
        def->prefix = prefix;

    localPtr = virXPathString("string(./@localPtr)", ctxt);
    if (localPtr) {
        def->localPTR = virTristateBoolTypeFromString(localPtr);
        if (def->localPTR <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid localPtr value '%s' in network '%s'"),
                           localPtr, networkName);
            goto cleanup;
        }
    }

    /* validate address, etc. for each family */
    if ((def->family == NULL) || (STREQ(def->family, "ipv4"))) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("%s family specified for non-IPv4 address '%s' in network '%s'"),
                           def->family == NULL? "no" : "ipv4", address, networkName);
            goto cleanup;
        }
        if (netmask) {
            if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Invalid netmask '%s' for address '%s' "
                                 "in network '%s' (both must be IPv4)"),
                               netmask, address, networkName);
                goto cleanup;
            }
            if (def->prefix > 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Network '%s' IP address cannot have "
                                 "both a prefix and a netmask"), networkName);
                goto cleanup;
            }
        } else if (def->prefix > 32) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid IPv4 prefix '%lu' in network '%s'"),
                           prefix, networkName);
            goto cleanup;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Family 'ipv6' specified for non-IPv6 address '%s' in network '%s'"),
                           address, networkName);
            goto cleanup;
        }
        if (netmask) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("netmask not allowed for IPv6 address '%s' in network '%s'"),
                           address, networkName);
            goto cleanup;
        }
        if (def->prefix > 128) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Invalid IPv6 prefix '%lu' in network '%s'"),
                           prefix, networkName);
            goto cleanup;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unrecognized family '%s' in network '%s'"),
                       def->family, networkName);
        goto cleanup;
    }

    if ((dhcp = virXPathNode("./dhcp[1]", ctxt)) &&
        virNetworkDHCPDefParseXML(networkName, dhcp, def) < 0)
        goto cleanup;

    if (virXPathNode("./tftp[1]", ctxt)) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported <tftp> element in an IPv6 element "
                             "in network '%s'"),
                           networkName);
            goto cleanup;
        }

        def->tftproot = virXPathString("string(./tftp[1]/@root)", ctxt);
    }

    result = 0;

 cleanup:
    if (result < 0)
        virNetworkIPDefClear(def);
    VIR_FREE(address);
    VIR_FREE(netmask);
    VIR_FREE(localPtr);

    ctxt->node = save;
    return result;
}

static int
virNetworkPortGroupParseXML(virPortGroupDefPtr def,
                            xmlNodePtr node,
                            xmlXPathContextPtr ctxt)
{
    /*
     * virPortGroupDef object is already allocated as part of an array.
     * On failure clear it out, but don't free it.
     */

    xmlNodePtr save;
    xmlNodePtr virtPortNode;
    xmlNodePtr vlanNode;
    xmlNodePtr bandwidth_node;
    char *isDefault = NULL;
    char *trustGuestRxFilters = NULL;

    int result = -1;

    save = ctxt->node;
    ctxt->node = node;

    /* grab raw data from XML */
    def->name = virXPathString("string(./@name)", ctxt);
    if (!def->name) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("Missing required name attribute in portgroup"));
        goto cleanup;
    }

    isDefault = virXPathString("string(./@default)", ctxt);
    def->isDefault = isDefault && STRCASEEQ(isDefault, "yes");

    trustGuestRxFilters
        = virXPathString("string(./@trustGuestRxFilters)", ctxt);
    if (trustGuestRxFilters) {
        if ((def->trustGuestRxFilters
             = virTristateBoolTypeFromString(trustGuestRxFilters)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid trustGuestRxFilters setting '%s' "
                             "in portgroup"), trustGuestRxFilters);
            goto cleanup;
        }
    }

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode, 0)))) {
        goto cleanup;
    }

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        virNetDevBandwidthParse(&def->bandwidth, bandwidth_node, -1) < 0)
        goto cleanup;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto cleanup;

    result = 0;
 cleanup:
    if (result < 0)
        virPortGroupDefClear(def);
    VIR_FREE(isDefault);
    VIR_FREE(trustGuestRxFilters);

    ctxt->node = save;
    return result;
}

static int
virNetworkForwardNatDefParseXML(const char *networkName,
                                xmlNodePtr node,
                                xmlXPathContextPtr ctxt,
                                virNetworkForwardDefPtr def)
{
    int ret = -1;
    xmlNodePtr *natAddrNodes = NULL;
    xmlNodePtr *natPortNodes = NULL;
    int nNatAddrs, nNatPorts;
    char *addrStart = NULL;
    char *addrEnd = NULL;
    xmlNodePtr save = ctxt->node;

    ctxt->node = node;

    if (def->type != VIR_NETWORK_FORWARD_NAT) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("The <nat> element can only be used when <forward> 'mode' is 'nat' in network %s"),
                       networkName);
        goto cleanup;
    }

    /* addresses for SNAT */
    nNatAddrs = virXPathNodeSet("./address", ctxt, &natAddrNodes);
    if (nNatAddrs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <address> element found in <forward> of "
                         "network %s"), networkName);
        goto cleanup;
    } else if (nNatAddrs > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <address> element is allowed in <nat> in "
                         "<forward> in network %s"), networkName);
        goto cleanup;
    } else if (nNatAddrs == 1) {
        addrStart = virXMLPropString(*natAddrNodes, "start");
        if (addrStart == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing 'start' attribute in <address> element in <nat> in "
                             "<forward> in network %s"), networkName);
            goto cleanup;
        }
        addrEnd = virXMLPropString(*natAddrNodes, "end");
        if (addrEnd == NULL) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("missing 'end' attribute in <address> element in <nat> in "
                             "<forward> in network %s"), networkName);
            goto cleanup;
        }
    }

    if (addrStart && virSocketAddrParse(&def->addr.start, addrStart, AF_INET) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Bad ipv4 start address '%s' in <nat> in <forward> in "
                         "network '%s'"), addrStart, networkName);
        goto cleanup;
    }

    if (addrEnd && virSocketAddrParse(&def->addr.end, addrEnd, AF_INET) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Bad ipv4 end address '%s' in <nat> in <forward> in "
                         "network '%s'"), addrEnd, networkName);
        goto cleanup;
    }

    if (addrStart && addrEnd) {
        /* verify that start <= end */
        if (virSocketAddrGetRange(&def->addr.start, &def->addr.end, NULL, 0) < 0)
            goto cleanup;
    } else {
        if (addrStart) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Only start address '%s' specified in <nat> in "
                             "<forward> in network '%s'"),
                           addrStart, networkName);
            goto cleanup;
        }
        if (addrEnd) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Only end address '%s' specified in <nat> in "
                             "<forward> in network '%s'"),
                           addrEnd, networkName);
            goto cleanup;
        }
    }

    /* ports for SNAT and MASQUERADE */
    nNatPorts = virXPathNodeSet("./port", ctxt, &natPortNodes);
    if (nNatPorts < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <port> element found in <forward> of "
                         "network %s"), networkName);
        goto cleanup;
    } else if (nNatPorts > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <port> element is allowed in <nat> in "
                         "<forward> in network %s"), networkName);
        goto cleanup;
    } else if (nNatPorts == 1) {
        if (virXPathUInt("string(./port[1]/@start)", ctxt, &def->port.start) < 0
            || def->port.start > 65535) {

            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing or invalid 'start' attribute in <port> "
                             "in <nat> in <forward> in network %s"),
                             networkName);
            goto cleanup;
        }
        if (virXPathUInt("string(./port[1]/@end)", ctxt, &def->port.end) < 0
            || def->port.end > 65535 || def->port.end < def->port.start) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("Missing or invalid 'end' attribute in <port> in "
                             "<nat> in <forward> in network %s"), networkName);
            goto cleanup;
        }
    }
    ret = 0;

 cleanup:
    VIR_FREE(addrStart);
    VIR_FREE(addrEnd);
    VIR_FREE(natAddrNodes);
    VIR_FREE(natPortNodes);
    ctxt->node = save;
    return ret;
}

static int
virNetworkForwardDefParseXML(const char *networkName,
                             xmlNodePtr node,
                             xmlXPathContextPtr ctxt,
                             virNetworkForwardDefPtr def)
{
    size_t i, j;
    int ret = -1;
    xmlNodePtr *forwardIfNodes = NULL;
    xmlNodePtr *forwardPfNodes = NULL;
    xmlNodePtr *forwardAddrNodes = NULL;
    xmlNodePtr *forwardNatNodes = NULL;
    int nForwardIfs, nForwardAddrs, nForwardPfs, nForwardNats;
    char *forwardDev = NULL;
    char *forwardManaged = NULL;
    char *forwardDriverName = NULL;
    char *type = NULL;
    xmlNodePtr save = ctxt->node;

    ctxt->node = node;

    if (!(type = virXPathString("string(./@mode)", ctxt))) {
        def->type = VIR_NETWORK_FORWARD_NAT;
    } else {
        if ((def->type = virNetworkForwardTypeFromString(type)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown forwarding type '%s'"), type);
            goto cleanup;
        }
        VIR_FREE(type);
    }

    forwardManaged = virXPathString("string(./@managed)", ctxt);
    if (forwardManaged != NULL &&
        STRCASEEQ(forwardManaged, "yes")) {
        def->managed = true;
    }

    forwardDriverName = virXPathString("string(./driver/@name)", ctxt);
    if (forwardDriverName) {
        int driverName
            = virNetworkForwardDriverNameTypeFromString(forwardDriverName);

        if (driverName <= 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unknown forward <driver name='%s'/> "
                             "in network %s"),
                           forwardDriverName, networkName);
            goto cleanup;
        }
        def->driverName = driverName;
    }

    /* bridge and hostdev modes can use a pool of physical interfaces */
    nForwardIfs = virXPathNodeSet("./interface", ctxt, &forwardIfNodes);
    if (nForwardIfs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <interface> element found in <forward> of network %s"),
                       networkName);
        goto cleanup;
    }

    nForwardAddrs = virXPathNodeSet("./address", ctxt, &forwardAddrNodes);
    if (nForwardAddrs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <address> element found in <forward> of network %s"),
                       networkName);
        goto cleanup;
    }

    nForwardPfs = virXPathNodeSet("./pf", ctxt, &forwardPfNodes);
    if (nForwardPfs < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <pf> element found in <forward> of network %s"),
                       networkName);
        goto cleanup;
    }

    nForwardNats = virXPathNodeSet("./nat", ctxt, &forwardNatNodes);
    if (nForwardNats < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("invalid <nat> element found in <forward> of network %s"),
                       networkName);
        goto cleanup;
    } else if (nForwardNats > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <nat> element is allowed in <forward> of network %s"),
                       networkName);
        goto cleanup;
    } else if (nForwardNats == 1) {
        if (virNetworkForwardNatDefParseXML(networkName,
                                            *forwardNatNodes,
                                            ctxt, def) < 0)
            goto cleanup;
    }

    forwardDev = virXPathString("string(./@dev)", ctxt);
    if (forwardDev && (nForwardAddrs > 0 || nForwardPfs > 0)) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("the <forward> 'dev' attribute cannot be used when "
                         "<address> or <pf> sub-elements are present "
                         "in network %s"));
        goto cleanup;
    }

    if (nForwardIfs > 0 || forwardDev) {
        if (VIR_ALLOC_N(def->ifs, MAX(nForwardIfs, 1)) < 0)
            goto cleanup;

        if (forwardDev) {
            def->ifs[0].device.dev = forwardDev;
            def->ifs[0].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
            forwardDev = NULL;
            def->nifs++;
        }

        /* parse each <interface> */
        for (i = 0; i < nForwardIfs; i++) {
            forwardDev = virXMLPropString(forwardIfNodes[i], "dev");
            if (!forwardDev) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Missing required dev attribute in "
                                 "<forward> <interface> element of network %s"),
                               networkName);
                goto cleanup;
            }

            if ((i == 0) && (def->nifs == 1)) {
                /* both <forward dev='x'> and <interface dev='x'/> are
                 * present.  If they don't match, it's an error.
                 */
                if (STRNEQ(forwardDev, def->ifs[0].device.dev)) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("<forward dev='%s'> must match first "
                                     "<interface dev='%s'/> in network %s"),
                                   def->ifs[0].device.dev,
                                   forwardDev, networkName);
                    goto cleanup;
                }
                VIR_FREE(forwardDev);
                continue;
            }

            for (j = 0; j < i; j++) {
                if (STREQ_NULLABLE(def->ifs[j].device.dev, forwardDev)) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("interface '%s' can only be "
                                     "listed once in network %s"),
                                   forwardDev, networkName);
                    goto cleanup;
                }
            }

            def->ifs[i].device.dev = forwardDev;
            forwardDev = NULL;
            def->ifs[i].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
            def->nifs++;
        }

    } else if (nForwardAddrs > 0) {
        if (VIR_ALLOC_N(def->ifs, nForwardAddrs) < 0)
            goto cleanup;

        for (i = 0; i < nForwardAddrs; i++) {
            if (!(type = virXMLPropString(forwardAddrNodes[i], "type"))) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("missing address type in network %s"),
                               networkName);
                goto cleanup;
            }

            if ((def->ifs[i].type = virNetworkForwardHostdevDeviceTypeFromString(type)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unknown address type '%s' in network %s"),
                               type, networkName);
                goto cleanup;
            }

            switch (def->ifs[i].type) {
            case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI:
            {
                virPCIDeviceAddressPtr addr = &def->ifs[i].device.pci;

                if (virPCIDeviceAddressParseXML(forwardAddrNodes[i], addr) < 0)
                    goto cleanup;

                for (j = 0; j < i; j++) {
                    if (virPCIDeviceAddressEqual(addr, &def->ifs[j].device.pci)) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("PCI device '%04x:%02x:%02x.%x' can "
                                         "only be listed once in network %s"),
                                       addr->domain, addr->bus,
                                       addr->slot, addr->function,
                                       networkName);
                        goto cleanup;
                    }
                }
                break;
            }
            /* Add USB case here if we ever find a reason to support it */

            default:
                virReportError(VIR_ERR_XML_ERROR,
                               _("unsupported address type '%s' in network %s"),
                               type, networkName);
                goto cleanup;
            }
            VIR_FREE(type);
            def->nifs++;
        }

    } else if (nForwardPfs > 1) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Only one <pf> element is allowed in <forward> of network %s"),
                       networkName);
        goto cleanup;
    } else if (nForwardPfs == 1) {
        if (VIR_ALLOC_N(def->pfs, nForwardPfs) < 0)
            goto cleanup;

        forwardDev = virXMLPropString(*forwardPfNodes, "dev");
        if (!forwardDev) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Missing required dev attribute "
                             "in <pf> element of network '%s'"),
                           networkName);
            goto cleanup;
        }

        def->pfs->dev = forwardDev;
        forwardDev = NULL;
        def->npfs++;
    }

    ret = 0;
 cleanup:
    VIR_FREE(type);
    VIR_FREE(forwardDev);
    VIR_FREE(forwardManaged);
    VIR_FREE(forwardDriverName);
    VIR_FREE(forwardPfNodes);
    VIR_FREE(forwardIfNodes);
    VIR_FREE(forwardAddrNodes);
    VIR_FREE(forwardNatNodes);
    ctxt->node = save;
    return ret;
}

static virNetworkDefPtr
virNetworkDefParseXML(xmlXPathContextPtr ctxt)
{
    virNetworkDefPtr def;
    char *tmp = NULL;
    char *stp = NULL;
    xmlNodePtr *ipNodes = NULL;
    xmlNodePtr *routeNodes = NULL;
    xmlNodePtr *portGroupNodes = NULL;
    int nips, nPortGroups, nRoutes;
    xmlNodePtr dnsNode = NULL;
    xmlNodePtr virtPortNode = NULL;
    xmlNodePtr forwardNode = NULL;
    char *ipv6nogwStr = NULL;
    char *trustGuestRxFilters = NULL;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr bandwidthNode = NULL;
    xmlNodePtr vlanNode;
    xmlNodePtr metadataNode = NULL;

    if (VIR_ALLOC(def) < 0)
        return NULL;

    /* Extract network name */
    def->name = virXPathString("string(./name[1])", ctxt);
    if (!def->name) {
        virReportError(VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    if (virXMLCheckIllegalChars("name", def->name, "/") < 0)
        goto error;

    /* Extract network uuid */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        if (virUUIDGenerate(def->uuid)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("Failed to generate UUID"));
            goto error;
        }
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
        def->uuid_specified = true;
    }

    /* check if definitions with no IPv6 gateway addresses is to
     * allow guest-to-guest communications.
     */
    ipv6nogwStr = virXPathString("string(./@ipv6)", ctxt);
    if (ipv6nogwStr) {
        if (STREQ(ipv6nogwStr, "yes")) {
            def->ipv6nogw = true;
        } else if (STRNEQ(ipv6nogwStr, "no")) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid ipv6 setting '%s' in network '%s'"),
                           ipv6nogwStr, def->name);
            goto error;
        }
        VIR_FREE(ipv6nogwStr);
    }

    trustGuestRxFilters
        = virXPathString("string(./@trustGuestRxFilters)", ctxt);
    if (trustGuestRxFilters) {
        if ((def->trustGuestRxFilters
             = virTristateBoolTypeFromString(trustGuestRxFilters)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid trustGuestRxFilters setting '%s' "
                             "in network '%s'"),
                           trustGuestRxFilters, def->name);
            goto error;
        }
        VIR_FREE(trustGuestRxFilters);
    }

    /* Parse network domain information */
    def->domain = virXPathString("string(./domain[1]/@name)", ctxt);
    tmp = virXPathString("string(./domain[1]/@localOnly)", ctxt);
    if (tmp) {
        def->domainLocalOnly = virTristateBoolTypeFromString(tmp);
        if (def->domainLocalOnly <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid domain localOnly setting '%s' "
                             "in network '%s'"),
                           tmp, def->name);
            goto error;
        }
        VIR_FREE(tmp);
    }

    if ((bandwidthNode = virXPathNode("./bandwidth", ctxt)) &&
        virNetDevBandwidthParse(&def->bandwidth, bandwidthNode, -1) < 0)
        goto error;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto error;

    /* Parse bridge information */
    def->bridge = virXPathString("string(./bridge[1]/@name)", ctxt);
    stp = virXPathString("string(./bridge[1]/@stp)", ctxt);
    def->stp = (stp && STREQ(stp, "off")) ? false : true;

    tmp = virXPathString("string(./bridge[1]/@delay)", ctxt);
    if (tmp) {
        if (virStrToLong_ulp(tmp, NULL, 10, &def->delay) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid delay value in network '%s'"),
                           def->name);
            goto error;
        }
    }
    VIR_FREE(tmp);

    tmp = virXPathString("string(./bridge[1]/@macTableManager)", ctxt);
    if (tmp) {
        if ((def->macTableManager
             = virNetworkBridgeMACTableManagerTypeFromString(tmp)) <= 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid macTableManager setting '%s' "
                             "in network '%s'"), tmp, def->name);
            goto error;
        }
        VIR_FREE(tmp);
    }

    tmp = virXPathString("string(./mac[1]/@address)", ctxt);
    if (tmp) {
        if (virMacAddrParse(tmp, &def->mac) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid bridge mac address '%s' in network '%s'"),
                           tmp, def->name);
            goto error;
        }
        if (virMacAddrIsMulticast(&def->mac)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid multicast bridge mac address '%s' in network '%s'"),
                           tmp, def->name);
            goto error;
        }
        VIR_FREE(tmp);
        def->mac_specified = true;
    }

    tmp = virXPathString("string(./mtu/@size)", ctxt);
    if (tmp) {
        if (virStrToLong_ui(tmp, NULL, 10, &def->mtu) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid mtu size '%s' in network '%s'"),
                           tmp, def->name);
            goto error;
        }
    }
    VIR_FREE(tmp);

    dnsNode = virXPathNode("./dns", ctxt);
    if (dnsNode != NULL &&
        virNetworkDNSDefParseXML(def->name, dnsNode, ctxt, &def->dns) < 0) {
        goto error;
    }

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode,
                                                             VIR_VPORT_XML_REQUIRE_TYPE)))) {
        goto error;
    }

    nPortGroups = virXPathNodeSet("./portgroup", ctxt, &portGroupNodes);
    if (nPortGroups < 0)
        goto error;

    if (nPortGroups > 0) {
        size_t i;

        /* allocate array to hold all the portgroups */
        if (VIR_ALLOC_N(def->portGroups, nPortGroups) < 0)
            goto error;
        /* parse each portgroup */
        for (i = 0; i < nPortGroups; i++) {
            if (virNetworkPortGroupParseXML(&def->portGroups[i],
                                            portGroupNodes[i],
                                            ctxt) < 0)
                goto error;
            def->nPortGroups++;
        }
    }
    VIR_FREE(portGroupNodes);

    nips = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nips < 0)
        goto error;

    if (nips > 0) {
        size_t i;

        /* allocate array to hold all the addrs */
        if (VIR_ALLOC_N(def->ips, nips) < 0)
            goto error;
        /* parse each addr */
        for (i = 0; i < nips; i++) {
            if (virNetworkIPDefParseXML(def->name,
                                        ipNodes[i],
                                        ctxt,
                                        &def->ips[i]) < 0)
                goto error;
            def->nips++;
        }
    }
    VIR_FREE(ipNodes);

    nRoutes = virXPathNodeSet("./route", ctxt, &routeNodes);
    if (nRoutes < 0)
        goto error;

    if (nRoutes > 0) {
        size_t i;

        /* allocate array to hold all the route definitions */
        if (VIR_ALLOC_N(def->routes, nRoutes) < 0)
            goto error;
        /* parse each definition */
        for (i = 0; i < nRoutes; i++) {
            virNetDevIPRoutePtr route = NULL;

            if (!(route = virNetDevIPRouteParseXML(def->name,
                                                   routeNodes[i],
                                                   ctxt)))
                goto error;
            def->routes[i] = route;
            def->nroutes++;
        }

        /* now validate the correctness of any static route gateways specified
         *
         * note: the parameters within each definition are verified/assumed valid;
         * the question being asked and answered here is if the specified gateway
         * is directly reachable from this bridge.
         */
        nRoutes = def->nroutes;
        nips = def->nips;
        for (i = 0; i < nRoutes; i++) {
            size_t j;
            virSocketAddr testAddr, testGw;
            bool addrMatch;
            virNetDevIPRoutePtr gwdef = def->routes[i];
            virSocketAddrPtr gateway = virNetDevIPRouteGetGateway(gwdef);
            addrMatch = false;
            for (j = 0; j < nips; j++) {
                virNetworkIPDefPtr def2 = &def->ips[j];
                if (VIR_SOCKET_ADDR_FAMILY(gateway)
                    != VIR_SOCKET_ADDR_FAMILY(&def2->address)) {
                    continue;
                }
                int prefix = virNetworkIPDefPrefix(def2);
                virSocketAddrMaskByPrefix(&def2->address, prefix, &testAddr);
                virSocketAddrMaskByPrefix(gateway, prefix, &testGw);
                if (VIR_SOCKET_ADDR_VALID(&testAddr) &&
                    VIR_SOCKET_ADDR_VALID(&testGw) &&
                    virSocketAddrEqual(&testAddr, &testGw)) {
                    addrMatch = true;
                    break;
                }
            }
            if (!addrMatch) {
                char *gw = virSocketAddrFormat(gateway);
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unreachable static route gateway '%s' specified for network '%s'"),
                               gw, def->name);
                VIR_FREE(gw);
                goto error;
            }
        }
    }
    VIR_FREE(routeNodes);

    forwardNode = virXPathNode("./forward", ctxt);
    if (forwardNode &&
        virNetworkForwardDefParseXML(def->name, forwardNode, ctxt, &def->forward) < 0) {
        goto error;
    }

    /* Validate some items in the main NetworkDef that need to align
     * with the chosen forward mode.
     */
    switch (def->forward.type) {
    case VIR_NETWORK_FORWARD_NONE:
        break;

    case VIR_NETWORK_FORWARD_ROUTE:
    case VIR_NETWORK_FORWARD_NAT:
    case VIR_NETWORK_FORWARD_OPEN:
        /* It's pointless to specify L3 forwarding without specifying
         * the network we're on.
         */
        if (def->nips == 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%s forwarding requested, "
                             "but no IP address provided for network '%s'"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            goto error;
        }
        if (def->forward.nifs > 1) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("multiple forwarding interfaces specified "
                             "for network '%s', only one is supported"),
                           def->name);
            goto error;
        }

        if (def->forward.type == VIR_NETWORK_FORWARD_OPEN && def->forward.nifs) {
            /* an open network by definition can't place any restrictions
             * on what traffic is allowed or where it goes, so specifying
             * a forwarding device is nonsensical.
             */
            virReportError(VIR_ERR_XML_ERROR,
                           _("forward dev not allowed for "
                             "network '%s' with forward mode='%s'"),
                           def->name,
                           virNetworkForwardTypeToString(def->forward.type));
            goto error;
        }
        break;

    case VIR_NETWORK_FORWARD_PRIVATE:
    case VIR_NETWORK_FORWARD_VEPA:
    case VIR_NETWORK_FORWARD_PASSTHROUGH:
    case VIR_NETWORK_FORWARD_HOSTDEV:
        if (def->bridge) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge name not allowed in %s mode (network '%s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            goto error;
        }
        if (def->macTableManager) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge macTableManager setting not allowed "
                             "in %s mode (network '%s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            goto error;
        }
        /* fall through to next case */
    case VIR_NETWORK_FORWARD_BRIDGE:
        if (def->delay || stp) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("bridge delay/stp options only allowed in "
                             "route, nat, and isolated mode, not in %s "
                             "(network '%s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            goto error;
        }
        if (def->bridge && (def->forward.nifs || def->forward.npfs)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("A network with forward mode='%s' can specify "
                             "a bridge name or a forward dev, but not "
                             "both (network '%s')"),
                           virNetworkForwardTypeToString(def->forward.type),
                           def->name);
            goto error;
        }
        break;
    }

    VIR_FREE(stp);

    if (def->mtu &&
        (def->forward.type != VIR_NETWORK_FORWARD_NONE &&
         def->forward.type != VIR_NETWORK_FORWARD_NAT &&
         def->forward.type != VIR_NETWORK_FORWARD_ROUTE &&
         def->forward.type != VIR_NETWORK_FORWARD_OPEN)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("mtu size only allowed in open, route, nat, "
                         "and isolated mode, not in %s (network '%s')"),
                       virNetworkForwardTypeToString(def->forward.type),
                       def->name);
        goto error;
    }

    /* Extract custom metadata */
    if ((metadataNode = virXPathNode("./metadata[1]", ctxt)) != NULL) {
        def->metadata = xmlCopyNode(metadataNode, 1);
        virXMLNodeSanitizeNamespaces(def->metadata);
    }

    ctxt->node = save;
    return def;

 error:
    VIR_FREE(tmp);
    VIR_FREE(routeNodes);
    VIR_FREE(stp);
    virNetworkDefFree(def);
    VIR_FREE(ipNodes);
    VIR_FREE(portGroupNodes);
    VIR_FREE(ipv6nogwStr);
    VIR_FREE(trustGuestRxFilters);
    ctxt->node = save;
    return NULL;
}

static virNetworkDefPtr
virNetworkDefParse(const char *xmlStr,
                   const char *filename)
{
    xmlDocPtr xml;
    virNetworkDefPtr def = NULL;
    int keepBlanksDefault = xmlKeepBlanksDefault(0);

    if ((xml = virXMLParse(filename, xmlStr, _("(network_definition)")))) {
        def = virNetworkDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

    xmlKeepBlanksDefault(keepBlanksDefault);
    return def;
}

virNetworkDefPtr virNetworkDefParseString(const char *xmlStr)
{
    return virNetworkDefParse(xmlStr, NULL);
}

virNetworkDefPtr virNetworkDefParseFile(const char *filename)
{
    return virNetworkDefParse(NULL, filename);
}


virNetworkDefPtr virNetworkDefParseNode(xmlDocPtr xml,
                                        xmlNodePtr root)
{
    xmlXPathContextPtr ctxt = NULL;
    virNetworkDefPtr def = NULL;

    if (!xmlStrEqual(root->name, BAD_CAST "network")) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected root element <%s>, "
                         "expecting <network>"),
                       root->name);
        return NULL;
    }

    ctxt = xmlXPathNewContext(xml);
    if (ctxt == NULL) {
        virReportOOMError();
        goto cleanup;
    }

    ctxt->node = root;
    def = virNetworkDefParseXML(ctxt);

 cleanup:
    xmlXPathFreeContext(ctxt);
    return def;
}


static int
virNetworkDNSDefFormat(virBufferPtr buf,
                       const virNetworkDNSDef *def)
{
    size_t i, j;

    if (!(def->enable || def->forwardPlainNames || def->nfwds || def->nhosts ||
          def->nsrvs || def->ntxts))
        return 0;

    virBufferAddLit(buf, "<dns");
    if (def->enable) {
        const char *fwd = virTristateBoolTypeToString(def->enable);

        if (!fwd) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown enable type %d in network"),
                           def->enable);
            return -1;
        }
        virBufferAsprintf(buf, " enable='%s'", fwd);
    }
    if (def->forwardPlainNames) {
        const char *fwd = virTristateBoolTypeToString(def->forwardPlainNames);

        if (!fwd) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown forwardPlainNames type %d in network"),
                           def->forwardPlainNames);
            return -1;
        }
        virBufferAsprintf(buf, " forwardPlainNames='%s'", fwd);
    }
    if (!(def->nfwds || def->nhosts || def->nsrvs || def->ntxts)) {
        virBufferAddLit(buf, "/>\n");
        return 0;
    }

    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < def->nfwds; i++) {

        virBufferAddLit(buf, "<forwarder");
        if (def->forwarders[i].domain) {
            virBufferEscapeString(buf, " domain='%s'",
                                  def->forwarders[i].domain);
        }
        if (VIR_SOCKET_ADDR_VALID(&def->forwarders[i].addr)) {
        char *addr = virSocketAddrFormat(&def->forwarders[i].addr);

        if (!addr)
            return -1;

        virBufferAsprintf(buf, " addr='%s'", addr);
        VIR_FREE(addr);
        }
        virBufferAddLit(buf, "/>\n");
    }

    for (i = 0; i < def->ntxts; i++) {
        virBufferEscapeString(buf, "<txt name='%s' ", def->txts[i].name);
        virBufferEscapeString(buf, "value='%s'/>\n", def->txts[i].value);
    }

    for (i = 0; i < def->nsrvs; i++) {
        if (def->srvs[i].service && def->srvs[i].protocol) {
            virBufferEscapeString(buf, "<srv service='%s' ",
                                  def->srvs[i].service);
            virBufferEscapeString(buf, "protocol='%s'", def->srvs[i].protocol);

            if (def->srvs[i].domain)
                virBufferEscapeString(buf, " domain='%s'", def->srvs[i].domain);
            if (def->srvs[i].target)
                virBufferEscapeString(buf, " target='%s'", def->srvs[i].target);
            if (def->srvs[i].port)
                virBufferAsprintf(buf, " port='%d'", def->srvs[i].port);
            if (def->srvs[i].priority)
                virBufferAsprintf(buf, " priority='%d'", def->srvs[i].priority);
            if (def->srvs[i].weight)
                virBufferAsprintf(buf, " weight='%d'", def->srvs[i].weight);

            virBufferAddLit(buf, "/>\n");
        }
    }

    if (def->nhosts) {
        for (i = 0; i < def->nhosts; i++) {
            char *ip = virSocketAddrFormat(&def->hosts[i].ip);

            virBufferAsprintf(buf, "<host ip='%s'>\n", ip);
            virBufferAdjustIndent(buf, 2);
            for (j = 0; j < def->hosts[i].nnames; j++)
                virBufferEscapeString(buf, "<hostname>%s</hostname>\n",
                                      def->hosts[i].names[j]);

            virBufferAdjustIndent(buf, -2);
            virBufferAddLit(buf, "</host>\n");
            VIR_FREE(ip);
        }
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</dns>\n");
    return 0;
}

static int
virNetworkIPDefFormat(virBufferPtr buf,
                      const virNetworkIPDef *def)
{
    int result = -1;

    virBufferAddLit(buf, "<ip");

    if (def->family)
        virBufferAsprintf(buf, " family='%s'", def->family);
    if (VIR_SOCKET_ADDR_VALID(&def->address)) {
        char *addr = virSocketAddrFormat(&def->address);
        if (!addr)
            goto error;
        virBufferAsprintf(buf, " address='%s'", addr);
        VIR_FREE(addr);
    }
    if (VIR_SOCKET_ADDR_VALID(&def->netmask)) {
        char *addr = virSocketAddrFormat(&def->netmask);
        if (!addr)
            goto error;
        virBufferAsprintf(buf, " netmask='%s'", addr);
        VIR_FREE(addr);
    }
    if (def->prefix > 0)
        virBufferAsprintf(buf, " prefix='%u'", def->prefix);

    if (def->localPTR) {
        virBufferAsprintf(buf, " localPtr='%s'",
                          virTristateBoolTypeToString(def->localPTR));
    }

    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (def->tftproot) {
        virBufferEscapeString(buf, "<tftp root='%s'/>\n",
                              def->tftproot);
    }
    if ((def->nranges || def->nhosts)) {
        size_t i;
        virBufferAddLit(buf, "<dhcp>\n");
        virBufferAdjustIndent(buf, 2);

        for (i = 0; i < def->nranges; i++) {
            char *saddr = virSocketAddrFormat(&def->ranges[i].start);
            if (!saddr)
                goto error;
            char *eaddr = virSocketAddrFormat(&def->ranges[i].end);
            if (!eaddr) {
                VIR_FREE(saddr);
                goto error;
            }
            virBufferAsprintf(buf, "<range start='%s' end='%s'/>\n",
                              saddr, eaddr);
            VIR_FREE(saddr);
            VIR_FREE(eaddr);
        }
        for (i = 0; i < def->nhosts; i++) {
            virBufferAddLit(buf, "<host");
            if (def->hosts[i].mac)
                virBufferAsprintf(buf, " mac='%s'", def->hosts[i].mac);
            if (def->hosts[i].id)
                virBufferAsprintf(buf, " id='%s'", def->hosts[i].id);
            if (def->hosts[i].name)
                virBufferAsprintf(buf, " name='%s'", def->hosts[i].name);
            if (VIR_SOCKET_ADDR_VALID(&def->hosts[i].ip)) {
                char *ipaddr = virSocketAddrFormat(&def->hosts[i].ip);
                if (!ipaddr)
                    goto error;
                virBufferAsprintf(buf, " ip='%s'", ipaddr);
                VIR_FREE(ipaddr);
            }
            virBufferAddLit(buf, "/>\n");
        }
        if (def->bootfile) {
            virBufferEscapeString(buf, "<bootp file='%s'",
                                  def->bootfile);
            if (VIR_SOCKET_ADDR_VALID(&def->bootserver)) {
                char *ipaddr = virSocketAddrFormat(&def->bootserver);
                if (!ipaddr)
                    goto error;
                virBufferEscapeString(buf, " server='%s'", ipaddr);
                VIR_FREE(ipaddr);
            }
            virBufferAddLit(buf, "/>\n");

        }

        virBufferAdjustIndent(buf, -2);
        virBufferAddLit(buf, "</dhcp>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</ip>\n");

    result = 0;
 error:
    return result;
}

static int
virPortGroupDefFormat(virBufferPtr buf,
                      const virPortGroupDef *def)
{
    virBufferAsprintf(buf, "<portgroup name='%s'", def->name);
    if (def->isDefault)
        virBufferAddLit(buf, " default='yes'");
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    if (virNetDevVlanFormat(&def->vlan, buf) < 0)
        return -1;
    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        return -1;
    virNetDevBandwidthFormat(def->bandwidth, buf);
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</portgroup>\n");
    return 0;
}

static int
virNetworkForwardNatDefFormat(virBufferPtr buf,
                              const virNetworkForwardDef *fwd)
{
    char *addrStart = NULL;
    char *addrEnd = NULL;
    int ret = -1;

    if (VIR_SOCKET_ADDR_VALID(&fwd->addr.start)) {
        addrStart = virSocketAddrFormat(&fwd->addr.start);
        if (!addrStart)
            goto cleanup;
    }

    if (VIR_SOCKET_ADDR_VALID(&fwd->addr.end)) {
        addrEnd = virSocketAddrFormat(&fwd->addr.end);
        if (!addrEnd)
            goto cleanup;
    }

    if (!addrEnd && !addrStart && !fwd->port.start && !fwd->port.end)
        return 0;

    virBufferAddLit(buf, "<nat>\n");
    virBufferAdjustIndent(buf, 2);

    if (addrStart) {
        virBufferAsprintf(buf, "<address start='%s'", addrStart);
        if (addrEnd)
            virBufferAsprintf(buf, " end='%s'", addrEnd);
        virBufferAddLit(buf, "/>\n");
    }

    if (fwd->port.start || fwd->port.end) {
        virBufferAsprintf(buf, "<port start='%d'", fwd->port.start);
        if (fwd->port.end)
            virBufferAsprintf(buf, " end='%d'", fwd->port.end);
        virBufferAddLit(buf, "/>\n");
    }

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</nat>\n");
    ret = 0;

 cleanup:
    VIR_FREE(addrStart);
    VIR_FREE(addrEnd);
    return ret;
}

int
virNetworkDefFormatBuf(virBufferPtr buf,
                       const virNetworkDef *def,
                       unsigned int flags)
{
    const unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    size_t i;
    bool shortforward;

    virBufferAddLit(buf, "<network");
    if (!(flags & VIR_NETWORK_XML_INACTIVE) && (def->connections > 0))
        virBufferAsprintf(buf, " connections='%d'", def->connections);
    if (def->ipv6nogw)
        virBufferAddLit(buf, " ipv6='yes'");
    if (def->trustGuestRxFilters)
        virBufferAsprintf(buf, " trustGuestRxFilters='%s'",
                          virTristateBoolTypeToString(def->trustGuestRxFilters));
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);
    virBufferEscapeString(buf, "<name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(buf, "<uuid>%s</uuid>\n", uuidstr);

    if (def->metadata) {
        xmlBufferPtr xmlbuf;
        int oldIndentTreeOutput = xmlIndentTreeOutput;

        /* Indentation on output requires that we previously set
         * xmlKeepBlanksDefault to 0 when parsing; also, libxml does 2
         * spaces per level of indentation of intermediate elements,
         * but no leading indentation before the starting element.
         * Thankfully, libxml maps what looks like globals into
         * thread-local uses, so we are thread-safe.  */
        xmlIndentTreeOutput = 1;
        xmlbuf = xmlBufferCreate();
        if (xmlNodeDump(xmlbuf, def->metadata->doc, def->metadata,
                        virBufferGetIndent(buf, false) / 2, 1) < 0) {
            xmlBufferFree(xmlbuf);
            xmlIndentTreeOutput = oldIndentTreeOutput;
            goto error;
        }
        virBufferAsprintf(buf, "%s\n", (char *) xmlBufferContent(xmlbuf));
        xmlBufferFree(xmlbuf);
        xmlIndentTreeOutput = oldIndentTreeOutput;
    }

    if (def->forward.type != VIR_NETWORK_FORWARD_NONE) {
        const char *dev = NULL;
        if (!def->forward.npfs)
            dev = virNetworkDefForwardIf(def, 0);
        const char *mode = virNetworkForwardTypeToString(def->forward.type);

        if (!mode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown forward type %d in network '%s'"),
                           def->forward.type, def->name);
            goto error;
        }
        virBufferAddLit(buf, "<forward");
        virBufferEscapeString(buf, " dev='%s'", dev);
        virBufferAsprintf(buf, " mode='%s'", mode);
        if (def->forward.type == VIR_NETWORK_FORWARD_HOSTDEV) {
            if (def->forward.managed)
                virBufferAddLit(buf, " managed='yes'");
            else
                virBufferAddLit(buf, " managed='no'");
        }
        shortforward = !(def->forward.nifs || def->forward.npfs
                         || VIR_SOCKET_ADDR_VALID(&def->forward.addr.start)
                         || VIR_SOCKET_ADDR_VALID(&def->forward.addr.end)
                         || def->forward.port.start
                         || def->forward.port.end
                         || (def->forward.driverName
                             != VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT));
        virBufferAsprintf(buf, "%s>\n", shortforward ? "/" : "");
        virBufferAdjustIndent(buf, 2);

        if (def->forward.driverName
            != VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT) {
            const char *driverName
                = virNetworkForwardDriverNameTypeToString(def->forward.driverName);
            if (!driverName) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected hostdev driver name type %d "),
                               def->forward.driverName);
                goto error;
            }
            virBufferAsprintf(buf, "<driver name='%s'/>\n", driverName);
        }
        if (def->forward.type == VIR_NETWORK_FORWARD_NAT) {
            if (virNetworkForwardNatDefFormat(buf, &def->forward) < 0)
                goto error;
        }

        /* For now, hard-coded to at most 1 forward.pfs */
        if (def->forward.npfs)
            virBufferEscapeString(buf, "<pf dev='%s'/>\n",
                                  def->forward.pfs[0].dev);

        if (def->forward.nifs &&
            (!def->forward.npfs || !(flags & VIR_NETWORK_XML_INACTIVE))) {
            for (i = 0; i < def->forward.nifs; i++) {
                if (def->forward.ifs[i].type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV) {
                    virBufferEscapeString(buf, "<interface dev='%s'",
                                          def->forward.ifs[i].device.dev);
                    if (!(flags & VIR_NETWORK_XML_INACTIVE) &&
                        (def->forward.ifs[i].connections > 0)) {
                        virBufferAsprintf(buf, " connections='%d'",
                                          def->forward.ifs[i].connections);
                    }
                    virBufferAddLit(buf, "/>\n");
                } else {
                    if (def->forward.ifs[i].type ==  VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI) {
                        if (virPCIDeviceAddressFormat(buf,
                                                      def->forward.ifs[i].device.pci,
                                                      true) < 0)
                            goto error;
                    }
                }
            }
        }
        virBufferAdjustIndent(buf, -2);
        if (!shortforward)
            virBufferAddLit(buf, "</forward>\n");
    }


    if (def->forward.type == VIR_NETWORK_FORWARD_NONE ||
        def->forward.type == VIR_NETWORK_FORWARD_NAT ||
        def->forward.type == VIR_NETWORK_FORWARD_ROUTE ||
        def->forward.type == VIR_NETWORK_FORWARD_OPEN ||
        def->bridge || def->macTableManager) {

        virBufferAddLit(buf, "<bridge");
        virBufferEscapeString(buf, " name='%s'", def->bridge);
        if (def->forward.type == VIR_NETWORK_FORWARD_NONE ||
            def->forward.type == VIR_NETWORK_FORWARD_NAT ||
            def->forward.type == VIR_NETWORK_FORWARD_ROUTE ||
            def->forward.type == VIR_NETWORK_FORWARD_OPEN) {
            virBufferAsprintf(buf, " stp='%s' delay='%ld'",
                              def->stp ? "on" : "off", def->delay);
        }
        if (def->macTableManager) {
            virBufferAsprintf(buf, " macTableManager='%s'",
                             virNetworkBridgeMACTableManagerTypeToString(def->macTableManager));
        }
        virBufferAddLit(buf, "/>\n");
    }

    if (def->mtu)
        virBufferAsprintf(buf, "<mtu size='%u'/>\n", def->mtu);

    if (def->mac_specified) {
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virMacAddrFormat(&def->mac, macaddr);
        virBufferAsprintf(buf, "<mac address='%s'/>\n", macaddr);
    }

    if (def->domain) {
        virBufferAsprintf(buf, "<domain name='%s'", def->domain);

        /* default to "no", but don't format it in the XML */
        if (def->domainLocalOnly) {
            const char *local = virTristateBoolTypeToString(def->domainLocalOnly);

            if (!local) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Unknown localOnly type %d in network"),
                               def->domainLocalOnly);
                return -1;
            }
            virBufferAsprintf(buf, " localOnly='%s'", local);
        }

        virBufferAddLit(buf, "/>\n");
    }

    if (virNetworkDNSDefFormat(buf, &def->dns) < 0)
        goto error;

    if (virNetDevVlanFormat(&def->vlan, buf) < 0)
        goto error;
    if (virNetDevBandwidthFormat(def->bandwidth, buf) < 0)
        goto error;

    for (i = 0; i < def->nips; i++) {
        if (virNetworkIPDefFormat(buf, &def->ips[i]) < 0)
            goto error;
    }

    for (i = 0; i < def->nroutes; i++) {
        if (virNetDevIPRouteFormat(buf, def->routes[i]) < 0)
            goto error;
    }

    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        goto error;

    for (i = 0; i < def->nPortGroups; i++)
        if (virPortGroupDefFormat(buf, &def->portGroups[i]) < 0)
            goto error;

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</network>\n");

    return 0;

 error:
    return -1;
}

char *
virNetworkDefFormat(const virNetworkDef *def,
                    unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (virNetworkDefFormatBuf(&buf, def, flags) < 0)
        goto error;

    if (virBufferCheckError(&buf) < 0)
        goto error;

    return virBufferContentAndReset(&buf);

 error:
    virBufferFreeAndReset(&buf);
    return NULL;
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

const char *
virNetworkDefForwardIf(const virNetworkDef *def, size_t n)
{
    return ((def->forward.ifs && (def->forward.nifs > n) &&
             def->forward.ifs[n].type == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV)
            ? def->forward.ifs[n].device.dev : NULL);
}

virPortGroupDefPtr virPortGroupFindByName(virNetworkDefPtr net,
                                          const char *portgroup)
{
    size_t i;
    for (i = 0; i < net->nPortGroups; i++) {
        if (portgroup) {
            if (STREQ(portgroup, net->portGroups[i].name))
                return &net->portGroups[i];
        } else {
            if (net->portGroups[i].isDefault)
                return &net->portGroups[i];
        }
    }
    return NULL;
}

int virNetworkSaveXML(const char *configDir,
                      virNetworkDefPtr def,
                      const char *xml)
{
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    char *configFile = NULL;
    int ret = -1;

    if ((configFile = virNetworkConfigFile(configDir, def->name)) == NULL)
        goto cleanup;

    if (virFileMakePath(configDir) < 0) {
        virReportSystemError(errno,
                             _("cannot create config directory '%s'"),
                             configDir);
        goto cleanup;
    }

    virUUIDFormat(def->uuid, uuidstr);
    ret = virXMLSaveFile(configFile,
                         virXMLPickShellSafeComment(def->name, uuidstr),
                         "net-edit", xml);

 cleanup:
    VIR_FREE(configFile);
    return ret;
}

int virNetworkSaveConfig(const char *configDir,
                         virNetworkDefPtr def)
{
    int ret = -1;
    char *xml;

    if (!(xml = virNetworkDefFormat(def, VIR_NETWORK_XML_INACTIVE)))
        goto cleanup;

    if (virNetworkSaveXML(configDir, def, xml))
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(xml);
    return ret;
}


int virNetworkSaveStatus(const char *statusDir,
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

virNetworkObjPtr virNetworkLoadConfig(virNetworkObjListPtr nets,
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


int virNetworkLoadAllConfigs(virNetworkObjListPtr nets,
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

int virNetworkDeleteConfig(const char *configDir,
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

char *virNetworkConfigFile(const char *dir,
                           const char *name)
{
    char *ret = NULL;

    ignore_value(virAsprintf(&ret, "%s/%s.xml", dir, name));
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

int virNetworkBridgeInUse(virNetworkObjListPtr nets,
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


void virNetworkSetBridgeMacAddr(virNetworkDefPtr def)
{
    if (!def->mac_specified) {
        /* if the bridge doesn't have a mac address explicitly defined,
         * autogenerate a random one.
         */
        virMacAddrGenerate((unsigned char[]){ 0x52, 0x54, 0 },
                           &def->mac);
        def->mac_specified = true;
    }
}

/* NetworkObj backend of the virNetworkUpdate API */

static void
virNetworkDefUpdateNoSupport(virNetworkDefPtr def, const char *section)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                   _("can't update '%s' section of network '%s'"),
                   section, def->name);
}
static void
virNetworkDefUpdateUnknownCommand(unsigned int command)
{
    virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                   _("unrecognized network update command code %d"), command);
}

static int
virNetworkDefUpdateCheckElementName(virNetworkDefPtr def,
                                    xmlNodePtr node,
                                    const char *section)
{
    if (!xmlStrEqual(node->name, BAD_CAST section)) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("unexpected element <%s>, expecting <%s>, "
                         "while updating network '%s'"),
                       node->name, section, def->name);
        return -1;
    }
    return 0;
}

static int
virNetworkDefUpdateBridge(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "bridge");
    return -1;
}

static int
virNetworkDefUpdateDomain(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "domain");
    return -1;
}

static int
virNetworkDefUpdateIP(virNetworkDefPtr def,
                      unsigned int command ATTRIBUTE_UNUSED,
                      int parentIndex ATTRIBUTE_UNUSED,
                      xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                      /* virNetworkUpdateFlags */
                      unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "ip");
    return -1;
}

static virNetworkIPDefPtr
virNetworkIPDefByIndex(virNetworkDefPtr def, int parentIndex)
{
    virNetworkIPDefPtr ipdef = NULL;
    size_t i;

    /* first find which ip element's dhcp host list to work on */
    if (parentIndex >= 0) {
        ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, parentIndex);
        if (!(ipdef)) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't update dhcp host entry - no <ip> "
                             "element found at index %d in network '%s'"),
                           parentIndex, def->name);
        }
        return ipdef;
    }

    /* -1 means "find the most appropriate", which in this case
     * means the one and only <ip> that has <dhcp> element
     */
    for (i = 0;
         (ipdef = virNetworkDefGetIPByIndex(def, AF_UNSPEC, i));
         i++) {
        if (ipdef->nranges || ipdef->nhosts)
            break;
    }
    if (!ipdef) {
        ipdef = virNetworkDefGetIPByIndex(def, AF_INET, 0);
        if (!ipdef)
            ipdef = virNetworkDefGetIPByIndex(def, AF_INET6, 0);
    }
    if (!ipdef) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't update dhcp host entry - no <ip> "
                         "element found in network '%s'"), def->name);
    }
    return ipdef;
}


static int
virNetworkDefUpdateCheckMultiDHCP(virNetworkDefPtr def,
                                  virNetworkIPDefPtr ipdef)
{
    int family = VIR_SOCKET_ADDR_FAMILY(&ipdef->address);
    size_t i;
    virNetworkIPDefPtr ip;

    for (i = 0; (ip = virNetworkDefGetIPByIndex(def, family, i)); i++) {
        if (ip != ipdef) {
            if (ip->nranges || ip->nhosts) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("dhcp is supported only for a "
                                 "single %s address on each network"),
                               (family == AF_INET) ? "IPv4" : "IPv6");
                return -1;
            }
        }
    }
    return 0;
}


static int
virNetworkDefUpdateIPDHCPHost(virNetworkDefPtr def,
                              unsigned int command,
                              int parentIndex,
                              xmlXPathContextPtr ctxt,
                              /* virNetworkUpdateFlags */
                              unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int ret = -1;
    virNetworkIPDefPtr ipdef = virNetworkIPDefByIndex(def, parentIndex);
    virNetworkDHCPHostDef host;
    bool partialOkay = (command == VIR_NETWORK_UPDATE_COMMAND_DELETE);

    memset(&host, 0, sizeof(host));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "host") < 0)
        goto cleanup;

    /* ipdef is the ip element that needs its host array updated */
    if (!ipdef)
        goto cleanup;

    if (virNetworkDHCPHostDefParseXML(def->name, ipdef, ctxt->node,
                                      &host, partialOkay) < 0)
        goto cleanup;

    if (!partialOkay &&
        VIR_SOCKET_ADDR_FAMILY(&ipdef->address)
        != VIR_SOCKET_ADDR_FAMILY(&host.ip)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("the address family of a host entry IP must match "
                         "the address family of the dhcp element's parent"));
        goto cleanup;
    }

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        /* search for the entry with this (ip|mac|name),
         * and update the IP+(mac|name) */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((host.mac && ipdef->hosts[i].mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) ||
                (VIR_SOCKET_ADDR_VALID(&host.ip) &&
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name))) {
                break;
            }
        }

        if (i == ipdef->nhosts) {
            char *ip = virSocketAddrFormat(&host.ip);
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate an existing dhcp host entry with "
                             "\"mac='%s'\" \"name='%s'\" \"ip='%s'\" in"
                             " network '%s'"),
                           host.mac ? host.mac : _("unknown"), host.name,
                           ip ? ip : _("unknown"), def->name);
            VIR_FREE(ip);
            goto cleanup;
        }

        /* clear the existing hosts entry, move the new one in its place,
         * then clear out the extra copy to get rid of the duplicate pointers
         * to its data (mac and name strings).
         */
        virNetworkDHCPHostDefClear(&ipdef->hosts[i]);
        ipdef->hosts[i] = host;
        memset(&host, 0, sizeof(host));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
               (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (virNetworkDefUpdateCheckMultiDHCP(def, ipdef) < 0)
            goto cleanup;

        /* log error if an entry with same name/address/ip already exists */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((host.mac && ipdef->hosts[i].mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name)) ||
                (VIR_SOCKET_ADDR_VALID(&host.ip) &&
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip))) {
                char *ip = virSocketAddrFormat(&host.ip);

                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("there is an existing dhcp host entry in "
                                 "network '%s' that matches "
                                 "\"<host mac='%s' name='%s' ip='%s'/>\""),
                               def->name, host.mac ? host.mac : _("unknown"),
                               host.name, ip ? ip : _("unknown"));
                VIR_FREE(ip);
                goto cleanup;
            }
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(ipdef->hosts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : ipdef->nhosts,
                               ipdef->nhosts, host) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        /* find matching entry - all specified attributes must match */
        for (i = 0; i < ipdef->nhosts; i++) {
            if ((!host.mac || !ipdef->hosts[i].mac ||
                 !virMacAddrCompare(host.mac, ipdef->hosts[i].mac)) &&
                (!host.name ||
                 STREQ_NULLABLE(host.name, ipdef->hosts[i].name)) &&
                (!VIR_SOCKET_ADDR_VALID(&host.ip) ||
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[i].ip))) {
                break;
            }
        }
        if (i == ipdef->nhosts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp host entry "
                             "in network '%s'"), def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDHCPHostDefClear(&ipdef->hosts[i]);
        VIR_DELETE_ELEMENT(ipdef->hosts, i, ipdef->nhosts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDHCPHostDefClear(&host);
    return ret;
}

static int
virNetworkDefUpdateIPDHCPRange(virNetworkDefPtr def,
                               unsigned int command,
                               int parentIndex,
                               xmlXPathContextPtr ctxt,
                               /* virNetworkUpdateFlags */
                               unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int ret = -1;
    virNetworkIPDefPtr ipdef = virNetworkIPDefByIndex(def, parentIndex);
    virSocketAddrRange range;

    memset(&range, 0, sizeof(range));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "range") < 0)
        goto cleanup;

    /* ipdef is the ip element that needs its range array updated */
    if (!ipdef)
        goto cleanup;

    /* parse the xml into a virSocketAddrRange */
    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("dhcp ranges cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    if (virSocketAddrRangeParseXML(def->name, ipdef, ctxt->node, &range) < 0)
        goto cleanup;

    if (VIR_SOCKET_ADDR_FAMILY(&ipdef->address)
        != VIR_SOCKET_ADDR_FAMILY(&range.start)) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("the address family of a dhcp range must match "
                         "the address family of the dhcp element's parent"));
        goto cleanup;
    }

    /* check if an entry with same name/address/ip already exists */
    for (i = 0; i < ipdef->nranges; i++) {
        if (virSocketAddrEqual(&range.start, &ipdef->ranges[i].start) &&
            virSocketAddrEqual(&range.end, &ipdef->ranges[i].end)) {
            break;
        }
    }

    if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (virNetworkDefUpdateCheckMultiDHCP(def, ipdef) < 0)
            goto cleanup;

        if (i < ipdef->nranges) {
            char *startip = virSocketAddrFormat(&range.start);
            char *endip = virSocketAddrFormat(&range.end);

            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is an existing dhcp range entry in "
                             "network '%s' that matches "
                             "\"<range start='%s' end='%s'/>\""),
                           def->name,
                           startip ? startip : "unknown",
                           endip ? endip : "unknown");
            VIR_FREE(startip);
            VIR_FREE(endip);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(ipdef->ranges,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : ipdef->nranges,
                               ipdef->nranges, range) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (i == ipdef->nranges) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp range entry "
                             "in network '%s'"), def->name);
            goto cleanup;
        }

        /* remove it */
        /* NB: nothing to clear from a RangeDef that's being freed */
        VIR_DELETE_ELEMENT(ipdef->ranges, i, ipdef->nranges);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static int
virNetworkDefUpdateForward(virNetworkDefPtr def,
                           unsigned int command ATTRIBUTE_UNUSED,
                           int parentIndex ATTRIBUTE_UNUSED,
                           xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                           /* virNetworkUpdateFlags */
                           unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "forward");
    return -1;
}

static int
virNetworkDefUpdateForwardInterface(virNetworkDefPtr def,
                                    unsigned int command,
                                    int parentIndex ATTRIBUTE_UNUSED,
                                    xmlXPathContextPtr ctxt,
                                    /* virNetworkUpdateFlags */
                                    unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int ret = -1;
    virNetworkForwardIfDef iface;

    memset(&iface, 0, sizeof(iface));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "interface") < 0)
        goto cleanup;

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("forward interface entries cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    /* parsing this is so simple that it doesn't have its own function */
    iface.type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
    if (!(iface.device.dev = virXMLPropString(ctxt->node, "dev"))) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("missing dev attribute in <interface> element"));
        goto cleanup;
    }

    /* check if an <interface> with same dev name already exists */
    for (i = 0; i < def->forward.nifs; i++) {
        if (def->forward.ifs[i].type
            == VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV &&
            STREQ(iface.device.dev, def->forward.ifs[i].device.dev))
            break;
    }

    if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (i < def->forward.nifs) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is an existing interface entry "
                             "in network '%s' that matches "
                             "\"<interface dev='%s'>\""),
                           def->name, iface.device.dev);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(def->forward.ifs,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : def->forward.nifs,
                               def->forward.nifs, iface) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (i == def->forward.nifs) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't find an interface entry "
                             "in network '%s' matching <interface dev='%s'>"),
                           def->name, iface.device.dev);
            goto cleanup;
        }

        /* fail if the interface is being used */
        if (def->forward.ifs[i].connections > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("unable to delete interface '%s' "
                             "in network '%s'. It is currently being used "
                             " by %d domains."),
                           iface.device.dev, def->name,
                           def->forward.ifs[i].connections);
            goto cleanup;
        }

        /* remove it */
        virNetworkForwardIfDefClear(&def->forward.ifs[i]);
        VIR_DELETE_ELEMENT(def->forward.ifs, i, def->forward.nifs);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkForwardIfDefClear(&iface);
    return ret;
}

static int
virNetworkDefUpdateForwardPF(virNetworkDefPtr def,
                             unsigned int command ATTRIBUTE_UNUSED,
                             int parentIndex ATTRIBUTE_UNUSED,
                             xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                             /* virNetworkUpdateFlags */
                             unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "forward pf");
    return -1;
}

static int
virNetworkDefUpdatePortGroup(virNetworkDefPtr def,
                             unsigned int command,
                             int parentIndex ATTRIBUTE_UNUSED,
                             xmlXPathContextPtr ctxt,
                             /* virNetworkUpdateFlags */
                             unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int foundName = -1, foundDefault = -1;
    int ret = -1;
    virPortGroupDef portgroup;

    memset(&portgroup, 0, sizeof(portgroup));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "portgroup") < 0)
        goto cleanup;

    if (virNetworkPortGroupParseXML(&portgroup, ctxt->node, ctxt) < 0)
        goto cleanup;

    /* check if a portgroup with same name already exists */
    for (i = 0; i < def->nPortGroups; i++) {
        if (STREQ(portgroup.name, def->portGroups[i].name))
            foundName = i;
        if (def->portGroups[i].isDefault)
            foundDefault = i;
    }
    if (foundName == -1 &&
        ((command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) ||
         (command == VIR_NETWORK_UPDATE_COMMAND_DELETE))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't find a portgroup entry "
                         "in network '%s' matching <portgroup name='%s'>"),
                       def->name, portgroup.name);
        goto cleanup;
    } else if (foundName >= 0 &&
               ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
                (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("there is an existing portgroup entry in "
                         "network '%s' that matches "
                         "\"<portgroup name='%s'>\""),
                       def->name, portgroup.name);
        goto cleanup;
    }

    /* if there is already a different default, we can't make this
     * one the default.
     */
    if (command != VIR_NETWORK_UPDATE_COMMAND_DELETE &&
        portgroup.isDefault &&
        foundDefault >= 0 && foundDefault != foundName) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("a different portgroup entry in "
                         "network '%s' is already set as the default. "
                         "Only one default is allowed."),
                       def->name);
        goto cleanup;
    }

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        /* replace existing entry */
        virPortGroupDefClear(&def->portGroups[foundName]);
        def->portGroups[foundName] = portgroup;
        memset(&portgroup, 0, sizeof(portgroup));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(def->portGroups,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : def->nPortGroups,
                               def->nPortGroups, portgroup) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        /* remove it */
        virPortGroupDefClear(&def->portGroups[foundName]);
        VIR_DELETE_ELEMENT(def->portGroups, foundName, def->nPortGroups);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virPortGroupDefClear(&portgroup);
    return ret;
}

static int
virNetworkDefUpdateDNSHost(virNetworkDefPtr def,
                           unsigned int command ATTRIBUTE_UNUSED,
                           int parentIndex ATTRIBUTE_UNUSED,
                           xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                           /* virNetworkUpdateFlags */
                           unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i, j, k;
    int foundIdx = -1, ret = -1;
    virNetworkDNSDefPtr dns = &def->dns;
    virNetworkDNSHostDef host;
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    int foundCt = 0;

    memset(&host, 0, sizeof(host));

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS HOST records cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "host") < 0)
        goto cleanup;

    if (virNetworkDNSHostDefParseXML(def->name, ctxt->node, &host, !isAdd) < 0)
        goto cleanup;

    for (i = 0; i < dns->nhosts; i++) {
        bool foundThisTime = false;

        if (virSocketAddrEqual(&host.ip, &dns->hosts[i].ip))
            foundThisTime = true;

        for (j = 0; j < host.nnames && !foundThisTime; j++) {
            for (k = 0; k < dns->hosts[i].nnames && !foundThisTime; k++) {
                if (STREQ(host.names[j], dns->hosts[i].names[k]))
                    foundThisTime = true;
            }
        }
        if (foundThisTime) {
            foundCt++;
            foundIdx = i;
        }
    }

    if (isAdd) {

        if (foundCt > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already at least one DNS HOST "
                             "record with a matching field in network %s"),
                           def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->hosts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->nhosts, dns->nhosts, host) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundCt == 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS HOST "
                             "record in network %s"), def->name);
            goto cleanup;
        }
        if (foundCt > 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("multiple matching DNS HOST records were "
                             "found in network %s"), def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSHostDefClear(&dns->hosts[foundIdx]);
        VIR_DELETE_ELEMENT(dns->hosts, foundIdx, dns->nhosts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSHostDefClear(&host);
    return ret;
}

static int
virNetworkDefUpdateDNSSrv(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    size_t i;
    int foundIdx = -1, ret = -1;
    virNetworkDNSDefPtr dns = &def->dns;
    virNetworkDNSSrvDef srv;
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);
    int foundCt = 0;

    memset(&srv, 0, sizeof(srv));

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS SRV records cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "srv") < 0)
        goto cleanup;

    if (virNetworkDNSSrvDefParseXML(def->name, ctxt->node, ctxt, &srv, !isAdd) < 0)
        goto cleanup;

    for (i = 0; i < dns->nsrvs; i++) {
        if ((!srv.domain || STREQ_NULLABLE(srv.domain, dns->srvs[i].domain)) &&
            (!srv.service || STREQ_NULLABLE(srv.service, dns->srvs[i].service)) &&
            (!srv.protocol || STREQ_NULLABLE(srv.protocol, dns->srvs[i].protocol)) &&
            (!srv.target || STREQ_NULLABLE(srv.target, dns->srvs[i].target))) {
            foundCt++;
            foundIdx = i;
        }
    }

    if (isAdd) {

        if (foundCt > 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already at least one DNS SRV "
                             "record matching all specified fields in network %s"),
                           def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->srvs,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->nsrvs, dns->nsrvs, srv) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundCt == 0) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS SRV "
                             "record in network %s"), def->name);
            goto cleanup;
        }
        if (foundCt > 1) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("multiple DNS SRV records matching all specified "
                             "fields were found in network %s"), def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSSrvDefClear(&dns->srvs[foundIdx]);
        VIR_DELETE_ELEMENT(dns->srvs, foundIdx, dns->nsrvs);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSSrvDefClear(&srv);
    return ret;
}

static int
virNetworkDefUpdateDNSTxt(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    int foundIdx, ret = -1;
    virNetworkDNSDefPtr dns = &def->dns;
    virNetworkDNSTxtDef txt;
    bool isAdd = (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST ||
                  command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST);

    memset(&txt, 0, sizeof(txt));

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("DNS TXT records cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "txt") < 0)
        goto cleanup;

    if (virNetworkDNSTxtDefParseXML(def->name, ctxt->node, &txt, !isAdd) < 0)
        goto cleanup;

    for (foundIdx = 0; foundIdx < dns->ntxts; foundIdx++) {
        if (STREQ(txt.name, dns->txts[foundIdx].name))
            break;
    }

    if (isAdd) {

        if (foundIdx < dns->ntxts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is already a DNS TXT record "
                             "with name '%s' in network %s"),
                           txt.name, def->name);
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_INSERT_ELEMENT(dns->txts,
                               command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST
                               ? 0 : dns->ntxts, dns->ntxts, txt) < 0)
            goto cleanup;
    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (foundIdx == dns->ntxts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching DNS TXT "
                             "record in network %s"), def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDNSTxtDefClear(&dns->txts[foundIdx]);
        VIR_DELETE_ELEMENT(dns->txts, foundIdx, dns->ntxts);

    } else {
        virNetworkDefUpdateUnknownCommand(command);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetworkDNSTxtDefClear(&txt);
    return ret;
}

int
virNetworkDefUpdateSection(virNetworkDefPtr def,
                           unsigned int command, /* virNetworkUpdateCommand */
                           unsigned int section, /* virNetworkUpdateSection */
                           int parentIndex,
                           const char *xml,
                           unsigned int flags)  /* virNetworkUpdateFlags */
{
    int ret = -1;
    xmlDocPtr doc;
    xmlXPathContextPtr ctxt = NULL;

    if (!(doc = virXMLParseStringCtxt(xml, _("network_update_xml"), &ctxt)))
        goto cleanup;

    switch (section) {
    case VIR_NETWORK_SECTION_BRIDGE:
       ret = virNetworkDefUpdateBridge(def, command, parentIndex, ctxt, flags);
        break;

    case VIR_NETWORK_SECTION_DOMAIN:
        ret = virNetworkDefUpdateDomain(def, command, parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_IP:
        ret = virNetworkDefUpdateIP(def, command, parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_IP_DHCP_HOST:
        ret = virNetworkDefUpdateIPDHCPHost(def, command,
                                            parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_IP_DHCP_RANGE:
        ret = virNetworkDefUpdateIPDHCPRange(def, command,
                                             parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_FORWARD:
        ret = virNetworkDefUpdateForward(def, command,
                                         parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_FORWARD_INTERFACE:
        ret = virNetworkDefUpdateForwardInterface(def, command,
                                                  parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_FORWARD_PF:
        ret = virNetworkDefUpdateForwardPF(def, command,
                                           parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_PORTGROUP:
        ret = virNetworkDefUpdatePortGroup(def, command,
                                           parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_DNS_HOST:
        ret = virNetworkDefUpdateDNSHost(def, command,
                                         parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_DNS_TXT:
        ret = virNetworkDefUpdateDNSTxt(def, command, parentIndex, ctxt, flags);
        break;
    case VIR_NETWORK_SECTION_DNS_SRV:
        ret = virNetworkDefUpdateDNSSrv(def, command, parentIndex, ctxt, flags);
        break;
    default:
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("can't update unrecognized section of network"));
        break;
    }

 cleanup:
    xmlFreeDoc(doc);
    xmlXPathFreeContext(ctxt);
    return ret;
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
