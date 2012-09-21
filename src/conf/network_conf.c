/*
 * network_conf.c: network XML handling
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#include "virterror_internal.h"
#include "datatypes.h"
#include "network_conf.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"
#include "memory.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "c-ctype.h"
#include "virfile.h"

#define MAX_BRIDGE_ID 256
#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route", "bridge", "private", "vepa", "passthrough", "hostdev")

VIR_ENUM_DECL(virNetworkForwardHostdevDevice)
VIR_ENUM_IMPL(virNetworkForwardHostdevDevice,
              VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST,
              "none", "pci", "netdev")

virNetworkObjPtr virNetworkFindByUUID(const virNetworkObjListPtr nets,
                                      const unsigned char *uuid)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++) {
        virNetworkObjLock(nets->objs[i]);
        if (!memcmp(nets->objs[i]->def->uuid, uuid, VIR_UUID_BUFLEN))
            return nets->objs[i];
        virNetworkObjUnlock(nets->objs[i]);
    }

    return NULL;
}

virNetworkObjPtr virNetworkFindByName(const virNetworkObjListPtr nets,
                                      const char *name)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++) {
        virNetworkObjLock(nets->objs[i]);
        if (STREQ(nets->objs[i]->def->name, name))
            return nets->objs[i];
        virNetworkObjUnlock(nets->objs[i]);
    }

    return NULL;
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
    VIR_FREE(def->name);
}

static void virNetworkIpDefClear(virNetworkIpDefPtr def)
{
    int ii;

    VIR_FREE(def->family);
    VIR_FREE(def->ranges);

    for (ii = 0 ; ii < def->nhosts && def->hosts ; ii++)
        virNetworkDHCPHostDefClear(&def->hosts[ii]);

    VIR_FREE(def->hosts);
    VIR_FREE(def->tftproot);
    VIR_FREE(def->bootfile);
}

static void virNetworkDNSDefFree(virNetworkDNSDefPtr def)
{
    if (def) {
        if (def->txtrecords) {
            while (def->ntxtrecords--) {
                VIR_FREE(def->txtrecords[def->ntxtrecords].name);
                VIR_FREE(def->txtrecords[def->ntxtrecords].value);
            }
        }
        VIR_FREE(def->txtrecords);
        if (def->nhosts) {
            while (def->nhosts--) {
                while (def->hosts[def->nhosts].nnames--)
                    VIR_FREE(def->hosts[def->nhosts].names[def->hosts[def->nhosts].nnames]);
                VIR_FREE(def->hosts[def->nhosts].names);
            }
        }
        VIR_FREE(def->hosts);
        if (def->nsrvrecords) {
            while (def->nsrvrecords--) {
                VIR_FREE(def->srvrecords[def->nsrvrecords].domain);
                VIR_FREE(def->srvrecords[def->nsrvrecords].service);
                VIR_FREE(def->srvrecords[def->nsrvrecords].protocol);
                VIR_FREE(def->srvrecords[def->nsrvrecords].target);
            }
        }
        VIR_FREE(def->srvrecords);
        VIR_FREE(def);
    }
}

void virNetworkDefFree(virNetworkDefPtr def)
{
    int ii;

    if (!def)
        return;

    VIR_FREE(def->name);
    VIR_FREE(def->bridge);
    VIR_FREE(def->domain);

    for (ii = 0 ; ii < def->nForwardPfs && def->forwardPfs ; ii++) {
        virNetworkForwardPfDefClear(&def->forwardPfs[ii]);
    }
    VIR_FREE(def->forwardPfs);

    for (ii = 0 ; ii < def->nForwardIfs && def->forwardIfs ; ii++) {
        virNetworkForwardIfDefClear(&def->forwardIfs[ii]);
    }
    VIR_FREE(def->forwardIfs);

    for (ii = 0 ; ii < def->nips && def->ips ; ii++) {
        virNetworkIpDefClear(&def->ips[ii]);
    }
    VIR_FREE(def->ips);

    for (ii = 0; ii < def->nPortGroups && def->portGroups; ii++) {
        virPortGroupDefClear(&def->portGroups[ii]);
    }
    VIR_FREE(def->portGroups);

    virNetworkDNSDefFree(def->dns);

    VIR_FREE(def->virtPortProfile);

    virNetDevBandwidthFree(def->bandwidth);
    virNetDevVlanClear(&def->vlan);
    VIR_FREE(def);
}

void virNetworkObjFree(virNetworkObjPtr net)
{
    if (!net)
        return;

    virNetworkDefFree(net->def);
    virNetworkDefFree(net->newDef);

    virMutexDestroy(&net->lock);

    VIR_FREE(net);
}

void virNetworkObjListFree(virNetworkObjListPtr nets)
{
    unsigned int i;

    for (i = 0 ; i < nets->count ; i++)
        virNetworkObjFree(nets->objs[i]);

    VIR_FREE(nets->objs);
    nets->count = 0;
}

/*
 * virNetworkObjAssignDef:
 * @network: the network object to update
 * @def: the new NetworkDef (will be consumed by this function iff successful)
 * @live: is this new def the "live" version, or the "persistent" version
 *
 * Replace the appropriate copy of the given network's NetworkDef
 * with def. Use "live" and current state of the network to determine
 * which to replace.
 *
 * Returns 0 on success, -1 on failure.
 */
int
virNetworkObjAssignDef(virNetworkObjPtr network,
                       const virNetworkDefPtr def,
                       bool live)
{
    if (virNetworkObjIsActive(network)) {
        if (live) {
            virNetworkDefFree(network->def);
            network->def = def;
        } else if (network->persistent) {
            /* save current configuration to be restored on network shutdown */
            virNetworkDefFree(network->newDef);
            network->newDef = def;
        } else {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("cannot save persistent config of transient "
                             "network '%s'"), network->def->name);
            return -1;
        }
    } else if (!live) {
        virNetworkDefFree(network->newDef); /* should be unnecessary */
        virNetworkDefFree(network->def);
        network->def = def;
    } else {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("cannot save live config of inactive "
                         "network '%s'"), network->def->name);
        return -1;
    }
    return 0;
}

/*
 * virNetworkAssignDef:
 * @nets: list of all networks
 * @def: the new NetworkDef (will be consumed by this function iff successful)
 * @live: is this new def the "live" version, or the "persistent" version
 *
 * Either replace the appropriate copy of the NetworkDef with name
 * matching def->name or, if not found, create a new NetworkObj with
 * def. For an existing network, use "live" and current state of the
 * network to determine which to replace.
 *
 * Returns -1 on failure, 0 on success.
 */
virNetworkObjPtr
virNetworkAssignDef(virNetworkObjListPtr nets,
                    const virNetworkDefPtr def,
                    bool live)
{
    virNetworkObjPtr network;

    if ((network = virNetworkFindByName(nets, def->name))) {
        if (virNetworkObjAssignDef(network, def, live) < 0) {
            return NULL;
        }
        return network;
    }

    if (VIR_REALLOC_N(nets->objs, nets->count + 1) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (VIR_ALLOC(network) < 0) {
        virReportOOMError();
        return NULL;
    }
    if (virMutexInit(&network->lock) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot initialize mutex"));
        VIR_FREE(network);
        return NULL;
    }
    virNetworkObjLock(network);
    network->def = def;

    nets->objs[nets->count] = network;
    nets->count++;

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
                              const virNetworkObjPtr net)
{
    unsigned int i;

    virNetworkObjUnlock(net);
    for (i = 0 ; i < nets->count ; i++) {
        virNetworkObjLock(nets->objs[i]);
        if (nets->objs[i] == net) {
            virNetworkObjUnlock(nets->objs[i]);
            virNetworkObjFree(nets->objs[i]);

            if (i < (nets->count - 1))
                memmove(nets->objs + i, nets->objs + i + 1,
                        sizeof(*(nets->objs)) * (nets->count - (i + 1)));

            if (VIR_REALLOC_N(nets->objs, nets->count - 1) < 0) {
                ; /* Failure to reduce memory allocation isn't fatal */
            }
            nets->count--;

            break;
        }
        virNetworkObjUnlock(nets->objs[i]);
    }
}

/* return ips[index], or NULL if there aren't enough ips */
virNetworkIpDefPtr
virNetworkDefGetIpByIndex(const virNetworkDefPtr def,
                          int family, size_t n)
{
    int ii;

    if (!def->ips || n >= def->nips)
        return NULL;

    if (family == AF_UNSPEC) {
        return &def->ips[n];
    }

    /* find the nth ip of type "family" */
    for (ii = 0; ii < def->nips; ii++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&def->ips[ii].address, family)
            && (n-- <= 0)) {
            return &def->ips[ii];
        }
    }
    /* failed to find enough of the right family */
    return NULL;
}

/* return number of 1 bits in netmask for the network's ipAddress,
 * or -1 on error
 */
int virNetworkIpDefPrefix(const virNetworkIpDefPtr def)
{
    if (def->prefix > 0) {
        return def->prefix;
    } else if (VIR_SOCKET_ADDR_VALID(&def->netmask)) {
        return virSocketAddrGetNumNetmaskBits(&def->netmask);
    } else if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
        /* Return the natural prefix for the network's ip address.
         * On Linux we could use the IN_CLASSx() macros, but those
         * aren't guaranteed on all platforms, so we just deal with
         * the bits ourselves.
         */
        unsigned char octet
            = ntohl(def->address.data.inet4.sin_addr.s_addr) >> 24;
        if ((octet & 0x80) == 0) {
            /* Class A network */
            return 8;
        } else if ((octet & 0xC0) == 0x80) {
            /* Class B network */
            return 16;
        } else if ((octet & 0xE0) == 0xC0) {
            /* Class C network */
            return 24;
        }
        return -1;
    } else if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
        return 64;
    }
    return -1;
}

/* Fill in a virSocketAddr with the proper netmask for this
 * definition, based on either the definition's netmask, or its
 * prefix. Return -1 on error (and set the netmask family to AF_UNSPEC)
 */
int virNetworkIpDefNetmask(const virNetworkIpDefPtr def,
                           virSocketAddrPtr netmask)
{
    if (VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
        *netmask = def->netmask;
        return 0;
    }

    return virSocketAddrPrefixToNetmask(virNetworkIpDefPrefix(def), netmask,
                                        VIR_SOCKET_ADDR_FAMILY(&def->address));
}


static int
virNetworkDHCPRangeDefParse(const char *networkName,
                            xmlNodePtr node,
                            virNetworkDHCPRangeDefPtr range)
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
    if (virSocketAddrGetRange(&range->start, &range->end) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid dhcp range '%s' to '%s' in network '%s'"),
                       start, end, networkName);
        goto cleanup;
    }

    ret = 0;

cleanup:
    VIR_FREE(start);
    VIR_FREE(end);
    return ret;
}

static int
virNetworkDHCPHostDefParse(const char *networkName,
                           xmlNodePtr node,
                           virNetworkDHCPHostDefPtr host,
                           bool partialOkay)
{
    char *mac = NULL, *name = NULL, *ip = NULL;
    virMacAddr addr;
    virSocketAddr inaddr;
    int ret = -1;

    mac = virXMLPropString(node, "mac");
    if (mac != NULL) {
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

    name = virXMLPropString(node, "name");
    if (name && (!c_isalpha(name[0]))) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Cannot use name address '%s' in network '%s'"),
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
        }
    } else {
        /* normal usage - you need at least one MAC address or one host name */
        if (!(mac || name)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Static host definition in network '%s' "
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
    host->name = name;
    name = NULL;
    if (ip)
        host->ip = inaddr;
    ret = 0;

cleanup:
    VIR_FREE(mac);
    VIR_FREE(name);
    VIR_FREE(ip);
    return ret;
}

static int
virNetworkDHCPDefParse(const char *networkName,
                       virNetworkIpDefPtr def,
                       xmlNodePtr node)
{

    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "range")) {

            if (VIR_REALLOC_N(def->ranges, def->nranges + 1) < 0) {
                virReportOOMError();
                return -1;
            }
            if (virNetworkDHCPRangeDefParse(networkName, cur,
                                            &def->ranges[def->nranges]) < 0) {
                return -1;
            }
            def->nranges++;

        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "host")) {

            if (VIR_REALLOC_N(def->hosts, def->nhosts + 1) < 0) {
                virReportOOMError();
                return -1;
            }
            if (virNetworkDHCPHostDefParse(networkName, cur,
                                           &def->hosts[def->nhosts],
                                           false) < 0) {
                return -1;
            }
            def->nhosts++;

        } else if (cur->type == XML_ELEMENT_NODE &&
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
                return -1;
            }

            def->bootfile = file;
            def->bootserver = inaddr;
            VIR_FREE(server);
        }

        cur = cur->next;
    }

    return 0;
}

static int
virNetworkDNSHostsDefParseXML(virNetworkDNSDefPtr def,
                              xmlNodePtr node)
{
    xmlNodePtr cur;
    char *ip;
    virSocketAddr inaddr;
    int ret = -1;

    if (!(ip = virXMLPropString(node, "ip")) ||
        (virSocketAddrParse(&inaddr, ip, AF_UNSPEC) < 0)) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("Missing IP address in DNS host definition"));
        VIR_FREE(ip);
        goto error;
    }
    VIR_FREE(ip);

    if (VIR_REALLOC_N(def->hosts, def->nhosts + 1) < 0) {
        virReportOOMError();
        goto error;
    }

    def->hosts[def->nhosts].ip = inaddr;
    def->hosts[def->nhosts].nnames = 0;

    if (VIR_ALLOC(def->hosts[def->nhosts].names) < 0) {
        virReportOOMError();
        goto error;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "hostname")) {
              if (cur->children != NULL) {
                  if (VIR_REALLOC_N(def->hosts[def->nhosts].names, def->hosts[def->nhosts].nnames + 1) < 0) {
                      virReportOOMError();
                      goto error;
                  }

                  def->hosts[def->nhosts].names[def->hosts[def->nhosts].nnames] = strdup((char *)cur->children->content);
                  def->hosts[def->nhosts].nnames++;
              }
        }

        cur = cur->next;
    }

    def->nhosts++;

    ret = 0;

error:
    return ret;
}

static int
virNetworkDNSSrvDefParseXML(virNetworkDNSDefPtr def,
                            xmlNodePtr cur,
                            xmlXPathContextPtr ctxt)
{
    char *domain = NULL;
    char *service = NULL;
    char *protocol = NULL;
    char *target = NULL;
    int port;
    int priority;
    int weight;
    int ret = 0;

    if (!(service = virXMLPropString(cur, "service"))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       "%s", _("Missing required service attribute in dns srv record"));
        goto error;
    }

    if (strlen(service) > DNS_RECORD_LENGTH_SRV) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Service name is too long, limit is %d bytes"),
                       DNS_RECORD_LENGTH_SRV);
        goto error;
    }

    if (!(protocol = virXMLPropString(cur, "protocol"))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Missing required protocol attribute in dns srv record '%s'"), service);
        goto error;
    }

    /* Check whether protocol value is the supported one */
    if (STRNEQ(protocol, "tcp") && (STRNEQ(protocol, "udp"))) {
        virReportError(VIR_ERR_XML_DETAIL,
                       _("Invalid protocol attribute value '%s'"), protocol);
        goto error;
    }

    if (VIR_REALLOC_N(def->srvrecords, def->nsrvrecords + 1) < 0) {
        virReportOOMError();
        goto error;
    }

    def->srvrecords[def->nsrvrecords].service = service;
    def->srvrecords[def->nsrvrecords].protocol = protocol;
    def->srvrecords[def->nsrvrecords].domain = NULL;
    def->srvrecords[def->nsrvrecords].target = NULL;
    def->srvrecords[def->nsrvrecords].port = 0;
    def->srvrecords[def->nsrvrecords].priority = 0;
    def->srvrecords[def->nsrvrecords].weight = 0;

    /* Following attributes are optional but we had to make sure they're NULL above */
    if ((target = virXMLPropString(cur, "target")) && (domain = virXMLPropString(cur, "domain"))) {
        xmlNodePtr save_ctxt = ctxt->node;

        ctxt->node = cur;
        if (virXPathInt("string(./@port)", ctxt, &port))
            def->srvrecords[def->nsrvrecords].port = port;

        if (virXPathInt("string(./@priority)", ctxt, &priority))
            def->srvrecords[def->nsrvrecords].priority = priority;

        if (virXPathInt("string(./@weight)", ctxt, &weight))
            def->srvrecords[def->nsrvrecords].weight = weight;
        ctxt->node = save_ctxt;

        def->srvrecords[def->nsrvrecords].domain = domain;
        def->srvrecords[def->nsrvrecords].target = target;
        def->srvrecords[def->nsrvrecords].port = port;
        def->srvrecords[def->nsrvrecords].priority = priority;
        def->srvrecords[def->nsrvrecords].weight = weight;
    }

    def->nsrvrecords++;

    goto cleanup;

error:
    VIR_FREE(domain);
    VIR_FREE(service);
    VIR_FREE(protocol);
    VIR_FREE(target);

    ret = -1;

cleanup:
    return ret;
}

static int
virNetworkDNSDefParseXML(virNetworkDNSDefPtr *dnsdef,
                         xmlNodePtr node,
                         xmlXPathContextPtr ctxt)
{
    xmlNodePtr cur;
    int ret = -1;
    char *name = NULL;
    char *value = NULL;
    virNetworkDNSDefPtr def = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto error;
    }

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "txt")) {
            if (!(name = virXMLPropString(cur, "name"))) {
                virReportError(VIR_ERR_XML_DETAIL,
                               "%s", _("Missing required name attribute in dns txt record"));
                goto error;
            }
            if (!(value = virXMLPropString(cur, "value"))) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("Missing required value attribute in dns txt record '%s'"), name);
                goto error;
            }

            if (strchr(name, ' ') != NULL) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("spaces are not allowed in DNS TXT record names (name is '%s')"), name);
                goto error;
            }

            if (VIR_REALLOC_N(def->txtrecords, def->ntxtrecords + 1) < 0) {
                virReportOOMError();
                goto error;
            }

            def->txtrecords[def->ntxtrecords].name = name;
            def->txtrecords[def->ntxtrecords].value = value;
            def->ntxtrecords++;
            name = NULL;
            value = NULL;
        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "srv")) {
            ret = virNetworkDNSSrvDefParseXML(def, cur, ctxt);
            if (ret < 0)
                goto error;
        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "host")) {
            ret = virNetworkDNSHostsDefParseXML(def, cur);
            if (ret < 0)
                goto error;
        }

        cur = cur->next;
    }

    ret = 0;
error:
    if (ret < 0) {
        VIR_FREE(name);
        VIR_FREE(value);
        virNetworkDNSDefFree(def);
    } else {
        *dnsdef = def;
    }
    return ret;
}

static int
virNetworkIPParseXML(const char *networkName,
                     virNetworkIpDefPtr def,
                     xmlNodePtr node,
                     xmlXPathContextPtr ctxt)
{
    /*
     * virNetworkIpDef object is already allocated as part of an array.
     * On failure clear it out, but don't free it.
     */

    xmlNodePtr cur, save;
    char *address = NULL, *netmask = NULL;
    unsigned long prefix;
    int result = -1;

    save = ctxt->node;
    ctxt->node = node;

    /* grab raw data from XML */
    def->family = virXPathString("string(./@family)", ctxt);
    address = virXPathString("string(./@address)", ctxt);
    if (virXPathULong("string(./@prefix)", ctxt, &prefix) < 0)
        def->prefix = 0;
    else
        def->prefix = prefix;

    netmask = virXPathString("string(./@netmask)", ctxt);

    if (address) {
        if (virSocketAddrParse(&def->address, address, AF_UNSPEC) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Bad address '%s' in definition of network '%s'"),
                           address, networkName);
            goto error;
        }

    }

    /* validate family vs. address */
    if (def->family == NULL) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("no family specified for non-IPv4 address '%s' in network '%s'"),
                           address, networkName);
            goto error;
        }
    } else if (STREQ(def->family, "ipv4")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("family 'ipv4' specified for non-IPv4 address '%s' in network '%s'"),
                           address, networkName);
            goto error;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("family 'ipv6' specified for non-IPv6 address '%s' in network '%s'"),
                           address, networkName);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unrecognized family '%s' in definition of network '%s'"),
                       def->family, networkName);
        goto error;
    }

    /* parse/validate netmask */
    if (netmask) {
        if (address == NULL) {
            /* netmask is meaningless without an address */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("netmask specified without address in network '%s'"),
                           networkName);
            goto error;
        }

        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("netmask not supported for address '%s' in network '%s' (IPv4 only)"),
                           address, networkName);
            goto error;
        }

        if (def->prefix > 0) {
            /* can't have both netmask and prefix at the same time */
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("network '%s' cannot have both prefix='%u' and a netmask"),
                           networkName, def->prefix);
            goto error;
        }

        if (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0)
            goto error;

        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("network '%s' has invalid netmask '%s' for address '%s' (both must be IPv4)"),
                           networkName, netmask, address);
            goto error;
        }
    }

    if (VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
        /* parse IPv4-related info */
        cur = node->children;
        while (cur != NULL) {
            if (cur->type == XML_ELEMENT_NODE &&
                xmlStrEqual(cur->name, BAD_CAST "dhcp")) {
                result = virNetworkDHCPDefParse(networkName, def, cur);
                if (result)
                    goto error;

            } else if (cur->type == XML_ELEMENT_NODE &&
                       xmlStrEqual(cur->name, BAD_CAST "tftp")) {
                char *root;

                if (!(root = virXMLPropString(cur, "root"))) {
                    cur = cur->next;
                    continue;
                }

                def->tftproot = (char *)root;
            }

            cur = cur->next;
        }
    }

    result = 0;

error:
    if (result < 0) {
        virNetworkIpDefClear(def);
    }
    VIR_FREE(address);
    VIR_FREE(netmask);

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

    int result = -1;

    save = ctxt->node;
    ctxt->node = node;

    /* grab raw data from XML */
    def->name = virXPathString("string(./@name)", ctxt);
    isDefault = virXPathString("string(./@default)", ctxt);
    def->isDefault = isDefault && STRCASEEQ(isDefault, "yes");

    virtPortNode = virXPathNode("./virtualport", ctxt);
    if (virtPortNode &&
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode, 0)))) {
        goto error;
    }

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        !(def->bandwidth = virNetDevBandwidthParse(bandwidth_node))) {
        goto error;
    }

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto error;

    result = 0;
error:
    if (result < 0) {
        virPortGroupDefClear(def);
    }
    VIR_FREE(isDefault);

    ctxt->node = save;
    return result;
}

static virNetworkDefPtr
virNetworkDefParseXML(xmlXPathContextPtr ctxt)
{
    virNetworkDefPtr def;
    char *tmp;
    char *stp = NULL;
    xmlNodePtr *ipNodes = NULL;
    xmlNodePtr *portGroupNodes = NULL;
    xmlNodePtr *forwardIfNodes = NULL;
    xmlNodePtr *forwardPfNodes = NULL;
    xmlNodePtr *forwardAddrNodes = NULL;
    xmlNodePtr dnsNode = NULL;
    xmlNodePtr virtPortNode = NULL;
    xmlNodePtr forwardNode = NULL;
    int nIps, nPortGroups, nForwardIfs, nForwardPfs, nForwardAddrs;
    char *forwardDev = NULL;
    char *forwardManaged = NULL;
    char *type = NULL;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr bandwidthNode = NULL;
    xmlNodePtr vlanNode;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    /* Extract network name */
    def->name = virXPathString("string(./name[1])", ctxt);
    if (!def->name) {
        virReportError(VIR_ERR_NO_NAME, NULL);
        goto error;
    }

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
            VIR_FREE(tmp);
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
        def->uuid_specified = true;
    }

    /* Parse network domain information */
    def->domain = virXPathString("string(./domain[1]/@name)", ctxt);

    if ((bandwidthNode = virXPathNode("./bandwidth", ctxt)) != NULL &&
        (def->bandwidth = virNetDevBandwidthParse(bandwidthNode)) == NULL)
        goto error;

    vlanNode = virXPathNode("./vlan", ctxt);
    if (vlanNode && virNetDevVlanParse(vlanNode, ctxt, &def->vlan) < 0)
        goto error;

    /* Parse bridge information */
    def->bridge = virXPathString("string(./bridge[1]/@name)", ctxt);
    stp = virXPathString("string(./bridge[1]/@stp)", ctxt);

    if (virXPathULong("string(./bridge[1]/@delay)", ctxt, &def->delay) < 0)
        def->delay = 0;

    tmp = virXPathString("string(./mac[1]/@address)", ctxt);
    if (tmp) {
        if (virMacAddrParse(tmp, &def->mac) < 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid bridge mac address '%s' in network '%s'"),
                           tmp, def->name);
            VIR_FREE(tmp);
            goto error;
        }
        if (virMacAddrIsMulticast(&def->mac)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid multicast bridge mac address '%s' in network '%s'"),
                           tmp, def->name);
            VIR_FREE(tmp);
            goto error;
        }
        VIR_FREE(tmp);
        def->mac_specified = true;
    }

    dnsNode = virXPathNode("./dns", ctxt);
    if (dnsNode != NULL) {
        if (virNetworkDNSDefParseXML(&def->dns, dnsNode, ctxt) < 0)
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
        int ii;

        /* allocate array to hold all the portgroups */
        if (VIR_ALLOC_N(def->portGroups, nPortGroups) < 0) {
            virReportOOMError();
            goto error;
        }
        /* parse each portgroup */
        for (ii = 0; ii < nPortGroups; ii++) {
            int ret = virNetworkPortGroupParseXML(&def->portGroups[ii],
                                                  portGroupNodes[ii], ctxt);
            if (ret < 0)
                goto error;
            def->nPortGroups++;
        }
    }
    VIR_FREE(portGroupNodes);

    nIps = virXPathNodeSet("./ip", ctxt, &ipNodes);
    if (nIps < 0)
        goto error;

    if (nIps > 0) {
        int ii;

        /* allocate array to hold all the addrs */
        if (VIR_ALLOC_N(def->ips, nIps) < 0) {
            virReportOOMError();
            goto error;
        }
        /* parse each addr */
        for (ii = 0; ii < nIps; ii++) {
            int ret = virNetworkIPParseXML(def->name, &def->ips[ii],
                                           ipNodes[ii], ctxt);
            if (ret < 0)
                goto error;
            def->nips++;
        }
    }
    VIR_FREE(ipNodes);

    forwardNode = virXPathNode("./forward", ctxt);
    if (!forwardNode) {
        def->forwardType = VIR_NETWORK_FORWARD_NONE;
        def->stp = (stp && STREQ(stp, "off")) ? 0 : 1;
    } else {
        ctxt->node = forwardNode;
        tmp = virXPathString("string(./@mode)", ctxt);
        if (tmp) {
            if ((def->forwardType = virNetworkForwardTypeFromString(tmp)) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("unknown forwarding type '%s'"), tmp);
                VIR_FREE(tmp);
                goto error;
            }
            VIR_FREE(tmp);
        } else {
            def->forwardType = VIR_NETWORK_FORWARD_NAT;
        }

        forwardDev = virXPathString("string(./@dev)", ctxt);
        forwardManaged = virXPathString("string(./@managed)", ctxt);
        if(forwardManaged != NULL) {
            if (STRCASEEQ(forwardManaged, "yes"))
                def->managed = 1;
        }

        /* all of these modes can use a pool of physical interfaces */
        nForwardIfs = virXPathNodeSet("./interface", ctxt, &forwardIfNodes);
        nForwardPfs = virXPathNodeSet("./pf", ctxt, &forwardPfNodes);
        nForwardAddrs = virXPathNodeSet("./address", ctxt, &forwardAddrNodes);

        if (nForwardIfs < 0 || nForwardPfs < 0 || nForwardAddrs < 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("No interface pool or SRIOV physical device given"));
            goto error;
        }

        if ((nForwardIfs > 0) && (nForwardAddrs > 0)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Address and interface attributes are mutually exclusive"));
            goto error;
        }

        if ((nForwardPfs > 0) && ((nForwardIfs > 0) || (nForwardAddrs > 0))) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Address/interface attributes and Physical function are mutually exclusive "));
            goto error;
        }

        if (nForwardPfs == 1) {
            if (VIR_ALLOC_N(def->forwardPfs, nForwardPfs) < 0) {
                virReportOOMError();
                goto error;
            }

            if (forwardDev) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("A forward Dev should not be used when using a SRIOV PF"));
                goto error;
            }

            forwardDev = virXMLPropString(*forwardPfNodes, "dev");
            if (!forwardDev) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Missing required dev attribute in network '%s' pf element"),
                               def->name);
                goto error;
            }

            def->forwardPfs->dev = forwardDev;
            forwardDev = NULL;
            def->nForwardPfs++;
        } else if (nForwardPfs > 1) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Use of more than one physical interface is not allowed"));
            goto error;
        }
        if (nForwardAddrs > 0) {
            int ii;

            if (VIR_ALLOC_N(def->forwardIfs, nForwardAddrs) < 0) {
                virReportOOMError();
                goto error;
            }

            if (forwardDev) {
                virReportError(VIR_ERR_XML_ERROR, "%s",
                               _("A forward Dev should not be used when using address attribute"));
                goto error;
            }

            for (ii = 0; ii < nForwardAddrs; ii++) {
                type = virXMLPropString(forwardAddrNodes[ii], "type");

                if (type) {
                    if ((def->forwardIfs[ii].type = virNetworkForwardHostdevDeviceTypeFromString(type)) < 0) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("unknown address type '%s'"), type);
                        goto error;
                    }
                } else {
                    virReportError(VIR_ERR_XML_ERROR,
                                   "%s", _("No type specified for device address"));
                    goto error;
                }

                switch (def->forwardIfs[ii].type) {
                case VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI:
                    if (virDevicePCIAddressParseXML(forwardAddrNodes[ii], &(def->forwardIfs[ii].device.pci)) < 0)
                        goto error;
                    break;

                /* Add USB case here */

                default:
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("unknown address type '%s'"), type);
                    goto error;
                }
                VIR_FREE(type);
                def->nForwardIfs++;
            }
        }
        else if (nForwardIfs > 0 || forwardDev) {
            int ii;

            /* allocate array to hold all the portgroups */
            if (VIR_ALLOC_N(def->forwardIfs, MAX(nForwardIfs, 1)) < 0) {
                virReportOOMError();
                goto error;
            }

            if (forwardDev) {
                def->forwardIfs[0].device.dev = forwardDev;
                def->forwardIfs[0].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
                forwardDev = NULL;
                def->nForwardIfs++;
            }

            /* parse each forwardIf */
            for (ii = 0; ii < nForwardIfs; ii++) {
                forwardDev = virXMLPropString(forwardIfNodes[ii], "dev");
                if (!forwardDev) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("Missing required dev attribute in network '%s' forward interface element"),
                                   def->name);
                    goto error;
                }

                if ((ii == 0) && (def->nForwardIfs == 1)) {
                    /* both forwardDev and an interface element are present.
                     * If they don't match, it's an error. */
                    if (STRNEQ(forwardDev, def->forwardIfs[0].device.dev)) {
                        virReportError(VIR_ERR_XML_ERROR,
                                       _("forward dev '%s' must match first interface element dev '%s' in network '%s'"),
                                       def->forwardIfs[0].device.dev,
                                       forwardDev, def->name);
                        goto error;
                    }
                    VIR_FREE(forwardDev);
                    continue;
                }

                def->forwardIfs[ii].device.dev = forwardDev;
                forwardDev = NULL;
                def->forwardIfs[ii].type = VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV;
                def->nForwardIfs++;
            }
        }
        VIR_FREE(type);
        VIR_FREE(forwardDev);
        VIR_FREE(forwardManaged);
        VIR_FREE(forwardPfNodes);
        VIR_FREE(forwardIfNodes);
        VIR_FREE(forwardAddrNodes);
        switch (def->forwardType) {
        case VIR_NETWORK_FORWARD_ROUTE:
        case VIR_NETWORK_FORWARD_NAT:
            /* It's pointless to specify L3 forwarding without specifying
             * the network we're on.
             */
            if (def->nips == 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("%s forwarding requested, but no IP address provided for network '%s'"),
                               virNetworkForwardTypeToString(def->forwardType),
                               def->name);
                goto error;
            }
            if (def->nForwardIfs > 1) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("multiple forwarding interfaces specified for network '%s', only one is supported"),
                               def->name);
                goto error;
            }
            def->stp = (stp && STREQ(stp, "off")) ? 0 : 1;
            break;
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
        case VIR_NETWORK_FORWARD_HOSTDEV:
            if (def->bridge) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("bridge name not allowed in %s mode (network '%s')"),
                               virNetworkForwardTypeToString(def->forwardType),
                               def->name);
                goto error;
            }
            /* fall through to next case */
        case VIR_NETWORK_FORWARD_BRIDGE:
            if (def->delay || stp) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("bridge delay/stp options only allowed in route, nat, and isolated mode, not in %s (network '%s')"),
                               virNetworkForwardTypeToString(def->forwardType),
                               def->name);
                goto error;
            }
            break;
        }
    }
    VIR_FREE(stp);
    ctxt->node = save;
    return def;

 error:
    VIR_FREE(stp);
    virNetworkDefFree(def);
    VIR_FREE(ipNodes);
    VIR_FREE(portGroupNodes);
    VIR_FREE(forwardIfNodes);
    VIR_FREE(forwardPfNodes);
    VIR_FREE(forwardDev);
    ctxt->node = save;
    return NULL;
}

static virNetworkDefPtr
virNetworkDefParse(const char *xmlStr,
                   const char *filename)
{
    xmlDocPtr xml;
    virNetworkDefPtr def = NULL;

    if ((xml = virXMLParse(filename, xmlStr, _("(network_definition)")))) {
        def = virNetworkDefParseNode(xml, xmlDocGetRootElement(xml));
        xmlFreeDoc(xml);
    }

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
                       virNetworkDNSDefPtr def)
{
    int result = 0;
    int i;

    if (def == NULL)
        goto out;

    virBufferAddLit(buf, "<dns>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0 ; i < def->ntxtrecords ; i++) {
        virBufferAsprintf(buf, "<txt name='%s' value='%s' />\n",
                              def->txtrecords[i].name,
                              def->txtrecords[i].value);
    }

    for (i = 0 ; i < def->nsrvrecords ; i++) {
        if (def->srvrecords[i].service && def->srvrecords[i].protocol) {
            virBufferAsprintf(buf, "<srv service='%s' protocol='%s'",
                                  def->srvrecords[i].service,
                                  def->srvrecords[i].protocol);

            if (def->srvrecords[i].domain)
                virBufferAsprintf(buf, " domain='%s'", def->srvrecords[i].domain);
            if (def->srvrecords[i].target)
                virBufferAsprintf(buf, " target='%s'", def->srvrecords[i].target);
            if (def->srvrecords[i].port)
                virBufferAsprintf(buf, " port='%d'", def->srvrecords[i].port);
            if (def->srvrecords[i].priority)
                virBufferAsprintf(buf, " priority='%d'", def->srvrecords[i].priority);
            if (def->srvrecords[i].weight)
                virBufferAsprintf(buf, " weight='%d'", def->srvrecords[i].weight);

            virBufferAsprintf(buf, "/>\n");
        }
    }

    if (def->nhosts) {
        int ii, j;

        for (ii = 0 ; ii < def->nhosts; ii++) {
            char *ip = virSocketAddrFormat(&def->hosts[ii].ip);

            virBufferAsprintf(buf, "<host ip='%s'>\n", ip);
            virBufferAdjustIndent(buf, 2);
            for (j = 0; j < def->hosts[ii].nnames; j++)
                virBufferAsprintf(buf, "<hostname>%s</hostname>\n",
                                  def->hosts[ii].names[j]);

            virBufferAdjustIndent(buf, -2);
            virBufferAsprintf(buf, "</host>\n");
            VIR_FREE(ip);
        }
    }
    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</dns>\n");
out:
    return result;
}

static int
virNetworkIpDefFormat(virBufferPtr buf,
                      const virNetworkIpDefPtr def)
{
    int result = -1;

    virBufferAddLit(buf, "<ip");

    if (def->family) {
        virBufferAsprintf(buf, " family='%s'", def->family);
    }
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
    if (def->prefix > 0) {
        virBufferAsprintf(buf," prefix='%u'", def->prefix);
    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 2);

    if (def->tftproot) {
        virBufferEscapeString(buf, "<tftp root='%s' />\n",
                              def->tftproot);
    }
    if ((def->nranges || def->nhosts)) {
        int ii;
        virBufferAddLit(buf, "<dhcp>\n");
        virBufferAdjustIndent(buf, 2);

        for (ii = 0 ; ii < def->nranges ; ii++) {
            char *saddr = virSocketAddrFormat(&def->ranges[ii].start);
            if (!saddr)
                goto error;
            char *eaddr = virSocketAddrFormat(&def->ranges[ii].end);
            if (!eaddr) {
                VIR_FREE(saddr);
                goto error;
            }
            virBufferAsprintf(buf, "<range start='%s' end='%s' />\n",
                              saddr, eaddr);
            VIR_FREE(saddr);
            VIR_FREE(eaddr);
        }
        for (ii = 0 ; ii < def->nhosts ; ii++) {
            virBufferAddLit(buf, "<host ");
            if (def->hosts[ii].mac)
                virBufferAsprintf(buf, "mac='%s' ", def->hosts[ii].mac);
            if (def->hosts[ii].name)
                virBufferAsprintf(buf, "name='%s' ", def->hosts[ii].name);
            if (VIR_SOCKET_ADDR_VALID(&def->hosts[ii].ip)) {
                char *ipaddr = virSocketAddrFormat(&def->hosts[ii].ip);
                if (!ipaddr)
                    goto error;
                virBufferAsprintf(buf, "ip='%s' ", ipaddr);
                VIR_FREE(ipaddr);
            }
            virBufferAddLit(buf, "/>\n");
        }
        if (def->bootfile) {
            virBufferEscapeString(buf, "<bootp file='%s' ",
                                  def->bootfile);
            if (VIR_SOCKET_ADDR_VALID(&def->bootserver)) {
                char *ipaddr = virSocketAddrFormat(&def->bootserver);
                if (!ipaddr)
                    goto error;
                virBufferEscapeString(buf, "server='%s' ", ipaddr);
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
                      const virPortGroupDefPtr def)
{
    virBufferAsprintf(buf, "<portgroup name='%s'", def->name);
    if (def->isDefault) {
        virBufferAddLit(buf, " default='yes'");
    }
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

char *virNetworkDefFormat(const virNetworkDefPtr def, unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ii;

    virBufferAddLit(&buf, "<network");
    if (!(flags & VIR_NETWORK_XML_INACTIVE) && (def->connections > 0)) {
        virBufferAsprintf(&buf, " connections='%d'", def->connections);
    }
    virBufferAddLit(&buf, ">\n");
    virBufferAdjustIndent(&buf, 2);
    virBufferEscapeString(&buf, "<name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(&buf, "<uuid>%s</uuid>\n", uuidstr);

    if (def->forwardType != VIR_NETWORK_FORWARD_NONE) {
        const char *dev = NULL;
        if (!def->nForwardPfs)
            dev = virNetworkDefForwardIf(def, 0);
        const char *mode = virNetworkForwardTypeToString(def->forwardType);

        if (!mode) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unknown forward type %d in network '%s'"),
                           def->forwardType, def->name);
            goto error;
        }
        virBufferAddLit(&buf, "<forward");
        virBufferEscapeString(&buf, " dev='%s'", dev);
        virBufferAsprintf(&buf, " mode='%s'", mode);
        if (def->forwardType == VIR_NETWORK_FORWARD_HOSTDEV) {
            if (def->managed == 1)
                virBufferAddLit(&buf, " managed='yes'");
            else
                virBufferAddLit(&buf, " managed='no'");
        }
        virBufferAsprintf(&buf, "%s>\n",
                          (def->nForwardIfs || def->nForwardPfs) ? "" : "/");
        virBufferAdjustIndent(&buf, 2);

        /* For now, hard-coded to at most 1 forwardPfs */
        if (def->nForwardPfs)
            virBufferEscapeString(&buf, "<pf dev='%s'/>\n",
                                  def->forwardPfs[0].dev);

        if (def->nForwardIfs &&
            (!def->nForwardPfs || !(flags & VIR_NETWORK_XML_INACTIVE))) {
            for (ii = 0; ii < def->nForwardIfs; ii++) {
                if (def->forwardType != VIR_NETWORK_FORWARD_HOSTDEV) {
                    virBufferEscapeString(&buf, "<interface dev='%s'",
                                          def->forwardIfs[ii].device.dev);
                    if (!(flags & VIR_NETWORK_XML_INACTIVE) &&
                        (def->forwardIfs[ii].connections > 0)) {
                        virBufferAsprintf(&buf, " connections='%d'",
                                          def->forwardIfs[ii].connections);
                    }
                    virBufferAddLit(&buf, "/>\n");
                }
                else {
                    if (def->forwardIfs[ii].type ==  VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI) {
                        if (virDevicePCIAddressFormat(&buf,
                                                      def->forwardIfs[ii].device.pci,
                                                      true) < 0)
                            goto error;
                    }
                }
            }
        }
        virBufferAdjustIndent(&buf, -2);
        if (def->nForwardPfs || def->nForwardIfs)
            virBufferAddLit(&buf, "</forward>\n");
    }

    if (def->forwardType == VIR_NETWORK_FORWARD_NONE ||
         def->forwardType == VIR_NETWORK_FORWARD_NAT ||
         def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {

        virBufferAddLit(&buf, "<bridge");
        if (def->bridge)
            virBufferEscapeString(&buf, " name='%s'", def->bridge);
        virBufferAsprintf(&buf, " stp='%s' delay='%ld' />\n",
                          def->stp ? "on" : "off",
                          def->delay);
    } else if (def->forwardType == VIR_NETWORK_FORWARD_BRIDGE &&
               def->bridge) {
       virBufferEscapeString(&buf, "<bridge name='%s' />\n", def->bridge);
    }


    if (def->mac_specified) {
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virMacAddrFormat(&def->mac, macaddr);
        virBufferAsprintf(&buf, "<mac address='%s'/>\n", macaddr);
    }

    if (def->domain)
        virBufferAsprintf(&buf, "<domain name='%s'/>\n", def->domain);

    if (virNetworkDNSDefFormat(&buf, def->dns) < 0)
        goto error;

    if (virNetDevVlanFormat(&def->vlan, &buf) < 0)
        goto error;
    if (virNetDevBandwidthFormat(def->bandwidth, &buf) < 0)
        goto error;

    for (ii = 0; ii < def->nips; ii++) {
        if (virNetworkIpDefFormat(&buf, &def->ips[ii]) < 0)
            goto error;
    }

    if (virNetDevVPortProfileFormat(def->virtPortProfile, &buf) < 0)
        goto error;

    for (ii = 0; ii < def->nPortGroups; ii++)
        if (virPortGroupDefFormat(&buf, &def->portGroups[ii]) < 0)
            goto error;

    virBufferAdjustIndent(&buf, -2);
    virBufferAddLit(&buf, "</network>\n");

    if (virBufferError(&buf))
        goto no_memory;

    return virBufferContentAndReset(&buf);

 no_memory:
    virReportOOMError();
  error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

virPortGroupDefPtr virPortGroupFindByName(virNetworkDefPtr net,
                                          const char *portgroup)
{
    int ii;
    for (ii = 0; ii < net->nPortGroups; ii++) {
        if (portgroup) {
            if (STREQ(portgroup, net->portGroups[ii].name))
                return &net->portGroups[ii];
        } else {
            if (net->portGroups[ii].isDefault)
                return &net->portGroups[ii];
        }
    }
    return NULL;
}

int virNetworkSaveXML(const char *configDir,
                      virNetworkDefPtr def,
                      const char *xml)
{
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

    ret = virXMLSaveFile(configFile, def->name, "net-edit", xml);

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
    char *xml;

    if (!(xml = virNetworkDefFormat(network->def, 0)))
        goto cleanup;

    if (virNetworkSaveXML(statusDir, network->def, xml))
        goto cleanup;

    ret = 0;
cleanup:
    VIR_FREE(xml);
    return ret;
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

    if (!STREQ(name, def->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network config filename '%s'"
                         " does not match network name '%s'"),
                       configFile, def->name);
        goto error;
    }

    if (def->forwardType == VIR_NETWORK_FORWARD_NONE ||
        def->forwardType == VIR_NETWORK_FORWARD_NAT ||
        def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {

        /* Generate a bridge if none is specified, but don't check for collisions
         * if a bridge is hardcoded, so the network is at least defined.
         */
        if (virNetworkSetBridgeName(nets, def, 0))
            goto error;
    }

    if (!(net = virNetworkAssignDef(nets, def, false)))
        goto error;

    net->autostart = autostart;
    net->persistent = 1;

    VIR_FREE(configFile);
    VIR_FREE(autostartLink);

    return net;

error:
    VIR_FREE(configFile);
    VIR_FREE(autostartLink);
    virNetworkDefFree(def);
    return NULL;
}

int virNetworkLoadAllConfigs(virNetworkObjListPtr nets,
                             const char *configDir,
                             const char *autostartDir)
{
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir(configDir))) {
        if (errno == ENOENT)
            return 0;
        virReportSystemError(errno,
                             _("Failed to open dir '%s'"),
                             configDir);
        return -1;
    }

    while ((entry = readdir(dir))) {
        virNetworkObjPtr net;

        if (entry->d_name[0] == '.')
            continue;

        if (!virFileStripSuffix(entry->d_name, ".xml"))
            continue;

        /* NB: ignoring errors, so one malformed config doesn't
           kill the whole process */
        net = virNetworkLoadConfig(nets,
                                   configDir,
                                   autostartDir,
                                   entry->d_name);
        if (net)
            virNetworkObjUnlock(net);
    }

    closedir(dir);

    return 0;
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

    if (virAsprintf(&ret, "%s/%s.xml", dir, name) < 0) {
        virReportOOMError();
        return NULL;
    }

    return ret;
}

int virNetworkBridgeInUse(const virNetworkObjListPtr nets,
                          const char *bridge,
                          const char *skipname)
{
    unsigned int i;
    unsigned int ret = 0;

    for (i = 0 ; i < nets->count ; i++) {
        virNetworkObjLock(nets->objs[i]);
        if (nets->objs[i]->def->bridge &&
            STREQ(nets->objs[i]->def->bridge, bridge) &&
            !(skipname && STREQ(nets->objs[i]->def->name, skipname)))
                ret = 1;
        virNetworkObjUnlock(nets->objs[i]);
    }

    return ret;
}

char *virNetworkAllocateBridge(const virNetworkObjListPtr nets,
                               const char *template)
{

    int id = 0;
    char *newname;

    if (!template)
        template = "virbr%d";

    do {
        if (virAsprintf(&newname, template, id) < 0) {
            virReportOOMError();
            return NULL;
        }
        if (!virNetworkBridgeInUse(nets, newname, NULL)) {
            return newname;
        }
        VIR_FREE(newname);

        id++;
    } while (id <= MAX_BRIDGE_ID);

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Bridge generation exceeded max id %d"),
                   MAX_BRIDGE_ID);
    return NULL;
}

int virNetworkSetBridgeName(const virNetworkObjListPtr nets,
                            virNetworkDefPtr def,
                            int check_collision) {

    int ret = -1;

    if (def->bridge && !strstr(def->bridge, "%d")) {
        /* We may want to skip collision detection in this case (ex. when
         * loading configs at daemon startup, so the network is at least
         * defined. */
        if (check_collision &&
            virNetworkBridgeInUse(nets, def->bridge, def->name)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("bridge name '%s' already in use."),
                           def->bridge);
            goto error;
        }
    } else {
        /* Allocate a bridge name */
        if (!(def->bridge = virNetworkAllocateBridge(nets, def->bridge)))
            goto error;
    }

    ret = 0;
error:
    return ret;
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
    virReportError(VIR_ERR_NO_SUPPORT,
                   _("can't update '%s' section of network '%s'"),
                   section, def->name);
}
static void
virNetworkDefUpdateUnknownCommand(unsigned int command)
{
    virReportError(VIR_ERR_NO_SUPPORT,
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

static virNetworkIpDefPtr
virNetworkIpDefByIndex(virNetworkDefPtr def, int parentIndex)
{
    virNetworkIpDefPtr ipdef = NULL;
    int ii;

    /* first find which ip element's dhcp host list to work on */
    if (parentIndex >= 0) {
        ipdef = virNetworkDefGetIpByIndex(def, AF_UNSPEC, parentIndex);
        if (!(ipdef &&
              VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET))) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't update dhcp host entry - "
                             "no <ip family='ipv4'> "
                             "element found at index %d in network '%s'"),
                           parentIndex, def->name);
        }
        return ipdef;
    }

    /* -1 means "find the most appropriate", which in this case
     * means the one and only <ip> that has <dhcp> element
     */
    for (ii = 0;
         (ipdef = virNetworkDefGetIpByIndex(def, AF_UNSPEC, ii));
         ii++) {
        if (VIR_SOCKET_ADDR_IS_FAMILY(&ipdef->address, AF_INET) &&
            (ipdef->nranges || ipdef->nhosts)) {
            break;
        }
    }
    if (!ipdef)
        ipdef = virNetworkDefGetIpByIndex(def, AF_INET, 0);
    if (!ipdef) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't update dhcp host entry - "
                         "no <ip family='ipv4'> "
                         "element found in network '%s'"), def->name);
    }
    return ipdef;
}

static int
virNetworkDefUpdateIPDHCPHost(virNetworkDefPtr def,
                              unsigned int command,
                              int parentIndex,
                              xmlXPathContextPtr ctxt,
                              /* virNetworkUpdateFlags */
                              unsigned int fflags ATTRIBUTE_UNUSED)
{
    int ii, ret = -1;
    virNetworkIpDefPtr ipdef = virNetworkIpDefByIndex(def, parentIndex);
    virNetworkDHCPHostDef host;

    memset(&host, 0, sizeof(host));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "host") < 0)
        goto cleanup;

    /* ipdef is the ip element that needs its host array updated */
    if (!ipdef)
        goto cleanup;

    /* parse the xml into a virNetworkDHCPHostDef */
    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        if (virNetworkDHCPHostDefParse(def->name, ctxt->node, &host, false) < 0)
            goto cleanup;

        /* search for the entry with this (mac|name),
         * and update the IP+(mac|name) */
        for (ii = 0; ii < ipdef->nhosts; ii++) {
            if ((host.mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[ii].mac)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[ii].name))) {
                break;
            }
        }

        if (ii == ipdef->nhosts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate an existing dhcp host entry with "
                             "\"mac='%s'\" in network '%s'"),
                           host.mac, def->name);
            goto cleanup;
        }

        /* clear the existing hosts entry, move the new one in its place,
         * then clear out the extra copy to get rid of the duplicate pointers
         * to its data (mac and name strings).
         */
        virNetworkDHCPHostDefClear(&ipdef->hosts[ii]);
        ipdef->hosts[ii] = host;
        memset(&host, 0, sizeof(host));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
               (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (virNetworkDHCPHostDefParse(def->name, ctxt->node, &host, true) < 0)
            goto cleanup;

        /* log error if an entry with same name/address/ip already exists */
        for (ii = 0; ii < ipdef->nhosts; ii++) {
            if ((host.mac &&
                 !virMacAddrCompare(host.mac, ipdef->hosts[ii].mac)) ||
                (host.name &&
                 STREQ_NULLABLE(host.name, ipdef->hosts[ii].name)) ||
                (VIR_SOCKET_ADDR_VALID(&host.ip) &&
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[ii].ip))) {
                char *ip = virSocketAddrFormat(&host.ip);

                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("there is an existing dhcp host entry in "
                                 "network '%s' that matches "
                                 "\"<host mac='%s' name='%s' ip='%s'/>\""),
                               def->name, host.mac, host.name,
                               ip ? ip : "unknown");
                VIR_FREE(ip);
                goto cleanup;
            }
        }
        /* add to beginning/end of list */
        if (VIR_REALLOC_N(ipdef->hosts, ipdef->nhosts +1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST) {

            ipdef->hosts[ipdef->nhosts] = host;
            ipdef->nhosts++;
            memset(&host, 0, sizeof(host));

        } else { /* implied (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) */

            memmove(ipdef->hosts + 1, ipdef->hosts,
                    sizeof(*ipdef->hosts) * ipdef->nhosts);
            ipdef->hosts[0] = host;
            ipdef->nhosts++;
            memset(&host, 0, sizeof(host));
        }

    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (virNetworkDHCPHostDefParse(def->name, ctxt->node, &host, false) < 0)
            goto cleanup;

        /* find matching entry - all specified attributes must match */
        for (ii = 0; ii < ipdef->nhosts; ii++) {
            if ((!host.mac ||
                 !virMacAddrCompare(host.mac, ipdef->hosts[ii].mac)) &&
                (!host.name ||
                 STREQ_NULLABLE(host.name, ipdef->hosts[ii].name)) &&
                (!VIR_SOCKET_ADDR_VALID(&host.ip) ||
                 virSocketAddrEqual(&host.ip, &ipdef->hosts[ii].ip))) {
                break;
            }
        }
        if (ii == ipdef->nhosts) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp host entry "
                             "in network '%s'"), def->name);
            goto cleanup;
        }

        /* remove it */
        virNetworkDHCPHostDefClear(&ipdef->hosts[ii]);
        memmove(ipdef->hosts + ii, ipdef->hosts + ii + 1,
                sizeof(*ipdef->hosts) * (ipdef->nhosts - ii - 1));
        ipdef->nhosts--;
        ignore_value(VIR_REALLOC_N(ipdef->hosts, ipdef->nhosts));
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
                               int parentIndex ATTRIBUTE_UNUSED,
                               xmlXPathContextPtr ctxt,
                               /* virNetworkUpdateFlags */
                               unsigned int fflags ATTRIBUTE_UNUSED)
{
    int ii, ret = -1;
    virNetworkIpDefPtr ipdef = virNetworkIpDefByIndex(def, parentIndex);
    virNetworkDHCPRangeDef range;

    memset(&range, 0, sizeof(range));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "range") < 0)
        goto cleanup;

    /* ipdef is the ip element that needs its range array updated */
    if (!ipdef)
        goto cleanup;

    /* parse the xml into a virNetworkDHCPRangeDef */
    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        virReportError(VIR_ERR_NO_SUPPORT, "%s",
                       _("dhcp ranges cannot be modified, "
                         "only added or deleted"));
        goto cleanup;
    }

    if (virNetworkDHCPRangeDefParse(def->name, ctxt->node, &range) < 0)
        goto cleanup;

    /* check if an entry with same name/address/ip already exists */
    for (ii = 0; ii < ipdef->nranges; ii++) {
        if (virSocketAddrEqual(&range.start, &ipdef->ranges[ii].start) &&
            virSocketAddrEqual(&range.end, &ipdef->ranges[ii].end)) {
            break;
        }
    }

    if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        if (ii < ipdef->nranges) {
            char *startip = virSocketAddrFormat(&range.start);
            char *endip = virSocketAddrFormat(&range.end);

            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("there is an existing dhcp range entry in "
                             "network '%s' that matches "
                             "\"<range start='%s' end='%s'/>\""),
                           def->name,
                           startip ? startip : "unknown",
                           endip ? endip : "unknown");
            goto cleanup;
        }

        /* add to beginning/end of list */
        if (VIR_REALLOC_N(ipdef->ranges, ipdef->nranges +1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST) {
            ipdef->ranges[ipdef->nranges] = range;
        } else { /* implied (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) */
            memmove(ipdef->ranges + 1, ipdef->ranges,
                    sizeof(*ipdef->ranges) * ipdef->nranges);
            ipdef->ranges[0] = range;
        }
        ipdef->nranges++;
        memset(&range, 0, sizeof(range));

    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        if (ii == ipdef->nranges) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("couldn't locate a matching dhcp range entry "
                             "in network '%s'"), def->name);
            goto cleanup;
        }

        /* remove it */
        /* NB: nothing to clear from a RangeDef that's being freed */
        memmove(ipdef->ranges + ii, ipdef->ranges + ii + 1,
                sizeof(*ipdef->ranges) * (ipdef->nranges - ii - 1));
        ipdef->nranges--;
        ignore_value(VIR_REALLOC_N(ipdef->ranges, ipdef->nranges));
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
                                    unsigned int command ATTRIBUTE_UNUSED,
                                    int parentIndex ATTRIBUTE_UNUSED,
                                    xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                                    /* virNetworkUpdateFlags */
                                    unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "forward interface");
    return -1;
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
    int ii, ret = -1;
    virPortGroupDef portgroup;

    memset(&portgroup, 0, sizeof(portgroup));

    if (virNetworkDefUpdateCheckElementName(def, ctxt->node, "portgroup") < 0)
        goto cleanup;

    if (virNetworkPortGroupParseXML(&portgroup, ctxt->node, ctxt) < 0)
        goto cleanup;

    /* check if a portgroup with same name already exists */
    for (ii = 0; ii < def->nPortGroups; ii++) {
        if (STREQ(portgroup.name, def->portGroups[ii].name))
            break;
    }
    if (ii == def->nPortGroups &&
        ((command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) ||
         (command == VIR_NETWORK_UPDATE_COMMAND_DELETE))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("couldn't find a portgroup entry "
                         "in network '%s' matching <portgroup name='%s'>"),
                       def->name, portgroup.name);
        goto cleanup;
    } else if (ii < def->nPortGroups &&
               ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
                (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("there is an existing portgroup entry in "
                         "network '%s' that matches "
                         "\"<portgroup name='%s'>\""),
                       def->name, portgroup.name);
        goto cleanup;
    }

    if (command == VIR_NETWORK_UPDATE_COMMAND_MODIFY) {

        /* replace existing entry */
        virPortGroupDefClear(&def->portGroups[ii]);
        def->portGroups[ii] = portgroup;
        memset(&portgroup, 0, sizeof(portgroup));

    } else if ((command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) ||
        (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST)) {

        /* add to beginning/end of list */
        if (VIR_REALLOC_N(def->portGroups, def->nPortGroups +1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (command == VIR_NETWORK_UPDATE_COMMAND_ADD_LAST) {
            def->portGroups[def->nPortGroups] = portgroup;
        } else { /* implied (command == VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST) */
            memmove(def->portGroups + 1, def->portGroups,
                    sizeof(*def->portGroups) * def->nPortGroups);
            def->portGroups[0] = portgroup;
        }
        def->nPortGroups++;
        memset(&portgroup, 0, sizeof(portgroup));

    } else if (command == VIR_NETWORK_UPDATE_COMMAND_DELETE) {

        /* remove it */
        virPortGroupDefClear(&def->portGroups[ii]);
        memmove(def->portGroups + ii, def->portGroups + ii + 1,
                sizeof(*def->portGroups) * (def->nPortGroups - ii - 1));
        def->nPortGroups--;
        ignore_value(VIR_REALLOC_N(def->portGroups, def->nPortGroups));
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
    virNetworkDefUpdateNoSupport(def, "dns host");
    return -1;
}

static int
virNetworkDefUpdateDNSTxt(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "dns txt");
    return -1;
}

static int
virNetworkDefUpdateDNSSrv(virNetworkDefPtr def,
                          unsigned int command ATTRIBUTE_UNUSED,
                          int parentIndex ATTRIBUTE_UNUSED,
                          xmlXPathContextPtr ctxt ATTRIBUTE_UNUSED,
                          /* virNetworkUpdateFlags */
                          unsigned int fflags ATTRIBUTE_UNUSED)
{
    virNetworkDefUpdateNoSupport(def, "dns txt");
    return -1;
}

static int
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
        virReportError(VIR_ERR_NO_SUPPORT, "%s",
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

/*
 * virNetworkObjIsDuplicate:
 * @doms : virNetworkObjListPtr to search
 * @def  : virNetworkDefPtr definition of network to lookup
 * @check_active: If true, ensure that network is not active
 *
 * Returns: -1 on error
 *          0 if network is new
 *          1 if network is a duplicate
 */
int
virNetworkObjIsDuplicate(virNetworkObjListPtr doms,
                         virNetworkDefPtr def,
                         unsigned int check_active)
{
    int ret = -1;
    int dupVM = 0;
    virNetworkObjPtr vm = NULL;

    /* See if a VM with matching UUID already exists */
    vm = virNetworkFindByUUID(doms, def->uuid);
    if (vm) {
        /* UUID matches, but if names don't match, refuse it */
        if (STRNEQ(vm->def->name, def->name)) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' is already defined with uuid %s"),
                           vm->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if VM is already active, refuse it */
            if (virNetworkObjIsActive(vm)) {
                virReportError(VIR_ERR_OPERATION_INVALID,
                               _("network is already active as '%s'"),
                               vm->def->name);
                goto cleanup;
            }
        }

        dupVM = 1;
    } else {
        /* UUID does not match, but if a name matches, refuse it */
        vm = virNetworkFindByName(doms, def->name);
        if (vm) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];
            virUUIDFormat(vm->def->uuid, uuidstr);
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("network '%s' already exists with uuid %s"),
                           def->name, uuidstr);
            goto cleanup;
        }
    }

    ret = dupVM;
cleanup:
    if (vm)
        virNetworkObjUnlock(vm);
    return ret;
}


void virNetworkObjLock(virNetworkObjPtr obj)
{
    virMutexLock(&obj->lock);
}

void virNetworkObjUnlock(virNetworkObjPtr obj)
{
    virMutexUnlock(&obj->lock);
}

#define MATCH(FLAG) (flags & (FLAG))
static bool
virNetworkMatch (virNetworkObjPtr netobj,
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

int
virNetworkList(virConnectPtr conn,
               virNetworkObjList netobjs,
               virNetworkPtr **nets,
               unsigned int flags)
{
    virNetworkPtr *tmp_nets = NULL;
    virNetworkPtr net = NULL;
    int nnets = 0;
    int ret = -1;
    int i;

    if (nets) {
        if (VIR_ALLOC_N(tmp_nets, netobjs.count + 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }
    }

    for (i = 0; i < netobjs.count; i++) {
        virNetworkObjPtr netobj = netobjs.objs[i];
        virNetworkObjLock(netobj);
        if (virNetworkMatch(netobj, flags)) {
            if (nets) {
                if (!(net = virGetNetwork(conn,
                                          netobj->def->name,
                                          netobj->def->uuid))) {
                    virNetworkObjUnlock(netobj);
                    goto cleanup;
                }
                tmp_nets[nnets] = net;
            }
            nnets++;
        }
        virNetworkObjUnlock(netobj);
    }

    if (tmp_nets) {
        /* trim the array to the final size */
        ignore_value(VIR_REALLOC_N(tmp_nets, nnets + 1));
        *nets = tmp_nets;
        tmp_nets = NULL;
    }

    ret = nnets;

cleanup:
    if (tmp_nets) {
        for (i = 0; i < nnets; i++) {
            if (tmp_nets[i])
                virNetworkFree(tmp_nets[i]);
        }
    }

    VIR_FREE(tmp_nets);
    return ret;
}
