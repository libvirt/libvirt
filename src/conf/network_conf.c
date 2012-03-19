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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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
#include "memory.h"
#include "xml.h"
#include "uuid.h"
#include "util.h"
#include "buf.h"
#include "c-ctype.h"
#include "virfile.h"

#define MAX_BRIDGE_ID 256
#define VIR_FROM_THIS VIR_FROM_NETWORK

VIR_ENUM_DECL(virNetworkForward)

VIR_ENUM_IMPL(virNetworkForward,
              VIR_NETWORK_FORWARD_LAST,
              "none", "nat", "route", "bridge", "private", "vepa", "passthrough" )

#define virNetworkReportError(code, ...)                                \
    virReportErrorHelper(VIR_FROM_NETWORK, code, __FILE__,              \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

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
    def->bandwidth = NULL;
}

static void
virNetworkForwardIfDefClear(virNetworkForwardIfDefPtr def)
{
    VIR_FREE(def->dev);
}

static void virNetworkIpDefClear(virNetworkIpDefPtr def)
{
    int ii;

    VIR_FREE(def->family);
    VIR_FREE(def->ranges);

    for (ii = 0 ; ii < def->nhosts && def->hosts ; ii++) {
        VIR_FREE(def->hosts[ii].mac);
        VIR_FREE(def->hosts[ii].name);
    }

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
        virNetworkForwardIfDefClear(&def->forwardPfs[ii]);
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

virNetworkObjPtr virNetworkAssignDef(virNetworkObjListPtr nets,
                                     const virNetworkDefPtr def)
{
    virNetworkObjPtr network;

    if ((network = virNetworkFindByName(nets, def->name))) {
        if (!virNetworkObjIsActive(network)) {
            virNetworkDefFree(network->def);
            network->def = def;
        } else {
            virNetworkDefFree(network->newDef);
            network->newDef = def;
        }

        return network;
    }

    if (VIR_ALLOC(network) < 0) {
        virReportOOMError();
        return NULL;
    }
    if (virMutexInit(&network->lock) < 0) {
        virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
                              "%s", _("cannot initialize mutex"));
        VIR_FREE(network);
        return NULL;
    }
    virNetworkObjLock(network);
    network->def = def;

    if (VIR_REALLOC_N(nets->objs, nets->count + 1) < 0) {
        virReportOOMError();
        VIR_FREE(network);
        return NULL;
    }

    nets->objs[nets->count] = network;
    nets->count++;

    return network;

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
virNetworkDHCPRangeDefParseXML(const char *networkName,
                               virNetworkIpDefPtr def,
                               xmlNodePtr node)
{

    xmlNodePtr cur;

    cur = node->children;
    while (cur != NULL) {
        if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "range")) {
            char *start, *end;
            virSocketAddr saddr, eaddr;
            int range;

            if (!(start = virXMLPropString(cur, "start"))) {
                cur = cur->next;
                continue;
            }
            if (!(end = virXMLPropString(cur, "end"))) {
                VIR_FREE(start);
                cur = cur->next;
                continue;
            }

            if (virSocketAddrParse(&saddr, start, AF_UNSPEC) < 0) {
                VIR_FREE(start);
                VIR_FREE(end);
                return -1;
            }
            if (virSocketAddrParse(&eaddr, end, AF_UNSPEC) < 0) {
                VIR_FREE(start);
                VIR_FREE(end);
                return -1;
            }

            range = virSocketAddrGetRange(&saddr, &eaddr);
            if (range < 0) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("Invalid dhcp range '%s' to '%s' in network '%s'"),
                                      start, end, networkName);
                VIR_FREE(start);
                VIR_FREE(end);
                return -1;
            }
            VIR_FREE(start);
            VIR_FREE(end);

            if (VIR_REALLOC_N(def->ranges, def->nranges + 1) < 0) {
                virReportOOMError();
                return -1;
            }
            def->ranges[def->nranges].start = saddr;
            def->ranges[def->nranges].end = eaddr;
            def->nranges++;
        } else if (cur->type == XML_ELEMENT_NODE &&
            xmlStrEqual(cur->name, BAD_CAST "host")) {
            char *mac = NULL, *name = NULL, *ip;
            unsigned char addr[6];
            virSocketAddr inaddr;

            mac = virXMLPropString(cur, "mac");
            if (mac != NULL) {
                if (virMacAddrParse(mac, &addr[0]) < 0) {
                    virNetworkReportError(VIR_ERR_XML_ERROR,
                                          _("Cannot parse MAC address '%s' in network '%s'"),
                                          mac, networkName);
                    VIR_FREE(mac);
                    return -1;
                }
                if (virMacAddrIsMulticast(addr)) {
                    virNetworkReportError(VIR_ERR_XML_ERROR,
                                         _("expected unicast mac address, found multicast '%s' in network '%s'"),
                                         (const char *)mac, networkName);
                    VIR_FREE(mac);
                    return -1;
                }
            }
            name = virXMLPropString(cur, "name");
            if ((name != NULL) && (!c_isalpha(name[0]))) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("Cannot use name address '%s' in network '%s'"),
                                      name, networkName);
                VIR_FREE(mac);
                VIR_FREE(name);
                return -1;
            }
            /*
             * You need at least one MAC address or one host name
             */
            if ((mac == NULL) && (name == NULL)) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("Static host definition in network '%s' must have mac or name attribute"),
                                      networkName);
                return -1;
            }
            ip = virXMLPropString(cur, "ip");
            if ((ip == NULL) ||
                (virSocketAddrParse(&inaddr, ip, AF_UNSPEC) < 0)) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("Missing IP address in static host definition for network '%s'"),
                                      networkName);
                VIR_FREE(ip);
                VIR_FREE(mac);
                VIR_FREE(name);
                return -1;
            }
            VIR_FREE(ip);
            if (VIR_REALLOC_N(def->hosts, def->nhosts + 1) < 0) {
                VIR_FREE(mac);
                VIR_FREE(name);
                virReportOOMError();
                return -1;
            }
            def->hosts[def->nhosts].mac = mac;
            def->hosts[def->nhosts].name = name;
            def->hosts[def->nhosts].ip = inaddr;
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
        virNetworkReportError(VIR_ERR_XML_DETAIL,
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
    char *domain;
    char *service;
    char *protocol;
    char *target;
    int port;
    int priority;
    int weight;
    int ret = 0;

    if (!(service = virXMLPropString(cur, "service"))) {
        virNetworkReportError(VIR_ERR_XML_DETAIL,
                              "%s", _("Missing required service attribute in dns srv record"));
        goto error;
    }

    if (strlen(service) > DNS_RECORD_LENGTH_SRV) {
        char *name = NULL;

        virAsprintf(&name, _("Service name is too long, limit is %d bytes"), DNS_RECORD_LENGTH_SRV);
        virNetworkReportError(VIR_ERR_XML_DETAIL,
                              "%s", name);
        VIR_FREE(name);
        goto error;
    }

    if (!(protocol = virXMLPropString(cur, "protocol"))) {
        virNetworkReportError(VIR_ERR_XML_DETAIL,
                              _("Missing required protocol attribute in dns srv record '%s'"), service);
        goto error;
    }

    /* Check whether protocol value is the supported one */
    if (STRNEQ(protocol, "tcp") && (STRNEQ(protocol, "udp"))) {
        virNetworkReportError(VIR_ERR_XML_DETAIL,
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
                virNetworkReportError(VIR_ERR_XML_DETAIL,
                                      "%s", _("Missing required name attribute in dns txt record"));
                goto error;
            }
            if (!(value = virXMLPropString(cur, "value"))) {
                virNetworkReportError(VIR_ERR_XML_DETAIL,
                                      _("Missing required value attribute in dns txt record '%s'"), name);
                goto error;
            }

            if (strchr(name, ' ') != NULL) {
                virNetworkReportError(VIR_ERR_XML_DETAIL,
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
            virNetworkReportError(VIR_ERR_XML_ERROR,
                                  _("Bad address '%s' in definition of network '%s'"),
                                  address, networkName);
            goto error;
        }

    }

    /* validate family vs. address */
    if (def->family == NULL) {
        if (!(VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET) ||
              VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_UNSPEC))) {
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("no family specified for non-IPv4 address '%s' in network '%s'"),
                                  address, networkName);
            goto error;
        }
    } else if (STREQ(def->family, "ipv4")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("family 'ipv4' specified for non-IPv4 address '%s' in network '%s'"),
                                  address, networkName);
            goto error;
        }
    } else if (STREQ(def->family, "ipv6")) {
        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET6)) {
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("family 'ipv6' specified for non-IPv6 address '%s' in network '%s'"),
                                  address, networkName);
            goto error;
        }
    } else {
        virNetworkReportError(VIR_ERR_XML_ERROR,
                              _("Unrecognized family '%s' in definition of network '%s'"),
                              def->family, networkName);
        goto error;
    }

    /* parse/validate netmask */
    if (netmask) {
        if (address == NULL) {
            /* netmask is meaningless without an address */
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("netmask specified without address in network '%s'"),
                                  networkName);
            goto error;
        }

        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->address, AF_INET)) {
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("netmask not supported for address '%s' in network '%s' (IPv4 only)"),
                                  address, networkName);
            goto error;
        }

        if (def->prefix > 0) {
            /* can't have both netmask and prefix at the same time */
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                  _("network '%s' cannot have both prefix='%u' and a netmask"),
                                  networkName, def->prefix);
            goto error;
        }

        if (virSocketAddrParse(&def->netmask, netmask, AF_UNSPEC) < 0)
            goto error;

        if (!VIR_SOCKET_ADDR_IS_FAMILY(&def->netmask, AF_INET)) {
            virNetworkReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
                result = virNetworkDHCPRangeDefParseXML(networkName, def, cur);
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
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode))))
        goto error;

    bandwidth_node = virXPathNode("./bandwidth", ctxt);
    if (bandwidth_node &&
        !(def->bandwidth = virNetDevBandwidthParse(bandwidth_node))) {
        goto error;
    }

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
    xmlNodePtr dnsNode = NULL;
    xmlNodePtr virtPortNode = NULL;
    xmlNodePtr forwardNode = NULL;
    int nIps, nPortGroups, nForwardIfs, nForwardPfs;
    char *forwardDev = NULL;
    xmlNodePtr save = ctxt->node;
    xmlNodePtr bandwidthNode = NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        return NULL;
    }

    /* Extract network name */
    def->name = virXPathString("string(./name[1])", ctxt);
    if (!def->name) {
        virNetworkReportError(VIR_ERR_NO_NAME, NULL);
        goto error;
    }

    /* Extract network uuid */
    tmp = virXPathString("string(./uuid[1])", ctxt);
    if (!tmp) {
        if (virUUIDGenerate(def->uuid)) {
            virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("Failed to generate UUID"));
            goto error;
        }
    } else {
        if (virUUIDParse(tmp, def->uuid) < 0) {
            VIR_FREE(tmp);
            virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
                                  "%s", _("malformed uuid element"));
            goto error;
        }
        VIR_FREE(tmp);
    }

    /* Parse network domain information */
    def->domain = virXPathString("string(./domain[1]/@name)", ctxt);

    if ((bandwidthNode = virXPathNode("./bandwidth", ctxt)) != NULL &&
        (def->bandwidth = virNetDevBandwidthParse(bandwidthNode)) == NULL)
        goto error;

    /* Parse bridge information */
    def->bridge = virXPathString("string(./bridge[1]/@name)", ctxt);
    stp = virXPathString("string(./bridge[1]/@stp)", ctxt);

    if (virXPathULong("string(./bridge[1]/@delay)", ctxt, &def->delay) < 0)
        def->delay = 0;

    tmp = virXPathString("string(./mac[1]/@address)", ctxt);
    if (tmp) {
        if (virMacAddrParse(tmp, def->mac) < 0) {
            virNetworkReportError(VIR_ERR_XML_ERROR,
                                  _("Invalid bridge mac address '%s' in network '%s'"),
                                  tmp, def->name);
            VIR_FREE(tmp);
            goto error;
        }
        if (virMacAddrIsMulticast(def->mac)) {
            virNetworkReportError(VIR_ERR_XML_ERROR,
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
        (!(def->virtPortProfile = virNetDevVPortProfileParse(virtPortNode))))
        goto error;

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
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("unknown forwarding type '%s'"), tmp);
                VIR_FREE(tmp);
                goto error;
            }
            VIR_FREE(tmp);
        } else {
            def->forwardType = VIR_NETWORK_FORWARD_NAT;
        }

        forwardDev = virXPathString("string(./@dev)", ctxt);

        /* all of these modes can use a pool of physical interfaces */
        nForwardIfs = virXPathNodeSet("./interface", ctxt, &forwardIfNodes);
        nForwardPfs = virXPathNodeSet("./pf", ctxt, &forwardPfNodes);

        if (nForwardIfs < 0 || nForwardPfs < 0) {
            virNetworkReportError(VIR_ERR_XML_ERROR,
                                  _("No interface pool or SRIOV physical device given"));
            goto error;
        }

        if (nForwardPfs == 1) {
            if (VIR_ALLOC_N(def->forwardPfs, nForwardPfs) < 0) {
                virReportOOMError();
                goto error;
            }

            if (forwardDev) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("A forward Dev should not be used when using a SRIOV PF"));
                goto error;
            }

            forwardDev = virXMLPropString(*forwardPfNodes, "dev");
            if (!forwardDev) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("Missing required dev attribute in network '%s' pf element"),
                                      def->name);
                goto error;
            }

            def->forwardPfs->usageCount = 0;
            def->forwardPfs->dev = forwardDev;
            forwardDev = NULL;
            def->nForwardPfs++;
        } else if (nForwardPfs > 1) {
            virNetworkReportError(VIR_ERR_XML_ERROR,
                                  _("Use of more than one physical interface is not allowed"));
            goto error;
        }
        if (nForwardIfs > 0 || forwardDev) {
            int ii;

            /* allocate array to hold all the portgroups */
            if (VIR_ALLOC_N(def->forwardIfs, MAX(nForwardIfs, 1)) < 0) {
                virReportOOMError();
                goto error;
            }

            if (forwardDev) {
                def->forwardIfs[0].usageCount = 0;
                def->forwardIfs[0].dev = forwardDev;
                forwardDev = NULL;
                def->nForwardIfs++;
            }

            /* parse each forwardIf */
            for (ii = 0; ii < nForwardIfs; ii++) {
                forwardDev = virXMLPropString(forwardIfNodes[ii], "dev");
                if (!forwardDev) {
                    virNetworkReportError(VIR_ERR_XML_ERROR,
                                          _("Missing required dev attribute in network '%s' forward interface element"),
                                          def->name);
                    goto error;
                }

                if ((ii == 0) && (def->nForwardIfs == 1)) {
                    /* both forwardDev and an interface element are present.
                     * If they don't match, it's an error. */
                    if (STRNEQ(forwardDev, def->forwardIfs[0].dev)) {
                        virNetworkReportError(VIR_ERR_XML_ERROR,
                                              _("forward dev '%s' must match first interface element dev '%s' in network '%s'"),
                                              def->forwardIfs[0].dev,
                                              forwardDev, def->name);
                        goto error;
                    }
                    VIR_FREE(forwardDev);
                    continue;
                }

                def->forwardIfs[ii].dev = forwardDev;
                forwardDev = NULL;
                def->forwardIfs[ii].usageCount = 0;
                def->nForwardIfs++;
            }
        }
        VIR_FREE(forwardDev);
        VIR_FREE(forwardPfNodes);
        VIR_FREE(forwardIfNodes);

        switch (def->forwardType) {
        case VIR_NETWORK_FORWARD_ROUTE:
        case VIR_NETWORK_FORWARD_NAT:
            /* It's pointless to specify L3 forwarding without specifying
             * the network we're on.
             */
            if (def->nips == 0) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("%s forwarding requested, but no IP address provided for network '%s'"),
                                      virNetworkForwardTypeToString(def->forwardType),
                                      def->name);
                goto error;
            }
            if (def->nForwardIfs > 1) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("multiple forwarding interfaces specified for network '%s', only one is supported"),
                                      def->name);
                goto error;
            }
            def->stp = (stp && STREQ(stp, "off")) ? 0 : 1;
            break;
        case VIR_NETWORK_FORWARD_PRIVATE:
        case VIR_NETWORK_FORWARD_VEPA:
        case VIR_NETWORK_FORWARD_PASSTHROUGH:
            if (def->bridge) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
                                      _("bridge name not allowed in %s mode (network '%s'"),
                                      virNetworkForwardTypeToString(def->forwardType),
                                      def->name);
                goto error;
            }
            /* fall through to next case */
        case VIR_NETWORK_FORWARD_BRIDGE:
            if (def->delay || stp) {
                virNetworkReportError(VIR_ERR_XML_ERROR,
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
        virNetworkReportError(VIR_ERR_XML_ERROR,
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

    virBufferAddLit(buf, "  <dns>\n");

    for (i = 0 ; i < def->ntxtrecords ; i++) {
        virBufferAsprintf(buf, "    <txt name='%s' value='%s' />\n",
                              def->txtrecords[i].name,
                              def->txtrecords[i].value);
    }

    for (i = 0 ; i < def->nsrvrecords ; i++) {
        if (def->srvrecords[i].service && def->srvrecords[i].protocol) {
            virBufferAsprintf(buf, "    <srv service='%s' protocol='%s'",
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

            virBufferAsprintf(buf, "    <host ip='%s'>\n", ip);

            for (j = 0; j < def->hosts[ii].nnames; j++)
                virBufferAsprintf(buf, "      <hostname>%s</hostname>\n",
                                               def->hosts[ii].names[j]);

            virBufferAsprintf(buf, "    </host>\n");
            VIR_FREE(ip);
        }
    }

    virBufferAddLit(buf, "  </dns>\n");
out:
    return result;
}

static int
virNetworkIpDefFormat(virBufferPtr buf,
                      const virNetworkIpDefPtr def)
{
    int result = -1;

    virBufferAddLit(buf, "  <ip");

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

    if (def->tftproot) {
        virBufferEscapeString(buf, "    <tftp root='%s' />\n",
                              def->tftproot);
    }
    if ((def->nranges || def->nhosts)) {
        int ii;
        virBufferAddLit(buf, "    <dhcp>\n");
        for (ii = 0 ; ii < def->nranges ; ii++) {
            char *saddr = virSocketAddrFormat(&def->ranges[ii].start);
            if (!saddr)
                goto error;
            char *eaddr = virSocketAddrFormat(&def->ranges[ii].end);
            if (!eaddr) {
                VIR_FREE(saddr);
                goto error;
            }
            virBufferAsprintf(buf, "      <range start='%s' end='%s' />\n",
                              saddr, eaddr);
            VIR_FREE(saddr);
            VIR_FREE(eaddr);
        }
        for (ii = 0 ; ii < def->nhosts ; ii++) {
            virBufferAddLit(buf, "      <host ");
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
            virBufferEscapeString(buf, "      <bootp file='%s' ",
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

        virBufferAddLit(buf, "    </dhcp>\n");
    }

    virBufferAddLit(buf, "  </ip>\n");

    result = 0;
error:
    return result;
}

static int
virPortGroupDefFormat(virBufferPtr buf,
                      const virPortGroupDefPtr def)
{
    virBufferAsprintf(buf, "  <portgroup name='%s'", def->name);
    if (def->isDefault) {
        virBufferAddLit(buf, " default='yes'");
    }
    virBufferAddLit(buf, ">\n");
    virBufferAdjustIndent(buf, 4);
    if (virNetDevVPortProfileFormat(def->virtPortProfile, buf) < 0)
        return -1;
    virNetDevBandwidthFormat(def->bandwidth, buf);
    virBufferAdjustIndent(buf, -4);
    virBufferAddLit(buf, "  </portgroup>\n");
    return 0;
}

char *virNetworkDefFormat(const virNetworkDefPtr def, unsigned int flags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    unsigned char *uuid;
    char uuidstr[VIR_UUID_STRING_BUFLEN];
    int ii;

    virBufferAddLit(&buf, "<network>\n");
    virBufferEscapeString(&buf, "  <name>%s</name>\n", def->name);

    uuid = def->uuid;
    virUUIDFormat(uuid, uuidstr);
    virBufferAsprintf(&buf, "  <uuid>%s</uuid>\n", uuidstr);

    if (def->forwardType != VIR_NETWORK_FORWARD_NONE) {
        const char *dev = NULL;
        if (!def->nForwardPfs)
            dev = virNetworkDefForwardIf(def, 0);
        const char *mode = virNetworkForwardTypeToString(def->forwardType);

        if (!mode) {
            virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
                                  _("Unknown forward type %d in network '%s'"),
                                  def->forwardType, def->name);
            goto error;
        }
        virBufferAddLit(&buf, "  <forward");
        virBufferEscapeString(&buf, " dev='%s'", dev);
        virBufferAsprintf(&buf, " mode='%s'%s>\n", mode,
                          (def->nForwardIfs || def->nForwardPfs) ? "" : "/");

        /* For now, hard-coded to at most 1 forwardPfs */
        if (def->nForwardPfs)
            virBufferEscapeString(&buf, "    <pf dev='%s'/>\n",
                                  def->forwardPfs[0].dev);

        if (def->nForwardIfs &&
            (!def->nForwardPfs || !(flags & VIR_NETWORK_XML_INACTIVE))) {
            for (ii = 0; ii < def->nForwardIfs; ii++) {
                virBufferEscapeString(&buf, "    <interface dev='%s'/>\n",
                                      def->forwardIfs[ii].dev);
            }
        }
        if (def->nForwardPfs || def->nForwardIfs)
            virBufferAddLit(&buf, "  </forward>\n");
    }

    if (def->forwardType == VIR_NETWORK_FORWARD_NONE ||
         def->forwardType == VIR_NETWORK_FORWARD_NAT ||
         def->forwardType == VIR_NETWORK_FORWARD_ROUTE) {

        virBufferAddLit(&buf, "  <bridge");
        if (def->bridge)
            virBufferEscapeString(&buf, " name='%s'", def->bridge);
        virBufferAsprintf(&buf, " stp='%s' delay='%ld' />\n",
                          def->stp ? "on" : "off",
                          def->delay);
    } else if (def->forwardType == VIR_NETWORK_FORWARD_BRIDGE &&
               def->bridge) {
       virBufferEscapeString(&buf, "  <bridge name='%s' />\n", def->bridge);
    }


    if (def->mac_specified) {
        char macaddr[VIR_MAC_STRING_BUFLEN];
        virMacAddrFormat(def->mac, macaddr);
        virBufferAsprintf(&buf, "  <mac address='%s'/>\n", macaddr);
    }

    if (def->domain)
        virBufferAsprintf(&buf, "  <domain name='%s'/>\n", def->domain);

    if (virNetworkDNSDefFormat(&buf, def->dns) < 0)
        goto error;

    virBufferAdjustIndent(&buf, 2);
    if (virNetDevBandwidthFormat(def->bandwidth, &buf) < 0)
        goto error;
    virBufferAdjustIndent(&buf, -2);

    for (ii = 0; ii < def->nips; ii++) {
        if (virNetworkIpDefFormat(&buf, &def->ips[ii]) < 0)
            goto error;
    }

    virBufferAdjustIndent(&buf, 2);
    if (virNetDevVPortProfileFormat(def->virtPortProfile, &buf) < 0)
        goto error;
    virBufferAdjustIndent(&buf, -2);

    for (ii = 0; ii < def->nPortGroups; ii++)
        if (virPortGroupDefFormat(&buf, &def->portGroups[ii]) < 0)
            goto error;

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

    if (!(xml = virNetworkDefFormat(def, 0)))
        goto cleanup;

    if (virNetworkSaveXML(configDir, def, xml))
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
        virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
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

    if (!(net = virNetworkAssignDef(nets, def)))
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

    virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
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
            virNetworkReportError(VIR_ERR_INTERNAL_ERROR,
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
                           def->mac);
        def->mac_specified = true;
    }
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
            virNetworkReportError(VIR_ERR_OPERATION_FAILED,
                                  _("network '%s' is already defined with uuid %s"),
                                  vm->def->name, uuidstr);
            goto cleanup;
        }

        if (check_active) {
            /* UUID & name match, but if VM is already active, refuse it */
            if (virNetworkObjIsActive(vm)) {
                virNetworkReportError(VIR_ERR_OPERATION_INVALID,
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
            virNetworkReportError(VIR_ERR_OPERATION_FAILED,
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
