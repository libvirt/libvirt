/*
 * network_conf.h: network XML handling
 *
 * Copyright (C) 2006-2008, 2012 Red Hat, Inc.
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

#ifndef __NETWORK_CONF_H__
# define __NETWORK_CONF_H__

# define DNS_RECORD_LENGTH_SRV  (512 - 30)  /* Limit minus overhead as mentioned in RFC-2782 */

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "threads.h"
# include "virsocketaddr.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvportprofile.h"
# include "virmacaddr.h"

enum virNetworkForwardType {
    VIR_NETWORK_FORWARD_NONE   = 0,
    VIR_NETWORK_FORWARD_NAT,
    VIR_NETWORK_FORWARD_ROUTE,
    VIR_NETWORK_FORWARD_BRIDGE,
    VIR_NETWORK_FORWARD_PRIVATE,
    VIR_NETWORK_FORWARD_VEPA,
    VIR_NETWORK_FORWARD_PASSTHROUGH,

    VIR_NETWORK_FORWARD_LAST,
};

typedef struct _virNetworkDHCPRangeDef virNetworkDHCPRangeDef;
typedef virNetworkDHCPRangeDef *virNetworkDHCPRangeDefPtr;
struct _virNetworkDHCPRangeDef {
    virSocketAddr start;
    virSocketAddr end;
};

typedef struct _virNetworkDHCPHostDef virNetworkDHCPHostDef;
typedef virNetworkDHCPHostDef *virNetworkDHCPHostDefPtr;
struct _virNetworkDHCPHostDef {
    char *mac;
    char *name;
    virSocketAddr ip;
};

typedef struct _virNetworkDNSTxtRecordsDef virNetworkDNSTxtRecordsDef;
typedef virNetworkDNSTxtRecordsDef *virNetworkDNSTxtRecordsDefPtr;
struct _virNetworkDNSTxtRecordsDef {
    char *name;
    char *value;
};

typedef struct _virNetworkDNSSrvRecordsDef virNetworkDNSSrvRecordsDef;
typedef virNetworkDNSSrvRecordsDef *virNetworkDNSSrvRecordsDefPtr;
struct _virNetworkDNSSrvRecordsDef {
    char *domain;
    char *service;
    char *protocol;
    char *target;
    int port;
    int priority;
    int weight;
};

struct _virNetworkDNSHostsDef {
    virSocketAddr ip;
    int nnames;
    char **names;
};

typedef struct _virNetworkDNSHostsDef *virNetworkDNSHostsDefPtr;

struct _virNetworkDNSDef {
    unsigned int ntxtrecords;
    virNetworkDNSTxtRecordsDefPtr txtrecords;
    unsigned int nhosts;
    virNetworkDNSHostsDefPtr hosts;
    unsigned int nsrvrecords;
    virNetworkDNSSrvRecordsDefPtr srvrecords;
};

typedef struct _virNetworkDNSDef *virNetworkDNSDefPtr;

typedef struct _virNetworkIpDef virNetworkIpDef;
typedef virNetworkIpDef *virNetworkIpDefPtr;
struct _virNetworkIpDef {
    char *family;               /* ipv4 or ipv6 - default is ipv4 */
    virSocketAddr address;      /* Bridge IP address */

    /* One or the other of the following two will be used for a given
     * IP address, but never both. The parser guarantees this.
     * Use virNetworkIpDefPrefix/virNetworkIpDefNetmask rather
     * than accessing the data directly - these utility functions
     * will convert one into the other as necessary.
     */
    unsigned int prefix;        /* ipv6 - only prefix allowed */
    virSocketAddr netmask;      /* ipv4 - either netmask or prefix specified */

    unsigned int nranges;        /* Zero or more dhcp ranges */
    virNetworkDHCPRangeDefPtr ranges;

    unsigned int nhosts;         /* Zero or more dhcp hosts */
    virNetworkDHCPHostDefPtr hosts;

    char *tftproot;
    char *bootfile;
    virSocketAddr bootserver;
   };

typedef struct _virNetworkForwardIfDef virNetworkForwardIfDef;
typedef virNetworkForwardIfDef *virNetworkForwardIfDefPtr;
struct _virNetworkForwardIfDef {
    char *dev;      /* name of device */
    int usageCount; /* how many guest interfaces are bound to this device? */
};

typedef struct _virPortGroupDef virPortGroupDef;
typedef virPortGroupDef *virPortGroupDefPtr;
struct _virPortGroupDef {
    char *name;
    bool isDefault;
    virNetDevVPortProfilePtr virtPortProfile;
    virNetDevBandwidthPtr bandwidth;
};

typedef struct _virNetworkDef virNetworkDef;
typedef virNetworkDef *virNetworkDefPtr;
struct _virNetworkDef {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *name;

    char *bridge;       /* Name of bridge device */
    char *domain;
    unsigned long delay;   /* Bridge forward delay (ms) */
    unsigned int stp :1; /* Spanning tree protocol */
    unsigned char mac[VIR_MAC_BUFLEN]; /* mac address of bridge device */
    bool mac_specified;

    int forwardType;    /* One of virNetworkForwardType constants */

    /* If there are multiple forward devices (i.e. a pool of
     * interfaces), they will be listed here.
     */
    size_t nForwardPfs;
    virNetworkForwardIfDefPtr forwardPfs;

    size_t nForwardIfs;
    virNetworkForwardIfDefPtr forwardIfs;

    size_t nips;
    virNetworkIpDefPtr ips; /* ptr to array of IP addresses on this network */

    virNetworkDNSDefPtr dns; /* ptr to dns related configuration */
    virNetDevVPortProfilePtr virtPortProfile;

    size_t nPortGroups;
    virPortGroupDefPtr portGroups;
    virNetDevBandwidthPtr bandwidth;
};

typedef struct _virNetworkObj virNetworkObj;
typedef virNetworkObj *virNetworkObjPtr;
struct _virNetworkObj {
    virMutex lock;

    pid_t dnsmasqPid;
    pid_t radvdPid;
    unsigned int active : 1;
    unsigned int autostart : 1;
    unsigned int persistent : 1;

    virNetworkDefPtr def; /* The current definition */
    virNetworkDefPtr newDef; /* New definition to activate at shutdown */
};

typedef struct _virNetworkObjList virNetworkObjList;
typedef virNetworkObjList *virNetworkObjListPtr;
struct _virNetworkObjList {
    unsigned int count;
    virNetworkObjPtr *objs;
};

static inline int
virNetworkObjIsActive(const virNetworkObjPtr net)
{
    return net->active;
}

virNetworkObjPtr virNetworkFindByUUID(const virNetworkObjListPtr nets,
                                      const unsigned char *uuid);
virNetworkObjPtr virNetworkFindByName(const virNetworkObjListPtr nets,
                                      const char *name);


void virNetworkDefFree(virNetworkDefPtr def);
void virNetworkObjFree(virNetworkObjPtr net);
void virNetworkObjListFree(virNetworkObjListPtr vms);

virNetworkObjPtr virNetworkAssignDef(virNetworkObjListPtr nets,
                                     const virNetworkDefPtr def);
void virNetworkRemoveInactive(virNetworkObjListPtr nets,
                              const virNetworkObjPtr net);

virNetworkDefPtr virNetworkDefParseString(const char *xmlStr);
virNetworkDefPtr virNetworkDefParseFile(const char *filename);
virNetworkDefPtr virNetworkDefParseNode(xmlDocPtr xml,
                                        xmlNodePtr root);

char *virNetworkDefFormat(const virNetworkDefPtr def, unsigned int flags);

static inline const char *
virNetworkDefForwardIf(const virNetworkDefPtr def, size_t n)
{
    return ((def->forwardIfs && (def->nForwardIfs > n))
            ? def->forwardIfs[n].dev : NULL);
}

virPortGroupDefPtr virPortGroupFindByName(virNetworkDefPtr net,
                                          const char *portgroup);

virNetworkIpDefPtr
virNetworkDefGetIpByIndex(const virNetworkDefPtr def,
                          int family, size_t n);
int virNetworkIpDefPrefix(const virNetworkIpDefPtr def);
int virNetworkIpDefNetmask(const virNetworkIpDefPtr def,
                           virSocketAddrPtr netmask);

int virNetworkSaveXML(const char *configDir,
                      virNetworkDefPtr def,
                      const char *xml);

int virNetworkSaveConfig(const char *configDir,
                         virNetworkDefPtr def);

virNetworkObjPtr virNetworkLoadConfig(virNetworkObjListPtr nets,
                                      const char *configDir,
                                      const char *autostartDir,
                                      const char *file);

int virNetworkLoadAllConfigs(virNetworkObjListPtr nets,
                             const char *configDir,
                             const char *autostartDir);

int virNetworkDeleteConfig(const char *configDir,
                           const char *autostartDir,
                           virNetworkObjPtr net);

char *virNetworkConfigFile(const char *dir,
                           const char *name);

int virNetworkBridgeInUse(const virNetworkObjListPtr nets,
                          const char *bridge,
                          const char *skipname);

char *virNetworkAllocateBridge(const virNetworkObjListPtr nets,
                               const char *template);

int virNetworkSetBridgeName(const virNetworkObjListPtr nets,
                            virNetworkDefPtr def,
                            int check_collision);

void virNetworkSetBridgeMacAddr(virNetworkDefPtr def);

int virNetworkObjIsDuplicate(virNetworkObjListPtr doms,
                             virNetworkDefPtr def,
                             unsigned int check_active);

void virNetworkObjLock(virNetworkObjPtr obj);
void virNetworkObjUnlock(virNetworkObjPtr obj);

#endif /* __NETWORK_CONF_H__ */
