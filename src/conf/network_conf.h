/*
 * network_conf.h: network XML handling
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
 */

#pragma once

#define DNS_RECORD_LENGTH_SRV  (512 - 30)  /* Limit minus overhead as mentioned in RFC-2782 */

#include "internal.h"
#include "virsocketaddr.h"
#include "virnetdevbandwidth.h"
#include "virnetdevvportprofile.h"
#include "virnetdevvlan.h"
#include "virmacaddr.h"
#include "device_conf.h"
#include "networkcommon_conf.h"
#include "virobject.h"
#include "virmacmap.h"
#include "virenum.h"
#include "virxml.h"

struct _virNetworkXMLOption {
    virObject parent;

    virXMLNamespace ns;
};
typedef struct _virNetworkXMLOption virNetworkXMLOption;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetworkXMLOption, virObjectUnref);


typedef enum {
    VIR_NETWORK_FORWARD_NONE   = 0,
    VIR_NETWORK_FORWARD_NAT,
    VIR_NETWORK_FORWARD_ROUTE,
    VIR_NETWORK_FORWARD_OPEN,
    VIR_NETWORK_FORWARD_BRIDGE,
    VIR_NETWORK_FORWARD_PRIVATE,
    VIR_NETWORK_FORWARD_VEPA,
    VIR_NETWORK_FORWARD_PASSTHROUGH,
    VIR_NETWORK_FORWARD_HOSTDEV,

    VIR_NETWORK_FORWARD_LAST,
} virNetworkForwardType;

typedef enum {
   VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_DEFAULT = 0,
   VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_KERNEL,
   VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LIBVIRT,

   VIR_NETWORK_BRIDGE_MAC_TABLE_MANAGER_LAST,
} virNetworkBridgeMACTableManagerType;

VIR_ENUM_DECL(virNetworkBridgeMACTableManager);

typedef enum {
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NONE = 0,
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI,
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV,
    /* USB Device to be added here when supported */

    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST,
} virNetworkForwardHostdevDeviceType;

typedef enum {
    VIR_NETWORK_DHCP_LEASETIME_UNIT_SECONDS = 0,
    VIR_NETWORK_DHCP_LEASETIME_UNIT_MINUTES,
    VIR_NETWORK_DHCP_LEASETIME_UNIT_HOURS,

    VIR_NETWORK_DHCP_LEASETIME_UNIT_LAST,
} virNetworkDHCPLeaseTimeUnitType;

VIR_ENUM_DECL(virNetworkDHCPLeaseTimeUnit);

/* The backend driver used for devices from the pool. Currently used
 * only for PCI devices (vfio vs. kvm), but could be used for other
 * device types in the future.
 */
typedef enum {
    VIR_NETWORK_FORWARD_DRIVER_NAME_DEFAULT, /* kvm now, could change */
    VIR_NETWORK_FORWARD_DRIVER_NAME_KVM,    /* force legacy kvm style */
    VIR_NETWORK_FORWARD_DRIVER_NAME_VFIO,   /* force vfio */

    VIR_NETWORK_FORWARD_DRIVER_NAME_LAST
} virNetworkForwardDriverNameType;

VIR_ENUM_DECL(virNetworkForwardDriverName);

typedef struct _virNetworkDHCPLeaseTimeDef virNetworkDHCPLeaseTimeDef;
struct _virNetworkDHCPLeaseTimeDef {
    unsigned long long expiry;
    virNetworkDHCPLeaseTimeUnitType unit;
};

typedef struct _virNetworkDHCPRangeDef virNetworkDHCPRangeDef;
struct _virNetworkDHCPRangeDef {
    virSocketAddrRange addr;
    virNetworkDHCPLeaseTimeDef *lease;
};

typedef struct _virNetworkDHCPHostDef virNetworkDHCPHostDef;
struct _virNetworkDHCPHostDef {
    char *mac;
    char *id;
    char *name;
    virSocketAddr ip;
    virNetworkDHCPLeaseTimeDef *lease;
};

typedef struct _virNetworkDNSTxtDef virNetworkDNSTxtDef;
struct _virNetworkDNSTxtDef {
    char *name;
    char *value;
};

typedef struct _virNetworkDNSSrvDef virNetworkDNSSrvDef;
struct _virNetworkDNSSrvDef {
    char *domain;
    char *service;
    char *protocol;
    char *target;
    unsigned int port;
    unsigned int priority;
    unsigned int weight;
};

typedef struct _virNetworkDNSHostDef virNetworkDNSHostDef;
struct _virNetworkDNSHostDef {
    virSocketAddr ip;
    size_t nnames;
    char **names;
};


typedef struct _virNetworkDNSForwarder virNetworkDNSForwarder;
struct _virNetworkDNSForwarder {
    virSocketAddr addr;
    char *domain;
};

typedef struct _virNetworkDNSDef virNetworkDNSDef;
struct _virNetworkDNSDef {
    virTristateBool enable;
    virTristateBool forwardPlainNames;
    size_t ntxts;
    virNetworkDNSTxtDef *txts;
    size_t nhosts;
    virNetworkDNSHostDef *hosts;
    size_t nsrvs;
    virNetworkDNSSrvDef *srvs;
    size_t nfwds;
    virNetworkDNSForwarder *forwarders;
};

typedef struct _virNetworkIPDef virNetworkIPDef;
struct _virNetworkIPDef {
    char *family;               /* ipv4 or ipv6 - default is ipv4 */
    virSocketAddr address;      /* Bridge IP address */

    /* One or the other of the following two will be used for a given
     * IP address, but never both. The parser guarantees this.
     * Use virNetworkIPDefPrefix/virNetworkIPDefNetmask rather
     * than accessing the data directly - these utility functions
     * will convert one into the other as necessary.
     */
    unsigned int prefix;        /* ipv6 - only prefix allowed */
    virSocketAddr netmask;      /* ipv4 - either netmask or prefix specified */

    virTristateBool localPTR;

    size_t nranges;             /* Zero or more dhcp ranges */
    virNetworkDHCPRangeDef *ranges;

    size_t nhosts;              /* Zero or more dhcp hosts */
    virNetworkDHCPHostDef *hosts;

    char *tftproot;
    char *bootfile;
    virSocketAddr bootserver;
   };

typedef struct _virNetworkForwardIfDef virNetworkForwardIfDef;
struct _virNetworkForwardIfDef {
    int type;
    union {
        virPCIDeviceAddress pci; /*PCI Address of device */
        /* when USB devices are supported a new variable to be added here */
        char *dev;      /* name of device */
    }device;
    int connections; /* how many guest interfaces are connected to this device? */
};

typedef struct _virNetworkForwardPfDef virNetworkForwardPfDef;
struct _virNetworkForwardPfDef {
    char *dev;      /* name of device */
    int connections; /* how many guest interfaces are connected to this device? */
};

typedef struct _virNetworkForwardDef virNetworkForwardDef;
struct _virNetworkForwardDef {
    int type;     /* One of virNetworkForwardType constants */
    bool managed;  /* managed attribute for hostdev mode */
    int driverName; /* enum virNetworkForwardDriverNameType */

    /* If there are multiple forward devices (i.e. a pool of
     * interfaces), they will be listed here.
     */
    size_t npfs;
    virNetworkForwardPfDef *pfs;

    size_t nifs;
    virNetworkForwardIfDef *ifs;

    /* ranges for NAT */
    virSocketAddrRange addr;
    virPortRange port;

    virTristateBool natIPv6;
};

typedef struct _virPortGroupDef virPortGroupDef;
struct _virPortGroupDef {
    char *name;
    bool isDefault;
    virNetDevVPortProfile *virtPortProfile;
    virNetDevBandwidth *bandwidth;
    virNetDevVlan vlan;
    virTristateBool trustGuestRxFilters;
};

typedef struct _virNetworkDef virNetworkDef;
struct _virNetworkDef {
    unsigned char uuid[VIR_UUID_BUFLEN];
    bool uuid_specified;
    char *name;
    char *title;
    char *description;
    int   connections; /* # of guest interfaces connected to this network */

    char *bridge;       /* Name of bridge device */
    char *bridgeZone;  /* name of firewalld zone for bridge */
    int  macTableManager; /* enum virNetworkBridgeMACTableManager */
    char *domain;
    virTristateBool domainLocalOnly; /* yes disables dns forwarding */
    unsigned long delay;   /* Bridge forward delay (ms) */
    bool stp; /* Spanning tree protocol */
    unsigned int mtu; /* MTU for bridge, 0 means "default" i.e. unset in config */
    virMacAddr mac; /* mac address of bridge device */
    bool mac_specified;

    /* specified if ip6tables rules added
     * when no ipv6 gateway addresses specified.
     */
    bool ipv6nogw;

    virNetworkForwardDef forward;

    size_t nips;
    virNetworkIPDef *ips; /* ptr to array of IP addresses on this network */

    size_t nroutes;
    virNetDevIPRoute **routes; /* ptr to array of static routes on this interface */

    virNetworkDNSDef dns;   /* dns related configuration */
    virNetDevVPortProfile *virtPortProfile;

    size_t nPortGroups;
    virPortGroupDef *portGroups;
    virNetDevBandwidth *bandwidth;
    virNetDevVlan vlan;
    virTristateBool trustGuestRxFilters;
    virTristateBool isolatedPort;

    /* Application-specific custom metadata */
    xmlNodePtr metadata;

    /* Network specific XML namespace data */
    void *namespaceData;
    virXMLNamespace ns;
};

typedef enum {
    VIR_NETWORK_TAINT_HOOK,                 /* Hook script was executed over
                                               network. We can't guarantee
                                               connectivity or other settings
                                               as the script may have played
                                               with iptables, tc, you name it.
                                             */

    VIR_NETWORK_TAINT_LAST
} virNetworkTaintFlags;

void virNetworkDefFree(virNetworkDef *def);
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetworkDef, virNetworkDefFree);

enum {
    VIR_NETWORK_OBJ_LIST_ADD_LIVE = (1 << 0),
    VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE = (1 << 1),
};

virNetworkXMLOption *
virNetworkXMLOptionNew(virXMLNamespace *xmlns);

virNetworkDef *
virNetworkDefCopy(virNetworkDef *def,
                  virNetworkXMLOption *xmlopt,
                  unsigned int flags);

virNetworkDef *
virNetworkDefParseXML(xmlXPathContextPtr ctxt,
                      virNetworkXMLOption *xmlopt);

virNetworkDef *
virNetworkDefParse(const char *xmlStr,
                   const char *filename,
                   virNetworkXMLOption *xmlopt,
                   bool validate);

char *
virNetworkDefFormat(const virNetworkDef *def,
                    virNetworkXMLOption *xmlopt,
                    unsigned int flags);

int
virNetworkDefFormatBuf(virBuffer *buf,
                       const virNetworkDef *def,
                       virNetworkXMLOption *xmlopt,
                       unsigned int flags);

const char *
virNetworkDefForwardIf(const virNetworkDef *def,
                       size_t n);

virPortGroupDef *
virPortGroupFindByName(virNetworkDef *net,
                       const char *portgroup);

virNetworkIPDef *
virNetworkDefGetIPByIndex(const virNetworkDef *def,
                          int family,
                          size_t n);

virNetDevIPRoute *
virNetworkDefGetRouteByIndex(const virNetworkDef *def,
                             int family,
                             size_t n);

int
virNetworkIPDefPrefix(const virNetworkIPDef *def);

int
virNetworkIPDefNetmask(const virNetworkIPDef *def,
                       virSocketAddr *netmask);

int
virNetworkSaveXML(const char *configDir,
                  virNetworkDef *def,
                  const char *xml);

int
virNetworkSaveConfig(const char *configDir,
                     virNetworkDef *def,
                     virNetworkXMLOption *xmlopt);

char *
virNetworkConfigFile(const char *dir,
                     const char *name);

void
virNetworkSetBridgeMacAddr(virNetworkDef *def);

int
virNetworkPortOptionsParseXML(xmlXPathContextPtr ctxt,
                              virTristateBool *isolatedPort);

void
virNetworkPortOptionsFormat(virTristateBool isolatedPort,
                            virBuffer *buf);

VIR_ENUM_DECL(virNetworkForward);

#define VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE \
                (VIR_CONNECT_LIST_NETWORKS_ACTIVE | \
                 VIR_CONNECT_LIST_NETWORKS_INACTIVE)

#define VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT \
                (VIR_CONNECT_LIST_NETWORKS_PERSISTENT | \
                 VIR_CONNECT_LIST_NETWORKS_TRANSIENT)

#define VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART \
                (VIR_CONNECT_LIST_NETWORKS_AUTOSTART | \
                 VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART)

#define VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL \
                (VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE     | \
                 VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT | \
                 VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART)

/* for testing */
int
virNetworkDefUpdateSection(virNetworkDef *def,
                           unsigned int command, /* virNetworkUpdateCommand */
                           unsigned int section, /* virNetworkUpdateSection */
                           int parentIndex,
                           const char *xml,
                           unsigned int flags);  /* virNetworkUpdateFlags */

VIR_ENUM_DECL(virNetworkTaint);
