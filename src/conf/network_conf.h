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
# include "virthread.h"
# include "virsocketaddr.h"
# include "virnetdevbandwidth.h"
# include "virnetdevvportprofile.h"
# include "virnetdevvlan.h"
# include "virmacaddr.h"
# include "device_conf.h"
# include "virbitmap.h"
# include "networkcommon_conf.h"
# include "virobject.h"
# include "virmacmap.h"

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

VIR_ENUM_DECL(virNetworkBridgeMACTableManager)

typedef enum {
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NONE = 0,
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_PCI,
    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_NETDEV,
    /* USB Device to be added here when supported */

    VIR_NETWORK_FORWARD_HOSTDEV_DEVICE_LAST,
} virNetworkForwardHostdevDeviceType;

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

VIR_ENUM_DECL(virNetworkForwardDriverName)

typedef struct _virNetworkDHCPHostDef virNetworkDHCPHostDef;
typedef virNetworkDHCPHostDef *virNetworkDHCPHostDefPtr;
struct _virNetworkDHCPHostDef {
    char *mac;
    char *id;
    char *name;
    virSocketAddr ip;
};

typedef struct _virNetworkDNSTxtDef virNetworkDNSTxtDef;
typedef virNetworkDNSTxtDef *virNetworkDNSTxtDefPtr;
struct _virNetworkDNSTxtDef {
    char *name;
    char *value;
};

typedef struct _virNetworkDNSSrvDef virNetworkDNSSrvDef;
typedef virNetworkDNSSrvDef *virNetworkDNSSrvDefPtr;
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
typedef virNetworkDNSHostDef *virNetworkDNSHostDefPtr;
struct _virNetworkDNSHostDef {
    virSocketAddr ip;
    size_t nnames;
    char **names;
};


typedef struct _virNetworkDNSForwarder virNetworkDNSForwarder;
typedef virNetworkDNSForwarder *virNetworkDNSForwarderPtr;
struct _virNetworkDNSForwarder {
    virSocketAddr addr;
    char *domain;
};

typedef struct _virNetworkDNSDef virNetworkDNSDef;
typedef virNetworkDNSDef *virNetworkDNSDefPtr;
struct _virNetworkDNSDef {
    int enable;            /* enum virTristateBool */
    int forwardPlainNames; /* enum virTristateBool */
    size_t ntxts;
    virNetworkDNSTxtDefPtr txts;
    size_t nhosts;
    virNetworkDNSHostDefPtr hosts;
    size_t nsrvs;
    virNetworkDNSSrvDefPtr srvs;
    size_t nfwds;
    virNetworkDNSForwarderPtr forwarders;
};

typedef struct _virNetworkIPDef virNetworkIPDef;
typedef virNetworkIPDef *virNetworkIPDefPtr;
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

    int localPTR; /* virTristateBool */

    size_t nranges;             /* Zero or more dhcp ranges */
    virSocketAddrRangePtr ranges;

    size_t nhosts;              /* Zero or more dhcp hosts */
    virNetworkDHCPHostDefPtr hosts;

    char *tftproot;
    char *bootfile;
    virSocketAddr bootserver;
   };

typedef struct _virNetworkForwardIfDef virNetworkForwardIfDef;
typedef virNetworkForwardIfDef *virNetworkForwardIfDefPtr;
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
typedef virNetworkForwardPfDef *virNetworkForwardPfDefPtr;
struct _virNetworkForwardPfDef {
    char *dev;      /* name of device */
    int connections; /* how many guest interfaces are connected to this device? */
};

typedef struct _virNetworkForwardDef virNetworkForwardDef;
typedef virNetworkForwardDef *virNetworkForwardDefPtr;
struct _virNetworkForwardDef {
    int type;     /* One of virNetworkForwardType constants */
    bool managed;  /* managed attribute for hostdev mode */
    int driverName; /* enum virNetworkForwardDriverNameType */

    /* If there are multiple forward devices (i.e. a pool of
     * interfaces), they will be listed here.
     */
    size_t npfs;
    virNetworkForwardPfDefPtr pfs;

    size_t nifs;
    virNetworkForwardIfDefPtr ifs;

    /* ranges for NAT */
    virSocketAddrRange addr;
    virPortRange port;
};

typedef struct _virPortGroupDef virPortGroupDef;
typedef virPortGroupDef *virPortGroupDefPtr;
struct _virPortGroupDef {
    char *name;
    bool isDefault;
    virNetDevVPortProfilePtr virtPortProfile;
    virNetDevBandwidthPtr bandwidth;
    virNetDevVlan vlan;
    int trustGuestRxFilters; /* enum virTristateBool */
};

typedef struct _virNetworkDef virNetworkDef;
typedef virNetworkDef *virNetworkDefPtr;
struct _virNetworkDef {
    unsigned char uuid[VIR_UUID_BUFLEN];
    bool uuid_specified;
    char *name;
    int   connections; /* # of guest interfaces connected to this network */

    char *bridge;       /* Name of bridge device */
    int  macTableManager; /* enum virNetworkBridgeMACTableManager */
    char *domain;
    int domainLocalOnly; /* enum virTristateBool: yes disables dns forwarding */
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
    virNetworkIPDefPtr ips; /* ptr to array of IP addresses on this network */

    size_t nroutes;
    virNetDevIPRoutePtr *routes; /* ptr to array of static routes on this interface */

    virNetworkDNSDef dns;   /* dns related configuration */
    virNetDevVPortProfilePtr virtPortProfile;

    size_t nPortGroups;
    virPortGroupDefPtr portGroups;
    virNetDevBandwidthPtr bandwidth;
    virNetDevVlan vlan;
    int trustGuestRxFilters; /* enum virTristateBool */

    /* Application-specific custom metadata */
    xmlNodePtr metadata;
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

void virNetworkDefFree(virNetworkDefPtr def);

enum {
    VIR_NETWORK_OBJ_LIST_ADD_LIVE = (1 << 0),
    VIR_NETWORK_OBJ_LIST_ADD_CHECK_LIVE = (1 << 1),
};

virNetworkDefPtr virNetworkDefCopy(virNetworkDefPtr def, unsigned int flags);
virNetworkDefPtr virNetworkDefParseXML(xmlXPathContextPtr ctxt);
virNetworkDefPtr virNetworkDefParseString(const char *xmlStr);
virNetworkDefPtr virNetworkDefParseFile(const char *filename);
virNetworkDefPtr virNetworkDefParseNode(xmlDocPtr xml,
                                        xmlNodePtr root);
char *virNetworkDefFormat(const virNetworkDef *def, unsigned int flags);
int virNetworkDefFormatBuf(virBufferPtr buf,
                           const virNetworkDef *def,
                           unsigned int flags);

const char * virNetworkDefForwardIf(const virNetworkDef *def, size_t n);

virPortGroupDefPtr virPortGroupFindByName(virNetworkDefPtr net,
                                          const char *portgroup);

virNetworkIPDefPtr
virNetworkDefGetIPByIndex(const virNetworkDef *def,
                          int family, size_t n);
virNetDevIPRoutePtr
virNetworkDefGetRouteByIndex(const virNetworkDef *def,
                             int family, size_t n);
int virNetworkIPDefPrefix(const virNetworkIPDef *def);
int virNetworkIPDefNetmask(const virNetworkIPDef *def,
                           virSocketAddrPtr netmask);

int virNetworkSaveXML(const char *configDir,
                      virNetworkDefPtr def,
                      const char *xml);

int virNetworkSaveConfig(const char *configDir,
                         virNetworkDefPtr def);

char *virNetworkConfigFile(const char *dir,
                           const char *name);

void virNetworkSetBridgeMacAddr(virNetworkDefPtr def);

VIR_ENUM_DECL(virNetworkForward)

# define VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE   \
                (VIR_CONNECT_LIST_NETWORKS_ACTIVE | \
                 VIR_CONNECT_LIST_NETWORKS_INACTIVE)

# define VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT   \
                (VIR_CONNECT_LIST_NETWORKS_PERSISTENT | \
                 VIR_CONNECT_LIST_NETWORKS_TRANSIENT)

# define VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART    \
                (VIR_CONNECT_LIST_NETWORKS_AUTOSTART |  \
                 VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART)

# define VIR_CONNECT_LIST_NETWORKS_FILTERS_ALL                  \
                (VIR_CONNECT_LIST_NETWORKS_FILTERS_ACTIVE     | \
                 VIR_CONNECT_LIST_NETWORKS_FILTERS_PERSISTENT | \
                 VIR_CONNECT_LIST_NETWORKS_FILTERS_AUTOSTART)

/* for testing */
int
virNetworkDefUpdateSection(virNetworkDefPtr def,
                           unsigned int command, /* virNetworkUpdateCommand */
                           unsigned int section, /* virNetworkUpdateSection */
                           int parentIndex,
                           const char *xml,
                           unsigned int flags);  /* virNetworkUpdateFlags */

VIR_ENUM_DECL(virNetworkTaint)
#endif /* __NETWORK_CONF_H__ */
