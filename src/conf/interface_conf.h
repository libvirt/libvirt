/*
 * interface_conf.h: interface XML handling entry points
 *
 * Copyright (C) 2006-2009, 2013 Red Hat, Inc.
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
 * Author: Daniel Veillard <veillard@redhat.com>
 *         Laine Stump <laine@redhat.com>
 */

#ifndef __INTERFACE_CONF_H__
# define __INTERFACE_CONF_H__

# include <libxml/parser.h>
# include <libxml/tree.h>
# include <libxml/xpath.h>

# include "internal.h"
# include "virutil.h"
# include "virthread.h"
# include "device_conf.h"

/* There is currently 3 types of interfaces */

typedef enum {
    VIR_INTERFACE_TYPE_ETHERNET,  /* simple ethernet */
    VIR_INTERFACE_TYPE_BRIDGE,    /* bridge interface */
    VIR_INTERFACE_TYPE_BOND,      /* bonding interface */
    VIR_INTERFACE_TYPE_VLAN,      /* vlan description */

    VIR_INTERFACE_TYPE_LAST,
} virInterfaceType;

VIR_ENUM_DECL(virInterface)

/* types of start mode */

typedef enum {
    VIR_INTERFACE_START_UNSPECIFIED = 0, /* not given in config */
    VIR_INTERFACE_START_NONE,     /* specified as not defined */
    VIR_INTERFACE_START_ONBOOT,   /* startup at boot */
    VIR_INTERFACE_START_HOTPLUG,  /* on hotplug */
} virInterfaceStartMode;

typedef enum {
    VIR_INTERFACE_BOND_NONE = 0,
    VIR_INTERFACE_BOND_BALRR,     /* balance-rr */
    VIR_INTERFACE_BOND_ABACKUP,   /* active backup */
    VIR_INTERFACE_BOND_BALXOR,    /* balance-xor */
    VIR_INTERFACE_BOND_BCAST,     /* broadcast */
    VIR_INTERFACE_BOND_8023AD,    /* 802.3ad */
    VIR_INTERFACE_BOND_BALTLB,    /* balance-tlb */
    VIR_INTERFACE_BOND_BALALB,    /* balance-alb */
} virInterfaceBondMode;

typedef enum {
    VIR_INTERFACE_BOND_MONIT_NONE = 0,
    VIR_INTERFACE_BOND_MONIT_MII, /* mii based monitoring */
    VIR_INTERFACE_BOND_MONIT_ARP, /* arp based monitoring */
} virInterfaceBondMonit;

typedef enum {
    VIR_INTERFACE_BOND_MII_NONE = 0,
    VIR_INTERFACE_BOND_MII_IOCTL, /* mii/ethtool ioctl */
    VIR_INTERFACE_BOND_MII_NETIF, /* netif_carrier_ok */
} virInterfaceBondMiiCarrier;

typedef enum {
    VIR_INTERFACE_BOND_ARP_NONE = 0,
    VIR_INTERFACE_BOND_ARP_ACTIVE, /* validate active */
    VIR_INTERFACE_BOND_ARP_BACKUP, /* validate backup */
    VIR_INTERFACE_BOND_ARP_ALL,    /* validate all */
} virInterfaceBondArpValid;

struct _virInterfaceDef; /* forward declaration required for bridge/bond */

typedef struct _virInterfaceBridgeDef virInterfaceBridgeDef;
typedef virInterfaceBridgeDef *virInterfaceBridgeDefPtr;
struct _virInterfaceBridgeDef {
    int stp;         /* 0, 1 or -1 if undefined */
    char *delay;
    int nbItf;       /* number of defined interfaces */
    struct _virInterfaceDef **itf;/* interfaces */
};

typedef struct _virInterfaceBondDef virInterfaceBondDef;
typedef virInterfaceBondDef *virInterfaceBondDefPtr;
struct _virInterfaceBondDef {
    int mode;                    /* virInterfaceBondMode */
    int monit;                   /* virInterfaceBondMonit */
    int frequency;               /* miimon frequency in ms */
    int downdelay;               /* miimon downdelay */
    int updelay;                 /* miimon updelay */
    int carrier;                 /* virInterfaceBondMiiCarrier */
    int interval;                /* arp monitoring interval */
    char *target;                /* arp monitoring target */
    int validate;                /* virInterfaceBondArpmValid */
    int nbItf;                   /* number of defined interfaces */
    struct _virInterfaceDef **itf; /* interfaces ethernet only */
};

typedef struct _virInterfaceVlanDef virInterfaceVlanDef;
typedef virInterfaceVlanDef *virInterfaceVlanDefPtr;
struct _virInterfaceVlanDef {
    char *tag;       /* TAG for vlan */
    char *dev_name;   /* device name for vlan */
};

typedef struct _virInterfaceIPDef virInterfaceIPDef;
typedef virInterfaceIPDef *virInterfaceIPDefPtr;
struct _virInterfaceIPDef {
    char *address;   /* ip address */
    int prefix;      /* ip prefix */
};


typedef struct _virInterfaceProtocolDef virInterfaceProtocolDef;
typedef virInterfaceProtocolDef *virInterfaceProtocolDefPtr;
struct _virInterfaceProtocolDef {
    char *family;    /* ipv4 or ipv6 */
    int dhcp;        /* use dhcp */
    int peerdns;     /* dhcp peerdns ? */
    int autoconf;    /* only useful if family is ipv6 */
    int nips;
    virInterfaceIPDefPtr *ips; /* ptr to array of ips[nips] */
    char *gateway;   /* route gateway */
};


typedef struct _virInterfaceDef virInterfaceDef;
typedef virInterfaceDef *virInterfaceDefPtr;
struct _virInterfaceDef {
    int type;                /* interface type */
    char *name;              /* interface name */
    unsigned int mtu;        /* maximum transmit size in byte */
    char *mac;               /* MAC address */
    virNetDevIfLink lnk;    /* interface link info */

    virInterfaceStartMode startmode; /* how it is started */

    union {
        virInterfaceBridgeDef bridge;
        virInterfaceVlanDef vlan;
        virInterfaceBondDef bond;
    } data;

    int nprotos;
    virInterfaceProtocolDefPtr *protos; /* ptr to array of protos[nprotos] */
};

void
virInterfaceDefFree(virInterfaceDefPtr def);

virInterfaceDefPtr
virInterfaceDefParseString(const char *xmlStr);

virInterfaceDefPtr
virInterfaceDefParseFile(const char *filename);

virInterfaceDefPtr
virInterfaceDefParseNode(xmlDocPtr xml,
                         xmlNodePtr root);

char *
virInterfaceDefFormat(const virInterfaceDef *def);

# define VIR_CONNECT_LIST_INTERFACES_FILTERS_ACTIVE   \
                (VIR_CONNECT_LIST_INTERFACES_ACTIVE | \
                 VIR_CONNECT_LIST_INTERFACES_INACTIVE)

#endif /* __INTERFACE_CONF_H__ */
