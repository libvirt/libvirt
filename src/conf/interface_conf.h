/*
 * interface_conf.h: interface XML handling entry points
 *
 * Copyright (C) 2006-2009 Red Hat, Inc.
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
 * Author: Daniel Veillard <veillard@redhat.com>
 *         Laine Stump <laine@redhat.com>
 */

#ifndef __INTERFACE_CONF_H__
#define __INTERFACE_CONF_H__

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>

#include "internal.h"
#include "util.h"
#include "threads.h"

/* There is currently 3 types of interfaces */

enum virInterfaceType {
    VIR_INTERFACE_TYPE_ETHERNET,  /* simple ethernet */
    VIR_INTERFACE_TYPE_BRIDGE,    /* bridge interface */
    VIR_INTERFACE_TYPE_BOND,      /* bonding interface */
    VIR_INTERFACE_TYPE_VLAN,      /* vlan description */

    VIR_INTERFACE_TYPE_LAST,
};

VIR_ENUM_DECL(virInterface)

/* types of start mode */

enum virInterfaceStartMode {
    VIR_INTERFACE_START_NONE = 0, /* not defined */
    VIR_INTERFACE_START_ONBOOT,   /* startup at boot */
    VIR_INTERFACE_START_HOTPLUG,  /* on hotplug */
};

enum virInterfaceBondMode {
    VIR_INTERFACE_BOND_NONE = 0,
    VIR_INTERFACE_BOND_BALRR,     /* balance-rr */
    VIR_INTERFACE_BOND_ABACKUP,   /* active backup */
    VIR_INTERFACE_BOND_BALXOR,    /* balance-xor */
    VIR_INTERFACE_BOND_BCAST,     /* broadcast */
    VIR_INTERFACE_BOND_8023AD,    /* 802.3ad */
    VIR_INTERFACE_BOND_BALTLB,    /* balance-tlb */
    VIR_INTERFACE_BOND_BALALB,    /* balance-alb */
};

enum virInterfaceBondMonit {
    VIR_INTERFACE_BOND_MONIT_NONE = 0,
    VIR_INTERFACE_BOND_MONIT_MII, /* mii based monitoring */
    VIR_INTERFACE_BOND_MONIT_ARP, /* arp based monitoring */
};

enum virInterfaceBondMiiCarrier {
    VIR_INTERFACE_BOND_MII_NONE = 0,
    VIR_INTERFACE_BOND_MII_IOCTL, /* mii/ethtool ioctl */
    VIR_INTERFACE_BOND_MII_NETIF, /* netif_carrier_ok */
};

enum virInterfaceBondArpValid {
    VIR_INTERFACE_BOND_ARP_NONE = 0,
    VIR_INTERFACE_BOND_ARP_ACTIVE, /* validate active */
    VIR_INTERFACE_BOND_ARP_BACKUP, /* validate backup */
    VIR_INTERFACE_BOND_ARP_ALL,    /* validate all */
};

typedef struct _virInterfaceBareDef virInterfaceBareDef;
typedef virInterfaceBareDef *virInterfaceBareDefPtr;
struct _virInterfaceBareDef {
    int type;                /* should be only ethernet or vlan */
    char *name;              /* the interface name */
    char *mac_or_tag;        /* MAC address for ethernet, TAG for vlan */
    char *devname;           /* device name for vlan */
};

typedef struct _virInterfaceBridgeDef virInterfaceBridgeDef;
typedef virInterfaceBridgeDef *virInterfaceBridgeDefPtr;
struct _virInterfaceBridgeDef {
    int stp;         /* 0, 1 or -1 if undefined */
    int nbItf;       /* number of defined interfaces */
    virInterfaceBareDefPtr *itf;/* interfaces */
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
    virInterfaceBareDefPtr *itf; /* interfaces ethernet only */
};

typedef struct _virInterfaceVlanDef virInterfaceVlanDef;
typedef virInterfaceVlanDef *virInterfaceVlanDefPtr;
struct _virInterfaceVlanDef {
    char *tag;       /* TAG for vlan */
    char *devname;   /* device name for vlan */
};

typedef struct _virInterfaceProtocolDef virInterfaceProtocolDef;
typedef virInterfaceProtocolDef *virInterfaceProtocolDefPtr;
struct _virInterfaceProtocolDef {
    char *family;    /* ipv4 only right now */
    int dhcp;        /* use dhcp */
    int peerdns;     /* dhcp peerdns ? */
    char *address;   /* ip address */
    int prefix;      /* ip prefix */
    char *gateway;   /* route gateway */
};


typedef struct _virInterfaceDef virInterfaceDef;
typedef virInterfaceDef *virInterfaceDefPtr;
struct _virInterfaceDef {
    int type;                /* interface type */
    char *name;              /* interface name */
    unsigned int mtu;        /* maximum transmit size in byte */
    char *mac;               /* MAC address */

    enum virInterfaceStartMode startmode; /* how it is started */

    union {
        virInterfaceBridgeDef bridge;
        virInterfaceVlanDef vlan;
        virInterfaceBondDef bond;
    } data;

    /* separated as we may allow multiple of those in the future */
    virInterfaceProtocolDef proto;
};

typedef struct _virInterfaceObj virInterfaceObj;
typedef virInterfaceObj *virInterfaceObjPtr;
struct _virInterfaceObj {
    virMutex lock;

    int active:1;           /* 1 if interface is active (up) */
    virInterfaceDefPtr def; /* The interface definition */
};

typedef struct _virInterfaceObjList virInterfaceObjList;
typedef virInterfaceObjList *virInterfaceObjListPtr;
struct _virInterfaceObjList {
    unsigned int count;
    virInterfaceObjPtr *objs;
};

static inline int
virInterfaceIsActive(const virInterfaceObjPtr iface)
{
    return iface->active;
}

int virInterfaceFindByMACString(const virInterfaceObjListPtr interfaces,
                                const char *mac,
                                virInterfaceObjPtr *matches, int maxmatches);
virInterfaceObjPtr virInterfaceFindByName(const virInterfaceObjListPtr
                                          interfaces,
                                          const char *name);


void virInterfaceDefFree(virInterfaceDefPtr def);
void virInterfaceObjFree(virInterfaceObjPtr iface);
void virInterfaceObjListFree(virInterfaceObjListPtr vms);

virInterfaceObjPtr virInterfaceAssignDef(virConnectPtr conn,
                                         virInterfaceObjListPtr interfaces,
                                         const virInterfaceDefPtr def);
void virInterfaceRemove(virInterfaceObjListPtr interfaces,
                        const virInterfaceObjPtr iface);

virInterfaceDefPtr virInterfaceDefParseString(virConnectPtr conn,
                                              const char *xmlStr);
virInterfaceDefPtr virInterfaceDefParseFile(virConnectPtr conn,
                                            const char *filename);
virInterfaceDefPtr virInterfaceDefParseNode(virConnectPtr conn,
                                            xmlDocPtr xml,
                                            xmlNodePtr root);

char *virInterfaceDefFormat(virConnectPtr conn,
                            const virInterfaceDefPtr def);

void virInterfaceObjLock(virInterfaceObjPtr obj);
void virInterfaceObjUnlock(virInterfaceObjPtr obj);

#endif /* __INTERFACE_CONF_H__ */
