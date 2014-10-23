/*
 * libvirt-network.h
 * Summary: APIs for management of networks
 * Description: Provides APIs for the management of networks
 * Author: Daniel Veillard <veillard@redhat.com>
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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

#ifndef __VIR_LIBVIRT_NETWORK_H__
# define __VIR_LIBVIRT_NETWORK_H__

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

typedef enum {
    VIR_NETWORK_XML_INACTIVE = (1 << 0), /* dump inactive network information */
} virNetworkXMLFlags;

/**
 * virNetwork:
 *
 * a virNetwork is a private structure representing a virtual network.
 */
typedef struct _virNetwork virNetwork;

/**
 * virNetworkPtr:
 *
 * a virNetworkPtr is pointer to a virNetwork private structure, this is the
 * type used to reference a virtual network in the API.
 */
typedef virNetwork *virNetworkPtr;

/*
 * Get connection from network.
 */
virConnectPtr           virNetworkGetConnect    (virNetworkPtr network);

/*
 * List active networks
 */
int                     virConnectNumOfNetworks (virConnectPtr conn);
int                     virConnectListNetworks  (virConnectPtr conn,
                                                 char **const names,
                                                 int maxnames);

/*
 * List inactive networks
 */
int                     virConnectNumOfDefinedNetworks  (virConnectPtr conn);
int                     virConnectListDefinedNetworks   (virConnectPtr conn,
                                                         char **const names,
                                                         int maxnames);
/*
 * virConnectListAllNetworks:
 *
 * Flags used to filter the returned networks. Flags in each group
 * are exclusive attributes of a network.
 */
typedef enum {
    VIR_CONNECT_LIST_NETWORKS_INACTIVE      = 1 << 0,
    VIR_CONNECT_LIST_NETWORKS_ACTIVE        = 1 << 1,

    VIR_CONNECT_LIST_NETWORKS_PERSISTENT    = 1 << 2,
    VIR_CONNECT_LIST_NETWORKS_TRANSIENT     = 1 << 3,

    VIR_CONNECT_LIST_NETWORKS_AUTOSTART     = 1 << 4,
    VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART  = 1 << 5,
} virConnectListAllNetworksFlags;

int                     virConnectListAllNetworks       (virConnectPtr conn,
                                                         virNetworkPtr **nets,
                                                         unsigned int flags);

/*
 * Lookup network by name or uuid
 */
virNetworkPtr           virNetworkLookupByName          (virConnectPtr conn,
                                                         const char *name);
virNetworkPtr           virNetworkLookupByUUID          (virConnectPtr conn,
                                                         const unsigned char *uuid);
virNetworkPtr           virNetworkLookupByUUIDString    (virConnectPtr conn,
                                                         const char *uuid);

/*
 * Create active transient network
 */
virNetworkPtr           virNetworkCreateXML     (virConnectPtr conn,
                                                 const char *xmlDesc);

/*
 * Define inactive persistent network
 */
virNetworkPtr           virNetworkDefineXML     (virConnectPtr conn,
                                                 const char *xmlDesc);

/*
 * Delete persistent network
 */
int                     virNetworkUndefine      (virNetworkPtr network);

/**
 * virNetworkUpdateCommand:
 *
 * describes which type of update to perform on a <network>
 * definition.
 *
 */
typedef enum {
    VIR_NETWORK_UPDATE_COMMAND_NONE      = 0, /* (invalid) */
    VIR_NETWORK_UPDATE_COMMAND_MODIFY    = 1, /* modify an existing element */
    VIR_NETWORK_UPDATE_COMMAND_DELETE    = 2, /* delete an existing element */
    VIR_NETWORK_UPDATE_COMMAND_ADD_LAST  = 3, /* add an element at end of list */
    VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST = 4, /* add an element at start of list */
# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_UPDATE_COMMAND_LAST
# endif
} virNetworkUpdateCommand;

/**
 * virNetworkUpdateSection:
 *
 * describes which section of a <network> definition the provided
 * xml should be applied to.
 *
 */
typedef enum {
    VIR_NETWORK_SECTION_NONE              =  0, /* (invalid) */
    VIR_NETWORK_SECTION_BRIDGE            =  1, /* <bridge> */
    VIR_NETWORK_SECTION_DOMAIN            =  2, /* <domain> */
    VIR_NETWORK_SECTION_IP                =  3, /* <ip> */
    VIR_NETWORK_SECTION_IP_DHCP_HOST      =  4, /* <ip>/<dhcp>/<host> */
    VIR_NETWORK_SECTION_IP_DHCP_RANGE     =  5, /* <ip>/<dhcp>/<range> */
    VIR_NETWORK_SECTION_FORWARD           =  6, /* <forward> */
    VIR_NETWORK_SECTION_FORWARD_INTERFACE =  7, /* <forward>/<interface> */
    VIR_NETWORK_SECTION_FORWARD_PF        =  8, /* <forward>/<pf> */
    VIR_NETWORK_SECTION_PORTGROUP         =  9, /* <portgroup> */
    VIR_NETWORK_SECTION_DNS_HOST          = 10, /* <dns>/<host> */
    VIR_NETWORK_SECTION_DNS_TXT           = 11, /* <dns>/<txt> */
    VIR_NETWORK_SECTION_DNS_SRV           = 12, /* <dns>/<srv> */
# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_SECTION_LAST
# endif
} virNetworkUpdateSection;

/**
 * virNetworkUpdateFlags:
 *
 * Flags to control options for virNetworkUpdate()
 */
typedef enum {
    VIR_NETWORK_UPDATE_AFFECT_CURRENT = 0,      /* affect live if network is active,
                                                   config if it's not active */
    VIR_NETWORK_UPDATE_AFFECT_LIVE    = 1 << 0, /* affect live state of network only */
    VIR_NETWORK_UPDATE_AFFECT_CONFIG  = 1 << 1, /* affect persistent config only */
} virNetworkUpdateFlags;

/*
 * Update an existing network definition
 */
int                     virNetworkUpdate(virNetworkPtr network,
                                         unsigned int command, /* virNetworkUpdateCommand */
                                         unsigned int section, /* virNetworkUpdateSection */
                                         int parentIndex,
                                         const char *xml,
                                         unsigned int flags);

/*
 * Activate persistent network
 */
int                     virNetworkCreate        (virNetworkPtr network);

/*
 * Network destroy/free
 */
int                     virNetworkDestroy       (virNetworkPtr network);
int                     virNetworkRef           (virNetworkPtr network);
int                     virNetworkFree          (virNetworkPtr network);

/*
 * Network information
 */
const char*             virNetworkGetName       (virNetworkPtr network);
int                     virNetworkGetUUID       (virNetworkPtr network,
                                                 unsigned char *uuid);
int                     virNetworkGetUUIDString (virNetworkPtr network,
                                                 char *buf);
char *                  virNetworkGetXMLDesc    (virNetworkPtr network,
                                                 unsigned int flags);
char *                  virNetworkGetBridgeName (virNetworkPtr network);

int                     virNetworkGetAutostart  (virNetworkPtr network,
                                                 int *autostart);
int                     virNetworkSetAutostart  (virNetworkPtr network,
                                                 int autostart);

int virNetworkIsActive(virNetworkPtr net);
int virNetworkIsPersistent(virNetworkPtr net);

/**
 * virNetworkEventLifecycleType:
 *
 * a virNetworkEventLifecycleType is emitted during network lifecycle events
 */
typedef enum {
    VIR_NETWORK_EVENT_DEFINED = 0,
    VIR_NETWORK_EVENT_UNDEFINED = 1,
    VIR_NETWORK_EVENT_STARTED = 2,
    VIR_NETWORK_EVENT_STOPPED = 3,

# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_EVENT_LAST
# endif
} virNetworkEventLifecycleType;

/**
 * virConnectNetworkEventLifecycleCallback:
 * @conn: connection object
 * @net: network on which the event occurred
 * @event: The specific virNetworkEventLifeCycleType which occurred
 * @detail: contains some details on the reason of the event.
 *          It will be 0 for the while.
 * @opaque: application specified data
 *
 * This callback occurs when the network is started or stopped.
 *
 * The callback signature to use when registering for an event of type
 * VIR_NETWORK_EVENT_ID_LIFECYCLE with virConnectNetworkEventRegisterAny()
 */
typedef void (*virConnectNetworkEventLifecycleCallback)(virConnectPtr conn,
                                                        virNetworkPtr net,
                                                        int event,
                                                        int detail,
                                                        void *opaque);

/**
 * VIR_NETWORK_EVENT_CALLBACK:
 *
 * Used to cast the event specific callback into the generic one
 * for use for virConnectNetworkEventRegisterAny()
 */
# define VIR_NETWORK_EVENT_CALLBACK(cb) ((virConnectNetworkEventGenericCallback)(cb))

/**
 * virNetworkEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectNetworkEventRegisterAny().  Each event id determines which
 * signature of callback function will be used.
 */
typedef enum {
    VIR_NETWORK_EVENT_ID_LIFECYCLE = 0,       /* virConnectNetworkEventLifecycleCallback */

# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     */
# endif
} virNetworkEventID;

typedef enum {
    VIR_IP_ADDR_TYPE_IPV4,
    VIR_IP_ADDR_TYPE_IPV6,

# ifdef VIR_ENUM_SENTINELS
    VIR_IP_ADDR_TYPE_LAST
# endif
} virIPAddrType;

typedef struct _virNetworkDHCPLease virNetworkDHCPLease;
typedef virNetworkDHCPLease *virNetworkDHCPLeasePtr;
struct _virNetworkDHCPLease {
    char *iface;                /* Network interface name */
    long long expirytime;       /* Seconds since epoch */
    int type;                   /* virIPAddrType */
    char *mac;                  /* MAC address */
    char *iaid;                 /* IAID */
    char *ipaddr;               /* IP address */
    unsigned int prefix;        /* IP address prefix */
    char *hostname;             /* Hostname */
    char *clientid;             /* Client ID or DUID */
};

void virNetworkDHCPLeaseFree(virNetworkDHCPLeasePtr lease);

int virNetworkGetDHCPLeases(virNetworkPtr network,
                            const char *mac,
                            virNetworkDHCPLeasePtr **leases,
                            unsigned int flags);

/**
 * virConnectNetworkEventGenericCallback:
 * @conn: the connection pointer
 * @net: the network pointer
 * @opaque: application specified data
 *
 * A generic network event callback handler, for use with
 * virConnectNetworkEventRegisterAny(). Specific events usually
 * have a customization with extra parameters, often with @opaque being
 * passed in a different parameter position; use VIR_NETWORK_EVENT_CALLBACK()
 * when registering an appropriate handler.
 */
typedef void (*virConnectNetworkEventGenericCallback)(virConnectPtr conn,
                                                      virNetworkPtr net,
                                                      void *opaque);

/* Use VIR_NETWORK_EVENT_CALLBACK() to cast the 'cb' parameter  */
int virConnectNetworkEventRegisterAny(virConnectPtr conn,
                                      virNetworkPtr net, /* Optional, to filter */
                                      int eventID,
                                      virConnectNetworkEventGenericCallback cb,
                                      void *opaque,
                                      virFreeCallback freecb);

int virConnectNetworkEventDeregisterAny(virConnectPtr conn,
                                        int callbackID);

#endif /* __VIR_LIBVIRT_NETWORK_H__ */
