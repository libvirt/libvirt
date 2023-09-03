/*
 * libvirt-network.h
 * Summary: APIs for management of networks
 * Description: Provides APIs for the management of networks
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

#ifndef LIBVIRT_NETWORK_H
# define LIBVIRT_NETWORK_H

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif

/**
 * virNetworkXMLFlags:
 *
 * Since: 0.9.10
 */
typedef enum {
    VIR_NETWORK_XML_INACTIVE = (1 << 0), /* dump inactive network information (Since: 0.9.10) */
} virNetworkXMLFlags;

/**
 * virNetwork:
 *
 * a virNetwork is a private structure representing a virtual network.
 *
 * Since: 0.2.0
 */
typedef struct _virNetwork virNetwork;

/**
 * virNetworkPtr:
 *
 * a virNetworkPtr is pointer to a virNetwork private structure, this is the
 * type used to reference a virtual network in the API.
 *
 * Since: 0.2.0
 */
typedef virNetwork *virNetworkPtr;

/**
 * virNetworkPort:
 *
 * a virNetworkPort is a private structure representing a virtual network
 * port
 *
 * Since: 5.5.0
 */
typedef struct _virNetworkPort virNetworkPort;

/**
 * virNetworkPortPtr:
 *
 * a virNetworkPortPtr is pointer to a virNetworkPort private structure,
 * this is the type used to reference a virtual network port in the API.
 *
 * Since: 5.5.0
 */
typedef virNetworkPort *virNetworkPortPtr;

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
/**
 * virConnectListAllNetworksFlags:
 *
 * Flags used to filter the returned networks. Flags in each group
 * are exclusive attributes of a network.
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_CONNECT_LIST_NETWORKS_INACTIVE      = 1 << 0, /* (Since: 0.10.2) */
    VIR_CONNECT_LIST_NETWORKS_ACTIVE        = 1 << 1, /* (Since: 0.10.2) */

    VIR_CONNECT_LIST_NETWORKS_PERSISTENT    = 1 << 2, /* (Since: 0.10.2) */
    VIR_CONNECT_LIST_NETWORKS_TRANSIENT     = 1 << 3, /* (Since: 0.10.2) */

    VIR_CONNECT_LIST_NETWORKS_AUTOSTART     = 1 << 4, /* (Since: 0.10.2) */
    VIR_CONNECT_LIST_NETWORKS_NO_AUTOSTART  = 1 << 5, /* (Since: 0.10.2) */
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
/**
 * virNetworkCreateFlags:
 *
 * Since: 7.8.0
 */
typedef enum {
    VIR_NETWORK_CREATE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.8.0) */
} virNetworkCreateFlags;

/*
 * Create active transient network
 */
virNetworkPtr           virNetworkCreateXML     (virConnectPtr conn,
                                                 const char *xmlDesc);
virNetworkPtr           virNetworkCreateXMLFlags(virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);
/**
 * virNetworkDefineFlags:
 *
 * Since: 7.7.0
 */
typedef enum {
    VIR_NETWORK_DEFINE_VALIDATE = 1 << 0, /* Validate the XML document against schema (Since: 7.7.0) */
} virNetworkDefineFlags;

/*
 * Define inactive persistent network
 */
virNetworkPtr           virNetworkDefineXML     (virConnectPtr conn,
                                                 const char *xmlDesc);
virNetworkPtr           virNetworkDefineXMLFlags(virConnectPtr conn,
                                                 const char *xmlDesc,
                                                 unsigned int flags);

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
 * Since: 0.10.2
 */
typedef enum {
    VIR_NETWORK_UPDATE_COMMAND_NONE      = 0, /* invalid (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_COMMAND_MODIFY    = 1, /* modify an existing element (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_COMMAND_DELETE    = 2, /* delete an existing element (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_COMMAND_ADD_LAST  = 3, /* add an element at end of list (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_COMMAND_ADD_FIRST = 4, /* add an element at start of list (Since: 0.10.2) */
# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_UPDATE_COMMAND_LAST /* (Since: 0.10.2) */
# endif
} virNetworkUpdateCommand;

/**
 * virNetworkUpdateSection:
 *
 * describes which section of a <network> definition the provided
 * xml should be applied to.
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_NETWORK_SECTION_NONE              =  0, /* invalid (Since: 0.10.2) */
    VIR_NETWORK_SECTION_BRIDGE            =  1, /* <bridge> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_DOMAIN            =  2, /* <domain> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_IP                =  3, /* <ip> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_IP_DHCP_HOST      =  4, /* <ip>/<dhcp>/<host> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_IP_DHCP_RANGE     =  5, /* <ip>/<dhcp>/<range> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_FORWARD           =  6, /* <forward> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_FORWARD_INTERFACE =  7, /* <forward>/<interface> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_FORWARD_PF        =  8, /* <forward>/<pf> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_PORTGROUP         =  9, /* <portgroup> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_DNS_HOST          = 10, /* <dns>/<host> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_DNS_TXT           = 11, /* <dns>/<txt> (Since: 0.10.2) */
    VIR_NETWORK_SECTION_DNS_SRV           = 12, /* <dns>/<srv> (Since: 0.10.2) */
# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_SECTION_LAST /* (Since: 0.10.2) */
# endif
} virNetworkUpdateSection;

/**
 * virNetworkUpdateFlags:
 *
 * Flags to control options for virNetworkUpdate()
 *
 * Since: 0.10.2
 */
typedef enum {
    VIR_NETWORK_UPDATE_AFFECT_CURRENT = 0,      /* affect live if network is active,
                                                   config if it's not active (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_AFFECT_LIVE    = 1 << 0, /* affect live state of network only (Since: 0.10.2) */
    VIR_NETWORK_UPDATE_AFFECT_CONFIG  = 1 << 1, /* affect persistent config only (Since: 0.10.2) */
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
 *
 * Since: 1.2.1
 */
typedef enum {
    VIR_NETWORK_EVENT_DEFINED = 0, /* (Since: 1.2.1) */
    VIR_NETWORK_EVENT_UNDEFINED = 1, /* (Since: 1.2.1) */
    VIR_NETWORK_EVENT_STARTED = 2, /* (Since: 1.2.1) */
    VIR_NETWORK_EVENT_STOPPED = 3, /* (Since: 1.2.1) */

# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_EVENT_LAST /* (Since: 1.2.1) */
# endif
} virNetworkEventLifecycleType;

/**
 * virConnectNetworkEventLifecycleCallback:
 * @conn: connection object
 * @net: network on which the event occurred
 * @event: The specific virNetworkEventLifecycleType which occurred
 * @detail: contains some details on the reason of the event.
 *          It will be 0 for the while.
 * @opaque: application specified data
 *
 * This callback occurs when the network is started or stopped.
 *
 * The callback signature to use when registering for an event of type
 * VIR_NETWORK_EVENT_ID_LIFECYCLE with virConnectNetworkEventRegisterAny()
 *
 * Since: 1.2.1
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
 *
 * Since: 1.2.1
 */
# define VIR_NETWORK_EVENT_CALLBACK(cb) ((virConnectNetworkEventGenericCallback)(cb))

/**
 * virNetworkEventID:
 *
 * An enumeration of supported eventId parameters for
 * virConnectNetworkEventRegisterAny().  Each event id determines which
 * signature of callback function will be used.
 *
 * Since: 1.2.1
 */
typedef enum {
    VIR_NETWORK_EVENT_ID_LIFECYCLE = 0,       /* virConnectNetworkEventLifecycleCallback (Since: 1.2.1) */
    VIR_NETWORK_EVENT_ID_METADATA_CHANGE = 1,   /* virConnectNetworkEventMetadataChangeCallback (Since: 9.8.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_EVENT_ID_LAST
    /*
     * NB: this enum value will increase over time as new events are
     * added to the libvirt API. It reflects the last event ID supported
     * by this version of the libvirt API.
     *
     * Since: 1.2.1
     */
# endif
} virNetworkEventID;

/**
 * virIPAddrType:
 *
 * Since: 1.2.6
 */
typedef enum {
    VIR_IP_ADDR_TYPE_IPV4, /* (Since: 1.2.6) */
    VIR_IP_ADDR_TYPE_IPV6, /* (Since: 1.2.6) */

# ifdef VIR_ENUM_SENTINELS
    VIR_IP_ADDR_TYPE_LAST /* (Since: 1.2.6) */
# endif
} virIPAddrType;

/**
 * virNetworkDHCPLease:
 *
 * Since: 1.2.6
 */
typedef struct _virNetworkDHCPLease virNetworkDHCPLease;

/**
 * virNetworkDHCPLeasePtr:
 *
 * Since: 1.2.6
 */
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
 *
 * Since: 1.2.1
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


virNetworkPortPtr
virNetworkPortLookupByUUID(virNetworkPtr net,
                           const unsigned char *uuid);

virNetworkPortPtr
virNetworkPortLookupByUUIDString(virNetworkPtr net,
                                 const char *uuidstr);

/**
 * virNetworkPortCreateFlags:
 *
 * Since: 5.5.0
 */
typedef enum {
    VIR_NETWORK_PORT_CREATE_RECLAIM = (1 << 0), /* reclaim existing used resources (Since: 5.5.0) */
    VIR_NETWORK_PORT_CREATE_VALIDATE = (1 << 1), /* Validate the XML document against schema (Since: 7.8.0) */
} virNetworkPortCreateFlags;

virNetworkPortPtr
virNetworkPortCreateXML(virNetworkPtr net,
                        const char *xmldesc,
                        unsigned int flags);

virNetworkPtr
virNetworkPortGetNetwork(virNetworkPortPtr port);

char *
virNetworkPortGetXMLDesc(virNetworkPortPtr port,
                         unsigned int flags);

int
virNetworkPortGetUUID(virNetworkPortPtr port,
                      unsigned char *uuid);
int
virNetworkPortGetUUIDString(virNetworkPortPtr port,
                            char *buf);

/* Management of interface parameters */

/**
 * VIR_NETWORK_PORT_BANDWIDTH_IN_AVERAGE:
 *
 * Macro represents the inbound average of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_IN_AVERAGE "inbound.average"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_IN_PEAK:
 *
 * Macro represents the inbound peak of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_IN_PEAK "inbound.peak"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_IN_BURST:
 *
 * Macro represents the inbound burst of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_IN_BURST "inbound.burst"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_IN_FLOOR:
 *
 * Macro represents the inbound floor of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_IN_FLOOR "inbound.floor"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_OUT_AVERAGE:
 *
 * Macro represents the outbound average of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_OUT_AVERAGE "outbound.average"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_OUT_PEAK:
 *
 * Macro represents the outbound peak of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_OUT_PEAK "outbound.peak"

/**
 * VIR_NETWORK_PORT_BANDWIDTH_OUT_BURST:
 *
 * Macro represents the outbound burst of NIC bandwidth, as a uint.
 *
 * Since: 5.5.0
 */
# define VIR_NETWORK_PORT_BANDWIDTH_OUT_BURST "outbound.burst"

int
virNetworkPortSetParameters(virNetworkPortPtr port,
                            virTypedParameterPtr params,
                            int nparams,
                            unsigned int flags);
int
virNetworkPortGetParameters(virNetworkPortPtr port,
                            virTypedParameterPtr *params,
                            int *nparams,
                            unsigned int flags);

int
virNetworkPortDelete(virNetworkPortPtr port,
                     unsigned int flags);

int
virNetworkListAllPorts(virNetworkPtr network,
                       virNetworkPortPtr **ports,
                       unsigned int flags);

int
virNetworkPortFree(virNetworkPortPtr port);

int
virNetworkPortRef(virNetworkPortPtr port);

/**
 * virNetworkMetadataType:
 *
 * Since: 9.7.0
 */
typedef enum {
    VIR_NETWORK_METADATA_DESCRIPTION = 0, /* Operate on <description> (Since: 9.7.0) */
    VIR_NETWORK_METADATA_TITLE       = 1, /* Operate on <title> (Since: 9.7.0) */
    VIR_NETWORK_METADATA_ELEMENT     = 2, /* Operate on <metadata> (Since: 9.7.0) */

# ifdef VIR_ENUM_SENTINELS
    VIR_NETWORK_METADATA_LAST /* (Since: 9.7.0) */
# endif
} virNetworkMetadataType;

int
virNetworkSetMetadata(virNetworkPtr network,
                      int type,
                      const char *metadata,
                      const char *key,
                      const char *uri,
                      unsigned int flags);

char *
virNetworkGetMetadata(virNetworkPtr network,
                      int type,
                      const char *uri,
                      unsigned int flags);

/**
 * virConnectNetworkEventMetadataChangeCallback:
 * @conn: connection object
 * @net: network on which the event occurred
 * @type: a value from virNetworkMetadataType
 * @nsuri: XML namespace URI
 * @opaque: application specified data
 *
 * This callback is triggered when the Network XML metadata changes
 *
 * The callback signature to use when registering for an event of type
 * VIR_NETWORK_EVENT_ID_METADATA_CHANGE with virConnectNetworkEventRegisterAny().
 *
 * Since: 9.8.0
 */
typedef void (*virConnectNetworkEventMetadataChangeCallback)(virConnectPtr conn,
                                                             virNetworkPtr net,
                                                             int type,
                                                             const char *nsuri,
                                                             void *opaque);

#endif /* LIBVIRT_NETWORK_H */
