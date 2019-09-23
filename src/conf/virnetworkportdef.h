/*
 * virnetworkportdef.h: network port XML processing
 *
 * Copyright (C) 2018 Red Hat, Inc.
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
 */

#pragma once

#include "internal.h"
#include "viruuid.h"
#include "virnetdevvlan.h"
#include "virnetdevvportprofile.h"
#include "virnetdevbandwidth.h"
#include "virpci.h"
#include "virxml.h"
#include "netdev_vport_profile_conf.h"
#include "netdev_bandwidth_conf.h"
#include "netdev_vlan_conf.h"

typedef struct _virNetworkPortDef virNetworkPortDef;
typedef virNetworkPortDef *virNetworkPortDefPtr;

typedef enum {
    VIR_NETWORK_PORT_PLUG_TYPE_NONE,
    VIR_NETWORK_PORT_PLUG_TYPE_NETWORK,
    VIR_NETWORK_PORT_PLUG_TYPE_BRIDGE,
    VIR_NETWORK_PORT_PLUG_TYPE_DIRECT,
    VIR_NETWORK_PORT_PLUG_TYPE_HOSTDEV_PCI,

    VIR_NETWORK_PORT_PLUG_TYPE_LAST,
} virNetworkPortPlugType;

VIR_ENUM_DECL(virNetworkPortPlug);

struct _virNetworkPortDef {
    unsigned char uuid[VIR_UUID_BUFLEN];
    char *ownername;
    unsigned char owneruuid[VIR_UUID_BUFLEN];

    char *group;
    virMacAddr mac;

    virNetDevVPortProfilePtr virtPortProfile;
    virNetDevBandwidthPtr bandwidth;
    unsigned int class_id; /* class ID for bandwidth 'floor' */
    virNetDevVlan vlan;
    int trustGuestRxFilters; /* enum virTristateBool */

    int plugtype; /* virNetworkPortPlugType */
    union {
        struct {
            char *brname;
            int macTableManager; /* enum virNetworkBridgeMACTableManagerType */
        } bridge; /* For TYPE_NETWORK & TYPE_BRIDGE */
        struct {
            char *linkdev;
            int mode; /* enum virNetDevMacVLanMode from util/virnetdevmacvlan.h */
        } direct;
        struct {
            virPCIDeviceAddress addr; /* PCI Address of device */
            int driver; /* virNetworkForwardDriverNameType */
            int managed;
        } hostdevpci;
    } plug;
};


void
virNetworkPortDefFree(virNetworkPortDefPtr port);
VIR_DEFINE_AUTOPTR_FUNC(virNetworkPortDef, virNetworkPortDefFree);

virNetworkPortDefPtr
virNetworkPortDefParseNode(xmlDocPtr xml,
                           xmlNodePtr root);

virNetworkPortDefPtr
virNetworkPortDefParseString(const char *xml);

virNetworkPortDefPtr
virNetworkPortDefParseFile(const char *filename);

char *
virNetworkPortDefFormat(const virNetworkPortDef *def);

int
virNetworkPortDefFormatBuf(virBufferPtr buf,
                           const virNetworkPortDef *def);

int
virNetworkPortDefSaveStatus(virNetworkPortDef *def,
                            const char *dir);

int
virNetworkPortDefDeleteStatus(virNetworkPortDef *def,
                              const char *dir);
