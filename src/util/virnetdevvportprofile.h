/*
 * Copyright (C) 2009-2013 Red Hat, Inc.
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_VPORT_PROFILE_H__
# define __VIR_NETDEV_VPORT_PROFILE_H__

# include "internal.h"
# include "viruuid.h"
# include "virutil.h"
# include "virmacaddr.h"

# define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX 40

enum virNetDevVPortProfile {
    VIR_NETDEV_VPORT_PROFILE_NONE,
    VIR_NETDEV_VPORT_PROFILE_8021QBG,
    VIR_NETDEV_VPORT_PROFILE_8021QBH,
    VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH,
    VIR_NETDEV_VPORT_PROFILE_MIDONET,

    VIR_NETDEV_VPORT_PROFILE_LAST,
};
VIR_ENUM_DECL(virNetDevVPort)

typedef enum {
    VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
    VIR_NETDEV_VPORT_PROFILE_OP_SAVE,
    VIR_NETDEV_VPORT_PROFILE_OP_RESTORE,
    VIR_NETDEV_VPORT_PROFILE_OP_DESTROY,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_OUT,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH,
    VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,

    VIR_NETDEV_VPORT_PROFILE_OP_LAST
} virNetDevVPortProfileOp;
VIR_ENUM_DECL(virNetDevVPortProfileOp)

/* profile data for macvtap (VEPA) and openvswitch */
typedef struct _virNetDevVPortProfile virNetDevVPortProfile;
typedef virNetDevVPortProfile *virNetDevVPortProfilePtr;
struct _virNetDevVPortProfile {
    int           virtPortType; /* enum virNetDevVPortProfile */
    /* these members are used when virtPortType == 802.1Qbg */
    uint8_t       managerID;
    bool          managerID_specified;
    uint32_t      typeID; /* 24 bit valid */
    bool          typeID_specified;
    uint8_t       typeIDVersion;
    bool          typeIDVersion_specified;
    unsigned char instanceID[VIR_UUID_BUFLEN];
    bool          instanceID_specified;

    /* this member is used when virtPortType == 802.1Qbh|openvswitch */
    /* this is a null-terminated character string */
    char          profileID[LIBVIRT_IFLA_VF_PORT_PROFILE_MAX];

    /* this member is used when virtPortType == openvswitch|midonet */
    unsigned char interfaceID[VIR_UUID_BUFLEN];
    bool          interfaceID_specified;
    /* NB - if virtPortType == NONE, any/all of the items could be used */
};


bool virNetDevVPortProfileEqual(virNetDevVPortProfilePtr a,
                                virNetDevVPortProfilePtr b);

int virNetDevVPortProfileCheckComplete(virNetDevVPortProfilePtr virtport,
                                       bool generateMissing);
int virNetDevVPortProfileCheckNoExtras(virNetDevVPortProfilePtr virtport);

int virNetDevVPortProfileMerge3(virNetDevVPortProfilePtr *result,
                                virNetDevVPortProfilePtr fromInterface,
                                virNetDevVPortProfilePtr fromNetwork,
                                virNetDevVPortProfilePtr fromPortgroup);

int virNetDevVPortProfileAssociate(const char *ifname,
                                   const virNetDevVPortProfile *virtPort,
                                   const virMacAddr *macvtap_macaddr,
                                   const char *linkdev,
                                   int vf,
                                   const unsigned char *vmuuid,
                                   virNetDevVPortProfileOp vmOp,
                                   bool setlink_only)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;

int virNetDevVPortProfileDisassociate(const char *ifname,
                                      const virNetDevVPortProfile *virtPort,
                                      const virMacAddr *macvtap_macaddr,
                                      const char *linkdev,
                                      int vf,
                                      virNetDevVPortProfileOp vmOp)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_RETURN_CHECK;


#endif /* __VIR_NETDEV_VPORT_PROFILE_H__ */
