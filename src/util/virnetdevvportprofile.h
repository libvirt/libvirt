/*
 * Copyright (C) 2009-2011 Red Hat, Inc.
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
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NETDEV_VPORT_PROFILE_H__
# define __VIR_NETDEV_VPORT_PROFILE_H__

# include <stdint.h>

# include "internal.h"
# include "uuid.h"
# include "util.h"

# define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX 40

enum virNetDevVPortProfile {
    VIR_NETDEV_VPORT_PROFILE_NONE,
    VIR_NETDEV_VPORT_PROFILE_8021QBG,
    VIR_NETDEV_VPORT_PROFILE_8021QBH,
    VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH,

    VIR_NETDEV_VPORT_PROFILE_LAST,
};
VIR_ENUM_DECL(virNetDevVPort)

enum virNetDevVPortProfileOp {
    VIR_NETDEV_VPORT_PROFILE_OP_CREATE,
    VIR_NETDEV_VPORT_PROFILE_OP_SAVE,
    VIR_NETDEV_VPORT_PROFILE_OP_RESTORE,
    VIR_NETDEV_VPORT_PROFILE_OP_DESTROY,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_OUT,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_START,
    VIR_NETDEV_VPORT_PROFILE_OP_MIGRATE_IN_FINISH,
    VIR_NETDEV_VPORT_PROFILE_OP_NO_OP,

    VIR_NETDEV_VPORT_PROFILE_OP_LAST
};
VIR_ENUM_DECL(virNetDevVPortProfileOp)

/* profile data for macvtap (VEPA) and openvswitch */
typedef struct _virNetDevVPortProfile virNetDevVPortProfile;
typedef virNetDevVPortProfile *virNetDevVPortProfilePtr;
struct _virNetDevVPortProfile {
    enum virNetDevVPortProfile   virtPortType;
    union {
        struct {
            uint8_t       managerID;
            uint32_t      typeID; /* 24 bit valid */
            uint8_t       typeIDVersion;
            unsigned char instanceID[VIR_UUID_BUFLEN];
        } virtPort8021Qbg;
        struct {
            char          profileID[LIBVIRT_IFLA_VF_PORT_PROFILE_MAX];
        } virtPort8021Qbh;
        struct {
            unsigned char interfaceID[VIR_UUID_BUFLEN];
            char          profileID[LIBVIRT_IFLA_VF_PORT_PROFILE_MAX];
        } openvswitch;
    } u;
};


bool virNetDevVPortProfileEqual(virNetDevVPortProfilePtr a,
                                virNetDevVPortProfilePtr b);

int virNetDevVPortProfileAssociate(const char *ifname,
                                   const virNetDevVPortProfilePtr virtPort,
                                   const unsigned char *macaddr,
                                   const char *linkdev,
                                   int vf,
                                   const unsigned char *vmuuid,
                                   enum virNetDevVPortProfileOp vmOp,
                                   bool setlink_only)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(6)
    ATTRIBUTE_RETURN_CHECK;

int virNetDevVPortProfileDisassociate(const char *ifname,
                                      const virNetDevVPortProfilePtr virtPort,
                                      const unsigned char *macaddr,
                                      const char *linkdev,
                                      int vf,
                                      enum virNetDevVPortProfileOp vmOp)
    ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
    ATTRIBUTE_RETURN_CHECK;


#endif /* __VIR_NETDEV_VPORT_PROFILE_H__ */
