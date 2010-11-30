/*
 * Copyright (C) 2010 IBM Corporation
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
 */

#ifndef __UTIL_MACVTAP_H__
# define __UTIL_MACVTAP_H__

# include <config.h>


enum virVirtualPortType {
    VIR_VIRTUALPORT_NONE,
    VIR_VIRTUALPORT_8021QBG,
    VIR_VIRTUALPORT_8021QBH,

    VIR_VIRTUALPORT_TYPE_LAST,
};

# ifdef IFLA_VF_PORT_PROFILE_MAX
#  define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX IFLA_VF_PORT_PROFILE_MAX
# else
#  define LIBVIRT_IFLA_VF_PORT_PROFILE_MAX 40
# endif

/* profile data for macvtap (VEPA) */
typedef struct _virVirtualPortProfileParams virVirtualPortProfileParams;
typedef virVirtualPortProfileParams *virVirtualPortProfileParamsPtr;
struct _virVirtualPortProfileParams {
    enum virVirtualPortType   virtPortType;
    union {
        struct {
            uint8_t       managerID;
            uint32_t      typeID; // 24 bit valid
            uint8_t       typeIDVersion;
            unsigned char instanceID[VIR_UUID_BUFLEN];
        } virtPort8021Qbg;
        struct {
            char          profileID[LIBVIRT_IFLA_VF_PORT_PROFILE_MAX];
        } virtPort8021Qbh;
    } u;
};


# if defined(WITH_MACVTAP)

#  include "internal.h"

enum virVMOperationType {
    VIR_VM_OP_CREATE,
    VIR_VM_OP_SAVE,
    VIR_VM_OP_RESTORE,
    VIR_VM_OP_DESTROY,
    VIR_VM_OP_MIGRATE_OUT,
    VIR_VM_OP_MIGRATE_IN_START,
    VIR_VM_OP_MIGRATE_IN_FINISH,
    VIR_VM_OP_NO_OP,

    VIR_VM_OP_LAST
};

int openMacvtapTap(const char *ifname,
                   const unsigned char *macaddress,
                   const char *linkdev,
                   int mode,
                   int vnet_hdr,
                   const unsigned char *vmuuid,
                   virVirtualPortProfileParamsPtr virtPortProfile,
                   char **res_ifname,
                   enum virVMOperationType vmop);

void delMacvtap(const char *ifname,
                const unsigned char *macaddress,
                const char *linkdev,
                virVirtualPortProfileParamsPtr virtPortProfile);

# endif /* WITH_MACVTAP */

# define MACVTAP_MODE_PRIVATE_STR  "private"
# define MACVTAP_MODE_VEPA_STR     "vepa"
# define MACVTAP_MODE_BRIDGE_STR   "bridge"

int vpAssociatePortProfileId(const char *macvtap_ifname,
                             const unsigned char *macvtap_macaddr,
                             const char *linkdev,
                             const virVirtualPortProfileParamsPtr virtPort,
                             const unsigned char *vmuuid,
                             enum virVMOperationType vmOp);

int vpDisassociatePortProfileId(const char *macvtap_ifname,
                                const unsigned char *macvtap_macaddr,
                                const char *linkdev,
                                const virVirtualPortProfileParamsPtr virtPort,
                                enum virVMOperationType vmOp);

VIR_ENUM_DECL(virVirtualPort)
VIR_ENUM_DECL(virVMOperation)

#endif /* __UTIL_MACVTAP_H__ */
