/*
 * Copyright (C) 2012 Nicira, Inc.
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
 *     Dan Wendlandt <dan@nicira.com>
 *     Kyle Mestery <kmestery@cisco.com>
 *     Ansis Atteka <aatteka@nicira.com>
 */

#include <config.h>

#include "virnetdevopenvswitch.h"
#include "command.h"
#include "memory.h"
#include "virterror_internal.h"
#include "virmacaddr.h"

#define VIR_FROM_THIS VIR_FROM_NONE

/**
 * virNetDevOpenvswitchAddPort:
 * @brname: the bridge name
 * @ifname: the network interface name
 * @macaddr: the mac address of the virtual interface
 * @vmuuid: the Domain UUID that has this interface
 * @ovsport: the ovs specific fields
 *
 * Add an interface to the OVS bridge
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
int virNetDevOpenvswitchAddPort(const char *brname, const char *ifname,
                                   const unsigned char *macaddr,
                                   const unsigned char *vmuuid,
                                   virNetDevVPortProfilePtr ovsport)
{
    int ret = -1;
    virCommandPtr cmd = NULL;
    char macaddrstr[VIR_MAC_STRING_BUFLEN];
    char ifuuidstr[VIR_UUID_STRING_BUFLEN];
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    char *attachedmac_ex_id = NULL;
    char *ifaceid_ex_id = NULL;
    char *profile_ex_id = NULL;
    char *vmid_ex_id = NULL;

    virMacAddrFormat(macaddr, macaddrstr);
    virUUIDFormat(ovsport->u.openvswitch.interfaceID, ifuuidstr);
    virUUIDFormat(vmuuid, vmuuidstr);

    if (virAsprintf(&attachedmac_ex_id, "external-ids:attached-mac=\"%s\"",
                    macaddrstr) < 0)
        goto out_of_memory;
    if (virAsprintf(&ifaceid_ex_id, "external-ids:iface-id=\"%s\"",
                    ifuuidstr) < 0)
        goto out_of_memory;
    if (virAsprintf(&vmid_ex_id, "external-ids:vm-id=\"%s\"",
                    vmuuidstr) < 0)
        goto out_of_memory;
    if (ovsport->u.openvswitch.profileID[0] != '\0') {
        if (virAsprintf(&profile_ex_id, "external-ids:port-profile=\"%s\"",
                        ovsport->u.openvswitch.profileID) < 0)
            goto out_of_memory;
    }

    cmd = virCommandNew(OVSVSCTL);
    if (ovsport->u.openvswitch.profileID[0] == '\0') {
        virCommandAddArgList(cmd, "--", "--may-exist", "add-port",
                        brname, ifname,
                        "--", "set", "Interface", ifname, attachedmac_ex_id,
                        "--", "set", "Interface", ifname, ifaceid_ex_id,
                        "--", "set", "Interface", ifname, vmid_ex_id,
                        "--", "set", "Interface", ifname,
                        "external-ids:iface-status=active",
                        NULL);
    } else {
        virCommandAddArgList(cmd, "--", "--may-exist", "add-port",
                        brname, ifname,
                        "--", "set", "Interface", ifname, attachedmac_ex_id,
                        "--", "set", "Interface", ifname, ifaceid_ex_id,
                        "--", "set", "Interface", ifname, vmid_ex_id,
                        "--", "set", "Interface", ifname, profile_ex_id,
                        "--", "set", "Interface", ifname,
                        "external-ids:iface-status=active",
                        NULL);
    }

    if (virCommandRun(cmd, NULL) < 0) {
        virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to add port %s to OVS bridge %s"),
                             ifname, brname);
        goto cleanup;
    }

    ret = 0;
cleanup:
    VIR_FREE(attachedmac_ex_id);
    VIR_FREE(ifaceid_ex_id);
    VIR_FREE(vmid_ex_id);
    VIR_FREE(profile_ex_id);
    virCommandFree(cmd);
    return ret;

out_of_memory:
    virReportOOMError();
    goto cleanup;
}

/**
 * virNetDevOpenvswitchRemovePort:
 * @ifname: the network interface name
 *
 * Deletes an interface from a OVS bridge
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
int virNetDevOpenvswitchRemovePort(const char *brname ATTRIBUTE_UNUSED, const char *ifname)
{
    int ret = -1;
    virCommandPtr cmd = NULL;

    cmd = virCommandNew(OVSVSCTL);
    virCommandAddArgList(cmd, "--", "--if-exists", "del-port", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to delete port %s from OVS"), ifname);
        goto cleanup;
    }
    ret = 0;

    cleanup:
        virCommandFree(cmd);
        return ret;
}
