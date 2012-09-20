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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
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
                                   const virMacAddrPtr macaddr,
                                   const unsigned char *vmuuid,
                                   virNetDevVPortProfilePtr ovsport,
                                   virNetDevVlanPtr virtVlan)
{
    int ret = -1;
    int i = 0;
    virCommandPtr cmd = NULL;
    char macaddrstr[VIR_MAC_STRING_BUFLEN];
    char ifuuidstr[VIR_UUID_STRING_BUFLEN];
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    char *attachedmac_ex_id = NULL;
    char *ifaceid_ex_id = NULL;
    char *profile_ex_id = NULL;
    char *vmid_ex_id = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virMacAddrFormat(macaddr, macaddrstr);
    virUUIDFormat(ovsport->interfaceID, ifuuidstr);
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
    if (ovsport->profileID[0] != '\0') {
        if (virAsprintf(&profile_ex_id, "external-ids:port-profile=\"%s\"",
                        ovsport->profileID) < 0)
            goto out_of_memory;
    }

    if (virtVlan && virtVlan->nTags > 0) {

        /* Trunk port first */
        if (virtVlan->trunk) {
            virBufferAddLit(&buf, "trunk=");

            /*
             * Trunk ports have at least one VLAN. Do the first one
             * outside the "for" loop so we can put a "," at the
             * start of the for loop if there are more than one VLANs
             * on this trunk port.
             */
            virBufferAsprintf(&buf, "%d", virtVlan->tag[i]);

            for (i = 1; i < virtVlan->nTags; i++) {
                virBufferAddLit(&buf, ",");
                virBufferAsprintf(&buf, "%d", virtVlan->tag[i]);
            }
        } else if (virtVlan->nTags) {
            virBufferAsprintf(&buf, "tag=%d", virtVlan->tag[0]);
        }
    }

    cmd = virCommandNew(OVSVSCTL);

    virCommandAddArgList(cmd, "--timeout=5", "--", "--may-exist", "add-port",
                        brname, ifname, NULL);

    if (virBufferUse(&buf) != 0)
        virCommandAddArgList(cmd, virBufferCurrentContent(&buf), NULL);

    if (ovsport->profileID[0] == '\0') {
        virCommandAddArgList(cmd,
                        "--", "set", "Interface", ifname, attachedmac_ex_id,
                        "--", "set", "Interface", ifname, ifaceid_ex_id,
                        "--", "set", "Interface", ifname, vmid_ex_id,
                        "--", "set", "Interface", ifname,
                        "external-ids:iface-status=active",
                        NULL);
    } else {
        virCommandAddArgList(cmd,
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
    virBufferFreeAndReset(&buf);
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
    virCommandAddArgList(cmd, "--timeout=5", "--", "--if-exists", "del-port", ifname, NULL);

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
