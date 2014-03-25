/*
 * Copyright (C) 2013 Red Hat, Inc.
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
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virmacaddr.h"
#include "virstring.h"

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
                                   const virMacAddr *macaddr,
                                   const unsigned char *vmuuid,
                                   virNetDevVPortProfilePtr ovsport,
                                   virNetDevVlanPtr virtVlan)
{
    int ret = -1;
    size_t i = 0;
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
        goto cleanup;
    if (virAsprintf(&ifaceid_ex_id, "external-ids:iface-id=\"%s\"",
                    ifuuidstr) < 0)
        goto cleanup;
    if (virAsprintf(&vmid_ex_id, "external-ids:vm-id=\"%s\"",
                    vmuuidstr) < 0)
        goto cleanup;
    if (ovsport->profileID[0] != '\0') {
        if (virAsprintf(&profile_ex_id, "external-ids:port-profile=\"%s\"",
                        ovsport->profileID) < 0)
            goto cleanup;
    }

    cmd = virCommandNew(OVSVSCTL);

    virCommandAddArgList(cmd, "--timeout=5", "--", "--may-exist", "add-port",
                        brname, ifname, NULL);

    if (virtVlan && virtVlan->nTags > 0) {

        switch (virtVlan->nativeMode) {
        case VIR_NATIVE_VLAN_MODE_TAGGED:
            virCommandAddArg(cmd, "vlan_mode=native-tagged");
            virCommandAddArgFormat(cmd, "tag=%d", virtVlan->nativeTag);
            break;
        case VIR_NATIVE_VLAN_MODE_UNTAGGED:
            virCommandAddArg(cmd, "vlan_mode=native-untagged");
            virCommandAddArgFormat(cmd, "tag=%d", virtVlan->nativeTag);
            break;
        case VIR_NATIVE_VLAN_MODE_DEFAULT:
        default:
            break;
        }

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

            if (virBufferError(&buf)) {
                virReportOOMError();
                goto cleanup;
            }
            virCommandAddArg(cmd, virBufferCurrentContent(&buf));
        } else if (virtVlan->nTags) {
            virCommandAddArgFormat(cmd, "tag=%d", virtVlan->tag[0]);
        }
    }

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

/**
 * virNetDevOpenvswitchGetMigrateData:
 * @migrate: a pointer to store the data into, allocated by this function
 * @ifname: name of the interface for which data is being migrated
 *
 * Allocates data to be migrated specific to Open vSwitch
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int virNetDevOpenvswitchGetMigrateData(char **migrate, const char *ifname)
{
    virCommandPtr cmd = NULL;
    int ret = -1;

    cmd = virCommandNewArgList(OVSVSCTL, "--timeout=5", "get", "Interface",
                               ifname, "external_ids:PortData", NULL);

    virCommandSetOutputBuffer(cmd, migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to run command to get OVS port data for "
                             "interface %s"), ifname);
        goto cleanup;
    }

    /* Wipeout the newline */
    (*migrate)[strlen(*migrate) - 1] = '\0';
    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevOpenvswitchSetMigrateData:
 * @migrate: the data which was transferred during migration
 * @ifname: the name of the interface the data is associated with
 *
 * Repopulates OVS per-port data on destination host
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int virNetDevOpenvswitchSetMigrateData(char *migrate, const char *ifname)
{
    virCommandPtr cmd = NULL;
    int ret = -1;

    cmd = virCommandNewArgList(OVSVSCTL, "--timeout=5", "set",
                               "Interface", ifname, NULL);
    virCommandAddArgFormat(cmd, "external_ids:PortData=%s", migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportSystemError(VIR_ERR_INTERNAL_ERROR,
                             _("Unable to run command to set OVS port data for "
                             "interface %s"), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}
