/*
 * Copyright (C) 2013 Red Hat, Inc.
 * Copyright (C) 2012 Nicira, Inc.
 * Copyright (C) 2017 IBM Corporation
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
 *     Boris Fiuczynski <fiuczy@linux.vnet.ibm.com>
 */

#include <config.h>

#include <stdio.h>

#include "virnetdevopenvswitch.h"
#include "vircommand.h"
#include "viralloc.h"
#include "virerror.h"
#include "virmacaddr.h"
#include "virstring.h"
#include "virlog.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevopenvswitch");

/*
 * Set openvswitch default timout
 */
static unsigned int virNetDevOpenvswitchTimeout = VIR_NETDEV_OVS_DEFAULT_TIMEOUT;

/**
 * virNetDevOpenvswitchSetTimeout:
 * @timeout: the timeout in seconds
 *
 * Set the openvswitch timeout
 */
void
virNetDevOpenvswitchSetTimeout(unsigned int timeout)
{
    virNetDevOpenvswitchTimeout = timeout;
}

static void
virNetDevOpenvswitchAddTimeout(virCommandPtr cmd)
{
    virCommandAddArgFormat(cmd, "--timeout=%u", virNetDevOpenvswitchTimeout);
}

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
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "--", "--if-exists", "del-port",
                         ifname, "--", "add-port", brname, ifname, NULL);

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

            if (virBufferCheckError(&buf) < 0)
                goto cleanup;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "--", "--if-exists", "del-port", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
    size_t len;
    int ret = -1;

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "--if-exists", "get", "Interface",
                         ifname, "external_ids:PortData", NULL);

    virCommandSetOutputBuffer(cmd, migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to get OVS port data for "
                         "interface %s"), ifname);
        goto cleanup;
    }

    /* Wipeout the newline, if it exists */
    len = strlen(*migrate);
    if (len > 0)
        (*migrate)[len - 1] = '\0';

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

    if (!migrate) {
        VIR_DEBUG("No OVS port data for interface %s", ifname);
        return 0;
    }

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "set", "Interface", ifname, NULL);
    virCommandAddArgFormat(cmd, "external_ids:PortData=%s", migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to set OVS port data for "
                         "interface %s"), ifname);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevOpenvswitchInterfaceStats:
 * @ifname: the name of the interface
 * @stats: the retreived domain interface stat
 *
 * Retrieves the OVS interfaces stats
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int
virNetDevOpenvswitchInterfaceStats(const char *ifname,
                                   virDomainInterfaceStatsPtr stats)
{
    virCommandPtr cmd = NULL;
    char *output;
    long long rx_bytes;
    long long rx_packets;
    long long tx_bytes;
    long long tx_packets;
    long long rx_errs;
    long long rx_drop;
    long long tx_errs;
    long long tx_drop;
    int ret = -1;

    /* Just ensure the interface exists in ovs */
    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "get", "Interface", ifname, "name", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0) {
        /* no ovs-vsctl or interface 'ifname' doesn't exists in ovs */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface not found"));
        goto cleanup;
    }

    VIR_FREE(output);
    virCommandFree(cmd);

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "get", "Interface", ifname,
                         "statistics:rx_bytes",
                         "statistics:rx_packets",
                         "statistics:tx_bytes",
                         "statistics:tx_packets", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface doesn't have statistics"));
        goto cleanup;
    }

    /* The TX/RX fields appear to be swapped here
     * because this is the host view. */
    if (sscanf(output, "%lld\n%lld\n%lld\n%lld\n",
               &tx_bytes, &tx_packets, &rx_bytes, &rx_packets) != 4) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Fail to parse ovs-vsctl output"));
        goto cleanup;
    }

    stats->rx_bytes = rx_bytes;
    stats->rx_packets = rx_packets;
    stats->tx_bytes = tx_bytes;
    stats->tx_packets = tx_packets;

    VIR_FREE(output);
    virCommandFree(cmd);

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "get", "Interface", ifname,
                         "statistics:rx_errors",
                         "statistics:rx_dropped",
                         "statistics:tx_errors",
                         "statistics:tx_dropped", NULL);
    virCommandSetOutputBuffer(cmd, &output);
    if (virCommandRun(cmd, NULL) < 0) {
        /* This interface don't have errors or dropped, so set them to 0 */
        stats->rx_errs = 0;
        stats->rx_drop = 0;
        stats->tx_errs = 0;
        stats->tx_drop = 0;
    } else if (sscanf(output, "%lld\n%lld\n%lld\n%lld\n",
                      &tx_errs, &tx_drop, &rx_errs, &rx_drop) == 4) {
        stats->rx_errs = rx_errs;
        stats->rx_drop = rx_drop;
        stats->tx_errs = tx_errs;
        stats->tx_drop = tx_drop;
        ret = 0;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Fail to parse ovs-vsctl output"));
        goto cleanup;
    }
    ret = 0;

 cleanup:
    VIR_FREE(output);
    virCommandFree(cmd);
    return ret;
}

/**
 * virNetDevOpenvswitchVhostuserGetIfname:
 * @path: the path of the unix socket
 * @ifname: the retrieved name of the interface
 *
 * Retreives the ovs ifname from vhostuser unix socket path.
 *
 * Returns: 1 if interface is an openvswitch interface,
 *          0 if it is not, but no other error occurred,
 *         -1 otherwise.
 */
int
virNetDevOpenvswitchGetVhostuserIfname(const char *path,
                                       char **ifname)
{
    virCommandPtr cmd = NULL;
    char *tmpIfname = NULL;
    char **tokens = NULL;
    size_t ntokens = 0;
    int status;
    int ret = -1;
    char *ovs_timeout = NULL;

    /* Openvswitch vhostuser path are hardcoded to
     * /<runstatedir>/openvswitch/<ifname>
     * for example: /var/run/openvswitch/dpdkvhostuser0
     *
     * so we pick the filename and check it's a openvswitch interface
     */
    if (!path ||
        !(tmpIfname = strrchr(path, '/'))) {
        ret = 0;
        goto cleanup;
    }

    tmpIfname++;
    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "get", "Interface", tmpIfname, "name", NULL);
    if (virCommandRun(cmd, &status) < 0 ||
        status) {
        /* it's not a openvswitch vhostuser interface. */
        ret = 0;
        goto cleanup;
    }

    if (VIR_STRDUP(*ifname, tmpIfname) < 0)
        goto cleanup;
    ret = 1;

 cleanup:
    virStringListFreeCount(tokens, ntokens);
    virCommandFree(cmd);
    VIR_FREE(ovs_timeout);
    return ret;
}
