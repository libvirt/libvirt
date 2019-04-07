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
 */

#include <config.h>


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
 * virNetDevOpenvswitchConstructVlans:
 * @cmd: command to construct
 * @virtVlan: VLAN configuration to be applied
 *
 * Construct the VLAN configuration parameters to be passed to
 * ovs-vsctl command.
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
static int
virNetDevOpenvswitchConstructVlans(virCommandPtr cmd, virNetDevVlanPtr virtVlan)
{
    int ret = -1;
    size_t i = 0;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!virtVlan || !virtVlan->nTags)
        return 0;

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

    ret = 0;
 cleanup:
    virBufferFreeAndReset(&buf);
    return ret;
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
    char macaddrstr[VIR_MAC_STRING_BUFLEN];
    char ifuuidstr[VIR_UUID_STRING_BUFLEN];
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) attachedmac_ex_id = NULL;
    VIR_AUTOFREE(char *) ifaceid_ex_id = NULL;
    VIR_AUTOFREE(char *) profile_ex_id = NULL;
    VIR_AUTOFREE(char *) vmid_ex_id = NULL;

    virMacAddrFormat(macaddr, macaddrstr);
    virUUIDFormat(ovsport->interfaceID, ifuuidstr);
    virUUIDFormat(vmuuid, vmuuidstr);

    if (virAsprintf(&attachedmac_ex_id, "external-ids:attached-mac=\"%s\"",
                    macaddrstr) < 0)
        return -1;
    if (virAsprintf(&ifaceid_ex_id, "external-ids:iface-id=\"%s\"",
                    ifuuidstr) < 0)
        return -1;
    if (virAsprintf(&vmid_ex_id, "external-ids:vm-id=\"%s\"",
                    vmuuidstr) < 0)
        return -1;
    if (ovsport->profileID[0] != '\0') {
        if (virAsprintf(&profile_ex_id, "external-ids:port-profile=\"%s\"",
                        ovsport->profileID) < 0)
            return -1;
    }

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "--", "--if-exists", "del-port",
                         ifname, "--", "add-port", brname, ifname, NULL);

    if (virNetDevOpenvswitchConstructVlans(cmd, virtVlan) < 0)
        return -1;

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
        return -1;
    }

    return 0;
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
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "--", "--if-exists", "del-port", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to delete port %s from OVS"), ifname);
        return -1;
    }

    return 0;
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
    size_t len;
    VIR_AUTOPTR(virCommand) cmd = NULL;

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
        return -1;
    }

    /* Wipeout the newline, if it exists */
    len = strlen(*migrate);
    if (len > 0)
        (*migrate)[len - 1] = '\0';

    return 0;
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
    VIR_AUTOPTR(virCommand) cmd = NULL;

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
        return -1;
    }

    return 0;
}

/**
 * virNetDevOpenvswitchInterfaceStats:
 * @ifname: the name of the interface
 * @stats: the retrieved domain interface stat
 *
 * Retrieves the OVS interfaces stats
 *
 * Returns 0 in case of success or -1 in case of failure
 */
int
virNetDevOpenvswitchInterfaceStats(const char *ifname,
                                   virDomainInterfaceStatsPtr stats)
{
    char *tmp;
    bool gotStats = false;
    VIR_AUTOPTR(virCommand) cmd = NULL;
    VIR_AUTOFREE(char *) output = NULL;

    /* Just ensure the interface exists in ovs */
    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "get", "Interface", ifname, "name", NULL);
    virCommandSetOutputBuffer(cmd, &output);

    if (virCommandRun(cmd, NULL) < 0) {
        /* no ovs-vsctl or interface 'ifname' doesn't exists in ovs */
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface not found"));
        return -1;
    }

#define GET_STAT(name, member) \
    do { \
        VIR_FREE(output); \
        virCommandFree(cmd); \
        cmd = virCommandNew(OVSVSCTL); \
        virNetDevOpenvswitchAddTimeout(cmd); \
        virCommandAddArgList(cmd, "--if-exists", "get", "Interface", \
                             ifname, "statistics:" name, NULL); \
        virCommandSetOutputBuffer(cmd, &output); \
        if (virCommandRun(cmd, NULL) < 0 || !output || !*output || *output == '\n') { \
            stats->member = -1; \
        } else { \
            if (virStrToLong_ll(output, &tmp, 10, &stats->member) < 0 || \
                *tmp != '\n') { \
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s", \
                               _("Fail to parse ovs-vsctl output")); \
                return -1; \
            } \
            gotStats = true; \
        } \
    } while (0)

    /* The TX/RX fields appear to be swapped here
     * because this is the host view. */
    GET_STAT("rx_bytes", tx_bytes);
    GET_STAT("rx_packets", tx_packets);
    GET_STAT("rx_errors", tx_errs);
    GET_STAT("rx_dropped", tx_drop);
    GET_STAT("tx_bytes", rx_bytes);
    GET_STAT("tx_packets", rx_packets);
    GET_STAT("tx_errors", rx_errs);
    GET_STAT("tx_dropped", rx_drop);

    if (!gotStats) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Interface doesn't have any statistics"));
        return -1;
    }

    return 0;
}


/**
 * virNetDeOpenvswitchGetMaster:
 * @ifname: name of interface we're interested in
 * @master: used to return a string containing the name of @ifname's "master"
 *          (this is the bridge or bond device that this device is attached to)
 *
 * Returns 0 on success, -1 on failure (if @ifname has no master
 * @master will be NULL, but return value will still be 0 (success)).
 *
 * NB: This function is needed because the IFLA_MASTER attribute of an
 * interface in a netlink dump (see virNetDevGetMaster()) will always
 * return "ovs-system" for any interface that is attached to an OVS
 * switch. When that happens, virNetDevOpenvswitchInterfaceGetMaster()
 * must be called to get the "real" master of the interface.
 */
int
virNetDevOpenvswitchInterfaceGetMaster(const char *ifname, char **master)
{
    virCommandPtr cmd = NULL;
    int exitstatus;

    *master = NULL;

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd, "iface-to-br", ifname, NULL);
    virCommandSetOutputBuffer(cmd, master);

    if (virCommandRun(cmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to get OVS master for "
                         "interface %s"), ifname);
        return -1;
    }

    /* non-0 exit code just means that the interface has no master in OVS */
    if (exitstatus != 0)
        VIR_FREE(*master);

    if (*master) {
        /* truncate at the first newline */
        char *nl = strchr(*master, '\n');
        if (nl)
            *nl = '\0';
    }

    VIR_DEBUG("OVS master for %s is %s", ifname, *master ? *master : "(none)");

    return 0;
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
    char *tmpIfname = NULL;
    char **tokens = NULL;
    size_t ntokens = 0;
    int status;
    int ret = -1;
    VIR_AUTOPTR(virCommand) cmd = NULL;

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
    return ret;
}

/**
 * virNetDevOpenvswitchUpdateVlan:
 * @ifname: the network interface name
 * @virtVlan: VLAN configuration to be applied
 *
 * Update VLAN configuration of an OVS port.
 *
 * Returns 0 in case of success or -1 in case of failure.
 */
int virNetDevOpenvswitchUpdateVlan(const char *ifname,
                                   virNetDevVlanPtr virtVlan)
{
    VIR_AUTOPTR(virCommand) cmd = NULL;

    cmd = virCommandNew(OVSVSCTL);
    virNetDevOpenvswitchAddTimeout(cmd);
    virCommandAddArgList(cmd,
                         "--", "--if-exists", "clear", "Port", ifname, "tag",
                         "--", "--if-exists", "clear", "Port", ifname, "trunk",
                         "--", "--if-exists", "clear", "Port", ifname, "vlan_mode",
                         "--", "--if-exists", "set", "Port", ifname, NULL);

    if (virNetDevOpenvswitchConstructVlans(cmd, virtVlan) < 0)
        return -1;

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to set vlan configuration on port %s"), ifname);
        return -1;
    }

    return 0;
}
