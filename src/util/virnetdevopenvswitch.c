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
#include "virjson.h"
#include "virfile.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("util.netdevopenvswitch");

/*
 * Set openvswitch default timeout
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

static virCommand *
virNetDevOpenvswitchCreateCmd(char **errbuf)
{
    virCommand *cmd = virCommandNew(OVS_VSCTL);

    virCommandAddArgFormat(cmd, "--timeout=%u", virNetDevOpenvswitchTimeout);
    if (errbuf)
        virCommandSetErrorBuffer(cmd, errbuf);

    return cmd;
}

/**
 * virNetDevOpenvswitchConstructVlans:
 * @cmd: command to construct
 * @virtVlan: VLAN configuration to be applied
 *
 * Construct the VLAN configuration parameters to be passed to
 * ovs-vsctl command.
 */
static void
virNetDevOpenvswitchConstructVlans(virCommand *cmd, const virNetDevVlan *virtVlan)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;

    if (!virtVlan || !virtVlan->nTags)
        return;

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
        size_t i;

        virBufferAddLit(&buf, "trunk=");

        /*
         * Trunk ports have at least one VLAN. Do the first one
         * outside the "for" loop so we can put a "," at the
         * start of the for loop if there are more than one VLANs
         * on this trunk port.
         */
        virBufferAsprintf(&buf, "%d", virtVlan->tag[0]);

        for (i = 1; i < virtVlan->nTags; i++) {
            virBufferAddLit(&buf, ",");
            virBufferAsprintf(&buf, "%d", virtVlan->tag[i]);
        }

        virCommandAddArg(cmd, virBufferCurrentContent(&buf));
    } else if (virtVlan->nTags) {
        virCommandAddArgFormat(cmd, "tag=%d", virtVlan->tag[0]);
    }
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
                                const virNetDevVPortProfile *ovsport,
                                const virNetDevVlan *virtVlan)
{
    char macaddrstr[VIR_MAC_STRING_BUFLEN];
    char ifuuidstr[VIR_UUID_STRING_BUFLEN];
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;
    g_autofree char *attachedmac_ex_id = NULL;
    g_autofree char *ifaceid_ex_id = NULL;
    g_autofree char *profile_ex_id = NULL;
    g_autofree char *vmid_ex_id = NULL;
    g_autofree char *ifname_ex_id = NULL;

    virMacAddrFormat(macaddr, macaddrstr);
    virUUIDFormat(ovsport->interfaceID, ifuuidstr);
    virUUIDFormat(vmuuid, vmuuidstr);

    attachedmac_ex_id = g_strdup_printf("external-ids:attached-mac=\"%s\"",
                                        macaddrstr);
    ifaceid_ex_id = g_strdup_printf("external-ids:iface-id=\"%s\"", ifuuidstr);
    vmid_ex_id = g_strdup_printf("external-ids:vm-id=\"%s\"", vmuuidstr);
    ifname_ex_id = g_strdup_printf("external-ids:ifname=\"%s\"", ifname);
    if (ovsport->profileID[0] != '\0') {
        profile_ex_id = g_strdup_printf("external-ids:port-profile=\"%s\"",
                                        ovsport->profileID);
    }

    cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    virCommandAddArgList(cmd, "--", "--may-exist",
                         "add-port", brname, ifname, NULL);

    virNetDevOpenvswitchConstructVlans(cmd, virtVlan);

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
                             "--", "set", "Interface", ifname, ifname_ex_id,
                             "--", "set", "Interface", ifname,
                             "external-ids:iface-status=active",
                             NULL);
    }

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to add port %1$s to OVS bridge %2$s: %3$s"),
                       ifname, brname, NULLSTR(errbuf));
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
int virNetDevOpenvswitchRemovePort(const char *brname G_GNUC_UNUSED, const char *ifname)
{
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(&errbuf);

    virCommandAddArgList(cmd, "--", "--if-exists", "del-port", ifname, NULL);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to delete port %1$s from OVS: %2$s"),
                       ifname, NULLSTR(errbuf));
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
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(&errbuf);

    virCommandAddArgList(cmd, "--if-exists", "get", "Interface",
                         ifname, "external_ids:PortData", NULL);

    virCommandSetOutputBuffer(cmd, migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to get OVS port data for interface %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
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
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;

    if (!migrate) {
        VIR_DEBUG("No OVS port data for interface %s", ifname);
        return 0;
    }

    cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    virCommandAddArgList(cmd, "set", "Interface", ifname, NULL);
    virCommandAddArgFormat(cmd, "external_ids:PortData=%s", migrate);

    /* Run the command */
    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to set OVS port data for interface %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
        return -1;
    }

    return 0;
}


/**
 * virNetDevOpenvswitchInterfaceParseStats:
 * @json: Input string in JSON format
 * @stats: parsed stats
 *
 * For given input string @json parse interface statistics and store them into
 * @stats.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported).
 */
int
virNetDevOpenvswitchInterfaceParseStats(const char *json,
                                        virDomainInterfaceStatsPtr stats)
{
    g_autoptr(virJSONValue) jsonStats = NULL;
    virJSONValue *jsonMap = NULL;
    size_t i;

    stats->rx_bytes = stats->rx_packets = stats->rx_errs = stats->rx_drop = -1;
    stats->tx_bytes = stats->tx_packets = stats->tx_errs = stats->tx_drop = -1;

    if (!(jsonStats = virJSONValueFromString(json)) ||
        !virJSONValueIsArray(jsonStats) ||
        !(jsonMap = virJSONValueArrayGet(jsonStats, 1))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to parse ovs-vsctl output"));
        return -1;
    }

    for (i = 0; i < virJSONValueArraySize(jsonMap); i++) {
        virJSONValue *item = virJSONValueArrayGet(jsonMap, i);
        virJSONValue *jsonKey;
        virJSONValue *jsonVal;
        const char *key;
        long long val;

        if (!item ||
            (!(jsonKey = virJSONValueArrayGet(item, 0))) ||
            (!(jsonVal = virJSONValueArrayGet(item, 1))) ||
            (!(key = virJSONValueGetString(jsonKey))) ||
            (virJSONValueGetNumberLong(jsonVal, &val) < 0)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Malformed ovs-vsctl output"));
            return -1;
        }

        /* The TX/RX fields appear to be swapped here
         * because this is the host view. */
        if (STREQ(key, "rx_bytes")) {
            stats->tx_bytes = val;
        } else if (STREQ(key, "rx_packets")) {
            stats->tx_packets = val;
        } else if (STREQ(key, "rx_errors")) {
            stats->tx_errs = val;
        } else if (STREQ(key, "rx_dropped")) {
            stats->tx_drop = val;
        } else if (STREQ(key, "tx_bytes")) {
            stats->rx_bytes = val;
        } else if (STREQ(key, "tx_packets")) {
            stats->rx_packets = val;
        } else if (STREQ(key, "tx_errors")) {
            stats->rx_errs = val;
        } else if (STREQ(key, "tx_dropped")) {
            stats->rx_drop = val;
        } else {
            VIR_DEBUG("Unused ovs-vsctl stat key=%s val=%lld", key, val);
        }
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
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    g_autofree char *output = NULL;

    virCommandAddArgList(cmd, "--if-exists", "--format=list", "--data=json",
                         "--no-headings", "--columns=statistics", "list",
                         "Interface", ifname, NULL);
    virCommandSetOutputBuffer(cmd, &output);

    /* The above command returns either:
     * 1) empty string if @ifname doesn't exist, or
     * 2) a JSON array, for instance:
     *    ["map",[["collisions",0],["rx_bytes",0],["rx_crc_err",0],["rx_dropped",0],
     *    ["rx_errors",0],["rx_frame_err",0],["rx_over_err",0],["rx_packets",0],
     *    ["tx_bytes",12406],["tx_dropped",0],["tx_errors",0],["tx_packets",173]]]
     */

    if (virCommandRun(cmd, NULL) < 0 ||
        STREQ_NULLABLE(output, "")) {
        /* no ovs-vsctl or interface 'ifname' doesn't exists in ovs */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Interface not found: %1$s"),
                       NULLSTR(errbuf));
        return -1;
    }

    if (virNetDevOpenvswitchInterfaceParseStats(output, stats) < 0)
        return -1;

    if (stats->rx_bytes == -1 &&
        stats->rx_packets == -1 &&
        stats->rx_errs == -1 &&
        stats->rx_drop == -1 &&
        stats->tx_bytes == -1 &&
        stats->tx_packets == -1 &&
        stats->tx_errs == -1 &&
        stats->tx_drop == -1) {
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
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    int exitstatus;

    *master = NULL;

    virCommandAddArgList(cmd, "iface-to-br", ifname, NULL);
    virCommandSetOutputBuffer(cmd, master);

    if (virCommandRun(cmd, &exitstatus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to run command to get OVS master for interface %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
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
 * virNetDevOpenvswitchMaybeUnescapeReply:
 * @reply: a string to unescape
 *
 * Depending on ovs-vsctl version a string might be escaped. For instance:
 *  -version 2.11.4 allows only is_alpha(), an underscore, a dash or a dot,
 *  -version 2.14.0 allows only is_alnum(), an underscore, a dash or a dot,
 * any other character causes the string to be escaped.
 *
 * What this function does, is it checks whether @reply string consists solely
 * from safe, not escaped characters (as defined by version 2.14.0) and if not
 * an error is reported. If @reply is a string enclosed in double quotes, but
 * otherwise safe those double quotes are removed.
 *
 * Returns: 0 on success,
 *         -1 otherwise (with error reported).
 */
int
virNetDevOpenvswitchMaybeUnescapeReply(char *reply)
{
    g_autoptr(virJSONValue) json = NULL;
    g_autofree char *jsonStr = NULL;
    const char *tmp = NULL;
    size_t replyLen = strlen(reply);

    if (*reply != '"')
        return 0;

    jsonStr = g_strdup_printf("{\"name\": %s}", reply);
    if (!(json = virJSONValueFromString(jsonStr)))
        return -1;

    if (!(tmp = virJSONValueObjectGetString(json, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Malformed ovs-vsctl output"));
        return -1;
    }

    return virStrcpy(reply, tmp, replyLen);
}


/**
 * virNetDevOpenvswitchGetVhostuserIfname:
 * @path: the path of the unix socket
 * @server: true if OVS creates the @path
 * @ifname: the retrieved name of the interface
 *
 * Retrieves the OVS ifname from vhostuser UNIX socket path.
 * There are two types of vhostuser ports which differ in client/server
 * role:
 *
 * dpdkvhostuser - OVS creates the socket and QEMU connects to it
 *                 (@server = true)
 * dpdkvhostuserclient - QEMU creates the socket and OVS connects to it
 *                       (@server = false)
 *
 * Since the way of retrieving ifname is different in these two cases,
 * caller must set @server according to the interface definition.
 *
 * Returns: 1 if interface is an openvswitch interface,
 *          0 if it is not, but no other error occurred,
 *         -1 otherwise.
 */
int
virNetDevOpenvswitchGetVhostuserIfname(const char *path,
                                       bool server,
                                       char **ifname)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *absoluteOvsVsctlPath = NULL;
    int status;

    if (!(absoluteOvsVsctlPath = virFindFileInPath(OVS_VSCTL))) {
        /* If there is no 'ovs-vsctl' then the interface is
         * probably not an OpenVSwitch interface and the @path to
         * socket was created by some DPDK testing script (e.g.
         * dpdk-testpmd). */
        return 0;
    }

    cmd = virNetDevOpenvswitchCreateCmd(NULL);

    if (server) {
        virCommandAddArgList(cmd, "--no-headings", "--columns=name", "find",
                             "Interface", NULL);
        virCommandAddArgPair(cmd, "options:vhost-server-path", path);
    } else {
        const char *tmpIfname = NULL;

        /* Openvswitch vhostuser path is hardcoded to
         * /<runstatedir>/openvswitch/<ifname>
         * for example: /var/run/openvswitch/dpdkvhostuser0
         *
         * so we pick the filename and check it's an openvswitch interface
         */
        if (!path ||
            !(tmpIfname = strrchr(path, '/'))) {
            return 0;
        }

        tmpIfname++;
        virCommandAddArgList(cmd, "get", "Interface", tmpIfname, "name", NULL);
    }

    virCommandSetOutputBuffer(cmd, ifname);
    if (virCommandRun(cmd, &status) < 0)
        return -1;

    if (status != 0) {
        /* it's not a openvswitch vhostuser interface. */
        return 0;
    }

    virStringTrimOptionalNewline(*ifname);
    if (virNetDevOpenvswitchMaybeUnescapeReply(*ifname) < 0) {
        VIR_FREE(*ifname);
        return -1;
    }

    return 1;
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
                                   const virNetDevVlan *virtVlan)
{
    g_autofree char *errbuf = NULL;
    g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(&errbuf);

    virCommandAddArgList(cmd,
                         "--", "--if-exists", "clear", "Port", ifname, "tag",
                         "--", "--if-exists", "clear", "Port", ifname, "trunk",
                         "--", "--if-exists", "clear", "Port", ifname, "vlan_mode", NULL);

    if (virtVlan && virtVlan->nTags > 0)
        virCommandAddArgList(cmd, "--", "--if-exists", "set", "Port", ifname, NULL);

    virNetDevOpenvswitchConstructVlans(cmd, virtVlan);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to set vlan configuration on port %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
        return -1;
    }

    return 0;
}

static char*
virNetDevOpenvswitchFindUUID(const char *table,
                             const char *vmid_ex_id,
                             const char *ifname_ex_id)
{
    g_autoptr(virCommand) cmd = NULL;
    char *uuid = NULL;

    cmd = virNetDevOpenvswitchCreateCmd(NULL);
    virCommandAddArgList(cmd, "--no-heading", "--columns=_uuid", "find", table,
                         vmid_ex_id, ifname_ex_id, NULL);
    virCommandSetOutputBuffer(cmd, &uuid);
    if (virCommandRun(cmd, NULL) < 0) {
        VIR_WARN("Unable to find queue on port with %s", ifname_ex_id);
    }
    return uuid;
}

static int
virNetDevOpenvswitchInterfaceClearTxQos(const char *ifname,
                                        const unsigned char *vmuuid)
{
    int ret = 0;
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    g_autofree char *ifname_ex_id = NULL;
    g_autofree char *vmid_ex_id = NULL;
    g_autofree char *qos_uuid = NULL;
    g_autofree char *queue_uuid = NULL;
    g_autofree char *port_qos = NULL;
    size_t i;

    /* find qos */
    virUUIDFormat(vmuuid, vmuuidstr);
    vmid_ex_id = g_strdup_printf("external-ids:vm-id=\"%s\"", vmuuidstr);
    ifname_ex_id = g_strdup_printf("external-ids:ifname=\"%s\"", ifname);
    /* find queue */
    queue_uuid = virNetDevOpenvswitchFindUUID("queue", vmid_ex_id, ifname_ex_id);
    /* find qos */
    qos_uuid = virNetDevOpenvswitchFindUUID("qos", vmid_ex_id, ifname_ex_id);

    if (qos_uuid && *qos_uuid) {
        g_auto(GStrv) lines = g_strsplit(qos_uuid, "\n", 0);

        /* destroy qos */
        for (i = 0; lines[i] != NULL; i++) {
            const char *line = lines[i];
            g_autoptr(virCommand) listcmd = NULL;
            g_autoptr(virCommand) destroycmd = NULL;

            if (!*line) {
                continue;
            }
            listcmd = virNetDevOpenvswitchCreateCmd(NULL);
            virCommandAddArgList(listcmd, "--no-heading", "--columns=_uuid", "--if-exists",
                                 "list", "port", ifname, "qos", NULL);
            virCommandSetOutputBuffer(listcmd, &port_qos);
            if (virCommandRun(listcmd, NULL) < 0) {
                VIR_WARN("Unable to remove port qos on port %s", ifname);
            }
            if (port_qos && *port_qos) {
                g_autoptr(virCommand) cmd = virNetDevOpenvswitchCreateCmd(NULL);
                virCommandAddArgList(cmd, "remove", "port", ifname, "qos", line, NULL);
                if (virCommandRun(cmd, NULL) < 0) {
                    VIR_WARN("Unable to remove port qos on port %s", ifname);
                }
            }
            destroycmd = virNetDevOpenvswitchCreateCmd(NULL);
            virCommandAddArgList(destroycmd, "destroy", "qos", line, NULL);
            if (virCommandRun(destroycmd, NULL) < 0) {
                VIR_WARN("Unable to destroy qos on port %s", ifname);
                ret = -1;
            }
        }
    }
    /* destroy queue */
    if (queue_uuid && *queue_uuid) {
        g_auto(GStrv) lines = g_strsplit(queue_uuid, "\n", 0);

        for (i = 0; lines[i] != NULL; i++) {
            g_autoptr(virCommand) cmd = NULL;
            const char *line = lines[i];
            if (!*line) {
                continue;
            }

            cmd = virNetDevOpenvswitchCreateCmd(NULL);
            virCommandAddArgList(cmd, "destroy", "queue", line, NULL);
            if (virCommandRun(cmd, NULL) < 0) {
                VIR_WARN("Unable to destroy queue on port %s", ifname);
                ret = -1;
            }
        }
    }

    return ret;
}

static int
virNetDevOpenvswitchInterfaceClearRxQos(const char *ifname)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;

    cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    virCommandAddArgList(cmd, "set", "Interface", ifname, NULL);
    virCommandAddArgFormat(cmd, "ingress_policing_rate=%llu", 0llu);
    virCommandAddArgFormat(cmd, "ingress_policing_burst=%llu", 0llu);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to reset ingress on port %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
        return -1;
    }

    return 0;
}

/*
 * In virNetDevBandwidthRate, average, peak, floor are in kilobyes and burst in
 * kibibytes. However other_config in ovs qos is in bits and
 * ingress_policing_rate in ovs interface is in kilobit and
 * ingress_policing_burst is in kibibits.
 */
#define KBYTE_TO_BITS(x) (x * 8000ULL)
#define KIBIBYTE_TO_BITS(x) (x * 8192ULL)
#define VIR_NETDEV_RX_TO_OVS 8

static int
virNetDevOpenvswitchInterfaceSetTxQos(const char *ifname,
                                      const virNetDevBandwidthRate *tx,
                                      const unsigned char *vmuuid)
{
    char vmuuidstr[VIR_UUID_STRING_BUFLEN];
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;
    g_autofree char *vmid_ex_id = NULL;
    g_autofree char *ifname_ex_id = NULL;
    g_autofree char *average = NULL;
    g_autofree char *peak = NULL;
    g_autofree char *burst = NULL;
    g_autofree char *qos_uuid = NULL;
    g_autofree char *queue_uuid = NULL;

    average = g_strdup_printf("%llu", KBYTE_TO_BITS(tx->average));
    if (tx->burst)
        burst = g_strdup_printf("%llu", KIBIBYTE_TO_BITS(tx->burst));
    if (tx->peak)
        peak = g_strdup_printf("%llu", KBYTE_TO_BITS(tx->peak));

    virUUIDFormat(vmuuid, vmuuidstr);
    vmid_ex_id = g_strdup_printf("external-ids:vm-id=\"%s\"", vmuuidstr);
    ifname_ex_id = g_strdup_printf("external-ids:ifname=\"%s\"", ifname);
    /* find queue */
    queue_uuid = virNetDevOpenvswitchFindUUID("queue", vmid_ex_id, ifname_ex_id);
    /* find qos */
    qos_uuid = virNetDevOpenvswitchFindUUID("qos", vmid_ex_id, ifname_ex_id);

    /* create qos and set */
    cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    if (queue_uuid && *queue_uuid) {
        g_auto(GStrv) lines = g_strsplit(queue_uuid, "\n", 0);
        virCommandAddArgList(cmd, "set", "queue", lines[0], NULL);
    } else {
        virCommandAddArgList(cmd, "set", "port", ifname, "qos=@qos1",
                             vmid_ex_id, ifname_ex_id,
                             "--", "--id=@qos1", "create", "qos", "type=linux-htb", NULL);
        virCommandAddArgFormat(cmd, "other_config:min-rate=%s", average);
        if (burst) {
            virCommandAddArgFormat(cmd, "other_config:burst=%s", burst);
        }
        if (peak) {
            virCommandAddArgFormat(cmd, "other_config:max-rate=%s", peak);
        }
        virCommandAddArgList(cmd, "queues:0=@queue0", vmid_ex_id, ifname_ex_id,
                             "--", "--id=@queue0", "create", "queue", NULL);
    }
    virCommandAddArgFormat(cmd, "other_config:min-rate=%s", average);
    if (burst) {
        virCommandAddArgFormat(cmd, "other_config:burst=%s", burst);
    }
    if (peak) {
        virCommandAddArgFormat(cmd, "other_config:max-rate=%s", peak);
    }
    virCommandAddArgList(cmd, vmid_ex_id, ifname_ex_id, NULL);
    if (virCommandRun(cmd, NULL) < 0) {
        if (queue_uuid && *queue_uuid) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to set queue configuration on port %1$s: %2$s"),
                           ifname, NULLSTR(errbuf));
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to create and set qos configuration on port %1$s: %2$s"),
                           ifname, NULLSTR(errbuf));
        }
        return -1;
    }

    if (qos_uuid && *qos_uuid) {
        g_auto(GStrv) lines = g_strsplit(qos_uuid, "\n", 0);
        g_autofree char *qoserrbuf = NULL;
        g_autoptr(virCommand) qoscmd = virNetDevOpenvswitchCreateCmd(&qoserrbuf);

        virCommandAddArgList(qoscmd, "set", "qos", lines[0], NULL);
        virCommandAddArgFormat(qoscmd, "other_config:min-rate=%s", average);
        if (burst) {
            virCommandAddArgFormat(qoscmd, "other_config:burst=%s", burst);
        }
        if (peak) {
            virCommandAddArgFormat(qoscmd, "other_config:max-rate=%s", peak);
        }
        virCommandAddArgList(qoscmd, vmid_ex_id, ifname_ex_id, NULL);
        if (virCommandRun(qoscmd, NULL) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to set qos configuration on port %1$s: %2$s"),
                           ifname, NULLSTR(qoserrbuf));
            return -1;
        }
    }

    return 0;
}

static int
virNetDevOpenvswitchInterfaceSetRxQos(const char *ifname,
                                      const virNetDevBandwidthRate *rx)
{
    g_autoptr(virCommand) cmd = NULL;
    g_autofree char *errbuf = NULL;

    cmd = virNetDevOpenvswitchCreateCmd(&errbuf);
    virCommandAddArgList(cmd, "set", "Interface", ifname, NULL);
    virCommandAddArgFormat(cmd, "ingress_policing_rate=%llu",
                           rx->average * VIR_NETDEV_RX_TO_OVS);
    if (rx->burst)
        virCommandAddArgFormat(cmd, "ingress_policing_burst=%llu",
                               rx->burst * VIR_NETDEV_RX_TO_OVS);

    if (virCommandRun(cmd, NULL) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to set vlan configuration on port %1$s: %2$s"),
                       ifname, NULLSTR(errbuf));
        return -1;
    }

    return 0;
}

/**
 * virNetDevOpenvswitchInterfaceSetQos:
 * @ifname: on which interface
 * @bandwidth: rates to set (may be NULL)
 * @vmuuid: the Domain UUID that has this interface
 * @swapped: true if IN/OUT should be set contrariwise
 *
 * Update qos configuration of an OVS port.
 *
 * If @swapped is set, the IN part of @bandwidth is set on
 * @ifname's TX, and vice versa. If it is not set, IN is set on
 * RX and OUT on TX. This is because for some types of interfaces
 * domain and the host live on the same side of the interface (so
 * domain's RX/TX is host's RX/TX), and for some it's swapped
 * (domain's RX/TX is hosts's TX/RX).
 *
 * Return 0 on success, -1 otherwise.
 */
int
virNetDevOpenvswitchInterfaceSetQos(const char *ifname,
                                    const virNetDevBandwidth *bandwidth,
                                    const unsigned char *vmuuid,
                                    bool swapped)
{
    virNetDevBandwidthRate *rx = NULL; /* From domain POV */
    virNetDevBandwidthRate *tx = NULL; /* From domain POV */

    if (!bandwidth) {
        /* nothing to be enabled */
        return 0;
    }

    if (geteuid() != 0) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Network bandwidth tuning is not available in session mode"));
        return -1;
    }

    if (!ifname) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("Unable to set bandwidth for interface because device name is unknown"));
        return -1;
    }

    if (swapped) {
        rx = bandwidth->out;
        tx = bandwidth->in;
    } else {
        rx = bandwidth->in;
        tx = bandwidth->out;
    }

    if (!bandwidth->out && !bandwidth->in) {
        if (virNetDevOpenvswitchInterfaceClearQos(ifname, vmuuid) < 0) {
            VIR_WARN("Clean qos for interface %s failed", ifname);
        }
        return 0;
    }

    if (tx && tx->average) {
        if (virNetDevOpenvswitchInterfaceSetTxQos(ifname, tx, vmuuid) < 0)
            return -1;
    } else {
        if (virNetDevOpenvswitchInterfaceClearTxQos(ifname, vmuuid) < 0) {
            VIR_WARN("Clean tx qos for interface %s failed", ifname);
        }
    }

    if (rx) {
        if (virNetDevOpenvswitchInterfaceSetRxQos(ifname, rx) < 0)
            return -1;
    } else {
        if (virNetDevOpenvswitchInterfaceClearRxQos(ifname) < 0) {
            VIR_WARN("Clean rx qos for interface %s failed", ifname);
        }
    }

    return 0;
}

int
virNetDevOpenvswitchInterfaceClearQos(const char *ifname,
                                      const unsigned char *vmuuid)
{
    int ret = 0;

    if (virNetDevOpenvswitchInterfaceClearTxQos(ifname, vmuuid) < 0) {
        VIR_WARN("Clean tx qos for interface %s failed", ifname);
        ret = -1;
    }

    if (virNetDevOpenvswitchInterfaceClearRxQos(ifname) < 0) {
        VIR_WARN("Clean rx qos for interface %s failed", ifname);
        ret = -1;
    }

    return ret;
}
