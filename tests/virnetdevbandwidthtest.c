/*
 * Copyright (C) 2014 Red Hat, Inc.
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

#include "testutils.h"
#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"
#include "virnetdevbandwidth.h"
#include "virnetdevopenvswitch.h"
#include "netdev_bandwidth_conf.c"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testSetStruct {
    const char *band;
    const char *exp_cmd_tc;
    const char *exp_cmd_ovs;
    bool ovs;
    const unsigned char *uuid;
    const char *iface;
    const bool hierarchical_class;
};

static int
testVirNetDevBandwidthParse(virNetDevBandwidth **var,
                            const char *xml)
{
    g_autoptr(xmlDoc) doc = NULL;
    g_autoptr(xmlXPathContext) ctxt = NULL;

    if (!xml)
        return 0;

    if (!(doc = virXMLParseStringCtxt((xml),
                                      "bandwidth definition",
                                      &ctxt)))
        return -1;

    return virNetDevBandwidthParse(var,
                                   NULL,
                                   ctxt->node,
                                   true);
}

static int
testVirNetDevBandwidthSet(const void *data)
{
    const struct testSetStruct *info = data;
    const char *iface = info->iface;
    const char *exp_cmd = NULL;
    g_autoptr(virNetDevBandwidth) band = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual_cmd = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    if (testVirNetDevBandwidthParse(&band, info->band) < 0)
        return -1;

    if (!iface)
        iface = "eth0";

    virCommandSetDryRun(dryRunToken, &buf, false, false, NULL, NULL);

    if (info->ovs) {
        exp_cmd = info->exp_cmd_ovs;
        if (virNetDevOpenvswitchInterfaceSetQos(iface, band, info->uuid, true) < 0)
            return -1;
    } else {
        exp_cmd = info->exp_cmd_tc;
        if (virNetDevBandwidthSet(iface, band, info->hierarchical_class, true) < 0)
            return -1;
    }

    if (!(actual_cmd = virBufferContentAndReset(&buf))) {
        /* This is interesting, no command has been executed.
         * Maybe that's expected, actually. */
    }

    if (virTestCompareToString(exp_cmd, actual_cmd) < 0) {
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;
    unsigned char uuid[VIR_UUID_BUFLEN] = { 0 };

#define VMUUID "c1018351-a229-4209-9faf-42446e0b53e5"

    if (virUUIDParse(VMUUID, uuid) < 0)
        return -1;

#define DO_TEST_SET(Band, Exp_cmd_tc, Exp_cmd_ovs, ...) \
    do { \
        struct testSetStruct data = {.band = Band, \
                                     .exp_cmd_tc = Exp_cmd_tc, \
                                     .exp_cmd_ovs = Exp_cmd_ovs, \
                                     .ovs = false, \
                                     .uuid = uuid, \
                                     __VA_ARGS__}; \
        if (virTestRun("virNetDevBandwidthSet TC", \
                       testVirNetDevBandwidthSet, \
                       &data) < 0) { \
            ret = -1; \
        } \
        data.ovs = true; \
        if (virTestRun("virNetDevBandwidthSet OVS", \
                       testVirNetDevBandwidthSet, \
                       &data) < 0) { \
            ret = -1; \
        } \
    } while (0)

    DO_TEST_SET(NULL, NULL, NULL);

    DO_TEST_SET("<bandwidth/>", NULL, NULL);

    DO_TEST_SET("<bandwidth>"
                "  <inbound average='1024'/>"
                "</bandwidth>",
                TC " qdisc del dev eth0 root\n"
                TC " qdisc del dev eth0 ingress\n"
                TC " qdisc add dev eth0 root handle 1: htb default 1\n"
                TC " class add dev eth0 parent 1: classid 1:1 htb rate 1024kbps quantum 87\n"
                TC " qdisc add dev eth0 parent 1:1 handle 2: sfq perturb 10\n"
                TC " filter add dev eth0 parent 1:0 protocol all prio 1 handle 1 fw flowid 1\n",
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set port eth0 qos=@qos1 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"' --"
                          " --id=@qos1 create qos type=linux-htb other_config:min-rate=8192000 queues:0=@queue0 'external-ids:vm-id=\"" VMUUID "\"'"
                            " 'external-ids:ifname=\"eth0\"' --"
                          " --id=@queue0 create queue other_config:min-rate=8192000 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set Interface eth0 ingress_policing_rate=0 ingress_policing_burst=0\n");

    DO_TEST_SET("<bandwidth>"
                "  <outbound average='1024'/>"
                "</bandwidth>",
                TC " qdisc del dev eth0 root\n"
                TC " qdisc del dev eth0 ingress\n"
                TC " qdisc add dev eth0 ingress\n"
                TC " filter add dev eth0 parent ffff: protocol all u32 match u32 0 0"
                   " police rate 1024kbps burst 1024kb mtu 64kb drop flowid :1\n",
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set Interface eth0 ingress_policing_rate=8192\n");

    DO_TEST_SET("<bandwidth>"
                "  <inbound average='1' peak='2' floor='3' burst='4'/>"
                "  <outbound average='5' peak='6' burst='7'/>"
                "</bandwidth>",
                TC " qdisc del dev eth0 root\n"
                TC " qdisc del dev eth0 ingress\n"
                TC " qdisc add dev eth0 root handle 1: htb default 1\n"
                TC " class add dev eth0 parent 1: classid 1:1 htb rate 1kbps ceil 2kbps burst 4kb quantum 1\n"
                TC " qdisc add dev eth0 parent 1:1 handle 2: sfq perturb 10\n"
                TC " filter add dev eth0 parent 1:0 protocol all prio 1 handle 1 fw flowid 1\n"
                TC " qdisc add dev eth0 ingress\n"
                TC " filter add dev eth0 parent ffff: protocol all u32 match u32 0 0"
                   " police rate 5kbps burst 7kb mtu 64kb drop flowid :1\n",
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set port eth0 qos=@qos1 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"' --"
                          " --id=@qos1 create qos type=linux-htb other_config:min-rate=8000 other_config:burst=32768 other_config:max-rate=16000"
                            " queues:0=@queue0 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"' --"
                          " --id=@queue0 create queue other_config:min-rate=8000 other_config:burst=32768 other_config:max-rate=16000"
                            " 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set Interface eth0 ingress_policing_rate=40 ingress_policing_burst=56\n");

    DO_TEST_SET("<bandwidth>"
                "  <inbound average='4294967295'/>"
                "  <outbound average='4294967295'/>"
                "</bandwidth>",
                TC " qdisc del dev eth0 root\n"
                TC " qdisc del dev eth0 ingress\n"
                TC " qdisc add dev eth0 root handle 1: htb default 1\n"
                TC " class add dev eth0 parent 1: classid 1:1 htb rate 4294967295kbps quantum 366503875\n"
                TC " qdisc add dev eth0 parent 1:1 handle 2: sfq perturb 10\n"
                TC " filter add dev eth0 parent 1:0 protocol all prio 1 handle 1 fw flowid 1\n"
                TC " qdisc add dev eth0 ingress\n"
                TC " filter add dev eth0 parent ffff: protocol all u32 match"
                   " u32 0 0 police rate 4294967295kbps burst 4194303kb mtu 64kb"
                   " drop flowid :1\n",
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set port eth0 qos=@qos1 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"' --"
                          " --id=@qos1 create qos type=linux-htb other_config:min-rate=34359738360000"
                            " queues:0=@queue0 'external-ids:vm-id=\"" VMUUID "\"' 'external-ids:ifname=\"eth0\"' --"
                          " --id=@queue0 create queue other_config:min-rate=34359738360000 'external-ids:vm-id=\"" VMUUID "\"'"
                            " 'external-ids:ifname=\"eth0\"'\n"
                OVS_VSCTL " --timeout=5 set Interface eth0 ingress_policing_rate=34359738360\n");

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virnetdevbandwidth"))
