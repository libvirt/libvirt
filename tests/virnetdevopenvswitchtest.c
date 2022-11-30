/*
 * Copyright (C) 2019 Red Hat, Inc.
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

typedef struct _InterfaceParseStatsData InterfaceParseStatsData;
struct _InterfaceParseStatsData {
    const char *filename;
    const virDomainInterfaceStatsStruct stats;
};

struct testSetQosStruct {
    const char *band;
    const char *exp_cmd;
    const char *iface;
};

struct testClearQosStruct {
    const char *exp_cmd;
    const char *iface;
    const unsigned char *vmid;
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

static const unsigned char vm_id[VIR_UUID_BUFLEN] = "fakeuuid";

static int
testInterfaceParseStats(const void *opaque)
{
    const InterfaceParseStatsData *data = opaque;
    g_autofree char *filename = NULL;
    g_autofree char *buf = NULL;
    virDomainInterfaceStatsStruct actual;

    filename = g_strdup_printf("%s/virnetdevopenvswitchdata/%s", abs_srcdir,
                               data->filename);

    if (virFileReadAll(filename, 1024, &buf) < 0)
        return -1;

    if (virNetDevOpenvswitchInterfaceParseStats(buf, &actual) < 0)
        return -1;

    if (memcmp(&actual, &data->stats, sizeof(actual)) != 0) {
        fprintf(stderr,
                "Expected stats: %lld %lld %lld %lld %lld %lld %lld %lld\n"
                "Actual stats: %lld %lld %lld %lld %lld %lld %lld %lld",
                data->stats.rx_bytes,
                data->stats.rx_packets,
                data->stats.rx_errs,
                data->stats.rx_drop,
                data->stats.tx_bytes,
                data->stats.tx_packets,
                data->stats.tx_errs,
                data->stats.tx_drop,
                actual.rx_bytes,
                actual.rx_packets,
                actual.rx_errs,
                actual.rx_drop,
                actual.tx_bytes,
                actual.tx_packets,
                actual.tx_errs,
                actual.tx_drop);

        return -1;
    }

    return 0;
}


typedef struct _escapeData escapeData;
struct _escapeData {
    const char *input;
    const char *expect;
};


static int
testNameEscape(const void *opaque)
{
    const escapeData *data = opaque;
    g_autofree char *reply = g_strdup(data->input);
    int rv;

    rv = virNetDevOpenvswitchMaybeUnescapeReply(reply);

    if (data->expect) {
        if (rv < 0 || STRNEQ(reply, data->expect)) {
            fprintf(stderr,
                    "Unexpected failure, expected: %s for input %s got %s\n",
                    data->expect, data->input, reply);
            return -1;
        }
    } else {
        if (rv >= 0) {
            fprintf(stderr,
                    "Unexpected success, input %s got %s\n",
                    data->input, reply);
            return -1;
        }
    }

    return 0;
}


static int
testVirNetDevOpenvswitchInterfaceSetQos(const void *data)
{
    const struct testSetQosStruct *info = data;
    const char *iface = info->iface;
    g_autoptr(virNetDevBandwidth) band = NULL;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual_cmd = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    if (testVirNetDevBandwidthParse(&band, info->band) < 0)
        return -1;

    if (!iface)
        iface = "tap-fake";

    virCommandSetDryRun(dryRunToken, &buf, false, false, NULL, NULL);

    if (virNetDevOpenvswitchInterfaceSetQos(iface, band, vm_id, true) < 0)
        return -1;

    if (!(actual_cmd = virBufferContentAndReset(&buf))) {
        /* This is interesting, no command has been executed.
         * Maybe that's expected, actually. */
    }

    if (virTestCompareToString(info->exp_cmd, actual_cmd) < 0) {
        return -1;
    }

    return 0;
}


static int
testVirNetDevOpenvswitchInterfaceClearQos(const void *data)
{
    const struct testClearQosStruct *info = data;
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    g_autofree char *actual_cmd = NULL;
    const char *iface = info->iface;
    const unsigned char *vmid = info->vmid;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, false, NULL, NULL);

    if (virNetDevOpenvswitchInterfaceClearQos(iface, vmid) < 0)
        return -1;

    if (!(actual_cmd = virBufferContentAndReset(&buf))) {
        /* This is interesting, no command has been executed.
         * Maybe that's expected, actually. */
    }

    if (virTestCompareToString(info->exp_cmd, actual_cmd) < 0) {
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

#define TEST_INTERFACE_STATS(file, \
                             rxBytes, rxPackets, rxErrs, rxDrop, \
                             txBytes, txPackets, txErrs, txDrop) \
    do { \
        const InterfaceParseStatsData data = {.filename = file, .stats = { \
                             rxBytes, rxPackets, rxErrs, rxDrop, \
                             txBytes, txPackets, txErrs, txDrop}}; \
        if (virTestRun("Interface stats " file, testInterfaceParseStats, &data) < 0) \
            ret = -1; \
    } while (0)

    TEST_INTERFACE_STATS("stats1.json", 9, 12, 11, 10, 2, 8, 5, 4);
    TEST_INTERFACE_STATS("stats2.json", 12406, 173, 0, 0, 0, 0, 0, 0);

#define TEST_NAME_ESCAPE(str, fail) \
    do { \
        const escapeData data = {str, fail};\
        if (virTestRun("Name escape " str, testNameEscape, &data) < 0) \
            ret = -1; \
    } while (0)

    TEST_NAME_ESCAPE("", "");
    TEST_NAME_ESCAPE("\"\"", "");
    TEST_NAME_ESCAPE("vhost-user1", "vhost-user1");
    TEST_NAME_ESCAPE("\"vhost-user1\"", "vhost-user1");
    TEST_NAME_ESCAPE("\"vhost_user-name.to.escape1", NULL);
    TEST_NAME_ESCAPE("\"vhost_user-name.to\\\"escape1\"", "vhost_user-name.to\"escape1");
    TEST_NAME_ESCAPE("\"vhost\"user1\"", NULL);
    TEST_NAME_ESCAPE("\"\\\\", NULL);

#define DO_TEST_SET(Band, Exp_cmd, ...) \
    do { \
        struct testSetQosStruct data = {.band = Band, \
                                     .exp_cmd = Exp_cmd, \
                                     __VA_ARGS__}; \
        if (virTestRun("virNetDevOpenvswitchInterfaceSetQos", \
                       testVirNetDevOpenvswitchInterfaceSetQos, \
                       &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_SET(("<bandwidth>"
                 "  <inbound average='20000'/>"
                 "</bandwidth>"),
                (OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 set port tap-fake qos=@qos1"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'"
                           " -- --id=@qos1 create qos type=linux-htb other_config:min-rate=160000000"
                           " queues:0=@queue0 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'"
                           " -- --id=@queue0 create queue other_config:min-rate=160000000 "
                           "'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 set Interface tap-fake ingress_policing_rate=0 ingress_policing_burst=0\n"));

    DO_TEST_SET(NULL, NULL);

    DO_TEST_SET("<bandwidth/>", NULL);

    DO_TEST_SET(("<bandwidth>"
                 "  <inbound average='0' />"
                 "</bandwidth>"),
                (OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 set Interface tap-fake ingress_policing_rate=0 ingress_policing_burst=0\n"));

    DO_TEST_SET(("<bandwidth>"
                 "  <inbound average='0' />"
                 "  <outbound average='5000' />"
                 "</bandwidth>"),
                (OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos"
                           " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                           " 'external-ids:ifname=\"tap-fake\"'\n"
                 OVS_VSCTL " --timeout=5 set Interface tap-fake ingress_policing_rate=40000\n"));

#define DO_TEST_CLEAR_QOS(Iface, Vmid, Exp_cmd, ...) \
    do { \
        struct testClearQosStruct data = {.iface = Iface, \
                                        .vmid = Vmid, \
                                        .exp_cmd = Exp_cmd, \
                                        __VA_ARGS__}; \
        if (virTestRun("virNetDevOpenvswitchInterfaceClearQos", \
                       testVirNetDevOpenvswitchInterfaceClearQos, \
                       &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_CLEAR_QOS(("fake-iface"), vm_id,
                      (OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find queue"
                                 " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                                 " 'external-ids:ifname=\"fake-iface\"'\n"
                       OVS_VSCTL " --timeout=5 --no-heading --columns=_uuid find qos"
                                 " 'external-ids:vm-id=\"66616b65-7575-6964-0000-000000000000\"'"
                                 " 'external-ids:ifname=\"fake-iface\"'\n"
                       OVS_VSCTL " --timeout=5 set Interface fake-iface ingress_policing_rate=0 ingress_policing_burst=0\n"));

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain,
                      VIR_TEST_MOCK("virnetdevbandwidth"))
