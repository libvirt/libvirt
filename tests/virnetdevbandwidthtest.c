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
#include "netdev_bandwidth_conf.c"

#define VIR_FROM_THIS VIR_FROM_NONE

struct testMinimalStruct {
    const char *expected_result;
    const char *band1;
    const char *band2;
};

struct testSetStruct {
    const char *band;
    const char *exp_cmd;
    const char *iface;
    const bool hierarchical_class;
};

#define PARSE(xml, var) \
    do { \
        int rc; \
        xmlDocPtr doc; \
        xmlXPathContextPtr ctxt = NULL; \
 \
        if (!xml) \
            break; \
 \
        if (!(doc = virXMLParseStringCtxt((xml), \
                                          "bandwidth definition", \
                                          &ctxt))) \
            goto cleanup; \
 \
        rc = virNetDevBandwidthParse(&(var), \
                                     ctxt->node, \
                                     VIR_DOMAIN_NET_TYPE_NETWORK); \
        xmlFreeDoc(doc); \
        xmlXPathFreeContext(ctxt); \
        if (rc < 0) \
            goto cleanup; \
    } while (0)

static int
testVirNetDevBandwidthSet(const void *data)
{
    int ret = -1;
    const struct testSetStruct *info = data;
    const char *iface = info->iface;
    virNetDevBandwidthPtr band = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *actual_cmd = NULL;

    PARSE(info->band, band);

    if (!iface)
        iface = "eth0";

    virCommandSetDryRun(&buf, NULL, NULL);

    if (virNetDevBandwidthSet(iface, band, info->hierarchical_class, true) < 0)
        goto cleanup;

    if (!(actual_cmd = virBufferContentAndReset(&buf))) {
        int err = virBufferError(&buf);
        if (err) {
            fprintf(stderr, "buffer's in error state: %d", err);
            goto cleanup;
        }
        /* This is interesting, no command has been executed.
         * Maybe that's expected, actually. */
    }

    if (STRNEQ_NULLABLE(info->exp_cmd, actual_cmd)) {
        virTestDifference(stderr,
                          NULLSTR(info->exp_cmd),
                          NULLSTR(actual_cmd));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virNetDevBandwidthFree(band);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual_cmd);
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

#define DO_TEST_SET(Band, Exp_cmd, ...) \
    do { \
        struct testSetStruct data = {.band = Band, \
                                     .exp_cmd = Exp_cmd, \
                                     __VA_ARGS__}; \
        if (virTestRun("virNetDevBandwidthSet", \
                       testVirNetDevBandwidthSet, \
                       &data) < 0) \
            ret = -1; \
    } while (0)


    DO_TEST_SET(NULL, NULL);

    DO_TEST_SET("<bandwidth/>", NULL);

    DO_TEST_SET(("<bandwidth>"
                 "  <inbound average='1024'/>"
                 "</bandwidth>"),
                (TC " qdisc del dev eth0 root\n"
                 TC " qdisc del dev eth0 ingress\n"
                 TC " qdisc add dev eth0 root handle 1: htb default 1\n"
                 TC " class add dev eth0 parent 1: classid 1:1 htb rate 1024kbps quantum 87\n"
                 TC " qdisc add dev eth0 parent 1:1 handle 2: sfq perturb 10\n"
                 TC " filter add dev eth0 parent 1:0 protocol all prio 1 handle 1 fw flowid 1\n"));

    DO_TEST_SET(("<bandwidth>"
                 "  <outbound average='1024'/>"
                 "</bandwidth>"),
                (TC " qdisc del dev eth0 root\n"
                 TC " qdisc del dev eth0 ingress\n"
                 TC " qdisc add dev eth0 ingress\n"
                 TC " filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 "
                 "police rate 1024kbps burst 1024kb mtu 64kb drop flowid :1\n"));

    DO_TEST_SET(("<bandwidth>"
                 "  <inbound average='1' peak='2' floor='3' burst='4'/>"
                 "  <outbound average='5' peak='6' burst='7'/>"
                 "</bandwidth>"),
                (TC " qdisc del dev eth0 root\n"
                 TC " qdisc del dev eth0 ingress\n"
                 TC " qdisc add dev eth0 root handle 1: htb default 1\n"
                 TC " class add dev eth0 parent 1: classid 1:1 htb rate 1kbps ceil 2kbps burst 4kb quantum 1\n"
                 TC " qdisc add dev eth0 parent 1:1 handle 2: sfq perturb 10\n"
                 TC " filter add dev eth0 parent 1:0 protocol all prio 1 handle 1 fw flowid 1\n"
                 TC " qdisc add dev eth0 ingress\n"
                 TC " filter add dev eth0 parent ffff: protocol all u32 match u32 0 0 "
                 "police rate 5kbps burst 7kb mtu 64kb drop flowid :1\n"));

    return ret;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnetdevbandwidthmock.so")
