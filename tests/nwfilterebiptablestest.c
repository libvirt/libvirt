/*
 * nwfilterebiptablestest.c: Test {eb,ip,ip6}tables rule generation
 *
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
 *
 */

#include <config.h>

#include "testutils.h"
#include "nwfilter/nwfilter_ebiptables_driver.h"
#include "virbuffer.h"
#include "virfirewall.h"

#define LIBVIRT_VIRFIREWALLPRIV_H_ALLOW
#include "virfirewallpriv.h"

#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE


#define VIR_NWFILTER_NEW_RULES_TEARDOWN \
    "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n" \
    "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n" \
    "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n" \
    "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n" \
    "iptables -F FP-vnet0\n" \
    "iptables -X FP-vnet0\n" \
    "iptables -F FJ-vnet0\n" \
    "iptables -X FJ-vnet0\n" \
    "iptables -F HJ-vnet0\n" \
    "iptables -X HJ-vnet0\n" \
    "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n" \
    "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n" \
    "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n" \
    "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n" \
    "ip6tables -F FP-vnet0\n" \
    "ip6tables -X FP-vnet0\n" \
    "ip6tables -F FJ-vnet0\n" \
    "ip6tables -X FJ-vnet0\n" \
    "ip6tables -F HJ-vnet0\n" \
    "ip6tables -X HJ-vnet0\n" \
    "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-J-vnet0\n" \
    "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-P-vnet0\n" \
    "ebtables -t nat -L libvirt-J-vnet0\n" \
    "ebtables -t nat -L libvirt-P-vnet0\n" \
    "ebtables -t nat -F libvirt-J-vnet0\n" \
    "ebtables -t nat -X libvirt-J-vnet0\n" \
    "ebtables -t nat -F libvirt-P-vnet0\n" \
    "ebtables -t nat -X libvirt-P-vnet0\n"

static int
testNWFilterEBIPTablesAllTeardown(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -F FO-vnet0\n"
        "iptables -X FO-vnet0\n"
        "iptables -F FI-vnet0\n"
        "iptables -X FI-vnet0\n"
        "iptables -F HI-vnet0\n"
        "iptables -X HI-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -F FO-vnet0\n"
        "ip6tables -X FO-vnet0\n"
        "ip6tables -F FI-vnet0\n"
        "ip6tables -X FI-vnet0\n"
        "ip6tables -F HI-vnet0\n"
        "ip6tables -X HI-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n";
    char *actual = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.allTeardown("vnet0") < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}


static int
testNWFilterEBIPTablesTearOldRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -F FO-vnet0\n"
        "iptables -X FO-vnet0\n"
        "iptables -F FI-vnet0\n"
        "iptables -X FI-vnet0\n"
        "iptables -F HI-vnet0\n"
        "iptables -X HI-vnet0\n"
        "iptables -E FP-vnet0 FO-vnet0\n"
        "iptables -E FJ-vnet0 FI-vnet0\n"
        "iptables -E HJ-vnet0 HI-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -F FO-vnet0\n"
        "ip6tables -X FO-vnet0\n"
        "ip6tables -F FI-vnet0\n"
        "ip6tables -X FI-vnet0\n"
        "ip6tables -F HI-vnet0\n"
        "ip6tables -X HI-vnet0\n"
        "ip6tables -E FP-vnet0 FO-vnet0\n"
        "ip6tables -E FJ-vnet0 FI-vnet0\n"
        "ip6tables -E HJ-vnet0 HI-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-J-vnet0\n"
        "ebtables -t nat -L libvirt-P-vnet0\n"
        "ebtables -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    char *actual = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.tearOldRules("vnet0") < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}


static int
testNWFilterEBIPTablesRemoveBasicRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables -t nat -L libvirt-J-vnet0\n"
        "ebtables -t nat -L libvirt-P-vnet0\n"
        "ebtables -t nat -F libvirt-J-vnet0\n"
        "ebtables -t nat -X libvirt-J-vnet0\n"
        "ebtables -t nat -F libvirt-P-vnet0\n"
        "ebtables -t nat -X libvirt-P-vnet0\n";
    char *actual = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.removeBasicRules("vnet0") < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}


static int
testNWFilterEBIPTablesTearNewRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN;
    char *actual = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.tearNewRules("vnet0") < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}


static int
testNWFilterEBIPTablesApplyBasicRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -F FO-vnet0\n"
        "iptables -X FO-vnet0\n"
        "iptables -F FI-vnet0\n"
        "iptables -X FI-vnet0\n"
        "iptables -F HI-vnet0\n"
        "iptables -X HI-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -F FO-vnet0\n"
        "ip6tables -X FO-vnet0\n"
        "ip6tables -F FI-vnet0\n"
        "ip6tables -X FI-vnet0\n"
        "ip6tables -F HI-vnet0\n"
        "ip6tables -X HI-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n"
        "ebtables -t nat -N libvirt-J-vnet0\n"
        "ebtables -t nat -A libvirt-J-vnet0 -s '!' 10:20:30:40:50:60 -j DROP\n"
        "ebtables -t nat -A libvirt-J-vnet0 -p IPv4 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-J-vnet0 -p ARP -j ACCEPT\n"
        "ebtables -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n";
    char *actual = NULL;
    int ret = -1;
    virMacAddr mac = { .addr = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 } };

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.applyBasicRules("vnet0", &mac) < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}


static int
testNWFilterEBIPTablesApplyDHCPOnlyRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -F FO-vnet0\n"
        "iptables -X FO-vnet0\n"
        "iptables -F FI-vnet0\n"
        "iptables -X FI-vnet0\n"
        "iptables -F HI-vnet0\n"
        "iptables -X HI-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -F FO-vnet0\n"
        "ip6tables -X FO-vnet0\n"
        "ip6tables -F FI-vnet0\n"
        "ip6tables -X FI-vnet0\n"
        "ip6tables -F HI-vnet0\n"
        "ip6tables -X HI-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n"
        "ebtables -t nat -N libvirt-J-vnet0\n"
        "ebtables -t nat -N libvirt-P-vnet0\n"
        "ebtables -t nat -A libvirt-J-vnet0 -s 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-sport 68 --ip-dport 67 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 192.168.122.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 192.168.122.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 10.0.0.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 10.0.0.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 10.0.0.2 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 10.0.0.2 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables -t nat -A libvirt-P-vnet0 -j DROP\n"
        "ebtables -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables -t nat -A POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    char *actual = NULL;
    int ret = -1;
    virMacAddr mac = { .addr = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 } };
    const char *servers[] = { "192.168.122.1", "10.0.0.1", "10.0.0.2" };
    virNWFilterVarValue val = {
        .valType = NWFILTER_VALUE_TYPE_ARRAY,
        .u = {
            .array = {
                .values = (char **)servers,
                .nValues = 3,
            }
        }
    };

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.applyDHCPOnlyRules("vnet0", &mac, &val, false) < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}



static int
testNWFilterEBIPTablesApplyDropAllRules(const void *opaque ATTRIBUTE_UNUSED)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -F FO-vnet0\n"
        "iptables -X FO-vnet0\n"
        "iptables -F FI-vnet0\n"
        "iptables -X FI-vnet0\n"
        "iptables -F HI-vnet0\n"
        "iptables -X HI-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -F FO-vnet0\n"
        "ip6tables -X FO-vnet0\n"
        "ip6tables -F FI-vnet0\n"
        "ip6tables -X FI-vnet0\n"
        "ip6tables -F HI-vnet0\n"
        "ip6tables -X HI-vnet0\n"
        "ebtables -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables -t nat -L libvirt-I-vnet0\n"
        "ebtables -t nat -L libvirt-O-vnet0\n"
        "ebtables -t nat -F libvirt-I-vnet0\n"
        "ebtables -t nat -X libvirt-I-vnet0\n"
        "ebtables -t nat -F libvirt-O-vnet0\n"
        "ebtables -t nat -X libvirt-O-vnet0\n"
        "ebtables -t nat -N libvirt-J-vnet0\n"
        "ebtables -t nat -N libvirt-P-vnet0\n"
        "ebtables -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables -t nat -A libvirt-P-vnet0 -j DROP\n"
        "ebtables -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables -t nat -A POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    char *actual = NULL;
    int ret = -1;

    virCommandSetDryRun(&buf, NULL, NULL);

    if (ebiptables_driver.applyDropAllRules("vnet0") < 0)
        goto cleanup;

    if (virBufferError(&buf))
        goto cleanup;

    actual = virBufferContentAndReset(&buf);
    virTestClearCommandPath(actual);

    if (STRNEQ_NULLABLE(actual, expected)) {
        virTestDifference(stderr, expected, actual);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virCommandSetDryRun(NULL, NULL, NULL);
    virBufferFreeAndReset(&buf);
    VIR_FREE(actual);
    return ret;
}

static bool
hasNetfilterTools(void)
{
    return virFileIsExecutable(IPTABLES_PATH) &&
        virFileIsExecutable(IP6TABLES_PATH) &&
        virFileIsExecutable(EBTABLES_PATH);
}


static int
mymain(void)
{
    int ret = 0;

    virFirewallSetLockOverride(true);

    if (virFirewallSetBackend(VIR_FIREWALL_BACKEND_DIRECT) < 0) {
        if (!hasNetfilterTools()) {
            fprintf(stderr, "iptables/ip6tables/ebtables tools not present");
            return EXIT_AM_SKIP;
        }

        ret = -1;
        goto cleanup;
    }

    if (virTestRun("ebiptablesAllTeardown",
                   testNWFilterEBIPTablesAllTeardown,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesTearOldRules",
                   testNWFilterEBIPTablesTearOldRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesRemoveBasicRules",
                   testNWFilterEBIPTablesRemoveBasicRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesTearNewRules",
                   testNWFilterEBIPTablesTearNewRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesApplyBasicRules",
                   testNWFilterEBIPTablesApplyBasicRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesApplyDHCPOnlyRules",
                   testNWFilterEBIPTablesApplyDHCPOnlyRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("ebiptablesApplyDropAllRules",
                   testNWFilterEBIPTablesApplyDropAllRules,
                   NULL) < 0)
        ret = -1;

 cleanup:
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
