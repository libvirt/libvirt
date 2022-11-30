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

#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE


#define VIR_NWFILTER_NEW_RULES_TEARDOWN \
    "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n" \
    "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n" \
    "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n" \
    "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n" \
    "iptables -w -F FP-vnet0\n" \
    "iptables -w -X FP-vnet0\n" \
    "iptables -w -F FJ-vnet0\n" \
    "iptables -w -X FJ-vnet0\n" \
    "iptables -w -F HJ-vnet0\n" \
    "iptables -w -X HJ-vnet0\n" \
    "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FP-vnet0\n" \
    "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FP-vnet0\n" \
    "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FJ-vnet0\n" \
    "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HJ-vnet0\n" \
    "ip6tables -w -F FP-vnet0\n" \
    "ip6tables -w -X FP-vnet0\n" \
    "ip6tables -w -F FJ-vnet0\n" \
    "ip6tables -w -X FJ-vnet0\n" \
    "ip6tables -w -F HJ-vnet0\n" \
    "ip6tables -w -X HJ-vnet0\n" \
    "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-J-vnet0\n" \
    "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-P-vnet0\n" \
    "ebtables --concurrent -t nat -L libvirt-J-vnet0\n" \
    "ebtables --concurrent -t nat -L libvirt-P-vnet0\n" \
    "ebtables --concurrent -t nat -F libvirt-J-vnet0\n" \
    "ebtables --concurrent -t nat -X libvirt-J-vnet0\n" \
    "ebtables --concurrent -t nat -F libvirt-P-vnet0\n" \
    "ebtables --concurrent -t nat -X libvirt-P-vnet0\n"

static int
testNWFilterEBIPTablesAllTeardown(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -w -F FO-vnet0\n"
        "iptables -w -X FO-vnet0\n"
        "iptables -w -F FI-vnet0\n"
        "iptables -w -X FI-vnet0\n"
        "iptables -w -F HI-vnet0\n"
        "iptables -w -X HI-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -w -F FO-vnet0\n"
        "ip6tables -w -X FO-vnet0\n"
        "ip6tables -w -F FI-vnet0\n"
        "ip6tables -w -X FI-vnet0\n"
        "ip6tables -w -F HI-vnet0\n"
        "ip6tables -w -X HI-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.allTeardown("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(actual, expected) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterEBIPTablesTearOldRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -w -F FO-vnet0\n"
        "iptables -w -X FO-vnet0\n"
        "iptables -w -F FI-vnet0\n"
        "iptables -w -X FI-vnet0\n"
        "iptables -w -F HI-vnet0\n"
        "iptables -w -X HI-vnet0\n"
        "iptables -w -E FP-vnet0 FO-vnet0\n"
        "iptables -w -E FJ-vnet0 FI-vnet0\n"
        "iptables -w -E HJ-vnet0 HI-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -w -F FO-vnet0\n"
        "ip6tables -w -X FO-vnet0\n"
        "ip6tables -w -F FI-vnet0\n"
        "ip6tables -w -X FI-vnet0\n"
        "ip6tables -w -F HI-vnet0\n"
        "ip6tables -w -X HI-vnet0\n"
        "ip6tables -w -E FP-vnet0 FO-vnet0\n"
        "ip6tables -w -E FJ-vnet0 FI-vnet0\n"
        "ip6tables -w -E HJ-vnet0 HI-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.tearOldRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterEBIPTablesRemoveBasicRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-P-vnet0\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.removeBasicRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterEBIPTablesTearNewRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN;
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.tearNewRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterEBIPTablesApplyBasicRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -w -F FO-vnet0\n"
        "iptables -w -X FO-vnet0\n"
        "iptables -w -F FI-vnet0\n"
        "iptables -w -X FI-vnet0\n"
        "iptables -w -F HI-vnet0\n"
        "iptables -w -X HI-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -w -F FO-vnet0\n"
        "ip6tables -w -X FO-vnet0\n"
        "ip6tables -w -F FI-vnet0\n"
        "ip6tables -w -X FI-vnet0\n"
        "ip6tables -w -F HI-vnet0\n"
        "ip6tables -w -X HI-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -N libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -s '!' 10:20:30:40:50:60 -j DROP\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -p IPv4 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -p ARP -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables --concurrent -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n";
    g_autofree char *actual = NULL;
    virMacAddr mac = { .addr = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 } };
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.applyBasicRules("vnet0", &mac) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterEBIPTablesApplyDHCPOnlyRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -w -F FO-vnet0\n"
        "iptables -w -X FO-vnet0\n"
        "iptables -w -F FI-vnet0\n"
        "iptables -w -X FI-vnet0\n"
        "iptables -w -F HI-vnet0\n"
        "iptables -w -X HI-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -w -F FO-vnet0\n"
        "ip6tables -w -X FO-vnet0\n"
        "ip6tables -w -F FI-vnet0\n"
        "ip6tables -w -X FI-vnet0\n"
        "ip6tables -w -F HI-vnet0\n"
        "ip6tables -w -X HI-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -N libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -N libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -s 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-sport 68 --ip-dport 67 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 192.168.122.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 192.168.122.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 10.0.0.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 10.0.0.1 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d 10:20:30:40:50:60 -p ipv4 --ip-protocol udp --ip-src 10.0.0.2 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -d ff:ff:ff:ff:ff:ff -p ipv4 --ip-protocol udp --ip-src 10.0.0.2 --ip-sport 67 --ip-dport 68 -j ACCEPT\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -j DROP\n"
        "ebtables --concurrent -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -A POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    g_autofree char *actual = NULL;
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
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.applyDHCPOnlyRules("vnet0", &mac, &val, false) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}



static int
testNWFilterEBIPTablesApplyDropAllRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        VIR_NWFILTER_NEW_RULES_TEARDOWN
        "iptables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "iptables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "iptables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "iptables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "iptables -w -F FO-vnet0\n"
        "iptables -w -X FO-vnet0\n"
        "iptables -w -F FI-vnet0\n"
        "iptables -w -X FI-vnet0\n"
        "iptables -w -F HI-vnet0\n"
        "iptables -w -X HI-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-is-bridged --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-out -m physdev --physdev-out vnet0 -g FO-vnet0\n"
        "ip6tables -w -D libvirt-in -m physdev --physdev-in vnet0 -g FI-vnet0\n"
        "ip6tables -w -D libvirt-host-in -m physdev --physdev-in vnet0 -g HI-vnet0\n"
        "ip6tables -w -D libvirt-in-post -m physdev --physdev-in vnet0 -j ACCEPT\n"
        "ip6tables -w -F FO-vnet0\n"
        "ip6tables -w -X FO-vnet0\n"
        "ip6tables -w -F FI-vnet0\n"
        "ip6tables -w -X FI-vnet0\n"
        "ip6tables -w -F HI-vnet0\n"
        "ip6tables -w -X HI-vnet0\n"
        "ebtables --concurrent -t nat -D PREROUTING -i vnet0 -j libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -D POSTROUTING -o vnet0 -j libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -L libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -F libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -X libvirt-O-vnet0\n"
        "ebtables --concurrent -t nat -N libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -N libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -A libvirt-J-vnet0 -j DROP\n"
        "ebtables --concurrent -t nat -A libvirt-P-vnet0 -j DROP\n"
        "ebtables --concurrent -t nat -A PREROUTING -i vnet0 -j libvirt-J-vnet0\n"
        "ebtables --concurrent -t nat -A POSTROUTING -o vnet0 -j libvirt-P-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-J-vnet0 libvirt-I-vnet0\n"
        "ebtables --concurrent -t nat -E libvirt-P-vnet0 libvirt-O-vnet0\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, NULL, NULL);

    if (ebiptables_driver.applyDropAllRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

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

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virfirewall"))
