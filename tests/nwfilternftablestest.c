/*
 * nwfilternftablestest.c: Test nftables rule generation
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
#include "nwfilter/nwfilter_nftables_driver.h"
#include "virbuffer.h"

#define LIBVIRT_VIRCOMMANDPRIV_H_ALLOW
#include "vircommandpriv.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define EXISTING_TABLE \
    "table bridge %s { # handle 562\n" \
    "    comment \"this table is managed by libvirt\"\n" \
    "    map vmap-oif { # handle 1\n" \
    "        type iface_index : verdict\n" \
    "        elements = { \"vnet0\" : jump vnet0-in }\n" \
    "    }\n" \
    "\n" \
    "    map vmap-iif { # handle 2\n" \
    "        type iface_index : verdict\n" \
    "        elements = { \"vnet0\" : jump vnet0-out }\n" \
    "    }\n" \
    "\n" \
    "    chain postrouting { # handle 3\n" \
    "        type filter hook postrouting priority 1; policy accept;\n" \
    "        meta nftrace set 1 # handle 4\n" \
    "        oif vmap @vmap-oif # handle 7\n" \
    "    }\n" \
    "\n" \
    "    chain prerouting { # handle 5\n" \
    "        type filter hook prerouting priority 1; policy accept;\n" \
    "        meta nftrace set 1 # handle 6\n" \
    "        iif vmap @vmap-iif # handle 8\n" \
    "    }\n" \
    "\n" \
    "    chain n-vnet0-in { # handle 880\n" \
    "        ether type ip jump vnet0-ipv4-in # handle 893\n" \
    "        ether type ip6 jump vnet0-ipv6-in # handle 897\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-in { # handle 880\n" \
    "        ether type ip jump vnet0-ipv4-in # handle 893\n" \
    "        ether type ip6 jump vnet0-ipv6-in # handle 897\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-out { # handle 881\n" \
    "        ip6 saddr 2a01:7c8:e100:1::78e2 tcp dport 465-465 ct direction original drop comment \"priority=100\" # handle 882\n" \
    "        ip6 saddr 2a01:7c8:e100:1::78e2 tcp dport 587-587 ct direction original drop comment \"priority=100\" # handle 883\n" \
    "        ip saddr 192.168.1.2 tcp dport 25-25 ct direction original drop comment \"priority=100\" # handle 884\n" \
    "        ip saddr 192.168.1.2 tcp dport 587-587 ct direction original drop comment \"priority=100\" # handle 885\n" \
    "        ether type ip tcp dport 25-25 ct direction original drop comment \"priority=100\" # handle 886\n" \
    "        ether type ip6 tcp dport 25-25 ct direction original drop comment \"priority=100\" # handle 887\n" \
    "        ip6 daddr 2a01:7c8:e100:1::78e2 tcp dport 465-465 ct direction original accept comment \"priority=100\" # handle 888\n" \
    "        ip6 saddr 2a01:7c8:e100:1::78e2 udp dport 587-587 ct direction original drop comment \"priority=100\" # handle 889\n" \
    "        ip saddr 192.168.1.2 udp dport 25-25 ct direction original continue comment \"priority=100\" # handle 890\n" \
    "        ether type ip ct direction original continue comment \"priority=100\" # handle 891\n" \
    "        ether type ip jump vnet0-ipv4-out # handle 895\n" \
    "        ether type ip6 jump vnet0-ipv6-out # handle 899\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-ipv4-in { # handle 892\n" \
    "        ip saddr 192.168.1.1 tcp dport 4444 ct direction reply ct state established,new accept comment \"priority=302\" # handle 902\n" \
    "        ether type ip meta l4proto tcp ct direction reply drop comment \"priority=601\" # handle 904\n" \
    "        ether type ip meta l4proto udp ct direction reply drop comment \"priority=603\" # handle 905\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-ipv4-out { # handle 894\n" \
    "        ip protocol icmp ct count over 42 drop comment \"priority=400\" # handle 903\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-ipv6-in { # handle 896\n" \
    "        ip6 daddr fe80::5054:ff:fe60:baae udp sport 547 udp dport 546 ct direction reply accept comment \"priority=111\" # handle 901\n" \
    "    }\n" \
    "\n" \
    "    chain vnet0-ipv6-out { # handle 898\n" \
    "        ip6 saddr fe80::5054:ff:fe60:baae ip6 daddr ff02::1:2 udp sport 546 udp dport 547 ct direction original accept comment \"priority=110\" # handle 900\n" \
    "    }\n" \
    "}\n"

#define OLD_REMOVES \
    "nft -a list table bridge libvirt_nwfilter_ethernet\n" \
    "nft -a list table bridge libvirt_nwfilter_inet\n" \
    "nft delete element bridge libvirt_nwfilter_ethernet vmap-oif '{' '\"vnet0\"' '}'\n" \
    "nft delete element bridge libvirt_nwfilter_ethernet vmap-iif '{' '\"vnet0\"' '}'\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-in\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-out\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-ipv4-in\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-ipv4-out\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-ipv6-in\n" \
    "nft delete chain bridge libvirt_nwfilter_ethernet vnet0-ipv6-out\n" \
    "nft delete element bridge libvirt_nwfilter_inet vmap-oif '{' '\"vnet0\"' '}'\n" \
    "nft delete element bridge libvirt_nwfilter_inet vmap-iif '{' '\"vnet0\"' '}'\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-in\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-out\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-ipv4-in\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-ipv4-out\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-ipv6-in\n" \
    "nft delete chain bridge libvirt_nwfilter_inet vnet0-ipv6-out\n"

static void
testCommandDryRunCallback(const char *const*args,
                          const char *const*env G_GNUC_UNUSED,
                          const char *input G_GNUC_UNUSED,
                          char **output,
                          char **error G_GNUC_UNUSED,
                          int *status,
                          void *opaque G_GNUC_UNUSED)
{
    size_t argc = 0;
    const char *table;

    while (args[argc] != NULL)
        argc++;

    if (STRNEQ(args[0], "nft")) {
        *status = EXIT_FAILURE;
        return;
    }

    /* simulate an empty existing set rules */
    if (argc == 6 && STREQ(args[1], "-a") && STREQ(args[2], "list")) {
        table = args[argc-1];
        *output = g_strdup_printf(EXISTING_TABLE, table);
        *status = EXIT_SUCCESS;
    }
}


static int
testNWFilterNFTablesAllTeardown(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected = OLD_REMOVES;
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.allTeardown("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterNFTablesTearOldRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "nft -a list table bridge libvirt_nwfilter_ethernet\n"
        "nft -a list table bridge libvirt_nwfilter_inet\n"
        OLD_REMOVES
        "nft rename chain bridge libvirt_nwfilter_ethernet n-vnet0-in vnet0-in\n"
        "nft rename chain bridge libvirt_nwfilter_inet n-vnet0-in vnet0-in\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.tearOldRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterNFTablesRemoveBasicRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected = OLD_REMOVES;
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.removeBasicRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterNFTablesTearNewRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "nft -a list table bridge libvirt_nwfilter_ethernet\n"
        "nft -a list table bridge libvirt_nwfilter_inet\n"\
        "nft delete chain bridge libvirt_nwfilter_ethernet n-vnet0-in\n"
        "nft delete chain bridge libvirt_nwfilter_inet n-vnet0-in\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.tearNewRules("vnet0") < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterNFTablesApplyBasicRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "nft list tables\n"
        OLD_REMOVES
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-out '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-out '{ }'\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out ether saddr '!=' 10:20:30:40:50:60 drop\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out ether type ip accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out ether type arp accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out accept\n"
        "nft delete element bridge libvirt_nwfilter_inet vmap-oif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_inet vmap-oif '{' vnet0 : jump vnet0-in '}'\n"
        "nft delete element bridge libvirt_nwfilter_ethernet vmap-oif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_ethernet vmap-oif '{' vnet0 : jump vnet0-in '}'\n"
        "nft delete element bridge libvirt_nwfilter_inet vmap-iif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_inet vmap-iif '{' vnet0 : jump vnet0-out '}'\n"
        "nft delete element bridge libvirt_nwfilter_ethernet vmap-iif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_ethernet vmap-iif '{' vnet0 : jump vnet0-out '}'\n";
    g_autofree char *actual = NULL;
    virMacAddr mac = { .addr = { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 } };
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.applyBasicRules("vnet0", &mac) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}


static int
testNWFilterNFTablesApplyDHCPOnlyRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "nft list tables\n"
        OLD_REMOVES
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-out '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-out '{ }'\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out ether saddr 10:20:30:40:50:60 ether type ip udp sport 68 udp dport 67 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out drop\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr 10:20:30:40:50:60 ether type ip ip saddr 192.168.122.1 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr ff:ff:ff:ff:ff:ff ether type ip ip saddr 192.168.122.1 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr 10:20:30:40:50:60 ether type ip ip saddr 10.0.0.1 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr ff:ff:ff:ff:ff:ff ether type ip ip saddr 10.0.0.1 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr 10:20:30:40:50:60 ether type ip ip saddr 10.0.0.2 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in ether daddr ff:ff:ff:ff:ff:ff ether type ip ip saddr 10.0.0.2 udp sport 67 udp dport 68 accept\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in drop\n"
        "nft delete element bridge libvirt_nwfilter_inet vmap-oif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_inet vmap-oif '{' vnet0 : jump vnet0-in '}'\n"
        "nft delete element bridge libvirt_nwfilter_ethernet vmap-oif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_ethernet vmap-oif '{' vnet0 : jump vnet0-in '}'\n"
        "nft delete element bridge libvirt_nwfilter_inet vmap-iif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_inet vmap-iif '{' vnet0 : jump vnet0-out '}'\n"
        "nft delete element bridge libvirt_nwfilter_ethernet vmap-iif '{' vnet0 '}'\n"
        "nft add element bridge libvirt_nwfilter_ethernet vmap-iif '{' vnet0 : jump vnet0-out '}'\n";
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

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.applyDHCPOnlyRules("vnet0", &mac, &val, false) < 0)
        return -1;

    actual = virBufferContentAndReset(&buf);

    if (virTestCompareToString(expected, actual) < 0) {
        return -1;
    }

    return 0;
}



static int
testNWFilterNFTablesApplyDropAllRules(const void *opaque G_GNUC_UNUSED)
{
    g_auto(virBuffer) buf = VIR_BUFFER_INITIALIZER;
    const char *expected =
        "nft list tables\n"
        OLD_REMOVES
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-in '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_ethernet vnet0-out '{ }'\n"
        "nft add chain bridge libvirt_nwfilter_inet vnet0-out '{ }'\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-out drop\n"
        "nft add rule bridge libvirt_nwfilter_ethernet vnet0-in drop\n"
        "nft add rule bridge libvirt_nwfilter_ethernet postrouting oifname vnet0 jump vnet0-in\n"
        "nft add rule bridge libvirt_nwfilter_ethernet prerouting iifname vnet0 jump vnet0-out\n";
    g_autofree char *actual = NULL;
    g_autoptr(virCommandDryRunToken) dryRunToken = virCommandDryRunTokenNew();

    virCommandSetDryRun(dryRunToken, &buf, false, true, testCommandDryRunCallback, NULL);

    if (nftables_driver.applyDropAllRules("vnet0") < 0)
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

    if (virTestRun("nftablesAllTeardown",
                   testNWFilterNFTablesAllTeardown,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesTearOldRules",
                   testNWFilterNFTablesTearOldRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesRemoveBasicRules",
                   testNWFilterNFTablesRemoveBasicRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesTearNewRules",
                   testNWFilterNFTablesTearNewRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesApplyBasicRules",
                   testNWFilterNFTablesApplyBasicRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesApplyDHCPOnlyRules",
                   testNWFilterNFTablesApplyDHCPOnlyRules,
                   NULL) < 0)
        ret = -1;

    if (virTestRun("nftablesApplyDropAllRules",
                   testNWFilterNFTablesApplyDropAllRules,
                   NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virfirewall"))
