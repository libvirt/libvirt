/*
 * sockettest.c: Testing for src/util/network.c APIs
 *
 * Copyright (C) 2010-2011, 2014, 2015 Red Hat, Inc.
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


#include "virsocketaddr.h"
#include "testutils.h"
#include "virlog.h"

VIR_LOG_INIT("tests.sockettest");

static int testParse(virSocketAddr *addr, const char *addrstr, int family, bool pass)
{
    int rc;

    rc = virSocketAddrParse(addr, addrstr, family);

    if (rc < 0)
        return pass ? -1 : 0;
    else
        return pass ? 0 : -1;
}

static int testFormat(virSocketAddr *addr, const char *addrstr, bool pass)
{
    g_autofree char *newaddrstr = NULL;

    newaddrstr = virSocketAddrFormat(addr);
    if (!newaddrstr)
        return pass ? -1 : 0;

    if (virTestCompareToString(newaddrstr, addrstr) < 0) {
        return pass ? -1 : 0;
    } else {
        return pass ? 0 : -1;
    }
}

struct testParseData {
    virSocketAddr *addr;
    const char *addrstr;
    int family;
    bool pass;
};
static int testParseHelper(const void *opaque)
{
    const struct testParseData *data = opaque;
    return testParse(data->addr, data->addrstr, data->family, data->pass);
}

struct testFormatData {
    virSocketAddr *addr;
    const char *addrstr;
    bool pass;
};
static int testFormatHelper(const void *opaque)
{
    const struct testFormatData *data = opaque;
    return testFormat(data->addr, data->addrstr, data->pass);
}


static int
testRange(const char *saddrstr, const char *eaddrstr,
          const char *netstr, int prefix, int size, bool pass)
{
    virSocketAddr saddr;
    virSocketAddr eaddr;
    virSocketAddr netaddr;
    int gotsize;

    if (virSocketAddrParse(&saddr, saddrstr, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&eaddr, eaddrstr, AF_UNSPEC) < 0)
        return -1;
    if (netstr && virSocketAddrParse(&netaddr, netstr, AF_UNSPEC) < 0)
        return -1;

    gotsize = virSocketAddrGetRange(&saddr, &eaddr,
                                    netstr ? &netaddr : NULL, prefix);
    VIR_DEBUG("Size want %d vs got %d", size, gotsize);
    if (pass) {
        /* fail if virSocketAddrGetRange returns failure, or unexpected size */
        return (gotsize < 0 || gotsize != size) ? -1 : 0;
    } else {
        /* succeed if virSocketAddrGetRange fails, otherwise fail. */
        return gotsize < 0 ? 0 : -1;
    }
}


struct testRangeData {
    const char *saddr;
    const char *eaddr;
    const char *netaddr;
    int prefix;
    int size;
    bool pass;
};


static int testRangeHelper(const void *opaque)
{
    const struct testRangeData *data = opaque;
    return testRange(data->saddr, data->eaddr,
                     data->netaddr, data->prefix,
                     data->size, data->pass);
}


static int testNetmask(const char *addr1str, const char *addr2str,
                       const char *netmaskstr, bool pass)
{
    virSocketAddr addr1;
    virSocketAddr addr2;
    virSocketAddr netmask;
    int ret;

    if (virSocketAddrParse(&addr1, addr1str, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&addr2, addr2str, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&netmask, netmaskstr, AF_UNSPEC) < 0)
        return -1;

    ret = virSocketAddrCheckNetmask(&addr1, &addr2, &netmask);

    if (ret <= 0) {
        return pass ? -1 : 0;
    } else {
        return pass ? 0 : -1;
    }
}

struct testNetmaskData {
    const char *addr1;
    const char *addr2;
    const char *netmask;
    bool pass;
};
static int testNetmaskHelper(const void *opaque)
{
    const struct testNetmaskData *data = opaque;
    return testNetmask(data->addr1, data->addr2, data->netmask, data->pass);
}



static int testMaskNetwork(const char *addrstr,
                           int prefix,
                           const char *networkstr)
{
    virSocketAddr addr;
    virSocketAddr network;
    g_autofree char *gotnet = NULL;

    /* Intentionally fill with garbage */
    memset(&network, 1, sizeof(network));

    if (virSocketAddrParse(&addr, addrstr, AF_UNSPEC) < 0)
        return -1;

    if (virSocketAddrMaskByPrefix(&addr, prefix, &network) < 0)
        return -1;

    if (!(gotnet = virSocketAddrFormat(&network)))
        return -1;

    if (STRNEQ(networkstr, gotnet)) {
        fprintf(stderr, "Expected %s, got %s\n", networkstr, gotnet);
        return -1;
    }
    return 0;
}

struct testMaskNetworkData {
    const char *addr1;
    int prefix;
    const char *network;
};
static int testMaskNetworkHelper(const void *opaque)
{
    const struct testMaskNetworkData *data = opaque;
    return testMaskNetwork(data->addr1, data->prefix, data->network);
}


static int testWildcard(const char *addrstr,
                        bool pass)
{
    virSocketAddr addr;

    if (virSocketAddrParse(&addr, addrstr, AF_UNSPEC) < 0)
        return -1;

    if (virSocketAddrIsWildcard(&addr))
        return pass ? 0 : -1;
    return pass ? -1 : 0;
}

struct testWildcardData {
    const char *addr;
    bool pass;
};
static int testWildcardHelper(const void *opaque)
{
    const struct testWildcardData *data = opaque;
    return testWildcard(data->addr, data->pass);
}

struct testNumericData {
    const char *addr;
    int expected;
};

static int
testNumericHelper(const void *opaque)
{
    const struct testNumericData *data = opaque;

    if (virSocketAddrNumericFamily(data->addr) != data->expected)
        return -1;
    return 0;
}

struct testIsLocalhostData {
    const char *addr;
    bool result;
};

static int
testIsLocalhostHelper(const void *opaque)
{
    const struct testIsLocalhostData *data = opaque;

    if (virSocketAddrIsNumericLocalhost(data->addr) != data->result)
        return -1;
    return 0;
}

static int
mymain(void)
{
    int ret = 0;
    /* Some of our tests deliberately test failure cases, so
     * register a handler to stop error messages cluttering
     * up display
     */
    virTestQuiesceLibvirtErrors(false);

#define DO_TEST_PARSE_AND_FORMAT(addrstr, family, pass) \
    do { \
        virSocketAddr addr = { 0 }; \
        struct testParseData data = { &addr, addrstr, family, pass }; \
        struct testFormatData data2 = { &addr, addrstr, pass }; \
        if (virTestRun("Test parse " addrstr " family " #family, \
                       testParseHelper, &data) < 0) \
            ret = -1; \
        if (virTestRun("Test format " addrstr " family " #family, \
                       testFormatHelper, &data2) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_PARSE_AND_CHECK_FORMAT(addrstr, addrformated, family, pass) \
    do { \
        virSocketAddr addr = { 0 }; \
        struct testParseData data = { &addr, addrstr, family, true}; \
        struct testFormatData data2 = { &addr, addrformated, pass }; \
        if (virTestRun("Test parse " addrstr " family " #family, \
                       testParseHelper, &data) < 0) \
            ret = -1; \
        if (virTestRun("Test format " addrstr " family " #family, \
                       testFormatHelper, &data2) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_RANGE(saddr, eaddr, netaddr, prefix, size, pass) \
    do { \
        struct testRangeData data \
           = { saddr, eaddr, netaddr, prefix, size, pass }; \
        if (virTestRun("Test range " saddr " -> " eaddr "(" netaddr \
                       "/" #prefix") size " #size, \
                       testRangeHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_RANGE_SIMPLE(saddr, eaddr, size, pass) \
    do { \
        struct testRangeData data \
           = { saddr, eaddr, NULL, 0, size, pass }; \
        if (virTestRun("Test range " saddr " -> " eaddr "size " #size, \
                       testRangeHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_NETMASK(addr1, addr2, netmask, pass) \
    do { \
        struct testNetmaskData data = { addr1, addr2, netmask, pass }; \
        if (virTestRun("Test netmask " addr1 " + " addr2 " in " netmask, \
                       testNetmaskHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_MASK_NETWORK(addr1, prefix, network) \
    do { \
        struct testMaskNetworkData data = { addr1, prefix, network }; \
        if (virTestRun("Test mask network " addr1 " / " #prefix " == " network, \
                       testMaskNetworkHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_WILDCARD(addr, pass) \
    do { \
        struct testWildcardData data = { addr, pass}; \
        if (virTestRun("Test wildcard " addr, \
                       testWildcardHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_NUMERIC_FAMILY(addr, pass) \
    do { \
        struct testNumericData data = { addr, pass }; \
        if (virTestRun("Test Numeric Family" addr, \
                       testNumericHelper, &data) < 0) \
            ret = -1; \
    } while (0)

#define DO_TEST_LOCALHOST(addr, pass) \
    do { \
        struct testIsLocalhostData data = { addr, pass }; \
        if (virTestRun("Test localhost " addr, \
                       testIsLocalhostHelper, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_UNSPEC, true);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_INET, true);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_INET6, false);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_UNIX, false);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.256", AF_UNSPEC, false);

    DO_TEST_PARSE_AND_CHECK_FORMAT("127.0.0.2", "127.0.0.2", AF_INET, true);
    DO_TEST_PARSE_AND_CHECK_FORMAT("127.0.0.2", "127.0.0.3", AF_INET, false);
    DO_TEST_PARSE_AND_CHECK_FORMAT("0", "0.0.0.0", AF_INET, true);
    DO_TEST_PARSE_AND_CHECK_FORMAT("127", "0.0.0.127", AF_INET, true);
    DO_TEST_PARSE_AND_CHECK_FORMAT("127", "127.0.0.0", AF_INET, false);
    DO_TEST_PARSE_AND_CHECK_FORMAT("127.2", "127.0.0.2", AF_INET, true);
    DO_TEST_PARSE_AND_CHECK_FORMAT("127.2", "127.2.0.0", AF_INET, false);
    DO_TEST_PARSE_AND_CHECK_FORMAT("1.2.3", "1.2.0.3", AF_INET, true);
    DO_TEST_PARSE_AND_CHECK_FORMAT("1.2.3", "1.2.3.0", AF_INET, false);
    DO_TEST_PARSE_AND_CHECK_FORMAT("::ffff:a01:203", "::ffff:10.1.2.3", AF_INET6, true);

    DO_TEST_PARSE_AND_FORMAT("::1", AF_UNSPEC, true);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_INET, false);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_INET6, true);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_UNIX, false);
    DO_TEST_PARSE_AND_FORMAT("::fffe:0:0", AF_UNSPEC, true);
    DO_TEST_PARSE_AND_FORMAT("::ffff:10.1.2.3", AF_UNSPEC, true);

    /* tests that specify a network that should contain the range */
    DO_TEST_RANGE("192.168.122.1", "192.168.122.1", "192.168.122.1", 24, 1, true);
    DO_TEST_RANGE("192.168.122.1", "192.168.122.20", "192.168.122.22", 24, 20, true);
    /* start of range is "network address" */
    DO_TEST_RANGE("192.168.122.0", "192.168.122.254", "192.168.122.1", 24, -1, false);
    /* end of range is "broadcast address" */
    DO_TEST_RANGE("192.168.122.1", "192.168.122.255", "192.168.122.1", 24, -1, false);
    DO_TEST_RANGE("192.168.122.0", "192.168.122.255", "192.168.122.1", 16, 256, true);
    /* range is reversed */
    DO_TEST_RANGE("192.168.122.20", "192.168.122.1", "192.168.122.1", 24, -1, false);
    /* start address outside network */
    DO_TEST_RANGE("10.0.0.1", "192.168.122.20", "192.168.122.1", 24, -1, false);
    /* end address outside network and range reversed */
    DO_TEST_RANGE("192.168.122.20", "10.0.0.1", "192.168.122.1", 24, -1, false);
    /* entire range outside network */
    DO_TEST_RANGE("172.16.0.50", "172.16.0.254", "1.2.3.4", 8, -1, false);
    /* end address outside network */
    DO_TEST_RANGE("192.168.122.1", "192.168.123.20", "192.168.122.22", 24, -1, false);
    DO_TEST_RANGE("192.168.122.1", "192.168.123.20", "192.168.122.22", 23, 276, true);

    DO_TEST_RANGE("2000::1", "2000::1", "2000::1", 64, 1, true);
    DO_TEST_RANGE("2000::1", "2000::2", "2000::1", 64, 2, true);
    /* range reversed */
    DO_TEST_RANGE("2000::2", "2000::1", "2000::1", 64, -1, false);
    /* range too large (> 65536) */
    DO_TEST_RANGE("2000::1", "9001::1", "2000::1", 64, -1, false);

    /* tests that *don't* specify a containing network
     * (so fewer things can be checked)
     */
    DO_TEST_RANGE_SIMPLE("192.168.122.1", "192.168.122.1", 1, true);
    DO_TEST_RANGE_SIMPLE("192.168.122.1", "192.168.122.20", 20, true);
    DO_TEST_RANGE_SIMPLE("192.168.122.0", "192.168.122.255", 256, true);
    /* range is reversed */
    DO_TEST_RANGE_SIMPLE("192.168.122.20", "192.168.122.1", -1, false);
    /* range too large (> 65536) */
    DO_TEST_RANGE_SIMPLE("10.0.0.1", "192.168.122.20", -1, false);
    /* range reversed */
    DO_TEST_RANGE_SIMPLE("192.168.122.20", "10.0.0.1", -1, false);
    DO_TEST_RANGE_SIMPLE("172.16.0.50", "172.16.0.254", 205, true);
    DO_TEST_RANGE_SIMPLE("192.168.122.1", "192.168.123.20", 276, true);

    DO_TEST_RANGE_SIMPLE("2000::1", "2000::1", 1, true);
    DO_TEST_RANGE_SIMPLE("2000::1", "2000::2", 2, true);
    /* range reversed */
    DO_TEST_RANGE_SIMPLE("2000::2", "2000::1", -1, false);
    /* range too large (> 65536) */
    DO_TEST_RANGE_SIMPLE("2000::1", "9001::1", -1, false);

    DO_TEST_NETMASK("192.168.122.1", "192.168.122.2",
                    "255.255.255.0", true);
    DO_TEST_NETMASK("192.168.122.1", "192.168.122.4",
                    "255.255.255.248", true);
    DO_TEST_NETMASK("192.168.122.1", "192.168.123.2",
                    "255.255.255.0", false);
    DO_TEST_NETMASK("192.168.122.1", "192.168.123.2",
                    "255.255.0.0", true);

    DO_TEST_NETMASK("2000::1:1", "2000::1:1",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0", true);
    DO_TEST_NETMASK("2000::1:1", "2000::2:1",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0", false);
    DO_TEST_NETMASK("2000::1:1", "2000::2:1",
                    "ffff:ffff:ffff:ffff:ffff:ffff:fff8:0", true);
    DO_TEST_NETMASK("2000::1:1", "9000::1:1",
                    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0", false);

    DO_TEST_MASK_NETWORK("2001:db8:ca2:2::1", 64, "2001:db8:ca2:2::");

    DO_TEST_WILDCARD("0.0.0.0", true);
    DO_TEST_WILDCARD("::", true);
    DO_TEST_WILDCARD("0", true);
    DO_TEST_WILDCARD("0.0", true);
    DO_TEST_WILDCARD("0.0.0", true);
    DO_TEST_WILDCARD("1", false);
    DO_TEST_WILDCARD("0.1", false);

    DO_TEST_NUMERIC_FAMILY("0.0.0.0", AF_INET);
    DO_TEST_NUMERIC_FAMILY("::", AF_INET6);
    DO_TEST_NUMERIC_FAMILY("1", AF_INET);
    DO_TEST_NUMERIC_FAMILY("::ffff", AF_INET6);
    DO_TEST_NUMERIC_FAMILY("examplehost", -1);

    DO_TEST_LOCALHOST("127.0.0.1", true);
    DO_TEST_LOCALHOST("2130706433", true);

    /* Octal IPv4 doesn't work in getaddrinfo on macOS */
#ifndef __APPLE__
    DO_TEST_LOCALHOST("0177.0.0.01", true);
#endif
    DO_TEST_LOCALHOST("::1", true);
    DO_TEST_LOCALHOST("0::1", true);
    DO_TEST_LOCALHOST("0:0:0::1", true);
    DO_TEST_LOCALHOST("[00:0::1]", false);
    DO_TEST_LOCALHOST("[::1]", false);
    DO_TEST_LOCALHOST("128.0.0.1", false);
    DO_TEST_LOCALHOST("0.0.0.1", false);
    DO_TEST_LOCALHOST("hello", false);
    DO_TEST_LOCALHOST("fe80::1:1", false);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
