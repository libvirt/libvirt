/*
 * sockettest.c: Testing for src/util/network.c APIs
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "virsocketaddr.h"
#include "testutils.h"
#include "logging.h"
#include "memory.h"

static void testQuietError(void *userData ATTRIBUTE_UNUSED,
                           virErrorPtr error ATTRIBUTE_UNUSED)
{
    /* nada */
}

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
    char *newaddrstr;

    newaddrstr = virSocketAddrFormat(addr);
    if (!newaddrstr)
        return pass ? -1 : 0;

    if (STRNEQ(newaddrstr, addrstr)) {
        virtTestDifference(stderr, newaddrstr, addrstr);
        VIR_FREE(newaddrstr);
        return pass ? -1 : 0;
    } else {
        VIR_FREE(newaddrstr);
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


static int testRange(const char *saddrstr, const char *eaddrstr, int size, bool pass)
{
    virSocketAddr saddr;
    virSocketAddr eaddr;

    if (virSocketAddrParse(&saddr, saddrstr, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&eaddr, eaddrstr, AF_UNSPEC) < 0)
        return -1;

    int gotsize = virSocketAddrGetRange(&saddr, &eaddr);
    VIR_DEBUG("Size want %d vs got %d", size, gotsize);
    if (gotsize < 0 || gotsize != size) {
        return pass ? -1 : 0;
    } else {
        return pass ? 0 : -1;
    }
}

struct testRangeData {
    const char *saddr;
    const char *eaddr;
    int size;
    bool pass;
};
static int testRangeHelper(const void *opaque)
{
    const struct testRangeData *data = opaque;
    return testRange(data->saddr, data->eaddr, data->size, data->pass);
}


static int testNetmask(const char *addr1str, const char *addr2str,
                       const char *netmaskstr, bool pass)
{
    virSocketAddr addr1;
    virSocketAddr addr2;
    virSocketAddr netmask;

    if (virSocketAddrParse(&addr1, addr1str, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&addr2, addr2str, AF_UNSPEC) < 0)
        return -1;
    if (virSocketAddrParse(&netmask, netmaskstr, AF_UNSPEC) < 0)
        return -1;

    int ret = virSocketAddrCheckNetmask(&addr1, &addr2, &netmask);

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


static int
mymain(void)
{
    int ret = 0;
    /* Some of our tests deliberately test failure cases, so
     * register a handler to stop error messages cluttering
     * up display
     */
    if (!virTestGetDebug())
        virSetErrorFunc(NULL, testQuietError);

#define DO_TEST_PARSE(addrstr, family, pass)                            \
    do {                                                                \
        virSocketAddr addr;                                             \
        struct testParseData data = { &addr, addrstr, family, pass };   \
        memset(&addr, 0, sizeof(addr));                                 \
        if (virtTestRun("Test parse " addrstr,                          \
                        1, testParseHelper, &data) < 0)                 \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_PARSE_AND_FORMAT(addrstr, family, pass)                 \
    do {                                                                \
        virSocketAddr addr;                                             \
        struct testParseData data = { &addr, addrstr, family, pass };   \
        memset(&addr, 0, sizeof(addr));                                 \
        if (virtTestRun("Test parse " addrstr " family " #family,       \
                        1, testParseHelper, &data) < 0)                 \
            ret = -1;                                                   \
        struct testFormatData data2 = { &addr, addrstr, pass };         \
        if (virtTestRun("Test format " addrstr " family " #family,      \
                        1, testFormatHelper, &data2) < 0)               \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_RANGE(saddr, eaddr, size, pass)                         \
    do {                                                                \
        struct testRangeData data = { saddr, eaddr, size, pass };       \
        if (virtTestRun("Test range " saddr " -> " eaddr " size " #size, \
                        1, testRangeHelper, &data) < 0)                 \
            ret = -1;                                                   \
    } while (0)

#define DO_TEST_NETMASK(addr1, addr2, netmask, pass)                    \
    do {                                                                \
        struct testNetmaskData data = { addr1, addr2, netmask, pass };  \
        if (virtTestRun("Test netmask " addr1 " + " addr2 " in " netmask, \
                        1, testNetmaskHelper, &data) < 0)               \
            ret = -1;                                                   \
    } while (0)


    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_UNSPEC, true);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_INET, true);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_INET6, false);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.1", AF_UNIX, false);
    DO_TEST_PARSE_AND_FORMAT("127.0.0.256", AF_UNSPEC, false);

    DO_TEST_PARSE_AND_FORMAT("::1", AF_UNSPEC, true);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_INET, false);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_INET6, true);
    DO_TEST_PARSE_AND_FORMAT("::1", AF_UNIX, false);
    DO_TEST_PARSE_AND_FORMAT("::ffff", AF_UNSPEC, true);

    DO_TEST_RANGE("192.168.122.1", "192.168.122.1", 1, true);
    DO_TEST_RANGE("192.168.122.1", "192.168.122.20", 20, true);
    DO_TEST_RANGE("192.168.122.0", "192.168.122.255", 256, true);
    DO_TEST_RANGE("192.168.122.20", "192.168.122.1", -1, false);
    DO_TEST_RANGE("10.0.0.1", "192.168.122.20", -1, false);
    DO_TEST_RANGE("192.168.122.20", "10.0.0.1", -1, false);

    DO_TEST_RANGE("2000::1", "2000::1", 1, true);
    DO_TEST_RANGE("2000::1", "2000::2", 2, true);
    DO_TEST_RANGE("2000::2", "2000::1", -1, false);
    DO_TEST_RANGE("2000::1", "9001::1", -1, false);

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

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
