/*
 * Copyright (C) 2015 Red Hat, Inc.
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

#include "internal.h"
#include "testutils.h"

#define LIBVIRT_VIRNETDEVPRIV_H_ALLOW

#ifdef __linux__

# include "virmock.h"
# include "virnetdevpriv.h"

# define VIR_FROM_THIS VIR_FROM_NONE

struct testVirNetDevGetLinkInfoData {
    const char *ifname;         /* ifname to get info on */
    virNetDevIfState state;     /* expected state */
    unsigned int speed;         /* expected speed */
};

static int
testVirNetDevGetLinkInfo(const void *opaque)
{
    const struct testVirNetDevGetLinkInfoData *data = opaque;
    virNetDevIfLink lnk;

    if (virNetDevGetLinkInfo(data->ifname, &lnk) < 0)
        return -1;

    if (lnk.state != data->state) {
        fprintf(stderr,
                "Fetched link state (%s) doesn't match the expected one (%s)",
                virNetDevIfStateTypeToString(lnk.state),
                virNetDevIfStateTypeToString(data->state));
        return -1;
    }

    if (lnk.speed != data->speed) {
        fprintf(stderr,
                "Fetched link speed (%u) doesn't match the expected one (%u)",
                lnk.speed, data->speed);
        return -1;
    }

    return 0;
}

# if defined(WITH_LIBNL)

int
(*real_virNetDevSendVfSetLinkRequest)(const char *ifname,
                                      int vfInfoType,
                                      const void *payload,
                                      const size_t payloadLen);

int
(*real_virNetDevSetVfMac)(const char *ifname,
                          int vf,
                          const virMacAddr *macaddr,
                          bool *allowRetry);

int
(*real_virNetDevSetVfVlan)(const char *ifname,
                           int vf,
                           const int *vlanid);

static void
init_syms(void)
{
    VIR_MOCK_REAL_INIT(virNetDevSendVfSetLinkRequest);
    VIR_MOCK_REAL_INIT(virNetDevSetVfMac);
    VIR_MOCK_REAL_INIT(virNetDevSetVfVlan);
}

int
virNetDevSetVfMac(const char *ifname,
                  int vf,
                  const virMacAddr *macaddr,
                  bool *allowRetry)
{
    init_syms();

    if (STREQ_NULLABLE(ifname, "fakeiface-macerror")) {
        return -EBUSY;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-altmacerror")) {
        return -EINVAL;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-macerror-novlanerror")) {
        return -EAGAIN;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-macerror-vlanerror")) {
        return -ENODEV;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-nomacerror-vlanerror")) {
        return 0;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-nomacerror-novlanerror")) {
        return 0;
    }
    return real_virNetDevSetVfMac(ifname, vf, macaddr, allowRetry);
}

int
virNetDevSetVfVlan(const char *ifname,
                   int vf,
                   const int *vlanid)
{
    init_syms();

    if (STREQ_NULLABLE(ifname, "fakeiface-macerror-vlanerror")) {
        return -EPERM;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-nomacerror-vlanerror")) {
        return -EPERM;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-macerror-novlanerror")) {
        return 0;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-nomacerror-novlanerror")) {
        return 0;
    }
    return real_virNetDevSetVfVlan(ifname, vf, vlanid);
}

int
virNetDevSendVfSetLinkRequest(const char *ifname,
                              int vfInfoType,
                              const void *payload,
                              const size_t payloadLen)
{
    init_syms();

    if (STREQ_NULLABLE(ifname, "fakeiface-eperm")) {
        return -EPERM;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-eagain")) {
        return -EAGAIN;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-einval")) {
        return -EINVAL;
    } else if (STREQ_NULLABLE(ifname, "fakeiface-ok")) {
        return 0;
    }
    return real_virNetDevSendVfSetLinkRequest(ifname, vfInfoType, payload, payloadLen);
}

static int
testVirNetDevSetVfMac(const void *opaque G_GNUC_UNUSED)
{
    struct testCase {
        const char *ifname;
        const int vf_num;
        const virMacAddr macaddr;
        bool allow_retry;
        const int rc;
    };
    size_t i = 0;
    int rc = 0;
    struct testCase testCases[] = {
        { .ifname = "fakeiface-ok", .vf_num = 1,
          .macaddr = { .addr = { 0, 0, 0, 0, 0, 0 } }, .allow_retry = false, .rc = 0 },
        { .ifname = "fakeiface-ok", .vf_num = 2,
          .macaddr = { .addr = { 0, 0, 0, 7, 7, 7 } }, .allow_retry = false, .rc = 0 },
        { .ifname = "fakeiface-ok", .vf_num = 3,
          .macaddr = { .addr = { 0, 0, 0, 0, 0, 0 } }, .allow_retry = true, .rc = 0 },
        { .ifname = "fakeiface-ok", .vf_num = 4,
          .macaddr = { .addr = { 0, 0, 0, 7, 7, 7 } }, .allow_retry = true, .rc = 0 },
        { .ifname = "fakeiface-eperm", .vf_num = 5,
          .macaddr = { .addr = { 0, 0, 0, 0, 0, 0 } }, .allow_retry = false, .rc = -EPERM },
        { .ifname = "fakeiface-einval", .vf_num = 6,
          .macaddr = { .addr = { 0, 0, 0, 0, 0, 0 } }, .allow_retry = false, .rc = -EINVAL },
        { .ifname = "fakeiface-einval", .vf_num = 7,
          .macaddr = { .addr = { 0, 0, 0, 0, 0, 0 } }, .allow_retry = true, .rc = -EINVAL },
        { .ifname = "fakeiface-einval", .vf_num = 8,
          .macaddr = { .addr = { 0, 0, 0, 7, 7, 7 } }, .allow_retry = false, .rc = -EINVAL },
        { .ifname = "fakeiface-einval", .vf_num = 9,
          .macaddr = { .addr = { 0, 0, 0, 7, 7, 7 } }, .allow_retry = true, .rc = -EINVAL },
    };

    for (i = 0; i < G_N_ELEMENTS(testCases); ++i) {
       rc = virNetDevSetVfMac(testCases[i].ifname, testCases[i].vf_num,
                              &testCases[i].macaddr, &testCases[i].allow_retry);
       if (rc != testCases[i].rc) {
           return -1;
       }
    }
    return 0;
}

static int
testVirNetDevSetVfMissingMac(const void *opaque G_GNUC_UNUSED)
{
    bool allowRetry = false;
    /* NULL MAC pointer. */
    if (virNetDevSetVfMac("fakeiface-ok", 1, NULL, &allowRetry) != -EINVAL) {
        return -1;
    }
    allowRetry = true;
    if (virNetDevSetVfMac("fakeiface-ok", 1, NULL, &allowRetry) != -EINVAL) {
        return -1;
    }
    return 0;
}

static int
testVirNetDevSetVfVlan(const void *opaque G_GNUC_UNUSED)
{
    struct testCase {
        const char *ifname;
        const int vf_num;
        const int vlan_id;
        const int rc;
    };
    struct nullVlanTestCase {
        const char *ifname;
        const int vf_num;
        const int rc;
    };
    size_t i = 0;
    int rc = 0;
    const struct testCase testCases[] = {
        /* VLAN ID is out of range of valid values (0-4095). */
        { .ifname = "enxdeadbeefcafe", .vf_num = 1, .vlan_id = 4096, .rc = -ERANGE },
        { .ifname = "enxdeadbeefcafe", .vf_num = 1, .vlan_id = -1, .rc = -ERANGE },
        { .ifname = "fakeiface-eperm", .vf_num = 1, .vlan_id = 0, .rc = -EPERM },
        { .ifname = "fakeiface-eagain", .vf_num = 1, .vlan_id = 0, .rc = -EAGAIN },
        /* Successful requests with vlan id 0 need to have a zero return code. */
        { .ifname = "fakeiface-ok", .vf_num = 1, .vlan_id = 0, .rc = 0 },
        /* Requests with a non-zero VLAN ID that result in an EPERM need to result in failures.
         * failures. */
        { .ifname = "fakeiface-eperm", .vf_num = 1, .vlan_id = 42, .rc = -EPERM },
        /* Requests with a non-zero VLAN ID that result in some other errors need to result in
         * failures. */
        { .ifname = "fakeiface-eagain", .vf_num = 1, .vlan_id = 42, .rc = -EAGAIN },
        /* Successful requests with a non-zero VLAN ID */
        { .ifname = "fakeiface-ok", .vf_num = 1, .vlan_id = 42, .rc = 0 },
    };

    const struct nullVlanTestCase nullVLANTestCases[] = {
        { .ifname = "fakeiface-eperm", .vf_num = 1, .rc = 0 },
        { .ifname = "fakeiface-eagain", .vf_num = 1, .rc = -EAGAIN },
        /* Successful requests with vlan id 0 need to have a zero return code. */
        { .ifname = "fakeiface-ok", .vf_num = 1, .rc = 0 },
    };

    for (i = 0; i < G_N_ELEMENTS(testCases); ++i) {
       rc = virNetDevSetVfVlan(testCases[i].ifname, testCases[i].vf_num, &testCases[i].vlan_id);
       if (rc != testCases[i].rc) {
           return -1;
       }
    }

    for (i = 0; i < G_N_ELEMENTS(nullVLANTestCases); ++i) {
       rc = virNetDevSetVfVlan(nullVLANTestCases[i].ifname, nullVLANTestCases[i].vf_num, NULL);
       if (rc != nullVLANTestCases[i].rc) {
           return -1;
       }
    }

    return 0;
}

static int
testVirNetDevSetVfConfig(const void *opaque G_GNUC_UNUSED)
{
    struct testCase {
        const char *ifname;
        const int rc;
    };
    int rc = 0;
    size_t i = 0;
    /* Nested functions are mocked so dummy values are used. */
    const virMacAddr mac = { .addr = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE }};
    const int vfNum = 1;
    const int vlanid = 0;
    bool *allowRetry = NULL;

    const struct testCase testCases[] = {
        { .ifname = "fakeiface-macerror", .rc = -EBUSY },
        { .ifname = "fakeiface-altmacerror", .rc = -EINVAL },
        { .ifname = "fakeiface-macerror-novlanerror", .rc = -EAGAIN },
        { .ifname = "fakeiface-macerror-vlanerror", .rc = -ENODEV },
        { .ifname = "fakeiface-nomacerror-novlanerror", .rc = 0 },
    };

    for (i = 0; i < G_N_ELEMENTS(testCases); ++i) {
       rc = virNetDevSetVfConfig(testCases[i].ifname, vfNum, &mac, &vlanid, allowRetry);
       if (rc != testCases[i].rc) {
           return -1;
       }
    }
    return 0;
}

# endif /* defined(WITH_LIBNL) */

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST_LINK(ifname, state, speed) \
    do { \
        struct testVirNetDevGetLinkInfoData data = {ifname, state, speed}; \
        if (virTestRun("Link info: " # ifname, \
                       testVirNetDevGetLinkInfo, &data) < 0) \
            ret = -1; \
    } while (0)

    DO_TEST_LINK("eth0", VIR_NETDEV_IF_STATE_UP, 1000);
    DO_TEST_LINK("lo", VIR_NETDEV_IF_STATE_UNKNOWN, 0);
    DO_TEST_LINK("eth0-broken", VIR_NETDEV_IF_STATE_DOWN, 0);

# if defined(WITH_LIBNL)

    if (virTestRun("Set VF MAC", testVirNetDevSetVfMac, NULL) < 0)
        ret = -1;
    if (virTestRun("Set VF MAC: missing MAC pointer", testVirNetDevSetVfMissingMac, NULL) < 0)
        ret = -1;
    if (virTestRun("Set VF VLAN", testVirNetDevSetVfVlan, NULL) < 0)
        ret = -1;
    if (virTestRun("Set VF Config", testVirNetDevSetVfConfig, NULL) < 0)
        ret = -1;

# endif /* defined(WITH_LIBNL) */

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("virnetdev"))
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
