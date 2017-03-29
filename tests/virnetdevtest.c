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
 *
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "testutils.h"

#ifdef __linux__

# include "virnetdev.h"

# define VIR_FROM_THIS VIR_FROM_NONE

struct testVirNetDevGetLinkInfoData {
    const char *ifname;         /* ifname to get info on */
    virNetDevIfState state;     /* expected state */
    unsigned int speed;         /* expected speed */
};

static int
testVirNetDevGetLinkInfo(const void *opaque)
{
    int ret = -1;
    const struct testVirNetDevGetLinkInfoData *data = opaque;
    virNetDevIfLink lnk;

    if (virNetDevGetLinkInfo(data->ifname, &lnk) < 0)
        goto cleanup;

    if (lnk.state != data->state) {
        fprintf(stderr,
                "Fetched link state (%s) doesn't match the expected one (%s)",
                virNetDevIfStateTypeToString(lnk.state),
                virNetDevIfStateTypeToString(data->state));
        goto cleanup;
    }

    if (lnk.speed != data->speed) {
        fprintf(stderr,
                "Fetched link speed (%u) doesn't match the expected one (%u)",
                lnk.speed, data->speed);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST_LINK(ifname, state, speed)                                 \
    do {                                                                    \
        struct testVirNetDevGetLinkInfoData data = {ifname, state, speed};  \
        if (virTestRun("Link info: " # ifname,                              \
                       testVirNetDevGetLinkInfo, &data) < 0)                \
            ret = -1;                                                       \
    } while (0)

    DO_TEST_LINK("eth0", VIR_NETDEV_IF_STATE_UP, 1000);
    DO_TEST_LINK("lo", VIR_NETDEV_IF_STATE_UNKNOWN, 0);
    DO_TEST_LINK("eth0-broken", VIR_NETDEV_IF_STATE_DOWN, 0);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/virnetdevmock.so")
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
