/*
 * Copyright (C) 2016 Red Hat, Inc.
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

#ifdef NSS

# include <stdbool.h>
# include <arpa/inet.h>
# include "libvirt_nss.h"
# include "virsocketaddr.h"

# define VIR_FROM_THIS VIR_FROM_NONE

# define BUF_SIZE 1024

struct testNSSData {
    const char *hostname;
    const char *const *ipAddr;
    int af;
};

static int
testGetHostByName(const void *opaque)
{
    const struct testNSSData *data = opaque;
    const bool existent = data->hostname && data->ipAddr && data->ipAddr[0];
    int ret = -1;
    struct hostent resolved;
    char buf[BUF_SIZE] = { 0 };
    char **addrList;
    int rv, tmp_errno = 0, tmp_herrno = 0;
    size_t i = 0, j = 0;

    memset(&resolved, 0, sizeof(resolved));

    rv = NSS_NAME(gethostbyname2)(data->hostname,
                                  data->af,
                                  &resolved,
                                  buf, sizeof(buf),
                                  &tmp_errno,
                                  &tmp_herrno);

    if (rv == NSS_STATUS_TRYAGAIN ||
        rv == NSS_STATUS_UNAVAIL ||
        rv == NSS_STATUS_RETURN) {
        /* Resolving failed in unexpected fashion. */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Resolving of %s failed due to internal error",
                       data->hostname);
        goto cleanup;
    } else if (rv == NSS_STATUS_NOTFOUND) {
        /* Resolving failed. Should it? */
        if (!existent)
            ret = 0;
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Resolving of %s failed",
                           data->hostname);
        goto cleanup;
    }

    /* Resolving succeeded. Should it? */
    if (!existent) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Resolving of %s succeeded but was expected to fail",
                       data->hostname);
        goto cleanup;
    }

    /* Now lets see if resolved address match our expectations. */

    if (!resolved.h_name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "resolved.h_name empty");
        goto cleanup;
    }

    if (data->af != AF_UNSPEC &&
        resolved.h_addrtype != data->af) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected AF_INET (%d) got %d",
                       data->af, resolved.h_addrtype);
        goto cleanup;
    }

    if ((resolved.h_addrtype == AF_INET && resolved.h_length != 4) ||
        (resolved.h_addrtype == AF_INET6 && resolved.h_length != 16)) {
        /* IPv4 addresses are encoded into 4 bytes */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected %d bytes long address, got %d",
                       resolved.h_addrtype == AF_INET ? 4 : 16,
                       resolved.h_length);
        goto cleanup;
    }

    if (!resolved.h_addr_list) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "resolved.h_addr_list empty");
        goto cleanup;
    }

    addrList = resolved.h_addr_list;
    while (*addrList) {
        virSocketAddr sa;
        char *ipAddr;
        void *address = *addrList;

        memset(&sa, 0, sizeof(sa));

        if (resolved.h_addrtype == AF_INET) {
            virSocketAddrSetIPv4AddrNetOrder(&sa, *((uint32_t *) address));
        } else {
            virSocketAddrSetIPv6AddrNetOrder(&sa, address);
        }

        if (!(ipAddr = virSocketAddrFormat(&sa))) {
            /* error reported by helper */
            goto cleanup;
        }

        for (j = 0; data->ipAddr[j]; j++) {
            if (STREQ(data->ipAddr[j], ipAddr))
                break;
        }

        if (!data->ipAddr[j]) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Unexpected address %s", ipAddr);
            VIR_FREE(ipAddr);
            goto cleanup;
        }
        VIR_FREE(ipAddr);

        addrList++;
        i++;
    }

    for (j = 0; data->ipAddr[j]; j++)
        ;

    if (i != j) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected %zu addresses, got %zu", j, i);
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

# define DO_TEST(name, family, ...)                             \
    do {                                                        \
        const char *addr[] = { __VA_ARGS__, NULL};              \
        struct testNSSData data = {                             \
            .hostname = name, .ipAddr = addr, .af = family,     \
        };                                                      \
        if (virTestRun(name, testGetHostByName, &data) < 0)     \
            ret = -1;                                           \
    } while (0)

# if !defined(LIBVIRT_NSS_GUEST)
    DO_TEST("fedora", AF_INET, "192.168.122.197", "192.168.122.198", "192.168.122.199");
    DO_TEST("gentoo", AF_INET, "192.168.122.254");
    DO_TEST("gentoo", AF_INET6, "2001:1234:dead:beef::2");
    DO_TEST("gentoo", AF_UNSPEC, "192.168.122.254");
    DO_TEST("non-existent", AF_UNSPEC, NULL);
# else /* defined(LIBVIRT_NSS_GUEST) */
    DO_TEST("debian", AF_INET, "192.168.122.2");
    DO_TEST("suse", AF_INET, "192.168.122.3");
# endif /* defined(LIBVIRT_NSS_GUEST) */

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, abs_builddir "/.libs/nssmock.so")
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
