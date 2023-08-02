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
 */

#include <config.h>

#include "testutils.h"

#ifdef WITH_NSS

# include "libvirt_nss.h"

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
    struct hostent resolved = { 0 };
    char buf[BUF_SIZE] = { 0 };
    char **addrList;
    int rv, tmp_errno = 0, tmp_herrno = 0;
    size_t i = 0;

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
        return -1;
    } else if (rv == NSS_STATUS_NOTFOUND) {
        /* Resolving failed. Should it? */
        if (!existent)
            return 0;
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Resolving of %s failed",
                           data->hostname);
        return -1;
    }

    /* Resolving succeeded. Should it? */
    if (!existent) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Resolving of %s succeeded but was expected to fail",
                       data->hostname);
        return -1;
    }

    /* Now lets see if resolved address match our expectations. */

    if (!resolved.h_name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "resolved.h_name empty");
        return -1;
    }

    if (data->af != AF_UNSPEC &&
        resolved.h_addrtype != data->af) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected AF_INET (%d) got %d",
                       data->af, resolved.h_addrtype);
        return -1;
    }

    if ((resolved.h_addrtype == AF_INET && resolved.h_length != 4) ||
        (resolved.h_addrtype == AF_INET6 && resolved.h_length != 16)) {
        /* IPv4 addresses are encoded into 4 bytes */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected %d bytes long address, got %d",
                       resolved.h_addrtype == AF_INET ? 4 : 16,
                       resolved.h_length);
        return -1;
    }

    if (!resolved.h_addr_list) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       "resolved.h_addr_list empty");
        return -1;
    }

    addrList = resolved.h_addr_list;
    i = 0;
    while (*addrList) {
        virSocketAddr sa = { 0 };
        g_autofree char *ipAddr = NULL;
        void *address = *addrList;

        if (resolved.h_addrtype == AF_INET) {
            virSocketAddrSetIPv4AddrNetOrder(&sa, *((uint32_t *) address));
        } else {
            virSocketAddrSetIPv6AddrNetOrder(&sa, address);
        }

        if (!(ipAddr = virSocketAddrFormat(&sa))) {
            /* error reported by helper */
            return -1;
        }

        if (STRNEQ_NULLABLE(data->ipAddr[i], ipAddr)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "Unexpected address %s, expecting %s",
                           ipAddr, NULLSTR(data->ipAddr[i]));
            return -1;
        }

        addrList++;
        i++;
    }

    if (data->ipAddr[i]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "Expected %s address, got NULL",
                       data->ipAddr[i]);
        return -1;
    }

    return 0;
}

static int
mymain(void)
{
    int ret = 0;

# define DO_TEST(name, family, ...) \
    do { \
        const char *addr[] = { __VA_ARGS__, NULL}; \
        struct testNSSData data = { \
            .hostname = name, .ipAddr = addr, .af = family, \
        }; \
        if (virTestRun(name, testGetHostByName, &data) < 0) \
            ret = -1; \
    } while (0)

# if !defined(LIBVIRT_NSS_GUEST)
    DO_TEST("fedora", AF_INET, "192.168.122.197", "192.168.122.198", "192.168.122.199", "192.168.122.3");
    DO_TEST("gentoo", AF_INET, "192.168.122.254");
    DO_TEST("Gentoo", AF_INET, "192.168.122.254");
    DO_TEST("gentoo", AF_INET6, "2001:1234:dead:beef::2");
    DO_TEST("gentoo", AF_UNSPEC, "192.168.122.254");
    DO_TEST("non-existent", AF_UNSPEC, NULL);
# else /* defined(LIBVIRT_NSS_GUEST) */
    DO_TEST("debian", AF_INET, "192.168.122.2");
    DO_TEST("suse", AF_INET, "192.168.122.3");
# endif /* defined(LIBVIRT_NSS_GUEST) */

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN_PRELOAD(mymain, VIR_TEST_MOCK("nss"))
#else
int
main(void)
{
    return EXIT_AM_SKIP;
}
#endif
