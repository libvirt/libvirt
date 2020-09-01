/*
 * Copyright (C) 2013-2014 Red Hat, Inc.
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

#if WITH_DLFCN_H
# include <dlfcn.h>
#endif

#if defined(__linux__) && defined(RTLD_NEXT)
# include "virsocket.h"
# include <unistd.h>

static bool host_has_ipv6;
static int (*realsocket)(int domain, int type, int protocol);

static void init_syms(void)
{
    int fd;

    if (realsocket)
        return;

    realsocket = dlsym(RTLD_NEXT, "socket");

    if (!realsocket) {
        fprintf(stderr, "Unable to find 'socket' symbol\n");
        abort();
    }

    fd = realsocket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
        return;

    host_has_ipv6 = true;
    close(fd);
}

int socket(int domain,
           int type,
           int protocol)
{
    init_syms();

    if (getenv("LIBVIRT_TEST_IPV4ONLY") && domain == AF_INET6) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    return realsocket(domain, type, protocol);
}

int bind(int sockfd G_GNUC_UNUSED,
         const struct sockaddr *addr,
         socklen_t addrlen G_GNUC_UNUSED)
{
    struct sockaddr_in saddr;

    memcpy(&saddr, addr, sizeof(saddr));

    if (host_has_ipv6 && !getenv("LIBVIRT_TEST_IPV4ONLY")) {
        if (saddr.sin_port == htons(5900) ||
            (saddr.sin_family == AF_INET &&
             saddr.sin_port == htons(5904)) ||
            (saddr.sin_family == AF_INET6 &&
             (saddr.sin_port == htons(5905) ||
              saddr.sin_port == htons(5906)))) {
            errno = EADDRINUSE;
            return -1;
        }
        return 0;
    }

    if (saddr.sin_port == htons(5900) ||
        saddr.sin_port == htons(5904) ||
        saddr.sin_port == htons(5905) ||
        saddr.sin_port == htons(5906)) {
        errno = EADDRINUSE;
        return -1;
    }

    return 0;
}

#else /* defined(__linux__) && defined(RTLD_NEXT) */
/* Nothing to override on other platforms. */
#endif
