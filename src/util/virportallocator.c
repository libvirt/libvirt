/*
 * virportallocator.c: Allocate & track TCP port allocations
 *
 * Copyright (C) 2013 Red Hat, Inc.
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

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "viralloc.h"
#include "virbitmap.h"
#include "virportallocator.h"
#include "virthread.h"
#include "virerror.h"
#include "virfile.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_NONE

struct _virPortAllocator {
    virObjectLockable parent;
    virBitmapPtr bitmap;

    char *name;

    unsigned short start;
    unsigned short end;
};

static virClassPtr virPortAllocatorClass;

static void
virPortAllocatorDispose(void *obj)
{
    virPortAllocatorPtr pa = obj;

    virBitmapFree(pa->bitmap);
    VIR_FREE(pa->name);
}

static int virPortAllocatorOnceInit(void)
{
    if (!(virPortAllocatorClass = virClassNew(virClassForObjectLockable(),
                                              "virPortAllocator",
                                              sizeof(virPortAllocator),
                                              virPortAllocatorDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virPortAllocator)

virPortAllocatorPtr virPortAllocatorNew(const char *name,
                                        unsigned short start,
                                        unsigned short end)
{
    virPortAllocatorPtr pa;

    if (start >= end) {
        virReportInvalidArg(start, "start port %d must be less than end port %d",
                            start, end);
        return NULL;
    }

    if (virPortAllocatorInitialize() < 0)
        return NULL;

    if (!(pa = virObjectLockableNew(virPortAllocatorClass)))
        return NULL;

    pa->start = start;
    pa->end = end;

    if (!(pa->bitmap = virBitmapNew((end-start)+1)) ||
        VIR_STRDUP(pa->name, name) < 0) {
        virObjectUnref(pa);
        return NULL;
    }

    return pa;
}

static int virPortAllocatorBindToPort(bool *used,
                                      unsigned short port,
                                      int family)
{
    struct sockaddr_in6 addr6 = {
        .sin6_family = AF_INET6,
        .sin6_port = htons(port),
        .sin6_addr = in6addr_any
    };
    struct sockaddr_in addr4 = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_ANY)
    };
    struct sockaddr* addr;
    size_t addrlen;
    int v6only = 1;
    int reuse = 1;
    int ret = -1;
    int fd = -1;
    bool ipv6 = false;

    if (family == AF_INET6) {
        addr = (struct sockaddr*)&addr6;
        addrlen = sizeof(addr6);
        ipv6 = true;
    } else if (family == AF_INET) {
        addr = (struct sockaddr*)&addr4;
        addrlen = sizeof(addr4);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Unknown family %d"), family);
        return -1;
    }

    *used = false;

    fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        if (errno == EAFNOSUPPORT)
            return 0;
        virReportSystemError(errno, "%s", _("Unable to open test socket"));
        goto cleanup;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse,
                   sizeof(reuse)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set socket reuse addr flag"));
        goto cleanup;
    }

    if (ipv6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&v6only,
                           sizeof(v6only)) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set IPV6_V6ONLY flag"));
        goto cleanup;
    }

    if (bind(fd, addr, addrlen) < 0) {
        if (errno == EADDRINUSE) {
            *used = true;
            ret = 0;
        } else {
            virReportSystemError(errno, _("Unable to bind to port %d"), port);
        }
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

int virPortAllocatorAcquire(virPortAllocatorPtr pa,
                            unsigned short *port)
{
    int ret = -1;
    size_t i;

    *port = 0;
    virObjectLock(pa);

    for (i = pa->start; i <= pa->end && !*port; i++) {
        bool used = false, v6used = false;

        if (virBitmapGetBit(pa->bitmap,
                            i - pa->start, &used) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to query port %zu"), i);
            goto cleanup;
        }

        if (used)
            continue;

        if (virPortAllocatorBindToPort(&v6used, i, AF_INET6) < 0 ||
            virPortAllocatorBindToPort(&used, i, AF_INET) < 0)
            goto cleanup;

        if (!used && !v6used) {
            /* Add port to bitmap of reserved ports */
            if (virBitmapSetBit(pa->bitmap,
                                i - pa->start) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to reserve port %zu"), i);
                goto cleanup;
            }
            *port = i;
            ret = 0;
        }
    }

    if (*port == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to find an unused port in range '%s' (%d-%d)"),
                       pa->name, pa->start, pa->end);
    }
 cleanup:
    virObjectUnlock(pa);
    return ret;
}

int virPortAllocatorRelease(virPortAllocatorPtr pa,
                            unsigned short port)
{
    int ret = -1;

    if (!port)
        return 0;

    virObjectLock(pa);

    if (port < pa->start ||
        port > pa->end) {
        virReportInvalidArg(port, "port %d must be in range (%d, %d)",
                            port, pa->start, pa->end);
        goto cleanup;
    }

    if (virBitmapClearBit(pa->bitmap,
                          port - pa->start) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to release port %d"),
                       port);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(pa);
    return ret;
}
