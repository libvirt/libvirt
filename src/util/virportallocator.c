/*
 * virportallocator.c: Allocate & track TCP port allocations
 *
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
 *
 */

#include <config.h>

#include <unistd.h>

#include "virsocket.h"
#include "virbitmap.h"
#include "virportallocator.h"
#include "virthread.h"
#include "virerror.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define VIR_PORT_ALLOCATOR_NUM_PORTS 65536

typedef struct _virPortAllocator virPortAllocator;
struct _virPortAllocator {
    virObjectLockable parent;
    virBitmap *bitmap;
};

struct _virPortAllocatorRange {
    char *name;

    unsigned short start;
    unsigned short end;
};

static virClass *virPortAllocatorClass;
static virPortAllocator *virPortAllocatorInstance;

static void
virPortAllocatorDispose(void *obj)
{
    virPortAllocator *pa = obj;

    virBitmapFree(pa->bitmap);
}

static virPortAllocator *
virPortAllocatorNew(void)
{
    virPortAllocator *pa;

    if (!(pa = virObjectLockableNew(virPortAllocatorClass)))
        return NULL;

    pa->bitmap = virBitmapNew(VIR_PORT_ALLOCATOR_NUM_PORTS);

    return pa;
}

static int
virPortAllocatorOnceInit(void)
{
    if (!VIR_CLASS_NEW(virPortAllocator, virClassForObjectLockable()))
        return -1;

    if (!(virPortAllocatorInstance = virPortAllocatorNew()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virPortAllocator);

virPortAllocatorRange *
virPortAllocatorRangeNew(const char *name,
                         unsigned short start,
                         unsigned short end)
{
    virPortAllocatorRange *range;

    if (start >= end) {
        virReportInvalidArg(start, "start port %d must be less than end port %d",
                            start, end);
        return NULL;
    }

    range = g_new0(virPortAllocatorRange, 1);

    range->start = start;
    range->end = end;
    range->name = g_strdup(name);

    return range;
}

void
virPortAllocatorRangeFree(virPortAllocatorRange *range)
{
    if (!range)
        return;

    g_free(range->name);
    g_free(range);
}

static int
virPortAllocatorBindToPort(bool *used,
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
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Unknown family %1$d"), family);
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

    if (virSetSockReuseAddr(fd, true) < 0)
        goto cleanup;

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
            virReportSystemError(errno, _("Unable to bind to port %1$d"), port);
        }
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (fd != -1)
        closesocket(fd);
    return ret;
}

static virPortAllocator *
virPortAllocatorGet(void)
{
    if (virPortAllocatorInitialize() < 0)
        return NULL;

    return virPortAllocatorInstance;
}

int
virPortAllocatorAcquire(const virPortAllocatorRange *range,
                        unsigned short *port)
{
    size_t i;
    virPortAllocator *pa = virPortAllocatorGet();

    *port = 0;

    if (!pa)
        return -1;

    VIR_WITH_OBJECT_LOCK_GUARD(pa) {
        for (i = range->start; i <= range->end; i++) {
            bool used = false, v6used = false;

            if (virBitmapIsBitSet(pa->bitmap, i))
                continue;

            if (virPortAllocatorBindToPort(&v6used, i, AF_INET6) < 0 ||
                virPortAllocatorBindToPort(&used, i, AF_INET) < 0)
                return -1;

            if (!used && !v6used) {
                /* Add port to bitmap of reserved ports */
                if (virBitmapSetBit(pa->bitmap, i) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("Failed to reserve port %1$zu"), i);
                    return -1;
                }
                *port = i;
                return 0;
            }
        }
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Unable to find an unused port in range '%1$s' (%2$d-%3$d)"),
                   range->name, range->start, range->end);
    return -1;
}

int
virPortAllocatorRelease(unsigned short port)
{
    virPortAllocator *pa = virPortAllocatorGet();

    if (!pa)
        return -1;

    if (!port)
        return 0;

    VIR_WITH_OBJECT_LOCK_GUARD(pa) {
        ignore_value(virBitmapClearBit(pa->bitmap, port));
    }

    return 0;
}

int
virPortAllocatorSetUsed(unsigned short port)
{
    virPortAllocator *pa = virPortAllocatorGet();

    if (!pa)
        return -1;

    if (!port)
        return 0;

    VIR_WITH_OBJECT_LOCK_GUARD(pa) {
        if (virBitmapIsBitSet(pa->bitmap, port) ||
            virBitmapSetBit(pa->bitmap, port) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to reserve port %1$d"), port);
            return -1;
        }
    }

    return 0;
}
