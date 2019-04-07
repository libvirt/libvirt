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

#define VIR_PORT_ALLOCATOR_NUM_PORTS 65536

typedef struct _virPortAllocator virPortAllocator;
typedef virPortAllocator *virPortAllocatorPtr;
struct _virPortAllocator {
    virObjectLockable parent;
    virBitmapPtr bitmap;
};

struct _virPortAllocatorRange {
    char *name;

    unsigned short start;
    unsigned short end;
};

static virClassPtr virPortAllocatorClass;
static virPortAllocatorPtr virPortAllocatorInstance;

static void
virPortAllocatorDispose(void *obj)
{
    virPortAllocatorPtr pa = obj;

    virBitmapFree(pa->bitmap);
}

static virPortAllocatorPtr
virPortAllocatorNew(void)
{
    virPortAllocatorPtr pa;

    if (!(pa = virObjectLockableNew(virPortAllocatorClass)))
        return NULL;

    if (!(pa->bitmap = virBitmapNew(VIR_PORT_ALLOCATOR_NUM_PORTS)))
        goto error;

    return pa;
 error:
    virObjectUnref(pa);
    return NULL;
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

virPortAllocatorRangePtr
virPortAllocatorRangeNew(const char *name,
                         unsigned short start,
                         unsigned short end)
{
    virPortAllocatorRangePtr range;

    if (start >= end) {
        virReportInvalidArg(start, "start port %d must be less than end port %d",
                            start, end);
        return NULL;
    }

    if (VIR_ALLOC(range) < 0)
        return NULL;

    range->start = start;
    range->end = end;

    if (VIR_STRDUP(range->name, name) < 0)
        goto error;

    return range;

 error:
    virPortAllocatorRangeFree(range);
    return NULL;
}

void
virPortAllocatorRangeFree(virPortAllocatorRangePtr range)
{
    if (!range)
        return;

    VIR_FREE(range->name);
    VIR_FREE(range);
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
            virReportSystemError(errno, _("Unable to bind to port %d"), port);
        }
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FORCE_CLOSE(fd);
    return ret;
}

static virPortAllocatorPtr
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
    int ret = -1;
    size_t i;
    virPortAllocatorPtr pa = virPortAllocatorGet();

    *port = 0;

    if (!pa)
        return -1;

    virObjectLock(pa);

    for (i = range->start; i <= range->end && !*port; i++) {
        bool used = false, v6used = false;

        if (virBitmapIsBitSet(pa->bitmap, i))
            continue;

        if (virPortAllocatorBindToPort(&v6used, i, AF_INET6) < 0 ||
            virPortAllocatorBindToPort(&used, i, AF_INET) < 0)
            goto cleanup;

        if (!used && !v6used) {
            /* Add port to bitmap of reserved ports */
            if (virBitmapSetBit(pa->bitmap, i) < 0) {
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
                       range->name, range->start, range->end);
    }
 cleanup:
    virObjectUnlock(pa);
    return ret;
}

int
virPortAllocatorRelease(unsigned short port)
{
    int ret = -1;
    virPortAllocatorPtr pa = virPortAllocatorGet();

    if (!pa)
        return -1;

    if (!port)
        return 0;

    virObjectLock(pa);

    if (virBitmapClearBit(pa->bitmap, port) < 0) {
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

int
virPortAllocatorSetUsed(unsigned short port)
{
    int ret = -1;
    virPortAllocatorPtr pa = virPortAllocatorGet();

    if (!pa)
        return -1;

    if (!port)
        return 0;

    virObjectLock(pa);

    if (virBitmapIsBitSet(pa->bitmap, port) ||
        virBitmapSetBit(pa->bitmap, port) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to reserve port %d"), port);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virObjectUnlock(pa);
    return ret;
}
