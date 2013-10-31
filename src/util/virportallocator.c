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

int virPortAllocatorAcquire(virPortAllocatorPtr pa,
                            unsigned short *port)
{
    int ret = -1;
    size_t i;
    int fd = -1;

    *port = 0;
    virObjectLock(pa);

    for (i = pa->start; i <= pa->end && !*port; i++) {
        int reuse = 1;
        struct sockaddr_in addr;
        bool used = false;

        if (virBitmapGetBit(pa->bitmap,
                            i - pa->start, &used) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to query port %zu"), i);
            goto cleanup;
        }

        if (used)
            continue;

        addr.sin_family = AF_INET;
        addr.sin_port = htons(i);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        fd = socket(PF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to open test socket"));
            goto cleanup;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to set socket reuse addr flag"));
            goto cleanup;
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            if (errno != EADDRINUSE) {
                virReportSystemError(errno,
                                     _("Unable to bind to port %zu"), i);
                goto cleanup;
            }
            /* In use, try next */
            VIR_FORCE_CLOSE(fd);
        } else {
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
    VIR_FORCE_CLOSE(fd);
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
