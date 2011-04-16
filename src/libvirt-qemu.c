/*
 * libvirt-qemu.c: Interfaces for the libvirt library to handle qemu-specific
 *                 APIs.
 *
 * Copyright (C) 2010 Red Hat, Inc.
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
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#include <config.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "libvirt/libvirt-qemu.h"

#define virLibConnError(conn, error, info)                               \
    virReportErrorHelper(VIR_FROM_NONE, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

#define virLibDomainError(domain, error, info)                          \
    virReportErrorHelper(VIR_FROM_DOM, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

int
virDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                            char **result, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DEBUG("domain=%p, cmd=%s, result=%p, flags=%u", domain, cmd, result, flags);

    virResetLastError();

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return -1;
    }

    conn = domain->conn;

    if (result == NULL) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->qemuDomainMonitorCommand) {
        int ret;
        ret = conn->driver->qemuDomainMonitorCommand(domain, cmd, result,
                                                     flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return -1;
}
