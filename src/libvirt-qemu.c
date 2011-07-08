/*
 * libvirt-qemu.c: Interfaces for the libvirt library to handle qemu-specific
 *                 APIs.
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

    VIR_DEBUG("domain=%p, cmd=%s, result=%p, flags=%x",
              domain, cmd, result, flags);

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



/**
 * virDomainQemuAttach:
 * @conn: pointer to a hypervisor connection
 * @pid: the UNIX process ID of the external QEMU process
 * @flags: optional flags, currently unused
 *
 * This API is QEMU specific, so will only work with hypervisor
 * connections to the QEMU driver.
 *
 * This API will attach to an externally launched QEMU process
 * identified by @pid. There are several requirements to succcesfully
 * attach to an external QEMU process:
 *
 *   - It must have been started with a monitor socket using the UNIX
 *     domain socket protocol.
 *   - No device hotplug/unplug, or other configuration changes can
 *     have been made via the monitor since it started.
 *   - The '-name' and '-uuid' arguments should have been set (not
 *     mandatory, but strongly recommended)
 *
 * If successful, then the guest will appear in the list of running
 * domains for this connection, and other APIs should operate
 * normally (provided the above requirements were honoured
 *
 * Returns a new domain object on success, NULL otherwise
 */
virDomainPtr
virDomainQemuAttach(virConnectPtr conn,
                    unsigned pid,
                    unsigned int flags)
{
    VIR_DEBUG("conn=%p, pid=%u, flags=%x", conn, pid, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    if (pid <= 1) {
        virLibDomainError(domain, VIR_ERR_INVALID_ARG, __FUNCTION__);
        goto error;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->qemuDomainAttach) {
        virDomainPtr ret;
        ret = conn->driver->qemuDomainAttach(conn, pid, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}
