/*
 * libvirt-qemu.c: Interfaces for the libvirt library to handle qemu-specific
 *                 APIs.
 *
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * Author: Chris Lalancette <clalance@redhat.com>
 */

#include <config.h>

#include "virerror.h"
#include "virlog.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_NONE

#define virLibConnError(conn, error, info)                               \
    virReportErrorHelper(VIR_FROM_NONE, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

#define virLibDomainError(domain, error, info)                          \
    virReportErrorHelper(VIR_FROM_DOM, error, NULL, __FUNCTION__,       \
                         __LINE__, info)

/**
 * virDomainQemuMonitorCommand:
 * @domain: a domain object
 * @cmd: the qemu monitor command string
 * @result: a string returned by @cmd
 * @flags: bitwise-or of supported virDomainQemuMonitorCommandFlags
 *
 * This API is QEMU specific, so it will only work with hypervisor
 * connections to the QEMU driver.
 *
 * Send an arbitrary monitor command @cmd to @domain through the
 * qemu monitor. There are several requirements to safely and
 * successfully use this API:
 *
 *   - A @cmd that queries state without making any modifications is safe
 *   - A @cmd that alters state that is also tracked by libvirt is unsafe,
 *     and may cause libvirtd to crash
 *   - A @cmd that alters state not tracked by the current version of
 *     libvirt is possible as a means to test new qemu features before
 *     they have support in libvirt, but no guarantees are made to safety
 *
 * If VIR_DOMAIN_QEMU_MONITOR_COMMAND_HMP is set, the command is
 * considered to be a human monitor command and libvirt will automatically
 * convert it into QMP if needed.  In that case the @result will also
 * be converted back from QMP.
 *
 * If successful, @result will be filled with the string output of the
 * @cmd, and the caller must free this string.
 *
 * Returns 0 in case of success, -1 in case of failure
 *
 */
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

    virCheckNonNullArgGoto(result, error);

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainQemuMonitorCommand) {
        int ret;
        ret = conn->driver->domainQemuMonitorCommand(domain, cmd, result,
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
 * @pid_value: the UNIX process ID of the external QEMU process
 * @flags: optional flags, currently unused
 *
 * This API is QEMU specific, so it will only work with hypervisor
 * connections to the QEMU driver.
 *
 * This API will attach to an externally launched QEMU process
 * identified by @pid. There are several requirements to successfully
 * attach to an external QEMU process:
 *
 *   - It must have been started with a monitor socket using the UNIX
 *     domain socket protocol.
 *   - No device hotplug/unplug, or other configuration changes can
 *     have been made via the monitor since it started.
 *   - The '-name' and '-uuid' arguments should have been set (not
 *     mandatory, but strongly recommended)
 *
 * To date, the only platforms we know of where pid_t is larger than
 * unsigned int (64-bit Windows) also lack UNIX sockets, so the choice
 * of @pid_value as an unsigned int should not present any difficulties.
 *
 * If successful, then the guest will appear in the list of running
 * domains for this connection, and other APIs should operate
 * normally (provided the above requirements were honored).
 *
 * Returns a new domain object on success, NULL otherwise
 */
virDomainPtr
virDomainQemuAttach(virConnectPtr conn,
                    unsigned int pid_value,
                    unsigned int flags)
{
    pid_t pid = pid_value;
    VIR_DEBUG("conn=%p, pid=%u, flags=%x", conn, pid_value, flags);

    virResetLastError();

    if (!VIR_IS_CONNECT(conn)) {
        virLibConnError(NULL, VIR_ERR_INVALID_CONN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    virCheckPositiveArgGoto(pid_value, error);
    if (pid != pid_value) {
        virReportInvalidArg(pid_value,
                            _("pid_value in %s is too large"),
                            __FUNCTION__);
        goto error;
    }

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(domain, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainQemuAttach) {
        virDomainPtr ret;
        ret = conn->driver->domainQemuAttach(conn, pid_value, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

error:
    virDispatchError(conn);
    return NULL;
}

/**
 * virDomainQemuAgentCommand:
 * @domain: a domain object
 * @cmd: the guest agent command string
 * @timeout: timeout seconds
 * @flags: execution flags
 *
 * Execute an arbitrary Guest Agent command.
 *
 * Issue @cmd to the guest agent running in @domain.
 * @timeout must be -2, -1, 0 or positive.
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_BLOCK(-2): meaning to block forever waiting for
 * a result.
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_DEFAULT(-1): use default timeout value.
 * VIR_DOMAIN_QEMU_AGENT_COMMAND_NOWAIT(0): does not wait.
 * positive value: wait for @timeout seconds
 *
 * Returns strings if success, NULL in failure.
 */
char *
virDomainQemuAgentCommand(virDomainPtr domain,
                          const char *cmd,
                          int timeout,
                          unsigned int flags)
{
    virConnectPtr conn;
    char *ret;

    VIR_DEBUG("domain=%p, cmd=%s, timeout=%d, flags=%x",
              domain, cmd, timeout, flags);

    if (!VIR_IS_CONNECTED_DOMAIN(domain)) {
        virLibDomainError(NULL, VIR_ERR_INVALID_DOMAIN, __FUNCTION__);
        virDispatchError(NULL);
        return NULL;
    }

    conn = domain->conn;

    if (conn->flags & VIR_CONNECT_RO) {
        virLibDomainError(NULL, VIR_ERR_OPERATION_DENIED, __FUNCTION__);
        goto error;
    }

    if (conn->driver->domainQemuAgentCommand) {
        ret = conn->driver->domainQemuAgentCommand(domain, cmd,
                                                   timeout, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virLibConnError(conn, VIR_ERR_NO_SUPPORT, __FUNCTION__);

    /* Copy to connection error object for back compatibility */
error:
    virDispatchError(conn);
    return NULL;
}
