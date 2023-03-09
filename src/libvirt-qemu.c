/*
 * libvirt-qemu.c: Interfaces for the libvirt library to handle QEMU-specific
 *                 APIs.
 *
 * Copyright (C) 2010-2014 Red Hat, Inc.
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

#include "virerror.h"
#include "virlog.h"
#include "viruuid.h"
#include "datatypes.h"

#define VIR_FROM_THIS VIR_FROM_NONE

VIR_LOG_INIT("libvirt-qemu");

/**
 * virDomainQemuMonitorCommand:
 * @domain: a domain object
 * @cmd: the QEMU monitor command string
 * @result: a string returned by @cmd
 * @flags: bitwise-or of supported virDomainQemuMonitorCommandFlags
 *
 * This API is QEMU specific, so it will only work with hypervisor
 * connections to the QEMU driver.
 *
 * Send an arbitrary monitor command @cmd to @domain through the
 * QEMU monitor. There are several requirements to safely and
 * successfully use this API:
 *
 *   - A @cmd that queries state without making any modifications is safe
 *   - A @cmd that alters state that is also tracked by libvirt is unsafe,
 *     and may cause libvirtd to crash
 *   - A @cmd that alters state not tracked by the current version of
 *     libvirt is possible as a means to test new QEMU features before
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
 * Since: 0.8.3
 */
int
virDomainQemuMonitorCommand(virDomainPtr domain, const char *cmd,
                            char **result, unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain, "cmd=%s, result=%p, flags=0x%x",
                     cmd, result, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(result, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainQemuMonitorCommand) {
        int ret;
        ret = conn->driver->domainQemuMonitorCommand(domain, cmd, result,
                                                     flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virDomainQemuMonitorCommandWithFiles:
 * @domain: a domain object
 * @cmd: the QEMU monitor command string
 * @ninfiles: number of filedescriptors passed in @infiles
 * @infiles: filedescriptors to be passed to QEMU with the command
 * @noutfiles: if non-NULL filled with number of returned file descriptors
 * @outfiles: if non-NULL filled with an array of returned file descriptors
 * @result: a string returned by @cmd
 * @flags: bitwise-or of supported virDomainQemuMonitorCommandFlags
 *
 * This API is QEMU specific, so it will only work with hypervisor
 * connections to the QEMU driver with local connections using the unix socket.
 *
 * Send an arbitrary monitor command @cmd with file descriptors @infiles to
 * @domain through the QEMU monitor and optionally return file descriptors via
 * @outfiles. There are several requirements to safely and successfully use
 * this API:
 *
 *   - A @cmd that queries state without making any modifications is safe
 *   - A @cmd that alters state that is also tracked by libvirt is unsafe,
 *     and may cause libvirtd to crash
 *   - A @cmd that alters state not tracked by the current version of
 *     libvirt is possible as a means to test new QEMU features before
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
 * Since: 8.2.0
 */
int
virDomainQemuMonitorCommandWithFiles(virDomainPtr domain,
                                     const char *cmd,
                                     unsigned int ninfiles,
                                     int *infiles,
                                     unsigned int *noutfiles,
                                     int **outfiles,
                                     char **result,
                                     unsigned int flags)
{
    virConnectPtr conn;

    VIR_DOMAIN_DEBUG(domain,
                     "cmd=%s, ninfiles=%u, infiles=%p, noutfiles=%p, outfiles=%p, result=%p, flags=0x%x",
                     cmd, ninfiles, infiles, noutfiles, outfiles, result, flags);

    virResetLastError();

    virCheckDomainReturn(domain, -1);
    conn = domain->conn;

    virCheckNonNullArgGoto(cmd, error);

    if (ninfiles > 0 || outfiles) {
        int rc;
        if ((rc = VIR_DRV_SUPPORTS_FEATURE(conn->driver, conn,
                                           VIR_DRV_FEATURE_FD_PASSING)) <= 0) {
            if (rc == 0)
                virReportError(VIR_ERR_ARGUMENT_UNSUPPORTED, "%s",
                               _("fd passing is not supported by this connection"));
            goto error;
        }
    }

    virCheckNonNullArgGoto(result, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainQemuMonitorCommandWithFiles) {
        int ret;
        ret = conn->driver->domainQemuMonitorCommandWithFiles(domain, cmd,
                                                              ninfiles, infiles,
                                                              noutfiles, outfiles,
                                                              result, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
 *
 * Since: 0.9.4
 */
virDomainPtr
virDomainQemuAttach(virConnectPtr conn,
                    unsigned int pid_value,
                    unsigned int flags)
{
    pid_t pid = pid_value;
    VIR_DEBUG("conn=%p, pid=%u, flags=0x%x", conn, pid_value, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);
    virCheckNonZeroArgGoto(pid_value, error);
    if (pid != pid_value) {
        virReportInvalidArg(pid_value,
                            _("pid_value in %1$s is too large"),
                            __FUNCTION__);
        goto error;
    }

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainQemuAttach) {
        virDomainPtr ret;
        ret = conn->driver->domainQemuAttach(conn, pid_value, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

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
 *
 * Since: 0.10.0
 */
char *
virDomainQemuAgentCommand(virDomainPtr domain,
                          const char *cmd,
                          int timeout,
                          unsigned int flags)
{
    virConnectPtr conn;
    char *ret;

    VIR_DOMAIN_DEBUG(domain, "cmd=%s, timeout=%d, flags=0x%x",
                     cmd, timeout, flags);

    virResetLastError();

    virCheckDomainReturn(domain, NULL);
    conn = domain->conn;

    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver->domainQemuAgentCommand) {
        ret = conn->driver->domainQemuAgentCommand(domain, cmd,
                                                   timeout, flags);
        if (!ret)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(conn);
    return NULL;
}


/**
 * virConnectDomainQemuMonitorEventRegister:
 * @conn: pointer to the connection
 * @dom: pointer to the domain, or NULL
 * @event: name of the event, or NULL
 * @cb: callback to the function handling monitor events
 * @opaque: opaque data to pass on to the callback
 * @freecb: optional function to deallocate opaque when not used anymore
 * @flags: bitwise-OR of virConnectDomainQemuMonitorEventRegisterFlags
 *
 * This API is QEMU specific, so it will only work with hypervisor
 * connections to the QEMU driver.
 *
 * Adds a callback to receive notifications of arbitrary QEMU monitor events
 * occurring on a domain.  Many QEMU monitor events also result in a libvirt
 * event which can be delivered via virConnectDomainEventRegisterAny(); this
 * command is primarily for testing new QEMU events that have not yet been
 * given a libvirt counterpart event.
 *
 * If @dom is NULL, then events will be monitored for any domain. If @dom
 * is non-NULL, then only the specific domain will be monitored.
 *
 * If @event is NULL, then all monitor events will be reported. If @event is
 * non-NULL, then only specific monitor events will be reported.  @flags
 * controls how the filtering is performed: 0 requests an exact match, while
 * VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_REGEX states that @event
 * is a basic regular expression.  Additionally, including
 * VIR_CONNECT_DOMAIN_QEMU_MONITOR_EVENT_REGISTER_NOCASE lets @event match
 * case-insensitively.
 *
 * The virDomainPtr object handle passed into the callback upon delivery
 * of an event is only valid for the duration of execution of the callback.
 * If the callback wishes to keep the domain object after the callback returns,
 * it shall take a reference to it, by calling virDomainRef().
 * The reference can be released once the object is no longer required
 * by calling virDomainFree().
 *
 * The return value from this method is a positive integer identifier
 * for the callback. To unregister a callback, this callback ID should
 * be passed to the virConnectDomainQemuMonitorEventDeregister() method.
 *
 * Returns a callback identifier on success, -1 on failure
 *
 * Since: 1.2.3
 */
int
virConnectDomainQemuMonitorEventRegister(virConnectPtr conn,
                                         virDomainPtr dom,
                                         const char *event,
                                         virConnectDomainQemuMonitorEventCallback cb,
                                         void *opaque,
                                         virFreeCallback freecb,
                                         unsigned int flags)
{
    VIR_DOMAIN_DEBUG(dom,
                     "conn=%p, event=%s, cb=%p, opaque=%p, freecb=%p, flags=0x%x",
                     conn, NULLSTR(event), cb, opaque, freecb, flags);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    if (dom) {
        virCheckDomainGoto(dom, error);
        if (dom->conn != conn) {
            virReportInvalidArg(dom,
                                _("domain '%1$s' in %2$s must match connection"),
                                dom->name, __FUNCTION__);
            goto error;
        }
    }
    virCheckNonNullArgGoto(cb, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver && conn->driver->connectDomainQemuMonitorEventRegister) {
        int ret;
        ret = conn->driver->connectDomainQemuMonitorEventRegister(conn, dom, event, cb, opaque, freecb, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}


/**
 * virConnectDomainQemuMonitorEventDeregister:
 * @conn: pointer to the connection
 * @callbackID: the callback identifier
 *
 * Removes an event callback. The callbackID parameter should be the
 * value obtained from a previous virConnectDomainQemuMonitorEventRegister()
 * method.
 *
 * Returns 0 on success, -1 on failure
 *
 * Since: 1.2.3
 */
int
virConnectDomainQemuMonitorEventDeregister(virConnectPtr conn,
                                           int callbackID)
{
    VIR_DEBUG("conn=%p, callbackID=%d", conn, callbackID);

    virResetLastError();

    virCheckConnectReturn(conn, -1);
    virCheckNonNegativeArgGoto(callbackID, error);
    virCheckReadOnlyGoto(conn->flags, error);

    if (conn->driver && conn->driver->connectDomainQemuMonitorEventDeregister) {
        int ret;
        ret = conn->driver->connectDomainQemuMonitorEventDeregister(conn, callbackID);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();
 error:
    virDispatchError(conn);
    return -1;
}
