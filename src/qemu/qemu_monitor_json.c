/*
 * qemu_monitor_json.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2016 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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

#include <poll.h>
#include <unistd.h>
#include <sys/time.h>

#include "qemu_monitor_json.h"
#include "qemu_alias.h"
#include "viralloc.h"
#include "virlog.h"
#include "virerror.h"
#include "virjson.h"
#include "virprobe.h"
#include "virstring.h"
#include "cpu/cpu_x86.h"
#include "virenum.h"

#ifdef WITH_DTRACE_PROBES
# include "libvirt_qemu_probes.h"
#endif

#define LIBVIRT_QEMU_MONITOR_PRIV_H_ALLOW
#include "qemu_monitor_priv.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_json");

#define LINE_ENDING "\r\n"

static void qemuMonitorJSONHandleShutdown(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleReset(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleStop(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleResume(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleRTCChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleWatchdog(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleIOError(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleVNCConnect(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleVNCInitialize(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleSPICEConnect(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleTrayChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandlePMWakeup(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandlePMSuspend(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleJobStatusChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleBalloonChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandlePMSuspendDisk(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleGuestCrashloaded(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleGuestPanic(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleDeviceDeleted(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleNicRxFilterChanged(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleSerialChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleSpiceMigrated(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleMigrationStatus(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleMigrationPass(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleAcpiOstInfo(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleBlockThreshold(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleDumpCompleted(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandlePRManagerStatusChanged(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleRdmaGidStatusChanged(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleMemoryFailure(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleMemoryDeviceSizeChange(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleDeviceUnplugErr(qemuMonitor *mon, virJSONValue *data);
static void qemuMonitorJSONHandleNetdevStreamDisconnected(qemuMonitor *mon, virJSONValue *data);

typedef struct {
    const char *type;
    void (*handler)(qemuMonitor *mon, virJSONValue *data);
} qemuEventHandler;

static qemuEventHandler eventHandlers[] = {
    { "ACPI_DEVICE_OST", qemuMonitorJSONHandleAcpiOstInfo, },
    { "BALLOON_CHANGE", qemuMonitorJSONHandleBalloonChange, },
    { "BLOCK_IO_ERROR", qemuMonitorJSONHandleIOError, },
    { "BLOCK_WRITE_THRESHOLD", qemuMonitorJSONHandleBlockThreshold, },
    { "DEVICE_DELETED", qemuMonitorJSONHandleDeviceDeleted, },
    { "DEVICE_TRAY_MOVED", qemuMonitorJSONHandleTrayChange, },
    { "DEVICE_UNPLUG_GUEST_ERROR", qemuMonitorJSONHandleDeviceUnplugErr, },
    { "DUMP_COMPLETED", qemuMonitorJSONHandleDumpCompleted, },
    { "GUEST_CRASHLOADED", qemuMonitorJSONHandleGuestCrashloaded, },
    { "GUEST_PANICKED", qemuMonitorJSONHandleGuestPanic, },
    { "JOB_STATUS_CHANGE", qemuMonitorJSONHandleJobStatusChange, },
    { "MEMORY_DEVICE_SIZE_CHANGE", qemuMonitorJSONHandleMemoryDeviceSizeChange, },
    { "MEMORY_FAILURE", qemuMonitorJSONHandleMemoryFailure, },
    { "MIGRATION", qemuMonitorJSONHandleMigrationStatus, },
    { "MIGRATION_PASS", qemuMonitorJSONHandleMigrationPass, },
    { "NETDEV_STREAM_DISCONNECTED", qemuMonitorJSONHandleNetdevStreamDisconnected, },
    { "NIC_RX_FILTER_CHANGED", qemuMonitorJSONHandleNicRxFilterChanged, },
    { "PR_MANAGER_STATUS_CHANGED", qemuMonitorJSONHandlePRManagerStatusChanged, },
    { "RDMA_GID_STATUS_CHANGED", qemuMonitorJSONHandleRdmaGidStatusChanged, },
    { "RESET", qemuMonitorJSONHandleReset, },
    { "RESUME", qemuMonitorJSONHandleResume, },
    { "RTC_CHANGE", qemuMonitorJSONHandleRTCChange, },
    { "SHUTDOWN", qemuMonitorJSONHandleShutdown, },
    { "SPICE_CONNECTED", qemuMonitorJSONHandleSPICEConnect, },
    { "SPICE_DISCONNECTED", qemuMonitorJSONHandleSPICEDisconnect, },
    { "SPICE_INITIALIZED", qemuMonitorJSONHandleSPICEInitialize, },
    { "SPICE_MIGRATE_COMPLETED", qemuMonitorJSONHandleSpiceMigrated, },
    { "STOP", qemuMonitorJSONHandleStop, },
    { "SUSPEND", qemuMonitorJSONHandlePMSuspend, },
    { "SUSPEND_DISK", qemuMonitorJSONHandlePMSuspendDisk, },
    { "VNC_CONNECTED", qemuMonitorJSONHandleVNCConnect, },
    { "VNC_DISCONNECTED", qemuMonitorJSONHandleVNCDisconnect, },
    { "VNC_INITIALIZED", qemuMonitorJSONHandleVNCInitialize, },
    { "VSERPORT_CHANGE", qemuMonitorJSONHandleSerialChange, },
    { "WAKEUP", qemuMonitorJSONHandlePMWakeup, },
    { "WATCHDOG", qemuMonitorJSONHandleWatchdog, },
    /* We use bsearch, so keep this list sorted.  */
};

static int
qemuMonitorEventCompare(const void *key, const void *elt)
{
    const char *type = key;
    const qemuEventHandler *handler = elt;
    return strcmp(type, handler->type);
}

static int
qemuMonitorJSONIOProcessEvent(qemuMonitor *mon,
                              virJSONValue *obj)
{
    const char *type;
    qemuEventHandler *handler;
    virJSONValue *data;
    g_autofree char *details = NULL;
    virJSONValue *timestamp;
    long long seconds = -1;
    unsigned int micros = 0;

    VIR_DEBUG("mon=%p obj=%p", mon, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

    /* Not all events have data; and event reporting is best-effort only */
    if ((data = virJSONValueObjectGet(obj, "data")))
        details = virJSONValueToString(data, false);
    if ((timestamp = virJSONValueObjectGet(obj, "timestamp"))) {
        ignore_value(virJSONValueObjectGetNumberLong(timestamp, "seconds",
                                                     &seconds));
        ignore_value(virJSONValueObjectGetNumberUint(timestamp, "microseconds",
                                                     &micros));
    }
    qemuMonitorEmitEvent(mon, type, seconds, micros, details);

    handler = bsearch(type, eventHandlers, G_N_ELEMENTS(eventHandlers),
                      sizeof(eventHandlers[0]), qemuMonitorEventCompare);
    if (handler) {
        VIR_DEBUG("handle %s handler=%p data=%p", type,
                  handler->handler, data);
        (handler->handler)(mon, data);
    }
    return 0;
}

int
qemuMonitorJSONIOProcessLine(qemuMonitor *mon,
                             const char *line,
                             qemuMonitorMessage *msg)
{
    g_autoptr(virJSONValue) obj = NULL;

    VIR_DEBUG("Line [%s]", line);

    if (!(obj = virJSONValueFromString(line)))
        return -1;

    if (virJSONValueGetType(obj) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%1$s' isn't an object"), line);
        return -1;
    }

    if (virJSONValueObjectHasKey(obj, "QMP")) {
        return 0;
    } else if (virJSONValueObjectHasKey(obj, "event")) {
        PROBE(QEMU_MONITOR_RECV_EVENT,
              "mon=%p event=%s", mon, line);
        return qemuMonitorJSONIOProcessEvent(mon, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") ||
               virJSONValueObjectHasKey(obj, "return")) {
        PROBE(QEMU_MONITOR_RECV_REPLY,
              "mon=%p reply=%s", mon, line);
        if (msg) {
            msg->rxObject = g_steal_pointer(&obj);
            msg->finished = 1;
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected JSON reply '%1$s'"), line);
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown JSON reply '%1$s'"), line);
    }

    return -1;
}

int qemuMonitorJSONIOProcess(qemuMonitor *mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessage *msg)
{
    int used = 0;
    /*VIR_DEBUG("Data %d bytes [%s]", len, data);*/

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            g_autofree char *line = g_strndup(data + used, got);

            used += got + strlen(LINE_ENDING);
            line[got] = '\0'; /* kill \n */
            if (qemuMonitorJSONIOProcessLine(mon, line, msg) < 0)
                return -1;
        } else {
            break;
        }
    }

    return used;
}

static int
qemuMonitorJSONCommandWithFd(qemuMonitor *mon,
                             virJSONValue *cmd,
                             int scm_fd,
                             virJSONValue **reply)
{
    int ret = -1;
    qemuMonitorMessage msg = { 0 };
    g_auto(virBuffer) cmdbuf = VIR_BUFFER_INITIALIZER;

    *reply = NULL;

    if (virJSONValueObjectHasKey(cmd, "execute")) {
        g_autofree char *id = qemuMonitorNextCommandID(mon);

        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to append command 'id' string"));
            return -1;
        }
    }

    if (virJSONValueToBuffer(cmd, &cmdbuf, false) < 0)
        return -1;
    virBufferAddLit(&cmdbuf, "\r\n");

    msg.txLength = virBufferUse(&cmdbuf);
    msg.txBuffer = virBufferCurrentContent(&cmdbuf);
    msg.txFD = scm_fd;

    ret = qemuMonitorSend(mon, &msg);

    if (ret == 0) {
        if (!msg.rxObject) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing monitor reply object"));
            ret = -1;
        } else {
            *reply = msg.rxObject;
        }
    }

    return ret;
}


static int
qemuMonitorJSONCommand(qemuMonitor *mon,
                       virJSONValue *cmd,
                       virJSONValue **reply)
{
    return qemuMonitorJSONCommandWithFd(mon, cmd, -1, reply);
}

/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuMonitorJSONStringifyError(virJSONValue *error)
{
    const char *klass = virJSONValueObjectGetString(error, "class");
    const char *detail = NULL;

    /* The QMP 'desc' field is usually sufficient for our generic
     * error reporting needs.
     */
    if (klass)
        detail = virJSONValueObjectGetString(error, "desc");


    if (!detail)
        detail = "unknown QEMU command error";

    return detail;
}

static const char *
qemuMonitorJSONCommandName(virJSONValue *cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    else
        return "<unknown>";
}

static int
qemuMonitorJSONCheckErrorFull(virJSONValue *cmd,
                              virJSONValue *reply,
                              bool report)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        virJSONValue *error = virJSONValueObjectGet(reply, "error");
        g_autofree char *cmdstr = virJSONValueToString(cmd, false);
        g_autofree char *replystr = virJSONValueToString(reply, false);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU command %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        if (!report)
            return -1;

        /* Only send the user the command name + friendly error */
        if (!error)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU command '%1$s'"),
                           qemuMonitorJSONCommandName(cmd));
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU command '%1$s': %2$s"),
                           qemuMonitorJSONCommandName(cmd),
                           qemuMonitorJSONStringifyError(error));

        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        g_autofree char *cmdstr = virJSONValueToString(cmd, false);
        g_autofree char *replystr = virJSONValueToString(reply, false);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        if (!report)
            return -1;

        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU command '%1$s'"),
                       qemuMonitorJSONCommandName(cmd));
        return -1;
    }
    return 0;
}


static int
qemuMonitorJSONCheckError(virJSONValue *cmd,
                          virJSONValue *reply)
{
    return qemuMonitorJSONCheckErrorFull(cmd, reply, true);
}


static virJSONValue *
qemuMonitorJSONGetReply(virJSONValue *cmd,
                        virJSONValue *reply,
                        virJSONType type)
{
    virJSONValue *data;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return NULL;

    data = virJSONValueObjectGet(reply, "return");
    if (virJSONValueGetType(data) != type) {
        g_autofree char *cmdstr = virJSONValueToString(cmd, false);
        g_autofree char *retstr = virJSONValueToString(data, false);

        VIR_DEBUG("Unexpected return type %d (expecting %d) for command %s: %s",
                  virJSONValueGetType(data), type, cmdstr, retstr);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected type returned by QEMU command '%1$s'"),
                       qemuMonitorJSONCommandName(cmd));

        return NULL;
    }

    return data;
}


static int
qemuMonitorJSONCheckReply(virJSONValue *cmd,
                          virJSONValue *reply,
                          virJSONType type)
{
    if (!qemuMonitorJSONGetReply(cmd, reply, type))
        return -1;

    return 0;
}


static bool
qemuMonitorJSONErrorIsClass(virJSONValue *error,
                            const char *klass)
{
    return STREQ_NULLABLE(virJSONValueObjectGetString(error, "class"), klass);
}


static bool
qemuMonitorJSONHasError(virJSONValue *reply,
                        const char *klass)
{
    virJSONValue *error;

    if (!(error = virJSONValueObjectGet(reply, "error")))
        return false;

    return qemuMonitorJSONErrorIsClass(error, klass);
}


/**
 * qemuMonitorJSONTransactionAdd:
 * @actions: array of actions for the 'transaction' command
 * @cmdname: command to add to @actions
 * @...: arguments for @cmdname (see virJSONValueObjectAddVArgs for formatting)
 *
 * Add a new command with arguments to the existing ones. The resulting array
 * is intended to be used as argument for the 'transaction' command.
 *
 * Returns 0 on success and -1 on error.
 */
static int
qemuMonitorJSONTransactionAdd(virJSONValue *actions,
                              const char *cmdname,
                              ...)
{
    g_autoptr(virJSONValue) entry = NULL;
    g_autoptr(virJSONValue) data = NULL;
    va_list args;

    va_start(args, cmdname);

    if (virJSONValueObjectAddVArgs(&data, args) < 0) {
        va_end(args);
        return -1;
    }

    va_end(args);

    if (virJSONValueObjectAdd(&entry,
                              "s:type", cmdname,
                              "A:data", &data, NULL) < 0)
        return -1;

    if (virJSONValueArrayAppend(actions, &entry) < 0)
        return -1;

    return 0;
}


/**
 * qemuMonitorJSONMakeCommandInternal:
 * @cmdname: QMP command name
 * @arguments: a JSON object containing command arguments or NULL
 *
 * Create a JSON object used on the QMP monitor to call a command.
 *
 * Note that @arguments is consumed and cleared.
 */
static virJSONValue *
qemuMonitorJSONMakeCommandInternal(const char *cmdname,
                                   virJSONValue **arguments)
{
    virJSONValue *ret = NULL;

    ignore_value(virJSONValueObjectAdd(&ret,
                                       "s:execute", cmdname,
                                       "A:arguments", arguments, NULL));

    return ret;
}


static virJSONValue *G_GNUC_NULL_TERMINATED
qemuMonitorJSONMakeCommand(const char *cmdname,
                           ...)
{
    virJSONValue *obj = NULL;
    g_autoptr(virJSONValue) jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (virJSONValueObjectAddVArgs(&jargs, args) < 0)
        goto cleanup;

    obj = qemuMonitorJSONMakeCommandInternal(cmdname, &jargs);

 cleanup:
    va_end(args);

    return obj;
}


static void qemuMonitorJSONHandleShutdown(qemuMonitor *mon, virJSONValue *data)
{
    bool guest = false;
    virTristateBool guest_initiated = VIR_TRISTATE_BOOL_ABSENT;

    if (data && virJSONValueObjectGetBoolean(data, "guest", &guest) == 0)
        guest_initiated = virTristateBoolFromBool(guest);

    qemuMonitorEmitShutdown(mon, guest_initiated);
}

static void qemuMonitorJSONHandleReset(qemuMonitor *mon, virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitReset(mon);
}

static void qemuMonitorJSONHandleStop(qemuMonitor *mon, virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitStop(mon);
}

static void qemuMonitorJSONHandleResume(qemuMonitor *mon, virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitResume(mon);
}


static qemuMonitorEventPanicInfo *
qemuMonitorJSONGuestPanicExtractInfoHyperv(virJSONValue *data)
{
    g_autoptr(qemuMonitorEventPanicInfo) ret = g_new0(qemuMonitorEventPanicInfo, 1);

    ret->type = QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_HYPERV;

    if (virJSONValueObjectGetNumberUlong(data, "arg1", &ret->data.hyperv.arg1) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg2", &ret->data.hyperv.arg2) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg3", &ret->data.hyperv.arg3) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg4", &ret->data.hyperv.arg4) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg5", &ret->data.hyperv.arg5) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed hyperv panic data"));
        return NULL;
    }

    return g_steal_pointer(&ret);
}

static qemuMonitorEventPanicInfo *
qemuMonitorJSONGuestPanicExtractInfoS390(virJSONValue *data)
{
    g_autoptr(qemuMonitorEventPanicInfo) ret = NULL;
    int core;
    unsigned long long psw_mask, psw_addr;
    const char *reason = NULL;

    ret = g_new0(qemuMonitorEventPanicInfo, 1);

    ret->type = QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_S390;

    if (virJSONValueObjectGetNumberInt(data, "core", &core) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "psw-mask", &psw_mask) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "psw-addr", &psw_addr) < 0 ||
        !(reason = virJSONValueObjectGetString(data, "reason"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("malformed s390 panic data"));
        return NULL;
    }

    ret->data.s390.core = core;
    ret->data.s390.psw_mask = psw_mask;
    ret->data.s390.psw_addr = psw_addr;

    ret->data.s390.reason = g_strdup(reason);

    return g_steal_pointer(&ret);
}

static qemuMonitorEventPanicInfo *
qemuMonitorJSONGuestPanicExtractInfo(virJSONValue *data)
{
    const char *type = virJSONValueObjectGetString(data, "type");

    if (STREQ_NULLABLE(type, "hyper-v"))
        return qemuMonitorJSONGuestPanicExtractInfoHyperv(data);
    else if (STREQ_NULLABLE(type, "s390"))
        return qemuMonitorJSONGuestPanicExtractInfoS390(data);

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("unknown panic info type '%1$s'"), NULLSTR(type));
    return NULL;
}


static void
qemuMonitorJSONHandleGuestPanic(qemuMonitor *mon,
                                virJSONValue *data)
{
    virJSONValue *infojson = virJSONValueObjectGetObject(data, "info");
    qemuMonitorEventPanicInfo *info = NULL;

    if (infojson)
        info = qemuMonitorJSONGuestPanicExtractInfo(infojson);

    qemuMonitorEmitGuestPanic(mon, info);
}


static void qemuMonitorJSONHandleRTCChange(qemuMonitor *mon, virJSONValue *data)
{
    long long offset = 0;
    if (virJSONValueObjectGetNumberLong(data, "offset", &offset) < 0) {
        VIR_WARN("missing offset in RTC change event");
        offset = 0;
    }
    qemuMonitorEmitRTCChange(mon, offset);
}

VIR_ENUM_DECL(qemuMonitorWatchdogAction);
VIR_ENUM_IMPL(qemuMonitorWatchdogAction,
              VIR_DOMAIN_EVENT_WATCHDOG_LAST,
              "none", "pause", "reset", "poweroff", "shutdown", "debug", "inject-nmi",
);

static void qemuMonitorJSONHandleWatchdog(qemuMonitor *mon, virJSONValue *data)
{
    const char *action;
    int actionID;
    if (!(action = virJSONValueObjectGetString(data, "action")))
        VIR_WARN("missing action in watchdog event");
    if (action) {
        if ((actionID = qemuMonitorWatchdogActionTypeFromString(action)) < 0) {
            VIR_WARN("unknown action %s in watchdog event", action);
            actionID = VIR_DOMAIN_EVENT_WATCHDOG_NONE;
        }
    } else {
            actionID = VIR_DOMAIN_EVENT_WATCHDOG_NONE;
    }
    qemuMonitorEmitWatchdog(mon, actionID);
}

VIR_ENUM_DECL(qemuMonitorIOErrorAction);
VIR_ENUM_IMPL(qemuMonitorIOErrorAction,
              VIR_DOMAIN_EVENT_IO_ERROR_LAST,
              "ignore", "stop", "report",
);


static void
qemuMonitorJSONHandleIOError(qemuMonitor *mon, virJSONValue *data)
{
    const char *device;
    const char *nodename;
    const char *action;
    const char *reason = "";
    bool nospc = false;
    int actionID;

    /* Throughout here we try our best to carry on upon errors,
       since it's important to get as much info as possible out
       to the application */

    if ((action = virJSONValueObjectGetString(data, "action")) == NULL) {
        VIR_WARN("Missing action in disk io error event");
        action = "ignore";
    }

    if ((device = virJSONValueObjectGetString(data, "device")) == NULL)
        VIR_WARN("missing device in disk io error event");

    nodename = virJSONValueObjectGetString(data, "node-name");

    if (virJSONValueObjectGetBoolean(data, "nospace", &nospc) == 0 && nospc)
        reason = "enospc";

    if ((actionID = qemuMonitorIOErrorActionTypeFromString(action)) < 0) {
        VIR_WARN("unknown disk io error action '%s'", action);
        actionID = VIR_DOMAIN_EVENT_IO_ERROR_NONE;
    }

    qemuMonitorEmitIOError(mon, device, nodename, actionID, reason);
}


VIR_ENUM_DECL(qemuMonitorGraphicsAddressFamily);
VIR_ENUM_IMPL(qemuMonitorGraphicsAddressFamily,
              VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST,
              "ipv4", "ipv6", "unix",
);

static void
qemuMonitorJSONHandleGraphicsVNC(qemuMonitor *mon,
                                 virJSONValue *data,
                                 int phase)
{
    const char *localNode, *localService, *localFamily;
    const char *remoteNode, *remoteService, *remoteFamily;
    const char *authScheme, *saslUsername, *x509dname;
    int localFamilyID, remoteFamilyID;
    virJSONValue *client;
    virJSONValue *server;

    if (!(client = virJSONValueObjectGetObject(data, "client"))) {
        VIR_WARN("missing client info in VNC event");
        return;
    }
    if (!(server = virJSONValueObjectGetObject(data, "server"))) {
        VIR_WARN("missing server info in VNC event");
        return;
    }

    if (!(authScheme = virJSONValueObjectGetString(server, "auth"))) {
        /* not all events are required to contain auth scheme */
        VIR_DEBUG("missing auth scheme in VNC event");
        authScheme = "";
    }

    if (!(localFamily = virJSONValueObjectGetString(server, "family"))) {
        VIR_WARN("missing local address family in VNC event");
        return;
    }
    if (!(localNode = virJSONValueObjectGetString(server, "host"))) {
        VIR_WARN("missing local hostname in VNC event");
        return;
    }
    if (!(localService = virJSONValueObjectGetString(server, "service"))) {
        VIR_WARN("missing local service in VNC event");
        return;
    }

    if (!(remoteFamily = virJSONValueObjectGetString(client, "family"))) {
        VIR_WARN("missing remote address family in VNC event");
        return;
    }
    if (!(remoteNode = virJSONValueObjectGetString(client, "host"))) {
        VIR_WARN("missing remote hostname in VNC event");
        return;
    }
    if (!(remoteService = virJSONValueObjectGetString(client, "service"))) {
        VIR_WARN("missing remote service in VNC event");
        return;
    }

    saslUsername = virJSONValueObjectGetString(client, "sasl_username");
    x509dname = virJSONValueObjectGetString(client, "x509_dname");

    if ((localFamilyID = qemuMonitorGraphicsAddressFamilyTypeFromString(localFamily)) < 0) {
        VIR_WARN("unknown address family '%s'", localFamily);
        localFamilyID = VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4;
    }
    if ((remoteFamilyID = qemuMonitorGraphicsAddressFamilyTypeFromString(remoteFamily)) < 0) {
        VIR_WARN("unknown address family '%s'", remoteFamily);
        remoteFamilyID = VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4;
    }

    qemuMonitorEmitGraphics(mon, phase,
                            localFamilyID, localNode, localService,
                            remoteFamilyID, remoteNode, remoteService,
                            authScheme, x509dname, saslUsername);
}

static void qemuMonitorJSONHandleVNCConnect(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleVNCInitialize(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}


static void
qemuMonitorJSONHandleGraphicsSPICE(qemuMonitor *mon,
                                   virJSONValue *data,
                                   int phase)
{
    const char *lhost, *lport, *lfamily;
    const char *rhost, *rport, *rfamily;
    const char *auth = "";
    int lfamilyID, rfamilyID;
    virJSONValue *client;
    virJSONValue *server;

    if (!(client = virJSONValueObjectGetObject(data, "client")) ||
        !(server = virJSONValueObjectGetObject(data, "server"))) {
        VIR_WARN("missing server or client info in SPICE event");
        return;
    }

    if (phase == VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE &&
        !(auth = virJSONValueObjectGetString(server, "auth"))) {
        VIR_DEBUG("missing auth scheme in SPICE event");
        auth = "";
    }

    if (!(lfamily = virJSONValueObjectGetString(server, "family"))) {
        VIR_WARN("missing local address family in SPICE event");
        return;
    }
    if (!(lhost = virJSONValueObjectGetString(server, "host"))) {
        VIR_WARN("missing local hostname in SPICE event");
        return;
    }
    if (!(lport = virJSONValueObjectGetString(server, "port"))) {
        VIR_WARN("missing local port in SPICE event");
        return;
    }

    if (!(rfamily = virJSONValueObjectGetString(client, "family"))) {
        VIR_WARN("missing remote address family in SPICE event");
        return;
    }
    if (!(rhost = virJSONValueObjectGetString(client, "host"))) {
        VIR_WARN("missing remote hostname in SPICE event");
        return;
    }
    if (!(rport = virJSONValueObjectGetString(client, "port"))) {
        VIR_WARN("missing remote service in SPICE event");
        return;
    }

    if ((lfamilyID = qemuMonitorGraphicsAddressFamilyTypeFromString(lfamily)) < 0) {
        VIR_WARN("unknown address family '%s'", lfamily);
        lfamilyID = VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4;
    }
    if ((rfamilyID = qemuMonitorGraphicsAddressFamilyTypeFromString(rfamily)) < 0) {
        VIR_WARN("unknown address family '%s'", rfamily);
        rfamilyID = VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_IPV4;
    }

    qemuMonitorEmitGraphics(mon, phase, lfamilyID, lhost, lport, rfamilyID,
                            rhost, rport, auth, NULL, NULL);
}


static void qemuMonitorJSONHandleSPICEConnect(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitor *mon, virJSONValue *data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}

static void
qemuMonitorJSONHandleJobStatusChange(qemuMonitor *mon,
                                     virJSONValue *data)
{
    const char *jobname = virJSONValueObjectGetString(data, "id");
    const char *statusstr = virJSONValueObjectGetString(data, "status");
    int status;

    if (!jobname) {
        VIR_WARN("missing job name in JOB_STATUS_CHANGE event");
        return;
    }

    if ((status = qemuMonitorJobStatusTypeFromString(statusstr)) < 0) {
        VIR_WARN("unknown job status '%s' for job '%s' in JOB_STATUS_CHANGE event",
                 statusstr, jobname);
        return;
    }

    qemuMonitorEmitJobStatusChange(mon, jobname, status);
}


static void
qemuMonitorJSONHandleTrayChange(qemuMonitor *mon,
                                virJSONValue *data)
{
    const char *devAlias = virJSONValueObjectGetString(data, "device");
    const char *devid = virJSONValueObjectGetString(data, "id");
    bool trayOpened;
    int reason;

    /* drive alias is always reported but empty for -blockdev */
    if (devAlias && *devAlias == '\0')
        devAlias = NULL;

    if (!devAlias && !devid) {
        VIR_WARN("missing device in tray change event");
        return;
    }

    if (virJSONValueObjectGetBoolean(data, "tray-open", &trayOpened) < 0) {
        VIR_WARN("missing tray-open in tray change event");
        return;
    }

    if (trayOpened)
        reason = VIR_DOMAIN_EVENT_TRAY_CHANGE_OPEN;
    else
        reason = VIR_DOMAIN_EVENT_TRAY_CHANGE_CLOSE;

    qemuMonitorEmitTrayChange(mon, devAlias, devid, reason);
}

static void
qemuMonitorJSONHandlePMWakeup(qemuMonitor *mon,
                              virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitPMWakeup(mon);
}

static void
qemuMonitorJSONHandlePMSuspend(qemuMonitor *mon,
                               virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitPMSuspend(mon);
}


static void
qemuMonitorJSONHandleBalloonChange(qemuMonitor *mon,
                                   virJSONValue *data)
{
    unsigned long long actual = 0;
    if (virJSONValueObjectGetNumberUlong(data, "actual", &actual) < 0) {
        VIR_WARN("missing actual in balloon change event");
        return;
    }
    actual = VIR_DIV_UP(actual, 1024);
    qemuMonitorEmitBalloonChange(mon, actual);
}

static void
qemuMonitorJSONHandlePMSuspendDisk(qemuMonitor *mon,
                                   virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitPMSuspendDisk(mon);
}

static void
qemuMonitorJSONHandleDeviceDeleted(qemuMonitor *mon, virJSONValue *data)
{
    const char *device;

    if (!(device = virJSONValueObjectGetString(data, "device"))) {
        VIR_DEBUG("missing device in device deleted event");
        return;
    }

    qemuMonitorEmitDeviceDeleted(mon, device);
}


static void
qemuMonitorJSONHandleDeviceUnplugErr(qemuMonitor *mon, virJSONValue *data)
{
    const char *device;
    const char *path;

    if (!(path = virJSONValueObjectGetString(data, "path"))) {
        VIR_DEBUG("missing path in device unplug guest error event");
        return;
    }

    device = virJSONValueObjectGetString(data, "device");

    qemuMonitorEmitDeviceUnplugErr(mon, path, device);
}


static void
qemuMonitorJSONHandleNetdevStreamDisconnected(qemuMonitor *mon, virJSONValue *data)
{
    const char *name;

    if (!(name = virJSONValueObjectGetString(data, "netdev-id"))) {
        VIR_WARN("missing device in NETDEV_STREAM_DISCONNECTED event");
        return;
    }

    qemuMonitorEmitNetdevStreamDisconnected(mon, name);
}


static void
qemuMonitorJSONHandleNicRxFilterChanged(qemuMonitor *mon, virJSONValue *data)
{
    const char *name;

    if (!(name = virJSONValueObjectGetString(data, "name"))) {
        VIR_WARN("missing device in NIC_RX_FILTER_CHANGED event");
        return;
    }

    qemuMonitorEmitNicRxFilterChanged(mon, name);
}


static void
qemuMonitorJSONHandleSerialChange(qemuMonitor *mon,
                                  virJSONValue *data)
{
    const char *name;
    bool connected;

    if (!(name = virJSONValueObjectGetString(data, "id"))) {
        VIR_WARN("missing device alias in VSERPORT_CHANGE event");
        return;
    }

    if (virJSONValueObjectGetBoolean(data, "open", &connected) < 0) {
        VIR_WARN("missing port state for '%s' in VSERPORT_CHANGE event", name);
        return;
    }

    qemuMonitorEmitSerialChange(mon, name, connected);
}


static void
qemuMonitorJSONHandleSpiceMigrated(qemuMonitor *mon,
                                   virJSONValue *data G_GNUC_UNUSED)
{
    qemuMonitorEmitSpiceMigrated(mon);
}


static void
qemuMonitorJSONHandleMemoryDeviceSizeChange(qemuMonitor *mon,
                                            virJSONValue *data)
{
    const char *name;
    unsigned long long size;

    if (!(name = virJSONValueObjectGetString(data, "id"))) {
        VIR_WARN("missing device alias in MEMORY_DEVICE_SIZE_CHANGE event");
        return;
    }

    if (virJSONValueObjectGetNumberUlong(data, "size", &size) < 0) {
        VIR_WARN("missing new size for '%s' in MEMORY_DEVICE_SIZE_CHANGE event", name);
        return;
    }


    qemuMonitorEmitMemoryDeviceSizeChange(mon, name, size);
}


static void
qemuMonitorJSONHandleMemoryFailure(qemuMonitor *mon,
                                   virJSONValue *data)
{
    virJSONValue *flagsjson = virJSONValueObjectGetObject(data, "flags");
    const char *str;
    int recipient;
    int action;
    bool ar = false;
    bool recursive = false;
    qemuMonitorEventMemoryFailure mf = {0};

    if (!(str = virJSONValueObjectGetString(data, "recipient"))) {
        VIR_WARN("missing recipient in memory failure event");
        return;
    }

    recipient = qemuMonitorMemoryFailureRecipientTypeFromString(str);
    if (recipient < 0) {
        VIR_WARN("unknown recipient '%s' in memory_failure event", str);
        return;
    }

    if (!(str = virJSONValueObjectGetString(data, "action"))) {
        VIR_WARN("missing action in memory failure event");
        return;
    }

    action = qemuMonitorMemoryFailureActionTypeFromString(str);
    if (action < 0) {
        VIR_WARN("unknown action '%s' in memory_failure event", str);
        return;
    }

    if (flagsjson) {
        virJSONValueObjectGetBoolean(flagsjson, "action-required", &ar);
        virJSONValueObjectGetBoolean(flagsjson, "recursive", &recursive);
    }

    mf.recipient = recipient;
    mf.action = action;
    mf.action_required = ar;
    mf.recursive = recursive;
    qemuMonitorEmitMemoryFailure(mon, &mf);
}


static void
qemuMonitorJSONHandleMigrationStatus(qemuMonitor *mon,
                                     virJSONValue *data)
{
    const char *str;
    int status;

    if (!(str = virJSONValueObjectGetString(data, "status"))) {
        VIR_WARN("missing status in migration event");
        return;
    }

    if ((status = qemuMonitorMigrationStatusTypeFromString(str)) == -1) {
        VIR_WARN("unknown status '%s' in migration event", str);
        return;
    }

    qemuMonitorEmitMigrationStatus(mon, status);
}


static void
qemuMonitorJSONHandleMigrationPass(qemuMonitor *mon,
                                   virJSONValue *data)
{
    int pass;

    if (virJSONValueObjectGetNumberInt(data, "pass", &pass) < 0) {
        VIR_WARN("missing dirty-sync-count in migration-pass event");
        return;
    }

    qemuMonitorEmitMigrationPass(mon, pass);
}


static void
qemuMonitorJSONHandleAcpiOstInfo(qemuMonitor *mon, virJSONValue *data)
{
    virJSONValue *info;
    const char *alias;
    const char *slotType;
    const char *slot;
    unsigned int source;
    unsigned int status;

    if (!(info = virJSONValueObjectGetObject(data, "info")))
        goto error;

    /* optional */
    alias = virJSONValueObjectGetString(info, "device");

    if (!(slotType = virJSONValueObjectGetString(info, "slot-type")))
        goto error;

    if (!(slot = virJSONValueObjectGetString(info, "slot")))
        goto error;

    if (virJSONValueObjectGetNumberUint(info, "source", &source) < 0)
        goto error;

    if (virJSONValueObjectGetNumberUint(info, "status", &status) < 0)
        goto error;

    qemuMonitorEmitAcpiOstInfo(mon, alias, slotType, slot, source, status);
    return;

 error:
    VIR_WARN("malformed ACPI_DEVICE_OST event");
    return;
}


static void
qemuMonitorJSONHandleBlockThreshold(qemuMonitor *mon, virJSONValue *data)
{
    const char *nodename;
    unsigned long long threshold;
    unsigned long long excess;

    if (!(nodename = virJSONValueObjectGetString(data, "node-name")))
        goto error;

    if (virJSONValueObjectGetNumberUlong(data, "write-threshold", &threshold) < 0)
        goto error;

    if (virJSONValueObjectGetNumberUlong(data, "amount-exceeded", &excess) < 0)
        goto error;

    qemuMonitorEmitBlockThreshold(mon, nodename, threshold, excess);
    return;

 error:
    VIR_WARN("malformed 'BLOCK_WRITE_THRESHOLD' event");
}


static int
qemuMonitorJSONExtractDumpStats(virJSONValue *result,
                                qemuMonitorDumpStats *ret)
{
    const char *statusstr;

    if (!(statusstr = virJSONValueObjectGetString(result, "status"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("incomplete result, failed to get status"));
        return -1;
    }

    ret->status = qemuMonitorDumpStatusTypeFromString(statusstr);
    if (ret->status < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("incomplete result, unknown status string '%1$s'"),
                       statusstr);
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(result, "completed", &ret->completed) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("incomplete result, failed to get completed"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(result, "total", &ret->total) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("incomplete result, failed to get total"));
        return -1;
    }

    return 0;
}


static void
qemuMonitorJSONHandleDumpCompleted(qemuMonitor *mon,
                                   virJSONValue *data)
{
    virJSONValue *result;
    int status;
    qemuMonitorDumpStats stats = { 0 };
    const char *error = NULL;

    if (!(result = virJSONValueObjectGetObject(data, "result"))) {
        VIR_WARN("missing result in dump completed event");
        return;
    }

    status = qemuMonitorJSONExtractDumpStats(result, &stats);

    error = virJSONValueObjectGetString(data, "error");

    qemuMonitorEmitDumpCompleted(mon, status, &stats, error);
}


static void qemuMonitorJSONHandlePRManagerStatusChanged(qemuMonitor *mon,
                                                        virJSONValue *data)
{
    const char *name;
    bool connected;

    if (!(name = virJSONValueObjectGetString(data, "id"))) {
        VIR_WARN("missing pr-manager alias in PR_MANAGER_STATUS_CHANGED event");
        return;
    }

    if (virJSONValueObjectGetBoolean(data, "connected", &connected) < 0) {
        VIR_WARN("missing connected state for %s "
                 "in PR_MANAGER_STATUS_CHANGED event", name);
        return;
    }

    qemuMonitorEmitPRManagerStatusChanged(mon, name, connected);
}


static void qemuMonitorJSONHandleRdmaGidStatusChanged(qemuMonitor *mon,
                                                      virJSONValue *data)
{
    const char *netdev;
    bool gid_status;
    unsigned long long subnet_prefix, interface_id;

    if (!(netdev = virJSONValueObjectGetString(data, "netdev"))) {
        VIR_WARN("missing netdev in GID_STATUS_CHANGED event");
        return;
    }

    if (virJSONValueObjectGetBoolean(data, "gid-status", &gid_status)) {
        VIR_WARN("missing gid-status in GID_STATUS_CHANGED event");
        return;
    }

    if (virJSONValueObjectGetNumberUlong(data, "subnet-prefix",
                                         &subnet_prefix)) {
        VIR_WARN("missing subnet-prefix in GID_STATUS_CHANGED event");
        return;
    }

    if (virJSONValueObjectGetNumberUlong(data, "interface-id",
                                         &interface_id)) {
        VIR_WARN("missing interface-id in GID_STATUS_CHANGED event");
        return;
    }

    qemuMonitorEmitRdmaGidStatusChanged(mon, netdev, gid_status, subnet_prefix,
                                        interface_id);
}


static void
qemuMonitorJSONHandleGuestCrashloaded(qemuMonitor *mon,
                                      virJSONValue *data)
{
    VIR_DEBUG("qemuMonitorJSONHandleGuestCrashloaded event, mon %p, data %p", mon, data);

    qemuMonitorEmitGuestCrashloaded(mon);
}


int
qemuMonitorJSONHumanCommand(qemuMonitor *mon,
                            const char *cmd_str,
                            int fd,
                            char **reply_str)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *obj;
    const char *data;

    cmd = qemuMonitorJSONMakeCommand("human-monitor-command",
                                     "s:command-line", cmd_str,
                                     NULL);

    if (!cmd || qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Human monitor command is not available to run %1$s"),
                       cmd_str);
        return -1;
    }

    if (qemuMonitorJSONCheckError(cmd, reply))
        return -1;

    obj = virJSONValueObjectGet(reply, "return");
    data = virJSONValueGetString(obj);
    *reply_str = g_strdup(NULLSTR_EMPTY(data));

    return 0;
}


int
qemuMonitorJSONSetCapabilities(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qmp_capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONStartCPUs(qemuMonitor *mon)
{
    int ret;
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("cont", NULL);
    size_t i = 0;
    int timeout = 3;
    if (!cmd)
        return -1;

    do {
        g_autoptr(virJSONValue) reply = NULL;

        ret = qemuMonitorJSONCommand(mon, cmd, &reply);

        if (ret != 0)
            break;

        /* If no error, we're done */
        if ((ret = qemuMonitorJSONCheckError(cmd, reply)) == 0)
            break;

        /* If error class is not MigrationExpected, we're done.
         * Otherwise try 'cont' cmd again */
        if (!qemuMonitorJSONHasError(reply, "MigrationExpected"))
            break;

        g_usleep(250000);
    } while (++i <= timeout);

    return ret;
}


int
qemuMonitorJSONStopCPUs(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("stop", NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONGetStatus(qemuMonitor *mon,
                         bool *running,
                         virDomainPausedReason *reason)
{
    const char *status;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (reason)
        *reason = VIR_DOMAIN_PAUSED_UNKNOWN;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-status", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (virJSONValueObjectGetBoolean(data, "running", running) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-status reply was missing running state"));
        return -1;
    }

    if ((status = virJSONValueObjectGetString(data, "status"))) {
        if (!*running && reason)
            *reason = qemuMonitorVMStatusToPausedReason(status);
    } else if (!*running) {
        VIR_DEBUG("query-status reply was missing status details");
    }

    return 0;
}


int qemuMonitorJSONSystemPowerdown(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("system_powerdown", NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONSetLink(qemuMonitor *mon,
                           const char *name,
                           virDomainNetInterfaceLinkState state)
{
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("set_link",
                                                             "s:name", name,
                                                             "b:up", state != VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN,
                                                             NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONSystemReset(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("system_reset", NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/**
 * qemuMonitorJSONExtractCPUS390Info:
 * @jsoncpu: pointer to a single JSON cpu entry
 * @cpu: pointer to a single cpu entry
 *
 * Derive the legacy cpu info 'halted' information
 * from the more accurate s390 cpu state. @cpu is
 * modified only on success.
 *
 * Note: the 'uninitialized' s390 cpu state can't be
 *       mapped to halted yes/no.
 *
 * A s390 cpu entry could look like this
 *  { "arch": "s390",
 *    "cpu-index": 0,
 *    "qom-path": "/machine/unattached/device[0]",
 *    "thread_id": 3081,
 *    "cpu-state": "operating" }
 *
 */
static void
qemuMonitorJSONExtractCPUS390Info(virJSONValue *jsoncpu,
                                  struct qemuMonitorQueryCpusEntry *cpu)
{
    const char *cpu_state = virJSONValueObjectGetString(jsoncpu, "cpu-state");

    if (STREQ_NULLABLE(cpu_state, "operating") ||
        STREQ_NULLABLE(cpu_state, "load"))
        cpu->halted = false;
    else if (STREQ_NULLABLE(cpu_state, "stopped") ||
             STREQ_NULLABLE(cpu_state, "check-stop"))
        cpu->halted = true;
}


/**
 * qemuMonitorJSONExtractCPUInfo:
 * @data: JSON response data
 * @entries: filled with detected cpu entries on success
 * @nentries: number of entries returned
 *
 * The JSON response @data will have the following format
 * [{ "arch": "x86",
 *    "cpu-index": 0,
 *    "props": {
 *       "core-id": 0,
 *       "thread-id": 0,
 *       "socket-id": 0
 *    },
 *    "qom-path": "/machine/unattached/device[0]",
 *    "thread-id": 2631237,
 *    ...},
 *    {...}
 *  ]
 * or for s390
 * [{ "arch": "s390",
 *    "cpu-index": 0,
 *    "props": {
 *       "core-id": 0
 *    },
 *    "qom-path": "/machine/unattached/device[0]",
 *    "thread-id": 1237,
 *    "cpu-state": "operating",
 *    ...},
 *    {...}
 *  ]
 *
 *  Note that since QEMU 2.13.0 the "arch" output member of the
 *  "query-cpus-fast" command is replaced by "target".
 */
static int
qemuMonitorJSONExtractCPUInfo(virJSONValue *data,
                              struct qemuMonitorQueryCpusEntry **entries,
                              size_t *nentries)
{
    const char *arch = NULL;
    struct qemuMonitorQueryCpusEntry *cpus = NULL;
    int ret = -1;
    size_t i;
    size_t ncpus;

    if ((ncpus = virJSONValueArraySize(data)) == 0)
        return -2;

    cpus = g_new0(struct qemuMonitorQueryCpusEntry, ncpus);

    for (i = 0; i < ncpus; i++) {
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        int cpuid = -1;
        int thread = 0;
        bool halted = false;
        const char *qom_path;
        if (!entry) {
            ret = -2;
            goto cleanup;
        }

        /* Some older qemu versions don't report the thread_id so treat this as
         * non-fatal, simply returning no data.
         * The return data of query-cpus-fast has different field names
         */
        if (!(arch = virJSONValueObjectGetString(entry, "target")))
            arch = virJSONValueObjectGetString(entry, "arch");
        ignore_value(virJSONValueObjectGetNumberInt(entry, "cpu-index", &cpuid));
        ignore_value(virJSONValueObjectGetNumberInt(entry, "thread-id", &thread));
        qom_path = virJSONValueObjectGetString(entry, "qom-path");

        cpus[i].qemu_id = cpuid;
        cpus[i].tid = thread;
        cpus[i].halted = halted;
        cpus[i].qom_path = g_strdup(qom_path);

        /* process optional architecture-specific data */
        if (STREQ_NULLABLE(arch, "s390") || STREQ_NULLABLE(arch, "s390x"))
            qemuMonitorJSONExtractCPUS390Info(entry, cpus + i);
    }

    *entries = g_steal_pointer(&cpus);
    *nentries = ncpus;
    ret = 0;

 cleanup:
    qemuMonitorQueryCpusFree(cpus, ncpus);
    return ret;
}


/**
 * qemuMonitorJSONQueryCPUs:
 *
 * @mon: monitor object
 * @entries: filled with detected entries on success
 * @nentries: number of entries returned
 * @force: force exit on error
 *
 * Queries qemu for cpu-related information. Failure to execute the command or
 * extract results does not produce an error as libvirt can continue without
 * this information, unless the caller has specified @force == true.
 *
 * Returns 0 on success, -1 on a fatal error (oom ...) and -2 if the
 * query failed gracefully.
 */
int
qemuMonitorJSONQueryCPUs(qemuMonitor *mon,
                         struct qemuMonitorQueryCpusEntry **entries,
                         size_t *nentries,
                         bool force)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    cmd = qemuMonitorJSONMakeCommand("query-cpus-fast", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (force && qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    if (!(data = virJSONValueObjectGetArray(reply, "return")))
        return -2;

    return qemuMonitorJSONExtractCPUInfo(data, entries, nentries);
}


/**
 * Loads correct video memory size values from QEMU and update the video
 * definition.
 *
 * Return 0 on success, -1 on failure and set proper error message.
 */
int
qemuMonitorJSONUpdateVideoMemorySize(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     char *path)
{
    qemuMonitorJSONObjectProperty prop = {
        QEMU_MONITOR_OBJECT_PROPERTY_ULONG,
        {0}
    };

    switch (video->type) {
    case VIR_DOMAIN_VIDEO_TYPE_VGA:
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vgamem_mb", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%1$s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_QXL:
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vram_size", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%1$s' has no property 'vram_size'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul / 1024;

        if (qemuMonitorJSONGetObjectProperty(mon, path, "ram_size", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%1$s' has no property 'ram_size'"),
                           path);
            return -1;
        }
        video->ram = prop.val.ul / 1024;
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vgamem_mb", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%1$s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vgamem = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vgamem_mb", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%1$s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_XEN:
    case VIR_DOMAIN_VIDEO_TYPE_VBOX:
    case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
    case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
    case VIR_DOMAIN_VIDEO_TYPE_GOP:
    case VIR_DOMAIN_VIDEO_TYPE_NONE:
    case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
    case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
    case VIR_DOMAIN_VIDEO_TYPE_LAST:
        break;
    }

    return 0;
}


/**
 * Loads correct video vram64 size value from QEMU and update the video
 * definition.
 *
 * Return 0 on success, -1 on failure and set proper error message.
 */
int
qemuMonitorJSONUpdateVideoVram64Size(qemuMonitor *mon,
                                     virDomainVideoDef *video,
                                     char *path)
{
    qemuMonitorJSONObjectProperty prop = {
        QEMU_MONITOR_OBJECT_PROPERTY_ULONG,
        {0}
    };

    switch (video->type) {
    case VIR_DOMAIN_VIDEO_TYPE_QXL:
        if (video->vram64 != 0) {
            if (qemuMonitorJSONGetObjectProperty(mon, path,
                                                 "vram64_size_mb", &prop) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("QOM Object '%1$s' has no property 'vram64_size_mb'"),
                               path);
                return -1;
            }
            video->vram64 = prop.val.ul * 1024;
        }
        break;
    case VIR_DOMAIN_VIDEO_TYPE_DEFAULT:
    case VIR_DOMAIN_VIDEO_TYPE_VGA:
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
    case VIR_DOMAIN_VIDEO_TYPE_XEN:
    case VIR_DOMAIN_VIDEO_TYPE_VBOX:
    case VIR_DOMAIN_VIDEO_TYPE_PARALLELS:
    case VIR_DOMAIN_VIDEO_TYPE_VIRTIO:
    case VIR_DOMAIN_VIDEO_TYPE_GOP:
    case VIR_DOMAIN_VIDEO_TYPE_NONE:
    case VIR_DOMAIN_VIDEO_TYPE_BOCHS:
    case VIR_DOMAIN_VIDEO_TYPE_RAMFB:
    case VIR_DOMAIN_VIDEO_TYPE_LAST:
        break;
    }

    return 0;
}


int
qemuMonitorJSONGetBalloonInfo(qemuMonitor *mon,
                              unsigned long long *currmem)
{
    virJSONValue *data;
    unsigned long long mem;
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-balloon",
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    *currmem = 0;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* See if balloon soft-failed */
    if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
        qemuMonitorJSONHasError(reply, "KVMMissingCap")) {
        return 0;
    }

    /* See if any other fatal error occurred */
    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (virJSONValueObjectGetNumberUlong(data, "actual", &mem) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("info balloon reply was missing balloon data"));
        return -1;
    }

    *currmem = (mem/1024);
    return 1;
}


/* Process the balloon driver statistics.  The request and data returned
 * will be as follows (although the 'child[#]' entry will differ based on
 * where it's run).
 *
 * { "execute": "qom-get","arguments": \
 *    { "path": "/machine/i440fx/pci.0/child[7]","property": "guest-stats"} }
 *
 * {"return": {"stats": \
 *               {"stat-swap-out": 0,
 *                "stat-free-memory": 686350336,
 *                "stat-minor-faults": 697283,
 *                "stat-major-faults": 951,
 *                "stat-total-memory": 1019924480,
 *                "stat-swap-in": 0},
 *            "last-update": 1371221540}}
 *
 * A value in "stats" can be -1 indicating it's never been collected/stored.
 * The 'last-update' value could be used in the future in order to determine
 * rates and/or whether data has been collected since a previous cycle.
 * It's currently unused.
 */
#define GET_BALLOON_STATS(OBJECT, FIELD, TAG, DIVISOR) \
    if (virJSONValueObjectHasKey(OBJECT, FIELD) && \
       (got < nr_stats)) { \
        if (virJSONValueObjectGetNumberUlong(OBJECT, FIELD, &mem) < 0) { \
            VIR_DEBUG("Failed to get '%s' value", FIELD); \
        } else { \
            /* Not being collected? No point in providing bad data */ \
            if (mem != -1UL) { \
                stats[got].tag = TAG; \
                stats[got].val = mem / DIVISOR; \
                got++; \
            } \
        } \
    }


int
qemuMonitorJSONGetMemoryStats(qemuMonitor *mon,
                              char *balloonpath,
                              virDomainMemoryStatPtr stats,
                              unsigned int nr_stats)
{
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    virJSONValue *statsdata;
    unsigned long long mem;
    int got = 0;

    ret = qemuMonitorJSONGetBalloonInfo(mon, &mem);
    if (ret == 1 && (got < nr_stats)) {
        stats[got].tag = VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON;
        stats[got].val = mem;
        got++;
    }

    if (!balloonpath)
        return got;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", balloonpath,
                                           "s:property", "guest-stats",
                                           NULL)))
        return got;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return got;

    if ((data = virJSONValueObjectGetObject(reply, "error"))) {
        const char *klass = virJSONValueObjectGetString(data, "class");
        const char *desc = virJSONValueObjectGetString(data, "desc");

        if (STREQ_NULLABLE(klass, "GenericError") &&
            STREQ_NULLABLE(desc, "guest hasn't updated any stats yet")) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("the guest hasn't updated any stats yet"));
            return got;
        }
    }

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return got;

    if (!(statsdata = virJSONValueObjectGet(data, "stats"))) {
        VIR_DEBUG("data does not include 'stats'");
        return got;
    }

    GET_BALLOON_STATS(statsdata, "stat-swap-in",
                      VIR_DOMAIN_MEMORY_STAT_SWAP_IN, 1024);
    GET_BALLOON_STATS(statsdata, "stat-swap-out",
                      VIR_DOMAIN_MEMORY_STAT_SWAP_OUT, 1024);
    GET_BALLOON_STATS(statsdata, "stat-major-faults",
                      VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT, 1);
    GET_BALLOON_STATS(statsdata, "stat-minor-faults",
                      VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT, 1);
    GET_BALLOON_STATS(statsdata, "stat-free-memory",
                      VIR_DOMAIN_MEMORY_STAT_UNUSED, 1024);
    GET_BALLOON_STATS(statsdata, "stat-total-memory",
                      VIR_DOMAIN_MEMORY_STAT_AVAILABLE, 1024);
    GET_BALLOON_STATS(statsdata, "stat-available-memory",
                      VIR_DOMAIN_MEMORY_STAT_USABLE, 1024);
    GET_BALLOON_STATS(data, "last-update",
                      VIR_DOMAIN_MEMORY_STAT_LAST_UPDATE, 1);
    GET_BALLOON_STATS(statsdata, "stat-disk-caches",
                      VIR_DOMAIN_MEMORY_STAT_DISK_CACHES, 1024);
    GET_BALLOON_STATS(statsdata, "stat-htlb-pgalloc",
                      VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGALLOC, 1);
    GET_BALLOON_STATS(statsdata, "stat-htlb-pgfail",
                      VIR_DOMAIN_MEMORY_STAT_HUGETLB_PGFAIL, 1);

    return got;
}
#undef GET_BALLOON_STATS


/*
 * Using the provided balloonpath, determine if we need to set the
 * collection interval property to enable statistics gathering.
 */
int
qemuMonitorJSONSetMemoryStatsPeriod(qemuMonitor *mon,
                                    char *balloonpath,
                                    int period)
{
    qemuMonitorJSONObjectProperty prop = { 0 };

    /* Set to the value in memballoon (could enable or disable) */
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_INT;
    prop.val.iv = period;
    if (qemuMonitorJSONSetObjectProperty(mon, balloonpath,
                                         "guest-stats-polling-interval",
                                         &prop) < 0) {
        return -1;
    }
    return 0;
}


int
qemuMonitorJSONSetDBusVMStateIdList(qemuMonitor *mon,
                                    const char *vmstatepath,
                                    const char *idstr)
{
    qemuMonitorJSONObjectProperty prop = {
        .type = QEMU_MONITOR_OBJECT_PROPERTY_STRING,
        .val.str = (char *) idstr,
    };

    return qemuMonitorJSONSetObjectProperty(mon, vmstatepath, "id-list", &prop);
}


/* qemuMonitorJSONQueryNamedBlockNodes:
 * @mon: Monitor pointer
 *
 * This helper will attempt to make a "query-named-block-nodes" call and check for
 * errors before returning with the reply.
 *
 * Returns: NULL on error, reply on success
 */
static virJSONValue *
qemuMonitorJSONQueryNamedBlockNodes(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-named-block-nodes",
                                           "B:flat", mon->queryNamedBlockNodesFlat,
                                           NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return NULL;

    return virJSONValueObjectStealArray(reply, "return");
}


/* qemuMonitorJSONQueryBlock:
 * @mon: Monitor pointer
 *
 * This helper will attempt to make a "query-block" call and check for
 * errors before returning with the reply.
 *
 * Returns: NULL on error, reply on success
 */
static virJSONValue *
qemuMonitorJSONQueryBlock(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-block", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0 ||
        qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return NULL;

    return virJSONValueObjectStealArray(reply, "return");
}


static virJSONValue *
qemuMonitorJSONGetBlockDev(virJSONValue *devices,
                           size_t idx)
{
    virJSONValue *dev = virJSONValueArrayGet(devices, idx);

    if (!dev || virJSONValueGetType(dev) != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-block device entry was not in expected format"));
        return NULL;
    }
    return dev;
}


static const char *
qemuMonitorJSONGetBlockDevDevice(virJSONValue *dev)
{
    const char *thisdev;

    if (!(thisdev = virJSONValueObjectGetString(dev, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-block device entry was not in expected format"));
        return NULL;
    }

    return thisdev;
}


static int
qemuMonitorJSONBlockInfoAdd(GHashTable *table,
                            struct qemuDomainDiskInfo *info,
                            const char *entryname)
{
    struct qemuDomainDiskInfo *tmp = NULL;

    if (g_hash_table_contains(table, entryname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Duplicate block info for '%1$s'"), entryname);
        return -1;
    }

    tmp = g_new0(struct qemuDomainDiskInfo, 1);

    *tmp = *info;
    tmp->nodename = g_strdup(info->nodename);

    g_hash_table_insert(table, g_strdup(entryname), tmp);

    return 0;
}


int qemuMonitorJSONGetBlockInfo(qemuMonitor *mon,
                                GHashTable *table)
{
    size_t i;
    g_autoptr(virJSONValue) devices = NULL;

    if (!(devices = qemuMonitorJSONQueryBlock(mon)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValue *dev;
        virJSONValue *image;
        struct qemuDomainDiskInfo info = { false };
        const char *thisdev;
        const char *status;
        const char *qdev;

        if (!(dev = qemuMonitorJSONGetBlockDev(devices, i)))
            return -1;

        if (!(thisdev = qemuMonitorJSONGetBlockDevDevice(dev)))
            return -1;

        thisdev = qemuAliasDiskDriveSkipPrefix(thisdev);
        qdev = virJSONValueObjectGetString(dev, "qdev");

        if (*thisdev == '\0')
            thisdev = NULL;

        if (!qdev && !thisdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-block device entry was not in expected format"));
            return -1;
        }

        if (virJSONValueObjectGetBoolean(dev, "removable", &info.removable) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot read %1$s value"),
                           "removable");
            return -1;
        }

        /* 'tray_open' is present only if the device has a tray */
        if (virJSONValueObjectGetBoolean(dev, "tray_open", &info.tray_open) == 0)
            info.tray = true;

        /* presence of 'inserted' notifies that a medium is in the device */
        if ((image = virJSONValueObjectGetObject(dev, "inserted"))) {
            info.nodename = (char *) virJSONValueObjectGetString(image, "node-name");
        } else {
            info.empty = true;
        }

        /* Missing io-status indicates no error */
        if ((status = virJSONValueObjectGetString(dev, "io-status"))) {
            info.io_status = qemuMonitorBlockIOStatusToError(status);
            if (info.io_status < 0)
                return -1;
        }

        if (thisdev &&
            qemuMonitorJSONBlockInfoAdd(table, &info, thisdev) < 0)
            return -1;

        if (qdev && STRNEQ_NULLABLE(thisdev, qdev) &&
            qemuMonitorJSONBlockInfoAdd(table, &info, qdev) < 0)
            return -1;
    }

    return 0;
}


static qemuBlockStats *
qemuMonitorJSONBlockStatsCollectData(virJSONValue *dev,
                                     int *nstats)
{
    g_autofree qemuBlockStats *bstats = NULL;
    virJSONValue *parent;
    virJSONValue *parentstats;
    virJSONValue *stats;

    if ((stats = virJSONValueObjectGetObject(dev, "stats")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("blockstats stats entry was not in expected format"));
        return NULL;
    }

    bstats = g_new0(qemuBlockStats, 1);

#define QEMU_MONITOR_BLOCK_STAT_GET(NAME, VAR, MANDATORY) \
    if (MANDATORY || virJSONValueObjectHasKey(stats, NAME)) { \
        (*nstats)++; \
        if (virJSONValueObjectGetNumberUlong(stats, NAME, &VAR) < 0) { \
            virReportError(VIR_ERR_INTERNAL_ERROR, \
                           _("cannot read %1$s statistic"), NAME); \
            return NULL; \
        } \
    }
    QEMU_MONITOR_BLOCK_STAT_GET("rd_bytes", bstats->rd_bytes, true);
    QEMU_MONITOR_BLOCK_STAT_GET("wr_bytes", bstats->wr_bytes, true);
    QEMU_MONITOR_BLOCK_STAT_GET("rd_operations", bstats->rd_req, true);
    QEMU_MONITOR_BLOCK_STAT_GET("wr_operations", bstats->wr_req, true);
    QEMU_MONITOR_BLOCK_STAT_GET("rd_total_time_ns", bstats->rd_total_times, false);
    QEMU_MONITOR_BLOCK_STAT_GET("wr_total_time_ns", bstats->wr_total_times, false);
    QEMU_MONITOR_BLOCK_STAT_GET("flush_operations", bstats->flush_req, false);
    QEMU_MONITOR_BLOCK_STAT_GET("flush_total_time_ns", bstats->flush_total_times, false);
#undef QEMU_MONITOR_BLOCK_STAT_GET

    if ((parent = virJSONValueObjectGetObject(dev, "parent")) &&
        (parentstats = virJSONValueObjectGetObject(parent, "stats"))) {
        if (virJSONValueObjectGetNumberUlong(parentstats, "wr_highest_offset",
                                             &bstats->wr_highest_offset) == 0)
            bstats->wr_highest_offset_valid = true;
    }

    return g_steal_pointer(&bstats);
}


static int
qemuMonitorJSONAddOneBlockStatsInfo(qemuBlockStats *bstats,
                                    const char *name,
                                    GHashTable *stats)
{
    qemuBlockStats *copy = NULL;

    copy = g_new0(qemuBlockStats, 1);

    if (bstats)
        *copy = *bstats;

    if (virHashAddEntry(stats, name, copy) < 0) {
        VIR_FREE(copy);
        return -1;
    }

    return 0;
}


static int
qemuMonitorJSONGetOneBlockStatsInfo(virJSONValue *dev,
                                    const char *dev_name,
                                    int depth,
                                    GHashTable *hash)
{
    g_autofree qemuBlockStats *bstats = NULL;
    int nstats = 0;
    const char *qdevname = NULL;
    const char *nodename = NULL;
    g_autofree char *devicename = NULL;
    virJSONValue *backing;

    if (dev_name &&
        !(devicename = qemuDomainStorageAlias(dev_name, depth)))
        return -1;

    qdevname = virJSONValueObjectGetString(dev, "qdev");
    nodename = virJSONValueObjectGetString(dev, "node-name");

    if (!devicename && !qdevname && !nodename) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("blockstats device entry was not in expected format"));
        return -1;
    }

    if (!(bstats = qemuMonitorJSONBlockStatsCollectData(dev, &nstats)))
        return -1;

    if (devicename &&
        qemuMonitorJSONAddOneBlockStatsInfo(bstats, devicename, hash) < 0)
        return -1;

    if (qdevname && STRNEQ_NULLABLE(qdevname, devicename) &&
        qemuMonitorJSONAddOneBlockStatsInfo(bstats, qdevname, hash) < 0)
        return -1;

    if (nodename &&
        qemuMonitorJSONAddOneBlockStatsInfo(bstats, nodename, hash) < 0)
        return -1;

    if ((backing = virJSONValueObjectGetObject(dev, "backing")) &&
        qemuMonitorJSONGetOneBlockStatsInfo(backing, dev_name, depth + 1, hash) < 0)
        return -1;

    return nstats;
}


static int
qemuMonitorJSONGetOneBlockStatsNodeInfo(virJSONValue *dev,
                                        GHashTable *hash)
{
    qemuBlockStats *bstats = NULL;
    int nstats = 0;
    const char *nodename = NULL;

    if (!(nodename = virJSONValueObjectGetString(dev, "node-name")))
        return 0;

    /* we already have the stats */
    if (g_hash_table_contains(hash, nodename))
        return 0;

    if (!(bstats = qemuMonitorJSONBlockStatsCollectData(dev, &nstats)))
        return -1;

    g_hash_table_insert(hash, g_strdup(nodename), bstats);

    return nstats;
}


virJSONValue *
qemuMonitorJSONQueryBlockstats(qemuMonitor *mon,
                               bool queryNodes)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-blockstats",
                                           "B:query-nodes", queryNodes,
                                           NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return NULL;

    return virJSONValueObjectStealArray(reply, "return");
}


int
qemuMonitorJSONGetAllBlockStatsInfo(qemuMonitor *mon,
                                    GHashTable *hash)
{
    int nstats = 0;
    int rc;
    size_t i;
    g_autoptr(virJSONValue) blockstatsDevices = NULL;
    g_autoptr(virJSONValue) blockstatsNodes = NULL;

    if (!(blockstatsDevices = qemuMonitorJSONQueryBlockstats(mon, false)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(blockstatsDevices); i++) {
        virJSONValue *dev = virJSONValueArrayGet(blockstatsDevices, i);
        const char *dev_name;

        if (!dev || virJSONValueGetType(dev) != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("blockstats device entry was not in expected format"));
            return -1;
        }

        if ((dev_name = virJSONValueObjectGetString(dev, "device"))) {
            if (*dev_name == '\0')
                dev_name = NULL;
        }

        rc = qemuMonitorJSONGetOneBlockStatsInfo(dev, dev_name, 0, hash);

        if (rc < 0)
            return -1;

        if (rc > nstats)
            nstats = rc;
    }

    if (!(blockstatsNodes = qemuMonitorJSONQueryBlockstats(mon, true)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(blockstatsNodes); i++) {
        virJSONValue *dev = virJSONValueArrayGet(blockstatsNodes, i);

        if (!dev || virJSONValueGetType(dev) != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("blockstats device entry was not in expected format"));
            return -1;
        }

        if ((rc = qemuMonitorJSONGetOneBlockStatsNodeInfo(dev, hash)) < 0)
            return -1;

        if (rc > nstats)
            nstats = rc;
    }

    return nstats;
}


static int
qemuMonitorJSONBlockStatsUpdateCapacityData(virJSONValue *image,
                                            const char *name,
                                            GHashTable *stats,
                                            qemuBlockStats **entry)
{
    qemuBlockStats *bstats;

    if (!(bstats = virHashLookup(stats, name))) {
        bstats = g_new0(qemuBlockStats, 1);

        if (virHashAddEntry(stats, name, bstats) < 0) {
            VIR_FREE(bstats);
            return -1;
        }
    }

    if (entry)
        *entry = bstats;

    /* failures can be ignored after this point */
    if (virJSONValueObjectGetNumberUlong(image, "virtual-size",
                                         &bstats->capacity) < 0)
        return 0;

    /* if actual-size is missing, image is not thin provisioned */
    if (virJSONValueObjectGetNumberUlong(image, "actual-size",
                                         &bstats->physical) < 0)
        bstats->physical = bstats->capacity;

    return 0;
}


static int
qemuMonitorJSONBlockStatsUpdateCapacityBlockdevWorker(size_t pos G_GNUC_UNUSED,
                                                      virJSONValue *val,
                                                      void *opaque)
{
    GHashTable *stats = opaque;
    virJSONValue *image;
    const char *nodename;
    qemuBlockStats *entry;

    if (!(nodename = virJSONValueObjectGetString(val, "node-name")) ||
        !(image = virJSONValueObjectGetObject(val, "image"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-named-block-nodes entry was not in expected format"));
        return -1;
    }

    if (qemuMonitorJSONBlockStatsUpdateCapacityData(image, nodename, stats, &entry) < 0)
        return -1;

    if (entry)
        ignore_value(virJSONValueObjectGetNumberUlong(val, "write_threshold",
                                                      &entry->write_threshold));

    return 1; /* we don't want to steal the value from the JSON array */
}


int
qemuMonitorJSONBlockStatsUpdateCapacityBlockdev(qemuMonitor *mon,
                                                GHashTable *stats)
{
    g_autoptr(virJSONValue) nodes = NULL;

    if (!(nodes = qemuMonitorJSONQueryNamedBlockNodes(mon)))
        return -1;

    if (virJSONValueArrayForeachSteal(nodes,
                                      qemuMonitorJSONBlockStatsUpdateCapacityBlockdevWorker,
                                      stats) < 0)
        return -1;

    return 0;
}


static void
qemuMonitorJSONBlockNamedNodeDataBitmapFree(qemuBlockNamedNodeDataBitmap *bitmap)
{
    if (!bitmap)
        return;

    g_free(bitmap->name);
    g_free(bitmap);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockNamedNodeDataBitmap,
                              qemuMonitorJSONBlockNamedNodeDataBitmapFree);


static void
qemuMonitorJSONBlockNamedNodeDataFree(qemuBlockNamedNodeData *data)
{
    size_t i;

    if (!data)
        return;

    for (i = 0; i < data->nbitmaps; i++)
        qemuMonitorJSONBlockNamedNodeDataBitmapFree(data->bitmaps[i]);
    g_free(data->bitmaps);
    g_free(data);
}
G_DEFINE_AUTOPTR_CLEANUP_FUNC(qemuBlockNamedNodeData, qemuMonitorJSONBlockNamedNodeDataFree);


static qemuBlockNamedNodeDataBitmap *
qemuMonitorJSONBlockGetNamedNodeDataBitmapOne(virJSONValue *val)
{
    g_autoptr(qemuBlockNamedNodeDataBitmap) bitmap = NULL;
    const char *name;

    bitmap = g_new0(qemuBlockNamedNodeDataBitmap, 1);

    if (!(name = virJSONValueObjectGetString(val, "name")))
        return NULL;

    bitmap->name = g_strdup(name);

    ignore_value(virJSONValueObjectGetBoolean(val, "recording", &bitmap->recording));
    ignore_value(virJSONValueObjectGetBoolean(val, "persistent", &bitmap->persistent));
    ignore_value(virJSONValueObjectGetBoolean(val, "busy", &bitmap->busy));
    ignore_value(virJSONValueObjectGetBoolean(val, "inconsistent", &bitmap->inconsistent));
    ignore_value(virJSONValueObjectGetNumberUlong(val, "granularity", &bitmap->granularity));
    ignore_value(virJSONValueObjectGetNumberUlong(val, "count", &bitmap->dirtybytes));

    return g_steal_pointer(&bitmap);
}


static void
qemuMonitorJSONBlockGetNamedNodeDataBitmaps(virJSONValue *bitmaps,
                                            qemuBlockNamedNodeData *data)
{
    size_t nbitmaps = virJSONValueArraySize(bitmaps);
    size_t i;

    data->bitmaps = g_new0(qemuBlockNamedNodeDataBitmap *, nbitmaps);

    for (i = 0; i < nbitmaps; i++) {
        virJSONValue *bitmap = virJSONValueArrayGet(bitmaps, i);
        qemuBlockNamedNodeDataBitmap *tmp;

        if (!bitmap)
            continue;

        if (!(tmp = qemuMonitorJSONBlockGetNamedNodeDataBitmapOne(bitmap)))
            continue;

        data->bitmaps[data->nbitmaps++] = tmp;
    }
}


static int
qemuMonitorJSONBlockGetNamedNodeDataWorker(size_t pos G_GNUC_UNUSED,
                                           virJSONValue *val,
                                           void *opaque)
{
    GHashTable *nodes = opaque;
    virJSONValue *img;
    virJSONValue *bitmaps;
    virJSONValue *format_specific;
    const char *nodename;
    g_autoptr(qemuBlockNamedNodeData) ent = NULL;

    ent = g_new0(qemuBlockNamedNodeData, 1);

    if (!(nodename = virJSONValueObjectGetString(val, "node-name")) ||
        !(img = virJSONValueObjectGetObject(val, "image")))
        goto broken;

    if (virJSONValueObjectGetNumberUlong(img, "virtual-size", &ent->capacity) < 0)
        goto broken;

    /* if actual-size is missing, image is not thin provisioned */
    if (virJSONValueObjectGetNumberUlong(img, "actual-size", &ent->physical) < 0)
        ent->physical = ent->capacity;

    /* try looking up the cluster size */
    ignore_value(virJSONValueObjectGetNumberUlong(img, "cluster-size", &ent->clusterSize));

    if ((bitmaps = virJSONValueObjectGetArray(val, "dirty-bitmaps")))
        qemuMonitorJSONBlockGetNamedNodeDataBitmaps(bitmaps, ent);

    /* query qcow2 format specific props */
    if ((format_specific = virJSONValueObjectGetObject(img, "format-specific")) &&
        STREQ_NULLABLE(virJSONValueObjectGetString(format_specific, "type"), "qcow2")) {
        virJSONValue *qcow2props = virJSONValueObjectGetObject(format_specific, "data");

        if (qcow2props) {
            if (STREQ_NULLABLE(virJSONValueObjectGetString(qcow2props, "compat"), "0.10"))
                ent->qcow2v2 = true;

            ignore_value(virJSONValueObjectGetBoolean(qcow2props, "extended-l2",
                                                      &ent->qcow2extendedL2));
        }
    }

    if (virHashAddEntry(nodes, nodename, ent) < 0)
        return -1;

    ent = NULL;

    return 1; /* we don't want to steal the value from the JSON array */

 broken:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("query-named-block-nodes entry was not in expected format"));
    return -1;
}


GHashTable *
qemuMonitorJSONBlockGetNamedNodeDataJSON(virJSONValue *nodes)
{
    g_autoptr(GHashTable) ret = NULL;

    ret = virHashNew((GDestroyNotify) qemuMonitorJSONBlockNamedNodeDataFree);

    if (virJSONValueArrayForeachSteal(nodes,
                                      qemuMonitorJSONBlockGetNamedNodeDataWorker,
                                      ret) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


GHashTable *
qemuMonitorJSONBlockGetNamedNodeData(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) nodes = NULL;

    if (!(nodes = qemuMonitorJSONQueryNamedBlockNodes(mon)))
        return NULL;

    return qemuMonitorJSONBlockGetNamedNodeDataJSON(nodes);
}


int qemuMonitorJSONBlockResize(qemuMonitor *mon,
                               const char *device,
                               const char *nodename,
                               unsigned long long size)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block_resize",
                                     "S:device", device,
                                     "S:node-name", nodename,
                                     "U:size", size,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONSetPassword(qemuMonitor *mon,
                               const char *protocol,
                               const char *password,
                               const char *action_if_connected)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("set_password",
                                                             "s:protocol", protocol,
                                                             "s:password", password,
                                                             "s:connected", action_if_connected,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONExpirePassword(qemuMonitor *mon,
                                  const char *protocol,
                                  const char *expire_time)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("expire_password",
                                                             "s:protocol", protocol,
                                                             "s:time", expire_time,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONSetBalloon(qemuMonitor *mon,
                          unsigned long long newmem)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("balloon",
                                                             "U:value", newmem * 1024,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* See if balloon soft-failed */
    if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
        qemuMonitorJSONHasError(reply, "KVMMissingCap")) {
        return 0;
    }

    /* See if any other fatal error occurred */
    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    /* Real success */
    return 1;
}


static int qemuMonitorJSONSaveMemory(qemuMonitor *mon,
                                     const char *cmdtype,
                                     unsigned long long offset,
                                     unsigned long long length,
                                     const char *path)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand(cmdtype,
                                                             "U:val", offset,
                                                             "U:size", length,
                                                             "s:filename", path,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONSaveVirtualMemory(qemuMonitor *mon,
                                 unsigned long long offset,
                                 unsigned long long length,
                                 const char *path)
{
    return qemuMonitorJSONSaveMemory(mon, "memsave", offset, length, path);
}


int
qemuMonitorJSONSavePhysicalMemory(qemuMonitor *mon,
                                  unsigned long long offset,
                                  unsigned long long length,
                                  const char *path)
{
    return qemuMonitorJSONSaveMemory(mon, "pmemsave", offset, length, path);
}


int
qemuMonitorJSONGetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    *params = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-migrate-parameters", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_OBJECT) < 0)
        return -1;

    *params = virJSONValueObjectStealObject(reply, "return");
    return 0;
}

int
qemuMonitorJSONSetMigrationParams(qemuMonitor *mon,
                                  virJSONValue **params)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("migrate-set-parameters", params)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


static int
qemuMonitorJSONGetMigrationStatsReply(virJSONValue *reply,
                                      qemuMonitorMigrationStats *stats,
                                      char **error)
{
    virJSONValue *ret;
    virJSONValue *ram;
    virJSONValue *disk;
    virJSONValue *comp;
    const char *statusstr;
    int rc;
    double mbps;
    const char *tmp;

    ret = virJSONValueObjectGetObject(reply, "return");

    if (!(statusstr = virJSONValueObjectGetString(ret, "status"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("info migration reply was missing return status"));
        return -1;
    }

    stats->status = qemuMonitorMigrationStatusTypeFromString(statusstr);
    if (stats->status < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected migration status in %1$s"), statusstr);
        return -1;
    }

    ignore_value(virJSONValueObjectGetNumberUlong(ret, "total-time",
                                                  &stats->total_time));
    if (stats->status == QEMU_MONITOR_MIGRATION_STATUS_COMPLETED) {
        rc = virJSONValueObjectGetNumberUlong(ret, "downtime",
                                              &stats->downtime);
    } else {
        rc = virJSONValueObjectGetNumberUlong(ret, "expected-downtime",
                                              &stats->downtime);
    }
    if (rc == 0)
        stats->downtime_set = true;

    if (virJSONValueObjectGetNumberUlong(ret, "setup-time",
                                         &stats->setup_time) == 0)
        stats->setup_time_set = true;

    ignore_value(virJSONValueObjectGetNumberInt(ret, "cpu-throttle-percentage",
                                                &stats->cpu_throttle_percentage));

    switch ((qemuMonitorMigrationStatus) stats->status) {
    case QEMU_MONITOR_MIGRATION_STATUS_INACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_SETUP:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
    case QEMU_MONITOR_MIGRATION_STATUS_WAIT_UNPLUG:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
        if (error) {
            tmp = virJSONValueObjectGetString(ret, "error-desc");
            *error = g_strdup(tmp);
        }
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_PAUSED:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY_RECOVER:
    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
    case QEMU_MONITOR_MIGRATION_STATUS_PRE_SWITCHOVER:
    case QEMU_MONITOR_MIGRATION_STATUS_DEVICE:
        ram = virJSONValueObjectGetObject(ret, "ram");
        if (ram) {
            if (virJSONValueObjectGetNumberUlong(ram, "transferred",
                                                 &stats->ram_transferred) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("migration was active, but RAM 'transferred' data was missing"));
                return -1;
            }
            if (virJSONValueObjectGetNumberUlong(ram, "remaining",
                                                 &stats->ram_remaining) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("migration was active, but RAM 'remaining' data was missing"));
                return -1;
            }
            if (virJSONValueObjectGetNumberUlong(ram, "total",
                                                 &stats->ram_total) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("migration was active, but RAM 'total' data was missing"));
                return -1;
            }

            if (virJSONValueObjectGetNumberDouble(ram, "mbps", &mbps) == 0 &&
                mbps > 0) {
                /* mpbs from QEMU reports Mbits/s (M as in 10^6 not Mi as 2^20) */
                stats->ram_bps = mbps * (1000 * 1000 / 8);
            }

            if (virJSONValueObjectGetNumberUlong(ram, "duplicate",
                                                 &stats->ram_duplicate) == 0)
                stats->ram_duplicate_set = true;
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "normal",
                                                          &stats->ram_normal));
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "normal-bytes",
                                                          &stats->ram_normal_bytes));
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "dirty-pages-rate",
                                                          &stats->ram_dirty_rate));
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "page-size",
                                                          &stats->ram_page_size));
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "dirty-sync-count",
                                                          &stats->ram_iteration));
            ignore_value(virJSONValueObjectGetNumberUlong(ram, "postcopy-requests",
                                                          &stats->ram_postcopy_reqs));
        }

        disk = virJSONValueObjectGetObject(ret, "disk");
        if (disk) {
            rc = virJSONValueObjectGetNumberUlong(disk, "transferred",
                                                  &stats->disk_transferred);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but 'transferred' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(disk, "remaining",
                                                  &stats->disk_remaining);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but 'remaining' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(disk, "total",
                                                  &stats->disk_total);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but 'total' data was missing"));
                return -1;
            }

            if (virJSONValueObjectGetNumberDouble(disk, "mbps", &mbps) == 0 &&
                mbps > 0) {
                /* mpbs from QEMU reports Mbits/s (M as in 10^6 not Mi as 2^20) */
                stats->disk_bps = mbps * (1000 * 1000 / 8);
            }
        }

        comp = virJSONValueObjectGetObject(ret, "xbzrle-cache");
        if (comp) {
            stats->xbzrle_set = true;
            rc = virJSONValueObjectGetNumberUlong(comp, "cache-size",
                                                  &stats->xbzrle_cache_size);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'cache-size' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "bytes",
                                                  &stats->xbzrle_bytes);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'bytes' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "pages",
                                                  &stats->xbzrle_pages);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'pages' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "cache-miss",
                                                  &stats->xbzrle_cache_miss);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'cache-miss' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "overflow",
                                                  &stats->xbzrle_overflow);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'overflow' data was missing"));
                return -1;
            }
        }
        break;
    }

    return 0;
}


int qemuMonitorJSONGetMigrationStats(qemuMonitor *mon,
                                     qemuMonitorMigrationStats *stats,
                                     char **error)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-migrate",
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    memset(stats, 0, sizeof(*stats));

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_OBJECT) < 0)
        return -1;

    if (qemuMonitorJSONGetMigrationStatsReply(reply, stats, error) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONMigrate(qemuMonitor *mon,
                           unsigned int flags,
                           const char *uri)
{
    bool resume = !!(flags & QEMU_MONITOR_MIGRATE_RESUME);
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("migrate",
                                                             "b:detach", true,
                                                             "b:resume", resume,
                                                             "s:uri", uri,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/*
 * Get the exposed migration blockers.
 *
 * This function assume qemu has the capability of request them.
 *
 * It returns a NULL terminated array on blockers if there are any, or it set
 * it to NULL otherwise.
 */
int
qemuMonitorJSONGetMigrationBlockers(qemuMonitor *mon,
                                    char ***blockers)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    virJSONValue *jblockers;
    size_t i;

    *blockers = NULL;
    if (!(cmd = qemuMonitorJSONMakeCommand("query-migrate", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (!(jblockers = virJSONValueObjectGetArray(data, "blocked-reasons")))
        return 0;

    *blockers = g_new0(char *, virJSONValueArraySize(jblockers) + 1);
    for (i = 0; i < virJSONValueArraySize(jblockers); i++) {
        virJSONValue *jblocker = virJSONValueArrayGet(jblockers, i);
        const char *blocker = virJSONValueGetString(jblocker);

        (*blockers)[i] = g_strdup(blocker);
    }

    return 0;
}


int qemuMonitorJSONMigrateCancel(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("migrate_cancel", NULL);
    g_autoptr(virJSONValue) reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONMigratePause(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-pause", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/* qemuMonitorJSONQueryDump:
 * @mon: Monitor pointer
 * @stats: Monitor dump stats
 *
 * Attempt to make a "query-dump" call, check for errors, and get/return
 * the current from the reply
 *
 * Returns: 0 on success, -1 on failure
 */
int
qemuMonitorJSONQueryDump(qemuMonitor *mon,
                         qemuMonitorDumpStats *stats)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-dump", NULL);
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *result = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(result = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    return qemuMonitorJSONExtractDumpStats(result, stats);
}


int
qemuMonitorJSONGetDumpGuestMemoryCapability(qemuMonitor *mon,
                                            const char *capability)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *caps;
    virJSONValue *formats;
    size_t i;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-dump-guest-memory-capability",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(caps = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (!(formats = virJSONValueObjectGetArray(caps, "formats"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing supported dump formats"));
        return -1;
    }

    for (i = 0; i < virJSONValueArraySize(formats); i++) {
        virJSONValue *dumpformat = virJSONValueArrayGet(formats, i);

        if (!dumpformat || virJSONValueGetType(dumpformat) != VIR_JSON_TYPE_STRING) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in supported dump formats"));
            return -1;
        }

        if (STREQ(virJSONValueGetString(dumpformat), capability))
            return 1;
    }

    return 0;
}

int
qemuMonitorJSONDump(qemuMonitor *mon,
                    const char *protocol,
                    const char *dumpformat,
                    bool detach)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("dump-guest-memory",
                                     "b:paging", false,
                                     "s:protocol", protocol,
                                     "S:format", dumpformat,
                                     "B:detach", detach,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONGraphicsRelocate(qemuMonitor *mon,
                                    int type,
                                    const char *hostname,
                                    int port,
                                    int tlsPort,
                                    const char *tlsSubject)
{
    const char *protocol = "vnc";
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE)
        protocol = "spice";

    if (!(cmd = qemuMonitorJSONMakeCommand("client_migrate_info",
                                           "s:protocol", protocol,
                                           "s:hostname", hostname,
                                           "i:port", port,
                                           "i:tls-port", tlsPort,
                                           "S:cert-subject", tlsSubject,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONAddFileHandleToSet(qemuMonitor *mon,
                                  int fd,
                                  int fdset,
                                  const char *opaque)
{
    g_autoptr(virJSONValue) args = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) cmd = NULL;

    if (virJSONValueObjectAdd(&args, "S:opaque", opaque, NULL) < 0)
        return -1;

    if (fdset >= 0 &&
        virJSONValueObjectAdd(&args, "j:fdset-id", fdset, NULL) < 0) {
        return -1;
    }

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("add-fd", &args)))
        return -1;

    if (qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


static int
qemuMonitorJSONQueryFdsetsParse(virJSONValue *msg,
                                qemuMonitorFdsets **fdsets)
{
    virJSONValue *returnArray;
    virJSONValue *entry;
    size_t i;
    g_autoptr(qemuMonitorFdsets) sets = g_new0(qemuMonitorFdsets, 1);
    int ninfo;

    returnArray = virJSONValueObjectGetArray(msg, "return");

    ninfo = virJSONValueArraySize(returnArray);
    if (ninfo > 0)
        sets->fdsets = g_new0(qemuMonitorFdsetInfo, ninfo);
    sets->nfdsets = ninfo;

    for (i = 0; i < ninfo; i++) {
        size_t j;
        virJSONValue *fdarray;
        qemuMonitorFdsetInfo *fdsetinfo = &sets->fdsets[i];

        if (!(entry = virJSONValueArrayGet(returnArray, i))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-fdsets return data missing fdset array element"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUint(entry, "fdset-id", &fdsetinfo->id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-fdsets reply was missing 'fdset-id'"));
            return -1;

        }

        if ((fdarray = virJSONValueObjectGetArray(entry, "fds"))) {
            fdsetinfo->nfds = virJSONValueArraySize(fdarray);
            if (fdsetinfo->nfds > 0)
                fdsetinfo->fds = g_new0(qemuMonitorFdsetFdInfo, fdsetinfo->nfds);

            for (j = 0; j < fdsetinfo->nfds; j++) {
                qemuMonitorFdsetFdInfo *fdinfo = &fdsetinfo->fds[j];
                virJSONValue *fdentry;

                if (!(fdentry = virJSONValueArrayGet(fdarray, j))) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("query-fdsets return data missing fd array element"));
                    return -1;
                }

                /* opaque is optional and may be missing */
                fdinfo->opaque = g_strdup(virJSONValueObjectGetString(fdentry, "opaque"));
            }
        }
    }

    *fdsets = g_steal_pointer(&sets);
    return 0;
}


int qemuMonitorJSONQueryFdsets(qemuMonitor *mon,
                               qemuMonitorFdsets **fdsets)
{
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-fdsets",
                                                             NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return -1;

    if (qemuMonitorJSONQueryFdsetsParse(reply, fdsets) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONRemoveFdset(qemuMonitor *mon,
                               unsigned int fdset)
{
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("remove-fd",
                                                             "u:fdset-id", fdset,
                                                             NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONSendFileHandle(qemuMonitor *mon,
                                  const char *fdname,
                                  int fd)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("getfd",
                                                             "s:fdname", fdname,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONCloseFileHandle(qemuMonitor *mon,
                                   const char *fdname)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("closefd",
                                                             "s:fdname", fdname,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONAddNetdev(qemuMonitor *mon,
                         virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("netdev_add", props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONRemoveNetdev(qemuMonitor *mon,
                            const char *alias)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("netdev_del",
                                                             "s:id", alias,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


static int
qemuMonitorJSONQueryRxFilterParse(virJSONValue *msg,
                                  virNetDevRxFilter **filter)
{
    const char *tmp;
    virJSONValue *returnArray;
    virJSONValue *entry;
    virJSONValue *table;
    virJSONValue *element;
    size_t nTable;
    size_t i;
    g_autoptr(virNetDevRxFilter) fil = virNetDevRxFilterNew();

    if (!fil)
        return -1;

    returnArray = virJSONValueObjectGetArray(msg, "return");

    if (!(entry = virJSONValueArrayGet(returnArray, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-rx-filter return data missing array element"));
        return -1;
    }

    if (!(tmp = virJSONValueObjectGetString(entry, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid name in query-rx-filter response"));
        return -1;
    }
    fil->name = g_strdup(tmp);
    if ((!(tmp = virJSONValueObjectGetString(entry, "main-mac"))) ||
        virMacAddrParse(tmp, &fil->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'main-mac' in query-rx-filter response"));
        return -1;
    }
    if (virJSONValueObjectGetBoolean(entry, "promiscuous",
                                     &fil->promiscuous) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'promiscuous' in query-rx-filter response"));
        return -1;
    }
    if (virJSONValueObjectGetBoolean(entry, "broadcast-allowed",
                                     &fil->broadcastAllowed) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'broadcast-allowed' in query-rx-filter response"));
        return -1;
    }

    if ((!(tmp = virJSONValueObjectGetString(entry, "unicast"))) ||
        ((fil->unicast.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast' in query-rx-filter response"));
        return -1;
    }
    if (virJSONValueObjectGetBoolean(entry, "unicast-overflow",
                                     &fil->unicast.overflow) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast-overflow' in query-rx-filter response"));
        return -1;
    }
    if ((!(table = virJSONValueObjectGetArray(entry, "unicast-table")))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast-table' array in query-rx-filter response"));
        return -1;
    }
    nTable = virJSONValueArraySize(table);
    fil->unicast.table = g_new0(virMacAddr, nTable);
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            !(tmp = virJSONValueGetString(element))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %1$zu of 'unicast' list in query-rx-filter response"),
                           i);
            return -1;
        }
        if (virMacAddrParse(tmp, &fil->unicast.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid mac address '%1$s' in 'unicast-table' array in query-rx-filter response"),
                           tmp);
            return -1;
        }
    }
    fil->unicast.nTable = nTable;

    if ((!(tmp = virJSONValueObjectGetString(entry, "multicast"))) ||
        ((fil->multicast.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast' in query-rx-filter response"));
        return -1;
    }
    if (virJSONValueObjectGetBoolean(entry, "multicast-overflow",
                                     &fil->multicast.overflow) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast-overflow' in query-rx-filter response"));
        return -1;
    }
    if ((!(table = virJSONValueObjectGetArray(entry, "multicast-table")))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast-table' array in query-rx-filter response"));
        return -1;
    }
    nTable = virJSONValueArraySize(table);
    fil->multicast.table = g_new0(virMacAddr, nTable);
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            !(tmp = virJSONValueGetString(element))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %1$zu of 'multicast' list in query-rx-filter response"),
                           i);
            return -1;
        }
        if (virMacAddrParse(tmp, &fil->multicast.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid mac address '%1$s' in 'multicast-table' array in query-rx-filter response"),
                           tmp);
            return -1;
        }
    }
    fil->multicast.nTable = nTable;

    if ((!(tmp = virJSONValueObjectGetString(entry, "vlan"))) ||
        ((fil->vlan.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'vlan' in query-rx-filter response"));
        return -1;
    }
    if ((!(table = virJSONValueObjectGetArray(entry, "vlan-table")))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'vlan-table' array in query-rx-filter response"));
        return -1;
    }
    nTable = virJSONValueArraySize(table);
    fil->vlan.table = g_new0(unsigned int, nTable);
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            virJSONValueGetNumberUint(element, &fil->vlan.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %1$zu of 'vlan-table' array in query-rx-filter response"),
                           i);
            return -1;
        }
    }
    fil->vlan.nTable = nTable;

    *filter = g_steal_pointer(&fil);
    return 0;
}


int
qemuMonitorJSONQueryRxFilter(qemuMonitor *mon, const char *alias,
                             virNetDevRxFilter **filter)
{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-rx-filter",
                                                             "s:name", alias,
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return -1;

    if (qemuMonitorJSONQueryRxFilterParse(reply, filter) < 0)
        return -1;

    return 0;
}


/*
 * Example return data
 *
 * {"return": [
 *      {"filename": "stdio", "label": "monitor"},
 *      {"filename": "pty:/dev/pts/6", "label": "serial0", "frontend-open": true},
 *      {"filename": "pty:/dev/pts/7", "label": "parallel0"}
 * ]}
 *
 */
static int
qemuMonitorJSONExtractChardevInfo(virJSONValue *reply,
                                  GHashTable *info)
{
    virJSONValue *data;
    int ret = -1;
    size_t i;
    qemuMonitorChardevInfo *entry = NULL;

    data = virJSONValueObjectGetArray(reply, "return");

    for (i = 0; i < virJSONValueArraySize(data); i++) {
        virJSONValue *chardev = virJSONValueArrayGet(data, i);
        const char *type;
        const char *alias;
        bool connected;

        if (!chardev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("character device information was missing array element"));
            goto cleanup;
        }

        if (!(alias = virJSONValueObjectGetString(chardev, "label"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("character device information was missing label"));
            goto cleanup;
        }

        if (!(type = virJSONValueObjectGetString(chardev, "filename"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("character device information was missing filename"));
            goto cleanup;
        }

        entry = g_new0(qemuMonitorChardevInfo, 1);

        if (STRPREFIX(type, "pty:"))
            entry->ptyPath = g_strdup(type + strlen("pty:"));

        if (virJSONValueObjectGetBoolean(chardev, "frontend-open", &connected) == 0) {
            if (connected)
                entry->state = VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED;
            else
                entry->state = VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED;
        }

        if (virHashAddEntry(info, alias, entry) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to add chardev '%1$s' info"), alias);
            goto cleanup;
        }

        entry = NULL;
    }

    ret = 0;

 cleanup:
    if (entry) {
        VIR_FREE(entry->ptyPath);
        VIR_FREE(entry);
    }

    return ret;
}


int
qemuMonitorJSONGetChardevInfo(qemuMonitor *mon,
                              GHashTable *info)

{
    g_autoptr(virJSONValue) cmd = qemuMonitorJSONMakeCommand("query-chardev",
                                                             NULL);
    g_autoptr(virJSONValue) reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return -1;

    return qemuMonitorJSONExtractChardevInfo(reply, info);
}


int qemuMonitorJSONDelDevice(qemuMonitor *mon,
                             const char *devalias)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("device_del",
                                     "s:id", devalias,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "DeviceNotFound"))
        return -2;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONAddDeviceProps(qemuMonitor *mon,
                              virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

     if (!(cmd = qemuMonitorJSONMakeCommandInternal("device_add", props)))
         return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONAddObject(qemuMonitor *mon,
                         virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("object-add", props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONDelObject(qemuMonitor *mon,
                         const char *objalias,
                         bool report_error)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("object-del", "s:id", objalias, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckErrorFull(cmd, reply, report_error) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevMirror(qemuMonitor *mon,
                              const char *jobname,
                              bool persistjob,
                              const char *device,
                              const char *target,
                              unsigned long long speed,
                              unsigned int granularity,
                              unsigned long long buf_size,
                              bool shallow,
                              bool syncWrite)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virTristateBool autofinalize = VIR_TRISTATE_BOOL_ABSENT;
    virTristateBool autodismiss = VIR_TRISTATE_BOOL_ABSENT;
    const char *syncmode = "full";
    const char *copymode = NULL;

    if (shallow)
        syncmode = "top";

    if (syncWrite)
        copymode = "write-blocking";

    if (persistjob) {
        autofinalize = VIR_TRISTATE_BOOL_YES;
        autodismiss = VIR_TRISTATE_BOOL_NO;
    }

    cmd = qemuMonitorJSONMakeCommand("blockdev-mirror",
                                     "S:job-id", jobname,
                                     "s:device", device,
                                     "s:target", target,
                                     "Y:speed", speed,
                                     "z:granularity", granularity,
                                     "P:buf-size", buf_size,
                                     "s:sync", syncmode,
                                     "S:copy-mode", copymode,
                                     "T:auto-finalize", autofinalize,
                                     "T:auto-dismiss", autodismiss,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    return qemuMonitorJSONCheckError(cmd, reply);
}


int
qemuMonitorJSONTransaction(qemuMonitor *mon, virJSONValue **actions)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("transaction",
                                     "a:actions", actions,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/* speed is in bytes/sec. Returns 0 on success, -1 with error message
 * emitted on failure. */
int
qemuMonitorJSONBlockCommit(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           const char *topNode,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long speed,
                           virTristateBool autofinalize)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virTristateBool autodismiss = VIR_TRISTATE_BOOL_NO;

    cmd = qemuMonitorJSONMakeCommand("block-commit",
                                     "s:device", device,
                                     "S:job-id", jobname,
                                     "Y:speed", speed,
                                     "S:top-node", topNode,
                                     "S:base-node", baseNode,
                                     "S:backing-file", backingName,
                                     "T:auto-finalize", autofinalize,
                                     "T:auto-dismiss", autodismiss,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONArbitraryCommand(qemuMonitor *mon,
                                    const char *cmd_str,
                                    int fd,
                                    char **reply_str)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = virJSONValueFromString(cmd_str)))
        return -1;

    if (qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        return -1;

    if (!(*reply_str = virJSONValueToString(reply, false)))
        return -1;

    return 0;
}

int qemuMonitorJSONInjectNMI(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("inject-nmi", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONSendKey(qemuMonitor *mon,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           unsigned int nkeycodes)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) keys = NULL;
    size_t i;

    /* create the key data array */
    keys = virJSONValueNewArray();

    for (i = 0; i < nkeycodes; i++) {
        g_autoptr(virJSONValue) key = NULL;

        if (keycodes[i] > 0xffff) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("keycode %1$zu is invalid: 0x%2$X"), i, keycodes[i]);
            return -1;
        }

        /* create single key object */
        key = virJSONValueNewObject();

        /* Union KeyValue has two types, use the generic one */
        if (virJSONValueObjectAppendString(key, "type", "number") < 0)
            return -1;

        /* with the keycode */
        if (virJSONValueObjectAppendNumberInt(key, "data", keycodes[i]) < 0)
            return -1;

        if (virJSONValueArrayAppend(keys, &key) < 0)
            return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("send-key",
                                     "a:keys", &keys,
                                     "p:hold-time", holdtime,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONScreendump(qemuMonitor *mon,
                              const char *device,
                              unsigned int head,
                              const char *format,
                              const char *file)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("screendump",
                                     "s:filename", file,
                                     "S:device", device,
                                     "p:head", head,
                                     "S:format", format,
                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


static int
qemuMonitorJSONParseBlockJobInfo(GHashTable *blockJobs,
                                 virJSONValue *entry,
                                 bool rawjobname)
{
    qemuMonitorBlockJobInfo *info = NULL;
    const char *device;
    const char *type;

    if (!(device = virJSONValueObjectGetString(entry, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'device'"));
        return -1;
    }

    if (!rawjobname)
        device = qemuAliasDiskDriveSkipPrefix(device);

    info = g_new0(qemuMonitorBlockJobInfo, 1);

    if (virHashAddEntry(blockJobs, device, info) < 0) {
        VIR_FREE(info);
        return -1;
    }

    if (!(type = virJSONValueObjectGetString(entry, "type"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'type'"));
        return -1;
    }
    if (STREQ(type, "stream"))
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_PULL;
    else if (STREQ(type, "commit"))
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT;
    else if (STREQ(type, "mirror"))
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;
    else if (STREQ(type, "backup"))
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_BACKUP;
    else
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;

    if (virJSONValueObjectGetNumberUlong(entry, "speed", &info->bandwidth) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'speed'"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(entry, "offset", &info->cur) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'offset'"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(entry, "len", &info->end) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'len'"));
        return -1;
    }

    if (virJSONValueObjectGetBoolean(entry, "ready", &info->ready) == 0)
        info->ready_present = true;

    return 0;
}

GHashTable *
qemuMonitorJSONGetAllBlockJobInfo(qemuMonitor *mon,
                                  bool rawjobname)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    size_t nr_results;
    size_t i;
    g_autoptr(GHashTable) blockJobs = virHashNew(g_free);

    cmd = qemuMonitorJSONMakeCommand("query-block-jobs", NULL);
    if (!cmd)
        return NULL;
    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if ((data = virJSONValueObjectGetArray(reply, "return")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("reply was missing return data"));
        return NULL;
    }

    nr_results = virJSONValueArraySize(data);

    for (i = 0; i < nr_results; i++) {
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing array element"));
            return NULL;
        }
        if (qemuMonitorJSONParseBlockJobInfo(blockJobs, entry, rawjobname) < 0)
            return NULL;
    }

    return g_steal_pointer(&blockJobs);
}


static int
qemuMonitorJSONBlockJobError(virJSONValue *cmd,
                             virJSONValue *reply,
                             const char *jobname)
{
    virJSONValue *error;

    if ((error = virJSONValueObjectGet(reply, "error")) &&
        (qemuMonitorJSONErrorIsClass(error, "DeviceNotActive"))) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No active block job '%1$s'"), jobname);
        return -1;
    }

    return qemuMonitorJSONCheckError(cmd, reply);
}


/* speed is in bytes/sec */
int
qemuMonitorJSONBlockStream(qemuMonitor *mon,
                           const char *device,
                           const char *jobname,
                           const char *baseNode,
                           const char *backingName,
                           unsigned long long speed)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virTristateBool autofinalize = VIR_TRISTATE_BOOL_YES;
    virTristateBool autodismiss = VIR_TRISTATE_BOOL_NO;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-stream",
                                           "s:device", device,
                                           "S:job-id", jobname,
                                           "Y:speed", speed,
                                           "S:base-node", baseNode,
                                           "S:backing-file", backingName,
                                           "T:auto-finalize", autofinalize,
                                           "T:auto-dismiss", autodismiss,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockJobCancel(qemuMonitor *mon,
                              const char *jobname,
                              bool force)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-job-cancel",
                                           "s:device", jobname,
                                           "B:force", force,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONBlockJobError(cmd, reply, jobname) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockJobSetSpeed(qemuMonitor *mon,
                                const char *jobname,
                                unsigned long long speed)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-job-set-speed",
                                           "s:device", jobname,
                                           "J:speed", speed,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONBlockJobError(cmd, reply, jobname) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONJobDismiss(qemuMonitor *mon,
                          const char *jobname)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("job-dismiss",
                                           "s:id", jobname,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONBlockJobError(cmd, reply, jobname) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONJobFinalize(qemuMonitor *mon,
                           const char *jobname)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("job-finalize",
                                           "s:id", jobname,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONBlockJobError(cmd, reply, jobname) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONJobComplete(qemuMonitor *mon,
                           const char *jobname)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("job-complete",
                                           "s:id", jobname,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONBlockJobError(cmd, reply, jobname) < 0)
        return -1;

    return 0;
}


int qemuMonitorJSONOpenGraphics(qemuMonitor *mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("add_client",
                                     "s:protocol", protocol,
                                     "s:fdname", fdname,
                                     "b:skipauth", skipauth,
                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


#define GET_THROTTLE_STATS_OPTIONAL(FIELD, STORE) \
    if (virJSONValueObjectGetNumberUlong(inserted, \
                                         FIELD, \
                                         &reply->STORE) < 0) { \
        reply->STORE = 0; \
    }
#define GET_THROTTLE_STATS(FIELD, STORE) \
    if (virJSONValueObjectGetNumberUlong(inserted, \
                                         FIELD, \
                                         &reply->STORE) < 0) { \
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, \
                       _("block_io_throttle field '%1$s' missing in qemu's output"), \
                       #STORE); \
        return -1; \
    }
static int
qemuMonitorJSONBlockIoThrottleInfo(virJSONValue *io_throttle,
                                   const char *qdevid,
                                   virDomainBlockIoTuneInfo *reply)
{
    size_t i;
    bool found = false;

    for (i = 0; i < virJSONValueArraySize(io_throttle); i++) {
        virJSONValue *temp_dev = virJSONValueArrayGet(io_throttle, i);
        virJSONValue *inserted;
        const char *current_drive;
        const char *current_qdev;

        if (!temp_dev || virJSONValueGetType(temp_dev) != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle device entry was not in expected format"));
            return -1;
        }

        current_qdev = virJSONValueObjectGetString(temp_dev, "qdev");
        current_drive = virJSONValueObjectGetString(temp_dev, "device");

        if (!current_drive && !current_qdev) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle device entry was not in expected format"));
            return -1;
        }

        if (STRNEQ_NULLABLE(current_qdev, qdevid) &&
            STRNEQ_NULLABLE(current_drive, qdevid))
            continue;

        found = true;
        if (!(inserted = virJSONValueObjectGetObject(temp_dev, "inserted"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle inserted entry was not in expected format"));
            return -1;
        }
        GET_THROTTLE_STATS("bps", total_bytes_sec);
        GET_THROTTLE_STATS("bps_rd", read_bytes_sec);
        GET_THROTTLE_STATS("bps_wr", write_bytes_sec);
        GET_THROTTLE_STATS("iops", total_iops_sec);
        GET_THROTTLE_STATS("iops_rd", read_iops_sec);
        GET_THROTTLE_STATS("iops_wr", write_iops_sec);
        GET_THROTTLE_STATS_OPTIONAL("bps_max", total_bytes_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("bps_rd_max", read_bytes_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("bps_wr_max", write_bytes_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("iops_max", total_iops_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("iops_rd_max", read_iops_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("iops_wr_max", write_iops_sec_max);
        GET_THROTTLE_STATS_OPTIONAL("iops_size", size_iops_sec);

        reply->group_name = g_strdup(virJSONValueObjectGetString(inserted, "group"));

        GET_THROTTLE_STATS_OPTIONAL("bps_max_length", total_bytes_sec_max_length);
        GET_THROTTLE_STATS_OPTIONAL("bps_rd_max_length", read_bytes_sec_max_length);
        GET_THROTTLE_STATS_OPTIONAL("bps_wr_max_length", write_bytes_sec_max_length);
        GET_THROTTLE_STATS_OPTIONAL("iops_max_length", total_iops_sec_max_length);
        GET_THROTTLE_STATS_OPTIONAL("iops_rd_max_length", read_iops_sec_max_length);
        GET_THROTTLE_STATS_OPTIONAL("iops_wr_max_length", write_iops_sec_max_length);

        break;
    }

    if (!found) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot find throttling info for device '%1$s'"),
                       qdevid);
        return -1;
    }

    return 0;
}
#undef GET_THROTTLE_STATS
#undef GET_THROTTLE_STATS_OPTIONAL

int qemuMonitorJSONSetBlockIoThrottle(qemuMonitor *mon,
                                      const char *qomid,
                                      virDomainBlockIoTuneInfo *info)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) result = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block_set_io_throttle",
                                           "s:id", qomid,
                                           "U:bps", info->total_bytes_sec,
                                           "U:bps_rd", info->read_bytes_sec,
                                           "U:bps_wr", info->write_bytes_sec,
                                           "U:iops", info->total_iops_sec,
                                           "U:iops_rd", info->read_iops_sec,
                                           "U:iops_wr", info->write_iops_sec,
                                           "U:bps_max", info->total_bytes_sec_max,
                                           "U:bps_rd_max", info->read_bytes_sec_max,
                                           "U:bps_wr_max", info->write_bytes_sec_max,
                                           "U:iops_max", info->total_iops_sec_max,
                                           "U:iops_rd_max", info->read_iops_sec_max,
                                           "U:iops_wr_max", info->write_iops_sec_max,
                                           "U:iops_size", info->size_iops_sec,
                                           "S:group", info->group_name,
                                           "P:bps_max_length", info->total_bytes_sec_max_length,
                                           "P:bps_rd_max_length", info->read_bytes_sec_max_length,
                                           "P:bps_wr_max_length", info->write_bytes_sec_max_length,
                                           "P:iops_max_length", info->total_iops_sec_max_length,
                                           "P:iops_rd_max_length", info->read_iops_sec_max_length,
                                           "P:iops_wr_max_length", info->write_iops_sec_max_length,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &result) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, result) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONGetBlockIoThrottle(qemuMonitor *mon,
                                      const char *qdevid,
                                      virDomainBlockIoTuneInfo *reply)
{
    g_autoptr(virJSONValue) devices = NULL;

    if (!(devices = qemuMonitorJSONQueryBlock(mon)))
        return -1;

    return qemuMonitorJSONBlockIoThrottleInfo(devices, qdevid, reply);
}

int qemuMonitorJSONSystemWakeup(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("system_wakeup", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int qemuMonitorJSONGetVersion(qemuMonitor *mon,
                              int *major,
                              int *minor,
                              int *micro,
                              char **package)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    virJSONValue *qemu;

    *major = *minor = *micro = 0;
    if (package)
        *package = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-version", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (!(qemu = virJSONValueObjectGetObject(data, "qemu"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'qemu' data"));
        return -1;
    }

    if (virJSONValueObjectGetNumberInt(qemu, "major", major) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'major' version"));
        return -1;
    }
    if (virJSONValueObjectGetNumberInt(qemu, "minor", minor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'minor' version"));
        return -1;
    }
    if (virJSONValueObjectGetNumberInt(qemu, "micro", micro) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'micro' version"));
        return -1;
    }

    if (package) {
        const char *tmp;
        if (!(tmp = virJSONValueObjectGetString(data, "package"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-version reply was missing 'package' version"));
            return -1;
        }
        *package = g_strdup(tmp);
    }

    return 0;
}


int qemuMonitorJSONGetMachines(qemuMonitor *mon,
                               qemuMonitorMachineInfo ***machines)
{
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    qemuMonitorMachineInfo **infolist = NULL;
    size_t n = 0;
    size_t i;

    *machines = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-machines", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        goto cleanup;

    n = virJSONValueArraySize(data);

    /* null-terminated list */
    infolist = g_new0(qemuMonitorMachineInfo *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorMachineInfo *info;

        info = g_new0(qemuMonitorMachineInfo, 1);

        infolist[i] = info;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-machines reply data was missing 'name'"));
            goto cleanup;
        }

        info->name = g_strdup(tmp);

        if (virJSONValueObjectHasKey(child, "is-default") &&
            virJSONValueObjectGetBoolean(child, "is-default", &info->isDefault) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-machines reply has malformed 'is-default' data"));
            goto cleanup;
        }

        if (virJSONValueObjectHasKey(child, "alias")) {
            if (!(tmp = virJSONValueObjectGetString(child, "alias"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-machines reply has malformed 'alias' data"));
                goto cleanup;
            }
            info->alias = g_strdup(tmp);
        }
        if (virJSONValueObjectHasKey(child, "cpu-max") &&
            virJSONValueObjectGetNumberUint(child, "cpu-max", &info->maxCpus) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-machines reply has malformed 'cpu-max' data"));
            goto cleanup;
        }

        ignore_value(virJSONValueObjectGetBoolean(child, "hotpluggable-cpus",
                                                  &info->hotplugCpus));

        if (virJSONValueObjectHasKey(child, "default-cpu-type")) {
            if (!(tmp = virJSONValueObjectGetString(child, "default-cpu-type"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-machines reply has malformed 'default-cpu-type' data"));
                goto cleanup;
            }

            info->defaultCPU = g_strdup(tmp);
        }

        if (virJSONValueObjectHasKey(child, "numa-mem-supported")) {
            if (virJSONValueObjectGetBoolean(child, "numa-mem-supported", &info->numaMemSupported) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-machines reply has malformed 'numa-mem-supported' data"));
                goto cleanup;
            }
        } else {
            info->numaMemSupported = true;
        }

        if (virJSONValueObjectHasKey(child, "default-ram-id")) {
            if (!(tmp = virJSONValueObjectGetString(child, "default-ram-id"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-machines reply has malformed 'default-ram-id' data"));
                goto cleanup;
            }

            info->defaultRAMid = g_strdup(tmp);
        }

        if (virJSONValueObjectHasKey(child, "deprecated") &&
            virJSONValueObjectGetBoolean(child, "deprecated", &info->deprecated) < 0)
            goto cleanup;

        if (virJSONValueObjectHasKey(child, "acpi")) {
            bool acpi;

            if (virJSONValueObjectGetBoolean(child, "acpi", &acpi) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-machines reply has malformed 'acpi data"));
                goto cleanup;
            }

            info->acpi = virTristateBoolFromBool(acpi);
        }
    }

    ret = n;
    *machines = g_steal_pointer(&infolist);

 cleanup:
    if (infolist) {
        for (i = 0; i < n; i++)
            qemuMonitorMachineInfoFree(infolist[i]);
        VIR_FREE(infolist);
    }
    return ret;
}


int
qemuMonitorJSONGetCPUDefinitions(qemuMonitor *mon,
                                 qemuMonitorCPUDefs **cpuDefs)
{
    g_autoptr(qemuMonitorCPUDefs) defs = NULL;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    size_t ncpus;
    size_t i;

    *cpuDefs = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-cpu-definitions", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* Urgh, some QEMU architectures have the query-cpu-definitions
     * command, but return 'GenericError' with string "Not supported",
     * instead of simply omitting the command entirely :-(
     */
    if (qemuMonitorJSONHasError(reply, "GenericError"))
        return 0;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    ncpus = virJSONValueArraySize(data);

    if (!(defs = qemuMonitorCPUDefsNew(ncpus)))
        return -1;

    for (i = 0; i < defs->ncpus; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorCPUDefInfo *cpu = defs->cpus + i;
        virJSONValue *feat;
        virJSONValue *deprecated;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-cpu-definitions reply data was missing 'name'"));
            return -1;
        }

        cpu->name = g_strdup(tmp);

        if ((tmp = virJSONValueObjectGetString(child, "typename")) && *tmp)
            cpu->type = g_strdup(tmp);

        if ((feat = virJSONValueObjectGetArray(child, "unavailable-features"))) {
            if (virJSONValueArraySize(feat) > 0) {
                if (!(cpu->blockers = virJSONValueArrayToStringList(feat)))
                    return -1;

                cpu->usable = VIR_DOMCAPS_CPU_USABLE_NO;
            } else {
                cpu->usable = VIR_DOMCAPS_CPU_USABLE_YES;
            }
        }

        if ((deprecated = virJSONValueObjectGet(child, "deprecated")) &&
            virJSONValueGetBoolean(deprecated, &cpu->deprecated) < 0)
            return -1;
    }

    *cpuDefs = g_steal_pointer(&defs);
    return 0;
}


static int
qemuMonitorJSONParseCPUModelProperty(const char *key,
                                     virJSONValue *value,
                                     void *opaque)
{
    qemuMonitorCPUModelInfo *machine_model = opaque;
    qemuMonitorCPUProperty *prop;

    prop = machine_model->props + machine_model->nprops;

    switch ((virJSONType)virJSONValueGetType(value)) {
    case VIR_JSON_TYPE_STRING:
        prop->value.string = g_strdup(virJSONValueGetString(value));
        prop->type = QEMU_MONITOR_CPU_PROPERTY_STRING;
        break;

    case VIR_JSON_TYPE_NUMBER:
        /* Ignore numbers which cannot be parsed as unsigned long long */
        if (virJSONValueGetNumberLong(value, &prop->value.number) < 0)
            return 0;
        prop->type = QEMU_MONITOR_CPU_PROPERTY_NUMBER;
        break;

    case VIR_JSON_TYPE_BOOLEAN:
        virJSONValueGetBoolean(value, &prop->value.boolean);
        prop->type = QEMU_MONITOR_CPU_PROPERTY_BOOLEAN;
        break;

    case VIR_JSON_TYPE_OBJECT:
    case VIR_JSON_TYPE_ARRAY:
    case VIR_JSON_TYPE_NULL:
        return 0;
    }

    machine_model->nprops++;
    prop->name = g_strdup(key);

    return 0;
}


static virJSONValue *
qemuMonitorJSONMakeCPUModel(virCPUDef *cpu,
                            bool migratable,
                            bool hv_passthrough)
{
    g_autoptr(virJSONValue) model = virJSONValueNewObject();
    size_t i;

    if (virJSONValueObjectAppendString(model, "name", cpu->model) < 0)
        return NULL;

    if (cpu->nfeatures || !migratable || hv_passthrough) {
        g_autoptr(virJSONValue) props = virJSONValueNewObject();

        for (i = 0; i < cpu->nfeatures; i++) {
            char *name = cpu->features[i].name;
            bool enabled = false;

            /* policy may be reported as -1 if the CPU def is a host model */
            if (cpu->features[i].policy == VIR_CPU_FEATURE_REQUIRE ||
                cpu->features[i].policy == VIR_CPU_FEATURE_FORCE ||
                cpu->features[i].policy == -1)
                enabled = true;

            if (virJSONValueObjectAppendBoolean(props, name, enabled) < 0)
                return NULL;
        }

        if (!migratable &&
            virJSONValueObjectAppendBoolean(props, "migratable", false) < 0) {
            return NULL;
        }

        if (hv_passthrough &&
            virJSONValueObjectAppendBoolean(props, "hv-passthrough", true) < 0) {
            return NULL;
        }

        if (virJSONValueObjectAppend(model, "props", &props) < 0)
            return NULL;
    }

    return g_steal_pointer(&model);
}


static int
qemuMonitorJSONParseCPUModelData(virJSONValue *data,
                                 const char *cmd_name,
                                 bool fail_no_props,
                                 virJSONValue **cpu_model,
                                 virJSONValue **cpu_props,
                                 const char **cpu_name)
{
    if (!(*cpu_model = virJSONValueObjectGetObject(data, "model"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s reply data was missing 'model'"), cmd_name);
        return -1;
    }

    if (!(*cpu_name = virJSONValueObjectGetString(*cpu_model, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s reply data was missing 'name'"), cmd_name);
        return -1;
    }

    if (!(*cpu_props = virJSONValueObjectGetObject(*cpu_model, "props")) &&
        fail_no_props) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%1$s reply data was missing 'props'"), cmd_name);
        return -1;
    }

    return 0;
}


static int
qemuMonitorJSONParseCPUModel(const char *cpu_name,
                             virJSONValue *cpu_props,
                             qemuMonitorCPUModelInfo **model_info)
{
    g_autoptr(qemuMonitorCPUModelInfo) machine_model = NULL;

    machine_model = g_new0(qemuMonitorCPUModelInfo, 1);
    machine_model->name = g_strdup(cpu_name);

    if (cpu_props) {
        size_t nprops = virJSONValueObjectKeysNumber(cpu_props);

        machine_model->props = g_new0(qemuMonitorCPUProperty, nprops);

        if (virJSONValueObjectForeachKeyValue(cpu_props,
                                              qemuMonitorJSONParseCPUModelProperty,
                                              machine_model) < 0)
            return -1;
    }

    *model_info = g_steal_pointer(&machine_model);
    return 0;
}


static int
qemuMonitorJSONQueryCPUModelExpansionOne(qemuMonitor *mon,
                                         qemuMonitorCPUModelExpansionType type,
                                         virJSONValue **model,
                                         virJSONValue **data)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    const char *typeStr = "";

    switch (type) {
    case QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC:
    case QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL:
        typeStr = "static";
        break;

    case QEMU_MONITOR_CPU_MODEL_EXPANSION_FULL:
        typeStr = "full";
        break;
    }
    if (!(cmd = qemuMonitorJSONMakeCommand("query-cpu-model-expansion",
                                           "s:type", typeStr,
                                           "a:model", model,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* Even though query-cpu-model-expansion is advertised by query-commands it
     * may just return GenericError if it is not implemented for the requested
     * guest architecture or it is not supported in the host environment.
     */
    if (qemuMonitorJSONHasError(reply, "GenericError"))
        return 0;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_OBJECT) < 0)
        return -1;

    *data = virJSONValueObjectStealObject(reply, "return");

    return 1;
}


int
qemuMonitorJSONGetCPUModelExpansion(qemuMonitor *mon,
                                    qemuMonitorCPUModelExpansionType type,
                                    virCPUDef *cpu,
                                    bool migratable,
                                    bool hv_passthrough,
                                    bool fail_no_props,
                                    qemuMonitorCPUModelInfo **model_info)
{
    g_autoptr(virJSONValue) model = NULL;
    g_autoptr(virJSONValue) data = NULL;
    g_autoptr(virJSONValue) fullData = NULL;
    virJSONValue *cpu_model;
    virJSONValue *cpu_props = NULL;
    const char *cpu_name = "";
    int rc;

    *model_info = NULL;

    if (!(model = qemuMonitorJSONMakeCPUModel(cpu, migratable, hv_passthrough)))
        return -1;

    if ((rc = qemuMonitorJSONQueryCPUModelExpansionOne(mon, type, &model, &data)) <= 0)
        return rc;

    if (qemuMonitorJSONParseCPUModelData(data, "query-cpu-model-expansion",
                                         fail_no_props, &cpu_model, &cpu_props,
                                         &cpu_name) < 0)
        return -1;

    /* QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL requests "full" expansion
     * on the result of the initial "static" expansion. */
    if (type == QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL) {
        g_autoptr(virJSONValue) fullModel = virJSONValueCopy(cpu_model);

        if (!fullModel)
            return -1;

        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_FULL;

        if ((rc = qemuMonitorJSONQueryCPUModelExpansionOne(mon, type, &fullModel, &fullData)) <= 0)
            return rc;

        if (qemuMonitorJSONParseCPUModelData(fullData, "query-cpu-model-expansion",
                                             fail_no_props, &cpu_model, &cpu_props,
                                             &cpu_name) < 0)
            return -1;
    }

    return qemuMonitorJSONParseCPUModel(cpu_name, cpu_props, model_info);
}


int
qemuMonitorJSONGetCPUModelBaseline(qemuMonitor *mon,
                                   virCPUDef *cpu_a,
                                   virCPUDef *cpu_b,
                                   qemuMonitorCPUModelInfo **baseline)
{
    g_autoptr(virJSONValue) model_a = NULL;
    g_autoptr(virJSONValue) model_b = NULL;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    virJSONValue *cpu_model;
    virJSONValue *cpu_props = NULL;
    const char *cpu_name = "";

    if (!(model_a = qemuMonitorJSONMakeCPUModel(cpu_a, true, false)) ||
        !(model_b = qemuMonitorJSONMakeCPUModel(cpu_b, true, false)))
        return -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-cpu-model-baseline",
                                           "a:modela", &model_a,
                                           "a:modelb", &model_b,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (qemuMonitorJSONParseCPUModelData(data, "query-cpu-model-baseline",
                                         false, &cpu_model, &cpu_props,
                                         &cpu_name) < 0)
        return -1;

    return qemuMonitorJSONParseCPUModel(cpu_name, cpu_props, baseline);
}


int
qemuMonitorJSONGetCPUModelComparison(qemuMonitor *mon,
                                     virCPUDef *cpu_a,
                                     virCPUDef *cpu_b,
                                     char **result)
{
    g_autoptr(virJSONValue) model_a = NULL;
    g_autoptr(virJSONValue) model_b = NULL;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    const char *data_result;
    virJSONValue *data;

    if (!(model_a = qemuMonitorJSONMakeCPUModel(cpu_a, true, false)) ||
        !(model_b = qemuMonitorJSONMakeCPUModel(cpu_b, true, false)))
        return -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-cpu-model-comparison",
                                           "a:modela", &model_a,
                                           "a:modelb", &model_b,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    data = virJSONValueObjectGetObject(reply, "return");

    if (!(data_result = virJSONValueObjectGetString(data, "result"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-cpu-model-comparison reply data was missing 'result'"));
        return -1;
    }

    *result = g_strdup(data_result);
    return 0;
}


static int
qemuMonitorJSONGetCommandLineOptionsWorker(size_t pos G_GNUC_UNUSED,
                                           virJSONValue *item,
                                           void *opaque)
{
    const char *name = virJSONValueObjectGetString(item, "option");
    g_autoptr(virJSONValue) parameters = NULL;
    GHashTable *options = opaque;

    if (!name ||
        virJSONValueObjectRemoveKey(item, "parameters", &parameters) <= 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("reply data was missing 'option' name or parameters"));
        return -1;
    }

    g_hash_table_insert(options, g_strdup(name), parameters);
    parameters = NULL;

    return 1;
}


GHashTable *
qemuMonitorJSONGetCommandLineOptions(qemuMonitor *mon)
{
    g_autoptr(GHashTable) ret = virHashNew(virJSONValueHashFree);
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-command-line-options", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return NULL;

    if (virJSONValueArrayForeachSteal(data,
                                      qemuMonitorJSONGetCommandLineOptionsWorker,
                                      ret) < 0)
        return NULL;

    return g_steal_pointer(&ret);
}


int qemuMonitorJSONGetKVMState(qemuMonitor *mon,
                               bool *enabled,
                               bool *present)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;

    /* Safe defaults */
    *enabled = *present = false;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-kvm", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (virJSONValueObjectGetBoolean(data, "enabled", enabled) < 0 ||
        virJSONValueObjectGetBoolean(data, "present", present) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-kvm replied unexpected data"));
        return -1;
    }

    return 0;
}


int
qemuMonitorJSONGetObjectTypes(qemuMonitor *mon,
                              char ***types)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    g_auto(GStrv) typelist = NULL;
    size_t n = 0;
    size_t i;

    *types = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list-types", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    n = virJSONValueArraySize(data);

    /* null-terminated list */
    typelist = g_new0(char *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qom-list-types reply data was missing 'name'"));
            return -1;
        }

        typelist[i] = g_strdup(tmp);
    }

    *types = g_steal_pointer(&typelist);
    return n;
}


int qemuMonitorJSONGetObjectListPaths(qemuMonitor *mon,
                                      const char *path,
                                      qemuMonitorJSONListPath ***paths)
{
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    qemuMonitorJSONListPath **pathlist = NULL;
    size_t n = 0;
    size_t i;

    *paths = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list",
                                           "s:path", path,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        goto cleanup;

    n = virJSONValueArraySize(data);

    /* null-terminated list */
    pathlist = g_new0(qemuMonitorJSONListPath *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorJSONListPath *info;

        info = g_new0(qemuMonitorJSONListPath, 1);

        pathlist[i] = info;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qom-list reply data was missing 'name'"));
            goto cleanup;
        }

        info->name = g_strdup(tmp);

        if (virJSONValueObjectHasKey(child, "type")) {
            if (!(tmp = virJSONValueObjectGetString(child, "type"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("qom-list reply has malformed 'type' data"));
                goto cleanup;
            }
            info->type = g_strdup(tmp);
        }
    }

    ret = n;
    *paths = g_steal_pointer(&pathlist);

 cleanup:
    if (pathlist) {
        for (i = 0; i < n; i++)
            qemuMonitorJSONListPathFree(pathlist[i]);
        VIR_FREE(pathlist);
    }
    return ret;
}

void qemuMonitorJSONListPathFree(qemuMonitorJSONListPath *paths)
{
    if (!paths)
        return;
    g_free(paths->name);
    g_free(paths->type);
    g_free(paths);
}


int qemuMonitorJSONGetObjectProperty(qemuMonitor *mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectProperty *prop)
{
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    const char *tmp;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", path,
                                           "s:property", property,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    data = virJSONValueObjectGet(reply, "return");

    switch ((qemuMonitorJSONObjectPropertyType) prop->type) {
    /* Simple cases of boolean, int, long, uint, ulong, double, and string
     * will receive return value as part of {"return": xxx} statement
     */
    case QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN:
        ret = virJSONValueGetBoolean(data, &prop->val.b);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_INT:
        ret = virJSONValueGetNumberInt(data, &prop->val.iv);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_LONG:
        ret = virJSONValueGetNumberLong(data, &prop->val.l);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_UINT:
        ret = virJSONValueGetNumberUint(data, &prop->val.ui);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_ULONG:
        ret = virJSONValueGetNumberUlong(data, &prop->val.ul);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_DOUBLE:
        ret = virJSONValueGetNumberDouble(data, &prop->val.d);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_STRING:
        tmp = virJSONValueGetString(data);
        if (tmp)
            prop->val.str = g_strdup(tmp);
        if (tmp)
            ret = 0;
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qom-get invalid object property type %1$d"),
                       prop->type);
        return -1;
        break;
    }

    if (ret == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qom-get reply was missing return data"));
        return -1;
    }

    return 0;
}


static int
qemuMonitorJSONGetStringListProperty(qemuMonitor *mon,
                                     const char *path,
                                     const char *property,
                                     char ***strList)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    *strList = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", path,
                                           "s:property", property,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    if (!(*strList = virJSONValueArrayToStringList(data)))
        return -1;

    return 0;
}


#define MAKE_SET_CMD(STRING, VALUE) \
    cmd = qemuMonitorJSONMakeCommand("qom-set", \
                                      "s:path", path, \
                                      "s:property", property, \
                                      STRING, VALUE, \
                                      NULL)
int qemuMonitorJSONSetObjectProperty(qemuMonitor *mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectProperty *prop)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    switch ((qemuMonitorJSONObjectPropertyType) prop->type) {
    /* Simple cases of boolean, int, long, uint, ulong, double, and string
     * will receive return value as part of {"return": xxx} statement
     */
    case QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN:
        MAKE_SET_CMD("b:value", prop->val.b);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_INT:
        MAKE_SET_CMD("i:value", prop->val.iv);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_LONG:
        MAKE_SET_CMD("I:value", prop->val.l);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_UINT:
        MAKE_SET_CMD("u:value", prop->val.ui);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_ULONG:
        MAKE_SET_CMD("U:value", prop->val.ul);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_DOUBLE:
        MAKE_SET_CMD("d:value", prop->val.d);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_STRING:
        MAKE_SET_CMD("s:value", prop->val.str);
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qom-set invalid object property type %1$d"),
                       prop->type);
        return -1;

    }
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}
#undef MAKE_SET_CMD


static int
qemuMonitorJSONParsePropsList(virJSONValue *cmd,
                              virJSONValue *reply,
                              const char *type,
                              char ***props)
{
    virJSONValue *data;
    g_auto(GStrv) proplist = NULL;
    size_t n = 0;
    size_t count = 0;
    size_t i;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    n = virJSONValueArraySize(data);

    /* null-terminated list */
    proplist = g_new0(char *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (type &&
            STRNEQ_NULLABLE(virJSONValueObjectGetString(child, "type"), type))
            continue;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("reply data was missing 'name'"));
            return -1;
        }

        proplist[count++] = g_strdup(tmp);
    }

    *props = g_steal_pointer(&proplist);
    return count;
}


static int
qemuMonitorJSONGetDevicePropsWorker(size_t pos G_GNUC_UNUSED,
                                    virJSONValue *item,
                                    void *opaque)
{
    const char *name = virJSONValueObjectGetString(item, "name");
    GHashTable *devices = opaque;

    if (!name) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("reply data was missing 'name'"));
        return -1;
    }

    if (virHashAddEntry(devices, name, item) < 0)
        return -1;

    return 0;
}


GHashTable *
qemuMonitorJSONGetDeviceProps(qemuMonitor *mon,
                              const char *device)
{
    g_autoptr(GHashTable) props = virHashNew(virJSONValueHashFree);
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("device-list-properties",
                                           "s:typename", device,
                                           NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    /* return empty hash */
    if (qemuMonitorJSONHasError(reply, "DeviceNotFound"))
        return g_steal_pointer(&props);

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return NULL;

    if (virJSONValueArrayForeachSteal(data,
                                      qemuMonitorJSONGetDevicePropsWorker,
                                      props) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


int
qemuMonitorJSONGetObjectProps(qemuMonitor *mon,
                              const char *object,
                              char ***props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    *props = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list-properties",
                                           "s:typename", object,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "DeviceNotFound"))
        return 0;

    return qemuMonitorJSONParsePropsList(cmd, reply, NULL, props);
}


char *
qemuMonitorJSONGetTargetArch(qemuMonitor *mon)
{
    const char *arch;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-target", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return NULL;

    if (!(arch = virJSONValueObjectGetString(data, "arch"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-target reply was missing arch data"));
        return NULL;
    }

    return g_strdup(arch);
}


int
qemuMonitorJSONGetMigrationCapabilities(qemuMonitor *mon,
                                        char ***capabilities)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *caps;
    g_auto(GStrv) list = NULL;
    size_t i;
    size_t n;

    *capabilities = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-migrate-capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(caps = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    n = virJSONValueArraySize(caps);

    list = g_new0(char *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *cap = virJSONValueArrayGet(caps, i);
        const char *name;

        if (!cap || virJSONValueGetType(cap) != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in migration capabilities list"));
            return -1;
        }

        if (!(name = virJSONValueObjectGetString(cap, "capability"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing migration capability name"));
            return -1;
        }

        list[i] = g_strdup(name);
    }

    *capabilities = g_steal_pointer(&list);
    return n;
}


int
qemuMonitorJSONSetMigrationCapabilities(qemuMonitor *mon,
                                        virJSONValue **caps)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-set-capabilities",
                                           "a:capabilities", caps,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/**
 * qemuMonitorJSONGetGICCapabilities:
 * @mon: QEMU JSON monitor
 * @capabilities: where to store the GIC capabilities
 *
 * Use @mon to obtain information about the GIC capabilities for the
 * corresponding QEMU binary, and store them in @capabilities.
 *
 * If the QEMU binary has no GIC capabilities, or if GIC capabilities could
 * not be determined due to the lack of 'query-gic-capabilities' QMP command,
 * a NULL pointer will be returned instead of an empty array.
 *
 * Returns: the number of GIC capabilities obtained from the monitor,
 *          <0 on failure
 */
int
qemuMonitorJSONGetGICCapabilities(qemuMonitor *mon,
                                  virGICCapability **capabilities)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *caps;
    g_autofree virGICCapability *list = NULL;
    size_t i;
    size_t n;

    *capabilities = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-gic-capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* If the 'query-gic-capabilities' QMP command was not available
     * we simply successfully return zero capabilities.
     * This is the case for QEMU <2.6 and all non-ARM architectures */
    if (qemuMonitorJSONHasError(reply, "CommandNotFound"))
        return 0;

    if (!(caps = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    n = virJSONValueArraySize(caps);

    /* If the returned array was empty we have to return successfully */
    if (n == 0)
        return 0;

    list = g_new0(virGICCapability, n);

    for (i = 0; i < n; i++) {
        virJSONValue *cap = virJSONValueArrayGet(caps, i);
        int version;
        bool kernel;
        bool emulated;

        if (!cap || virJSONValueGetType(cap) != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in GIC capabilities list"));
            return -1;
        }

        if (virJSONValueObjectGetNumberInt(cap, "version", &version) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing GIC version"));
            return -1;
        }

        if (virJSONValueObjectGetBoolean(cap, "kernel", &kernel) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing in-kernel GIC information"));
            return -1;
        }

        if (virJSONValueObjectGetBoolean(cap, "emulated", &emulated) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing emulated GIC information"));
            return -1;
        }

        list[i].version = version;
        if (kernel)
            list[i].implementation |= VIR_GIC_IMPLEMENTATION_KERNEL;
        if (emulated)
            list[i].implementation |= VIR_GIC_IMPLEMENTATION_EMULATED;
    }

    *capabilities = g_steal_pointer(&list);
    return n;
}


/**
 * qemuMonitorJSONGetSEVCapabilities:
 * @mon: qemu monitor object
 * @capabilities: pointer to pointer to a SEV capability structure to be filled
 *
 * This function queries and fills in AMD's SEV platform-specific data.
 * Note that from QEMU's POV both -object sev-guest and query-sev-capabilities
 * can be present even if SEV is not available, which basically leaves us with
 * checking for JSON "GenericError" in order to differentiate between
 * compiled-in support and actual SEV support on the platform.
 *
 * Returns -1 on error, 0 if SEV is not supported, and 1 if SEV is supported on
 * the platform.
 */
int
qemuMonitorJSONGetSEVCapabilities(qemuMonitor *mon,
                                  virSEVCapability **capabilities)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *caps;
    const char *pdh = NULL;
    const char *cert_chain = NULL;
    const char *cpu0_id = NULL;
    unsigned int cbitpos;
    unsigned int reduced_phys_bits;
    g_autoptr(virSEVCapability) capability = NULL;

    *capabilities = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-sev-capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* QEMU has only compiled-in support of SEV */
    if (qemuMonitorJSONHasError(reply, "GenericError"))
        return 0;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    caps = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetNumberUint(caps, "cbitpos", &cbitpos) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sev-capabilities reply was missing 'cbitpos' field"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(caps, "reduced-phys-bits",
                                        &reduced_phys_bits) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sev-capabilities reply was missing 'reduced-phys-bits' field"));
        return -1;
    }

    if (!(pdh = virJSONValueObjectGetString(caps, "pdh"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sev-capabilities reply was missing 'pdh' field"));
        return -1;
    }

    if (!(cert_chain = virJSONValueObjectGetString(caps, "cert-chain"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sev-capabilities reply was missing 'cert-chain' field"));
        return -1;
    }

    capability = g_new0(virSEVCapability, 1);

    capability->pdh = g_strdup(pdh);

    capability->cert_chain = g_strdup(cert_chain);

    cpu0_id = virJSONValueObjectGetString(caps, "cpu0-id");
    if (cpu0_id != NULL) {
        capability->cpu0_id = g_strdup(cpu0_id);
    }

    capability->cbitpos = cbitpos;
    capability->reduced_phys_bits = reduced_phys_bits;
    *capabilities = g_steal_pointer(&capability);
    return 1;
}


/**
 * qemuMonitorJSONGetSGXCapabilities:
 * @mon: qemu monitor object
 * @capabilities: pointer to pointer to a SGX capability structure to be filled
 *
 * This function queries and fills in INTEL's SGX platform-specific data.
 * Note that from QEMU's POV both -object sgx-epc and query-sgx-capabilities
 * can be present even if SGX is not available, which basically leaves us with
 * checking for JSON "GenericError" in order to differentiate between compiled-in
 * support and actual SGX support on the platform.
 *
 * Returns: -1 on error,
 *           0 if SGX is not supported, and
 *           1 if SGX is supported on the platform.
 */
int
qemuMonitorJSONGetSGXCapabilities(qemuMonitor *mon,
                                  virSGXCapability **capabilities)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virSGXCapability) capability = NULL;
    unsigned long long section_size_sum = 0;
    virJSONValue *sgxSections = NULL;
    virJSONValue *caps;
    size_t i;

    *capabilities = NULL;
    capability = g_new0(virSGXCapability, 1);

    if (!(cmd = qemuMonitorJSONMakeCommand("query-sgx-capabilities", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    /* QEMU has only compiled-in support of SGX */
    if (qemuMonitorJSONHasError(reply, "GenericError"))
        return 0;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    caps = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetBoolean(caps, "flc", &capability->flc) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sgx-capabilities reply was missing 'flc' field"));
        return -1;
    }

    if (virJSONValueObjectGetBoolean(caps, "sgx1", &capability->sgx1) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sgx-capabilities reply was missing 'sgx1' field"));
        return -1;
    }

    if (virJSONValueObjectGetBoolean(caps, "sgx2", &capability->sgx2) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-sgx-capabilities reply was missing 'sgx2' field"));
        return -1;
    }

    if ((sgxSections = virJSONValueObjectGetArray(caps, "sections"))) {
        /* SGX EPC sections info was added since QEMU 7.0.0 */
        unsigned long long size;

        capability->nSgxSections = virJSONValueArraySize(sgxSections);
        capability->sgxSections = g_new0(virSGXSection, capability->nSgxSections);

        for (i = 0; i < capability->nSgxSections; i++) {
            virJSONValue *elem = virJSONValueArrayGet(sgxSections, i);

            if (virJSONValueObjectGetNumberUlong(elem, "size", &size) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-sgx-capabilities reply was missing 'size' field"));
                return -1;
            }
            capability->sgxSections[i].size = size / 1024;
            section_size_sum += capability->sgxSections[i].size;

            if (virJSONValueObjectGetNumberUint(elem, "node",
                                               &capability->sgxSections[i].node) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-sgx-capabilities reply was missing 'node' field"));
                return -1;
            }
        }
    } else {
        /* no support for QEMU version older than 7.0.0 */
        return 0;
    }

    if (virJSONValueObjectHasKey(caps, "section-size")) {
        unsigned long long section_size = 0;

        if (virJSONValueObjectGetNumberUlong(caps, "section-size", &section_size) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-sgx-capabilities reply was missing 'section-size' field"));
            return -1;
        }
        capability->section_size = section_size / 1024;
    } else {
        /* QEMU no longer reports deprecated attribute. */
        capability->section_size = section_size_sum;
    }

    *capabilities = g_steal_pointer(&capability);
    return 1;
}


static virJSONValue *
qemuMonitorJSONBuildInetSocketAddress(const char *host,
                                      const char *port)
{
    g_autoptr(virJSONValue) addr = NULL;
    g_autoptr(virJSONValue) data = NULL;

    if (virJSONValueObjectAdd(&data,
                              "s:host", host,
                              "s:port", port,
                              NULL) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&addr,
                              "s:type", "inet",
                              "a:data", &data,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&addr);
}

static virJSONValue *
qemuMonitorJSONBuildUnixSocketAddress(const char *path)
{
    g_autoptr(virJSONValue) addr = NULL;
    g_autoptr(virJSONValue) data = NULL;

    if (virJSONValueObjectAdd(&data, "s:path", path, NULL) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&addr,
                              "s:type", "unix",
                              "a:data", &data, NULL) < 0)
        return NULL;

    return g_steal_pointer(&addr);
}


static virJSONValue *
qemuMonitorJSONBuildFDSocketAddress(const char *fdname)
{
    g_autoptr(virJSONValue) addr = NULL;
    g_autoptr(virJSONValue) data = NULL;

    if (virJSONValueObjectAdd(&data, "s:str", fdname, NULL) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&addr,
                              "s:type", "fd",
                              "a:data", &data, NULL) < 0)
        return NULL;

    return g_steal_pointer(&addr);
}
int
qemuMonitorJSONNBDServerStart(qemuMonitor *mon,
                              const virStorageNetHostDef *server,
                              const char *tls_alias)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) addr = NULL;
    g_autofree char *port_str = NULL;

    switch (server->transport) {
    case VIR_STORAGE_NET_HOST_TRANS_TCP:
        port_str = g_strdup_printf("%u", server->port);
        addr = qemuMonitorJSONBuildInetSocketAddress(server->name, port_str);
        break;
    case VIR_STORAGE_NET_HOST_TRANS_UNIX:
        addr = qemuMonitorJSONBuildUnixSocketAddress(server->socket);
        break;
    case VIR_STORAGE_NET_HOST_TRANS_RDMA:
    case VIR_STORAGE_NET_HOST_TRANS_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid server address"));
        return -1;
    }
    if (!addr)
        return -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-start",
                                           "a:addr", &addr,
                                           "S:tls-creds", tls_alias,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int
qemuMonitorJSONNBDServerAdd(qemuMonitor *mon,
                            const char *deviceID,
                            const char *export,
                            bool writable,
                            const char *bitmap)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    /* Note: bitmap must be NULL if QEMU_CAPS_NBD_BITMAP is lacking */
    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-add",
                                           "s:device", deviceID,
                                           "S:name", export,
                                           "b:writable", writable,
                                           "S:bitmap", bitmap,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

int
qemuMonitorJSONNBDServerStop(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-stop",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockExportAdd(qemuMonitor *mon,
                              virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("block-export-add", props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


static int
qemuMonitorJSONGetStringArray(qemuMonitor *mon,
                              const char *qmpCmd,
                              char ***array)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    *array = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand(qmpCmd, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound"))
        return 0;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    if (!(*array = virJSONValueArrayToStringList(data)))
        return -1;

    return 0;
}

int qemuMonitorJSONGetTPMModels(qemuMonitor *mon,
                                char ***tpmmodels)
{
    return qemuMonitorJSONGetStringArray(mon, "query-tpm-models", tpmmodels);
}


int qemuMonitorJSONGetTPMTypes(qemuMonitor *mon,
                               char ***tpmtypes)
{
    return qemuMonitorJSONGetStringArray(mon, "query-tpm-types", tpmtypes);
}


static virJSONValue *
qemuMonitorJSONAttachCharDevGetProps(const char *chrID,
                                     const virDomainChrSourceDef *chr)
{
    qemuDomainChrSourcePrivate *chrSourcePriv = QEMU_DOMAIN_CHR_SOURCE_PRIVATE(chr);
    g_autoptr(virJSONValue) props = NULL;
    g_autoptr(virJSONValue) backend = NULL;
    g_autoptr(virJSONValue) backendData = virJSONValueNewObject();
    const char *backendType = NULL;

    switch ((virDomainChrType)chr->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_PTY:
        backendType = virDomainChrTypeToString(chr->type);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE: {
        const char *path = chr->data.file.path;
        virTristateSwitch append = chr->data.file.append;
        backendType = "file";

        if (chrSourcePriv->sourcefd) {
            path = qemuFDPassGetPath(chrSourcePriv->sourcefd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        if (virJSONValueObjectAdd(&backendData,
                                  "s:out", path,
                                  "T:append", append,
                                  NULL) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        if (STRPREFIX(chrID, "parallel"))
            backendType = "parallel";
        else
            backendType = "serial";

        if (virJSONValueObjectAdd(&backendData,
                                  "s:device", chr->data.file.path,
                                  NULL) < 0)
            return NULL;

        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
    case VIR_DOMAIN_CHR_TYPE_TCP: {
        const char *tlsalias = NULL;
        g_autoptr(virJSONValue) addr = NULL;
        virTristateBool waitval = VIR_TRISTATE_BOOL_ABSENT;
        virTristateBool telnet = VIR_TRISTATE_BOOL_ABSENT;
        bool server = false;
        int reconnect = -1;

        backendType = "socket";

        if (chr->type == VIR_DOMAIN_CHR_TYPE_TCP) {
            telnet = virTristateBoolFromBool(chr->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET);

            if (chr->data.tcp.listen) {
                server = true;
                waitval = VIR_TRISTATE_BOOL_NO;
            }

            tlsalias = chrSourcePriv->tlsCredsAlias;

            if (!(addr = qemuMonitorJSONBuildInetSocketAddress(chr->data.tcp.host,
                                                               chr->data.tcp.service)))
                return NULL;

            if (chr->data.tcp.reconnect.enabled == VIR_TRISTATE_BOOL_YES)
                reconnect = chr->data.tcp.reconnect.timeout;
            else if (chr->data.tcp.reconnect.enabled == VIR_TRISTATE_BOOL_NO)
                reconnect = 0;
        } else {
            if (chr->data.nix.listen) {
                server = true;
                waitval = VIR_TRISTATE_BOOL_NO;
            }

            if (chrSourcePriv->directfd) {
                if (!(addr = qemuMonitorJSONBuildFDSocketAddress(qemuFDPassDirectGetPath(chrSourcePriv->directfd))))
                    return NULL;
            } else {
                if (!(addr = qemuMonitorJSONBuildUnixSocketAddress(chr->data.nix.path)))
                    return NULL;

                if (chr->data.nix.reconnect.enabled == VIR_TRISTATE_BOOL_YES)
                    reconnect = chr->data.nix.reconnect.timeout;
                else if (chr->data.nix.reconnect.enabled == VIR_TRISTATE_BOOL_NO)
                    reconnect = 0;
            }
        }

        if (virJSONValueObjectAdd(&backendData,
                                  "a:addr", &addr,
                                  "T:wait", waitval,
                                  "T:telnet", telnet,
                                  "b:server", server,
                                  "S:tls-creds", tlsalias,
                                  "k:reconnect", reconnect,
                                  NULL) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        g_autoptr(virJSONValue) local = NULL;
        g_autoptr(virJSONValue) remote = NULL;

        backendType = "udp";

        if (!(remote = qemuMonitorJSONBuildInetSocketAddress(NULLSTR_EMPTY(chr->data.udp.connectHost),
                                                             chr->data.udp.connectService)))
            return NULL;

        if (chr->data.udp.bindHost || chr->data.udp.bindService) {
            if (!(local = qemuMonitorJSONBuildInetSocketAddress(NULLSTR_EMPTY(chr->data.udp.bindHost),
                                                                NULLSTR_EMPTY(chr->data.udp.bindService))))
                return NULL;
        }

        if (virJSONValueObjectAdd(&backendData,
                                  "a:remote", &remote,
                                  "A:local", &local,
                                  NULL) < 0)
            return NULL;
    }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        backendType = "spicevmc";

        if (virJSONValueObjectAdd(&backendData,
                                  "s:type", virDomainChrSpicevmcTypeToString(chr->data.spicevmc),
                                  NULL) < 0)
            return NULL;

        break;

    case VIR_DOMAIN_CHR_TYPE_QEMU_VDAGENT: {
        virTristateBool mouse = VIR_TRISTATE_BOOL_ABSENT;
        switch (chr->data.qemuVdagent.mouse) {
            case VIR_DOMAIN_MOUSE_MODE_CLIENT:
                mouse = VIR_TRISTATE_BOOL_YES;
                break;
            case VIR_DOMAIN_MOUSE_MODE_SERVER:
                mouse = VIR_TRISTATE_BOOL_NO;
                break;
            case VIR_DOMAIN_MOUSE_MODE_DEFAULT:
                break;
            case VIR_DOMAIN_MOUSE_MODE_LAST:
            default:
                virReportEnumRangeError(virDomainMouseMode,
                                        chr->data.qemuVdagent.mouse);
                return NULL;
        }
        backendType = "qemu-vdagent";

        if (virJSONValueObjectAdd(&backendData,
                                  "T:clipboard", chr->data.qemuVdagent.clipboard,
                                  "T:mouse", mouse,
                                  NULL) < 0)
            return NULL;
        break;
    }

    case VIR_DOMAIN_CHR_TYPE_DBUS:
        backendType = "dbus";

        if (virJSONValueObjectAdd(&backendData,
                                  "s:name", chr->data.dbus.channel,
                                  NULL) < 0)
            return NULL;

        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Hotplug unsupported for char device type '%1$s'"),
                       virDomainChrTypeToString(chr->type));
        return NULL;

    case VIR_DOMAIN_CHR_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainChrType, chr->type);
        return NULL;
    }

    if (chr->logfile) {
        const char *path = chr->logfile;
        virTristateSwitch append = chr->logappend;

        if (chrSourcePriv->logfd) {
            path = qemuFDPassGetPath(chrSourcePriv->logfd);
            append = VIR_TRISTATE_SWITCH_ON;
        }

        if (virJSONValueObjectAdd(&backendData,
                                  "s:logfile", path,
                                  "T:logappend", append,
                                  NULL) < 0)
            return NULL;
    }

    if (virJSONValueObjectAdd(&backend,
                              "s:type", backendType,
                              "A:data", &backendData,
                              NULL) < 0)
        return NULL;

    if (virJSONValueObjectAdd(&props,
                              "s:id", chrID,
                              "a:backend", &backend,
                              NULL) < 0)
        return NULL;

    return g_steal_pointer(&props);
}


int
qemuMonitorJSONAttachCharDev(qemuMonitor *mon,
                             const char *chrID,
                             virDomainChrSourceDef *chr)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) props = NULL;

    if (!(props = qemuMonitorJSONAttachCharDevGetProps(chrID, chr)))
        return -1;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("chardev-add", &props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
        virJSONValue *data;

        if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
            return -1;

        if (!(chr->data.file.path = g_strdup(virJSONValueObjectGetString(data, "pty")))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("chardev-add reply was missing pty path"));
            return -1;
        }
    } else {
        if (qemuMonitorJSONCheckError(cmd, reply) < 0)
            return -1;
    }

    return 0;
}

int
qemuMonitorJSONDetachCharDev(qemuMonitor *mon,
                             const char *chrID)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("chardev-remove",
                                           "s:id", chrID,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONGetDeviceAliases(qemuMonitor *mon,
                                char ***aliases)
{
    qemuMonitorJSONListPath **paths = NULL;
    char **alias;
    int ret = -1;
    size_t i;
    int n;

    *aliases = NULL;

    n = qemuMonitorJSONGetObjectListPaths(mon, "/machine/peripheral", &paths);
    if (n < 0)
        return -1;

    *aliases = g_new0(char *, n + 1);

    alias = *aliases;
    for (i = 0; i < n; i++) {
        if (STRPREFIX(paths[i]->type, "child<")) {
            *alias = g_steal_pointer(&paths[i]->name);
            alias++;
        }
    }

    ret = 0;

    for (i = 0; i < n; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    return ret;
}


static int
qemuMonitorJSONParseCPUx86FeatureWord(virJSONValue *data,
                                      virCPUx86CPUID *cpuid)
{
    const char *reg;
    unsigned long long eax_in;
    unsigned long long ecx_in = 0;
    unsigned long long features;

    memset(cpuid, 0, sizeof(*cpuid));

    if (!(reg = virJSONValueObjectGetString(data, "cpuid-register"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing cpuid-register in CPU data"));
        return -1;
    }
    if (virJSONValueObjectGetNumberUlong(data, "cpuid-input-eax", &eax_in) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing or invalid cpuid-input-eax in CPU data"));
        return -1;
    }
    ignore_value(virJSONValueObjectGetNumberUlong(data, "cpuid-input-ecx",
                                                  &ecx_in));
    if (virJSONValueObjectGetNumberUlong(data, "features", &features) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing or invalid features in CPU data"));
        return -1;
    }

    cpuid->eax_in = eax_in;
    cpuid->ecx_in = ecx_in;
    if (STREQ(reg, "EAX")) {
        cpuid->eax = features;
    } else if (STREQ(reg, "EBX")) {
        cpuid->ebx = features;
    } else if (STREQ(reg, "ECX")) {
        cpuid->ecx = features;
    } else if (STREQ(reg, "EDX")) {
        cpuid->edx = features;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown CPU register '%1$s'"), reg);
        return -1;
    }

    return 0;
}


static virCPUData *
qemuMonitorJSONParseCPUx86Features(virJSONValue *data)
{
    g_autoptr(virCPUData) cpudata = NULL;
    virCPUx86DataItem item = { 0 };
    size_t i;

    if (!(cpudata = virCPUDataNew(VIR_ARCH_X86_64)))
        return NULL;

    item.type = VIR_CPU_X86_DATA_CPUID;
    for (i = 0; i < virJSONValueArraySize(data); i++) {
        if (qemuMonitorJSONParseCPUx86FeatureWord(virJSONValueArrayGet(data, i),
                                                  &item.data.cpuid) < 0 ||
            virCPUx86DataAdd(cpudata, &item) < 0)
            return NULL;
    }

    return g_steal_pointer(&cpudata);
}


static int
qemuMonitorJSONGetCPUx86Data(qemuMonitor *mon,
                             const char *cpuQOMPath,
                             const char *property,
                             virCPUData **cpudata)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", cpuQOMPath,
                                           "s:property", property,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    if (!(*cpudata = qemuMonitorJSONParseCPUx86Features(data)))
        return -1;

    return 0;
}


/*
 * Returns -1 on error, 0 if QEMU does not support reporting CPUID features
 * of a guest CPU, and 1 if the feature is supported.
 */
static int
qemuMonitorJSONCheckCPUx86(qemuMonitor *mon,
                           const char *cpuQOMPath)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    size_t i;
    size_t n;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list",
                                           "s:path", cpuQOMPath,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if ((data = virJSONValueObjectGet(reply, "error"))) {
        const char *klass = virJSONValueObjectGetString(data, "class");
        if (STREQ_NULLABLE(klass, "DeviceNotFound") ||
            STREQ_NULLABLE(klass, "CommandNotFound")) {
            return 0;
        }
    }

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    n = virJSONValueArraySize(data);

    for (i = 0; i < n; i++) {
        virJSONValue *element = virJSONValueArrayGet(data, i);
        if (STREQ_NULLABLE(virJSONValueObjectGetString(element, "name"),
                           "feature-words"))
            return 1;
    }

    return 0;
}


/**
 * qemuMonitorJSONGetGuestCPUx86:
 * @mon: Pointer to the monitor
 * @cpuQOMPath: QOM path of a CPU to probe
 * @data: returns the cpu data of the guest
 * @disabled: returns the CPU data for features which were disabled by QEMU
 *
 * Retrieve the definition of the guest CPU from a running qemu instance.
 *
 * Returns 0 on success, -2 if guest doesn't support this feature,
 * -1 on other errors.
 */
int
qemuMonitorJSONGetGuestCPUx86(qemuMonitor *mon,
                              const char *cpuQOMPath,
                              virCPUData **data,
                              virCPUData **disabled)
{
    g_autoptr(virCPUData) cpuEnabled = NULL;
    g_autoptr(virCPUData) cpuDisabled = NULL;
    int rc;

    if ((rc = qemuMonitorJSONCheckCPUx86(mon, cpuQOMPath)) < 0)
        return -1;
    else if (!rc)
        return -2;

    if (qemuMonitorJSONGetCPUx86Data(mon, cpuQOMPath, "feature-words",
                                     &cpuEnabled) < 0)
        return -1;

    if (disabled &&
        qemuMonitorJSONGetCPUx86Data(mon, cpuQOMPath, "filtered-features",
                                     &cpuDisabled) < 0)
        return -1;

    *data = g_steal_pointer(&cpuEnabled);
    if (disabled)
        *disabled = g_steal_pointer(&cpuDisabled);
    return 0;
}


static int
qemuMonitorJSONGetCPUProperties(qemuMonitor *mon,
                                const char *cpuQOMPath,
                                char ***props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    *props = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list",
                                           "s:path", cpuQOMPath,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "DeviceNotFound"))
        return 0;

    return qemuMonitorJSONParsePropsList(cmd, reply, "bool", props);
}


static int
qemuMonitorJSONGetCPUData(qemuMonitor *mon,
                          const char *cpuQOMPath,
                          qemuMonitorCPUFeatureTranslationCallback translate,
                          virCPUData *data)
{
    qemuMonitorJSONObjectProperty prop = { .type = QEMU_MONITOR_OBJECT_PROPERTY_BOOLEAN };
    g_auto(GStrv) props = NULL;
    char **p;

    if (qemuMonitorJSONGetCPUProperties(mon, cpuQOMPath, &props) < 0)
        return -1;

    for (p = props; p && *p; p++) {
        const char *name = *p;

        if (qemuMonitorJSONGetObjectProperty(mon, cpuQOMPath, name, &prop) < 0)
            return -1;

        if (!prop.val.b)
            continue;

        if (translate)
            name = translate(data->arch, name);

        if (virCPUDataAddFeature(data, name) < 0)
            return -1;
    }

    return 0;
}


static int
qemuMonitorJSONGetCPUDataDisabled(qemuMonitor *mon,
                                  const char *cpuQOMPath,
                                  qemuMonitorCPUFeatureTranslationCallback translate,
                                  virCPUData *data)
{
    g_auto(GStrv) props = NULL;
    char **p;

    if (qemuMonitorJSONGetStringListProperty(mon, cpuQOMPath,
                                             "unavailable-features", &props) < 0)
        return -1;

    for (p = props; p && *p; p++) {
        const char *name = *p;

        if (translate)
            name = translate(data->arch, name);

        if (virCPUDataAddFeature(data, name) < 0)
            return -1;
    }

    return 0;
}


/**
 * qemuMonitorJSONGetGuestCPU:
 * @mon: Pointer to the monitor
 * @arch: CPU architecture
 * @cpuQOMPath: QOM path of a CPU to probe
 * @translate: callback for translating CPU feature names from QEMU to libvirt
 * @opaque: data for @translate callback
 * @enabled: returns the CPU data for all enabled features
 * @disabled: returns the CPU data for features which we asked for
 *      (either explicitly or via a named CPU model) but QEMU disabled them
 *
 * Retrieve the definition of the guest CPU from a running QEMU instance.
 *
 * Returns 0 on success, -1 on error.
 */
int
qemuMonitorJSONGetGuestCPU(qemuMonitor *mon,
                           virArch arch,
                           const char *cpuQOMPath,
                           qemuMonitorCPUFeatureTranslationCallback translate,
                           virCPUData **enabled,
                           virCPUData **disabled)
{
    g_autoptr(virCPUData) cpuEnabled = NULL;
    g_autoptr(virCPUData) cpuDisabled = NULL;

    if (!(cpuEnabled = virCPUDataNew(arch)) ||
        !(cpuDisabled = virCPUDataNew(arch)))
        return -1;

    if (qemuMonitorJSONGetCPUData(mon, cpuQOMPath, translate, cpuEnabled) < 0)
        return -1;

    if (disabled &&
        qemuMonitorJSONGetCPUDataDisabled(mon, cpuQOMPath, translate, cpuDisabled) < 0)
        return -1;

    *enabled = g_steal_pointer(&cpuEnabled);
    if (disabled)
        *disabled = g_steal_pointer(&cpuDisabled);

    return 0;
}


int
qemuMonitorJSONRTCResetReinjection(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("rtc-reset-reinjection",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

/**
 * Query and parse returned array of data such as:
 *
 *  {u'return': [{u'id': u'iothread1', u'thread-id': 30992}, \
 *               {u'id': u'iothread2', u'thread-id': 30993}]}
 */
int
qemuMonitorJSONGetIOThreads(qemuMonitor *mon,
                            qemuMonitorIOThreadInfo ***iothreads,
                            int *niothreads)
{
    int ret = -1;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;
    qemuMonitorIOThreadInfo **infolist = NULL;
    size_t n = 0;
    size_t i;

    *iothreads = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-iothreads", NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        goto cleanup;

    n = virJSONValueArraySize(data);

    /* null-terminated list */
    infolist = g_new0(qemuMonitorIOThreadInfo *, n + 1);

    for (i = 0; i < n; i++) {
        virJSONValue *child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorIOThreadInfo *info;

        if (!(tmp = virJSONValueObjectGetString(child, "id"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-iothreads reply data was missing 'id'"));
            goto cleanup;
        }

        if (!STRPREFIX(tmp, "iothread"))
            continue;

        info = g_new0(qemuMonitorIOThreadInfo, 1);

        infolist[i] = info;

        if (virStrToLong_ui(tmp + strlen("iothread"),
                            NULL, 10, &info->iothread_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to find iothread id for '%1$s'"),
                           tmp);
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(child, "thread-id",
                                           &info->thread_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-iothreads reply has malformed 'thread-id' data"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(child, "poll-max-ns",
                                             &info->poll_max_ns) == 0 &&
            virJSONValueObjectGetNumberUlong(child, "poll-grow",
                                             &info->poll_grow) == 0 &&
            virJSONValueObjectGetNumberUlong(child, "poll-shrink",
                                             &info->poll_shrink) == 0)
            info->poll_valid = true;
    }

    *niothreads = n;
    *iothreads = g_steal_pointer(&infolist);
    ret = 0;

 cleanup:
    if (infolist) {
        for (i = 0; i < n; i++)
            VIR_FREE(infolist[i]);
        VIR_FREE(infolist);
    }
    return ret;
}


int
qemuMonitorJSONSetIOThread(qemuMonitor *mon,
                           qemuMonitorIOThreadInfo *iothreadInfo)
{
    g_autofree char *path = NULL;
    qemuMonitorJSONObjectProperty prop;
    bool setMaxFirst = false;

    path = g_strdup_printf("/objects/iothread%u", iothreadInfo->iothread_id);

#define VIR_IOTHREAD_SET_PROP_UL(propName, propVal) \
    if (iothreadInfo->set_##propVal) { \
        memset(&prop, 0, sizeof(prop)); \
        prop.type = QEMU_MONITOR_OBJECT_PROPERTY_ULONG; \
        prop.val.ul = iothreadInfo->propVal; \
        if (qemuMonitorJSONSetObjectProperty(mon, path, propName, &prop) < 0) \
            return -1; \
    }

    VIR_IOTHREAD_SET_PROP_UL("poll-max-ns", poll_max_ns);
    VIR_IOTHREAD_SET_PROP_UL("poll-grow", poll_grow);
    VIR_IOTHREAD_SET_PROP_UL("poll-shrink", poll_shrink);

#undef VIR_IOTHREAD_SET_PROP_UL

    if (iothreadInfo->set_thread_pool_min &&
        iothreadInfo->set_thread_pool_max) {
        int curr_max = -1;

        /* By default, the minimum is set first, followed by the maximum. But
         * if the current maximum is below the minimum we want to set we need
         * to set the maximum first. Otherwise would get an error because we
         * would be attempting to shift minimum above maximum. */
        prop.type = QEMU_MONITOR_OBJECT_PROPERTY_INT;
        if (qemuMonitorJSONGetObjectProperty(mon, path,
                                             "thread-pool-max", &prop) < 0)
            return -1;
        curr_max = prop.val.iv;

        if (curr_max < iothreadInfo->thread_pool_min)
            setMaxFirst = true;
    }

#define VIR_IOTHREAD_SET_PROP_INT(propName, propVal) \
    if (iothreadInfo->set_##propVal) { \
        memset(&prop, 0, sizeof(prop)); \
        prop.type = QEMU_MONITOR_OBJECT_PROPERTY_INT; \
        prop.val.iv = iothreadInfo->propVal; \
        if (qemuMonitorJSONSetObjectProperty(mon, path, propName, &prop) < 0) \
            return -1; \
    }

    if (setMaxFirst) {
        VIR_IOTHREAD_SET_PROP_INT("thread-pool-max", thread_pool_max);
        VIR_IOTHREAD_SET_PROP_INT("thread-pool-min", thread_pool_min);
    } else {
        VIR_IOTHREAD_SET_PROP_INT("thread-pool-min", thread_pool_min);
        VIR_IOTHREAD_SET_PROP_INT("thread-pool-max", thread_pool_max);
    }

#undef VIR_IOTHREAD_SET_PROP_INT

    return 0;
}


int
qemuMonitorJSONGetMemoryDeviceInfo(qemuMonitor *mon,
                                   GHashTable *info)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;
    size_t i;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-memory-devices", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(data); i++) {
        virJSONValue *elem = virJSONValueArrayGet(data, i);
        g_autofree qemuMonitorMemoryDeviceInfo *meminfo = NULL;
        virJSONValue *dimminfo;
        const char *devalias = NULL;
        const char *modelStr;
        int model;

        if (!(modelStr = virJSONValueObjectGetString(elem, "type"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-memory-devices reply data doesn't contain enum type discriminator"));
            return -1;
        }

        if ((model = virDomainMemoryModelTypeFromString(modelStr)) < 0) {
            VIR_WARN("Unknown memory model: %s", modelStr);
            continue;
        }

        if (!(dimminfo = virJSONValueObjectGetObject(elem, "data"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-memory-devices reply data doesn't contain enum data"));
            return -1;
        }

        meminfo = g_new0(qemuMonitorMemoryDeviceInfo, 1);

        switch ((virDomainMemoryModel) model) {
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
            /* While 'id' attribute is marked as optional in QEMU's QAPI
             * specification, Libvirt always sets it. Thus we can fail if not
             * present. */
            if (!(devalias = virJSONValueObjectGetString(dimminfo, "id"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("dimm memory info data is missing 'id'"));
                return -1;
            }

            if (model == VIR_DOMAIN_MEMORY_MODEL_DIMM ||
                model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM) {
                if (virJSONValueObjectGetNumberUlong(dimminfo, "addr",
                                                     &meminfo->address) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing addr in dimm memory info"));
                    return -1;
                }

                if (virJSONValueObjectGetNumberUint(dimminfo, "slot",
                                                    &meminfo->slot) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing slot in dimm memory info"));
                    return -1;
                }

                if (virJSONValueObjectGetBoolean(dimminfo, "hotplugged",
                                                 &meminfo->hotplugged) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing hotplugged in dimm memory info"));
                    return -1;

                }

                if (virJSONValueObjectGetBoolean(dimminfo, "hotpluggable",
                                                 &meminfo->hotpluggable) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing hotpluggable in dimm memory info"));
                    return -1;

                }
            } else if (model == VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM ||
                       model == VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM) {
                if (virJSONValueObjectGetNumberUlong(dimminfo, "size",
                                                     &meminfo->size) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing size in virtio memory info"));
                    return -1;
                }

                if (virJSONValueObjectGetNumberUlong(dimminfo, "memaddr",
                                                     &meminfo->address) < 0) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("malformed/missing memaddr in virtio memory info"));
                    return -1;
                }
            }
            break;

        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
            if (!(devalias = virJSONValueObjectGetString(dimminfo, "memdev"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("sgx-epc memory info data is missing 'memdev'"));
                return -1;
            }
            if (virJSONValueObjectGetNumberUlong(dimminfo, "memaddr",
                                                 &meminfo->address) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing memaddr in sgx-epc memory info"));
                return -1;
            }

            if (virJSONValueObjectGetNumberUlong(dimminfo, "size",
                                                 &meminfo->size) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing size in sgx-epc memory info"));
                return -1;
            }
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            /* type not handled yet */
            continue;
        }

        if (virHashAddEntry(info, devalias, meminfo) < 0)
            return -1;

        meminfo = NULL;
    }

    return 0;
}


/**
 * Search for a QOM object link by alias and name.
 *
 * For @alias and @name, this function tries to find QOM object named @name
 * with id @alias in /machine/peripheral.
 *
 * Returns:
 *   0  - Found
 *  -1  - Error - bail out
 *  -2  - Not found
 */
static int
qemuMonitorJSONFindObjectPathByAlias(qemuMonitor *mon,
                                     const char *name,
                                     const char *alias,
                                     char **path)
{
    qemuMonitorJSONListPath **paths = NULL;
    g_autofree char *child = NULL;
    int npaths;
    int ret = -1;
    size_t i;

    npaths = qemuMonitorJSONGetObjectListPaths(mon, "/machine/peripheral", &paths);
    if (npaths < 0)
        return -1;

    child = g_strdup_printf("child<%s>", name);

    for (i = 0; i < npaths; i++) {
        if (STREQ(paths[i]->name, alias) && STREQ(paths[i]->type, child)) {
            *path = g_strdup_printf("/machine/peripheral/%s", alias);

            ret = 0;
            goto cleanup;
        }
    }

    ret = -2;

 cleanup:
    for (i = 0; i < npaths; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    return ret;
}


/**
 * Recursively search for a QOM object link only by name.
 *
 * For @name, this function finds the first QOM object
 * named @name, recursively going through all the "child<>"
 * entries, starting from @curpath.
 *
 * Returns:
 *   0  - Found
 *  -1  - Error - bail out
 *  -2  - Not found
 */
static int
qemuMonitorJSONFindObjectPathByName(qemuMonitor *mon,
                                    const char *curpath,
                                    const char *name,
                                    char **path)
{
    ssize_t i, npaths = 0;
    int ret = -2;
    qemuMonitorJSONListPath **paths = NULL;

    VIR_DEBUG("Searching for '%s' Object Path starting at '%s'", name, curpath);

    npaths = qemuMonitorJSONGetObjectListPaths(mon, curpath, &paths);
    if (npaths < 0)
        goto cleanup;

    for (i = 0; i < npaths && ret == -2; i++) {

        if (STREQ_NULLABLE(paths[i]->type, name)) {
            VIR_DEBUG("Path to '%s' is '%s/%s'", name, curpath, paths[i]->name);
            ret = 0;
            *path = g_strdup_printf("%s/%s", curpath, paths[i]->name);
            goto cleanup;
        }

        /* Type entries that begin with "child<" are a branch that can be
         * traversed looking for more entries
         */
        if (paths[i]->type && STRPREFIX(paths[i]->type, "child<")) {
            g_autofree char *nextpath = g_strdup_printf("%s/%s", curpath, paths[i]->name);

            ret = qemuMonitorJSONFindObjectPathByName(mon, nextpath, name, path);
        }
    }

 cleanup:
    for (i = 0; i < npaths; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    return ret;
}


/**
 * Recursively search for a QOM object link.
 *
 * For @name and @alias, this function finds the first QOM object.
 * The search is done at first by @alias and @name and if nothing was found
 * it continues recursively only with @name.
 *
 * Returns:
 *   0  - Found
 *  -1  - Error
 *  -2  - Not found
 */
int
qemuMonitorJSONFindLinkPath(qemuMonitor *mon,
                            const char *name,
                            const char *alias,
                            char **path)
{
    g_autofree char *linkname = NULL;
    int ret = -1;

    if (alias) {
        ret = qemuMonitorJSONFindObjectPathByAlias(mon, name, alias, path);
        if (ret == -1 || ret == 0)
            return ret;
    }

    linkname = g_strdup_printf("link<%s>", name);

    ret = qemuMonitorJSONFindObjectPathByName(mon, "/", linkname, path);
    return ret;
}


int
qemuMonitorJSONMigrateIncoming(qemuMonitor *mon,
                               const char *uri)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-incoming",
                                           "s:uri", uri,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    return qemuMonitorJSONCheckError(cmd, reply);
}


int
qemuMonitorJSONMigrateStartPostCopy(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-start-postcopy", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    return qemuMonitorJSONCheckError(cmd, reply);
}


int
qemuMonitorJSONMigrateContinue(qemuMonitor *mon,
                               qemuMonitorMigrationStatus status)
{
    const char *statusStr = qemuMonitorMigrationStatusTypeToString(status);
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-continue",
                                           "s:state", statusStr,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    return qemuMonitorJSONCheckError(cmd, reply);
}


int
qemuMonitorJSONGetRTCTime(qemuMonitor *mon,
                          struct tm *tm)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", "/machine",
                                           "s:property", "rtc-time",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (virJSONValueObjectGetNumberInt(data, "tm_year", &tm->tm_year) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_mon", &tm->tm_mon) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_mday", &tm->tm_mday) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_hour", &tm->tm_hour) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_min", &tm->tm_min) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_sec", &tm->tm_sec) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu returned malformed time"));
        return -1;
    }

    return 0;
}


void
qemuMonitorQueryHotpluggableCpusFree(struct qemuMonitorQueryHotpluggableCpusEntry *entries,
                                     size_t nentries)
{
    struct qemuMonitorQueryHotpluggableCpusEntry *entry;
    size_t i;

    if (!entries)
        return;

    for (i = 0; i < nentries; i++) {
        entry = entries + i;

        g_free(entry->type);
        g_free(entry->qom_path);
        g_free(entry->alias);
        virJSONValueFree(entry->props);
    }

    g_free(entries);
}


/**
 * [{
 *    "props": {
 *      "core-id": 0,
 *      "thread-id": 0,
 *      "socket-id": 0
 *    },
 *    "vcpus-count": 1,
 *    "qom-path": "/machine/unattached/device[0]",
 *    "type": "qemu64-x86_64-cpu"
 *  },
 *  {...}
 * ]
 */
static int
qemuMonitorJSONProcessHotpluggableCpusReply(virJSONValue *vcpu,
                                            struct qemuMonitorQueryHotpluggableCpusEntry *entry)
{
    virJSONValue *props;
    const char *tmp;

    if (!(tmp = virJSONValueObjectGetString(vcpu, "type"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus didn't return device type"));
        return -1;
    }

    entry->type = g_strdup(tmp);

    if (virJSONValueObjectGetNumberUint(vcpu, "vcpus-count", &entry->vcpus) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus didn't return vcpus-count"));
        return -1;
    }

    if (!(props = virJSONValueObjectGetObject(vcpu, "props"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus didn't return device props"));
        return -1;
    }

    if (!(entry->props = virJSONValueCopy(props)))
        return -1;

    entry->node_id = -1;
    entry->socket_id = -1;
    entry->die_id = -1;
    entry->core_id = -1;
    entry->thread_id = -1;

    ignore_value(virJSONValueObjectGetNumberInt(props, "node-id", &entry->node_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "socket-id", &entry->socket_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "die-id", &entry->die_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "core-id", &entry->core_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "thread-id", &entry->thread_id));

    if (entry->node_id == -1 && entry->socket_id == -1 &&
        entry->core_id == -1 && entry->thread_id == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus entry doesn't report topology information"));
        return -1;
    }

    /* qom path is not present unless the vCPU is online */
    if ((tmp = virJSONValueObjectGetString(vcpu, "qom-path"))) {
        entry->qom_path = g_strdup(tmp);

        /* alias is the part after last slash having a "vcpu" prefix */
        if ((tmp = strrchr(tmp, '/')) && STRPREFIX(tmp + 1, "vcpu"))
            entry->alias = g_strdup(tmp + 1);
    }

    return 0;
}


static int
qemuMonitorQueryHotpluggableCpusEntrySort(const void *p1,
                                          const void *p2)
{
    const struct qemuMonitorQueryHotpluggableCpusEntry *a = p1;
    const struct qemuMonitorQueryHotpluggableCpusEntry *b = p2;

    if (a->socket_id != b->socket_id)
        return a->socket_id - b->socket_id;

    if (a->die_id != b->die_id)
        return a->die_id - b->die_id;

    if (a->core_id != b->core_id)
        return a->core_id - b->core_id;

    return a->thread_id - b->thread_id;
}


int
qemuMonitorJSONGetHotpluggableCPUs(qemuMonitor *mon,
                                   struct qemuMonitorQueryHotpluggableCpusEntry **entries,
                                   size_t *nentries)
{
    struct qemuMonitorQueryHotpluggableCpusEntry *info = NULL;
    size_t ninfo = 0;
    int ret = -1;
    size_t i;
    virJSONValue *data;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *vcpu;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-hotpluggable-cpus", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        goto cleanup;

    ninfo = virJSONValueArraySize(data);

    info = g_new0(struct qemuMonitorQueryHotpluggableCpusEntry, ninfo);

    for (i = 0; i < ninfo; i++) {
        vcpu = virJSONValueArrayGet(data, i);

        if (qemuMonitorJSONProcessHotpluggableCpusReply(vcpu, info + i) < 0)
            goto cleanup;
    }

    qsort(info, ninfo, sizeof(*info), qemuMonitorQueryHotpluggableCpusEntrySort);

    *entries = g_steal_pointer(&info);
    *nentries = ninfo;
    ret = 0;

 cleanup:
    qemuMonitorQueryHotpluggableCpusFree(info, ninfo);
    return ret;
}


virJSONValue *
qemuMonitorJSONQueryQMPSchema(qemuMonitor *mon)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-qmp-schema", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return NULL;

    return virJSONValueObjectStealArray(reply, "return");
}


int
qemuMonitorJSONSetBlockThreshold(qemuMonitor *mon,
                                 const char *nodename,
                                 unsigned long long threshold)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-set-write-threshold",
                                           "s:node-name", nodename,
                                           "U:write-threshold", threshold,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONSetWatchdogAction(qemuMonitor *mon,
                                 const char *action)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("watchdog-set-action",
                                           "s:action", action,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevCreate(qemuMonitor *mon,
                              const char *jobname,
                              virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("blockdev-create",
                                     "s:job-id", jobname,
                                     "a:options", props,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevAdd(qemuMonitor *mon,
                           virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("blockdev-add", props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevReopen(qemuMonitor *mon,
                              virJSONValue **props)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommandInternal("blockdev-reopen", props)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevDel(qemuMonitor *mon,
                           const char *nodename)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("blockdev-del",
                                           "s:node-name", nodename,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevTrayOpen(qemuMonitor *mon,
                                const char *id,
                                bool force)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("blockdev-open-tray",
                                           "s:id", id,
                                           "b:force", force, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevTrayClose(qemuMonitor *mon,
                                 const char *id)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("blockdev-close-tray",
                                           "s:id", id, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevMediumRemove(qemuMonitor *mon,
                                    const char *id)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("blockdev-remove-medium",
                                           "s:id", id, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONBlockdevMediumInsert(qemuMonitor *mon,
                                    const char *id,
                                    const char *nodename)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("blockdev-insert-medium",
                                           "s:id", id,
                                           "s:node-name", nodename,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/**
 * The function is used to retrieve the measurement of a SEV guest.
 * The measurement is signature of the memory contents that was encrypted
 * through the SEV launch flow.
 *
 * A example JSON output:
 *
 * { "execute" : "query-sev-launch-measure" }
 * { "return" : { "data" : "4l8LXeNlSPUDlXPJG5966/8%YZ" } }
 */
char *
qemuMonitorJSONGetSEVMeasurement(qemuMonitor *mon)
{
    const char *tmp;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-sev-launch-measure", NULL)))
         return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return NULL;

    if (!(tmp = virJSONValueObjectGetString(data, "data")))
        return NULL;

    return g_strdup(tmp);
}


/**
 * Retrieve info about the SEV setup, returning those fields that
 * are required to do a launch attestation, as per
 *
 * HMAC(0x04 || API_MAJOR || API_MINOR || BUILD || GCTX.POLICY || GCTX.LD || MNONCE; GCTX.TIK)
 *
 * specified in section 6.5.1 of AMD Secure Encrypted
 * Virtualization API.
 *
 *  { "execute": "query-sev" }
 *  { "return": { "enabled": true, "api-major" : 0, "api-minor" : 0,
 *                "build-id" : 0, "policy" : 0, "state" : "running",
 *                "handle" : 1 } }
 */
int
qemuMonitorJSONGetSEVInfo(qemuMonitor *mon,
                          unsigned int *apiMajor,
                          unsigned int *apiMinor,
                          unsigned int *buildID,
                          unsigned int *policy)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-sev", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_OBJECT)))
        return -1;

    if (virJSONValueObjectGetNumberUint(data, "api-major", apiMajor) < 0 ||
        virJSONValueObjectGetNumberUint(data, "api-minor", apiMinor) < 0 ||
        virJSONValueObjectGetNumberUint(data, "build-id", buildID) < 0 ||
        virJSONValueObjectGetNumberUint(data, "policy", policy) < 0)
        return -1;

    return 0;
}


/**
 * Set a launch secret in guest memory
 *
 * Example JSON:
 *
 * { "execute" : "sev-inject-launch-secret",
 *   "data": { "packet-header": "str", "secret": "str", "gpa": "uint64" } }
 *
 * The guest physical address (gpa) parameter is optional
 */
int
qemuMonitorJSONSetLaunchSecurityState(qemuMonitor *mon,
                                      const char *secrethdr,
                                      const char *secret,
                                      unsigned long long setaddr,
                                      bool hasSetaddr)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (hasSetaddr) {
        cmd = qemuMonitorJSONMakeCommand("sev-inject-launch-secret",
                                         "s:packet-header", secrethdr,
                                         "s:secret", secret,
                                         "U:gpa", setaddr,
                                         NULL);
    } else {
        cmd = qemuMonitorJSONMakeCommand("sev-inject-launch-secret",
                                         "s:packet-header", secrethdr,
                                         "s:secret", secret,
                                         NULL);
    }
    if (cmd == NULL)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


/*
 * Example return data
 *
 * "return": [
 *   { "connected": true, "id": "pr-helper0" }
 *  ]
 */
static int
qemuMonitorJSONExtractPRManagerInfo(virJSONValue *reply,
                                    GHashTable *info)
{
    virJSONValue *data;
    size_t i;

    data = virJSONValueObjectGetArray(reply, "return");

    for (i = 0; i < virJSONValueArraySize(data); i++) {
        g_autofree qemuMonitorPRManagerInfo *entry = NULL;
        virJSONValue *prManager = virJSONValueArrayGet(data, i);
        const char *alias;

        if (!(alias = virJSONValueObjectGetString(prManager, "id")))
            goto malformed;

        entry = g_new0(qemuMonitorPRManagerInfo, 1);

        if (virJSONValueObjectGetBoolean(prManager,
                                         "connected",
                                         &entry->connected) < 0) {
            goto malformed;
        }

        if (virHashAddEntry(info, alias, entry) < 0)
            return -1;

        entry = NULL;
    }

    return 0;

 malformed:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed prManager reply"));
    return -1;
}


int
qemuMonitorJSONGetPRManagerInfo(qemuMonitor *mon,
                                GHashTable *info)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-pr-managers",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return -1;

    return qemuMonitorJSONExtractPRManagerInfo(reply, info);
}


static int
qemuMonitorJSONExtractCurrentMachineInfo(virJSONValue *reply,
                                         qemuMonitorCurrentMachineInfo *info)
{
    virJSONValue *data;

    data = virJSONValueObjectGetObject(reply, "return");
    if (!data)
        goto malformed;

    if (virJSONValueObjectGetBoolean(data, "wakeup-suspend-support",
                                     &info->wakeupSuspendSupport) < 0)
        goto malformed;

    return 0;

 malformed:
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("malformed qemu-current-machine reply"));
    return -1;
}


int
qemuMonitorJSONGetCurrentMachineInfo(qemuMonitor *mon,
                                     qemuMonitorCurrentMachineInfo *info)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-current-machine",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_OBJECT) < 0)
        return -1;

    return qemuMonitorJSONExtractCurrentMachineInfo(reply, info);
}


int
qemuMonitorJSONTransactionBitmapAdd(virJSONValue *actions,
                                    const char *node,
                                    const char *name,
                                    bool persistent,
                                    bool disabled,
                                    unsigned long long granularity)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "block-dirty-bitmap-add",
                                         "s:node", node,
                                         "s:name", name,
                                         "b:persistent", persistent,
                                         "b:disabled", disabled,
                                         "P:granularity", granularity,
                                         NULL);
}


int
qemuMonitorJSONTransactionBitmapRemove(virJSONValue *actions,
                                       const char *node,
                                       const char *name)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "block-dirty-bitmap-remove",
                                         "s:node", node,
                                         "s:name", name,
                                         NULL);
}


int
qemuMonitorJSONBitmapRemove(qemuMonitor *mon,
                            const char *node,
                            const char *name)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-dirty-bitmap-remove",
                                           "s:node", node,
                                           "s:name", name,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONTransactionBitmapEnable(virJSONValue *actions,
                                       const char *node,
                                       const char *name)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "block-dirty-bitmap-enable",
                                         "s:node", node,
                                         "s:name", name,
                                         NULL);
}


int
qemuMonitorJSONTransactionBitmapDisable(virJSONValue *actions,
                                        const char *node,
                                        const char *name)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "block-dirty-bitmap-disable",
                                         "s:node", node,
                                         "s:name", name,
                                         NULL);
}


int
qemuMonitorJSONTransactionBitmapMerge(virJSONValue *actions,
                                      const char *node,
                                      const char *target,
                                      virJSONValue **sources)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "block-dirty-bitmap-merge",
                                         "s:node", node,
                                         "s:target", target,
                                         "a:bitmaps", sources,
                                         NULL);
}


int
qemuMonitorJSONTransactionBitmapMergeSourceAddBitmap(virJSONValue *sources,
                                                     const char *sourcenode,
                                                     const char *sourcebitmap)
{
    g_autoptr(virJSONValue) sourceobj = NULL;

    if (virJSONValueObjectAdd(&sourceobj,
                              "s:node", sourcenode,
                              "s:name", sourcebitmap,
                              NULL) < 0)
        return -1;

    if (virJSONValueArrayAppend(sources, &sourceobj) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONTransactionSnapshotBlockdev(virJSONValue *actions,
                                           const char *node,
                                           const char *overlay)
{
    return qemuMonitorJSONTransactionAdd(actions,
                                         "blockdev-snapshot",
                                         "s:node", node,
                                         "s:overlay", overlay,
                                         NULL);
}

VIR_ENUM_DECL(qemuMonitorTransactionBackupSyncMode);
VIR_ENUM_IMPL(qemuMonitorTransactionBackupSyncMode,
              QEMU_MONITOR_TRANSACTION_BACKUP_SYNC_MODE_LAST,
              "none",
              "incremental",
              "full");

int
qemuMonitorJSONTransactionBackup(virJSONValue *actions,
                                 const char *device,
                                 const char *jobname,
                                 const char *target,
                                 const char *bitmap,
                                 qemuMonitorTransactionBackupSyncMode syncmode)
{
    const char *syncmodestr = qemuMonitorTransactionBackupSyncModeTypeToString(syncmode);

    return qemuMonitorJSONTransactionAdd(actions,
                                         "blockdev-backup",
                                         "s:device", device,
                                         "s:job-id", jobname,
                                         "s:target", target,
                                         "s:sync", syncmodestr,
                                         "S:bitmap", bitmap,
                                         "T:auto-finalize", VIR_TRISTATE_BOOL_YES,
                                         "T:auto-dismiss", VIR_TRISTATE_BOOL_NO,
                                         NULL);
}


static qemuMonitorJobInfo *
qemuMonitorJSONGetJobInfoOne(virJSONValue *data)
{
    const char *id = virJSONValueObjectGetString(data, "id");
    const char *type = virJSONValueObjectGetString(data, "type");
    const char *status = virJSONValueObjectGetString(data, "status");
    const char *errmsg = virJSONValueObjectGetString(data, "error");
    int tmp;
    g_autoptr(qemuMonitorJobInfo) job = NULL;

    job = g_new0(qemuMonitorJobInfo, 1);

    if ((tmp = qemuMonitorJobTypeFromString(type)) < 0)
        tmp = QEMU_MONITOR_JOB_TYPE_UNKNOWN;

    job->type = tmp;

    if ((tmp = qemuMonitorJobStatusTypeFromString(status)) < 0)
        tmp = QEMU_MONITOR_JOB_STATUS_UNKNOWN;

    job->status = tmp;

    job->id = g_strdup(id);
    job->error = g_strdup(errmsg);

    /* failure to fetch progress stats is not fatal */
    ignore_value(virJSONValueObjectGetNumberUlong(data, "current-progress",
                                                  &job->progressCurrent));
    ignore_value(virJSONValueObjectGetNumberUlong(data, "total-progress",
                                                  &job->progressTotal));

    return g_steal_pointer(&job);
}


int
qemuMonitorJSONGetJobInfo(qemuMonitor *mon,
                          qemuMonitorJobInfo ***jobs,
                          size_t *njobs)
{
    virJSONValue *data;
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    size_t i;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-jobs", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(data); i++) {
        qemuMonitorJobInfo *job = NULL;

        if (!(job = qemuMonitorJSONGetJobInfoOne(virJSONValueArrayGet(data, i))))
            return -1;

        VIR_APPEND_ELEMENT(*jobs, *njobs, job);
    }

    return 0;
}


int
qemuMonitorJSONGetCPUMigratable(qemuMonitor *mon,
                                const char *cpuQOMPath,
                                bool *migratable)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", cpuQOMPath,
                                           "s:property", "migratable",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONHasError(reply, "GenericError"))
        return 1;

    if (!(data = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_BOOLEAN)))
        return -1;

    return virJSONValueGetBoolean(data, migratable);
}


int
qemuMonitorJSONStartDirtyRateCalc(qemuMonitor *mon,
                                  int seconds,
                                  qemuMonitorDirtyRateCalcMode mode)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    const char *modestr = NULL;

    if (mode != QEMU_MONITOR_DIRTYRATE_CALC_MODE_PAGE_SAMPLING)
       modestr = qemuMonitorDirtyRateCalcModeTypeToString(mode);

    if (!(cmd = qemuMonitorJSONMakeCommand("calc-dirty-rate",
                                           "i:calc-time", seconds,
                                           "S:mode", modestr,
                                           NULL))) {
        return -1;
    }

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}

VIR_ENUM_DECL(qemuMonitorDirtyRateStatus);
VIR_ENUM_IMPL(qemuMonitorDirtyRateStatus,
              VIR_DOMAIN_DIRTYRATE_LAST,
              "unstarted",
              "measuring",
              "measured");

static int
qemuMonitorJSONExtractVcpuDirtyRate(virJSONValue *data,
                                    qemuMonitorDirtyRateInfo *info)
{
    size_t nvcpus;
    size_t i;

    nvcpus = virJSONValueArraySize(data);
    info->nvcpus = nvcpus;
    info->rates = g_new0(qemuMonitorDirtyRateVcpu, nvcpus);

    for (i = 0; i < nvcpus; i++) {
        virJSONValue *entry = virJSONValueArrayGet(data, i);
        if (virJSONValueObjectGetNumberInt(entry, "id",
                                           &info->rates[i].idx) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-dirty-rate reply was missing 'id' data"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUlong(entry, "dirty-rate",
                                            &info->rates[i].value) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-dirty-rate reply was missing 'dirty-rate' data"));
            return -1;
        }
    }

    return 0;
}

static int
qemuMonitorJSONExtractDirtyRateInfo(virJSONValue *data,
                                    qemuMonitorDirtyRateInfo *info)
{
    const char *statusstr;
    const char *modestr;
    int status;
    int mode;
    virJSONValue *rates = NULL;

    if (!(statusstr = virJSONValueObjectGetString(data, "status"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate reply was missing 'status' data"));
        return -1;
    }

    if ((status = qemuMonitorDirtyRateStatusTypeFromString(statusstr)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown dirty rate status: %1$s"), statusstr);
        return -1;
    }
    info->status = status;

    /* `query-dirty-rate` replies `dirty-rate` data only if the status of the latest
     * calculation is `measured`.
     */
    if ((info->status == VIR_DOMAIN_DIRTYRATE_MEASURED) &&
        (virJSONValueObjectGetNumberLong(data, "dirty-rate", &info->dirtyRate) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate reply was missing 'dirty-rate' data"));
        return -1;
    }

    if (virJSONValueObjectGetNumberLong(data, "start-time", &info->startTime) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate reply was missing 'start-time' data"));
        return -1;
    }

    if (virJSONValueObjectGetNumberInt(data, "calc-time", &info->calcTime) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate reply was missing 'calc-time' data"));
        return -1;
    }

    if ((modestr = virJSONValueObjectGetString(data, "mode"))) {
        if ((mode = qemuMonitorDirtyRateCalcModeTypeFromString(modestr)) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown dirty page rate calculation mode: %1$s"), modestr);
            return -1;
        }
        info->mode = mode;
    } else {
        info->mode = QEMU_MONITOR_DIRTYRATE_CALC_MODE_PAGE_SAMPLING;
    }

    if ((rates = virJSONValueObjectGetArray(data, "vcpu-dirty-rate"))) {
        if (qemuMonitorJSONExtractVcpuDirtyRate(rates, info) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate parsing 'vcpu-dirty-rate' in failure"));
            return -1;
        }
    }

    return 0;
}


int
qemuMonitorJSONQueryDirtyRate(qemuMonitor *mon,
                              qemuMonitorDirtyRateInfo *info)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *data = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-dirty-rate", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    if (!(data = virJSONValueObjectGetObject(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-dirty-rate reply was missing 'return' data"));
        return -1;
    }

    return qemuMonitorJSONExtractDirtyRateInfo(data, info);
}


VIR_ENUM_DECL(qemuMonitorActionShutdown);
VIR_ENUM_IMPL(qemuMonitorActionShutdown,
              QEMU_MONITOR_ACTION_SHUTDOWN_LAST,
              "",
              "poweroff",
              "pause");

VIR_ENUM_DECL(qemuMonitorActionReboot);
VIR_ENUM_IMPL(qemuMonitorActionReboot,
              QEMU_MONITOR_ACTION_REBOOT_LAST,
              "",
              "reset",
              "shutdown");

VIR_ENUM_DECL(qemuMonitorActionWatchdog);
VIR_ENUM_IMPL(qemuMonitorActionWatchdog,
              QEMU_MONITOR_ACTION_WATCHDOG_LAST,
              "",
              "reset",
              "shutdown",
              "poweroff",
              "pause",
              "debug",
              "none",
              "inject-nmi");

VIR_ENUM_DECL(qemuMonitorActionPanic);
VIR_ENUM_IMPL(qemuMonitorActionPanic,
              QEMU_MONITOR_ACTION_PANIC_LAST,
              "",
              "pause",
              "shutdown",
              "none");


int
qemuMonitorJSONSetAction(qemuMonitor *mon,
                         qemuMonitorActionShutdown shutdown,
                         qemuMonitorActionReboot reboot,
                         qemuMonitorActionWatchdog watchdog,
                         qemuMonitorActionPanic panic)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    const char *actionShutdown = NULL;
    const char *actionReboot = NULL;
    const char *actionWatchdog = NULL;
    const char *actionPanic = NULL;

    if (shutdown != QEMU_MONITOR_ACTION_SHUTDOWN_KEEP)
        actionShutdown = qemuMonitorActionShutdownTypeToString(shutdown);

    if (reboot != QEMU_MONITOR_ACTION_REBOOT_KEEP)
        actionReboot = qemuMonitorActionRebootTypeToString(reboot);

    if (watchdog != QEMU_MONITOR_ACTION_WATCHDOG_KEEP)
        actionWatchdog = qemuMonitorActionWatchdogTypeToString(watchdog);

    if (panic != QEMU_MONITOR_ACTION_PANIC_KEEP)
        actionPanic = qemuMonitorActionPanicTypeToString(panic);

    if (!(cmd = qemuMonitorJSONMakeCommand("set-action",
                                           "S:shutdown", actionShutdown,
                                           "S:reboot", actionReboot,
                                           "S:watchdog", actionWatchdog,
                                           "S:panic", actionPanic,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        return -1;

    return 0;
}


int
qemuMonitorJSONChangeMemoryRequestedSize(qemuMonitor *mon,
                                         const char *alias,
                                         unsigned long long requestedsize)
{
    g_autofree char *path = g_strdup_printf("/machine/peripheral/%s", alias);
    qemuMonitorJSONObjectProperty prop = {
        .type = QEMU_MONITOR_OBJECT_PROPERTY_ULONG,
        .val.ul = requestedsize * 1024, /* monitor needs bytes */
    };

    return qemuMonitorJSONSetObjectProperty(mon, path, "requested-size", &prop);
}


int
qemuMonitorJSONMigrateRecover(qemuMonitor *mon,
                              const char *uri)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-recover",
                                           "s:uri", uri,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return -1;

    return qemuMonitorJSONCheckError(cmd, reply);
}

static GHashTable *
qemuMonitorJSONExtractQueryStatsSchema(virJSONValue *json)
{
    g_autoptr(GHashTable) schema = virHashNew(g_free);
    size_t i;

    for (i = 0; i < virJSONValueArraySize(json); i++) {
        virJSONValue *obj, *stats;
        const char *target_str;
        int target;
        size_t j;

        obj = virJSONValueArrayGet(json, i);

        if (!virJSONValueIsObject(obj))
            continue;

        if (!(stats = virJSONValueObjectGetArray(obj, "stats")))
            continue;

        target_str = virJSONValueObjectGetString(obj, "target");
        target = qemuMonitorQueryStatsTargetTypeFromString(target_str);

        for (j = 0; j < virJSONValueArraySize(stats); j++) {
            virJSONValue *stat = virJSONValueArrayGet(stats, j);
            const char *name = NULL;
            const char *tmp = NULL;
            g_autofree qemuMonitorQueryStatsSchemaData *data = NULL;
            int type = -1;
            int unit = -1;

            if (!virJSONValueIsObject(stat))
                continue;

            name = virJSONValueObjectGetString(stat, "name");
            if (!name)
                continue;

            tmp = virJSONValueObjectGetString(stat, "type");
            type = qemuMonitorQueryStatsTypeTypeFromString(tmp);

            tmp = virJSONValueObjectGetString(stat, "unit");
            unit = qemuMonitorQueryStatsUnitTypeFromString(tmp);

            data = g_new0(qemuMonitorQueryStatsSchemaData, 1);
            data->target = (target == -1) ? QEMU_MONITOR_QUERY_STATS_TARGET_LAST : target;
            data->type = (type == -1) ? QEMU_MONITOR_QUERY_STATS_TYPE_LAST : type;
            data->unit = (unit == -1) ? QEMU_MONITOR_QUERY_STATS_UNIT_LAST : unit;

            if (virJSONValueObjectGetNumberInt(stat, "base", &data->base) < 0 ||
                virJSONValueObjectGetNumberInt(stat, "exponent", &data->exponent) < 0) {
                /*
                 * Base of zero means that there is simply no scale, data->exponent
                 * is set to 0 just for safety measures
                 */
                data->base = 0;
                data->exponent = 0;
            }

            if (data->type == QEMU_MONITOR_QUERY_STATS_TYPE_LINEAR_HISTOGRAM &&
                virJSONValueObjectGetNumberUint(stat, "bucket-size", &data->bucket_size) < 0)
                data->bucket_size = 0;

            if (virHashAddEntry(schema, name, data) < 0)
                return NULL;
            data = NULL;
        }
    }

    return g_steal_pointer(&schema);
}

GHashTable *
qemuMonitorJSONQueryStatsSchema(qemuMonitor *mon,
                                qemuMonitorQueryStatsProviderType provider_type)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    virJSONValue *ret;

    const char *type_str = qemuMonitorQueryStatsProviderTypeToString(provider_type);

    if (!(cmd = qemuMonitorJSONMakeCommand("query-stats-schemas",
                                           "S:provider", type_str,
                                           NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (!(ret = qemuMonitorJSONGetReply(cmd, reply, VIR_JSON_TYPE_ARRAY)))
        return NULL;

    return qemuMonitorJSONExtractQueryStatsSchema(ret);
}


/**
 * qemuMonitorJSONQueryStats:
 * @mon: monitor object
 * @target: the target type for the query
 * @vcpus: a list of vCPU QOM paths for filtering the statistics
 * @providers: an array of providers to filter statistics
 *
 * @vcpus is a NULL terminated array of strings. @providers is a GPtrArray
 * for qemuMonitorQueryStatsProvider.
 * @vcpus and @providers are optional and can be NULL.
 *
 * Queries for the @target based statistics.
 * Returns NULL on failure.
 */
virJSONValue *
qemuMonitorJSONQueryStats(qemuMonitor *mon,
                          qemuMonitorQueryStatsTargetType target,
                          char **vcpus,
                          GPtrArray *providers)
{
    g_autoptr(virJSONValue) cmd = NULL;
    g_autoptr(virJSONValue) reply = NULL;
    g_autoptr(virJSONValue) vcpu_list = NULL;
    g_autoptr(virJSONValue) provider_list = NULL;
    size_t i;

    if (providers) {
        provider_list = virJSONValueNewArray();

        for (i = 0; i < providers->len; i++) {
            qemuMonitorQueryStatsProvider *provider = providers->pdata[i];
            g_autoptr(virJSONValue) provider_obj = NULL;
            g_autoptr(virJSONValue) provider_names = NULL;
            ssize_t curBit = -1;

            while ((curBit = virBitmapNextSetBit(provider->names, curBit)) != -1) {
                if (!provider_names)
                    provider_names = virJSONValueNewArray();

                if (virJSONValueArrayAppendString(provider_names,
                                                  qemuMonitorQueryStatsNameTypeToString(curBit)) < 0)
                    return NULL;
            }

            if (virJSONValueObjectAdd(&provider_obj,
                                      "s:provider", qemuMonitorQueryStatsProviderTypeToString(provider->type),
                                      "A:names", &provider_names,
                                      NULL) < 0)
                return NULL;

            if (virJSONValueArrayAppend(provider_list, &provider_obj) < 0)
                return NULL;
        }
    }

    if (vcpus) {
        vcpu_list = virJSONValueNewArray();

        for (i = 0; vcpus[i]; i++)
            if (virJSONValueArrayAppendString(vcpu_list, vcpus[i]) < 0)
                return NULL;
    }

    cmd = qemuMonitorJSONMakeCommand("query-stats",
                                     "s:target", qemuMonitorQueryStatsTargetTypeToString(target),
                                     "A:vcpus", &vcpu_list,
                                     "A:providers", &provider_list,
                                     NULL);

    if (!cmd)
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        return NULL;

    if (qemuMonitorJSONCheckReply(cmd, reply, VIR_JSON_TYPE_ARRAY) < 0)
        return NULL;

    return virJSONValueObjectStealArray(reply, "return");
}
