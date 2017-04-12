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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "qemu_monitor_text.h"
#include "qemu_monitor_json.h"
#include "qemu_alias.h"
#include "qemu_parse_command.h"
#include "qemu_capabilities.h"
#include "viralloc.h"
#include "virlog.h"
#include "driver.h"
#include "datatypes.h"
#include "virerror.h"
#include "virjson.h"
#include "virprobe.h"
#include "virstring.h"
#include "cpu/cpu_x86.h"
#include "c-strcasestr.h"

#ifdef WITH_DTRACE_PROBES
# include "libvirt_qemu_probes.h"
#endif

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor_json");

#define QOM_CPU_PATH  "/machine/unattached/device[0]"

#define LINE_ENDING "\r\n"

static void qemuMonitorJSONHandleShutdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleReset(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePowerdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleStop(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleResume(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleRTCChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleWatchdog(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleIOError(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCConnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCInitialize(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEConnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleTrayChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePMWakeup(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePMSuspend(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBlockJobCompleted(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBlockJobCanceled(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBlockJobReady(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBalloonChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePMSuspendDisk(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleGuestPanic(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleDeviceDeleted(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleNicRxFilterChanged(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSerialChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSpiceMigrated(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleMigrationStatus(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleMigrationPass(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleAcpiOstInfo(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBlockThreshold(qemuMonitorPtr mon, virJSONValuePtr data);

typedef struct {
    const char *type;
    void (*handler)(qemuMonitorPtr mon, virJSONValuePtr data);
} qemuEventHandler;

static qemuEventHandler eventHandlers[] = {
    { "ACPI_DEVICE_OST", qemuMonitorJSONHandleAcpiOstInfo, },
    { "BALLOON_CHANGE", qemuMonitorJSONHandleBalloonChange, },
    { "BLOCK_IO_ERROR", qemuMonitorJSONHandleIOError, },
    { "BLOCK_JOB_CANCELLED", qemuMonitorJSONHandleBlockJobCanceled, },
    { "BLOCK_JOB_COMPLETED", qemuMonitorJSONHandleBlockJobCompleted, },
    { "BLOCK_JOB_READY", qemuMonitorJSONHandleBlockJobReady, },
    { "BLOCK_WRITE_THRESHOLD", qemuMonitorJSONHandleBlockThreshold, },
    { "DEVICE_DELETED", qemuMonitorJSONHandleDeviceDeleted, },
    { "DEVICE_TRAY_MOVED", qemuMonitorJSONHandleTrayChange, },
    { "GUEST_PANICKED", qemuMonitorJSONHandleGuestPanic, },
    { "MIGRATION", qemuMonitorJSONHandleMigrationStatus, },
    { "MIGRATION_PASS", qemuMonitorJSONHandleMigrationPass, },
    { "NIC_RX_FILTER_CHANGED", qemuMonitorJSONHandleNicRxFilterChanged, },
    { "POWERDOWN", qemuMonitorJSONHandlePowerdown, },
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
qemuMonitorJSONIOProcessEvent(qemuMonitorPtr mon,
                              virJSONValuePtr obj)
{
    const char *type;
    qemuEventHandler *handler;
    virJSONValuePtr data;
    char *details = NULL;
    virJSONValuePtr timestamp;
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
    VIR_FREE(details);

    handler = bsearch(type, eventHandlers, ARRAY_CARDINALITY(eventHandlers),
                      sizeof(eventHandlers[0]), qemuMonitorEventCompare);
    if (handler) {
        VIR_DEBUG("handle %s handler=%p data=%p", type,
                  handler->handler, data);
        (handler->handler)(mon, data);
    }
    return 0;
}

int
qemuMonitorJSONIOProcessLine(qemuMonitorPtr mon,
                             const char *line,
                             qemuMonitorMessagePtr msg)
{
    virJSONValuePtr obj = NULL;
    int ret = -1;

    VIR_DEBUG("Line [%s]", line);

    if (!(obj = virJSONValueFromString(line)))
        goto cleanup;

    if (obj->type != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Parsed JSON reply '%s' isn't an object"), line);
        goto cleanup;
    }

    if (virJSONValueObjectHasKey(obj, "QMP") == 1) {
        ret = 0;
    } else if (virJSONValueObjectHasKey(obj, "event") == 1) {
        PROBE(QEMU_MONITOR_RECV_EVENT,
              "mon=%p event=%s", mon, line);
        ret = qemuMonitorJSONIOProcessEvent(mon, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") == 1 ||
               virJSONValueObjectHasKey(obj, "return") == 1) {
        PROBE(QEMU_MONITOR_RECV_REPLY,
              "mon=%p reply=%s", mon, line);
        if (msg) {
            msg->rxObject = obj;
            msg->finished = 1;
            obj = NULL;
            ret = 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unexpected JSON reply '%s'"), line);
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown JSON reply '%s'"), line);
    }

 cleanup:
    virJSONValueFree(obj);
    return ret;
}

int qemuMonitorJSONIOProcess(qemuMonitorPtr mon,
                             const char *data,
                             size_t len,
                             qemuMonitorMessagePtr msg)
{
    int used = 0;
    /*VIR_DEBUG("Data %d bytes [%s]", len, data);*/

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            char *line;
            if (VIR_STRNDUP(line, data + used, got) < 0)
                return -1;
            used += got + strlen(LINE_ENDING);
            line[got] = '\0'; /* kill \n */
            if (qemuMonitorJSONIOProcessLine(mon, line, msg) < 0) {
                VIR_FREE(line);
                return -1;
            }

            VIR_FREE(line);
        } else {
            break;
        }
    }

    VIR_DEBUG("Total used %d bytes out of %zd available in buffer", used, len);
    return used;
}

static int
qemuMonitorJSONCommandWithFd(qemuMonitorPtr mon,
                             virJSONValuePtr cmd,
                             int scm_fd,
                             virJSONValuePtr *reply)
{
    int ret = -1;
    qemuMonitorMessage msg;
    char *cmdstr = NULL;
    char *id = NULL;

    *reply = NULL;

    memset(&msg, 0, sizeof(msg));

    if (virJSONValueObjectHasKey(cmd, "execute") == 1) {
        if (!(id = qemuMonitorNextCommandID(mon)))
            goto cleanup;
        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to append command 'id' string"));
            goto cleanup;
        }
    }

    if (!(cmdstr = virJSONValueToString(cmd, false)))
        goto cleanup;
    if (virAsprintf(&msg.txBuffer, "%s\r\n", cmdstr) < 0)
        goto cleanup;
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmdstr, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);


    if (ret == 0) {
        if (!msg.rxObject) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing monitor reply object"));
            ret = -1;
        } else {
            *reply = msg.rxObject;
        }
    }

 cleanup:
    VIR_FREE(id);
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);

    return ret;
}


static int
qemuMonitorJSONCommand(qemuMonitorPtr mon,
                       virJSONValuePtr cmd,
                       virJSONValuePtr *reply)
{
    return qemuMonitorJSONCommandWithFd(mon, cmd, -1, reply);
}

/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuMonitorJSONStringifyError(virJSONValuePtr error)
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
qemuMonitorJSONCommandName(virJSONValuePtr cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    else
        return "<unknown>";
}

static int
qemuMonitorJSONCheckError(virJSONValuePtr cmd,
                          virJSONValuePtr reply)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        virJSONValuePtr error = virJSONValueObjectGet(reply, "error");
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU command %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));

        /* Only send the user the command name + friendly error */
        if (!error)
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU command '%s'"),
                           qemuMonitorJSONCommandName(cmd));
        else
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute QEMU command '%s': %s"),
                           qemuMonitorJSONCommandName(cmd),
                           qemuMonitorJSONStringifyError(error));

        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        char *cmdstr = virJSONValueToString(cmd, false);
        char *replystr = virJSONValueToString(reply, false);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  NULLSTR(cmdstr), NULLSTR(replystr));
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to execute QEMU command '%s'"),
                       qemuMonitorJSONCommandName(cmd));
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    }
    return 0;
}


static bool
qemuMonitorJSONErrorIsClass(virJSONValuePtr error,
                            const char *klass)
{
    return STREQ_NULLABLE(virJSONValueObjectGetString(error, "class"), klass);
}


static bool
qemuMonitorJSONHasError(virJSONValuePtr reply,
                        const char *klass)
{
    virJSONValuePtr error;

    if (!(error = virJSONValueObjectGet(reply, "error")))
        return false;

    return qemuMonitorJSONErrorIsClass(error, klass);
}


/* Top-level commands and nested transaction list elements share a
 * common structure for everything except the dictionary names.  */
static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuMonitorJSONMakeCommandRaw(bool wrap, const char *cmdname, ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendString(obj, wrap ? "type" : "execute",
                                       cmdname) < 0)
        goto error;

    if (virJSONValueObjectCreateVArgs(&jargs, args) < 0)
        goto error;

    if (jargs &&
        virJSONValueObjectAppend(obj, wrap ? "data" : "arguments", jargs) < 0)
        goto error;

    va_end(args);

    return obj;

 error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}

#define qemuMonitorJSONMakeCommand(cmdname, ...) \
    qemuMonitorJSONMakeCommandRaw(false, cmdname, __VA_ARGS__)

static void
qemuFreeKeywords(int nkeywords, char **keywords, char **values)
{
    size_t i;
    for (i = 0; i < nkeywords; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
}

static virJSONValuePtr
qemuMonitorJSONKeywordStringToJSON(const char *str, const char *firstkeyword)
{
    virJSONValuePtr ret = NULL;
    char **keywords = NULL;
    char **values = NULL;
    int nkeywords = 0;
    size_t i;

    if (!(ret = virJSONValueNewObject()))
        return NULL;

    if (qemuParseKeywords(str, &keywords, &values, &nkeywords, 1) < 0)
        goto error;

    for (i = 0; i < nkeywords; i++) {
        if (values[i] == NULL) {
            if (i != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unexpected empty keyword in %s"), str);
                goto error;
            } else {
                /* This 3rd arg isn't a typo - the way the parser works is
                 * that the value ended up in the keyword field */
                if (virJSONValueObjectAppendString(ret, firstkeyword, keywords[i]) < 0)
                    goto error;
            }
        } else {
            if (virJSONValueObjectAppendString(ret, keywords[i], values[i]) < 0)
                goto error;
        }
    }

    qemuFreeKeywords(nkeywords, keywords, values);
    return ret;

 error:
    qemuFreeKeywords(nkeywords, keywords, values);
    virJSONValueFree(ret);
    return NULL;
}


static void qemuMonitorJSONHandleShutdown(qemuMonitorPtr mon, virJSONValuePtr data)
{
    bool guest = false;
    virTristateBool guest_initiated = VIR_TRISTATE_BOOL_ABSENT;

    if (virJSONValueObjectGetBoolean(data, "guest", &guest) == 0)
        guest_initiated = guest ? VIR_TRISTATE_BOOL_YES : VIR_TRISTATE_BOOL_NO;

    qemuMonitorEmitShutdown(mon, guest_initiated);
}

static void qemuMonitorJSONHandleReset(qemuMonitorPtr mon, virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitReset(mon);
}

static void qemuMonitorJSONHandlePowerdown(qemuMonitorPtr mon, virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitPowerdown(mon);
}

static void qemuMonitorJSONHandleStop(qemuMonitorPtr mon, virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitStop(mon);
}

static void qemuMonitorJSONHandleResume(qemuMonitorPtr mon, virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitResume(mon);
}


static qemuMonitorEventPanicInfoPtr
qemuMonitorJSONGuestPanicExtractInfoHyperv(virJSONValuePtr data)
{
    qemuMonitorEventPanicInfoPtr ret;

    if (VIR_ALLOC(ret) < 0)
        return NULL;

    ret->type = QEMU_MONITOR_EVENT_PANIC_INFO_TYPE_HYPERV;

    if (virJSONValueObjectGetNumberUlong(data, "arg1", &ret->data.hyperv.arg1) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg2", &ret->data.hyperv.arg2) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg3", &ret->data.hyperv.arg3) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg4", &ret->data.hyperv.arg4) < 0 ||
        virJSONValueObjectGetNumberUlong(data, "arg5", &ret->data.hyperv.arg5) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed hyperv panic data"));
        goto error;
    }

    return ret;

 error:
    qemuMonitorEventPanicInfoFree(ret);
    return NULL;
}


static qemuMonitorEventPanicInfoPtr
qemuMonitorJSONGuestPanicExtractInfo(virJSONValuePtr data)
{
    const char *type = virJSONValueObjectGetString(data, "type");

    if (STREQ_NULLABLE(type, "hyper-v"))
        return qemuMonitorJSONGuestPanicExtractInfoHyperv(data);

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("unknown panic info type '%s'"), NULLSTR(type));
    return NULL;
}


static void
qemuMonitorJSONHandleGuestPanic(qemuMonitorPtr mon,
                                virJSONValuePtr data)
{
    virJSONValuePtr infojson = virJSONValueObjectGetObject(data, "info");
    qemuMonitorEventPanicInfoPtr info = NULL;

    if (infojson)
        info = qemuMonitorJSONGuestPanicExtractInfo(infojson);

    qemuMonitorEmitGuestPanic(mon, info);
}


static void qemuMonitorJSONHandleRTCChange(qemuMonitorPtr mon, virJSONValuePtr data)
{
    long long offset = 0;
    if (virJSONValueObjectGetNumberLong(data, "offset", &offset) < 0) {
        VIR_WARN("missing offset in RTC change event");
        offset = 0;
    }
    qemuMonitorEmitRTCChange(mon, offset);
}

VIR_ENUM_DECL(qemuMonitorWatchdogAction)
VIR_ENUM_IMPL(qemuMonitorWatchdogAction, VIR_DOMAIN_EVENT_WATCHDOG_LAST,
              "none", "pause", "reset", "poweroff", "shutdown", "debug", "inject-nmi");

static void qemuMonitorJSONHandleWatchdog(qemuMonitorPtr mon, virJSONValuePtr data)
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

VIR_ENUM_DECL(qemuMonitorIOErrorAction)
VIR_ENUM_IMPL(qemuMonitorIOErrorAction, VIR_DOMAIN_EVENT_IO_ERROR_LAST,
              "ignore", "stop", "report");


static void
qemuMonitorJSONHandleIOError(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *device;
    const char *action;
    const char *reason = "";
    bool nospc = false;
    int actionID;

    /* Throughout here we try our best to carry on upon errors,
       since it's imporatant to get as much info as possible out
       to the application */

    if ((action = virJSONValueObjectGetString(data, "action")) == NULL) {
        VIR_WARN("Missing action in disk io error event");
        action = "ignore";
    }

    if ((device = virJSONValueObjectGetString(data, "device")) == NULL)
        VIR_WARN("missing device in disk io error event");

    if (virJSONValueObjectGetBoolean(data, "nospace", &nospc) == 0 && nospc)
        reason = "enospc";

    if ((actionID = qemuMonitorIOErrorActionTypeFromString(action)) < 0) {
        VIR_WARN("unknown disk io error action '%s'", action);
        actionID = VIR_DOMAIN_EVENT_IO_ERROR_NONE;
    }

    qemuMonitorEmitIOError(mon, device, actionID, reason);
}


VIR_ENUM_DECL(qemuMonitorGraphicsAddressFamily)
VIR_ENUM_IMPL(qemuMonitorGraphicsAddressFamily,
              VIR_DOMAIN_EVENT_GRAPHICS_ADDRESS_LAST,
              "ipv4", "ipv6", "unix");

static void
qemuMonitorJSONHandleGraphicsVNC(qemuMonitorPtr mon,
                                 virJSONValuePtr data,
                                 int phase)
{
    const char *localNode, *localService, *localFamily;
    const char *remoteNode, *remoteService, *remoteFamily;
    const char *authScheme, *saslUsername, *x509dname;
    int localFamilyID, remoteFamilyID;
    virJSONValuePtr client;
    virJSONValuePtr server;

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

static void qemuMonitorJSONHandleVNCConnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleVNCInitialize(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsVNC(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}


static void
qemuMonitorJSONHandleGraphicsSPICE(qemuMonitorPtr mon,
                                   virJSONValuePtr data,
                                   int phase)
{
    const char *lhost, *lport, *lfamily;
    const char *rhost, *rport, *rfamily;
    const char *auth = "";
    int lfamilyID, rfamilyID;
    virJSONValuePtr client;
    virJSONValuePtr server;

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


static void qemuMonitorJSONHandleSPICEConnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphicsSPICE(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}

static void
qemuMonitorJSONHandleBlockJobImpl(qemuMonitorPtr mon,
                                  virJSONValuePtr data,
                                  int event)
{
    const char *device;
    const char *type_str;
    int type = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
    unsigned long long offset, len;

    if ((device = virJSONValueObjectGetString(data, "device")) == NULL) {
        VIR_WARN("missing device in block job event");
        goto out;
    }

    if (virJSONValueObjectGetNumberUlong(data, "offset", &offset) < 0) {
        VIR_WARN("missing offset in block job event");
        goto out;
    }

    if (virJSONValueObjectGetNumberUlong(data, "len", &len) < 0) {
        VIR_WARN("missing len in block job event");
        goto out;
    }

    if ((type_str = virJSONValueObjectGetString(data, "type")) == NULL) {
        VIR_WARN("missing type in block job event");
        goto out;
    }

    if (STREQ(type_str, "stream"))
        type = VIR_DOMAIN_BLOCK_JOB_TYPE_PULL;
    else if (STREQ(type_str, "commit"))
        type = VIR_DOMAIN_BLOCK_JOB_TYPE_COMMIT;
    else if (STREQ(type_str, "mirror"))
        type = VIR_DOMAIN_BLOCK_JOB_TYPE_COPY;

    switch ((virConnectDomainEventBlockJobStatus) event) {
    case VIR_DOMAIN_BLOCK_JOB_COMPLETED:
        /* Make sure the whole device has been processed */
        if (offset != len)
            event = VIR_DOMAIN_BLOCK_JOB_FAILED;
        break;
    case VIR_DOMAIN_BLOCK_JOB_CANCELED:
    case VIR_DOMAIN_BLOCK_JOB_READY:
        break;
    case VIR_DOMAIN_BLOCK_JOB_FAILED:
    case VIR_DOMAIN_BLOCK_JOB_LAST:
        VIR_DEBUG("should not get here");
        break;
    }

 out:
    qemuMonitorEmitBlockJob(mon, device, type, event);
}

static void
qemuMonitorJSONHandleTrayChange(qemuMonitorPtr mon,
                                virJSONValuePtr data)
{
    const char *devAlias = NULL;
    bool trayOpened;
    int reason;

    if ((devAlias = virJSONValueObjectGetString(data, "device")) == NULL) {
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

    qemuMonitorEmitTrayChange(mon, devAlias, reason);
}

static void
qemuMonitorJSONHandlePMWakeup(qemuMonitorPtr mon,
                              virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitPMWakeup(mon);
}

static void
qemuMonitorJSONHandlePMSuspend(qemuMonitorPtr mon,
                               virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitPMSuspend(mon);
}

static void
qemuMonitorJSONHandleBlockJobCompleted(qemuMonitorPtr mon,
                                       virJSONValuePtr data)
{
    qemuMonitorJSONHandleBlockJobImpl(mon, data,
                                      VIR_DOMAIN_BLOCK_JOB_COMPLETED);
}

static void
qemuMonitorJSONHandleBlockJobCanceled(qemuMonitorPtr mon,
                                       virJSONValuePtr data)
{
    qemuMonitorJSONHandleBlockJobImpl(mon, data,
                                      VIR_DOMAIN_BLOCK_JOB_CANCELED);
}

static void
qemuMonitorJSONHandleBlockJobReady(qemuMonitorPtr mon,
                                   virJSONValuePtr data)
{
    qemuMonitorJSONHandleBlockJobImpl(mon, data,
                                      VIR_DOMAIN_BLOCK_JOB_READY);
}

static void
qemuMonitorJSONHandleBalloonChange(qemuMonitorPtr mon,
                                   virJSONValuePtr data)
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
qemuMonitorJSONHandlePMSuspendDisk(qemuMonitorPtr mon,
                                   virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitPMSuspendDisk(mon);
}

static void
qemuMonitorJSONHandleDeviceDeleted(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *device;

    if (!(device = virJSONValueObjectGetString(data, "device"))) {
        VIR_DEBUG("missing device in device deleted event");
        return;
    }

    qemuMonitorEmitDeviceDeleted(mon, device);
}


static void
qemuMonitorJSONHandleNicRxFilterChanged(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *name;

    if (!(name = virJSONValueObjectGetString(data, "name"))) {
        VIR_WARN("missing device in NIC_RX_FILTER_CHANGED event");
        return;
    }

    qemuMonitorEmitNicRxFilterChanged(mon, name);
}


static void
qemuMonitorJSONHandleSerialChange(qemuMonitorPtr mon,
                                  virJSONValuePtr data)
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
qemuMonitorJSONHandleSpiceMigrated(qemuMonitorPtr mon,
                                   virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitSpiceMigrated(mon);
}


static void
qemuMonitorJSONHandleMigrationStatus(qemuMonitorPtr mon,
                                     virJSONValuePtr data)
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
qemuMonitorJSONHandleMigrationPass(qemuMonitorPtr mon,
                                   virJSONValuePtr data)
{
    int pass;

    if (virJSONValueObjectGetNumberInt(data, "pass", &pass) < 0) {
        VIR_WARN("missing dirty-sync-count in migration-pass event");
        return;
    }

    qemuMonitorEmitMigrationPass(mon, pass);
}


static void
qemuMonitorJSONHandleAcpiOstInfo(qemuMonitorPtr mon, virJSONValuePtr data)
{
    virJSONValuePtr info;
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
qemuMonitorJSONHandleBlockThreshold(qemuMonitorPtr mon, virJSONValuePtr data)
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


int
qemuMonitorJSONHumanCommandWithFd(qemuMonitorPtr mon,
                                  const char *cmd_str,
                                  int scm_fd,
                                  char **reply_str)
{
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr obj;
    int ret = -1;

    cmd = qemuMonitorJSONMakeCommand("human-monitor-command",
                                     "s:command-line", cmd_str,
                                     NULL);

    if (!cmd || qemuMonitorJSONCommandWithFd(mon, cmd, scm_fd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("Human monitor command is not available to run %s"),
                       cmd_str);
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply))
        goto cleanup;

    obj = virJSONValueObjectGet(reply, "return");

    if (reply_str) {
        const char *data;

        data = virJSONValueGetString(obj);
        if (VIR_STRDUP(*reply_str, data ? data : "") < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONSetCapabilities(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("qmp_capabilities", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONStartCPUs(qemuMonitorPtr mon,
                         virConnectPtr conn ATTRIBUTE_UNUSED)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("cont", NULL);
    virJSONValuePtr reply = NULL;
    size_t i = 0;
    int timeout = 3;
    if (!cmd)
        return -1;

    do {
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

        virJSONValueFree(reply);
        reply = NULL;
        usleep(250000);
    } while (++i <= timeout);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONStopCPUs(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("stop", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetStatus(qemuMonitorPtr mon,
                         bool *running,
                         virDomainPausedReason *reason)
{
    int ret = -1;
    const char *status;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;

    if (reason)
        *reason = VIR_DOMAIN_PAUSED_UNKNOWN;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-status", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetBoolean(data, "running", running) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-status reply was missing running state"));
        goto cleanup;
    }

    if ((status = virJSONValueObjectGetString(data, "status"))) {
        if (!*running && reason)
            *reason = qemuMonitorVMStatusToPausedReason(status);
    } else if (!*running) {
        VIR_DEBUG("query-status reply was missing status details");
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSystemPowerdown(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("system_powerdown", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSetLink(qemuMonitorPtr mon,
                           const char *name,
                           virDomainNetInterfaceLinkState state)
{

    int ret = -1;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("set_link",
                                                     "s:name", name,
                                                     "b:up", state != VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN,
                                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSystemReset(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("system_reset", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 *
 * [{ "arch": "x86",
 *    "current": true,
 *    "CPU": 0,
 *    "qom_path": "/machine/unattached/device[0]",
 *    "pc": -2130415978,
 *    "halted": true,
 *    "thread_id": 2631237},
 *    {...}
 *  ]
 */
static int
qemuMonitorJSONExtractCPUInfo(virJSONValuePtr data,
                              struct qemuMonitorQueryCpusEntry **entries,
                              size_t *nentries)
{
    struct qemuMonitorQueryCpusEntry *cpus = NULL;
    int ret = -1;
    size_t i;
    ssize_t ncpus;

    if ((ncpus = virJSONValueArraySize(data)) <= 0)
        return -2;

    if (VIR_ALLOC_N(cpus, ncpus) < 0)
        goto cleanup;

    for (i = 0; i < ncpus; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        int cpuid = -1;
        int thread = 0;
        bool halted = false;
        const char *qom_path;
        if (!entry) {
            ret = -2;
            goto cleanup;
        }

        /* Some older qemu versions don't report the thread_id so treat this as
         * non-fatal, simply returning no data */
        ignore_value(virJSONValueObjectGetNumberInt(entry, "CPU", &cpuid));
        ignore_value(virJSONValueObjectGetNumberInt(entry, "thread_id", &thread));
        ignore_value(virJSONValueObjectGetBoolean(entry, "halted", &halted));
        qom_path = virJSONValueObjectGetString(entry, "qom_path");

        cpus[i].qemu_id = cpuid;
        cpus[i].tid = thread;
        cpus[i].halted = halted;
        if (VIR_STRDUP(cpus[i].qom_path, qom_path) < 0)
            goto cleanup;
    }

    VIR_STEAL_PTR(*entries, cpus);
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
 *
 * Queries qemu for cpu-related information. Failure to execute the command or
 * extract results does not produce an error as libvirt can continue without
 * this information.
 *
 * Returns 0 on success, -1 on a fatal error (oom ...) and -2 if the
 * query failed gracefully.
 */
int
qemuMonitorJSONQueryCPUs(qemuMonitorPtr mon,
                         struct qemuMonitorQueryCpusEntry **entries,
                         size_t *nentries,
                         bool force)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-cpus", NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (force && qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        ret = -2;
        goto cleanup;
    }

    ret = qemuMonitorJSONExtractCPUInfo(data, entries, nentries);

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetVirtType(qemuMonitorPtr mon,
                               virDomainVirtType *virtType)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-kvm",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    bool val = false;

    *virtType = VIR_DOMAIN_VIRT_QEMU;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetBoolean(data, "enabled", &val) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("info kvm reply missing 'enabled' field"));
        goto cleanup;
    }

    if (val)
        *virtType = VIR_DOMAIN_VIRT_KVM;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/**
 * Loads correct video memory size values from QEMU and update the video
 * definition.
 *
 * Return 0 on success, -1 on failure and set proper error message.
 */
int
qemuMonitorJSONUpdateVideoMemorySize(qemuMonitorPtr mon,
                                     virDomainVideoDefPtr video,
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
                           _("QOM Object '%s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_QXL:
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vram_size", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%s' has no property 'vram_size'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul / 1024;

        if (qemuMonitorJSONGetObjectProperty(mon, path, "ram_size", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%s' has no property 'ram_size'"),
                           path);
            return -1;
        }
        video->ram = prop.val.ul / 1024;
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vgamem_mb", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vgamem = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
        if (qemuMonitorJSONGetObjectProperty(mon, path, "vgamem_mb", &prop) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("QOM Object '%s' has no property 'vgamem_mb'"),
                           path);
            return -1;
        }
        video->vram = prop.val.ul * 1024;
        break;
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_XEN:
    case VIR_DOMAIN_VIDEO_TYPE_VBOX:
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
qemuMonitorJSONUpdateVideoVram64Size(qemuMonitorPtr mon,
                                     virDomainVideoDefPtr video,
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
                               _("QOM Object '%s' has no property 'vram64_size_mb'"),
                               path);
                return -1;
            }
            video->vram64 = prop.val.ul * 1024;
        }
        break;
    case VIR_DOMAIN_VIDEO_TYPE_VGA:
    case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
    case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
    case VIR_DOMAIN_VIDEO_TYPE_XEN:
    case VIR_DOMAIN_VIDEO_TYPE_VBOX:
    case VIR_DOMAIN_VIDEO_TYPE_LAST:
        break;
    }

    return 0;
}


int
qemuMonitorJSONGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long long *currmem)
{
    int ret = -1;
    virJSONValuePtr data;
    unsigned long long mem;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-balloon",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    *currmem = 0;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* See if balloon soft-failed */
    if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
        qemuMonitorJSONHasError(reply, "KVMMissingCap")) {
        ret = 0;
        goto cleanup;
    }

    /* See if any other fatal error occurred */
    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetNumberUlong(data, "actual", &mem) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("info balloon reply was missing balloon data"));
        goto cleanup;
    }

    *currmem = (mem/1024);
    ret = 1;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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
#define GET_BALLOON_STATS(OBJECT, FIELD, TAG, DIVISOR)                        \
    if (virJSONValueObjectHasKey(OBJECT, FIELD) &&                            \
       (got < nr_stats)) {                                                    \
        if (virJSONValueObjectGetNumberUlong(OBJECT, FIELD, &mem) < 0) {      \
            VIR_DEBUG("Failed to get '%s' value", FIELD);                     \
        } else {                                                              \
            /* Not being collected? No point in providing bad data */         \
            if (mem != -1UL) {                                                \
                stats[got].tag = TAG;                                         \
                stats[got].val = mem / DIVISOR;                               \
                got++;                                                        \
            }                                                                 \
        }                                                                     \
    }


int qemuMonitorJSONGetMemoryStats(qemuMonitorPtr mon,
                                  char *balloonpath,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    virJSONValuePtr statsdata;
    unsigned long long mem;
    int got = 0;

    ret = qemuMonitorJSONGetBalloonInfo(mon, &mem);
    if (ret == 1 && (got < nr_stats)) {
        stats[got].tag = VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON;
        stats[got].val = mem;
        got++;
    }

    if (!balloonpath)
        goto cleanup;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", balloonpath,
                                           "s:property", "guest-stats",
                                           NULL)))
        goto cleanup;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if ((data = virJSONValueObjectGetObject(reply, "error"))) {
        const char *klass = virJSONValueObjectGetString(data, "class");
        const char *desc = virJSONValueObjectGetString(data, "desc");

        if (STREQ_NULLABLE(klass, "GenericError") &&
            STREQ_NULLABLE(desc, "guest hasn't updated any stats yet")) {
            virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                           _("the guest hasn't updated any stats yet"));
            goto cleanup;
        }
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (!(statsdata = virJSONValueObjectGet(data, "stats"))) {
        VIR_DEBUG("data does not include 'stats'");
        goto cleanup;
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
    ret = got;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
#undef GET_BALLOON_STATS


/*
 * Using the provided balloonpath, determine if we need to set the
 * collection interval property to enable statistics gathering.
 */
int
qemuMonitorJSONSetMemoryStatsPeriod(qemuMonitorPtr mon,
                                    char *balloonpath,
                                    int period)
{
    qemuMonitorJSONObjectProperty prop;

    /* Set to the value in memballoon (could enable or disable) */
    memset(&prop, 0, sizeof(qemuMonitorJSONObjectProperty));
    prop.type = QEMU_MONITOR_OBJECT_PROPERTY_INT;
    prop.val.iv = period;
    if (qemuMonitorJSONSetObjectProperty(mon, balloonpath,
                                         "guest-stats-polling-interval",
                                         &prop) < 0) {
        return -1;
    }
    return 0;
}


/* qemuMonitorJSONQueryBlock:
 * @mon: Monitor pointer
 *
 * This helper will attempt to make a "query-block" call and check for
 * errors before returning with the reply.
 *
 * Returns: NULL on error, reply on success
 */
static virJSONValuePtr
qemuMonitorJSONQueryBlock(qemuMonitorPtr mon)
{
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-block", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0 ||
        qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(devices = virJSONValueObjectStealArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-block reply was missing device list"));
        goto cleanup;
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return devices;
}


static virJSONValuePtr
qemuMonitorJSONGetBlockDev(virJSONValuePtr devices,
                           size_t idx)
{
    virJSONValuePtr dev = virJSONValueArrayGet(devices, idx);

    if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-block device entry was not in expected format"));
        return NULL;
    }
    return dev;
}


static const char *
qemuMonitorJSONGetBlockDevDevice(virJSONValuePtr dev)
{
    const char *thisdev;

    if (!(thisdev = virJSONValueObjectGetString(dev, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-block device entry was not in expected format"));
        return NULL;
    }

    return thisdev;
}


int qemuMonitorJSONGetBlockInfo(qemuMonitorPtr mon,
                                virHashTablePtr table)
{
    int ret = -1;
    size_t i;

    virJSONValuePtr devices;

    if (!(devices = qemuMonitorJSONQueryBlock(mon)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValuePtr dev;
        virJSONValuePtr image;
        struct qemuDomainDiskInfo *info;
        const char *thisdev;
        const char *status;
        const char *nodename;

        if (!(dev = qemuMonitorJSONGetBlockDev(devices, i)))
            goto cleanup;

        if (!(thisdev = qemuMonitorJSONGetBlockDevDevice(dev)))
            goto cleanup;

        thisdev = qemuAliasDiskDriveSkipPrefix(thisdev);

        if (VIR_ALLOC(info) < 0)
            goto cleanup;

        if (virHashAddEntry(table, thisdev, info) < 0) {
            VIR_FREE(info);
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(dev, "removable", &info->removable) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot read %s value"),
                           "removable");
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(dev, "locked", &info->locked) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot read %s value"),
                           "locked");
            goto cleanup;
        }

        /* 'tray_open' is present only if the device has a tray */
        if (virJSONValueObjectGetBoolean(dev, "tray_open", &info->tray_open) == 0)
            info->tray = true;

        /* presence of 'inserted' notifies that a medium is in the device */
        if ((image = virJSONValueObjectGetObject(dev, "inserted"))) {
            if ((nodename = virJSONValueObjectGetString(image, "node-name")))
                ignore_value(VIR_STRDUP(info->nodename, nodename));
        } else {
            info->empty = true;
        }

        /* Missing io-status indicates no error */
        if ((status = virJSONValueObjectGetString(dev, "io-status"))) {
            info->io_status = qemuMonitorBlockIOStatusToError(status);
            if (info->io_status < 0)
                goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virJSONValueFree(devices);
    return ret;
}


static int
qemuMonitorJSONGetOneBlockStatsInfo(virJSONValuePtr dev,
                                    const char *dev_name,
                                    int depth,
                                    virHashTablePtr hash,
                                    bool backingChain)
{
    qemuBlockStatsPtr bstats = NULL;
    virJSONValuePtr stats;
    virJSONValuePtr parent;
    virJSONValuePtr parentstats;
    int ret = -1;
    int nstats = 0;
    char *entry_name = qemuDomainStorageAlias(dev_name, depth);
    virJSONValuePtr backing;

    if (!entry_name)
        goto cleanup;
    if (VIR_ALLOC(bstats) < 0)
        goto cleanup;

    if ((stats = virJSONValueObjectGetObject(dev, "stats")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("blockstats stats entry was not "
                         "in expected format"));
        goto cleanup;
    }

#define QEMU_MONITOR_BLOCK_STAT_GET(NAME, VAR, MANDATORY)                      \
    if (MANDATORY || virJSONValueObjectHasKey(stats, NAME)) {                  \
        nstats++;                                                              \
        if (virJSONValueObjectGetNumberLong(stats, NAME, &VAR) < 0) {          \
            virReportError(VIR_ERR_INTERNAL_ERROR,                             \
                           _("cannot read %s statistic"), NAME);               \
            goto cleanup;                                                      \
        }                                                                      \
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

    if (virHashAddEntry(hash, entry_name, bstats) < 0)
        goto cleanup;
    bstats = NULL;

    if (backingChain &&
        (backing = virJSONValueObjectGetObject(dev, "backing")) &&
        qemuMonitorJSONGetOneBlockStatsInfo(backing, dev_name, depth + 1,
                                            hash, true) < 0)
        goto cleanup;

    ret = nstats;
 cleanup:
    VIR_FREE(bstats);
    VIR_FREE(entry_name);
    return ret;
}


int
qemuMonitorJSONGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                    virHashTablePtr hash,
                                    bool backingChain)
{
    int ret = -1;
    int nstats = 0;
    int rc;
    size_t i;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-blockstats", NULL)))
        return -1;

    if ((rc = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(devices = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("blockstats reply was missing device list"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValuePtr dev = virJSONValueArrayGet(devices, i);
        const char *dev_name;

        if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("blockstats device entry was not "
                             "in expected format"));
            goto cleanup;
        }

        if (!(dev_name = virJSONValueObjectGetString(dev, "device"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("blockstats device entry was not "
                             "in expected format"));
            goto cleanup;
        }

        rc = qemuMonitorJSONGetOneBlockStatsInfo(dev, dev_name, 0, hash,
                                                 backingChain);

        if (rc < 0)
            goto cleanup;

        if (rc > nstats)
            nstats = rc;
    }

    ret = nstats;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONBlockStatsUpdateCapacityOne(virJSONValuePtr image,
                                           const char *dev_name,
                                           int depth,
                                           virHashTablePtr stats,
                                           bool backingChain)
{
    qemuBlockStatsPtr bstats;
    int ret = -1;
    char *entry_name = qemuDomainStorageAlias(dev_name, depth);
    virJSONValuePtr backing;

    if (!(bstats = virHashLookup(stats, entry_name))) {
        if (VIR_ALLOC(bstats) < 0)
            goto cleanup;

        if (virHashAddEntry(stats, entry_name, bstats) < 0) {
            VIR_FREE(bstats);
            goto cleanup;
        }
    }

    /* After this point, we ignore failures; the stats were
     * zero-initialized when created which is a sane fallback.  */
    ret = 0;
    if (virJSONValueObjectGetNumberUlong(image, "virtual-size",
                                         &bstats->capacity) < 0)
        goto cleanup;

    /* if actual-size is missing, image is not thin provisioned */
    if (virJSONValueObjectGetNumberUlong(image, "actual-size",
                                         &bstats->physical) < 0)
        bstats->physical = bstats->capacity;

    if (backingChain &&
        (backing = virJSONValueObjectGetObject(image, "backing-image"))) {
        ret = qemuMonitorJSONBlockStatsUpdateCapacityOne(backing,
                                                         dev_name,
                                                         depth + 1,
                                                         stats,
                                                         true);
    }

 cleanup:
    VIR_FREE(entry_name);
    return ret;
}


int
qemuMonitorJSONBlockStatsUpdateCapacity(qemuMonitorPtr mon,
                                        virHashTablePtr stats,
                                        bool backingChain)
{
    int ret = -1;
    size_t i;
    virJSONValuePtr devices;

    if (!(devices = qemuMonitorJSONQueryBlock(mon)))
        return -1;

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValuePtr dev;
        virJSONValuePtr inserted;
        virJSONValuePtr image;
        const char *dev_name;

        if (!(dev = qemuMonitorJSONGetBlockDev(devices, i)))
            goto cleanup;

        if (!(dev_name = qemuMonitorJSONGetBlockDevDevice(dev)))
            goto cleanup;

        /* drive may be empty */
        if (!(inserted = virJSONValueObjectGetObject(dev, "inserted")) ||
            !(image = virJSONValueObjectGetObject(inserted, "image")))
            continue;

        if (qemuMonitorJSONBlockStatsUpdateCapacityOne(image, dev_name, 0,
                                                       stats,
                                                       backingChain) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(devices);
    return ret;
}


/* Return 0 on success, -1 on failure, or -2 if not supported.  Size
 * is in bytes.  */
int qemuMonitorJSONBlockResize(qemuMonitorPtr mon,
                               const char *device,
                               unsigned long long size)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block_resize",
                                     "s:device", device,
                                     "U:size", size,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = -2;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("change",
                                                     "s:device", "vnc",
                                                     "s:target", "password",
                                                     "s:arg", password,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/* Returns -1 on error, -2 if not supported */
int qemuMonitorJSONSetPassword(qemuMonitorPtr mon,
                               const char *protocol,
                               const char *password,
                               const char *action_if_connected)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("set_password",
                                                     "s:protocol", protocol,
                                                     "s:password", password,
                                                     "s:connected", action_if_connected,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = -2;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/* Returns -1 on error, -2 if not supported */
int qemuMonitorJSONExpirePassword(qemuMonitorPtr mon,
                                  const char *protocol,
                                  const char *expire_time)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("expire_password",
                                                     "s:protocol", protocol,
                                                     "s:time", expire_time,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = -2;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONSetBalloon(qemuMonitorPtr mon,
                          unsigned long long newmem)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("balloon",
                                                     "U:value", newmem * 1024,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* See if balloon soft-failed */
    if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
        qemuMonitorJSONHasError(reply, "KVMMissingCap")) {
        ret = 0;
        goto cleanup;
    }

    /* See if any other fatal error occurred */
    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    /* Real success */
    ret = 1;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSetCPU(qemuMonitorPtr mon,
                          int cpu, bool online)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    if (online) {
        cmd = qemuMonitorJSONMakeCommand("cpu-add",
                                         "i:id", cpu,
                                         NULL);
    } else {
        /* offlining is not yet implemented in qmp */
        goto fallback;
    }
    if (!cmd)
        goto cleanup;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound"))
        goto fallback;
    else
        ret = qemuMonitorJSONCheckError(cmd, reply);

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;

 fallback:
    VIR_DEBUG("no QMP support for cpu_set, trying HMP");
    ret = qemuMonitorTextSetCPU(mon, cpu, online);
    goto cleanup;
}


/**
 * Run QMP command to eject a media from ejectable device.
 *
 * Returns:
 *      -1 on error
 *      0 on success
 */
int qemuMonitorJSONEjectMedia(qemuMonitorPtr mon,
                              const char *dev_name,
                              bool force)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("eject",
                                                     "s:device", dev_name,
                                                     "b:force", force ? 1 : 0,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONChangeMedia(qemuMonitorPtr mon,
                               const char *dev_name,
                               const char *newmedia,
                               const char *format)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("change",
                                     "s:device", dev_name,
                                     "s:target", newmedia,
                                     "S:arg", format,
                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int qemuMonitorJSONSaveMemory(qemuMonitorPtr mon,
                                     const char *cmdtype,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand(cmdtype,
                                                     "U:val", offset,
                                                     "u:size", length,
                                                     "s:filename", path,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSaveVirtualMemory(qemuMonitorPtr mon,
                                     unsigned long long offset,
                                     size_t length,
                                     const char *path)
{
    return qemuMonitorJSONSaveMemory(mon, "memsave", offset, length, path);
}

int qemuMonitorJSONSavePhysicalMemory(qemuMonitorPtr mon,
                                      unsigned long long offset,
                                      size_t length,
                                      const char *path)
{
    return qemuMonitorJSONSaveMemory(mon, "pmemsave", offset, length, path);
}


int qemuMonitorJSONSetMigrationSpeed(qemuMonitorPtr mon,
                                     unsigned long bandwidth)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    cmd = qemuMonitorJSONMakeCommand("migrate_set_speed",
                                     "U:value", bandwidth * 1024ULL * 1024ULL,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSetMigrationDowntime(qemuMonitorPtr mon,
                                        unsigned long long downtime)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("migrate_set_downtime",
                                     "d:value", downtime / 1000.0,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetMigrationCacheSize(qemuMonitorPtr mon,
                                     unsigned long long *cacheSize)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    *cacheSize = 0;

    cmd = qemuMonitorJSONMakeCommand("query-migrate-cache-size", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberUlong(reply, "return", cacheSize) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-migrate-cache-size reply was missing "
                         "'return' data"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONSetMigrationCacheSize(qemuMonitorPtr mon,
                                     unsigned long long cacheSize)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("migrate-set-cache-size",
                                     "U:value", cacheSize,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetMigrationParams(qemuMonitorPtr mon,
                                  qemuMonitorMigrationParamsPtr params)
{
    int ret = -1;
    virJSONValuePtr result;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    const char *tlsStr = NULL;

    memset(params, 0, sizeof(*params));

    if (!(cmd = qemuMonitorJSONMakeCommand("query-migrate-parameters", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    result = virJSONValueObjectGet(reply, "return");

#define PARSE(VAR, FIELD)                                                   \
    do {                                                                    \
        if (virJSONValueObjectGetNumberInt(result, FIELD,                   \
                                           &params->VAR) == 0)              \
            params->VAR ## _set = true;                                     \
    } while (0)

    PARSE(compressLevel, "compress-level");
    PARSE(compressThreads, "compress-threads");
    PARSE(decompressThreads, "decompress-threads");
    PARSE(cpuThrottleInitial, "cpu-throttle-initial");
    PARSE(cpuThrottleIncrement, "cpu-throttle-increment");

#undef PARSE

    if ((tlsStr = virJSONValueObjectGetString(result, "tls-creds"))) {
        if (VIR_STRDUP(params->migrateTLSAlias, tlsStr) < 0)
            goto cleanup;
    }

    if ((tlsStr = virJSONValueObjectGetString(result, "tls-hostname"))) {
        if (VIR_STRDUP(params->migrateTLSHostname, tlsStr) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONSetMigrationParams(qemuMonitorPtr mon,
                                  qemuMonitorMigrationParamsPtr params)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr args = NULL;
    virJSONValuePtr reply = NULL;

    if (!(cmd = virJSONValueNewObject()))
        goto cleanup;

    if (virJSONValueObjectAppendString(cmd, "execute",
                                       "migrate-set-parameters") < 0)
        goto cleanup;

    if (!(args = virJSONValueNewObject()))
        goto cleanup;

#define APPEND(VAR, FIELD)                                                  \
    do {                                                                    \
        if (params->VAR ## _set &&                                          \
            virJSONValueObjectAppendNumberInt(args, FIELD,                  \
                                              params->VAR) < 0)             \
            goto cleanup;                                                   \
    } while (0)

    APPEND(compressLevel, "compress-level");
    APPEND(compressThreads, "compress-threads");
    APPEND(decompressThreads, "decompress-threads");
    APPEND(cpuThrottleInitial, "cpu-throttle-initial");
    APPEND(cpuThrottleIncrement, "cpu-throttle-increment");

#undef APPEND

    if (params->migrateTLSAlias &&
        virJSONValueObjectAppendString(args, "tls-creds",
                                       params->migrateTLSAlias) < 0)
        goto cleanup;

    if (params->migrateTLSHostname &&
        virJSONValueObjectAppendString(args, "tls-hostname",
                                       params->migrateTLSHostname) < 0)
        goto cleanup;

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0)
        goto cleanup;
    args = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(args);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONGetMigrationStatsReply(virJSONValuePtr reply,
                                      qemuMonitorMigrationStatsPtr stats)
{
    virJSONValuePtr ret;
    virJSONValuePtr ram;
    virJSONValuePtr disk;
    virJSONValuePtr comp;
    const char *statusstr;
    int rc;
    double mbps;

    ret = virJSONValueObjectGetObject(reply, "return");

    if (!(statusstr = virJSONValueObjectGetString(ret, "status"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("info migration reply was missing return status"));
        return -1;
    }

    stats->status = qemuMonitorMigrationStatusTypeFromString(statusstr);
    if (stats->status < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unexpected migration status in %s"), statusstr);
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
    case QEMU_MONITOR_MIGRATION_STATUS_ERROR:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLED:
    case QEMU_MONITOR_MIGRATION_STATUS_LAST:
        break;

    case QEMU_MONITOR_MIGRATION_STATUS_ACTIVE:
    case QEMU_MONITOR_MIGRATION_STATUS_POSTCOPY:
    case QEMU_MONITOR_MIGRATION_STATUS_COMPLETED:
    case QEMU_MONITOR_MIGRATION_STATUS_CANCELLING:
        ram = virJSONValueObjectGetObject(ret, "ram");
        if (!ram) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("migration was active, but no RAM info was set"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUlong(ram, "transferred",
                                             &stats->ram_transferred) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("migration was active, but RAM 'transferred' "
                             "data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "remaining",
                                             &stats->ram_remaining) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("migration was active, but RAM 'remaining' "
                             "data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "total",
                                             &stats->ram_total) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("migration was active, but RAM 'total' "
                             "data was missing"));
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
        ignore_value(virJSONValueObjectGetNumberUlong(ram, "dirty-sync-count",
                                                      &stats->ram_iteration));

        disk = virJSONValueObjectGetObject(ret, "disk");
        if (disk) {
            rc = virJSONValueObjectGetNumberUlong(disk, "transferred",
                                                  &stats->disk_transferred);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but "
                                 "'transferred' data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(disk, "remaining",
                                                  &stats->disk_remaining);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but 'remaining' "
                                 "data was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(disk, "total",
                                                  &stats->disk_total);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("disk migration was active, but 'total' "
                                 "data was missing"));
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
                               _("XBZRLE is active, but 'cache-size' data "
                                 "was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "bytes",
                                                  &stats->xbzrle_bytes);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'bytes' data "
                                 "was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "pages",
                                                  &stats->xbzrle_pages);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'pages' data "
                                 "was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "cache-miss",
                                                  &stats->xbzrle_cache_miss);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'cache-miss' data "
                                 "was missing"));
                return -1;
            }

            rc = virJSONValueObjectGetNumberUlong(comp, "overflow",
                                                  &stats->xbzrle_overflow);
            if (rc < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("XBZRLE is active, but 'overflow' data "
                                 "was missing"));
                return -1;
            }
        }
        break;
    }

    return 0;
}


int qemuMonitorJSONGetMigrationStats(qemuMonitorPtr mon,
                                     qemuMonitorMigrationStatsPtr stats)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-migrate",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    memset(stats, 0, sizeof(*stats));

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONGetMigrationStatsReply(reply, stats) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0)
        memset(stats, 0, sizeof(*stats));
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONMigrate(qemuMonitorPtr mon,
                           unsigned int flags,
                           const char *uri)
{
    int ret = -1;
    virJSONValuePtr cmd =
      qemuMonitorJSONMakeCommand("migrate",
                                 "b:detach", flags & QEMU_MONITOR_MIGRATE_BACKGROUND ? 1 : 0,
                                 "b:blk", flags & QEMU_MONITOR_MIGRATE_NON_SHARED_DISK ? 1 : 0,
                                 "b:inc", flags & QEMU_MONITOR_MIGRATE_NON_SHARED_INC ? 1 : 0,
                                 "s:uri", uri,
                                 NULL);
    virJSONValuePtr reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONMigrateCancel(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("migrate_cancel", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONGetDumpGuestMemoryCapability(qemuMonitorPtr mon,
                                            const char *capability)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr caps;
    virJSONValuePtr formats;
    size_t i;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-dump-guest-memory-capability",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    caps = virJSONValueObjectGetObject(reply, "return");

    if (!(formats = virJSONValueObjectGetArray(caps, "formats"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing supported dump formats"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(formats); i++) {
        virJSONValuePtr dumpformat = virJSONValueArrayGet(formats, i);

        if (!dumpformat || dumpformat->type != VIR_JSON_TYPE_STRING) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in supported dump formats"));
            goto cleanup;
        }

        if (STREQ(virJSONValueGetString(dumpformat), capability)) {
            ret = 1;
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONDump(qemuMonitorPtr mon,
                    const char *protocol,
                    const char *dumpformat)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    if (dumpformat) {
        cmd = qemuMonitorJSONMakeCommand("dump-guest-memory",
                                         "b:paging", false,
                                         "s:protocol", protocol,
                                         "s:format", dumpformat,
                                         NULL);
    } else {
        cmd = qemuMonitorJSONMakeCommand("dump-guest-memory",
                                         "b:paging", false,
                                         "s:protocol", protocol,
                                         NULL);
    }

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONGraphicsRelocate(qemuMonitorPtr mon,
                                    int type,
                                    const char *hostname,
                                    int port,
                                    int tlsPort,
                                    const char *tlsSubject)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("client_migrate_info",
                                                     "s:protocol",
                                                     (type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE ? "spice" : "vnc"),
                                                     "s:hostname", hostname,
                                                     "i:port", port,
                                                     "i:tls-port", tlsPort,
                                                     "S:cert-subject", tlsSubject,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("getfd",
                                                     "s:fdname", fdname,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("closefd",
                                                     "s:fdname", fdname,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONAddFd(qemuMonitorPtr mon, int fdset, int fd, const char *name)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("add-fd",
                                                     "i:fdset-id", fdset,
                                                     "S:opaque", name,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply);

    if (ret == 0) {
        /* qemu 1.2 lacks the functionality we need; but we have to
         * probe to find that out.  Don't log errors in that case.  */
        if (STREQ_NULLABLE(name, "/dev/null") &&
            qemuMonitorJSONHasError(reply, "GenericError")) {
            ret = -2;
            goto cleanup;
        }
        ret = qemuMonitorJSONCheckError(cmd, reply);
    }
    if (ret == 0) {
        virJSONValuePtr data = virJSONValueObjectGetObject(reply, "return");

        if (virJSONValueObjectGetNumberInt(data, "fd", &ret) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("incomplete return information"));
            goto error;
        }
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;

 error:
    /* Best effort cleanup - kill the entire fdset (even if it has
     * earlier successful fd registrations), since we don't know which
     * fd qemu got, and don't want to leave the fd leaked in qemu.  */
    qemuMonitorJSONRemoveFd(mon, fdset, -1);
    ret = -1;
    goto cleanup;
}


int
qemuMonitorJSONRemoveFd(qemuMonitorPtr mon, int fdset, int fd)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("remove-fd",
                                                     "i:fdset-id", fdset,
                                                     fd < 0 ? NULL : "i:fd",
                                                     fd, NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddNetdev(qemuMonitorPtr mon,
                             const char *netdevstr)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr args = NULL;

    cmd = qemuMonitorJSONMakeCommand("netdev_add", NULL);
    if (!cmd)
        return -1;

    args = qemuMonitorJSONKeywordStringToJSON(netdevstr, "type");
    if (!args)
        goto cleanup;

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0)
        goto cleanup;
    args = NULL; /* obj owns reference to args now */

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(args);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONRemoveNetdev(qemuMonitorPtr mon,
                                const char *alias)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("netdev_del",
                                                     "s:id", alias,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONQueryRxFilterParse(virJSONValuePtr msg,
                                  virNetDevRxFilterPtr *filter)
{
    int ret = -1;
    const char *tmp;
    virJSONValuePtr returnArray, entry, table, element;
    ssize_t nTable;
    size_t i;
    virNetDevRxFilterPtr fil = virNetDevRxFilterNew();

    if (!fil)
        goto cleanup;

    if (!(returnArray = virJSONValueObjectGetArray(msg, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-rx-filter reply was missing return data"));
        goto cleanup;
    }
    if (!(entry = virJSONValueArrayGet(returnArray, 0))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query -rx-filter return data missing array element"));
        goto cleanup;
    }

    if (!(tmp = virJSONValueObjectGetString(entry, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid name "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (VIR_STRDUP(fil->name, tmp) < 0)
        goto cleanup;
    if ((!(tmp = virJSONValueObjectGetString(entry, "main-mac"))) ||
        virMacAddrParse(tmp, &fil->mac) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'main-mac' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (virJSONValueObjectGetBoolean(entry, "promiscuous",
                                     &fil->promiscuous) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'promiscuous' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (virJSONValueObjectGetBoolean(entry, "broadcast-allowed",
                                     &fil->broadcastAllowed) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'broadcast-allowed' "
                         "in query-rx-filter response"));
        goto cleanup;
    }

    if ((!(tmp = virJSONValueObjectGetString(entry, "unicast"))) ||
        ((fil->unicast.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (virJSONValueObjectGetBoolean(entry, "unicast-overflow",
                                     &fil->unicast.overflow) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast-overflow' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if ((!(table = virJSONValueObjectGet(entry, "unicast-table"))) ||
        ((nTable = virJSONValueArraySize(table)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'unicast-table' array "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(fil->unicast.table, nTable))
        goto cleanup;
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            !(tmp = virJSONValueGetString(element))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %zu of 'unicast' "
                             "list in query-rx-filter response"), i);
            goto cleanup;
        }
        if (virMacAddrParse(tmp, &fil->unicast.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid mac address '%s' in 'unicast-table' "
                             "array in query-rx-filter response"), tmp);
            goto cleanup;
        }
    }
    fil->unicast.nTable = nTable;

    if ((!(tmp = virJSONValueObjectGetString(entry, "multicast"))) ||
        ((fil->multicast.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (virJSONValueObjectGetBoolean(entry, "multicast-overflow",
                                     &fil->multicast.overflow) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast-overflow' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if ((!(table = virJSONValueObjectGet(entry, "multicast-table"))) ||
        ((nTable = virJSONValueArraySize(table)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'multicast-table' array "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(fil->multicast.table, nTable))
        goto cleanup;
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            !(tmp = virJSONValueGetString(element))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %zu of 'multicast' "
                             "list in query-rx-filter response"), i);
            goto cleanup;
        }
        if (virMacAddrParse(tmp, &fil->multicast.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("invalid mac address '%s' in 'multicast-table' "
                             "array in query-rx-filter response"), tmp);
            goto cleanup;
        }
    }
    fil->multicast.nTable = nTable;

    if ((!(tmp = virJSONValueObjectGetString(entry, "vlan"))) ||
        ((fil->vlan.mode
          = virNetDevRxFilterModeTypeFromString(tmp)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'vlan' "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if ((!(table = virJSONValueObjectGet(entry, "vlan-table"))) ||
        ((nTable = virJSONValueArraySize(table)) < 0)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing or invalid 'vlan-table' array "
                         "in query-rx-filter response"));
        goto cleanup;
    }
    if (VIR_ALLOC_N(fil->vlan.table, nTable))
        goto cleanup;
    for (i = 0; i < nTable; i++) {
        if (!(element = virJSONValueArrayGet(table, i)) ||
            virJSONValueGetNumberUint(element, &fil->vlan.table[i]) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Missing or invalid element %zu of 'vlan-table' "
                             "array in query-rx-filter response"), i);
            goto cleanup;
        }
    }
    fil->vlan.nTable = nTable;

    ret = 0;
 cleanup:
    if (ret < 0) {
        virNetDevRxFilterFree(fil);
        fil = NULL;
    }
    *filter = fil;
    return ret;
}


int
qemuMonitorJSONQueryRxFilter(qemuMonitorPtr mon, const char *alias,
                             virNetDevRxFilterPtr *filter)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-rx-filter",
                                                     "s:name", alias,
                                                     NULL);
    virJSONValuePtr reply = NULL;

    if (!cmd)
        goto cleanup;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONQueryRxFilterParse(reply, filter) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    if (ret < 0) {
        virNetDevRxFilterFree(*filter);
        *filter = NULL;
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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
qemuMonitorJSONExtractChardevInfo(virJSONValuePtr reply,
                                  virHashTablePtr info)
{
    virJSONValuePtr data;
    int ret = -1;
    size_t i;
    qemuMonitorChardevInfoPtr entry = NULL;

    if (!(data = virJSONValueObjectGetArray(reply, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("character device reply was missing return data"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(data); i++) {
        virJSONValuePtr chardev = virJSONValueArrayGet(data, i);
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

        if (VIR_ALLOC(entry) < 0)
            goto cleanup;

        if (STRPREFIX(type, "pty:") &&
            VIR_STRDUP(entry->ptyPath, type + strlen("pty:")) < 0)
            goto cleanup;

        if (virJSONValueObjectGetBoolean(chardev, "frontend-open", &connected) == 0) {
            if (connected)
                entry->state = VIR_DOMAIN_CHR_DEVICE_STATE_CONNECTED;
            else
                entry->state = VIR_DOMAIN_CHR_DEVICE_STATE_DISCONNECTED;
        }

        if (virHashAddEntry(info, alias, entry) < 0) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("failed to add chardev '%s' info"), alias);
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
qemuMonitorJSONGetChardevInfo(qemuMonitorPtr mon,
                              virHashTablePtr info)

{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-chardev",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = qemuMonitorJSONExtractChardevInfo(reply, info);
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONDelDevice(qemuMonitorPtr mon,
                             const char *devalias)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("device_del",
                                     "s:id", devalias,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONAddDeviceArgs(qemuMonitorPtr mon,
                             virJSONValuePtr args)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("device_add", NULL)))
        goto cleanup;

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0)
        goto cleanup;
    args = NULL; /* obj owns reference to args now */

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(args);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONAddDevice(qemuMonitorPtr mon,
                         const char *devicestr)
{
    virJSONValuePtr args;

    if (!(args = qemuMonitorJSONKeywordStringToJSON(devicestr, "driver")))
        return -1;

    return qemuMonitorJSONAddDeviceArgs(mon, args);
}


int qemuMonitorJSONAddObject(qemuMonitorPtr mon,
                             const char *type,
                             const char *objalias,
                             virJSONValuePtr props)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("object-add",
                                     "s:qom-type", type,
                                     "s:id", objalias,
                                     "A:props", props,
                                     NULL);
    if (!cmd)
        goto cleanup;

    /* @props is part of @cmd now. Avoid double free */
    props = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virJSONValueFree(props);
    return ret;
}


int qemuMonitorJSONDelObject(qemuMonitorPtr mon,
                             const char *objalias)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("object-del",
                                     "s:id", objalias,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSetDrivePassphrase(qemuMonitorPtr mon,
                                      const char *alias,
                                      const char *passphrase)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block_passwd",
                                     "s:device", alias,
                                     "s:password", passphrase,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONCreateSnapshot(qemuMonitorPtr mon, const char *name)
{
    /* XXX Update to use QMP, if QMP ever adds support for savevm */
    VIR_DEBUG("savevm command not found, trying HMP");
    return qemuMonitorTextCreateSnapshot(mon, name);
}

int qemuMonitorJSONLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    /* XXX Update to use QMP, if QMP ever adds support for loadvm */
    VIR_DEBUG("loadvm command not found, trying HMP");
    return qemuMonitorTextLoadSnapshot(mon, name);
}

int qemuMonitorJSONDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    /* XXX Update to use QMP, if QMP ever adds support for delvm */
    VIR_DEBUG("delvm command not found, trying HMP");
    return qemuMonitorTextDeleteSnapshot(mon, name);
}

int
qemuMonitorJSONDiskSnapshot(qemuMonitorPtr mon, virJSONValuePtr actions,
                            const char *device, const char *file,
                            const char *format, bool reuse)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommandRaw(actions != NULL,
                                        "blockdev-snapshot-sync",
                                        "s:device", device,
                                        "s:snapshot-file", file,
                                        "s:format", format,
                                        "S:mode", reuse ? "existing" : NULL,
                                        NULL);
    if (!cmd)
        return -1;

    if (actions) {
        if (virJSONValueArrayAppend(actions, cmd) == 0) {
            ret = 0;
            cmd = NULL;
        }
    } else {
        if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
            goto cleanup;

        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/* speed is in bytes/sec */
int
qemuMonitorJSONDriveMirror(qemuMonitorPtr mon,
                           const char *device, const char *file,
                           const char *format, unsigned long long speed,
                           unsigned int granularity,
                           unsigned long long buf_size,
                           unsigned int flags)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    bool shallow = (flags & VIR_DOMAIN_BLOCK_REBASE_SHALLOW) != 0;
    bool reuse = (flags & VIR_DOMAIN_BLOCK_REBASE_REUSE_EXT) != 0;

    cmd = qemuMonitorJSONMakeCommand("drive-mirror",
                                     "s:device", device,
                                     "s:target", file,
                                     "Y:speed", speed,
                                     "z:granularity", granularity,
                                     "P:buf-size", buf_size,
                                     "s:sync", shallow ? "top" : "full",
                                     "s:mode", reuse ? "existing" : "absolute-paths",
                                     "S:format", format,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONTransaction(qemuMonitorPtr mon, virJSONValuePtr actions)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    bool protect = actions->protect;

    /* We do NOT want to free actions when recursively freeing cmd.  */
    actions->protect = true;
    cmd = qemuMonitorJSONMakeCommand("transaction",
                                     "a:actions", actions,
                                     NULL);
    if (!cmd)
        goto cleanup;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    actions->protect = protect;
    return ret;
}

/* speed is in bytes/sec. Returns 0 on success, -1 with error message
 * emitted on failure.
 *
 * Additionally, can be used to probe if active commit is supported:
 * pass in a bogus device and NULL top and base.  The probe return is
 * -2 if active commit is detected, -3 if inconclusive; with no error
 * message issued.
 */
int
qemuMonitorJSONBlockCommit(qemuMonitorPtr mon, const char *device,
                           const char *top, const char *base,
                           const char *backingName,
                           unsigned long long speed)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block-commit",
                                     "s:device", device,
                                     "Y:speed", speed,
                                     "S:top", top,
                                     "S:base", base,
                                     "S:backing-file", backingName,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;
    if (!top && !base) {
        /* Normally we always specify top and base; but omitting them
         * allows for probing whether qemu is new enough to support
         * live commit.  */
        if (qemuMonitorJSONHasError(reply, "DeviceNotFound")) {
            VIR_DEBUG("block-commit supports active commit");
            ret = -2;
        } else {
            /* This is a false negative for qemu 2.0; but probably not
             * worth the additional complexity to worry about it */
            VIR_DEBUG("block-commit requires 'top' parameter, "
                      "assuming it lacks active commit");
            ret = -3;
        }
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONDrivePivot(qemuMonitorPtr mon,
                          const char *device)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block-job-complete",
                                     "s:device", device,
                                     NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static char *
qemuMonitorJSONDiskNameLookupOne(virJSONValuePtr image,
                                 virStorageSourcePtr top,
                                 virStorageSourcePtr target)
{
    virJSONValuePtr backing;
    char *ret;

    /* The caller will report a generic message if we return NULL
     * without an error; but in some cases we can improve by reporting
     * a more specific message.  */
    if (!top || !image)
        return NULL;
    if (top != target) {
        backing = virJSONValueObjectGetObject(image, "backing-image");
        return qemuMonitorJSONDiskNameLookupOne(backing, top->backingStore,
                                                target);
    }
    if (VIR_STRDUP(ret, virJSONValueObjectGetString(image, "filename")) < 0)
        return NULL;
    /* Sanity check - the name qemu gave us should resolve to the same
       file tracked by our target description. */
    if (virStorageSourceIsLocalStorage(target) &&
        STRNEQ(ret, target->path) &&
        !virFileLinkPointsTo(ret, target->path)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qemu block name '%s' doesn't match expected '%s'"),
                       ret, target->path);
        VIR_FREE(ret);
    }
    return ret;
}


char *
qemuMonitorJSONDiskNameLookup(qemuMonitorPtr mon,
                              const char *device,
                              virStorageSourcePtr top,
                              virStorageSourcePtr target)
{
    char *ret = NULL;
    virJSONValuePtr devices;
    size_t i;

    if (!(devices = qemuMonitorJSONQueryBlock(mon)))
        return NULL;

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValuePtr dev;
        virJSONValuePtr inserted;
        virJSONValuePtr image;
        const char *thisdev;

        if (!(dev = qemuMonitorJSONGetBlockDev(devices, i)))
            goto cleanup;

        if (!(thisdev = qemuMonitorJSONGetBlockDevDevice(dev)))
            goto cleanup;

        if (STREQ(thisdev, device)) {
            if ((inserted = virJSONValueObjectGetObject(dev, "inserted")) &&
                (image = virJSONValueObjectGetObject(inserted, "image"))) {
                ret = qemuMonitorJSONDiskNameLookupOne(image, top, target);
            }
            break;
        }
    }
    /* Guarantee an error when returning NULL, but don't override a
     * more specific error if one was already generated.  */
    if (!ret && !virGetLastError())
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to find backing name for device %s"),
                       device);

 cleanup:
    virJSONValueFree(devices);

    return ret;
}


int qemuMonitorJSONArbitraryCommand(qemuMonitorPtr mon,
                                    const char *cmd_str,
                                    char **reply_str,
                                    bool hmp)
{
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    int ret = -1;

    if (hmp) {
        return qemuMonitorJSONHumanCommandWithFd(mon, cmd_str, -1, reply_str);
    } else {
        if (!(cmd = virJSONValueFromString(cmd_str)))
            goto cleanup;

        if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
            goto cleanup;

        if (!(*reply_str = virJSONValueToString(reply, false)))
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONInjectNMI(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("inject-nmi", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        VIR_DEBUG("inject-nmi command not found, trying HMP");
        if (qemuMonitorTextInjectNMI(mon) < 0)
            goto cleanup;
    } else {
        if (qemuMonitorJSONCheckError(cmd, reply) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSendKey(qemuMonitorPtr mon,
                           unsigned int holdtime,
                           unsigned int *keycodes,
                           unsigned int nkeycodes)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr keys = NULL;
    virJSONValuePtr key = NULL;
    size_t i;

    /* create the key data array */
    if (!(keys = virJSONValueNewArray()))
        goto cleanup;

    for (i = 0; i < nkeycodes; i++) {
        if (keycodes[i] > 0xffff) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("keycode %zu is invalid: 0x%X"), i, keycodes[i]);
            goto cleanup;
        }

        /* create single key object */
        if (!(key = virJSONValueNewObject()))
            goto cleanup;

        /* Union KeyValue has two types, use the generic one */
        if (virJSONValueObjectAppendString(key, "type", "number") < 0)
            goto cleanup;

        /* with the keycode */
        if (virJSONValueObjectAppendNumberInt(key, "data", keycodes[i]) < 0)
            goto cleanup;

        if (virJSONValueArrayAppend(keys, key) < 0)
            goto cleanup;

        key = NULL;

    }

    cmd = qemuMonitorJSONMakeCommand("send-key",
                                     "a:keys", keys,
                                     "p:hold-time", holdtime,
                                     NULL);
    if (!cmd)
        goto cleanup;

    /* @keys is part of @cmd now. Avoid double free */
    keys = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        VIR_DEBUG("send-key command not found, trying HMP");
        if (qemuMonitorTextSendKey(mon, holdtime, keycodes, nkeycodes) < 0)
            goto cleanup;
    } else {
        if (qemuMonitorJSONCheckError(cmd, reply) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virJSONValueFree(keys);
    virJSONValueFree(key);
    return ret;
}

int qemuMonitorJSONScreendump(qemuMonitorPtr mon,
                              const char *file)
{
    int ret = -1;
    virJSONValuePtr cmd, reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("screendump",
                                     "s:filename", file,
                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONParseBlockJobInfo(virHashTablePtr blockJobs,
                                 virJSONValuePtr entry)
{
    qemuMonitorBlockJobInfoPtr info = NULL;
    const char *device;
    const char *type;
    bool ready;

    if (!(device = virJSONValueObjectGetString(entry, "device"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("entry was missing 'device'"));
        return -1;
    }
    device = qemuAliasDiskDriveSkipPrefix(device);

    if (VIR_ALLOC(info) < 0 ||
        virHashAddEntry(blockJobs, device, info) < 0) {
        VIR_FREE(info);
        return -1;
    }

    /* assume we don't know the state */
    info->ready = -1;

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

    if (virJSONValueObjectGetBoolean(entry, "ready", &ready) == 0)
        info->ready = ready;

    return 0;
}

virHashTablePtr
qemuMonitorJSONGetAllBlockJobInfo(qemuMonitorPtr mon)
{
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    ssize_t nr_results;
    size_t i;
    virHashTablePtr blockJobs = NULL;

    cmd = qemuMonitorJSONMakeCommand("query-block-jobs", NULL);
    if (!cmd)
        return NULL;
    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if ((data = virJSONValueObjectGetArray(reply, "return")) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("reply was missing return data"));
        goto cleanup;
    }

    if ((nr_results = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to determine array size"));
        goto cleanup;
    }

    if (!(blockJobs = virHashCreate(nr_results, virHashValueFree)))
        goto cleanup;

    for (i = 0; i < nr_results; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        if (!entry) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing array element"));
            goto error;
        }
        if (qemuMonitorJSONParseBlockJobInfo(blockJobs, entry) < 0)
            goto error;
    }

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return blockJobs;

 error:
    virHashFree(blockJobs);
    blockJobs = NULL;
    goto cleanup;
}


static int
qemuMonitorJSONBlockJobError(virJSONValuePtr reply,
                             const char *cmd_name,
                             const char *device)
{
    virJSONValuePtr error;

    if (!(error = virJSONValueObjectGet(reply, "error")))
        return 0;

    if (qemuMonitorJSONErrorIsClass(error, "DeviceNotActive")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("No active operation on device: %s"), device);
    } else if (qemuMonitorJSONErrorIsClass(error, "DeviceInUse")) {
        virReportError(VIR_ERR_OPERATION_FAILED,
                       _("Device %s in use"), device);
    } else if (qemuMonitorJSONErrorIsClass(error, "NotSupported")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Operation is not supported for device: %s"), device);
    } else if (qemuMonitorJSONErrorIsClass(error, "CommandNotFound")) {
        virReportError(VIR_ERR_OPERATION_INVALID,
                       _("Command '%s' is not found"), cmd_name);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unexpected error: (%s) '%s'"),
                       NULLSTR(virJSONValueObjectGetString(error, "class")),
                       NULLSTR(virJSONValueObjectGetString(error, "desc")));
    }

    return -1;
}


/* speed is in bytes/sec */
int
qemuMonitorJSONBlockStream(qemuMonitorPtr mon,
                           const char *device,
                           const char *base,
                           const char *backingName,
                           unsigned long long speed,
                           bool modern)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    const char *cmd_name = modern ? "block-stream" : "block_stream";

    if (!(cmd = qemuMonitorJSONMakeCommand(cmd_name,
                                           "s:device", device,
                                           "Y:speed", speed,
                                           "S:base", base,
                                           "S:backing-file", backingName,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONBlockJobError(reply, cmd_name, device) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONBlockJobCancel(qemuMonitorPtr mon,
                              const char *device,
                              bool modern)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    const char *cmd_name = modern ? "block-job-cancel" : "block_job_cancel";

    if (!(cmd = qemuMonitorJSONMakeCommand(cmd_name,
                                           "s:device", device,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONBlockJobError(reply, cmd_name, device) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONBlockJobSetSpeed(qemuMonitorPtr mon,
                                const char *device,
                                unsigned long long speed,
                                bool modern)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    const char *cmd_name = modern ? "block-job-set-speed" : "block_job_set_speed";

    if (!(cmd = qemuMonitorJSONMakeCommand(cmd_name,
                                           "s:device", device,
                                           modern ? "J:speed" : "J:value", speed,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONBlockJobError(reply, cmd_name, device) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONOpenGraphics(qemuMonitorPtr mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth)
{
    int ret = -1;
    virJSONValuePtr cmd, reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("add_client",
                                     "s:protocol", protocol,
                                     "s:fdname", fdname,
                                     "b:skipauth", skipauth,
                                     NULL);

    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


#define GET_THROTTLE_STATS_OPTIONAL(FIELD, STORE)                             \
    if (virJSONValueObjectGetNumberUlong(inserted,                            \
                                         FIELD,                               \
                                         &reply->STORE) < 0) {                \
        reply->STORE = 0;                                                     \
    }
#define GET_THROTTLE_STATS(FIELD, STORE)                                      \
    if (virJSONValueObjectGetNumberUlong(inserted,                            \
                                         FIELD,                               \
                                         &reply->STORE) < 0) {                \
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,                         \
                       _("block_io_throttle field '%s' missing "              \
                         "in qemu's output"),                                 \
                       #STORE);                                               \
        goto cleanup;                                                         \
    }
static int
qemuMonitorJSONBlockIoThrottleInfo(virJSONValuePtr result,
                                   const char *device,
                                   virDomainBlockIoTuneInfoPtr reply)
{
    virJSONValuePtr io_throttle;
    int ret = -1;
    size_t i;
    bool found = false;

    if (!(io_throttle = virJSONValueObjectGetArray(result, "return"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _(" block_io_throttle reply was missing device list"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(io_throttle); i++) {
        virJSONValuePtr temp_dev = virJSONValueArrayGet(io_throttle, i);
        virJSONValuePtr inserted;
        const char *current_dev;

        if (!temp_dev || temp_dev->type != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle device entry "
                             "was not in expected format"));
            goto cleanup;
        }

        if (!(current_dev = virJSONValueObjectGetString(temp_dev, "device"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle device entry "
                             "was not in expected format"));
            goto cleanup;
        }

        if (STRNEQ(current_dev, device))
            continue;

        found = true;
        if (!(inserted = virJSONValueObjectGetObject(temp_dev, "inserted"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("block_io_throttle inserted entry "
                             "was not in expected format"));
            goto cleanup;
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

        if (VIR_STRDUP(reply->group_name,
                       virJSONValueObjectGetString(inserted, "group")) < 0)
            goto cleanup;

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
                       _("cannot find throttling info for device '%s'"),
                       device);
        goto cleanup;
    }
    ret = 0;

 cleanup:
    return ret;
}
#undef GET_THROTTLE_STATS
#undef GET_THROTTLE_STATS_OPTIONAL

int qemuMonitorJSONSetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr info,
                                      bool supportMaxOptions,
                                      bool supportGroupNameOption,
                                      bool supportMaxLengthOptions)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr result = NULL;
    virJSONValuePtr args = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("block_set_io_throttle", NULL)))
        return -1;

    if (virJSONValueObjectCreate(&args,
                                 "s:device", device,
                                 "U:bps", info->total_bytes_sec,
                                 "U:bps_rd", info->read_bytes_sec,
                                 "U:bps_wr", info->write_bytes_sec,
                                 "U:iops", info->total_iops_sec,
                                 "U:iops_rd", info->read_iops_sec,
                                 "U:iops_wr", info->write_iops_sec,
                                 NULL) < 0)
        goto cleanup;

    if (supportMaxOptions &&
        virJSONValueObjectAdd(args,
                              "U:bps_max", info->total_bytes_sec_max,
                              "U:bps_rd_max", info->read_bytes_sec_max,
                              "U:bps_wr_max", info->write_bytes_sec_max,
                              "U:iops_max", info->total_iops_sec_max,
                              "U:iops_rd_max", info->read_iops_sec_max,
                              "U:iops_wr_max", info->write_iops_sec_max,
                              "U:iops_size", info->size_iops_sec,
                              NULL) < 0)
        goto cleanup;

    if (supportGroupNameOption &&
        virJSONValueObjectAdd(args,
                              "S:group", info->group_name,
                              NULL) < 0)
        goto cleanup;

    if (supportMaxLengthOptions &&
        virJSONValueObjectAdd(args,
                              "P:bps_max_length",
                              info->total_bytes_sec_max_length,
                              "P:bps_rd_max_length",
                              info->read_bytes_sec_max_length,
                              "P:bps_wr_max_length",
                              info->write_bytes_sec_max_length,
                              "P:iops_max_length",
                              info->total_iops_sec_max_length,
                              "P:iops_rd_max_length",
                              info->read_iops_sec_max_length,
                              "P:iops_wr_max_length",
                              info->write_iops_sec_max_length,
                              NULL) < 0)
        goto cleanup;

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0)
        goto cleanup;
    args = NULL; /* obj owns reference to args now */

    if (qemuMonitorJSONCommand(mon, cmd, &result) < 0)
        goto cleanup;

    if (virJSONValueObjectHasKey(result, "error")) {
        if (qemuMonitorJSONHasError(result, "DeviceNotActive")) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("No active operation on device: %s"), device);
        } else if (qemuMonitorJSONHasError(result, "NotSupported")) {
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Operation is not supported for device: %s"), device);
        } else {
            virJSONValuePtr error = virJSONValueObjectGet(result, "error");
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unable to execute '%s', unexpected error: '%s'"),
                           qemuMonitorJSONCommandName(cmd),
                           qemuMonitorJSONStringifyError(error));
        }
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(result);
    virJSONValueFree(args);
    return ret;
}

int qemuMonitorJSONGetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr reply)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr result = NULL;

    cmd = qemuMonitorJSONMakeCommand("query-block", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &result) < 0)
        goto cleanup;

    if (virJSONValueObjectHasKey(result, "error")) {
        if (qemuMonitorJSONHasError(result, "DeviceNotActive"))
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("No active operation on device: %s"), device);
        else if (qemuMonitorJSONHasError(result, "NotSupported"))
            virReportError(VIR_ERR_OPERATION_INVALID,
                           _("Operation is not supported for device: %s"), device);
        else
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unexpected error"));
        goto cleanup;
    }

    ret = qemuMonitorJSONBlockIoThrottleInfo(result, device, reply);
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(result);
    return ret;
}

int qemuMonitorJSONSystemWakeup(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("system_wakeup", NULL);
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONGetVersion(qemuMonitorPtr mon,
                              int *major,
                              int *minor,
                              int *micro,
                              char **package)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    virJSONValuePtr qemu;

    *major = *minor = *micro = 0;
    if (package)
        *package = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-version", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (!(qemu = virJSONValueObjectGetObject(data, "qemu"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'qemu' data"));
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberInt(qemu, "major", major) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'major' version"));
        goto cleanup;
    }
    if (virJSONValueObjectGetNumberInt(qemu, "minor", minor) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'minor' version"));
        goto cleanup;
    }
    if (virJSONValueObjectGetNumberInt(qemu, "micro", micro) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-version reply was missing 'micro' version"));
        goto cleanup;
    }

    if (package) {
        const char *tmp;
        if (!(tmp = virJSONValueObjectGetString(data, "package"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-version reply was missing 'package' version"));
            goto cleanup;
        }
        if (VIR_STRDUP(*package, tmp) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetMachines(qemuMonitorPtr mon,
                               qemuMonitorMachineInfoPtr **machines)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    qemuMonitorMachineInfoPtr *infolist = NULL;
    ssize_t n = 0;
    size_t i;

    *machines = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-machines", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-machines reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(infolist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorMachineInfoPtr info;

        if (VIR_ALLOC(info) < 0)
            goto cleanup;

        infolist[i] = info;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-machines reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(info->name, tmp) < 0)
            goto cleanup;

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
            if (VIR_STRDUP(info->alias, tmp) < 0)
                goto cleanup;
        }
        if (virJSONValueObjectHasKey(child, "cpu-max") &&
            virJSONValueObjectGetNumberUint(child, "cpu-max", &info->maxCpus) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-machines reply has malformed 'cpu-max' data"));
            goto cleanup;
        }

        ignore_value(virJSONValueObjectGetBoolean(child, "hotpluggable-cpus",
                                                  &info->hotplugCpus));
    }

    ret = n;
    *machines = infolist;
    infolist = NULL;

 cleanup:
    if (infolist) {
        for (i = 0; i < n; i++)
            qemuMonitorMachineInfoFree(infolist[i]);
        VIR_FREE(infolist);
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetCPUDefinitions(qemuMonitorPtr mon,
                                 qemuMonitorCPUDefInfoPtr **cpus)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    qemuMonitorCPUDefInfoPtr *cpulist = NULL;
    int n = 0;
    size_t i;

    *cpus = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-cpu-definitions", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* Urgh, some QEMU architectures have the query-cpu-definitions
     * command, but return 'GenericError' with string "Not supported",
     * instead of simply omitting the command entirely :-(
     */
    if (qemuMonitorJSONHasError(reply, "GenericError")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-cpu-definitions reply data was not an array"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(cpulist, n) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorCPUDefInfoPtr cpu;

        if (VIR_ALLOC(cpu) < 0)
            goto cleanup;

        cpulist[i] = cpu;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-cpu-definitions reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(cpu->name, tmp) < 0)
            goto cleanup;

        if (virJSONValueObjectHasKey(child, "unavailable-features")) {
            virJSONValuePtr blockers;

            blockers = virJSONValueObjectGetArray(child,
                                                  "unavailable-features");
            if (!blockers) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("unavailable-features in query-cpu-definitions "
                                 "reply data was not an array"));
                goto cleanup;
            }

            if (virJSONValueArraySize(blockers) > 0)
                cpu->usable = VIR_TRISTATE_BOOL_NO;
            else
                cpu->usable = VIR_TRISTATE_BOOL_YES;
        }
    }

    ret = n;
    *cpus = cpulist;
    cpulist = NULL;

 cleanup:
    if (cpulist) {
        for (i = 0; i < n; i++)
            qemuMonitorCPUDefInfoFree(cpulist[i]);
        VIR_FREE(cpulist);
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


VIR_ENUM_IMPL(qemuMonitorCPUProperty,
              QEMU_MONITOR_CPU_PROPERTY_LAST,
              "boolean", "string", "number")

static int
qemuMonitorJSONParseCPUModelProperty(const char *key,
                                     virJSONValue *value,
                                     void *opaque)
{
    qemuMonitorCPUModelInfoPtr machine_model = opaque;
    qemuMonitorCPUPropertyPtr prop;

    prop = machine_model->props + machine_model->nprops;

    switch ((virJSONType) value->type) {
    case VIR_JSON_TYPE_STRING:
        if (VIR_STRDUP(prop->value.string, virJSONValueGetString(value)) < 0)
            return -1;
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
    if (VIR_STRDUP(prop->name, key) < 0)
        return -1;

    return 0;
}

int
qemuMonitorJSONGetCPUModelExpansion(qemuMonitorPtr mon,
                                    qemuMonitorCPUModelExpansionType type,
                                    const char *model_name,
                                    bool migratable,
                                    qemuMonitorCPUModelInfoPtr *model_info)
{
    int ret = -1;
    virJSONValuePtr model = NULL;
    virJSONValuePtr props = NULL;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    virJSONValuePtr cpu_model;
    virJSONValuePtr cpu_props;
    qemuMonitorCPUModelInfoPtr machine_model = NULL;
    char const *cpu_name;
    const char *typeStr = "";

    *model_info = NULL;

    if (!(model = virJSONValueNewObject()))
        goto cleanup;

    if (virJSONValueObjectAppendString(model, "name", model_name) < 0)
        goto cleanup;

    if (!migratable) {
        if (!(props = virJSONValueNewObject()) ||
            virJSONValueObjectAppendBoolean(props, "migratable", false) < 0 ||
            virJSONValueObjectAppend(model, "props", props) < 0)
            goto cleanup;
        props = NULL;
    }

 retry:
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
        goto cleanup;

    /* model will be freed when cmd is freed. we set model
     * to NULL to avoid double freeing.
     */
    model = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* Even though query-cpu-model-expansion is advertised by query-commands it
     * may just return GenericError if it is not implemented for the requested
     * guest architecture or it is not supported in the host environment.
     */
    if (qemuMonitorJSONHasError(reply, "GenericError")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (!(cpu_model = virJSONValueObjectGetObject(data, "model"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-cpu-model-expansion reply data was missing 'model'"));
        goto cleanup;
    }

    /* QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL requests "full" expansion
     * on the result of the initial "static" expansion.
     */
    if (type == QEMU_MONITOR_CPU_MODEL_EXPANSION_STATIC_FULL) {
        if (!(model = virJSONValueCopy(cpu_model)))
            goto cleanup;

        virJSONValueFree(cmd);
        virJSONValueFree(reply);
        type = QEMU_MONITOR_CPU_MODEL_EXPANSION_FULL;
        goto retry;
    }

    if (!(cpu_name = virJSONValueObjectGetString(cpu_model, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-cpu-model-expansion reply data was missing 'name'"));
        goto cleanup;
    }

    if (!(cpu_props = virJSONValueObjectGetObject(cpu_model, "props"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-cpu-model-expansion reply data was missing 'props'"));
        goto cleanup;
    }

    if (VIR_ALLOC(machine_model) < 0)
        goto cleanup;

    if (VIR_STRDUP(machine_model->name, cpu_name) < 0)
        goto cleanup;

    if (VIR_ALLOC_N(machine_model->props, cpu_props->data.object.npairs) < 0)
        goto cleanup;

    if (virJSONValueObjectForeachKeyValue(cpu_props,
                                          qemuMonitorJSONParseCPUModelProperty,
                                          machine_model) < 0)
        goto cleanup;

    ret = 0;
    *model_info = machine_model;
    machine_model = NULL;

 cleanup:
    qemuMonitorCPUModelInfoFree(machine_model);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virJSONValueFree(model);
    virJSONValueFree(props);
    return ret;
}


int qemuMonitorJSONGetCommands(qemuMonitorPtr mon,
                               char ***commands)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    char **commandlist = NULL;
    ssize_t n = 0;
    size_t i;

    *commands = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-commands", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-commands reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(commandlist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-commands reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(commandlist[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *commands = commandlist;
    commandlist = NULL;


 cleanup:
    virStringListFree(commandlist);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetEvents(qemuMonitorPtr mon,
                             char ***events)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    char **eventlist = NULL;
    ssize_t n = 0;
    size_t i;

    *events = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-events", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-events reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(eventlist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-events reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(eventlist[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *events = eventlist;
    eventlist = NULL;

 cleanup:
    virStringListFree(eventlist);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetCommandLineOptionParameters(qemuMonitorPtr mon,
                                              const char *option,
                                              char ***params,
                                              bool *found)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;
    virJSONValuePtr array = NULL;
    char **paramlist = NULL;
    ssize_t n = 0;
    size_t i;

    *params = NULL;
    if (found)
        *found = false;

    /* query-command-line-options has fixed output for a given qemu
     * binary; but since callers want to query parameters for one
     * option at a time, we cache the option list from qemu.  */
    if (!(array = qemuMonitorGetOptions(mon))) {
        if (!(cmd = qemuMonitorJSONMakeCommand("query-command-line-options",
                                               NULL)))
            return -1;

        if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
            goto cleanup;

        if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
            ret = 0;
            goto cleanup;
        }

        if (qemuMonitorJSONCheckError(cmd, reply) < 0)
            goto cleanup;

        if (virJSONValueObjectRemoveKey(reply, "return", &array) <= 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-command-line-options reply was missing "
                             "return data"));
            goto cleanup;
        }
        qemuMonitorSetOptions(mon, array);
    }

    if ((n = virJSONValueArraySize(array)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-command-line-options reply data was not "
                         "an array"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(array, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "option"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-command-line-options reply data was "
                             "missing 'option'"));
            goto cleanup;
        }
        if (STREQ(tmp, option)) {
            data = virJSONValueObjectGet(child, "parameters");
            break;
        }
    }

    if (!data) {
        /* Option not found; return 0 parameters rather than an error.  */
        ret = 0;
        goto cleanup;
    }

    if (found)
        *found = true;

    if ((n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-command-line-options parameter data was not "
                         "an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(paramlist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-command-line-options parameter data was "
                             "missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(paramlist[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *params = paramlist;
    paramlist = NULL;

 cleanup:
    /* If we failed before getting the JSON array of options, we (try)
     * to cache an empty array to speed up the next failure.  */
    if (!qemuMonitorGetOptions(mon))
        qemuMonitorSetOptions(mon, virJSONValueNewArray());

    virStringListFree(paramlist);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetKVMState(qemuMonitorPtr mon,
                               bool *enabled,
                               bool *present)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;

    /* Safe defaults */
    *enabled = *present = false;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-kvm", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (virJSONValueObjectGetBoolean(data, "enabled", enabled) < 0 ||
        virJSONValueObjectGetBoolean(data, "present", present) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-kvm replied unexpected data"));
        goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetObjectTypes(qemuMonitorPtr mon,
                                  char ***types)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    char **typelist = NULL;
    ssize_t n = 0;
    size_t i;

    *types = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list-types", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qom-list-types reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(typelist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qom-list-types reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(typelist[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *types = typelist;
    typelist = NULL;

 cleanup:
    virStringListFree(typelist);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetObjectListPaths(qemuMonitorPtr mon,
                                      const char *path,
                                      qemuMonitorJSONListPathPtr **paths)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    qemuMonitorJSONListPathPtr *pathlist = NULL;
    ssize_t n = 0;
    size_t i;

    *paths = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list",
                                           "s:path", path,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qom-list reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(pathlist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorJSONListPathPtr info;

        if (VIR_ALLOC(info) < 0)
            goto cleanup;

        pathlist[i] = info;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qom-list reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(info->name, tmp) < 0)
            goto cleanup;

        if (virJSONValueObjectHasKey(child, "type")) {
            if (!(tmp = virJSONValueObjectGetString(child, "type"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("qom-list reply has malformed 'type' data"));
                goto cleanup;
            }
            if (VIR_STRDUP(info->type, tmp) < 0)
                goto cleanup;
        }
    }

    ret = n;
    *paths = pathlist;
    pathlist = NULL;

 cleanup:
    if (pathlist) {
        for (i = 0; i < n; i++)
            qemuMonitorJSONListPathFree(pathlist[i]);
        VIR_FREE(pathlist);
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

void qemuMonitorJSONListPathFree(qemuMonitorJSONListPathPtr paths)
{
    if (!paths)
        return;
    VIR_FREE(paths->name);
    VIR_FREE(paths->type);
    VIR_FREE(paths);
}


int qemuMonitorJSONGetObjectProperty(qemuMonitorPtr mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectPropertyPtr prop)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    const char *tmp;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", path,
                                           "s:property", property,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

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
        if (tmp && VIR_STRDUP(prop->val.str, tmp) < 0)
            goto cleanup;
        if (tmp)
            ret = 0;
        break;
    case QEMU_MONITOR_OBJECT_PROPERTY_LAST:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("qom-get invalid object property type %d"),
                       prop->type);
        goto cleanup;
        break;
    }

    if (ret == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qom-get reply was missing return data"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}


#define MAKE_SET_CMD(STRING, VALUE)                                   \
    cmd = qemuMonitorJSONMakeCommand("qom-set",                       \
                                      "s:path", path,                 \
                                      "s:property", property,         \
                                      STRING, VALUE,                  \
                                      NULL)
int qemuMonitorJSONSetObjectProperty(qemuMonitorPtr mon,
                                     const char *path,
                                     const char *property,
                                     qemuMonitorJSONObjectPropertyPtr prop)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;

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
                       _("qom-set invalid object property type %d"),
                       prop->type);
        goto cleanup;

    }
    if (!cmd)
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}
#undef MAKE_SET_CMD


int qemuMonitorJSONGetObjectProps(qemuMonitorPtr mon,
                                  const char *type,
                                  char ***props)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    char **proplist = NULL;
    ssize_t n = 0;
    size_t i;

    *props = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("device-list-properties",
                                           "s:typename", type,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "DeviceNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("device-list-properties reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(proplist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueObjectGetString(child, "name"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("device-list-properties reply data was missing 'name'"));
            goto cleanup;
        }

        if (VIR_STRDUP(proplist[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *props = proplist;
    proplist = NULL;

 cleanup:
    virStringListFree(proplist);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


char *
qemuMonitorJSONGetTargetArch(qemuMonitorPtr mon)
{
    char *ret = NULL;
    const char *arch;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-target", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGetObject(reply, "return");

    if (!(arch = virJSONValueObjectGetString(data, "arch"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-target reply was missing arch data"));
        goto cleanup;
    }

    ignore_value(VIR_STRDUP(ret, arch));

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetMigrationCapabilities(qemuMonitorPtr mon,
                                        char ***capabilities)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr caps;
    char **list = NULL;
    size_t i;
    ssize_t n;

    *capabilities = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-migrate-capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(caps = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(caps)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing migration capabilities"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(list, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr cap = virJSONValueArrayGet(caps, i);
        const char *name;

        if (!cap || cap->type != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in migration capabilities list"));
            goto cleanup;
        }

        if (!(name = virJSONValueObjectGetString(cap, "capability"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing migration capability name"));
            goto cleanup;
        }

        if (VIR_STRDUP(list[i], name) < 1)
            goto cleanup;
    }

    ret = n;
    *capabilities = list;
    list = NULL;

 cleanup:
    virStringListFree(list);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetMigrationCapability(qemuMonitorPtr mon,
                                      qemuMonitorMigrationCaps capability)
{
    int ret;
    char **capsList = NULL;
    const char *cap = qemuMonitorMigrationCapsTypeToString(capability);

    if (qemuMonitorJSONGetMigrationCapabilities(mon, &capsList) < 0)
        return -1;

    ret = virStringListHasString((const char **) capsList, cap);

    virStringListFree(capsList);
    return ret;
}


int
qemuMonitorJSONSetMigrationCapability(qemuMonitorPtr mon,
                                      qemuMonitorMigrationCaps capability,
                                      bool state)
{
    int ret = -1;

    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr cap = NULL;
    virJSONValuePtr caps;

    if (!(caps = virJSONValueNewArray()))
        goto cleanup;

    if (!(cap = virJSONValueNewObject()))
        goto cleanup;

    if (virJSONValueObjectAppendString(
                cap, "capability",
                qemuMonitorMigrationCapsTypeToString(capability)) < 0)
        goto cleanup;

    if (virJSONValueObjectAppendBoolean(cap, "state", state) < 0)
        goto cleanup;

    if (virJSONValueArrayAppend(caps, cap) < 0)
        goto cleanup;

    cap = NULL;

    cmd = qemuMonitorJSONMakeCommand("migrate-set-capabilities",
                                     "a:capabilities", caps,
                                     NULL);
    if (!cmd)
        goto cleanup;

    caps = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(caps);
    virJSONValueFree(cap);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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
qemuMonitorJSONGetGICCapabilities(qemuMonitorPtr mon,
                                  virGICCapability **capabilities)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr caps;
    virGICCapability *list = NULL;
    size_t i;
    ssize_t n;

    *capabilities = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-gic-capabilities",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    /* If the 'query-gic-capabilities' QMP command was not available
     * we simply successfully return zero capabilities.
     * This is the case for QEMU <2.6 and all non-ARM architectures */
    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(caps = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(caps)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing GIC capabilities"));
        goto cleanup;
    }

    /* If the returned array was empty we have to return successfully */
    if (n == 0) {
        ret = 0;
        goto cleanup;
    }

    if (VIR_ALLOC_N(list, n) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr cap = virJSONValueArrayGet(caps, i);
        int version;
        bool kernel;
        bool emulated;

        if (!cap || cap->type != VIR_JSON_TYPE_OBJECT) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing entry in GIC capabilities list"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(cap, "version", &version) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing GIC version"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(cap, "kernel", &kernel) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing in-kernel GIC information"));
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(cap, "emulated", &emulated) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("missing emulated GIC information"));
            goto cleanup;
        }

        list[i].version = version;
        if (kernel)
            list[i].implementation |= VIR_GIC_IMPLEMENTATION_KERNEL;
        if (emulated)
            list[i].implementation |= VIR_GIC_IMPLEMENTATION_EMULATED;
    }

    ret = n;
    *capabilities = list;
    list = NULL;

 cleanup:
    VIR_FREE(list);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}

static virJSONValuePtr
qemuMonitorJSONBuildInetSocketAddress(const char *host,
                                      const char *port)
{
    virJSONValuePtr addr = NULL;
    virJSONValuePtr data = NULL;

    if (virJSONValueObjectCreate(&data, "s:host", host,
                                        "s:port", port, NULL) < 0)
        return NULL;

    if (virJSONValueObjectCreate(&addr, "s:type", "inet",
                                        "a:data", data, NULL) < 0) {
        virJSONValueFree(data);
        return NULL;
    }

    return addr;
}

static virJSONValuePtr
qemuMonitorJSONBuildUnixSocketAddress(const char *path)
{
    virJSONValuePtr addr = NULL;
    virJSONValuePtr data = NULL;

    if (virJSONValueObjectCreate(&data, "s:path", path, NULL) < 0)
        return NULL;

    if (virJSONValueObjectCreate(&addr, "s:type", "unix",
                                        "a:data", data, NULL) < 0) {
        virJSONValueFree(data);
        return NULL;
    }

    return addr;
}

int
qemuMonitorJSONNBDServerStart(qemuMonitorPtr mon,
                              const char *host,
                              unsigned int port)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr addr = NULL;
    char *port_str = NULL;

    if (virAsprintf(&port_str, "%u", port) < 0)
        return ret;

    if (!(addr = qemuMonitorJSONBuildInetSocketAddress(host, port_str)))
        return ret;

    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-start",
                                           "a:addr", addr,
                                           NULL)))
        goto cleanup;

    /* From now on, @addr is part of @cmd */
    addr = NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_FREE(port_str);
    virJSONValueFree(reply);
    virJSONValueFree(cmd);
    virJSONValueFree(addr);
    return ret;
}

int
qemuMonitorJSONNBDServerAdd(qemuMonitorPtr mon,
                            const char *deviceID,
                            bool writable)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-add",
                                           "s:device", deviceID,
                                           "b:writable", writable,
                                           NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONNBDServerStop(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("nbd-server-stop",
                                           NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONGetStringArray(qemuMonitorPtr mon, const char *qmpCmd,
                              char ***array)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    char **list = NULL;
    ssize_t n = 0;
    size_t i;

    *array = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand(qmpCmd, NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = 0;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("%s reply data was not an array"),
                       qmpCmd);
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(list, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;

        if (!(tmp = virJSONValueGetString(child))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s array element does not contain data"),
                           qmpCmd);
            goto cleanup;
        }

        if (VIR_STRDUP(list[i], tmp) < 0)
            goto cleanup;
    }

    ret = n;
    *array = list;
    list = NULL;

 cleanup:
    virStringListFree(list);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONGetTPMModels(qemuMonitorPtr mon,
                                char ***tpmmodels)
{
    return qemuMonitorJSONGetStringArray(mon, "query-tpm-models", tpmmodels);
}


int qemuMonitorJSONGetTPMTypes(qemuMonitorPtr mon,
                               char ***tpmtypes)
{
    return qemuMonitorJSONGetStringArray(mon, "query-tpm-types", tpmtypes);
}

static virJSONValuePtr
qemuMonitorJSONAttachCharDevCommand(const char *chrID,
                                    const virDomainChrSourceDef *chr)
{
    virJSONValuePtr ret;
    virJSONValuePtr backend;
    virJSONValuePtr data = NULL;
    virJSONValuePtr addr = NULL;
    const char *backend_type = NULL;
    char *tlsalias = NULL;
    bool telnet;

    if (!(backend = virJSONValueNewObject()) ||
        !(data = virJSONValueNewObject())) {
        goto error;
    }

    switch ((virDomainChrType) chr->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_VC:
        backend_type = "null";
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        backend_type = "pty";
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        backend_type = "file";
        if (virJSONValueObjectAppendString(data, "out", chr->data.file.path) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        backend_type = STRPREFIX(chrID, "parallel") ? "parallel" : "serial";
        if (virJSONValueObjectAppendString(data, "device",
                                           chr->data.file.path) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        backend_type = "socket";
        addr = qemuMonitorJSONBuildInetSocketAddress(chr->data.tcp.host,
                                                     chr->data.tcp.service);
        if (!addr ||
            virJSONValueObjectAppend(data, "addr", addr) < 0)
            goto error;
        addr = NULL;

        telnet = chr->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;

        if (virJSONValueObjectAppendBoolean(data, "wait", false) < 0 ||
            virJSONValueObjectAppendBoolean(data, "telnet", telnet) < 0 ||
            virJSONValueObjectAppendBoolean(data, "server", chr->data.tcp.listen) < 0)
            goto error;
        if (chr->data.tcp.tlscreds) {
            if (!(tlsalias = qemuAliasTLSObjFromSrcAlias(chrID)))
                goto error;

            if (virJSONValueObjectAppendString(data, "tls-creds", tlsalias) < 0)
                goto error;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        backend_type = "udp";
        addr = qemuMonitorJSONBuildInetSocketAddress(chr->data.udp.connectHost,
                                                     chr->data.udp.connectService);
        if (!addr ||
            virJSONValueObjectAppend(data, "remote", addr) < 0)
            goto error;

        if (chr->data.udp.bindHost) {
            addr = qemuMonitorJSONBuildInetSocketAddress(chr->data.udp.bindHost,
                                                         chr->data.udp.bindService);
            if (!addr ||
                virJSONValueObjectAppend(data, "local", addr) < 0)
                goto error;
        }
        addr = NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        backend_type = "socket";
        addr = qemuMonitorJSONBuildUnixSocketAddress(chr->data.nix.path);

        if (!addr ||
            virJSONValueObjectAppend(data, "addr", addr) < 0)
            goto error;
        addr = NULL;

        if (virJSONValueObjectAppendBoolean(data, "wait", false) < 0 ||
            virJSONValueObjectAppendBoolean(data, "server", chr->data.nix.listen) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        backend_type = "spicevmc";

        if (virJSONValueObjectAppendString(data, "type",
                                           virDomainChrSpicevmcTypeToString(chr->data.spicevmc)) < 0)
            goto error;
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_NMDM:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        if (virDomainChrTypeToString(chr->type)) {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Hotplug unsupported for char device type '%s'"),
                           virDomainChrTypeToString(chr->type));
        } else {
            virReportError(VIR_ERR_OPERATION_FAILED,
                           _("Hotplug unsupported for char device type '%d'"),
                           chr->type);
        }
        goto error;
    }

    if (virJSONValueObjectAppendString(backend, "type", backend_type) < 0 ||
        virJSONValueObjectAppend(backend, "data", data) < 0)
        goto error;
    data = NULL;

    if (!(ret = qemuMonitorJSONMakeCommand("chardev-add",
                                           "s:id", chrID,
                                           "a:backend", backend,
                                           NULL)))
        goto error;

    return ret;

 error:
    VIR_FREE(tlsalias);
    virJSONValueFree(addr);
    virJSONValueFree(data);
    virJSONValueFree(backend);
    return NULL;
}


int
qemuMonitorJSONAttachCharDev(qemuMonitorPtr mon,
                             const char *chrID,
                             virDomainChrSourceDefPtr chr)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONAttachCharDevCommand(chrID, chr)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (chr->type == VIR_DOMAIN_CHR_TYPE_PTY) {
        virJSONValuePtr data = virJSONValueObjectGetObject(reply, "return");
        const char *path;

        if (!(path = virJSONValueObjectGetString(data, "pty"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("chardev-add reply was missing pty path"));
            goto cleanup;
        }

        if (VIR_STRDUP(chr->data.file.path, path) < 0)
            goto cleanup;
    }

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONDetachCharDev(qemuMonitorPtr mon,
                             const char *chrID)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("chardev-remove",
                                           "s:id", chrID,
                                           NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetDeviceAliases(qemuMonitorPtr mon,
                                char ***aliases)
{
    qemuMonitorJSONListPathPtr *paths = NULL;
    char **alias;
    int ret = -1;
    size_t i;
    int n;

    *aliases = NULL;

    n = qemuMonitorJSONGetObjectListPaths(mon, "/machine/peripheral", &paths);
    if (n < 0)
        return -1;

    if (VIR_ALLOC_N(*aliases, n + 1) < 0)
        goto cleanup;

    alias = *aliases;
    for (i = 0; i < n; i++) {
        if (STRPREFIX(paths[i]->type, "child<")) {
            *alias = paths[i]->name;
            paths[i]->name = NULL;
            alias++;
        }
    }

    ret = 0;

 cleanup:
    for (i = 0; i < n; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    return ret;
}


static int
qemuMonitorJSONParseCPUx86FeatureWord(virJSONValuePtr data,
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
                       _("unknown CPU register '%s'"), reg);
        return -1;
    }

    return 0;
}


static virCPUDataPtr
qemuMonitorJSONParseCPUx86Features(virJSONValuePtr data)
{
    virCPUDataPtr cpudata = NULL;
    virCPUx86CPUID cpuid;
    size_t i;
    ssize_t n;

    if (!data || (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("invalid array of CPUID features"));
        goto error;
    }

    if (!(cpudata = virCPUDataNew(VIR_ARCH_X86_64)))
        goto error;

    for (i = 0; i < n; i++) {
        if (qemuMonitorJSONParseCPUx86FeatureWord(virJSONValueArrayGet(data, i),
                                                  &cpuid) < 0 ||
            virCPUx86DataAddCPUID(cpudata, &cpuid) < 0)
            goto error;
    }

    return cpudata;

 error:
    virCPUDataFree(cpudata);
    return NULL;
}


int
qemuMonitorJSONGetCPUx86Data(qemuMonitorPtr mon,
                             const char *property,
                             virCPUDataPtr *cpudata)
{
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    int ret = -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", QOM_CPU_PATH,
                                           "s:property", property,
                                           NULL)))
        goto cleanup;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply))
        goto cleanup;

    data = virJSONValueObjectGetArray(reply, "return");
    if (!(*cpudata = qemuMonitorJSONParseCPUx86Features(data)))
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * Returns -1 on error, 0 if QEMU does not support reporting CPUID features
 * of a guest CPU, and 1 if the feature is supported.
 */
static int
qemuMonitorJSONCheckCPUx86(qemuMonitorPtr mon)
{
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    size_t i;
    ssize_t n;
    int ret = -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-list",
                                           "s:path", QOM_CPU_PATH,
                                           NULL)))
        goto cleanup;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if ((data = virJSONValueObjectGet(reply, "error"))) {
        const char *klass = virJSONValueObjectGetString(data, "class");
        if (STREQ_NULLABLE(klass, "DeviceNotFound") ||
            STREQ_NULLABLE(klass, "CommandNotFound")) {
            ret = 0;
            goto cleanup;
        }
    }

    if (qemuMonitorJSONCheckError(cmd, reply))
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qom-list reply data was not an array"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        virJSONValuePtr element = virJSONValueArrayGet(data, i);
        if (STREQ_NULLABLE(virJSONValueObjectGetString(element, "name"),
                           "feature-words"))
            break;
    }

    if (i == n)
        ret = 0;
    else
        ret = 1;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/**
 * qemuMonitorJSONGetGuestCPU:
 * @mon: Pointer to the monitor
 * @arch: arch of the guest
 * @data: returns the cpu data of the guest
 * @disabled: returns the CPU data for features which were disabled by QEMU
 *
 * Retrieve the definition of the guest CPU from a running qemu instance.
 *
 * Returns 0 on success, -2 if guest doesn't support this feature,
 * -1 on other errors.
 */
int
qemuMonitorJSONGetGuestCPU(qemuMonitorPtr mon,
                           virArch arch,
                           virCPUDataPtr *data,
                           virCPUDataPtr *disabled)
{
    virCPUDataPtr cpuEnabled = NULL;
    virCPUDataPtr cpuDisabled = NULL;
    int rc;

    if (ARCH_IS_X86(arch)) {
        if ((rc = qemuMonitorJSONCheckCPUx86(mon)) < 0)
            return -1;
        else if (!rc)
            return -2;

        if (qemuMonitorJSONGetCPUx86Data(mon, "feature-words",
                                         &cpuEnabled) < 0)
            goto error;

        if (disabled &&
            qemuMonitorJSONGetCPUx86Data(mon, "filtered-features",
                                         &cpuDisabled) < 0)
            goto error;

        *data = cpuEnabled;
        if (disabled)
            *disabled = cpuDisabled;
        return 0;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("CPU definition retrieval isn't supported for '%s'"),
                   virArchToString(arch));
    return -1;

 error:
    virCPUDataFree(cpuEnabled);
    virCPUDataFree(cpuDisabled);
    return -1;
}

int
qemuMonitorJSONRTCResetReinjection(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("rtc-reset-reinjection",
                                           NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/**
 * Query and parse returned array of data such as:
 *
 *  {u'return': [{u'id': u'iothread1', u'thread-id': 30992}, \
 *               {u'id': u'iothread2', u'thread-id': 30993}]}
 */
int
qemuMonitorJSONGetIOThreads(qemuMonitorPtr mon,
                            qemuMonitorIOThreadInfoPtr **iothreads)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    qemuMonitorIOThreadInfoPtr *infolist = NULL;
    ssize_t n = 0;
    size_t i;

    *iothreads = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-iothreads", NULL)))
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-iothreads reply data was not an array"));
        goto cleanup;
    }

    /* null-terminated list */
    if (VIR_ALLOC_N(infolist, n + 1) < 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr child = virJSONValueArrayGet(data, i);
        const char *tmp;
        qemuMonitorIOThreadInfoPtr info;

        if (!(tmp = virJSONValueObjectGetString(child, "id"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-iothreads reply data was missing 'id'"));
            goto cleanup;
        }

        if (!STRPREFIX(tmp, "iothread"))
            continue;

        if (VIR_ALLOC(info) < 0)
            goto cleanup;

        infolist[i] = info;

        if (virStrToLong_ui(tmp + strlen("iothread"),
                            NULL, 10, &info->iothread_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("failed to find iothread id for '%s'"),
                           tmp);
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(child, "thread-id",
                                           &info->thread_id) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-iothreads reply has malformed "
                             "'thread-id' data"));
            goto cleanup;
        }
    }

    ret = n;
    *iothreads = infolist;
    infolist = NULL;

 cleanup:
    if (infolist) {
        for (i = 0; i < n; i++)
            VIR_FREE(infolist[i]);
        VIR_FREE(infolist);
    }
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetMemoryDeviceInfo(qemuMonitorPtr mon,
                                   virHashTablePtr info)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data = NULL;
    qemuMonitorMemoryDeviceInfoPtr meminfo = NULL;
    ssize_t n;
    size_t i;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-memory-devices", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        ret = -2;
        goto cleanup;
    }

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGetArray(reply, "return")) ||
        (n = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-memory-devices reply data was not an array"));
        goto cleanup;
    }

    for (i = 0; i < n; i++) {
        virJSONValuePtr elem = virJSONValueArrayGet(data, i);
        const char *type;

        if (!(type = virJSONValueObjectGetString(elem, "type"))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("query-memory-devices reply data doesn't contain "
                             "enum type discriminator"));
            goto cleanup;
        }

        /* dimm memory devices */
        if (STREQ(type, "dimm")) {
            virJSONValuePtr dimminfo;
            const char *devalias;

            if (!(dimminfo = virJSONValueObjectGetObject(elem, "data"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("query-memory-devices reply data doesn't "
                                 "contain enum data"));
                goto cleanup;
            }

            if (!(devalias = virJSONValueObjectGetString(dimminfo, "id"))) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("dimm memory info data is missing 'id'"));
                goto cleanup;
            }

            if (VIR_ALLOC(meminfo) < 0)
                goto cleanup;

            if (virJSONValueObjectGetNumberUlong(dimminfo, "addr",
                                                 &meminfo->address) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing addr in dimm memory info"));
                goto cleanup;
            }

            if (virJSONValueObjectGetNumberUint(dimminfo, "slot",
                                                &meminfo->slot) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing slot in dimm memory info"));
                goto cleanup;
            }

            if (virJSONValueObjectGetBoolean(dimminfo, "hotplugged",
                                             &meminfo->hotplugged) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing hotplugged in dimm memory info"));
                goto cleanup;

            }

            if (virJSONValueObjectGetBoolean(dimminfo, "hotpluggable",
                                             &meminfo->hotpluggable) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("malformed/missing hotpluggable in dimm memory info"));
                goto cleanup;

            }

            if (virHashAddEntry(info, devalias, meminfo) < 0)
                goto cleanup;

            meminfo = NULL;
        }
    }

    ret = 0;

 cleanup:
    VIR_FREE(meminfo);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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
qemuMonitorJSONFindObjectPathByAlias(qemuMonitorPtr mon,
                                     const char *name,
                                     const char *alias,
                                     char **path)
{
    qemuMonitorJSONListPathPtr *paths = NULL;
    char *child = NULL;
    int npaths;
    int ret = -1;
    size_t i;

    npaths = qemuMonitorJSONGetObjectListPaths(mon, "/machine/peripheral", &paths);
    if (npaths < 0)
        return -1;

    if (virAsprintf(&child, "child<%s>", name) < 0)
        goto cleanup;

    for (i = 0; i < npaths; i++) {
        if (STREQ(paths[i]->name, alias) && STREQ(paths[i]->type, child)) {
            if (virAsprintf(path, "/machine/peripheral/%s", alias) < 0)
                goto cleanup;

            ret = 0;
            goto cleanup;
        }
    }

    ret = -2;

 cleanup:
    for (i = 0; i < npaths; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    VIR_FREE(child);
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
qemuMonitorJSONFindObjectPathByName(qemuMonitorPtr mon,
                                    const char *curpath,
                                    const char *name,
                                    char **path)
{
    ssize_t i, npaths = 0;
    int ret = -2;
    char *nextpath = NULL;
    qemuMonitorJSONListPathPtr *paths = NULL;

    VIR_DEBUG("Searching for '%s' Object Path starting at '%s'", name, curpath);

    npaths = qemuMonitorJSONGetObjectListPaths(mon, curpath, &paths);
    if (npaths < 0)
        goto cleanup;

    for (i = 0; i < npaths && ret == -2; i++) {

        if (STREQ_NULLABLE(paths[i]->type, name)) {
            VIR_DEBUG("Path to '%s' is '%s/%s'", name, curpath, paths[i]->name);
            ret = 0;
            if (virAsprintf(path, "%s/%s", curpath, paths[i]->name) < 0) {
                *path = NULL;
                ret = -1;
            }
            goto cleanup;
        }

        /* Type entries that begin with "child<" are a branch that can be
         * traversed looking for more entries
         */
        if (paths[i]->type && STRPREFIX(paths[i]->type, "child<")) {
            if (virAsprintf(&nextpath, "%s/%s", curpath, paths[i]->name) < 0) {
                ret = -1;
                goto cleanup;
            }

            ret = qemuMonitorJSONFindObjectPathByName(mon, nextpath, name, path);
            VIR_FREE(nextpath);
        }
    }

 cleanup:
    for (i = 0; i < npaths; i++)
        qemuMonitorJSONListPathFree(paths[i]);
    VIR_FREE(paths);
    VIR_FREE(nextpath);
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
qemuMonitorJSONFindLinkPath(qemuMonitorPtr mon,
                            const char *name,
                            const char *alias,
                            char **path)
{
    char *linkname = NULL;
    int ret = -1;

    if (alias) {
        ret = qemuMonitorJSONFindObjectPathByAlias(mon, name, alias, path);
        if (ret == -1 || ret == 0)
            return ret;
    }

    if (virAsprintf(&linkname, "link<%s>", name) < 0)
        return -1;

    ret = qemuMonitorJSONFindObjectPathByName(mon, "/", linkname, path);
    VIR_FREE(linkname);
    return ret;
}


int
qemuMonitorJSONMigrateIncoming(qemuMonitorPtr mon,
                               const char *uri)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-incoming",
                                           "s:uri", uri,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    ret = qemuMonitorJSONCheckError(cmd, reply);

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONMigrateStartPostCopy(qemuMonitorPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("migrate-start-postcopy", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    ret = qemuMonitorJSONCheckError(cmd, reply);

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONGetRTCTime(qemuMonitorPtr mon,
                          struct tm *tm)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;

    if (!(cmd = qemuMonitorJSONMakeCommand("qom-get",
                                           "s:path", "/machine",
                                           "s:property", "rtc-time",
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGet(reply, "return");

    if (virJSONValueObjectGetNumberInt(data, "tm_year", &tm->tm_year) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_mon", &tm->tm_mon) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_mday", &tm->tm_mday) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_hour", &tm->tm_hour) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_min", &tm->tm_min) < 0 ||
        virJSONValueObjectGetNumberInt(data, "tm_sec", &tm->tm_sec) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("qemu returned malformed time"));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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

        VIR_FREE(entry->type);
        VIR_FREE(entry->qom_path);
        VIR_FREE(entry->alias);
    }

    VIR_FREE(entries);
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
qemuMonitorJSONProcessHotpluggableCpusReply(virJSONValuePtr vcpu,
                                            struct qemuMonitorQueryHotpluggableCpusEntry *entry)
{
    virJSONValuePtr props;
    const char *tmp;

    if (!(tmp = virJSONValueObjectGetString(vcpu, "type"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus didn't return device type"));
        return -1;
    }

    if (VIR_STRDUP(entry->type, tmp) < 0)
        return -1;

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

    entry->node_id = -1;
    entry->socket_id = -1;
    entry->core_id = -1;
    entry->thread_id = -1;

    ignore_value(virJSONValueObjectGetNumberInt(props, "node-id", &entry->node_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "socket-id", &entry->socket_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "core-id", &entry->core_id));
    ignore_value(virJSONValueObjectGetNumberInt(props, "thread-id", &entry->thread_id));

    if (entry->node_id == -1 && entry->socket_id == -1 &&
        entry->core_id == -1 && entry->thread_id == -1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus entry doesn't report "
                         "topology information"));
        return -1;
    }

    /* qom path is not present unless the vCPU is online */
    if ((tmp = virJSONValueObjectGetString(vcpu, "qom-path"))) {
        if (VIR_STRDUP(entry->qom_path, tmp) < 0)
            return -1;

        /* alias is the part after last slash having a "vcpu" prefix */
        if ((tmp = strrchr(tmp, '/')) && STRPREFIX(tmp + 1, "vcpu")) {
            if (VIR_STRDUP(entry->alias, tmp + 1) < 0)
                return -1;
        }
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

    if (a->core_id != b->core_id)
        return a->core_id - b->core_id;

    return a->thread_id - b->thread_id;
}


int
qemuMonitorJSONGetHotpluggableCPUs(qemuMonitorPtr mon,
                                   struct qemuMonitorQueryHotpluggableCpusEntry **entries,
                                   size_t *nentries)
{
    struct qemuMonitorQueryHotpluggableCpusEntry *info = NULL;
    ssize_t ninfo = 0;
    int ret = -1;
    size_t i;
    virJSONValuePtr data;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr vcpu;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-hotpluggable-cpus", NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    data = virJSONValueObjectGet(reply, "return");

    if ((ninfo = virJSONValueArraySize(data)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("query-hotpluggable-cpus reply is not an array"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(info, ninfo) < 0)
        goto cleanup;

    for (i = 0; i < ninfo; i++) {
        vcpu = virJSONValueArrayGet(data, i);

        if (qemuMonitorJSONProcessHotpluggableCpusReply(vcpu, info + i) < 0)
            goto cleanup;
    }

    qsort(info, ninfo, sizeof(*info), qemuMonitorQueryHotpluggableCpusEntrySort);

    VIR_STEAL_PTR(*entries, info);
    *nentries = ninfo;
    ret = 0;

 cleanup:
    qemuMonitorQueryHotpluggableCpusFree(info, ninfo);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONFillQMPSchema(size_t pos ATTRIBUTE_UNUSED,
                             virJSONValuePtr item,
                             void *opaque)
{
    const char *name;
    virHashTablePtr schema = opaque;

    if (!(name = virJSONValueObjectGetString(item, "name"))) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("malformed QMP schema"));
        return -1;
    }

    if (virHashAddEntry(schema, name, item) < 0)
        return -1;

    return 0;
}


virHashTablePtr
qemuMonitorJSONQueryQMPSchema(qemuMonitorPtr mon)
{
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr arr;
    virHashTablePtr schema = NULL;
    virHashTablePtr ret = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-qmp-schema", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    arr = virJSONValueObjectGet(reply, "return");

    if (!(schema = virHashCreate(512, virJSONValueHashFree)))
        goto cleanup;

    if (virJSONValueArrayForeachSteal(arr, qemuMonitorJSONFillQMPSchema,
                                      schema) < 0)
        goto cleanup;

    VIR_STEAL_PTR(ret, schema);

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    virHashFree(schema);

    return ret;
}


int
qemuMonitorJSONSetBlockThreshold(qemuMonitorPtr mon,
                                 const char *nodename,
                                 unsigned long long threshold)
{
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    int ret = -1;

    if (!(cmd = qemuMonitorJSONMakeCommand("block-set-write-threshold",
                                           "s:node-name", nodename,
                                           "U:write-threshold", threshold,
                                           NULL)))
        return -1;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}


virJSONValuePtr
qemuMonitorJSONQueryNamedBlockNodes(qemuMonitorPtr mon)
{
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr ret = NULL;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-named-block-nodes", NULL)))
        return NULL;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
        goto cleanup;

    if (qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    ret = virJSONValueObjectStealArray(reply, "return");

 cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}
