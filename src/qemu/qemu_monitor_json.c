/*
 * qemu_monitor_json.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
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
#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "memory.h"
#include "logging.h"
#include "driver.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "json.h"
#include "ignore-value.h"

#define VIR_FROM_THIS VIR_FROM_QEMU


#define LINE_ENDING "\r\n"

static void qemuMonitorJSONHandleShutdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleReset(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePowerdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleStop(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleRTCChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleWatchdog(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleIOError(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCConnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCInitialize(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleBlockJob(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEConnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleTrayChange(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePMWakeup(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePMSuspend(qemuMonitorPtr mon, virJSONValuePtr data);

static struct {
    const char *type;
    void (*handler)(qemuMonitorPtr mon, virJSONValuePtr data);
} eventHandlers[] = {
    { "SHUTDOWN", qemuMonitorJSONHandleShutdown, },
    { "RESET", qemuMonitorJSONHandleReset, },
    { "POWERDOWN", qemuMonitorJSONHandlePowerdown, },
    { "STOP", qemuMonitorJSONHandleStop, },
    { "RTC_CHANGE", qemuMonitorJSONHandleRTCChange, },
    { "WATCHDOG", qemuMonitorJSONHandleWatchdog, },
    { "BLOCK_IO_ERROR", qemuMonitorJSONHandleIOError, },
    { "VNC_CONNECTED", qemuMonitorJSONHandleVNCConnect, },
    { "VNC_INITIALIZED", qemuMonitorJSONHandleVNCInitialize, },
    { "VNC_DISCONNECTED", qemuMonitorJSONHandleVNCDisconnect, },
    { "BLOCK_JOB_COMPLETED", qemuMonitorJSONHandleBlockJob, },
    { "SPICE_CONNECTED", qemuMonitorJSONHandleSPICEConnect, },
    { "SPICE_INITIALIZED", qemuMonitorJSONHandleSPICEInitialize, },
    { "SPICE_DISCONNECTED", qemuMonitorJSONHandleSPICEDisconnect, },
    { "DEVICE_TRAY_MOVED", qemuMonitorJSONHandleTrayChange, },
    { "WAKEUP", qemuMonitorJSONHandlePMWakeup, },
    { "SUSPEND", qemuMonitorJSONHandlePMSuspend, },
};


static int
qemuMonitorJSONIOProcessEvent(qemuMonitorPtr mon,
                              virJSONValuePtr obj)
{
    const char *type;
    int i;
    VIR_DEBUG("mon=%p obj=%p", mon, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

    for (i = 0 ; i < ARRAY_CARDINALITY(eventHandlers) ; i++) {
        if (STREQ(eventHandlers[i].type, type)) {
            virJSONValuePtr data = virJSONValueObjectGet(obj, "data");
            VIR_DEBUG("handle %s handler=%p data=%p", type,
                      eventHandlers[i].handler, data);
            (eventHandlers[i].handler)(mon, data);
            break;
        }
    }
    return 0;
}

static int
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unexpected JSON reply '%s'"), line);
        }
    } else {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
            char *line = strndup(data + used, got);
            if (!line) {
                virReportOOMError();
                return -1;
            }
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
    virJSONValuePtr exe;

    *reply = NULL;

    memset(&msg, 0, sizeof(msg));

    exe = virJSONValueObjectGet(cmd, "execute");
    if (exe) {
        if (!(id = qemuMonitorNextCommandID(mon)))
            goto cleanup;
        if (virJSONValueObjectAppendString(cmd, "id", id) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Unable to append command 'id' string"));
            goto cleanup;
        }
    }

    if (!(cmdstr = virJSONValueToString(cmd))) {
        virReportOOMError();
        goto cleanup;
    }
    if (virAsprintf(&msg.txBuffer, "%s\r\n", cmdstr) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmdstr, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d rxObject=%p",
              ret, msg.rxObject);


    if (ret == 0) {
        if (!msg.rxObject) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
                       virJSONValuePtr *reply) {
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
        char *cmdstr = virJSONValueToString(cmd);
        char *replystr = virJSONValueToString(reply);

        /* Log the full JSON formatted command & error */
        VIR_DEBUG("unable to execute QEMU command %s: %s",
                  cmdstr, replystr);

        /* Only send the user the command name + friendly error */
        if (!error)
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unable to execute QEMU command '%s'"),
                            qemuMonitorJSONCommandName(cmd));
        else
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unable to execute QEMU command '%s': %s"),
                            qemuMonitorJSONCommandName(cmd),
                            qemuMonitorJSONStringifyError(error));

        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        char *cmdstr = virJSONValueToString(cmd);
        char *replystr = virJSONValueToString(reply);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  cmdstr, replystr);
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unable to execute QEMU command '%s'"),
                        qemuMonitorJSONCommandName(cmd));
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    }
    return 0;
}


static int
qemuMonitorJSONHasError(virJSONValuePtr reply,
                        const char *klass)
{
    virJSONValuePtr error;
    const char *thisklass;

    if (!virJSONValueObjectHasKey(reply, "error"))
        return 0;

    error = virJSONValueObjectGet(reply, "error");
    if (!error)
        return 0;

    if (!virJSONValueObjectHasKey(error, "class"))
        return 0;

    thisklass = virJSONValueObjectGetString(error, "class");

    if (!thisklass)
        return 0;

    return STREQ(klass, thisklass);
}

/* Top-level commands and nested transaction list elements share a
 * common structure for everything except the dictionary names.  */
static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuMonitorJSONMakeCommandRaw(bool wrap, const char *cmdname, ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;
    char *key;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto no_memory;

    if (virJSONValueObjectAppendString(obj, wrap ? "type" : "execute",
                                       cmdname) < 0)
        goto no_memory;

    while ((key = va_arg(args, char *)) != NULL) {
        int ret;
        char type;

        if (strlen(key) < 3) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("argument key '%s' is too short, missing type prefix"),
                            key);
            goto error;
        }

        /* Keys look like   s:name  the first letter is a type code */
        type = key[0];
        key += 2;

        if (!jargs &&
            !(jargs = virJSONValueNewObject()))
            goto no_memory;

        /* This doesn't support maps, but no command uses those.  */
        switch (type) {
        case 's': {
            char *val = va_arg(args, char *);
            if (!val) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("argument key '%s' must not have null value"),
                                key);
                goto error;
            }
            ret = virJSONValueObjectAppendString(jargs, key, val);
        }   break;
        case 'i': {
            int val = va_arg(args, int);
            ret = virJSONValueObjectAppendNumberInt(jargs, key, val);
        }   break;
        case 'u': {
            unsigned int val = va_arg(args, unsigned int);
            ret = virJSONValueObjectAppendNumberUint(jargs, key, val);
        }   break;
        case 'I': {
            long long val = va_arg(args, long long);
            ret = virJSONValueObjectAppendNumberLong(jargs, key, val);
        }   break;
        case 'U': {
            /* qemu silently truncates numbers larger than LLONG_MAX,
             * so passing the full range of unsigned 64 bit integers
             * is not safe here.  Pass them as signed 64 bit integers
             * instead.
             */
            long long val = va_arg(args, long long);
            ret = virJSONValueObjectAppendNumberLong(jargs, key, val);
        }   break;
        case 'd': {
            double val = va_arg(args, double);
            ret = virJSONValueObjectAppendNumberDouble(jargs, key, val);
        }   break;
        case 'b': {
            int val = va_arg(args, int);
            ret = virJSONValueObjectAppendBoolean(jargs, key, val);
        }   break;
        case 'n': {
            ret = virJSONValueObjectAppendNull(jargs, key);
        }   break;
        case 'a': {
            virJSONValuePtr val = va_arg(args, virJSONValuePtr);
            ret = virJSONValueObjectAppend(jargs, key, val);
        }   break;
        default:
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unsupported data type '%c' for arg '%s'"), type, key - 2);
            goto error;
        }
        if (ret < 0)
            goto no_memory;
    }

    if (jargs &&
        virJSONValueObjectAppend(obj, wrap ? "data" : "arguments", jargs) < 0)
        goto no_memory;

    va_end(args);

    return obj;

no_memory:
    virReportOOMError();
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
    int i;
    for (i = 0 ; i < nkeywords ; i++) {
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
    int i;

    if (!(ret = virJSONValueNewObject()))
        goto no_memory;

    nkeywords = qemuParseKeywords(str, &keywords, &values, 1);

    if (nkeywords < 0)
        goto error;

    for (i = 0 ; i < nkeywords ; i++) {
        if (values[i] == NULL) {
            if (i != 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("unexpected empty keyword in %s"), str);
                goto error;
            } else {
                /* This 3rd arg isn't a typo - the way the parser works is
                 * that the value ended up in the keyword field */
                if (virJSONValueObjectAppendString(ret, firstkeyword, keywords[i]) < 0)
                    goto no_memory;
            }
        } else {
            if (virJSONValueObjectAppendString(ret, keywords[i], values[i]) < 0)
                goto no_memory;
        }
    }

    qemuFreeKeywords(nkeywords, keywords, values);
    return ret;

no_memory:
    virReportOOMError();
error:
    qemuFreeKeywords(nkeywords, keywords, values);
    virJSONValueFree(ret);
    return NULL;
}


static void qemuMonitorJSONHandleShutdown(qemuMonitorPtr mon, virJSONValuePtr data ATTRIBUTE_UNUSED)
{
    qemuMonitorEmitShutdown(mon);
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
              "none", "pause", "reset", "poweroff", "shutdown", "debug");

static void qemuMonitorJSONHandleWatchdog(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *action;
    int actionID;
    if (!(action = virJSONValueObjectGetString(data, "action"))) {
        VIR_WARN("missing action in watchdog event");
    }
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


static void qemuMonitorJSONHandleIOError(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *device;
    const char *action;
    const char *reason;
    int actionID;

    /* Throughout here we try our best to carry on upon errors,
       since it's imporatant to get as much info as possible out
       to the application */

    if ((action = virJSONValueObjectGetString(data, "action")) == NULL) {
        VIR_WARN("Missing action in disk io error event");
        action = "ignore";
    }

    if ((device = virJSONValueObjectGetString(data, "device")) == NULL) {
        VIR_WARN("missing device in disk io error event");
    }

#if 0
    if ((reason = virJSONValueObjectGetString(data, "reason")) == NULL) {
        VIR_WARN("missing reason in disk io error event");
        reason = "";
    }
#else
    reason = "";
#endif

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

static void qemuMonitorJSONHandleGraphics(qemuMonitorPtr mon, virJSONValuePtr data, int phase)
{
    const char *localNode, *localService, *localFamily;
    const char *remoteNode, *remoteService, *remoteFamily;
    const char *authScheme, *saslUsername, *x509dname;
    int localFamilyID, remoteFamilyID;
    virJSONValuePtr client;
    virJSONValuePtr server;

    if (!(client = virJSONValueObjectGet(data, "client"))) {
        VIR_WARN("missing client info in VNC event");
        return;
    }
    if (!(server = virJSONValueObjectGet(data, "server"))) {
        VIR_WARN("missing server info in VNC event");
        return;
    }

    authScheme = virJSONValueObjectGetString(server, "auth");
    if (!authScheme) {
        VIR_WARN("missing auth scheme in graphics event");
        return;
    }

    localFamily = virJSONValueObjectGetString(server, "family");
    if (!localFamily) {
        VIR_WARN("missing local address family in graphics event");
        return;
    }
    localNode = virJSONValueObjectGetString(server, "host");
    if (!localNode) {
        VIR_WARN("missing local hostname in graphics event");
        return;
    }
    localService = virJSONValueObjectGetString(server, "service");
    if (!localService)
        localService = ""; /* Spice has multiple ports, so this isn't provided */

    remoteFamily = virJSONValueObjectGetString(client, "family");
    if (!remoteFamily) {
        VIR_WARN("missing remote address family in graphics event");
        return;
    }
    remoteNode = virJSONValueObjectGetString(client, "host");
    if (!remoteNode) {
        VIR_WARN("missing remote hostname in graphics event");
        return;
    }
    remoteService = virJSONValueObjectGetString(client, "service");
    if (!remoteService)
        remoteService = ""; /* Spice has multiple ports, so this isn't provided */

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
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleVNCInitialize(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleVNCDisconnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}


static void qemuMonitorJSONHandleSPICEConnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_CONNECT);
}


static void qemuMonitorJSONHandleSPICEInitialize(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_INITIALIZE);
}


static void qemuMonitorJSONHandleSPICEDisconnect(qemuMonitorPtr mon, virJSONValuePtr data)
{
    qemuMonitorJSONHandleGraphics(mon, data, VIR_DOMAIN_EVENT_GRAPHICS_DISCONNECT);
}

static void qemuMonitorJSONHandleBlockJob(qemuMonitorPtr mon, virJSONValuePtr data)
{
    const char *device;
    const char *type_str;
    int type = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;
    unsigned long long offset, len;
    int status = VIR_DOMAIN_BLOCK_JOB_FAILED;

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

    if (offset != 0 && offset == len)
        status = VIR_DOMAIN_BLOCK_JOB_COMPLETED;

out:
    qemuMonitorEmitBlockJob(mon, device, type, status);
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

    if (qemuMonitorJSONCheckError(cmd, reply))
        goto cleanup;

    if (!(obj = virJSONValueObjectGet(reply, "return"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("human monitor command was missing return data"));
        goto cleanup;
    }

    if (reply_str) {
        const char *data;

        if ((data = virJSONValueGetString(obj)))
            *reply_str = strdup(data);
        else
            *reply_str = strdup("");

        if (!*reply_str) {
            virReportOOMError();
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
qemuMonitorJSONSetCapabilities(qemuMonitorPtr mon)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("qmp_capabilities", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * Returns: 0 if human-monitor-command is not supported, +1 if
 * human-monitor-command worked or -1 on failure
 */
int
qemuMonitorJSONCheckCommands(qemuMonitorPtr mon,
                             virBitmapPtr qemuCaps,
                             int *json_hmp)
{
    int ret = -1;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-commands", NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;
    int i, n;

    if (!cmd)
        return ret;

    if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0 ||
        qemuMonitorJSONCheckError(cmd, reply) < 0)
        goto cleanup;

    if (!(data = virJSONValueObjectGet(reply, "return")) ||
        data->type != VIR_JSON_TYPE_ARRAY ||
        (n = virJSONValueArraySize(data)) <= 0)
        goto cleanup;

    for (i = 0; i < n; i++) {
        virJSONValuePtr entry;
        const char *name;

        if (!(entry = virJSONValueArrayGet(data, i)) ||
            !(name = virJSONValueObjectGetString(entry, "name")))
            goto cleanup;

        if (STREQ(name, "human-monitor-command"))
            *json_hmp = 1;

        if (STREQ(name, "system_wakeup"))
            qemuCapsSet(qemuCaps, QEMU_CAPS_WAKEUP);

        if (STREQ(name, "transaction"))
            qemuCapsSet(qemuCaps, QEMU_CAPS_TRANSACTION);
    }

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
    int i = 0, timeout = 3;
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
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("stop", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int
qemuMonitorJSONGetStatus(qemuMonitorPtr mon,
                         bool *running,
                         virDomainPausedReason *reason)
{
    int ret;
    const char *status;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr data;

    if (reason)
        *reason = VIR_DOMAIN_PAUSED_UNKNOWN;

    if (!(cmd = qemuMonitorJSONMakeCommand("query-status", NULL)))
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret < 0)
        goto cleanup;

    ret = -1;

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("query-status reply was missing return data"));
        goto cleanup;
    }

    if (virJSONValueObjectGetBoolean(data, "running", running) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("system_powerdown", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSetLink(qemuMonitorPtr mon,
                           const char *name,
                           enum virDomainNetInterfaceLinkState state)
{

    int ret;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("set_link",
                                                     "s:name", name,
                                                     "b:up", state != VIR_DOMAIN_NET_INTERFACE_LINK_STATE_DOWN,
                                                     NULL);

    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);

    return ret;
}

int qemuMonitorJSONSystemReset(qemuMonitorPtr mon)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("system_reset", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * [ { "CPU": 0, "current": true, "halted": false, "pc": 3227107138 },
 *   { "CPU": 1, "current": false, "halted": true, "pc": 7108165 } ]
 */
static int
qemuMonitorJSONExtractCPUInfo(virJSONValuePtr reply,
                              int **pids)
{
    virJSONValuePtr data;
    int ret = -1;
    int i;
    int *threads = NULL;
    int ncpus;

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cpu reply was missing return data"));
        goto cleanup;
    }

    if (data->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cpu information was not an array"));
        goto cleanup;
    }

    if ((ncpus = virJSONValueArraySize(data)) <= 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cpu information was empty"));
        goto cleanup;
    }

    if (VIR_REALLOC_N(threads, ncpus) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    for (i = 0 ; i < ncpus ; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        int cpu;
        int thread;
        if (!entry) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("character device information was missing array element"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(entry, "CPU", &cpu) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cpu information was missing cpu number"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(entry, "thread_id", &thread) < 0) {
            /* Only qemu-kvm tree includs thread_id, so treat this as
               non-fatal, simply returning no data */
            ret = 0;
            goto cleanup;
        }

        if (cpu != i) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unexpected cpu index %d expecting %d"),
                            i, cpu);
            goto cleanup;
        }

        threads[i] = thread;
    }

    *pids = threads;
    threads = NULL;
    ret = ncpus;

cleanup:
    VIR_FREE(threads);
    return ret;
}


int qemuMonitorJSONGetCPUInfo(qemuMonitorPtr mon,
                              int **pids)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-cpus",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    *pids = NULL;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0)
        ret = qemuMonitorJSONExtractCPUInfo(reply, pids);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetVirtType(qemuMonitorPtr mon,
                               int *virtType)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-kvm",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    *virtType = VIR_DOMAIN_VIRT_QEMU;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0) {
        virJSONValuePtr data;
        bool val = false;

        if (!(data = virJSONValueObjectGet(reply, "return"))) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("info kvm reply was missing return data"));
            ret = -1;
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(data, "enabled", &val) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("info kvm reply missing 'running' field"));
            ret = -1;
            goto cleanup;
        }
        if (val)
            *virtType = VIR_DOMAIN_VIRT_KVM;
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * Returns: 0 if balloon not supported, +1 if balloon query worked
 * or -1 on failure
 */
int qemuMonitorJSONGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long long *currmem)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-balloon",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    *currmem = 0;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        /* See if balloon soft-failed */
        if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
            qemuMonitorJSONHasError(reply, "KVMMissingCap"))
            goto cleanup;

        /* See if any other fatal error occurred */
        ret = qemuMonitorJSONCheckError(cmd, reply);

        /* Success */
        if (ret == 0) {
            virJSONValuePtr data;
            unsigned long long mem;

            if (!(data = virJSONValueObjectGet(reply, "return"))) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("info balloon reply was missing return data"));
                ret = -1;
                goto cleanup;
            }

            if (virJSONValueObjectGetNumberUlong(data, "actual", &mem) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("info balloon reply was missing balloon data"));
                ret = -1;
                goto cleanup;
            }

            *currmem = (mem/1024);
            ret = 1;
        }
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetMemoryStats(qemuMonitorPtr mon,
                                  virDomainMemoryStatPtr stats,
                                  unsigned int nr_stats)
{
    int ret;
    int got = 0;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-balloon",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        /* See if balloon soft-failed */
        if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
            qemuMonitorJSONHasError(reply, "KVMMissingCap"))
            goto cleanup;

        /* See if any other fatal error occurred */
        ret = qemuMonitorJSONCheckError(cmd, reply);

        /* Success */
        if (ret == 0) {
            virJSONValuePtr data;
            unsigned long long mem;

            if (!(data = virJSONValueObjectGet(reply, "return"))) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("info balloon reply was missing return data"));
                ret = -1;
                goto cleanup;
            }

            if (virJSONValueObjectHasKey(data, "actual") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "actual", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon actual"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_ACTUAL_BALLOON;
                stats[got].val = (mem/1024);
                got++;
            }

            if (virJSONValueObjectHasKey(data, "mem_swapped_in") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "mem_swapped_in", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon mem_swapped_in"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_SWAP_IN;
                stats[got].val = (mem/1024);
                got++;
            }
            if (virJSONValueObjectHasKey(data, "mem_swapped_out") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "mem_swapped_out", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon mem_swapped_out"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_SWAP_OUT;
                stats[got].val = (mem/1024);
                got++;
            }
            if (virJSONValueObjectHasKey(data, "major_page_faults") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "major_page_faults", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon major_page_faults"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_MAJOR_FAULT;
                stats[got].val = mem;
                got++;
            }
            if (virJSONValueObjectHasKey(data, "minor_page_faults") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "minor_page_faults", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon minor_page_faults"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_MINOR_FAULT;
                stats[got].val = mem;
                got++;
            }
            if (virJSONValueObjectHasKey(data, "free_mem") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "free_mem", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon free_mem"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_UNUSED;
                stats[got].val = (mem/1024);
                got++;
            }
            if (virJSONValueObjectHasKey(data, "total_mem") && (got < nr_stats)) {
                if (virJSONValueObjectGetNumberUlong(data, "total_mem", &mem) < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("info balloon reply was missing balloon total_mem"));
                    ret = -1;
                    goto cleanup;
                }
                stats[got].tag = VIR_DOMAIN_MEMORY_STAT_AVAILABLE;
                stats[got].val = (mem/1024);
                got++;
            }
        }
    }

    if (got > 0)
        ret = got;

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetBlockInfo(qemuMonitorPtr mon,
                                virHashTablePtr table)
{
    int ret;
    int i;

    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-block",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);
    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);
    if (ret < 0)
        goto cleanup;

    ret = -1;

    devices = virJSONValueObjectGet(reply, "return");
    if (!devices || devices->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("block info reply was missing device list"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(devices); i++) {
        virJSONValuePtr dev = virJSONValueArrayGet(devices, i);
        struct qemuDomainDiskInfo *info;
        const char *thisdev;
        const char *status;

        if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("block info device entry was not in expected format"));
            goto cleanup;
        }

        if ((thisdev = virJSONValueObjectGetString(dev, "device")) == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("block info device entry was not in expected format"));
            goto cleanup;
        }

        if (STRPREFIX(thisdev, QEMU_DRIVE_HOST_PREFIX))
            thisdev += strlen(QEMU_DRIVE_HOST_PREFIX);

        if (VIR_ALLOC(info) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (virHashAddEntry(table, thisdev, info) < 0) {
            VIR_FREE(info);
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(dev, "removable", &info->removable) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s value"),
                            "removable");
            goto cleanup;
        }

        if (virJSONValueObjectGetBoolean(dev, "locked", &info->locked) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s value"),
                            "locked");
            goto cleanup;
        }

        /* Don't check for success here, because 'tray-open' is presented iff
         * medium is ejected.
         */
        ignore_value(virJSONValueObjectGetBoolean(dev, "tray-open",
                                                  &info->tray_open));

        /* Missing io-status indicates no error */
        if ((status = virJSONValueObjectGetString(dev, "io-status"))) {
            info->io_status = qemuMonitorBlockIOStatusToError(status);
            if (info->io_status < 0)
                goto cleanup;
        }
    }

    ret = 0;

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetBlockStatsInfo(qemuMonitorPtr mon,
                                     const char *dev_name,
                                     long long *rd_req,
                                     long long *rd_bytes,
                                     long long *rd_total_times,
                                     long long *wr_req,
                                     long long *wr_bytes,
                                     long long *wr_total_times,
                                     long long *flush_req,
                                     long long *flush_total_times,
                                     long long *errs)
{
    int ret;
    int i;
    int found = 0;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-blockstats",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices;

    *rd_req = *rd_bytes = -1;
    *wr_req = *wr_bytes = *errs = -1;

    if (rd_total_times)
        *rd_total_times = -1;
    if (wr_total_times)
        *wr_total_times = -1;
    if (flush_req)
        *flush_req = -1;
    if (flush_total_times)
        *flush_total_times = -1;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);
    if (ret < 0)
        goto cleanup;
    ret = -1;

    devices = virJSONValueObjectGet(reply, "return");
    if (!devices || devices->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("blockstats reply was missing device list"));
        goto cleanup;
    }

    for (i = 0 ; i < virJSONValueArraySize(devices) ; i++) {
        virJSONValuePtr dev = virJSONValueArrayGet(devices, i);
        virJSONValuePtr stats;
        const char *thisdev;
        if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        if ((thisdev = virJSONValueObjectGetString(dev, "device")) == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        /* New QEMU has separate names for host & guest side of the disk
         * and libvirt gives the host side a 'drive-' prefix. The passed
         * in dev_name is the guest side though
         */
        if (STRPREFIX(thisdev, QEMU_DRIVE_HOST_PREFIX))
            thisdev += strlen(QEMU_DRIVE_HOST_PREFIX);

        if (STRNEQ(thisdev, dev_name))
            continue;

        found = 1;
        if ((stats = virJSONValueObjectGet(dev, "stats")) == NULL ||
            stats->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats stats entry was not in expected format"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberLong(stats, "rd_bytes", rd_bytes) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "rd_bytes");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "rd_operations", rd_req) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "rd_operations");
            goto cleanup;
        }
        if (rd_total_times &&
            virJSONValueObjectHasKey(stats, "rd_total_times_ns") &&
            (virJSONValueObjectGetNumberLong(stats, "rd_total_times_ns",
                                             rd_total_times) < 0)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "rd_total_times_ns");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "wr_bytes", wr_bytes) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "wr_bytes");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "wr_operations", wr_req) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "wr_operations");
            goto cleanup;
        }
        if (wr_total_times &&
            virJSONValueObjectHasKey(stats, "wr_total_times_ns") &&
            (virJSONValueObjectGetNumberLong(stats, "wr_total_times_ns",
                                             wr_total_times) < 0)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "wr_total_times_ns");
            goto cleanup;
        }
        if (flush_req &&
            virJSONValueObjectHasKey(stats, "flush_operations") &&
            (virJSONValueObjectGetNumberLong(stats, "flush_operations",
                                            flush_req) < 0)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "flush_operations");
            goto cleanup;
        }
        if (flush_total_times &&
            virJSONValueObjectHasKey(stats, "flush_total_times_ns") &&
            (virJSONValueObjectGetNumberLong(stats, "flush_total_times_ns",
                                            flush_total_times) < 0)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "flush_total_times_ns");
            goto cleanup;
        }
    }

    if (!found) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find statistics for device '%s'"), dev_name);
        goto cleanup;
    }
    ret = 0;

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetBlockStatsParamsNumber(qemuMonitorPtr mon,
                                             int *nparams)
{
    int ret, i, num = 0;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-blockstats",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices = NULL;
    virJSONValuePtr dev = NULL;
    virJSONValuePtr stats = NULL;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);
    if (ret < 0)
        goto cleanup;
    ret = -1;

    devices = virJSONValueObjectGet(reply, "return");
    if (!devices || devices->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("blockstats reply was missing device list"));
        goto cleanup;
    }

    dev = virJSONValueArrayGet(devices, 0);

    if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("blockstats device entry was not in expected format"));
        goto cleanup;
    }

    if ((stats = virJSONValueObjectGet(dev, "stats")) == NULL ||
        stats->type != VIR_JSON_TYPE_OBJECT) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("blockstats stats entry was not in expected format"));
        goto cleanup;
    }

    for (i = 0 ; i < stats->data.object.npairs; i++) {
        const char *key = stats->data.object.pairs[i].key;

        if (STREQ(key, "rd_bytes") ||
            STREQ(key, "rd_operations") ||
            STREQ(key, "rd_total_times_ns") ||
            STREQ(key, "wr_bytes") ||
            STREQ(key, "wr_operations") ||
            STREQ(key, "wr_total_times_ns") ||
            STREQ(key, "flush_operations") ||
            STREQ(key, "flush_total_times_ns")) {
            num++;
        } else {
            /* wr_highest_offset is parsed by qemuMonitorJSONGetBlockExtent. */
            if (STRNEQ(key, "wr_highest_offset"))
                VIR_DEBUG("Missed block stat: %s", key);
        }
    }

    *nparams = num;
    ret = 0;

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONGetBlockExtent(qemuMonitorPtr mon,
                                  const char *dev_name,
                                  unsigned long long *extent)
{
    int ret = -1;
    int i;
    int found = 0;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-blockstats",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices;

    *extent = 0;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);
    if (ret < 0)
        goto cleanup;
    ret = -1;

    devices = virJSONValueObjectGet(reply, "return");
    if (!devices || devices->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("blockstats reply was missing device list"));
        goto cleanup;
    }

    for (i = 0 ; i < virJSONValueArraySize(devices) ; i++) {
        virJSONValuePtr dev = virJSONValueArrayGet(devices, i);
        virJSONValuePtr stats;
        virJSONValuePtr parent;
        const char *thisdev;
        if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        if ((thisdev = virJSONValueObjectGetString(dev, "device")) == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        /* New QEMU has separate names for host & guest side of the disk
         * and libvirt gives the host side a 'drive-' prefix. The passed
         * in dev_name is the guest side though
         */
        if (STRPREFIX(thisdev, QEMU_DRIVE_HOST_PREFIX))
            thisdev += strlen(QEMU_DRIVE_HOST_PREFIX);

        if (STRNEQ(thisdev, dev_name))
            continue;

        found = 1;
        if ((parent = virJSONValueObjectGet(dev, "parent")) == NULL ||
            parent->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats parent entry was not in expected format"));
            goto cleanup;
        }

        if ((stats = virJSONValueObjectGet(parent, "stats")) == NULL ||
            stats->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("blockstats stats entry was not in expected format"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(stats, "wr_highest_offset", extent) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot read %s statistic"),
                            "wr_highest_offset");
            goto cleanup;
        }
    }

    if (!found) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find statistics for device '%s'"), dev_name);
        goto cleanup;
    }
    ret = 0;

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/* Return 0 on success, -1 on failure, or -2 if not supported.  Size
 * is in bytes.  */
int qemuMonitorJSONBlockResize(qemuMonitorPtr mon,
                               const char *device,
                               unsigned long long size)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("block_resize",
                                     "s:device", device,
                                     "U:size", size,
                                     NULL);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
            ret = -2;
            goto cleanup;
        }

        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSetVNCPassword(qemuMonitorPtr mon,
                                  const char *password)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("change",
                                                     "s:device", "vnc",
                                                     "s:target", "password",
                                                     "s:arg", password,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

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
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("set_password",
                                                     "s:protocol", protocol,
                                                     "s:password", password,
                                                     "s:connected", action_if_connected,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
            ret = -2;
            goto cleanup;
        }

        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

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
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("expire_password",
                                                     "s:protocol", protocol,
                                                     "s:time", expire_time,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
            ret = -2;
            goto cleanup;
        }

        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * Returns: 0 if balloon not supported, +1 if balloon adjust worked
 * or -1 on failure
 */
int qemuMonitorJSONSetBalloon(qemuMonitorPtr mon,
                              unsigned long newmem)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("balloon",
                                                     "U:value", ((unsigned long long)newmem)*1024,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        /* See if balloon soft-failed */
        if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
            qemuMonitorJSONHasError(reply, "KVMMissingCap"))
            goto cleanup;

        /* See if any other fatal error occurred */
        ret = qemuMonitorJSONCheckError(cmd, reply);

        /* Real success */
        if (ret == 0)
            ret = 1;
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * Returns: 0 if CPU hotplug not supported, +1 if CPU hotplug worked
 * or -1 on failure
 */
int qemuMonitorJSONSetCPU(qemuMonitorPtr mon,
                          int cpu, int online)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("cpu_set",
                                                     "U:cpu", (unsigned long long)cpu,
                                                     "s:state", online ? "online" : "offline",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "cpu_set")) {
        VIR_DEBUG("cpu_set command not found, trying HMP");
        ret = qemuMonitorTextSetCPU(mon, cpu, online);
        goto cleanup;
    }

    if (ret == 0) {
        /* XXX See if CPU soft-failed due to lack of ACPI */
#if 0
        if (qemuMonitorJSONHasError(reply, "DeviceNotActive") ||
            qemuMonitorJSONHasError(reply, "KVMMissingCap"))
            goto cleanup;
#endif

        /* See if any other fatal error occurred */
        ret = qemuMonitorJSONCheckError(cmd, reply);

        /* Real success */
        if (ret == 0)
            ret = 1;
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONEjectMedia(qemuMonitorPtr mon,
                              const char *dev_name,
                              bool force)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("eject",
                                                     "s:device", dev_name,
                                                     "b:force", force ? 1 : 0,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONChangeMedia(qemuMonitorPtr mon,
                               const char *dev_name,
                               const char *newmedia,
                               const char *format)
{
    int ret;
    virJSONValuePtr cmd;
    if (format)
        cmd = qemuMonitorJSONMakeCommand("change",
                                         "s:device", dev_name,
                                         "s:target", newmedia,
                                         "s:arg", format,
                                         NULL);
    else
        cmd = qemuMonitorJSONMakeCommand("change",
                                         "s:device", dev_name,
                                         "s:target", newmedia,
                                         NULL);

    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

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
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand(cmdtype,
                                                     "U:val", offset,
                                                     "u:size", length,
                                                     "s:filename", path,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

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
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    cmd = qemuMonitorJSONMakeCommand("migrate_set_speed",
                                     "U:value", bandwidth * 1024ULL * 1024ULL,
                                     NULL);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONSetMigrationDowntime(qemuMonitorPtr mon,
                                        unsigned long long downtime)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("migrate_set_downtime",
                                     "d:value", downtime / 1000.0,
                                     NULL);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONGetMigrationStatusReply(virJSONValuePtr reply,
                                       int *status,
                                       unsigned long long *transferred,
                                       unsigned long long *remaining,
                                       unsigned long long *total)
{
    virJSONValuePtr ret;
    const char *statusstr;
    unsigned long long t;

    if (!(ret = virJSONValueObjectGet(reply, "return"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("info migration reply was missing return data"));
        return -1;
    }

    if (!(statusstr = virJSONValueObjectGetString(ret, "status"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("info migration reply was missing return status"));
        return -1;
    }

    if ((*status = qemuMonitorMigrationStatusTypeFromString(statusstr)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unexpected migration status in %s"), statusstr);
        return -1;
    }

    if (*status == QEMU_MONITOR_MIGRATION_STATUS_ACTIVE) {
        virJSONValuePtr ram = virJSONValueObjectGet(ret, "ram");
        if (!ram) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("migration was active, but no RAM info was set"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUlong(ram, "transferred",
                                             transferred) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("migration was active, but RAM 'transferred' "
                              "data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "remaining", remaining) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("migration was active, but RAM 'remaining' "
                              "data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "total", total) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("migration was active, but RAM 'total' "
                              "data was missing"));
            return -1;
        }

        virJSONValuePtr disk = virJSONValueObjectGet(ret, "disk");
        if (!disk) {
            return 0;
        }

        if (virJSONValueObjectGetNumberUlong(disk, "transferred", &t) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("disk migration was active, but 'transferred' "
                              "data was missing"));
            return -1;
        }
        *transferred += t;
        if (virJSONValueObjectGetNumberUlong(disk, "remaining", &t) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("disk migration was active, but 'remaining' "
                              "data was missing"));
            return -1;
        }
        *remaining += t;
        if (virJSONValueObjectGetNumberUlong(disk, "total", &t) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("disk migration was active, but 'total' "
                              "data was missing"));
            return -1;
        }
        *total += t;
    }

    return 0;
}


int qemuMonitorJSONGetMigrationStatus(qemuMonitorPtr mon,
                                      int *status,
                                      unsigned long long *transferred,
                                      unsigned long long *remaining,
                                      unsigned long long *total)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-migrate",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    *status = 0;
    *transferred = *remaining = *total = 0;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetMigrationStatusReply(reply,
                                               status,
                                               transferred,
                                               remaining,
                                               total) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONMigrate(qemuMonitorPtr mon,
                           unsigned int flags,
                           const char *uri)
{
    int ret;
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

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONMigrateCancel(qemuMonitorPtr mon)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("migrate_cancel", NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

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
                                                     (tlsSubject ? "s:cert-subject" : NULL),
                                                     (tlsSubject ? tlsSubject : NULL),
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddUSBDisk(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("usb_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddUSBDeviceExact(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                     int bus ATTRIBUTE_UNUSED,
                                     int dev ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("usb_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddUSBDeviceMatch(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                     int vendor ATTRIBUTE_UNUSED,
                                     int product ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("usb_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddPCIHostDevice(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                    virDomainDevicePCIAddress *hostAddr ATTRIBUTE_UNUSED,
                                    virDomainDevicePCIAddress *guestAddr ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("pci_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddPCIDisk(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                              const char *path ATTRIBUTE_UNUSED,
                              const char *bus ATTRIBUTE_UNUSED,
                              virDomainDevicePCIAddress *guestAddr ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("pci_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddPCINetwork(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                 const char *nicstr ATTRIBUTE_UNUSED,
                                 virDomainDevicePCIAddress *guestAddr ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("pci_add not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONRemovePCIDevice(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                   virDomainDevicePCIAddress *guestAddr ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("pci_del not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONSendFileHandle(qemuMonitorPtr mon,
                                  const char *fdname,
                                  int fd)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("getfd",
                                                     "s:fdname", fdname,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommandWithFd(mon, cmd, fd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONCloseFileHandle(qemuMonitorPtr mon,
                                   const char *fdname)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("closefd",
                                                     "s:fdname", fdname,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddHostNetwork(qemuMonitorPtr mon,
                                  const char *netstr)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("host_net_add",
                                                     "s:device", netstr,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONRemoveHostNetwork(qemuMonitorPtr mon,
                                     int vlan,
                                     const char *netname)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("host_net_remove",
                                                     "i:vlan", vlan,
                                                     "s:device", netname,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

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

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    args = NULL; /* obj owns reference to args now */

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(args);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONRemoveNetdev(qemuMonitorPtr mon,
                                const char *alias)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("netdev_del",
                                                     "s:id", alias,
                                                     NULL);
    virJSONValuePtr reply = NULL;
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


/*
 * Example return data
 *
 * {"return": [
 *      {"filename": "stdio", "label": "monitor"},
 *      {"filename": "pty:/dev/pts/6", "label": "serial0"},
 *      {"filename": "pty:/dev/pts/7", "label": "parallel0"}
 * ]}
 *
 */
static int qemuMonitorJSONExtractPtyPaths(virJSONValuePtr reply,
                                          virHashTablePtr paths)
{
    virJSONValuePtr data;
    int ret = -1;
    int i;

    if (!(data = virJSONValueObjectGet(reply, "return"))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("character device reply was missing return data"));
        goto cleanup;
    }

    if (data->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("character device information was not an array"));
        goto cleanup;
    }

    for (i = 0 ; i < virJSONValueArraySize(data) ; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        const char *type;
        const char *id;
        if (!entry) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("character device information was missing array element"));
            goto cleanup;
        }

        if (!(type = virJSONValueObjectGetString(entry, "filename"))) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("character device information was missing filename"));
            goto cleanup;
        }

        if (!(id = virJSONValueObjectGetString(entry, "label"))) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("character device information was missing filename"));
            goto cleanup;
        }

        if (STRPREFIX(type, "pty:")) {
            char *path = strdup(type + strlen("pty:"));
            if (!path) {
                virReportOOMError();
                goto cleanup;
            }

            if (virHashAddEntry(paths, id, path) < 0) {
                qemuReportError(VIR_ERR_OPERATION_FAILED,
                                _("failed to save chardev path '%s'"), path);
                VIR_FREE(path);
                goto cleanup;
            }
        }
    }

    ret = 0;

cleanup:
    return ret;
}

int qemuMonitorJSONGetPtyPaths(qemuMonitorPtr mon,
                               virHashTablePtr paths)

{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-chardev",
                                                     NULL);
    virJSONValuePtr reply = NULL;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0)
        ret = qemuMonitorJSONExtractPtyPaths(reply, paths);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAttachPCIDiskController(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                           const char *bus ATTRIBUTE_UNUSED,
                                           virDomainDevicePCIAddress *guestAddr ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("pci_add not supported in JSON mode"));
    return -1;
}


static int
qemuMonitorJSONGetGuestDriveAddress(virJSONValuePtr reply,
                                    virDomainDeviceDriveAddress *driveAddr)
{
    virJSONValuePtr addr;

    addr = virJSONValueObjectGet(reply, "return");
    if (!addr || addr->type != VIR_JSON_TYPE_OBJECT) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("drive_add reply was missing device address"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "bus", &driveAddr->bus) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("drive_add reply was missing device bus number"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "unit", &driveAddr->unit) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("drive_add reply was missing device unit number"));
        return -1;
    }

    return 0;
}


int qemuMonitorJSONAttachDrive(qemuMonitorPtr mon,
                               const char *drivestr,
                               virDomainDevicePCIAddress* controllerAddr,
                               virDomainDeviceDriveAddress* driveAddr)
{
    int ret;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    char *dev;

    if (virAsprintf(&dev, "%.2x:%.2x.%.1x",
                    controllerAddr->bus, controllerAddr->slot, controllerAddr->function) < 0) {
        virReportOOMError();
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("drive_add",
                                     "s:pci_addr", dev,
                                     "s:opts", drivestr,
                                     NULL);
    VIR_FREE(dev);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetGuestDriveAddress(reply, driveAddr) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetAllPCIAddresses(qemuMonitorPtr mon ATTRIBUTE_UNUSED,
                                      qemuMonitorPCIAddress **addrs ATTRIBUTE_UNUSED)
{
    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("query-pci not supported in JSON mode"));
    return -1;
}


int qemuMonitorJSONDelDevice(qemuMonitorPtr mon,
                             const char *devalias)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("device_del",
                                     "s:id", devalias,
                                     NULL);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddDevice(qemuMonitorPtr mon,
                             const char *devicestr)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    virJSONValuePtr args;

    cmd = qemuMonitorJSONMakeCommand("device_add", NULL);
    if (!cmd)
        return -1;

    args = qemuMonitorJSONKeywordStringToJSON(devicestr, "driver");
    if (!args)
        goto cleanup;

    if (virJSONValueObjectAppend(cmd, "arguments", args) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    args = NULL; /* obj owns reference to args now */

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(args);
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddDrive(qemuMonitorPtr mon,
                            const char *drivestr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("drive_add",
                                     "s:pci_addr", "dummy",
                                     "s:opts", drivestr,
                                     NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply) < 0))
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "drive_add")) {
        VIR_DEBUG("drive_add command not found, trying HMP");
        ret = qemuMonitorTextAddDrive(mon, drivestr);
        goto cleanup;
    }

    ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONDriveDel(qemuMonitorPtr mon,
                            const char *drivestr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    VIR_DEBUG("JSONDriveDel drivestr=%s", drivestr);
    cmd = qemuMonitorJSONMakeCommand("drive_del",
                                     "s:id", drivestr,
                                     NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound")) {
        if (qemuMonitorCheckHMP(mon, "drive_del")) {
            VIR_DEBUG("drive_del command not found, trying HMP");
            ret = qemuMonitorTextDriveDel(mon, drivestr);
        } else {
            VIR_ERROR(_("deleting disk is not supported.  "
                        "This may leak data if disk is reassigned"));
            ret = 1;
        }
    } else if (qemuMonitorJSONHasError(reply, "DeviceNotFound")) {
        /* NB: device not found errors mean the drive was
         * auto-deleted and we ignore the error */
        ret = 0;
    } else {
        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONSetDrivePassphrase(qemuMonitorPtr mon,
                                      const char *alias,
                                      const char *passphrase)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    char *drive;

    if (virAsprintf(&drive, "%s%s", QEMU_DRIVE_HOST_PREFIX, alias) < 0) {
        virReportOOMError();
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("block_passwd",
                                     "s:device", drive,
                                     "s:password", passphrase,
                                     NULL);
    VIR_FREE(drive);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONCreateSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("savevm",
                                     "s:name", name,
                                     NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "savevm")) {
        VIR_DEBUG("savevm command not found, trying HMP");
        ret = qemuMonitorTextCreateSnapshot(mon, name);
        goto cleanup;
    }

    ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("loadvm",
                                     "s:name", name,
                                     NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "loadvm")) {
        VIR_DEBUG("loadvm command not found, trying HMP");
        ret = qemuMonitorTextLoadSnapshot(mon, name);
        goto cleanup;
    }

    ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("delvm",
                                     "s:name", name,
                                     NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "delvm")) {
        VIR_DEBUG("delvm command not found, trying HMP");
        ret = qemuMonitorTextDeleteSnapshot(mon, name);
        goto cleanup;
    }

    ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int
qemuMonitorJSONDiskSnapshot(qemuMonitorPtr mon, virJSONValuePtr actions,
                            const char *device, const char *file,
                            const char *format, bool reuse)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommandRaw(actions != NULL,
                                        "blockdev-snapshot-sync",
                                        "s:device", device,
                                        "s:snapshot-file", file,
                                        "s:format", format,
                                        reuse ? "s:mode" : NULL,
                                        reuse ? "existing" : NULL,
                                        NULL);
    if (!cmd)
        return -1;

    if (actions) {
        if (virJSONValueArrayAppend(actions, cmd) < 0) {
            virReportOOMError();
            ret = -1;
        } else {
            ret = 0;
            cmd = NULL;
        }
    } else {
        if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

        if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
            qemuMonitorCheckHMP(mon, "snapshot_blkdev")) {
            VIR_DEBUG("blockdev-snapshot-sync command not found, trying HMP");
            ret = qemuMonitorTextDiskSnapshot(mon, device, file);
            goto cleanup;
        }

        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/* Note that this call frees actions regardless of whether the call
 * succeeds.  */
int
qemuMonitorJSONTransaction(qemuMonitorPtr mon, virJSONValuePtr actions)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("transaction",
                                     "a:actions", actions,
                                     NULL);
    if (!cmd) {
        virJSONValueFree(actions);
        return -1;
    }

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    ret = qemuMonitorJSONCheckError(cmd, reply);

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
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
        if (!qemuMonitorCheckHMP(mon, NULL)) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("HMP passthrough is not supported by qemu"
                              " process; only QMP commands can be used"));
            return -1;
        }
        return qemuMonitorJSONHumanCommandWithFd(mon, cmd_str, -1, reply_str);
    } else {
        if (!(cmd = virJSONValueFromString(cmd_str)))
            goto cleanup;

        if (qemuMonitorJSONCommand(mon, cmd, &reply) < 0)
            goto cleanup;

        if (!(*reply_str = virJSONValueToString(reply)))
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
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("inject-nmi", NULL);
    if (!cmd)
        return -1;

    if ((ret = qemuMonitorJSONCommand(mon, cmd, &reply)) < 0)
        goto cleanup;

    if (qemuMonitorJSONHasError(reply, "CommandNotFound") &&
        qemuMonitorCheckHMP(mon, "inject-nmi")) {
        VIR_DEBUG("inject-nmi command not found, trying HMP");
        ret = qemuMonitorTextInjectNMI(mon);
    } else {
        ret = qemuMonitorJSONCheckError(cmd, reply);
    }

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
    /*
     * FIXME: qmp sendkey has not been implemented yet,
     * and qmp API of it cannot be anticipated, so we use hmp temporary.
     */
    if (qemuMonitorCheckHMP(mon, "sendkey")) {
        return qemuMonitorTextSendKey(mon, holdtime, keycodes, nkeycodes);
    } else
        return -1;
}

int qemuMonitorJSONScreendump(qemuMonitorPtr mon,
                              const char *file)
{
    int ret;
    virJSONValuePtr cmd, reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("screendump",
                                     "s:filename", file,
                                     NULL);

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

static int qemuMonitorJSONGetBlockJobInfoOne(virJSONValuePtr entry,
                                              const char *device,
                                              virDomainBlockJobInfoPtr info)
{
    const char *this_dev;
    const char *type;
    unsigned long long speed_bytes;

    if ((this_dev = virJSONValueObjectGetString(entry, "device")) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("entry was missing 'device'"));
        return -1;
    }
    if (!STREQ(this_dev, device))
        return -1;

    type = virJSONValueObjectGetString(entry, "type");
    if (!type) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("entry was missing 'type'"));
        return -1;
    }
    if (STREQ(type, "stream"))
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_PULL;
    else
        info->type = VIR_DOMAIN_BLOCK_JOB_TYPE_UNKNOWN;

    if (virJSONValueObjectGetNumberUlong(entry, "speed", &speed_bytes) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("entry was missing 'speed'"));
        return -1;
    }
    info->bandwidth = speed_bytes / 1024ULL / 1024ULL;

    if (virJSONValueObjectGetNumberUlong(entry, "offset", &info->cur) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("entry was missing 'offset'"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUlong(entry, "len", &info->end) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("entry was missing 'len'"));
        return -1;
    }
    return 0;
}

/** qemuMonitorJSONGetBlockJobInfo:
 * Parse Block Job information.
 * The reply is a JSON array of objects, one per active job.
 */
static int qemuMonitorJSONGetBlockJobInfo(virJSONValuePtr reply,
                                           const char *device,
                                           virDomainBlockJobInfoPtr info)
{
    virJSONValuePtr data;
    int nr_results, i;

    if (!info)
        return -1;

    if ((data = virJSONValueObjectGet(reply, "return")) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("reply was missing return data"));
        return -1;
    }

    if (data->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("unrecognized format of block job information"));
        return -1;
    }

    if ((nr_results = virJSONValueArraySize(data)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("unable to determine array size"));
        return -1;
    }

    for (i = 0; i < nr_results; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        if (!entry) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("missing array element"));
            return -1;
        }
        if (qemuMonitorJSONGetBlockJobInfoOne(entry, device, info) == 0)
            return 1;
    }

    return 0;
}


int
qemuMonitorJSONBlockJob(qemuMonitorPtr mon,
                        const char *device,
                        const char *base,
                        unsigned long bandwidth,
                        virDomainBlockJobInfoPtr info,
                        int mode)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr reply = NULL;
    const char *cmd_name = NULL;

    if (base && mode != BLOCK_JOB_PULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("only block pull supports base: %s"), base);
        return -1;
    }

    if (mode == BLOCK_JOB_ABORT) {
        cmd_name = "block_job_cancel";
        cmd = qemuMonitorJSONMakeCommand(cmd_name, "s:device", device, NULL);
    } else if (mode == BLOCK_JOB_INFO) {
        cmd_name = "query-block-jobs";
        cmd = qemuMonitorJSONMakeCommand(cmd_name, NULL);
    } else if (mode == BLOCK_JOB_SPEED) {
        cmd_name = "block_job_set_speed";
        cmd = qemuMonitorJSONMakeCommand(cmd_name, "s:device",
                                         device, "U:value",
                                         bandwidth * 1024ULL * 1024ULL,
                                         NULL);
    } else if (mode == BLOCK_JOB_PULL) {
        cmd_name = "block_stream";
        if (base)
            cmd = qemuMonitorJSONMakeCommand(cmd_name, "s:device",
                                             device, "s:base", base, NULL);
        else
            cmd = qemuMonitorJSONMakeCommand(cmd_name, "s:device",
                                             device, NULL);
    }

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0 && virJSONValueObjectHasKey(reply, "error")) {
        if (qemuMonitorJSONHasError(reply, "DeviceNotActive"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("No active operation on device: %s"), device);
        else if (qemuMonitorJSONHasError(reply, "DeviceInUse"))
            qemuReportError(VIR_ERR_OPERATION_FAILED,
                _("Device %s in use"), device);
        else if (qemuMonitorJSONHasError(reply, "NotSupported"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("Operation is not supported for device: %s"), device);
        else if (qemuMonitorJSONHasError(reply, "CommandNotFound"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("Command '%s' is not found"), cmd_name);
        else
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Unexpected error"));
        ret = -1;
    }

    if (ret == 0 && mode == BLOCK_JOB_INFO)
        ret = qemuMonitorJSONGetBlockJobInfo(reply, device, info);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

int qemuMonitorJSONOpenGraphics(qemuMonitorPtr mon,
                                const char *protocol,
                                const char *fdname,
                                bool skipauth)
{
    int ret;
    virJSONValuePtr cmd, reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("add_client",
                                     "s:protocol", protocol,
                                     "s:fdname", fdname,
                                     "b:skipauth", skipauth,
                                     NULL);

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONBlockIoThrottleInfo(virJSONValuePtr result,
                                   const char *device,
                                   virDomainBlockIoTuneInfoPtr reply)
{
    virJSONValuePtr io_throttle;
    int ret = -1;
    int i;
    int found = 0;

    io_throttle = virJSONValueObjectGet(result, "return");

    if (!io_throttle || io_throttle->type != VIR_JSON_TYPE_ARRAY) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _(" block_io_throttle reply was missing device list"));
        goto cleanup;
    }

    for (i = 0; i < virJSONValueArraySize(io_throttle); i++) {
        virJSONValuePtr temp_dev = virJSONValueArrayGet(io_throttle, i);
        virJSONValuePtr inserted;
        const char *current_dev;

        if (!temp_dev || temp_dev->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("block_io_throttle device entry was not in expected format"));
            goto cleanup;
        }

        if ((current_dev = virJSONValueObjectGetString(temp_dev, "device")) == NULL) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("block_io_throttle device entry was not in expected format"));
            goto cleanup;
        }

       if(STRPREFIX(current_dev, QEMU_DRIVE_HOST_PREFIX))
            current_dev += strlen(QEMU_DRIVE_HOST_PREFIX);

        if (STREQ(current_dev, device))
            continue;

        found = 1;
        if ((inserted = virJSONValueObjectGet(temp_dev, "inserted")) == NULL ||
            inserted->type != VIR_JSON_TYPE_OBJECT) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("block_io_throttle inserted entry was not in expected format"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "bps", &reply->total_bytes_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read total_bytes_sec"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "bps_rd", &reply->read_bytes_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read read_bytes_sec"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "bps_wr", &reply->write_bytes_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read write_bytes_sec"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "iops", &reply->total_iops_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read total_iops_sec"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "iops_rd", &reply->read_iops_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read read_iops_sec"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberUlong(inserted, "iops_wr", &reply->write_iops_sec) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("cannot read write_iops_sec"));
            goto cleanup;
        }
        break;
    }

    if (!found) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find throttling info for device '%s'"),
                        device);
        goto cleanup;
    }
    ret = 0;

cleanup:
    return ret;
}

int qemuMonitorJSONSetBlockIoThrottle(qemuMonitorPtr mon,
                                      const char *device,
                                      virDomainBlockIoTuneInfoPtr info)
{
    int ret = -1;
    virJSONValuePtr cmd = NULL;
    virJSONValuePtr result = NULL;

    cmd = qemuMonitorJSONMakeCommand("block_set_io_throttle",
                                     "s:device", device,
                                     "U:bps", info->total_bytes_sec,
                                     "U:bps_rd", info->read_bytes_sec,
                                     "U:bps_wr", info->write_bytes_sec,
                                     "U:iops", info->total_iops_sec,
                                     "U:iops_rd", info->read_iops_sec,
                                     "U:iops_wr", info->write_iops_sec,
                                     NULL);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &result);

    if (ret == 0 && virJSONValueObjectHasKey(result, "error")) {
        if (qemuMonitorJSONHasError(result, "DeviceNotActive"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("No active operation on device: %s"), device);
        else if (qemuMonitorJSONHasError(result, "NotSupported"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("Operation is not supported for device: %s"), device);
        else
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Unexpected error"));
        ret = -1;
    }

    virJSONValueFree(cmd);
    virJSONValueFree(result);
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
    if (!cmd) {
        return -1;
    }

    ret = qemuMonitorJSONCommand(mon, cmd, &result);

    if (ret == 0 && virJSONValueObjectHasKey(result, "error")) {
        if (qemuMonitorJSONHasError(result, "DeviceNotActive"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("No active operation on device: %s"), device);
        else if (qemuMonitorJSONHasError(result, "NotSupported"))
            qemuReportError(VIR_ERR_OPERATION_INVALID,
                _("Operation is not supported for device: %s"), device);
        else
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                _("Unexpected error"));
        ret = -1;
    }

    if (ret == 0)
        ret = qemuMonitorJSONBlockIoThrottleInfo(result, device, reply);

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
    if (!cmd) {
        return -1;
    }

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
