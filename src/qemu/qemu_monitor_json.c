/*
 * qemu_monitor_json.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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

#include "qemu_monitor_json.h"
#include "qemu_conf.h"
#include "memory.h"
#include "logging.h"
#include "driver.h"
#include "datatypes.h"
#include "virterror_internal.h"
#include "json.h"

#define VIR_FROM_THIS VIR_FROM_QEMU


#define LINE_ENDING "\r\n"

static void qemuMonitorJSONHandleShutdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleReset(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandlePowerdown(qemuMonitorPtr mon, virJSONValuePtr data);
static void qemuMonitorJSONHandleStop(qemuMonitorPtr mon, virJSONValuePtr data);

struct {
    const char *type;
    void (*handler)(qemuMonitorPtr mon, virJSONValuePtr data);
} eventHandlers[] = {
    { "SHUTDOWN", qemuMonitorJSONHandleShutdown, },
    { "RESET", qemuMonitorJSONHandleReset, },
    { "POWERDOWN", qemuMonitorJSONHandlePowerdown, },
    { "STOP", qemuMonitorJSONHandleStop, },
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
        VIR_WARN0("missing event type in message");
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

    if (!(obj = virJSONValueFromString(line))) {
        VIR_DEBUG0("Parsing JSON string failed");
        errno = EINVAL;
        goto cleanup;
    }

    if (obj->type != VIR_JSON_TYPE_OBJECT) {
        VIR_DEBUG0("Parsed JSON string isn't an object");
        errno = EINVAL;
    }

    if (virJSONValueObjectHasKey(obj, "QMP") == 1) {
        VIR_DEBUG0("Got QMP capabilities data");
        ret = 0;
        goto cleanup;
    }

    if (virJSONValueObjectHasKey(obj, "event") == 1) {
        ret = qemuMonitorJSONIOProcessEvent(mon, obj);
        goto cleanup;
    }

    if (msg) {
        if (!(msg->rxBuffer = strdup(line))) {
            errno = ENOMEM;
            goto cleanup;
        }
        msg->rxLength = strlen(line);
        msg->finished = 1;
    } else {
        VIR_DEBUG("Ignoring unexpected JSON message [%s]", line);
    }

    ret = 0;

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
                errno = ENOMEM;
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

    *reply = NULL;

    memset(&msg, 0, sizeof msg);

    if (!(cmdstr = virJSONValueToString(cmd))) {
        virReportOOMError(NULL);
        goto cleanup;
    }
    if (virAsprintf(&msg.txBuffer, "%s\r\n", cmdstr) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }
    msg.txLength = strlen(msg.txBuffer);
    msg.txFD = scm_fd;

    VIR_DEBUG("Send command '%s' for write with FD %d", cmdstr, scm_fd);

    ret = qemuMonitorSend(mon, &msg);

    VIR_DEBUG("Receive command reply ret=%d errno=%d %d bytes '%s'",
              ret, msg.lastErrno, msg.rxLength, msg.rxBuffer);


    /* If we got ret==0, but not reply data something rather bad
     * went wrong, so lets fake an EIO error */
    if (!msg.rxBuffer && ret == 0) {
        msg.lastErrno = EIO;
        ret = -1;
    }

    if (ret == 0) {
        if (!((*reply) = virJSONValueFromString(msg.rxBuffer))) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot parse JSON doc '%s'"), msg.rxBuffer);
            goto cleanup;
        }
    }

    if (ret < 0)
        virReportSystemError(NULL, msg.lastErrno,
                             _("cannot send monitor command '%s'"), cmdstr);

cleanup:
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);
    VIR_FREE(msg.rxBuffer);

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
static char *qemuMonitorJSONStringifyError(virJSONValuePtr error)
{
    const char *klass = virJSONValueObjectGetString(error, "class");

    if (klass) {
        return strdup(klass);
    } else {
        return strdup(_("Missing QEMU error klass"));
    }
}

static int
qemuMonitorJSONCheckError(virJSONValuePtr cmd,
                          virJSONValuePtr reply)
{
    if (virJSONValueObjectHasKey(reply, "error")) {
        virJSONValuePtr error = virJSONValueObjectGet(reply, "error");
        char *cmdstr = virJSONValueToString(cmd);
        char *replystr = virJSONValueToString(reply);

        if (!error) {
            VIR_DEBUG("Saw a JSON error, but value is null for %s: %s",
                      cmdstr, replystr);
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("error running QEMU command '%s': '%s'"),
                             cmdstr, replystr);
        } else {
            VIR_DEBUG("Got a JSON error set for %s", cmdstr);
            char *detail = qemuMonitorJSONStringifyError(error);
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("error running QEMU command '%s': %s ('%s')"),
                             cmdstr, detail, replystr);
            VIR_FREE(detail);
        }
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    } else if (!virJSONValueObjectHasKey(reply, "return")) {
        char *cmdstr = virJSONValueToString(cmd);
        char *replystr = virJSONValueToString(reply);

        VIR_DEBUG("Neither 'return' nor 'error' is set in the JSON reply %s: %s",
                  cmdstr, replystr);
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("error running QEMU command '%s': '%s'"), cmdstr, replystr);
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

static int
qemuMonitorJSONCommandAddTimestamp(virJSONValuePtr obj)
{
    struct timeval tv;
    virJSONValuePtr timestamp = NULL;

    if (gettimeofday(&tv, NULL) < 0) {
        virReportSystemError(NULL, errno, "%s",
                             _("cannot query time of day"));
        return -1;
    }

    if (!(timestamp = virJSONValueNewObject()))
        goto no_memory;

    if (virJSONValueObjectAppendNumberLong(timestamp, "seconds", tv.tv_sec) < 0)
        goto no_memory;
    if (virJSONValueObjectAppendNumberLong(timestamp, "microseconds", tv.tv_usec) < 0)
        goto no_memory;

    if (virJSONValueObjectAppend(obj, "timestamp", timestamp) < 0)
        goto no_memory;

    return 0;

no_memory:
    virReportOOMError(NULL);
    virJSONValueFree(timestamp);
    return -1;
}

static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuMonitorJSONMakeCommand(const char *cmdname,
                           ...)
{
    virJSONValuePtr obj;
    virJSONValuePtr jargs = NULL;
    va_list args;
    char *key;

    va_start(args, cmdname);

    if (!(obj = virJSONValueNewObject()))
        goto no_memory;

    if (virJSONValueObjectAppendString(obj, "execute", cmdname) < 0)
        goto no_memory;

    if (qemuMonitorJSONCommandAddTimestamp(obj) < 0)
        goto error;

    while ((key = va_arg(args, char *)) != NULL) {
        int ret;
        char type;

        if (strlen(key) < 3) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
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

        /* This doesn't supports maps/arrays.  This hasn't
         * proved to be a problem..... yet :-)  */
        switch (type) {
        case 's': {
            char *val = va_arg(args, char *);
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
            unsigned long long val = va_arg(args, unsigned long long);
            ret = virJSONValueObjectAppendNumberUlong(jargs, key, val);
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
        default:
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unsupported data type '%c' for arg '%s'"), type, key - 2);
            goto error;
        }
        if (ret < 0)
            goto no_memory;
    }

    if (jargs &&
        virJSONValueObjectAppend(obj, "arguments", jargs) < 0)
        goto no_memory;

    va_end(args);

    return obj;

no_memory:
    virReportOOMError(NULL);
error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
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


int
qemuMonitorJSONStartCPUs(qemuMonitorPtr mon,
                         virConnectPtr conn ATTRIBUTE_UNUSED)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("cont", NULL);
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
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("cpu reply was missing return data"));
        goto cleanup;
    }

    if (data->type != VIR_JSON_TYPE_ARRAY) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("cpu information was not an array"));
        goto cleanup;
    }

    if ((ncpus = virJSONValueArraySize(data)) <= 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("cpu information was empty"));
        goto cleanup;
    }

    if (VIR_REALLOC_N(threads, ncpus) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    for (i = 0 ; i < ncpus ; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        int cpu;
        int thread;
        if (!entry) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("character device information was missing aray element"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(entry, "CPU", &cpu) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("cpu information was missing cpu number"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberInt(entry, "thread_id", &thread) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("cpu information was missing thread ID"));
            goto cleanup;
        }

        if (cpu != i) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("unexpected cpu index %d expecting %d"),
                             i, cpu);
            goto cleanup;
        }

        threads[i] = thread;
    }

    *pids = threads;
    threads = NULL;
    ret = 0;

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


/*
 * Returns: 0 if balloon not supported, +1 if balloon query worked
 * or -1 on failure
 */
int qemuMonitorJSONGetBalloonInfo(qemuMonitorPtr mon,
                                  unsigned long *currmem)
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
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("info balloon reply was missing return data"));
                ret = -1;
                goto cleanup;
            }

            if (virJSONValueObjectGetNumberUlong(data, "balloon", &mem) < 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                                 _("info balloon reply was missing balloon data"));
                ret = -1;
                goto cleanup;
            }

            *currmem = mem;
            ret = 1;
        }
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONGetBlockStatsInfo(qemuMonitorPtr mon,
                                     const char *devname,
                                     long long *rd_req,
                                     long long *rd_bytes,
                                     long long *wr_req,
                                     long long *wr_bytes,
                                     long long *errs)
{
    int ret;
    int i;
    int found = 0;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-blockstats",
                                                     NULL);
    virJSONValuePtr reply = NULL;
    virJSONValuePtr devices;

    *rd_req = *rd_bytes = *wr_req = *wr_bytes = *errs = 0;

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0) {
        ret = qemuMonitorJSONCheckError(cmd, reply);
        if (ret < 0)
            goto cleanup;
    }
    ret = -1;

    devices = virJSONValueObjectGet(reply, "return");
    if (!devices || devices->type != VIR_JSON_TYPE_ARRAY) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("blockstats reply was missing device list"));
        goto cleanup;
    }

    for (i = 0 ; i < virJSONValueArraySize(devices) ; i++) {
        virJSONValuePtr dev = virJSONValueArrayGet(devices, i);
        virJSONValuePtr stats;
        const char *thisdev;
        if (!dev || dev->type != VIR_JSON_TYPE_OBJECT) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        if ((thisdev = virJSONValueObjectGetString(dev, "device")) == NULL) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("blockstats device entry was not in expected format"));
            goto cleanup;
        }

        if (STRNEQ(thisdev, devname))
            continue;

        found = 1;
        if ((stats = virJSONValueObjectGet(dev, "stats")) == NULL ||
            stats->type != VIR_JSON_TYPE_OBJECT) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("blockstats stats entry was not in expected format"));
            goto cleanup;
        }

        if (virJSONValueObjectGetNumberLong(stats, "rd_bytes", rd_bytes) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot read %s statistic"),
                             "rd_bytes");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "rd_operations", rd_req) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot read %s statistic"),
                             "rd_operations");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "wr_bytes", wr_bytes) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot read %s statistic"),
                             "wr_bytes");
            goto cleanup;
        }
        if (virJSONValueObjectGetNumberLong(stats, "wr_operations", wr_req) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                             _("cannot read %s statistic"),
                             "wr_operations");
            goto cleanup;
        }
    }

    if (!found) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("cannot find statistics for device '%s'"), devname);
        goto cleanup;
    }
    ret = 0;

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

/*
 * Returns: 0 if balloon not supported, +1 if balloon adjust worked
 * or -1 on failure
 */
int qemuMonitorJSONSetBalloon(qemuMonitorPtr mon,
                              unsigned long newmem)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("balloon",
                                                     "U:value", (unsigned long long)newmem,
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


int qemuMonitorJSONEjectMedia(qemuMonitorPtr mon,
                              const char *devname)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("eject",
                                                     "s:device", devname,
                                                     "i:force", 0,
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
                               const char *devname,
                               const char *newmedia,
                               const char *format)
{
    int ret;
    virJSONValuePtr cmd;
    if (format)
        cmd = qemuMonitorJSONMakeCommand("change",
                                         "s:device", devname,
                                         "s:target", newmedia,
                                         "s:arg", format,
                                         NULL);
    else
        cmd = qemuMonitorJSONMakeCommand("change",
                                         "s:device", devname,
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
    char *bandwidthstr;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    if (virAsprintf(&bandwidthstr, "%lum", bandwidth) < 0) {
        virReportOOMError(NULL);
        return -1;
    }
    cmd = qemuMonitorJSONMakeCommand("migrate_set_speed",
                                     "s:value", bandwidthstr,
                                     NULL);
    VIR_FREE(bandwidthstr);
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

    if (!(ret = virJSONValueObjectGet(reply, "return"))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("info migration reply was missing return data"));
        return -1;
    }

    if (!(statusstr = virJSONValueObjectGetString(ret, "status"))) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("info migration reply was missing return status"));
        return -1;
    }

    if ((*status = qemuMonitorMigrationStatusTypeFromString(statusstr)) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR,
                         _("unexpected migration status in %s"), statusstr);
        return -1;
    }

    if (*status == QEMU_MONITOR_MIGRATION_STATUS_ACTIVE) {
        virJSONValuePtr ram = virJSONValueObjectGet(ret, "ram");
        if (!ram) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("migration was active, but no RAM info was set"));
            return -1;
        }

        if (virJSONValueObjectGetNumberUlong(ram, "transferred", transferred) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("migration was active, but RAM 'transferred' data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "remaining", remaining) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("migration was active, but RAM 'remaining' data was missing"));
            return -1;
        }
        if (virJSONValueObjectGetNumberUlong(ram, "total", total) < 0) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("migration was active, but RAM 'total' data was missing"));
            return -1;
        }
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
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("query-migration",
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


static int qemuMonitorJSONMigrate(qemuMonitorPtr mon,
                                  int background,
                                  const char *uri)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("migrate",
                                                     "i:detach", background ? 1 : 0,
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


int qemuMonitorJSONMigrateToHost(qemuMonitorPtr mon,
                                 int background,
                                 const char *hostname,
                                 int port)
{
    char *uri = NULL;
    int ret;

    if (virAsprintf(&uri, "tcp:%s:%d", hostname, port) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorJSONMigrate(mon, background, uri);

    VIR_FREE(uri);

    return ret;
}


int qemuMonitorJSONMigrateToCommand(qemuMonitorPtr mon,
                                    int background,
                                    const char * const *argv,
                                    const char *target)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    char *safe_target = NULL;

    argstr = virArgvToString(argv);
    if (!argstr) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    /* Migrate to file */
    safe_target = qemuMonitorEscapeShell(target);
    if (!safe_target) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (virAsprintf(&dest, "exec:%s >>%s 2>/dev/null", argstr, safe_target) < 0) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    ret = qemuMonitorJSONMigrate(mon, background, dest);

cleanup:
    VIR_FREE(safe_target);
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}

int qemuMonitorJSONMigrateToUnix(qemuMonitorPtr mon,
                                 int background,
                                 const char *unixfile)
{
    char *dest = NULL;
    int ret = -1;

    if (virAsprintf(&dest, "unix:%s", unixfile) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorJSONMigrate(mon, background, dest);

    VIR_FREE(dest);

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


static int qemuMonitorJSONAddUSB(qemuMonitorPtr mon,
                                 const char *dev)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("usb_add",
                                                     "s:devname", dev,
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


int qemuMonitorJSONAddUSBDisk(qemuMonitorPtr mon,
                              const char *path)
{
    int ret;
    char *disk;

    if (virAsprintf(&disk, "disk:%s", path) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorJSONAddUSB(mon, disk);

    VIR_FREE(disk);

    return ret;
}


int qemuMonitorJSONAddUSBDeviceExact(qemuMonitorPtr mon,
                                     int bus,
                                     int dev)
{
    int ret;
    char *addr;

    if (virAsprintf(&addr, "host:%.3d.%.3d", bus, dev) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorJSONAddUSB(mon, addr);

    VIR_FREE(addr);
    return ret;
}


int qemuMonitorJSONAddUSBDeviceMatch(qemuMonitorPtr mon,
                                     int vendor,
                                     int product)
{
    int ret;
    char *addr;

    if (virAsprintf(&addr, "host:%.4x:%.4x", vendor, product) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    ret = qemuMonitorJSONAddUSB(mon, addr);

    VIR_FREE(addr);
    return ret;
}


static int
qemuMonitorJSONGetGuestPCIAddress(virJSONValuePtr reply,
                                  virDomainDevicePCIAddress *guestAddr)
{
    virJSONValuePtr addr;

    addr = virJSONValueObjectGet(reply, "return");
    if (!addr || addr->type != VIR_JSON_TYPE_OBJECT) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("pci_add reply was missing device address"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "domain", &guestAddr->domain) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("pci_add reply was missing device domain number"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "bus", &guestAddr->bus) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("pci_add reply was missing device bus number"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "slot", &guestAddr->slot) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("pci_add reply was missing device slot number"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "function", &guestAddr->function) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("pci_add reply was missing device function number"));
        return -1;
    }

    return 0;
}


int qemuMonitorJSONAddPCIHostDevice(qemuMonitorPtr mon,
                                    virDomainDevicePCIAddress *hostAddr,
                                    virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    char *dev;

    memset(guestAddr, 0, sizeof(*guestAddr));

    /* XXX hostDomain */
    if (virAsprintf(&dev, "host=%.2x:%.2x.%.1x",
                    hostAddr->bus, hostAddr->slot, hostAddr->function) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("pci_add",
                                     "s:pci_addr", "auto"
                                     "s:type", "host",
                                     "s:opts", dev,
                                     NULL);
    VIR_FREE(dev);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetGuestPCIAddress(reply, guestAddr) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddPCIDisk(qemuMonitorPtr mon,
                              const char *path,
                              const char *bus,
                              virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    char *dev;

    memset(guestAddr, 0, sizeof(*guestAddr));

    if (virAsprintf(&dev, "file=%s,if=%s", path, bus) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("pci_add",
                                     "s:pci_addr", "auto",
                                     "s:type", "storage",
                                     "s:opts", dev,
                                     NULL);
    VIR_FREE(dev);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetGuestPCIAddress(reply, guestAddr) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONAddPCINetwork(qemuMonitorPtr mon,
                                 const char *nicstr,
                                 virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    virJSONValuePtr cmd = qemuMonitorJSONMakeCommand("pci_add",
                                                     "s:pci_addr", "auto",
                                                     "s:type", "nic",
                                                     "s:opts", nicstr,
                                                     NULL);
    virJSONValuePtr reply = NULL;

    memset(guestAddr, 0, sizeof(*guestAddr));

    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetGuestPCIAddress(reply, guestAddr) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


int qemuMonitorJSONRemovePCIDevice(qemuMonitorPtr mon,
                                   virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    char *addr;

    /* XXX what about function ? */
    if (virAsprintf(&addr, "%.4x:%.2x:%.2x",
                    guestAddr->domain, guestAddr->bus, guestAddr->slot) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("pci_del",
                                     "s:pci_addr", addr,
                                     NULL);
    VIR_FREE(addr);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
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
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("character device reply was missing return data"));
        goto cleanup;
    }

    if (data->type != VIR_JSON_TYPE_ARRAY) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("character device information was not an array"));
        goto cleanup;
    }

    for (i = 0 ; i < virJSONValueArraySize(data) ; i++) {
        virJSONValuePtr entry = virJSONValueArrayGet(data, i);
        const char *type;
        const char *id;
        if (!entry) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("character device information was missing aray element"));
            goto cleanup;
        }

        if (!(type = virJSONValueObjectGetString(entry, "filename"))) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("character device information was missing filename"));
            goto cleanup;
        }

        if (!(id = virJSONValueObjectGetString(entry, "label"))) {
            qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                             _("character device information was missing filename"));
            goto cleanup;
        }

        if (STRPREFIX(type, "pty:")) {
            char *path = strdup(type + strlen("pty:"));
            if (!path) {
                virReportOOMError(NULL);
                goto cleanup;
            }

            if (virHashAddEntry(paths, id, path) < 0) {
                qemudReportError(NULL, NULL, NULL, VIR_ERR_OPERATION_FAILED,
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


int qemuMonitorJSONAttachPCIDiskController(qemuMonitorPtr mon,
                                           const char *bus,
                                           virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;
    char *dev;

    memset(guestAddr, 0, sizeof(*guestAddr));

    if (virAsprintf(&dev, "if=%s", bus) < 0) {
        virReportOOMError(NULL);
        return -1;
    }

    cmd = qemuMonitorJSONMakeCommand("pci_add",
                                     "s:pci_addr", "auto",
                                     "s:type", "storage",
                                     "s:opts", dev,
                                     NULL);
    VIR_FREE(dev);
    if (!cmd)
        return -1;

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    if (ret == 0 &&
        qemuMonitorJSONGetGuestPCIAddress(reply, guestAddr) < 0)
        ret = -1;

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}


static int
qemuMonitorJSONGetGuestDriveAddress(virJSONValuePtr reply,
                                    virDomainDeviceDriveAddress *driveAddr)
{
    virJSONValuePtr addr;

    addr = virJSONValueObjectGet(reply, "return");
    if (!addr || addr->type != VIR_JSON_TYPE_OBJECT) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("drive_add reply was missing device address"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "bus", &driveAddr->bus) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                         _("drive_add reply was missing device bus number"));
        return -1;
    }

    if (virJSONValueObjectGetNumberUint(addr, "unit", &driveAddr->unit) < 0) {
        qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
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
        virReportOOMError(NULL);
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
    qemudReportError(NULL, NULL, NULL, VIR_ERR_INTERNAL_ERROR, "%s",
                     _("query-pci not suppported in JSON mode"));
    return -1;
}


int qemuMonitorJSONAddDevice(qemuMonitorPtr mon,
                             const char *devicestr)
{
    int ret;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuMonitorJSONMakeCommand("device_add",
                                     "s:config", devicestr,
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

    ret = qemuMonitorJSONCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuMonitorJSONCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
