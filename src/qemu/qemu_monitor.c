/*
 * qemu_monitor.c: interaction with QEMU monitor console
 *
 * Copyright (C) 2006-2015 Red Hat, Inc.
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

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_monitor.h"
#include "qemu_monitor_text.h"
#include "qemu_monitor_json.h"
#include "qemu_domain.h"
#include "qemu_process.h"
#include "virerror.h"
#include "viralloc.h"
#include "virlog.h"
#include "virfile.h"
#include "virprocess.h"
#include "virobject.h"
#include "virprobe.h"
#include "virstring.h"
#include "virtime.h"

#ifdef WITH_DTRACE_PROBES
# include "libvirt_qemu_probes.h"
#endif

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_monitor");

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

struct _qemuMonitor {
    virObjectLockable parent;

    virCond notify;

    int fd;
    int watch;
    int hasSendFD;

    virDomainObjPtr vm;

    qemuMonitorCallbacksPtr cb;
    void *callbackOpaque;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuMonitorMessagePtr msg;

    /* Buffer incoming data ready for Text/QMP monitor
     * code to process & find message boundaries */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer;

    /* If anything went wrong, this will be fed back
     * the next monitor msg */
    virError lastError;

    int nextSerial;

    bool json;
    bool waitGreeting;

    /* cache of query-command-line-options results */
    virJSONValuePtr options;

    /* If found, path to the virtio memballoon driver */
    char *balloonpath;
    bool ballooninit;

    /* Log file context of the qemu process to dig for usable info */
    qemuMonitorReportDomainLogError logFunc;
    void *logOpaque;
    virFreeCallback logDestroy;
};

/**
 * QEMU_CHECK_MONITOR_FULL:
 * @mon: monitor pointer variable to check, evaluated multiple times, no parentheses
 * @force_json: force JSON monitor, true or false
 * @exit: statement that is used to exit the function
 *
 * This macro checks that the monitor is valid for given operation and exits
 * the function if not. The macro also adds a debug statement regarding the
 * monitor.
 */
#define QEMU_CHECK_MONITOR_FULL(mon, force_json, exit)                         \
    do {                                                                       \
        if (!mon) {                                                            \
            virReportError(VIR_ERR_INVALID_ARG, "%s",                          \
                           _("monitor must not be NULL"));                     \
            exit;                                                              \
        }                                                                      \
        VIR_DEBUG("mon:%p vm:%p json:%d fd:%d",                                \
                  mon, mon->vm, mon->json, mon->fd);                           \
        if (force_json && !mon->json) {                                        \
            virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",                \
                           _("JSON monitor is required"));                     \
            exit;                                                              \
        }                                                                      \
    } while (0)

/* Check monitor and return NULL on error */
#define QEMU_CHECK_MONITOR_NULL(mon) \
    QEMU_CHECK_MONITOR_FULL(mon, false, return NULL)
#define QEMU_CHECK_MONITOR_JSON_NULL(mon) \
    QEMU_CHECK_MONITOR_FULL(mon, true, return NULL)

/* Check monitor and return -1 on error */
#define QEMU_CHECK_MONITOR(mon) \
    QEMU_CHECK_MONITOR_FULL(mon, false, return -1)
#define QEMU_CHECK_MONITOR_JSON(mon) \
    QEMU_CHECK_MONITOR_FULL(mon, true, return -1)

/* Check monitor and jump to the provided label */
#define QEMU_CHECK_MONITOR_GOTO(mon, label) \
    QEMU_CHECK_MONITOR_FULL(mon, false, goto label)
#define QEMU_CHECK_MONITOR_JSON_GOTO(mon, label) \
    QEMU_CHECK_MONITOR_FULL(mon, true, goto label)

static virClassPtr qemuMonitorClass;
static void qemuMonitorDispose(void *obj);

static int qemuMonitorOnceInit(void)
{
    if (!(qemuMonitorClass = virClassNew(virClassForObjectLockable(),
                                         "qemuMonitor",
                                         sizeof(qemuMonitor),
                                         qemuMonitorDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(qemuMonitor)


VIR_ENUM_IMPL(qemuMonitorMigrationStatus,
              QEMU_MONITOR_MIGRATION_STATUS_LAST,
              "inactive", "setup",
              "active", "postcopy-active",
              "completed", "failed",
              "cancelling", "cancelled")

VIR_ENUM_IMPL(qemuMonitorMigrationCaps,
              QEMU_MONITOR_MIGRATION_CAPS_LAST,
              "xbzrle", "auto-converge", "rdma-pin-all", "events",
              "postcopy-ram", "compress")

VIR_ENUM_IMPL(qemuMonitorVMStatus,
              QEMU_MONITOR_VM_STATUS_LAST,
              "debug", "inmigrate", "internal-error", "io-error", "paused",
              "postmigrate", "prelaunch", "finish-migrate", "restore-vm",
              "running", "save-vm", "shutdown", "watchdog", "guest-panicked")

typedef enum {
    QEMU_MONITOR_BLOCK_IO_STATUS_OK,
    QEMU_MONITOR_BLOCK_IO_STATUS_FAILED,
    QEMU_MONITOR_BLOCK_IO_STATUS_NOSPACE,

    QEMU_MONITOR_BLOCK_IO_STATUS_LAST
} qemuMonitorBlockIOStatus;

VIR_ENUM_DECL(qemuMonitorBlockIOStatus)

VIR_ENUM_IMPL(qemuMonitorBlockIOStatus,
              QEMU_MONITOR_BLOCK_IO_STATUS_LAST,
              "ok", "failed", "nospace")

char *
qemuMonitorEscapeArg(const char *in)
{
    int len = 0;
    size_t i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch (in[i]) {
        case '\r':
        case '\n':
        case '"':
        case '\\':
            len += 2;
            break;
        default:
            len += 1;
            break;
        }
    }

    if (VIR_ALLOC_N(out, len + 1) < 0)
        return NULL;

    for (i = j = 0; in[i] != '\0'; i++) {
        switch (in[i]) {
        case '\r':
            out[j++] = '\\';
            out[j++] = 'r';
            break;
        case '\n':
            out[j++] = '\\';
            out[j++] = 'n';
            break;
        case '"':
        case '\\':
            out[j++] = '\\';
            out[j++] = in[i];
            break;
        default:
            out[j++] = in[i];
            break;
        }
    }
    out[j] = '\0';

    return out;
}


char *
qemuMonitorUnescapeArg(const char *in)
{
    size_t i, j;
    char *out;
    int len = strlen(in);
    char next;

    if (VIR_ALLOC_N(out, len + 1) < 0)
        return NULL;

    for (i = j = 0; i < len; ++i) {
        next = in[i];
        if (in[i] == '\\') {
            ++i;
            switch (in[i]) {
            case 'r':
                next = '\r';
                break;
            case 'n':
                next = '\n';
                break;
            case '"':
            case '\\':
                next = in[i];
                break;
            default:
                /* invalid input (including trailing '\' at end of in) */
                VIR_FREE(out);
                return NULL;
            }
        }
        out[j++] = next;
    }
    out[j] = '\0';

    return out;
}


#if DEBUG_RAW_IO
# include <c-ctype.h>
static char *
qemuMonitorEscapeNonPrintable(const char *text)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    for (i = 0; text[i] != '\0'; i++) {
        if (c_isprint(text[i]) ||
            text[i] == '\n' ||
            (text[i] == '\r' && text[i + 1] == '\n'))
            virBufferAddChar(&buf, text[i]);
        else
            virBufferAsprintf(&buf, "0x%02x", text[i]);
    }
    return virBufferContentAndReset(&buf);
}
#endif


static void
qemuMonitorDispose(void *obj)
{
    qemuMonitorPtr mon = obj;

    VIR_DEBUG("mon=%p", mon);
    if (mon->cb && mon->cb->destroy)
        (mon->cb->destroy)(mon, mon->vm, mon->callbackOpaque);
    virObjectUnref(mon->vm);

    virResetError(&mon->lastError);
    virCondDestroy(&mon->notify);
    VIR_FREE(mon->buffer);
    virJSONValueFree(mon->options);
    VIR_FREE(mon->balloonpath);
}


static int
qemuMonitorOpenUnix(const char *monitor, pid_t cpid)
{
    struct sockaddr_un addr;
    int monfd;
    virTimeBackOffVar timeout;
    int ret = -1;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Monitor path %s too big for destination"), monitor);
        goto error;
    }

    if (virTimeBackOffStart(&timeout, 1, 30*1000 /* ms */) < 0)
        goto error;
    while (virTimeBackOffWait(&timeout)) {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));

        if (ret == 0)
            break;

        if ((errno == ENOENT || errno == ECONNREFUSED) &&
            (!cpid || virProcessKill(cpid, 0) == 0)) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        virReportSystemError(errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;

    }

    if (ret != 0) {
        virReportSystemError(errno, "%s",
                             _("monitor socket did not show up"));
        goto error;
    }

    return monfd;

 error:
    VIR_FORCE_CLOSE(monfd);
    return -1;
}


static int
qemuMonitorOpenPty(const char *monitor)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    return monfd;
}


/* This method processes data that has been received
 * from the monitor. Looking for async events and
 * replies/errors.
 */
static int
qemuMonitorIOProcess(qemuMonitorPtr mon)
{
    int len;
    qemuMonitorMessagePtr msg = NULL;

    /* See if there's a message & whether its ready for its reply
     * ie whether its completed writing all its data */
    if (mon->msg && mon->msg->txOffset == mon->msg->txLength)
        msg = mon->msg;

#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuMonitorEscapeNonPrintable(msg ? msg->txBuffer : "");
    char *str2 = qemuMonitorEscapeNonPrintable(mon->buffer);
    VIR_ERROR(_("Process %d %p %p [[[[%s]]][[[%s]]]"), (int)mon->bufferOffset, mon->msg, msg, str1, str2);
    VIR_FREE(str1);
    VIR_FREE(str2);
# else
    VIR_DEBUG("Process %d", (int)mon->bufferOffset);
# endif
#endif

    PROBE(QEMU_MONITOR_IO_PROCESS,
          "mon=%p buf=%s len=%zu", mon, mon->buffer, mon->bufferOffset);

    if (mon->json)
        len = qemuMonitorJSONIOProcess(mon,
                                       mon->buffer, mon->bufferOffset,
                                       msg);
    else
        len = qemuMonitorTextIOProcess(mon,
                                       mon->buffer, mon->bufferOffset,
                                       msg);

    if (len < 0)
        return -1;

    if (len && mon->waitGreeting)
        mon->waitGreeting = false;

    if (len < mon->bufferOffset) {
        memmove(mon->buffer, mon->buffer + len, mon->bufferOffset - len);
        mon->bufferOffset -= len;
    } else {
        VIR_FREE(mon->buffer);
        mon->bufferOffset = mon->bufferLength = 0;
    }
#if DEBUG_IO
    VIR_DEBUG("Process done %d used %d", (int)mon->bufferOffset, len);
#endif
    if (msg && msg->finished)
        virCondBroadcast(&mon->notify);
    return len;
}


/* Call this function while holding the monitor lock. */
static int
qemuMonitorIOWriteWithFD(qemuMonitorPtr mon,
                         const char *data,
                         size_t len,
                         int fd)
{
    struct msghdr msg;
    struct iovec iov[1];
    int ret;
    char control[CMSG_SPACE(sizeof(int))];
    struct cmsghdr *cmsg;

    memset(&msg, 0, sizeof(msg));
    memset(control, 0, sizeof(control));

    iov[0].iov_base = (void *)data;
    iov[0].iov_len = len;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);

    cmsg = CMSG_FIRSTHDR(&msg);
    /* Some static analyzers, like clang 2.6-0.6.pre2, fail to see
       that our use of CMSG_FIRSTHDR will not return NULL.  */
    sa_assert(cmsg);
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

    do {
        ret = sendmsg(mon->fd, &msg, 0);
    } while (ret < 0 && errno == EINTR);

    return ret;
}


/*
 * Called when the monitor is able to write data
 * Call this function while holding the monitor lock.
 */
static int
qemuMonitorIOWrite(qemuMonitorPtr mon)
{
    int done;
    char *buf;
    size_t len;

    /* If no active message, or fully transmitted, the no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    if (mon->msg->txFD != -1 && !mon->hasSendFD) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Monitor does not support sending of file descriptors"));
        return -1;
    }

    buf = mon->msg->txBuffer + mon->msg->txOffset;
    len = mon->msg->txLength - mon->msg->txOffset;
    if (mon->msg->txFD == -1)
        done = write(mon->fd, buf, len);
    else
        done = qemuMonitorIOWriteWithFD(mon, buf, len, mon->msg->txFD);

    PROBE(QEMU_MONITOR_IO_WRITE,
          "mon=%p buf=%s len=%zu ret=%d errno=%d",
          mon, buf, len, done, done < 0 ? errno : 0);

    if (mon->msg->txFD != -1) {
        PROBE(QEMU_MONITOR_IO_SEND_FD,
              "mon=%p fd=%d ret=%d errno=%d",
              mon, mon->msg->txFD, done, done < 0 ? errno : 0);
    }

    if (done < 0) {
        if (errno == EAGAIN)
            return 0;

        virReportSystemError(errno, "%s",
                             _("Unable to write to monitor"));
        return -1;
    }
    mon->msg->txOffset += done;
    return done;
}


/*
 * Called when the monitor has incoming data to read
 * Call this function while holding the monitor lock.
 *
 * Returns -1 on error, or number of bytes read
 */
static int
qemuMonitorIORead(qemuMonitorPtr mon)
{
    size_t avail = mon->bufferLength - mon->bufferOffset;
    int ret = 0;

    if (avail < 1024) {
        if (VIR_REALLOC_N(mon->buffer,
                          mon->bufferLength + 1024) < 0)
            return -1;
        mon->bufferLength += 1024;
        avail += 1024;
    }

    /* Read as much as we can get into our buffer,
       until we block on EAGAIN, or hit EOF */
    while (avail > 1) {
        int got;
        got = read(mon->fd,
                   mon->buffer + mon->bufferOffset,
                   avail - 1);
        if (got < 0) {
            if (errno == EAGAIN)
                break;
            virReportSystemError(errno, "%s",
                                 _("Unable to read from monitor"));
            ret = -1;
            break;
        }
        if (got == 0)
            break;

        ret += got;
        avail -= got;
        mon->bufferOffset += got;
        mon->buffer[mon->bufferOffset] = '\0';
    }

#if DEBUG_IO
    VIR_DEBUG("Now read %d bytes of data", (int)mon->bufferOffset);
#endif

    return ret;
}


static void
qemuMonitorUpdateWatch(qemuMonitorPtr mon)
{
    int events =
        VIR_EVENT_HANDLE_HANGUP |
        VIR_EVENT_HANDLE_ERROR;

    if (!mon->watch)
        return;

    if (mon->lastError.code == VIR_ERR_OK) {
        events |= VIR_EVENT_HANDLE_READABLE;

        if ((mon->msg && mon->msg->txOffset < mon->msg->txLength) &&
            !mon->waitGreeting)
            events |= VIR_EVENT_HANDLE_WRITABLE;
    }

    virEventUpdateHandle(mon->watch, events);
}


static void
qemuMonitorIO(int watch, int fd, int events, void *opaque)
{
    qemuMonitorPtr mon = opaque;
    bool error = false;
    bool eof = false;
    bool hangup = false;

    virObjectRef(mon);

    /* lock access to the monitor and protect fd */
    virObjectLock(mon);
#if DEBUG_IO
    VIR_DEBUG("Monitor %p I/O on watch %d fd %d events %d", mon, watch, fd, events);
#endif
    if (mon->fd == -1 || mon->watch == 0) {
        virObjectUnlock(mon);
        virObjectUnref(mon);
        return;
    }

    if (mon->fd != fd || mon->watch != watch) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("event from unexpected fd %d!=%d / watch %d!=%d"),
                       mon->fd, fd, mon->watch, watch);
        error = true;
    } else if (mon->lastError.code != VIR_ERR_OK) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        error = true;
    } else {
        if (events & VIR_EVENT_HANDLE_WRITABLE) {
            if (qemuMonitorIOWrite(mon) < 0) {
                error = true;
                if (errno == ECONNRESET)
                    hangup = true;
            }
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }

        if (!error &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuMonitorIORead(mon);
            events &= ~VIR_EVENT_HANDLE_READABLE;
            if (got < 0) {
                error = true;
                if (errno == ECONNRESET)
                    hangup = true;
            } else if (got == 0) {
                eof = true;
            } else {
                /* Ignore hangup/error events if we read some data, to
                 * give time for that data to be consumed */
                events = 0;

                if (qemuMonitorIOProcess(mon) < 0)
                    error = true;
            }
        }

        if (events & VIR_EVENT_HANDLE_HANGUP) {
            hangup = true;
            if (!error) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("End of file from qemu monitor"));
                eof = true;
                events &= ~VIR_EVENT_HANDLE_HANGUP;
            }
        }

        if (!error && !eof &&
            events & VIR_EVENT_HANDLE_ERROR) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Invalid file descriptor while waiting for monitor"));
            eof = true;
            events &= ~VIR_EVENT_HANDLE_ERROR;
        }
        if (!error && events) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unhandled event %d for monitor fd %d"),
                           events, mon->fd);
            error = true;
        }
    }

    if (error || eof) {
        if (hangup && mon->logFunc != NULL) {
            /* Check if an error message from qemu is available and if so, use
             * it to overwrite the actual message. It's done only in early
             * startup phases or during incoming migration when the message
             * from qemu is certainly more interesting than a
             * "connection reset by peer" message.
             */
            mon->logFunc(mon,
                         _("qemu unexpectedly closed the monitor"),
                         mon->logOpaque);
            virCopyLastError(&mon->lastError);
            virResetLastError();
        }

        if (mon->lastError.code != VIR_ERR_OK) {
            /* Already have an error, so clear any new error */
            virResetLastError();
        } else {
            virErrorPtr err = virGetLastError();
            if (!err)
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Error while processing monitor IO"));
            virCopyLastError(&mon->lastError);
            virResetLastError();
        }

        VIR_DEBUG("Error on monitor %s", NULLSTR(mon->lastError.message));
        /* If IO process resulted in an error & we have a message,
         * then wakeup that waiter */
        if (mon->msg && !mon->msg->finished) {
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }
    }

    qemuMonitorUpdateWatch(mon);

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (eof) {
        qemuMonitorEofNotifyCallback eofNotify = mon->cb->eofNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        virObjectUnlock(mon);
        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(mon, vm, mon->callbackOpaque);
        virObjectUnref(mon);
    } else if (error) {
        qemuMonitorErrorNotifyCallback errorNotify = mon->cb->errorNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        virObjectUnlock(mon);
        VIR_DEBUG("Triggering error callback");
        (errorNotify)(mon, vm, mon->callbackOpaque);
        virObjectUnref(mon);
    } else {
        virObjectUnlock(mon);
        virObjectUnref(mon);
    }
}


static qemuMonitorPtr
qemuMonitorOpenInternal(virDomainObjPtr vm,
                        int fd,
                        bool hasSendFD,
                        bool json,
                        qemuMonitorCallbacksPtr cb,
                        void *opaque)
{
    qemuMonitorPtr mon;

    if (!cb->eofNotify) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("EOF notify callback must be supplied"));
        return NULL;
    }
    if (!cb->errorNotify) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Error notify callback must be supplied"));
        return NULL;
    }

    if (qemuMonitorInitialize() < 0)
        return NULL;

    if (!(mon = virObjectLockableNew(qemuMonitorClass)))
        return NULL;

    if (virCondInit(&mon->notify) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot initialize monitor condition"));
        goto cleanup;
    }
    mon->fd = fd;
    mon->hasSendFD = hasSendFD;
    mon->vm = virObjectRef(vm);
    mon->json = json;
    if (json)
        mon->waitGreeting = true;
    mon->cb = cb;
    mon->callbackOpaque = opaque;

    if (virSetCloseExec(mon->fd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Unable to set monitor close-on-exec flag"));
        goto cleanup;
    }
    if (virSetNonBlock(mon->fd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("Unable to put monitor into non-blocking mode"));
        goto cleanup;
    }


    virObjectLock(mon);
    virObjectRef(mon);
    if ((mon->watch = virEventAddHandle(mon->fd,
                                        VIR_EVENT_HANDLE_HANGUP |
                                        VIR_EVENT_HANDLE_ERROR |
                                        VIR_EVENT_HANDLE_READABLE,
                                        qemuMonitorIO,
                                        mon,
                                        virObjectFreeCallback)) < 0) {
        virObjectUnref(mon);
        virObjectUnlock(mon);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unable to register monitor events"));
        goto cleanup;
    }

    PROBE(QEMU_MONITOR_NEW,
          "mon=%p refs=%d fd=%d",
          mon, mon->parent.parent.u.s.refs, mon->fd);
    virObjectUnlock(mon);

    return mon;

 cleanup:
    /* We don't want the 'destroy' callback invoked during
     * cleanup from construction failure, because that can
     * give a double-unref on virDomainObjPtr in the caller,
     * so kill the callbacks now.
     */
    mon->cb = NULL;
    /* The caller owns 'fd' on failure */
    mon->fd = -1;
    qemuMonitorClose(mon);
    return NULL;
}


qemuMonitorPtr
qemuMonitorOpen(virDomainObjPtr vm,
                virDomainChrSourceDefPtr config,
                bool json,
                qemuMonitorCallbacksPtr cb,
                void *opaque)
{
    int fd;
    bool hasSendFD = false;
    qemuMonitorPtr ret;

    switch (config->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        hasSendFD = true;
        if ((fd = qemuMonitorOpenUnix(config->data.nix.path, vm ? vm->pid : 0)) < 0)
            return NULL;
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        if ((fd = qemuMonitorOpenPty(config->data.file.path)) < 0)
            return NULL;
        break;

    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unable to handle monitor type: %s"),
                       virDomainChrTypeToString(config->type));
        return NULL;
    }

    ret = qemuMonitorOpenInternal(vm, fd, hasSendFD, json, cb, opaque);
    if (!ret)
        VIR_FORCE_CLOSE(fd);
    return ret;
}


qemuMonitorPtr
qemuMonitorOpenFD(virDomainObjPtr vm,
                  int sockfd,
                  bool json,
                  qemuMonitorCallbacksPtr cb,
                  void *opaque)
{
    return qemuMonitorOpenInternal(vm, sockfd, true, json, cb, opaque);
}


void
qemuMonitorUnregister(qemuMonitorPtr mon)
{
    if (mon->watch) {
        virEventRemoveHandle(mon->watch);
        mon->watch = 0;
    }
}

void
qemuMonitorClose(qemuMonitorPtr mon)
{
    if (!mon)
        return;

    virObjectLock(mon);
    PROBE(QEMU_MONITOR_CLOSE,
          "mon=%p refs=%d", mon, mon->parent.parent.u.s.refs);

    qemuMonitorSetDomainLog(mon, NULL, NULL, NULL);

    if (mon->fd >= 0) {
        qemuMonitorUnregister(mon);
        VIR_FORCE_CLOSE(mon->fd);
    }

    /* In case another thread is waiting for its monitor command to be
     * processed, we need to wake it up with appropriate error set.
     */
    if (mon->msg) {
        if (mon->lastError.code == VIR_ERR_OK) {
            virErrorPtr err = virSaveLastError();

            virReportError(VIR_ERR_OPERATION_FAILED, "%s",
                           _("Qemu monitor was closed"));
            virCopyLastError(&mon->lastError);
            if (err) {
                virSetError(err);
                virFreeError(err);
            } else {
                virResetLastError();
            }
        }
        mon->msg->finished = 1;
        virCondSignal(&mon->notify);
    }

    /* Propagate existing monitor error in case the current thread has no
     * error set.
     */
    if (mon->lastError.code != VIR_ERR_OK && !virGetLastError())
        virSetError(&mon->lastError);

    virObjectUnlock(mon);
    virObjectUnref(mon);
}


char *
qemuMonitorNextCommandID(qemuMonitorPtr mon)
{
    char *id;

    ignore_value(virAsprintf(&id, "libvirt-%d", ++mon->nextSerial));
    return id;
}


int
qemuMonitorSend(qemuMonitorPtr mon,
                qemuMonitorMessagePtr msg)
{
    int ret = -1;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    PROBE(QEMU_MONITOR_SEND_MSG,
          "mon=%p msg=%s fd=%d",
          mon, mon->msg->txBuffer, mon->msg->txFD);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->parent.lock) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to wait on monitor condition"));
            goto cleanup;
        }
    }

    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Send command resulted in error %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}


/**
 * This function returns a new virError object; the caller is responsible
 * for freeing it.
 */
virErrorPtr
qemuMonitorLastError(qemuMonitorPtr mon)
{
    if (mon->lastError.code == VIR_ERR_OK)
        return NULL;

    return virErrorCopyNew(&mon->lastError);
}


virJSONValuePtr
qemuMonitorGetOptions(qemuMonitorPtr mon)
{
    return mon->options;
}


void
qemuMonitorSetOptions(qemuMonitorPtr mon, virJSONValuePtr options)
{
    mon->options = options;
}


/**
 * Search the qom objects for the balloon driver object by its known names
 * of "virtio-balloon-pci" or "virtio-balloon-ccw". The entry for the driver
 * will be found by using function "qemuMonitorJSONFindLinkPath".
 *
 * Once found, check the entry to ensure it has the correct property listed.
 * If it does not, then obtaining statistics from QEMU will not be possible.
 * This feature was added to QEMU 1.5.
 */
static void
qemuMonitorInitBalloonObjectPath(qemuMonitorPtr mon,
                                 virDomainMemballoonDefPtr balloon)
{
    ssize_t i, nprops = 0;
    char *path = NULL;
    const char *name;
    qemuMonitorJSONListPathPtr *bprops = NULL;

    if (mon->balloonpath) {
        return;
    } else if (mon->ballooninit) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Cannot determine balloon device path"));
        return;
    }
    mon->ballooninit = true;

    switch (balloon->info.type) {
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI:
        name = "virtio-balloon-pci";
        break;
    case VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW:
        name = "virtio-balloon-ccw";
        break;
    default:
        return;
    }

    if (qemuMonitorJSONFindLinkPath(mon, name, balloon->info.alias, &path) < 0)
        return;

    nprops = qemuMonitorJSONGetObjectListPaths(mon, path, &bprops);
    if (nprops < 0)
        goto cleanup;

    for (i = 0; i < nprops; i++) {
        if (STREQ(bprops[i]->name, "guest-stats-polling-interval")) {
            VIR_DEBUG("Found Balloon Object Path %s", path);
            mon->balloonpath = path;
            path = NULL;
            goto cleanup;
        }
    }


    /* If we get here, we found the path, but not the property */
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                   _("Property 'guest-stats-polling-interval' "
                     "not found on memory balloon driver."));

 cleanup:
    for (i = 0; i < nprops; i++)
        qemuMonitorJSONListPathFree(bprops[i]);
    VIR_FREE(bprops);
    VIR_FREE(path);
    return;
}


/**
 * To update video memory size in status XML we need to load correct values from
 * QEMU.  This is supported only with JSON monitor.
 *
 * Returns 0 on success, -1 on failure and sets proper error message.
 */
int
qemuMonitorUpdateVideoMemorySize(qemuMonitorPtr mon,
                                 virDomainVideoDefPtr video,
                                 const char *videoName)
{
    int ret = -1;
    char *path = NULL;

    QEMU_CHECK_MONITOR(mon);

    if (mon->json) {
        ret = qemuMonitorJSONFindLinkPath(mon, videoName,
                                          video->info.alias, &path);
        if (ret < 0) {
            if (ret == -2)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to find QOM Object path for "
                                 "device '%s'"), videoName);
            return -1;
        }

        ret = qemuMonitorJSONUpdateVideoMemorySize(mon, video, path);
        VIR_FREE(path);
        return ret;
    }

    return 0;
}


/**
 * To update video vram64 size in status XML we need to load correct value from
 * QEMU.  This is supported only with JSON monitor.
 *
 * Returns 0 on success, -1 on failure and sets proper error message.
 */
int
qemuMonitorUpdateVideoVram64Size(qemuMonitorPtr mon,
                                 virDomainVideoDefPtr video,
                                 const char *videoName)
{
    int ret = -1;
    char *path = NULL;

    QEMU_CHECK_MONITOR(mon);

    if (mon->json) {
        ret = qemuMonitorJSONFindLinkPath(mon, videoName,
                                          video->info.alias, &path);
        if (ret < 0) {
            if (ret == -2)
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Failed to find QOM Object path for "
                                 "device '%s'"), videoName);
            return -1;
        }

        ret = qemuMonitorJSONUpdateVideoVram64Size(mon, video, path);
        VIR_FREE(path);
        return ret;
    }

    return 0;
}


int
qemuMonitorHMPCommandWithFd(qemuMonitorPtr mon,
                            const char *cmd,
                            int scm_fd,
                            char **reply)
{
    char *json_cmd = NULL;
    int ret = -1;

    QEMU_CHECK_MONITOR(mon);

    if (mon->json) {
        /* hack to avoid complicating each call to text monitor functions */
        json_cmd = qemuMonitorUnescapeArg(cmd);
        if (!json_cmd) {
            VIR_DEBUG("Could not unescape command: %s", cmd);
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to unescape command"));
            goto cleanup;
        }
        ret = qemuMonitorJSONHumanCommandWithFd(mon, json_cmd, scm_fd, reply);
    } else {
        ret = qemuMonitorTextCommandWithFd(mon, cmd, scm_fd, reply);
    }

 cleanup:
    VIR_FREE(json_cmd);
    return ret;
}


/* Ensure proper locking around callbacks.  */
#define QEMU_MONITOR_CALLBACK(mon, ret, callback, ...)          \
    do {                                                        \
        virObjectRef(mon);                                      \
        virObjectUnlock(mon);                                   \
        if ((mon)->cb && (mon)->cb->callback)                   \
            (ret) = (mon)->cb->callback(mon, __VA_ARGS__,       \
                                        (mon)->callbackOpaque); \
        virObjectLock(mon);                                     \
        virObjectUnref(mon);                                    \
    } while (0)


int
qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                         virConnectPtr conn,
                         const char *path,
                         char **secret,
                         size_t *secretLen)
{
    int ret = -1;
    *secret = NULL;
    *secretLen = 0;

    QEMU_MONITOR_CALLBACK(mon, ret, diskSecretLookup, conn, mon->vm,
                          path, secret, secretLen);
    return ret;
}


int
qemuMonitorEmitEvent(qemuMonitorPtr mon, const char *event,
                     long long seconds, unsigned int micros,
                     const char *details)
{
    int ret = -1;
    VIR_DEBUG("mon=%p event=%s", mon, event);

    QEMU_MONITOR_CALLBACK(mon, ret, domainEvent, mon->vm, event, seconds,
                          micros, details);
    return ret;
}


int
qemuMonitorEmitShutdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainShutdown, mon->vm);
    return ret;
}


int
qemuMonitorEmitReset(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainReset, mon->vm);
    return ret;
}


int
qemuMonitorEmitPowerdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPowerdown, mon->vm);
    return ret;
}


int
qemuMonitorEmitStop(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainStop, mon->vm);
    return ret;
}


int
qemuMonitorEmitResume(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainResume, mon->vm);
    return ret;
}


int
qemuMonitorEmitGuestPanic(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);
    QEMU_MONITOR_CALLBACK(mon, ret, domainGuestPanic, mon->vm);
    return ret;
}


int
qemuMonitorEmitRTCChange(qemuMonitorPtr mon, long long offset)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainRTCChange, mon->vm, offset);
    return ret;
}


int
qemuMonitorEmitWatchdog(qemuMonitorPtr mon, int action)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainWatchdog, mon->vm, action);
    return ret;
}


int
qemuMonitorEmitIOError(qemuMonitorPtr mon,
                       const char *diskAlias,
                       int action,
                       const char *reason)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainIOError, mon->vm,
                          diskAlias, action, reason);
    return ret;
}


int
qemuMonitorEmitGraphics(qemuMonitorPtr mon,
                        int phase,
                        int localFamily,
                        const char *localNode,
                        const char *localService,
                        int remoteFamily,
                        const char *remoteNode,
                        const char *remoteService,
                        const char *authScheme,
                        const char *x509dname,
                        const char *saslUsername)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainGraphics, mon->vm, phase,
                          localFamily, localNode, localService,
                          remoteFamily, remoteNode, remoteService,
                          authScheme, x509dname, saslUsername);
    return ret;
}


int
qemuMonitorEmitTrayChange(qemuMonitorPtr mon,
                          const char *devAlias,
                          int reason)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainTrayChange, mon->vm,
                          devAlias, reason);

    return ret;
}


int
qemuMonitorEmitPMWakeup(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPMWakeup, mon->vm);

    return ret;
}


int
qemuMonitorEmitPMSuspend(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPMSuspend, mon->vm);

    return ret;
}


int
qemuMonitorEmitPMSuspendDisk(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPMSuspendDisk, mon->vm);

    return ret;
}


int
qemuMonitorEmitBlockJob(qemuMonitorPtr mon,
                        const char *diskAlias,
                        int type,
                        int status)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainBlockJob, mon->vm,
                          diskAlias, type, status);
    return ret;
}


int
qemuMonitorEmitBalloonChange(qemuMonitorPtr mon,
                             unsigned long long actual)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainBalloonChange, mon->vm, actual);
    return ret;
}


int
qemuMonitorEmitDeviceDeleted(qemuMonitorPtr mon,
                             const char *devAlias)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainDeviceDeleted, mon->vm, devAlias);

    return ret;
}


int
qemuMonitorEmitNicRxFilterChanged(qemuMonitorPtr mon,
                                  const char *devAlias)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainNicRxFilterChanged, mon->vm, devAlias);

    return ret;
}


int
qemuMonitorEmitSerialChange(qemuMonitorPtr mon,
                            const char *devAlias,
                            bool connected)
{
    int ret = -1;
    VIR_DEBUG("mon=%p, devAlias='%s', connected=%d", mon, devAlias, connected);

    QEMU_MONITOR_CALLBACK(mon, ret, domainSerialChange, mon->vm, devAlias, connected);

    return ret;
}


int
qemuMonitorEmitSpiceMigrated(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainSpiceMigrated, mon->vm);

    return ret;
}


int
qemuMonitorEmitMigrationStatus(qemuMonitorPtr mon,
                               int status)
{
    int ret = -1;
    VIR_DEBUG("mon=%p, status=%s",
              mon, NULLSTR(qemuMonitorMigrationStatusTypeToString(status)));

    QEMU_MONITOR_CALLBACK(mon, ret, domainMigrationStatus, mon->vm, status);

    return ret;
}


int
qemuMonitorEmitMigrationPass(qemuMonitorPtr mon,
                             int pass)
{
    int ret = -1;
    VIR_DEBUG("mon=%p, pass=%d", mon, pass);

    QEMU_MONITOR_CALLBACK(mon, ret, domainMigrationPass, mon->vm, pass);

    return ret;
}


int
qemuMonitorEmitAcpiOstInfo(qemuMonitorPtr mon,
                           const char *alias,
                           const char *slotType,
                           const char *slot,
                           unsigned int source,
                           unsigned int status)
{
    int ret = -1;
    VIR_DEBUG("mon=%p, alias='%s', slotType='%s', slot='%s', source='%u' status=%u",
              mon, NULLSTR(alias), slotType, slot, source, status);

    QEMU_MONITOR_CALLBACK(mon, ret, domainAcpiOstInfo, mon->vm,
                          alias, slotType, slot, source, status);

    return ret;
}


int
qemuMonitorSetCapabilities(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (!mon->json)
        return 0;

    return qemuMonitorJSONSetCapabilities(mon);
}


int
qemuMonitorStartCPUs(qemuMonitorPtr mon,
                     virConnectPtr conn)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONStartCPUs(mon, conn);
    else
        return qemuMonitorTextStartCPUs(mon, conn);
}


int
qemuMonitorStopCPUs(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONStopCPUs(mon);
    else
        return qemuMonitorTextStopCPUs(mon);
}


int
qemuMonitorCheck(qemuMonitorPtr mon)
{
    bool running;
    return qemuMonitorGetStatus(mon, &running, NULL);
}


int
qemuMonitorGetStatus(qemuMonitorPtr mon,
                     bool *running,
                     virDomainPausedReason *reason)
{
    VIR_DEBUG("running=%p, reason=%p", running, reason);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGetStatus(mon, running, reason);
    else
        return qemuMonitorTextGetStatus(mon, running, reason);
}


int
qemuMonitorSystemPowerdown(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSystemPowerdown(mon);
    else
        return qemuMonitorTextSystemPowerdown(mon);
}


int
qemuMonitorSystemReset(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSystemReset(mon);
    else
        return qemuMonitorTextSystemReset(mon);
}


static void
qemuMonitorCPUInfoClear(qemuMonitorCPUInfoPtr cpus,
                        size_t ncpus)
{
    size_t i;

    for (i = 0; i < ncpus; i++) {
        cpus[i].id = 0;
        cpus[i].qemu_id = -1;
        cpus[i].socket_id = -1;
        cpus[i].core_id = -1;
        cpus[i].thread_id = -1;
        cpus[i].vcpus = 0;
        cpus[i].tid = 0;
        cpus[i].halted = false;

        VIR_FREE(cpus[i].qom_path);
        VIR_FREE(cpus[i].alias);
        VIR_FREE(cpus[i].type);
    }
}


void
qemuMonitorCPUInfoFree(qemuMonitorCPUInfoPtr cpus,
                       size_t ncpus)
{
    if (!cpus)
        return;

    qemuMonitorCPUInfoClear(cpus, ncpus);

    VIR_FREE(cpus);
}

void
qemuMonitorQueryCpusFree(struct qemuMonitorQueryCpusEntry *entries,
                         size_t nentries)
{
    size_t i;

    if (!entries)
        return;

    for (i = 0; i < nentries; i++)
        VIR_FREE(entries[i].qom_path);

    VIR_FREE(entries);
}


/**
 * Legacy approach doesn't allow out of order cpus, thus no complex matching
 * algorithm is necessary */
static void
qemuMonitorGetCPUInfoLegacy(struct qemuMonitorQueryCpusEntry *cpuentries,
                            size_t ncpuentries,
                            qemuMonitorCPUInfoPtr vcpus,
                            size_t maxvcpus)
{
    size_t i;

    for (i = 0; i < maxvcpus; i++) {
        if (i < ncpuentries) {
            vcpus[i].tid = cpuentries[i].tid;
            vcpus[i].halted = cpuentries[i].halted;
            vcpus[i].qemu_id = cpuentries[i].qemu_id;
        }

        /* for legacy hotplug to work we need to fake the vcpu count added by
         * enabling a given vcpu */
        vcpus[i].vcpus = 1;
    }
}


/**
 * qemuMonitorGetCPUInfoHotplug:
 *
 * This function stitches together data retrieved via query-hotpluggable-cpus
 * which returns entities on the hotpluggable level (which may describe more
 * than one guest logical vcpu) with the output of query-cpus, having an entry
 * per enabled guest logical vcpu.
 *
 * query-hotpluggable-cpus conveys following information:
 * - topology information and number of logical vcpus this entry creates
 * - device type name of the entry that needs to be used when hotplugging
 * - qom path in qemu which can be used to map the entry against query-cpus
 *
 * query-cpus conveys following information:
 * - thread id of a given guest logical vcpu
 * - order in which the vcpus were inserted
 * - qom path to allow mapping the two together
 *
 * The libvirt's internal structure has an entry for each possible (even
 * disabled) guest vcpu. The purpose is to map the data together so that we are
 * certain of the thread id mapping and the information required for vcpu
 * hotplug.
 *
 * This function returns 0 on success and -1 on error, but does not report
 * libvirt errors so that fallback approach can be used.
 */
static int
qemuMonitorGetCPUInfoHotplug(struct qemuMonitorQueryHotpluggableCpusEntry *hotplugvcpus,
                             size_t nhotplugvcpus,
                             struct qemuMonitorQueryCpusEntry *cpuentries,
                             size_t ncpuentries,
                             qemuMonitorCPUInfoPtr vcpus,
                             size_t maxvcpus)
{
    char *tmp;
    int order = 1;
    size_t totalvcpus = 0;
    size_t mastervcpu; /* this iterator is used for iterating hotpluggable entities */
    size_t slavevcpu; /* this corresponds to subentries of a hotpluggable entry */
    size_t anyvcpu; /* this iterator is used for any vcpu entry in the result */
    size_t i;
    size_t j;

    /* ensure that the total vcpu count reported by query-hotpluggable-cpus equals
     * to the libvirt maximum cpu count */
    for (i = 0; i < nhotplugvcpus; i++)
        totalvcpus += hotplugvcpus[i].vcpus;

    /* trim '/thread...' suffix from the data returned by query-cpus */
    for (i = 0; i < ncpuentries; i++) {
        if (cpuentries[i].qom_path &&
            (tmp = strstr(cpuentries[i].qom_path, "/thread")))
            *tmp = '\0';
    }

    if (totalvcpus != maxvcpus) {
        VIR_DEBUG("expected '%zu' total vcpus got '%zu'", maxvcpus, totalvcpus);
        return -1;
    }

    /* Note the order in which the hotpluggable entities are inserted by
     * matching them to the query-cpus entries */
    for (i = 0; i < ncpuentries; i++) {
        for (j = 0; j < nhotplugvcpus; j++) {
            if (!cpuentries[i].qom_path ||
                !hotplugvcpus[j].qom_path ||
                STRNEQ(cpuentries[i].qom_path, hotplugvcpus[j].qom_path))
                continue;

            /* add ordering info for hotpluggable entries */
            if (hotplugvcpus[j].enable_id == 0)
                hotplugvcpus[j].enable_id = order++;

            break;
        }
    }

    /* transfer appropriate data from the hotpluggable list to corresponding
     * entries. the entries returned by qemu may in fact describe multiple
     * logical vcpus in the guest */
    mastervcpu = 0;
    for (i = 0; i < nhotplugvcpus; i++) {
        vcpus[mastervcpu].online = !!hotplugvcpus[i].qom_path;
        vcpus[mastervcpu].hotpluggable = !!hotplugvcpus[i].alias ||
                                         !vcpus[mastervcpu].online;
        vcpus[mastervcpu].socket_id = hotplugvcpus[i].socket_id;
        vcpus[mastervcpu].core_id = hotplugvcpus[i].core_id;
        vcpus[mastervcpu].thread_id = hotplugvcpus[i].thread_id;
        vcpus[mastervcpu].vcpus = hotplugvcpus[i].vcpus;
        VIR_STEAL_PTR(vcpus[mastervcpu].qom_path, hotplugvcpus[i].qom_path);
        VIR_STEAL_PTR(vcpus[mastervcpu].alias, hotplugvcpus[i].alias);
        VIR_STEAL_PTR(vcpus[mastervcpu].type, hotplugvcpus[i].type);
        vcpus[mastervcpu].id = hotplugvcpus[i].enable_id;

        /* copy state information to slave vcpus */
        for (slavevcpu = mastervcpu + 1; slavevcpu < mastervcpu + hotplugvcpus[i].vcpus; slavevcpu++) {
            vcpus[slavevcpu].online = vcpus[mastervcpu].online;
            vcpus[slavevcpu].hotpluggable = vcpus[mastervcpu].hotpluggable;
        }

        /* calculate next master vcpu (hotpluggable unit) entry */
        mastervcpu += hotplugvcpus[i].vcpus;
    }

    /* match entries from query cpus to the output array taking into account
     * multi-vcpu objects */
    for (j = 0; j < ncpuentries; j++) {
        /* find the correct entry or beginning of group of entries */
        for (anyvcpu = 0; anyvcpu < maxvcpus; anyvcpu++) {
            if (cpuentries[j].qom_path && vcpus[anyvcpu].qom_path &&
                STREQ(cpuentries[j].qom_path, vcpus[anyvcpu].qom_path))
                break;
        }

        if (anyvcpu == maxvcpus) {
            VIR_DEBUG("too many query-cpus entries for a given "
                      "query-hotpluggable-cpus entry");
            return -1;
        }

        if (vcpus[anyvcpu].vcpus != 1) {
            /* find a possibly empty vcpu thread for core granularity systems */
            for (; anyvcpu < maxvcpus; anyvcpu++) {
                if (vcpus[anyvcpu].tid == 0)
                    break;
            }
        }

        vcpus[anyvcpu].qemu_id = cpuentries[j].qemu_id;
        vcpus[anyvcpu].tid = cpuentries[j].tid;
        vcpus[anyvcpu].halted = cpuentries[j].halted;
    }

    return 0;
}


/**
 * qemuMonitorGetCPUInfo:
 * @mon: monitor
 * @vcpus: pointer filled by array of qemuMonitorCPUInfo structures
 * @maxvcpus: total possible number of vcpus
 * @hotplug: query data relevant for hotplug support
 *
 * Detects VCPU information. If qemu doesn't support or fails reporting
 * information this function will return success as other parts of libvirt
 * are able to cope with that.
 *
 * Returns 0 on success (including if qemu didn't report any data) and
 *  -1 on error (reports libvirt error).
 */
int
qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                      qemuMonitorCPUInfoPtr *vcpus,
                      size_t maxvcpus,
                      bool hotplug)
{
    struct qemuMonitorQueryHotpluggableCpusEntry *hotplugcpus = NULL;
    size_t nhotplugcpus = 0;
    struct qemuMonitorQueryCpusEntry *cpuentries = NULL;
    size_t ncpuentries = 0;
    int ret = -1;
    int rc;
    qemuMonitorCPUInfoPtr info = NULL;

    QEMU_CHECK_MONITOR(mon);

    if (VIR_ALLOC_N(info, maxvcpus) < 0)
        return -1;

    if (!mon->json)
        hotplug = false;

    /* initialize a few non-zero defaults */
    qemuMonitorCPUInfoClear(info, maxvcpus);

    if (hotplug &&
        (qemuMonitorJSONGetHotpluggableCPUs(mon, &hotplugcpus, &nhotplugcpus)) < 0)
        goto cleanup;

    if (mon->json)
        rc = qemuMonitorJSONQueryCPUs(mon, &cpuentries, &ncpuentries, hotplug);
    else
        rc = qemuMonitorTextQueryCPUs(mon, &cpuentries, &ncpuentries);

    if (rc < 0) {
        if (!hotplug && rc == -2) {
            VIR_STEAL_PTR(*vcpus, info);
            ret = 0;
        }

        goto cleanup;
    }

    if (!hotplugcpus ||
        qemuMonitorGetCPUInfoHotplug(hotplugcpus, nhotplugcpus,
                                     cpuentries, ncpuentries,
                                     info, maxvcpus) < 0) {
        /* Fallback to the legacy algorithm. Hotplug paths will make sure that
         * the apropriate data is present */
        qemuMonitorCPUInfoClear(info, maxvcpus);
        qemuMonitorGetCPUInfoLegacy(cpuentries, ncpuentries, info, maxvcpus);
    }

    VIR_STEAL_PTR(*vcpus, info);
    ret = 0;

 cleanup:
    qemuMonitorQueryHotpluggableCpusFree(hotplugcpus, nhotplugcpus);
    qemuMonitorQueryCpusFree(cpuentries, ncpuentries);
    qemuMonitorCPUInfoFree(info, maxvcpus);
    return ret;
}


/**
 * qemuMonitorGetCpuHalted:
 *
 * Returns a bitmap of vcpu id's that are halted. The id's correspond to the
 * 'CPU' field as reported by query-cpus'.
 */
virBitmapPtr
qemuMonitorGetCpuHalted(qemuMonitorPtr mon,
                        size_t maxvcpus)
{
    struct qemuMonitorQueryCpusEntry *cpuentries = NULL;
    size_t ncpuentries = 0;
    size_t i;
    int rc;
    virBitmapPtr ret = NULL;

    QEMU_CHECK_MONITOR_NULL(mon);

    if (mon->json)
        rc = qemuMonitorJSONQueryCPUs(mon, &cpuentries, &ncpuentries, false);
    else
        rc = qemuMonitorTextQueryCPUs(mon, &cpuentries, &ncpuentries);

    if (rc < 0)
        goto cleanup;

    if (!(ret = virBitmapNew(maxvcpus)))
        goto cleanup;

    for (i = 0; i < ncpuentries; i++) {
        if (cpuentries[i].halted)
            ignore_value(virBitmapSetBit(ret, cpuentries[i].qemu_id));
    }

 cleanup:
    qemuMonitorQueryCpusFree(cpuentries, ncpuentries);
    return ret;
}


int
qemuMonitorSetLink(qemuMonitorPtr mon,
                   const char *name,
                   virDomainNetInterfaceLinkState state)
{
    VIR_DEBUG("name=%s, state=%u", name, state);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetLink(mon, name, state);
    else
        return qemuMonitorTextSetLink(mon, name, state);
}


int
qemuMonitorGetVirtType(qemuMonitorPtr mon,
                       virDomainVirtType *virtType)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGetVirtType(mon, virtType);
    else
        return qemuMonitorTextGetVirtType(mon, virtType);
}


/**
 * Returns: 0 if balloon not supported, +1 if balloon query worked
 * or -1 on failure
 */
int
qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                          unsigned long long *currmem)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGetBalloonInfo(mon, currmem);
    else
        return qemuMonitorTextGetBalloonInfo(mon, currmem);
}


int
qemuMonitorGetMemoryStats(qemuMonitorPtr mon,
                          virDomainMemballoonDefPtr balloon,
                          virDomainMemoryStatPtr stats,
                          unsigned int nr_stats)
{
    VIR_DEBUG("stats=%p nstats=%u", stats, nr_stats);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json) {
        qemuMonitorInitBalloonObjectPath(mon, balloon);
        return qemuMonitorJSONGetMemoryStats(mon, mon->balloonpath,
                                             stats, nr_stats);
    } else {
        return qemuMonitorTextGetMemoryStats(mon, stats, nr_stats);
    }
}


/**
 * qemuMonitorSetMemoryStatsPeriod:
 *
 * This function sets balloon stats update period.
 *
 * Returns 0 on success and -1 on error, but does *not* set an error.
 */
int
qemuMonitorSetMemoryStatsPeriod(qemuMonitorPtr mon,
                                virDomainMemballoonDefPtr balloon,
                                int period)
{
    int ret = -1;
    VIR_DEBUG("mon=%p period=%d", mon, period);

    if (!mon)
        return -1;

    if (!mon->json)
        return -1;

    if (period < 0)
        return -1;

    qemuMonitorInitBalloonObjectPath(mon, balloon);
    if (mon->balloonpath) {
        ret = qemuMonitorJSONSetMemoryStatsPeriod(mon, mon->balloonpath,
                                                  period);

        /*
         * Most of the calls to this function are supposed to be
         * non-fatal and the only one that should be fatal wants its
         * own error message.  More details for debugging will be in
         * the log file.
         */
        if (ret < 0)
            virResetLastError();
    }
    return ret;
}


int
qemuMonitorBlockIOStatusToError(const char *status)
{
    int st = qemuMonitorBlockIOStatusTypeFromString(status);

    if (st < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown block IO status: %s"), status);
        return -1;
    }

    switch ((qemuMonitorBlockIOStatus) st) {
    case QEMU_MONITOR_BLOCK_IO_STATUS_OK:
        return VIR_DOMAIN_DISK_ERROR_NONE;
    case QEMU_MONITOR_BLOCK_IO_STATUS_FAILED:
        return VIR_DOMAIN_DISK_ERROR_UNSPEC;
    case QEMU_MONITOR_BLOCK_IO_STATUS_NOSPACE:
        return VIR_DOMAIN_DISK_ERROR_NO_SPACE;

    /* unreachable */
    case QEMU_MONITOR_BLOCK_IO_STATUS_LAST:
        break;
    }
    return -1;
}


virHashTablePtr
qemuMonitorGetBlockInfo(qemuMonitorPtr mon)
{
    int ret;
    virHashTablePtr table;

    QEMU_CHECK_MONITOR_NULL(mon);

    if (!(table = virHashCreate(32, virHashValueFree)))
        return NULL;

    if (mon->json)
        ret = qemuMonitorJSONGetBlockInfo(mon, table);
    else
        ret = qemuMonitorTextGetBlockInfo(mon, table);

    if (ret < 0) {
        virHashFree(table);
        return NULL;
    }

    return table;
}


/**
 * qemuMonitorGetAllBlockStatsInfo:
 * @mon: monitor object
 * @ret_stats: pointer that is filled with a hash table containing the stats
 * @backingChain: recurse into the backing chain of devices
 *
 * Creates a hash table in @ret_stats with block stats of all devices. In case
 * @backingChain is true @ret_stats will additionally contain stats for
 * backing chain members of block devices.
 *
 * Returns < 0 on error, count of supported block stats fields on success.
 */
int
qemuMonitorGetAllBlockStatsInfo(qemuMonitorPtr mon,
                                virHashTablePtr *ret_stats,
                                bool backingChain)
{
    int ret = -1;
    VIR_DEBUG("ret_stats=%p, backing=%d", ret_stats, backingChain);

    QEMU_CHECK_MONITOR(mon);

    if (!(*ret_stats = virHashCreate(10, virHashValueFree)))
        goto error;

    if (mon->json) {
        ret = qemuMonitorJSONGetAllBlockStatsInfo(mon, *ret_stats,
                                                  backingChain);
    } else {
         if (backingChain) {
             virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                            _("text monitor doesn't support block stats for "
                              "backing chain members"));
             goto error;
         }

         ret = qemuMonitorTextGetAllBlockStatsInfo(mon, *ret_stats);
    }

    if (ret < 0)
        goto error;

    return ret;

 error:
    virHashFree(*ret_stats);
    *ret_stats = NULL;
    return -1;
}


/* Updates "stats" to fill virtual and physical size of the image */
int
qemuMonitorBlockStatsUpdateCapacity(qemuMonitorPtr mon,
                                    virHashTablePtr stats,
                                    bool backingChain)
{
    VIR_DEBUG("stats=%p, backing=%d", stats, backingChain);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONBlockStatsUpdateCapacity(mon, stats, backingChain);
}


int
qemuMonitorBlockResize(qemuMonitorPtr mon,
                       const char *device,
                       unsigned long long size)
{
    VIR_DEBUG("device=%s size=%llu", device, size);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONBlockResize(mon, device, size);
    else
        return qemuMonitorTextBlockResize(mon, device, size);
}


int
qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                          const char *password)
{
    VIR_DEBUG("password=%p", password);

    QEMU_CHECK_MONITOR(mon);

    if (!password)
        password = "";

    if (mon->json)
        return qemuMonitorJSONSetVNCPassword(mon, password);
    else
        return qemuMonitorTextSetVNCPassword(mon, password);
}


static const char *
qemuMonitorTypeToProtocol(int type)
{
    switch (type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        return "vnc";
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        return "spice";
    default:
        virReportError(VIR_ERR_INVALID_ARG,
                       _("unsupported protocol type %s"),
                       virDomainGraphicsTypeToString(type));
        return NULL;
    }
}


/* Returns -2 if not supported with this monitor connection */
int
qemuMonitorSetPassword(qemuMonitorPtr mon,
                       int type,
                       const char *password,
                       const char *action_if_connected)
{
    const char *protocol = qemuMonitorTypeToProtocol(type);

    if (!protocol)
        return -1;

    VIR_DEBUG("protocol=%s, password=%p, action_if_connected=%s",
              protocol, password, action_if_connected);

    QEMU_CHECK_MONITOR(mon);

    if (!password)
        password = "";

    if (!action_if_connected)
        action_if_connected = "keep";

    if (mon->json)
        return qemuMonitorJSONSetPassword(mon, protocol, password, action_if_connected);
    else
        return qemuMonitorTextSetPassword(mon, protocol, password, action_if_connected);
}


int
qemuMonitorExpirePassword(qemuMonitorPtr mon,
                          int type,
                          const char *expire_time)
{
    const char *protocol = qemuMonitorTypeToProtocol(type);

    if (!protocol)
        return -1;

    VIR_DEBUG("protocol=%s, expire_time=%s", protocol, expire_time);

    QEMU_CHECK_MONITOR(mon);

    if (!expire_time)
        expire_time = "now";

    if (mon->json)
        return qemuMonitorJSONExpirePassword(mon, protocol, expire_time);
    else
        return qemuMonitorTextExpirePassword(mon, protocol, expire_time);
}


/*
 * Returns: 0 if balloon not supported, +1 if balloon adjust worked
 * or -1 on failure
 */
int
qemuMonitorSetBalloon(qemuMonitorPtr mon,
                      unsigned long long newmem)
{
    VIR_DEBUG("newmem=%llu", newmem);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetBalloon(mon, newmem);
    else
        return qemuMonitorTextSetBalloon(mon, newmem);
}


/*
 * Returns: 0 if CPU modification was successful or -1 on failure
 */
int
qemuMonitorSetCPU(qemuMonitorPtr mon, int cpu, bool online)
{
    VIR_DEBUG("cpu=%d online=%d", cpu, online);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetCPU(mon, cpu, online);
    else
        return qemuMonitorTextSetCPU(mon, cpu, online);
}


int
qemuMonitorEjectMedia(qemuMonitorPtr mon,
                      const char *dev_name,
                      bool force)
{
    VIR_DEBUG("dev_name=%s force=%d", dev_name, force);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONEjectMedia(mon, dev_name, force);
    else
        return qemuMonitorTextEjectMedia(mon, dev_name, force);
}


int
qemuMonitorChangeMedia(qemuMonitorPtr mon,
                       const char *dev_name,
                       const char *newmedia,
                       const char *format)
{
    VIR_DEBUG("dev_name=%s newmedia=%s format=%s", dev_name, newmedia, format);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONChangeMedia(mon, dev_name, newmedia, format);
    else
        return qemuMonitorTextChangeMedia(mon, dev_name, newmedia, format);
}


int
qemuMonitorSaveVirtualMemory(qemuMonitorPtr mon,
                             unsigned long long offset,
                             size_t length,
                             const char *path)
{
    VIR_DEBUG("offset=%llu length=%zu path=%s", offset, length, path);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSaveVirtualMemory(mon, offset, length, path);
    else
        return qemuMonitorTextSaveVirtualMemory(mon, offset, length, path);
}


int
qemuMonitorSavePhysicalMemory(qemuMonitorPtr mon,
                              unsigned long long offset,
                              size_t length,
                              const char *path)
{
    VIR_DEBUG("offset=%llu length=%zu path=%s", offset, length, path);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSavePhysicalMemory(mon, offset, length, path);
    else
        return qemuMonitorTextSavePhysicalMemory(mon, offset, length, path);
}


int
qemuMonitorSetMigrationSpeed(qemuMonitorPtr mon,
                             unsigned long bandwidth)
{
    VIR_DEBUG("bandwidth=%lu", bandwidth);

    QEMU_CHECK_MONITOR(mon);

    if (bandwidth > QEMU_DOMAIN_MIG_BANDWIDTH_MAX) {
        virReportError(VIR_ERR_OVERFLOW,
                       _("bandwidth must be less than %llu"),
                       QEMU_DOMAIN_MIG_BANDWIDTH_MAX + 1ULL);
        return -1;
    }

    if (mon->json)
        return qemuMonitorJSONSetMigrationSpeed(mon, bandwidth);
    else
        return qemuMonitorTextSetMigrationSpeed(mon, bandwidth);
}


int
qemuMonitorSetMigrationDowntime(qemuMonitorPtr mon,
                                unsigned long long downtime)
{
    VIR_DEBUG("downtime=%llu", downtime);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetMigrationDowntime(mon, downtime);
    else
        return qemuMonitorTextSetMigrationDowntime(mon, downtime);
}


int
qemuMonitorGetMigrationCacheSize(qemuMonitorPtr mon,
                                 unsigned long long *cacheSize)
{
    VIR_DEBUG("cacheSize=%p", cacheSize);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetMigrationCacheSize(mon, cacheSize);
}


int
qemuMonitorSetMigrationCacheSize(qemuMonitorPtr mon,
                                 unsigned long long cacheSize)
{
    VIR_DEBUG("cacheSize=%llu", cacheSize);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONSetMigrationCacheSize(mon, cacheSize);
}


int
qemuMonitorGetMigrationParams(qemuMonitorPtr mon,
                              qemuMonitorMigrationParamsPtr params)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetMigrationParams(mon, params);
}

int
qemuMonitorSetMigrationParams(qemuMonitorPtr mon,
                              qemuMonitorMigrationParamsPtr params)
{
    VIR_DEBUG("compressLevel=%d:%d compressThreads=%d:%d "
              "decompressThreads=%d:%d cpuThrottleInitial=%d:%d "
              "cpuThrottleIncrement=%d:%d",
              params->compressLevel_set, params->compressLevel,
              params->compressThreads_set, params->compressThreads,
              params->decompressThreads_set, params->decompressThreads,
              params->cpuThrottleInitial_set, params->cpuThrottleInitial,
              params->cpuThrottleIncrement_set, params->cpuThrottleIncrement);

    QEMU_CHECK_MONITOR_JSON(mon);

    if (!params->compressLevel_set &&
        !params->compressThreads_set &&
        !params->decompressThreads_set &&
        !params->cpuThrottleInitial_set &&
        !params->cpuThrottleIncrement_set)
        return 0;

    return qemuMonitorJSONSetMigrationParams(mon, params);
}


int
qemuMonitorGetMigrationStats(qemuMonitorPtr mon,
                             qemuMonitorMigrationStatsPtr stats)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGetMigrationStats(mon, stats);
    else
        return qemuMonitorTextGetMigrationStats(mon, stats);
}


int
qemuMonitorMigrateToFd(qemuMonitorPtr mon,
                       unsigned int flags,
                       int fd)
{
    int ret;
    VIR_DEBUG("fd=%d flags=%x", fd, flags);

    QEMU_CHECK_MONITOR(mon);

    if (qemuMonitorSendFileHandle(mon, "migrate", fd) < 0)
        return -1;

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, "fd:migrate");
    else
        ret = qemuMonitorTextMigrate(mon, flags, "fd:migrate");

    if (ret < 0) {
        if (qemuMonitorCloseFileHandle(mon, "migrate") < 0)
            VIR_WARN("failed to close migration handle");
    }

    return ret;
}


int
qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                         unsigned int flags,
                         const char *protocol,
                         const char *hostname,
                         int port)
{
    int ret;
    char *uri = NULL;
    VIR_DEBUG("hostname=%s port=%d flags=%x", hostname, port, flags);

    QEMU_CHECK_MONITOR(mon);

    if (strchr(hostname, ':')) {
        if (virAsprintf(&uri, "%s:[%s]:%d", protocol, hostname, port) < 0)
            return -1;
    } else if (virAsprintf(&uri, "%s:%s:%d", protocol, hostname, port) < 0) {
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, uri);
    else
        ret = qemuMonitorTextMigrate(mon, flags, uri);

    VIR_FREE(uri);
    return ret;
}


int
qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                            unsigned int flags,
                            const char * const *argv)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    VIR_DEBUG("argv=%p flags=%x", argv, flags);

    QEMU_CHECK_MONITOR(mon);

    argstr = virArgvToString(argv);
    if (!argstr)
        goto cleanup;

    if (virAsprintf(&dest, "exec:%s", argstr) < 0)
        goto cleanup;

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, dest);
    else
        ret = qemuMonitorTextMigrate(mon, flags, dest);

 cleanup:
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}


int
qemuMonitorMigrateCancel(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONMigrateCancel(mon);
    else
        return qemuMonitorTextMigrateCancel(mon);
}


/**
 * Returns 1 if @capability is supported, 0 if it's not, or -1 on error.
 */
int
qemuMonitorGetDumpGuestMemoryCapability(qemuMonitorPtr mon,
                                        const char *capability)
{
    VIR_DEBUG("capability=%s", capability);

    QEMU_CHECK_MONITOR(mon);

    /* No capability is supported without JSON monitor */
    if (!mon->json)
        return 0;

    return qemuMonitorJSONGetDumpGuestMemoryCapability(mon, capability);
}


int
qemuMonitorDumpToFd(qemuMonitorPtr mon, int fd, const char *dumpformat)
{
    int ret;
    VIR_DEBUG("fd=%d dumpformat=%s", fd, dumpformat);

    QEMU_CHECK_MONITOR_JSON(mon);

    if (qemuMonitorSendFileHandle(mon, "dump", fd) < 0)
        return -1;

    ret = qemuMonitorJSONDump(mon, "fd:dump", dumpformat);

    if (ret < 0) {
        if (qemuMonitorCloseFileHandle(mon, "dump") < 0)
            VIR_WARN("failed to close dumping handle");
    }

    return ret;
}


int
qemuMonitorGraphicsRelocate(qemuMonitorPtr mon,
                            int type,
                            const char *hostname,
                            int port,
                            int tlsPort,
                            const char *tlsSubject)
{
    VIR_DEBUG("type=%d hostname=%s port=%d tlsPort=%d tlsSubject=%s",
              type, hostname, port, tlsPort, NULLSTR(tlsSubject));

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGraphicsRelocate(mon,
                                               type,
                                               hostname,
                                               port,
                                               tlsPort,
                                               tlsSubject);
    else
        return qemuMonitorTextGraphicsRelocate(mon,
                                               type,
                                               hostname,
                                               port,
                                               tlsPort,
                                               tlsSubject);
}


int
qemuMonitorSendFileHandle(qemuMonitorPtr mon,
                          const char *fdname,
                          int fd)
{
    VIR_DEBUG("fdname=%s fd=%d", fdname, fd);

    QEMU_CHECK_MONITOR(mon);

    if (fd < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("fd must be valid"));
        return -1;
    }

    if (!mon->hasSendFD) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("qemu is not using a unix socket monitor, "
                         "cannot send fd %s"), fdname);
        return -1;
    }

    if (mon->json)
        return qemuMonitorJSONSendFileHandle(mon, fdname, fd);
    else
        return qemuMonitorTextSendFileHandle(mon, fdname, fd);
}


int
qemuMonitorCloseFileHandle(qemuMonitorPtr mon,
                           const char *fdname)
{
    int ret = -1;
    virErrorPtr error;

    VIR_DEBUG("fdname=%s", fdname);

    error = virSaveLastError();

    QEMU_CHECK_MONITOR_GOTO(mon, cleanup);

    if (mon->json)
        ret = qemuMonitorJSONCloseFileHandle(mon, fdname);
    else
        ret = qemuMonitorTextCloseFileHandle(mon, fdname);

 cleanup:
    if (error) {
        virSetError(error);
        virFreeError(error);
    }
    return ret;
}


/* Add the open file descriptor FD into the non-negative set FDSET.
 * If NAME is present, it will be passed along for logging purposes.
 * Returns the counterpart fd that qemu received, or -1 on error.  */
int
qemuMonitorAddFd(qemuMonitorPtr mon, int fdset, int fd, const char *name)
{
    VIR_DEBUG("fdset=%d, fd=%d, name=%s", fdset, fd, NULLSTR(name));

    QEMU_CHECK_MONITOR_JSON(mon);

    if (fd < 0 || fdset < 0) {
        virReportError(VIR_ERR_INVALID_ARG, "%s",
                       _("fd and fdset must be valid"));
        return -1;
    }

    if (!mon->hasSendFD) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED,
                       _("qemu is not using a unix socket monitor, "
                         "cannot send fd %s"), NULLSTR(name));
        return -1;
    }

    return qemuMonitorJSONAddFd(mon, fdset, fd, name);
}


/* Remove one of qemu's fds from the given FDSET, or if FD is
 * negative, remove the entire set.  Preserve any previous error on
 * entry.  Returns 0 on success, -1 on error.  */
int
qemuMonitorRemoveFd(qemuMonitorPtr mon, int fdset, int fd)
{
    int ret = -1;
    virErrorPtr error;

    VIR_DEBUG("fdset=%d, fd=%d", fdset, fd);

    error = virSaveLastError();

    QEMU_CHECK_MONITOR_JSON_GOTO(mon, cleanup);

    ret = qemuMonitorJSONRemoveFd(mon, fdset, fd);

 cleanup:
    if (error) {
        virSetError(error);
        virFreeError(error);
    }
    return ret;
}


int
qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                          const char *netstr,
                          int *tapfd, char **tapfdName, int tapfdSize,
                          int *vhostfd, char **vhostfdName, int vhostfdSize)
{
    int ret = -1;
    size_t i = 0, j = 0;

    VIR_DEBUG("netstr=%s tapfd=%p tapfdName=%p tapfdSize=%d "
              "vhostfd=%p vhostfdName=%p vhostfdSize=%d",
              netstr, tapfd, tapfdName, tapfdSize,
              vhostfd, vhostfdName, vhostfdSize);

    QEMU_CHECK_MONITOR(mon);

    for (i = 0; i < tapfdSize; i++) {
        if (qemuMonitorSendFileHandle(mon, tapfdName[i], tapfd[i]) < 0)
            goto cleanup;
    }
    for (j = 0; j < vhostfdSize; j++) {
        if (qemuMonitorSendFileHandle(mon, vhostfdName[j], vhostfd[j]) < 0)
            goto cleanup;
    }

    if (mon->json)
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("JSON monitor should be using AddNetdev"));
    else
        ret = qemuMonitorTextAddHostNetwork(mon, netstr);

 cleanup:
    if (ret < 0) {
        while (i--) {
            if (qemuMonitorCloseFileHandle(mon, tapfdName[i]) < 0)
                VIR_WARN("failed to close device handle '%s'", tapfdName[i]);
        }
        while (j--) {
            if (qemuMonitorCloseFileHandle(mon, vhostfdName[j]) < 0)
                VIR_WARN("failed to close device handle '%s'", vhostfdName[j]);
        }
    }

    return ret;
}


int
qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                             int vlan,
                             const char *netname)
{
    VIR_DEBUG("netname=%s", netname);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json) {
        virReportError(VIR_ERR_OPERATION_UNSUPPORTED, "%s",
                       _("JSON monitor should be using RemoveNetdev"));
        return -1;
    }

    return qemuMonitorTextRemoveHostNetwork(mon, vlan, netname);
}


int
qemuMonitorAddNetdev(qemuMonitorPtr mon,
                     const char *netdevstr,
                     int *tapfd, char **tapfdName, int tapfdSize,
                     int *vhostfd, char **vhostfdName, int vhostfdSize)
{
    int ret = -1;
    size_t i = 0, j = 0;

    VIR_DEBUG("netdevstr=%s tapfd=%p tapfdName=%p tapfdSize=%d"
              "vhostfd=%p vhostfdName=%p vhostfdSize=%d",
              netdevstr, tapfd, tapfdName, tapfdSize,
              vhostfd, vhostfdName, vhostfdSize);

    QEMU_CHECK_MONITOR(mon);

    for (i = 0; i < tapfdSize; i++) {
        if (qemuMonitorSendFileHandle(mon, tapfdName[i], tapfd[i]) < 0)
            goto cleanup;
    }
    for (j = 0; j < vhostfdSize; j++) {
        if (qemuMonitorSendFileHandle(mon, vhostfdName[j], vhostfd[j]) < 0)
            goto cleanup;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddNetdev(mon, netdevstr);
    else
        ret = qemuMonitorTextAddNetdev(mon, netdevstr);

 cleanup:
    if (ret < 0) {
        while (i--) {
            if (qemuMonitorCloseFileHandle(mon, tapfdName[i]) < 0)
                VIR_WARN("failed to close device handle '%s'", tapfdName[i]);
        }
        while (j--) {
            if (qemuMonitorCloseFileHandle(mon, vhostfdName[j]) < 0)
                VIR_WARN("failed to close device handle '%s'", vhostfdName[j]);
        }
    }

    return ret;
}


int
qemuMonitorRemoveNetdev(qemuMonitorPtr mon,
                        const char *alias)
{
    VIR_DEBUG("alias=%s", alias);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONRemoveNetdev(mon, alias);
    else
        return qemuMonitorTextRemoveNetdev(mon, alias);
}


int
qemuMonitorQueryRxFilter(qemuMonitorPtr mon, const char *alias,
                         virNetDevRxFilterPtr *filter)
{
    VIR_DEBUG("alias=%s filter=%p", alias, filter);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONQueryRxFilter(mon, alias, filter);
}


void
qemuMonitorChardevInfoFree(void *data,
                           const void *name ATTRIBUTE_UNUSED)
{
    qemuMonitorChardevInfoPtr info = data;

    VIR_FREE(info->ptyPath);
    VIR_FREE(info);
}


int
qemuMonitorGetChardevInfo(qemuMonitorPtr mon,
                          virHashTablePtr *retinfo)
{
    int ret;
    virHashTablePtr info = NULL;

    VIR_DEBUG("retinfo=%p", retinfo);

    QEMU_CHECK_MONITOR_GOTO(mon, error);

    if (!(info = virHashCreate(10, qemuMonitorChardevInfoFree)))
        goto error;

    if (mon->json)
        ret = qemuMonitorJSONGetChardevInfo(mon, info);
    else
        ret = qemuMonitorTextGetChardevInfo(mon, info);

    if (ret < 0)
        goto error;

    *retinfo = info;
    return 0;

 error:
    virHashFree(info);
    *retinfo = NULL;
    return -1;
}


/**
 * qemuMonitorDriveDel:
 * @mon: monitor object
 * @drivestr: identifier of drive to delete.
 *
 * Attempts to remove a host drive.
 * Returns 1 if unsupported, 0 if ok, and -1 on other failure */
int
qemuMonitorDriveDel(qemuMonitorPtr mon,
                    const char *drivestr)
{
    VIR_DEBUG("drivestr=%s", drivestr);

    QEMU_CHECK_MONITOR(mon);

    /* there won't be a direct replacement for drive_del in QMP */
    return qemuMonitorTextDriveDel(mon, drivestr);
}


int
qemuMonitorDelDevice(qemuMonitorPtr mon,
                     const char *devalias)
{
    VIR_DEBUG("devalias=%s", devalias);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONDelDevice(mon, devalias);
    else
        return qemuMonitorTextDelDevice(mon, devalias);
}


int
qemuMonitorAddDeviceWithFd(qemuMonitorPtr mon,
                           const char *devicestr,
                           int fd,
                           const char *fdname)
{
    VIR_DEBUG("device=%s fd=%d fdname=%s", devicestr, fd, NULLSTR(fdname));
    int ret;

    QEMU_CHECK_MONITOR(mon);

    if (fd >= 0 && qemuMonitorSendFileHandle(mon, fdname, fd) < 0)
        return -1;

    if (mon->json)
        ret = qemuMonitorJSONAddDevice(mon, devicestr);
    else
        ret = qemuMonitorTextAddDevice(mon, devicestr);

    if (ret < 0 && fd >= 0) {
        if (qemuMonitorCloseFileHandle(mon, fdname) < 0)
            VIR_WARN("failed to close device handle '%s'", fdname);
    }

    return ret;
}


int
qemuMonitorAddDevice(qemuMonitorPtr mon,
                     const char *devicestr)
{
    return qemuMonitorAddDeviceWithFd(mon, devicestr, -1, NULL);
}


/**
 * qemuMonitorAddDeviceArgs:
 * @mon: monitor object
 * @args: arguments for device add, consumed on success or failure
 *
 * Adds a device described by @args. Requires JSON monitor.
 * Returns 0 on success -1 on error.
 */
int
qemuMonitorAddDeviceArgs(qemuMonitorPtr mon,
                         virJSONValuePtr args)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONAddDeviceArgs(mon, args);
}


/**
 * qemuMonitorAddObject:
 * @mon: Pointer to monitor object
 * @type: Type name of object to add
 * @objalias: Alias of the new object
 * @props: Optional arguments for the given type. The object is consumed and
 *         should not be referenced by the caller after this function returns.
 *
 * Returns 0 on success -1 on error.
 */
int
qemuMonitorAddObject(qemuMonitorPtr mon,
                     const char *type,
                     const char *objalias,
                     virJSONValuePtr props)
{
    VIR_DEBUG("type=%s objalias=%s props=%p", type, objalias, props);

    QEMU_CHECK_MONITOR_JSON_GOTO(mon, error);

    return qemuMonitorJSONAddObject(mon, type, objalias, props);

 error:
    virJSONValueFree(props);
    return -1;
}


int
qemuMonitorDelObject(qemuMonitorPtr mon,
                     const char *objalias)
{
    VIR_DEBUG("objalias=%s", objalias);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDelObject(mon, objalias);
}


int
qemuMonitorAddDrive(qemuMonitorPtr mon,
                    const char *drivestr)
{
    VIR_DEBUG("drive=%s", drivestr);

    QEMU_CHECK_MONITOR(mon);

    /* there won't ever be a direct QMP replacement for this function */
    return qemuMonitorTextAddDrive(mon, drivestr);
}


int
qemuMonitorSetDrivePassphrase(qemuMonitorPtr mon,
                              const char *alias,
                              const char *passphrase)
{
    VIR_DEBUG("alias=%s passphrase=%p(value hidden)", alias, passphrase);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetDrivePassphrase(mon, alias, passphrase);
    else
        return qemuMonitorTextSetDrivePassphrase(mon, alias, passphrase);
}


int
qemuMonitorCreateSnapshot(qemuMonitorPtr mon, const char *name)
{
    VIR_DEBUG("name=%s", name);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONCreateSnapshot(mon, name);
    else
        return qemuMonitorTextCreateSnapshot(mon, name);
}

int
qemuMonitorLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    VIR_DEBUG("name=%s", name);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONLoadSnapshot(mon, name);
    else
        return qemuMonitorTextLoadSnapshot(mon, name);
}


int
qemuMonitorDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    VIR_DEBUG("name=%s", name);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONDeleteSnapshot(mon, name);
    else
        return qemuMonitorTextDeleteSnapshot(mon, name);
}


/* Use the snapshot_blkdev command to convert the existing file for
 * device into a read-only backing file of a new qcow2 image located
 * at file.  */
int
qemuMonitorDiskSnapshot(qemuMonitorPtr mon, virJSONValuePtr actions,
                        const char *device, const char *file,
                        const char *format, bool reuse)
{
    VIR_DEBUG("actions=%p, device=%s, file=%s, format=%s, reuse=%d",
              actions, device, file, format, reuse);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDiskSnapshot(mon, actions, device, file, format, reuse);
}


/* Start a drive-mirror block job.  bandwidth is in bytes/sec.  */
int
qemuMonitorDriveMirror(qemuMonitorPtr mon,
                       const char *device, const char *file,
                       const char *format, unsigned long long bandwidth,
                       unsigned int granularity, unsigned long long buf_size,
                       unsigned int flags)
{
    VIR_DEBUG("device=%s, file=%s, format=%s, bandwidth=%lld, "
              "granularity=%#x, buf_size=%lld, flags=%x",
              device, file, NULLSTR(format), bandwidth, granularity,
              buf_size, flags);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDriveMirror(mon, device, file, format, bandwidth,
                                      granularity, buf_size, flags);
}


/* Use the transaction QMP command to run atomic snapshot commands.  */
int
qemuMonitorTransaction(qemuMonitorPtr mon, virJSONValuePtr actions)
{
    VIR_DEBUG("actions=%p", actions);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONTransaction(mon, actions);
}


/* Start a block-commit block job.  bandwidth is in bytes/sec.  */
int
qemuMonitorBlockCommit(qemuMonitorPtr mon, const char *device,
                       const char *top, const char *base,
                       const char *backingName,
                       unsigned long long bandwidth)
{
    VIR_DEBUG("device=%s, top=%s, base=%s, backingName=%s, bandwidth=%llu",
              device, top, base, NULLSTR(backingName), bandwidth);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONBlockCommit(mon, device, top, base,
                                         backingName, bandwidth);
}


/* Probe whether active commits are supported by a given qemu binary. */
bool
qemuMonitorSupportsActiveCommit(qemuMonitorPtr mon)
{
    if (!mon || !mon->json)
        return false;

    return qemuMonitorJSONBlockCommit(mon, "bogus", NULL, NULL, NULL, 0) == -2;
}


/* Determine the name that qemu is using for tracking the backing
 * element TARGET within the chain starting at TOP.  */
char *
qemuMonitorDiskNameLookup(qemuMonitorPtr mon,
                          const char *device,
                          virStorageSourcePtr top,
                          virStorageSourcePtr target)
{
    QEMU_CHECK_MONITOR_JSON_NULL(mon);

    return qemuMonitorJSONDiskNameLookup(mon, device, top, target);
}


/* Use the block-job-complete monitor command to pivot a block copy job.  */
int
qemuMonitorDrivePivot(qemuMonitorPtr mon,
                      const char *device)
{
    VIR_DEBUG("device=%s", device);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDrivePivot(mon, device);
}


int
qemuMonitorArbitraryCommand(qemuMonitorPtr mon,
                            const char *cmd,
                            char **reply,
                            bool hmp)
{
    VIR_DEBUG("cmd=%s, reply=%p, hmp=%d", cmd, reply, hmp);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONArbitraryCommand(mon, cmd, reply, hmp);
    else
        return qemuMonitorTextArbitraryCommand(mon, cmd, reply);
}


int
qemuMonitorInjectNMI(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONInjectNMI(mon);
    else
        return qemuMonitorTextInjectNMI(mon);
}


int
qemuMonitorSendKey(qemuMonitorPtr mon,
                   unsigned int holdtime,
                   unsigned int *keycodes,
                   unsigned int nkeycodes)
{
    VIR_DEBUG("holdtime=%u, nkeycodes=%u", holdtime, nkeycodes);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSendKey(mon, holdtime, keycodes, nkeycodes);
    else
        return qemuMonitorTextSendKey(mon, holdtime, keycodes, nkeycodes);
}


int
qemuMonitorScreendump(qemuMonitorPtr mon,
                      const char *file)
{
    VIR_DEBUG("file=%s", file);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONScreendump(mon, file);
    else
        return qemuMonitorTextScreendump(mon, file);
}


/* bandwidth is in bytes/sec */
int
qemuMonitorBlockStream(qemuMonitorPtr mon,
                       const char *device,
                       const char *base,
                       const char *backingName,
                       unsigned long long bandwidth,
                       bool modern)
{
    VIR_DEBUG("device=%s, base=%s, backingName=%s, bandwidth=%lluB, modern=%d",
              device, NULLSTR(base), NULLSTR(backingName), bandwidth, modern);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONBlockStream(mon, device, base, backingName,
                                      bandwidth, modern);
}


int
qemuMonitorBlockJobCancel(qemuMonitorPtr mon,
                          const char *device,
                          bool modern)
{
    VIR_DEBUG("device=%s, modern=%d", device, modern);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONBlockJobCancel(mon, device, modern);
}


int
qemuMonitorBlockJobSetSpeed(qemuMonitorPtr mon,
                            const char *device,
                            unsigned long long bandwidth,
                            bool modern)
{
    VIR_DEBUG("device=%s, bandwidth=%lluB, modern=%d", device, bandwidth, modern);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONBlockJobSetSpeed(mon, device, bandwidth, modern);
}


virHashTablePtr
qemuMonitorGetAllBlockJobInfo(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR_JSON_NULL(mon);
    return qemuMonitorJSONGetAllBlockJobInfo(mon);
}


/**
 * qemuMonitorGetBlockJobInfo:
 * Parse Block Job information, and populate info for the named device.
 * Return 1 if info available, 0 if device has no block job, and -1 on error.
 */
int
qemuMonitorGetBlockJobInfo(qemuMonitorPtr mon,
                           const char *alias,
                           qemuMonitorBlockJobInfoPtr info)
{
    virHashTablePtr all;
    qemuMonitorBlockJobInfoPtr data;
    int ret = 0;

    VIR_DEBUG("alias=%s, info=%p", alias, info);

    if (!(all = qemuMonitorGetAllBlockJobInfo(mon)))
        return -1;

    if ((data = virHashLookup(all, alias))) {
        *info = *data;
        ret = 1;
    }

    virHashFree(all);
    return ret;
}


int
qemuMonitorSetBlockIoThrottle(qemuMonitorPtr mon,
                              const char *device,
                              virDomainBlockIoTuneInfoPtr info,
                              bool supportMaxOptions,
                              bool supportGroupNameOption,
                              bool supportMaxLengthOptions)
{
    VIR_DEBUG("device=%p, info=%p", device, info);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONSetBlockIoThrottle(mon, device, info,
                                                 supportMaxOptions,
                                                 supportGroupNameOption,
                                                 supportMaxLengthOptions);
    else
        return qemuMonitorTextSetBlockIoThrottle(mon, device, info);
}


int
qemuMonitorGetBlockIoThrottle(qemuMonitorPtr mon,
                              const char *device,
                              virDomainBlockIoTuneInfoPtr reply)
{
    VIR_DEBUG("device=%p, reply=%p", device, reply);

    QEMU_CHECK_MONITOR(mon);

    if (mon->json)
        return qemuMonitorJSONGetBlockIoThrottle(mon, device, reply);
    else
        return qemuMonitorTextGetBlockIoThrottle(mon, device, reply);
}


int
qemuMonitorVMStatusToPausedReason(const char *status)
{
    int st;

    if (!status)
        return VIR_DOMAIN_PAUSED_UNKNOWN;

    if ((st = qemuMonitorVMStatusTypeFromString(status)) < 0) {
        VIR_WARN("Qemu reported unknown VM status: '%s'", status);
        return VIR_DOMAIN_PAUSED_UNKNOWN;
    }

    switch ((qemuMonitorVMStatus) st) {
    case QEMU_MONITOR_VM_STATUS_DEBUG:
    case QEMU_MONITOR_VM_STATUS_INTERNAL_ERROR:
    case QEMU_MONITOR_VM_STATUS_RESTORE_VM:
        return VIR_DOMAIN_PAUSED_UNKNOWN;

    case QEMU_MONITOR_VM_STATUS_INMIGRATE:
    case QEMU_MONITOR_VM_STATUS_POSTMIGRATE:
    case QEMU_MONITOR_VM_STATUS_FINISH_MIGRATE:
        return VIR_DOMAIN_PAUSED_MIGRATION;

    case QEMU_MONITOR_VM_STATUS_IO_ERROR:
        return VIR_DOMAIN_PAUSED_IOERROR;

    case QEMU_MONITOR_VM_STATUS_PAUSED:
    case QEMU_MONITOR_VM_STATUS_PRELAUNCH:
        return VIR_DOMAIN_PAUSED_USER;

    case QEMU_MONITOR_VM_STATUS_RUNNING:
        VIR_WARN("Qemu reports the guest is paused but status is 'running'");
        return VIR_DOMAIN_PAUSED_UNKNOWN;

    case QEMU_MONITOR_VM_STATUS_SAVE_VM:
        return VIR_DOMAIN_PAUSED_SAVE;

    case QEMU_MONITOR_VM_STATUS_SHUTDOWN:
        return VIR_DOMAIN_PAUSED_SHUTTING_DOWN;

    case QEMU_MONITOR_VM_STATUS_WATCHDOG:
        return VIR_DOMAIN_PAUSED_WATCHDOG;

    case QEMU_MONITOR_VM_STATUS_GUEST_PANICKED:
        return VIR_DOMAIN_PAUSED_CRASHED;

    /* unreachable from this point on */
    case QEMU_MONITOR_VM_STATUS_LAST:
        ;
    }
    return VIR_DOMAIN_PAUSED_UNKNOWN;
}


int
qemuMonitorOpenGraphics(qemuMonitorPtr mon,
                        const char *protocol,
                        int fd,
                        const char *fdname,
                        bool skipauth)
{
    VIR_DEBUG("protocol=%s fd=%d fdname=%s skipauth=%d",
              protocol, fd, NULLSTR(fdname), skipauth);
    int ret;

    QEMU_CHECK_MONITOR(mon);

    if (qemuMonitorSendFileHandle(mon, fdname, fd) < 0)
        return -1;

    if (mon->json)
        ret = qemuMonitorJSONOpenGraphics(mon, protocol, fdname, skipauth);
    else
        ret = qemuMonitorTextOpenGraphics(mon, protocol, fdname, skipauth);

    if (ret < 0) {
        if (qemuMonitorCloseFileHandle(mon, fdname) < 0)
            VIR_WARN("failed to close device handle '%s'", fdname);
    }

    return ret;
}


int
qemuMonitorSystemWakeup(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONSystemWakeup(mon);
}


int
qemuMonitorGetVersion(qemuMonitorPtr mon,
                      int *major,
                      int *minor,
                      int *micro,
                      char **package)
{
    VIR_DEBUG("major=%p minor=%p micro=%p package=%p",
              major, minor, micro, package);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetVersion(mon, major, minor, micro, package);
}


int
qemuMonitorGetMachines(qemuMonitorPtr mon,
                       qemuMonitorMachineInfoPtr **machines)
{
    VIR_DEBUG("machines=%p", machines);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetMachines(mon, machines);
}


void
qemuMonitorMachineInfoFree(qemuMonitorMachineInfoPtr machine)
{
    if (!machine)
        return;
    VIR_FREE(machine->name);
    VIR_FREE(machine->alias);
    VIR_FREE(machine);
}


int
qemuMonitorGetCPUDefinitions(qemuMonitorPtr mon,
                             qemuMonitorCPUDefInfoPtr **cpus)
{
    VIR_DEBUG("cpus=%p", cpus);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetCPUDefinitions(mon, cpus);
}


void
qemuMonitorCPUDefInfoFree(qemuMonitorCPUDefInfoPtr cpu)
{
    if (!cpu)
        return;
    VIR_FREE(cpu->name);
    VIR_FREE(cpu);
}


int
qemuMonitorGetCPUModelExpansion(qemuMonitorPtr mon,
                                qemuMonitorCPUModelExpansionType type,
                                const char *model_name,
                                qemuMonitorCPUModelInfoPtr *model_info)
{
    VIR_DEBUG("type=%d model_name=%s", type, model_name);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetCPUModelExpansion(mon, type, model_name, model_info);
}


void
qemuMonitorCPUModelInfoFree(qemuMonitorCPUModelInfoPtr model_info)
{
    size_t i;

    if (!model_info)
        return;

    for (i = 0; i < model_info->nprops; i++) {
        VIR_FREE(model_info->props[i].name);
        if (model_info->props[i].type == QEMU_MONITOR_CPU_PROPERTY_STRING)
            VIR_FREE(model_info->props[i].value.string);
    }

    VIR_FREE(model_info->props);
    VIR_FREE(model_info->name);
    VIR_FREE(model_info);
}


qemuMonitorCPUModelInfoPtr
qemuMonitorCPUModelInfoCopy(const qemuMonitorCPUModelInfo *orig)
{
    qemuMonitorCPUModelInfoPtr copy;
    size_t i;

    if (VIR_ALLOC(copy) < 0)
        goto error;

    if (VIR_ALLOC_N(copy->props, orig->nprops) < 0)
        goto error;

    if (VIR_STRDUP(copy->name, orig->name) < 0)
        goto error;

    copy->nprops = orig->nprops;

    for (i = 0; i < orig->nprops; i++) {
        if (VIR_STRDUP(copy->props[i].name, orig->props[i].name) < 0)
            goto error;

        copy->props[i].type = orig->props[i].type;
        switch (orig->props[i].type) {
        case QEMU_MONITOR_CPU_PROPERTY_BOOLEAN:
            copy->props[i].value.boolean = orig->props[i].value.boolean;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_STRING:
            if (VIR_STRDUP(copy->props[i].value.string,
                           orig->props[i].value.string) < 0)
                goto error;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_NUMBER:
            copy->props[i].value.number = orig->props[i].value.number;
            break;

        case QEMU_MONITOR_CPU_PROPERTY_LAST:
            break;
        }
    }

    return copy;

 error:
    qemuMonitorCPUModelInfoFree(copy);
    return NULL;
}


int
qemuMonitorGetCommands(qemuMonitorPtr mon,
                       char ***commands)
{
    VIR_DEBUG("commands=%p", commands);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetCommands(mon, commands);
}


int
qemuMonitorGetEvents(qemuMonitorPtr mon,
                     char ***events)
{
    VIR_DEBUG("events=%p", events);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetEvents(mon, events);
}


/* Collect the parameters associated with a given command line option.
 * Return count of known parameters or -1 on error.  */
int
qemuMonitorGetCommandLineOptionParameters(qemuMonitorPtr mon,
                                          const char *option,
                                          char ***params,
                                          bool *found)
{
    VIR_DEBUG("option=%s params=%p", option, params);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetCommandLineOptionParameters(mon, option,
                                                         params, found);
}


int
qemuMonitorGetKVMState(qemuMonitorPtr mon,
                       bool *enabled,
                       bool *present)
{
    VIR_DEBUG("enabled=%p present=%p", enabled, present);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetKVMState(mon, enabled, present);
}


int
qemuMonitorGetObjectTypes(qemuMonitorPtr mon,
                          char ***types)
{
    VIR_DEBUG("types=%p", types);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetObjectTypes(mon, types);
}


int
qemuMonitorGetObjectProps(qemuMonitorPtr mon,
                          const char *type,
                          char ***props)
{
    VIR_DEBUG("type=%s props=%p", type, props);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetObjectProps(mon, type, props);
}


char *
qemuMonitorGetTargetArch(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR_JSON_NULL(mon);

    return qemuMonitorJSONGetTargetArch(mon);
}


int
qemuMonitorGetMigrationCapabilities(qemuMonitorPtr mon,
                                    char ***capabilities)
{
    QEMU_CHECK_MONITOR(mon);

    /* No capability is supported without JSON monitor */
    if (!mon->json)
        return 0;

    return qemuMonitorJSONGetMigrationCapabilities(mon, capabilities);
}


/**
 * Returns 1 if @capability is supported, 0 if it's not, or -1 on error.
 */
int
qemuMonitorGetMigrationCapability(qemuMonitorPtr mon,
                                  qemuMonitorMigrationCaps capability)
{
    VIR_DEBUG("capability=%d", capability);

    QEMU_CHECK_MONITOR(mon);

    /* No capability is supported without JSON monitor */
    if (!mon->json)
        return 0;

    return qemuMonitorJSONGetMigrationCapability(mon, capability);
}


int
qemuMonitorSetMigrationCapability(qemuMonitorPtr mon,
                                  qemuMonitorMigrationCaps capability,
                                  bool state)
{
    VIR_DEBUG("capability=%d", capability);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONSetMigrationCapability(mon, capability, state);
}


/**
 * qemuMonitorGetGICCapabilities:
 * @mon: QEMU monitor
 * @capabilities: where to store the GIC capabilities
 *
 * See qemuMonitorJSONGetGICCapabilities().
 */
int
qemuMonitorGetGICCapabilities(qemuMonitorPtr mon,
                              virGICCapability **capabilities)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetGICCapabilities(mon, capabilities);
}


int
qemuMonitorNBDServerStart(qemuMonitorPtr mon,
                          const char *host,
                          unsigned int port)
{
    VIR_DEBUG("host=%s port=%u", host, port);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONNBDServerStart(mon, host, port);
}


int
qemuMonitorNBDServerAdd(qemuMonitorPtr mon,
                        const char *deviceID,
                        bool writable)
{
    VIR_DEBUG("deviceID=%s", deviceID);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONNBDServerAdd(mon, deviceID, writable);
}


int
qemuMonitorNBDServerStop(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONNBDServerStop(mon);
}


int
qemuMonitorGetTPMModels(qemuMonitorPtr mon,
                            char ***tpmmodels)
{
    VIR_DEBUG("tpmmodels=%p", tpmmodels);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetTPMModels(mon, tpmmodels);
}


int
qemuMonitorGetTPMTypes(qemuMonitorPtr mon,
                       char ***tpmtypes)
{
    VIR_DEBUG("tpmtypes=%p", tpmtypes);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetTPMTypes(mon, tpmtypes);
}


int
qemuMonitorAttachCharDev(qemuMonitorPtr mon,
                         const char *chrID,
                         virDomainChrSourceDefPtr chr)
{
    VIR_DEBUG("chrID=%s chr=%p", chrID, chr);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONAttachCharDev(mon, chrID, chr);
}


int
qemuMonitorDetachCharDev(qemuMonitorPtr mon,
                         const char *chrID)
{
    VIR_DEBUG("chrID=%s", chrID);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONDetachCharDev(mon, chrID);
}


int
qemuMonitorGetDeviceAliases(qemuMonitorPtr mon,
                            char ***aliases)
{
    VIR_DEBUG("aliases=%p", aliases);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetDeviceAliases(mon, aliases);
}


/**
 * qemuMonitorSetDomainLog:
 * Set the file descriptor of the open VM log file to report potential
 * early startup errors of qemu.
 *
 * @mon: Monitor object to set the log file reading on
 * @func: the callback to report errors
 * @opaque: data to pass to @func
 * @destroy: optional callback to free @opaque
 */
void
qemuMonitorSetDomainLog(qemuMonitorPtr mon,
                        qemuMonitorReportDomainLogError func,
                        void *opaque,
                        virFreeCallback destroy)
{
    if (mon->logDestroy && mon->logOpaque)
        mon->logDestroy(mon->logOpaque);

    mon->logFunc = func;
    mon->logOpaque = opaque;
    mon->logDestroy = destroy;
}


/**
 * qemuMonitorJSONGetGuestCPU:
 * @mon: Pointer to the monitor
 * @arch: arch of the guest
 * @data: returns the cpu data
 *
 * Retrieve the definition of the guest CPU from a running qemu instance.
 *
 * Returns 0 on success, -2 if the operation is not supported by the guest,
 * -1 on other errors.
 */
int
qemuMonitorGetGuestCPU(qemuMonitorPtr mon,
                       virArch arch,
                       virCPUDataPtr *data)
{
    VIR_DEBUG("arch='%s' data='%p'", virArchToString(arch), data);

    QEMU_CHECK_MONITOR_JSON(mon);

    *data = NULL;

    return qemuMonitorJSONGetGuestCPU(mon, arch, data);
}


/**
 * qemuMonitorRTCResetReinjection:
 * @mon: Pointer to the monitor
 *
 * Issue rtc-reset-reinjection command.
 * This should be used in cases where guest time is restored via
 * guest agent, so RTC injection is not needed (in fact it would
 * confuse guest's RTC).
 *
 * Returns 0 on success
 *        -1 on error.
 */
int
qemuMonitorRTCResetReinjection(qemuMonitorPtr mon)
{
    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONRTCResetReinjection(mon);
}


/**
 * qemuMonitorGetIOThreads:
 * @mon: Pointer to the monitor
 * @iothreads: Location to return array of IOThreadInfo data
 *
 * Issue query-iothreads command.
 * Retrieve the list of iothreads defined/running for the machine
 *
 * Returns count of IOThreadInfo structures on success
 *        -1 on error.
 */
int
qemuMonitorGetIOThreads(qemuMonitorPtr mon,
                        qemuMonitorIOThreadInfoPtr **iothreads)
{

    VIR_DEBUG("iothreads=%p", iothreads);

    QEMU_CHECK_MONITOR(mon);

    /* Requires JSON to make the query */
    if (!mon->json) {
        *iothreads = NULL;
        return 0;
    }

    return qemuMonitorJSONGetIOThreads(mon, iothreads);
}


/**
 * qemuMonitorGetMemoryDeviceInfo:
 * @mon: pointer to the monitor
 * @info: Location to return the hash of qemuMonitorMemoryDeviceInfo
 *
 * Retrieve state and addresses of frontend memory devices present in
 * the guest.
 *
 * Returns 0 on success and fills @info with a newly allocated struct; if the
 * data can't be retrieved due to lack of support in qemu, returns -2. On
 * other errors returns -1.
 */
int
qemuMonitorGetMemoryDeviceInfo(qemuMonitorPtr mon,
                               virHashTablePtr *info)
{
    VIR_DEBUG("info=%p", info);
    int ret;

    *info = NULL;

    QEMU_CHECK_MONITOR(mon);

    if (!mon->json)
        return -2;

    if (!(*info = virHashCreate(10, virHashValueFree)))
        return -1;

    if ((ret = qemuMonitorJSONGetMemoryDeviceInfo(mon, *info)) < 0) {
        virHashFree(*info);
        *info = NULL;
    }

    return ret;
}


int
qemuMonitorMigrateIncoming(qemuMonitorPtr mon,
                           const char *uri)
{
    VIR_DEBUG("uri=%s", uri);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONMigrateIncoming(mon, uri);
}


int
qemuMonitorMigrateStartPostCopy(qemuMonitorPtr mon)
{
    VIR_DEBUG("mon=%p", mon);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONMigrateStartPostCopy(mon);
}

int
qemuMonitorGetRTCTime(qemuMonitorPtr mon,
                      struct tm *tm)
{
    VIR_DEBUG("mon=%p", mon);

    QEMU_CHECK_MONITOR_JSON(mon);

    return qemuMonitorJSONGetRTCTime(mon, tm);
}


virHashTablePtr
qemuMonitorQueryQMPSchema(qemuMonitorPtr mon)
{
    VIR_DEBUG("mon=%p", mon);

    QEMU_CHECK_MONITOR_JSON_NULL(mon);

    return qemuMonitorJSONQueryQMPSchema(mon);
}
