/*
 * qemu_monitor.c: interaction with QEMU monitor console
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

#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_monitor.h"
#include "qemu_monitor_text.h"
#include "qemu_monitor_json.h"
#include "qemu_conf.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"
#include "virfile.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

struct _qemuMonitor {
    virMutex lock; /* also used to protect fd */
    virCond notify;

    int refs;

    int fd;
    int watch;
    int hasSendFD;

    virDomainObjPtr vm;

    qemuMonitorCallbacksPtr cb;

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

    unsigned json: 1;
    unsigned json_hmp: 1;
};


VIR_ENUM_IMPL(qemuMonitorMigrationStatus,
              QEMU_MONITOR_MIGRATION_STATUS_LAST,
              "inactive", "active", "completed", "failed", "cancelled")

VIR_ENUM_IMPL(qemuMonitorVMStatus,
              QEMU_MONITOR_VM_STATUS_LAST,
              "debug", "inmigrate", "internal-error", "io-error", "paused",
              "postmigrate", "prelaunch", "finish-migrate", "restore-vm",
              "running", "save-vm", "shutdown", "watchdog")

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

char *qemuMonitorEscapeArg(const char *in)
{
    int len = 0;
    int i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
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
        switch(in[i]) {
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

char *qemuMonitorUnescapeArg(const char *in)
{
    int i, j;
    char *out;
    int len = strlen(in) + 1;
    char next;

    if (VIR_ALLOC_N(out, len) < 0)
        return NULL;

    for (i = j = 0; i < len; ++i) {
        next = in[i];
        if (in[i] == '\\') {
            if (len < i + 1) {
                /* trailing backslash shouldn't be possible */
                VIR_FREE(out);
                return NULL;
            }
            ++i;
            switch(in[i]) {
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
                /* invalid input */
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
static char * qemuMonitorEscapeNonPrintable(const char *text)
{
    int i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    for (i = 0 ; text[i] != '\0' ; i++) {
        if (c_isprint(text[i]) ||
            text[i] == '\n' ||
            (text[i] == '\r' && text[i+1] == '\n'))
            virBufferAsprintf(&buf,"%c", text[i]);
        else
            virBufferAsprintf(&buf, "0x%02x", text[i]);
    }
    return virBufferContentAndReset(&buf);
}
#endif

void qemuMonitorLock(qemuMonitorPtr mon)
{
    virMutexLock(&mon->lock);
}

void qemuMonitorUnlock(qemuMonitorPtr mon)
{
    virMutexUnlock(&mon->lock);
}


static void qemuMonitorFree(qemuMonitorPtr mon)
{
    VIR_DEBUG("mon=%p", mon);
    if (mon->cb && mon->cb->destroy)
        (mon->cb->destroy)(mon, mon->vm);
    if (virCondDestroy(&mon->notify) < 0)
    {}
    virMutexDestroy(&mon->lock);
    VIR_FREE(mon->buffer);
    VIR_FREE(mon);
}

int qemuMonitorRef(qemuMonitorPtr mon)
{
    mon->refs++;
    PROBE(QEMU_MONITOR_REF,
          "mon=%p refs=%d", mon, mon->refs);
    return mon->refs;
}

int qemuMonitorUnref(qemuMonitorPtr mon)
{
    mon->refs--;

    PROBE(QEMU_MONITOR_UNREF,
          "mon=%p refs=%d", mon, mon->refs);
    if (mon->refs == 0) {
        qemuMonitorUnlock(mon);
        qemuMonitorFree(mon);
        return 0;
    }

    return mon->refs;
}

static void
qemuMonitorUnwatch(void *monitor)
{
    qemuMonitorPtr mon = monitor;

    qemuMonitorLock(mon);
    if (qemuMonitorUnref(mon) > 0)
        qemuMonitorUnlock(mon);
}

static int
qemuMonitorOpenUnix(const char *monitor, pid_t cpid)
{
    struct sockaddr_un addr;
    int monfd;
    int timeout = 3; /* In seconds */
    int ret, i = 0;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Monitor path %s too big for destination"), monitor);
        goto error;
    }

    do {
        ret = connect(monfd, (struct sockaddr *) &addr, sizeof(addr));

        if (ret == 0)
            break;

        if ((errno == ENOENT || errno == ECONNREFUSED) &&
            virKillProcess(cpid, 0) == 0) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        virReportSystemError(errno, "%s",
                             _("failed to connect to monitor socket"));
        goto error;

    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if (ret != 0) {
        virReportSystemError(errno, "%s",
                             _("monitor socket did not show up."));
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
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

    /* If no active message, or fully transmitted, the no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    if (mon->msg->txFD != -1 && !mon->hasSendFD) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Monitor does not support sending of file descriptors"));
        return -1;
    }

    if (mon->msg->txFD == -1)
        done = write(mon->fd,
                     mon->msg->txBuffer + mon->msg->txOffset,
                     mon->msg->txLength - mon->msg->txOffset);
    else
        done = qemuMonitorIOWriteWithFD(mon,
                                        mon->msg->txBuffer + mon->msg->txOffset,
                                        mon->msg->txLength - mon->msg->txOffset,
                                        mon->msg->txFD);

    PROBE(QEMU_MONITOR_IO_WRITE,
          "mon=%p buf=%s len=%d ret=%d errno=%d",
          mon,
          mon->msg->txBuffer + mon->msg->txOffset,
          mon->msg->txLength - mon->msg->txOffset,
          done, errno);

    if (mon->msg->txFD != -1)
        PROBE(QEMU_MONITOR_IO_SEND_FD,
              "mon=%p fd=%d ret=%d errno=%d",
              mon, mon->msg->txFD, done, errno);

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
                          mon->bufferLength + 1024) < 0) {
            virReportOOMError();
            return -1;
        }
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


static void qemuMonitorUpdateWatch(qemuMonitorPtr mon)
{
    int events =
        VIR_EVENT_HANDLE_HANGUP |
        VIR_EVENT_HANDLE_ERROR;

    if (mon->lastError.code == VIR_ERR_OK) {
        events |= VIR_EVENT_HANDLE_READABLE;

        if (mon->msg && mon->msg->txOffset < mon->msg->txLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;
    }

    virEventUpdateHandle(mon->watch, events);
}


static void
qemuMonitorIO(int watch, int fd, int events, void *opaque) {
    qemuMonitorPtr mon = opaque;
    bool error = false;
    bool eof = false;

    /* lock access to the monitor and protect fd */
    qemuMonitorLock(mon);
    qemuMonitorRef(mon);
#if DEBUG_IO
    VIR_DEBUG("Monitor %p I/O on watch %d fd %d events %d", mon, watch, fd, events);
#endif

    if (mon->fd != fd || mon->watch != watch) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("event from unexpected fd %d!=%d / watch %d!=%d"),
                        mon->fd, fd, mon->watch, watch);
        error = true;
    } else if (mon->lastError.code != VIR_ERR_OK) {
        if (events & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR))
            eof = true;
        error = true;
    } else {
        if (events & VIR_EVENT_HANDLE_WRITABLE) {
            if (qemuMonitorIOWrite(mon) < 0)
                error = true;
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }

        if (!error &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuMonitorIORead(mon);
            events &= ~VIR_EVENT_HANDLE_READABLE;
            if (got < 0) {
                error = true;
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

        if (!error &&
            events & VIR_EVENT_HANDLE_HANGUP) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("End of file from monitor"));
            eof = 1;
            events &= ~VIR_EVENT_HANDLE_HANGUP;
        }

        if (!error && !eof &&
            events & VIR_EVENT_HANDLE_ERROR) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Invalid file descriptor while waiting for monitor"));
            eof = 1;
            events &= ~VIR_EVENT_HANDLE_ERROR;
        }
        if (!error && events) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Unhandled event %d for monitor fd %d"),
                            events, mon->fd);
            error = 1;
        }
    }

    if (error || eof) {
        if (mon->lastError.code != VIR_ERR_OK) {
            /* Already have an error, so clear any new error */
            virResetLastError();
        } else {
            virErrorPtr err = virGetLastError();
            if (!err)
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
        void (*eofNotify)(qemuMonitorPtr, virDomainObjPtr)
            = mon->cb->eofNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        if (qemuMonitorUnref(mon) > 0)
            qemuMonitorUnlock(mon);
        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(mon, vm);
    } else if (error) {
        void (*errorNotify)(qemuMonitorPtr, virDomainObjPtr)
            = mon->cb->errorNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        if (qemuMonitorUnref(mon) > 0)
            qemuMonitorUnlock(mon);
        VIR_DEBUG("Triggering error callback");
        (errorNotify)(mon, vm);
    } else {
        if (qemuMonitorUnref(mon) > 0)
            qemuMonitorUnlock(mon);
    }
}


qemuMonitorPtr
qemuMonitorOpen(virDomainObjPtr vm,
                virDomainChrSourceDefPtr config,
                int json,
                qemuMonitorCallbacksPtr cb)
{
    qemuMonitorPtr mon;

    if (!cb || !cb->eofNotify) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("EOF notify callback must be supplied"));
        return NULL;
    }

    if (VIR_ALLOC(mon) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&mon->lock) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot initialize monitor mutex"));
        VIR_FREE(mon);
        return NULL;
    }
    if (virCondInit(&mon->notify) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot initialize monitor condition"));
        virMutexDestroy(&mon->lock);
        VIR_FREE(mon);
        return NULL;
    }
    mon->fd = -1;
    mon->refs = 1;
    mon->vm = vm;
    mon->json = json;
    mon->cb = cb;
    qemuMonitorLock(mon);

    switch (config->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        mon->hasSendFD = 1;
        mon->fd = qemuMonitorOpenUnix(config->data.nix.path, vm->pid);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        mon->fd = qemuMonitorOpenPty(config->data.file.path);
        break;

    default:
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unable to handle monitor type: %s"),
                        virDomainChrTypeToString(config->type));
        goto cleanup;
    }

    if (mon->fd == -1) goto cleanup;

    if (virSetCloseExec(mon->fd) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Unable to set monitor close-on-exec flag"));
        goto cleanup;
    }
    if (virSetNonBlock(mon->fd) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Unable to put monitor into non-blocking mode"));
        goto cleanup;
    }


    if ((mon->watch = virEventAddHandle(mon->fd,
                                        VIR_EVENT_HANDLE_HANGUP |
                                        VIR_EVENT_HANDLE_ERROR |
                                        VIR_EVENT_HANDLE_READABLE,
                                        qemuMonitorIO,
                                        mon, qemuMonitorUnwatch)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("unable to register monitor events"));
        goto cleanup;
    }
    qemuMonitorRef(mon);

    PROBE(QEMU_MONITOR_NEW,
          "mon=%p refs=%d fd=%d",
          mon, mon->refs, mon->fd);
    qemuMonitorUnlock(mon);

    return mon;

cleanup:
    /* We don't want the 'destroy' callback invoked during
     * cleanup from construction failure, because that can
     * give a double-unref on virDomainObjPtr in the caller,
     * so kill the callbacks now.
     */
    mon->cb = NULL;
    qemuMonitorUnlock(mon);
    qemuMonitorClose(mon);
    return NULL;
}


void qemuMonitorClose(qemuMonitorPtr mon)
{
    if (!mon)
        return;

    qemuMonitorLock(mon);
    PROBE(QEMU_MONITOR_CLOSE,
          "mon=%p refs=%d", mon, mon->refs);

    if (mon->fd >= 0) {
        if (mon->watch)
            virEventRemoveHandle(mon->watch);
        VIR_FORCE_CLOSE(mon->fd);
    }

    /* In case another thread is waiting for its monitor command to be
     * processed, we need to wake it up with appropriate error set.
     */
    if (mon->msg) {
        if (mon->lastError.code == VIR_ERR_OK) {
            virErrorPtr err = virSaveLastError();

            qemuReportError(VIR_ERR_OPERATION_FAILED,
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

    if (qemuMonitorUnref(mon) > 0)
        qemuMonitorUnlock(mon);
}


char *qemuMonitorNextCommandID(qemuMonitorPtr mon)
{
    char *id;

    if (virAsprintf(&id, "libvirt-%d", ++mon->nextSerial) < 0) {
        virReportOOMError();
        return NULL;
    }
    return id;
}


int qemuMonitorSend(qemuMonitorPtr mon,
                    qemuMonitorMessagePtr msg)
{
    int ret = -1;

    /* Check whether qemu quited unexpectedly */
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
        if (virCondWait(&mon->notify, &mon->lock) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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


int qemuMonitorHMPCommandWithFd(qemuMonitorPtr mon,
                                const char *cmd,
                                int scm_fd,
                                char **reply)
{
    char *json_cmd = NULL;
    int ret = -1;

    if (mon->json) {
        /* hack to avoid complicating each call to text monitor functions */
        json_cmd = qemuMonitorUnescapeArg(cmd);
        if (!json_cmd) {
            VIR_DEBUG("Could not unescape command: %s", cmd);
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
        qemuMonitorRef(mon);                                    \
        qemuMonitorUnlock(mon);                                 \
        if ((mon)->cb && (mon)->cb->callback)                   \
            (ret) = ((mon)->cb->callback)(mon, __VA_ARGS__);    \
        qemuMonitorLock(mon);                                   \
        ignore_value(qemuMonitorUnref(mon));                    \
    } while (0)

int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
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


int qemuMonitorEmitShutdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainShutdown, mon->vm);
    return ret;
}


int qemuMonitorEmitReset(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainReset, mon->vm);
    return ret;
}


int qemuMonitorEmitPowerdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPowerdown, mon->vm);
    return ret;
}


int qemuMonitorEmitStop(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainStop, mon->vm);
    return ret;
}


int qemuMonitorEmitRTCChange(qemuMonitorPtr mon, long long offset)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainRTCChange, mon->vm, offset);
    return ret;
}


int qemuMonitorEmitWatchdog(qemuMonitorPtr mon, int action)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainWatchdog, mon->vm, action);
    return ret;
}


int qemuMonitorEmitIOError(qemuMonitorPtr mon,
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


int qemuMonitorEmitGraphics(qemuMonitorPtr mon,
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

int qemuMonitorEmitTrayChange(qemuMonitorPtr mon,
                              const char *devAlias,
                              int reason)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainTrayChange, mon->vm,
                          devAlias, reason);

    return ret;
}

int qemuMonitorEmitPMWakeup(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPMWakeup, mon->vm);

    return ret;
}

int qemuMonitorEmitPMSuspend(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    QEMU_MONITOR_CALLBACK(mon, ret, domainPMSuspend, mon->vm);

    return ret;
}

int qemuMonitorEmitBlockJob(qemuMonitorPtr mon,
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



int qemuMonitorSetCapabilities(qemuMonitorPtr mon,
                               virBitmapPtr qemuCaps)
{
    int ret;
    int json_hmp;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json) {
        ret = qemuMonitorJSONSetCapabilities(mon);
        if (ret)
            goto cleanup;

        ret = qemuMonitorJSONCheckCommands(mon, qemuCaps, &json_hmp);
        mon->json_hmp = json_hmp > 0;
    } else {
        ret = 0;
    }

cleanup:
    return ret;
}


int
qemuMonitorCheckHMP(qemuMonitorPtr mon, const char *cmd)
{
    if (!mon->json || mon->json_hmp)
        return 1;

    if (cmd) {
        VIR_DEBUG("HMP passthrough not supported by qemu process;"
                  " not trying HMP for command %s", cmd);
    }

    return 0;
}


int
qemuMonitorStartCPUs(qemuMonitorPtr mon,
                     virConnectPtr conn)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONStartCPUs(mon, conn);
    else
        ret = qemuMonitorTextStartCPUs(mon, conn);
    return ret;
}


int
qemuMonitorStopCPUs(qemuMonitorPtr mon)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONStopCPUs(mon);
    else
        ret = qemuMonitorTextStopCPUs(mon);
    return ret;
}


int
qemuMonitorGetStatus(qemuMonitorPtr mon,
                     bool *running,
                     virDomainPausedReason *reason)
{
    int ret;
    VIR_DEBUG("mon=%p, running=%p, reason=%p", mon, running, reason);

    if (!mon || !running) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("both monitor and running must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetStatus(mon, running, reason);
    else
        ret = qemuMonitorTextGetStatus(mon, running, reason);
    return ret;
}


int qemuMonitorSystemPowerdown(qemuMonitorPtr mon)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSystemPowerdown(mon);
    else
        ret = qemuMonitorTextSystemPowerdown(mon);
    return ret;
}


int qemuMonitorSystemReset(qemuMonitorPtr mon)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSystemReset(mon);
    else
        ret = qemuMonitorTextSystemReset(mon);
    return ret;
}


int qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                          int **pids)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetCPUInfo(mon, pids);
    else
        ret = qemuMonitorTextGetCPUInfo(mon, pids);
    return ret;
}

int qemuMonitorSetLink(qemuMonitorPtr mon,
                       const char *name,
                       enum virDomainNetInterfaceLinkState state)
{
    int ret;
    VIR_DEBUG("mon=%p, name=%p:%s, state=%u", mon, name, name, state);

    if (!mon || !name) {
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("monitor || name must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetLink(mon, name, state);
    else
        ret = qemuMonitorTextSetLink(mon, name, state);
    return ret;
}

int qemuMonitorGetVirtType(qemuMonitorPtr mon,
                           int *virtType)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetVirtType(mon, virtType);
    else
        ret = qemuMonitorTextGetVirtType(mon, virtType);
    return ret;
}


int qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long long *currmem)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetBalloonInfo(mon, currmem);
    else
        ret = qemuMonitorTextGetBalloonInfo(mon, currmem);
    return ret;
}


int qemuMonitorGetMemoryStats(qemuMonitorPtr mon,
                              virDomainMemoryStatPtr stats,
                              unsigned int nr_stats)
{
    int ret;
    VIR_DEBUG("mon=%p stats=%p nstats=%u", mon, stats, nr_stats);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetMemoryStats(mon, stats, nr_stats);
    else
        ret = qemuMonitorTextGetMemoryStats(mon, stats, nr_stats);
    return ret;
}

int
qemuMonitorBlockIOStatusToError(const char *status)
{
    int st = qemuMonitorBlockIOStatusTypeFromString(status);

    if (st < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
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

    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return NULL;
    }

    if (!(table = virHashCreate(32, (virHashDataFree) free)))
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

struct qemuDomainDiskInfo *
qemuMonitorBlockInfoLookup(virHashTablePtr blockInfo,
                           const char *devname)
{
    struct qemuDomainDiskInfo *info;

    VIR_DEBUG("blockInfo=%p dev=%s", blockInfo, NULLSTR(devname));

    if (!(info = virHashLookup(blockInfo, devname))) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot find info for device '%s'"),
                        NULLSTR(devname));
    }

    return info;
}

int qemuMonitorGetBlockStatsInfo(qemuMonitorPtr mon,
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
    VIR_DEBUG("mon=%p dev=%s", mon, dev_name);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetBlockStatsInfo(mon, dev_name,
                                               rd_req, rd_bytes,
                                               rd_total_times,
                                               wr_req, wr_bytes,
                                               wr_total_times,
                                               flush_req,
                                               flush_total_times,
                                               errs);
    else
        ret = qemuMonitorTextGetBlockStatsInfo(mon, dev_name,
                                               rd_req, rd_bytes,
                                               rd_total_times,
                                               wr_req, wr_bytes,
                                               wr_total_times,
                                               flush_req,
                                               flush_total_times,
                                               errs);
    return ret;
}

/* Return 0 and update @nparams with the number of block stats
 * QEMU supports if success. Return -1 if failure.
 */
int qemuMonitorGetBlockStatsParamsNumber(qemuMonitorPtr mon,
                                         int *nparams)
{
    int ret;
    VIR_DEBUG("mon=%p nparams=%p", mon, nparams);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetBlockStatsParamsNumber(mon, nparams);
    else
        ret = qemuMonitorTextGetBlockStatsParamsNumber(mon, nparams);

    return ret;
}

int qemuMonitorGetBlockExtent(qemuMonitorPtr mon,
                              const char *dev_name,
                              unsigned long long *extent)
{
    int ret;
    VIR_DEBUG("mon=%p, fd=%d, dev_name=%p",
          mon, mon->fd, dev_name);

    if (mon->json)
        ret = qemuMonitorJSONGetBlockExtent(mon, dev_name, extent);
    else
        ret = qemuMonitorTextGetBlockExtent(mon, dev_name, extent);

    return ret;
}

int qemuMonitorBlockResize(qemuMonitorPtr mon,
                           const char *device,
                           unsigned long long size)
{
    int ret;
    VIR_DEBUG("mon=%p, fd=%d, devname=%p size=%llu",
              mon, mon->fd, device, size);

    if (mon->json)
        ret = qemuMonitorJSONBlockResize(mon, device, size);
    else
        ret = qemuMonitorTextBlockResize(mon, device, size);

    return ret;
}

int qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                              const char *password)
{
    int ret;
    VIR_DEBUG("mon=%p, password=%p",
          mon, password);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (!password)
        password = "";

    if (mon->json)
        ret = qemuMonitorJSONSetVNCPassword(mon, password);
    else
        ret = qemuMonitorTextSetVNCPassword(mon, password);
    return ret;
}

static const char* qemuMonitorTypeToProtocol(int type)
{
    switch (type) {
    case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
        return "vnc";
    case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
        return "spice";
    default:
        qemuReportError(VIR_ERR_INVALID_ARG,
                        _("unsupported protocol type %s"),
                        virDomainGraphicsTypeToString(type));
        return NULL;
    }
}

/* Returns -2 if not supported with this monitor connection */
int qemuMonitorSetPassword(qemuMonitorPtr mon,
                           int type,
                           const char *password,
                           const char *action_if_connected)
{
    const char *protocol = qemuMonitorTypeToProtocol(type);
    int ret;

    if (!protocol)
        return -1;

    VIR_DEBUG("mon=%p, protocol=%s, password=%p, action_if_connected=%s",
          mon, protocol, password, action_if_connected);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (!password)
        password = "";

    if (!action_if_connected)
        action_if_connected = "keep";

    if (mon->json)
        ret = qemuMonitorJSONSetPassword(mon, protocol, password, action_if_connected);
    else
        ret = qemuMonitorTextSetPassword(mon, protocol, password, action_if_connected);
    return ret;
}

int qemuMonitorExpirePassword(qemuMonitorPtr mon,
                              int type,
                              const char *expire_time)
{
    const char *protocol = qemuMonitorTypeToProtocol(type);
    int ret;

    if (!protocol)
        return -1;

    VIR_DEBUG("mon=%p, protocol=%s, expire_time=%s",
          mon, protocol, expire_time);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (!expire_time)
        expire_time = "now";

    if (mon->json)
        ret = qemuMonitorJSONExpirePassword(mon, protocol, expire_time);
    else
        ret = qemuMonitorTextExpirePassword(mon, protocol, expire_time);
    return ret;
}

int qemuMonitorSetBalloon(qemuMonitorPtr mon,
                          unsigned long newmem)
{
    int ret;
    VIR_DEBUG("mon=%p newmem=%lu", mon, newmem);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetBalloon(mon, newmem);
    else
        ret = qemuMonitorTextSetBalloon(mon, newmem);
    return ret;
}


int qemuMonitorSetCPU(qemuMonitorPtr mon, int cpu, int online)
{
    int ret;
    VIR_DEBUG("mon=%p cpu=%d online=%d", mon, cpu, online);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetCPU(mon, cpu, online);
    else
        ret = qemuMonitorTextSetCPU(mon, cpu, online);
    return ret;
}


int qemuMonitorEjectMedia(qemuMonitorPtr mon,
                          const char *dev_name,
                          bool force)
{
    int ret;
    VIR_DEBUG("mon=%p dev_name=%s force=%d", mon, dev_name, force);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONEjectMedia(mon, dev_name, force);
    else
        ret = qemuMonitorTextEjectMedia(mon, dev_name, force);
    return ret;
}


int qemuMonitorChangeMedia(qemuMonitorPtr mon,
                           const char *dev_name,
                           const char *newmedia,
                           const char *format)
{
    int ret;
    VIR_DEBUG("mon=%p dev_name=%s newmedia=%s format=%s",
          mon, dev_name, newmedia, format);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONChangeMedia(mon, dev_name, newmedia, format);
    else
        ret = qemuMonitorTextChangeMedia(mon, dev_name, newmedia, format);
    return ret;
}


int qemuMonitorSaveVirtualMemory(qemuMonitorPtr mon,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path)
{
    int ret;
    VIR_DEBUG("mon=%p offset=%llu length=%zu path=%s",
          mon, offset, length, path);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSaveVirtualMemory(mon, offset, length, path);
    else
        ret = qemuMonitorTextSaveVirtualMemory(mon, offset, length, path);
    return ret;
}

int qemuMonitorSavePhysicalMemory(qemuMonitorPtr mon,
                                  unsigned long long offset,
                                  size_t length,
                                  const char *path)
{
    int ret;
    VIR_DEBUG("mon=%p offset=%llu length=%zu path=%s",
          mon, offset, length, path);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSavePhysicalMemory(mon, offset, length, path);
    else
        ret = qemuMonitorTextSavePhysicalMemory(mon, offset, length, path);
    return ret;
}


int qemuMonitorSetMigrationSpeed(qemuMonitorPtr mon,
                                 unsigned long bandwidth)
{
    int ret;
    VIR_DEBUG("mon=%p bandwidth=%lu", mon, bandwidth);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetMigrationSpeed(mon, bandwidth);
    else
        ret = qemuMonitorTextSetMigrationSpeed(mon, bandwidth);
    return ret;
}


int qemuMonitorSetMigrationDowntime(qemuMonitorPtr mon,
                                    unsigned long long downtime)
{
    int ret;
    VIR_DEBUG("mon=%p downtime=%llu", mon, downtime);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetMigrationDowntime(mon, downtime);
    else
        ret = qemuMonitorTextSetMigrationDowntime(mon, downtime);
    return ret;
}


int qemuMonitorGetMigrationStatus(qemuMonitorPtr mon,
                                  int *status,
                                  unsigned long long *transferred,
                                  unsigned long long *remaining,
                                  unsigned long long *total)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetMigrationStatus(mon, status,
                                                transferred,
                                                remaining,
                                                total);
    else
        ret = qemuMonitorTextGetMigrationStatus(mon, status,
                                                transferred,
                                                remaining,
                                                total);
    return ret;
}


int qemuMonitorMigrateToFd(qemuMonitorPtr mon,
                           unsigned int flags,
                           int fd)
{
    int ret;
    VIR_DEBUG("mon=%p fd=%d flags=%x",
          mon, fd, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

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


int qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *hostname,
                             int port)
{
    int ret;
    char *uri = NULL;
    VIR_DEBUG("mon=%p hostname=%s port=%d flags=%x",
          mon, hostname, port, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }


    if (virAsprintf(&uri, "tcp:%s:%d", hostname, port) < 0) {
        virReportOOMError();
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, uri);
    else
        ret = qemuMonitorTextMigrate(mon, flags, uri);

    VIR_FREE(uri);
    return ret;
}


int qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                                unsigned int flags,
                                const char * const *argv)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    VIR_DEBUG("mon=%p argv=%p flags=%x",
          mon, argv, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    argstr = virArgvToString(argv);
    if (!argstr) {
        virReportOOMError();
        goto cleanup;
    }

    if (virAsprintf(&dest, "exec:%s", argstr) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, dest);
    else
        ret = qemuMonitorTextMigrate(mon, flags, dest);

cleanup:
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}

int qemuMonitorMigrateToFile(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char * const *argv,
                             const char *target,
                             unsigned long long offset)
{
    char *argstr;
    char *dest = NULL;
    int ret = -1;
    char *safe_target = NULL;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    VIR_DEBUG("mon=%p argv=%p target=%s offset=%llu flags=%x",
          mon, argv, target, offset, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (offset % QEMU_MONITOR_MIGRATE_TO_FILE_BS) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("file offset must be a multiple of %llu"),
                        QEMU_MONITOR_MIGRATE_TO_FILE_BS);
        return -1;
    }

    argstr = virArgvToString(argv);
    if (!argstr) {
        virReportOOMError();
        goto cleanup;
    }

    /* Migrate to file */
    virBufferEscapeShell(&buf, target);
    if (virBufferError(&buf)) {
        virReportOOMError();
        virBufferFreeAndReset(&buf);
        goto cleanup;
    }
    safe_target = virBufferContentAndReset(&buf);

    /* Two dd processes, sharing the same stdout, are necessary to
     * allow starting at an alignment of 512, but without wasting
     * padding to get to the larger alignment useful for speed.  Use
     * <> redirection to avoid truncating a regular file.  */
    if (virAsprintf(&dest, "exec:" VIR_WRAPPER_SHELL_PREFIX "%s | "
                    "{ dd bs=%llu seek=%llu if=/dev/null && "
                    "dd ibs=%llu obs=%llu; } 1<>%s" VIR_WRAPPER_SHELL_SUFFIX,
                    argstr, QEMU_MONITOR_MIGRATE_TO_FILE_BS,
                    offset / QEMU_MONITOR_MIGRATE_TO_FILE_BS,
                    QEMU_MONITOR_MIGRATE_TO_FILE_TRANSFER_SIZE,
                    QEMU_MONITOR_MIGRATE_TO_FILE_TRANSFER_SIZE,
                    safe_target) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, dest);
    else
        ret = qemuMonitorTextMigrate(mon, flags, dest);

cleanup:
    VIR_FREE(safe_target);
    VIR_FREE(argstr);
    VIR_FREE(dest);
    return ret;
}

int qemuMonitorMigrateToUnix(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *unixfile)
{
    char *dest = NULL;
    int ret = -1;
    VIR_DEBUG("mon=%p, unixfile=%s flags=%x",
          mon, unixfile, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (virAsprintf(&dest, "unix:%s", unixfile) < 0) {
        virReportOOMError();
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrate(mon, flags, dest);
    else
        ret = qemuMonitorTextMigrate(mon, flags, dest);

    VIR_FREE(dest);
    return ret;
}

int qemuMonitorMigrateCancel(qemuMonitorPtr mon)
{
    int ret;
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrateCancel(mon);
    else
        ret = qemuMonitorTextMigrateCancel(mon);
    return ret;
}


int qemuMonitorGraphicsRelocate(qemuMonitorPtr mon,
                                int type,
                                const char *hostname,
                                int port,
                                int tlsPort,
                                const char *tlsSubject)
{
    int ret;
    VIR_DEBUG("mon=%p type=%d hostname=%s port=%d tlsPort=%d tlsSubject=%s",
              mon, type, hostname, port, tlsPort, NULLSTR(tlsSubject));

    if (mon->json)
        ret = qemuMonitorJSONGraphicsRelocate(mon,
                                              type,
                                              hostname,
                                              port,
                                              tlsPort,
                                              tlsSubject);
    else
        ret = qemuMonitorTextGraphicsRelocate(mon,
                                              type,
                                              hostname,
                                              port,
                                              tlsPort,
                                              tlsSubject);

    return ret;
}


int qemuMonitorAddUSBDisk(qemuMonitorPtr mon,
                          const char *path)
{
    int ret;
    VIR_DEBUG("mon=%p path=%s", mon, path);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddUSBDisk(mon, path);
    else
        ret = qemuMonitorTextAddUSBDisk(mon, path);
    return ret;
}


int qemuMonitorAddUSBDeviceExact(qemuMonitorPtr mon,
                                 int bus,
                                 int dev)
{
    int ret;
    VIR_DEBUG("mon=%p bus=%d dev=%d", mon, bus, dev);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddUSBDeviceExact(mon, bus, dev);
    else
        ret = qemuMonitorTextAddUSBDeviceExact(mon, bus, dev);
    return ret;
}

int qemuMonitorAddUSBDeviceMatch(qemuMonitorPtr mon,
                                 int vendor,
                                 int product)
{
    int ret;
    VIR_DEBUG("mon=%p vendor=%d product=%d",
          mon, vendor, product);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddUSBDeviceMatch(mon, vendor, product);
    else
        ret = qemuMonitorTextAddUSBDeviceMatch(mon, vendor, product);
    return ret;
}


int qemuMonitorAddPCIHostDevice(qemuMonitorPtr mon,
                                virDomainDevicePCIAddress *hostAddr,
                                virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    VIR_DEBUG("mon=%p domain=%d bus=%d slot=%d function=%d",
          mon,
          hostAddr->domain, hostAddr->bus, hostAddr->slot, hostAddr->function);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddPCIHostDevice(mon, hostAddr, guestAddr);
    else
        ret = qemuMonitorTextAddPCIHostDevice(mon, hostAddr, guestAddr);
    return ret;
}


int qemuMonitorAddPCIDisk(qemuMonitorPtr mon,
                          const char *path,
                          const char *bus,
                          virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    VIR_DEBUG("mon=%p path=%s bus=%s",
          mon, path, bus);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddPCIDisk(mon, path, bus, guestAddr);
    else
        ret = qemuMonitorTextAddPCIDisk(mon, path, bus, guestAddr);
    return ret;
}


int qemuMonitorAddPCINetwork(qemuMonitorPtr mon,
                             const char *nicstr,
                             virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    VIR_DEBUG("mon=%p nicstr=%s", mon, nicstr);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddPCINetwork(mon, nicstr, guestAddr);
    else
        ret = qemuMonitorTextAddPCINetwork(mon, nicstr, guestAddr);
    return ret;
}


int qemuMonitorRemovePCIDevice(qemuMonitorPtr mon,
                               virDomainDevicePCIAddress *guestAddr)
{
    int ret;
    VIR_DEBUG("mon=%p domain=%d bus=%d slot=%d function=%d",
          mon, guestAddr->domain, guestAddr->bus,
          guestAddr->slot, guestAddr->function);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONRemovePCIDevice(mon, guestAddr);
    else
        ret = qemuMonitorTextRemovePCIDevice(mon, guestAddr);
    return ret;
}


int qemuMonitorSendFileHandle(qemuMonitorPtr mon,
                              const char *fdname,
                              int fd)
{
    int ret;
    VIR_DEBUG("mon=%p, fdname=%s fd=%d",
          mon, fdname, fd);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (fd < 0) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("fd must be valid"));
        return -1;
    }

    if (!mon->hasSendFD) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("qemu is not using a unix socket monitor, "
                          "cannot send fd %s"), fdname);
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSendFileHandle(mon, fdname, fd);
    else
        ret = qemuMonitorTextSendFileHandle(mon, fdname, fd);
    return ret;
}


int qemuMonitorCloseFileHandle(qemuMonitorPtr mon,
                               const char *fdname)
{
    int ret = -1;
    virErrorPtr error;

    VIR_DEBUG("mon=%p fdname=%s",
          mon, fdname);

    error = virSaveLastError();

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        goto cleanup;
    }

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


int qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                              const char *netstr,
                              int tapfd, const char *tapfd_name,
                              int vhostfd, const char *vhostfd_name)
{
    int ret = -1;
    VIR_DEBUG("mon=%p netstr=%s tapfd=%d tapfd_name=%s "
              "vhostfd=%d vhostfd_name=%s",
              mon, netstr, tapfd, NULLSTR(tapfd_name),
              vhostfd, NULLSTR(vhostfd_name));

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (tapfd >= 0 && qemuMonitorSendFileHandle(mon, tapfd_name, tapfd) < 0)
        return -1;
    if (vhostfd >= 0 &&
        qemuMonitorSendFileHandle(mon, vhostfd_name, vhostfd) < 0) {
        vhostfd = -1;
        goto cleanup;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddHostNetwork(mon, netstr);
    else
        ret = qemuMonitorTextAddHostNetwork(mon, netstr);

cleanup:
    if (ret < 0) {
        if (tapfd >= 0 && qemuMonitorCloseFileHandle(mon, tapfd_name) < 0)
            VIR_WARN("failed to close device handle '%s'", tapfd_name);
        if (vhostfd >= 0 && qemuMonitorCloseFileHandle(mon, vhostfd_name) < 0)
            VIR_WARN("failed to close device handle '%s'", vhostfd_name);
    }

    return ret;
}


int qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                                 int vlan,
                                 const char *netname)
{
    int ret;
    VIR_DEBUG("mon=%p netname=%s",
          mon, netname);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONRemoveHostNetwork(mon, vlan, netname);
    else
        ret = qemuMonitorTextRemoveHostNetwork(mon, vlan, netname);
    return ret;
}


int qemuMonitorAddNetdev(qemuMonitorPtr mon,
                         const char *netdevstr,
                         int tapfd, const char *tapfd_name,
                         int vhostfd, const char *vhostfd_name)
{
    int ret = -1;
    VIR_DEBUG("mon=%p netdevstr=%s tapfd=%d tapfd_name=%s "
              "vhostfd=%d vhostfd_name=%s",
              mon, netdevstr, tapfd, NULLSTR(tapfd_name),
              vhostfd, NULLSTR(vhostfd_name));

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (tapfd >= 0 && qemuMonitorSendFileHandle(mon, tapfd_name, tapfd) < 0)
        return -1;
    if (vhostfd >= 0 &&
        qemuMonitorSendFileHandle(mon, vhostfd_name, vhostfd) < 0) {
        vhostfd = -1;
        goto cleanup;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddNetdev(mon, netdevstr);
    else
        ret = qemuMonitorTextAddNetdev(mon, netdevstr);

cleanup:
    if (ret < 0) {
        if (tapfd >= 0 && qemuMonitorCloseFileHandle(mon, tapfd_name) < 0)
            VIR_WARN("failed to close device handle '%s'", tapfd_name);
        if (vhostfd >= 0 && qemuMonitorCloseFileHandle(mon, vhostfd_name) < 0)
            VIR_WARN("failed to close device handle '%s'", vhostfd_name);
    }

    return ret;
}

int qemuMonitorRemoveNetdev(qemuMonitorPtr mon,
                            const char *alias)
{
    int ret;
    VIR_DEBUG("mon=%p alias=%s",
          mon, alias);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONRemoveNetdev(mon, alias);
    else
        ret = qemuMonitorTextRemoveNetdev(mon, alias);
    return ret;
}


int qemuMonitorGetPtyPaths(qemuMonitorPtr mon,
                           virHashTablePtr paths)
{
    int ret;
    VIR_DEBUG("mon=%p",
          mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetPtyPaths(mon, paths);
    else
        ret = qemuMonitorTextGetPtyPaths(mon, paths);
    return ret;
}


int qemuMonitorAttachPCIDiskController(qemuMonitorPtr mon,
                                       const char *bus,
                                       virDomainDevicePCIAddress *guestAddr)
{
    VIR_DEBUG("mon=%p type=%s", mon, bus);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAttachPCIDiskController(mon, bus, guestAddr);
    else
        ret = qemuMonitorTextAttachPCIDiskController(mon, bus, guestAddr);

    return ret;
}


int qemuMonitorAttachDrive(qemuMonitorPtr mon,
                           const char *drivestr,
                           virDomainDevicePCIAddress *controllerAddr,
                           virDomainDeviceDriveAddress *driveAddr)
{
    VIR_DEBUG("mon=%p drivestr=%s domain=%d bus=%d slot=%d function=%d",
          mon, drivestr,
          controllerAddr->domain, controllerAddr->bus,
          controllerAddr->slot, controllerAddr->function);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAttachDrive(mon, drivestr, controllerAddr, driveAddr);
    else
        ret = qemuMonitorTextAttachDrive(mon, drivestr, controllerAddr, driveAddr);

    return ret;
}

int qemuMonitorGetAllPCIAddresses(qemuMonitorPtr mon,
                                  qemuMonitorPCIAddress **addrs)
{
    VIR_DEBUG("mon=%p addrs=%p", mon, addrs);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetAllPCIAddresses(mon, addrs);
    else
        ret = qemuMonitorTextGetAllPCIAddresses(mon, addrs);
    return ret;
}

int qemuMonitorDriveDel(qemuMonitorPtr mon,
                        const char *drivestr)
{
    VIR_DEBUG("mon=%p drivestr=%s", mon, drivestr);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONDriveDel(mon, drivestr);
    else
        ret = qemuMonitorTextDriveDel(mon, drivestr);
    return ret;
}

int qemuMonitorDelDevice(qemuMonitorPtr mon,
                         const char *devalias)
{
    VIR_DEBUG("mon=%p devalias=%s", mon, devalias);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONDelDevice(mon, devalias);
    else
        ret = qemuMonitorTextDelDevice(mon, devalias);
    return ret;
}


int qemuMonitorAddDeviceWithFd(qemuMonitorPtr mon,
                               const char *devicestr,
                               int fd,
                               const char *fdname)
{
    VIR_DEBUG("mon=%p device=%s fd=%d fdname=%s", mon, devicestr, fd,
              NULLSTR(fdname));
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

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

int qemuMonitorAddDevice(qemuMonitorPtr mon,
                         const char *devicestr)
{
    return qemuMonitorAddDeviceWithFd(mon, devicestr, -1, NULL);
}

int qemuMonitorAddDrive(qemuMonitorPtr mon,
                        const char *drivestr)
{
    VIR_DEBUG("mon=%p drive=%s", mon, drivestr);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddDrive(mon, drivestr);
    else
        ret = qemuMonitorTextAddDrive(mon, drivestr);
    return ret;
}


int qemuMonitorSetDrivePassphrase(qemuMonitorPtr mon,
                                  const char *alias,
                                  const char *passphrase)
{
    VIR_DEBUG("mon=%p alias=%s passphrase=%p(value hidden)", mon, alias, passphrase);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetDrivePassphrase(mon, alias, passphrase);
    else
        ret = qemuMonitorTextSetDrivePassphrase(mon, alias, passphrase);
    return ret;
}

int qemuMonitorCreateSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;

    VIR_DEBUG("mon=%p, name=%s",mon,name);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONCreateSnapshot(mon, name);
    else
        ret = qemuMonitorTextCreateSnapshot(mon, name);
    return ret;
}

int qemuMonitorLoadSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;

    VIR_DEBUG("mon=%p, name=%s",mon,name);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONLoadSnapshot(mon, name);
    else
        ret = qemuMonitorTextLoadSnapshot(mon, name);
    return ret;
}

int qemuMonitorDeleteSnapshot(qemuMonitorPtr mon, const char *name)
{
    int ret;

    VIR_DEBUG("mon=%p, name=%s",mon,name);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONDeleteSnapshot(mon, name);
    else
        ret = qemuMonitorTextDeleteSnapshot(mon, name);
    return ret;
}

/* Use the snapshot_blkdev command to convert the existing file for
 * device into a read-only backing file of a new qcow2 image located
 * at file.  */
int
qemuMonitorDiskSnapshot(qemuMonitorPtr mon, virJSONValuePtr actions,
                        const char *device, const char *file,
                        const char *format, bool reuse)
{
    int ret;

    VIR_DEBUG("mon=%p, actions=%p, device=%s, file=%s, format=%s, reuse=%d",
              mon, actions, device, file, format, reuse);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json) {
        ret = qemuMonitorJSONDiskSnapshot(mon, actions, device, file, format,
                                          reuse);
    } else {
        if (actions || STRNEQ(format, "qcow2") || reuse) {
            qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                            _("text monitor lacks several snapshot features"));
            return -1;
        }
        ret = qemuMonitorTextDiskSnapshot(mon, device, file);
    }
    return ret;
}

/* Use the transaction QMP command to run atomic snapshot commands.  */
int
qemuMonitorTransaction(qemuMonitorPtr mon, virJSONValuePtr actions)
{
    int ret = -1;

    VIR_DEBUG("mon=%p, actions=%p", mon, actions);

    if (mon->json)
        ret = qemuMonitorJSONTransaction(mon, actions);
    else
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("transaction requires JSON monitor"));
    return ret;
}

int qemuMonitorArbitraryCommand(qemuMonitorPtr mon,
                                const char *cmd,
                                char **reply,
                                bool hmp)
{
    int ret;

    VIR_DEBUG("mon=%p, cmd=%s, reply=%p, hmp=%d", mon, cmd, reply, hmp);

    if (mon->json)
        ret = qemuMonitorJSONArbitraryCommand(mon, cmd, reply, hmp);
    else
        ret = qemuMonitorTextArbitraryCommand(mon, cmd, reply);
    return ret;
}


int qemuMonitorInjectNMI(qemuMonitorPtr mon)
{
    int ret;

    VIR_DEBUG("mon=%p", mon);

    if (mon->json)
        ret = qemuMonitorJSONInjectNMI(mon);
    else
        ret = qemuMonitorTextInjectNMI(mon);
    return ret;
}

int qemuMonitorSendKey(qemuMonitorPtr mon,
                       unsigned int holdtime,
                       unsigned int *keycodes,
                       unsigned int nkeycodes)
{
    int ret;

    VIR_DEBUG("mon=%p, holdtime=%u, nkeycodes=%u",
              mon, holdtime, nkeycodes);

    if (mon->json)
        ret = qemuMonitorJSONSendKey(mon, holdtime, keycodes, nkeycodes);
    else
        ret = qemuMonitorTextSendKey(mon, holdtime, keycodes, nkeycodes);
    return ret;
}

int qemuMonitorScreendump(qemuMonitorPtr mon,
                          const char *file)
{
    int ret;

    VIR_DEBUG("mon=%p, file=%s", mon, file);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG,"%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONScreendump(mon, file);
    else
        ret = qemuMonitorTextScreendump(mon, file);
    return ret;
}

int qemuMonitorBlockJob(qemuMonitorPtr mon,
                        const char *device,
                        const char *base,
                        unsigned long bandwidth,
                        virDomainBlockJobInfoPtr info,
                        int mode)
{
    int ret = -1;

    VIR_DEBUG("mon=%p, device=%s, base=%s, bandwidth=%lu, info=%p, mode=%o",
              mon, device, NULLSTR(base), bandwidth, info, mode);

    if (mon->json)
        ret = qemuMonitorJSONBlockJob(mon, device, base, bandwidth, info, mode);
    else
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("block jobs require JSON monitor"));
    return ret;
}

int qemuMonitorSetBlockIoThrottle(qemuMonitorPtr mon,
                                  const char *device,
                                  virDomainBlockIoTuneInfoPtr info)
{
    int ret;

    VIR_DEBUG("mon=%p, device=%p, info=%p", mon, device, info);

    if (mon->json) {
        ret = qemuMonitorJSONSetBlockIoThrottle(mon, device, info);
    } else {
        ret = qemuMonitorTextSetBlockIoThrottle(mon, device, info);
    }
    return ret;
}

int qemuMonitorGetBlockIoThrottle(qemuMonitorPtr mon,
                                  const char *device,
                                  virDomainBlockIoTuneInfoPtr reply)
{
    int ret;

    VIR_DEBUG("mon=%p, device=%p, reply=%p", mon, device, reply);

    if (mon->json) {
        ret = qemuMonitorJSONGetBlockIoThrottle(mon, device, reply);
    } else {
        ret = qemuMonitorTextGetBlockIoThrottle(mon, device, reply);
    }
    return ret;
}


int qemuMonitorVMStatusToPausedReason(const char *status)
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

    /* unreachable from this point on */
    case QEMU_MONITOR_VM_STATUS_LAST:
        ;
    }
    return VIR_DOMAIN_PAUSED_UNKNOWN;
}


int qemuMonitorOpenGraphics(qemuMonitorPtr mon,
                            const char *protocol,
                            int fd,
                            const char *fdname,
                            bool skipauth)
{
    VIR_DEBUG("mon=%p protocol=%s fd=%d fdname=%s skipauth=%d",
              mon, protocol, fd, NULLSTR(fdname), skipauth);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

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

int qemuMonitorSystemWakeup(qemuMonitorPtr mon)
{
    VIR_DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (!mon->json) {
        qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                        _("JSON monitor is required"));
        return -1;
    }

    return qemuMonitorJSONSystemWakeup(mon);
}
