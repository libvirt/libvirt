/*
 * qemu_monitor.c: interaction with QEMU monitor console
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

#include <poll.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>

#include "qemu_monitor.h"
#include "qemu_monitor_text.h"
#include "qemu_monitor_json.h"
#include "qemu_conf.h"
#include "event.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

struct _qemuMonitor {
    virMutex lock;
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
    int lastErrno;

    /* If the monitor EOF callback is currently active (stops more commands being run) */
    unsigned eofcb: 1;
    /* If the monitor is in process of shutting down */
    unsigned closed: 1;

    unsigned json: 1;
};


VIR_ENUM_IMPL(qemuMonitorMigrationStatus,
              QEMU_MONITOR_MIGRATION_STATUS_LAST,
              "inactive", "active", "completed", "failed", "cancelled")

static char *qemuMonitorEscape(const char *in, int shell)
{
    int len = 0;
    int i, j;
    char *out;

    /* To pass through the QEMU monitor, we need to use escape
       sequences: \r, \n, \", \\

       To pass through both QEMU + the shell, we need to escape
       the single character ' as the five characters '\\''
    */

    for (i = 0; in[i] != '\0'; i++) {
        switch(in[i]) {
        case '\r':
        case '\n':
        case '"':
        case '\\':
            len += 2;
            break;
        case '\'':
            if (shell)
                len += 5;
            else
                len += 1;
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
        case '\'':
            if (shell) {
                out[j++] = '\'';
                out[j++] = '\\';
                out[j++] = '\\';
                out[j++] = '\'';
                out[j++] = '\'';
            } else {
                out[j++] = in[i];
            }
            break;
        default:
            out[j++] = in[i];
            break;
        }
    }
    out[j] = '\0';

    return out;
}

char *qemuMonitorEscapeArg(const char *in)
{
    return qemuMonitorEscape(in, 0);
}

char *qemuMonitorEscapeShell(const char *in)
{
    return qemuMonitorEscape(in, 1);
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
            virBufferVSprintf(&buf,"%c", text[i]);
        else
            virBufferVSprintf(&buf, "0x%02x", text[i]);
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
    VIR_FREE(mon);
}

int qemuMonitorRef(qemuMonitorPtr mon)
{
    mon->refs++;
    return mon->refs;
}

int qemuMonitorUnref(qemuMonitorPtr mon)
{
    mon->refs--;

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
    qemuMonitorUnref(mon);
}

static int
qemuMonitorOpenUnix(const char *monitor)
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

        if (errno == ENOENT || errno == ECONNREFUSED) {
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
    close(monfd);
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

    if (mon->json)
        len = qemuMonitorJSONIOProcess(mon,
                                       mon->buffer, mon->bufferOffset,
                                       msg);
    else
        len = qemuMonitorTextIOProcess(mon,
                                       mon->buffer, mon->bufferOffset,
                                       msg);

    if (len < 0) {
        mon->lastErrno = errno;
        return -1;
    }

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

    if (!mon->hasSendFD) {
        errno = EINVAL;
        return -1;
    }

    memset(&msg, 0, sizeof(msg));

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

/* Called when the monitor is able to write data */
static int
qemuMonitorIOWrite(qemuMonitorPtr mon)
{
    int done;

    /* If no active message, or fully transmitted, the no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    if (mon->msg->txFD == -1)
        done = write(mon->fd,
                     mon->msg->txBuffer + mon->msg->txOffset,
                     mon->msg->txLength - mon->msg->txOffset);
    else
        done = qemuMonitorIOWriteWithFD(mon,
                                        mon->msg->txBuffer + mon->msg->txOffset,
                                        mon->msg->txLength - mon->msg->txOffset,
                                        mon->msg->txFD);

    if (done < 0) {
        if (errno == EAGAIN)
            return 0;

        mon->lastErrno = errno;
        return -1;
    }
    mon->msg->txOffset += done;
    return done;
}

/*
 * Called when the monitor has incoming data to read
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
            errno = ENOMEM;
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
            mon->lastErrno = errno;
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

    if (!mon->lastErrno) {
        events |= VIR_EVENT_HANDLE_READABLE;

        if (mon->msg && mon->msg->txOffset < mon->msg->txLength)
            events |= VIR_EVENT_HANDLE_WRITABLE;
    }

    virEventUpdateHandle(mon->watch, events);
}


static void
qemuMonitorIO(int watch, int fd, int events, void *opaque) {
    qemuMonitorPtr mon = opaque;
    int quit = 0, failed = 0;

    qemuMonitorLock(mon);
    qemuMonitorRef(mon);
#if DEBUG_IO
    VIR_DEBUG("Monitor %p I/O on watch %d fd %d events %d", mon, watch, fd, events);
#endif

    if (mon->fd != fd || mon->watch != watch) {
        VIR_ERROR(_("event from unexpected fd %d!=%d / watch %d!=%d"), mon->fd, fd, mon->watch, watch);
        failed = 1;
    } else {
        if (!mon->lastErrno &&
            events & VIR_EVENT_HANDLE_WRITABLE) {
            int done = qemuMonitorIOWrite(mon);
            if (done < 0)
                failed = 1;
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }
        if (!mon->lastErrno &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuMonitorIORead(mon);
            if (got < 0)
                failed = 1;
            /* Ignore hangup/error events if we read some data, to
             * give time for that data to be consumed */
            if (got > 0) {
                events = 0;

                if (qemuMonitorIOProcess(mon) < 0)
                    failed = 1;
            } else
                events &= ~VIR_EVENT_HANDLE_READABLE;
        }

        /* If IO process resulted in an error & we have a message,
         * then wakeup that waiter */
        if (mon->lastErrno && mon->msg && !mon->msg->finished) {
            mon->msg->lastErrno = mon->lastErrno;
            mon->msg->finished = 1;
            virCondSignal(&mon->notify);
        }

        qemuMonitorUpdateWatch(mon);

        if (events & VIR_EVENT_HANDLE_HANGUP) {
            /* If IO process resulted in EOF & we have a message,
             * then wakeup that waiter */
            if (mon->msg && !mon->msg->finished) {
                mon->msg->finished = 1;
                mon->msg->lastErrno = EIO;
                virCondSignal(&mon->notify);
            }
            quit = 1;
        } else if (events) {
            VIR_ERROR(_("unhandled fd event %d for monitor fd %d"),
                      events, mon->fd);
            failed = 1;
        }
    }

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (failed || quit) {
        void (*eofNotify)(qemuMonitorPtr, virDomainObjPtr, int)
            = mon->cb->eofNotify;
        virDomainObjPtr vm = mon->vm;
        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        if (qemuMonitorUnref(mon) > 0)
            qemuMonitorUnlock(mon);
        VIR_DEBUG("Triggering EOF callback error? %d", failed);
        (eofNotify)(mon, vm, failed);
    } else {
        if (qemuMonitorUnref(mon) > 0)
            qemuMonitorUnlock(mon);
    }
}


qemuMonitorPtr
qemuMonitorOpen(virDomainObjPtr vm,
                virDomainChrDefPtr config,
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
        mon->fd = qemuMonitorOpenUnix(config->data.nix.path);
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

    VIR_DEBUG("New mon %p fd =%d watch=%d", mon, mon->fd, mon->watch);
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
    int refs;

    if (!mon)
        return;

    VIR_DEBUG("mon=%p", mon);

    qemuMonitorLock(mon);
    if (!mon->closed) {
        if (mon->watch)
            virEventRemoveHandle(mon->watch);
        if (mon->fd != -1)
            close(mon->fd);
        /* NB: ordinarily one might immediately set mon->watch to -1
         * and mon->fd to -1, but there may be a callback active
         * that is still relying on these fields being valid. So
         * we merely close them, but not clear their values and
         * use this explicit 'closed' flag to track this state */
        mon->closed = 1;
    }

    if ((refs = qemuMonitorUnref(mon)) > 0)
        qemuMonitorUnlock(mon);
}


int qemuMonitorSend(qemuMonitorPtr mon,
                    qemuMonitorMessagePtr msg)
{
    int ret = -1;

    if (mon->eofcb) {
        msg->lastErrno = EIO;
        return -1;
    }

    mon->msg = msg;
    qemuMonitorUpdateWatch(mon);

    while (!mon->msg->finished) {
        if (virCondWait(&mon->notify, &mon->lock) < 0)
            goto cleanup;
    }

    if (mon->lastErrno == 0)
        ret = 0;

cleanup:
    mon->msg = NULL;
    qemuMonitorUpdateWatch(mon);

    return ret;
}


int qemuMonitorGetDiskSecret(qemuMonitorPtr mon,
                             virConnectPtr conn,
                             const char *path,
                             char **secret,
                             size_t *secretLen)
{
    int ret = -1;
    *secret = NULL;
    *secretLen = 0;

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->diskSecretLookup)
        ret = mon->cb->diskSecretLookup(mon, conn, mon->vm, path, secret, secretLen);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitShutdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainShutdown)
        ret = mon->cb->domainShutdown(mon, mon->vm);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitReset(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainReset)
        ret = mon->cb->domainReset(mon, mon->vm);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitPowerdown(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainPowerdown)
        ret = mon->cb->domainPowerdown(mon, mon->vm);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitStop(qemuMonitorPtr mon)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainStop)
        ret = mon->cb->domainStop(mon, mon->vm);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitRTCChange(qemuMonitorPtr mon, long long offset)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainRTCChange)
        ret = mon->cb->domainRTCChange(mon, mon->vm, offset);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitWatchdog(qemuMonitorPtr mon, int action)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainWatchdog)
        ret = mon->cb->domainWatchdog(mon, mon->vm, action);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}


int qemuMonitorEmitIOError(qemuMonitorPtr mon,
                           const char *diskAlias,
                           int action,
                           const char *reason)
{
    int ret = -1;
    VIR_DEBUG("mon=%p", mon);

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainIOError)
        ret = mon->cb->domainIOError(mon, mon->vm, diskAlias, action, reason);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
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

    qemuMonitorRef(mon);
    qemuMonitorUnlock(mon);
    if (mon->cb && mon->cb->domainGraphics)
        ret = mon->cb->domainGraphics(mon, mon->vm,
                                      phase,
                                      localFamily, localNode, localService,
                                      remoteFamily, remoteNode, remoteService,
                                      authScheme, x509dname, saslUsername);
    qemuMonitorLock(mon);
    qemuMonitorUnref(mon);
    return ret;
}



int qemuMonitorSetCapabilities(qemuMonitorPtr mon)
{
    int ret;
    DEBUG("mon=%p", mon);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONSetCapabilities(mon);
    else
        ret = 0;
    return ret;
}


int
qemuMonitorStartCPUs(qemuMonitorPtr mon,
                     virConnectPtr conn)
{
    int ret;
    DEBUG("mon=%p", mon);

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
    DEBUG("mon=%p", mon);

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


int qemuMonitorSystemPowerdown(qemuMonitorPtr mon)
{
    int ret;
    DEBUG("mon=%p", mon);

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


int qemuMonitorGetCPUInfo(qemuMonitorPtr mon,
                          int **pids)
{
    int ret;
    DEBUG("mon=%p", mon);

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

int qemuMonitorGetBalloonInfo(qemuMonitorPtr mon,
                              unsigned long *currmem)
{
    int ret;
    DEBUG("mon=%p", mon);

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
    DEBUG("mon=%p stats=%p nstats=%u", mon, stats, nr_stats);

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


int qemuMonitorGetBlockStatsInfo(qemuMonitorPtr mon,
                                 const char *devname,
                                 long long *rd_req,
                                 long long *rd_bytes,
                                 long long *wr_req,
                                 long long *wr_bytes,
                                 long long *errs)
{
    int ret;
    DEBUG("mon=%p dev=%s", mon, devname);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONGetBlockStatsInfo(mon, devname,
                                               rd_req, rd_bytes,
                                               wr_req, wr_bytes,
                                               errs);
    else
        ret = qemuMonitorTextGetBlockStatsInfo(mon, devname,
                                               rd_req, rd_bytes,
                                               wr_req, wr_bytes,
                                               errs);
    return ret;
}

int qemuMonitorGetBlockExtent(qemuMonitorPtr mon,
                              const char *devname,
                              unsigned long long *extent)
{
    int ret;
    DEBUG("mon=%p, fd=%d, devname=%p",
          mon, mon->fd, devname);

    if (mon->json)
        ret = qemuMonitorJSONGetBlockExtent(mon, devname, extent);
    else
        ret = qemuMonitorTextGetBlockExtent(mon, devname, extent);

    return ret;
}


int qemuMonitorSetVNCPassword(qemuMonitorPtr mon,
                              const char *password)
{
    int ret;
    DEBUG("mon=%p, password=%p",
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


int qemuMonitorSetBalloon(qemuMonitorPtr mon,
                          unsigned long newmem)
{
    int ret;
    DEBUG("mon=%p newmem=%lu", mon, newmem);

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
    DEBUG("mon=%p cpu=%d online=%d", mon, cpu, online);

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
                          const char *devname)
{
    int ret;
    DEBUG("mon=%p devname=%s", mon, devname);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONEjectMedia(mon, devname);
    else
        ret = qemuMonitorTextEjectMedia(mon, devname);
    return ret;
}


int qemuMonitorChangeMedia(qemuMonitorPtr mon,
                           const char *devname,
                           const char *newmedia,
                           const char *format)
{
    int ret;
    DEBUG("mon=%p devname=%s newmedia=%s format=%s",
          mon, devname, newmedia, format);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONChangeMedia(mon, devname, newmedia, format);
    else
        ret = qemuMonitorTextChangeMedia(mon, devname, newmedia, format);
    return ret;
}


int qemuMonitorSaveVirtualMemory(qemuMonitorPtr mon,
                                 unsigned long long offset,
                                 size_t length,
                                 const char *path)
{
    int ret;
    DEBUG("mon=%p offset=%llu length=%zu path=%s",
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
    DEBUG("mon=%p offset=%llu length=%zu path=%s",
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
    DEBUG("mon=%p bandwidth=%lu", mon, bandwidth);

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
    DEBUG("mon=%p downtime=%llu", mon, downtime);

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
    DEBUG("mon=%p", mon);

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


int qemuMonitorMigrateToHost(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *hostname,
                             int port)
{
    int ret;
    DEBUG("mon=%p hostname=%s port=%d flags=%u",
          mon, hostname, port, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrateToHost(mon, flags, hostname, port);
    else
        ret = qemuMonitorTextMigrateToHost(mon, flags, hostname, port);
    return ret;
}


int qemuMonitorMigrateToCommand(qemuMonitorPtr mon,
                                unsigned int flags,
                                const char * const *argv)
{
    int ret;
    DEBUG("mon=%p argv=%p flags=%u",
          mon, argv, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrateToCommand(mon, flags, argv);
    else
        ret = qemuMonitorTextMigrateToCommand(mon, flags, argv);
    return ret;
}

int qemuMonitorMigrateToFile(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char * const *argv,
                             const char *target,
                             unsigned long long offset)
{
    int ret;
    DEBUG("mon=%p argv=%p target=%s offset=%llu flags=%u",
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

    if (mon->json)
        ret = qemuMonitorJSONMigrateToFile(mon, flags, argv, target, offset);
    else
        ret = qemuMonitorTextMigrateToFile(mon, flags, argv, target, offset);
    return ret;
}

int qemuMonitorMigrateToUnix(qemuMonitorPtr mon,
                             unsigned int flags,
                             const char *unixfile)
{
    int ret;
    DEBUG("mon=%p, unixfile=%s flags=%u",
          mon, unixfile, flags);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONMigrateToUnix(mon, flags, unixfile);
    else
        ret = qemuMonitorTextMigrateToUnix(mon, flags, unixfile);
    return ret;
}

int qemuMonitorMigrateCancel(qemuMonitorPtr mon)
{
    int ret;
    DEBUG("mon=%p", mon);

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

int qemuMonitorAddUSBDisk(qemuMonitorPtr mon,
                          const char *path)
{
    int ret;
    DEBUG("mon=%p path=%s", mon, path);

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
    DEBUG("mon=%p bus=%d dev=%d", mon, bus, dev);

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
    DEBUG("mon=%p vendor=%d product=%d",
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
    DEBUG("mon=%p domain=%d bus=%d slot=%d function=%d",
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
    DEBUG("mon=%p path=%s bus=%s",
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
    DEBUG("mon=%p nicstr=%s", mon, nicstr);

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
    DEBUG("mon=%p domain=%d bus=%d slot=%d function=%d",
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
    DEBUG("mon=%p, fdname=%s fd=%d",
          mon, fdname, fd);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
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
    int ret;
    DEBUG("mon=%p fdname=%s",
          mon, fdname);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONCloseFileHandle(mon, fdname);
    else
        ret = qemuMonitorTextCloseFileHandle(mon, fdname);
    return ret;
}


int qemuMonitorAddHostNetwork(qemuMonitorPtr mon,
                              const char *netstr)
{
    int ret;
    DEBUG("mon=%p netstr=%s",
          mon, netstr);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddHostNetwork(mon, netstr);
    else
        ret = qemuMonitorTextAddHostNetwork(mon, netstr);
    return ret;
}


int qemuMonitorRemoveHostNetwork(qemuMonitorPtr mon,
                                 int vlan,
                                 const char *netname)
{
    int ret;
    DEBUG("mon=%p netname=%s",
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
                         const char *netdevstr)
{
    int ret;
    DEBUG("mon=%p netdevstr=%s",
          mon, netdevstr);

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddNetdev(mon, netdevstr);
    else
        ret = qemuMonitorTextAddNetdev(mon, netdevstr);
    return ret;
}


int qemuMonitorRemoveNetdev(qemuMonitorPtr mon,
                            const char *alias)
{
    int ret;
    DEBUG("mon=%p alias=%s",
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
    DEBUG("mon=%p",
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
    DEBUG("mon=%p type=%s", mon, bus);
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
    DEBUG("mon=%p drivestr=%s domain=%d bus=%d slot=%d function=%d",
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
    DEBUG("mon=%p addrs=%p", mon, addrs);
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

int qemuMonitorDelDevice(qemuMonitorPtr mon,
                         const char *devalias)
{
    DEBUG("mon=%p devalias=%s", mon, devalias);
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


int qemuMonitorAddDevice(qemuMonitorPtr mon,
                         const char *devicestr)
{
    DEBUG("mon=%p device=%s", mon, devicestr);
    int ret;

    if (!mon) {
        qemuReportError(VIR_ERR_INVALID_ARG, "%s",
                        _("monitor must not be NULL"));
        return -1;
    }

    if (mon->json)
        ret = qemuMonitorJSONAddDevice(mon, devicestr);
    else
        ret = qemuMonitorTextAddDevice(mon, devicestr);
    return ret;
}

int qemuMonitorAddDrive(qemuMonitorPtr mon,
                        const char *drivestr)
{
    DEBUG("mon=%p drive=%s", mon, drivestr);
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
    DEBUG("mon=%p alias=%s passphrase=%p(value hidden)", mon, alias, passphrase);
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

    DEBUG("mon=%p, name=%s",mon,name);

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

    DEBUG("mon=%p, name=%s",mon,name);

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

    DEBUG("mon=%p, name=%s",mon,name);

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
