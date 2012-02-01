/*
 * qemu_agent.h: interaction with QEMU guest agent
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
#include <fcntl.h>
#include <string.h>
#include <sys/time.h>

#include "qemu_agent.h"
#include "qemu_command.h"
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "json.h"
#include "virfile.h"
#include "virtime.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#define LINE_ENDING "\n"

#define DEBUG_IO 0
#define DEBUG_RAW_IO 0

/* When you are the first to uncomment this,
 * don't forget to uncomment the corresponding
 * part in qemuAgentIOProcessEvent as well.
 *
static struct {
    const char *type;
    void (*handler)(qemuAgentPtr mon, virJSONValuePtr data);
} eventHandlers[] = {
};
*/

typedef struct _qemuAgentMessage qemuAgentMessage;
typedef qemuAgentMessage *qemuAgentMessagePtr;

struct _qemuAgentMessage {
    char *txBuffer;
    int txOffset;
    int txLength;

    /* Used by the JSON monitor to hold reply / error */
    char *rxBuffer;
    int rxLength;
    void *rxObject;

    /* True if rxBuffer / rxObject are ready, or a
     * fatal error occurred on the monitor channel
     */
    bool finished;
};


struct _qemuAgent {
    virMutex lock; /* also used to protect fd */
    virCond notify;

    int refs;

    int fd;
    int watch;

    bool connectPending;

    virDomainObjPtr vm;

    qemuAgentCallbacksPtr cb;

    /* If there's a command being processed this will be
     * non-NULL */
    qemuAgentMessagePtr msg;

    /* Buffer incoming data ready for Agent monitor
     * code to process & find message boundaries */
    size_t bufferOffset;
    size_t bufferLength;
    char *buffer;

    /* If anything went wrong, this will be fed back
     * the next monitor msg */
    virError lastError;
};

#if DEBUG_RAW_IO
# include <c-ctype.h>
static char *
qemuAgentEscapeNonPrintable(const char *text)
{
    int i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    for (i = 0 ; text[i] != '\0' ; i++) {
        if (text[i] == '\\')
            virBufferAddLit(&buf, "\\\\");
        else if (c_isprint(text[i]) || text[i] == '\n' ||
                 (text[i] == '\r' && text[i+1] == '\n'))
            virBufferAddChar(&buf, text[i]);
        else
            virBufferAsprintf(&buf, "\\x%02x", text[i]);
    }
    return virBufferContentAndReset(&buf);
}
#endif

void qemuAgentLock(qemuAgentPtr mon)
{
    virMutexLock(&mon->lock);
}


void qemuAgentUnlock(qemuAgentPtr mon)
{
    virMutexUnlock(&mon->lock);
}


static void qemuAgentFree(qemuAgentPtr mon)
{
    VIR_DEBUG("mon=%p", mon);
    if (mon->cb && mon->cb->destroy)
        (mon->cb->destroy)(mon, mon->vm);
    ignore_value(virCondDestroy(&mon->notify));
    virMutexDestroy(&mon->lock);
    VIR_FREE(mon->buffer);
    VIR_FREE(mon);
}

int qemuAgentRef(qemuAgentPtr mon)
{
    mon->refs++;
    return mon->refs;
}

int qemuAgentUnref(qemuAgentPtr mon)
{
    mon->refs--;

    if (mon->refs == 0) {
        qemuAgentUnlock(mon);
        qemuAgentFree(mon);
        return 0;
    }

    return mon->refs;
}

static void
qemuAgentUnwatch(void *monitor)
{
    qemuAgentPtr mon = monitor;

    qemuAgentLock(mon);
    if (qemuAgentUnref(mon) > 0)
        qemuAgentUnlock(mon);
}

static int
qemuAgentOpenUnix(const char *monitor, pid_t cpid, bool *inProgress)
{
    struct sockaddr_un addr;
    int monfd;
    int timeout = 3; /* In seconds */
    int ret, i = 0;

    *inProgress = false;

    if ((monfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno,
                             "%s", _("failed to create socket"));
        return -1;
    }

    if (virSetNonBlock(monfd) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Unable to put monitor into non-blocking mode"));
        goto error;
    }

    if (virSetCloseExec(monfd) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Unable to set monitor close-on-exec flag"));
        goto error;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, monitor) == NULL) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Agent path %s too big for destination"), monitor);
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

        if ((errno == EINPROGRESS) ||
            (errno == EAGAIN)) {
            VIR_DEBUG("Connection attempt continuing in background");
            *inProgress = true;
            ret = 0;
            break;
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
qemuAgentOpenPty(const char *monitor)
{
    int monfd;

    if ((monfd = open(monitor, O_RDWR | O_NONBLOCK)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Unable to open monitor path %s"), monitor);
        return -1;
    }

    if (virSetCloseExec(monfd) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("Unable to set monitor close-on-exec flag"));
        goto error;
    }

    return monfd;

error:
    VIR_FORCE_CLOSE(monfd);
    return -1;
}


static int
qemuAgentIOProcessEvent(qemuAgentPtr mon,
                        virJSONValuePtr obj)
{
    const char *type;
    VIR_DEBUG("mon=%p obj=%p", mon, obj);

    type = virJSONValueObjectGetString(obj, "event");
    if (!type) {
        VIR_WARN("missing event type in message");
        errno = EINVAL;
        return -1;
    }

/*
    for (i = 0 ; i < ARRAY_CARDINALITY(eventHandlers) ; i++) {
        if (STREQ(eventHandlers[i].type, type)) {
            virJSONValuePtr data = virJSONValueObjectGet(obj, "data");
            VIR_DEBUG("handle %s handler=%p data=%p", type,
                      eventHandlers[i].handler, data);
            (eventHandlers[i].handler)(mon, data);
            break;
        }
    }
*/
    return 0;
}

static int
qemuAgentIOProcessLine(qemuAgentPtr mon,
                       const char *line,
                       qemuAgentMessagePtr msg)
{
    virJSONValuePtr obj = NULL;
    int ret = -1;
    unsigned long long id;

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
        ret = qemuAgentIOProcessEvent(mon, obj);
    } else if (virJSONValueObjectHasKey(obj, "error") == 1 ||
               virJSONValueObjectHasKey(obj, "return") == 1) {
        if (msg) {
            msg->rxObject = obj;
            msg->finished = 1;
            obj = NULL;
            ret = 0;
        } else {
            /* If we've received something like:
             *  {"return": 1234}
             * it is likely that somebody started GA
             * which is now processing our previous
             * guest-sync commands. Check if this is
             * the case and don't report an error but
             * return silently.
             */
            if (virJSONValueObjectGetNumberUlong(obj, "return", &id) == 0) {
                VIR_DEBUG("Ignoring delayed reply to guest-sync: %llu", id);
                ret = 0;
                goto cleanup;
            }

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

static int qemuAgentIOProcessData(qemuAgentPtr mon,
                                  char *data,
                                  size_t len,
                                  qemuAgentMessagePtr msg)
{
    int used = 0;
    int i = 0;
#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(data);
    VIR_ERROR("[%s]", str1);
    VIR_FREE(str1);
# else
    VIR_DEBUG("Data %zu bytes [%s]", len, data);
# endif
#endif

    while (used < len) {
        char *nl = strstr(data + used, LINE_ENDING);

        if (nl) {
            int got = nl - (data + used);
            for (i = 0; i < strlen(LINE_ENDING); i++)
                data[used + got + i] = '\0';
            if (qemuAgentIOProcessLine(mon, data + used, msg) < 0) {
                return -1;
            }
            used += got + strlen(LINE_ENDING);
        } else {
            break;
        }
    }

    VIR_DEBUG("Total used %d bytes out of %zd available in buffer", used, len);
    return used;
}

/* This method processes data that has been received
 * from the monitor. Looking for async events and
 * replies/errors.
 */
static int
qemuAgentIOProcess(qemuAgentPtr mon)
{
    int len;
    qemuAgentMessagePtr msg = NULL;

    /* See if there's a message ready for reply; that is,
     * one that has completed writing all its data.
     */
    if (mon->msg && mon->msg->txOffset == mon->msg->txLength)
        msg = mon->msg;

#if DEBUG_IO
# if DEBUG_RAW_IO
    char *str1 = qemuAgentEscapeNonPrintable(msg ? msg->txBuffer : "");
    char *str2 = qemuAgentEscapeNonPrintable(mon->buffer);
    VIR_ERROR(_("Process %zu %p %p [[[%s]]][[[%s]]]"),
              mon->bufferOffset, mon->msg, msg, str1, str2);
    VIR_FREE(str1);
    VIR_FREE(str2);
# else
    VIR_DEBUG("Process %zu", mon->bufferOffset);
# endif
#endif

    len = qemuAgentIOProcessData(mon,
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
    VIR_DEBUG("Process done %zu used %d", mon->bufferOffset, len);
#endif
    if (msg && msg->finished)
        virCondBroadcast(&mon->notify);
    return len;
}


static int
qemuAgentIOConnect(qemuAgentPtr mon)
{
    int optval;
    socklen_t optlen;

    VIR_DEBUG("Checking on background connection status");

    mon->connectPending = false;

    optlen = sizeof(optval);

    if (getsockopt(mon->fd, SOL_SOCKET, SO_ERROR,
                   &optval, &optlen) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot check socket connection status"));
        return -1;
    }

    if (optval != 0) {
        virReportSystemError(optval, "%s",
                             _("Cannot connect to agent socket"));
        return -1;
    }

    VIR_DEBUG("Agent is now connected");
    return 0;
}

/*
 * Called when the monitor is able to write data
 * Call this function while holding the monitor lock.
 */
static int
qemuAgentIOWrite(qemuAgentPtr mon)
{
    int done;

    /* If no active message, or fully transmitted, then no-op */
    if (!mon->msg || mon->msg->txOffset == mon->msg->txLength)
        return 0;

    done = safewrite(mon->fd,
                     mon->msg->txBuffer + mon->msg->txOffset,
                     mon->msg->txLength - mon->msg->txOffset);

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
qemuAgentIORead(qemuAgentPtr mon)
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
    VIR_DEBUG("Now read %zu bytes of data", mon->bufferOffset);
#endif

    return ret;
}


static void qemuAgentUpdateWatch(qemuAgentPtr mon)
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
qemuAgentIO(int watch, int fd, int events, void *opaque) {
    qemuAgentPtr mon = opaque;
    bool error = false;
    bool eof = false;

    /* lock access to the monitor and protect fd */
    qemuAgentLock(mon);
    qemuAgentRef(mon);
#if DEBUG_IO
    VIR_DEBUG("Agent %p I/O on watch %d fd %d events %d", mon, watch, fd, events);
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
            if (mon->connectPending) {
                if (qemuAgentIOConnect(mon) < 0)
                    error = true;
            } else {
                if (qemuAgentIOWrite(mon) < 0)
                    error = true;
            }
            events &= ~VIR_EVENT_HANDLE_WRITABLE;
        }

        if (!error &&
            events & VIR_EVENT_HANDLE_READABLE) {
            int got = qemuAgentIORead(mon);
            events &= ~VIR_EVENT_HANDLE_READABLE;
            if (got < 0) {
                error = true;
            } else if (got == 0) {
                eof = true;
            } else {
                /* Ignore hangup/error events if we read some data, to
                 * give time for that data to be consumed */
                events = 0;

                if (qemuAgentIOProcess(mon) < 0)
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

    qemuAgentUpdateWatch(mon);

    /* We have to unlock to avoid deadlock against command thread,
     * but is this safe ?  I think it is, because the callback
     * will try to acquire the virDomainObjPtr mutex next */
    if (eof) {
        void (*eofNotify)(qemuAgentPtr, virDomainObjPtr)
            = mon->cb->eofNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        if (qemuAgentUnref(mon) > 0)
            qemuAgentUnlock(mon);
        VIR_DEBUG("Triggering EOF callback");
        (eofNotify)(mon, vm);
    } else if (error) {
        void (*errorNotify)(qemuAgentPtr, virDomainObjPtr)
            = mon->cb->errorNotify;
        virDomainObjPtr vm = mon->vm;

        /* Make sure anyone waiting wakes up now */
        virCondSignal(&mon->notify);
        if (qemuAgentUnref(mon) > 0)
            qemuAgentUnlock(mon);
        VIR_DEBUG("Triggering error callback");
        (errorNotify)(mon, vm);
    } else {
        if (qemuAgentUnref(mon) > 0)
            qemuAgentUnlock(mon);
    }
}


qemuAgentPtr
qemuAgentOpen(virDomainObjPtr vm,
              virDomainChrSourceDefPtr config,
              qemuAgentCallbacksPtr cb)
{
    qemuAgentPtr mon;

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
    mon->cb = cb;
    qemuAgentLock(mon);

    switch (config->type) {
    case VIR_DOMAIN_CHR_TYPE_UNIX:
        mon->fd = qemuAgentOpenUnix(config->data.nix.path, vm->pid,
                                    &mon->connectPending);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        mon->fd = qemuAgentOpenPty(config->data.file.path);
        break;

    default:
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unable to handle monitor type: %s"),
                        virDomainChrTypeToString(config->type));
        goto cleanup;
    }

    if (mon->fd == -1)
        goto cleanup;

    if ((mon->watch = virEventAddHandle(mon->fd,
                                        VIR_EVENT_HANDLE_HANGUP |
                                        VIR_EVENT_HANDLE_ERROR |
                                        VIR_EVENT_HANDLE_READABLE |
                                        (mon->connectPending ?
                                         VIR_EVENT_HANDLE_WRITABLE :
                                         0),
                                        qemuAgentIO,
                                        mon, qemuAgentUnwatch)) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("unable to register monitor events"));
        goto cleanup;
    }
    qemuAgentRef(mon);

    VIR_DEBUG("New mon %p fd =%d watch=%d", mon, mon->fd, mon->watch);
    qemuAgentUnlock(mon);

    return mon;

cleanup:
    /* We don't want the 'destroy' callback invoked during
     * cleanup from construction failure, because that can
     * give a double-unref on virDomainObjPtr in the caller,
     * so kill the callbacks now.
     */
    mon->cb = NULL;
    qemuAgentUnlock(mon);
    qemuAgentClose(mon);
    return NULL;
}


void qemuAgentClose(qemuAgentPtr mon)
{
    if (!mon)
        return;

    VIR_DEBUG("mon=%p", mon);

    qemuAgentLock(mon);

    if (mon->fd >= 0) {
        if (mon->watch)
            virEventRemoveHandle(mon->watch);
        VIR_FORCE_CLOSE(mon->fd);
    }

    if (qemuAgentUnref(mon) > 0)
        qemuAgentUnlock(mon);
}

#define QEMU_AGENT_WAIT_TIME (1000ull * 5)

/**
 * qemuAgentSend:
 * @mon: Monitor
 * @msg: Message
 * @timeout: use timeout?
 *
 * Send @msg to agent @mon.
 * Wait max QEMU_AGENT_WAIT_TIME for agent
 * to reply.
 *
 * Returns: 0 on success,
 *          -2 on timeout,
 *          -1 otherwise
 */
static int qemuAgentSend(qemuAgentPtr mon,
                         qemuAgentMessagePtr msg,
                         bool timeout)
{
    int ret = -1;
    unsigned long long now, then = 0;

    /* Check whether qemu quit unexpectedly */
    if (mon->lastError.code != VIR_ERR_OK) {
        VIR_DEBUG("Attempt to send command while error is set %s",
                  NULLSTR(mon->lastError.message));
        virSetError(&mon->lastError);
        return -1;
    }

    if (timeout) {
        if (virTimeMillisNow(&now) < 0)
            return -1;
        then = now + QEMU_AGENT_WAIT_TIME;
    }

    mon->msg = msg;
    qemuAgentUpdateWatch(mon);

    while (!mon->msg->finished) {
        if ((timeout && virCondWaitUntil(&mon->notify, &mon->lock, then) < 0) ||
            (!timeout && virCondWait(&mon->notify, &mon->lock) < 0)) {
            if (errno == ETIMEDOUT) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Guest agent not available for now"));
                ret = -2;
            } else {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Unable to wait on monitor condition"));
            }
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
    qemuAgentUpdateWatch(mon);

    return ret;
}


/**
 * qemuAgentGuestSync:
 * @mon: Monitor
 *
 * Send guest-sync with unique ID
 * and wait for reply. If we get one, check if
 * received ID is equal to given.
 *
 * Returns: 0 on success,
 *          -1 otherwise
 */
static int
qemuAgentGuestSync(qemuAgentPtr mon)
{
    int ret = -1;
    int send_ret;
    unsigned long long id, id_ret;
    qemuAgentMessage sync_msg;

    memset(&sync_msg, 0, sizeof(sync_msg));

    if (virTimeMillisNow(&id) < 0)
        return -1;

    if (virAsprintf(&sync_msg.txBuffer,
                    "{\"execute\":\"guest-sync\", "
                    "\"arguments\":{\"id\":%llu}}", id) < 0) {
        virReportOOMError();
        return -1;
    }

    sync_msg.txLength = strlen(sync_msg.txBuffer);

    VIR_DEBUG("Sending guest-sync command with ID: %llu", id);

    send_ret = qemuAgentSend(mon, &sync_msg, true);

    VIR_DEBUG("qemuAgentSend returned: %d", send_ret);

    if (send_ret < 0) {
        /* error reported */
        goto cleanup;
    }

    if (!sync_msg.rxObject) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Missing monitor reply object"));
        goto cleanup;
    }

    if (virJSONValueObjectGetNumberUlong(sync_msg.rxObject,
                                         "return", &id_ret) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Malformed return value"));
        goto cleanup;
    }

    VIR_DEBUG("Guest returned ID: %llu", id_ret);
    if (id_ret != id) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Guest agent returned ID: %llu instead of %llu"),
                        id_ret, id);
        goto cleanup;
    }
    ret = 0;

cleanup:
    virJSONValueFree(sync_msg.rxObject);
    VIR_FREE(sync_msg.txBuffer);
    return ret;
}

static int
qemuAgentCommand(qemuAgentPtr mon,
                 virJSONValuePtr cmd,
                 virJSONValuePtr *reply)
{
    int ret = -1;
    qemuAgentMessage msg;
    char *cmdstr = NULL;

    *reply = NULL;

    if (qemuAgentGuestSync(mon) < 0) {
        /* helper reported the error */
        return -1;
    }

    memset(&msg, 0, sizeof(msg));

    if (!(cmdstr = virJSONValueToString(cmd))) {
        virReportOOMError();
        goto cleanup;
    }
    if (virAsprintf(&msg.txBuffer, "%s" LINE_ENDING, cmdstr) < 0) {
        virReportOOMError();
        goto cleanup;
    }
    msg.txLength = strlen(msg.txBuffer);

    VIR_DEBUG("Send command '%s' for write", cmdstr);

    ret = qemuAgentSend(mon, &msg, false);

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
    VIR_FREE(cmdstr);
    VIR_FREE(msg.txBuffer);

    return ret;
}


/* Ignoring OOM in this method, since we're already reporting
 * a more important error
 *
 * XXX see qerror.h for different klasses & fill out useful params
 */
static const char *
qemuAgentStringifyError(virJSONValuePtr error)
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
qemuAgentCommandName(virJSONValuePtr cmd)
{
    const char *name = virJSONValueObjectGetString(cmd, "execute");
    if (name)
        return name;
    else
        return "<unknown>";
}

static int
qemuAgentCheckError(virJSONValuePtr cmd,
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
                            qemuAgentCommandName(cmd));
        else
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unable to execute QEMU command '%s': %s"),
                            qemuAgentCommandName(cmd),
                            qemuAgentStringifyError(error));

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
                        qemuAgentCommandName(cmd));
        VIR_FREE(cmdstr);
        VIR_FREE(replystr);
        return -1;
    }
    return 0;
}

static virJSONValuePtr ATTRIBUTE_SENTINEL
qemuAgentMakeCommand(const char *cmdname,
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

        /* This doesn't support maps/arrays.  This hasn't
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
        default:
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
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
    virReportOOMError();
error:
    virJSONValueFree(obj);
    virJSONValueFree(jargs);
    va_end(args);
    return NULL;
}

VIR_ENUM_DECL(qemuAgentShutdownMode);

VIR_ENUM_IMPL(qemuAgentShutdownMode,
              QEMU_AGENT_SHUTDOWN_LAST,
              "powerdown", "reboot", "halt");

int qemuAgentShutdown(qemuAgentPtr mon,
                      qemuAgentShutdownMode mode)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-shutdown",
                               "s:mode", qemuAgentShutdownModeTypeToString(mode),
                               NULL);
    if (!cmd)
        return -1;

    ret = qemuAgentCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuAgentCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSFreeze:
 * @mon: Agent
 *
 * Issue guest-fsfreeze-freeze command to guest agent,
 * which freezes all mounted file systems and returns
 * number of frozen file systems on success.
 *
 * Returns: number of file system frozen on success,
 *          -1 on error.
 */
int qemuAgentFSFreeze(qemuAgentPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fsfreeze-freeze", NULL);

    if (!cmd)
        return -1;

    if (qemuAgentCommand(mon, cmd, &reply) < 0 ||
        qemuAgentCheckError(cmd, reply) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("malformed return value"));
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

/*
 * qemuAgentFSThaw:
 * @mon: Agent
 *
 * Issue guest-fsfreeze-thaw command to guest agent,
 * which unfreezes all mounted file systems and returns
 * number of thawed file systems on success.
 *
 * Returns: number of file system thawed on success,
 *          -1 on error.
 */
int qemuAgentFSThaw(qemuAgentPtr mon)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand("guest-fsfreeze-thaw", NULL);

    if (!cmd)
        return -1;

    if (qemuAgentCommand(mon, cmd, &reply) < 0 ||
        qemuAgentCheckError(cmd, reply) < 0)
        goto cleanup;

    if (virJSONValueObjectGetNumberInt(reply, "return", &ret) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("malformed return value"));
    }

cleanup:
    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}

VIR_ENUM_DECL(qemuAgentSuspendMode);

VIR_ENUM_IMPL(qemuAgentSuspendMode,
              VIR_NODE_SUSPEND_TARGET_LAST,
              "guest-suspend-ram",
              "guest-suspend-disk",
              "guest-suspend-hybrid");

int
qemuAgentSuspend(qemuAgentPtr mon,
                 unsigned int target)
{
    int ret = -1;
    virJSONValuePtr cmd;
    virJSONValuePtr reply = NULL;

    cmd = qemuAgentMakeCommand(qemuAgentSuspendModeTypeToString(target),
                               NULL);
    if (!cmd)
        return -1;

    ret = qemuAgentCommand(mon, cmd, &reply);

    if (ret == 0)
        ret = qemuAgentCheckError(cmd, reply);

    virJSONValueFree(cmd);
    virJSONValueFree(reply);
    return ret;
}
