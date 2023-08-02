/*
 * virfdstream.c: generic streams impl for file descriptors
 *
 * Copyright (C) 2009-2012, 2014 Red Hat, Inc.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef WIN32
# include <termios.h>
#endif

#include "virfdstream.h"
#include "virerror.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "virutil.h"
#include "virfile.h"
#include "configmake.h"
#include "virstring.h"
#include "virtime.h"
#include "virsocket.h"

#define VIR_FROM_THIS VIR_FROM_STREAMS

VIR_LOG_INIT("fdstream");

#ifndef WIN32
typedef enum {
    VIR_FDSTREAM_MSG_TYPE_DATA,
    VIR_FDSTREAM_MSG_TYPE_HOLE,
} virFDStreamMsgType;

typedef struct _virFDStreamMsg virFDStreamMsg;
struct _virFDStreamMsg {
    virFDStreamMsg *next;

    virFDStreamMsgType type;

    union {
        struct {
            char *buf;
            size_t len;
            size_t offset;
        } data;
        struct {
            long long len;
        } hole;
    } stream;
};


/* Tunnelled migration stream support */
typedef struct virFDStreamData virFDStreamData;
struct virFDStreamData {
    virObjectLockable parent;

    int fd;
    unsigned long long offset;
    unsigned long long length;

    int watch;
    int events;         /* events the stream callback is subscribed for */
    bool cbRemoved;
    bool dispatching;
    bool closed;
    virStreamEventCallback cb;
    void *opaque;
    virFreeCallback ff;

    /* don't call the abort callback more than once */
    bool abortCallbackCalled;
    bool abortCallbackDispatching;

    /* internal callback, as the regular one (from generic streams) gets
     * eaten up by the server stream driver */
    virFDStreamInternalCloseCb icbCb;
    virFDStreamInternalCloseCbFreeOpaque icbFreeOpaque;
    void *icbOpaque;

    /* Thread data */
    virThread *thread;
    virCond threadCond;
    virErrorPtr threadErr;
    bool threadQuit;
    bool threadAbort;
    bool threadDoRead;
    virFDStreamMsg *msg;
};

static virClass *virFDStreamDataClass;
static __thread bool virFDStreamDataDisposed;

static void virFDStreamMsgQueueFree(virFDStreamMsg **queue);

static void
virFDStreamDataDispose(void *obj)
{
    virFDStreamData *fdst = obj;

    VIR_DEBUG("obj=%p", fdst);
    virFDStreamDataDisposed = true;
    virFreeError(fdst->threadErr);
    virFDStreamMsgQueueFree(&fdst->msg);
}

static int virFDStreamDataOnceInit(void)
{
    if (!VIR_CLASS_NEW(virFDStreamData, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virFDStreamData);


static int
virFDStreamMsgQueuePush(virFDStreamData *fdst,
                        virFDStreamMsg **msg,
                        int fd,
                        const char *fdname)
{
    virFDStreamMsg **tmp = &fdst->msg;
    char c = '1';

    while (*tmp)
        tmp = &(*tmp)->next;

    *tmp = g_steal_pointer(msg);
    virCondSignal(&fdst->threadCond);

    if (safewrite(fd, &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno,
                             _("Unable to write to %1$s"),
                             fdname);
        return -1;
    }

    return 0;
}


static virFDStreamMsg *
virFDStreamMsgQueuePop(virFDStreamData *fdst,
                       int fd,
                       const char *fdname)
{
    virFDStreamMsg *tmp = fdst->msg;
    char c;

    if (tmp) {
        fdst->msg = g_steal_pointer(&tmp->next);
    }

    virCondSignal(&fdst->threadCond);

    if (saferead(fd, &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno,
                             _("Unable to read from %1$s"),
                             fdname);
        return NULL;
    }

    return tmp;
}


static void
virFDStreamMsgFree(virFDStreamMsg *msg)
{
    if (!msg)
        return;

    switch (msg->type) {
    case VIR_FDSTREAM_MSG_TYPE_DATA:
        g_free(msg->stream.data.buf);
        break;
    case VIR_FDSTREAM_MSG_TYPE_HOLE:
        /* nada */
        break;
    }

    g_free(msg);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virFDStreamMsg, virFDStreamMsgFree);


static void
virFDStreamMsgQueueFree(virFDStreamMsg **queue)
{
    virFDStreamMsg *tmp = *queue;

    while (tmp) {
        virFDStreamMsg *next = tmp->next;
        virFDStreamMsgFree(tmp);
        tmp = next;
    }

    *queue = NULL;
}


static int virFDStreamRemoveCallback(virStreamPtr stream)
{
    virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virObjectLock(fdst);
    if (fdst->watch == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventRemoveHandle(fdst->watch);
    if (fdst->dispatching)
        fdst->cbRemoved = true;
    else if (fdst->ff)
        (fdst->ff)(fdst->opaque);

    fdst->watch = 0;
    fdst->ff = NULL;
    fdst->cb = NULL;
    fdst->events = 0;
    fdst->opaque = NULL;

    ret = 0;

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}

static int virFDStreamUpdateCallback(virStreamPtr stream, int events)
{
    virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virObjectLock(fdst);
    if (fdst->watch == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventUpdateHandle(fdst->watch, events);
    fdst->events = events;

    ret = 0;

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}

static void virFDStreamEvent(int watch G_GNUC_UNUSED,
                             int fd G_GNUC_UNUSED,
                             int events,
                             void *opaque)
{
    virStreamPtr stream = opaque;
    virFDStreamData *fdst = stream->privateData;
    virStreamEventCallback cb;
    void *cbopaque;
    virFreeCallback ff;
    bool closed;

    if (!fdst)
        return;

    virObjectLock(fdst);
    if (!fdst->cb) {
        virObjectUnlock(fdst);
        return;
    }

    if (fdst->threadErr) {
        events |= VIR_STREAM_EVENT_ERROR;
        virSetError(fdst->threadErr);
    }

    cb = fdst->cb;
    cbopaque = fdst->opaque;
    ff = fdst->ff;
    fdst->dispatching = true;
    virObjectUnlock(fdst);

    cb(stream, events, cbopaque);

    virObjectLock(fdst);
    fdst->dispatching = false;
    if (fdst->cbRemoved && ff)
        (ff)(cbopaque);
    closed = fdst->closed;
    virObjectUnlock(fdst);

    if (closed)
        virObjectUnref(fdst);
}

static void virFDStreamCallbackFree(void *opaque)
{
    virObjectUnref(opaque);
}


static int
virFDStreamAddCallback(virStreamPtr st,
                       int events,
                       virStreamEventCallback cb,
                       void *opaque,
                       virFreeCallback ff)
{
    virFDStreamData *fdst = st->privateData;
    int ret = -1;

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virObjectLock(fdst);
    if (fdst->watch != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream already has a callback registered"));
        goto cleanup;
    }

    if ((fdst->watch = virEventAddHandle(fdst->fd,
                                         events,
                                         virFDStreamEvent,
                                         st,
                                         virFDStreamCallbackFree)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("cannot register file watch on stream"));
        goto cleanup;
    }

    fdst->cbRemoved = false;
    fdst->cb = cb;
    fdst->opaque = opaque;
    fdst->ff = ff;
    fdst->events = events;
    fdst->abortCallbackCalled = false;
    virStreamRef(st);

    ret = 0;

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}


typedef struct _virFDStreamThreadData virFDStreamThreadData;
struct _virFDStreamThreadData {
    virStreamPtr st;
    size_t length;
    bool doRead;
    bool sparse;
    bool isBlock;
    int fdin;
    char *fdinname;
    int fdout;
    char *fdoutname;
};


static void
virFDStreamThreadDataFree(virFDStreamThreadData *data)
{
    if (!data)
        return;

    virObjectUnref(data->st);
    g_free(data->fdinname);
    g_free(data->fdoutname);
    g_free(data);
}


static ssize_t
virFDStreamThreadDoRead(virFDStreamData *fdst,
                        bool sparse,
                        bool isBlock,
                        const int fdin,
                        const int fdout,
                        const char *fdinname,
                        const char *fdoutname,
                        size_t length,
                        size_t total,
                        size_t *dataLen,
                        size_t buflen)
{
    g_autoptr(virFDStreamMsg) msg = NULL;
    int inData = 0;
    long long sectionLen = 0;
    g_autofree char *buf = NULL;
    ssize_t got;

    if (sparse && *dataLen == 0) {
        if (isBlock) {
            /* Block devices are always in data section by definition. The
             * @sectionLen is slightly more tricky. While we could try and get
             * how much bytes is there left until EOF, we can pretend there is
             * always X bytes left and let the saferead() below hit EOF (which
             * is then handled gracefully anyway). Worst case scenario, this
             * branch is called more than once.
             * X was chosen to be 1MiB but it has ho special meaning. */
            inData = 1;
            sectionLen = 1 * 1024 * 1024;
        } else {
            if (virFileInData(fdin, &inData, &sectionLen) < 0)
                return -1;
        }

        if (length &&
            sectionLen > length - total)
            sectionLen = length - total;

        if (inData)
            *dataLen = sectionLen;
    }

    if (length &&
        buflen > length - total)
        buflen = length - total;

    msg = g_new0(virFDStreamMsg, 1);

    if (sparse && *dataLen == 0) {
        msg->type = VIR_FDSTREAM_MSG_TYPE_HOLE;
        msg->stream.hole.len = sectionLen;
        got = sectionLen;

        /* HACK: The message queue is one directional. So caller
         * cannot make us skip the hole. Do that for them instead. */
        if (sectionLen &&
            lseek(fdin, sectionLen, SEEK_CUR) == (off_t) -1) {
            virReportSystemError(errno,
                                 _("unable to seek in %1$s"),
                                 fdinname);
            return -1;
        }
    } else {
        if (sparse &&
            buflen > *dataLen)
            buflen = *dataLen;

        buf = g_new0(char, buflen);

        if ((got = saferead(fdin, buf, buflen)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to read %1$s"),
                                 fdinname);
            return -1;
        }

        msg->type = VIR_FDSTREAM_MSG_TYPE_DATA;
        msg->stream.data.buf = g_steal_pointer(&buf);
        msg->stream.data.len = got;
        if (sparse)
            *dataLen -= got;
    }

    virFDStreamMsgQueuePush(fdst, &msg, fdout, fdoutname);

    return got;
}


static ssize_t
virFDStreamThreadDoWrite(virFDStreamData *fdst,
                         bool sparse,
                         bool isBlock,
                         const int fdin,
                         const int fdout,
                         const char *fdinname,
                         const char *fdoutname)
{
    ssize_t got = 0;
    virFDStreamMsg *msg = fdst->msg;
    bool pop = false;

    switch (msg->type) {
    case VIR_FDSTREAM_MSG_TYPE_DATA:
        got = safewrite(fdout,
                        msg->stream.data.buf + msg->stream.data.offset,
                        msg->stream.data.len - msg->stream.data.offset);
        if (got < 0) {
            virReportSystemError(errno,
                                 _("Unable to write %1$s"),
                                 fdoutname);
            return -1;
        }

        msg->stream.data.offset += got;

        pop = msg->stream.data.offset == msg->stream.data.len;
        break;

    case VIR_FDSTREAM_MSG_TYPE_HOLE:
        if (!sparse) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected stream hole"));
            return -1;
        }

        got = msg->stream.hole.len;
        if (isBlock) {
            g_autofree char * buf = NULL;
            const size_t buflen = 1 * 1024 * 1024; /* 1MiB */
            size_t toWrite = got;

            /* While for files it's enough to lseek() and ftruncate() to create
             * a hole which would emulate zeroes on read(), for block devices
             * we have to write zeroes to read() zeroes. And we have to write
             * @got bytes of zeroes. Do that in smaller chunks though.*/

            buf = g_new0(char, buflen);

            while (toWrite) {
                size_t count = MIN(toWrite, buflen);
                ssize_t r;

                if ((r = safewrite(fdout, buf, count)) < 0) {
                    virReportSystemError(errno,
                                         _("Unable to write %1$s"),
                                         fdoutname);
                    return -1;
                }

                toWrite -= r;
            }
        } else {
            off_t off;

            off = lseek(fdout, got, SEEK_CUR);
            if (off == (off_t) -1) {
                virReportSystemError(errno,
                                     _("unable to seek in %1$s"),
                                     fdoutname);
                return -1;
            }

            if (ftruncate(fdout, off) < 0) {
                virReportSystemError(errno,
                                     _("unable to truncate %1$s"),
                                     fdoutname);
                return -1;
            }
        }

        pop = true;
        break;
    }

    if (pop) {
        virFDStreamMsgQueuePop(fdst, fdin, fdinname);
        virFDStreamMsgFree(msg);
    }

    return got;
}


static void
virFDStreamThread(void *opaque)
{
    virFDStreamThreadData *data = opaque;
    virStreamPtr st = data->st;
    size_t length = data->length;
    bool sparse = data->sparse;
    bool isBlock = data->isBlock;
    VIR_AUTOCLOSE fdin = data->fdin;
    char *fdinname = data->fdinname;
    VIR_AUTOCLOSE fdout = data->fdout;
    char *fdoutname = data->fdoutname;
    virFDStreamData *fdst = st->privateData;
    bool doRead = fdst->threadDoRead;
    size_t buflen = 256 * 1024;
    size_t total = 0;
    size_t dataLen = 0;

    virObjectRef(fdst);
    virObjectLock(fdst);

    while (1) {
        ssize_t got;

        while (doRead == (fdst->msg != NULL) &&
               !fdst->threadQuit) {
            if (virCondWait(&fdst->threadCond, &fdst->parent.lock)) {
                virReportSystemError(errno, "%s",
                                     _("failed to wait on condition"));
                goto error;
            }
        }

        if (fdst->threadQuit) {
            /* If stream abort was requested, quit early. */
            if (fdst->threadAbort)
                goto cleanup;

            /* Otherwise flush buffers and quit gracefully. */
            if (doRead == (fdst->msg != NULL))
                break;
        }

        if (doRead)
            got = virFDStreamThreadDoRead(fdst, sparse, isBlock,
                                          fdin, fdout,
                                          fdinname, fdoutname,
                                          length, total,
                                          &dataLen, buflen);
        else
            got = virFDStreamThreadDoWrite(fdst, sparse, isBlock,
                                           fdin, fdout,
                                           fdinname, fdoutname);

        if (got < 0)
            goto error;

        if (got == 0)
            break;

        total += got;
    }

 cleanup:
    fdst->threadQuit = true;
    virObjectUnlock(fdst);
    virFDStreamDataDisposed = false;
    virObjectUnref(fdst);
    if (virFDStreamDataDisposed)
        st->privateData = NULL;
    virFDStreamThreadDataFree(data);
    return;

 error:
    fdst->threadErr = virSaveLastError();
    goto cleanup;
}


static int
virFDStreamJoinWorker(virFDStreamData *fdst,
                      bool streamAbort)
{
    int ret = -1;
    if (!fdst->thread)
        return 0;

    fdst->threadAbort = streamAbort;
    fdst->threadQuit = true;
    virCondSignal(&fdst->threadCond);

    /* Give the thread a chance to lock the FD stream object. */
    virObjectUnlock(fdst);
    virThreadJoin(fdst->thread);
    virObjectLock(fdst);

    if (fdst->threadErr && !streamAbort) {
        /* errors are expected on streamAbort */
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(fdst->thread);
    virCondDestroy(&fdst->threadCond);
    return ret;
}


static int
virFDStreamCloseInt(virStreamPtr st, bool streamAbort)
{
    virFDStreamData *fdst;
    virStreamEventCallback cb;
    void *opaque;
    int ret;

    VIR_DEBUG("st=%p", st);

    if (!st || !(fdst = st->privateData) || fdst->abortCallbackDispatching)
        return 0;

    virObjectLock(fdst);

    /* aborting the stream, ensure the callback is called if it's
     * registered for stream error event */
    if (streamAbort &&
        fdst->cb &&
        (fdst->events & (VIR_STREAM_EVENT_READABLE |
                         VIR_STREAM_EVENT_WRITABLE))) {
        /* don't enter this function accidentally from the callback again */
        if (fdst->abortCallbackCalled) {
            virObjectUnlock(fdst);
            return 0;
        }

        fdst->abortCallbackCalled = true;
        fdst->abortCallbackDispatching = true;

        /* cache the pointers */
        cb = fdst->cb;
        opaque = fdst->opaque;
        virObjectUnlock(fdst);

        /* call failure callback, poll reports nothing on closed fd */
        (cb)(st, VIR_STREAM_EVENT_ERROR, opaque);

        virObjectLock(fdst);
        fdst->abortCallbackDispatching = false;
    }

    if (virFDStreamJoinWorker(fdst, streamAbort) < 0)
        ret = -1;

    /* mutex locked */
    if ((ret = VIR_CLOSE(fdst->fd)) < 0)
        virReportSystemError(errno, "%s",
                             _("Unable to close"));

    st->privateData = NULL;

    /* call the internal stream closing callback */
    if (fdst->icbCb) {
        /* the mutex is not accessible anymore, as private data is null */
        (fdst->icbCb)(st, fdst->icbOpaque);
        if (fdst->icbFreeOpaque)
            (fdst->icbFreeOpaque)(fdst->icbOpaque);
    }

    if (fdst->dispatching) {
        fdst->closed = true;
        virObjectUnlock(fdst);
    } else {
        virObjectUnlock(fdst);
        virObjectUnref(fdst);
    }

    return ret;
}

static int
virFDStreamClose(virStreamPtr st)
{
    return virFDStreamCloseInt(st, false);
}

static int
virFDStreamAbort(virStreamPtr st)
{
    return virFDStreamCloseInt(st, true);
}

static int virFDStreamWrite(virStreamPtr st, const char *bytes, size_t nbytes)
{
    virFDStreamData *fdst = st->privateData;
    g_autoptr(virFDStreamMsg) msg = NULL;
    int ret = -1;

    if (nbytes > INT_MAX) {
        virReportSystemError(ERANGE, "%s",
                             _("Too many bytes to write to stream"));
        return -1;
    }

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virObjectLock(fdst);

    if (fdst->length) {
        if (fdst->length == fdst->offset) {
            virReportSystemError(ENOSPC, "%s",
                                 _("cannot write to stream"));
            virObjectUnlock(fdst);
            return -1;
        }

        if ((fdst->length - fdst->offset) < nbytes)
            nbytes = fdst->length - fdst->offset;
    }

    if (fdst->thread) {
        char *buf;

        if (fdst->threadQuit || fdst->threadErr) {

            /* virStreamSend will virResetLastError possibly set
             * by virFDStreamEvent */
            if (fdst->threadErr && !virGetLastError())
                virSetError(fdst->threadErr);
            else
                virReportSystemError(EBADF, "%s", _("cannot write to stream"));
            goto cleanup;
        }

        msg = g_new0(virFDStreamMsg, 1);
        buf = g_new0(char, nbytes);

        memcpy(buf, bytes, nbytes);
        msg->type = VIR_FDSTREAM_MSG_TYPE_DATA;
        msg->stream.data.buf = buf;
        msg->stream.data.len = nbytes;

        virFDStreamMsgQueuePush(fdst, &msg, fdst->fd, "pipe");
        ret = nbytes;
    } else {
     retry:
        ret = write(fdst->fd, bytes, nbytes); /* sc_avoid_write */
        if (ret < 0) {
            VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
            VIR_WARNINGS_RESET
                ret = -2;
            } else if (errno == EINTR) {
                goto retry;
            } else {
                ret = -1;
                virReportSystemError(errno, "%s",
                                     _("cannot write to stream"));
            }
        }
    }

    if (fdst->length)
        fdst->offset += ret;

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}


static int virFDStreamRead(virStreamPtr st, char *bytes, size_t nbytes)
{
    virFDStreamData *fdst = st->privateData;
    int ret = -1;

    if (nbytes > INT_MAX) {
        virReportSystemError(ERANGE, "%s",
                             _("Too many bytes to read from stream"));
        return -1;
    }

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virObjectLock(fdst);

    if (fdst->length) {
        if (fdst->length == fdst->offset) {
            virObjectUnlock(fdst);
            return 0;
        }

        if ((fdst->length - fdst->offset) < nbytes)
            nbytes = fdst->length - fdst->offset;
    }

    if (fdst->thread) {
        virFDStreamMsg *msg = NULL;

        while (!(msg = fdst->msg)) {
            if (fdst->threadQuit || fdst->threadErr) {
                if (nbytes) {
                    /* virStreamRecv will virResetLastError possibly set
                     * by virFDStreamEvent */
                    if (fdst->threadErr && !virGetLastError())
                        virSetError(fdst->threadErr);
                    else
                        virReportSystemError(EBADF, "%s",
                                             _("stream is not open"));
                } else {
                    ret = 0;
                }
                goto cleanup;
            } else {
                virObjectUnlock(fdst);
                virCondSignal(&fdst->threadCond);
                virObjectLock(fdst);
            }
        }

        /* Shortcut, if the stream is in the trailing hole,
         * return 0 immediately. */
        if (msg->type == VIR_FDSTREAM_MSG_TYPE_HOLE &&
            msg->stream.hole.len == 0) {
            ret = 0;
            goto cleanup;
        }

        if (msg->type != VIR_FDSTREAM_MSG_TYPE_DATA) {
            /* Nope, nope, I'm outta here */
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected message type"));
            goto cleanup;
        }

        if (nbytes > msg->stream.data.len - msg->stream.data.offset)
            nbytes = msg->stream.data.len - msg->stream.data.offset;

        memcpy(bytes,
               msg->stream.data.buf + msg->stream.data.offset,
               nbytes);

        msg->stream.data.offset += nbytes;
        if (msg->stream.data.offset == msg->stream.data.len) {
            virFDStreamMsgQueuePop(fdst, fdst->fd, "pipe");
            virFDStreamMsgFree(msg);
        }

        ret = nbytes;

    } else {
     retry:
        ret = read(fdst->fd, bytes, nbytes);
        if (ret < 0) {
            VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
            VIR_WARNINGS_RESET
                ret = -2;
            } else if (errno == EINTR) {
                goto retry;
            } else {
                ret = -1;
                virReportSystemError(errno, "%s",
                                     _("cannot read from stream"));
            }
            goto cleanup;
        }
    }

    if (fdst->length)
        fdst->offset += ret;

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}


static int
virFDStreamSendHole(virStreamPtr st,
                    long long length,
                    unsigned int flags)
{
    virFDStreamData *fdst = st->privateData;
    g_autoptr(virFDStreamMsg) msg = NULL;
    off_t off;
    int ret = -1;

    virCheckFlags(0, -1);
    virCheckPositiveArgReturn(length, -1);

    virObjectLock(fdst);
    if (fdst->length) {
        if (length > fdst->length - fdst->offset)
            length = fdst->length - fdst->offset;
        fdst->offset += length;
    }

    if (fdst->thread) {
        /* Things are a bit complicated here. If FDStream is in a
         * read mode, then if the message at the queue head is
         * HOLE, just pop it. The thread has lseek()-ed anyway.
         * However, if the FDStream is in write mode, then tell
         * the thread to do the lseek() for us. Under no
         * circumstances we can do the lseek() ourselves here. We
         * might mess up file position for the thread. */

        if (fdst->threadQuit || fdst->threadErr) {
            /* virStreamSendHole will virResetLastError possibly set
             * by virFDStreamEvent */
            if (fdst->threadErr && !virGetLastError())
                virSetError(fdst->threadErr);
            else
                virReportSystemError(EBADF, "%s", _("stream is not open"));
            goto cleanup;
        }

        if (fdst->threadDoRead) {
            msg = fdst->msg;
            if (msg->type != VIR_FDSTREAM_MSG_TYPE_HOLE) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Invalid stream hole"));
                goto cleanup;
            }

            virFDStreamMsgQueuePop(fdst, fdst->fd, "pipe");
        } else {
            msg = g_new0(virFDStreamMsg, 1);

            msg->type = VIR_FDSTREAM_MSG_TYPE_HOLE;
            msg->stream.hole.len = length;
            virFDStreamMsgQueuePush(fdst, &msg, fdst->fd, "pipe");
        }
    } else {
        off = lseek(fdst->fd, length, SEEK_CUR);
        if (off == (off_t) -1) {
            virReportSystemError(errno, "%s",
                                 _("unable to seek"));
            goto cleanup;
        }

        if (ftruncate(fdst->fd, off) < 0) {
            virReportSystemError(errno, "%s",
                                 _("unable to truncate"));
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    virObjectUnlock(fdst);
    return ret;
}


static int
virFDStreamInData(virStreamPtr st,
                  int *inData,
                  long long *length)
{
    virFDStreamData *fdst = st->privateData;
    int ret = -1;

    virObjectLock(fdst);

    if (fdst->thread) {
        virFDStreamMsg *msg;

        if (fdst->threadErr)
            goto cleanup;

        while (!(msg = fdst->msg)) {
            if (fdst->threadQuit) {
                *inData = *length = 0;
                ret = 0;
                goto cleanup;
            } else {
                virObjectUnlock(fdst);
                virCondSignal(&fdst->threadCond);
                virObjectLock(fdst);
            }
        }

        if (msg->type == VIR_FDSTREAM_MSG_TYPE_DATA) {
            *inData = 1;
            *length = msg->stream.data.len - msg->stream.data.offset;
        } else {
            *inData = 0;
            *length = msg->stream.hole.len;
        }
        ret = 0;
    } else {
        ret = virFileInData(fdst->fd, inData, length);
    }

 cleanup:
    virObjectUnlock(fdst);
    return ret;
}


static virStreamDriver virFDStreamDrv = {
    .streamSend = virFDStreamWrite,
    .streamRecv = virFDStreamRead,
    .streamFinish = virFDStreamClose,
    .streamAbort = virFDStreamAbort,
    .streamSendHole = virFDStreamSendHole,
    .streamInData = virFDStreamInData,
    .streamEventAddCallback = virFDStreamAddCallback,
    .streamEventUpdateCallback = virFDStreamUpdateCallback,
    .streamEventRemoveCallback = virFDStreamRemoveCallback
};

static int virFDStreamOpenInternal(virStreamPtr st,
                                   int fd,
                                   virFDStreamThreadData *threadData,
                                   unsigned long long length)
{
    virFDStreamData *fdst;

    VIR_DEBUG("st=%p fd=%d threadData=%p length=%llu",
              st, fd, threadData, length);

    if (virFDStreamDataInitialize() < 0)
        return -1;

    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        virSetNonBlock(fd) < 0) {
        virReportSystemError(errno, "%s", _("Unable to set non-blocking mode"));
        return -1;
    }

    if (!(fdst = virObjectLockableNew(virFDStreamDataClass)))
        return -1;

    fdst->fd = fd;
    fdst->length = length;

    st->driver = &virFDStreamDrv;
    st->privateData = fdst;

    if (threadData) {
        fdst->threadDoRead = threadData->doRead;

        /* Create the thread after fdst and st were initialized.
         * The thread worker expects them to be that way. */
        fdst->thread = g_new0(virThread, 1);

        if (virCondInit(&fdst->threadCond) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot initialize condition variable"));
            goto error;
        }

        if (virThreadCreateFull(fdst->thread,
                                true,
                                virFDStreamThread,
                                "fd-stream",
                                false,
                                threadData) < 0)
            goto error;
    }

    return 0;

 error:
    VIR_FREE(fdst->thread);
    st->driver = NULL;
    st->privateData = NULL;
    virObjectUnref(fdst);
    return -1;
}


int virFDStreamOpen(virStreamPtr st,
                    int fd)
{
    return virFDStreamOpenInternal(st, fd, NULL, 0);
}


int virFDStreamConnectUNIX(virStreamPtr st,
                           const char *path,
                           bool abstract)
{
    struct sockaddr_un sa = { 0 };
    virTimeBackOffVar timeout;
    VIR_AUTOCLOSE fd = -1;
    int ret;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        virReportSystemError(errno, "%s", _("Unable to open UNIX socket"));
        return -1;
    }

    sa.sun_family = AF_UNIX;
    if (abstract) {
        if (virStrcpy(sa.sun_path+1, path, sizeof(sa.sun_path)-1) < 0)
            return -1;
        sa.sun_path[0] = '\0';
    } else {
        if (virStrcpyStatic(sa.sun_path, path) < 0)
            return -1;
    }

    if (virTimeBackOffStart(&timeout, 1, 3*1000 /* ms */) < 0)
        return -1;
    while (virTimeBackOffWait(&timeout)) {
        ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        return -1;
    }

    if (virFDStreamOpenInternal(st, fd, NULL, 0) < 0)
        return -1;
    fd = -1;

    return 0;
}


static int
virFDStreamOpenFileInternal(virStreamPtr st,
                            const char *path,
                            unsigned long long offset,
                            unsigned long long length,
                            int oflags,
                            int mode,
                            bool forceIOHelper,
                            bool sparse)
{
    int fd = -1;
    int pipefds[2] = { -1, -1 };
    int tmpfd = -1;
    struct stat sb;
    virFDStreamThreadData *threadData = NULL;

    VIR_DEBUG("st=%p path=%s oflags=0x%x offset=%llu length=%llu mode=0%o",
              st, path, oflags, offset, length, mode);

    oflags |= O_NOCTTY;

    if (oflags & O_CREAT)
        fd = open(path, oflags, mode);
    else
        fd = open(path, oflags);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("Unable to open stream for '%1$s'"),
                             path);
        return -1;
    }
    tmpfd = fd;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access stream for '%1$s'"),
                             path);
        goto error;
    }

    if (offset &&
        lseek(fd, offset, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Unable to seek %1$s to %2$llu"),
                             path, offset);
        goto error;
    }

    /* Thanks to the POSIX i/o model, we can't reliably get
     * non-blocking I/O on block devs/regular files. To
     * support those we need to create a helper thread to do
     * the I/O so we just have a fifo. Or use AIO :-(
     */
    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        ((!S_ISCHR(sb.st_mode) &&
          !S_ISFIFO(sb.st_mode)) || forceIOHelper)) {

        if ((oflags & O_ACCMODE) == O_RDWR) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%1$s: Cannot request read and write flags together"),
                           path);
            goto error;
        }

        if (virPipe(pipefds) < 0)
            goto error;

        threadData = g_new0(virFDStreamThreadData, 1);

        threadData->st = virObjectRef(st);
        threadData->length = length;
        threadData->sparse = sparse;
        threadData->isBlock = !!S_ISBLK(sb.st_mode);

        if ((oflags & O_ACCMODE) == O_RDONLY) {
            threadData->fdin = fd;
            threadData->fdout = pipefds[1];
            threadData->fdinname = g_strdup(path);
            threadData->fdoutname = g_strdup("pipe");
            tmpfd = pipefds[0];
            threadData->doRead = true;
        } else {
            threadData->fdin = pipefds[0];
            threadData->fdout = fd;
            threadData->fdinname = g_strdup("pipe");
            threadData->fdoutname = g_strdup(path);
            tmpfd = pipefds[1];
            threadData->doRead = false;
        }
    }

    if (virFDStreamOpenInternal(st, tmpfd, threadData, length) < 0)
        goto error;

    return 0;

 error:
    VIR_FORCE_CLOSE(fd);
    VIR_FORCE_CLOSE(pipefds[0]);
    VIR_FORCE_CLOSE(pipefds[1]);
    if (oflags & O_CREAT)
        unlink(path);
    virFDStreamThreadDataFree(threadData);
    return -1;
}

int virFDStreamOpenFile(virStreamPtr st,
                        const char *path,
                        unsigned long long offset,
                        unsigned long long length,
                        int oflags)
{
    if (oflags & O_CREAT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Attempt to create %1$s without specifying mode"),
                       path);
        return -1;
    }
    return virFDStreamOpenFileInternal(st, path,
                                       offset, length,
                                       oflags, 0, false, false);
}

int virFDStreamCreateFile(virStreamPtr st,
                          const char *path,
                          unsigned long long offset,
                          unsigned long long length,
                          int oflags,
                          mode_t mode)
{
    return virFDStreamOpenFileInternal(st, path,
                                       offset, length,
                                       oflags | O_CREAT, mode,
                                       false, false);
}

int virFDStreamOpenPTY(virStreamPtr st,
                       const char *path,
                       unsigned long long offset,
                       unsigned long long length,
                       int oflags)
{
    virFDStreamData *fdst = NULL;
    struct termios rawattr;

    if (virFDStreamOpenFileInternal(st, path,
                                    offset, length,
                                    oflags | O_CREAT, 0,
                                    false, false) < 0)
        return -1;

    fdst = st->privateData;

    if (tcgetattr(fdst->fd, &rawattr) < 0) {
        virReportSystemError(errno,
                             _("unable to get tty attributes: %1$s"),
                             path);
        goto cleanup;
    }

    cfmakeraw(&rawattr);

    if (tcsetattr(fdst->fd, TCSANOW, &rawattr) < 0) {
        virReportSystemError(errno,
                             _("unable to set tty attributes: %1$s"),
                             path);
        goto cleanup;
    }

    return 0;

 cleanup:
    virFDStreamClose(st);
    return -1;
}

int virFDStreamOpenBlockDevice(virStreamPtr st,
                               const char *path,
                               unsigned long long offset,
                               unsigned long long length,
                               bool sparse,
                               int oflags)
{
    return virFDStreamOpenFileInternal(st, path,
                                       offset, length,
                                       oflags, 0, true, sparse);
}

int virFDStreamSetInternalCloseCb(virStreamPtr st,
                                  virFDStreamInternalCloseCb cb,
                                  void *opaque,
                                  virFDStreamInternalCloseCbFreeOpaque fcb)
{
    virFDStreamData *fdst = st->privateData;

    virObjectLock(fdst);

    if (fdst->icbFreeOpaque)
        (fdst->icbFreeOpaque)(fdst->icbOpaque);

    fdst->icbCb = cb;
    fdst->icbOpaque = opaque;
    fdst->icbFreeOpaque = fcb;

    virObjectUnlock(fdst);
    return 0;
}

#else /* WIN32 */

int
virFDStreamOpen(virStreamPtr st G_GNUC_UNUSED,
                int fd G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamConnectUNIX(virStreamPtr st G_GNUC_UNUSED,
                       const char *path G_GNUC_UNUSED,
                       bool abstract G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamOpenFile(virStreamPtr st G_GNUC_UNUSED,
                    const char *path G_GNUC_UNUSED,
                    unsigned long long offset G_GNUC_UNUSED,
                    unsigned long long length G_GNUC_UNUSED,
                    int oflags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamCreateFile(virStreamPtr st G_GNUC_UNUSED,
                      const char *path G_GNUC_UNUSED,
                      unsigned long long offset G_GNUC_UNUSED,
                      unsigned long long length G_GNUC_UNUSED,
                      int oflags G_GNUC_UNUSED,
                      mode_t mode G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamOpenPTY(virStreamPtr st G_GNUC_UNUSED,
                   const char *path G_GNUC_UNUSED,
                   unsigned long long offset G_GNUC_UNUSED,
                   unsigned long long length G_GNUC_UNUSED,
                   int oflags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamOpenBlockDevice(virStreamPtr st G_GNUC_UNUSED,
                           const char *path G_GNUC_UNUSED,
                           unsigned long long offset G_GNUC_UNUSED,
                           unsigned long long length G_GNUC_UNUSED,
                           bool sparse G_GNUC_UNUSED,
                           int oflags G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}


int
virFDStreamSetInternalCloseCb(virStreamPtr st G_GNUC_UNUSED,
                              virFDStreamInternalCloseCb cb G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED,
                              virFDStreamInternalCloseCbFreeOpaque fcb G_GNUC_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("File streams are not supported on this platform"));
    return -1;
}

#endif /* WIN32 */
