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
#include <sys/socket.h>
#include <sys/wait.h>
#if HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#include <netinet/in.h>
#include <termios.h>

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
#include "virprocess.h"

#define VIR_FROM_THIS VIR_FROM_STREAMS

VIR_LOG_INIT("fdstream");

typedef enum {
    VIR_FDSTREAM_MSG_TYPE_DATA,
    VIR_FDSTREAM_MSG_TYPE_HOLE,
} virFDStreamMsgType;

typedef struct _virFDStreamMsg virFDStreamMsg;
typedef virFDStreamMsg *virFDStreamMsgPtr;
struct _virFDStreamMsg {
    virFDStreamMsgPtr next;

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
typedef virFDStreamData *virFDStreamDataPtr;
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
    virThreadPtr thread;
    virCond threadCond;
    int threadErr;
    bool threadQuit;
    bool threadAbort;
    bool threadDoRead;
    virFDStreamMsgPtr msg;
};

static virClassPtr virFDStreamDataClass;

static void virFDStreamMsgQueueFree(virFDStreamMsgPtr *queue);

static void
virFDStreamDataDispose(void *obj)
{
    virFDStreamDataPtr fdst = obj;

    VIR_DEBUG("obj=%p", fdst);
    virFDStreamMsgQueueFree(&fdst->msg);
}

static int virFDStreamDataOnceInit(void)
{
    if (!(virFDStreamDataClass = virClassNew(virClassForObjectLockable(),
                                             "virFDStreamData",
                                             sizeof(virFDStreamData),
                                             virFDStreamDataDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virFDStreamData)


static int
virFDStreamMsgQueuePush(virFDStreamDataPtr fdst,
                        virFDStreamMsgPtr msg,
                        int fd,
                        const char *fdname)
{
    virFDStreamMsgPtr *tmp = &fdst->msg;
    char c = '1';

    while (*tmp)
        tmp = &(*tmp)->next;

    *tmp = msg;
    virCondSignal(&fdst->threadCond);

    if (safewrite(fd, &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno,
                             _("Unable to write to %s"),
                             fdname);
        return -1;
    }

    return 0;
}


static virFDStreamMsgPtr
virFDStreamMsgQueuePop(virFDStreamDataPtr fdst,
                       int fd,
                       const char *fdname)
{
    virFDStreamMsgPtr tmp = fdst->msg;
    char c;

    if (tmp) {
        fdst->msg = tmp->next;
        tmp->next = NULL;
    }

    virCondSignal(&fdst->threadCond);

    if (saferead(fd, &c, sizeof(c)) != sizeof(c)) {
        virReportSystemError(errno,
                             _("Unable to read from %s"),
                             fdname);
        return NULL;
    }

    return tmp;
}


static void
virFDStreamMsgFree(virFDStreamMsgPtr msg)
{
    if (!msg)
        return;

    switch (msg->type) {
    case VIR_FDSTREAM_MSG_TYPE_DATA:
        VIR_FREE(msg->stream.data.buf);
        break;
    case VIR_FDSTREAM_MSG_TYPE_HOLE:
        /* nada */
        break;
    }

    VIR_FREE(msg);
}


static void
virFDStreamMsgQueueFree(virFDStreamMsgPtr *queue)
{
    virFDStreamMsgPtr tmp = *queue;

    while (tmp) {
        virFDStreamMsgPtr next = tmp->next;
        virFDStreamMsgFree(tmp);
        tmp = next;
    }

    *queue = NULL;
}


static int virFDStreamRemoveCallback(virStreamPtr stream)
{
    virFDStreamDataPtr fdst = stream->privateData;
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
    virFDStreamDataPtr fdst = stream->privateData;
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

static void virFDStreamEvent(int watch ATTRIBUTE_UNUSED,
                             int fd ATTRIBUTE_UNUSED,
                             int events,
                             void *opaque)
{
    virStreamPtr stream = opaque;
    virFDStreamDataPtr fdst = stream->privateData;
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

    if (fdst->threadErr)
        events |= VIR_STREAM_EVENT_ERROR;

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
    virFDStreamDataPtr fdst = st->privateData;
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
typedef virFDStreamThreadData *virFDStreamThreadDataPtr;
struct _virFDStreamThreadData {
    virStreamPtr st;
    size_t length;
    bool doRead;
    bool sparse;
    int fdin;
    char *fdinname;
    int fdout;
    char *fdoutname;
};


static void
virFDStreamThreadDataFree(virFDStreamThreadDataPtr data)
{
    if (!data)
        return;

    virObjectUnref(data->st);
    VIR_FREE(data->fdinname);
    VIR_FREE(data->fdoutname);
    VIR_FREE(data);
}


static ssize_t
virFDStreamThreadDoRead(virFDStreamDataPtr fdst,
                        bool sparse,
                        const int fdin,
                        const int fdout,
                        const char *fdinname,
                        const char *fdoutname,
                        size_t length,
                        size_t total,
                        size_t *dataLen,
                        size_t buflen)
{
    virFDStreamMsgPtr msg = NULL;
    int inData = 0;
    long long sectionLen = 0;
    char *buf = NULL;
    ssize_t got;

    if (sparse && *dataLen == 0) {
        if (virFileInData(fdin, &inData, &sectionLen) < 0)
            goto error;

        if (length &&
            sectionLen > length - total)
            sectionLen = length - total;

        if (inData)
            *dataLen = sectionLen;
    }

    if (length &&
        buflen > length - total)
        buflen = length - total;

    if (VIR_ALLOC(msg) < 0)
        goto error;

    if (sparse && *dataLen == 0) {
        msg->type = VIR_FDSTREAM_MSG_TYPE_HOLE;
        msg->stream.hole.len = sectionLen;
        got = sectionLen;

        /* HACK: The message queue is one directional. So caller
         * cannot make us skip the hole. Do that for them instead. */
        if (sectionLen &&
            lseek(fdin, sectionLen, SEEK_CUR) == (off_t) -1) {
            virReportSystemError(errno,
                                 _("unable to seek in %s"),
                                 fdinname);
            goto error;
        }
    } else {
        if (sparse &&
            buflen > *dataLen)
            buflen = *dataLen;

        if (VIR_ALLOC_N(buf, buflen) < 0)
            goto error;

        if ((got = saferead(fdin, buf, buflen)) < 0) {
            virReportSystemError(errno,
                                 _("Unable to read %s"),
                                 fdinname);
            goto error;
        }

        msg->type = VIR_FDSTREAM_MSG_TYPE_DATA;
        msg->stream.data.buf = buf;
        msg->stream.data.len = got;
        buf = NULL;
        if (sparse)
            *dataLen -= got;
    }

    virFDStreamMsgQueuePush(fdst, msg, fdout, fdoutname);
    msg = NULL;

    return got;

 error:
    VIR_FREE(buf);
    virFDStreamMsgFree(msg);
    return -1;
}


static ssize_t
virFDStreamThreadDoWrite(virFDStreamDataPtr fdst,
                         bool sparse,
                         const int fdin,
                         const int fdout,
                         const char *fdinname,
                         const char *fdoutname)
{
    ssize_t got = 0;
    virFDStreamMsgPtr msg = fdst->msg;
    off_t off;
    bool pop = false;

    switch (msg->type) {
    case VIR_FDSTREAM_MSG_TYPE_DATA:
        got = safewrite(fdout,
                        msg->stream.data.buf + msg->stream.data.offset,
                        msg->stream.data.len - msg->stream.data.offset);
        if (got < 0) {
            virReportSystemError(errno,
                                 _("Unable to write %s"),
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
        off = lseek(fdout, got, SEEK_CUR);
        if (off == (off_t) -1) {
            virReportSystemError(errno,
                                 _("unable to seek in %s"),
                                 fdoutname);
            return -1;
        }

        if (ftruncate(fdout, off) < 0) {
            virReportSystemError(errno,
                                 _("unable to truncate %s"),
                                 fdoutname);
            return -1;
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
    virFDStreamThreadDataPtr data = opaque;
    virStreamPtr st = data->st;
    size_t length = data->length;
    bool sparse = data->sparse;
    int fdin = data->fdin;
    char *fdinname = data->fdinname;
    int fdout = data->fdout;
    char *fdoutname = data->fdoutname;
    virFDStreamDataPtr fdst = st->privateData;
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
            got = virFDStreamThreadDoRead(fdst, sparse,
                                          fdin, fdout,
                                          fdinname, fdoutname,
                                          length, total,
                                          &dataLen, buflen);
        else
            got = virFDStreamThreadDoWrite(fdst, sparse,
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
    if (!virObjectUnref(fdst))
        st->privateData = NULL;
    VIR_FORCE_CLOSE(fdin);
    VIR_FORCE_CLOSE(fdout);
    virFDStreamThreadDataFree(data);
    return;

 error:
    fdst->threadErr = errno;
    goto cleanup;
}


static int
virFDStreamJoinWorker(virFDStreamDataPtr fdst,
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
    virFDStreamDataPtr fdst;
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
    virFDStreamDataPtr fdst = st->privateData;
    virFDStreamMsgPtr msg = NULL;
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
            virReportSystemError(EBADF, "%s",
                                 _("cannot write to stream"));
            goto cleanup;
        }

        if (VIR_ALLOC(msg) < 0 ||
            VIR_ALLOC_N(buf, nbytes) < 0)
            goto cleanup;

        memcpy(buf, bytes, nbytes);
        msg->type = VIR_FDSTREAM_MSG_TYPE_DATA;
        msg->stream.data.buf = buf;
        msg->stream.data.len = nbytes;

        virFDStreamMsgQueuePush(fdst, msg, fdst->fd, "pipe");
        msg = NULL;
        ret = nbytes;
    } else {
     retry:
        ret = write(fdst->fd, bytes, nbytes);
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
    virFDStreamMsgFree(msg);
    return ret;
}


static int virFDStreamRead(virStreamPtr st, char *bytes, size_t nbytes)
{
    virFDStreamDataPtr fdst = st->privateData;
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
        virFDStreamMsgPtr msg = NULL;

        while (!(msg = fdst->msg)) {
            if (fdst->threadQuit || fdst->threadErr) {
                if (nbytes) {
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
    virFDStreamDataPtr fdst = st->privateData;
    virFDStreamMsgPtr msg = NULL;
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
            virReportSystemError(EBADF, "%s",
                                 _("stream is not open"));
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
            if (VIR_ALLOC(msg) < 0)
                goto cleanup;

            msg->type = VIR_FDSTREAM_MSG_TYPE_HOLE;
            msg->stream.hole.len = length;
            virFDStreamMsgQueuePush(fdst, msg, fdst->fd, "pipe");
            msg = NULL;
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
    virFDStreamMsgFree(msg);
    return ret;
}


static int
virFDStreamInData(virStreamPtr st,
                  int *inData,
                  long long *length)
{
    virFDStreamDataPtr fdst = st->privateData;
    int ret = -1;

    virObjectLock(fdst);

    if (fdst->thread) {
        virFDStreamMsgPtr msg;

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
                                   virFDStreamThreadDataPtr threadData,
                                   unsigned long long length)
{
    virFDStreamDataPtr fdst;

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
        if (VIR_ALLOC(fdst->thread) < 0)
            goto error;

        if (virCondInit(&fdst->threadCond) < 0) {
            virReportSystemError(errno, "%s",
                                 _("cannot initialize condition variable"));
            goto error;
        }

        if (virThreadCreate(fdst->thread,
                            true,
                            virFDStreamThread,
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


#if HAVE_SYS_UN_H
int virFDStreamConnectUNIX(virStreamPtr st,
                           const char *path,
                           bool abstract)
{
    struct sockaddr_un sa;
    virTimeBackOffVar timeout;
    int ret;

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        virReportSystemError(errno, "%s", _("Unable to open UNIX socket"));
        goto error;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (abstract) {
        if (virStrcpy(sa.sun_path+1, path, sizeof(sa.sun_path)-1) == NULL)
            goto error;
        sa.sun_path[0] = '\0';
    } else {
        if (virStrcpy(sa.sun_path, path, sizeof(sa.sun_path)) == NULL)
            goto error;
    }

    if (virTimeBackOffStart(&timeout, 1, 3*1000 /* ms */) < 0)
        goto error;
    while (virTimeBackOffWait(&timeout)) {
        ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        goto error;
    }

    if (virFDStreamOpenInternal(st, fd, NULL, 0) < 0)
        goto error;
    return 0;

 error:
    VIR_FORCE_CLOSE(fd);
    return -1;
}
#else
int virFDStreamConnectUNIX(virStreamPtr st ATTRIBUTE_UNUSED,
                           const char *path ATTRIBUTE_UNUSED,
                           bool abstract ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("UNIX domain sockets are not supported on this platform"));
    return -1;
}
#endif

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
    virFDStreamThreadDataPtr threadData = NULL;

    VIR_DEBUG("st=%p path=%s oflags=%x offset=%llu length=%llu mode=%o",
              st, path, oflags, offset, length, mode);

    oflags |= O_NOCTTY | O_BINARY;

    if (oflags & O_CREAT)
        fd = open(path, oflags, mode);
    else
        fd = open(path, oflags);
    if (fd < 0) {
        virReportSystemError(errno,
                             _("Unable to open stream for '%s'"),
                             path);
        return -1;
    }
    tmpfd = fd;

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access stream for '%s'"),
                             path);
        goto error;
    }

    if (offset &&
        lseek(fd, offset, SEEK_SET) < 0) {
        virReportSystemError(errno,
                             _("Unable to seek %s to %llu"),
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
                           _("%s: Cannot request read and write flags together"),
                           path);
            goto error;
        }

        if (pipe(pipefds) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create pipe"));
            goto error;
        }

        if (VIR_ALLOC(threadData) < 0)
            goto error;

        threadData->st = virObjectRef(st);
        threadData->length = length;
        threadData->sparse = sparse;

        if ((oflags & O_ACCMODE) == O_RDONLY) {
            threadData->fdin = fd;
            threadData->fdout = pipefds[1];
            if (VIR_STRDUP(threadData->fdinname, path) < 0 ||
                VIR_STRDUP(threadData->fdoutname, "pipe") < 0)
                goto error;
            tmpfd = pipefds[0];
            threadData->doRead = true;
        } else {
            threadData->fdin = pipefds[0];
            threadData->fdout = fd;
            if (VIR_STRDUP(threadData->fdinname, "pipe") < 0 ||
                VIR_STRDUP(threadData->fdoutname, path) < 0)
                goto error;
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
                       _("Attempt to create %s without specifying mode"),
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

#ifdef HAVE_CFMAKERAW
int virFDStreamOpenPTY(virStreamPtr st,
                       const char *path,
                       unsigned long long offset,
                       unsigned long long length,
                       int oflags)
{
    virFDStreamDataPtr fdst = NULL;
    struct termios rawattr;

    if (virFDStreamOpenFileInternal(st, path,
                                    offset, length,
                                    oflags | O_CREAT, 0,
                                    false, false) < 0)
        return -1;

    fdst = st->privateData;

    if (tcgetattr(fdst->fd, &rawattr) < 0) {
        virReportSystemError(errno,
                             _("unable to get tty attributes: %s"),
                             path);
        goto cleanup;
    }

    cfmakeraw(&rawattr);

    if (tcsetattr(fdst->fd, TCSANOW, &rawattr) < 0) {
        virReportSystemError(errno,
                             _("unable to set tty attributes: %s"),
                             path);
        goto cleanup;
    }

    return 0;

 cleanup:
    virFDStreamClose(st);
    return -1;
}
#else /* !HAVE_CFMAKERAW */
int virFDStreamOpenPTY(virStreamPtr st,
                       const char *path,
                       unsigned long long offset,
                       unsigned long long length,
                       int oflags)
{
    return virFDStreamOpenFileInternal(st, path,
                                       offset, length,
                                       oflags | O_CREAT, 0,
                                       false, false);
}
#endif /* !HAVE_CFMAKERAW */

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
    virFDStreamDataPtr fdst = st->privateData;

    virObjectLock(fdst);

    if (fdst->icbFreeOpaque)
        (fdst->icbFreeOpaque)(fdst->icbOpaque);

    fdst->icbCb = cb;
    fdst->icbOpaque = opaque;
    fdst->icbFreeOpaque = fcb;

    virObjectUnlock(fdst);
    return 0;
}
