/*
 * fdstream.h: generic streams impl for file descriptors
 *
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#if HAVE_SYS_UN_H
# include <sys/un.h>
#endif
#include <netinet/in.h>

#include "fdstream.h"
#include "virterror_internal.h"
#include "datatypes.h"
#include "memory.h"
#include "event.h"
#include "util.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_STREAMS
#define streamsReportError(code, ...)                                \
    virReportErrorHelper(NULL, VIR_FROM_THIS, code, __FILE__,        \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

/* Tunnelled migration stream support */
struct virFDStreamData {
    int fd;

    int watch;
    unsigned int cbRemoved;
    unsigned int dispatching;
    virStreamEventCallback cb;
    void *opaque;
    virFreeCallback ff;

    virMutex lock;
};

static int virFDStreamRemoveCallback(virStreamPtr stream)
{
    struct virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
    if (fdst->watch == 0) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventRemoveHandle(fdst->watch);
    if (fdst->dispatching)
        fdst->cbRemoved = 1;
    else if (fdst->ff)
        (fdst->ff)(fdst->opaque);

    fdst->watch = 0;
    fdst->ff = NULL;
    fdst->cb = NULL;
    fdst->opaque = NULL;

    ret = 0;

cleanup:
    virMutexUnlock(&fdst->lock);
    return ret;
}

static int virFDStreamUpdateCallback(virStreamPtr stream, int events)
{
    struct virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
    if (fdst->watch == 0) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventUpdateHandle(fdst->watch, events);

    ret = 0;

cleanup:
    virMutexUnlock(&fdst->lock);
    return ret;
}

static void virFDStreamEvent(int watch ATTRIBUTE_UNUSED,
                             int fd ATTRIBUTE_UNUSED,
                             int events,
                             void *opaque)
{
    virStreamPtr stream = opaque;
    struct virFDStreamData *fdst = stream->privateData;
    virStreamEventCallback cb;
    void *cbopaque;
    virFreeCallback ff;

    if (!fdst)
        return;

    virMutexLock(&fdst->lock);
    if (!fdst->cb) {
        virMutexUnlock(&fdst->lock);
        return;
    }

    cb = fdst->cb;
    cbopaque = fdst->opaque;
    ff = fdst->ff;
    fdst->dispatching = 1;
    virMutexUnlock(&fdst->lock);

    cb(stream, events, cbopaque);

    virMutexLock(&fdst->lock);
    fdst->dispatching = 0;
    if (fdst->cbRemoved && ff)
        (ff)(cbopaque);
    virMutexUnlock(&fdst->lock);
}

static int
virFDStreamAddCallback(virStreamPtr st,
                       int events,
                       virStreamEventCallback cb,
                       void *opaque,
                       virFreeCallback ff)
{
    struct virFDStreamData *fdst = st->privateData;
    int ret = -1;

    if (!fdst) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
    if (fdst->watch != 0) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream already has a callback registered"));
        goto cleanup;
    }

    if ((fdst->watch = virEventAddHandle(fdst->fd,
                                           events,
                                           virFDStreamEvent,
                                           st,
                                           NULL)) < 0) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("cannot register file watch on stream"));
        goto cleanup;
    }

    fdst->cbRemoved = 0;
    fdst->cb = cb;
    fdst->opaque = opaque;
    fdst->ff = ff;
    virStreamRef(st);

    ret = 0;

cleanup:
    virMutexUnlock(&fdst->lock);
    return ret;
}

static int virFDStreamFree(struct virFDStreamData *fdst)
{
    int ret;
    ret = VIR_CLOSE(fdst->fd);
    VIR_FREE(fdst);
    return ret;
}


static int
virFDStreamClose(virStreamPtr st)
{
    struct virFDStreamData *fdst = st->privateData;
    int ret;

    if (!fdst)
        return 0;

    virMutexLock(&fdst->lock);

    ret = virFDStreamFree(fdst);

    st->privateData = NULL;

    virMutexUnlock(&fdst->lock);

    return ret;
}

static int virFDStreamWrite(virStreamPtr st, const char *bytes, size_t nbytes)
{
    struct virFDStreamData *fdst = st->privateData;
    int ret;

    if (nbytes > INT_MAX) {
        virReportSystemError(ERANGE, "%s",
                             _("Too many bytes to write to stream"));
        return -1;
    }

    if (!fdst) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);

retry:
    ret = write(fdst->fd, bytes, nbytes);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ret = -2;
        } else if (errno == EINTR) {
            goto retry;
        } else {
            ret = -1;
            virReportSystemError(errno, "%s",
                                 _("cannot write to stream"));
        }
    }

    virMutexUnlock(&fdst->lock);
    return ret;
}


static int virFDStreamRead(virStreamPtr st, char *bytes, size_t nbytes)
{
    struct virFDStreamData *fdst = st->privateData;
    int ret;

    if (nbytes > INT_MAX) {
        virReportSystemError(ERANGE, "%s",
                             _("Too many bytes to read from stream"));
        return -1;
    }

    if (!fdst) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);

retry:
    ret = read(fdst->fd, bytes, nbytes);
    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            ret = -2;
        } else if (errno == EINTR) {
            goto retry;
        } else {
            ret = -1;
            virReportSystemError(errno, "%s",
                                 _("cannot read from stream"));
        }
    }

    virMutexUnlock(&fdst->lock);
    return ret;
}


static virStreamDriver virFDStreamDrv = {
    .streamSend = virFDStreamWrite,
    .streamRecv = virFDStreamRead,
    .streamFinish = virFDStreamClose,
    .streamAbort = virFDStreamClose,
    .streamAddCallback = virFDStreamAddCallback,
    .streamUpdateCallback = virFDStreamUpdateCallback,
    .streamRemoveCallback = virFDStreamRemoveCallback
};

int virFDStreamOpen(virStreamPtr st,
                    int fd)
{
    struct virFDStreamData *fdst;

    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        virSetNonBlock(fd) < 0)
        return -1;

    if (VIR_ALLOC(fdst) < 0) {
        virReportOOMError();
        return -1;
    }

    fdst->fd = fd;
    if (virMutexInit(&fdst->lock) < 0) {
        VIR_FREE(fdst);
        streamsReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to initialize mutex"));
        return -1;
    }

    st->driver = &virFDStreamDrv;
    st->privateData = fdst;

    return 0;
}


#if HAVE_SYS_UN_H
int virFDStreamConnectUNIX(virStreamPtr st,
                           const char *path,
                           bool abstract)
{
    struct sockaddr_un sa;
    int i = 0;
    int timeout = 3;
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

    do {
        ret = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if (ret == 0)
            break;

        if (errno == ENOENT || errno == ECONNREFUSED) {
            /* ENOENT       : Socket may not have shown up yet
             * ECONNREFUSED : Leftover socket hasn't been removed yet */
            continue;
        }

        goto error;
    } while ((++i <= timeout*5) && (usleep(.2 * 1000000) <= 0));

    if (virFDStreamOpen(st, fd) < 0)
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

int virFDStreamOpenFile(virStreamPtr st,
                        const char *path,
                        int flags)
{
    int fd;
    struct stat sb;

    if (flags & O_CREAT) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unexpected O_CREAT flag when opening existing file"));
    }

    if ((fd  = open(path, flags)) < 0) {
        virReportSystemError(errno,
                             _("Unable to open stream for '%s'"),
                             path);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access stream for '%s'"),
                             path);
        goto error;
    }

    /* Thanks to the POSIX i/o model, we can't reliably get
     * non-blocking I/O on block devs/regular files. To
     * support those we need to fork a helper process todo
     * the I/O so we just have a fifo. Or use AIO :-(
     */
    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        (!S_ISCHR(sb.st_mode) &&
         !S_ISFIFO(sb.st_mode))) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Non-blocking I/O is not supported on %s"),
                           path);
        goto error;
    }

    if (virFDStreamOpen(st, fd) < 0)
        goto error;

    return 0;

error:
    close(fd);
    return -1;
}

int virFDStreamCreateFile(virStreamPtr st,
                          const char *path,
                          int flags,
                          mode_t mode)
{
    int fd = open(path, flags, mode);
    struct stat sb;

    if (fd < 0) {
        virReportSystemError(errno,
                             _("Unable to open stream for '%s'"),
                             path);
        return -1;
    }

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access stream for '%s'"),
                             path);
        goto error;
    }

    /* Thanks to the POSIX i/o model, we can't reliably get
     * non-blocking I/O on block devs/regular files. To
     * support those we need to fork a helper process todo
     * the I/O so we just have a fifo. Or use AIO :-(
     */
    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        (!S_ISCHR(sb.st_mode) &&
         !S_ISFIFO(sb.st_mode))) {
        streamsReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Non-blocking I/O is not supported on %s"),
                           path);
        goto error;
    }

    if (virFDStreamOpen(st, fd) < 0)
        goto error;

    return 0;

error:
    close(fd);
    return -1;
}
