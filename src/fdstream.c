/*
 * fdstream.c: generic streams impl for file descriptors
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

#include "fdstream.h"
#include "virerror.h"
#include "datatypes.h"
#include "virlog.h"
#include "viralloc.h"
#include "virutil.h"
#include "virfile.h"
#include "configmake.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_STREAMS

VIR_LOG_INIT("fdstream");

/* Tunnelled migration stream support */
struct virFDStreamData {
    int fd;
    int errfd;
    virCommandPtr cmd;
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

    virMutex lock;
};


static const char *iohelper_path = LIBEXECDIR "/libvirt_iohelper";

void virFDStreamSetIOHelper(const char *path)
{
    if (path == NULL)
        iohelper_path = LIBEXECDIR "/libvirt_iohelper";
    else
        iohelper_path = path;
}


static int virFDStreamRemoveCallback(virStreamPtr stream)
{
    struct virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
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
    virMutexUnlock(&fdst->lock);
    return ret;
}

static int virFDStreamUpdateCallback(virStreamPtr stream, int events)
{
    struct virFDStreamData *fdst = stream->privateData;
    int ret = -1;

    if (!fdst) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
    if (fdst->watch == 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream does not have a callback registered"));
        goto cleanup;
    }

    virEventUpdateHandle(fdst->watch, events);
    fdst->events = events;

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
    bool closed;

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
    fdst->dispatching = true;
    virMutexUnlock(&fdst->lock);

    cb(stream, events, cbopaque);

    virMutexLock(&fdst->lock);
    fdst->dispatching = false;
    if (fdst->cbRemoved && ff)
        (ff)(cbopaque);
    closed = fdst->closed;
    virMutexUnlock(&fdst->lock);

    if (closed) {
        virMutexDestroy(&fdst->lock);
        VIR_FREE(fdst);
    }
}

static void virFDStreamCallbackFree(void *opaque)
{
    virStreamPtr st = opaque;
    virStreamFree(st);
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);
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
    virMutexUnlock(&fdst->lock);
    return ret;
}


static int
virFDStreamCloseInt(virStreamPtr st, bool streamAbort)
{
    struct virFDStreamData *fdst;
    virStreamEventCallback cb;
    void *opaque;
    int ret;

    VIR_DEBUG("st=%p", st);

    if (!st || !(fdst = st->privateData) || fdst->abortCallbackDispatching)
        return 0;

    virMutexLock(&fdst->lock);

    /* aborting the stream, ensure the callback is called if it's
     * registered for stream error event */
    if (streamAbort &&
        fdst->cb &&
        (fdst->events & (VIR_STREAM_EVENT_READABLE |
                         VIR_STREAM_EVENT_WRITABLE))) {
        /* don't enter this function accidentally from the callback again */
        if (fdst->abortCallbackCalled) {
            virMutexUnlock(&fdst->lock);
            return 0;
        }

        fdst->abortCallbackCalled = true;
        fdst->abortCallbackDispatching = true;

        /* cache the pointers */
        cb = fdst->cb;
        opaque = fdst->opaque;
        virMutexUnlock(&fdst->lock);

        /* call failure callback, poll reports nothing on closed fd */
        (cb)(st, VIR_STREAM_EVENT_ERROR, opaque);

        virMutexLock(&fdst->lock);
        fdst->abortCallbackDispatching = false;
    }

    /* mutex locked */
    ret = VIR_CLOSE(fdst->fd);
    if (fdst->cmd) {
        char buf[1024];
        ssize_t len;
        int status;
        if ((len = saferead(fdst->errfd, buf, sizeof(buf)-1)) < 0)
            buf[0] = '\0';
        else
            buf[len] = '\0';

        virCommandRawStatus(fdst->cmd);
        if (virCommandWait(fdst->cmd, &status) < 0) {
            ret = -1;
        } else if (status != 0) {
            if (buf[0] == '\0') {
                if (WIFEXITED(status)) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("I/O helper exited with status %d"),
                                   WEXITSTATUS(status));
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("I/O helper exited abnormally"));
                }
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               buf);
            }
            ret = -1;
        }
        virCommandFree(fdst->cmd);
        fdst->cmd = NULL;
    }

    if (VIR_CLOSE(fdst->errfd) < 0)
        VIR_DEBUG("ignoring failed close on fd %d", fdst->errfd);

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
        virMutexUnlock(&fdst->lock);
    } else {
        virMutexUnlock(&fdst->lock);
        virMutexDestroy(&fdst->lock);
        VIR_FREE(fdst);
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
    struct virFDStreamData *fdst = st->privateData;
    int ret;

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

    virMutexLock(&fdst->lock);

    if (fdst->length) {
        if (fdst->length == fdst->offset) {
            virReportSystemError(ENOSPC, "%s",
                                 _("cannot write to stream"));
            virMutexUnlock(&fdst->lock);
            return -1;
        }

        if ((fdst->length - fdst->offset) < nbytes)
            nbytes = fdst->length - fdst->offset;
    }

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
    } else if (fdst->length) {
        fdst->offset += ret;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("stream is not open"));
        return -1;
    }

    virMutexLock(&fdst->lock);

    if (fdst->length) {
        if (fdst->length == fdst->offset) {
            virMutexUnlock(&fdst->lock);
            return 0;
        }

        if ((fdst->length - fdst->offset) < nbytes)
            nbytes = fdst->length - fdst->offset;
    }

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
    } else if (fdst->length) {
        fdst->offset += ret;
    }

    virMutexUnlock(&fdst->lock);
    return ret;
}


static virStreamDriver virFDStreamDrv = {
    .streamSend = virFDStreamWrite,
    .streamRecv = virFDStreamRead,
    .streamFinish = virFDStreamClose,
    .streamAbort = virFDStreamAbort,
    .streamEventAddCallback = virFDStreamAddCallback,
    .streamEventUpdateCallback = virFDStreamUpdateCallback,
    .streamEventRemoveCallback = virFDStreamRemoveCallback
};

static int virFDStreamOpenInternal(virStreamPtr st,
                                   int fd,
                                   virCommandPtr cmd,
                                   int errfd,
                                   unsigned long long length)
{
    struct virFDStreamData *fdst;

    VIR_DEBUG("st=%p fd=%d cmd=%p errfd=%d length=%llu",
              st, fd, cmd, errfd, length);

    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        virSetNonBlock(fd) < 0)
        return -1;

    if (VIR_ALLOC(fdst) < 0)
        return -1;

    fdst->fd = fd;
    fdst->cmd = cmd;
    fdst->errfd = errfd;
    fdst->length = length;
    if (virMutexInit(&fdst->lock) < 0) {
        VIR_FREE(fdst);
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to initialize mutex"));
        return -1;
    }

    st->driver = &virFDStreamDrv;
    st->privateData = fdst;

    return 0;
}


int virFDStreamOpen(virStreamPtr st,
                    int fd)
{
    return virFDStreamOpenInternal(st, fd, NULL, -1, 0);
}


#if HAVE_SYS_UN_H
int virFDStreamConnectUNIX(virStreamPtr st,
                           const char *path,
                           bool abstract)
{
    struct sockaddr_un sa;
    size_t i = 0;
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

    if (virFDStreamOpenInternal(st, fd, NULL, -1, 0) < 0)
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
                            int mode)
{
    int fd = -1;
    int childfd = -1;
    struct stat sb;
    virCommandPtr cmd = NULL;
    int errfd = -1;

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

    if (fstat(fd, &sb) < 0) {
        virReportSystemError(errno,
                             _("Unable to access stream for '%s'"),
                             path);
        goto error;
    }

    if (offset &&
        lseek(fd, offset, SEEK_SET) != offset) {
        virReportSystemError(errno,
                             _("Unable to seek %s to %llu"),
                             path, offset);
        goto error;
    }

    /* Thanks to the POSIX i/o model, we can't reliably get
     * non-blocking I/O on block devs/regular files. To
     * support those we need to fork a helper process to do
     * the I/O so we just have a fifo. Or use AIO :-(
     */
    if ((st->flags & VIR_STREAM_NONBLOCK) &&
        (!S_ISCHR(sb.st_mode) &&
         !S_ISFIFO(sb.st_mode))) {
        int fds[2] = { -1, -1 };

        if ((oflags & O_ACCMODE) == O_RDWR) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("%s: Cannot request read and write flags together"),
                           path);
            goto error;
        }

        if (pipe(fds) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to create pipe"));
            goto error;
        }

        cmd = virCommandNewArgList(iohelper_path,
                                   path,
                                   NULL);
        virCommandAddArgFormat(cmd, "%llu", length);
        virCommandPassFD(cmd, fd,
                         VIR_COMMAND_PASS_FD_CLOSE_PARENT);
        virCommandAddArgFormat(cmd, "%d", fd);

        if ((oflags & O_ACCMODE) == O_RDONLY) {
            childfd = fds[1];
            fd = fds[0];
            virCommandSetOutputFD(cmd, &childfd);
        } else {
            childfd = fds[0];
            fd = fds[1];
            virCommandSetInputFD(cmd, childfd);
        }
        virCommandSetErrorFD(cmd, &errfd);

        if (virCommandRunAsync(cmd, NULL) < 0)
            goto error;

        VIR_FORCE_CLOSE(childfd);
    }

    if (virFDStreamOpenInternal(st, fd, cmd, errfd, length) < 0)
        goto error;

    return 0;

 error:
    virCommandFree(cmd);
    VIR_FORCE_CLOSE(fd);
    VIR_FORCE_CLOSE(childfd);
    VIR_FORCE_CLOSE(errfd);
    if (oflags & O_CREAT)
        unlink(path);
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
                                       oflags, 0);
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
                                       oflags | O_CREAT, mode);
}

#ifdef HAVE_CFMAKERAW
int virFDStreamOpenPTY(virStreamPtr st,
                       const char *path,
                       unsigned long long offset,
                       unsigned long long length,
                       int oflags)
{
    struct virFDStreamData *fdst = NULL;
    struct termios rawattr;

    if (virFDStreamOpenFileInternal(st, path,
                                    offset, length,
                                    oflags | O_CREAT, 0) < 0)
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
                                       oflags | O_CREAT, 0);
}
#endif /* !HAVE_CFMAKERAW */

int virFDStreamSetInternalCloseCb(virStreamPtr st,
                                  virFDStreamInternalCloseCb cb,
                                  void *opaque,
                                  virFDStreamInternalCloseCbFreeOpaque fcb)
{
    struct virFDStreamData *fdst = st->privateData;

    virMutexLock(&fdst->lock);

    if (fdst->icbFreeOpaque)
        (fdst->icbFreeOpaque)(fdst->icbOpaque);

    fdst->icbCb = cb;
    fdst->icbOpaque = opaque;
    fdst->icbFreeOpaque = fcb;

    virMutexUnlock(&fdst->lock);
    return 0;
}
