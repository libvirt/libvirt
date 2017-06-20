/*
 * libvirt-stream.c: entry points for virStreamPtr APIs
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 */

#include <config.h>

#include "datatypes.h"
#include "viralloc.h"
#include "virlog.h"
#include "rpc/virnetprotocol.h"

VIR_LOG_INIT("libvirt.stream");

#define VIR_FROM_THIS VIR_FROM_STREAMS


/**
 * virStreamNew:
 * @conn: pointer to the connection
 * @flags: bitwise-OR of virStreamFlags
 *
 * Creates a new stream object which can be used to perform
 * streamed I/O with other public API function.
 *
 * When no longer needed, a stream object must be released
 * with virStreamFree. If a data stream has been used,
 * then the application must call virStreamFinish or
 * virStreamAbort before free'ing to, in order to notify
 * the driver of termination.
 *
 * If a non-blocking data stream is required passed
 * VIR_STREAM_NONBLOCK for flags, otherwise pass 0.
 *
 * Returns the new stream, or NULL upon error
 */
virStreamPtr
virStreamNew(virConnectPtr conn,
             unsigned int flags)
{
    virStreamPtr st;

    VIR_DEBUG("conn=%p, flags=%x", conn, flags);

    virResetLastError();

    virCheckConnectReturn(conn, NULL);

    st = virGetStream(conn);
    if (st)
        st->flags = flags;
    else
        virDispatchError(conn);

    return st;
}


/**
 * virStreamRef:
 * @stream: pointer to the stream
 *
 * Increment the reference count on the stream. For each
 * additional call to this method, there shall be a corresponding
 * call to virStreamFree to release the reference count, once
 * the caller no longer needs the reference to this object.
 *
 * Returns 0 in case of success, -1 in case of failure
 */
int
virStreamRef(virStreamPtr stream)
{
    VIR_DEBUG("stream=%p refs=%d", stream,
              stream ? stream->object.u.s.refs : 0);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    virObjectRef(stream);
    return 0;
}


/**
 * virStreamSend:
 * @stream: pointer to the stream object
 * @data: buffer to write to stream
 * @nbytes: size of @data buffer
 *
 * Write a series of bytes to the stream. This method may
 * block the calling application for an arbitrary amount
 * of time. Once an application has finished sending data
 * it should call virStreamFinish to wait for successful
 * confirmation from the driver, or detect any error.
 *
 * This method may not be used if a stream source has been
 * registered.
 *
 * Errors are not guaranteed to be reported synchronously
 * with the call, but may instead be delayed until a
 * subsequent call.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *     virStreamPtr st = virStreamNew(conn, 0);
 *     int fd = open("demo.iso", O_RDONLY);
 *
 *     virConnectUploadFile(conn, "demo.iso", st);
 *
 *     while (1) {
 *          char buf[1024];
 *          int got = read(fd, buf, 1024);
 *          if (got < 0) {
 *             virStreamAbort(st);
 *             break;
 *          }
 *          if (got == 0) {
 *             virStreamFinish(st);
 *             break;
 *          }
 *          int offset = 0;
 *          while (offset < got) {
 *             int sent = virStreamSend(st, buf+offset, got-offset);
 *             if (sent < 0) {
 *                virStreamAbort(st);
 *                goto done;
 *             }
 *             offset += sent;
 *          }
 *      }
 *      if (virStreamFinish(st) < 0)
 *         ... report an error ....
 *    done:
 *      virStreamFree(st);
 *      close(fd);
 *
 * Returns the number of bytes written, which may be less
 * than requested.
 *
 * Returns -1 upon error, at which time the stream will
 * be marked as aborted, and the caller should now release
 * the stream with virStreamFree.
 *
 * Returns -2 if the outgoing transmit buffers are full &
 * the stream is marked as non-blocking.
 */
int
virStreamSend(virStreamPtr stream,
              const char *data,
              size_t nbytes)
{
    VIR_DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(data, error);

    if (stream->driver &&
        stream->driver->streamSend) {
        int ret;
        ret = (stream->driver->streamSend)(stream, data, nbytes);
        if (ret == -2)
            return -2;
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamRecv:
 * @stream: pointer to the stream object
 * @data: buffer to read into from stream
 * @nbytes: size of @data buffer
 *
 * Reads a series of bytes from the stream. This method may
 * block the calling application for an arbitrary amount
 * of time.
 *
 * Errors are not guaranteed to be reported synchronously
 * with the call, but may instead be delayed until a
 * subsequent call.
 *
 * An example using this with a hypothetical file download
 * API looks like
 *
 *     virStreamPtr st = virStreamNew(conn, 0);
 *     int fd = open("demo.iso", O_WRONLY, 0600);
 *
 *     virConnectDownloadFile(conn, "demo.iso", st);
 *
 *     while (1) {
 *         char buf[1024];
 *         int got = virStreamRecv(st, buf, 1024);
 *         if (got < 0)
 *            break;
 *         if (got == 0) {
 *            virStreamFinish(st);
 *            break;
 *         }
 *         int offset = 0;
 *         while (offset < got) {
 *            int sent = write(fd, buf + offset, got - offset);
 *            if (sent < 0) {
 *               virStreamAbort(st);
 *               goto done;
 *            }
 *            offset += sent;
 *         }
 *     }
 *     if (virStreamFinish(st) < 0)
 *        ... report an error ....
 *   done:
 *     virStreamFree(st);
 *     close(fd);
 *
 *
 * Returns the number of bytes read, which may be less
 * than requested.
 *
 * Returns 0 when the end of the stream is reached, at
 * which time the caller should invoke virStreamFinish()
 * to get confirmation of stream completion.
 *
 * Returns -1 upon error, at which time the stream will
 * be marked as aborted, and the caller should now release
 * the stream with virStreamFree.
 *
 * Returns -2 if there is no data pending to be read & the
 * stream is marked as non-blocking.
 */
int
virStreamRecv(virStreamPtr stream,
              char *data,
              size_t nbytes)
{
    VIR_DEBUG("stream=%p, data=%p, nbytes=%zi", stream, data, nbytes);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(data, error);

    if (stream->driver &&
        stream->driver->streamRecv) {
        int ret;
        ret = (stream->driver->streamRecv)(stream, data, nbytes);
        if (ret == -2)
            return -2;
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamRecvFlags:
 * @stream: pointer to the stream object
 * @data: buffer to read into from stream
 * @nbytes: size of @data buffer
 * @flags: bitwise-OR of virStreamRecvFlagsValues
 *
 * Reads a series of bytes from the stream. This method may
 * block the calling application for an arbitrary amount
 * of time.
 *
 * This is just like virStreamRecv except this one has extra
 * @flags. Calling this function with no @flags set (equal to
 * zero) is equivalent to calling virStreamRecv(stream, data, nbytes).
 *
 * If flag VIR_STREAM_RECV_STOP_AT_HOLE is set, this function
 * will stop reading from stream if it has reached a hole. In
 * that case, -3 is returned and virStreamRecvHole() should be
 * called to get the hole size. An example using this flag might
 * look like this:
 *
 *   while (1) {
 *     char buf[4096];
 *
 *     int ret = virStreamRecvFlags(st, buf, len, VIR_STREAM_STOP_AT_HOLE);
 *     if (ret < 0) {
 *       if (ret == -3) {
 *         long long len;
 *         ret = virStreamRecvHole(st, &len, 0);
 *         if (ret < 0) {
 *           ...error..
 *         } else {
 *           ...seek len bytes in target...
 *         }
 *       } else {
 *         return -1;
 *       }
 *     } else {
 *         ...write buf to target...
 *     }
 *   }
 *
 * Returns 0 when the end of the stream is reached, at
 * which time the caller should invoke virStreamFinish()
 * to get confirmation of stream completion.
 *
 * Returns -1 upon error, at which time the stream will
 * be marked as aborted, and the caller should now release
 * the stream with virStreamFree.
 *
 * Returns -2 if there is no data pending to be read & the
 * stream is marked as non-blocking.
 *
 * Returns -3 if there is a hole in stream and caller requested
 * to stop at a hole.
 */
int
virStreamRecvFlags(virStreamPtr stream,
                   char *data,
                   size_t nbytes,
                   unsigned int flags)
{
    VIR_DEBUG("stream=%p, data=%p, nbytes=%zu flags=%x",
              stream, data, nbytes, flags);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(data, error);

    if (stream->driver &&
        stream->driver->streamRecvFlags) {
        int ret;
        ret = (stream->driver->streamRecvFlags)(stream, data, nbytes, flags);
        if (ret == -2)
            return -2;
        if (ret == -3)
            return -3;
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamSendHole:
 * @stream: pointer to the stream object
 * @length: number of bytes to skip
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * Rather than transmitting empty file space, this API directs
 * the @stream target to create @length bytes of empty space.
 * This API would be used when uploading or downloading sparsely
 * populated files to avoid the needless copy of empty file
 * space.
 *
 * An example using this with a hypothetical file upload API
 * looks like:
 *
 *   virStream st;
 *
 *   while (1) {
 *     char buf[4096];
 *     size_t len;
 *     if (..in hole...) {
 *       ..get hole size...
 *       virStreamSendHole(st, len, 0);
 *     } else {
 *       ...read len bytes...
 *       virStreamSend(st, buf, len);
 *     }
 *   }
 *
 * Returns 0 on success,
 *        -1 error
 */
int
virStreamSendHole(virStreamPtr stream,
                  long long length,
                  unsigned int flags)
{
    VIR_DEBUG("stream=%p, length=%lld flags=%x",
              stream, length, flags);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (stream->driver &&
        stream->driver->streamSendHole) {
        int ret;
        ret = (stream->driver->streamSendHole)(stream, length, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamRecvHole:
 * @stream: pointer to the stream object
 * @length: number of bytes to skip
 * @flags: extra flags; not used yet, so callers should always pass 0
 *
 * This API is used to determine the @length in bytes of the
 * empty space to be created in a @stream's target file when
 * uploading or downloading sparsely populated files. This is the
 * counterpart to virStreamSendHole().
 *
 * Returns 0 on success,
 *        -1 on error or when there's currently no hole in the stream
 */
int
virStreamRecvHole(virStreamPtr stream,
                  long long *length,
                  unsigned int flags)
{
    VIR_DEBUG("stream=%p, length=%p flags=%x",
              stream, length, flags);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgReturn(length, -1);

    if (stream->driver &&
        stream->driver->streamRecvHole) {
        int ret;
        ret = (stream->driver->streamRecvHole)(stream, length, flags);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamInData:
 * @stream: stream
 * @data: are we in data or hole
 * @length: length to next section
 *
 * This function checks the underlying stream (typically a file)
 * to learn whether the current stream position lies within a
 * data section or a hole. Upon return @data is set to a nonzero
 * value if former is the case, or to zero if @stream is in a
 * hole. Moreover, @length is updated to tell caller how many
 * bytes can be read from @stream until current section changes
 * (from data to a hole or vice versa).
 *
 * NB: there's an implicit hole at EOF. In this situation this
 * function should set @data = false, @length = 0 and return 0.
 *
 * To sum it up:
 *
 * data section: @data = true,  @length > 0
 * hole:         @data = false, @length > 0
 * EOF:          @data = false, @length = 0
 *
 * Returns 0 on success,
 *        -1 otherwise
 */
int
virStreamInData(virStreamPtr stream,
                int *data,
                long long *length)
{
    VIR_DEBUG("stream=%p, data=%p, length=%p", stream, data, length);

    virResetLastError();
    virCheckNonNullArgReturn(data, -1);
    virCheckNonNullArgReturn(length, -1);

    if (stream->driver->streamInData) {
        int ret;
        ret = (stream->driver->streamInData)(stream, data, length);
        return ret;
    }

    virReportUnsupportedError();
    return -1;
}


/**
 * virStreamSendAll:
 * @stream: pointer to the stream object
 * @handler: source callback for reading data from application
 * @opaque: application defined data
 *
 * Send the entire data stream, reading the data from the
 * requested data source. This is simply a convenient alternative
 * to virStreamSend, for apps that do blocking-I/O.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *   int mysource(virStreamPtr st, char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return read(*fd, buf, nbytes);
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_RDONLY);
 *
 *   virConnectUploadFile(conn, st);
 *   if (virStreamSendAll(st, mysource, &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Returns 0 if all the data was successfully sent. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called,  so the caller need only call
 * virStreamFree()
 */
int
virStreamSendAll(virStreamPtr stream,
                 virStreamSourceFunc handler,
                 void *opaque)
{
    char *bytes = NULL;
    size_t want = VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX;
    int ret = -1;
    VIR_DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(handler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("data sources cannot be used for non-blocking streams"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(bytes, want) < 0)
        goto cleanup;

    for (;;) {
        int got, offset = 0;
        got = (handler)(stream, bytes, want, opaque);
        if (got < 0) {
            virStreamAbort(stream);
            goto cleanup;
        }
        if (got == 0)
            break;
        while (offset < got) {
            int done;
            done = virStreamSend(stream, bytes + offset, got - offset);
            if (done < 0)
                goto cleanup;
            offset += done;
        }
    }
    ret = 0;

 cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}


/**
 * virStreamSparseSendAll:
 * @stream: pointer to the stream object
 * @handler: source callback for reading data from application
 * @holeHandler: source callback for determining holes
 * @skipHandler: skip holes as reported by @holeHandler
 * @opaque: application defined data
 *
 * Send the entire data stream, reading the data from the
 * requested data source. This is simply a convenient alternative
 * to virStreamSend, for apps that do blocking-I/O.
 *
 * An example using this with a hypothetical file upload
 * API looks like
 *
 *   int mysource(virStreamPtr st, char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return read(*fd, buf, nbytes);
 *   }
 *
 *   int myskip(virStreamPtr st, long long offset, void *opaque) {
 *       int *fd = opaque;
 *
 *       return lseek(*fd, offset, SEEK_CUR) == (off_t) -1 ? -1 : 0;
 *   }
 *
 *   int myindata(virStreamPtr st, int *inData,
 *                long long *offset, void *opaque) {
 *       int *fd = opaque;
 *
 *       if (@fd in hole) {
 *           *inData = 0;
 *           *offset = holeSize;
 *       } else {
 *           *inData = 1;
 *           *offset = dataSize;
 *       }
 *
 *       return 0;
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_RDONLY);
 *
 *   virConnectUploadSparseFile(conn, st);
 *   if (virStreamSparseSendAll(st,
 *                              mysource,
 *                              myindata,
 *                              myskip,
 *                              &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Note that @opaque data are shared between @handler, @holeHandler and @skipHandler.
 *
 * Returns 0 if all the data was successfully sent. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree.
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called,  so the caller need only call
 * virStreamFree().
 */
int virStreamSparseSendAll(virStreamPtr stream,
                           virStreamSourceFunc handler,
                           virStreamSourceHoleFunc holeHandler,
                           virStreamSourceSkipFunc skipHandler,
                           void *opaque)
{
    char *bytes = NULL;
    size_t bufLen = VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX;
    int ret = -1;
    unsigned long long dataLen = 0;

    VIR_DEBUG("stream=%p handler=%p holeHandler=%p opaque=%p",
              stream, handler, holeHandler, opaque);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(handler, cleanup);
    virCheckNonNullArgGoto(holeHandler, cleanup);
    virCheckNonNullArgGoto(skipHandler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("data sources cannot be used for non-blocking streams"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(bytes, bufLen) < 0)
        goto cleanup;

    for (;;) {
        int inData, got, offset = 0;
        long long sectionLen;
        size_t want = bufLen;
        const unsigned int skipFlags = 0;

        if (!dataLen) {
            if (holeHandler(stream, &inData, &sectionLen, opaque) < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }

            if (!inData && sectionLen) {
                if (virStreamSendHole(stream, sectionLen, skipFlags) < 0) {
                    virStreamAbort(stream);
                    goto cleanup;
                }

                if (skipHandler(stream, sectionLen, opaque) < 0) {
                    virReportSystemError(errno, "%s",
                                         _("unable to skip hole"));
                    virStreamAbort(stream);
                    goto cleanup;
                }
                continue;
            } else {
                dataLen = sectionLen;
            }
        }

        if (want > dataLen)
            want = dataLen;

        got = (handler)(stream, bytes, want, opaque);
        if (got < 0) {
            virStreamAbort(stream);
            goto cleanup;
        }
        if (got == 0)
            break;
        while (offset < got) {
            int done;
            done = virStreamSend(stream, bytes + offset, got - offset);
            if (done < 0)
                goto cleanup;
            offset += done;
            dataLen -= done;
        }
    }
    ret = 0;

 cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}


/**
 * virStreamRecvAll:
 * @stream: pointer to the stream object
 * @handler: sink callback for writing data to application
 * @opaque: application defined data
 *
 * Receive the entire data stream, sending the data to the
 * requested data sink. This is simply a convenient alternative
 * to virStreamRecv, for apps that do blocking-I/O.
 *
 * An example using this with a hypothetical file download
 * API looks like
 *
 *   int mysink(virStreamPtr st, const char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return write(*fd, buf, nbytes);
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_WRONLY);
 *
 *   virConnectUploadFile(conn, st);
 *   if (virStreamRecvAll(st, mysink, &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Returns 0 if all the data was successfully received. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called,  so the caller need only call
 * virStreamFree()
 */
int
virStreamRecvAll(virStreamPtr stream,
                 virStreamSinkFunc handler,
                 void *opaque)
{
    char *bytes = NULL;
    size_t want = VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX;
    int ret = -1;
    VIR_DEBUG("stream=%p, handler=%p, opaque=%p", stream, handler, opaque);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(handler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("data sinks cannot be used for non-blocking streams"));
        goto cleanup;
    }


    if (VIR_ALLOC_N(bytes, want) < 0)
        goto cleanup;

    for (;;) {
        int got, offset = 0;
        got = virStreamRecv(stream, bytes, want);
        if (got < 0)
            goto cleanup;
        if (got == 0)
            break;
        while (offset < got) {
            int done;
            done = (handler)(stream, bytes + offset, got - offset, opaque);
            if (done < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }
            offset += done;
        }
    }
    ret = 0;

 cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}


/**
 * virStreamSparseRecvAll:
 * @stream: pointer to the stream object
 * @handler: sink callback for writing data to application
 * @holeHandler: stream hole callback for skipping holes
 * @opaque: application defined data
 *
 * Receive the entire data stream, sending the data to the
 * requested data sink @handler and calling the skip @holeHandler
 * to generate holes for sparse stream targets. This is simply a
 * convenient alternative to virStreamRecvFlags, for apps that do
 * blocking-I/O.
 *
 * An example using this with a hypothetical file download
 * API looks like:
 *
 *   int mysink(virStreamPtr st, const char *buf, int nbytes, void *opaque) {
 *       int *fd = opaque;
 *
 *       return write(*fd, buf, nbytes);
 *   }
 *
 *   int myskip(virStreamPtr st, long long offset, void *opaque) {
 *       int *fd = opaque;
 *
 *       return lseek(*fd, offset, SEEK_CUR) == (off_t) -1 ? -1 : 0;
 *   }
 *
 *   virStreamPtr st = virStreamNew(conn, 0);
 *   int fd = open("demo.iso", O_WRONLY);
 *
 *   virConnectDownloadSparseFile(conn, st);
 *   if (virStreamSparseRecvAll(st, mysink, myskip, &fd) < 0) {
 *      ...report an error ...
 *      goto done;
 *   }
 *   if (virStreamFinish(st) < 0)
 *      ...report an error...
 *   virStreamFree(st);
 *   close(fd);
 *
 * Note that @opaque data is shared between both @handler and
 * @holeHandler callbacks.
 *
 * Returns 0 if all the data was successfully received. The caller
 * should invoke virStreamFinish(st) to flush the stream upon
 * success and then virStreamFree(st).
 *
 * Returns -1 upon any error, with virStreamAbort() already
 * having been called, so the caller need only call virStreamFree().
 */
int
virStreamSparseRecvAll(virStreamPtr stream,
                       virStreamSinkFunc handler,
                       virStreamSinkHoleFunc holeHandler,
                       void *opaque)
{
    char *bytes = NULL;
    size_t want = VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX;
    const unsigned int flags = VIR_STREAM_RECV_STOP_AT_HOLE;
    int ret = -1;

    VIR_DEBUG("stream=%p handler=%p holeHandler=%p opaque=%p",
              stream, handler, holeHandler, opaque);

    virResetLastError();

    virCheckStreamReturn(stream, -1);
    virCheckNonNullArgGoto(handler, cleanup);
    virCheckNonNullArgGoto(holeHandler, cleanup);

    if (stream->flags & VIR_STREAM_NONBLOCK) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("data sinks cannot be used for non-blocking streams"));
        goto cleanup;
    }

    if (VIR_ALLOC_N(bytes, want) < 0)
        goto cleanup;

    for (;;) {
        int got, offset = 0;
        long long holeLen;
        const unsigned int holeFlags = 0;

        got = virStreamRecvFlags(stream, bytes, want, flags);
        if (got == -3) {
            if (virStreamRecvHole(stream, &holeLen, holeFlags) < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }

            if (holeHandler(stream, holeLen, opaque) < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }
            continue;
        } else if (got < 0) {
            goto cleanup;
        } else if (got == 0) {
            break;
        }
        while (offset < got) {
            int done;
            done = (handler)(stream, bytes + offset, got - offset, opaque);
            if (done < 0) {
                virStreamAbort(stream);
                goto cleanup;
            }
            offset += done;
        }
    }
    ret = 0;

 cleanup:
    VIR_FREE(bytes);

    if (ret != 0)
        virDispatchError(stream->conn);

    return ret;
}

/**
 * virStreamEventAddCallback:
 * @stream: pointer to the stream object
 * @events: set of events to monitor
 * @cb: callback to invoke when an event occurs
 * @opaque: application defined data
 * @ff: callback to free @opaque data
 *
 * Register a callback to be notified when a stream
 * becomes writable, or readable. This is most commonly
 * used in conjunction with non-blocking data streams
 * to integrate into an event loop
 *
 * Returns 0 on success, -1 upon error
 */
int
virStreamEventAddCallback(virStreamPtr stream,
                          int events,
                          virStreamEventCallback cb,
                          void *opaque,
                          virFreeCallback ff)
{
    VIR_DEBUG("stream=%p, events=%d, cb=%p, opaque=%p, ff=%p",
              stream, events, cb, opaque, ff);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (stream->driver &&
        stream->driver->streamEventAddCallback) {
        int ret;
        ret = (stream->driver->streamEventAddCallback)(stream, events, cb, opaque, ff);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamEventUpdateCallback:
 * @stream: pointer to the stream object
 * @events: set of events to monitor
 *
 * Changes the set of events to monitor for a stream. This allows
 * for event notification to be changed without having to
 * unregister & register the callback completely. This method
 * is guaranteed to succeed if a callback is already registered
 *
 * Returns 0 on success, -1 if no callback is registered
 */
int
virStreamEventUpdateCallback(virStreamPtr stream,
                             int events)
{
    VIR_DEBUG("stream=%p, events=%d", stream, events);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (stream->driver &&
        stream->driver->streamEventUpdateCallback) {
        int ret;
        ret = (stream->driver->streamEventUpdateCallback)(stream, events);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamEventRemoveCallback:
 * @stream: pointer to the stream object
 *
 * Remove an event callback from the stream
 *
 * Returns 0 on success, -1 on error
 */
int
virStreamEventRemoveCallback(virStreamPtr stream)
{
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (stream->driver &&
        stream->driver->streamEventRemoveCallback) {
        int ret;
        ret = (stream->driver->streamEventRemoveCallback)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamFinish:
 * @stream: pointer to the stream object
 *
 * Indicate that there is no further data to be transmitted
 * on the stream. For output streams this should be called once
 * all data has been written. For input streams this should be
 * called once virStreamRecv returns end-of-file.
 *
 * This method is a synchronization point for all asynchronous
 * errors, so if this returns a success code the application can
 * be sure that all data has been successfully processed.
 *
 * If the stream is non-blocking, any callback must be removed
 * beforehand.
 *
 * Returns 0 on success, -1 upon error
 */
int
virStreamFinish(virStreamPtr stream)
{
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (stream->driver &&
        stream->driver->streamFinish) {
        int ret;
        ret = (stream->driver->streamFinish)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamAbort:
 * @stream: pointer to the stream object
 *
 * Request that the in progress data transfer be cancelled
 * abnormally before the end of the stream has been reached.
 * For output streams this can be used to inform the driver
 * that the stream is being terminated early. For input
 * streams this can be used to inform the driver that it
 * should stop sending data.
 *
 * If the stream is non-blocking, any callback must be removed
 * beforehand.
 *
 * Returns 0 on success, -1 upon error
 */
int
virStreamAbort(virStreamPtr stream)
{
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    if (!stream->driver) {
        VIR_DEBUG("aborting unused stream");
        return 0;
    }

    if (stream->driver->streamAbort) {
        int ret;
        ret = (stream->driver->streamAbort)(stream);
        if (ret < 0)
            goto error;
        return ret;
    }

    virReportUnsupportedError();

 error:
    virDispatchError(stream->conn);
    return -1;
}


/**
 * virStreamFree:
 * @stream: pointer to the stream object
 *
 * Decrement the reference count on a stream, releasing
 * the stream object if the reference count has hit zero.
 *
 * There must not be an active data transfer in progress
 * when releasing the stream. If a stream needs to be
 * disposed of prior to end of stream being reached, then
 * the virStreamAbort function should be called first.
 *
 * Returns 0 upon success, or -1 on error
 */
int
virStreamFree(virStreamPtr stream)
{
    VIR_DEBUG("stream=%p", stream);

    virResetLastError();

    virCheckStreamReturn(stream, -1);

    /* XXX Enforce shutdown before free'ing resources ? */

    virObjectUnref(stream);
    return 0;
}
