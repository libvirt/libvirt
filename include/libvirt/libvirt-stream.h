/*
 * libvirt-stream.h
 * Summary: APIs for management of streams
 * Description: Provides APIs for the management of streams
 * Author: Daniel Veillard <veillard@redhat.com>
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

#ifndef __VIR_LIBVIRT_STREAM_H__
# define __VIR_LIBVIRT_STREAM_H__

# ifndef __VIR_LIBVIRT_H_INCLUDES__
#  error "Don't include this file directly, only use libvirt/libvirt.h"
# endif


typedef enum {
    VIR_STREAM_NONBLOCK = (1 << 0),
} virStreamFlags;

virStreamPtr virStreamNew(virConnectPtr conn,
                          unsigned int flags);
int virStreamRef(virStreamPtr st);

int virStreamSend(virStreamPtr st,
                  const char *data,
                  size_t nbytes);

int virStreamRecv(virStreamPtr st,
                  char *data,
                  size_t nbytes);

typedef enum {
    VIR_STREAM_RECV_STOP_AT_HOLE = (1 << 0),
} virStreamRecvFlagsValues;

int virStreamRecvFlags(virStreamPtr st,
                       char *data,
                       size_t nbytes,
                       unsigned int flags);

int virStreamSendHole(virStreamPtr st,
                      long long length,
                      unsigned int flags);

int virStreamRecvHole(virStreamPtr,
                      long long *length,
                      unsigned int flags);


/**
 * virStreamSourceFunc:
 *
 * @st: the stream object
 * @data: preallocated array to be filled with data
 * @nbytes: size of the data array
 * @opaque: optional application provided data
 *
 * The virStreamSourceFunc callback is used together with
 * the virStreamSendAll and virStreamSparseSendAll functions
 * for libvirt to obtain the data that is to be sent.
 *
 * The callback will be invoked multiple times,
 * fetching data in small chunks. The application
 * should fill the 'data' array with up to 'nbytes'
 * of data and then return the number actual number
 * of bytes. The callback will continue to be
 * invoked until it indicates the end of the source
 * has been reached by returning 0. A return value
 * of -1 at any time will abort the send operation.
 *
 * Please note that for more accurate error reporting the
 * callback should set appropriate errno on failure.
 *
 * Returns the number of bytes filled, 0 upon end
 * of file, or -1 upon error
 */
typedef int (*virStreamSourceFunc)(virStreamPtr st,
                                   char *data,
                                   size_t nbytes,
                                   void *opaque);

int virStreamSendAll(virStreamPtr st,
                     virStreamSourceFunc handler,
                     void *opaque);

/**
 * virStreamSourceHoleFunc:
 * @st: the stream object
 * @inData: are we in data section
 * @length: how long is the section we are currently in
 * @opaque: optional application provided data
 *
 * The virStreamSourceHoleFunc callback is used together with the
 * virStreamSparseSendAll function for libvirt to obtain the
 * length of section stream is currently in.
 *
 * Moreover, upon successful return, @length should be updated
 * with how many bytes are left until the current section ends
 * (either data section or hole section). Also the stream is
 * currently in data section, @inData should be set to a non-zero
 * value and vice versa.
 *
 * NB: there's an implicit hole at the end of each file. If
 * that's the case, @inData and @length should be both set to 0.
 *
 * This function should not adjust the current position within
 * the file.
 *
 * Please note that for more accurate error reporting the
 * callback should set appropriate errno on failure.
 *
 * Returns 0 on success,
 *        -1 upon error
 */
typedef int (*virStreamSourceHoleFunc)(virStreamPtr st,
                                       int *inData,
                                       long long *length,
                                       void *opaque);

/**
 * virStreamSourceSkipFunc:
 * @st: the stream object
 * @length: stream hole size
 * @opaque: optional application provided data
 *
 * This callback is used together with the virStreamSparseSendAll
 * to skip holes in the underlying file as reported by
 * virStreamSourceHoleFunc.
 *
 * The callback may be invoked multiple times as holes are found
 * during processing a stream. The application should skip
 * processing the hole in the stream source and then return.
 * A return value of -1 at any time will abort the send operation.
 *
 * Please note that for more accurate error reporting the
 * callback should set appropriate errno on failure.
 *
 * Returns 0 on success,
 *        -1 upon error.
 */
typedef int (*virStreamSourceSkipFunc)(virStreamPtr st,
                                       long long length,
                                       void *opaque);

int virStreamSparseSendAll(virStreamPtr st,
                           virStreamSourceFunc handler,
                           virStreamSourceHoleFunc holeHandler,
                           virStreamSourceSkipFunc skipHandler,
                           void *opaque);

/**
 * virStreamSinkFunc:
 *
 * @st: the stream object
 * @data: preallocated array to be filled with data
 * @nbytes: size of the data array
 * @opaque: optional application provided data
 *
 * The virStreamSinkFunc callback is used together with the
 * virStreamRecvAll or virStreamSparseRecvAll functions for
 * libvirt to provide the data that has been received.
 *
 * The callback will be invoked multiple times,
 * providing data in small chunks. The application
 * should consume up 'nbytes' from the 'data' array
 * of data and then return the number actual number
 * of bytes consumed. The callback will continue to be
 * invoked until it indicates the end of the stream
 * has been reached. A return value of -1 at any time
 * will abort the receive operation
 *
 * Please note that for more accurate error reporting the
 * callback should set appropriate errno on failure.
 *
 * Returns the number of bytes consumed or -1 upon
 * error
 */
typedef int (*virStreamSinkFunc)(virStreamPtr st,
                                 const char *data,
                                 size_t nbytes,
                                 void *opaque);

int virStreamRecvAll(virStreamPtr st,
                     virStreamSinkFunc handler,
                     void *opaque);

/**
 * virStreamSinkHoleFunc:
 * @st: the stream object
 * @length: stream hole size
 * @opaque: optional application provided data
 *
 * This callback is used together with the virStreamSparseRecvAll
 * function for libvirt to provide the size of a hole that
 * occurred in the stream.
 *
 * The callback may be invoked multiple times as holes are found
 * during processing a stream. The application should create the
 * hole in the stream target and then return. A return value of
 * -1 at any time will abort the receive operation.
 *
 * Please note that for more accurate error reporting the
 * callback should set appropriate errno on failure.
 *
 * Returns 0 on success,
 *        -1 upon error
 */
typedef int (*virStreamSinkHoleFunc)(virStreamPtr st,
                                     long long length,
                                     void *opaque);

int virStreamSparseRecvAll(virStreamPtr stream,
                           virStreamSinkFunc handler,
                           virStreamSinkHoleFunc holeHandler,
                           void *opaque);

typedef enum {
    VIR_STREAM_EVENT_READABLE  = (1 << 0),
    VIR_STREAM_EVENT_WRITABLE  = (1 << 1),
    VIR_STREAM_EVENT_ERROR     = (1 << 2),
    VIR_STREAM_EVENT_HANGUP    = (1 << 3),
} virStreamEventType;


/**
 * virStreamEventCallback:
 *
 * @stream: stream on which the event occurred
 * @events: bitset of events from virEventHandleType constants
 * @opaque: user data registered with handle
 *
 * Callback for receiving stream events. The callback will
 * be invoked once for each event which is pending.
 */
typedef void (*virStreamEventCallback)(virStreamPtr stream, int events, void *opaque);

int virStreamEventAddCallback(virStreamPtr stream,
                              int events,
                              virStreamEventCallback cb,
                              void *opaque,
                              virFreeCallback ff);

int virStreamEventUpdateCallback(virStreamPtr stream,
                                 int events);

int virStreamEventRemoveCallback(virStreamPtr stream);


int virStreamFinish(virStreamPtr st);
int virStreamAbort(virStreamPtr st);

int virStreamFree(virStreamPtr st);

#endif /* __VIR_LIBVIRT_STREAM_H__ */
