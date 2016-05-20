/*
 * driver-stream.h: entry points for stream drivers
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

#ifndef __VIR_DRIVER_STREAM_H__
# define __VIR_DRIVER_STREAM_H__

# ifndef __VIR_DRIVER_H_INCLUDES___
#  error "Don't include this file directly, only use driver.h"
# endif

typedef int
(*virDrvStreamSend)(virStreamPtr st,
                    const char *data,
                    size_t nbytes);

typedef int
(*virDrvStreamRecv)(virStreamPtr st,
                    char *data,
                    size_t nbytes);

typedef int
(*virDrvStreamRecvFlags)(virStreamPtr st,
                         char *data,
                         size_t nbytes,
                         unsigned int flags);

typedef int
(*virDrvStreamSendHole)(virStreamPtr st,
                        long long length,
                        unsigned int flags);

typedef int
(*virDrvStreamRecvHole)(virStreamPtr st,
                        long long *length,
                        unsigned int flags);

typedef int
(*virDrvStreamEventAddCallback)(virStreamPtr stream,
                                int events,
                                virStreamEventCallback cb,
                                void *opaque,
                                virFreeCallback ff);

typedef int
(*virDrvStreamEventUpdateCallback)(virStreamPtr stream,
                                   int events);

typedef int
(*virDrvStreamEventRemoveCallback)(virStreamPtr stream);

typedef int
(*virDrvStreamFinish)(virStreamPtr st);

typedef int
(*virDrvStreamAbort)(virStreamPtr st);

typedef struct _virStreamDriver virStreamDriver;
typedef virStreamDriver *virStreamDriverPtr;

struct _virStreamDriver {
    virDrvStreamSend streamSend;
    virDrvStreamRecv streamRecv;
    virDrvStreamRecvFlags streamRecvFlags;
    virDrvStreamSendHole streamSendHole;
    virDrvStreamRecvHole streamRecvHole;
    virDrvStreamEventAddCallback streamEventAddCallback;
    virDrvStreamEventUpdateCallback streamEventUpdateCallback;
    virDrvStreamEventRemoveCallback streamEventRemoveCallback;
    virDrvStreamFinish streamFinish;
    virDrvStreamAbort streamAbort;
};


#endif /* __VIR_DRIVER_STREAM_H__ */
