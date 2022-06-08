/*
 * virnetclientstream.h: generic network RPC client stream
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#pragma once

#include "virnetclientprogram.h"

typedef struct _virNetClientStream virNetClientStream;

typedef enum {
    VIR_NET_CLIENT_STREAM_CLOSED_NOT = 0,
    VIR_NET_CLIENT_STREAM_CLOSED_FINISHED,
    VIR_NET_CLIENT_STREAM_CLOSED_ABORTED,
} virNetClientStreamClosed;

typedef void (*virNetClientStreamEventCallback)(virNetClientStream *stream,
                                                int events, void *opaque);

virNetClientStream *virNetClientStreamNew(virNetClientProgram *prog,
                                            int proc,
                                            unsigned serial,
                                            bool allowSkip);

int virNetClientStreamCheckState(virNetClientStream *st);

int virNetClientStreamCheckSendStatus(virNetClientStream *st,
                                      virNetMessage *msg);

int virNetClientStreamSetError(virNetClientStream *st,
                               virNetMessage *msg);

void virNetClientStreamSetClosed(virNetClientStream *st,
                                 virNetClientStreamClosed closed);

bool virNetClientStreamMatches(virNetClientStream *st,
                               virNetMessage *msg);

int virNetClientStreamQueuePacket(virNetClientStream *st,
                                  virNetMessage *msg);

int virNetClientStreamSendPacket(virNetClientStream *st,
                                 virNetClient *client,
                                 int status,
                                 const char *data,
                                 size_t nbytes);

int virNetClientStreamRecvPacket(virNetClientStream *st,
                                 virNetClient *client,
                                 char *data,
                                 size_t nbytes,
                                 bool nonblock,
                                 unsigned int flags);

int virNetClientStreamSendHole(virNetClientStream *st,
                               virNetClient *client,
                               long long length,
                               unsigned int flags);

int virNetClientStreamRecvHole(virNetClient *client,
                               virNetClientStream *st,
                               long long *length);

int virNetClientStreamEventAddCallback(virNetClientStream *st,
                                       int events,
                                       virNetClientStreamEventCallback cb,
                                       void *opaque,
                                       virFreeCallback ff);

int virNetClientStreamEventUpdateCallback(virNetClientStream *st,
                                          int events);
int virNetClientStreamEventRemoveCallback(virNetClientStream *st);

bool virNetClientStreamEOF(virNetClientStream *st)
    ATTRIBUTE_NONNULL(1);

int virNetClientStreamInData(virNetClientStream *st,
                             int *inData,
                             long long *length);
