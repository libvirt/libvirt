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

#ifndef LIBVIRT_VIRNETCLIENTSTREAM_H
# define LIBVIRT_VIRNETCLIENTSTREAM_H

# include "virnetclientprogram.h"
# include "virobject.h"

typedef struct _virNetClientStream virNetClientStream;
typedef virNetClientStream *virNetClientStreamPtr;

typedef void (*virNetClientStreamEventCallback)(virNetClientStreamPtr stream,
                                                int events, void *opaque);

virNetClientStreamPtr virNetClientStreamNew(virStreamPtr stream,
                                            virNetClientProgramPtr prog,
                                            int proc,
                                            unsigned serial,
                                            bool allowSkip);

bool virNetClientStreamRaiseError(virNetClientStreamPtr st);

int virNetClientStreamSetError(virNetClientStreamPtr st,
                               virNetMessagePtr msg);

bool virNetClientStreamMatches(virNetClientStreamPtr st,
                               virNetMessagePtr msg);

int virNetClientStreamQueuePacket(virNetClientStreamPtr st,
                                  virNetMessagePtr msg);

int virNetClientStreamSendPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 int status,
                                 const char *data,
                                 size_t nbytes);

int virNetClientStreamRecvPacket(virNetClientStreamPtr st,
                                 virNetClientPtr client,
                                 char *data,
                                 size_t nbytes,
                                 bool nonblock,
                                 unsigned int flags);

int virNetClientStreamSendHole(virNetClientStreamPtr st,
                               virNetClientPtr client,
                               long long length,
                               unsigned int flags);

int virNetClientStreamRecvHole(virNetClientPtr client,
                               virNetClientStreamPtr st,
                               long long *length);

int virNetClientStreamEventAddCallback(virNetClientStreamPtr st,
                                       int events,
                                       virNetClientStreamEventCallback cb,
                                       void *opaque,
                                       virFreeCallback ff);

int virNetClientStreamEventUpdateCallback(virNetClientStreamPtr st,
                                          int events);
int virNetClientStreamEventRemoveCallback(virNetClientStreamPtr st);

bool virNetClientStreamEOF(virNetClientStreamPtr st)
    ATTRIBUTE_NONNULL(1);

#endif /* LIBVIRT_VIRNETCLIENTSTREAM_H */
