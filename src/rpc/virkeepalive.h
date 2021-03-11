/*
 * virkeepalive.h: keepalive handling
 *
 * Copyright (C) 2011 Red Hat, Inc.
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

#include "virnetmessage.h"
#include "virobject.h"

typedef int (*virKeepAliveSendFunc)(void *client, virNetMessage *msg);
typedef void (*virKeepAliveDeadFunc)(void *client);
typedef void (*virKeepAliveFreeFunc)(void *client);

typedef struct _virKeepAlive virKeepAlive;


virKeepAlive *virKeepAliveNew(int interval,
                                unsigned int count,
                                void *client,
                                virKeepAliveSendFunc sendCB,
                                virKeepAliveDeadFunc deadCB,
                                virKeepAliveFreeFunc freeCB)
                                ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
                                ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

int virKeepAliveStart(virKeepAlive *ka,
                      int interval,
                      unsigned int count);
void virKeepAliveStop(virKeepAlive *ka);

int virKeepAliveTimeout(virKeepAlive *ka);
bool virKeepAliveTrigger(virKeepAlive *ka,
                         virNetMessage **msg);
bool virKeepAliveCheckMessage(virKeepAlive *ka,
                              virNetMessage *msg,
                              virNetMessage **response);
