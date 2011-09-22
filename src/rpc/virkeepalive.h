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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Jiri Denemark <jdenemar@redhat.com>
 */

#ifndef __VIR_KEEPALIVE_H__
# define __VIR_KEEPALIVE_H__

# include "virnetmessage.h"

typedef int (*virKeepAliveSendFunc)(void *client, virNetMessagePtr msg);
typedef void (*virKeepAliveDeadFunc)(void *client);
typedef void (*virKeepAliveFreeFunc)(void *client);

typedef struct _virKeepAlive virKeepAlive;
typedef virKeepAlive *virKeepAlivePtr;


virKeepAlivePtr virKeepAliveNew(int interval,
                                unsigned int count,
                                void *client,
                                virKeepAliveSendFunc sendCB,
                                virKeepAliveDeadFunc deadCB,
                                virKeepAliveFreeFunc freeCB)
                                ATTRIBUTE_NONNULL(3) ATTRIBUTE_NONNULL(4)
                                ATTRIBUTE_NONNULL(5) ATTRIBUTE_NONNULL(6);

void virKeepAliveRef(virKeepAlivePtr ka);
void virKeepAliveFree(virKeepAlivePtr ka);

int virKeepAliveStart(virKeepAlivePtr ka,
                      int interval,
                      unsigned int count);
void virKeepAliveStop(virKeepAlivePtr ka);

bool virKeepAliveCheckMessage(virKeepAlivePtr ka,
                              virNetMessagePtr msg);

#endif /* __VIR_KEEPALIVE_H__ */
