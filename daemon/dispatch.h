/*
 * dispatch.h: RPC message dispatching infrastructure
 *
 * Copyright (C) 2007, 2008, 2009 Red Hat, Inc.
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
 * Author: Richard W.M. Jones <rjones@redhat.com>
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __LIBVIRTD_DISPATCH_H__
#define __LIBVIRTD_DISPATCH_H__


#include "libvirtd.h"


int
remoteDecodeClientMessageHeader (struct qemud_client_message *req);
int
remoteEncodeClientMessageHeader (struct qemud_client_message *req);

int
remoteDispatchClientRequest (struct qemud_server *server,
                             struct qemud_client *client,
                             struct qemud_client_message *req);


void remoteDispatchFormatError (remote_error *rerr,
                                const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(2, 3);

void remoteDispatchAuthError (remote_error *rerr);
void remoteDispatchGenericError (remote_error *rerr);
void remoteDispatchOOMError (remote_error *rerr);
void remoteDispatchConnError (remote_error *rerr,
                              virConnectPtr conn);


int
remoteSerializeReplyError(struct qemud_client *client,
                          remote_error *rerr,
                          remote_message_header *req);
int
remoteSerializeStreamError(struct qemud_client *client,
                           remote_error *rerr,
                           int proc,
                           int serial);

/* Having this here is dubious. It should be in remote.h
 * but qemud.c shouldn't depend on that header directly.
 * Refactor this later to deal with this properly.
 */
int remoteRelayDomainEvent (virConnectPtr conn ATTRIBUTE_UNUSED,
                            virDomainPtr dom,
                            int event,
                            int detail,
                            void *opaque);


int
remoteSendStreamData(struct qemud_client *client,
                     struct qemud_client_stream *stream,
                     const char *data,
                     unsigned int len);

#endif /* __LIBVIRTD_DISPATCH_H__ */
