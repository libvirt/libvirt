/*
 * stream.h: APIs for managing client streams
 *
 * Copyright (C) 2009 Red Hat, Inc.
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */


#ifndef __LIBVIRTD_STREAM_H__
#define __LIBVIRTD_STREAM_H__

#include "libvirtd.h"



struct qemud_client_stream *
remoteCreateClientStream(virConnectPtr conn,
                         remote_message_header *hdr);

void remoteFreeClientStream(struct qemud_client *client,
                            struct qemud_client_stream *stream);

int remoteAddClientStream(struct qemud_client *client,
                          struct qemud_client_stream *stream,
                          int transmit);

struct qemud_client_stream *
remoteFindClientStream(struct qemud_client *client,
                       virStreamPtr stream);

int
remoteRemoveClientStream(struct qemud_client *client,
                         struct qemud_client_stream *stream);

void
remoteStreamMessageFinished(struct qemud_client *client,
                            struct qemud_client_message *msg);

#endif /* __LIBVIRTD_STREAM_H__ */
