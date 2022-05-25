/*
 * virnetmessage.h: basic RPC message encoding/decoding
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "virnetprotocol.h"

typedef struct _virNetMessage virNetMessage;

typedef void (*virNetMessageFreeCallback)(virNetMessage *msg, void *opaque);

struct _virNetMessage {
    bool tracked;

    char *buffer; /* Initially VIR_NET_MESSAGE_INITIAL + VIR_NET_MESSAGE_LEN_MAX */
                  /* Maximum   VIR_NET_MESSAGE_MAX     + VIR_NET_MESSAGE_LEN_MAX */
    size_t bufferLength;
    size_t bufferOffset;

    virNetMessageHeader header;

    virNetMessageFreeCallback cb;
    void *opaque;

    size_t nfds;
    int *fds;
    size_t donefds;

    virNetMessage *next;
};


virNetMessage *virNetMessageNew(bool tracked);

void virNetMessageClearFDs(virNetMessage *msg);
void virNetMessageClearPayload(virNetMessage *msg);

void virNetMessageClear(virNetMessage *);

void virNetMessageFree(virNetMessage *msg);

virNetMessage *virNetMessageQueueServe(virNetMessage **queue)
    ATTRIBUTE_NONNULL(1);
void virNetMessageQueuePush(virNetMessage **queue,
                            virNetMessage *msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virNetMessageEncodeHeader(virNetMessage *msg)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetMessageDecodeLength(virNetMessage *msg)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;
int virNetMessageDecodeHeader(virNetMessage *msg)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

int virNetMessageEncodePayload(virNetMessage *msg,
                               xdrproc_t filter,
                               void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;
int virNetMessageDecodePayload(virNetMessage *msg,
                               xdrproc_t filter,
                               void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(2) G_GNUC_WARN_UNUSED_RESULT;

int virNetMessageEncodeNumFDs(virNetMessage *msg);
int virNetMessageDecodeNumFDs(virNetMessage *msg);

int virNetMessageEncodePayloadRaw(virNetMessage *msg,
                                  const char *buf,
                                  size_t len)
    ATTRIBUTE_NONNULL(1) G_GNUC_WARN_UNUSED_RESULT;

void virNetMessageSaveError(struct virNetMessageError *rerr)
    ATTRIBUTE_NONNULL(1);

int virNetMessageDupFD(virNetMessage *msg,
                       size_t slot);

int virNetMessageAddFD(virNetMessage *msg,
                       int fd);
