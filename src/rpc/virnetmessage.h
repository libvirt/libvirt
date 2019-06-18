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

typedef struct virNetMessageHeader *virNetMessageHeaderPtr;
typedef struct virNetMessageError *virNetMessageErrorPtr;

typedef struct _virNetMessage virNetMessage;
typedef virNetMessage *virNetMessagePtr;

typedef void (*virNetMessageFreeCallback)(virNetMessagePtr msg, void *opaque);

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

    virNetMessagePtr next;
};


virNetMessagePtr virNetMessageNew(bool tracked);

void virNetMessageClearPayload(virNetMessagePtr msg);

void virNetMessageClear(virNetMessagePtr);

void virNetMessageFree(virNetMessagePtr msg);

virNetMessagePtr virNetMessageQueueServe(virNetMessagePtr *queue)
    ATTRIBUTE_NONNULL(1);
void virNetMessageQueuePush(virNetMessagePtr *queue,
                            virNetMessagePtr msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2);

int virNetMessageEncodeHeader(virNetMessagePtr msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetMessageDecodeLength(virNetMessagePtr msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetMessageDecodeHeader(virNetMessagePtr msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

int virNetMessageEncodePayload(virNetMessagePtr msg,
                               xdrproc_t filter,
                               void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;
int virNetMessageDecodePayload(virNetMessagePtr msg,
                               xdrproc_t filter,
                               void *data)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(2) ATTRIBUTE_RETURN_CHECK;

int virNetMessageEncodeNumFDs(virNetMessagePtr msg);
int virNetMessageDecodeNumFDs(virNetMessagePtr msg);

int virNetMessageEncodePayloadRaw(virNetMessagePtr msg,
                                  const char *buf,
                                  size_t len)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;
int virNetMessageEncodePayloadEmpty(virNetMessagePtr msg)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_RETURN_CHECK;

void virNetMessageSaveError(virNetMessageErrorPtr rerr)
    ATTRIBUTE_NONNULL(1);

int virNetMessageDupFD(virNetMessagePtr msg,
                       size_t slot);

int virNetMessageAddFD(virNetMessagePtr msg,
                       int fd);
