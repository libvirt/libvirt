/*
 * virnetmessage.c: basic RPC message encoding/decoding
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <config.h>

#include <stdlib.h>

#include "virnetmessage.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"

#define VIR_FROM_THIS VIR_FROM_RPC
#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

virNetMessagePtr virNetMessageNew(bool tracked)
{
    virNetMessagePtr msg;

    if (VIR_ALLOC(msg) < 0) {
        virReportOOMError();
        return NULL;
    }

    msg->tracked = tracked;
    VIR_DEBUG("msg=%p tracked=%d", msg, tracked);

    return msg;
}


void virNetMessageClear(virNetMessagePtr msg)
{
    bool tracked = msg->tracked;
    memset(msg, 0, sizeof(*msg));
    msg->tracked = tracked;
}


void virNetMessageFree(virNetMessagePtr msg)
{
    if (!msg)
        return;

    if (msg->cb)
        msg->cb(msg, msg->opaque);

    VIR_DEBUG("msg=%p", msg);

    VIR_FREE(msg);
}

void virNetMessageQueuePush(virNetMessagePtr *queue, virNetMessagePtr msg)
{
    virNetMessagePtr tmp = *queue;

    if (tmp) {
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = msg;
    } else {
        *queue = msg;
    }
}


virNetMessagePtr virNetMessageQueueServe(virNetMessagePtr *queue)
{
    virNetMessagePtr tmp = *queue;

    if (tmp) {
        *queue = tmp->next;
        tmp->next = NULL;
    }

    return tmp;
}


int virNetMessageDecodeLength(virNetMessagePtr msg)
{
    XDR xdr;
    unsigned int len;
    int ret = -1;

    xdrmem_create(&xdr, msg->buffer,
                  msg->bufferLength, XDR_DECODE);
    if (!xdr_u_int(&xdr, &len)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to decode message length"));
        goto cleanup;
    }
    msg->bufferOffset = xdr_getpos(&xdr);

    if (len < VIR_NET_MESSAGE_LEN_MAX) {
        virNetError(VIR_ERR_RPC,
                    _("packet %d bytes received from server too small, want %d"),
                    len, VIR_NET_MESSAGE_LEN_MAX);
        goto cleanup;
    }

    /* Length includes length word - adjust to real length to read. */
    len -= VIR_NET_MESSAGE_LEN_MAX;

    if (len > VIR_NET_MESSAGE_MAX) {
        virNetError(VIR_ERR_RPC,
                    _("packet %d bytes received from server too large, want %d"),
                    len, VIR_NET_MESSAGE_MAX);
        goto cleanup;
    }

    /* Extend our declared buffer length and carry
       on reading the header + payload */
    msg->bufferLength += len;

    VIR_DEBUG("Got length, now need %zu total (%u more)",
              msg->bufferLength, len);

    ret = 0;

cleanup:
    xdr_destroy(&xdr);
    return ret;
}


/*
 * @msg: the complete incoming message, whose header to decode
 *
 * Decodes the header part of the message, but does not
 * validate the decoded fields in the header. It expects
 * bufferLength to refer to length of the data packet. Upon
 * return bufferOffset will refer to the amount of the packet
 * consumed by decoding of the header.
 *
 * returns 0 if successfully decoded, -1 upon fatal error
 */
int virNetMessageDecodeHeader(virNetMessagePtr msg)
{
    XDR xdr;
    int ret = -1;

    msg->bufferOffset = VIR_NET_MESSAGE_LEN_MAX;

    /* Parse the header. */
    xdrmem_create(&xdr,
                  msg->buffer + msg->bufferOffset,
                  msg->bufferLength - msg->bufferOffset,
                  XDR_DECODE);

    if (!xdr_virNetMessageHeader(&xdr, &msg->header)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to decode message header"));
        goto cleanup;
    }

    msg->bufferOffset += xdr_getpos(&xdr);

    ret = 0;

cleanup:
    xdr_destroy(&xdr);
    return ret;
}


/*
 * @msg: the outgoing message, whose header to encode
 *
 * Encodes the length word and header of the message, setting the
 * message offset ready to encode the payload. Leaves space
 * for the length field later. Upon return bufferLength will
 * refer to the total available space for message, while
 * bufferOffset will refer to current space used by header
 *
 * returns 0 if successfully encoded, -1 upon fatal error
 */
int virNetMessageEncodeHeader(virNetMessagePtr msg)
{
    XDR xdr;
    int ret = -1;
    unsigned int len = 0;

    msg->bufferLength = sizeof(msg->buffer);
    msg->bufferOffset = 0;

    /* Format the header. */
    xdrmem_create(&xdr,
                  msg->buffer,
                  msg->bufferLength,
                  XDR_ENCODE);

    /* The real value is filled in shortly */
    if (!xdr_u_int(&xdr, &len)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message length"));
        goto cleanup;
    }

    if (!xdr_virNetMessageHeader(&xdr, &msg->header)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message header"));
        goto cleanup;
    }

    len = xdr_getpos(&xdr);
    xdr_setpos(&xdr, 0);

    /* Fill in current length - may be re-written later
     * if a payload is added
     */
    if (!xdr_u_int(&xdr, &len)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to re-encode message length"));
        goto cleanup;
    }

    msg->bufferOffset += len;

    ret = 0;

cleanup:
    xdr_destroy(&xdr);
    return ret;
}


int virNetMessageEncodePayload(virNetMessagePtr msg,
                               xdrproc_t filter,
                               void *data)
{
    XDR xdr;
    unsigned int msglen;

    /* Serialise payload of the message. This assumes that
     * virNetMessageEncodeHeader has already been run, so
     * just appends to that data */
    xdrmem_create(&xdr, msg->buffer + msg->bufferOffset,
                  msg->bufferLength - msg->bufferOffset, XDR_ENCODE);

    if (!(*filter)(&xdr, data)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message payload"));
        goto error;
    }

    /* Get the length stored in buffer. */
    msg->bufferOffset += xdr_getpos(&xdr);
    xdr_destroy(&xdr);

    /* Re-encode the length word. */
    VIR_DEBUG("Encode length as %zu", msg->bufferOffset);
    xdrmem_create(&xdr, msg->buffer, VIR_NET_MESSAGE_HEADER_XDR_LEN, XDR_ENCODE);
    msglen = msg->bufferOffset;
    if (!xdr_u_int(&xdr, &msglen)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message length"));
        goto error;
    }
    xdr_destroy(&xdr);

    msg->bufferLength = msg->bufferOffset;
    msg->bufferOffset = 0;
    return 0;

error:
    xdr_destroy(&xdr);
    return -1;
}


int virNetMessageDecodePayload(virNetMessagePtr msg,
                               xdrproc_t filter,
                               void *data)
{
    XDR xdr;

    /* Deserialise payload of the message. This assumes that
     * virNetMessageDecodeHeader has already been run, so
     * just start from after that data */
    xdrmem_create(&xdr, msg->buffer + msg->bufferOffset,
                  msg->bufferLength - msg->bufferOffset, XDR_DECODE);

    if (!(*filter)(&xdr, data)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to decode message payload"));
        goto error;
    }

    /* Get the length stored in buffer. */
    msg->bufferLength += xdr_getpos(&xdr);
    xdr_destroy(&xdr);
    return 0;

error:
    xdr_destroy(&xdr);
    return -1;
}


int virNetMessageEncodePayloadRaw(virNetMessagePtr msg,
                                  const char *data,
                                  size_t len)
{
    XDR xdr;
    unsigned int msglen;

    if ((msg->bufferLength - msg->bufferOffset) < len) {
        virNetError(VIR_ERR_RPC,
                    _("Stream data too long to send (%zu bytes needed, %zu bytes available)"),
                    len, (msg->bufferLength - msg->bufferOffset));
        return -1;
    }

    memcpy(msg->buffer + msg->bufferOffset, data, len);
    msg->bufferOffset += len;

    /* Re-encode the length word. */
    VIR_DEBUG("Encode length as %zu", msg->bufferOffset);
    xdrmem_create(&xdr, msg->buffer, VIR_NET_MESSAGE_HEADER_XDR_LEN, XDR_ENCODE);
    msglen = msg->bufferOffset;
    if (!xdr_u_int(&xdr, &msglen)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message length"));
        goto error;
    }
    xdr_destroy(&xdr);

    msg->bufferLength = msg->bufferOffset;
    msg->bufferOffset = 0;
    return 0;

error:
    xdr_destroy(&xdr);
    return -1;
}


int virNetMessageEncodePayloadEmpty(virNetMessagePtr msg)
{
    XDR xdr;
    unsigned int msglen;

    /* Re-encode the length word. */
    VIR_DEBUG("Encode length as %zu", msg->bufferOffset);
    xdrmem_create(&xdr, msg->buffer, VIR_NET_MESSAGE_HEADER_XDR_LEN, XDR_ENCODE);
    msglen = msg->bufferOffset;
    if (!xdr_u_int(&xdr, &msglen)) {
        virNetError(VIR_ERR_RPC, "%s", _("Unable to encode message length"));
        goto error;
    }
    xdr_destroy(&xdr);

    msg->bufferLength = msg->bufferOffset;
    msg->bufferOffset = 0;
    return 0;

error:
    xdr_destroy(&xdr);
    return -1;
}


void virNetMessageSaveError(virNetMessageErrorPtr rerr)
{
    /* This func may be called several times & the first
     * error is the one we want because we don't want
     * cleanup code overwriting the first one.
     */
    if (rerr->code != VIR_ERR_OK)
        return;

    virErrorPtr verr = virGetLastError();
    if (verr) {
        rerr->code = verr->code;
        rerr->domain = verr->domain;
        rerr->message = verr->message ? malloc(sizeof(char*)) : NULL;
        if (rerr->message) *rerr->message = strdup(verr->message);
        rerr->level = verr->level;
        rerr->str1 = verr->str1 ? malloc(sizeof(char*)) : NULL;
        if (rerr->str1) *rerr->str1 = strdup(verr->str1);
        rerr->str2 = verr->str2 ? malloc(sizeof(char*)) : NULL;
        if (rerr->str2) *rerr->str2 = strdup(verr->str2);
        rerr->str3 = verr->str3 ? malloc(sizeof(char*)) : NULL;
        if (rerr->str3) *rerr->str3 = strdup(verr->str3);
        rerr->int1 = verr->int1;
        rerr->int2 = verr->int2;
    } else {
        rerr->code = VIR_ERR_INTERNAL_ERROR;
        rerr->domain = VIR_FROM_RPC;
        rerr->message = malloc(sizeof(char*));
        if (rerr->message) *rerr->message = strdup(_("Library function returned error but did not set virError"));
        rerr->level = VIR_ERR_ERROR;
    }
}
