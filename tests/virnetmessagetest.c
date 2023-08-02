/*
 * Copyright (C) 2011, 2014 Red Hat, Inc.
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

#include <config.h>

#include <signal.h>

#include "testutils.h"
#include "viralloc.h"
#include "virlog.h"
#include "rpc/virnetmessage.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("tests.netmessagetest");

static int testMessageHeaderEncode(const void *args G_GNUC_UNUSED)
{
    virNetMessage *msg = virNetMessageNew(true);
    static const char expect[] = {
        0x00, 0x00, 0x00, 0x1c,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x00,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x00,  /* Status */
    };
    /* According to doc to virNetMessageEncodeHeader(&msg):
     * msg->buffer will be this long */
    unsigned long msg_buf_size = VIR_NET_MESSAGE_INITIAL + VIR_NET_MESSAGE_LEN_MAX;
    int ret = -1;

    if (!msg)
        return -1;

    msg->header.prog = 0x11223344;
    msg->header.vers = 0x01;
    msg->header.proc = 0x666;
    msg->header.type = VIR_NET_CALL;
    msg->header.serial = 0x99;
    msg->header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto cleanup;

    if (G_N_ELEMENTS(expect) != msg->bufferOffset) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  sizeof(expect), msg->bufferOffset);
        goto cleanup;
    }

    if (msg->bufferLength != msg_buf_size) {
        VIR_DEBUG("Expect message offset %lu got %zu",
                  msg_buf_size, msg->bufferLength);
        goto cleanup;
    }

    if (memcmp(expect, msg->buffer, sizeof(expect)) != 0) {
        virTestDifferenceBin(stderr, expect, msg->buffer, sizeof(expect));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetMessageFree(msg);
    return ret;
}

static int testMessageHeaderDecode(const void *args G_GNUC_UNUSED)
{
    virNetMessage *msg = virNetMessageNew(true);
    static char input_buf [] =  {
        0x00, 0x00, 0x00, 0x1c,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x01,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x01,  /* Status */
    };
    int ret = -1;

    if (!msg)
        return -1;

    msg->bufferLength = 4;
    msg->buffer = g_new0(char, msg->bufferLength);
    memcpy(msg->buffer, input_buf, msg->bufferLength);

    msg->header.prog = 0x11223344;
    msg->header.vers = 0x01;
    msg->header.proc = 0x666;
    msg->header.type = VIR_NET_CALL;
    msg->header.serial = 0x99;
    msg->header.status = VIR_NET_OK;

    if (virNetMessageDecodeLength(msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        goto cleanup;
    }

    if (msg->bufferOffset != 0x4) {
        VIR_DEBUG("Expecting offset %zu got %zu",
                  (size_t)4, msg->bufferOffset);
        goto cleanup;
    }

    if (msg->bufferLength != 0x1c) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x1c, msg->bufferLength);
        goto cleanup;
    }

    memcpy(msg->buffer, input_buf, msg->bufferLength);

    if (virNetMessageDecodeHeader(msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        goto cleanup;
    }

    if (msg->bufferOffset != msg->bufferLength) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  msg->bufferOffset, msg->bufferLength);
        goto cleanup;
    }

    if (msg->header.prog != 0x11223344) {
        VIR_DEBUG("Expect prog %d got %d",
                  0x11223344, msg->header.prog);
        goto cleanup;
    }
    if (msg->header.vers != 0x1) {
        VIR_DEBUG("Expect vers %d got %d",
                  0x11223344, msg->header.vers);
        goto cleanup;
    }
    if (msg->header.proc != 0x666) {
        VIR_DEBUG("Expect proc %d got %d",
                  0x666, msg->header.proc);
        goto cleanup;
    }
    if (msg->header.type != VIR_NET_REPLY) {
        VIR_DEBUG("Expect type %d got %d",
                  VIR_NET_REPLY, msg->header.type);
        goto cleanup;
    }
    if (msg->header.serial != 0x99) {
        VIR_DEBUG("Expect serial %d got %d",
                  0x99, msg->header.serial);
        goto cleanup;
    }
    if (msg->header.status != VIR_NET_ERROR) {
        VIR_DEBUG("Expect status %d got %d",
                  VIR_NET_ERROR, msg->header.status);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetMessageFree(msg);
    return ret;
}

static int testMessagePayloadEncode(const void *args G_GNUC_UNUSED)
{
    virNetMessageError err = { 0 };
    virNetMessage *msg = virNetMessageNew(true);
    int ret = -1;
    static const char expect[] = {
        0x00, 0x00, 0x00, 0x74,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x02,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x01,  /* Status */

        0x00, 0x00, 0x00, 0x01,  /* Error code */
        0x00, 0x00, 0x00, 0x07,  /* Error domain */
        0x00, 0x00, 0x00, 0x01,  /* Error message pointer */
        0x00, 0x00, 0x00, 0x0b,  /* Error message length */
        'H', 'e', 'l', 'l',  /* Error message string */
        'o', ' ', 'W', 'o',
        'r', 'l', 'd', '\0',
        0x00, 0x00, 0x00, 0x02,  /* Error level */
        0x00, 0x00, 0x00, 0x00,  /* Error domain pointer */
        0x00, 0x00, 0x00, 0x01,  /* Error str1 pointer */
        0x00, 0x00, 0x00, 0x03,  /* Error str1 length */
        'O', 'n', 'e', '\0',  /* Error str1 message */
        0x00, 0x00, 0x00, 0x01,  /* Error str2 pointer */
        0x00, 0x00, 0x00, 0x03,  /* Error str2 length */
        'T', 'w', 'o', '\0',  /* Error str2 message */
        0x00, 0x00, 0x00, 0x01,  /* Error str3 pointer */
        0x00, 0x00, 0x00, 0x05,  /* Error str3 length */
        'T', 'h', 'r', 'e',  /* Error str3 message */
        'e', '\0', '\0', '\0',
        0x00, 0x00, 0x00, 0x01,  /* Error int1 */
        0x00, 0x00, 0x00, 0x02,  /* Error int2 */
        0x00, 0x00, 0x00, 0x00,  /* Error network pointer */
    };

    if (!msg)
        return -1;

    err.code = VIR_ERR_INTERNAL_ERROR;
    err.domain = VIR_FROM_RPC;
    err.level = VIR_ERR_ERROR;

    err.message = g_new0(char *, 1);
    err.str1 = g_new0(char *, 1);
    err.str2 = g_new0(char *, 1);
    err.str3 = g_new0(char *, 1);

    *err.message = g_strdup("Hello World");
    *err.str1 = g_strdup("One");
    *err.str2 = g_strdup("Two");
    *err.str3 = g_strdup("Three");

    err.int1 = 1;
    err.int2 = 2;

    msg->header.prog = 0x11223344;
    msg->header.vers = 0x01;
    msg->header.proc = 0x666;
    msg->header.type = VIR_NET_MESSAGE;
    msg->header.serial = 0x99;
    msg->header.status = VIR_NET_ERROR;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto cleanup;

    if (virNetMessageEncodePayload(msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0)
        goto cleanup;

    if (G_N_ELEMENTS(expect) != msg->bufferLength) {
        VIR_DEBUG("Expect message length %zu got %zu",
                  sizeof(expect), msg->bufferLength);
        goto cleanup;
    }

    if (msg->bufferOffset != 0) {
        VIR_DEBUG("Expect message offset 0 got %zu",
                  msg->bufferOffset);
        goto cleanup;
    }

    if (memcmp(expect, msg->buffer, sizeof(expect)) != 0) {
        virTestDifferenceBin(stderr, expect, msg->buffer, sizeof(expect));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    if (err.message)
        VIR_FREE(*err.message);
    if (err.str1)
        VIR_FREE(*err.str1);
    if (err.str2)
        VIR_FREE(*err.str2);
    if (err.str3)
        VIR_FREE(*err.str3);
    VIR_FREE(err.message);
    VIR_FREE(err.str1);
    VIR_FREE(err.str2);
    VIR_FREE(err.str3);
    virNetMessageFree(msg);
    return ret;
}

static int testMessagePayloadDecode(const void *args G_GNUC_UNUSED)
{
    virNetMessageError err = { 0 };
    virNetMessage *msg = virNetMessageNew(true);
    static char input_buffer[] = {
        0x00, 0x00, 0x00, 0x74,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x02,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x01,  /* Status */

        0x00, 0x00, 0x00, 0x01,  /* Error code */
        0x00, 0x00, 0x00, 0x07,  /* Error domain */
        0x00, 0x00, 0x00, 0x01,  /* Error message pointer */
        0x00, 0x00, 0x00, 0x0b,  /* Error message length */
        'H', 'e', 'l', 'l',  /* Error message string */
        'o', ' ', 'W', 'o',
        'r', 'l', 'd', '\0',
        0x00, 0x00, 0x00, 0x02,  /* Error level */
        0x00, 0x00, 0x00, 0x00,  /* Error domain pointer */
        0x00, 0x00, 0x00, 0x01,  /* Error str1 pointer */
        0x00, 0x00, 0x00, 0x03,  /* Error str1 length */
        'O', 'n', 'e', '\0',  /* Error str1 message */
        0x00, 0x00, 0x00, 0x01,  /* Error str2 pointer */
        0x00, 0x00, 0x00, 0x03,  /* Error str2 length */
        'T', 'w', 'o', '\0',  /* Error str2 message */
        0x00, 0x00, 0x00, 0x01,  /* Error str3 pointer */
        0x00, 0x00, 0x00, 0x05,  /* Error str3 length */
        'T', 'h', 'r', 'e',  /* Error str3 message */
        'e', '\0', '\0', '\0',
        0x00, 0x00, 0x00, 0x01,  /* Error int1 */
        0x00, 0x00, 0x00, 0x02,  /* Error int2 */
        0x00, 0x00, 0x00, 0x00,  /* Error network pointer */
    };
    int ret = -1;

    if (!msg)
        return -1;

    msg->bufferLength = 4;
    msg->buffer = g_new0(char, msg->bufferLength);
    memcpy(msg->buffer, input_buffer, msg->bufferLength);

    if (virNetMessageDecodeLength(msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        goto cleanup;
    }

    if (msg->bufferOffset != 0x4) {
        VIR_DEBUG("Expecting offset %zu got %zu",
                  (size_t)4, msg->bufferOffset);
        goto cleanup;
    }

    if (msg->bufferLength != 0x74) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x74, msg->bufferLength);
        goto cleanup;
    }

    memcpy(msg->buffer, input_buffer, msg->bufferLength);

    if (virNetMessageDecodeHeader(msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        goto cleanup;
    }

    if (msg->bufferOffset != 28) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  msg->bufferOffset, (size_t)28);
        goto cleanup;
    }

    if (msg->bufferLength != 0x74) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x1c, msg->bufferLength);
        goto cleanup;
    }

    if (virNetMessageDecodePayload(msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0) {
        VIR_DEBUG("Failed to decode message payload");
        goto cleanup;
    }

    if (err.code != VIR_ERR_INTERNAL_ERROR) {
        VIR_DEBUG("Expect code %d got %d",
                  VIR_ERR_INTERNAL_ERROR, err.code);
        goto cleanup;
    }

    if (err.domain != VIR_FROM_RPC) {
        VIR_DEBUG("Expect domain %d got %d",
                  VIR_ERR_RPC, err.domain);
        goto cleanup;
    }

    if (err.message == NULL ||
        STRNEQ(*err.message, "Hello World")) {
        VIR_DEBUG("Expect str1 'Hello World' got %s",
                  err.message ? *err.message : "(null)");
        goto cleanup;
    }

    if (err.dom != NULL) {
        VIR_DEBUG("Expect NULL dom");
        goto cleanup;
    }

    if (err.level != VIR_ERR_ERROR) {
        VIR_DEBUG("Expect leve %d got %d",
                  VIR_ERR_ERROR, err.level);
        goto cleanup;
    }

    if (err.str1 == NULL ||
        STRNEQ(*err.str1, "One")) {
        VIR_DEBUG("Expect str1 'One' got %s",
                  err.str1 ? *err.str1 : "(null)");
        goto cleanup;
    }

    if (err.str2 == NULL ||
        STRNEQ(*err.str2, "Two")) {
        VIR_DEBUG("Expect str3 'Two' got %s",
                  err.str2 ? *err.str2 : "(null)");
        goto cleanup;
    }

    if (err.str3 == NULL ||
        STRNEQ(*err.str3, "Three")) {
        VIR_DEBUG("Expect str3 'Three' got %s",
                  err.str3 ? *err.str3 : "(null)");
        goto cleanup;
    }

    if (err.int1 != 1) {
        VIR_DEBUG("Expect int1 1 got %d",
                  err.int1);
        goto cleanup;
    }

    if (err.int2 != 2) {
        VIR_DEBUG("Expect int2 2 got %d",
                  err.int2);
        goto cleanup;
    }

    if (err.net != NULL) {
        VIR_DEBUG("Expect NULL network");
        goto cleanup;
    }

    ret = 0;
 cleanup:
    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)&err);
    virNetMessageFree(msg);
    return ret;
}

static int testMessagePayloadStreamEncode(const void *args G_GNUC_UNUSED)
{
    char stream[] = "The quick brown fox jumps over the lazy dog";
    virNetMessage *msg = virNetMessageNew(true);
    static const char expect[] = {
        0x00, 0x00, 0x00, 0x47,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x03,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x02,  /* Status */

        'T', 'h', 'e', ' ',
        'q', 'u', 'i', 'c',
        'k', ' ', 'b', 'r',
        'o', 'w', 'n', ' ',
        'f', 'o', 'x', ' ',
        'j', 'u', 'm', 'p',
        's', ' ', 'o', 'v',
        'e', 'r', ' ', 't',
        'h', 'e', ' ', 'l',
        'a', 'z', 'y', ' ',
        'd', 'o', 'g',
    };
    int ret = -1;

    if (!msg)
        return -1;

    msg->header.prog = 0x11223344;
    msg->header.vers = 0x01;
    msg->header.proc = 0x666;
    msg->header.type = VIR_NET_STREAM;
    msg->header.serial = 0x99;
    msg->header.status = VIR_NET_CONTINUE;

    if (virNetMessageEncodeHeader(msg) < 0)
        goto cleanup;

    if (virNetMessageEncodePayloadRaw(msg, stream, strlen(stream)) < 0)
        goto cleanup;

    if (G_N_ELEMENTS(expect) != msg->bufferLength) {
        VIR_DEBUG("Expect message length %zu got %zu",
                  sizeof(expect), msg->bufferLength);
        goto cleanup;
    }

    if (msg->bufferOffset != 0) {
        VIR_DEBUG("Expect message offset 0 got %zu",
                  msg->bufferOffset);
        goto cleanup;
    }

    if (memcmp(expect, msg->buffer, sizeof(expect)) != 0) {
        virTestDifferenceBin(stderr, expect, msg->buffer, sizeof(expect));
        goto cleanup;
    }

    ret = 0;
 cleanup:
    virNetMessageFree(msg);
    return ret;
}


static int
mymain(void)
{
    int ret = 0;

#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif /* WIN32 */

    if (virTestRun("Message Header Encode", testMessageHeaderEncode, NULL) < 0)
        ret = -1;

    if (virTestRun("Message Header Decode", testMessageHeaderDecode, NULL) < 0)
        ret = -1;

    if (virTestRun("Message Payload Encode", testMessagePayloadEncode, NULL) < 0)
        ret = -1;

    if (virTestRun("Message Payload Decode", testMessagePayloadDecode, NULL) < 0)
        ret = -1;

    if (virTestRun("Message Payload Stream Encode", testMessagePayloadStreamEncode, NULL) < 0)
        ret = -1;

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIR_TEST_MAIN(mymain)
