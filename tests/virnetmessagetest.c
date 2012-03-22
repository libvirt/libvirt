/*
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <stdlib.h>
#include <signal.h>

#include "testutils.h"
#include "util.h"
#include "virterror_internal.h"
#include "memory.h"
#include "logging.h"

#include "rpc/virnetmessage.h"

#define VIR_FROM_THIS VIR_FROM_RPC

static int testMessageHeaderEncode(const void *args ATTRIBUTE_UNUSED)
{
    static virNetMessage msg;
    static const char expect[] = {
        0x00, 0x00, 0x00, 0x1c,  /* Length */
        0x11, 0x22, 0x33, 0x44,  /* Program */
        0x00, 0x00, 0x00, 0x01,  /* Version */
        0x00, 0x00, 0x06, 0x66,  /* Procedure */
        0x00, 0x00, 0x00, 0x00,  /* Type */
        0x00, 0x00, 0x00, 0x99,  /* Serial */
        0x00, 0x00, 0x00, 0x00,  /* Status */
    };
    memset(&msg, 0, sizeof(msg));

    msg.header.prog = 0x11223344;
    msg.header.vers = 0x01;
    msg.header.proc = 0x666;
    msg.header.type = VIR_NET_CALL;
    msg.header.serial = 0x99;
    msg.header.status = VIR_NET_OK;

    if (virNetMessageEncodeHeader(&msg) < 0)
        return -1;

    if (ARRAY_CARDINALITY(expect) != msg.bufferOffset) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  sizeof(expect), msg.bufferOffset);
        return -1;
    }

    if (msg.bufferLength != sizeof(msg.buffer)) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  sizeof(msg.buffer), msg.bufferLength);
        return -1;
    }

    if (memcmp(expect, msg.buffer, sizeof(expect)) != 0) {
        virtTestDifferenceBin(stderr, expect, msg.buffer, sizeof(expect));
        return -1;
    }

    return 0;
}

static int testMessageHeaderDecode(const void *args ATTRIBUTE_UNUSED)
{
    static virNetMessage msg = {
        .bufferOffset = 0,
        .bufferLength = 0x4,
        .buffer = {
            0x00, 0x00, 0x00, 0x1c,  /* Length */
            0x11, 0x22, 0x33, 0x44,  /* Program */
            0x00, 0x00, 0x00, 0x01,  /* Version */
            0x00, 0x00, 0x06, 0x66,  /* Procedure */
            0x00, 0x00, 0x00, 0x01,  /* Type */
            0x00, 0x00, 0x00, 0x99,  /* Serial */
            0x00, 0x00, 0x00, 0x01,  /* Status */
        },
        .header = { 0, 0, 0, 0, 0, 0 },
    };

    msg.header.prog = 0x11223344;
    msg.header.vers = 0x01;
    msg.header.proc = 0x666;
    msg.header.type = VIR_NET_CALL;
    msg.header.serial = 0x99;
    msg.header.status = VIR_NET_OK;

    if (virNetMessageDecodeLength(&msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        return -1;
    }

    if (msg.bufferOffset != 0x4) {
        VIR_DEBUG("Expecting offset %zu got %zu",
                  (size_t)4, msg.bufferOffset);
        return -1;
    }

    if (msg.bufferLength != 0x1c) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x1c, msg.bufferLength);
        return -1;
    }

    if (virNetMessageDecodeHeader(&msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        return -1;
    }

    if (msg.bufferOffset != msg.bufferLength) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  msg.bufferOffset, msg.bufferLength);
        return -1;
    }

    if (msg.header.prog != 0x11223344) {
        VIR_DEBUG("Expect prog %d got %d",
                  0x11223344, msg.header.prog);
        return -1;
    }
    if (msg.header.vers != 0x1) {
        VIR_DEBUG("Expect vers %d got %d",
                  0x11223344, msg.header.vers);
        return -1;
    }
    if (msg.header.proc != 0x666) {
        VIR_DEBUG("Expect proc %d got %d",
                  0x666, msg.header.proc);
        return -1;
    }
    if (msg.header.type != VIR_NET_REPLY) {
        VIR_DEBUG("Expect type %d got %d",
                  VIR_NET_REPLY, msg.header.type);
        return -1;
    }
    if (msg.header.serial != 0x99) {
        VIR_DEBUG("Expect serial %d got %d",
                  0x99, msg.header.serial);
        return -1;
    }
    if (msg.header.status != VIR_NET_ERROR) {
        VIR_DEBUG("Expect status %d got %d",
                  VIR_NET_ERROR, msg.header.status);
        return -1;
    }

    return 0;
}

static int testMessagePayloadEncode(const void *args ATTRIBUTE_UNUSED)
{
    virNetMessageError err;
    static virNetMessage msg;
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
    memset(&msg, 0, sizeof(msg));
    memset(&err, 0, sizeof(err));

    err.code = VIR_ERR_INTERNAL_ERROR;
    err.domain = VIR_FROM_RPC;
    err.level = VIR_ERR_ERROR;

    if (VIR_ALLOC(err.message) < 0)
        goto cleanup;
    *err.message = strdup("Hello World");
    if (VIR_ALLOC(err.str1) < 0)
        goto cleanup;
    *err.str1 = strdup("One");
    if (VIR_ALLOC(err.str2) < 0)
        goto cleanup;
    *err.str2 = strdup("Two");
    if (VIR_ALLOC(err.str3) < 0)
        goto cleanup;
    *err.str3 = strdup("Three");

    err.int1 = 1;
    err.int2 = 2;

    msg.header.prog = 0x11223344;
    msg.header.vers = 0x01;
    msg.header.proc = 0x666;
    msg.header.type = VIR_NET_MESSAGE;
    msg.header.serial = 0x99;
    msg.header.status = VIR_NET_ERROR;

    if (virNetMessageEncodeHeader(&msg) < 0)
        goto cleanup;

    if (virNetMessageEncodePayload(&msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0)
        goto cleanup;

    if (ARRAY_CARDINALITY(expect) != msg.bufferLength) {
        VIR_DEBUG("Expect message length %zu got %zu",
                  sizeof(expect), msg.bufferLength);
        goto cleanup;
    }

    if (msg.bufferOffset != 0) {
        VIR_DEBUG("Expect message offset 0 got %zu",
                  msg.bufferOffset);
        goto cleanup;
    }

    if (memcmp(expect, msg.buffer, sizeof(expect)) != 0) {
        virtTestDifferenceBin(stderr, expect, msg.buffer, sizeof(expect));
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
    return ret;
}

static int testMessagePayloadDecode(const void *args ATTRIBUTE_UNUSED)
{
    virNetMessageError err;
    static virNetMessage msg = {
        .bufferOffset = 0,
        .bufferLength = 0x4,
        .buffer = {
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
        },
        .header = { 0, 0, 0, 0, 0, 0 },
    };
    memset(&err, 0, sizeof(err));

    if (virNetMessageDecodeLength(&msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        return -1;
    }

    if (msg.bufferOffset != 0x4) {
        VIR_DEBUG("Expecting offset %zu got %zu",
                  (size_t)4, msg.bufferOffset);
        return -1;
    }

    if (msg.bufferLength != 0x74) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x74, msg.bufferLength);
        return -1;
    }

    if (virNetMessageDecodeHeader(&msg) < 0) {
        VIR_DEBUG("Failed to decode message header");
        return -1;
    }

    if (msg.bufferOffset != 28) {
        VIR_DEBUG("Expect message offset %zu got %zu",
                  msg.bufferOffset, (size_t)28);
        return -1;
    }

    if (msg.bufferLength != 0x74) {
        VIR_DEBUG("Expecting length %zu got %zu",
                  (size_t)0x1c, msg.bufferLength);
        return -1;
    }

    if (virNetMessageDecodePayload(&msg, (xdrproc_t)xdr_virNetMessageError, &err) < 0) {
        VIR_DEBUG("Failed to decode message payload");
        return -1;
    }

    if (err.code != VIR_ERR_INTERNAL_ERROR) {
        VIR_DEBUG("Expect code %d got %d",
                  VIR_ERR_INTERNAL_ERROR, err.code);
        return -1;
    }

    if (err.domain != VIR_FROM_RPC) {
        VIR_DEBUG("Expect domain %d got %d",
                  VIR_ERR_RPC, err.domain);
        return -1;
    }

    if (err.message == NULL ||
        STRNEQ(*err.message, "Hello World")) {
        VIR_DEBUG("Expect str1 'Hello World' got %s",
                  err.message ? *err.message : "(null)");
        return -1;
    }

    if (err.dom != NULL) {
        VIR_DEBUG("Expect NULL dom");
        return -1;
    }

    if (err.level != VIR_ERR_ERROR) {
        VIR_DEBUG("Expect leve %d got %d",
                  VIR_ERR_ERROR, err.level);
        return -1;
    }

    if (err.str1 == NULL ||
        STRNEQ(*err.str1, "One")) {
        VIR_DEBUG("Expect str1 'One' got %s",
                  err.str1 ? *err.str1 : "(null)");
        return -1;
    }

    if (err.str2 == NULL ||
        STRNEQ(*err.str2, "Two")) {
        VIR_DEBUG("Expect str3 'Two' got %s",
                  err.str2 ? *err.str2 : "(null)");
        return -1;
    }

    if (err.str3 == NULL ||
        STRNEQ(*err.str3, "Three")) {
        VIR_DEBUG("Expect str3 'Three' got %s",
                  err.str3 ? *err.str3 : "(null)");
        return -1;
    }

    if (err.int1 != 1) {
        VIR_DEBUG("Expect int1 1 got %d",
                  err.int1);
        return -1;
    }

    if (err.int2 != 2) {
        VIR_DEBUG("Expect int2 2 got %d",
                  err.int2);
        return -1;
    }

    if (err.net != NULL) {
        VIR_DEBUG("Expect NULL network");
        return -1;
    }

    xdr_free((xdrproc_t)xdr_virNetMessageError, (void*)&err);
    return 0;
}

static int testMessagePayloadStreamEncode(const void *args ATTRIBUTE_UNUSED)
{
    char stream[] = "The quick brown fox jumps over the lazy dog";
    static virNetMessage msg;
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
    memset(&msg, 0, sizeof(msg));

    msg.header.prog = 0x11223344;
    msg.header.vers = 0x01;
    msg.header.proc = 0x666;
    msg.header.type = VIR_NET_STREAM;
    msg.header.serial = 0x99;
    msg.header.status = VIR_NET_CONTINUE;

    if (virNetMessageEncodeHeader(&msg) < 0)
        return -1;

    if (virNetMessageEncodePayloadRaw(&msg, stream, strlen(stream)) < 0)
        return -1;

    if (ARRAY_CARDINALITY(expect) != msg.bufferLength) {
        VIR_DEBUG("Expect message length %zu got %zu",
                  sizeof(expect), msg.bufferLength);
        return -1;
    }

    if (msg.bufferOffset != 0) {
        VIR_DEBUG("Expect message offset 0 got %zu",
                  msg.bufferOffset);
        return -1;
    }

    if (memcmp(expect, msg.buffer, sizeof(expect)) != 0) {
        virtTestDifferenceBin(stderr, expect, msg.buffer, sizeof(expect));
        return -1;
    }

    return 0;
}


static int
mymain(void)
{
    int ret = 0;

    signal(SIGPIPE, SIG_IGN);

    if (virtTestRun("Message Header Encode", 1, testMessageHeaderEncode, NULL) < 0)
        ret = -1;

    if (virtTestRun("Message Header Decode", 1, testMessageHeaderDecode, NULL) < 0)
        ret = -1;

    if (virtTestRun("Message Payload Encode", 1, testMessagePayloadEncode, NULL) < 0)
        ret = -1;

    if (virtTestRun("Message Payload Decode", 1, testMessagePayloadDecode, NULL) < 0)
        ret = -1;

    if (virtTestRun("Message Payload Stream Encode", 1, testMessagePayloadStreamEncode, NULL) < 0)
        ret = -1;

    return ret==0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

VIRT_TEST_MAIN(mymain)
