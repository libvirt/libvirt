/* -*- c -*-
 * virnetprotocol.x: basic protocol for all RPC services.
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 *
 * Author: Richard Jones <rjones@redhat.com>
 */

%#include "internal.h"
%#include "virxdrdefs.h"
%#include <arpa/inet.h>

/*----- Data types. -----*/

/* Initial message size.
 * When the message payload is larger this initial size will be
 * quadrupled until the maximum total message size is reached.
 */
const VIR_NET_MESSAGE_INITIAL = 65536;

/*
 * Until we enlarged the message buffers, this was the max
 * payload size. We need to remember this for compat with
 * old clients.
 */
const VIR_NET_MESSAGE_LEGACY_PAYLOAD_MAX = 262120;

/* Maximum total message size (serialised). */
const VIR_NET_MESSAGE_MAX = 33554432;

/* Size of struct virNetMessageHeader (serialised)*/
const VIR_NET_MESSAGE_HEADER_MAX = 24;

/* Size of message payload */
const VIR_NET_MESSAGE_PAYLOAD_MAX = 33554408;

/* Size of message length field. Not counted in VIR_NET_MESSAGE_MAX
 * and VIR_NET_MESSAGE_INITIAL.
 */
const VIR_NET_MESSAGE_LEN_MAX = 4;

/* Length of long, but not unbounded, strings.
 * This is an arbitrary limit designed to stop the decoder from trying
 * to allocate unbounded amounts of memory when fed with a bad message.
 */
const VIR_NET_MESSAGE_STRING_MAX = 4194304;

/* Limit on number of File Descriptors allowed to be
 * passed per message
 */
const VIR_NET_MESSAGE_NUM_FDS_MAX = 32;

/*
 * RPC wire format
 *
 * Each message consists of:
 *
 *    Name    | Type                  | Description
 * -----------+-----------------------+------------------
 *    Length  | int                   | Total number of bytes in message _including_ length.
 *    Header  | virNetMessageHeader   | Control information about procedure call
 *    Payload | -                     | Variable payload data per procedure
 *
 * In header, the 'serial' field varies according to:
 *
 *  - type == VIR_NET_CALL
 *      * serial is set by client, incrementing by 1 each time
 *
 *  - type == VIR_NET_REPLY
 *      * serial matches that from the corresponding VIR_NET_CALL
 *
 *  - type == VIR_NET_MESSAGE
 *      * serial is always zero
 *
 *  - type == VIR_NET_STREAM
 *      * serial matches that from the corresponding VIR_NET_CALL
 *
 * and the 'status' field varies according to:
 *
 *  - type == VIR_NET_CALL
 *     * VIR_NET_OK always
 *
 *  - type == VIR_NET_REPLY
 *     * VIR_NET_OK if RPC finished successfully
 *     * VIR_NET_ERROR if something failed
 *
 *  - type == VIR_NET_MESSAGE
 *     * VIR_NET_OK always
 *
 *  - type == VIR_NET_STREAM
 *     * VIR_NET_CONTINUE if more data is following
 *     * VIR_NET_OK if stream is complete
 *     * VIR_NET_ERROR
 *         server message: stream had an error
 *         client message: client aborted the stream
 *
 * Payload varies according to type and status:
 *
 *  - type == VIR_NET_CALL
 *          XXX_args  for procedure
 *
 *  - type == VIR_NET_REPLY
 *     * status == VIR_NET_OK
 *          XXX_ret         for procedure
 *     * status == VIR_NET_ERROR
 *          remote_error    Error information
 *
 *  - type == VIR_NET_MESSAGE
 *     * status == VIR_NET_OK
 *          XXX_msg        for event information
 *
 *  - type == VIR_NET_STREAM
 *     * status == VIR_NET_CONTINUE
 *          byte[]       raw stream data
 *     * status == VIR_NET_ERROR
 *          server message: remote_error error information
 *          client message: <empty>
 *     * status == VIR_NET_OK
 *          <empty>
 *
 *  - type == VIR_NET_CALL_WITH_FDS
 *          int8 - number of FDs
 *          XXX_args  for procedure
 *
 *  - type == VIR_NET_REPLY_WITH_FDS
 *          int8 - number of FDs
 *     * status == VIR_NET_OK
 *          XXX_ret         for procedure
 *     * status == VIR_NET_ERROR
 *          remote_error    Error information
 *
 *  - type == VIR_NET_STREAM_HOLE
 *     * status == VIR_NET_CONTINUE
 *          byte[]  hole data
 *     * status == VIR_NET_ERROR
 *          remote_error error information
 *     * status == VIR_NET_OK
 *          <empty>
 *
 */
enum virNetMessageType {
    /* client -> server. args from a method call */
    VIR_NET_CALL = 0,
    /* server -> client. reply/error from a method call */
    VIR_NET_REPLY = 1,
    /* either direction. async notification */
    VIR_NET_MESSAGE = 2,
    /* either direction. stream data packet */
    VIR_NET_STREAM = 3,
    /* client -> server. args from a method call, with passed FDs */
    VIR_NET_CALL_WITH_FDS = 4,
    /* server -> client. reply/error from a method call, with passed FDs */
    VIR_NET_REPLY_WITH_FDS = 5,
    /* either direction, stream hole data packet */
    VIR_NET_STREAM_HOLE = 6
};

enum virNetMessageStatus {
    /* Status is always VIR_NET_OK for calls.
     * For replies, indicates no error.
     */
    VIR_NET_OK = 0,

    /* For replies, indicates that an error happened, and a struct
     * remote_error follows.
     */
    VIR_NET_ERROR = 1,

    /* For streams, indicates that more data is still expected
     */
    VIR_NET_CONTINUE = 2
};

/* 4 byte length word per header */
const VIR_NET_MESSAGE_HEADER_XDR_LEN = 4;

struct virNetMessageHeader {
    unsigned prog;              /* Unique ID for the program */
    unsigned vers;              /* Program version number */
    int proc;                   /* Unique ID for the procedure within the program */
    virNetMessageType type;     /* Type of message */
    unsigned serial;            /* Serial number of message. */
    virNetMessageStatus status;
};

/* Error message. See <virterror.h> for explanation of fields. */

/* Most of these don't really belong here. There are sadly needed
 * for wire ABI backwards compatibility with the rather crazy
 * error struct we previously defined :-(
 */

typedef opaque virNetMessageUUID[VIR_UUID_BUFLEN];
typedef string virNetMessageNonnullString<VIR_NET_MESSAGE_STRING_MAX>;

/* A long string, which may be NULL. */
typedef virNetMessageNonnullString *virNetMessageString;

/* A domain which may not be NULL. */
struct virNetMessageNonnullDomain {
    virNetMessageNonnullString name;
    virNetMessageUUID uuid;
    int id;
};

/* A network which may not be NULL. */
struct virNetMessageNonnullNetwork {
    virNetMessageNonnullString name;
    virNetMessageUUID uuid;
};


typedef virNetMessageNonnullDomain *virNetMessageDomain;
typedef virNetMessageNonnullNetwork *virNetMessageNetwork;

/* NB. Fields "code", "domain" and "level" are really enums.  The
 * numeric value should remain compatible between libvirt and
 * libvirtd.  This means, no changing or reordering the enums as
 * defined in <virterror.h> (but we don't do that anyway, for separate
 * ABI reasons).
 */
struct virNetMessageError {
    int code;
    int domain;
    virNetMessageString message;
    int level;
    virNetMessageDomain dom; /* unused */
    virNetMessageString str1;
    virNetMessageString str2;
    virNetMessageString str3;
    int int1;
    int int2;
    virNetMessageNetwork net; /* unused */
};

struct virNetStreamHole {
    hyper length;
    unsigned int flags;
};
