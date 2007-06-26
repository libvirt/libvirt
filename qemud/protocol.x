/* -*- c -*-
 * protocol_xdr.x: wire protocol message format & data structures
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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


/* The first two words in the messages are length and program number
 * (previously called "magic").  This makes the protocol compatible
 * with the remote protocol, although beyond the first two words
 * the protocols are completely different.
 *
 * Note the length is the total number of bytes in the message
 * _including_ the length and program number.
 */

const QEMUD_PROGRAM = 0x20001A64;
const QEMUD_PKT_HEADER_XDR_LEN = 8;

struct qemud_packet_header {
  uint32_t length;
  uint32_t prog;
};
