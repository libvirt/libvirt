/* packet-libvirt.h --- Libvirt packet dissector header file.
 *
 * Copyright (C) 2013 Yuto KAWAMURA(kawamuray) <kawamuray.dadada@gmail.com>
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
 * Author: Yuto KAWAMURA(kawamuray)
 */
#ifndef _PACKET_LIBVIRT_H_
# define _PACKET_LIBVIRT_H_

# include "libvirt/libvirt.h"

# ifndef LIBVIRT_PORT
#  define LIBVIRT_PORT 16509
# endif

# define VIR_HEADER_LEN 28

# ifdef DEBUG
#  define dbg(fmt, ...) \
    g_print("[LIBVIRT] " fmt " at " __FILE__ " line %d\n", ##__VA_ARGS__, __LINE__)
# else
#  define dbg(fmt, ...)
# endif

typedef gboolean (*vir_xdr_dissector_t)(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);

typedef struct vir_dissector_index vir_dissector_index_t;
struct vir_dissector_index {
    guint32             proc;
    vir_xdr_dissector_t args;
    vir_xdr_dissector_t ret;
    vir_xdr_dissector_t msg;
};

enum vir_net_message_type {
    VIR_NET_CALL           = 0,
    VIR_NET_REPLY          = 1,
    VIR_NET_MESSAGE        = 2,
    VIR_NET_STREAM         = 3,
    VIR_NET_CALL_WITH_FDS  = 4,
    VIR_NET_REPLY_WITH_FDS = 5,
    VIR_NET_STREAM_HOLE    = 6,
};

enum vir_net_message_status {
    VIR_NET_OK       = 0,
    VIR_NET_ERROR    = 1,
    VIR_NET_CONTINUE = 2,
};

enum vir_program_data_index {
    VIR_PROGRAM_PROCHFVAR,
    VIR_PROGRAM_PROCSTRINGS,
    VIR_PROGRAM_DISSECTORS,
    VIR_PROGRAM_DISSECTORS_LEN,
    VIR_PROGRAM_LAST,
};

static const value_string type_strings[] = {
    { VIR_NET_CALL,           "CALL"           },
    { VIR_NET_REPLY,          "REPLY"          },
    { VIR_NET_MESSAGE,        "MESSAGE"        },
    { VIR_NET_STREAM,         "STREAM"         },
    { VIR_NET_CALL_WITH_FDS,  "CALL_WITH_FDS"  },
    { VIR_NET_REPLY_WITH_FDS, "REPLY_WITH_FDS" },
    { VIR_NET_STREAM_HOLE,    "STREAM_HOLE"    },
    { -1, NULL }
};

static const value_string status_strings[] = {
    { VIR_NET_OK,       "OK"       },
    { VIR_NET_ERROR,    "ERROR"    },
    { VIR_NET_CONTINUE, "CONTINUE" },
    { -1, NULL }
};

# define VIR_ERROR_MESSAGE_DISSECTOR dissect_xdr_remote_error

static gboolean dissect_xdr_int(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_int(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_short(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_short(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_char(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_char(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_hyper(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_u_hyper(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_float(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_double(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_bool(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf);
static gboolean dissect_xdr_string(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, guint32 maxlen);
static gboolean dissect_xdr_opaque(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, guint32 size);
static gboolean dissect_xdr_bytes(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, guint32 maxlen);
static gboolean dissect_xdr_pointer(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                                    vir_xdr_dissector_t dp);
static gboolean dissect_xdr_vector(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                                   int rhf, const gchar *rtype, guint32 size, vir_xdr_dissector_t dp);
static gboolean dissect_xdr_array(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                                  int rhf, const gchar *rtype, guint32 maxlen, vir_xdr_dissector_t dp);

# include "libvirt/protocol.h"

#endif /* _PACKET_LIBVIRT_H_ */
