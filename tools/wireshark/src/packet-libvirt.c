/* packet-libvirt.c --- Libvirt packet dissector routines.
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
 */
#include <config.h>

#include <wireshark/epan/proto.h>
#include <wireshark/epan/packet.h>
#include <wireshark/epan/dissectors/packet-tcp.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include "packet-libvirt.h"
#include "internal.h"

#ifndef LIBVIRT_PORT
# define LIBVIRT_PORT 16509
#endif

#define VIR_HEADER_LEN 28

#ifdef DEBUG
# define dbg(fmt, ...) \
   g_print("[LIBVIRT] " fmt " at " __FILE__ " line %d\n", ##__VA_ARGS__, __LINE__)
#else
# define dbg(fmt, ...)
#endif

static int proto_libvirt = -1;
static int hf_libvirt_length = -1;
static int hf_libvirt_program = -1;
static int hf_libvirt_version = -1;
static int hf_libvirt_procedure = -1;
static int hf_libvirt_type = -1;
static int hf_libvirt_serial = -1;
static int hf_libvirt_status = -1;
static int hf_libvirt_stream = -1;
static int hf_libvirt_num_of_fds = -1;
static int hf_libvirt_stream_hole_length = -1;
static int hf_libvirt_stream_hole_flags = -1;
static int hf_libvirt_stream_hole = -1;
int hf_libvirt_unknown = -1;
static gint ett_libvirt = -1;
static gint ett_libvirt_stream_hole = -1;

#define XDR_PRIMITIVE_DISSECTOR(xtype, ctype, ftype) \
    static gboolean \
    dissect_xdr_##xtype(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf) \
    { \
        goffset start; \
        ctype val; \
        start = xdr_getpos(xdrs); \
        if (xdr_##xtype(xdrs, &val)) { \
            proto_tree_add_##ftype(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val); \
            return TRUE; \
        } else { \
            proto_tree_add_item(tree, hf_libvirt_unknown, tvb, start, -1, ENC_NA); \
            return FALSE; \
        } \
    }

VIR_WARNINGS_NO_UNUSED_FUNCTION

XDR_PRIMITIVE_DISSECTOR(int,     gint32,   int)
XDR_PRIMITIVE_DISSECTOR(u_int,   guint32,  uint)
XDR_PRIMITIVE_DISSECTOR(short,   gint16,   int)
XDR_PRIMITIVE_DISSECTOR(u_short, guint16,  uint)
XDR_PRIMITIVE_DISSECTOR(char,    gchar,    int)
XDR_PRIMITIVE_DISSECTOR(u_char,  guchar,   uint)
XDR_PRIMITIVE_DISSECTOR(hyper,   quad_t,   int64)
XDR_PRIMITIVE_DISSECTOR(u_hyper, u_quad_t, uint64)
XDR_PRIMITIVE_DISSECTOR(float,   gfloat,   float)
XDR_PRIMITIVE_DISSECTOR(double,  gdouble,  double)
XDR_PRIMITIVE_DISSECTOR(bool,    bool_t,   boolean)

VIR_WARNINGS_RESET

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

static gboolean
dissect_xdr_string(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                   guint32 maxlen)
{
    goffset start;
    gchar *val = NULL;

    start = xdr_getpos(xdrs);
    if (xdr_string(xdrs, &val, maxlen)) {
        proto_tree_add_string(tree, hf, tvb, start, xdr_getpos(xdrs) - start, val);
        xdr_free((xdrproc_t)xdr_string, (char *)&val);
        return TRUE;
    } else {
        proto_tree_add_item(tree, hf_libvirt_unknown, tvb, start, -1, ENC_NA);
        return FALSE;
    }
}

static gboolean
dissect_xdr_opaque(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                   guint32 size)
{
    goffset start;
    gboolean rc;
    guint8 *val;

    val = g_malloc(size);
    start = xdr_getpos(xdrs);
    if ((rc = xdr_opaque(xdrs, (caddr_t)val, size))) {
        gint len = xdr_getpos(xdrs) - start;
        const char *s = tvb_bytes_to_str(wmem_packet_scope(), tvb, start, len);

        proto_tree_add_bytes_format_value(tree, hf, tvb, start, len, NULL, "%s", s);
    } else {
        proto_tree_add_item(tree, hf_libvirt_unknown, tvb, start, -1, ENC_NA);
    }

    g_free(val);
    return rc;
}

static gboolean
dissect_xdr_bytes(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                  guint32 maxlen)
{
    goffset start;
    guint8 *val = NULL;
    guint32 length;

    start = xdr_getpos(xdrs);
    if (xdr_bytes(xdrs, (char **)&val, &length, maxlen)) {
        gint len = xdr_getpos(xdrs) - start;
        const char *s = tvb_bytes_to_str(wmem_packet_scope(), tvb, start, len);

        proto_tree_add_bytes_format_value(tree, hf, tvb, start, len, NULL, "%s", s);
        free(val);
        return TRUE;
    } else {
        proto_tree_add_item(tree, hf_libvirt_unknown, tvb, start, -1, ENC_NA);
        return FALSE;
    }
}

static gboolean
dissect_xdr_pointer(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf,
                    vir_xdr_dissector_t dissect)
{
    goffset start;
    bool_t not_null;

    start = xdr_getpos(xdrs);
    if (!xdr_bool(xdrs, &not_null)) {
        proto_tree_add_item(tree, hf_libvirt_unknown, tvb, start, -1, ENC_NA);
        return FALSE;
    }
    if (not_null) {
        return dissect(tvb, tree, xdrs, hf);
    } else {
        proto_item *ti;
        ti = proto_tree_add_item(tree, hf, tvb, start, xdr_getpos(xdrs) - start, ENC_NA);
        proto_item_append_text(ti, ": (null)");
        return TRUE;
    }
}

static gboolean
dissect_xdr_iterable(tvbuff_t *tvb, proto_item *ti, XDR *xdrs, gint ett, int rhf,
                     guint32 length, vir_xdr_dissector_t dissect, goffset start)
{
    proto_tree *tree;
    guint32 i;

    tree = proto_item_add_subtree(ti, ett);
    for (i = 0; i < length; i++) {
        if (!dissect(tvb, tree, xdrs, rhf))
            return FALSE;
    }
    proto_item_set_len(ti, xdr_getpos(xdrs) - start);
    return TRUE;
}

static gboolean
dissect_xdr_vector(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                   int rhf, const gchar *rtype, guint32 size, vir_xdr_dissector_t dissect)
{
    goffset start;
    proto_item *ti;

    start = xdr_getpos(xdrs);
    ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
    proto_item_append_text(ti, " :: %s[%u]", rtype, size);
    return dissect_xdr_iterable(tvb, ti, xdrs, ett, rhf, size, dissect, start);
}

static gboolean
dissect_xdr_array(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf, gint ett,
                  int rhf, const gchar *rtype, guint32 maxlen, vir_xdr_dissector_t dissect)
{
    goffset start;
    proto_item *ti;
    guint32 length;

    start = xdr_getpos(xdrs);

    if (!xdr_u_int(xdrs, &length))
        return FALSE;
    if (length > maxlen)
        return FALSE;

    ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
    proto_item_append_text(ti, " :: %s<%u>", rtype, length);
    return dissect_xdr_iterable(tvb, ti, xdrs, ett, rhf, length, dissect, start);
}

static vir_xdr_dissector_t
find_payload_dissector(guint32 proc, guint32 type,
                       const vir_dissector_index_t *pds, gsize length)
{
    const vir_dissector_index_t *pd;
    guint32 first, last, direction;

    if (pds == NULL || length < 1)
        return NULL;

    first = pds[0].proc;
    last = pds[length-1].proc;
    if (proc < first || proc > last)
        return NULL;

    pd = &pds[proc-first];
    /* There is no guarantee to proc numbers has no gap */
    if (pd->proc != proc) {
        direction = (pd->proc < proc) ? 1 : -1;
        while (pd->proc != proc) {
            if (pd->proc == first || pd->proc == last)
                return NULL;
            pd += direction;
        }
    }

    switch (type) {
    case VIR_NET_CALL:
    case VIR_NET_CALL_WITH_FDS:
        return pd->args;
    case VIR_NET_REPLY:
    case VIR_NET_REPLY_WITH_FDS:
        return pd->ret;
    case VIR_NET_MESSAGE:
        return pd->msg;
    }
    return NULL;
}

static void
dissect_libvirt_stream(tvbuff_t *tvb, proto_tree *tree, gint payload_length)
{
    proto_tree_add_item(tree, hf_libvirt_stream, tvb, VIR_HEADER_LEN,
                        payload_length - VIR_HEADER_LEN, ENC_NA);
}

static gint32
dissect_libvirt_num_of_fds(tvbuff_t *tvb, proto_tree *tree)
{
    gint32 nfds;
    nfds = tvb_get_ntohl(tvb, VIR_HEADER_LEN);
    proto_tree_add_int(tree, hf_libvirt_num_of_fds, tvb, VIR_HEADER_LEN, 4, nfds);
    return nfds;
}

static void
dissect_libvirt_fds(tvbuff_t *tvb G_GNUC_UNUSED,
                    gint start G_GNUC_UNUSED,
                    gint32 nfds G_GNUC_UNUSED)
{
    /* TODO: NOP for now */
}

static void
dissect_libvirt_payload_xdr_data(tvbuff_t *tvb, proto_tree *tree, gint payload_length,
                                 gint32 status, vir_xdr_dissector_t dissect)
{
    gint32 nfds = 0;
    gint start = VIR_HEADER_LEN;
    tvbuff_t *payload_tvb;
    caddr_t payload_data;
    XDR xdrs;

    if (status == VIR_NET_CALL_WITH_FDS ||
        status == VIR_NET_REPLY_WITH_FDS) {
        nfds = dissect_libvirt_num_of_fds(tvb, tree);
        start += 4;
        payload_length -= 4;
    }

    payload_tvb = tvb_new_subset_remaining(tvb, start);
    payload_data = (caddr_t)tvb_memdup(NULL, payload_tvb, 0, payload_length);
    xdrmem_create(&xdrs, payload_data, payload_length, XDR_DECODE);

    dissect(payload_tvb, tree, &xdrs, -1);

    xdr_destroy(&xdrs);
    g_free(payload_data);

    if (nfds != 0)
        dissect_libvirt_fds(tvb, start + payload_length, nfds);
}

static gboolean
dissect_xdr_stream_hole(tvbuff_t *tvb, proto_tree *tree, XDR *xdrs, int hf)
{
    goffset start;
    proto_item *ti;

    start = xdr_getpos(xdrs);
    if (hf == -1) {
        ti = proto_tree_add_item(tree, hf_libvirt_stream_hole, tvb, start, -1, ENC_NA);
    } else {
        header_field_info *hfinfo;
        hfinfo = proto_registrar_get_nth(hf_libvirt_stream_hole);
        ti = proto_tree_add_item(tree, hf, tvb, start, -1, ENC_NA);
        proto_item_append_text(ti, " :: %s", hfinfo->name);
    }
    tree = proto_item_add_subtree(ti, ett_libvirt_stream_hole);

    hf = hf_libvirt_stream_hole_length;
    if (!dissect_xdr_hyper(tvb, tree, xdrs, hf)) return FALSE;

    hf = hf_libvirt_stream_hole_flags;
    if (!dissect_xdr_u_int(tvb, tree, xdrs, hf)) return FALSE;

    proto_item_set_len(ti, xdr_getpos(xdrs) - start);
    return TRUE;
}

#include "libvirt/protocol.h"

static void
dissect_libvirt_payload(tvbuff_t *tvb, proto_tree *tree,
                        guint32 prog, guint32 proc, guint32 type, guint32 status)
{
    gssize payload_length;

    payload_length = tvb_captured_length(tvb) - VIR_HEADER_LEN;
    if (payload_length <= 0)
        return; /* No payload */

    if (status == VIR_NET_OK) {
        const vir_dissector_index_t *pds = get_program_data(prog, VIR_PROGRAM_DISSECTORS);
        const gsize *len = get_program_data(prog, VIR_PROGRAM_DISSECTORS_LEN);
        vir_xdr_dissector_t xd;

        if (!len)
            goto unknown;

        xd = find_payload_dissector(proc, type, pds, *len);
        if (xd == NULL)
            goto unknown;
        dissect_libvirt_payload_xdr_data(tvb, tree, payload_length, status, xd);
    } else if (status == VIR_NET_ERROR) {
        dissect_libvirt_payload_xdr_data(tvb, tree, payload_length, status, dissect_xdr_remote_error);
    } else if (type == VIR_NET_STREAM) { /* implicitly, status == VIR_NET_CONTINUE */
        dissect_libvirt_stream(tvb, tree, payload_length);
    } else if (type == VIR_NET_STREAM_HOLE) {
        dissect_libvirt_payload_xdr_data(tvb, tree, payload_length, status, dissect_xdr_stream_hole);
    } else {
        goto unknown;
    }
    return;

 unknown:
    dbg("Cannot determine payload: Prog=%u, Proc=%u, Type=%u, Status=%u", prog, proc, type, status);
    proto_tree_add_item(tree, hf_libvirt_unknown, tvb, VIR_HEADER_LEN, -1, ENC_NA);
}

static int
dissect_libvirt_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        void *opaque G_GNUC_UNUSED)
{
    goffset offset;
    guint32 prog, proc, type, serial, status;
    const value_string *vs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Libvirt");
    col_clear(pinfo->cinfo, COL_INFO);

    offset = 4; /* End of length field */
    prog   = tvb_get_ntohl(tvb, offset); offset += 4;
    offset += 4; /* Ignore version header field */
    proc   = tvb_get_ntohl(tvb, offset); offset += 4;
    type   = tvb_get_ntohl(tvb, offset); offset += 4;
    serial = tvb_get_ntohl(tvb, offset); offset += 4;
    status = tvb_get_ntohl(tvb, offset); offset += 4;

    col_add_fstr(pinfo->cinfo, COL_INFO, "Prog=%s",
                 val_to_str(prog, program_strings, "%x"));

    vs = get_program_data(prog, VIR_PROGRAM_PROCSTRINGS);
    if (vs == NULL) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Proc=%u", proc);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Proc=%s", val_to_str(proc, vs, "%d"));
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " Type=%s Serial=%u Status=%s",
                    val_to_str(type, type_strings, "%d"), serial,
                    val_to_str(status, status_strings, "%d"));

    if (tree) {
        gint *hf_proc;
        proto_item *ti;
        proto_tree *libvirt_tree;

        ti = proto_tree_add_item(tree, proto_libvirt, tvb, 0, tvb_captured_length(tvb), ENC_NA);
        libvirt_tree = proto_item_add_subtree(ti, ett_libvirt);

        offset = 0;
        proto_tree_add_item(libvirt_tree, hf_libvirt_length,  tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_program, tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_version, tvb, offset, 4, ENC_NA); offset += 4;

        hf_proc = (int *)get_program_data(prog, VIR_PROGRAM_PROCHFVAR);
        if (hf_proc != NULL && *hf_proc != -1) {
            proto_tree_add_item(libvirt_tree, *hf_proc, tvb, offset, 4, ENC_NA);
        } else {
            /* No string representation, but still useful displaying proc number */
            proto_tree_add_item(libvirt_tree, hf_libvirt_procedure, tvb, offset, 4, ENC_NA);
        }
        offset += 4;

        proto_tree_add_item(libvirt_tree, hf_libvirt_type,    tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_serial,  tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(libvirt_tree, hf_libvirt_status,  tvb, offset, 4, ENC_NA); offset += 4;

        /* Dissect payload remaining */
        dissect_libvirt_payload(tvb, libvirt_tree, prog, proc, type, status);
    }

    return 0;
}

static guint
get_message_len(packet_info *pinfo G_GNUC_UNUSED, tvbuff_t *tvb, int offset, void *data G_GNUC_UNUSED)
{
    return tvb_get_ntohl(tvb, offset);
}

static int
dissect_libvirt(tvbuff_t *tvb, packet_info *pinfo,
                proto_tree *tree, void *data G_GNUC_UNUSED)
{
    /* Another magic const - 4; simply, how much bytes
     * is needed to tell the length of libvirt packet. */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4,
                     get_message_len, dissect_libvirt_message, NULL);

    return tvb_captured_length(tvb);
}

void
proto_register_libvirt(void)
{
    static hf_register_info hf[] = {
        { &hf_libvirt_length,
          { "length", "libvirt.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_program,
          { "program", "libvirt.program",
            FT_UINT32, BASE_HEX,
            VALS(program_strings), 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_version,
          { "version", "libvirt.version",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_procedure,
          { "procedure", "libvirt.procedure",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_type,
          { "type", "libvirt.type",
            FT_INT32, BASE_DEC,
            VALS(type_strings), 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_serial,
          { "serial", "libvirt.serial",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_status,
          { "status", "libvirt.status",
            FT_INT32, BASE_DEC,
            VALS(status_strings), 0x0,
            NULL, HFILL}
        },

        VIR_DYNAMIC_HFSET

        { &hf_libvirt_stream,
          { "stream", "libvirt.stream",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_num_of_fds,
          { "num_of_fds", "libvirt.num_of_fds",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_stream_hole,
          { "stream_hole", "libvirt.stream_hole",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_stream_hole_length,
          { "length", "libvirt.stream_hole.length",
            FT_INT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_stream_hole_flags,
          { "flags", "libvirt.stream_hole.flags",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_libvirt_unknown,
          { "unknown", "libvirt.unknown",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL}
        },
    };

    static gint *ett[] = {
        VIR_DYNAMIC_ETTSET
        &ett_libvirt_stream_hole,
        &ett_libvirt
    };

    proto_libvirt = proto_register_protocol(
        "Libvirt", /* name */
        "libvirt", /* short name */
        "libvirt"  /* abbrev */
    );

    proto_register_field_array(proto_libvirt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_libvirt(void)
{
    static dissector_handle_t libvirt_handle;

    libvirt_handle = create_dissector_handle(dissect_libvirt, proto_libvirt);
    dissector_add_uint("tcp.port", LIBVIRT_PORT, libvirt_handle);
}
