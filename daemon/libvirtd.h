/*
 * libvirtd.h: daemon data structure definitions
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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


#ifndef QEMUD_INTERNAL_H__
# define QEMUD_INTERNAL_H__

# include <config.h>

# include <rpc/types.h>
# include <rpc/xdr.h>
# include "remote_protocol.h"
# include "qemu_protocol.h"
# include "logging.h"
# include "threads.h"
# include "network.h"
# if HAVE_SASL
#  include "virnetsaslcontext.h"
# endif
# include "virnetserverprogram.h"

# if WITH_DTRACE
#  ifndef LIBVIRTD_PROBES_H
#   define LIBVIRTD_PROBES_H
#   include "probes.h"
#  endif /* LIBVIRTD_PROBES_H */

/* Systemtap 1.2 headers have a bug where they cannot handle a
 * variable declared with array type.  Work around this by casting all
 * arguments.  This is some gross use of the preprocessor because
 * PROBE is a var-arg macro, but it is better than the alternative of
 * making all callers to PROBE have to be aware of the issues.  And
 * hopefully, if we ever add a call to PROBE with other than 2 or 3
 * end arguments, you can figure out the pattern to extend this hack.
 */
#  define VIR_COUNT_ARGS(...) VIR_ARG5(__VA_ARGS__, 4, 3, 2, 1)
#  define VIR_ARG5(_1, _2, _3, _4, _5, ...) _5
#  define VIR_ADD_CAST_EXPAND(a, b, ...) VIR_ADD_CAST_PASTE(a, b, __VA_ARGS__)
#  define VIR_ADD_CAST_PASTE(a, b, ...) a##b(__VA_ARGS__)

/* The double cast is necessary to silence gcc warnings; any pointer
 * can safely go to intptr_t and back to void *, which collapses
 * arrays into pointers; while any integer can be widened to intptr_t
 * then cast to void *.  */
#  define VIR_ADD_CAST(a) ((void *)(intptr_t)(a))
#  define VIR_ADD_CAST2(a, b)                           \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b)
#  define VIR_ADD_CAST3(a, b, c)                        \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c)

#  define VIR_ADD_CASTS(...)                                            \
    VIR_ADD_CAST_EXPAND(VIR_ADD_CAST, VIR_COUNT_ARGS(__VA_ARGS__),      \
                        __VA_ARGS__)

#  define PROBE_EXPAND(NAME, ARGS) NAME(ARGS)
#  define PROBE(NAME, FMT, ...)                              \
    VIR_DEBUG_INT("trace." __FILE__ , __func__, __LINE__,    \
                  #NAME ": " FMT, __VA_ARGS__);              \
    if (LIBVIRTD_ ## NAME ## _ENABLED()) {                   \
        PROBE_EXPAND(LIBVIRTD_ ## NAME,                      \
                     VIR_ADD_CASTS(__VA_ARGS__));            \
    }
# else
#  define PROBE(NAME, FMT, ...)                              \
    VIR_DEBUG_INT("trace." __FILE__, __func__, __LINE__,     \
                  #NAME ": " FMT, __VA_ARGS__);
# endif

typedef struct daemonClientStream daemonClientStream;
typedef daemonClientStream *daemonClientStreamPtr;
typedef struct daemonClientPrivate daemonClientPrivate;
typedef daemonClientPrivate *daemonClientPrivatePtr;

/* Stores the per-client connection state */
struct daemonClientPrivate {
    /* Hold while accessing any data except conn */
    virMutex lock;

    int domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LAST];

# if HAVE_SASL
    virNetSASLSessionPtr sasl;
# endif

    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;

    daemonClientStreamPtr streams;
};

# if HAVE_SASL
extern virNetSASLContextPtr saslCtxt;
# endif
extern virNetServerProgramPtr remoteProgram;
extern virNetServerProgramPtr qemuProgram;

#endif
