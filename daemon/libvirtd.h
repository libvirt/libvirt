/*
 * libvirtd.h: daemon data structure definitions
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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


#ifndef LIBVIRTD_H__
# define LIBVIRTD_H__

# define VIR_ENUM_SENTINELS

# include <config.h>

# include <rpc/types.h>
# include <rpc/xdr.h>
# include "remote_protocol.h"
# include "qemu_protocol.h"
# include "logging.h"
# include "threads.h"
# if HAVE_SASL
#  include "virnetsaslcontext.h"
# endif
# include "virnetserverprogram.h"

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
    bool keepalive_supported;
};

# if HAVE_SASL
extern virNetSASLContextPtr saslCtxt;
# endif
extern virNetServerProgramPtr remoteProgram;
extern virNetServerProgramPtr qemuProgram;

#endif
