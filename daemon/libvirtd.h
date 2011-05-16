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

# if HAVE_POLKIT0
#  include <dbus/dbus.h>
# endif

# include <rpc/types.h>
# include <rpc/xdr.h>
# include "remote_protocol.h"
# include "qemu_protocol.h"
# include "logging.h"
# include "threads.h"
# include "network.h"
# include "virnetsaslcontext.h"
# include "virnetserverprogram.h"

# if WITH_DTRACE
#  ifndef LIBVIRTD_PROBES_H
#   define LIBVIRTD_PROBES_H
#   include "probes.h"
#  endif /* LIBVIRTD_PROBES_H */
#  define PROBE(NAME, FMT, ...)                              \
    VIR_DEBUG_INT("trace." __FILE__ , __func__, __LINE__,    \
                  #NAME ": " FMT, __VA_ARGS__);              \
    if (LIBVIRTD_ ## NAME ## _ENABLED()) {                   \
        LIBVIRTD_ ## NAME(__VA_ARGS__);                      \
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

    virNetSASLSessionPtr sasl;

    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;

    daemonClientStreamPtr streams;
};

extern virNetSASLContextPtr saslCtxt;
extern virNetServerProgramPtr remoteProgram;
extern virNetServerProgramPtr qemuProgram;

/* Main server state */
struct qemud_server {
    int privileged;

    int sigread;
    int sigwrite;
    char *logDir;
    pthread_t eventThread;
    unsigned int hasEventThread :1;
    unsigned int quitEventThread :1;
# ifdef HAVE_AVAHI
    struct libvirtd_mdns *mdns;
# endif
# if HAVE_SASL
    char **saslUsernameWhitelist;
# endif
# if HAVE_POLKIT0
    DBusConnection *sysbus;
# endif
};


# if HAVE_POLKIT
int qemudGetSocketIdentity(int fd, uid_t *uid, pid_t *pid);
# endif

#endif
