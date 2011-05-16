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

# include <gnutls/gnutls.h>
# include <gnutls/x509.h>
# include "gnutls_1_0_compat.h"
# if HAVE_SASL
#  include <sasl/sasl.h>
# endif

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

# ifdef __GNUC__
#  ifdef HAVE_ANSIDECL_H
#   include <ansidecl.h>
#  endif

#  ifndef __GNUC_PREREQ
#   if defined __GNUC__ && defined __GNUC_MINOR__
#    define __GNUC_PREREQ(maj, min)                                        \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#   else
#    define __GNUC_PREREQ(maj,min) 0
#   endif
#  endif

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
#  ifndef ATTRIBUTE_UNUSED
#   define ATTRIBUTE_UNUSED __attribute__((__unused__))
#  endif

/**
 * ATTRIBUTE_FMT_PRINTF
 *
 * Macro used to check printf like functions, if compiling
 * with gcc.
 *
 * We use gnulib which guarentees we always have GNU style
 * printf format specifiers even on broken Win32 platforms
 * hence we have to force 'gnu_printf' for new GCC
 */
#  ifndef ATTRIBUTE_FMT_PRINTF
#   if __GNUC_PREREQ (4, 4)
#    define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (gnu_printf, fmtpos,argpos)))
#   else
#    define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (printf, fmtpos,argpos)))
#   endif
#  endif

#  ifndef ATTRIBUTE_RETURN_CHECK
#   if __GNUC_PREREQ (3, 4)
#    define ATTRIBUTE_RETURN_CHECK __attribute__((__warn_unused_result__))
#   else
#    define ATTRIBUTE_RETURN_CHECK
#   endif
#  endif

# else
#  ifndef ATTRIBUTE_UNUSED
#   define ATTRIBUTE_UNUSED
#  endif
#  ifndef ATTRIBUTE_FMT_PRINTF
#   define ATTRIBUTE_FMT_PRINTF(...)
#  endif
#  ifndef ATTRIBUTE_RETURN_CHECK
#   define ATTRIBUTE_RETURN_CHECK
#  endif
# endif

/* Whether we're passing reads & writes through a sasl SSF */
enum qemud_sasl_ssf {
    QEMUD_SASL_SSF_NONE = 0,
    QEMUD_SASL_SSF_READ = 1,
    QEMUD_SASL_SSF_WRITE = 2,
};

enum qemud_sock_type {
    QEMUD_SOCK_TYPE_UNIX = 0,
    QEMUD_SOCK_TYPE_TCP = 1,
    QEMUD_SOCK_TYPE_TLS = 2,
};

struct qemud_client_message {
    char buffer [REMOTE_MESSAGE_MAX + REMOTE_MESSAGE_HEADER_XDR_LEN];
    unsigned int bufferLength;
    unsigned int bufferOffset;

    unsigned int async : 1;
    unsigned int streamTX : 1;

    remote_message_header hdr;

    struct qemud_client_message *next;
};

struct qemud_client;

/* Allow for filtering of incoming messages to a custom
 * dispatch processing queue, instead of client->dx.
 */
typedef int (*qemud_client_filter_func)(struct qemud_client *client,
                                        struct qemud_client_message *msg, void *opaque);
struct qemud_client_filter {
    qemud_client_filter_func query;
    void *opaque;

    struct qemud_client_filter *next;
};

struct qemud_client_stream {
    virStreamPtr st;
    int procedure;
    int serial;

    unsigned int recvEOF : 1;
    unsigned int closed : 1;

    struct qemud_client_filter filter;

    struct qemud_client_message *rx;
    int tx;

    struct qemud_client_stream *next;
};

/* Stores the per-client connection state */
struct qemud_client {
    virMutex lock;

    int magic;

    int fd;
    int watch;
    unsigned int readonly :1;
    unsigned int closing :1;
    int domainEventCallbackID[VIR_DOMAIN_EVENT_ID_LAST];

    virSocketAddr addr;
    const char *addrstr;

    int type; /* qemud_sock_type */
    gnutls_session_t tlssession;
    int auth;
    unsigned int handshake :1; /* If we're in progress for TLS handshake */
# if HAVE_SASL
    sasl_conn_t *saslconn;
    int saslSSF;
    const char *saslDecoded;
    unsigned int saslDecodedLength;
    unsigned int saslDecodedOffset;
    const char *saslEncoded;
    unsigned int saslEncodedLength;
    unsigned int saslEncodedOffset;
    char *saslUsername;
    char saslTemporary[8192]; /* temorary holds data to be decoded */
# endif

    /* Count of meages in 'dx' or 'tx' queue
     * ie RPC calls in progress. Does not count
     * async events which are not used for
     * throttling calculations */
    int nrequests;
    /* Zero or one messages being received. Zero if
     * nrequests >= max_clients and throttling */
    struct qemud_client_message *rx;
    /* Zero or many messages waiting for a worker
     * to process them */
    struct qemud_client_message *dx;
    /* Zero or many messages waiting for transmit
     * back to client, including async events */
    struct qemud_client_message *tx;
    /* Filters to capture messages that would otherwise
     * end up on the 'dx' queue */
    struct qemud_client_filter *filters;

    /* Data streams */
    struct qemud_client_stream *streams;


    /* This is only valid if a remote open call has been made on this
     * connection, otherwise it will be NULL.  Also if remote close is
     * called, it will be set back to NULL if that succeeds.
     */
    virConnectPtr conn;
    int refs;

};

# define QEMUD_CLIENT_MAGIC 0x7788aaee


struct qemud_socket {
    char *path;

    virSocketAddr addr;
    const char *addrstr;

    int fd;
    int watch;
    int readonly;
    int type; /* qemud_sock_type */
    int auth;

    struct qemud_socket *next;
};

struct qemud_worker {
    pthread_t thread;
    unsigned int hasThread :1;
    unsigned int processingCall :1;
    unsigned int quitRequest :1;

    /* back-pointer to our server */
    struct qemud_server *server;
};

/* Main server state */
struct qemud_server {
    virMutex lock;
    virCond job;

    int privileged;

    size_t nworkers;
    size_t nactiveworkers;
    struct qemud_worker *workers;
    size_t nsockets;
    struct qemud_socket *sockets;
    size_t nclients;
    size_t nclients_max;
    struct qemud_client **clients;

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

void qemudLog(int priority, const char *fmt, ...)
    ATTRIBUTE_FMT_PRINTF(2,3);



int qemudRegisterClientEvent(struct qemud_server *server,
                             struct qemud_client *client);
void qemudUpdateClientEvent(struct qemud_client *client);

void qemudDispatchClientFailure(struct qemud_client *client);

void
qemudClientMessageQueuePush(struct qemud_client_message **queue,
                            struct qemud_client_message *msg);
struct qemud_client_message *
qemudClientMessageQueueServe(struct qemud_client_message **queue);

void
qemudClientMessageRelease(struct qemud_client *client,
                          struct qemud_client_message *msg);


# if HAVE_POLKIT
int qemudGetSocketIdentity(int fd, uid_t *uid, pid_t *pid);
# endif

#endif
