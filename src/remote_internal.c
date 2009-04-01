/*
 * remote_internal.c: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2007-2009 Red Hat, Inc.
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
 * Author: Richard Jones <rjones@redhat.com>
 */

#include <config.h>

/* Windows socket compatibility functions. */
#include <errno.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef HAVE_WINSOCK2_H		/* Unix & Cygwin. */
# include <sys/un.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_PATHS_H
#include <paths.h>
#endif

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "gnutls_1_0_compat.h"
#if HAVE_SASL
#include <sasl/sasl.h>
#endif
#include <libxml/uri.h>

#include <netdb.h>

#include <poll.h>

/* AI_ADDRCONFIG is missing on some systems. */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "domain_event.h"
#include "driver.h"
#include "buf.h"
#include "qparams.h"
#include "remote_internal.h"
#include "remote_protocol.h"
#include "memory.h"
#include "util.h"
#include "event.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

#ifdef WIN32
#define pipe(fds) _pipe(fds,4096, _O_BINARY)
#endif


static int inside_daemon = 0;

struct remote_thread_call;


enum {
    REMOTE_MODE_WAIT_TX,
    REMOTE_MODE_WAIT_RX,
    REMOTE_MODE_COMPLETE,
    REMOTE_MODE_ERROR,
};

struct remote_thread_call {
    int mode;

    /* 4 byte length, followed by RPC message header+body */
    char buffer[4 + REMOTE_MESSAGE_MAX];
    unsigned int bufferLength;
    unsigned int bufferOffset;

    unsigned int serial;
    unsigned int proc_nr;

    virCond cond;

    xdrproc_t ret_filter;
    char *ret;

    remote_error err;

    struct remote_thread_call *next;
};

struct private_data {
    virMutex lock;

    int sock;                   /* Socket. */
    int watch;                  /* File handle watch */
    pid_t pid;                  /* PID of tunnel process */
    int uses_tls;               /* TLS enabled on socket? */
    gnutls_session_t session;   /* GnuTLS session (if uses_tls != 0). */
    char *type;                 /* Cached return from remoteType. */
    int counter;                /* Generates serial numbers for RPC. */
    int localUses;              /* Ref count for private data */
    char *hostname;             /* Original hostname */
    FILE *debugLog;             /* Debug remote protocol */

#if HAVE_SASL
    sasl_conn_t *saslconn;      /* SASL context */

    const char *saslDecoded;
    unsigned int saslDecodedLength;
    unsigned int saslDecodedOffset;

    const char *saslEncoded;
    unsigned int saslEncodedLength;
    unsigned int saslEncodedOffset;
#endif

    /* 4 byte length, followed by RPC message header+body */
    char buffer[4 + REMOTE_MESSAGE_MAX];
    unsigned int bufferLength;
    unsigned int bufferOffset;

    /* The list of domain event callbacks */
    virDomainEventCallbackListPtr callbackList;
    /* The queue of domain events generated
       during a call / response rpc          */
    virDomainEventQueuePtr domainEvents;
    /* Timer for flushing domainEvents queue */
    int eventFlushTimer;

    /* Self-pipe to wakeup threads waiting in poll() */
    int wakeupSendFD;
    int wakeupReadFD;

    /* List of threads currently waiting for dispatch */
    struct remote_thread_call *waitDispatch;
};

enum {
    REMOTE_CALL_IN_OPEN = 1,
    REMOTE_CALL_QUIET_MISSING_RPC = 2,
};


static void remoteDriverLock(struct private_data *driver)
{
    virMutexLock(&driver->lock);
}

static void remoteDriverUnlock(struct private_data *driver)
{
    virMutexUnlock(&driver->lock);
}

static int call (virConnectPtr conn, struct private_data *priv,
                 int flags, int proc_nr,
                 xdrproc_t args_filter, char *args,
                 xdrproc_t ret_filter, char *ret);
static int remoteAuthenticate (virConnectPtr conn, struct private_data *priv, int in_open,
                               virConnectAuthPtr auth, const char *authtype);
#if HAVE_SASL
static int remoteAuthSASL (virConnectPtr conn, struct private_data *priv, int in_open,
                           virConnectAuthPtr auth, const char *mech);
#endif
#if HAVE_POLKIT
static int remoteAuthPolkit (virConnectPtr conn, struct private_data *priv, int in_open,
                             virConnectAuthPtr auth);
#endif /* HAVE_POLKIT */
static void error (virConnectPtr conn, virErrorNumber code, const char *info);
static void errorf (virConnectPtr conn, virErrorNumber code,
                     const char *fmt, ...) ATTRIBUTE_FORMAT(printf, 3, 4);
static void server_error (virConnectPtr conn, remote_error *err);
static virDomainPtr get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network (virConnectPtr conn, remote_nonnull_network network);
static virStoragePoolPtr get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol);
static virNodeDevicePtr get_nonnull_node_device (virConnectPtr conn, remote_nonnull_node_device dev);
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr vol_src);
static void make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);
void remoteDomainEventFired(int watch, int fd, int event, void *data);
static void remoteDomainQueueEvent(virConnectPtr conn, XDR *xdr);
void remoteDomainEventQueueFlush(int timer, void *opaque);
/*----------------------------------------------------------------------*/

/* Helper functions for remoteOpen. */
static char *get_transport_from_scheme (char *scheme);

/* GnuTLS functions used by remoteOpen. */
static int initialise_gnutls (virConnectPtr conn);
static gnutls_session_t negotiate_gnutls_on_connection (virConnectPtr conn, struct private_data *priv, int no_verify);

#ifdef WITH_LIBVIRTD
static int
remoteStartup(void)
{
    /* Mark that we're inside the daemon so we can avoid
     * re-entering ourselves
     */
    inside_daemon = 1;
    return 0;
}
#endif

#ifndef WIN32
/**
 * remoteFindServerPath:
 *
 * Tries to find the path to the libvirtd binary.
 *
 * Returns path on success or NULL in case of error.
 */
static const char *
remoteFindDaemonPath(void)
{
    static const char *serverPaths[] = {
        SBINDIR "/libvirtd",
        SBINDIR "/libvirtd_dbg",
        NULL
    };
    int i;
    const char *customDaemon = getenv("LIBVIRTD_PATH");

    if (customDaemon)
        return(customDaemon);

    for (i = 0; serverPaths[i]; i++) {
        if (access(serverPaths[i], X_OK | R_OK) == 0) {
            return serverPaths[i];
        }
    }
    return NULL;
}

/**
 * qemuForkDaemon:
 *
 * Forks and try to launch the libvirtd daemon
 *
 * Returns 0 in case of success or -1 in case of detected error.
 */
static int
remoteForkDaemon(virConnectPtr conn)
{
    const char *daemonPath = remoteFindDaemonPath();
    const char *const daemonargs[] = { daemonPath, "--timeout=30", NULL };
    int ret, status;
    pid_t pid;

    if (!daemonPath) {
        error(conn, VIR_ERR_INTERNAL_ERROR, _("failed to find libvirtd binary"));
        return -1;
    }

    if (virExec(NULL, daemonargs, NULL, NULL,
                &pid, -1, NULL, NULL, VIR_EXEC_DAEMON) < 0)
        return -1;
    /*
     * do a waitpid on the intermediate process to avoid zombies.
     */
 retry_wait:
    ret = waitpid(pid, &status, 0);
    if (ret < 0) {
        if (errno == EINTR)
            goto retry_wait;
    }

    return 0;
}
#endif

enum virDrvOpenRemoteFlags {
    VIR_DRV_OPEN_REMOTE_RO = (1 << 0),
    VIR_DRV_OPEN_REMOTE_UNIX = (1 << 1),
    VIR_DRV_OPEN_REMOTE_USER = (1 << 2),
    VIR_DRV_OPEN_REMOTE_AUTOSTART = (1 << 3),
};

/* What transport? */
enum {
    trans_tls,
    trans_unix,
    trans_ssh,
    trans_ext,
    trans_tcp,
} transport;


static int
doRemoteOpen (virConnectPtr conn,
              struct private_data *priv,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              int flags)
{
    int wakeupFD[2] = { -1, -1 };
    char *transport_str = NULL;

    if (conn->uri) {
        if (!conn->uri->scheme)
            return VIR_DRV_OPEN_DECLINED;

        transport_str = get_transport_from_scheme (conn->uri->scheme);

        if (!transport_str || STRCASEEQ (transport_str, "tls"))
            transport = trans_tls;
        else if (STRCASEEQ (transport_str, "unix"))
            transport = trans_unix;
        else if (STRCASEEQ (transport_str, "ssh"))
            transport = trans_ssh;
        else if (STRCASEEQ (transport_str, "ext"))
            transport = trans_ext;
        else if (STRCASEEQ (transport_str, "tcp"))
            transport = trans_tcp;
        else {
            error (conn, VIR_ERR_INVALID_ARG,
                   _("remote_open: transport in URL not recognised "
                     "(should be tls|unix|ssh|ext|tcp)"));
            return VIR_DRV_OPEN_ERROR;
        }
    }

    if (!transport_str) {
        if ((!conn->uri || !conn->uri->server) &&
            (flags & VIR_DRV_OPEN_REMOTE_UNIX))
            transport = trans_unix;
        else
            return VIR_DRV_OPEN_DECLINED; /* Decline - not a remote URL. */
    }

    /* Local variables which we will initialise. These can
     * get freed in the failed: path.
     */
    char *name = NULL, *command = NULL, *sockname = NULL, *netcat = NULL;
    char *port = NULL, *authtype = NULL, *username = NULL;
    int no_verify = 0, no_tty = 0;
    char **cmd_argv = NULL;

    /* Return code from this function, and the private data. */
    int retcode = VIR_DRV_OPEN_ERROR;

    /* Remote server defaults to "localhost" if not specified. */
    if (conn->uri && conn->uri->port != 0) {
        if (virAsprintf(&port, "%d", conn->uri->port) == -1) goto out_of_memory;
    } else if (transport == trans_tls) {
        port = strdup (LIBVIRTD_TLS_PORT);
        if (!port) goto out_of_memory;
    } else if (transport == trans_tcp) {
        port = strdup (LIBVIRTD_TCP_PORT);
        if (!port) goto out_of_memory;
    } else
        port = NULL; /* Port not used for unix, ext., default for ssh */


    priv->hostname = strdup (conn->uri && conn->uri->server ?
                             conn->uri->server : "localhost");
    if (!priv->hostname)
        goto out_of_memory;
    if (conn->uri && conn->uri->user) {
        username = strdup (conn->uri->user);
        if (!username)
            goto out_of_memory;
    }

    /* Get the variables from the query string.
     * Then we need to reconstruct the query string (because
     * feasibly it might contain variables needed by the real driver,
     * although that won't be the case for now).
     */
    struct qparam_set *vars;
    struct qparam *var;
    int i;
    char *query;

    if (conn->uri) {
#ifdef HAVE_XMLURI_QUERY_RAW
        query = conn->uri->query_raw;
#else
        query = conn->uri->query;
#endif
        vars = qparam_query_parse (query);
        if (vars == NULL) goto failed;

        for (i = 0; i < vars->n; i++) {
            var = &vars->p[i];
            if (STRCASEEQ (var->name, "name")) {
                name = strdup (var->value);
                if (!name) goto out_of_memory;
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "command")) {
                command = strdup (var->value);
                if (!command) goto out_of_memory;
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "socket")) {
                sockname = strdup (var->value);
                if (!sockname) goto out_of_memory;
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "auth")) {
                authtype = strdup (var->value);
                if (!authtype) goto out_of_memory;
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "netcat")) {
                netcat = strdup (var->value);
                if (!netcat) goto out_of_memory;
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "no_verify")) {
                no_verify = atoi (var->value);
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "no_tty")) {
                no_tty = atoi (var->value);
                var->ignore = 1;
            } else if (STRCASEEQ (var->name, "debug")) {
                if (var->value &&
                    STRCASEEQ (var->value, "stdout"))
                    priv->debugLog = stdout;
                else
                    priv->debugLog = stderr;
            } else
                DEBUG("passing through variable '%s' ('%s') to remote end",
                      var->name, var->value);
        }

        /* Construct the original name. */
        if (!name) {
            if (STREQ(conn->uri->scheme, "remote") ||
                STRPREFIX(conn->uri->scheme, "remote+")) {
                /* Allow remote serve to probe */
                name = strdup("");
            } else {
                xmlURI tmpuri = {
                    .scheme = conn->uri->scheme,
#ifdef HAVE_XMLURI_QUERY_RAW
                    .query_raw = qparam_get_query (vars),
#else
                    .query = qparam_get_query (vars),
#endif
                    .path = conn->uri->path,
                    .fragment = conn->uri->fragment,
                };

                /* Evil, blank out transport scheme temporarily */
                if (transport_str) {
                    assert (transport_str[-1] == '+');
                    transport_str[-1] = '\0';
                }

                name = (char *) xmlSaveUri (&tmpuri);

#ifdef HAVE_XMLURI_QUERY_RAW
                VIR_FREE(tmpuri.query_raw);
#else
                VIR_FREE(tmpuri.query);
#endif

                /* Restore transport scheme */
                if (transport_str)
                    transport_str[-1] = '+';
            }
        }

        free_qparam_set (vars);
    } else {
        /* Probe URI server side */
        name = strdup("");
    }

    if (!name) {
        virReportOOMError(conn);
        goto failed;
    }

    DEBUG("proceeding with name = %s", name);

    /* For ext transport, command is required. */
    if (transport == trans_ext && !command) {
        error (conn, VIR_ERR_INVALID_ARG,
               _("remote_open: for 'ext' transport, command is required"));
        goto failed;
    }

    /* Connect to the remote service. */
    switch (transport) {
    case trans_tls:
        if (initialise_gnutls (conn) == -1) goto failed;
        priv->uses_tls = 1;

        /*FALLTHROUGH*/
    case trans_tcp: {
        // http://people.redhat.com/drepper/userapi-ipv6.html
        struct addrinfo *res, *r;
        struct addrinfo hints;
        int saved_errno = EINVAL;
        memset (&hints, 0, sizeof hints);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ADDRCONFIG;
        int e = getaddrinfo (priv->hostname, port, &hints, &res);
        if (e != 0) {
            errorf (conn, VIR_ERR_SYSTEM_ERROR,
                    _("unable to resolve hostname '%s': %s"),
                    priv->hostname, gai_strerror (e));
            goto failed;
        }

        /* Try to connect to each returned address in turn. */
        /* XXX This loop contains a subtle problem.  In the case
         * where a host is accessible over IPv4 and IPv6, it will
         * try the IPv4 and IPv6 addresses in turn.  However it
         * should be able to present different client certificates
         * (because the commonName field in a client cert contains
         * the client IP address, which is different for IPv4 and
         * IPv6).  At the moment we only have a single client
         * certificate, and no way to specify what address family
         * that certificate belongs to.
         */
        for (r = res; r; r = r->ai_next) {
            int no_slow_start = 1;

            priv->sock = socket (r->ai_family, SOCK_STREAM, 0);
            if (priv->sock == -1) {
                saved_errno = errno;
                continue;
            }

            /* Disable Nagle - Dan Berrange. */
            setsockopt (priv->sock,
                        IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                        sizeof no_slow_start);

            if (connect (priv->sock, r->ai_addr, r->ai_addrlen) == -1) {
                saved_errno = errno;
                close (priv->sock);
                continue;
            }

            if (priv->uses_tls) {
                priv->session =
                    negotiate_gnutls_on_connection
                      (conn, priv, no_verify);
                if (!priv->session) {
                    close (priv->sock);
                    priv->sock = -1;
                    continue;
                }
            }
            goto tcp_connected;
        }

        freeaddrinfo (res);
        virReportSystemError(conn, saved_errno,
                             _("unable to connect to '%s'"),
                             priv->hostname);
        goto failed;

       tcp_connected:
        freeaddrinfo (res);

        // NB. All versioning is done by the RPC headers, so we don't
        // need to worry (at this point anyway) about versioning.
        break;
    }

#ifndef WIN32
    case trans_unix: {
        if (!sockname) {
            if (flags & VIR_DRV_OPEN_REMOTE_USER) {
                char *userdir = virGetUserDirectory(conn, getuid());

                if (!userdir)
                    goto failed;

                if (virAsprintf(&sockname, "@%s" LIBVIRTD_USER_UNIX_SOCKET, userdir) < 0) {
                    VIR_FREE(userdir);
                    goto out_of_memory;
                }
                VIR_FREE(userdir);
            } else {
                if (flags & VIR_DRV_OPEN_REMOTE_RO)
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET_RO);
                else
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET);
                if (sockname == NULL)
                    goto out_of_memory;
            }
        }

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX(addr) (sizeof (addr).sun_path)
#endif
        struct sockaddr_un addr;
        int trials = 0;

        memset (&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        strncpy (addr.sun_path, sockname, UNIX_PATH_MAX (addr));
        if (addr.sun_path[0] == '@')
            addr.sun_path[0] = '\0';

      autostart_retry:
        priv->sock = socket (AF_UNIX, SOCK_STREAM, 0);
        if (priv->sock == -1) {
            virReportSystemError(conn, errno, "%s",
                                 _("unable to create socket"));
            goto failed;
        }
        if (connect (priv->sock, (struct sockaddr *) &addr, sizeof addr) == -1) {
            /* We might have to autostart the daemon in some cases....
             * It takes a short while for the daemon to startup, hence we
             * have a number of retries, with a small sleep. This will
             * sometimes cause multiple daemons to be started - this is
             * ok because the duplicates will fail to bind to the socket
             * and immediately exit, leaving just one daemon.
             */
            if (errno == ECONNREFUSED &&
                flags & VIR_DRV_OPEN_REMOTE_AUTOSTART &&
                trials < 20) {
                close(priv->sock);
                priv->sock = -1;
                if (trials > 0 ||
                    remoteForkDaemon(conn) == 0) {
                    trials++;
                    usleep(1000 * 100 * trials);
                    goto autostart_retry;
                }
            }
            virReportSystemError(conn, errno,
                                 _("unable to connect to '%s'"),
                                 sockname);
            goto failed;
        }

        break;
    }

    case trans_ssh: {
        int j, nr_args = 6;

        if (username) nr_args += 2; /* For -l username */
        if (no_tty) nr_args += 5;   /* For -T -o BatchMode=yes -e none */
        if (port) nr_args += 2;     /* For -p port */

        command = command ? command : strdup ("ssh");
        if (command == NULL)
            goto out_of_memory;

        // Generate the final command argv[] array.
        //   ssh [-p $port] [-l $username] $hostname $netcat -U $sockname [NULL]
        if (VIR_ALLOC_N(cmd_argv, nr_args) < 0)
            goto out_of_memory;

        j = 0;
        cmd_argv[j++] = strdup (command);
        if (port) {
            cmd_argv[j++] = strdup ("-p");
            cmd_argv[j++] = strdup (port);
        }
        if (username) {
            cmd_argv[j++] = strdup ("-l");
            cmd_argv[j++] = strdup (username);
        }
        if (no_tty) {
            cmd_argv[j++] = strdup ("-T");
            cmd_argv[j++] = strdup ("-o");
            cmd_argv[j++] = strdup ("BatchMode=yes");
            cmd_argv[j++] = strdup ("-e");
            cmd_argv[j++] = strdup ("none");
        }
        cmd_argv[j++] = strdup (priv->hostname);
        cmd_argv[j++] = strdup (netcat ? netcat : "nc");
        cmd_argv[j++] = strdup ("-U");
        cmd_argv[j++] = strdup (sockname ? sockname : LIBVIRTD_PRIV_UNIX_SOCKET);
        cmd_argv[j++] = 0;
        assert (j == nr_args);
        for (j = 0; j < (nr_args-1); j++)
            if (cmd_argv[j] == NULL)
                goto out_of_memory;
    }

        /*FALLTHROUGH*/
    case trans_ext: {
        pid_t pid;
        int sv[2];

        /* Fork off the external process.  Use socketpair to create a private
         * (unnamed) Unix domain socket to the child process so we don't have
         * to faff around with two file descriptors (a la 'pipe(2)').
         */
        if (socketpair (PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            virReportSystemError(conn, errno, "%s",
                                 _("unable to create socket pair"));
            goto failed;
        }

        if (virExec(conn, (const char**)cmd_argv, NULL, NULL,
                    &pid, sv[1], &(sv[1]), NULL, VIR_EXEC_NONE) < 0)
            goto failed;

        /* Parent continues here. */
        close (sv[1]);
        priv->sock = sv[0];
        priv->pid = pid;
    }
#else /* WIN32 */

    case trans_unix:
    case trans_ssh:
    case trans_ext:
        error (conn, VIR_ERR_INVALID_ARG,
               _("transport methods unix, ssh and ext are not supported under Windows"));
        goto failed;

#endif /* WIN32 */

    } /* switch (transport) */

    if (virSetNonBlock(priv->sock) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("unable to make socket non-blocking"));
        goto failed;
    }

    if (pipe(wakeupFD) < 0) {
        virReportSystemError(conn, errno, "%s",
                             _("unable to make pipe"));
        goto failed;
    }
    priv->wakeupReadFD = wakeupFD[0];
    priv->wakeupSendFD = wakeupFD[1];

    /* Try and authenticate with server */
    if (remoteAuthenticate(conn, priv, 1, auth, authtype) == -1)
        goto failed;

    /* Finally we can call the remote side's open function. */
    remote_open_args args = { &name, flags };

    if (call (conn, priv, REMOTE_CALL_IN_OPEN, REMOTE_PROC_OPEN,
              (xdrproc_t) xdr_remote_open_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto failed;

    /* Now try and find out what URI the daemon used */
    if (conn->uri == NULL) {
        remote_get_uri_ret uriret;
        int urierr;

        memset (&uriret, 0, sizeof uriret);
        urierr = call (conn, priv,
                       REMOTE_CALL_IN_OPEN | REMOTE_CALL_QUIET_MISSING_RPC,
                       REMOTE_PROC_GET_URI,
                       (xdrproc_t) xdr_void, (char *) NULL,
                       (xdrproc_t) xdr_remote_get_uri_ret, (char *) &uriret);
        if (urierr == -2) {
            /* Should not really happen, since we only probe local libvirtd's,
               & the library should always match the daemon. Only case is post
               RPM upgrade where an old daemon instance is still running with
               new client. Too bad. It is not worth the hassle to fix this */
            error (conn, VIR_ERR_INTERNAL_ERROR, _("unable to auto-detect URI"));
            goto failed;
        }
        if (urierr == -1) {
            goto failed;
        }

        DEBUG("Auto-probed URI is %s", uriret.uri);
        conn->uri = xmlParseURI(uriret.uri);
        VIR_FREE(uriret.uri);
        if (!conn->uri) {
            virReportOOMError (conn);
            goto failed;
        }
    }

    if(VIR_ALLOC(priv->callbackList)<0) {
        error(conn, VIR_ERR_INVALID_ARG, _("Error allocating callbacks list"));
        goto failed;
    }

    if(VIR_ALLOC(priv->domainEvents)<0) {
        error(conn, VIR_ERR_INVALID_ARG, _("Error allocating domainEvents"));
        goto failed;
    }

    DEBUG0("Adding Handler for remote events");
    /* Set up a callback to listen on the socket data */
    if ((priv->watch = virEventAddHandle(priv->sock,
                                         VIR_EVENT_HANDLE_READABLE,
                                         remoteDomainEventFired,
                                         conn, NULL)) < 0) {
        DEBUG0("virEventAddHandle failed: No addHandleImpl defined."
               " continuing without events.");
    } else {

        DEBUG0("Adding Timeout for remote event queue flushing");
        if ( (priv->eventFlushTimer = virEventAddTimeout(-1,
                                                         remoteDomainEventQueueFlush,
                                                         conn, NULL)) < 0) {
            DEBUG0("virEventAddTimeout failed: No addTimeoutImpl defined. "
                    "continuing without events.");
            virEventRemoveHandle(priv->watch);
            priv->watch = -1;
        }
    }
    /* Successful. */
    retcode = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    /* Free up the URL and strings. */
    VIR_FREE(name);
    VIR_FREE(command);
    VIR_FREE(sockname);
    VIR_FREE(authtype);
    VIR_FREE(netcat);
    VIR_FREE(username);
    VIR_FREE(port);
    if (cmd_argv) {
        char **cmd_argv_ptr = cmd_argv;
        while (*cmd_argv_ptr) {
            VIR_FREE(*cmd_argv_ptr);
            cmd_argv_ptr++;
        }
        VIR_FREE(cmd_argv);
    }

    return retcode;

 out_of_memory:
    virReportOOMError (conn);

 failed:
    /* Close the socket if we failed. */
    if (priv->sock >= 0) {
        if (priv->uses_tls && priv->session) {
            gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
            gnutls_deinit (priv->session);
        }
        close (priv->sock);
#ifndef WIN32
        if (priv->pid > 0) {
            pid_t reap;
            do {
                reap = waitpid(priv->pid, NULL, 0);
                if (reap == -1 && errno == EINTR)
                    continue;
            } while (reap != -1 && reap != priv->pid);
        }
#endif
    }

    if (wakeupFD[0] >= 0) {
        close(wakeupFD[0]);
        close(wakeupFD[1]);
    }

    VIR_FREE(priv->hostname);
    goto cleanup;
}

static struct private_data *
remoteAllocPrivateData(virConnectPtr conn)
{
    struct private_data *priv;
    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    if (virMutexInit(&priv->lock) < 0) {
        error(conn, VIR_ERR_INTERNAL_ERROR,
              _("cannot initialize mutex"));
        VIR_FREE(priv);
        return NULL;
    }
    remoteDriverLock(priv);
    priv->localUses = 1;
    priv->watch = -1;
    priv->sock = -1;

    return priv;
}

static int
remoteOpenSecondaryDriver(virConnectPtr conn,
                          virConnectAuthPtr auth,
                          int flags,
                          struct private_data **priv)
{
    int ret;
    int rflags = 0;

    if (!((*priv) = remoteAllocPrivateData(conn)))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;
    rflags |= VIR_DRV_OPEN_REMOTE_UNIX;

    ret = doRemoteOpen(conn, *priv, auth, rflags);
    if (ret != VIR_DRV_OPEN_SUCCESS) {
        remoteDriverUnlock(*priv);
        VIR_FREE(*priv);
    } else {
        (*priv)->localUses = 1;
        remoteDriverUnlock(*priv);
    }

    return ret;
}

static virDrvOpenStatus
remoteOpen (virConnectPtr conn,
            virConnectAuthPtr auth,
            int flags)
{
    struct private_data *priv;
    int ret, rflags = 0;

    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (!(priv = remoteAllocPrivateData(conn)))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

    /*
     * If no servername is given, and no +XXX
     * transport is listed, then force to a
     * local UNIX socket connection
     */
    if (conn->uri &&
        !conn->uri->server &&
        conn->uri->scheme &&
        !strchr(conn->uri->scheme, '+')) {
        DEBUG0("Auto-remote UNIX socket");
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
    }

    /*
     * If no servername is given, and no +XXX
     * transport is listed, or transport is unix,
     * and path is /session, and uid is unprivileged
     * then auto-spawn a daemon.
     */
    if (conn->uri &&
        !conn->uri->server &&
        conn->uri->path &&
        conn->uri->scheme &&
        ((strchr(conn->uri->scheme, '+') == 0)||
         (strstr(conn->uri->scheme, "+unix") != NULL)) &&
        STREQ(conn->uri->path, "/session") &&
        getuid() > 0) {
        DEBUG0("Auto-spawn user daemon instance");
        rflags |= VIR_DRV_OPEN_REMOTE_USER;
        rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
    }

    /*
     * If URI is NULL, then do a UNIX connection possibly auto-spawning
     * unprivileged server and probe remote server for URI. On Solaris,
     * this isn't supported, but we may be privileged enough to connect
     * to the UNIX socket anyway.
     */
    if (!conn->uri) {
        DEBUG0("Auto-probe remote URI");
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
#ifndef __sun
        if (getuid() > 0) {
            DEBUG0("Auto-spawn user daemon instance");
            rflags |= VIR_DRV_OPEN_REMOTE_USER;
            rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
        }
#endif
    }

    ret = doRemoteOpen(conn, priv, auth, rflags);
    if (ret != VIR_DRV_OPEN_SUCCESS) {
        conn->privateData = NULL;
        remoteDriverUnlock(priv);
        VIR_FREE(priv);
    } else {
        conn->privateData = priv;
        remoteDriverUnlock(priv);
    }
    return ret;
}


/* In a string "driver+transport" return a pointer to "transport". */
static char *
get_transport_from_scheme (char *scheme)
{
    char *p = strchr (scheme, '+');
    return p ? p+1 : 0;
}

/* GnuTLS functions used by remoteOpen. */
static gnutls_certificate_credentials_t x509_cred;


static int
check_cert_file (virConnectPtr conn, const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        virReportSystemError(conn, errno,
                             _("Cannot access %s '%s'"),
                             type, file);
        return -1;
    }
    return 0;
}


static int
initialise_gnutls (virConnectPtr conn)
{
    static int initialised = 0;
    int err;

    if (initialised) return 0;

    gnutls_global_init ();

    /* X509 stuff */
    err = gnutls_certificate_allocate_credentials (&x509_cred);
    if (err) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to allocate TLS credentials: %s"),
                gnutls_strerror (err));
        return -1;
    }


    if (check_cert_file(conn, "CA certificate", LIBVIRT_CACERT) < 0)
        return -1;
    if (check_cert_file(conn, "client key", LIBVIRT_CLIENTKEY) < 0)
        return -1;
    if (check_cert_file(conn, "client certificate", LIBVIRT_CLIENTCERT) < 0)
        return -1;

    /* Set the trusted CA cert. */
    DEBUG("loading CA file %s", LIBVIRT_CACERT);
    err =
        gnutls_certificate_set_x509_trust_file (x509_cred, LIBVIRT_CACERT,
                                                GNUTLS_X509_FMT_PEM);
    if (err < 0) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to load CA certificate: %s"),
                gnutls_strerror (err));
        return -1;
    }

    /* Set the client certificate and private key. */
    DEBUG("loading client cert and key from files %s and %s",
          LIBVIRT_CLIENTCERT, LIBVIRT_CLIENTKEY);
    err =
        gnutls_certificate_set_x509_key_file (x509_cred,
                                              LIBVIRT_CLIENTCERT,
                                              LIBVIRT_CLIENTKEY,
                                              GNUTLS_X509_FMT_PEM);
    if (err < 0) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to load private key/certificate: %s"),
                gnutls_strerror (err));
        return -1;
    }

    initialised = 1;
    return 0;
}

static int verify_certificate (virConnectPtr conn, struct private_data *priv, gnutls_session_t session);

static gnutls_session_t
negotiate_gnutls_on_connection (virConnectPtr conn,
                                struct private_data *priv,
                                int no_verify)
{
    const int cert_type_priority[3] = {
        GNUTLS_CRT_X509,
        GNUTLS_CRT_OPENPGP,
        0
    };
    int err;
    gnutls_session_t session;

    /* Initialize TLS session
     */
    err = gnutls_init (&session, GNUTLS_CLIENT);
    if (err) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to initialize TLS client: %s"),
                gnutls_strerror (err));
        return NULL;
    }

    /* Use default priorities */
    err = gnutls_set_default_priority (session);
    if (err) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to set TLS algorithm priority: %s"),
                gnutls_strerror (err));
        return NULL;
    }
    err =
        gnutls_certificate_type_set_priority (session,
                                              cert_type_priority);
    if (err) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to set certificate priority: %s"),
                gnutls_strerror (err));
        return NULL;
    }

    /* put the x509 credentials to the current session
     */
    err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (err) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to set session credentials: %s"),
                gnutls_strerror (err));
        return NULL;
    }

    gnutls_transport_set_ptr (session,
                              (gnutls_transport_ptr_t) (long) priv->sock);

    /* Perform the TLS handshake. */
 again:
    err = gnutls_handshake (session);
    if (err < 0) {
        if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED)
            goto again;
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to complete TLS handshake: %s"),
                gnutls_strerror (err));
        return NULL;
    }

    /* Verify certificate. */
    if (verify_certificate (conn, priv, session) == -1) {
        DEBUG0("failed to verify peer's certificate");
        if (!no_verify) return NULL;
    }

    /* At this point, the server is verifying _our_ certificate, IP address,
     * etc.  If we make the grade, it will send us a '\1' byte.
     */
    char buf[1];
    int len;
 again_2:
    len = gnutls_record_recv (session, buf, 1);
    if (len < 0 && len != GNUTLS_E_UNEXPECTED_PACKET_LENGTH) {
        if (len == GNUTLS_E_AGAIN || len == GNUTLS_E_INTERRUPTED)
            goto again_2;
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to complete TLS initialization: %s"),
                gnutls_strerror (len));
        return NULL;
    }
    if (len != 1 || buf[0] != '\1') {
        error (conn, VIR_ERR_RPC,
               _("server verification (of our certificate or IP address) failed\n"));
        return NULL;
    }

#if 0
    /* Print session info. */
    print_info (session);
#endif

    return session;
}

static int
verify_certificate (virConnectPtr conn ATTRIBUTE_UNUSED,
                    struct private_data *priv,
                    gnutls_session_t session)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    time_t now;

    if ((ret = gnutls_certificate_verify_peers2 (session, &status)) < 0) {
        errorf (conn, VIR_ERR_GNUTLS_ERROR,
                _("unable to verify server certificate: %s"),
                gnutls_strerror (ret));
        return -1;
    }

    if ((now = time(NULL)) == ((time_t)-1)) {
        virReportSystemError(conn, errno, "%s",
                             _("cannot get current time"));
        return -1;
    }

    if (status != 0) {
        const char *reason = _("Invalid certificate");

        if (status & GNUTLS_CERT_INVALID)
            reason = _("The certificate is not trusted.");

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            reason = _("The certificate hasn't got a known issuer.");

        if (status & GNUTLS_CERT_REVOKED)
            reason = _("The certificate has been revoked.");

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            reason = _("The certificate uses an insecure algorithm");
#endif

        errorf (conn, VIR_ERR_RPC,
                _("server certificate failed validation: %s"),
                reason);
        return -1;
    }

    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
        error (conn, VIR_ERR_RPC, _("Certificate type is not X.509"));
        return -1;
    }

    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        error (conn, VIR_ERR_RPC, _("gnutls_certificate_get_peers failed"));
        return -1;
    }

    for (i = 0 ; i < nCerts ; i++) {
        gnutls_x509_crt_t cert;

        ret = gnutls_x509_crt_init (&cert);
        if (ret < 0) {
            errorf (conn, VIR_ERR_GNUTLS_ERROR,
                    _("unable to initialize certificate: %s"),
                    gnutls_strerror (ret));
            return -1;
        }

        ret = gnutls_x509_crt_import (cert, &certs[i], GNUTLS_X509_FMT_DER);
        if (ret < 0) {
            errorf (conn, VIR_ERR_GNUTLS_ERROR,
                    _("unable to import certificate: %s"),
                    gnutls_strerror (ret));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            error (conn, VIR_ERR_RPC, _("The certificate has expired"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            error (conn, VIR_ERR_RPC, _("The certificate is not yet activated"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (i == 0) {
            if (!gnutls_x509_crt_check_hostname (cert, priv->hostname)) {
                errorf(conn, VIR_ERR_RPC,
                       _("Certificate's owner does not match the hostname (%s)"),
                       priv->hostname);
                gnutls_x509_crt_deinit (cert);
                return -1;
            }
        }
    }

    return 0;
}

/*----------------------------------------------------------------------*/


static int
doRemoteClose (virConnectPtr conn, struct private_data *priv)
{
    if (call (conn, priv, 0, REMOTE_PROC_CLOSE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    if (priv->eventFlushTimer >= 0) {
        /* Remove timeout */
        virEventRemoveTimeout(priv->eventFlushTimer);
        /* Remove handle for remote events */
        virEventRemoveHandle(priv->watch);
        priv->watch = -1;
    }

    /* Close socket. */
    if (priv->uses_tls && priv->session) {
        gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
        gnutls_deinit (priv->session);
    }
#if HAVE_SASL
    if (priv->saslconn)
        sasl_dispose (&priv->saslconn);
#endif
    close (priv->sock);

#ifndef WIN32
    if (priv->pid > 0) {
        pid_t reap;
        do {
            reap = waitpid(priv->pid, NULL, 0);
            if (reap == -1 && errno == EINTR)
                continue;
        } while (reap != -1 && reap != priv->pid);
    }
#endif
    if (priv->wakeupReadFD >= 0) {
        close(priv->wakeupReadFD);
        close(priv->wakeupSendFD);
    }


    /* Free hostname copy */
    free (priv->hostname);

    /* See comment for remoteType. */
    free (priv->type);

    /* Free callback list */
    virDomainEventCallbackListFree(priv->callbackList);

    /* Free queued events */
    virDomainEventQueueFree(priv->domainEvents);

    return 0;
}

static int
remoteClose (virConnectPtr conn)
{
    int ret = 0;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        ret = doRemoteClose(conn, priv);
        conn->privateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE (priv);
    }
    if (priv)
        remoteDriverUnlock(priv);

    return ret;
}

static int
remoteSupportsFeature (virConnectPtr conn, int feature)
{
    int rv = -1;
    remote_supports_feature_args args;
    remote_supports_feature_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    /* VIR_DRV_FEATURE_REMOTE* features are handled directly. */
    if (feature == VIR_DRV_FEATURE_REMOTE) {
        rv = 1;
        goto done;
    }

    args.feature = feature;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_SUPPORTS_FEATURE,
              (xdrproc_t) xdr_remote_supports_feature_args, (char *) &args,
              (xdrproc_t) xdr_remote_supports_feature_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.supported;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/* Unfortunately this function is defined to return a static string.
 * Since the remote end always answers with the same type (for a
 * single connection anyway) we cache the type in the connection's
 * private data, and free it when we close the connection.
 *
 * See also:
 * http://www.redhat.com/archives/libvir-list/2007-February/msg00096.html
 */
static const char *
remoteType (virConnectPtr conn)
{
    char *rv = NULL;
    remote_get_type_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    /* Cached? */
    if (priv->type) {
        rv = priv->type;
        goto done;
    }

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_TYPE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_type_ret, (char *) &ret) == -1)
        goto done;

    /* Stash. */
    rv = priv->type = ret.type;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteGetVersion (virConnectPtr conn, unsigned long *hvVer)
{
    int rv = -1;
    remote_get_version_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_VERSION,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_version_ret, (char *) &ret) == -1)
        goto done;

    if (hvVer) *hvVer = ret.hv_ver;
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteGetHostname (virConnectPtr conn)
{
    char *rv = NULL;
    remote_get_hostname_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_HOSTNAME,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_hostname_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees this. */
    rv = ret.hostname;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteGetMaxVcpus (virConnectPtr conn, const char *type)
{
    int rv = -1;
    remote_get_max_vcpus_args args;
    remote_get_max_vcpus_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    args.type = type == NULL ? NULL : (char **) &type;
    if (call (conn, priv, 0, REMOTE_PROC_GET_MAX_VCPUS,
              (xdrproc_t) xdr_remote_get_max_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_get_max_vcpus_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.max_vcpus;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info)
{
    int rv = -1;
    remote_node_get_info_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_INFO,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_node_get_info_ret, (char *) &ret) == -1)
        goto done;

    strncpy (info->model, ret.model, 32);
    info->model[31] = '\0';
    info->memory = ret.memory;
    info->cpus = ret.cpus;
    info->mhz = ret.mhz;
    info->nodes = ret.nodes;
    info->sockets = ret.sockets;
    info->cores = ret.cores;
    info->threads = ret.threads;
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteGetCapabilities (virConnectPtr conn)
{
    char *rv = NULL;
    remote_get_capabilities_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_CAPABILITIES,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_capabilities_ret, (char *)&ret) == -1)
        goto done;

    /* Caller frees this. */
    rv = ret.capabilities;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetCellsFreeMemory(virConnectPtr conn,
                            unsigned long long *freeMems,
                            int startCell,
                            int maxCells)
{
    int rv = -1;
    remote_node_get_cells_free_memory_args args;
    remote_node_get_cells_free_memory_ret ret;
    int i;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (maxCells > REMOTE_NODE_MAX_CELLS) {
        errorf (conn, VIR_ERR_RPC,
                _("too many NUMA cells: %d > %d"),
                maxCells,
                REMOTE_NODE_MAX_CELLS);
        goto done;
    }

    args.startCell = startCell;
    args.maxCells = maxCells;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_CELLS_FREE_MEMORY,
              (xdrproc_t) xdr_remote_node_get_cells_free_memory_args, (char *)&args,
              (xdrproc_t) xdr_remote_node_get_cells_free_memory_ret, (char *)&ret) == -1)
        goto done;

    for (i = 0 ; i < ret.freeMems.freeMems_len ; i++)
        freeMems[i] = ret.freeMems.freeMems_val[i];

    xdr_free((xdrproc_t) xdr_remote_node_get_cells_free_memory_ret, (char *) &ret);

    rv = ret.freeMems.freeMems_len;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static unsigned long long
remoteNodeGetFreeMemory (virConnectPtr conn)
{
    unsigned long long rv = 0; /* 0 is error value this special function*/
    remote_node_get_free_memory_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_FREE_MEMORY,
              (xdrproc_t) xdr_void, NULL,
              (xdrproc_t) xdr_remote_node_get_free_memory_ret, (char *)&ret) == -1)
        goto done;

    rv = ret.freeMem;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteListDomains (virConnectPtr conn, int *ids, int maxids)
{
    int rv = -1;
    int i;
    remote_list_domains_args args;
    remote_list_domains_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (maxids > REMOTE_DOMAIN_ID_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain IDs: %d > %d"),
                maxids, REMOTE_DOMAIN_ID_LIST_MAX);
        goto done;
    }
    args.maxids = maxids;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DOMAINS,
              (xdrproc_t) xdr_remote_list_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret) == -1)
        goto done;

    if (ret.ids.ids_len > maxids) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain IDs: %d > %d"),
                ret.ids.ids_len, maxids);
        goto cleanup;
    }

    for (i = 0; i < ret.ids.ids_len; ++i)
        ids[i] = ret.ids.ids_val[i];

    rv = ret.ids.ids_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfDomains (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_domains_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DOMAINS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_domains_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virDomainPtr
remoteDomainCreateXML (virConnectPtr conn,
                         const char *xmlDesc,
                         unsigned int flags)
{
    virDomainPtr dom = NULL;
    remote_domain_create_xml_args args;
    remote_domain_create_xml_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.xml_desc = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE_XML,
              (xdrproc_t) xdr_remote_domain_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_create_xml_ret, (char *) &ret) == -1)
        goto done;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dom;
}

static virDomainPtr
remoteDomainLookupByID (virConnectPtr conn, int id)
{
    virDomainPtr dom = NULL;
    remote_domain_lookup_by_id_args args;
    remote_domain_lookup_by_id_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.id = id;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_ID,
              (xdrproc_t) xdr_remote_domain_lookup_by_id_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_id_ret, (char *) &ret) == -1)
        goto done;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_id_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dom;
}

static virDomainPtr
remoteDomainLookupByUUID (virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr dom = NULL;
    remote_domain_lookup_by_uuid_args args;
    remote_domain_lookup_by_uuid_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret) == -1)
        goto done;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dom;
}

static virDomainPtr
remoteDomainLookupByName (virConnectPtr conn, const char *name)
{
    virDomainPtr dom = NULL;
    remote_domain_lookup_by_name_args args;
    remote_domain_lookup_by_name_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_domain_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dom;
}

static int
remoteDomainSuspend (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_suspend_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SUSPEND,
              (xdrproc_t) xdr_remote_domain_suspend_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainResume (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_resume_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_RESUME,
              (xdrproc_t) xdr_remote_domain_resume_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainShutdown (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_shutdown_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SHUTDOWN,
              (xdrproc_t) xdr_remote_domain_shutdown_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainReboot (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_reboot_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_REBOOT,
              (xdrproc_t) xdr_remote_domain_reboot_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainDestroy (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_destroy_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DESTROY,
              (xdrproc_t) xdr_remote_domain_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteDomainGetOSType (virDomainPtr domain)
{
    char *rv = NULL;
    remote_domain_get_os_type_args args;
    remote_domain_get_os_type_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_OS_TYPE,
              (xdrproc_t) xdr_remote_domain_get_os_type_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_os_type_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.type;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static unsigned long
remoteDomainGetMaxMemory (virDomainPtr domain)
{
    unsigned long rv = 0;
    remote_domain_get_max_memory_args args;
    remote_domain_get_max_memory_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MAX_MEMORY,
              (xdrproc_t) xdr_remote_domain_get_max_memory_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_max_memory_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.memory;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSetMaxMemory (virDomainPtr domain, unsigned long memory)
{
    int rv = -1;
    remote_domain_set_max_memory_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.memory = memory;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_MAX_MEMORY,
              (xdrproc_t) xdr_remote_domain_set_max_memory_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSetMemory (virDomainPtr domain, unsigned long memory)
{
    int rv = -1;
    remote_domain_set_memory_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.memory = memory;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_MEMORY,
              (xdrproc_t) xdr_remote_domain_set_memory_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetInfo (virDomainPtr domain, virDomainInfoPtr info)
{
    int rv = -1;
    remote_domain_get_info_args args;
    remote_domain_get_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_INFO,
              (xdrproc_t) xdr_remote_domain_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_info_ret, (char *) &ret) == -1)
        goto done;

    info->state = ret.state;
    info->maxMem = ret.max_mem;
    info->memory = ret.memory;
    info->nrVirtCpu = ret.nr_virt_cpu;
    info->cpuTime = ret.cpu_time;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSave (virDomainPtr domain, const char *to)
{
    int rv = -1;
    remote_domain_save_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.to = (char *) to;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SAVE,
              (xdrproc_t) xdr_remote_domain_save_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainRestore (virConnectPtr conn, const char *from)
{
    int rv = -1;
    remote_domain_restore_args args;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.from = (char *) from;

    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_RESTORE,
              (xdrproc_t) xdr_remote_domain_restore_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainCoreDump (virDomainPtr domain, const char *to, int flags)
{
    int rv = -1;
    remote_domain_core_dump_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.to = (char *) to;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CORE_DUMP,
              (xdrproc_t) xdr_remote_domain_core_dump_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSetVcpus (virDomainPtr domain, unsigned int nvcpus)
{
    int rv = -1;
    remote_domain_set_vcpus_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.nvcpus = nvcpus;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_VCPUS,
              (xdrproc_t) xdr_remote_domain_set_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainPinVcpu (virDomainPtr domain,
                     unsigned int vcpu,
                     unsigned char *cpumap,
                     int maplen)
{
    int rv = -1;
    remote_domain_pin_vcpu_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (maplen > REMOTE_CPUMAP_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("map length greater than maximum: %d > %d"),
                maplen, REMOTE_CPUMAP_MAX);
        goto done;
    }

    make_nonnull_domain (&args.dom, domain);
    args.vcpu = vcpu;
    args.cpumap.cpumap_len = maplen;
    args.cpumap.cpumap_val = (char *) cpumap;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_PIN_VCPU,
              (xdrproc_t) xdr_remote_domain_pin_vcpu_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetVcpus (virDomainPtr domain,
                      virVcpuInfoPtr info,
                      int maxinfo,
                      unsigned char *cpumaps,
                      int maplen)
{
    int rv = -1;
    int i;
    remote_domain_get_vcpus_args args;
    remote_domain_get_vcpus_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (maxinfo > REMOTE_VCPUINFO_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("vCPU count exceeds maximum: %d > %d"),
                maxinfo, REMOTE_VCPUINFO_MAX);
        goto done;
    }
    if (maxinfo * maplen > REMOTE_CPUMAPS_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("vCPU map buffer length exceeds maximum: %d > %d"),
                maxinfo * maplen, REMOTE_CPUMAPS_MAX);
        goto done;
    }

    make_nonnull_domain (&args.dom, domain);
    args.maxinfo = maxinfo;
    args.maplen = maplen;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_VCPUS,
              (xdrproc_t) xdr_remote_domain_get_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret) == -1)
        goto done;

    if (ret.info.info_len > maxinfo) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("host reports too many vCPUs: %d > %d"),
                ret.info.info_len, maxinfo);
        goto cleanup;
    }
    if (ret.cpumaps.cpumaps_len > maxinfo * maplen) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("host reports map buffer length exceeds maximum: %d > %d"),
                ret.cpumaps.cpumaps_len, maxinfo * maplen);
        goto cleanup;
    }

    memset (info, 0, sizeof (virVcpuInfo) * maxinfo);
    memset (cpumaps, 0, maxinfo * maplen);

    for (i = 0; i < ret.info.info_len; ++i) {
        info[i].number = ret.info.info_val[i].number;
        info[i].state = ret.info.info_val[i].state;
        info[i].cpuTime = ret.info.info_val[i].cpu_time;
        info[i].cpu = ret.info.info_val[i].cpu;
    }

    for (i = 0; i < ret.cpumaps.cpumaps_len; ++i)
        cpumaps[i] = ret.cpumaps.cpumaps_val[i];

    rv = ret.info.info_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetMaxVcpus (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_get_max_vcpus_args args;
    remote_domain_get_max_vcpus_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MAX_VCPUS,
              (xdrproc_t) xdr_remote_domain_get_max_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_max_vcpus_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetSecurityLabel (virDomainPtr domain, virSecurityLabelPtr seclabel)
{
    remote_domain_get_security_label_args args;
    remote_domain_get_security_label_ret ret;
    struct private_data *priv = domain->conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL,
              (xdrproc_t) xdr_remote_domain_get_security_label_args, (char *)&args,
              (xdrproc_t) xdr_remote_domain_get_security_label_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.label.label_val != NULL) {
        if (strlen (ret.label.label_val) >= sizeof seclabel->label) {
            errorf (domain->conn, VIR_ERR_RPC, _("security label exceeds maximum: %zd"),
                    sizeof seclabel->label - 1);
            goto done;
        }
        strcpy (seclabel->label, ret.label.label_val);
        seclabel->enforcing = ret.enforcing;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeGetSecurityModel (virConnectPtr conn, virSecurityModelPtr secmodel)
{
    remote_node_get_security_model_ret ret;
    struct private_data *priv = conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_SECURITY_MODEL,
              (xdrproc_t) xdr_void, NULL,
              (xdrproc_t) xdr_remote_node_get_security_model_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.model.model_val != NULL) {
        if (strlen (ret.model.model_val) >= sizeof secmodel->model) {
            errorf (conn, VIR_ERR_RPC, _("security model exceeds maximum: %zd"),
                    sizeof secmodel->model - 1);
            goto done;
        }
        strcpy (secmodel->model, ret.model.model_val);
    }

    if (ret.doi.doi_val != NULL) {
        if (strlen (ret.doi.doi_val) >= sizeof secmodel->doi) {
            errorf (conn, VIR_ERR_RPC, _("security doi exceeds maximum: %zd"),
                    sizeof secmodel->doi - 1);
            goto done;
        }
        strcpy (secmodel->doi, ret.doi.doi_val);
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteDomainDumpXML (virDomainPtr domain, int flags)
{
    char *rv = NULL;
    remote_domain_dump_xml_args args;
    remote_domain_dump_xml_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DUMP_XML,
              (xdrproc_t) xdr_remote_domain_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMigratePrepare (virConnectPtr dconn,
                            char **cookie, int *cookielen,
                            const char *uri_in, char **uri_out,
                            unsigned long flags, const char *dname,
                            unsigned long resource)
{
    int rv = -1;
    remote_domain_migrate_prepare_args args;
    remote_domain_migrate_prepare_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE,
              (xdrproc_t) xdr_remote_domain_migrate_prepare_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_prepare_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie.cookie_len > 0) {
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out)
        *uri_out = *ret.uri_out; /* Caller frees. */

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMigratePerform (virDomainPtr domain,
                            const char *cookie,
                            int cookielen,
                            const char *uri,
                            unsigned long flags,
                            const char *dname,
                            unsigned long resource)
{
    int rv = -1;
    remote_domain_migrate_perform_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.cookie.cookie_len = cookielen;
    args.cookie.cookie_val = (char *) cookie;
    args.uri = (char *) uri;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PERFORM,
              (xdrproc_t) xdr_remote_domain_migrate_perform_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virDomainPtr
remoteDomainMigrateFinish (virConnectPtr dconn,
                           const char *dname,
                           const char *cookie,
                           int cookielen,
                           const char *uri,
                           unsigned long flags)
{
    virDomainPtr ddom = NULL;
    remote_domain_migrate_finish_args args;
    remote_domain_migrate_finish_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.dname = (char *) dname;
    args.cookie.cookie_len = cookielen;
    args.cookie.cookie_val = (char *) cookie;
    args.uri = (char *) uri;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_FINISH,
              (xdrproc_t) xdr_remote_domain_migrate_finish_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_finish_ret, (char *) &ret) == -1)
        goto done;

    ddom = get_nonnull_domain (dconn, ret.ddom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_migrate_finish_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return ddom;
}

static int
remoteDomainMigratePrepare2 (virConnectPtr dconn,
                             char **cookie, int *cookielen,
                             const char *uri_in, char **uri_out,
                             unsigned long flags, const char *dname,
                             unsigned long resource,
                             const char *dom_xml)
{
    int rv = -1;
    remote_domain_migrate_prepare2_args args;
    remote_domain_migrate_prepare2_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;
    args.dom_xml = (char *) dom_xml;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE2,
              (xdrproc_t) xdr_remote_domain_migrate_prepare2_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_prepare2_ret, (char *) &ret) == -1)
        goto done;

    if (ret.cookie.cookie_len > 0) {
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out)
        *uri_out = *ret.uri_out; /* Caller frees. */

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virDomainPtr
remoteDomainMigrateFinish2 (virConnectPtr dconn,
                            const char *dname,
                            const char *cookie,
                            int cookielen,
                            const char *uri,
                            unsigned long flags,
                            int retcode)
{
    virDomainPtr ddom = NULL;
    remote_domain_migrate_finish2_args args;
    remote_domain_migrate_finish2_ret ret;
    struct private_data *priv = dconn->privateData;

    remoteDriverLock(priv);

    args.dname = (char *) dname;
    args.cookie.cookie_len = cookielen;
    args.cookie.cookie_val = (char *) cookie;
    args.uri = (char *) uri;
    args.flags = flags;
    args.retcode = retcode;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_FINISH2,
              (xdrproc_t) xdr_remote_domain_migrate_finish2_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_finish2_ret, (char *) &ret) == -1)
        goto done;

    ddom = get_nonnull_domain (dconn, ret.ddom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_migrate_finish2_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return ddom;
}

static int
remoteListDefinedDomains (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_defined_domains_args args;
    remote_list_defined_domains_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_DOMAIN_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain names: %d > %d"),
                maxnames, REMOTE_DOMAIN_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_DOMAINS,
              (xdrproc_t) xdr_remote_list_defined_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain names: %d > %d"),
                ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfDefinedDomains (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_defined_domains_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_DOMAINS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_domains_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainCreate (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_create_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE,
              (xdrproc_t) xdr_remote_domain_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virDomainPtr
remoteDomainDefineXML (virConnectPtr conn, const char *xml)
{
    virDomainPtr dom = NULL;
    remote_domain_define_xml_args args;
    remote_domain_define_xml_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.xml = (char *) xml;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_DEFINE_XML,
              (xdrproc_t) xdr_remote_domain_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_define_xml_ret, (char *) &ret) == -1)
        goto done;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) xdr_remote_domain_define_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dom;
}

static int
remoteDomainUndefine (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_undefine_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_UNDEFINE,
              (xdrproc_t) xdr_remote_domain_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainAttachDevice (virDomainPtr domain, const char *xml)
{
    int rv = -1;
    remote_domain_attach_device_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_ATTACH_DEVICE,
              (xdrproc_t) xdr_remote_domain_attach_device_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainDetachDevice (virDomainPtr domain, const char *xml)
{
    int rv = -1;
    remote_domain_detach_device_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DETACH_DEVICE,
              (xdrproc_t) xdr_remote_domain_detach_device_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetAutostart (virDomainPtr domain, int *autostart)
{
    int rv = -1;
    remote_domain_get_autostart_args args;
    remote_domain_get_autostart_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_domain_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_autostart_ret, (char *) &ret) == -1)
        goto done;

    if (autostart) *autostart = ret.autostart;
    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSetAutostart (virDomainPtr domain, int autostart)
{
    int rv = -1;
    remote_domain_set_autostart_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.autostart = autostart;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_domain_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteDomainGetSchedulerType (virDomainPtr domain, int *nparams)
{
    char *rv = NULL;
    remote_domain_get_scheduler_type_args args;
    remote_domain_get_scheduler_type_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE,
              (xdrproc_t) xdr_remote_domain_get_scheduler_type_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_scheduler_type_ret, (char *) &ret) == -1)
        goto done;

    if (nparams) *nparams = ret.nparams;

    /* Caller frees this. */
    rv = ret.type;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetSchedulerParameters (virDomainPtr domain,
                                    virSchedParameterPtr params, int *nparams)
{
    int rv = -1;
    remote_domain_get_scheduler_parameters_args args;
    remote_domain_get_scheduler_parameters_ret ret;
    int i = -1;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.nparams = *nparams;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_get_scheduler_parameters_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX ||
        ret.params.params_len > *nparams) {
        error (domain->conn, VIR_ERR_RPC,
               _("remoteDomainGetSchedulerParameters: "
                 "returned number of parameters exceeds limit"));
        goto cleanup;
    }
    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    for (i = 0; i < *nparams; ++i) {
        strncpy (params[i].field, ret.params.params_val[i].field,
                 VIR_DOMAIN_SCHED_FIELD_LENGTH);
        params[i].field[VIR_DOMAIN_SCHED_FIELD_LENGTH-1] = '\0';
        params[i].type = ret.params.params_val[i].value.type;
        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            params[i].value.i = ret.params.params_val[i].value.remote_sched_param_value_u.i; break;
        case VIR_DOMAIN_SCHED_FIELD_UINT:
            params[i].value.ui = ret.params.params_val[i].value.remote_sched_param_value_u.ui; break;
        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            params[i].value.l = ret.params.params_val[i].value.remote_sched_param_value_u.l; break;
        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            params[i].value.ul = ret.params.params_val[i].value.remote_sched_param_value_u.ul; break;
        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            params[i].value.d = ret.params.params_val[i].value.remote_sched_param_value_u.d; break;
        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            params[i].value.b = ret.params.params_val[i].value.remote_sched_param_value_u.b; break;
        default:
            error (domain->conn, VIR_ERR_RPC,
                   _("remoteDomainGetSchedulerParameters: "
                     "unknown parameter type"));
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret);
done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainSetSchedulerParameters (virDomainPtr domain,
                                    virSchedParameterPtr params, int nparams)
{
    int rv = -1;
    remote_domain_set_scheduler_parameters_args args;
    int i, do_error;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    /* Serialise the scheduler parameters. */
    args.params.params_len = nparams;
    if (VIR_ALLOC_N(args.params.params_val, nparams) < 0) {
        error (domain->conn, VIR_ERR_RPC, _("out of memory allocating array"));
        goto done;
    }

    do_error = 0;
    for (i = 0; i < nparams; ++i) {
        // call() will free this:
        args.params.params_val[i].field = strdup (params[i].field);
        if (args.params.params_val[i].field == NULL) {
            virReportOOMError (domain->conn);
            do_error = 1;
        }
        args.params.params_val[i].value.type = params[i].type;
        switch (params[i].type) {
        case VIR_DOMAIN_SCHED_FIELD_INT:
            args.params.params_val[i].value.remote_sched_param_value_u.i = params[i].value.i; break;
        case VIR_DOMAIN_SCHED_FIELD_UINT:
            args.params.params_val[i].value.remote_sched_param_value_u.ui = params[i].value.ui; break;
        case VIR_DOMAIN_SCHED_FIELD_LLONG:
            args.params.params_val[i].value.remote_sched_param_value_u.l = params[i].value.l; break;
        case VIR_DOMAIN_SCHED_FIELD_ULLONG:
            args.params.params_val[i].value.remote_sched_param_value_u.ul = params[i].value.ul; break;
        case VIR_DOMAIN_SCHED_FIELD_DOUBLE:
            args.params.params_val[i].value.remote_sched_param_value_u.d = params[i].value.d; break;
        case VIR_DOMAIN_SCHED_FIELD_BOOLEAN:
            args.params.params_val[i].value.remote_sched_param_value_u.b = params[i].value.b; break;
        default:
            error (domain->conn, VIR_ERR_RPC, _("unknown parameter type"));
            do_error = 1;
        }
    }

    if (do_error) {
        xdr_free ((xdrproc_t) xdr_remote_domain_set_scheduler_parameters_args, (char *) &args);
        goto done;
    }

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_set_scheduler_parameters_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainBlockStats (virDomainPtr domain, const char *path,
                        struct _virDomainBlockStats *stats)
{
    int rv = -1;
    remote_domain_block_stats_args args;
    remote_domain_block_stats_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_BLOCK_STATS,
              (xdrproc_t) xdr_remote_domain_block_stats_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_block_stats_ret, (char *) &ret)
        == -1)
        goto done;

    stats->rd_req = ret.rd_req;
    stats->rd_bytes = ret.rd_bytes;
    stats->wr_req = ret.wr_req;
    stats->wr_bytes = ret.wr_bytes;
    stats->errs = ret.errs;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainInterfaceStats (virDomainPtr domain, const char *path,
                            struct _virDomainInterfaceStats *stats)
{
    int rv = -1;
    remote_domain_interface_stats_args args;
    remote_domain_interface_stats_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_INTERFACE_STATS,
              (xdrproc_t) xdr_remote_domain_interface_stats_args,
                (char *) &args,
              (xdrproc_t) xdr_remote_domain_interface_stats_ret,
                (char *) &ret) == -1)
        goto done;

    stats->rx_bytes = ret.rx_bytes;
    stats->rx_packets = ret.rx_packets;
    stats->rx_errs = ret.rx_errs;
    stats->rx_drop = ret.rx_drop;
    stats->tx_bytes = ret.tx_bytes;
    stats->tx_packets = ret.tx_packets;
    stats->tx_errs = ret.tx_errs;
    stats->tx_drop = ret.tx_drop;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainBlockPeek (virDomainPtr domain,
                       const char *path,
                       unsigned long long offset,
                       size_t size,
                       void *buffer,
                       unsigned int flags)
{
    int rv = -1;
    remote_domain_block_peek_args args;
    remote_domain_block_peek_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (size > REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("block peek request too large for remote protocol, %zi > %d"),
                size, REMOTE_DOMAIN_BLOCK_PEEK_BUFFER_MAX);
        goto done;
    }

    make_nonnull_domain (&args.dom, domain);
    args.path = (char *) path;
    args.offset = offset;
    args.size = size;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_BLOCK_PEEK,
              (xdrproc_t) xdr_remote_domain_block_peek_args,
                (char *) &args,
              (xdrproc_t) xdr_remote_domain_block_peek_ret,
                (char *) &ret) == -1)
        goto done;

    if (ret.buffer.buffer_len != size) {
        errorf (domain->conn, VIR_ERR_RPC,
                "%s", _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy (buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    free (ret.buffer.buffer_val);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainMemoryPeek (virDomainPtr domain,
                        unsigned long long offset,
                        size_t size,
                        void *buffer,
                        unsigned int flags)
{
    int rv = -1;
    remote_domain_memory_peek_args args;
    remote_domain_memory_peek_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (size > REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("memory peek request too large for remote protocol, %zi > %d"),
                size, REMOTE_DOMAIN_MEMORY_PEEK_BUFFER_MAX);
        goto done;
    }

    make_nonnull_domain (&args.dom, domain);
    args.offset = offset;
    args.size = size;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MEMORY_PEEK,
              (xdrproc_t) xdr_remote_domain_memory_peek_args,
                (char *) &args,
              (xdrproc_t) xdr_remote_domain_memory_peek_ret,
                (char *) &ret) == -1)
        goto done;

    if (ret.buffer.buffer_len != size) {
        errorf (domain->conn, VIR_ERR_RPC,
                "%s", _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy (buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    free (ret.buffer.buffer_val);

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus
remoteNetworkOpen (virConnectPtr conn,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn &&
        conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv;

       /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        priv = conn->privateData;
        remoteDriverLock(priv);
        priv->localUses++;
        conn->networkPrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->networkPrivateData = priv;
        return ret;
    }
}

static int
remoteNetworkClose (virConnectPtr conn)
{
    int rv = 0;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        rv = doRemoteClose(conn, priv);
        conn->networkPrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfNetworks (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_networks_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_NETWORKS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_networks_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListNetworks (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_networks_args args;
    remote_list_networks_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                maxnames, REMOTE_NETWORK_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_NETWORKS,
              (xdrproc_t) xdr_remote_list_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfDefinedNetworks (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_defined_networks_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_NETWORKS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_networks_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListDefinedNetworks (virConnectPtr conn,
                           char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_defined_networks_args args;
    remote_list_defined_networks_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                maxnames, REMOTE_NETWORK_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_NETWORKS,
              (xdrproc_t) xdr_remote_list_defined_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virNetworkPtr
remoteNetworkLookupByUUID (virConnectPtr conn,
                           const unsigned char *uuid)
{
    virNetworkPtr net = NULL;
    remote_network_lookup_by_uuid_args args;
    remote_network_lookup_by_uuid_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_network_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_lookup_by_uuid_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_lookup_by_uuid_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}

static virNetworkPtr
remoteNetworkLookupByName (virConnectPtr conn,
                           const char *name)
{
    virNetworkPtr net = NULL;
    remote_network_lookup_by_name_args args;
    remote_network_lookup_by_name_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_network_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}

static virNetworkPtr
remoteNetworkCreateXML (virConnectPtr conn, const char *xmlDesc)
{
    virNetworkPtr net = NULL;
    remote_network_create_xml_args args;
    remote_network_create_xml_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xmlDesc;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_CREATE_XML,
              (xdrproc_t) xdr_remote_network_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_create_xml_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}

static virNetworkPtr
remoteNetworkDefineXML (virConnectPtr conn, const char *xml)
{
    virNetworkPtr net = NULL;
    remote_network_define_xml_args args;
    remote_network_define_xml_ret ret;
    struct private_data *priv = conn->networkPrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xml;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_DEFINE_XML,
              (xdrproc_t) xdr_remote_network_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_define_xml_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_define_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}

static int
remoteNetworkUndefine (virNetworkPtr network)
{
    int rv = -1;
    remote_network_undefine_args args;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_UNDEFINE,
              (xdrproc_t) xdr_remote_network_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNetworkCreate (virNetworkPtr network)
{
    int rv = -1;
    remote_network_create_args args;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_CREATE,
              (xdrproc_t) xdr_remote_network_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNetworkDestroy (virNetworkPtr network)
{
    int rv = -1;
    remote_network_destroy_args args;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_DESTROY,
              (xdrproc_t) xdr_remote_network_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteNetworkDumpXML (virNetworkPtr network, int flags)
{
    char *rv = NULL;
    remote_network_dump_xml_args args;
    remote_network_dump_xml_ret ret;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_DUMP_XML,
              (xdrproc_t) xdr_remote_network_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteNetworkGetBridgeName (virNetworkPtr network)
{
    char *rv = NULL;
    remote_network_get_bridge_name_args args;
    remote_network_get_bridge_name_ret ret;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_GET_BRIDGE_NAME,
              (xdrproc_t) xdr_remote_network_get_bridge_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_get_bridge_name_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.name;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNetworkGetAutostart (virNetworkPtr network, int *autostart)
{
    int rv = -1;
    remote_network_get_autostart_args args;
    remote_network_get_autostart_ret ret;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_network_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_get_autostart_ret, (char *) &ret) == -1)
        goto done;

    if (autostart) *autostart = ret.autostart;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNetworkSetAutostart (virNetworkPtr network, int autostart)
{
    int rv = -1;
    remote_network_set_autostart_args args;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);
    args.autostart = autostart;

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_network_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}




/*----------------------------------------------------------------------*/

static virDrvOpenStatus
remoteStorageOpen (virConnectPtr conn,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn &&
        conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv = conn->privateData;
        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        remoteDriverLock(priv);
        priv->localUses++;
        conn->storagePrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else if (conn->networkDriver &&
               STREQ (conn->networkDriver->name, "remote")) {
        struct private_data *priv = conn->networkPrivateData;
        remoteDriverLock(priv);
        conn->storagePrivateData = priv;
        priv->localUses++;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->storagePrivateData = priv;
        return ret;
    }
}

static int
remoteStorageClose (virConnectPtr conn)
{
    int ret = 0;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        ret = doRemoteClose(conn, priv);
        conn->storagePrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);

    return ret;
}

static int
remoteNumOfStoragePools (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_storage_pools_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_STORAGE_POOLS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListStoragePools (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_storage_pools_args args;
    remote_list_storage_pools_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        error (conn, VIR_ERR_RPC, _("too many storage pools requested"));
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, _("too many storage pools received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfDefinedStoragePools (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_defined_storage_pools_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_STORAGE_POOLS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListDefinedStoragePools (virConnectPtr conn,
                               char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_defined_storage_pools_args args;
    remote_list_defined_storage_pools_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        error (conn, VIR_ERR_RPC, _("too many storage pools requested"));
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, _("too many storage pools received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteFindStoragePoolSources (virConnectPtr conn,
                              const char *type,
                              const char *srcSpec,
                              unsigned int flags)
{
    char *rv = NULL;
    remote_find_storage_pool_sources_args args;
    remote_find_storage_pool_sources_ret ret;
    struct private_data *priv = conn->storagePrivateData;
    const char *emptyString = "";

    remoteDriverLock(priv);

    args.type = (char*)type;
    /*
     * I'd think the following would work here:
     *    args.srcSpec = (char**)&srcSpec;
     * since srcSpec is a remote_string (not a remote_nonnull_string).
     *
     * But when srcSpec is NULL, this yields:
     *    libvir: Remote error : marshalling args
     *
     * So for now I'm working around this by turning NULL srcSpecs
     * into empty strings.
     */
    args.srcSpec = srcSpec ? (char **)&srcSpec : (char **)&emptyString;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_FIND_STORAGE_POOL_SOURCES,
              (xdrproc_t) xdr_remote_find_storage_pool_sources_args, (char *) &args,
              (xdrproc_t) xdr_remote_find_storage_pool_sources_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.xml;
    ret.xml = NULL; /* To stop xdr_free free'ing it */

    xdr_free ((xdrproc_t) xdr_remote_find_storage_pool_sources_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virStoragePoolPtr
remoteStoragePoolLookupByUUID (virConnectPtr conn,
                               const unsigned char *uuid)
{
    virStoragePoolPtr pool = NULL;
    remote_storage_pool_lookup_by_uuid_args args;
    remote_storage_pool_lookup_by_uuid_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_uuid_ret, (char *) &ret) == -1)
        goto done;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_uuid_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return pool;
}

static virStoragePoolPtr
remoteStoragePoolLookupByName (virConnectPtr conn,
                               const char *name)
{
    virStoragePoolPtr pool = NULL;
    remote_storage_pool_lookup_by_name_args args;
    remote_storage_pool_lookup_by_name_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return pool;
}

static virStoragePoolPtr
remoteStoragePoolLookupByVolume (virStorageVolPtr vol)
{
    virStoragePoolPtr pool = NULL;
    remote_storage_pool_lookup_by_volume_args args;
    remote_storage_pool_lookup_by_volume_ret ret;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_VOLUME,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_volume_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_volume_ret, (char *) &ret) == -1)
        goto done;

    pool = get_nonnull_storage_pool (vol->conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_volume_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return pool;
}


static virStoragePoolPtr
remoteStoragePoolCreateXML (virConnectPtr conn, const char *xmlDesc, unsigned int flags)
{
    virStoragePoolPtr pool = NULL;
    remote_storage_pool_create_xml_args args;
    remote_storage_pool_create_xml_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_CREATE_XML,
              (xdrproc_t) xdr_remote_storage_pool_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_create_xml_ret, (char *) &ret) == -1)
        goto done;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return pool;
}

static virStoragePoolPtr
remoteStoragePoolDefineXML (virConnectPtr conn, const char *xml, unsigned int flags)
{
    virStoragePoolPtr pool = NULL;
    remote_storage_pool_define_xml_args args;
    remote_storage_pool_define_xml_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xml;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DEFINE_XML,
              (xdrproc_t) xdr_remote_storage_pool_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_define_xml_ret, (char *) &ret) == -1)
        goto done;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_define_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return pool;
}

static int
remoteStoragePoolUndefine (virStoragePoolPtr pool)
{
    int rv = -1;
    remote_storage_pool_undefine_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_UNDEFINE,
              (xdrproc_t) xdr_remote_storage_pool_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolCreate (virStoragePoolPtr pool, unsigned int flags)
{
    int rv = -1;
    remote_storage_pool_create_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_CREATE,
              (xdrproc_t) xdr_remote_storage_pool_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolBuild (virStoragePoolPtr pool,
                        unsigned int flags)
{
    int rv = -1;
    remote_storage_pool_build_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_BUILD,
              (xdrproc_t) xdr_remote_storage_pool_build_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolDestroy (virStoragePoolPtr pool)
{
    int rv = -1;
    remote_storage_pool_destroy_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DESTROY,
              (xdrproc_t) xdr_remote_storage_pool_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolDelete (virStoragePoolPtr pool,
                         unsigned int flags)
{
    int rv = -1;
    remote_storage_pool_delete_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DELETE,
              (xdrproc_t) xdr_remote_storage_pool_delete_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolRefresh (virStoragePoolPtr pool,
                          unsigned int flags)
{
    int rv = -1;
    remote_storage_pool_refresh_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_REFRESH,
              (xdrproc_t) xdr_remote_storage_pool_refresh_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolGetInfo (virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    int rv = -1;
    remote_storage_pool_get_info_args args;
    remote_storage_pool_get_info_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_GET_INFO,
              (xdrproc_t) xdr_remote_storage_pool_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_get_info_ret, (char *) &ret) == -1)
        goto done;

    info->state = ret.state;
    info->capacity = ret.capacity;
    info->allocation = ret.allocation;
    info->available = ret.available;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteStoragePoolDumpXML (virStoragePoolPtr pool,
                          unsigned int flags)
{
    char *rv = NULL;
    remote_storage_pool_dump_xml_args args;
    remote_storage_pool_dump_xml_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DUMP_XML,
              (xdrproc_t) xdr_remote_storage_pool_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolGetAutostart (virStoragePoolPtr pool, int *autostart)
{
    int rv = -1;
    remote_storage_pool_get_autostart_args args;
    remote_storage_pool_get_autostart_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_storage_pool_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_get_autostart_ret, (char *) &ret) == -1)
        goto done;

    if (autostart) *autostart = ret.autostart;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolSetAutostart (virStoragePoolPtr pool, int autostart)
{
    int rv = -1;
    remote_storage_pool_set_autostart_args args;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.autostart = autostart;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_storage_pool_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteStoragePoolNumOfVolumes (virStoragePoolPtr pool)
{
    int rv = -1;
    remote_storage_pool_num_of_volumes_args args;
    remote_storage_pool_num_of_volumes_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool(&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_NUM_OF_VOLUMES,
              (xdrproc_t) xdr_remote_storage_pool_num_of_volumes_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_num_of_volumes_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolListVolumes (virStoragePoolPtr pool, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_storage_pool_list_volumes_args args;
    remote_storage_pool_list_volumes_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX) {
        error (pool->conn, VIR_ERR_RPC, _("too many storage volumes requested"));
        goto done;
    }
    args.maxnames = maxnames;
    make_nonnull_storage_pool(&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES,
              (xdrproc_t) xdr_remote_storage_pool_list_volumes_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_list_volumes_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        error (pool->conn, VIR_ERR_RPC, _("too many storage volumes received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_storage_pool_list_volumes_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}



static virStorageVolPtr
remoteStorageVolLookupByName (virStoragePoolPtr pool,
                              const char *name)
{
    virStorageVolPtr vol = NULL;
    remote_storage_vol_lookup_by_name_args args;
    remote_storage_vol_lookup_by_name_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool(&args.pool, pool);
    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    vol = get_nonnull_storage_vol (pool->conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return vol;
}

static virStorageVolPtr
remoteStorageVolLookupByKey (virConnectPtr conn,
                             const char *key)
{
    virStorageVolPtr  vol = NULL;
    remote_storage_vol_lookup_by_key_args args;
    remote_storage_vol_lookup_by_key_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.key = (char *) key;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_KEY,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_key_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_key_ret, (char *) &ret) == -1)
        goto done;

    vol = get_nonnull_storage_vol (conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_key_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return vol;
}

static virStorageVolPtr
remoteStorageVolLookupByPath (virConnectPtr conn,
                              const char *path)
{
    virStorageVolPtr vol = NULL;
    remote_storage_vol_lookup_by_path_args args;
    remote_storage_vol_lookup_by_path_ret ret;
    struct private_data *priv = conn->storagePrivateData;

    remoteDriverLock(priv);

    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_PATH,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_path_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_path_ret, (char *) &ret) == -1)
        goto done;

    vol = get_nonnull_storage_vol (conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_path_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return vol;
}

static virStorageVolPtr
remoteStorageVolCreateXML (virStoragePoolPtr pool, const char *xmlDesc,
                           unsigned int flags)
{
    virStorageVolPtr vol = NULL;
    remote_storage_vol_create_xml_args args;
    remote_storage_vol_create_xml_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_CREATE_XML,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_ret, (char *) &ret) == -1)
        goto done;

    vol = get_nonnull_storage_vol (pool->conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return vol;
}

static int
remoteStorageVolDelete (virStorageVolPtr vol,
                        unsigned int flags)
{
    int rv = -1;
    remote_storage_vol_delete_args args;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol (&args.vol, vol);
    args.flags = flags;

    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_DELETE,
              (xdrproc_t) xdr_remote_storage_vol_delete_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStorageVolGetInfo (virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    int rv = -1;
    remote_storage_vol_get_info_args args;
    remote_storage_vol_get_info_ret ret;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_GET_INFO,
              (xdrproc_t) xdr_remote_storage_vol_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_get_info_ret, (char *) &ret) == -1)
        goto done;

    info->type = ret.type;
    info->capacity = ret.capacity;
    info->allocation = ret.allocation;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteStorageVolDumpXML (virStorageVolPtr vol,
                         unsigned int flags)
{
    char *rv = NULL;
    remote_storage_vol_dump_xml_args args;
    remote_storage_vol_dump_xml_ret ret;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol (&args.vol, vol);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_DUMP_XML,
              (xdrproc_t) xdr_remote_storage_vol_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteStorageVolGetPath (virStorageVolPtr vol)
{
    char *rv = NULL;
    remote_storage_vol_get_path_args args;
    remote_storage_vol_get_path_ret ret;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_GET_PATH,
              (xdrproc_t) xdr_remote_storage_vol_get_path_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_get_path_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.name;

done:
    remoteDriverUnlock(priv);
    return rv;
}


/*----------------------------------------------------------------------*/

static virDrvOpenStatus
remoteDevMonOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 int flags ATTRIBUTE_UNUSED)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn &&
        conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv = conn->privateData;
        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        remoteDriverLock(priv);
        priv->localUses++;
        conn->devMonPrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else if (conn->networkDriver &&
               STREQ (conn->networkDriver->name, "remote")) {
        struct private_data *priv = conn->networkPrivateData;
        remoteDriverLock(priv);
        conn->devMonPrivateData = priv;
        priv->localUses++;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->devMonPrivateData = priv;
        return ret;
    }
}

static int remoteDevMonClose(virConnectPtr conn)
{
    int ret = 0;
    struct private_data *priv = conn->devMonPrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        ret = doRemoteClose(conn, priv);
        conn->devMonPrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return ret;
}

static int remoteNodeNumOfDevices(virConnectPtr conn,
                                  const char *cap,
                                  unsigned int flags)
{
    int rv = -1;
    remote_node_num_of_devices_args args;
    remote_node_num_of_devices_ret ret;
    struct private_data *priv = conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.cap = cap ? (char **)&cap : NULL;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_NUM_OF_DEVICES,
              (xdrproc_t) xdr_remote_node_num_of_devices_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_num_of_devices_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int remoteNodeListDevices(virConnectPtr conn,
                                 const char *cap,
                                 char **const names,
                                 int maxnames,
                                 unsigned int flags)
{
    int rv = -1;
    int i;
    remote_node_list_devices_args args;
    remote_node_list_devices_ret ret;
    struct private_data *priv = conn->devMonPrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_NODE_DEVICE_NAME_LIST_MAX) {
        error (conn, VIR_ERR_RPC, _("too many device names requested"));
        goto done;
    }
    args.cap = cap ? (char **)&cap : NULL;
    args.maxnames = maxnames;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_LIST_DEVICES,
              (xdrproc_t) xdr_remote_node_list_devices_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_list_devices_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, _("too many device names received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_node_list_devices_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


static virNodeDevicePtr remoteNodeDeviceLookupByName(virConnectPtr conn,
                                                     const char *name)
{
    remote_node_device_lookup_by_name_args args;
    remote_node_device_lookup_by_name_ret ret;
    virNodeDevicePtr dev = NULL;
    struct private_data *priv = conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.name = (char *)name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_DEVICE_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_node_device_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_device_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    dev = get_nonnull_node_device(conn, ret.dev);

    xdr_free ((xdrproc_t) xdr_remote_node_device_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dev;
}

static char *remoteNodeDeviceDumpXML(virNodeDevicePtr dev,
                                     unsigned int flags)
{
    char *rv = NULL;
    remote_node_device_dump_xml_args args;
    remote_node_device_dump_xml_ret ret;
    struct private_data *priv = dev->conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.name = dev->name;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_DUMP_XML,
              (xdrproc_t) xdr_remote_node_device_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_device_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *remoteNodeDeviceGetParent(virNodeDevicePtr dev)
{
    char *rv = NULL;
    remote_node_device_get_parent_args args;
    remote_node_device_get_parent_ret ret;
    struct private_data *priv = dev->conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    memset (&ret, 0, sizeof ret);
    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_GET_PARENT,
              (xdrproc_t) xdr_remote_node_device_get_parent_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_device_get_parent_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.parent ? *ret.parent : NULL;
    VIR_FREE(ret.parent);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteNodeDeviceNumOfCaps(virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_num_of_caps_args args;
    remote_node_device_num_of_caps_ret ret;
    struct private_data *priv = dev->conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    memset (&ret, 0, sizeof ret);
    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_NUM_OF_CAPS,
              (xdrproc_t) xdr_remote_node_device_num_of_caps_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_device_num_of_caps_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteNodeDeviceListCaps(virNodeDevicePtr dev,
                                    char **const names,
                                    int maxnames)
{
    int rv = -1;
    int i;
    remote_node_device_list_caps_args args;
    remote_node_device_list_caps_ret ret;
    struct private_data *priv = dev->conn->devMonPrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_NODE_DEVICE_CAPS_LIST_MAX) {
        error (dev->conn, VIR_ERR_RPC, _("too many capability names requested"));
        goto done;
    }
    args.maxnames = maxnames;
    args.name = dev->name;

    memset (&ret, 0, sizeof ret);
    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_LIST_CAPS,
              (xdrproc_t) xdr_remote_node_device_list_caps_args, (char *) &args,
              (xdrproc_t) xdr_remote_node_device_list_caps_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        error (dev->conn, VIR_ERR_RPC, _("too many capability names received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_node_device_list_caps_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceDettach (virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_dettach_args args;
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_DETTACH,
              (xdrproc_t) xdr_remote_node_device_dettach_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceReAttach (virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_re_attach_args args;
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_RE_ATTACH,
              (xdrproc_t) xdr_remote_node_device_re_attach_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNodeDeviceReset (virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_reset_args args;
    struct private_data *priv = dev->conn->privateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call (dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_RESET,
              (xdrproc_t) xdr_remote_node_device_reset_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


/*----------------------------------------------------------------------*/

static int
remoteAuthenticate (virConnectPtr conn, struct private_data *priv, int in_open,
                    virConnectAuthPtr auth
#if !HAVE_SASL && !HAVE_POLKIT
                    ATTRIBUTE_UNUSED
#endif
                    ,
                    const char *authtype)
{
    struct remote_auth_list_ret ret;
    int err, type = REMOTE_AUTH_NONE;

    memset(&ret, 0, sizeof ret);
    err = call (conn, priv,
                REMOTE_CALL_IN_OPEN | REMOTE_CALL_QUIET_MISSING_RPC,
                REMOTE_PROC_AUTH_LIST,
                (xdrproc_t) xdr_void, (char *) NULL,
                (xdrproc_t) xdr_remote_auth_list_ret, (char *) &ret);
    if (err == -2) /* Missing RPC - old server - ignore */
        return 0;

    if (err < 0)
        return -1;

    if (ret.types.types_len == 0)
        return 0;

    if (authtype) {
        int want, i;
        if (STRCASEEQ(authtype, "sasl") ||
            STRCASEEQLEN(authtype, "sasl.", 5)) {
            want = REMOTE_AUTH_SASL;
        } else if (STRCASEEQ(authtype, "polkit")) {
            want = REMOTE_AUTH_POLKIT;
        } else {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                             NULL, NULL, NULL, 0, 0,
                             _("unknown authentication type %s"), authtype);
            return -1;
        }
        for (i = 0 ; i < ret.types.types_len ; i++) {
            if (ret.types.types_val[i] == want)
                type = want;
        }
        if (type == REMOTE_AUTH_NONE) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("requested authentication type %s rejected"),
                             authtype);
            return -1;
        }
    } else {
        type = ret.types.types_val[0];
    }

    switch (type) {
#if HAVE_SASL
    case REMOTE_AUTH_SASL: {
        const char *mech = NULL;
        if (authtype &&
            STRCASEEQLEN(authtype, "sasl.", 5))
            mech = authtype + 5;

        if (remoteAuthSASL(conn, priv, in_open, auth, mech) < 0) {
            VIR_FREE(ret.types.types_val);
            return -1;
        }
        break;
    }
#endif

#if HAVE_POLKIT
    case REMOTE_AUTH_POLKIT:
        if (remoteAuthPolkit(conn, priv, in_open, auth) < 0) {
            VIR_FREE(ret.types.types_val);
            return -1;
        }
        break;
#endif

    case REMOTE_AUTH_NONE:
        /* Nothing todo, hurrah ! */
        break;

    default:
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                         NULL, NULL, NULL, 0, 0,
                         _("unsupported authentication type %d"),
                         ret.types.types_val[0]);
        VIR_FREE(ret.types.types_val);
        return -1;
    }

    VIR_FREE(ret.types.types_val);

    return 0;
}



#if HAVE_SASL
/*
 * NB, keep in sync with similar method in qemud/remote.c
 */
static char *addrToString(struct sockaddr_storage *sa, socklen_t salen)
{
    char host[NI_MAXHOST], port[NI_MAXSERV];
    char *addr;
    int err;

    if ((err = getnameinfo((struct sockaddr *)sa, salen,
                           host, sizeof(host),
                           port, sizeof(port),
                           NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
        virRaiseError (NULL, NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_UNKNOWN_HOST, VIR_ERR_ERROR,
                       NULL, NULL, NULL, 0, 0,
                       _("Cannot resolve address %d: %s"),
                       err, gai_strerror(err));
        return NULL;
    }

    if (VIR_ALLOC_N(addr, strlen(host) + 1 + strlen(port) + 1) < 0) {
        virReportOOMError (NULL);
        return NULL;
    }

    strcpy(addr, host);
    strcat(addr, ";");
    strcat(addr, port);
    return addr;
}


static int remoteAuthCredVir2SASL(int vircred)
{
    switch (vircred) {
    case VIR_CRED_USERNAME:
        return SASL_CB_USER;

    case VIR_CRED_AUTHNAME:
        return SASL_CB_AUTHNAME;

    case VIR_CRED_LANGUAGE:
        return SASL_CB_LANGUAGE;

    case VIR_CRED_CNONCE:
        return SASL_CB_CNONCE;

    case VIR_CRED_PASSPHRASE:
        return SASL_CB_PASS;

    case VIR_CRED_ECHOPROMPT:
        return SASL_CB_ECHOPROMPT;

    case VIR_CRED_NOECHOPROMPT:
        return SASL_CB_NOECHOPROMPT;

    case VIR_CRED_REALM:
        return SASL_CB_GETREALM;
    }

    return 0;
}

static int remoteAuthCredSASL2Vir(int vircred)
{
    switch (vircred) {
    case SASL_CB_USER:
        return VIR_CRED_USERNAME;

    case SASL_CB_AUTHNAME:
        return VIR_CRED_AUTHNAME;

    case SASL_CB_LANGUAGE:
        return VIR_CRED_LANGUAGE;

    case SASL_CB_CNONCE:
        return VIR_CRED_CNONCE;

    case SASL_CB_PASS:
        return VIR_CRED_PASSPHRASE;

    case SASL_CB_ECHOPROMPT:
        return VIR_CRED_ECHOPROMPT;

    case SASL_CB_NOECHOPROMPT:
        return VIR_CRED_NOECHOPROMPT;

    case SASL_CB_GETREALM:
        return VIR_CRED_REALM;
    }

    return 0;
}

/*
 * @param credtype array of credential types client supports
 * @param ncredtype size of credtype array
 * @return the SASL callback structure, or NULL on error
 *
 * Build up the SASL callback structure. We register one callback for
 * each credential type that the libvirt client indicated they support.
 * We explicitly leav the callback function pointer at NULL though,
 * because we don't actually want to get SASL callbacks triggered.
 * Instead, we want the start/step functions to return SASL_INTERACT.
 * This lets us give the libvirt client a list of all required
 * credentials in one go, rather than triggering the callback one
 * credential at a time,
 */
static sasl_callback_t *remoteAuthMakeCallbacks(int *credtype, int ncredtype)
{
    sasl_callback_t *cbs;
    int i, n;
    if (VIR_ALLOC_N(cbs, ncredtype+1) < 0) {
        return NULL;
    }

    for (i = 0, n = 0 ; i < ncredtype ; i++) {
        int id = remoteAuthCredVir2SASL(credtype[i]);
        if (id != 0)
            cbs[n++].id = id;
        /* Don't fill proc or context fields of sasl_callback_t
         * because we want to use interactions instead */
    }
    cbs[n].id = 0;
    return cbs;
}


/*
 * @param interact SASL interactions required
 * @param cred populated with libvirt credential metadata
 * @return the size of the cred array returned
 *
 * Builds up an array of libvirt credential structs, populating
 * with data from the SASL interaction struct. These two structs
 * are basically a 1-to-1 copy of each other.
 */
static int remoteAuthMakeCredentials(sasl_interact_t *interact,
                                     virConnectCredentialPtr *cred)
{
    int ninteract;
    if (!cred)
        return -1;

    for (ninteract = 0 ; interact[ninteract].id != 0 ; ninteract++)
        ; /* empty */

    if (VIR_ALLOC_N(*cred, ninteract) < 0)
        return -1;

    for (ninteract = 0 ; interact[ninteract].id != 0 ; ninteract++) {
        (*cred)[ninteract].type = remoteAuthCredSASL2Vir(interact[ninteract].id);
        if (!(*cred)[ninteract].type) {
            VIR_FREE(*cred);
            return -1;
        }
        if (interact[ninteract].challenge)
            (*cred)[ninteract].challenge = interact[ninteract].challenge;
        (*cred)[ninteract].prompt = interact[ninteract].prompt;
        if (interact[ninteract].defresult)
            (*cred)[ninteract].defresult = interact[ninteract].defresult;
        (*cred)[ninteract].result = NULL;
    }

    return ninteract;
}

static void remoteAuthFreeCredentials(virConnectCredentialPtr cred,
                                      int ncred)
{
    int i;
    for (i = 0 ; i < ncred ; i++)
        VIR_FREE(cred[i].result);
    VIR_FREE(cred);
}


/*
 * @param cred the populated libvirt credentials
 * @param interact the SASL interactions to fill in results for
 *
 * Fills the SASL interactions with the result from the libvirt
 * callbacks
 */
static void remoteAuthFillInteract(virConnectCredentialPtr cred,
                                   sasl_interact_t *interact)
{
    int ninteract;
    for (ninteract = 0 ; interact[ninteract].id != 0 ; ninteract++) {
        interact[ninteract].result = cred[ninteract].result;
        interact[ninteract].len = cred[ninteract].resultlen;
    }
}

/* Perform the SASL authentication process
 */
static int
remoteAuthSASL (virConnectPtr conn, struct private_data *priv, int in_open,
                virConnectAuthPtr auth, const char *wantmech)
{
    sasl_conn_t *saslconn = NULL;
    sasl_security_properties_t secprops;
    remote_auth_sasl_init_ret iret;
    remote_auth_sasl_start_args sargs;
    remote_auth_sasl_start_ret sret;
    remote_auth_sasl_step_args pargs;
    remote_auth_sasl_step_ret pret;
    const char *clientout;
    char *serverin = NULL;
    unsigned int clientoutlen, serverinlen;
    const char *mech;
    int err, complete;
    struct sockaddr_storage sa;
    socklen_t salen;
    char *localAddr = NULL, *remoteAddr = NULL;
    const void *val;
    sasl_ssf_t ssf;
    sasl_callback_t *saslcb = NULL;
    sasl_interact_t *interact = NULL;
    virConnectCredentialPtr cred = NULL;
    int ncred = 0;
    int ret = -1;
    const char *mechlist;

    DEBUG0("Client initialize SASL authentication");
    /* Sets up the SASL library as a whole */
    err = sasl_client_init(NULL);
    if (err != SASL_OK) {
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("failed to initialize SASL library: %d (%s)"),
                         err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* Get local address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getsockname(priv->sock, (struct sockaddr*)&sa, &salen) < 0) {
        virReportSystemError(in_open ? NULL : conn, errno, "%s",
                             _("failed to get sock address"));
        goto cleanup;
    }
    if ((localAddr = addrToString(&sa, salen)) == NULL)
        goto cleanup;

    /* Get remote address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getpeername(priv->sock, (struct sockaddr*)&sa, &salen) < 0) {
        virReportSystemError(in_open ? NULL : conn, errno, "%s",
                             _("failed to get peer address"));
        goto cleanup;
    }
    if ((remoteAddr = addrToString(&sa, salen)) == NULL)
        goto cleanup;

    if (auth) {
        if ((saslcb = remoteAuthMakeCallbacks(auth->credtype, auth->ncredtype)) == NULL)
            goto cleanup;
    } else {
        saslcb = NULL;
    }

    /* Setup a handle for being a client */
    err = sasl_client_new("libvirt",
                          priv->hostname,
                          localAddr,
                          remoteAddr,
                          saslcb,
                          SASL_SUCCESS_DATA,
                          &saslconn);

    if (err != SASL_OK) {
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("Failed to create SASL client context: %d (%s)"),
                         err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* Initialize some connection props we care about */
    if (priv->uses_tls) {
        gnutls_cipher_algorithm_t cipher;

        cipher = gnutls_cipher_get(priv->session);
        if (!(ssf = (sasl_ssf_t)gnutls_cipher_get_key_size(cipher))) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_INTERNAL_ERROR, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             "%s", _("invalid cipher size for TLS session"));
            goto cleanup;
        }
        ssf *= 8; /* key size is bytes, sasl wants bits */

        DEBUG("Setting external SSF %d", ssf);
        err = sasl_setprop(saslconn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_INTERNAL_ERROR, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("cannot set external SSF %d (%s)"),
                             err, sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
    }

    memset (&secprops, 0, sizeof secprops);
    /* If we've got TLS, we don't care about SSF */
    secprops.min_ssf = priv->uses_tls ? 0 : 56; /* Equiv to DES supported by all Kerberos */
    secprops.max_ssf = priv->uses_tls ? 0 : 100000; /* Very strong ! AES == 256 */
    secprops.maxbufsize = 100000;
    /* If we're not TLS, then forbid any anonymous or trivially crackable auth */
    secprops.security_flags = priv->uses_tls ? 0 :
        SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;

    err = sasl_setprop(saslconn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_INTERNAL_ERROR, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("cannot set security props %d (%s)"),
                         err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* First call is to inquire about supported mechanisms in the server */
    memset (&iret, 0, sizeof iret);
    if (call (conn, priv, in_open, REMOTE_PROC_AUTH_SASL_INIT,
              (xdrproc_t) xdr_void, (char *)NULL,
              (xdrproc_t) xdr_remote_auth_sasl_init_ret, (char *) &iret) != 0)
        goto cleanup;


    mechlist = iret.mechlist;
    if (wantmech) {
        if (strstr(mechlist, wantmech) == NULL) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                             NULL, NULL, NULL, 0, 0,
                             _("SASL mechanism %s not supported by server"),
                             wantmech);
            VIR_FREE(iret.mechlist);
            goto cleanup;
        }
        mechlist = wantmech;
    }
 restart:
    /* Start the auth negotiation on the client end first */
    DEBUG("Client start negotiation mechlist '%s'", mechlist);
    err = sasl_client_start(saslconn,
                            mechlist,
                            &interact,
                            &clientout,
                            &clientoutlen,
                            &mech);
    if (err != SASL_OK && err != SASL_CONTINUE && err != SASL_INTERACT) {
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("Failed to start SASL negotiation: %d (%s)"),
                         err, sasl_errdetail(saslconn));
        VIR_FREE(iret.mechlist);
        goto cleanup;
    }

    /* Need to gather some credentials from the client */
    if (err == SASL_INTERACT) {
        const char *msg;
        if (cred) {
            remoteAuthFreeCredentials(cred, ncred);
            cred = NULL;
        }
        if ((ncred =
             remoteAuthMakeCredentials(interact, &cred)) < 0) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                             NULL, NULL, NULL, 0, 0,
                             "%s", _("Failed to make auth credentials"));
            VIR_FREE(iret.mechlist);
            goto cleanup;
        }
        /* Run the authentication callback */
        if (auth && auth->cb) {
            if ((*(auth->cb))(cred, ncred, auth->cbdata) >= 0) {
                remoteAuthFillInteract(cred, interact);
                goto restart;
            }
            msg = "Failed to collect auth credentials";
        } else {
            msg = "No authentication callback available";
        }
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL,
                         0, 0, "%s", msg);
        goto cleanup;
    }
    VIR_FREE(iret.mechlist);

    if (clientoutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("SASL negotiation data too long: %d bytes"),
                         clientoutlen);
        goto cleanup;
    }
    /* NB, distinction of NULL vs "" is *critical* in SASL */
    memset(&sargs, 0, sizeof sargs);
    sargs.nil = clientout ? 0 : 1;
    sargs.data.data_val = (char*)clientout;
    sargs.data.data_len = clientoutlen;
    sargs.mech = (char*)mech;
    DEBUG("Server start negotiation with mech %s. Data %d bytes %p", mech, clientoutlen, clientout);

    /* Now send the initial auth data to the server */
    memset (&sret, 0, sizeof sret);
    if (call (conn, priv, in_open, REMOTE_PROC_AUTH_SASL_START,
              (xdrproc_t) xdr_remote_auth_sasl_start_args, (char *) &sargs,
              (xdrproc_t) xdr_remote_auth_sasl_start_ret, (char *) &sret) != 0)
        goto cleanup;

    complete = sret.complete;
    /* NB, distinction of NULL vs "" is *critical* in SASL */
    serverin = sret.nil ? NULL : sret.data.data_val;
    serverinlen = sret.data.data_len;
    DEBUG("Client step result complete: %d. Data %d bytes %p",
          complete, serverinlen, serverin);

    /* Loop-the-loop...
     * Even if the server has completed, the client must *always* do at least one step
     * in this loop to verify the server isn't lying about something. Mutual auth */
    for (;;) {
    restep:
        err = sasl_client_step(saslconn,
                               serverin,
                               serverinlen,
                               &interact,
                               &clientout,
                               &clientoutlen);
        if (err != SASL_OK && err != SASL_CONTINUE && err != SASL_INTERACT) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("Failed SASL step: %d (%s)"),
                             err, sasl_errdetail(saslconn));
            goto cleanup;
        }
        /* Need to gather some credentials from the client */
        if (err == SASL_INTERACT) {
            const char *msg;
            if (cred) {
                remoteAuthFreeCredentials(cred, ncred);
                cred = NULL;
            }
            if ((ncred = remoteAuthMakeCredentials(interact, &cred)) < 0) {
                virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                                 VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                                 "%s", _("Failed to make auth credentials"));
                goto cleanup;
            }
            /* Run the authentication callback */
            if (auth && auth->cb) {
                if ((*(auth->cb))(cred, ncred, auth->cbdata) >= 0) {
                    remoteAuthFillInteract(cred, interact);
                    goto restep;
                }
                msg = "Failed to collect auth credentials";
            } else {
                msg = "No authentication callback available";
            }
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL,
                             0, 0, "%s", msg);
            goto cleanup;
        }

        VIR_FREE(serverin);
        DEBUG("Client step result %d. Data %d bytes %p", err, clientoutlen, clientout);

        /* Previous server call showed completion & we're now locally complete too */
        if (complete && err == SASL_OK)
            break;

        /* Not done, prepare to talk with the server for another iteration */
        /* NB, distinction of NULL vs "" is *critical* in SASL */
        memset(&pargs, 0, sizeof pargs);
        pargs.nil = clientout ? 0 : 1;
        pargs.data.data_val = (char*)clientout;
        pargs.data.data_len = clientoutlen;
        DEBUG("Server step with %d bytes %p", clientoutlen, clientout);

        memset (&pret, 0, sizeof pret);
        if (call (conn, priv, in_open, REMOTE_PROC_AUTH_SASL_STEP,
                  (xdrproc_t) xdr_remote_auth_sasl_step_args, (char *) &pargs,
                  (xdrproc_t) xdr_remote_auth_sasl_step_ret, (char *) &pret) != 0)
            goto cleanup;

        complete = pret.complete;
        /* NB, distinction of NULL vs "" is *critical* in SASL */
        serverin = pret.nil ? NULL : pret.data.data_val;
        serverinlen = pret.data.data_len;

        DEBUG("Client step result complete: %d. Data %d bytes %p",
              complete, serverinlen, serverin);

        /* This server call shows complete, and earlier client step was OK */
        if (complete && err == SASL_OK) {
            VIR_FREE(serverin);
            break;
        }
    }

    /* Check for suitable SSF if non-TLS */
    if (!priv->uses_tls) {
        err = sasl_getprop(saslconn, SASL_SSF, &val);
        if (err != SASL_OK) {
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("cannot query SASL ssf on connection %d (%s)"),
                             err, sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
        ssf = *(const int *)val;
        DEBUG("SASL SSF value %d", ssf);
        if (ssf < 56) { /* 56 == DES level, good for Kerberos */
            virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("negotiation SSF %d was not strong enough"), ssf);
            goto cleanup;
        }
    }

    DEBUG0("SASL authentication complete");
    priv->saslconn = saslconn;
    ret = 0;

 cleanup:
    VIR_FREE(localAddr);
    VIR_FREE(remoteAddr);
    VIR_FREE(serverin);

    VIR_FREE(saslcb);
    remoteAuthFreeCredentials(cred, ncred);
    if (ret != 0 && saslconn)
        sasl_dispose(&saslconn);

    return ret;
}
#endif /* HAVE_SASL */


#if HAVE_POLKIT
/* Perform the PolicyKit authentication process
 */
static int
remoteAuthPolkit (virConnectPtr conn, struct private_data *priv, int in_open,
                  virConnectAuthPtr auth)
{
    remote_auth_polkit_ret ret;
    int i, allowcb = 0;
    virConnectCredential cred = {
        VIR_CRED_EXTERNAL,
        conn->flags & VIR_CONNECT_RO ? "org.libvirt.unix.monitor" : "org.libvirt.unix.manage",
        "PolicyKit",
        NULL,
        NULL,
        0,
    };
    DEBUG0("Client initialize PolicyKit authentication");

    if (auth && auth->cb) {
        /* Check if the necessary credential type for PolicyKit is supported */
        for (i = 0 ; i < auth->ncredtype ; i++) {
            if (auth->credtype[i] == VIR_CRED_EXTERNAL)
                allowcb = 1;
        }

        if (allowcb) {
            /* Run the authentication callback */
            if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
                virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                                 VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                                 "%s", _("Failed to collect auth credentials"));
                return -1;
            }
        } else {
            DEBUG0("Client auth callback does not support PolicyKit");
        }
    } else {
        DEBUG0("No auth callback provided");
    }

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, in_open, REMOTE_PROC_AUTH_POLKIT,
              (xdrproc_t) xdr_void, (char *)NULL,
              (xdrproc_t) xdr_remote_auth_polkit_ret, (char *) &ret) != 0) {
        return -1; /* virError already set by call */
    }

    DEBUG0("PolicyKit authentication complete");
    return 0;
}
#endif /* HAVE_POLKIT */
/*----------------------------------------------------------------------*/

static int remoteDomainEventRegister (virConnectPtr conn,
                                      virConnectDomainEventCallback callback,
                                      void *opaque,
                                      virFreeCallback freecb)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (priv->eventFlushTimer < 0) {
         error (conn, VIR_ERR_NO_SUPPORT, _("no event support"));
         goto done;
    }
    if (virDomainEventCallbackListAdd(conn, priv->callbackList,
                                      callback, opaque, freecb) < 0) {
         error (conn, VIR_ERR_RPC, _("adding cb to list"));
         goto done;
    }

    if ( priv->callbackList->count == 1 ) {
        /* Tell the server when we are the first callback deregistering */
        if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_EVENTS_REGISTER,
                (xdrproc_t) xdr_void, (char *) NULL,
                (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteDomainEventDeregister (virConnectPtr conn,
                                        virConnectDomainEventCallback callback)
{
    struct private_data *priv = conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    if (virDomainEventCallbackListRemove(conn, priv->callbackList,
                                         callback) < 0) {
         error (conn, VIR_ERR_RPC, _("removing cb fron list"));
         goto done;
    }

    if ( priv->callbackList->count == 0 ) {
        /* Tell the server when we are the last callback deregistering */
        if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER,
                (xdrproc_t) xdr_void, (char *) NULL,
                (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/


static struct remote_thread_call *
prepareCall(virConnectPtr conn,
            struct private_data *priv,
            int flags,
            int proc_nr,
            xdrproc_t args_filter, char *args,
            xdrproc_t ret_filter, char *ret)
{
    XDR xdr;
    struct remote_message_header hdr;
    struct remote_thread_call *rv;

    if (VIR_ALLOC(rv) < 0)
        return NULL;

    if (virCondInit(&rv->cond) < 0) {
        VIR_FREE(rv);
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_INTERNAL_ERROR,
               _("cannot initialize mutex"));
        return NULL;
    }

    /* Get a unique serial number for this message. */
    rv->serial = priv->counter++;
    rv->proc_nr = proc_nr;
    rv->ret_filter = ret_filter;
    rv->ret = ret;

    hdr.prog = REMOTE_PROGRAM;
    hdr.vers = REMOTE_PROTOCOL_VERSION;
    hdr.proc = proc_nr;
    hdr.direction = REMOTE_CALL;
    hdr.serial = rv->serial;
    hdr.status = REMOTE_OK;

    /* Serialise header followed by args. */
    xdrmem_create (&xdr, rv->buffer+4, REMOTE_MESSAGE_MAX, XDR_ENCODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_RPC, _("xdr_remote_message_header failed"));
        goto error;
    }

    if (!(*args_filter) (&xdr, args)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, VIR_ERR_RPC,
               _("marshalling args"));
        goto error;
    }

    /* Get the length stored in buffer. */
    rv->bufferLength = xdr_getpos (&xdr);
    xdr_destroy (&xdr);

    /* Length must include the length word itself (always encoded in
     * 4 bytes as per RFC 4506).
     */
    rv->bufferLength += REMOTE_MESSAGE_HEADER_XDR_LEN;

    /* Encode the length word. */
    xdrmem_create (&xdr, rv->buffer, REMOTE_MESSAGE_HEADER_XDR_LEN, XDR_ENCODE);
    if (!xdr_u_int (&xdr, &rv->bufferLength)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, VIR_ERR_RPC,
               _("xdr_u_int (length word)"));
        goto error;
    }
    xdr_destroy (&xdr);

    return rv;

error:
    xdr_destroy (&xdr);
    VIR_FREE(rv);
    return NULL;
}



static int
processCallWrite(virConnectPtr conn,
                 struct private_data *priv,
                 int in_open /* if we are in virConnectOpen */,
                 const char *bytes, int len)
{
    int ret;

    if (priv->uses_tls) {
    tls_resend:
        ret = gnutls_record_send (priv->session, bytes, len);
        if (ret < 0) {
            if (ret == GNUTLS_E_INTERRUPTED)
                goto tls_resend;
            if (ret == GNUTLS_E_AGAIN)
                return 0;

            error (in_open ? NULL : conn,
                   VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
            return -1;
        }
    } else {
    resend:
        ret = send (priv->sock, bytes, len, 0);
        if (ret == -1) {
            if (errno == EINTR)
                goto resend;
            if (errno == EWOULDBLOCK)
                return 0;

            virReportSystemError(in_open ? NULL : conn, errno,
                                 "%s", _("cannot send data"));
            return -1;

        }
    }

    return ret;
}


static int
processCallRead(virConnectPtr conn,
                struct private_data *priv,
                int in_open /* if we are in virConnectOpen */,
                char *bytes, int len)
{
    int ret;

    if (priv->uses_tls) {
    tls_resend:
        ret = gnutls_record_recv (priv->session, bytes, len);
        if (ret == GNUTLS_E_INTERRUPTED)
            goto tls_resend;
        if (ret == GNUTLS_E_AGAIN)
            return 0;

        /* Treat 0 == EOF as an error */
        if (ret <= 0) {
            if (ret < 0)
                errorf (in_open ? NULL : conn,
                        VIR_ERR_GNUTLS_ERROR,
                        _("failed to read from TLS socket %s"),
                        gnutls_strerror (ret));
            else
                errorf (in_open ? NULL : conn,
                        VIR_ERR_SYSTEM_ERROR,
                        "%s", _("server closed connection"));
            return -1;
        }
    } else {
    resend:
        ret = recv (priv->sock, bytes, len, 0);
        if (ret <= 0) {
            if (ret == -1) {
                if (errno == EINTR)
                    goto resend;
                if (errno == EWOULDBLOCK)
                    return 0;

                virReportSystemError(in_open ? NULL : conn, errno,
                                     "%s", _("cannot recv data"));
            } else {
                errorf (in_open ? NULL : conn,
                        VIR_ERR_SYSTEM_ERROR,
                        "%s", _("server closed connection"));
            }
            return -1;
        }
    }

    return ret;
}


static int
processCallSendOne(virConnectPtr conn,
                   struct private_data *priv,
                   int in_open,
                   struct remote_thread_call *thecall)
{
#if HAVE_SASL
    if (priv->saslconn) {
        const char *output;
        unsigned int outputlen;
        int err, ret;

        if (!priv->saslEncoded) {
            err = sasl_encode(priv->saslconn,
                              thecall->buffer + thecall->bufferOffset,
                              thecall->bufferLength - thecall->bufferOffset,
                              &output, &outputlen);
            if (err != SASL_OK) {
                errorf (in_open ? NULL : conn, VIR_ERR_INTERNAL_ERROR,
                        _("failed to encode SASL data: %s"),
                        sasl_errstring(err, NULL, NULL));
                return -1;
            }
            priv->saslEncoded = output;
            priv->saslEncodedLength = outputlen;
            priv->saslEncodedOffset = 0;

            thecall->bufferOffset = thecall->bufferLength;
        }

        ret = processCallWrite(conn, priv, in_open,
                               priv->saslEncoded + priv->saslEncodedOffset,
                               priv->saslEncodedLength - priv->saslEncodedOffset);
        if (ret < 0)
            return ret;
        priv->saslEncodedOffset += ret;

        if (priv->saslEncodedOffset == priv->saslEncodedLength) {
            priv->saslEncoded = NULL;
            priv->saslEncodedOffset = priv->saslEncodedLength = 0;
            thecall->mode = REMOTE_MODE_WAIT_RX;
        }
    } else {
#endif
        int ret;
        ret = processCallWrite(conn, priv, in_open,
                               thecall->buffer + thecall->bufferOffset,
                               thecall->bufferLength - thecall->bufferOffset);
        if (ret < 0)
            return ret;
        thecall->bufferOffset += ret;

        if (thecall->bufferOffset == thecall->bufferLength) {
            thecall->bufferOffset = thecall->bufferLength = 0;
            thecall->mode = REMOTE_MODE_WAIT_RX;
        }
#if HAVE_SASL
    }
#endif
    return 0;
}


static int
processCallSend(virConnectPtr conn, struct private_data *priv,
                int in_open) {
    struct remote_thread_call *thecall = priv->waitDispatch;

    while (thecall &&
           thecall->mode != REMOTE_MODE_WAIT_TX)
        thecall = thecall->next;

    if (!thecall)
        return -1; /* Shouldn't happen, but you never know... */

    while (thecall) {
        int ret = processCallSendOne(conn, priv, in_open, thecall);
        if (ret < 0)
            return ret;

        if (thecall->mode == REMOTE_MODE_WAIT_TX)
            return 0; /* Blocking write, to back to event loop */

        thecall = thecall->next;
    }

    return 0; /* No more calls to send, all done */
}

static int
processCallRecvSome(virConnectPtr conn, struct private_data *priv,
                    int in_open) {
    unsigned int wantData;

    /* Start by reading length word */
    if (priv->bufferLength == 0)
        priv->bufferLength = 4;

    wantData = priv->bufferLength - priv->bufferOffset;

#if HAVE_SASL
    if (priv->saslconn) {
        if (priv->saslDecoded == NULL) {
            char encoded[8192];
            unsigned int encodedLen = sizeof(encoded);
            int ret, err;
            ret = processCallRead(conn, priv, in_open,
                                  encoded, encodedLen);
            if (ret < 0)
                return -1;
            if (ret == 0)
                return 0;

            err = sasl_decode(priv->saslconn, encoded, ret,
                              &priv->saslDecoded, &priv->saslDecodedLength);
            if (err != SASL_OK) {
                errorf (in_open ? NULL : conn, VIR_ERR_INTERNAL_ERROR,
                        _("failed to decode SASL data: %s"),
                        sasl_errstring(err, NULL, NULL));
                return -1;
            }
            priv->saslDecodedOffset = 0;
        }

        if ((priv->saslDecodedLength - priv->saslDecodedOffset) < wantData)
            wantData = (priv->saslDecodedLength - priv->saslDecodedOffset);

        memcpy(priv->buffer + priv->bufferOffset,
               priv->saslDecoded + priv->saslDecodedOffset,
               wantData);
        priv->saslDecodedOffset += wantData;
        priv->bufferOffset += wantData;
        if (priv->saslDecodedOffset == priv->saslDecodedLength) {
            priv->saslDecodedLength = priv->saslDecodedLength = 0;
            priv->saslDecoded = NULL;
        }

        return wantData;
    } else {
#endif
        int ret;

        ret = processCallRead(conn, priv, in_open,
                              priv->buffer + priv->bufferOffset,
                              wantData);
        if (ret < 0)
            return -1;
        if (ret == 0)
            return 0;

        priv->bufferOffset += ret;

        return ret;
#if HAVE_SASL
    }
#endif
}


static void
processCallAsyncEvent(virConnectPtr conn, struct private_data *priv,
                      int in_open,
                      remote_message_header *hdr,
                      XDR *xdr) {
    /* An async message has come in while we were waiting for the
     * response. Process it to pull it off the wire, and try again
     */
    DEBUG0("Encountered an event while waiting for a response");

    if (in_open) {
        DEBUG("Ignoring bogus event %d received while in open", hdr->proc);
        return;
    }

    if (hdr->proc == REMOTE_PROC_DOMAIN_EVENT) {
        remoteDomainQueueEvent(conn, xdr);
        virEventUpdateTimeout(priv->eventFlushTimer, 0);
    } else {
        DEBUG("Unexpected event proc %d", hdr->proc);
    }
}

static int
processCallRecvLen(virConnectPtr conn, struct private_data *priv,
                   int in_open) {
    XDR xdr;
    unsigned int len;

    xdrmem_create (&xdr, priv->buffer, priv->bufferLength, XDR_DECODE);
    if (!xdr_u_int (&xdr, &len)) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, _("xdr_u_int (length word, reply)"));
        return -1;
    }
    xdr_destroy (&xdr);

    if (len < REMOTE_MESSAGE_HEADER_XDR_LEN) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, _("packet received from server too small"));
        return -1;
    }

    /* Length includes length word - adjust to real length to read. */
    len -= REMOTE_MESSAGE_HEADER_XDR_LEN;

    if (len > REMOTE_MESSAGE_MAX) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, _("packet received from server too large"));
        return -1;
    }

    /* Extend our declared buffer length and carry
       on reading the header + payload */
    priv->bufferLength += len;
    DEBUG("Got length, now need %d total (%d more)", priv->bufferLength, len);
    return 0;
}


static int
processCallRecvMsg(virConnectPtr conn, struct private_data *priv,
                   int in_open) {
    XDR xdr;
    struct remote_message_header hdr;
    int len = priv->bufferLength - 4;
    struct remote_thread_call *thecall;

    /* Deserialise reply header. */
    xdrmem_create (&xdr, priv->buffer + 4, len, XDR_DECODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, _("invalid header in reply"));
        return -1;
    }

    /* Check program, version, etc. are what we expect. */
    if (hdr.prog != REMOTE_PROGRAM) {
        virRaiseError (in_open ? NULL : conn,
                       NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("unknown program (received %x, expected %x)"),
                       hdr.prog, REMOTE_PROGRAM);
        return -1;
    }
    if (hdr.vers != REMOTE_PROTOCOL_VERSION) {
        virRaiseError (in_open ? NULL : conn,
                       NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("unknown protocol version (received %x, expected %x)"),
                       hdr.vers, REMOTE_PROTOCOL_VERSION);
        return -1;
    }

    /* Async events from server need special handling */
    if (hdr.direction == REMOTE_MESSAGE) {
        processCallAsyncEvent(conn, priv, in_open,
                              &hdr, &xdr);
        xdr_destroy(&xdr);
        return 0;
    }

    if (hdr.direction != REMOTE_REPLY) {
        virRaiseError (in_open ? NULL : conn,
                       NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("got unexpected RPC call %d from server"),
                       hdr.proc);
        xdr_destroy(&xdr);
        return -1;
    }

    /* Ok, definitely got an RPC reply now find
       out who's been waiting for it */

    thecall = priv->waitDispatch;
    while (thecall &&
           thecall->serial != hdr.serial)
        thecall = thecall->next;

    if (!thecall) {
        virRaiseError (in_open ? NULL : conn,
                       NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("no call waiting for reply with serial %d"),
                       hdr.serial);
        xdr_destroy(&xdr);
        return -1;
    }

    if (hdr.proc != thecall->proc_nr) {
        virRaiseError (in_open ? NULL : conn,
                       NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("unknown procedure (received %x, expected %x)"),
                       hdr.proc, thecall->proc_nr);
        xdr_destroy (&xdr);
        return -1;
    }

    /* Status is either REMOTE_OK (meaning that what follows is a ret
     * structure), or REMOTE_ERROR (and what follows is a remote_error
     * structure).
     */
    switch (hdr.status) {
    case REMOTE_OK:
        if (!(*thecall->ret_filter) (&xdr, thecall->ret)) {
            error (in_open ? NULL : conn, VIR_ERR_RPC,
                   _("unmarshalling ret"));
            return -1;
        }
        thecall->mode = REMOTE_MODE_COMPLETE;
        xdr_destroy (&xdr);
        return 0;

    case REMOTE_ERROR:
        memset (&thecall->err, 0, sizeof thecall->err);
        if (!xdr_remote_error (&xdr, &thecall->err)) {
            error (in_open ? NULL : conn,
                   VIR_ERR_RPC, _("unmarshalling remote_error"));
            return -1;
        }
        xdr_destroy (&xdr);
        thecall->mode = REMOTE_MODE_ERROR;
        return 0;

    default:
        virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                       VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                       _("unknown status (received %x)"),
                       hdr.status);
        xdr_destroy (&xdr);
        return -1;
    }
}


static int
processCallRecv(virConnectPtr conn, struct private_data *priv,
                int in_open)
{
    /* Read as much data as is available, until we get
     * EAGAIN
     */
    for (;;) {
        int ret = processCallRecvSome(conn, priv, in_open);

        if (ret < 0)
            return -1;
        if (ret == 0)
            return 0;  /* Blocking on read */

        /* Check for completion of our goal */
        if (priv->bufferOffset == priv->bufferLength) {
            if (priv->bufferOffset == 4) {
                ret = processCallRecvLen(conn, priv, in_open);
                if (ret < 0)
                    return -1;

                /*
                 * We'll carry on around the loop to immediately
                 * process the message body, because it has probably
                 * already arrived. Worst case, we'll get EAGAIN on
                 * next iteration.
                 */
            } else {
                ret = processCallRecvMsg(conn, priv, in_open);
                priv->bufferOffset = priv->bufferLength = 0;
                /*
                 * We've completed one call, so return even
                 * though there might still be more data on
                 * the wire. We need to actually let the caller
                 * deal with this arrived message to keep good
                 * response, and also to correctly handle EOF.
                 */
                return ret;
            }
        }
    }
}

/*
 * Process all calls pending dispatch/receive until we
 * get a reply to our own call. Then quit and pass the buck
 * to someone else.
 */
static int
processCalls(virConnectPtr conn,
             struct private_data *priv,
             int in_open,
             struct remote_thread_call *thiscall)
{
    struct pollfd fds[2];
    int ret;

    fds[0].fd = priv->sock;
    fds[1].fd = priv->wakeupReadFD;

    for (;;) {
        struct remote_thread_call *tmp = priv->waitDispatch;
        struct remote_thread_call *prev;
        char ignore;

        fds[0].events = fds[0].revents = 0;
        fds[1].events = fds[1].revents = 0;

        fds[1].events = POLLIN;
        while (tmp) {
            if (tmp->mode == REMOTE_MODE_WAIT_RX)
                fds[0].events |= POLLIN;
            if (tmp->mode == REMOTE_MODE_WAIT_TX)
                fds[0].events |= POLLOUT;

            tmp = tmp->next;
        }

        /* Release lock while poll'ing so other threads
         * can stuff themselves on the queue */
        remoteDriverUnlock(priv);

    repoll:
        ret = poll(fds, ARRAY_CARDINALITY(fds), -1);
        if (ret < 0 && errno == EINTR)
            goto repoll;
        remoteDriverLock(priv);

        if (fds[1].revents) {
            DEBUG0("Woken up from poll by other thread");
            saferead(priv->wakeupReadFD, &ignore, sizeof(ignore));
        }

        if (ret < 0) {
            if (errno == EWOULDBLOCK)
                continue;
            virReportSystemError(in_open ? NULL : conn, errno,
                                 "%s", _("poll on socket failed"));
            goto error;
        }

        if (fds[0].revents & POLLOUT) {
            if (processCallSend(conn, priv, in_open) < 0)
                goto error;
        }

        if (fds[0].revents & POLLIN) {
            if (processCallRecv(conn, priv, in_open) < 0)
                goto error;
        }

        /* Iterate through waiting threads and if
         * any are complete then tell 'em to wakeup
         */
        tmp = priv->waitDispatch;
        prev = NULL;
        while (tmp) {
            if (tmp != thiscall &&
                (tmp->mode == REMOTE_MODE_COMPLETE ||
                 tmp->mode == REMOTE_MODE_ERROR)) {
                /* Take them out of the list */
                if (prev)
                    prev->next = tmp->next;
                else
                    priv->waitDispatch = tmp->next;

                /* And wake them up....
                 * ...they won't actually wakeup until
                 * we release our mutex a short while
                 * later...
                 */
                DEBUG("Waking up sleep %d %p %p", tmp->proc_nr, tmp, priv->waitDispatch);
                virCondSignal(&tmp->cond);
            }
            prev = tmp;
            tmp = tmp->next;
        }

        /* Now see if *we* are done */
        if (thiscall->mode == REMOTE_MODE_COMPLETE ||
            thiscall->mode == REMOTE_MODE_ERROR) {
            /* We're at head of the list already, so
             * remove us
             */
            priv->waitDispatch = thiscall->next;
            DEBUG("Giving up the buck %d %p %p", thiscall->proc_nr, thiscall, priv->waitDispatch);
            /* See if someone else is still waiting
             * and if so, then pass the buck ! */
            if (priv->waitDispatch) {
                DEBUG("Passing the buck to %d %p", priv->waitDispatch->proc_nr, priv->waitDispatch);
                virCondSignal(&priv->waitDispatch->cond);
            }
            return 0;
        }


        if (fds[0].revents & (POLLHUP | POLLERR)) {
            errorf(in_open ? NULL : conn, VIR_ERR_INTERNAL_ERROR,
                   "%s", _("received hangup / error event on socket"));
            goto error;
        }
    }


error:
    priv->waitDispatch = thiscall->next;
    DEBUG("Giving up the buck due to I/O error %d %p %p", thiscall->proc_nr, thiscall, priv->waitDispatch);
    /* See if someone else is still waiting
     * and if so, then pass the buck ! */
    if (priv->waitDispatch) {
        DEBUG("Passing the buck to %d %p", priv->waitDispatch->proc_nr, priv->waitDispatch);
        virCondSignal(&priv->waitDispatch->cond);
    }
    return -1;
}

/*
 * This function performs a remote procedure call to procedure PROC_NR.
 *
 * NB. This does not free the args structure (not desirable, since you
 * often want this allocated on the stack or else it contains strings
 * which come from the user).  It does however free any intermediate
 * results, eg. the error structure if there is one.
 *
 * NB(2). Make sure to memset (&ret, 0, sizeof ret) before calling,
 * else Bad Things will happen in the XDR code.
 *
 * NB(3) You must have the private_data lock before calling this
 *
 * NB(4) This is very complicated. Due to connection cloning, multiple
 * threads can want to use the socket at once. Obviously only one of
 * them can. So if someone's using the socket, other threads are put
 * to sleep on condition variables. THe existing thread may completely
 * send & receive their RPC call/reply while they're asleep. Or it
 * may only get around to dealing with sending the call. Or it may
 * get around to neither. So upon waking up from slumber, the other
 * thread may or may not have more work todo.
 *
 * We call this dance  'passing the buck'
 *
 *      http://en.wikipedia.org/wiki/Passing_the_buck
 *
 *   "Buck passing or passing the buck is the action of transferring
 *    responsibility or blame unto another person. It is also used as
 *    a strategy in power politics when the actions of one country/
 *    nation are blamed on another, providing an opportunity for war."
 *
 * NB(5) Don't Panic!
 */
static int
call (virConnectPtr conn, struct private_data *priv,
      int flags /* if we are in virConnectOpen */,
      int proc_nr,
      xdrproc_t args_filter, char *args,
      xdrproc_t ret_filter, char *ret)
{
    int rv;
    struct remote_thread_call *thiscall;

    DEBUG("Doing call %d %p", proc_nr, priv->waitDispatch);
    thiscall = prepareCall(conn, priv, flags, proc_nr,
                           args_filter, args,
                           ret_filter, ret);

    if (!thiscall) {
        virReportOOMError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn);
        return -1;
    }

    /* Check to see if another thread is dispatching */
    if (priv->waitDispatch) {
        /* Stick ourselves on the end of the wait queue */
        struct remote_thread_call *tmp = priv->waitDispatch;
        char ignore = 1;
        while (tmp && tmp->next)
            tmp = tmp->next;
        if (tmp)
            tmp->next = thiscall;
        else
            priv->waitDispatch = thiscall;

        /* Force other thread to wakup from poll */
        safewrite(priv->wakeupSendFD, &ignore, sizeof(ignore));

        DEBUG("Going to sleep %d %p %p", proc_nr, priv->waitDispatch, thiscall);
        /* Go to sleep while other thread is working... */
        if (virCondWait(&thiscall->cond, &priv->lock) < 0) {
            if (priv->waitDispatch == thiscall) {
                priv->waitDispatch = thiscall->next;
            } else {
                tmp = priv->waitDispatch;
                while (tmp && tmp->next &&
                       tmp->next != thiscall) {
                    tmp = tmp->next;
                }
                if (tmp && tmp->next == thiscall)
                    tmp->next = thiscall->next;
            }
            errorf(flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                   VIR_ERR_INTERNAL_ERROR, "%s",
                   _("failed to wait on condition"));
            VIR_FREE(thiscall);
            return -1;
        }

        DEBUG("Wokeup from sleep %d %p %p", proc_nr, priv->waitDispatch, thiscall);
        /* Two reasons we can be woken up
         *  1. Other thread has got our reply ready for us
         *  2. Other thread is all done, and it is our turn to
         *     be the dispatcher to finish waiting for
         *     our reply
         */
        if (thiscall->mode == REMOTE_MODE_COMPLETE ||
            thiscall->mode == REMOTE_MODE_ERROR) {
            /*
             * We avoided catching the buck and our reply is ready !
             * We've already had 'thiscall' removed from the list
             * so just need to (maybe) handle errors & free it
             */
            goto cleanup;
        }

        /* Grr, someone passed the buck onto us ... */

    } else {
        /* We're first to catch the buck */
        priv->waitDispatch = thiscall;
    }

    DEBUG("We have the buck %d %p %p", proc_nr, priv->waitDispatch, thiscall);
    /*
     * The buck stops here!
     *
     * At this point we're about to own the dispatch
     * process...
     */

    /*
     * Avoid needless wake-ups of the event loop in the
     * case where this call is being made from a different
     * thread than the event loop. These wake-ups would
     * cause the event loop thread to be blocked on the
     * mutex for the duration of the call
     */
    if (priv->watch >= 0)
        virEventUpdateHandle(priv->watch, 0);

    rv = processCalls(conn, priv,
                      flags & REMOTE_CALL_IN_OPEN ? 1 : 0,
                      thiscall);

    if (priv->watch >= 0)
        virEventUpdateHandle(priv->watch, VIR_EVENT_HANDLE_READABLE);

    if (rv < 0) {
        VIR_FREE(thiscall);
        return -1;
    }

cleanup:
    DEBUG("All done with our call %d %p %p", proc_nr, priv->waitDispatch, thiscall);
    if (thiscall->mode == REMOTE_MODE_ERROR) {
        /* See if caller asked us to keep quiet about missing RPCs
         * eg for interop with older servers */
        if (flags & REMOTE_CALL_QUIET_MISSING_RPC &&
            thiscall->err.domain == VIR_FROM_REMOTE &&
            thiscall->err.code == VIR_ERR_RPC &&
            thiscall->err.level == VIR_ERR_ERROR &&
            thiscall->err.message &&
            STRPREFIX(*thiscall->err.message, "unknown procedure")) {
            rv = -2;
        } else {
            server_error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                          &thiscall->err);
            rv = -1;
        }
        xdr_free((xdrproc_t)xdr_remote_error,  (char *)&thiscall->err);
    } else {
        rv = 0;
    }
    VIR_FREE(thiscall);
    return rv;
}

/**
 * remoteDomainReadEvent
 *
 * Read the event data off the wire
 */
static virDomainEventPtr
remoteDomainReadEvent(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_ret ret;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&ret, 0, sizeof ret);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_ret(xdr, &ret) ) {
        error (conn, VIR_ERR_RPC,
               _("remoteDomainProcessEvent: unmarshalling ret"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,ret.dom);
    if (!dom)
        return NULL;

    event = virDomainEventNewFromDom(dom, ret.event, ret.detail);

    virDomainFree(dom);
    return event;
}

static void
remoteDomainQueueEvent(virConnectPtr conn, XDR *xdr)
{
    struct private_data *priv = conn->privateData;
    virDomainEventPtr event;

    event = remoteDomainReadEvent(conn, xdr);
    if (!event)
        return;

    if (virDomainEventQueuePush(priv->domainEvents,
                                event) < 0) {
        DEBUG0("Error adding event to queue");
        virDomainEventFree(event);
    }
}

/** remoteDomainEventFired:
 *
 * The callback for monitoring the remote socket
 * for event data
 */
void
remoteDomainEventFired(int watch,
                       int fd,
                       int event,
                       void *opaque)
{
    virConnectPtr        conn = opaque;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    /* This should be impossible, but it doesn't hurt to check */
    if (priv->waitDispatch)
        goto done;

    DEBUG("Event fired %d %d %d %X", watch, fd, event, event);

    if (event & (VIR_EVENT_HANDLE_HANGUP | VIR_EVENT_HANDLE_ERROR)) {
         DEBUG("%s : VIR_EVENT_HANDLE_HANGUP or "
               "VIR_EVENT_HANDLE_ERROR encountered", __FUNCTION__);
         virEventRemoveHandle(watch);
         priv->watch = -1;
         goto done;
    }

    if (fd != priv->sock) {
        virEventRemoveHandle(watch);
        priv->watch = -1;
        goto done;
    }

    if (processCallRecv(conn, priv, 0) < 0)
        DEBUG0("Something went wrong during async message processing");

done:
    remoteDriverUnlock(priv);
}

void
remoteDomainEventQueueFlush(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    virDomainEventQueueDispatch(priv->domainEvents, priv->callbackList,
                                virDomainEventDispatchDefaultFunc, NULL);
    virEventUpdateTimeout(priv->eventFlushTimer, -1);

    remoteDriverUnlock(priv);
}


/* For errors internal to this library. */
static void
error (virConnectPtr conn, virErrorNumber code, const char *info)
{
    const char *errmsg;

    errmsg = virErrorMsg (code, info);
    virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
                     code, VIR_ERR_ERROR, errmsg, info, NULL, 0, 0,
                     errmsg, info);
}

/* For errors internal to this library.
   Identical to the above, but with a format string and optional params.  */
static void
errorf (virConnectPtr conn, virErrorNumber code, const char *fmt, ...)
{
    const char *errmsg;
    va_list args;
    char errorMessage[256];

    if (fmt) {
        va_start(args, fmt);
        vsnprintf(errorMessage, sizeof errorMessage - 1, fmt, args);
        va_end(args);
    } else {
        errorMessage[0] = '\0';
    }

    errmsg = virErrorMsg (code, errorMessage);
    virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
                     code, VIR_ERR_ERROR,
                     errmsg, errorMessage, NULL, -1, -1,
                     errmsg, errorMessage);
}

/* For errors generated on the server side and sent back to us. */
static void
server_error (virConnectPtr conn, remote_error *err)
{
    virDomainPtr dom;
    virNetworkPtr net;

    /* Get the domain and network, if set. */
    dom = err->dom ? get_nonnull_domain (conn, *err->dom) : NULL;
    net = err->net ? get_nonnull_network (conn, *err->net) : NULL;

    virRaiseError (conn, dom, net,
                     err->domain, err->code, err->level,
                     err->str1 ? *err->str1 : NULL,
                     err->str2 ? *err->str2 : NULL,
                     err->str3 ? *err->str3 : NULL,
                     err->int1, err->int2,
                     "%s", err->message ? *err->message : NULL);
    if (dom)
        virDomainFree(dom);
    if (net)
        virNetworkFree(net);
}

/* get_nonnull_domain and get_nonnull_network turn an on-wire
 * (name, uuid) pair into virDomainPtr or virNetworkPtr object.
 * These can return NULL if underlying memory allocations fail,
 * but if they do then virterror_internal.has been set.
 */
static virDomainPtr
get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain)
{
    virDomainPtr dom;
    dom = virGetDomain (conn, domain.name, BAD_CAST domain.uuid);
    if (dom) dom->id = domain.id;
    return dom;
}

static virNetworkPtr
get_nonnull_network (virConnectPtr conn, remote_nonnull_network network)
{
    return virGetNetwork (conn, network.name, BAD_CAST network.uuid);
}

static virStoragePoolPtr
get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool)
{
    return virGetStoragePool (conn, pool.name, BAD_CAST pool.uuid);
}

static virStorageVolPtr
get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol)
{
    return virGetStorageVol (conn, vol.pool, vol.name, vol.key);
}

static virNodeDevicePtr
get_nonnull_node_device (virConnectPtr conn, remote_nonnull_node_device dev)
{
    return virGetNodeDevice(conn, dev.name);
}

/* Make remote_nonnull_domain and remote_nonnull_network. */
static void
make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src)
{
    dom_dst->id = dom_src->id;
    dom_dst->name = dom_src->name;
    memcpy (dom_dst->uuid, dom_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src)
{
    net_dst->name = net_src->name;
    memcpy (net_dst->uuid, net_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr pool_src)
{
    pool_dst->name = pool_src->name;
    memcpy (pool_dst->uuid, pool_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src)
{
    vol_dst->pool = vol_src->pool;
    vol_dst->name = vol_src->name;
    vol_dst->key = vol_src->key;
}

/*----------------------------------------------------------------------*/

unsigned long remoteVersion(void)
{
    return REMOTE_PROTOCOL_VERSION;
}

static virDriver driver = {
    VIR_DRV_REMOTE,
    "remote",
    remoteOpen, /* open */
    remoteClose, /* close */
    remoteSupportsFeature, /* supports_feature */
    remoteType, /* type */
    remoteGetVersion, /* version */
    remoteGetHostname, /* getHostname */
    remoteGetMaxVcpus, /* getMaxVcpus */
    remoteNodeGetInfo, /* nodeGetInfo */
    remoteGetCapabilities, /* getCapabilities */
    remoteListDomains, /* listDomains */
    remoteNumOfDomains, /* numOfDomains */
    remoteDomainCreateXML, /* domainCreateXML */
    remoteDomainLookupByID, /* domainLookupByID */
    remoteDomainLookupByUUID, /* domainLookupByUUID */
    remoteDomainLookupByName, /* domainLookupByName */
    remoteDomainSuspend, /* domainSuspend */
    remoteDomainResume, /* domainResume */
    remoteDomainShutdown, /* domainShutdown */
    remoteDomainReboot, /* domainReboot */
    remoteDomainDestroy, /* domainDestroy */
    remoteDomainGetOSType, /* domainGetOSType */
    remoteDomainGetMaxMemory, /* domainGetMaxMemory */
    remoteDomainSetMaxMemory, /* domainSetMaxMemory */
    remoteDomainSetMemory, /* domainSetMemory */
    remoteDomainGetInfo, /* domainGetInfo */
    remoteDomainSave, /* domainSave */
    remoteDomainRestore, /* domainRestore */
    remoteDomainCoreDump, /* domainCoreDump */
    remoteDomainSetVcpus, /* domainSetVcpus */
    remoteDomainPinVcpu, /* domainPinVcpu */
    remoteDomainGetVcpus, /* domainGetVcpus */
    remoteDomainGetMaxVcpus, /* domainGetMaxVcpus */
    remoteDomainGetSecurityLabel, /* domainGetSecurityLabel */
    remoteNodeGetSecurityModel, /* nodeGetSecurityModel */
    remoteDomainDumpXML, /* domainDumpXML */
    remoteListDefinedDomains, /* listDefinedDomains */
    remoteNumOfDefinedDomains, /* numOfDefinedDomains */
    remoteDomainCreate, /* domainCreate */
    remoteDomainDefineXML, /* domainDefineXML */
    remoteDomainUndefine, /* domainUndefine */
    remoteDomainAttachDevice, /* domainAttachDevice */
    remoteDomainDetachDevice, /* domainDetachDevice */
    remoteDomainGetAutostart, /* domainGetAutostart */
    remoteDomainSetAutostart, /* domainSetAutostart */
    remoteDomainGetSchedulerType, /* domainGetSchedulerType */
    remoteDomainGetSchedulerParameters, /* domainGetSchedulerParameters */
    remoteDomainSetSchedulerParameters, /* domainSetSchedulerParameters */
    remoteDomainMigratePrepare, /* domainMigratePrepare */
    remoteDomainMigratePerform, /* domainMigratePerform */
    remoteDomainMigrateFinish, /* domainMigrateFinish */
    remoteDomainBlockStats, /* domainBlockStats */
    remoteDomainInterfaceStats, /* domainInterfaceStats */
    remoteDomainBlockPeek, /* domainBlockPeek */
    remoteDomainMemoryPeek, /* domainMemoryPeek */
    remoteNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    remoteNodeGetFreeMemory, /* getFreeMemory */
    remoteDomainEventRegister, /* domainEventRegister */
    remoteDomainEventDeregister, /* domainEventDeregister */
    remoteDomainMigratePrepare2, /* domainMigratePrepare2 */
    remoteDomainMigrateFinish2, /* domainMigrateFinish2 */
    remoteNodeDeviceDettach, /* nodeDeviceDettach */
    remoteNodeDeviceReAttach, /* nodeDeviceReAttach */
    remoteNodeDeviceReset, /* nodeDeviceReset */
};

static virNetworkDriver network_driver = {
    .name = "remote",
    .open = remoteNetworkOpen,
    .close = remoteNetworkClose,
    .numOfNetworks = remoteNumOfNetworks,
    .listNetworks = remoteListNetworks,
    .numOfDefinedNetworks = remoteNumOfDefinedNetworks,
    .listDefinedNetworks = remoteListDefinedNetworks,
    .networkLookupByUUID = remoteNetworkLookupByUUID,
    .networkLookupByName = remoteNetworkLookupByName,
    .networkCreateXML = remoteNetworkCreateXML,
    .networkDefineXML = remoteNetworkDefineXML,
    .networkUndefine = remoteNetworkUndefine,
    .networkCreate = remoteNetworkCreate,
    .networkDestroy = remoteNetworkDestroy,
    .networkDumpXML = remoteNetworkDumpXML,
    .networkGetBridgeName = remoteNetworkGetBridgeName,
    .networkGetAutostart = remoteNetworkGetAutostart,
    .networkSetAutostart = remoteNetworkSetAutostart,
};

static virStorageDriver storage_driver = {
    .name = "remote",
    .open = remoteStorageOpen,
    .close = remoteStorageClose,
    .numOfPools = remoteNumOfStoragePools,
    .listPools = remoteListStoragePools,
    .numOfDefinedPools = remoteNumOfDefinedStoragePools,
    .listDefinedPools = remoteListDefinedStoragePools,
    .findPoolSources = remoteFindStoragePoolSources,
    .poolLookupByName = remoteStoragePoolLookupByName,
    .poolLookupByUUID = remoteStoragePoolLookupByUUID,
    .poolLookupByVolume = remoteStoragePoolLookupByVolume,
    .poolCreateXML = remoteStoragePoolCreateXML,
    .poolDefineXML = remoteStoragePoolDefineXML,
    .poolBuild = remoteStoragePoolBuild,
    .poolUndefine = remoteStoragePoolUndefine,
    .poolCreate = remoteStoragePoolCreate,
    .poolDestroy = remoteStoragePoolDestroy,
    .poolDelete = remoteStoragePoolDelete,
    .poolRefresh = remoteStoragePoolRefresh,
    .poolGetInfo = remoteStoragePoolGetInfo,
    .poolGetXMLDesc = remoteStoragePoolDumpXML,
    .poolGetAutostart = remoteStoragePoolGetAutostart,
    .poolSetAutostart = remoteStoragePoolSetAutostart,
    .poolNumOfVolumes = remoteStoragePoolNumOfVolumes,
    .poolListVolumes = remoteStoragePoolListVolumes,

    .volLookupByName = remoteStorageVolLookupByName,
    .volLookupByKey = remoteStorageVolLookupByKey,
    .volLookupByPath = remoteStorageVolLookupByPath,
    .volCreateXML = remoteStorageVolCreateXML,
    .volDelete = remoteStorageVolDelete,
    .volGetInfo = remoteStorageVolGetInfo,
    .volGetXMLDesc = remoteStorageVolDumpXML,
    .volGetPath = remoteStorageVolGetPath,
};

static virDeviceMonitor dev_monitor = {
    .name = "remote",
    .open = remoteDevMonOpen,
    .close = remoteDevMonClose,
    .numOfDevices = remoteNodeNumOfDevices,
    .listDevices = remoteNodeListDevices,
    .deviceLookupByName = remoteNodeDeviceLookupByName,
    .deviceDumpXML = remoteNodeDeviceDumpXML,
    .deviceGetParent = remoteNodeDeviceGetParent,
    .deviceNumOfCaps = remoteNodeDeviceNumOfCaps,
    .deviceListCaps = remoteNodeDeviceListCaps,
};


#ifdef WITH_LIBVIRTD
static virStateDriver state_driver = {
    .initialize = remoteStartup,
};
#endif


/** remoteRegister:
 *
 * Register driver with libvirt driver system.
 *
 * Returns -1 on error.
 */
int
remoteRegister (void)
{
    if (virRegisterDriver (&driver) == -1) return -1;
    if (virRegisterNetworkDriver (&network_driver) == -1) return -1;
    if (virRegisterStorageDriver (&storage_driver) == -1) return -1;
    if (virRegisterDeviceMonitor (&dev_monitor) == -1) return -1;
#ifdef WITH_LIBVIRTD
    if (virRegisterStateDriver (&state_driver) == -1) return -1;
#endif

    return 0;
}
