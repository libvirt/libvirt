/*
 * remote_internal.c: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2007-2010 Red Hat, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/wait.h>

/* Windows socket compatibility functions. */
#include <errno.h>
#include <sys/socket.h>

#ifndef HAVE_WINSOCK2_H /* Unix & Cygwin. */
# include <sys/un.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif

#ifdef HAVE_PWD_H
# include <pwd.h>
#endif

#ifdef HAVE_PATHS_H
# include <paths.h>
#endif

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "gnutls_1_0_compat.h"
#if HAVE_SASL
# include <sasl/sasl.h>
#endif
#include <libxml/uri.h>

#include <netdb.h>

#include <poll.h>

#include "virterror_internal.h"
#include "logging.h"
#include "datatypes.h"
#include "domain_event.h"
#include "driver.h"
#include "buf.h"
#include "qparams.h"
#include "remote_driver.h"
#include "remote_protocol.h"
#include "qemu_protocol.h"
#include "memory.h"
#include "util.h"
#include "event.h"
#include "ignore-value.h"
#include "files.h"

#define VIR_FROM_THIS VIR_FROM_REMOTE

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

    /* Buffer for outgoing data packet
     * 4 byte length, followed by RPC message header+body */
    char buffer[4 + REMOTE_MESSAGE_MAX];
    unsigned int bufferLength;
    unsigned int bufferOffset;

    unsigned int serial;
    unsigned int proc_nr;

    virCond cond;

    int want_reply;
    xdrproc_t ret_filter;
    char *ret;

    remote_error err;

    struct remote_thread_call *next;
};

struct private_stream_data {
    unsigned int has_error : 1;
    remote_error err;

    unsigned int serial;
    unsigned int proc_nr;

    virStreamEventCallback cb;
    void *cbOpaque;
    virFreeCallback cbFree;
    int cbEvents;
    int cbTimer;
    int cbDispatch;

    /* XXX this is potentially unbounded if the client
     * app has domain events registered, since packets
     * may be read off wire, while app isn't ready to
     * recv them. Figure out how to address this some
     * time....
     */
    char *incoming;
    unsigned int incomingOffset;
    unsigned int incomingLength;

    struct private_stream_data *next;
};

struct private_data {
    virMutex lock;

    int sock;                   /* Socket. */
    int errfd;                /* File handle connected to remote stderr */
    int watch;                  /* File handle watch */
    pid_t pid;                  /* PID of tunnel process */
    int uses_tls;               /* TLS enabled on socket? */
    int is_secure;              /* Secure if TLS or SASL or UNIX sockets */
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

    /* Buffer for incoming data packets
     * 4 byte length, followed by RPC message header+body */
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
    /* Flag if we're in process of dispatching */
    int domainEventDispatching;

    /* Self-pipe to wakeup threads waiting in poll() */
    int wakeupSendFD;
    int wakeupReadFD;

    /* List of threads currently waiting for dispatch */
    struct remote_thread_call *waitDispatch;

    struct private_stream_data *streams;
};

enum {
    REMOTE_CALL_IN_OPEN           = (1 << 0),
    REMOTE_CALL_QUIET_MISSING_RPC = (1 << 1),
    REMOTE_CALL_QEMU              = (1 << 2),
    REMOTE_CALL_NONBLOCK          = (1 << 3),
};


static void remoteDriverLock(struct private_data *driver)
{
    virMutexLock(&driver->lock);
}

static void remoteDriverUnlock(struct private_data *driver)
{
    virMutexUnlock(&driver->lock);
}

static int remoteIO(virConnectPtr conn,
                    struct private_data *priv,
                    int flags,
                    struct remote_thread_call *thiscall);
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

#define remoteError(code, ...)                                    \
    virReportErrorHelper(NULL, VIR_FROM_REMOTE, code, __FILE__,   \
                         __FUNCTION__, __LINE__, __VA_ARGS__)

static virDomainPtr get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network (virConnectPtr conn, remote_nonnull_network network);
static virNWFilterPtr get_nonnull_nwfilter (virConnectPtr conn, remote_nonnull_nwfilter nwfilter);
static virInterfacePtr get_nonnull_interface (virConnectPtr conn, remote_nonnull_interface iface);
static virStoragePoolPtr get_nonnull_storage_pool (virConnectPtr conn, remote_nonnull_storage_pool pool);
static virStorageVolPtr get_nonnull_storage_vol (virConnectPtr conn, remote_nonnull_storage_vol vol);
static virNodeDevicePtr get_nonnull_node_device (virConnectPtr conn, remote_nonnull_node_device dev);
static virSecretPtr get_nonnull_secret (virConnectPtr conn, remote_nonnull_secret secret);
static virDomainSnapshotPtr get_nonnull_domain_snapshot (virDomainPtr domain, remote_nonnull_domain_snapshot snapshot);
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_interface (remote_nonnull_interface *interface_dst, virInterfacePtr interface_src);
static void make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr vol_src);
static void make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);
static void make_nonnull_secret (remote_nonnull_secret *secret_dst, virSecretPtr secret_src);
static void make_nonnull_nwfilter (remote_nonnull_nwfilter *nwfilter_dst, virNWFilterPtr nwfilter_src);
static void make_nonnull_domain_snapshot (remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src);
void remoteDomainEventFired(int watch, int fd, int event, void *data);
void remoteDomainEventQueueFlush(int timer, void *opaque);
/*----------------------------------------------------------------------*/

/* Helper functions for remoteOpen. */
static char *get_transport_from_scheme (char *scheme);

/* GnuTLS functions used by remoteOpen. */
static int initialize_gnutls(void);
static gnutls_session_t negotiate_gnutls_on_connection (virConnectPtr conn, struct private_data *priv, int no_verify);

#ifdef WITH_LIBVIRTD
static int
remoteStartup(int privileged ATTRIBUTE_UNUSED)
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
remoteForkDaemon(void)
{
    const char *daemonPath = remoteFindDaemonPath();
    const char *const daemonargs[] = { daemonPath, "--timeout=30", NULL };
    pid_t pid;

    if (!daemonPath) {
        remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("failed to find libvirtd binary"));
        return -1;
    }

    if (virExecDaemonize(daemonargs, NULL, NULL,
                         &pid, -1, NULL, NULL,
                         VIR_EXEC_CLEAR_CAPS,
                         NULL, NULL, NULL) < 0)
        return -1;

    return 0;
}
#endif

enum virDrvOpenRemoteFlags {
    VIR_DRV_OPEN_REMOTE_RO = (1 << 0),
    VIR_DRV_OPEN_REMOTE_USER      = (1 << 1), /* Use the per-user socket path */
    VIR_DRV_OPEN_REMOTE_AUTOSTART = (1 << 2), /* Autostart a per-user daemon */
};


/*
 * URIs that this driver needs to handle:
 *
 * The easy answer:
 *   - Everything that no one else has yet claimed, but nothing if
 *     we're inside the libvirtd daemon
 *
 * The hard answer:
 *   - Plain paths (///var/lib/xen/xend-socket)  -> UNIX domain socket
 *   - xxx://servername/      -> TLS connection
 *   - xxx+tls://servername/  -> TLS connection
 *   - xxx+tls:///            -> TLS connection to localhost
 *   - xxx+tcp://servername/  -> TCP connection
 *   - xxx+tcp:///            -> TCP connection to localhost
 *   - xxx+unix:///           -> UNIX domain socket
 *   - xxx:///                -> UNIX domain socket
 */
static int
doRemoteOpen (virConnectPtr conn,
              struct private_data *priv,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              int flags)
{
    struct qparam_set *vars = NULL;
    int wakeupFD[2] = { -1, -1 };
    char *transport_str = NULL;
    enum {
        trans_tls,
        trans_unix,
        trans_ssh,
        trans_ext,
        trans_tcp,
    } transport;

    /* We handle *ALL*  URIs here. The caller has rejected any
     * URIs we don't care about */

    if (conn->uri) {
        if (!conn->uri->scheme) {
            /* This is the ///var/lib/xen/xend-socket local path style */
            transport = trans_unix;
        } else {
            transport_str = get_transport_from_scheme (conn->uri->scheme);

            if (!transport_str) {
                if (conn->uri->server)
                    transport = trans_tls;
                else
                    transport = trans_unix;
            } else {
                if (STRCASEEQ (transport_str, "tls"))
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
                    remoteError(VIR_ERR_INVALID_ARG, "%s",
                                _("remote_open: transport in URL not recognised "
                                  "(should be tls|unix|ssh|ext|tcp)"));
                    return VIR_DRV_OPEN_ERROR;
                }
            }
        }
    } else {
        /* No URI, then must be probing so use UNIX socket */
        transport = trans_unix;
    }

    /* Local variables which we will initialize. These can
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
            if (conn->uri->scheme &&
                (STREQ(conn->uri->scheme, "remote") ||
                 STRPREFIX(conn->uri->scheme, "remote+"))) {
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
        vars = NULL;
    } else {
        /* Probe URI server side */
        name = strdup("");
    }

    if (!name) {
        virReportOOMError();
        goto failed;
    }

    DEBUG("proceeding with name = %s", name);

    /* For ext transport, command is required. */
    if (transport == trans_ext && !command) {
        remoteError(VIR_ERR_INVALID_ARG, "%s",
                    _("remote_open: for 'ext' transport, command is required"));
        goto failed;
    }

    /* Connect to the remote service. */
    switch (transport) {
    case trans_tls:
        if (initialize_gnutls() == -1) goto failed;
        priv->uses_tls = 1;
        priv->is_secure = 1;

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
            remoteError(VIR_ERR_SYSTEM_ERROR,
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
                VIR_FORCE_CLOSE(priv->sock);
                continue;
            }

            if (priv->uses_tls) {
                priv->session =
                    negotiate_gnutls_on_connection
                      (conn, priv, no_verify);
                if (!priv->session) {
                    VIR_FORCE_CLOSE(priv->sock);
                    goto failed;
                }
            }
            goto tcp_connected;
        }

        freeaddrinfo (res);
        virReportSystemError(saved_errno,
                             _("unable to connect to libvirtd at '%s'"),
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
                char *userdir = virGetUserDirectory(getuid());

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

# ifndef UNIX_PATH_MAX
#  define UNIX_PATH_MAX(addr) (sizeof (addr).sun_path)
# endif
        struct sockaddr_un addr;
        int trials = 0;

        memset (&addr, 0, sizeof addr);
        addr.sun_family = AF_UNIX;
        if (virStrcpyStatic(addr.sun_path, sockname) == NULL) {
            remoteError(VIR_ERR_INTERNAL_ERROR,
                        _("Socket %s too big for destination"), sockname);
            goto failed;
        }
        if (addr.sun_path[0] == '@')
            addr.sun_path[0] = '\0';

      autostart_retry:
        priv->is_secure = 1;
        priv->sock = socket (AF_UNIX, SOCK_STREAM, 0);
        if (priv->sock == -1) {
            virReportSystemError(errno, "%s",
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
                VIR_FORCE_CLOSE(priv->sock);
                if (trials > 0 ||
                    remoteForkDaemon() == 0) {
                    trials++;
                    usleep(1000 * 100 * trials);
                    goto autostart_retry;
                }
            }
            virReportSystemError(errno,
              _("unable to connect to '%s', libvirtd may need to be started"),
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
        cmd_argv[j++] = strdup (sockname ? sockname :
                                (flags & VIR_CONNECT_RO
                                 ? LIBVIRTD_PRIV_UNIX_SOCKET_RO
                                 : LIBVIRTD_PRIV_UNIX_SOCKET));
        cmd_argv[j++] = 0;
        assert (j == nr_args);
        for (j = 0; j < (nr_args-1); j++)
            if (cmd_argv[j] == NULL)
                goto out_of_memory;

        priv->is_secure = 1;
    }

        /*FALLTHROUGH*/
    case trans_ext: {
        pid_t pid;
        int sv[2];
        int errfd[2];

        /* Fork off the external process.  Use socketpair to create a private
         * (unnamed) Unix domain socket to the child process so we don't have
         * to faff around with two file descriptors (a la 'pipe(2)').
         */
        if (socketpair (PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
            virReportSystemError(errno, "%s",
                                 _("unable to create socket pair"));
            goto failed;
        }

        if (pipe(errfd) == -1) {
            virReportSystemError(errno, "%s",
                                 _("unable to create socket pair"));
            goto failed;
        }

        if (virExec((const char**)cmd_argv, NULL, NULL,
                    &pid, sv[1], &(sv[1]), &(errfd[1]),
                    VIR_EXEC_CLEAR_CAPS) < 0)
            goto failed;

        /* Parent continues here. */
        VIR_FORCE_CLOSE(sv[1]);
        VIR_FORCE_CLOSE(errfd[1]);
        priv->sock = sv[0];
        priv->errfd = errfd[0];
        priv->pid = pid;

        /* Do not set 'is_secure' flag since we can't guarentee
         * an external program is secure, and this flag must be
         * pessimistic */
    }
#else /* WIN32 */

    case trans_unix:
    case trans_ssh:
    case trans_ext:
        remoteError(VIR_ERR_INVALID_ARG, "%s",
                    _("transport methods unix, ssh and ext are not supported "
                      "under Windows"));
        goto failed;

#endif /* WIN32 */

    } /* switch (transport) */

    if (virSetNonBlock(priv->sock) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to make socket non-blocking"));
        goto failed;
    }

    if ((priv->errfd != -1) && virSetNonBlock(priv->errfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to make socket non-blocking"));
        goto failed;
    }

    if (pipe(wakeupFD) < 0) {
        virReportSystemError(errno, "%s",
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
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("unable to auto-detect URI"));
            goto failed;
        }
        if (urierr == -1) {
            goto failed;
        }

        DEBUG("Auto-probed URI is %s", uriret.uri);
        conn->uri = xmlParseURI(uriret.uri);
        VIR_FREE(uriret.uri);
        if (!conn->uri) {
            virReportOOMError();
            goto failed;
        }
    }

    if(VIR_ALLOC(priv->callbackList)<0) {
        virReportOOMError();
        goto failed;
    }

    if(VIR_ALLOC(priv->domainEvents)<0) {
        virReportOOMError();
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
    virReportOOMError();
    if (vars)
        free_qparam_set (vars);

 failed:
    /* Close the socket if we failed. */
    VIR_FORCE_CLOSE(priv->errfd);

    if (priv->sock >= 0) {
        if (priv->uses_tls && priv->session) {
            gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
            gnutls_deinit (priv->session);
        }
        VIR_FORCE_CLOSE(priv->sock);
#ifndef WIN32
        if (priv->pid > 0) {
            pid_t reap;
            do {
retry:
                reap = waitpid(priv->pid, NULL, 0);
                if (reap == -1 && errno == EINTR)
                    goto retry;
            } while (reap != -1 && reap != priv->pid);
        }
#endif
    }

    VIR_FORCE_CLOSE(wakeupFD[0]);
    VIR_FORCE_CLOSE(wakeupFD[1]);

    VIR_FREE(priv->hostname);
    goto cleanup;
}

static struct private_data *
remoteAllocPrivateData(void)
{
    struct private_data *priv;
    if (VIR_ALLOC(priv) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&priv->lock) < 0) {
        remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize mutex"));
        VIR_FREE(priv);
        return NULL;
    }
    remoteDriverLock(priv);
    priv->localUses = 1;
    priv->watch = -1;
    priv->sock = -1;
    priv->errfd = -1;

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

    if (!((*priv) = remoteAllocPrivateData()))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

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
    const char *autostart = getenv("LIBVIRT_AUTOSTART");

    if (inside_daemon && (!conn->uri || (conn->uri && !conn->uri->server)))
        return VIR_DRV_OPEN_DECLINED;

    if (!(priv = remoteAllocPrivateData()))
        return VIR_DRV_OPEN_ERROR;

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

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
        (STREQ(conn->uri->path, "/session") ||
         STRPREFIX(conn->uri->scheme, "test+")) &&
        getuid() > 0) {
        DEBUG0("Auto-spawn user daemon instance");
        rflags |= VIR_DRV_OPEN_REMOTE_USER;
        if (!autostart ||
            STRNEQ(autostart, "0"))
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
#ifndef __sun
        if (getuid() > 0) {
            DEBUG0("Auto-spawn user daemon instance");
            rflags |= VIR_DRV_OPEN_REMOTE_USER;
            if (!autostart ||
                STRNEQ(autostart, "0"))
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
check_cert_file(const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        virReportSystemError(errno,
                             _("Cannot access %s '%s'"),
                             type, file);
        return -1;
    }
    return 0;
}


static void remote_debug_gnutls_log(int level, const char* str) {
    DEBUG("%d %s", level, str);
}

static int
initialize_gnutls(void)
{
    static int initialized = 0;
    int err;
    char *gnutlsdebug;

    if (initialized) return 0;

    gnutls_global_init ();

    if ((gnutlsdebug = getenv("LIBVIRT_GNUTLS_DEBUG")) != NULL) {
        int val;
        if (virStrToLong_i(gnutlsdebug, NULL, 10, &val) < 0)
            val = 10;
        gnutls_global_set_log_level(val);
        gnutls_global_set_log_function(remote_debug_gnutls_log);
    }

    /* X509 stuff */
    err = gnutls_certificate_allocate_credentials (&x509_cred);
    if (err) {
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to allocate TLS credentials: %s"),
                    gnutls_strerror (err));
        return -1;
    }


    if (check_cert_file("CA certificate", LIBVIRT_CACERT) < 0)
        return -1;
    if (check_cert_file("client key", LIBVIRT_CLIENTKEY) < 0)
        return -1;
    if (check_cert_file("client certificate", LIBVIRT_CLIENTCERT) < 0)
        return -1;

    /* Set the trusted CA cert. */
    DEBUG("loading CA file %s", LIBVIRT_CACERT);
    err =
        gnutls_certificate_set_x509_trust_file (x509_cred, LIBVIRT_CACERT,
                                                GNUTLS_X509_FMT_PEM);
    if (err < 0) {
        remoteError(VIR_ERR_GNUTLS_ERROR,
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
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to load private key/certificate: %s"),
                    gnutls_strerror (err));
        return -1;
    }

    initialized = 1;
    return 0;
}

static int verify_certificate (virConnectPtr conn, struct private_data *priv, gnutls_session_t session);

#if HAVE_WINSOCK2_H
static ssize_t
custom_gnutls_push(void *s, const void *buf, size_t len)
{
    return send((size_t)s, buf, len, 0);
}

static ssize_t
custom_gnutls_pull(void *s, void *buf, size_t len)
{
    return recv((size_t)s, buf, len, 0);
}
#endif

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
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to initialize TLS client: %s"),
                    gnutls_strerror (err));
        return NULL;
    }

    /* Use default priorities */
    err = gnutls_set_default_priority (session);
    if (err) {
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to set TLS algorithm priority: %s"),
                    gnutls_strerror (err));
        return NULL;
    }
    err =
        gnutls_certificate_type_set_priority (session,
                                              cert_type_priority);
    if (err) {
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to set certificate priority: %s"),
                    gnutls_strerror (err));
        return NULL;
    }

    /* put the x509 credentials to the current session
     */
    err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (err) {
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to set session credentials: %s"),
                    gnutls_strerror (err));
        return NULL;
    }

    gnutls_transport_set_ptr (session,
                              (gnutls_transport_ptr_t) (long) priv->sock);

#if HAVE_WINSOCK2_H
    /* Make sure GnuTLS uses gnulib's replacment functions for send() and
     * recv() on Windows */
    gnutls_transport_set_push_function(session, custom_gnutls_push);
    gnutls_transport_set_pull_function(session, custom_gnutls_pull);
#endif

    /* Perform the TLS handshake. */
 again:
    err = gnutls_handshake (session);
    if (err < 0) {
        if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED)
            goto again;
        remoteError(VIR_ERR_GNUTLS_ERROR,
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
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to complete TLS initialization: %s"),
                    gnutls_strerror (len));
        return NULL;
    }
    if (len != 1 || buf[0] != '\1') {
        remoteError(VIR_ERR_RPC, "%s",
                    _("server verification (of our certificate or IP "
                      "address) failed"));
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
        remoteError(VIR_ERR_GNUTLS_ERROR,
                    _("unable to verify server certificate: %s"),
                    gnutls_strerror (ret));
        return -1;
    }

    if ((now = time(NULL)) == ((time_t)-1)) {
        virReportSystemError(errno, "%s",
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

        remoteError(VIR_ERR_RPC,
                    _("server certificate failed validation: %s"),
                    reason);
        return -1;
    }

    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
        remoteError(VIR_ERR_RPC,  "%s",_("Certificate type is not X.509"));
        return -1;
    }

    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        remoteError(VIR_ERR_RPC,  "%s",_("gnutls_certificate_get_peers failed"));
        return -1;
    }

    for (i = 0 ; i < nCerts ; i++) {
        gnutls_x509_crt_t cert;

        ret = gnutls_x509_crt_init (&cert);
        if (ret < 0) {
            remoteError(VIR_ERR_GNUTLS_ERROR,
                        _("unable to initialize certificate: %s"),
                        gnutls_strerror (ret));
            return -1;
        }

        ret = gnutls_x509_crt_import (cert, &certs[i], GNUTLS_X509_FMT_DER);
        if (ret < 0) {
            remoteError(VIR_ERR_GNUTLS_ERROR,
                        _("unable to import certificate: %s"),
                        gnutls_strerror (ret));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            remoteError(VIR_ERR_RPC, "%s", _("The certificate has expired"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            remoteError(VIR_ERR_RPC, "%s",
                        _("The certificate is not yet activated"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (i == 0) {
            if (!gnutls_x509_crt_check_hostname (cert, priv->hostname)) {
                remoteError(VIR_ERR_RPC,
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
    if (priv->eventFlushTimer >= 0) {
        /* Remove timeout */
        virEventRemoveTimeout(priv->eventFlushTimer);
        /* Remove handle for remote events */
        virEventRemoveHandle(priv->watch);
        priv->watch = -1;
    }

    if (call (conn, priv, 0, REMOTE_PROC_CLOSE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    /* Close socket. */
    if (priv->uses_tls && priv->session) {
        gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
        gnutls_deinit (priv->session);
    }
#if HAVE_SASL
    if (priv->saslconn)
        sasl_dispose (&priv->saslconn);
#endif
    VIR_FORCE_CLOSE(priv->sock);
    VIR_FORCE_CLOSE(priv->errfd);

#ifndef WIN32
    if (priv->pid > 0) {
        pid_t reap;
        do {
retry:
            reap = waitpid(priv->pid, NULL, 0);
            if (reap == -1 && errno == EINTR)
                goto retry;
        } while (reap != -1 && reap != priv->pid);
    }
#endif
    VIR_FORCE_CLOSE(priv->wakeupReadFD);
    VIR_FORCE_CLOSE(priv->wakeupSendFD);


    /* Free hostname copy */
    VIR_FREE(priv->hostname);

    /* See comment for remoteType. */
    VIR_FREE(priv->type);

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

static int
remoteGetLibVersion (virConnectPtr conn, unsigned long *libVer)
{
    int rv = -1;
    remote_get_lib_version_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_LIB_VERSION,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_lib_version_ret,
              (char *) &ret) == -1)
        goto done;

    if (libVer) *libVer = ret.lib_ver;
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

static int remoteIsSecure(virConnectPtr conn)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;
    remote_is_secure_ret ret;
    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_IS_SECURE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_is_secure_ret, (char *) &ret) == -1)
        goto done;

    /* We claim to be secure, if the remote driver
     * transport itself is secure, and the remote
     * HV connection is secure
     *
     * ie, we don't want to claim to be secure if the
     * remote driver is used to connect to a XenD
     * driver using unencrypted HTTP:/// access
     */
    rv = priv->is_secure && ret.secure ? 1 : 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteIsEncrypted(virConnectPtr conn)
{
    int rv = -1;
    int encrypted = 0;
    struct private_data *priv = conn->privateData;
    remote_is_secure_ret ret;
    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_IS_SECURE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_is_secure_ret, (char *) &ret) == -1)
        goto done;

    if (priv->uses_tls)
        encrypted = 1;
#if HAVE_SASL
    else if (priv->saslconn)
        encrypted = 1;
#endif


    /* We claim to be encrypted, if the remote driver
     * transport itself is encrypted, and the remote
     * HV connection is secure.
     *
     * Yes, we really don't check the remote 'encrypted'
     * option, since it will almost always be false,
     * even if secure (eg UNIX sockets).
     */
    rv = encrypted && ret.secure ? 1 : 0;

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

    if (virStrcpyStatic(info->model, ret.model) == NULL)
        goto done;
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
        remoteError(VIR_ERR_RPC,
                    _("too many NUMA cells: %d > %d"),
                    maxCells, REMOTE_NODE_MAX_CELLS);
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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
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

static int
remoteDomainIsActive(virDomainPtr domain)
{
    int rv = -1;
    remote_domain_is_active_args args;
    remote_domain_is_active_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_IS_ACTIVE,
              (xdrproc_t) xdr_remote_domain_is_active_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_is_active_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.active;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainIsPersistent(virDomainPtr domain)
{
    int rv = -1;
    remote_domain_is_persistent_args args;
    remote_domain_is_persistent_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_IS_PERSISTENT,
              (xdrproc_t) xdr_remote_domain_is_persistent_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_is_persistent_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.persistent;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainIsUpdated(virDomainPtr domain)
{
    int rv = -1;
    remote_domain_is_updated_args args;
    remote_domain_is_updated_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_IS_UPDATED,
              (xdrproc_t) xdr_remote_domain_is_updated_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_is_updated_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.updated;

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
    domain->id = -1;

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
remoteDomainSetMemoryParameters (virDomainPtr domain,
                                 virMemoryParameterPtr params,
                                 int nparams,
                                 unsigned int flags)
{
    int rv = -1;
    remote_domain_set_memory_parameters_args args;
    int i, do_error;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    /* Serialise the memory parameters. */
    args.params.params_len = nparams;
    args.flags = flags;
    if (VIR_ALLOC_N(args.params.params_val, nparams) < 0) {
        virReportOOMError();
        goto done;
    }

    do_error = 0;
    for (i = 0; i < nparams; ++i) {
        // call() will free this:
        args.params.params_val[i].field = strdup (params[i].field);
        if (args.params.params_val[i].field == NULL) {
            virReportOOMError();
            do_error = 1;
        }
        args.params.params_val[i].value.type = params[i].type;
        switch (params[i].type) {
        case VIR_DOMAIN_MEMORY_PARAM_INT:
            args.params.params_val[i].value.remote_memory_param_value_u.i =
                params[i].value.i; break;
        case VIR_DOMAIN_MEMORY_PARAM_UINT:
            args.params.params_val[i].value.remote_memory_param_value_u.ui =
                params[i].value.ui; break;
        case VIR_DOMAIN_MEMORY_PARAM_LLONG:
            args.params.params_val[i].value.remote_memory_param_value_u.l =
                params[i].value.l; break;
        case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
            args.params.params_val[i].value.remote_memory_param_value_u.ul =
                params[i].value.ul; break;
        case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
            args.params.params_val[i].value.remote_memory_param_value_u.d =
                params[i].value.d; break;
        case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
            args.params.params_val[i].value.remote_memory_param_value_u.b =
                params[i].value.b; break;
        default:
            remoteError(VIR_ERR_RPC, "%s", _("unknown parameter type"));
            do_error = 1;
        }
    }

    if (do_error) {
        xdr_free ((xdrproc_t) xdr_remote_domain_set_memory_parameters_args,
                  (char *) &args);
        goto done;
    }

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_MEMORY_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_set_memory_parameters_args,
              (char *) &args, (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetMemoryParameters (virDomainPtr domain,
                                 virMemoryParameterPtr params, int *nparams,
                                 unsigned int flags)
{
    int rv = -1;
    remote_domain_get_memory_parameters_args args;
    remote_domain_get_memory_parameters_ret ret;
    int i = -1;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.nparams = *nparams;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MEMORY_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_get_memory_parameters_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_memory_parameters_ret, (char *) &ret) == -1)
        goto done;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_DOMAIN_MEMORY_PARAMETERS_MAX ||
        ret.params.params_len > *nparams) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("remoteDomainGetMemoryParameters: "
                      "returned number of parameters exceeds limit"));
        goto cleanup;
    }
    /* Handle the case when the caller does not know the number of parameters
     * and is asking for the number of parameters supported
     */
    if (*nparams == 0) {
        *nparams = ret.nparams;
        rv = 0;
        goto cleanup;
    }

    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    for (i = 0; i < *nparams; ++i) {
        if (virStrcpyStatic(params[i].field, ret.params.params_val[i].field) == NULL) {
            remoteError(VIR_ERR_INTERNAL_ERROR,
                        _("Parameter %s too big for destination"),
                        ret.params.params_val[i].field);
            goto cleanup;
        }
        params[i].type = ret.params.params_val[i].value.type;
        switch (params[i].type) {
        case VIR_DOMAIN_MEMORY_PARAM_INT:
            params[i].value.i =
                ret.params.params_val[i].value.remote_memory_param_value_u.i;
            break;
        case VIR_DOMAIN_MEMORY_PARAM_UINT:
            params[i].value.ui =
                ret.params.params_val[i].value.remote_memory_param_value_u.ui;
            break;
        case VIR_DOMAIN_MEMORY_PARAM_LLONG:
            params[i].value.l =
                ret.params.params_val[i].value.remote_memory_param_value_u.l;
            break;
        case VIR_DOMAIN_MEMORY_PARAM_ULLONG:
            params[i].value.ul =
                ret.params.params_val[i].value.remote_memory_param_value_u.ul;
            break;
        case VIR_DOMAIN_MEMORY_PARAM_DOUBLE:
            params[i].value.d =
                ret.params.params_val[i].value.remote_memory_param_value_u.d;
            break;
        case VIR_DOMAIN_MEMORY_PARAM_BOOLEAN:
            params[i].value.b =
                ret.params.params_val[i].value.remote_memory_param_value_u.b;
            break;
        default:
            remoteError(VIR_ERR_RPC, "%s",
                        _("remoteDomainGetMemoryParameters: "
                          "unknown parameter type"));
            goto cleanup;
        }
    }

    rv = 0;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_domain_get_memory_parameters_ret,
              (char *) &ret);
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
remoteDomainSetVcpusFlags (virDomainPtr domain, unsigned int nvcpus,
                           unsigned int flags)
{
    int rv = -1;
    remote_domain_set_vcpus_flags_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.nvcpus = nvcpus;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_VCPUS_FLAGS,
              (xdrproc_t) xdr_remote_domain_set_vcpus_flags_args,
              (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetVcpusFlags (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_get_vcpus_flags_args args;
    remote_domain_get_vcpus_flags_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_VCPUS_FLAGS,
              (xdrproc_t) xdr_remote_domain_get_vcpus_flags_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_vcpus_flags_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
                    _("vCPU count exceeds maximum: %d > %d"),
                    maxinfo, REMOTE_VCPUINFO_MAX);
        goto done;
    }
    if (maxinfo * maplen > REMOTE_CPUMAPS_MAX) {
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
                    _("host reports too many vCPUs: %d > %d"),
                    ret.info.info_len, maxinfo);
        goto cleanup;
    }
    if (ret.cpumaps.cpumaps_len > maxinfo * maplen) {
        remoteError(VIR_ERR_RPC,
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
    memset (seclabel, 0, sizeof (*seclabel));

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SECURITY_LABEL,
              (xdrproc_t) xdr_remote_domain_get_security_label_args, (char *)&args,
              (xdrproc_t) xdr_remote_domain_get_security_label_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.label.label_val != NULL) {
        if (strlen (ret.label.label_val) >= sizeof seclabel->label) {
            remoteError(VIR_ERR_RPC, _("security label exceeds maximum: %zd"),
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
    memset (secmodel, 0, sizeof (*secmodel));

    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_SECURITY_MODEL,
              (xdrproc_t) xdr_void, NULL,
              (xdrproc_t) xdr_remote_node_get_security_model_ret, (char *)&ret) == -1) {
        goto done;
    }

    if (ret.model.model_val != NULL) {
        if (strlen (ret.model.model_val) >= sizeof secmodel->model) {
            remoteError(VIR_ERR_RPC, _("security model exceeds maximum: %zd"),
                        sizeof secmodel->model - 1);
            goto done;
        }
        strcpy (secmodel->model, ret.model.model_val);
    }

    if (ret.doi.doi_val != NULL) {
        if (strlen (ret.doi.doi_val) >= sizeof secmodel->doi) {
            remoteError(VIR_ERR_RPC, _("security doi exceeds maximum: %zd"),
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

static char *
remoteDomainXMLFromNative (virConnectPtr conn,
                           const char *format,
                           const char *config,
                           unsigned int flags)
{
    char *rv = NULL;
    remote_domain_xml_from_native_args args;
    remote_domain_xml_from_native_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.nativeFormat = (char *)format;
    args.nativeConfig = (char *)config;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_XML_FROM_NATIVE,
              (xdrproc_t) xdr_remote_domain_xml_from_native_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_xml_from_native_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.domainXml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static char *
remoteDomainXMLToNative (virConnectPtr conn,
                         const char *format,
                         const char *xml,
                         unsigned int flags)
{
    char *rv = NULL;
    remote_domain_xml_to_native_args args;
    remote_domain_xml_to_native_ret ret;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    args.nativeFormat = (char *)format;
    args.domainXml = (char *)xml;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_XML_TO_NATIVE,
              (xdrproc_t) xdr_remote_domain_xml_to_native_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_xml_to_native_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.nativeConfig;

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
        if (!cookie || !cookielen) {
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("caller ignores cookie or cookielen"));
            goto error;
        }
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out) {
        if (!uri_out) {
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("caller ignores uri_out"));
            goto error;
        }
        *uri_out = *ret.uri_out; /* Caller frees. */
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
error:
    if (ret.cookie.cookie_len)
        VIR_FREE(ret.cookie.cookie_val);
    if (ret.uri_out)
        VIR_FREE(*ret.uri_out);
    goto done;
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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
                    _("too many remote domain names: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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
    remote_domain_lookup_by_uuid_args args2;
    remote_domain_lookup_by_uuid_ret ret2;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE,
              (xdrproc_t) xdr_remote_domain_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    /* Need to do a lookup figure out ID of newly started guest, because
     * bug in design of REMOTE_PROC_DOMAIN_CREATE means we aren't getting
     * it returned.
     */
    memcpy (args2.uuid, domain->uuid, VIR_UUID_BUFLEN);
    memset (&ret2, 0, sizeof ret2);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_args, (char *) &args2,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret2) == -1)
        goto done;

    domain->id = ret2.dom.id;
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret2);

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainCreateWithFlags (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_create_with_flags_args args;
    remote_domain_create_with_flags_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE_WITH_FLAGS,
              (xdrproc_t) xdr_remote_domain_create_with_flags_args,
              (char *) &args,
              (xdrproc_t) xdr_remote_domain_create_with_flags_ret,
              (char *) &ret) == -1)
        goto done;

    domain->id = ret.dom.id;
    xdr_free ((xdrproc_t) &xdr_remote_domain_create_with_flags_ret,
              (char *) &ret);

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
remoteDomainAttachDeviceFlags (virDomainPtr domain, const char *xml,
                               unsigned int flags)
{
    int rv = -1;
    remote_domain_attach_device_flags_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_ATTACH_DEVICE_FLAGS,
              (xdrproc_t) xdr_remote_domain_attach_device_flags_args, (char *) &args,
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
remoteDomainDetachDeviceFlags (virDomainPtr domain, const char *xml,
                               unsigned int flags)
{
    int rv = -1;
    remote_domain_detach_device_flags_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DETACH_DEVICE_FLAGS,
              (xdrproc_t) xdr_remote_domain_detach_device_flags_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainUpdateDeviceFlags (virDomainPtr domain, const char *xml,
                               unsigned int flags)
{
    int rv = -1;
    remote_domain_update_device_flags_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_UPDATE_DEVICE_FLAGS,
              (xdrproc_t) xdr_remote_domain_update_device_flags_args, (char *) &args,
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
        remoteError(VIR_ERR_RPC, "%s",
                    _("remoteDomainGetSchedulerParameters: "
                      "returned number of parameters exceeds limit"));
        goto cleanup;
    }
    *nparams = ret.params.params_len;

    /* Deserialise the result. */
    for (i = 0; i < *nparams; ++i) {
        if (virStrcpyStatic(params[i].field, ret.params.params_val[i].field) == NULL) {
            remoteError(VIR_ERR_INTERNAL_ERROR,
                        _("Parameter %s too big for destination"),
                        ret.params.params_val[i].field);
            goto cleanup;
        }
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
            remoteError(VIR_ERR_RPC, "%s",
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
        virReportOOMError();
        goto done;
    }

    do_error = 0;
    for (i = 0; i < nparams; ++i) {
        // call() will free this:
        args.params.params_val[i].field = strdup (params[i].field);
        if (args.params.params_val[i].field == NULL) {
            virReportOOMError();
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
            remoteError(VIR_ERR_RPC, "%s", _("unknown parameter type"));
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
remoteDomainMemoryStats (virDomainPtr domain,
                         struct _virDomainMemoryStat *stats,
                         unsigned int nr_stats)
{
    int rv = -1;
    remote_domain_memory_stats_args args;
    remote_domain_memory_stats_ret ret;
    struct private_data *priv = domain->conn->privateData;
    unsigned int i;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    if (nr_stats > REMOTE_DOMAIN_MEMORY_STATS_MAX) {
        remoteError(VIR_ERR_RPC,
                    _("too many memory stats requested: %d > %d"), nr_stats,
                    REMOTE_DOMAIN_MEMORY_STATS_MAX);
        goto done;
    }
    args.maxStats = nr_stats;
    args.flags = 0;
    memset (&ret, 0, sizeof ret);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MEMORY_STATS,
              (xdrproc_t) xdr_remote_domain_memory_stats_args,
                (char *) &args,
              (xdrproc_t) xdr_remote_domain_memory_stats_ret,
                (char *) &ret) == -1)
        goto done;

    for (i = 0; i < ret.stats.stats_len; i++) {
        stats[i].tag = ret.stats.stats_val[i].tag;
        stats[i].val = ret.stats.stats_val[i].val;
    }
    rv = ret.stats.stats_len;
    xdr_free((xdrproc_t) xdr_remote_domain_memory_stats_ret, (char *) &ret);

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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC, "%s",
                    _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy (buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    VIR_FREE(ret.buffer.buffer_val);

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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC, "%s",
                    _("returned buffer is not same size as requested"));
        goto cleanup;
    }

    memcpy (buffer, ret.buffer.buffer_val, size);
    rv = 0;

cleanup:
    VIR_FREE(ret.buffer.buffer_val);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainGetBlockInfo (virDomainPtr domain,
                          const char *path,
                          virDomainBlockInfoPtr info,
                          unsigned int flags)
{
    int rv = -1;
    remote_domain_get_block_info_args args;
    remote_domain_get_block_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.path = (char*)path;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_BLOCK_INFO,
              (xdrproc_t) xdr_remote_domain_get_block_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_block_info_ret, (char *) &ret) == -1)
        goto done;

    info->allocation = ret.allocation;
    info->capacity = ret.capacity;
    info->physical = ret.physical;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainManagedSave (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_managed_save_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MANAGED_SAVE,
              (xdrproc_t) xdr_remote_domain_managed_save_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainHasManagedSaveImage (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_has_managed_save_image_args args;
    remote_domain_has_managed_save_image_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_HAS_MANAGED_SAVE_IMAGE,
              (xdrproc_t) xdr_remote_domain_has_managed_save_image_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_has_managed_save_image_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.ret;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteDomainManagedSaveRemove (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_managed_save_remove_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MANAGED_SAVE_REMOVE,
              (xdrproc_t) xdr_remote_domain_managed_save_remove_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteNetworkOpen (virConnectPtr conn,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
                    _("too many remote networks: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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
        remoteError(VIR_ERR_RPC,
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
        remoteError(VIR_ERR_RPC,
                    _("too many remote networks: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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

static int
remoteNetworkIsActive(virNetworkPtr network)
{
    int rv = -1;
    remote_network_is_active_args args;
    remote_network_is_active_ret ret;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_IS_ACTIVE,
              (xdrproc_t) xdr_remote_network_is_active_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_is_active_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.active;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNetworkIsPersistent(virNetworkPtr network)
{
    int rv = -1;
    remote_network_is_persistent_args args;
    remote_network_is_persistent_ret ret;
    struct private_data *priv = network->conn->networkPrivateData;

    remoteDriverLock(priv);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_IS_PERSISTENT,
              (xdrproc_t) xdr_remote_network_is_persistent_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_is_persistent_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.persistent;

done:
    remoteDriverUnlock(priv);
    return rv;
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

static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteInterfaceOpen (virConnectPtr conn,
                     virConnectAuthPtr auth,
                     int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv;

       /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        priv = conn->privateData;
        remoteDriverLock(priv);
        priv->localUses++;
        conn->interfacePrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for interface APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the interface APIs.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->interfacePrivateData = priv;
        return ret;
    }
}

static int
remoteInterfaceClose (virConnectPtr conn)
{
    int rv = 0;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        rv = doRemoteClose(conn, priv);
        conn->interfacePrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfInterfaces (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_interfaces_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_INTERFACES,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_interfaces_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListInterfaces (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_interfaces_args args;
    remote_list_interfaces_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_INTERFACE_NAME_LIST_MAX) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote interfaces: %d > %d"),
                    maxnames, REMOTE_INTERFACE_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_INTERFACES,
              (xdrproc_t) xdr_remote_list_interfaces_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_interfaces_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote interfaces: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_interfaces_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteNumOfDefinedInterfaces (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_defined_interfaces_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_INTERFACES,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_interfaces_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteListDefinedInterfaces (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_defined_interfaces_args args;
    remote_list_defined_interfaces_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote interfaces: %d > %d"),
                    maxnames, REMOTE_DEFINED_INTERFACE_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_INTERFACES,
              (xdrproc_t) xdr_remote_list_defined_interfaces_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_interfaces_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote interfaces: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_defined_interfaces_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virInterfacePtr
remoteInterfaceLookupByName (virConnectPtr conn,
                             const char *name)
{
    virInterfacePtr iface = NULL;
    remote_interface_lookup_by_name_args args;
    remote_interface_lookup_by_name_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_INTERFACE_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_interface_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_interface_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    iface = get_nonnull_interface (conn, ret.iface);
    xdr_free ((xdrproc_t) &xdr_remote_interface_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return iface;
}

static virInterfacePtr
remoteInterfaceLookupByMACString (virConnectPtr conn,
                                  const char *mac)
{
    virInterfacePtr iface = NULL;
    remote_interface_lookup_by_mac_string_args args;
    remote_interface_lookup_by_mac_string_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    args.mac = (char *) mac;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_INTERFACE_LOOKUP_BY_MAC_STRING,
              (xdrproc_t) xdr_remote_interface_lookup_by_mac_string_args, (char *) &args,
              (xdrproc_t) xdr_remote_interface_lookup_by_mac_string_ret, (char *) &ret) == -1)
        goto done;

    iface = get_nonnull_interface (conn, ret.iface);
    xdr_free ((xdrproc_t) &xdr_remote_interface_lookup_by_mac_string_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return iface;
}


static int
remoteInterfaceIsActive(virInterfacePtr iface)
{
    int rv = -1;
    remote_interface_is_active_args args;
    remote_interface_is_active_ret ret;
    struct private_data *priv = iface->conn->interfacePrivateData;

    remoteDriverLock(priv);

    make_nonnull_interface (&args.iface, iface);

    if (call (iface->conn, priv, 0, REMOTE_PROC_INTERFACE_IS_ACTIVE,
              (xdrproc_t) xdr_remote_interface_is_active_args, (char *) &args,
              (xdrproc_t) xdr_remote_interface_is_active_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.active;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static char *
remoteInterfaceGetXMLDesc (virInterfacePtr iface,
                           unsigned int flags)
{
    char *rv = NULL;
    remote_interface_get_xml_desc_args args;
    remote_interface_get_xml_desc_ret ret;
    struct private_data *priv = iface->conn->interfacePrivateData;

    remoteDriverLock(priv);

    make_nonnull_interface (&args.iface, iface);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (iface->conn, priv, 0, REMOTE_PROC_INTERFACE_GET_XML_DESC,
              (xdrproc_t) xdr_remote_interface_get_xml_desc_args, (char *) &args,
              (xdrproc_t) xdr_remote_interface_get_xml_desc_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virInterfacePtr
remoteInterfaceDefineXML (virConnectPtr conn,
                          const char *xmlDesc,
                          unsigned int flags)
{
    virInterfacePtr iface = NULL;
    remote_interface_define_xml_args args;
    remote_interface_define_xml_ret ret;
    struct private_data *priv = conn->interfacePrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_INTERFACE_DEFINE_XML,
              (xdrproc_t) xdr_remote_interface_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_interface_define_xml_ret, (char *) &ret) == -1)
        goto done;

    iface = get_nonnull_interface (conn, ret.iface);
    xdr_free ((xdrproc_t) &xdr_remote_interface_define_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return iface;
}

static int
remoteInterfaceUndefine (virInterfacePtr iface)
{
    int rv = -1;
    remote_interface_undefine_args args;
    struct private_data *priv = iface->conn->interfacePrivateData;

    remoteDriverLock(priv);

    make_nonnull_interface (&args.iface, iface);

    if (call (iface->conn, priv, 0, REMOTE_PROC_INTERFACE_UNDEFINE,
              (xdrproc_t) xdr_remote_interface_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteInterfaceCreate (virInterfacePtr iface,
                       unsigned int flags)
{
    int rv = -1;
    remote_interface_create_args args;
    struct private_data *priv = iface->conn->interfacePrivateData;

    remoteDriverLock(priv);

    make_nonnull_interface (&args.iface, iface);
    args.flags = flags;

    if (call (iface->conn, priv, 0, REMOTE_PROC_INTERFACE_CREATE,
              (xdrproc_t) xdr_remote_interface_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteInterfaceDestroy (virInterfacePtr iface,
                        unsigned int flags)
{
    int rv = -1;
    remote_interface_destroy_args args;
    struct private_data *priv = iface->conn->interfacePrivateData;

    remoteDriverLock(priv);

    make_nonnull_interface (&args.iface, iface);
    args.flags = flags;

    if (call (iface->conn, priv, 0, REMOTE_PROC_INTERFACE_DESTROY,
              (xdrproc_t) xdr_remote_interface_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/

static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteStorageOpen (virConnectPtr conn,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
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
        remoteError(VIR_ERR_RPC, "%s", _("too many storage pools requested"));
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        remoteError(VIR_ERR_RPC, "%s", _("too many storage pools received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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
        remoteError(VIR_ERR_RPC, "%s", _("too many storage pools requested"));
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        remoteError(VIR_ERR_RPC, "%s", _("too many storage pools received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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


static int
remoteStoragePoolIsActive(virStoragePoolPtr pool)
{
    int rv = -1;
    remote_storage_pool_is_active_args args;
    remote_storage_pool_is_active_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_IS_ACTIVE,
              (xdrproc_t) xdr_remote_storage_pool_is_active_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_is_active_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.active;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int
remoteStoragePoolIsPersistent(virStoragePoolPtr pool)
{
    int rv = -1;
    remote_storage_pool_is_persistent_args args;
    remote_storage_pool_is_persistent_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_IS_PERSISTENT,
              (xdrproc_t) xdr_remote_storage_pool_is_persistent_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_is_persistent_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.persistent;

done:
    remoteDriverUnlock(priv);
    return rv;
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
        remoteError(VIR_ERR_RPC, "%s", _("too many storage volumes requested"));
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
        remoteError(VIR_ERR_RPC, "%s", _("too many storage volumes received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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

static virStorageVolPtr
remoteStorageVolCreateXMLFrom (virStoragePoolPtr pool,
                               const char *xmlDesc,
                               virStorageVolPtr clonevol,
                               unsigned int flags)
{
    virStorageVolPtr newvol = NULL;
    remote_storage_vol_create_xml_from_args args;
    remote_storage_vol_create_xml_from_ret ret;
    struct private_data *priv = pool->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_pool (&args.pool, pool);
    make_nonnull_storage_vol (&args.clonevol, clonevol);
    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_CREATE_XML_FROM,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_from_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_from_ret, (char *) &ret) == -1)
        goto done;

    newvol = get_nonnull_storage_vol (pool->conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_create_xml_from_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return newvol;
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
remoteStorageVolWipe(virStorageVolPtr vol,
                     unsigned int flags)
{
    int rv = -1;
    remote_storage_vol_wipe_args args;
    struct private_data *priv = vol->conn->storagePrivateData;

    remoteDriverLock(priv);

    make_nonnull_storage_vol(&args.vol, vol);
    args.flags = flags;

    if (call(vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_WIPE,
             (xdrproc_t) xdr_remote_storage_vol_wipe_args, (char *) &args,
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

static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteDevMonOpen(virConnectPtr conn,
                 virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                 int flags ATTRIBUTE_UNUSED)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
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
        remoteError(VIR_ERR_RPC, "%s", _("too many device names requested"));
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
        remoteError(VIR_ERR_RPC, "%s", _("too many device names received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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
        remoteError(VIR_ERR_RPC, "%s", _("too many capability names requested"));
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
        remoteError(VIR_ERR_RPC, "%s", _("too many capability names received"));
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

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
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of devMonPrivateData */
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
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of devMonPrivateData */
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
    /* This method is unusual in that it uses the HV driver, not the devMon driver
     * hence its use of privateData, instead of devMonPrivateData */
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


static virNodeDevicePtr
remoteNodeDeviceCreateXML(virConnectPtr conn,
                          const char *xmlDesc,
                          unsigned int flags)
{
    remote_node_device_create_xml_args args;
    remote_node_device_create_xml_ret ret;
    virNodeDevicePtr dev = NULL;
    struct private_data *priv = conn->devMonPrivateData;

    remoteDriverLock(priv);

    memset(&ret, 0, sizeof ret);
    args.xml_desc = (char *)xmlDesc;
    args.flags = flags;

    if (call(conn, priv, 0, REMOTE_PROC_NODE_DEVICE_CREATE_XML,
             (xdrproc_t) xdr_remote_node_device_create_xml_args, (char *) &args,
             (xdrproc_t) xdr_remote_node_device_create_xml_ret, (char *) &ret) == -1)
        goto done;

    dev = get_nonnull_node_device(conn, ret.dev);
    xdr_free ((xdrproc_t) xdr_remote_node_device_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return dev;
}

static int
remoteNodeDeviceDestroy(virNodeDevicePtr dev)
{
    int rv = -1;
    remote_node_device_destroy_args args;
    struct private_data *priv = dev->conn->devMonPrivateData;

    remoteDriverLock(priv);

    args.name = dev->name;

    if (call(dev->conn, priv, 0, REMOTE_PROC_NODE_DEVICE_DESTROY,
             (xdrproc_t) xdr_remote_node_device_destroy_args, (char *) &args,
             (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

/* ------------------------------------------------------------- */

static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteNWFilterOpen (virConnectPtr conn,
                    virConnectAuthPtr auth,
                    int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv;

       /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        priv = conn->privateData;
        remoteDriverLock(priv);
        priv->localUses++;
        conn->nwfilterPrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network filtering APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network filtering APIs.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->nwfilterPrivateData = priv;
        return ret;
    }
}

static int
remoteNWFilterClose (virConnectPtr conn)
{
    int rv = 0;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        rv = doRemoteClose(conn, priv);
        conn->nwfilterPrivateData = NULL;
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return rv;
}


static int
remoteNumOfNWFilters (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_nwfilters_ret ret;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_NWFILTERS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_nwfilters_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static virNWFilterPtr
remoteNWFilterDefineXML (virConnectPtr conn, const char *xmlDesc,
                         unsigned int flags ATTRIBUTE_UNUSED)
{
    virNWFilterPtr net = NULL;
    remote_nwfilter_define_xml_args args;
    remote_nwfilter_define_xml_ret ret;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    args.xml = (char *) xmlDesc;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NWFILTER_DEFINE_XML,
              (xdrproc_t) xdr_remote_nwfilter_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_nwfilter_define_xml_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_nwfilter (conn, ret.nwfilter);
    xdr_free ((xdrproc_t) &xdr_remote_nwfilter_define_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}


static int
remoteNWFilterUndefine (virNWFilterPtr nwfilter)
{
    int rv = -1;
    remote_nwfilter_undefine_args args;
    struct private_data *priv = nwfilter->conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    make_nonnull_nwfilter (&args.nwfilter, nwfilter);

    if (call (nwfilter->conn, priv, 0, REMOTE_PROC_NWFILTER_UNDEFINE,
              (xdrproc_t) xdr_remote_nwfilter_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteListNWFilters (virConnectPtr conn, char **const names, int maxnames)
{
    int rv = -1;
    int i;
    remote_list_nwfilters_args args;
    remote_list_nwfilters_ret ret;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    if (maxnames > REMOTE_NWFILTER_NAME_LIST_MAX) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote nwfilters: %d > %d"),
                    maxnames, REMOTE_NWFILTER_NAME_LIST_MAX);
        goto done;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_NWFILTERS,
              (xdrproc_t) xdr_remote_list_nwfilters_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_nwfilters_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > maxnames) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote nwfilters: %d > %d"),
                    ret.names.names_len, maxnames);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_nwfilters_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}



static virNWFilterPtr
remoteNWFilterLookupByUUID (virConnectPtr conn,
                            const unsigned char *uuid)
{
    virNWFilterPtr net = NULL;
    remote_nwfilter_lookup_by_uuid_args args;
    remote_nwfilter_lookup_by_uuid_ret ret;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NWFILTER_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_nwfilter_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_nwfilter_lookup_by_uuid_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_nwfilter (conn, ret.nwfilter);
    xdr_free ((xdrproc_t) &xdr_remote_nwfilter_lookup_by_uuid_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}

static virNWFilterPtr
remoteNWFilterLookupByName (virConnectPtr conn,
                            const char *name)
{
    virNWFilterPtr net = NULL;
    remote_nwfilter_lookup_by_name_args args;
    remote_nwfilter_lookup_by_name_ret ret;
    struct private_data *priv = conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NWFILTER_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_nwfilter_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_nwfilter_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    net = get_nonnull_nwfilter (conn, ret.nwfilter);
    xdr_free ((xdrproc_t) &xdr_remote_nwfilter_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return net;
}


static char *
remoteNWFilterGetXMLDesc (virNWFilterPtr nwfilter, unsigned int flags)
{
    char *rv = NULL;
    remote_nwfilter_get_xml_desc_args args;
    remote_nwfilter_get_xml_desc_ret ret;
    struct private_data *priv = nwfilter->conn->nwfilterPrivateData;

    remoteDriverLock(priv);

    make_nonnull_nwfilter (&args.nwfilter, nwfilter);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (nwfilter->conn, priv, 0, REMOTE_PROC_NWFILTER_GET_XML_DESC,
              (xdrproc_t) xdr_remote_nwfilter_get_xml_desc_args, (char *) &args,
              (xdrproc_t) xdr_remote_nwfilter_get_xml_desc_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}


/*----------------------------------------------------------------------*/

static int
remoteAuthenticate (virConnectPtr conn, struct private_data *priv,
                    int in_open ATTRIBUTE_UNUSED,
                    virConnectAuthPtr auth ATTRIBUTE_UNUSED,
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
            remoteError(VIR_ERR_AUTH_FAILED,
                        _("unknown authentication type %s"), authtype);
            return -1;
        }
        for (i = 0 ; i < ret.types.types_len ; i++) {
            if (ret.types.types_val[i] == want)
                type = want;
        }
        if (type == REMOTE_AUTH_NONE) {
            remoteError(VIR_ERR_AUTH_FAILED,
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
        remoteError(VIR_ERR_AUTH_FAILED,
                    _("unsupported authentication type %d"),
                    ret.types.types_val[0]);
        VIR_FREE(ret.types.types_val);
        return -1;
    }

    VIR_FREE(ret.types.types_val);

    return 0;
}



#if HAVE_SASL
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
    virSocketAddr sa;
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
        remoteError(VIR_ERR_AUTH_FAILED,
                    _("failed to initialize SASL library: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* Get local address in form  IPADDR:PORT */
    sa.len = sizeof(sa.data.stor);
    if (getsockname(priv->sock, &sa.data.sa, &sa.len) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to get sock address"));
        goto cleanup;
    }
    if ((localAddr = virSocketFormatAddrFull(&sa, true, ";")) == NULL)
        goto cleanup;

    /* Get remote address in form  IPADDR:PORT */
    sa.len = sizeof(sa.data.stor);
    if (getpeername(priv->sock, &sa.data.sa, &sa.len) < 0) {
        virReportSystemError(errno, "%s",
                             _("failed to get peer address"));
        goto cleanup;
    }
    if ((remoteAddr = virSocketFormatAddrFull(&sa, true, ";")) == NULL)
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
        remoteError(VIR_ERR_AUTH_FAILED,
                    _("Failed to create SASL client context: %d (%s)"),
                    err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* Initialize some connection props we care about */
    if (priv->uses_tls) {
        gnutls_cipher_algorithm_t cipher;

        cipher = gnutls_cipher_get(priv->session);
        if (!(ssf = (sasl_ssf_t)gnutls_cipher_get_key_size(cipher))) {
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("invalid cipher size for TLS session"));
            goto cleanup;
        }
        ssf *= 8; /* key size is bytes, sasl wants bits */

        DEBUG("Setting external SSF %d", ssf);
        err = sasl_setprop(saslconn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            remoteError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot set external SSF %d (%s)"),
                        err, sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
    }

    memset (&secprops, 0, sizeof secprops);
    /* If we've got a secure channel (TLS or UNIX sock), we don't care about SSF */
    secprops.min_ssf = priv->is_secure ? 0 : 56; /* Equiv to DES supported by all Kerberos */
    secprops.max_ssf = priv->is_secure ? 0 : 100000; /* Very strong ! AES == 256 */
    secprops.maxbufsize = 100000;
    /* If we're not secure, then forbid any anonymous or trivially crackable auth */
    secprops.security_flags = priv->is_secure ? 0 :
        SASL_SEC_NOANONYMOUS | SASL_SEC_NOPLAINTEXT;

    err = sasl_setprop(saslconn, SASL_SEC_PROPS, &secprops);
    if (err != SASL_OK) {
        remoteError(VIR_ERR_INTERNAL_ERROR,
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
            remoteError(VIR_ERR_AUTH_FAILED,
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
        remoteError(VIR_ERR_AUTH_FAILED,
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
        if ((ncred = remoteAuthMakeCredentials(interact, &cred)) < 0) {
            remoteError(VIR_ERR_AUTH_FAILED, "%s",
                        _("Failed to make auth credentials"));
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
        remoteError(VIR_ERR_AUTH_FAILED, "%s", msg);
        goto cleanup;
    }
    VIR_FREE(iret.mechlist);

    if (clientoutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        remoteError(VIR_ERR_AUTH_FAILED,
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
            remoteError(VIR_ERR_AUTH_FAILED,
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
                remoteError(VIR_ERR_AUTH_FAILED, "%s",
                            _("Failed to make auth credentials"));
                goto cleanup;
            }
            /* Run the authentication callback */
            if (auth && auth->cb) {
                if ((*(auth->cb))(cred, ncred, auth->cbdata) >= 0) {
                    remoteAuthFillInteract(cred, interact);
                    goto restep;
                }
                msg = _("Failed to collect auth credentials");
            } else {
                msg = _("No authentication callback available");
            }
            remoteError(VIR_ERR_AUTH_FAILED, "%s", msg);
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

    /* Check for suitable SSF if not already secure (TLS or UNIX sock) */
    if (!priv->is_secure) {
        err = sasl_getprop(saslconn, SASL_SSF, &val);
        if (err != SASL_OK) {
            remoteError(VIR_ERR_AUTH_FAILED,
                        _("cannot query SASL ssf on connection %d (%s)"),
                        err, sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
        ssf = *(const int *)val;
        DEBUG("SASL SSF value %d", ssf);
        if (ssf < 56) { /* 56 == DES level, good for Kerberos */
            remoteError(VIR_ERR_AUTH_FAILED,
                        _("negotiation SSF %d was not strong enough"), ssf);
            goto cleanup;
        }
        priv->is_secure = 1;
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
# if HAVE_POLKIT1
static int
remoteAuthPolkit (virConnectPtr conn, struct private_data *priv, int in_open,
                  virConnectAuthPtr auth ATTRIBUTE_UNUSED)
{
    remote_auth_polkit_ret ret;
    DEBUG0("Client initialize PolicyKit-1 authentication");

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, in_open, REMOTE_PROC_AUTH_POLKIT,
              (xdrproc_t) xdr_void, (char *)NULL,
              (xdrproc_t) xdr_remote_auth_polkit_ret, (char *) &ret) != 0) {
        return -1; /* virError already set by call */
    }

    DEBUG0("PolicyKit-1 authentication complete");
    return 0;
}
# elif HAVE_POLKIT0
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
    DEBUG0("Client initialize PolicyKit-0 authentication");

    if (auth && auth->cb) {
        /* Check if the necessary credential type for PolicyKit is supported */
        for (i = 0 ; i < auth->ncredtype ; i++) {
            if (auth->credtype[i] == VIR_CRED_EXTERNAL)
                allowcb = 1;
        }

        if (allowcb) {
            DEBUG0("Client run callback for PolicyKit authentication");
            /* Run the authentication callback */
            if ((*(auth->cb))(&cred, 1, auth->cbdata) < 0) {
                remoteError(VIR_ERR_AUTH_FAILED, "%s",
                            _("Failed to collect auth credentials"));
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

    DEBUG0("PolicyKit-0 authentication complete");
    return 0;
}
# endif /* HAVE_POLKIT0 */
#endif /* HAVE_POLKIT */
/*----------------------------------------------------------------------*/

static int remoteDomainEventRegister(virConnectPtr conn,
                                     virConnectDomainEventCallback callback,
                                     void *opaque,
                                     virFreeCallback freecb)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;

    remoteDriverLock(priv);

    if (priv->eventFlushTimer < 0) {
         remoteError(VIR_ERR_NO_SUPPORT, "%s", _("no event support"));
         goto done;
    }
    if (virDomainEventCallbackListAdd(conn, priv->callbackList,
                                      callback, opaque, freecb) < 0) {
         remoteError(VIR_ERR_RPC, "%s", _("adding cb to list"));
         goto done;
    }

    if (virDomainEventCallbackListCountID(conn, priv->callbackList, VIR_DOMAIN_EVENT_ID_LIFECYCLE) == 1) {
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

static int remoteDomainEventDeregister(virConnectPtr conn,
                                       virConnectDomainEventCallback callback)
{
    struct private_data *priv = conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    if (priv->domainEventDispatching) {
        if (virDomainEventCallbackListMarkDelete(conn, priv->callbackList,
                                                 callback) < 0) {
            remoteError(VIR_ERR_RPC, "%s", _("marking cb for deletion"));
            goto done;
        }
    } else {
        if (virDomainEventCallbackListRemove(conn, priv->callbackList,
                                             callback) < 0) {
            remoteError(VIR_ERR_RPC, "%s", _("removing cb from list"));
            goto done;
        }
    }

    if (virDomainEventCallbackListCountID(conn, priv->callbackList, VIR_DOMAIN_EVENT_ID_LIFECYCLE) == 0) {
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

/**
 * remoteDomainReadEventLifecycle
 *
 * Read the domain lifecycle event data off the wire
 */
static virDomainEventPtr
remoteDomainReadEventLifecycle(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_lifecycle_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_lifecycle_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall lifecycle event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventNewFromDom(dom, msg.event, msg.detail);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_lifecycle_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventReboot(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_reboot_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_reboot_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventRebootNewFromDom(dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_reboot_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventRTCChange(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_rtc_change_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_rtc_change_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventRTCChangeNewFromDom(dom, msg.offset);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_rtc_change_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventWatchdog(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_watchdog_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_watchdog_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventWatchdogNewFromDom(dom, msg.action);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_watchdog_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventIOError(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_io_error_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_io_error_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventIOErrorNewFromDom(dom,
                                            msg.srcPath,
                                            msg.devAlias,
                                            msg.action);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_io_error_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventIOErrorReason(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_io_error_reason_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_io_error_reason_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    event = virDomainEventIOErrorReasonNewFromDom(dom,
                                                  msg.srcPath,
                                                  msg.devAlias,
                                                  msg.action,
                                                  msg.reason);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_io_error_reason_msg, (char *) &msg);

    virDomainFree(dom);
    return event;
}


static virDomainEventPtr
remoteDomainReadEventGraphics(virConnectPtr conn, XDR *xdr)
{
    remote_domain_event_graphics_msg msg;
    virDomainPtr dom;
    virDomainEventPtr event = NULL;
    virDomainEventGraphicsAddressPtr localAddr = NULL;
    virDomainEventGraphicsAddressPtr remoteAddr = NULL;
    virDomainEventGraphicsSubjectPtr subject = NULL;
    int i;

    memset (&msg, 0, sizeof msg);

    /* unmarshall parameters, and process it*/
    if (! xdr_remote_domain_event_graphics_msg(xdr, &msg) ) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("unable to demarshall reboot event"));
        return NULL;
    }

    dom = get_nonnull_domain(conn,msg.dom);
    if (!dom)
        return NULL;

    if (VIR_ALLOC(localAddr) < 0)
        goto no_memory;
    localAddr->family = msg.local.family;
    if (!(localAddr->service = strdup(msg.local.service)) ||
        !(localAddr->node = strdup(msg.local.node)))
        goto no_memory;

    if (VIR_ALLOC(remoteAddr) < 0)
        goto no_memory;
    remoteAddr->family = msg.remote.family;
    if (!(remoteAddr->service = strdup(msg.remote.service)) ||
        !(remoteAddr->node = strdup(msg.remote.node)))
        goto no_memory;

    if (VIR_ALLOC(subject) < 0)
        goto no_memory;
    if (VIR_ALLOC_N(subject->identities, msg.subject.subject_len) < 0)
        goto no_memory;
    subject->nidentity = msg.subject.subject_len;
    for (i = 0 ; i < subject->nidentity ; i++) {
        if (!(subject->identities[i].type = strdup(msg.subject.subject_val[i].type)) ||
            !(subject->identities[i].name = strdup(msg.subject.subject_val[i].name)))
            goto no_memory;
    }

    event = virDomainEventGraphicsNewFromDom(dom,
                                             msg.phase,
                                             localAddr,
                                             remoteAddr,
                                             msg.authScheme,
                                             subject);
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_graphics_msg, (char *) &msg);

    virDomainFree(dom);
    return event;

no_memory:
    xdr_free ((xdrproc_t) &xdr_remote_domain_event_graphics_msg, (char *) &msg);

    if (localAddr) {
        VIR_FREE(localAddr->service);
        VIR_FREE(localAddr->node);
        VIR_FREE(localAddr);
    }
    if (remoteAddr) {
        VIR_FREE(remoteAddr->service);
        VIR_FREE(remoteAddr->node);
        VIR_FREE(remoteAddr);
    }
    if (subject) {
        for (i = 0 ; i < subject->nidentity ; i++) {
            VIR_FREE(subject->identities[i].type);
            VIR_FREE(subject->identities[i].name);
        }
        VIR_FREE(subject->identities);
        VIR_FREE(subject);
    }
    return NULL;
}


static virDrvOpenStatus ATTRIBUTE_NONNULL (1)
remoteSecretOpen (virConnectPtr conn,
                  virConnectAuthPtr auth,
                  int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        struct private_data *priv;

        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        priv = conn->privateData;
        remoteDriverLock(priv);
        priv->localUses++;
        conn->secretPrivateData = priv;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else if (conn->networkDriver &&
               STREQ (conn->networkDriver->name, "remote")) {
        struct private_data *priv = conn->networkPrivateData;
        remoteDriverLock(priv);
        conn->secretPrivateData = priv;
        priv->localUses++;
        remoteDriverUnlock(priv);
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for secret APIs, forcing it to
         * use the UNIX transport.
         */
        struct private_data *priv;
        int ret;
        ret = remoteOpenSecondaryDriver(conn,
                                        auth,
                                        flags,
                                        &priv);
        if (ret == VIR_DRV_OPEN_SUCCESS)
            conn->secretPrivateData = priv;
        return ret;
    }
}

static int
remoteSecretClose (virConnectPtr conn)
{
    int rv = 0;
    struct private_data *priv = conn->secretPrivateData;

    conn->secretPrivateData = NULL;
    remoteDriverLock(priv);
    priv->localUses--;
    if (!priv->localUses) {
        rv = doRemoteClose(conn, priv);
        remoteDriverUnlock(priv);
        virMutexDestroy(&priv->lock);
        VIR_FREE(priv);
    }
    if (priv)
        remoteDriverUnlock(priv);
    return rv;
}

static int
remoteSecretNumOfSecrets (virConnectPtr conn)
{
    int rv = -1;
    remote_num_of_secrets_ret ret;
    struct private_data *priv = conn->secretPrivateData;

    remoteDriverLock (priv);

    memset (&ret, 0, sizeof (ret));
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_SECRETS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_secrets_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock (priv);
    return rv;
}

static int
remoteSecretListSecrets (virConnectPtr conn, char **uuids, int maxuuids)
{
    int rv = -1;
    int i;
    remote_list_secrets_args args;
    remote_list_secrets_ret ret;
    struct private_data *priv = conn->secretPrivateData;

    remoteDriverLock(priv);

    if (maxuuids > REMOTE_SECRET_UUID_LIST_MAX) {
        remoteError(VIR_ERR_RPC, _("too many remote secret UUIDs: %d > %d"),
                    maxuuids, REMOTE_SECRET_UUID_LIST_MAX);
        goto done;
    }
    args.maxuuids = maxuuids;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_SECRETS,
              (xdrproc_t) xdr_remote_list_secrets_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_secrets_ret, (char *) &ret) == -1)
        goto done;

    if (ret.uuids.uuids_len > maxuuids) {
        remoteError(VIR_ERR_RPC, _("too many remote secret UUIDs: %d > %d"),
                    ret.uuids.uuids_len, maxuuids);
        goto cleanup;
    }

    /* This call is caller-frees.  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.uuids.uuids_len; ++i) {
        uuids[i] = strdup (ret.uuids.uuids_val[i]);

        if (uuids[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(uuids[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

    rv = ret.uuids.uuids_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_list_secrets_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virSecretPtr
remoteSecretLookupByUUID (virConnectPtr conn, const unsigned char *uuid)
{
    virSecretPtr rv = NULL;
    remote_secret_lookup_by_uuid_args args;
    remote_secret_lookup_by_uuid_ret ret;
    struct private_data *priv = conn->secretPrivateData;

    remoteDriverLock (priv);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof (ret));
    if (call (conn, priv, 0, REMOTE_PROC_SECRET_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_secret_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_secret_lookup_by_uuid_ret, (char *) &ret) == -1)
        goto done;

    rv = get_nonnull_secret (conn, ret.secret);
    xdr_free ((xdrproc_t) xdr_remote_secret_lookup_by_uuid_ret,
              (char *) &ret);

done:
    remoteDriverUnlock (priv);
    return rv;
}

static virSecretPtr
remoteSecretLookupByUsage (virConnectPtr conn, int usageType, const char *usageID)
{
    virSecretPtr rv = NULL;
    remote_secret_lookup_by_usage_args args;
    remote_secret_lookup_by_usage_ret ret;
    struct private_data *priv = conn->secretPrivateData;

    remoteDriverLock (priv);

    args.usageType = usageType;
    args.usageID = (char *)usageID;

    memset (&ret, 0, sizeof (ret));
    if (call (conn, priv, 0, REMOTE_PROC_SECRET_LOOKUP_BY_USAGE,
              (xdrproc_t) xdr_remote_secret_lookup_by_usage_args, (char *) &args,
              (xdrproc_t) xdr_remote_secret_lookup_by_usage_ret, (char *) &ret) == -1)
        goto done;

    rv = get_nonnull_secret (conn, ret.secret);
    xdr_free ((xdrproc_t) xdr_remote_secret_lookup_by_usage_ret,
              (char *) &ret);

done:
    remoteDriverUnlock (priv);
    return rv;
}

static virSecretPtr
remoteSecretDefineXML (virConnectPtr conn, const char *xml, unsigned int flags)
{
    virSecretPtr rv = NULL;
    remote_secret_define_xml_args args;
    remote_secret_define_xml_ret ret;
    struct private_data *priv = conn->secretPrivateData;

    remoteDriverLock (priv);

    args.xml = (char *) xml;
    args.flags = flags;

    memset (&ret, 0, sizeof (ret));
    if (call (conn, priv, 0, REMOTE_PROC_SECRET_DEFINE_XML,
              (xdrproc_t) xdr_remote_secret_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_secret_define_xml_ret, (char *) &ret) == -1)
        goto done;

    rv = get_nonnull_secret (conn, ret.secret);
    xdr_free ((xdrproc_t) xdr_remote_secret_define_xml_ret,
              (char *) &ret);

done:
    remoteDriverUnlock (priv);
    return rv;
}

static char *
remoteSecretGetXMLDesc (virSecretPtr secret, unsigned int flags)
{
    char *rv = NULL;
    remote_secret_get_xml_desc_args args;
    remote_secret_get_xml_desc_ret ret;
    struct private_data *priv = secret->conn->secretPrivateData;

    remoteDriverLock (priv);

    make_nonnull_secret (&args.secret, secret);
    args.flags = flags;

    memset (&ret, 0, sizeof (ret));
    if (call (secret->conn, priv, 0, REMOTE_PROC_SECRET_GET_XML_DESC,
              (xdrproc_t) xdr_remote_secret_get_xml_desc_args, (char *) &args,
              (xdrproc_t) xdr_remote_secret_get_xml_desc_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock (priv);
    return rv;
}

static int
remoteSecretSetValue (virSecretPtr secret, const unsigned char *value,
                      size_t value_size, unsigned int flags)
{
    int rv = -1;
    remote_secret_set_value_args args;
    struct private_data *priv = secret->conn->secretPrivateData;

    remoteDriverLock (priv);

    make_nonnull_secret (&args.secret, secret);
    args.value.value_len = value_size;
    args.value.value_val = (char *) value;
    args.flags = flags;

    if (call (secret->conn, priv, 0, REMOTE_PROC_SECRET_SET_VALUE,
              (xdrproc_t) xdr_remote_secret_set_value_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock (priv);
    return rv;
}

static unsigned char *
remoteSecretGetValue (virSecretPtr secret, size_t *value_size,
                      unsigned int flags)
{
    unsigned char *rv = NULL;
    remote_secret_get_value_args args;
    remote_secret_get_value_ret ret;
    struct private_data *priv = secret->conn->secretPrivateData;

    remoteDriverLock (priv);

    make_nonnull_secret (&args.secret, secret);
    args.flags = flags;

    memset (&ret, 0, sizeof (ret));
    if (call (secret->conn, priv, 0, REMOTE_PROC_SECRET_GET_VALUE,
              (xdrproc_t) xdr_remote_secret_get_value_args, (char *) &args,
              (xdrproc_t) xdr_remote_secret_get_value_ret, (char *) &ret) == -1)
        goto done;

    *value_size = ret.value.value_len;
    rv = (unsigned char *) ret.value.value_val; /* Caller frees. */

done:
    remoteDriverUnlock (priv);
    return rv;
}

static int
remoteSecretUndefine (virSecretPtr secret)
{
    int rv = -1;
    remote_secret_undefine_args args;
    struct private_data *priv = secret->conn->secretPrivateData;

    remoteDriverLock (priv);

    make_nonnull_secret (&args.secret, secret);

    if (call (secret->conn, priv, 0, REMOTE_PROC_SECRET_UNDEFINE,
              (xdrproc_t) xdr_remote_secret_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock (priv);
    return rv;
}


static struct private_stream_data *
remoteStreamOpen(virStreamPtr st,
                 int output ATTRIBUTE_UNUSED,
                 unsigned int proc_nr,
                 unsigned int serial)
{
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *stpriv;

    if (VIR_ALLOC(stpriv) < 0) {
        virReportOOMError();
        return NULL;
    }

    /* Initialize call object used to receive replies */
    stpriv->proc_nr = proc_nr;
    stpriv->serial = serial;

    stpriv->next = priv->streams;
    priv->streams = stpriv;

    return stpriv;
}


static void
remoteStreamEventTimerUpdate(struct private_stream_data *privst)
{
    if (!privst->cb)
        return;

    VIR_DEBUG("Check timer offset=%d %d", privst->incomingOffset, privst->cbEvents);
    if ((privst->incomingOffset &&
         (privst->cbEvents & VIR_STREAM_EVENT_READABLE)) ||
        (privst->cbEvents & VIR_STREAM_EVENT_WRITABLE)) {
        VIR_DEBUG0("Enabling event timer");
        virEventUpdateTimeout(privst->cbTimer, 0);
    } else {
        VIR_DEBUG0("Disabling event timer");
        virEventUpdateTimeout(privst->cbTimer, -1);
    }
}


static int
remoteStreamPacket(virStreamPtr st,
                   int status,
                   const char *data,
                   size_t nbytes)
{
    DEBUG("st=%p status=%d data=%p nbytes=%zu", st, status, data, nbytes);
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    XDR xdr;
    struct remote_thread_call *thiscall;
    remote_message_header hdr;
    int ret;

    memset(&hdr, 0, sizeof hdr);

    if (VIR_ALLOC(thiscall) < 0) {
        virReportOOMError();
        return -1;
    }

    thiscall->mode = REMOTE_MODE_WAIT_TX;
    thiscall->serial = privst->serial;
    thiscall->proc_nr = privst->proc_nr;
    if (status == REMOTE_OK ||
        status == REMOTE_ERROR)
        thiscall->want_reply = 1;

    if (virCondInit(&thiscall->cond) < 0) {
        VIR_FREE(thiscall);
        remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize mutex"));
        return -1;
    }

    /* Don't fill in any other fields in 'thiscall' since
     * we're not expecting a reply for this */

    hdr.prog = REMOTE_PROGRAM;
    hdr.vers = REMOTE_PROTOCOL_VERSION;
    hdr.proc = privst->proc_nr;
    hdr.type = REMOTE_STREAM;
    hdr.serial = privst->serial;
    hdr.status = status;


    /* Length must include the length word itself (always encoded in
     * 4 bytes as per RFC 4506), so offset start length. We write this
     * later.
     */
    thiscall->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;

    /* Serialise header followed by args. */
    xdrmem_create (&xdr, thiscall->buffer + thiscall->bufferLength,
                   REMOTE_MESSAGE_MAX, XDR_ENCODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        remoteError(VIR_ERR_RPC, "%s", _("xdr_remote_message_header failed"));
        goto error;
    }

    thiscall->bufferLength += xdr_getpos (&xdr);
    xdr_destroy (&xdr);

    if (status == REMOTE_CONTINUE) {
        if (((4 + REMOTE_MESSAGE_MAX) - thiscall->bufferLength) < nbytes) {
            remoteError(VIR_ERR_RPC, _("data size %zu too large for payload %d"),
                        nbytes, ((4 + REMOTE_MESSAGE_MAX) - thiscall->bufferLength));
            goto error;
        }

        memcpy(thiscall->buffer + thiscall->bufferLength, data, nbytes);
        thiscall->bufferLength += nbytes;
    }

    /* Go back to packet start and encode the length word. */
    xdrmem_create (&xdr, thiscall->buffer, REMOTE_MESSAGE_HEADER_XDR_LEN, XDR_ENCODE);
    if (!xdr_u_int (&xdr, &thiscall->bufferLength)) {
        remoteError(VIR_ERR_RPC, "%s", _("xdr_u_int (length word)"));
        goto error;
    }
    xdr_destroy (&xdr);

    ret = remoteIO(st->conn, priv, 0, thiscall);
    VIR_FREE(thiscall);
    if (ret < 0)
        return -1;

    return nbytes;

error:
    xdr_destroy (&xdr);
    VIR_FREE(thiscall);
    return -1;
}

static int
remoteStreamHasError(virStreamPtr st) {
    struct private_stream_data *privst = st->privateData;
    if (!privst->has_error) {
        return 0;
    }

    VIR_DEBUG0("Raising async error");
    virRaiseErrorFull(st->conn,
                      __FILE__, __FUNCTION__, __LINE__,
                      privst->err.domain,
                      privst->err.code,
                      privst->err.level,
                      privst->err.str1 ? *privst->err.str1 : NULL,
                      privst->err.str2 ? *privst->err.str2 : NULL,
                      privst->err.str3 ? *privst->err.str3 : NULL,
                      privst->err.int1,
                      privst->err.int2,
                      "%s", privst->err.message ? *privst->err.message : NULL);

    return 1;
}

static void
remoteStreamRelease(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;

    if (priv->streams == privst)
        priv->streams = privst->next;
    else {
        struct private_stream_data *tmp = priv->streams;
        while (tmp && tmp->next) {
            if (tmp->next == privst) {
                tmp->next = privst->next;
                break;
            }
        }
    }

    if (privst->has_error)
        xdr_free((xdrproc_t)xdr_remote_error,  (char *)&privst->err);

    VIR_FREE(privst);

    st->driver = NULL;
    st->privateData = NULL;
}


static int
remoteStreamSend(virStreamPtr st,
                 const char *data,
                 size_t nbytes)
{
    DEBUG("st=%p data=%p nbytes=%zu", st, data, nbytes);
    struct private_data *priv = st->conn->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    if (remoteStreamHasError(st))
        goto cleanup;

    rv = remoteStreamPacket(st,
                            REMOTE_CONTINUE,
                            data,
                            nbytes);

cleanup:
    if (rv == -1)
        remoteStreamRelease(st);

    remoteDriverUnlock(priv);

    return rv;
}


static int
remoteStreamRecv(virStreamPtr st,
                 char *data,
                 size_t nbytes)
{
    DEBUG("st=%p data=%p nbytes=%zu", st, data, nbytes);
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    int rv = -1;

    remoteDriverLock(priv);

    if (remoteStreamHasError(st))
        goto cleanup;

    if (!privst->incomingOffset) {
        struct remote_thread_call *thiscall;
        int ret;

        if (st->flags & VIR_STREAM_NONBLOCK) {
            DEBUG0("Non-blocking mode and no data available");
            rv = -2;
            goto cleanup;
        }

        if (VIR_ALLOC(thiscall) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        /* We're not really doing an RPC calls, so we're
         * skipping straight to RX part */
        thiscall->mode = REMOTE_MODE_WAIT_RX;
        thiscall->serial = privst->serial;
        thiscall->proc_nr = privst->proc_nr;
        thiscall->want_reply = 1;

        if (virCondInit(&thiscall->cond) < 0) {
            VIR_FREE(thiscall);
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("cannot initialize mutex"));
            goto cleanup;
        }

        ret = remoteIO(st->conn, priv, 0, thiscall);
        VIR_FREE(thiscall);
        if (ret < 0)
            goto cleanup;
    }

    DEBUG("After IO %d", privst->incomingOffset);
    if (privst->incomingOffset) {
        int want = privst->incomingOffset;
        if (want > nbytes)
            want = nbytes;
        memcpy(data, privst->incoming, want);
        if (want < privst->incomingOffset) {
            memmove(privst->incoming, privst->incoming + want, privst->incomingOffset - want);
            privst->incomingOffset -= want;
        } else {
            VIR_FREE(privst->incoming);
            privst->incomingOffset = privst->incomingLength = 0;
        }
        rv = want;
    } else {
        rv = 0;
    }

    remoteStreamEventTimerUpdate(privst);

    DEBUG("Done %d", rv);

cleanup:
    if (rv == -1)
        remoteStreamRelease(st);
    remoteDriverUnlock(priv);

    return rv;
}


static void
remoteStreamEventTimer(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virStreamPtr st = opaque;
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    int events = 0;

    remoteDriverLock(priv);

    if (privst->cb &&
        (privst->cbEvents & VIR_STREAM_EVENT_READABLE) &&
        privst->incomingOffset)
        events |= VIR_STREAM_EVENT_READABLE;
    if (privst->cb &&
        (privst->cbEvents & VIR_STREAM_EVENT_WRITABLE))
        events |= VIR_STREAM_EVENT_WRITABLE;
    VIR_DEBUG("Got Timer dispatch %d %d offset=%d", events, privst->cbEvents, privst->incomingOffset);
    if (events) {
        virStreamEventCallback cb = privst->cb;
        void *cbOpaque = privst->cbOpaque;
        virFreeCallback cbFree = privst->cbFree;

        privst->cbDispatch = 1;
        remoteDriverUnlock(priv);
        (cb)(st, events, cbOpaque);
        remoteDriverLock(priv);
        privst->cbDispatch = 0;

        if (!privst->cb && cbFree)
            (cbFree)(cbOpaque);
    }

    remoteDriverUnlock(priv);
}


static void
remoteStreamEventTimerFree(void *opaque)
{
    virStreamPtr st = opaque;
    virUnrefStream(st);
}


static int
remoteStreamEventAddCallback(virStreamPtr st,
                             int events,
                             virStreamEventCallback cb,
                             void *opaque,
                             virFreeCallback ff)
{
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (privst->cb) {
        remoteError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("multiple stream callbacks not supported"));
        goto cleanup;
    }

    virStreamRef(st);
    if ((privst->cbTimer =
         virEventAddTimeout(-1,
                            remoteStreamEventTimer,
                            st,
                            remoteStreamEventTimerFree)) < 0) {
        virUnrefStream(st);
        goto cleanup;
    }

    privst->cb = cb;
    privst->cbOpaque = opaque;
    privst->cbFree = ff;
    privst->cbEvents = events;

    remoteStreamEventTimerUpdate(privst);

    ret = 0;

cleanup:
    remoteDriverUnlock(priv);
    return ret;
}

static int
remoteStreamEventUpdateCallback(virStreamPtr st,
                                int events)
{
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (!privst->cb) {
        remoteError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("no stream callback registered"));
        goto cleanup;
    }

    privst->cbEvents = events;

    remoteStreamEventTimerUpdate(privst);

    ret = 0;

cleanup:
    remoteDriverUnlock(priv);
    return ret;
}


static int
remoteStreamEventRemoveCallback(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    struct private_stream_data *privst = st->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (!privst->cb) {
        remoteError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("no stream callback registered"));
        goto cleanup;
    }

    if (!privst->cbDispatch &&
        privst->cbFree)
        (privst->cbFree)(privst->cbOpaque);
    privst->cb = NULL;
    privst->cbOpaque = NULL;
    privst->cbFree = NULL;
    privst->cbEvents = 0;
    virEventRemoveTimeout(privst->cbTimer);

    ret = 0;

cleanup:
    remoteDriverUnlock(priv);
    return ret;
}

static int
remoteStreamFinish(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (remoteStreamHasError(st))
        goto cleanup;

    ret = remoteStreamPacket(st,
                             REMOTE_OK,
                             NULL,
                             0);

cleanup:
    remoteStreamRelease(st);

    remoteDriverUnlock(priv);
    return ret;
}

static int
remoteStreamAbort(virStreamPtr st)
{
    struct private_data *priv = st->conn->privateData;
    int ret = -1;

    remoteDriverLock(priv);

    if (remoteStreamHasError(st))
        goto cleanup;

    ret = remoteStreamPacket(st,
                             REMOTE_ERROR,
                             NULL,
                             0);

cleanup:
    remoteStreamRelease(st);

    remoteDriverUnlock(priv);
    return ret;
}



static virStreamDriver remoteStreamDrv = {
    .streamRecv = remoteStreamRecv,
    .streamSend = remoteStreamSend,
    .streamFinish = remoteStreamFinish,
    .streamAbort = remoteStreamAbort,
    .streamAddCallback = remoteStreamEventAddCallback,
    .streamUpdateCallback = remoteStreamEventUpdateCallback,
    .streamRemoveCallback = remoteStreamEventRemoveCallback,
};


static int
remoteDomainMigratePrepareTunnel(virConnectPtr conn,
                                 virStreamPtr st,
                                 unsigned long flags,
                                 const char *dname,
                                 unsigned long resource,
                                 const char *dom_xml)
{
    struct private_data *priv = conn->privateData;
    struct private_stream_data *privst = NULL;
    int rv = -1;
    remote_domain_migrate_prepare_tunnel_args args;

    remoteDriverLock(priv);

    if (!(privst = remoteStreamOpen(st, 1, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL, priv->counter)))
        goto done;

    st->driver = &remoteStreamDrv;
    st->privateData = privst;

    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;
    args.dom_xml = (char *) dom_xml;

    if (call(conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE_TUNNEL,
             (xdrproc_t) xdr_remote_domain_migrate_prepare_tunnel_args, (char *) &args,
             (xdrproc_t) xdr_void, NULL) == -1) {
        remoteStreamRelease(st);
        goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);

    return rv;
}


static int
remoteCPUCompare(virConnectPtr conn, const char *xmlDesc,
                 unsigned int flags ATTRIBUTE_UNUSED)
{
    struct private_data *priv = conn->privateData;
    remote_cpu_compare_args args;
    remote_cpu_compare_ret ret;
    int rv = VIR_CPU_COMPARE_ERROR;

    remoteDriverLock(priv);

    args.xml = (char *) xmlDesc;

    memset(&ret, 0, sizeof (ret));
    if (call(conn, priv, 0, REMOTE_PROC_CPU_COMPARE,
             (xdrproc_t) xdr_remote_cpu_compare_args, (char *) &args,
             (xdrproc_t) xdr_remote_cpu_compare_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.result;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static char *
remoteCPUBaseline(virConnectPtr conn,
                  const char **xmlCPUs,
                  unsigned int ncpus,
                  unsigned int flags)
{
    struct private_data *priv = conn->privateData;
    remote_cpu_baseline_args args;
    remote_cpu_baseline_ret ret;
    char *cpu = NULL;

    remoteDriverLock(priv);

    args.xmlCPUs.xmlCPUs_len = ncpus;
    args.xmlCPUs.xmlCPUs_val = (char **) xmlCPUs;
    args.flags = flags;

    memset(&ret, 0, sizeof (ret));
    if (call(conn, priv, 0, REMOTE_PROC_CPU_BASELINE,
             (xdrproc_t) xdr_remote_cpu_baseline_args, (char *) &args,
             (xdrproc_t) xdr_remote_cpu_baseline_ret, (char *) &ret) == -1)
        goto done;

    cpu = ret.cpu;

done:
    remoteDriverUnlock(priv);
    return cpu;
}


static int
remoteDomainGetJobInfo (virDomainPtr domain, virDomainJobInfoPtr info)
{
    int rv = -1;
    remote_domain_get_job_info_args args;
    remote_domain_get_job_info_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_JOB_INFO,
              (xdrproc_t) xdr_remote_domain_get_job_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_job_info_ret, (char *) &ret) == -1)
        goto done;

    info->type = ret.type;
    info->timeElapsed = ret.timeElapsed;
    info->timeRemaining = ret.timeRemaining;
    info->dataTotal = ret.dataTotal;
    info->dataProcessed = ret.dataProcessed;
    info->dataRemaining = ret.dataRemaining;
    info->memTotal = ret.memTotal;
    info->memProcessed = ret.memProcessed;
    info->memRemaining = ret.memRemaining;
    info->fileTotal = ret.fileTotal;
    info->fileProcessed = ret.fileProcessed;
    info->fileRemaining = ret.fileRemaining;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainAbortJob (virDomainPtr domain)
{
    int rv = -1;
    remote_domain_abort_job_args args;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_ABORT_JOB,
              (xdrproc_t) xdr_remote_domain_abort_job_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainMigrateSetMaxDowntime(virDomainPtr domain,
                                  unsigned long long downtime,
                                  unsigned int flags)
{
    struct private_data *priv = domain->conn->privateData;
    remote_domain_migrate_set_max_downtime_args args;
    int rv = -1;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.dom, domain);
    args.downtime = downtime;
    args.flags = flags;

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_SET_MAX_DOWNTIME,
             (xdrproc_t) xdr_remote_domain_migrate_set_max_downtime_args,
             (char *) &args,
             (xdrproc_t) xdr_void,
             (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static virDomainSnapshotPtr
remoteDomainSnapshotCreateXML(virDomainPtr domain,
                              const char *xmlDesc,
                              unsigned int flags)
{
    virDomainSnapshotPtr snapshot = NULL;
    remote_domain_snapshot_create_xml_args args;
    remote_domain_snapshot_create_xml_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.domain, domain);
    args.xml_desc = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_CREATE_XML,
              (xdrproc_t) xdr_remote_domain_snapshot_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_snapshot_create_xml_ret, (char *) &ret) == -1)
        goto done;

    snapshot = get_nonnull_domain_snapshot(domain, ret.snap);
    xdr_free ((xdrproc_t) &xdr_remote_domain_snapshot_create_xml_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return snapshot;
}


static char *
remoteDomainSnapshotDumpXML(virDomainSnapshotPtr snapshot, unsigned int flags)
{
    char *rv = NULL;
    remote_domain_snapshot_dump_xml_args args;
    remote_domain_snapshot_dump_xml_ret ret;
    struct private_data *priv = snapshot->domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain_snapshot(&args.snap, snapshot);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (snapshot->domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_DUMP_XML,
              (xdrproc_t) xdr_remote_domain_snapshot_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_snapshot_dump_xml_ret, (char *) &ret) == -1)
        goto done;

    /* Caller frees. */
    rv = ret.xml;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainSnapshotNum (virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_snapshot_num_args args;
    remote_domain_snapshot_num_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain (&args.domain, domain);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_NUM,
              (xdrproc_t) xdr_remote_domain_snapshot_num_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_snapshot_num_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.num;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainSnapshotListNames (virDomainPtr domain, char **const names,
                               int nameslen, unsigned int flags)
{
    int rv = -1;
    int i;
    remote_domain_snapshot_list_names_args args;
    remote_domain_snapshot_list_names_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    if (nameslen > REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote domain snapshot names: %d > %d"),
                    nameslen, REMOTE_DOMAIN_SNAPSHOT_LIST_NAMES_MAX);
        goto done;
    }

    make_nonnull_domain(&args.domain, domain);
    args.nameslen = nameslen;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_LIST_NAMES,
              (xdrproc_t) xdr_remote_domain_snapshot_list_names_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_snapshot_list_names_ret, (char *) &ret) == -1)
        goto done;

    if (ret.names.names_len > nameslen) {
        remoteError(VIR_ERR_RPC,
                    _("too many remote domain snapshots: %d > %d"),
                    ret.names.names_len, nameslen);
        goto cleanup;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i) {
        names[i] = strdup (ret.names.names_val[i]);

        if (names[i] == NULL) {
            for (--i; i >= 0; --i)
                VIR_FREE(names[i]);

            virReportOOMError();
            goto cleanup;
        }
    }

    rv = ret.names.names_len;

cleanup:
    xdr_free ((xdrproc_t) xdr_remote_domain_snapshot_list_names_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}


static virDomainSnapshotPtr
remoteDomainSnapshotLookupByName (virDomainPtr domain, const char *name,
                                  unsigned int flags)
{
    virDomainSnapshotPtr snapshot = NULL;
    remote_domain_snapshot_lookup_by_name_args args;
    remote_domain_snapshot_lookup_by_name_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.domain, domain);
    args.name = (char *) name;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_domain_snapshot_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_snapshot_lookup_by_name_ret, (char *) &ret) == -1)
        goto done;

    snapshot = get_nonnull_domain_snapshot (domain, ret.snap);
    xdr_free ((xdrproc_t) &xdr_remote_domain_snapshot_lookup_by_name_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return snapshot;
}


static int
remoteDomainHasCurrentSnapshot(virDomainPtr domain, unsigned int flags)
{
    int rv = -1;
    remote_domain_has_current_snapshot_args args;
    remote_domain_has_current_snapshot_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.domain, domain);
    args.flags = flags;

    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_HAS_CURRENT_SNAPSHOT,
             (xdrproc_t) xdr_remote_domain_has_current_snapshot_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_has_current_snapshot_ret, (char *) &ret) == -1)
        goto done;

    rv = ret.result;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static virDomainSnapshotPtr
remoteDomainSnapshotCurrent(virDomainPtr domain,
                            unsigned int flags)
{
    virDomainSnapshotPtr snapshot = NULL;
    remote_domain_snapshot_current_args args;
    remote_domain_snapshot_current_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.domain, domain);
    args.flags = flags;

    memset(&ret, 0, sizeof ret);
    if (call(domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_CURRENT,
             (xdrproc_t) xdr_remote_domain_snapshot_current_args, (char *) &args,
             (xdrproc_t) xdr_remote_domain_snapshot_current_ret, (char *) &ret) == -1)
        goto done;

    snapshot = get_nonnull_domain_snapshot(domain, ret.snap);
    xdr_free((xdrproc_t) &xdr_remote_domain_snapshot_current_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return snapshot;
}


static int
remoteDomainRevertToSnapshot (virDomainSnapshotPtr snapshot,
                              unsigned int flags)
{
    int rv = -1;
    remote_domain_revert_to_snapshot_args args;
    struct private_data *priv = snapshot->domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain_snapshot(&args.snap, snapshot);
    args.flags = flags;

    if (call (snapshot->domain->conn, priv, 0, REMOTE_PROC_DOMAIN_REVERT_TO_SNAPSHOT,
              (xdrproc_t) xdr_remote_domain_revert_to_snapshot_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainSnapshotDelete (virDomainSnapshotPtr snapshot,
                            unsigned int flags)
{
    int rv = -1;
    remote_domain_snapshot_delete_args args;
    struct private_data *priv = snapshot->domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain_snapshot(&args.snap, snapshot);
    args.flags = flags;

    if (call (snapshot->domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SNAPSHOT_DELETE,
              (xdrproc_t) xdr_remote_domain_snapshot_delete_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto done;

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}

static int remoteDomainEventRegisterAny(virConnectPtr conn,
                                        virDomainPtr dom,
                                        int eventID,
                                        virConnectDomainEventGenericCallback callback,
                                        void *opaque,
                                        virFreeCallback freecb)
{
    int rv = -1;
    struct private_data *priv = conn->privateData;
    remote_domain_events_register_any_args args;
    int callbackID;

    remoteDriverLock(priv);

    if (priv->eventFlushTimer < 0) {
         remoteError(VIR_ERR_NO_SUPPORT, "%s", _("no event support"));
         goto done;
    }

    if ((callbackID = virDomainEventCallbackListAddID(conn, priv->callbackList,
                                                      dom, eventID,
                                                      callback, opaque, freecb)) < 0) {
         remoteError(VIR_ERR_RPC, "%s", _("adding cb to list"));
         goto done;
    }

    /* If this is the first callback for this eventID, we need to enable
     * events on the server */
    if (virDomainEventCallbackListCountID(conn, priv->callbackList, eventID) == 1) {
        args.eventID = eventID;

        if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_EVENTS_REGISTER_ANY,
                  (xdrproc_t) xdr_remote_domain_events_register_any_args, (char *) &args,
                  (xdrproc_t) xdr_void, (char *)NULL) == -1) {
            virDomainEventCallbackListRemoveID(conn, priv->callbackList, callbackID);
            goto done;
        }
    }

    rv = callbackID;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int remoteDomainEventDeregisterAny(virConnectPtr conn,
                                          int callbackID)
{
    struct private_data *priv = conn->privateData;
    int rv = -1;
    remote_domain_events_deregister_any_args args;
    int eventID;

    remoteDriverLock(priv);

    if ((eventID = virDomainEventCallbackListEventID(conn, priv->callbackList, callbackID)) < 0) {
        remoteError(VIR_ERR_RPC, _("unable to find callback ID %d"), callbackID);
        goto done;
    }

    if (priv->domainEventDispatching) {
        if (virDomainEventCallbackListMarkDeleteID(conn, priv->callbackList,
                                                   callbackID) < 0) {
            remoteError(VIR_ERR_RPC, "%s", _("marking cb for deletion"));
            goto done;
        }
    } else {
        if (virDomainEventCallbackListRemoveID(conn, priv->callbackList,
                                               callbackID) < 0) {
            remoteError(VIR_ERR_RPC, "%s", _("removing cb from list"));
            goto done;
        }
    }

    /* If that was the last callback for this eventID, we need to disable
     * events on the server */
    if (virDomainEventCallbackListCountID(conn, priv->callbackList, eventID) == 0) {
        args.eventID = eventID;

        if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_EVENTS_DEREGISTER_ANY,
                  (xdrproc_t) xdr_remote_domain_events_deregister_any_args, (char *) &args,
                  (xdrproc_t) xdr_void, (char *) NULL) == -1)
            goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);
    return rv;
}


static int
remoteDomainOpenConsole(virDomainPtr dom,
                        const char *devname,
                        virStreamPtr st,
                        unsigned int flags)
{
    struct private_data *priv = dom->conn->privateData;
    struct private_stream_data *privst = NULL;
    int rv = -1;
    remote_domain_open_console_args args;

    remoteDriverLock(priv);

    if (!(privst = remoteStreamOpen(st, 1, REMOTE_PROC_DOMAIN_OPEN_CONSOLE, priv->counter)))
        goto done;

    st->driver = &remoteStreamDrv;
    st->privateData = privst;

    make_nonnull_domain (&args.domain, dom);
    args.devname = devname ? (char **)&devname : NULL;
    args.flags = flags;

    if (call(dom->conn, priv, 0, REMOTE_PROC_DOMAIN_OPEN_CONSOLE,
             (xdrproc_t) xdr_remote_domain_open_console_args, (char *) &args,
             (xdrproc_t) xdr_void, NULL) == -1) {
        remoteStreamRelease(st);
        goto done;
    }

    rv = 0;

done:
    remoteDriverUnlock(priv);

    return rv;

}


/*----------------------------------------------------------------------*/

static int
remoteQemuDomainMonitorCommand (virDomainPtr domain, const char *cmd,
                                char **result, unsigned int flags)
{
    int rv = -1;
    qemu_monitor_command_args args;
    qemu_monitor_command_ret ret;
    struct private_data *priv = domain->conn->privateData;

    remoteDriverLock(priv);

    make_nonnull_domain(&args.domain, domain);
    args.cmd = (char *)cmd;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, REMOTE_CALL_QEMU, QEMU_PROC_MONITOR_COMMAND,
              (xdrproc_t) xdr_qemu_monitor_command_args, (char *) &args,
              (xdrproc_t) xdr_qemu_monitor_command_ret, (char *) &ret) == -1)
        goto done;

    *result = strdup(ret.result);
    if (*result == NULL) {

        virReportOOMError();
        goto cleanup;
    }

    rv = 0;

cleanup:
    xdr_free ((xdrproc_t) xdr_qemu_monitor_command_ret, (char *) &ret);

done:
    remoteDriverUnlock(priv);
    return rv;
}

/*----------------------------------------------------------------------*/

static struct remote_thread_call *
prepareCall(struct private_data *priv,
            int flags,
            int proc_nr,
            xdrproc_t args_filter, char *args,
            xdrproc_t ret_filter, char *ret)
{
    XDR xdr;
    struct remote_message_header hdr;
    struct remote_thread_call *rv;

    if (VIR_ALLOC(rv) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virCondInit(&rv->cond) < 0) {
        VIR_FREE(rv);
        remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                    _("cannot initialize mutex"));
        return NULL;
    }

    /* Get a unique serial number for this message. */
    rv->serial = priv->counter++;
    rv->proc_nr = proc_nr;
    rv->ret_filter = ret_filter;
    rv->ret = ret;
    rv->want_reply = 1;

    if (flags & REMOTE_CALL_QEMU) {
        hdr.prog = QEMU_PROGRAM;
        hdr.vers = QEMU_PROTOCOL_VERSION;
    }
    else {
        hdr.prog = REMOTE_PROGRAM;
        hdr.vers = REMOTE_PROTOCOL_VERSION;
    }
    hdr.proc = proc_nr;
    hdr.type = REMOTE_CALL;
    hdr.serial = rv->serial;
    hdr.status = REMOTE_OK;

    /* Serialise header followed by args. */
    xdrmem_create (&xdr, rv->buffer+4, REMOTE_MESSAGE_MAX, XDR_ENCODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        remoteError(VIR_ERR_RPC, "%s", _("xdr_remote_message_header failed"));
        goto error;
    }

    if (!(*args_filter) (&xdr, args)) {
        remoteError(VIR_ERR_RPC, "%s", _("marshalling args"));
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
        remoteError(VIR_ERR_RPC, "%s", _("xdr_u_int (length word)"));
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
remoteIOWriteBuffer(struct private_data *priv,
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

            remoteError(VIR_ERR_GNUTLS_ERROR, "%s", gnutls_strerror (ret));
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

            virReportSystemError(errno, "%s", _("cannot send data"));
            return -1;

        }
    }

    return ret;
}


static int
remoteIOReadBuffer(struct private_data *priv,
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
                remoteError(VIR_ERR_GNUTLS_ERROR,
                            _("failed to read from TLS socket %s"),
                            gnutls_strerror (ret));
            else
                remoteError(VIR_ERR_SYSTEM_ERROR, "%s",
                            _("server closed connection"));
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

                char errout[1024] = "\0";
                if (priv->errfd != -1) {
                    if (saferead(priv->errfd, errout, sizeof(errout)) < 0) {
                        virReportSystemError(errno, "%s",
                                             _("cannot recv data"));
                        return -1;
                    }
                }

                virReportSystemError(errno,
                                     _("cannot recv data: %s"), errout);

            } else {
                char errout[1024] = "\0";
                if (priv->errfd != -1) {
                    if (saferead(priv->errfd, errout, sizeof(errout)) < 0) {
                        remoteError(VIR_ERR_SYSTEM_ERROR,
                                    _("server closed connection: %s"),
                                    virStrerror(errno, errout, sizeof errout));
                        return -1;
                    }
                }

                remoteError(VIR_ERR_SYSTEM_ERROR,
                            _("server closed connection: %s"), errout);
            }
            return -1;
        }
    }

    return ret;
}


static int
remoteIOWriteMessage(struct private_data *priv,
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
                remoteError(VIR_ERR_INTERNAL_ERROR,
                            _("failed to encode SASL data: %s"),
                            sasl_errstring(err, NULL, NULL));
                return -1;
            }
            priv->saslEncoded = output;
            priv->saslEncodedLength = outputlen;
            priv->saslEncodedOffset = 0;

            thecall->bufferOffset = thecall->bufferLength;
        }

        ret = remoteIOWriteBuffer(priv,
                                  priv->saslEncoded + priv->saslEncodedOffset,
                                  priv->saslEncodedLength - priv->saslEncodedOffset);
        if (ret < 0)
            return ret;
        priv->saslEncodedOffset += ret;

        if (priv->saslEncodedOffset == priv->saslEncodedLength) {
            priv->saslEncoded = NULL;
            priv->saslEncodedOffset = priv->saslEncodedLength = 0;
            if (thecall->want_reply)
                thecall->mode = REMOTE_MODE_WAIT_RX;
            else
                thecall->mode = REMOTE_MODE_COMPLETE;
        }
    } else {
#endif
        int ret;
        ret = remoteIOWriteBuffer(priv,
                                  thecall->buffer + thecall->bufferOffset,
                                  thecall->bufferLength - thecall->bufferOffset);
        if (ret < 0)
            return ret;
        thecall->bufferOffset += ret;

        if (thecall->bufferOffset == thecall->bufferLength) {
            thecall->bufferOffset = thecall->bufferLength = 0;
            if (thecall->want_reply)
                thecall->mode = REMOTE_MODE_WAIT_RX;
            else
                thecall->mode = REMOTE_MODE_COMPLETE;
        }
#if HAVE_SASL
    }
#endif
    return 0;
}


static int
remoteIOHandleOutput(struct private_data *priv) {
    struct remote_thread_call *thecall = priv->waitDispatch;

    while (thecall &&
           thecall->mode != REMOTE_MODE_WAIT_TX)
        thecall = thecall->next;

    if (!thecall)
        return -1; /* Shouldn't happen, but you never know... */

    while (thecall) {
        int ret = remoteIOWriteMessage(priv, thecall);
        if (ret < 0)
            return ret;

        if (thecall->mode == REMOTE_MODE_WAIT_TX)
            return 0; /* Blocking write, to back to event loop */

        thecall = thecall->next;
    }

    return 0; /* No more calls to send, all done */
}

static int
remoteIOReadMessage(struct private_data *priv) {
    unsigned int wantData;

    /* Start by reading length word */
    if (priv->bufferLength == 0)
        priv->bufferLength = 4;

    wantData = priv->bufferLength - priv->bufferOffset;

#if HAVE_SASL
    if (priv->saslconn) {
        if (priv->saslDecoded == NULL) {
            char encoded[8192];
            int ret, err;
            ret = remoteIOReadBuffer(priv, encoded, sizeof(encoded));
            if (ret < 0)
                return -1;
            if (ret == 0)
                return 0;

            err = sasl_decode(priv->saslconn, encoded, ret,
                              &priv->saslDecoded, &priv->saslDecodedLength);
            if (err != SASL_OK) {
                remoteError(VIR_ERR_INTERNAL_ERROR,
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
            priv->saslDecodedOffset = priv->saslDecodedLength = 0;
            priv->saslDecoded = NULL;
        }

        return wantData;
    } else {
#endif
        int ret;

        ret = remoteIOReadBuffer(priv,
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


static int
remoteIODecodeMessageLength(struct private_data *priv) {
    XDR xdr;
    unsigned int len;

    xdrmem_create (&xdr, priv->buffer, priv->bufferLength, XDR_DECODE);
    if (!xdr_u_int (&xdr, &len)) {
        remoteError(VIR_ERR_RPC, "%s", _("xdr_u_int (length word, reply)"));
        return -1;
    }
    xdr_destroy (&xdr);

    if (len < REMOTE_MESSAGE_HEADER_XDR_LEN) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("packet received from server too small"));
        return -1;
    }

    /* Length includes length word - adjust to real length to read. */
    len -= REMOTE_MESSAGE_HEADER_XDR_LEN;

    if (len > REMOTE_MESSAGE_MAX) {
        remoteError(VIR_ERR_RPC, "%s",
                    _("packet received from server too large"));
        return -1;
    }

    /* Extend our declared buffer length and carry
       on reading the header + payload */
    priv->bufferLength += len;
    DEBUG("Got length, now need %d total (%d more)", priv->bufferLength, len);
    return 0;
}


static int
processCallDispatchReply(virConnectPtr conn, struct private_data *priv,
                         remote_message_header *hdr,
                         XDR *xdr);

static int
processCallDispatchMessage(virConnectPtr conn, struct private_data *priv,
                           int in_open,
                           remote_message_header *hdr,
                           XDR *xdr);

static int
processCallDispatchStream(virConnectPtr conn, struct private_data *priv,
                          remote_message_header *hdr,
                          XDR *xdr);


static int
processCallDispatch(virConnectPtr conn, struct private_data *priv,
                    int flags) {
    XDR xdr;
    struct remote_message_header hdr;
    int len = priv->bufferLength - 4;
    int rv = -1;
    int expectedprog;
    int expectedvers;

    /* Length word has already been read */
    priv->bufferOffset = 4;

    /* Deserialise reply header. */
    xdrmem_create (&xdr, priv->buffer + priv->bufferOffset, len, XDR_DECODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        remoteError(VIR_ERR_RPC, "%s", _("invalid header in reply"));
        return -1;
    }

    priv->bufferOffset += xdr_getpos(&xdr);

    expectedprog = REMOTE_PROGRAM;
    expectedvers = REMOTE_PROTOCOL_VERSION;
    if (flags & REMOTE_CALL_QEMU) {
        expectedprog = QEMU_PROGRAM;
        expectedvers = QEMU_PROTOCOL_VERSION;
    }

    /* Check program, version, etc. are what we expect. */
    if (hdr.prog != expectedprog) {
        remoteError(VIR_ERR_RPC,
                    _("unknown program (received %x, expected %x)"),
                    hdr.prog, expectedprog);
        return -1;
    }
    if (hdr.vers != expectedvers) {
        remoteError(VIR_ERR_RPC,
                    _("unknown protocol version (received %x, expected %x)"),
                    hdr.vers, expectedvers);
        return -1;
    }


    switch (hdr.type) {
    case REMOTE_REPLY: /* Normal RPC replies */
        rv = processCallDispatchReply(conn, priv, &hdr, &xdr);
        break;

    case REMOTE_MESSAGE: /* Async notifications */
        rv = processCallDispatchMessage(conn, priv, flags & REMOTE_CALL_IN_OPEN,
                                        &hdr, &xdr);
        break;

    case REMOTE_STREAM: /* Stream protocol */
        rv = processCallDispatchStream(conn, priv, &hdr, &xdr);
        break;

    default:
        remoteError(VIR_ERR_RPC,
                    _("got unexpected RPC call %d from server"),
                    hdr.proc);
        rv = -1;
        break;
    }

    xdr_destroy(&xdr);
    return rv;
}


static int
processCallDispatchReply(virConnectPtr conn ATTRIBUTE_UNUSED,
                         struct private_data *priv,
                         remote_message_header *hdr,
                         XDR *xdr) {
    struct remote_thread_call *thecall;

    /* Ok, definitely got an RPC reply now find
       out who's been waiting for it */
    thecall = priv->waitDispatch;
    while (thecall &&
           thecall->serial != hdr->serial)
        thecall = thecall->next;

    if (!thecall) {
        remoteError(VIR_ERR_RPC,
                    _("no call waiting for reply with serial %d"),
                    hdr->serial);
        return -1;
    }

    if (hdr->proc != thecall->proc_nr) {
        remoteError(VIR_ERR_RPC,
                    _("unknown procedure (received %x, expected %x)"),
                    hdr->proc, thecall->proc_nr);
        return -1;
    }

    /* Status is either REMOTE_OK (meaning that what follows is a ret
     * structure), or REMOTE_ERROR (and what follows is a remote_error
     * structure).
     */
    switch (hdr->status) {
    case REMOTE_OK:
        if (!(*thecall->ret_filter) (xdr, thecall->ret)) {
            remoteError(VIR_ERR_RPC, "%s", _("unmarshalling ret"));
            return -1;
        }
        thecall->mode = REMOTE_MODE_COMPLETE;
        return 0;

    case REMOTE_ERROR:
        memset (&thecall->err, 0, sizeof thecall->err);
        if (!xdr_remote_error (xdr, &thecall->err)) {
            remoteError(VIR_ERR_RPC, "%s", _("unmarshalling remote_error"));
            return -1;
        }
        thecall->mode = REMOTE_MODE_ERROR;
        return 0;

    default:
        remoteError(VIR_ERR_RPC, _("unknown status (received %x)"), hdr->status);
        return -1;
    }
}

static int
processCallDispatchMessage(virConnectPtr conn, struct private_data *priv,
                           int in_open,
                           remote_message_header *hdr,
                           XDR *xdr) {
    virDomainEventPtr event = NULL;
    /* An async message has come in while we were waiting for the
     * response. Process it to pull it off the wire, and try again
     */
    DEBUG0("Encountered an event while waiting for a response");

    if (in_open) {
        DEBUG("Ignoring bogus event %d received while in open", hdr->proc);
        return -1;
    }

    switch (hdr->proc) {
    case REMOTE_PROC_DOMAIN_EVENT_LIFECYCLE:
        event = remoteDomainReadEventLifecycle(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_REBOOT:
        event = remoteDomainReadEventReboot(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_RTC_CHANGE:
        event = remoteDomainReadEventRTCChange(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_WATCHDOG:
        event = remoteDomainReadEventWatchdog(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_IO_ERROR:
        event = remoteDomainReadEventIOError(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_IO_ERROR_REASON:
        event = remoteDomainReadEventIOErrorReason(conn, xdr);
        break;

    case REMOTE_PROC_DOMAIN_EVENT_GRAPHICS:
        event = remoteDomainReadEventGraphics(conn, xdr);
        break;

    default:
        DEBUG("Unexpected event proc %d", hdr->proc);
        break;
    }

    if (!event)
        return -1;

    if (virDomainEventQueuePush(priv->domainEvents,
                                event) < 0) {
        DEBUG0("Error adding event to queue");
        virDomainEventFree(event);
    }
    virEventUpdateTimeout(priv->eventFlushTimer, 0);

    return 0;
}

static int
processCallDispatchStream(virConnectPtr conn ATTRIBUTE_UNUSED,
                          struct private_data *priv,
                          remote_message_header *hdr,
                          XDR *xdr) {
    struct private_stream_data *privst;
    struct remote_thread_call *thecall;

    /* Try and find a matching stream */
    privst = priv->streams;
    while (privst &&
           privst->serial != hdr->serial &&
           privst->proc_nr != hdr->proc)
        privst = privst->next;

    if (!privst) {
        VIR_DEBUG("No registered stream matching serial=%d, proc=%d",
                  hdr->serial, hdr->proc);
        return -1;
    }

    /* See if there's also a (optional) call waiting for this reply */
    thecall = priv->waitDispatch;
    while (thecall &&
           thecall->serial != hdr->serial)
        thecall = thecall->next;


    /* Status is either REMOTE_OK (meaning that what follows is a ret
     * structure), or REMOTE_ERROR (and what follows is a remote_error
     * structure).
     */
    switch (hdr->status) {
    case REMOTE_CONTINUE: {
        int avail = privst->incomingLength - privst->incomingOffset;
        int need = priv->bufferLength - priv->bufferOffset;
        VIR_DEBUG0("Got a stream data packet");

        /* XXX flag stream as complete somwhere if need==0 */

        if (need > avail) {
            int extra = need - avail;
            if (VIR_REALLOC_N(privst->incoming,
                              privst->incomingLength + extra) < 0) {
                VIR_DEBUG0("Out of memory handling stream data");
                return -1;
            }
            privst->incomingLength += extra;
        }

        memcpy(privst->incoming + privst->incomingOffset,
               priv->buffer + priv->bufferOffset,
               priv->bufferLength - priv->bufferOffset);
        privst->incomingOffset += (priv->bufferLength - priv->bufferOffset);

        if (thecall && thecall->want_reply) {
            VIR_DEBUG("Got sync data packet offset=%d", privst->incomingOffset);
            thecall->mode = REMOTE_MODE_COMPLETE;
        } else {
            VIR_DEBUG("Got aysnc data packet offset=%d", privst->incomingOffset);
            remoteStreamEventTimerUpdate(privst);
        }
        return 0;
    }

    case REMOTE_OK:
        VIR_DEBUG0("Got a synchronous confirm");
        if (!thecall) {
            VIR_DEBUG0("Got unexpected stream finish confirmation");
            return -1;
        }
        thecall->mode = REMOTE_MODE_COMPLETE;
        return 0;

    case REMOTE_ERROR:
        if (thecall && thecall->want_reply) {
            VIR_DEBUG0("Got a synchronous error");
            /* Give the error straight to this call */
            memset (&thecall->err, 0, sizeof thecall->err);
            if (!xdr_remote_error (xdr, &thecall->err)) {
                remoteError(VIR_ERR_RPC, "%s", _("unmarshalling remote_error"));
                return -1;
            }
            thecall->mode = REMOTE_MODE_ERROR;
        } else {
            VIR_DEBUG0("Got a asynchronous error");
            /* No call, so queue the error against the stream */
            if (privst->has_error) {
                VIR_DEBUG0("Got unexpected duplicate stream error");
                return -1;
            }
            privst->has_error = 1;
            memset (&privst->err, 0, sizeof privst->err);
            if (!xdr_remote_error (xdr, &privst->err)) {
                VIR_DEBUG0("Failed to unmarshall error");
                return -1;
            }
        }
        return 0;

    default:
        VIR_WARN("Stream with unexpected serial=%d, proc=%d, status=%d",
                 hdr->serial, hdr->proc, hdr->status);
        return -1;
    }
}

static int
remoteIOHandleInput(virConnectPtr conn, struct private_data *priv,
                    int flags)
{
    /* Read as much data as is available, until we get
     * EAGAIN
     */
    for (;;) {
        int ret = remoteIOReadMessage(priv);

        if (ret < 0)
            return -1;
        if (ret == 0)
            return 0;  /* Blocking on read */

        /* Check for completion of our goal */
        if (priv->bufferOffset == priv->bufferLength) {
            if (priv->bufferOffset == 4) {
                ret = remoteIODecodeMessageLength(priv);
                if (ret < 0)
                    return -1;

                /*
                 * We'll carry on around the loop to immediately
                 * process the message body, because it has probably
                 * already arrived. Worst case, we'll get EAGAIN on
                 * next iteration.
                 */
            } else {
                ret = processCallDispatch(conn, priv, flags);
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
remoteIOEventLoop(virConnectPtr conn,
                  struct private_data *priv,
                  int flags,
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
#ifdef HAVE_PTHREAD_SIGMASK
        sigset_t oldmask, blockedsigs;
#endif

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

        if (priv->streams)
            fds[0].events |= POLLIN;

        /* Release lock while poll'ing so other threads
         * can stuff themselves on the queue */
        remoteDriverUnlock(priv);

        /* Block SIGWINCH from interrupting poll in curses programs,
         * then restore the original signal mask again immediately
         * after the call (RHBZ#567931).  Same for SIGCHLD and SIGPIPE
         * at the suggestion of Paolo Bonzini and Daniel Berrange.
         */
#ifdef HAVE_PTHREAD_SIGMASK
        sigemptyset (&blockedsigs);
        sigaddset (&blockedsigs, SIGWINCH);
        sigaddset (&blockedsigs, SIGCHLD);
        sigaddset (&blockedsigs, SIGPIPE);
        ignore_value(pthread_sigmask(SIG_BLOCK, &blockedsigs, &oldmask));
#endif

    repoll:
        ret = poll(fds, ARRAY_CARDINALITY(fds), -1);
        if (ret < 0 && errno == EAGAIN)
            goto repoll;

#ifdef HAVE_PTHREAD_SIGMASK
        ignore_value(pthread_sigmask(SIG_SETMASK, &oldmask, NULL));
#endif

        remoteDriverLock(priv);

        if (fds[1].revents) {
            ssize_t s;
            DEBUG0("Woken up from poll by other thread");
            s = saferead(priv->wakeupReadFD, &ignore, sizeof(ignore));
            if (s < 0) {
                virReportSystemError(errno, "%s",
                                     _("read on wakeup fd failed"));
                goto error;
            } else if (s != sizeof(ignore)) {
                remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("read on wakeup fd failed"));
                goto error;
            }
        }

        if (ret < 0) {
            if (errno == EWOULDBLOCK)
                continue;
            virReportSystemError(errno,
                                 "%s", _("poll on socket failed"));
            goto error;
        }

        if (fds[0].revents & POLLOUT) {
            if (remoteIOHandleOutput(priv) < 0)
                goto error;
        }

        if (fds[0].revents & POLLIN) {
            if (remoteIOHandleInput(conn, priv, flags) < 0)
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
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("received hangup / error event on socket"));
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
 * This function sends a message to remote server and awaits a reply
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
 * to sleep on condition variables. The existing thread may completely
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
remoteIO(virConnectPtr conn,
         struct private_data *priv,
         int flags,
         struct remote_thread_call *thiscall)
{
    int rv;

    DEBUG("Do proc=%d serial=%d length=%d wait=%p",
          thiscall->proc_nr, thiscall->serial,
          thiscall->bufferLength, priv->waitDispatch);

    /* Check to see if another thread is dispatching */
    if (priv->waitDispatch) {
        /* Stick ourselves on the end of the wait queue */
        struct remote_thread_call *tmp = priv->waitDispatch;
        char ignore = 1;
        ssize_t s;
        while (tmp && tmp->next)
            tmp = tmp->next;
        if (tmp)
            tmp->next = thiscall;
        else
            priv->waitDispatch = thiscall;

        /* Force other thread to wakeup from poll */
        s = safewrite(priv->wakeupSendFD, &ignore, sizeof(ignore));
        if (s < 0) {
            char errout[1024];
            remoteError(VIR_ERR_INTERNAL_ERROR,
                        _("failed to wake up polling thread: %s"),
                        virStrerror(errno, errout, sizeof errout));
            return -1;
        } else if (s != sizeof(ignore)) {
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to wake up polling thread"));
            return -1;
        }

        DEBUG("Going to sleep %d %p %p", thiscall->proc_nr, priv->waitDispatch, thiscall);
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
            remoteError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("failed to wait on condition"));
            return -1;
        }

        DEBUG("Wokeup from sleep %d %p %p", thiscall->proc_nr, priv->waitDispatch, thiscall);
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

    DEBUG("We have the buck %d %p %p", thiscall->proc_nr, priv->waitDispatch, thiscall);
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

    rv = remoteIOEventLoop(conn, priv, flags, thiscall);

    if (priv->watch >= 0)
        virEventUpdateHandle(priv->watch, VIR_EVENT_HANDLE_READABLE);

    if (rv < 0)
        return -1;

cleanup:
    DEBUG("All done with our call %d %p %p", thiscall->proc_nr,
          priv->waitDispatch, thiscall);
    if (thiscall->mode == REMOTE_MODE_ERROR) {
        /* Interop for virErrorNumber glitch in 0.8.0, if server is
         * 0.7.1 through 0.7.7; see comments in virterror.h. */
        switch (thiscall->err.code) {
        case VIR_WAR_NO_NWFILTER:
            /* no way to tell old VIR_WAR_NO_SECRET apart from
             * VIR_WAR_NO_NWFILTER, but both are very similar
             * warnings, so ignore the difference */
            break;
        case VIR_ERR_INVALID_NWFILTER:
        case VIR_ERR_NO_NWFILTER:
        case VIR_ERR_BUILD_FIREWALL:
            /* server was trying to pass VIR_ERR_INVALID_SECRET,
             * VIR_ERR_NO_SECRET, or VIR_ERR_CONFIG_UNSUPPORTED */
            if (thiscall->err.domain != VIR_FROM_NWFILTER)
                thiscall->err.code += 4;
            break;
        case VIR_WAR_NO_SECRET:
            if (thiscall->err.domain == VIR_FROM_QEMU)
                thiscall->err.code = VIR_ERR_OPERATION_TIMEOUT;
            break;
        case VIR_ERR_INVALID_SECRET:
            if (thiscall->err.domain == VIR_FROM_XEN)
                thiscall->err.code = VIR_ERR_MIGRATE_PERSIST_FAILED;
            break;
        default:
            /* Nothing to alter. */
            break;
        }

        /* See if caller asked us to keep quiet about missing RPCs
         * eg for interop with older servers */
        if (flags & REMOTE_CALL_QUIET_MISSING_RPC &&
            thiscall->err.domain == VIR_FROM_REMOTE &&
            thiscall->err.code == VIR_ERR_RPC &&
            thiscall->err.level == VIR_ERR_ERROR &&
            thiscall->err.message &&
            STRPREFIX(*thiscall->err.message, "unknown procedure")) {
            rv = -2;
        } else if (thiscall->err.domain == VIR_FROM_REMOTE &&
                   thiscall->err.code == VIR_ERR_RPC &&
                   thiscall->err.level == VIR_ERR_ERROR &&
                   thiscall->err.message &&
                   STRPREFIX(*thiscall->err.message, "unknown procedure")) {
            /*
             * convert missing remote entry points into the unsupported
             * feature error
             */
            virRaiseErrorFull(flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                              __FILE__, __FUNCTION__, __LINE__,
                              thiscall->err.domain,
                              VIR_ERR_NO_SUPPORT,
                              thiscall->err.level,
                              thiscall->err.str1 ? *thiscall->err.str1 : NULL,
                              thiscall->err.str2 ? *thiscall->err.str2 : NULL,
                              thiscall->err.str3 ? *thiscall->err.str3 : NULL,
                              thiscall->err.int1,
                              thiscall->err.int2,
                              "%s", *thiscall->err.message);
            rv = -1;
        } else {
            virRaiseErrorFull(flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                              __FILE__, __FUNCTION__, __LINE__,
                              thiscall->err.domain,
                              thiscall->err.code,
                              thiscall->err.level,
                              thiscall->err.str1 ? *thiscall->err.str1 : NULL,
                              thiscall->err.str2 ? *thiscall->err.str2 : NULL,
                              thiscall->err.str3 ? *thiscall->err.str3 : NULL,
                              thiscall->err.int1,
                              thiscall->err.int2,
                              "%s", thiscall->err.message ? *thiscall->err.message : "unknown");
            rv = -1;
        }
        xdr_free((xdrproc_t)xdr_remote_error,  (char *)&thiscall->err);
    } else {
        rv = 0;
    }
    return rv;
}


/*
 * Serial a set of arguments into a method call message,
 * send that to the server and wait for reply
 */
static int
call (virConnectPtr conn, struct private_data *priv,
      int flags,
      int proc_nr,
      xdrproc_t args_filter, char *args,
      xdrproc_t ret_filter, char *ret)
{
    struct remote_thread_call *thiscall;
    int rv;

    thiscall = prepareCall(priv, flags, proc_nr, args_filter, args,
                           ret_filter, ret);

    if (!thiscall) {
        virReportOOMError();
        return -1;
    }

    rv = remoteIO(conn, priv, flags, thiscall);
    VIR_FREE(thiscall);
    return rv;
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

    if (remoteIOHandleInput(conn, priv, 0) < 0)
        DEBUG0("Something went wrong during async message processing");

done:
    remoteDriverUnlock(priv);
}

static void remoteDomainEventDispatchFunc(virConnectPtr conn,
                                          virDomainEventPtr event,
                                          virConnectDomainEventGenericCallback cb,
                                          void *cbopaque,
                                          void *opaque)
{
    struct private_data *priv = opaque;

    /* Drop the lock whle dispatching, for sake of re-entrancy */
    remoteDriverUnlock(priv);
    virDomainEventDispatchDefaultFunc(conn, event, cb, cbopaque, NULL);
    remoteDriverLock(priv);
}

void
remoteDomainEventQueueFlush(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    virConnectPtr conn = opaque;
    struct private_data *priv = conn->privateData;
    virDomainEventQueue tempQueue;

    remoteDriverLock(priv);

    priv->domainEventDispatching = 1;

    /* Copy the queue, so we're reentrant safe */
    tempQueue.count = priv->domainEvents->count;
    tempQueue.events = priv->domainEvents->events;
    priv->domainEvents->count = 0;
    priv->domainEvents->events = NULL;

    virDomainEventQueueDispatch(&tempQueue, priv->callbackList,
                                remoteDomainEventDispatchFunc, priv);
    virEventUpdateTimeout(priv->eventFlushTimer, -1);

    /* Purge any deleted callbacks */
    virDomainEventCallbackListPurgeMarked(priv->callbackList);

    priv->domainEventDispatching = 0;

    remoteDriverUnlock(priv);
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

static virInterfacePtr
get_nonnull_interface (virConnectPtr conn, remote_nonnull_interface iface)
{
    return virGetInterface (conn, iface.name, iface.mac);
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

static virSecretPtr
get_nonnull_secret (virConnectPtr conn, remote_nonnull_secret secret)
{
    return virGetSecret(conn, BAD_CAST secret.uuid, secret.usageType, secret.usageID);
}

static virNWFilterPtr
get_nonnull_nwfilter (virConnectPtr conn, remote_nonnull_nwfilter nwfilter)
{
    return virGetNWFilter (conn, nwfilter.name, BAD_CAST nwfilter.uuid);
}

static virDomainSnapshotPtr
get_nonnull_domain_snapshot (virDomainPtr domain, remote_nonnull_domain_snapshot snapshot)
{
    return virGetDomainSnapshot(domain, snapshot.name);
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
make_nonnull_interface (remote_nonnull_interface *interface_dst,
                        virInterfacePtr interface_src)
{
    interface_dst->name = interface_src->name;
    interface_dst->mac = interface_src->mac;
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

static void
make_nonnull_secret (remote_nonnull_secret *secret_dst, virSecretPtr secret_src)
{
    memcpy (secret_dst->uuid, secret_src->uuid, VIR_UUID_BUFLEN);
    secret_dst->usageType = secret_src->usageType;
    secret_dst->usageID = secret_src->usageID;
}

static void
make_nonnull_nwfilter (remote_nonnull_nwfilter *nwfilter_dst, virNWFilterPtr nwfilter_src)
{
    nwfilter_dst->name = nwfilter_src->name;
    memcpy (nwfilter_dst->uuid, nwfilter_src->uuid, VIR_UUID_BUFLEN);
}

static void
make_nonnull_domain_snapshot (remote_nonnull_domain_snapshot *snapshot_dst, virDomainSnapshotPtr snapshot_src)
{
    snapshot_dst->name = snapshot_src->name;
    make_nonnull_domain(&snapshot_dst->domain, snapshot_src->domain);
}

/*----------------------------------------------------------------------*/

unsigned long remoteVersion(void)
{
    return REMOTE_PROTOCOL_VERSION;
}

static virDriver remote_driver = {
    VIR_DRV_REMOTE,
    "remote",
    remoteOpen, /* open */
    remoteClose, /* close */
    remoteSupportsFeature, /* supports_feature */
    remoteType, /* type */
    remoteGetVersion, /* version */
    remoteGetLibVersion, /* libvirtVersion */
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
    remoteDomainSetVcpusFlags, /* domainSetVcpusFlags */
    remoteDomainGetVcpusFlags, /* domainGetVcpusFlags */
    remoteDomainPinVcpu, /* domainPinVcpu */
    remoteDomainGetVcpus, /* domainGetVcpus */
    remoteDomainGetMaxVcpus, /* domainGetMaxVcpus */
    remoteDomainGetSecurityLabel, /* domainGetSecurityLabel */
    remoteNodeGetSecurityModel, /* nodeGetSecurityModel */
    remoteDomainDumpXML, /* domainDumpXML */
    remoteDomainXMLFromNative, /* domainXMLFromNative */
    remoteDomainXMLToNative, /* domainXMLToNative */
    remoteListDefinedDomains, /* listDefinedDomains */
    remoteNumOfDefinedDomains, /* numOfDefinedDomains */
    remoteDomainCreate, /* domainCreate */
    remoteDomainCreateWithFlags, /* domainCreateWithFlags */
    remoteDomainDefineXML, /* domainDefineXML */
    remoteDomainUndefine, /* domainUndefine */
    remoteDomainAttachDevice, /* domainAttachDevice */
    remoteDomainAttachDeviceFlags, /* domainAttachDeviceFlags */
    remoteDomainDetachDevice, /* domainDetachDevice */
    remoteDomainDetachDeviceFlags, /* domainDetachDeviceFlags */
    remoteDomainUpdateDeviceFlags, /* domainUpdateDeviceFlags */
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
    remoteDomainMemoryStats, /* domainMemoryStats */
    remoteDomainBlockPeek, /* domainBlockPeek */
    remoteDomainMemoryPeek, /* domainMemoryPeek */
    remoteDomainGetBlockInfo, /* domainGetBlockInfo */
    remoteNodeGetCellsFreeMemory, /* nodeGetCellsFreeMemory */
    remoteNodeGetFreeMemory, /* getFreeMemory */
    remoteDomainEventRegister, /* domainEventRegister */
    remoteDomainEventDeregister, /* domainEventDeregister */
    remoteDomainMigratePrepare2, /* domainMigratePrepare2 */
    remoteDomainMigrateFinish2, /* domainMigrateFinish2 */
    remoteNodeDeviceDettach, /* nodeDeviceDettach */
    remoteNodeDeviceReAttach, /* nodeDeviceReAttach */
    remoteNodeDeviceReset, /* nodeDeviceReset */
    remoteDomainMigratePrepareTunnel, /* domainMigratePrepareTunnel */
    remoteIsEncrypted, /* isEncrypted */
    remoteIsSecure, /* isSecure */
    remoteDomainIsActive, /* domainIsActive */
    remoteDomainIsPersistent, /* domainIsPersistent */
    remoteDomainIsUpdated, /* domainIsUpdated */
    remoteCPUCompare, /* cpuCompare */
    remoteCPUBaseline, /* cpuBaseline */
    remoteDomainGetJobInfo, /* domainGetJobInfo */
    remoteDomainAbortJob, /* domainFinishJob */
    remoteDomainMigrateSetMaxDowntime, /* domainMigrateSetMaxDowntime */
    remoteDomainEventRegisterAny, /* domainEventRegisterAny */
    remoteDomainEventDeregisterAny, /* domainEventDeregisterAny */
    remoteDomainManagedSave, /* domainManagedSave */
    remoteDomainHasManagedSaveImage, /* domainHasManagedSaveImage */
    remoteDomainManagedSaveRemove, /* domainManagedSaveRemove */
    remoteDomainSnapshotCreateXML, /* domainSnapshotCreateXML */
    remoteDomainSnapshotDumpXML, /* domainSnapshotDumpXML */
    remoteDomainSnapshotNum, /* domainSnapshotNum */
    remoteDomainSnapshotListNames, /* domainSnapshotListNames */
    remoteDomainSnapshotLookupByName, /* domainSnapshotLookupByName */
    remoteDomainHasCurrentSnapshot, /* domainHasCurrentSnapshot */
    remoteDomainSnapshotCurrent, /* domainSnapshotCurrent */
    remoteDomainRevertToSnapshot, /* domainRevertToSnapshot */
    remoteDomainSnapshotDelete, /* domainSnapshotDelete */
    remoteQemuDomainMonitorCommand, /* qemuDomainMonitorCommand */
    remoteDomainSetMemoryParameters, /* domainSetMemoryParameters */
    remoteDomainGetMemoryParameters, /* domainGetMemoryParameters */
    remoteDomainOpenConsole, /* domainOpenConsole */
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
    .networkIsActive = remoteNetworkIsActive,
    .networkIsPersistent = remoteNetworkIsPersistent,
};

static virInterfaceDriver interface_driver = {
    .name = "remote",
    .open = remoteInterfaceOpen,
    .close = remoteInterfaceClose,
    .numOfInterfaces = remoteNumOfInterfaces,
    .listInterfaces = remoteListInterfaces,
    .numOfDefinedInterfaces = remoteNumOfDefinedInterfaces,
    .listDefinedInterfaces = remoteListDefinedInterfaces,
    .interfaceLookupByName = remoteInterfaceLookupByName,
    .interfaceLookupByMACString = remoteInterfaceLookupByMACString,
    .interfaceGetXMLDesc = remoteInterfaceGetXMLDesc,
    .interfaceDefineXML = remoteInterfaceDefineXML,
    .interfaceUndefine = remoteInterfaceUndefine,
    .interfaceCreate = remoteInterfaceCreate,
    .interfaceDestroy = remoteInterfaceDestroy,
    .interfaceIsActive = remoteInterfaceIsActive,
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
    .volCreateXMLFrom = remoteStorageVolCreateXMLFrom,
    .volDelete = remoteStorageVolDelete,
    .volWipe = remoteStorageVolWipe,
    .volGetInfo = remoteStorageVolGetInfo,
    .volGetXMLDesc = remoteStorageVolDumpXML,
    .volGetPath = remoteStorageVolGetPath,
    .poolIsActive = remoteStoragePoolIsActive,
    .poolIsPersistent = remoteStoragePoolIsPersistent,
};

static virSecretDriver secret_driver = {
    .name = "remote",
    .open = remoteSecretOpen,
    .close = remoteSecretClose,
    .numOfSecrets = remoteSecretNumOfSecrets,
    .listSecrets = remoteSecretListSecrets,
    .lookupByUUID = remoteSecretLookupByUUID,
    .lookupByUsage = remoteSecretLookupByUsage,
    .defineXML = remoteSecretDefineXML,
    .getXMLDesc = remoteSecretGetXMLDesc,
    .setValue = remoteSecretSetValue,
    .getValue = remoteSecretGetValue,
    .undefine = remoteSecretUndefine
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
    .deviceCreateXML = remoteNodeDeviceCreateXML,
    .deviceDestroy = remoteNodeDeviceDestroy
};

static virNWFilterDriver nwfilter_driver = {
    .name = "remote",
    .open = remoteNWFilterOpen,
    .close = remoteNWFilterClose,
    .nwfilterLookupByUUID = remoteNWFilterLookupByUUID,
    .nwfilterLookupByName = remoteNWFilterLookupByName,
    .getXMLDesc           = remoteNWFilterGetXMLDesc,
    .defineXML            = remoteNWFilterDefineXML,
    .undefine             = remoteNWFilterUndefine,
    .numOfNWFilters       = remoteNumOfNWFilters,
    .listNWFilters        = remoteListNWFilters,
};


#ifdef WITH_LIBVIRTD
static virStateDriver state_driver = {
    .name = "Remote",
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
    if (virRegisterDriver (&remote_driver) == -1) return -1;
    if (virRegisterNetworkDriver (&network_driver) == -1) return -1;
    if (virRegisterInterfaceDriver (&interface_driver) == -1) return -1;
    if (virRegisterStorageDriver (&storage_driver) == -1) return -1;
    if (virRegisterDeviceMonitor (&dev_monitor) == -1) return -1;
    if (virRegisterSecretDriver (&secret_driver) == -1) return -1;
    if (virRegisterNWFilterDriver(&nwfilter_driver) == -1) return -1;
#ifdef WITH_LIBVIRTD
    if (virRegisterStateDriver (&state_driver) == -1) return -1;
#endif

    return 0;
}
