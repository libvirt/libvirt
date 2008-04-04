/*
 * remote_internal.c: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2007-2008 Red Hat, Inc.
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
#include "socketcompat.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

#include "getaddrinfo.h"

/* AI_ADDRCONFIG is missing on some systems. */
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

#include "internal.h"
#include "driver.h"
#include "buf.h"
#include "qparams.h"
#include "remote_internal.h"
#include "remote_protocol.h"

#define DEBUG(fmt,...) VIR_DEBUG(__FILE__, fmt,__VA_ARGS__)
#define DEBUG0(msg) VIR_DEBUG(__FILE__, "%s", msg)

/* Per-connection private data. */
#define MAGIC 999               /* private_data->magic if OK */
#define DEAD 998                /* private_data->magic if dead/closed */

static int inside_daemon = 0;

struct private_data {
    int magic;                  /* Should be MAGIC or DEAD. */
    int sock;                   /* Socket. */
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
#endif
};

#define GET_PRIVATE(conn,retcode)                                       \
    struct private_data *priv = (struct private_data *) (conn)->privateData; \
    if (!priv || priv->magic != MAGIC) {                                \
        error (conn, VIR_ERR_INVALID_ARG,                               \
               _("tried to use a closed or uninitialised handle"));     \
        return (retcode);                                               \
    }

#define GET_NETWORK_PRIVATE(conn,retcode)                               \
    struct private_data *priv = (struct private_data *) (conn)->networkPrivateData; \
    if (!priv || priv->magic != MAGIC) {                                \
        error (conn, VIR_ERR_INVALID_ARG,                               \
               _("tried to use a closed or uninitialised handle"));     \
        return (retcode);                                               \
    }

#define GET_STORAGE_PRIVATE(conn,retcode)                               \
    struct private_data *priv = (struct private_data *) (conn)->storagePrivateData; \
    if (!priv || priv->magic != MAGIC) {                                \
        error (conn, VIR_ERR_INVALID_ARG,                               \
               "tried to use a closed or uninitialised handle");        \
        return (retcode);                                               \
    }


enum {
    REMOTE_CALL_IN_OPEN = 1,
    REMOTE_CALL_QUIET_MISSING_RPC = 2,
};


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
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);
static void make_nonnull_storage_pool (remote_nonnull_storage_pool *pool_dst, virStoragePoolPtr vol_src);
static void make_nonnull_storage_vol (remote_nonnull_storage_vol *vol_dst, virStorageVolPtr vol_src);

/*----------------------------------------------------------------------*/

/* Helper functions for remoteOpen. */
static char *get_transport_from_scheme (char *scheme);

/* GnuTLS functions used by remoteOpen. */
static int initialise_gnutls (virConnectPtr conn);
static gnutls_session_t negotiate_gnutls_on_connection (virConnectPtr conn, struct private_data *priv, int no_verify);

static int
remoteStartup(void)
{
    /* Mark that we're inside the daemon so we can avoid
     * re-entering ourselves
     */
    inside_daemon = 1;
    return 0;
}

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

#ifndef WIN32
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
    int ret, pid, status;

    if (!daemonPath) {
        error(conn, VIR_ERR_INTERNAL_ERROR, _("failed to find libvirtd binary"));
        return(-1);
    }

    /* Become a daemon */
    pid = fork();
    if (pid == 0) {
        int stdinfd = -1;
        int stdoutfd = -1;
        int i, open_max;
        if ((stdinfd = open(_PATH_DEVNULL, O_RDONLY)) < 0)
            goto cleanup;
        if ((stdoutfd = open(_PATH_DEVNULL, O_WRONLY)) < 0)
            goto cleanup;
        if (dup2(stdinfd, STDIN_FILENO) != STDIN_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDOUT_FILENO) != STDOUT_FILENO)
            goto cleanup;
        if (dup2(stdoutfd, STDERR_FILENO) != STDERR_FILENO)
            goto cleanup;
        if (close(stdinfd) < 0)
            goto cleanup;
        stdinfd = -1;
        if (close(stdoutfd) < 0)
            goto cleanup;
        stdoutfd = -1;

        open_max = sysconf (_SC_OPEN_MAX);
        for (i = 0; i < open_max; i++)
            if (i != STDIN_FILENO &&
                i != STDOUT_FILENO &&
                i != STDERR_FILENO)
                close(i);

        setsid();
        if (fork() == 0) {
            /* Run daemon in auto-shutdown mode, so it goes away when
               no longer needed by an active guest, or client */
            execl(daemonPath, daemonPath, "--timeout", "30", NULL);
        }
        /*
         * calling exit() generate troubles for termination handlers
         */
        _exit(0);

    cleanup:
        if (stdoutfd != -1)
            close(stdoutfd);
        if (stdinfd != -1)
            close(stdinfd);
        _exit(-1);
    }

    /*
     * do a waitpid on the intermediate process to avoid zombies.
     */
 retry_wait:
    ret = waitpid(pid, &status, 0);
    if (ret < 0) {
        if (errno == EINTR)
            goto retry_wait;
    }

    return (0);
}
#endif

enum virDrvOpenRemoteFlags {
    VIR_DRV_OPEN_REMOTE_RO = (1 << 0),
    VIR_DRV_OPEN_REMOTE_UNIX = (1 << 1),
    VIR_DRV_OPEN_REMOTE_USER = (1 << 2),
    VIR_DRV_OPEN_REMOTE_AUTOSTART = (1 << 3),
};

static int
doRemoteOpen (virConnectPtr conn,
              struct private_data *priv,
              xmlURIPtr uri,
              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
              int flags)
{
    if (!uri || !uri->scheme)
        return VIR_DRV_OPEN_DECLINED; /* Decline - not a URL. */

    char *transport_str = get_transport_from_scheme (uri->scheme);

    /* What transport? */
    enum {
        trans_tls,
        trans_unix,
        trans_ssh,
        trans_ext,
        trans_tcp,
    } transport;

    if (!transport_str || strcasecmp (transport_str, "tls") == 0)
        transport = trans_tls;
    else if (strcasecmp (transport_str, "unix") == 0)
        transport = trans_unix;
    else if (strcasecmp (transport_str, "ssh") == 0)
        transport = trans_ssh;
    else if (strcasecmp (transport_str, "ext") == 0)
        transport = trans_ext;
    else if (strcasecmp (transport_str, "tcp") == 0)
        transport = trans_tcp;
    else {
        error (conn, VIR_ERR_INVALID_ARG,
               _("remote_open: transport in URL not recognised "
                 "(should be tls|unix|ssh|ext|tcp)"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (!uri->server && !transport_str) {
        if (flags & VIR_DRV_OPEN_REMOTE_UNIX)
            transport = trans_unix;
        else
            return VIR_DRV_OPEN_DECLINED; /* Decline - not a remote URL. */
    }

    /* Local variables which we will initialise. These can
     * get freed in the failed: path.
     */
    char *name = 0, *command = 0, *sockname = 0, *netcat = 0, *username = 0;
    char *port = 0, *authtype = 0;
    int no_verify = 0, no_tty = 0;
    char **cmd_argv = 0;

    /* Return code from this function, and the private data. */
    int retcode = VIR_DRV_OPEN_ERROR;

    /* Remote server defaults to "localhost" if not specified. */
    if (uri->port != 0) {
        if (asprintf (&port, "%d", uri->port) == -1) goto out_of_memory;
    } else if (transport == trans_tls) {
        port = strdup (LIBVIRTD_TLS_PORT);
        if (!port) goto out_of_memory;
    } else if (transport == trans_tcp) {
        port = strdup (LIBVIRTD_TCP_PORT);
        if (!port) goto out_of_memory;
    } else if (transport == trans_ssh) {
        port = strdup ("22");
        if (!port) goto out_of_memory;
    } else
        port = NULL;           /* Port not used for unix, ext. */


    priv->hostname = strdup (uri->server ? uri->server : "localhost");
    if (!priv->hostname) {
        error (NULL, VIR_ERR_NO_MEMORY, _("allocating priv->hostname"));
        goto failed;
    }
    if (uri->user) {
        username = strdup (uri->user);
        if (!username) goto out_of_memory;
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
#ifdef HAVE_XMLURI_QUERY_RAW
    query = uri->query_raw;
#else
    query = uri->query;
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

#ifdef HAVE_XMLURI_QUERY_RAW
    if (uri->query_raw) xmlFree (uri->query_raw);
#else
    if (uri->query) xmlFree (uri->query);
#endif

    if ((
#ifdef HAVE_XMLURI_QUERY_RAW
         uri->query_raw =
#else
         uri->query =
#endif
         qparam_get_query (vars)) == NULL) goto failed;

    free_qparam_set (vars);

    /* For ext transport, command is required. */
    if (transport == trans_ext && !command) {
        error (conn, VIR_ERR_INVALID_ARG,
               _("remote_open: for 'ext' transport, command is required"));
        goto failed;
    }

    /* Construct the original name. */
    if (!name) {
        /* Remove the transport (if any) from the scheme. */
        if (transport_str) {
            assert (transport_str[-1] == '+');
            transport_str[-1] = '\0';
        }
        /* Remove the username, server name and port number. */
        if (uri->user) xmlFree (uri->user);
        uri->user = 0;

        if (uri->server) xmlFree (uri->server);
        uri->server = 0;

        uri->port = 0;

        name = (char *) xmlSaveUri (uri);
    }

    assert (name);
    DEBUG("proceeding with name = %s", name);

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
        memset (&hints, 0, sizeof hints);
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ADDRCONFIG;
        int e = getaddrinfo (priv->hostname, port, &hints, &res);
        if (e != 0) {
            error (conn, VIR_ERR_INVALID_ARG, gai_strerror (e));
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
                error (conn, VIR_ERR_SYSTEM_ERROR, strerror (socket_errno ()));
                continue;
            }

            /* Disable Nagle - Dan Berrange. */
            setsockopt (priv->sock,
                        IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                        sizeof no_slow_start);

            if (connect (priv->sock, r->ai_addr, r->ai_addrlen) == -1) {
                error (conn, VIR_ERR_SYSTEM_ERROR, strerror (socket_errno ()));
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
                struct passwd *pw;
                uid_t uid = getuid();

                if (!(pw = getpwuid(uid))) {
                    error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }

                if (asprintf (&sockname, "@%s" LIBVIRTD_USER_UNIX_SOCKET, pw->pw_dir) < 0) {
                    error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }
            } else {
                if (flags & VIR_DRV_OPEN_REMOTE_RO)
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET_RO);
                else
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET);
                if (sockname == NULL) {
                    error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }
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
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
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
                trials < 5) {
                close(priv->sock);
                priv->sock = -1;
                if (remoteForkDaemon(conn) == 0) {
                    trials++;
                    usleep(5000 * trials * trials);
                    goto autostart_retry;
                }
            }
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        break;
    }

    case trans_ssh: {
        int j, nr_args = 8;

        if (username) nr_args += 2; /* For -l username */
        if (no_tty) nr_args += 5;   /* For -T -o BatchMode=yes -e none */

        command = command ? : strdup ("ssh");
        if (command == NULL) {
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        // Generate the final command argv[] array.
        //   ssh -p $port [-l $username] $hostname $netcat -U $sockname [NULL]
        cmd_argv = malloc (nr_args * sizeof (*cmd_argv));
        if (cmd_argv == NULL) {
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        j = 0;
        cmd_argv[j++] = strdup (command);
        cmd_argv[j++] = strdup ("-p");
        cmd_argv[j++] = strdup (port);
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
        for (j = 0; j < (nr_args-1); j++) {
            if (cmd_argv[j] == NULL) {
                error (conn, VIR_ERR_SYSTEM_ERROR, strerror (ENOMEM));
                goto failed;
            }
        }
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
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        pid = fork ();
        if (pid == -1) {
            error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        } else if (pid == 0) { /* Child. */
            close (sv[0]);
            // Connect socket (sv[1]) to stdin/stdout.
            close (0);
            if (dup (sv[1]) == -1) perror ("dup");
            close (1);
            if (dup (sv[1]) == -1) perror ("dup");
            close (sv[1]);

            // Run the external process.
            if (!cmd_argv) {
                cmd_argv = malloc (2 * sizeof (*cmd_argv));
                if (cmd_argv == NULL) {
                    error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }
                cmd_argv[0] = command;
                cmd_argv[1] = 0;
            }
            execvp (command, cmd_argv);
            perror (command);
            _exit (1);
        }

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

#endif /* WIN32 */

    } /* switch (transport) */


    /* Try and authenticate with server */
    if (remoteAuthenticate(conn, priv, 1, auth, authtype) == -1)
        goto failed;

    /* Finally we can call the remote side's open function. */
    remote_open_args args = { &name, flags };

    if (call (conn, priv, REMOTE_CALL_IN_OPEN, REMOTE_PROC_OPEN,
              (xdrproc_t) xdr_remote_open_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto failed;

    /* Successful. */
    retcode = VIR_DRV_OPEN_SUCCESS;

 cleanup:
    /* Free up the URL and strings. */
    free (name);
    free (command);
    free (sockname);
    free (authtype);
    free (netcat);
    free (username);
    free (port);
    if (cmd_argv) {
        char **cmd_argv_ptr = cmd_argv;
        while (*cmd_argv_ptr) {
            free (*cmd_argv_ptr);
            cmd_argv_ptr++;
        }
        free (cmd_argv);
    }

    return retcode;

 out_of_memory:
    error (NULL, VIR_ERR_NO_MEMORY, _("uri params"));

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

    if (priv->hostname) {
        free (priv->hostname);
        priv->hostname = NULL;
    }

    goto cleanup;
}

static int
remoteOpen (virConnectPtr conn,
            xmlURIPtr uri,
            virConnectAuthPtr auth,
            int flags)
{
    struct private_data *priv;
    int ret, rflags = 0;

    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    priv = calloc (1, sizeof(*priv));
    if (!priv) {
        error (conn, VIR_ERR_NO_MEMORY, _("struct private_data"));
        return VIR_DRV_OPEN_ERROR;
    }

    if (flags & VIR_CONNECT_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

#if WITH_QEMU
    if (uri &&
        uri->scheme && STREQ (uri->scheme, "qemu") &&
        (!uri->server || STREQ (uri->server, "")) &&
        uri->path) {
        if (STREQ (uri->path, "/system")) {
            rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
        } else if (STREQ (uri->path, "/session")) {
            rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
            if (getuid() > 0) {
                rflags |= VIR_DRV_OPEN_REMOTE_USER;
                rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
            }
        }
    }
#endif
#if WITH_XEN
    if (uri &&
        uri->scheme && STREQ (uri->scheme, "xen") &&
        (!uri->server || STREQ (uri->server, "")) &&
        (!uri->path || STREQ(uri->path, "/"))) {
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
    }
#endif
#if WITH_LXC
    if (uri &&
        uri->scheme && STREQ (uri->scheme, "lxc")) {
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
    }
#endif

    priv->magic = DEAD;
    priv->sock = -1;
    ret = doRemoteOpen(conn, priv, uri, auth, rflags);
    if (ret != VIR_DRV_OPEN_SUCCESS) {
        conn->privateData = NULL;
        free(priv);
    } else {
        priv->magic = MAGIC;
        conn->privateData = priv;
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
        __virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE, VIR_ERR_RPC,
                         VIR_ERR_ERROR, LIBVIRT_CACERT, NULL, NULL, 0, 0,
                         _("Cannot access %s '%s': %s (%d)"),
                         type, file, strerror(errno), errno);
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    /* Use default priorities */
    err = gnutls_set_default_priority (session);
    if (err) {
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }
    err =
        gnutls_certificate_type_set_priority (session,
                                              cert_type_priority);
    if (err) {
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    /* put the x509 credentials to the current session
     */
    err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (err) {
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (len));
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
        error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
        return -1;
    }

    if ((now = time(NULL)) == ((time_t)-1)) {
        error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return -1;
    }

    if (status != 0) {
        const char *reason = "Invalid certificate";

        if (status & GNUTLS_CERT_INVALID)
            reason = "The certificate is not trusted.";

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            reason = "The certificate hasn't got a known issuer.";

        if (status & GNUTLS_CERT_REVOKED)
            reason = "The certificate has been revoked.";

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            reason = "The certificate uses an insecure algorithm";
#endif

        error (conn, VIR_ERR_RPC, reason);
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
            error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
            return -1;
        }

        ret = gnutls_x509_crt_import (cert, &certs[i], GNUTLS_X509_FMT_DER);
        if (ret < 0) {
            error (conn, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
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
                __virRaiseError
                    (conn, NULL, NULL,
                     VIR_FROM_REMOTE, VIR_ERR_RPC,
                     VIR_ERR_ERROR, priv->hostname, NULL, NULL,
                     0, 0,
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

    /* Free hostname copy */
    free (priv->hostname);

    /* See comment for remoteType. */
    free (priv->type);

    /* Free private data. */
    priv->magic = DEAD;

    return 0;
}

static int
remoteClose (virConnectPtr conn)
{
    int ret;
    GET_PRIVATE (conn, -1);

    ret = doRemoteClose(conn, priv);
    free (priv);
    conn->privateData = NULL;

    return ret;
}

static int
remoteSupportsFeature (virConnectPtr conn, int feature)
{
    remote_supports_feature_args args;
    remote_supports_feature_ret ret;
    GET_PRIVATE (conn, -1);

    /* VIR_DRV_FEATURE_REMOTE* features are handled directly. */
    if (feature == VIR_DRV_FEATURE_REMOTE) return 1;

    args.feature = feature;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_SUPPORTS_FEATURE,
              (xdrproc_t) xdr_remote_supports_feature_args, (char *) &args,
              (xdrproc_t) xdr_remote_supports_feature_ret, (char *) &ret) == -1)
        return -1;

    return ret.supported;
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
    remote_get_type_ret ret;
    GET_PRIVATE (conn, NULL);

    /* Cached? */
    if (priv->type) return priv->type;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_TYPE,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_type_ret, (char *) &ret) == -1)
        return NULL;

    /* Stash. */
    return priv->type = ret.type;
}

static int
remoteVersion (virConnectPtr conn, unsigned long *hvVer)
{
    remote_get_version_ret ret;
    GET_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_VERSION,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_version_ret, (char *) &ret) == -1)
        return -1;

    if (hvVer) *hvVer = ret.hv_ver;
    return 0;
}

static char *
remoteGetHostname (virConnectPtr conn)
{
    remote_get_hostname_ret ret;
    GET_PRIVATE (conn, NULL);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_HOSTNAME,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_hostname_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees this. */
    return ret.hostname;
}

static int
remoteGetMaxVcpus (virConnectPtr conn, const char *type)
{
    remote_get_max_vcpus_args args;
    remote_get_max_vcpus_ret ret;
    GET_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    args.type = type == NULL ? NULL : (char **) &type;
    if (call (conn, priv, 0, REMOTE_PROC_GET_MAX_VCPUS,
              (xdrproc_t) xdr_remote_get_max_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_get_max_vcpus_ret, (char *) &ret) == -1)
        return -1;

    return ret.max_vcpus;
}

static int
remoteNodeGetInfo (virConnectPtr conn, virNodeInfoPtr info)
{
    remote_node_get_info_ret ret;
    GET_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NODE_GET_INFO,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_node_get_info_ret, (char *) &ret) == -1)
        return -1;

    strncpy (info->model, ret.model, 32);
    info->model[31] = '\0';
    info->memory = ret.memory;
    info->cpus = ret.cpus;
    info->mhz = ret.mhz;
    info->nodes = ret.nodes;
    info->sockets = ret.sockets;
    info->cores = ret.cores;
    info->threads = ret.threads;
    return 0;
}

static char *
remoteGetCapabilities (virConnectPtr conn)
{
    remote_get_capabilities_ret ret;
    GET_PRIVATE (conn, NULL);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_GET_CAPABILITIES,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_get_capabilities_ret, (char *)&ret) == -1)
        return NULL;

    /* Caller frees this. */
    return ret.capabilities;
}

static int
remoteListDomains (virConnectPtr conn, int *ids, int maxids)
{
    int i;
    remote_list_domains_args args;
    remote_list_domains_ret ret;
    GET_PRIVATE (conn, -1);

    if (maxids > REMOTE_DOMAIN_ID_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain IDs: %d > %d"),
                maxids, REMOTE_DOMAIN_ID_LIST_MAX);
        return -1;
    }
    args.maxids = maxids;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DOMAINS,
              (xdrproc_t) xdr_remote_list_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret) == -1)
        return -1;

    if (ret.ids.ids_len > maxids) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain IDs: %d > %d"),
                ret.ids.ids_len, maxids);
        xdr_free ((xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret);
        return -1;
    }

    for (i = 0; i < ret.ids.ids_len; ++i)
        ids[i] = ret.ids.ids_val[i];

    xdr_free ((xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret);

    return ret.ids.ids_len;
}

static int
remoteNumOfDomains (virConnectPtr conn)
{
    remote_num_of_domains_ret ret;
    GET_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DOMAINS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_domains_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static virDomainPtr
remoteDomainCreateLinux (virConnectPtr conn,
                         const char *xmlDesc,
                         unsigned int flags)
{
    virDomainPtr dom;
    remote_domain_create_linux_args args;
    remote_domain_create_linux_ret ret;
    GET_PRIVATE (conn, NULL);

    args.xml_desc = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE_LINUX,
              (xdrproc_t) xdr_remote_domain_create_linux_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_create_linux_ret, (char *) &ret) == -1)
        return NULL;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_create_linux_ret, (char *) &ret);

    return dom;
}

static virDomainPtr
remoteDomainLookupByID (virConnectPtr conn, int id)
{
    virDomainPtr dom;
    remote_domain_lookup_by_id_args args;
    remote_domain_lookup_by_id_ret ret;
    GET_PRIVATE (conn, NULL);

    args.id = id;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_ID,
              (xdrproc_t) xdr_remote_domain_lookup_by_id_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_id_ret, (char *) &ret) == -1)
        return NULL;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_id_ret, (char *) &ret);

    return dom;
}

static virDomainPtr
remoteDomainLookupByUUID (virConnectPtr conn, const unsigned char *uuid)
{
    virDomainPtr dom;
    remote_domain_lookup_by_uuid_args args;
    remote_domain_lookup_by_uuid_ret ret;
    GET_PRIVATE (conn, NULL);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret) == -1)
        return NULL;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_uuid_ret, (char *) &ret);
    return dom;
}

static virDomainPtr
remoteDomainLookupByName (virConnectPtr conn, const char *name)
{
    virDomainPtr dom;
    remote_domain_lookup_by_name_args args;
    remote_domain_lookup_by_name_ret ret;
    GET_PRIVATE (conn, NULL);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_domain_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_lookup_by_name_ret, (char *) &ret) == -1)
        return NULL;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_lookup_by_name_ret, (char *) &ret);

    return dom;
}

static int
remoteDomainSuspend (virDomainPtr domain)
{
    remote_domain_suspend_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SUSPEND,
              (xdrproc_t) xdr_remote_domain_suspend_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainResume (virDomainPtr domain)
{
    remote_domain_resume_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_RESUME,
              (xdrproc_t) xdr_remote_domain_resume_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainShutdown (virDomainPtr domain)
{
    remote_domain_shutdown_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SHUTDOWN,
              (xdrproc_t) xdr_remote_domain_shutdown_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainReboot (virDomainPtr domain, unsigned int flags)
{
    remote_domain_reboot_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_REBOOT,
              (xdrproc_t) xdr_remote_domain_reboot_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainDestroy (virDomainPtr domain)
{
    remote_domain_destroy_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DESTROY,
              (xdrproc_t) xdr_remote_domain_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static char *
remoteDomainGetOSType (virDomainPtr domain)
{
    remote_domain_get_os_type_args args;
    remote_domain_get_os_type_ret ret;
    GET_PRIVATE (domain->conn, NULL);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_OS_TYPE,
              (xdrproc_t) xdr_remote_domain_get_os_type_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_os_type_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.type;
}

static unsigned long
remoteDomainGetMaxMemory (virDomainPtr domain)
{
    remote_domain_get_max_memory_args args;
    remote_domain_get_max_memory_ret ret;
    GET_PRIVATE (domain->conn, 0);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MAX_MEMORY,
              (xdrproc_t) xdr_remote_domain_get_max_memory_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_max_memory_ret, (char *) &ret) == -1)
        return 0;

    return ret.memory;
}

static int
remoteDomainSetMaxMemory (virDomainPtr domain, unsigned long memory)
{
    remote_domain_set_max_memory_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.memory = memory;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_MAX_MEMORY,
              (xdrproc_t) xdr_remote_domain_set_max_memory_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainSetMemory (virDomainPtr domain, unsigned long memory)
{
    remote_domain_set_memory_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.memory = memory;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_MEMORY,
              (xdrproc_t) xdr_remote_domain_set_memory_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainGetInfo (virDomainPtr domain, virDomainInfoPtr info)
{
    remote_domain_get_info_args args;
    remote_domain_get_info_ret ret;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_INFO,
              (xdrproc_t) xdr_remote_domain_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_info_ret, (char *) &ret) == -1)
        return -1;

    info->state = ret.state;
    info->maxMem = ret.max_mem;
    info->memory = ret.memory;
    info->nrVirtCpu = ret.nr_virt_cpu;
    info->cpuTime = ret.cpu_time;

    return 0;
}

static int
remoteDomainSave (virDomainPtr domain, const char *to)
{
    remote_domain_save_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.to = (char *) to;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SAVE,
              (xdrproc_t) xdr_remote_domain_save_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainRestore (virConnectPtr conn, const char *from)
{
    remote_domain_restore_args args;
    GET_PRIVATE (conn, -1);

    args.from = (char *) from;

    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_RESTORE,
              (xdrproc_t) xdr_remote_domain_restore_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainCoreDump (virDomainPtr domain, const char *to, int flags)
{
    remote_domain_core_dump_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.to = (char *) to;
    args.flags = flags;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CORE_DUMP,
              (xdrproc_t) xdr_remote_domain_core_dump_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainSetVcpus (virDomainPtr domain, unsigned int nvcpus)
{
    remote_domain_set_vcpus_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.nvcpus = nvcpus;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_VCPUS,
              (xdrproc_t) xdr_remote_domain_set_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainPinVcpu (virDomainPtr domain,
                     unsigned int vcpu,
                     unsigned char *cpumap,
                     int maplen)
{
    remote_domain_pin_vcpu_args args;
    GET_PRIVATE (domain->conn, -1);

    if (maplen > REMOTE_CPUMAP_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("map length greater than maximum: %d > %d"),
                maplen, REMOTE_CPUMAP_MAX);
        return -1;
    }

    make_nonnull_domain (&args.dom, domain);
    args.vcpu = vcpu;
    args.cpumap.cpumap_len = maplen;
    args.cpumap.cpumap_val = (char *) cpumap;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_PIN_VCPU,
              (xdrproc_t) xdr_remote_domain_pin_vcpu_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainGetVcpus (virDomainPtr domain,
                      virVcpuInfoPtr info,
                      int maxinfo,
                      unsigned char *cpumaps,
                      int maplen)
{
    int i;
    remote_domain_get_vcpus_args args;
    remote_domain_get_vcpus_ret ret;
    GET_PRIVATE (domain->conn, -1);

    if (maxinfo > REMOTE_VCPUINFO_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("vCPU count exceeds maximum: %d > %d"),
                maxinfo, REMOTE_VCPUINFO_MAX);
        return -1;
    }
    if (maxinfo * maplen > REMOTE_CPUMAPS_MAX) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("vCPU map buffer length exceeds maximum: %d > %d"),
                maxinfo * maplen, REMOTE_CPUMAPS_MAX);
        return -1;
    }

    make_nonnull_domain (&args.dom, domain);
    args.maxinfo = maxinfo;
    args.maplen = maplen;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_VCPUS,
              (xdrproc_t) xdr_remote_domain_get_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret) == -1)
        return -1;

    if (ret.info.info_len > maxinfo) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("host reports too many vCPUs: %d > %d"),
                ret.info.info_len, maxinfo);
        xdr_free ((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);
        return -1;
    }
    if (ret.cpumaps.cpumaps_len > maxinfo * maplen) {
        errorf (domain->conn, VIR_ERR_RPC,
                _("host reports map buffer length exceeds maximum: %d > %d"),
                ret.cpumaps.cpumaps_len, maxinfo * maplen);
        xdr_free ((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);
        return -1;
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

    xdr_free ((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);
    return ret.info.info_len;
}

static int
remoteDomainGetMaxVcpus (virDomainPtr domain)
{
    remote_domain_get_max_vcpus_args args;
    remote_domain_get_max_vcpus_ret ret;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_MAX_VCPUS,
              (xdrproc_t) xdr_remote_domain_get_max_vcpus_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_max_vcpus_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static char *
remoteDomainDumpXML (virDomainPtr domain, int flags)
{
    remote_domain_dump_xml_args args;
    remote_domain_dump_xml_ret ret;
    GET_PRIVATE (domain->conn, NULL);

    make_nonnull_domain (&args.dom, domain);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DUMP_XML,
              (xdrproc_t) xdr_remote_domain_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_dump_xml_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.xml;
}

static int
remoteDomainMigratePrepare (virConnectPtr dconn,
                            char **cookie, int *cookielen,
                            const char *uri_in, char **uri_out,
                            unsigned long flags, const char *dname,
                            unsigned long resource)
{
    remote_domain_migrate_prepare_args args;
    remote_domain_migrate_prepare_ret ret;
    GET_PRIVATE (dconn, -1);

    args.uri_in = uri_in == NULL ? NULL : (char **) &uri_in;
    args.flags = flags;
    args.dname = dname == NULL ? NULL : (char **) &dname;
    args.resource = resource;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_PREPARE,
              (xdrproc_t) xdr_remote_domain_migrate_prepare_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_prepare_ret, (char *) &ret) == -1)
        return -1;

    if (ret.cookie.cookie_len > 0) {
        *cookie = ret.cookie.cookie_val; /* Caller frees. */
        *cookielen = ret.cookie.cookie_len;
    }
    if (ret.uri_out)
        *uri_out = *ret.uri_out; /* Caller frees. */

    return 0;
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
    remote_domain_migrate_perform_args args;
    GET_PRIVATE (domain->conn, -1);

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
        return -1;

    return 0;
}

static virDomainPtr
remoteDomainMigrateFinish (virConnectPtr dconn,
                           const char *dname,
                           const char *cookie,
                           int cookielen,
                           const char *uri,
                           unsigned long flags)
{
    virDomainPtr ddom;
    remote_domain_migrate_finish_args args;
    remote_domain_migrate_finish_ret ret;
    GET_PRIVATE (dconn, NULL);

    args.dname = (char *) dname;
    args.cookie.cookie_len = cookielen;
    args.cookie.cookie_val = (char *) cookie;
    args.uri = (char *) uri;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (dconn, priv, 0, REMOTE_PROC_DOMAIN_MIGRATE_FINISH,
              (xdrproc_t) xdr_remote_domain_migrate_finish_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_migrate_finish_ret, (char *) &ret) == -1)
        return NULL;

    ddom = get_nonnull_domain (dconn, ret.ddom);
    xdr_free ((xdrproc_t) &xdr_remote_domain_migrate_finish_ret, (char *) &ret);

    return ddom;
}

static int
remoteListDefinedDomains (virConnectPtr conn, char **const names, int maxnames)
{
    int i;
    remote_list_defined_domains_args args;
    remote_list_defined_domains_ret ret;
    GET_PRIVATE (conn, -1);

    if (maxnames > REMOTE_DOMAIN_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain names: %d > %d"),
                maxnames, REMOTE_DOMAIN_NAME_LIST_MAX);
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_DOMAINS,
              (xdrproc_t) xdr_remote_list_defined_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote domain names: %d > %d"),
                ret.names.names_len, maxnames);
        xdr_free ((xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret);

    return ret.names.names_len;
}

static int
remoteNumOfDefinedDomains (virConnectPtr conn)
{
    remote_num_of_defined_domains_ret ret;
    GET_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_DOMAINS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_domains_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteDomainCreate (virDomainPtr domain)
{
    remote_domain_create_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_CREATE,
              (xdrproc_t) xdr_remote_domain_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static virDomainPtr
remoteDomainDefineXML (virConnectPtr conn, const char *xml)
{
    virDomainPtr dom;
    remote_domain_define_xml_args args;
    remote_domain_define_xml_ret ret;
    GET_PRIVATE (conn, NULL);

    args.xml = (char *) xml;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_DOMAIN_DEFINE_XML,
              (xdrproc_t) xdr_remote_domain_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_define_xml_ret, (char *) &ret) == -1)
        return NULL;

    dom = get_nonnull_domain (conn, ret.dom);
    xdr_free ((xdrproc_t) xdr_remote_domain_define_xml_ret, (char *) &ret);

    return dom;
}

static int
remoteDomainUndefine (virDomainPtr domain)
{
    remote_domain_undefine_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_UNDEFINE,
              (xdrproc_t) xdr_remote_domain_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainAttachDevice (virDomainPtr domain, const char *xml)
{
    remote_domain_attach_device_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_ATTACH_DEVICE,
              (xdrproc_t) xdr_remote_domain_attach_device_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainDetachDevice (virDomainPtr domain, const char *xml)
{
    remote_domain_detach_device_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.xml = (char *) xml;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_DETACH_DEVICE,
              (xdrproc_t) xdr_remote_domain_detach_device_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainGetAutostart (virDomainPtr domain, int *autostart)
{
    remote_domain_get_autostart_args args;
    remote_domain_get_autostart_ret ret;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_domain_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_autostart_ret, (char *) &ret) == -1)
        return -1;

    if (autostart) *autostart = ret.autostart;
    return 0;
}

static int
remoteDomainSetAutostart (virDomainPtr domain, int autostart)
{
    remote_domain_set_autostart_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.autostart = autostart;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_domain_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static char *
remoteDomainGetSchedulerType (virDomainPtr domain, int *nparams)
{
    remote_domain_get_scheduler_type_args args;
    remote_domain_get_scheduler_type_ret ret;
    GET_PRIVATE (domain->conn, NULL);

    make_nonnull_domain (&args.dom, domain);

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SCHEDULER_TYPE,
              (xdrproc_t) xdr_remote_domain_get_scheduler_type_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_scheduler_type_ret, (char *) &ret) == -1)
        return NULL;

    if (nparams) *nparams = ret.nparams;

    /* Caller frees this. */
    return ret.type;
}

static int
remoteDomainGetSchedulerParameters (virDomainPtr domain,
                                    virSchedParameterPtr params, int *nparams)
{
    remote_domain_get_scheduler_parameters_args args;
    remote_domain_get_scheduler_parameters_ret ret;
    int i;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.nparams = *nparams;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_GET_SCHEDULER_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_get_scheduler_parameters_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret) == -1)
        return -1;

    /* Check the length of the returned list carefully. */
    if (ret.params.params_len > REMOTE_DOMAIN_SCHEDULER_PARAMETERS_MAX ||
        ret.params.params_len > *nparams) {
        xdr_free ((xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret);
        error (domain->conn, VIR_ERR_RPC,
               _("remoteDomainGetSchedulerParameters: "
                 "returned number of parameters exceeds limit"));
        return -1;
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
            xdr_free ((xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret);
            error (domain->conn, VIR_ERR_RPC,
                   _("remoteDomainGetSchedulerParameters: "
                     "unknown parameter type"));
            return -1;
        }
    }

    xdr_free ((xdrproc_t) xdr_remote_domain_get_scheduler_parameters_ret, (char *) &ret);
    return 0;
}

static int
remoteDomainSetSchedulerParameters (virDomainPtr domain,
                                    virSchedParameterPtr params, int nparams)
{
    remote_domain_set_scheduler_parameters_args args;
    int i, do_error;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);

    /* Serialise the scheduler parameters. */
    args.params.params_len = nparams;
    args.params.params_val = malloc (sizeof (*args.params.params_val)
                                     * nparams);
    if (args.params.params_val == NULL) {
        error (domain->conn, VIR_ERR_RPC, _("out of memory allocating array"));
        return -1;
    }

    do_error = 0;
    for (i = 0; i < nparams; ++i) {
        // call() will free this:
        args.params.params_val[i].field = strdup (params[i].field);
        if (args.params.params_val[i].field == NULL) {
            error (domain->conn, VIR_ERR_NO_MEMORY, _("out of memory"));
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
        return -1;
    }

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_SET_SCHEDULER_PARAMETERS,
              (xdrproc_t) xdr_remote_domain_set_scheduler_parameters_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainBlockStats (virDomainPtr domain, const char *path,
                        struct _virDomainBlockStats *stats)
{
    remote_domain_block_stats_args args;
    remote_domain_block_stats_ret ret;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_BLOCK_STATS,
              (xdrproc_t) xdr_remote_domain_block_stats_args, (char *) &args,
              (xdrproc_t) xdr_remote_domain_block_stats_ret, (char *) &ret)
        == -1)
        return -1;

    stats->rd_req = ret.rd_req;
    stats->rd_bytes = ret.rd_bytes;
    stats->wr_req = ret.wr_req;
    stats->wr_bytes = ret.wr_bytes;
    stats->errs = ret.errs;

    return 0;
}

static int
remoteDomainInterfaceStats (virDomainPtr domain, const char *path,
                            struct _virDomainInterfaceStats *stats)
{
    remote_domain_interface_stats_args args;
    remote_domain_interface_stats_ret ret;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_INTERFACE_STATS,
              (xdrproc_t) xdr_remote_domain_interface_stats_args,
                (char *) &args,
              (xdrproc_t) xdr_remote_domain_interface_stats_ret,
                (char *) &ret) == -1)
        return -1;

    stats->rx_bytes = ret.rx_bytes;
    stats->rx_packets = ret.rx_packets;
    stats->rx_errs = ret.rx_errs;
    stats->rx_drop = ret.rx_drop;
    stats->tx_bytes = ret.tx_bytes;
    stats->tx_packets = ret.tx_packets;
    stats->tx_errs = ret.tx_errs;
    stats->tx_drop = ret.tx_drop;

    return 0;
}

/*----------------------------------------------------------------------*/

static int
remoteNetworkOpen (virConnectPtr conn,
                   xmlURIPtr uri,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn &&
        conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        conn->networkPrivateData = conn->privateData;
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs.
         */
        struct private_data *priv = calloc (1, sizeof(*priv));
        int ret, rflags = 0;
        if (!priv) {
            error (conn, VIR_ERR_NO_MEMORY, _("struct private_data"));
            return VIR_DRV_OPEN_ERROR;
        }
        if (flags & VIR_CONNECT_RO)
            rflags |= VIR_DRV_OPEN_REMOTE_RO;
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;

        priv->magic = DEAD;
        priv->sock = -1;
        ret = doRemoteOpen(conn, priv, uri, auth, rflags);
        if (ret != VIR_DRV_OPEN_SUCCESS) {
            conn->networkPrivateData = NULL;
            free(priv);
        } else {
            priv->magic = MAGIC;
            priv->localUses = 1;
            conn->networkPrivateData = priv;
        }
        return ret;
    }
}

static int
remoteNetworkClose (virConnectPtr conn)
{
    int ret = 0;
    GET_NETWORK_PRIVATE (conn, -1);
    if (priv->localUses) {
        priv->localUses--;
        if (!priv->localUses) {
            ret = doRemoteClose(conn, priv);
            free(priv);
            conn->networkPrivateData = NULL;
        }
    }
    return ret;
}

static int
remoteNumOfNetworks (virConnectPtr conn)
{
    remote_num_of_networks_ret ret;
    GET_NETWORK_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_NETWORKS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_networks_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteListNetworks (virConnectPtr conn, char **const names, int maxnames)
{
    int i;
    remote_list_networks_args args;
    remote_list_networks_ret ret;
    GET_NETWORK_PRIVATE (conn, -1);

    if (maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                maxnames, REMOTE_NETWORK_NAME_LIST_MAX);
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_NETWORKS,
              (xdrproc_t) xdr_remote_list_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                ret.names.names_len, maxnames);
        xdr_free ((xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret);

    return ret.names.names_len;
}

static int
remoteNumOfDefinedNetworks (virConnectPtr conn)
{
    remote_num_of_defined_networks_ret ret;
    GET_NETWORK_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_NETWORKS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_networks_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteListDefinedNetworks (virConnectPtr conn,
                           char **const names, int maxnames)
{
    int i;
    remote_list_defined_networks_args args;
    remote_list_defined_networks_ret ret;
    GET_NETWORK_PRIVATE (conn, -1);

    if (maxnames > REMOTE_NETWORK_NAME_LIST_MAX) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                maxnames, REMOTE_NETWORK_NAME_LIST_MAX);
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_NETWORKS,
              (xdrproc_t) xdr_remote_list_defined_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        errorf (conn, VIR_ERR_RPC,
                _("too many remote networks: %d > %d"),
                ret.names.names_len, maxnames);
        xdr_free ((xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret);

    return ret.names.names_len;
}

static virNetworkPtr
remoteNetworkLookupByUUID (virConnectPtr conn,
                           const unsigned char *uuid)
{
    virNetworkPtr net;
    remote_network_lookup_by_uuid_args args;
    remote_network_lookup_by_uuid_ret ret;
    GET_NETWORK_PRIVATE (conn, NULL);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_network_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_lookup_by_uuid_ret, (char *) &ret) == -1)
        return NULL;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_lookup_by_uuid_ret, (char *) &ret);

    return net;
}

static virNetworkPtr
remoteNetworkLookupByName (virConnectPtr conn,
                           const char *name)
{
    virNetworkPtr net;
    remote_network_lookup_by_name_args args;
    remote_network_lookup_by_name_ret ret;
    GET_NETWORK_PRIVATE (conn, NULL);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_network_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_lookup_by_name_ret, (char *) &ret) == -1)
        return NULL;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_lookup_by_name_ret, (char *) &ret);

    return net;
}

static virNetworkPtr
remoteNetworkCreateXML (virConnectPtr conn, const char *xmlDesc)
{
    virNetworkPtr net;
    remote_network_create_xml_args args;
    remote_network_create_xml_ret ret;
    GET_NETWORK_PRIVATE (conn, NULL);

    args.xml = (char *) xmlDesc;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_CREATE_XML,
              (xdrproc_t) xdr_remote_network_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_create_xml_ret, (char *) &ret) == -1)
        return NULL;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_create_xml_ret, (char *) &ret);

    return net;
}

static virNetworkPtr
remoteNetworkDefineXML (virConnectPtr conn, const char *xml)
{
    virNetworkPtr net;
    remote_network_define_xml_args args;
    remote_network_define_xml_ret ret;
    GET_NETWORK_PRIVATE (conn, NULL);

    args.xml = (char *) xml;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NETWORK_DEFINE_XML,
              (xdrproc_t) xdr_remote_network_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_define_xml_ret, (char *) &ret) == -1)
        return NULL;

    net = get_nonnull_network (conn, ret.net);
    xdr_free ((xdrproc_t) &xdr_remote_network_define_xml_ret, (char *) &ret);

    return net;
}

static int
remoteNetworkUndefine (virNetworkPtr network)
{
    remote_network_undefine_args args;
    GET_NETWORK_PRIVATE (network->conn, -1);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_UNDEFINE,
              (xdrproc_t) xdr_remote_network_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteNetworkCreate (virNetworkPtr network)
{
    remote_network_create_args args;
    GET_NETWORK_PRIVATE (network->conn, -1);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_CREATE,
              (xdrproc_t) xdr_remote_network_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteNetworkDestroy (virNetworkPtr network)
{
    remote_network_destroy_args args;
    GET_NETWORK_PRIVATE (network->conn, -1);

    make_nonnull_network (&args.net, network);

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_DESTROY,
              (xdrproc_t) xdr_remote_network_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static char *
remoteNetworkDumpXML (virNetworkPtr network, int flags)
{
    remote_network_dump_xml_args args;
    remote_network_dump_xml_ret ret;
    GET_NETWORK_PRIVATE (network->conn, NULL);

    make_nonnull_network (&args.net, network);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_DUMP_XML,
              (xdrproc_t) xdr_remote_network_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_dump_xml_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.xml;
}

static char *
remoteNetworkGetBridgeName (virNetworkPtr network)
{
    remote_network_get_bridge_name_args args;
    remote_network_get_bridge_name_ret ret;
    GET_NETWORK_PRIVATE (network->conn, NULL);

    make_nonnull_network (&args.net, network);

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_GET_BRIDGE_NAME,
              (xdrproc_t) xdr_remote_network_get_bridge_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_get_bridge_name_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.name;
}

static int
remoteNetworkGetAutostart (virNetworkPtr network, int *autostart)
{
    remote_network_get_autostart_args args;
    remote_network_get_autostart_ret ret;
    GET_NETWORK_PRIVATE (network->conn, -1);

    make_nonnull_network (&args.net, network);

    memset (&ret, 0, sizeof ret);
    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_network_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_network_get_autostart_ret, (char *) &ret) == -1)
        return -1;

    if (autostart) *autostart = ret.autostart;

    return 0;
}

static int
remoteNetworkSetAutostart (virNetworkPtr network, int autostart)
{
    remote_network_set_autostart_args args;
    GET_NETWORK_PRIVATE (network->conn, -1);

    make_nonnull_network (&args.net, network);
    args.autostart = autostart;

    if (call (network->conn, priv, 0, REMOTE_PROC_NETWORK_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_network_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}




/*----------------------------------------------------------------------*/

static int
remoteStorageOpen (virConnectPtr conn,
                   xmlURIPtr uri,
                   virConnectAuthPtr auth,
                   int flags)
{
    if (inside_daemon)
        return VIR_DRV_OPEN_DECLINED;

    if (conn &&
        conn->driver &&
        STREQ (conn->driver->name, "remote")) {
        /* If we're here, the remote driver is already
         * in use due to a) a QEMU uri, or b) a remote
         * URI. So we can re-use existing connection
         */
        conn->storagePrivateData = conn->privateData;
        return VIR_DRV_OPEN_SUCCESS;
    } else if (conn->networkDriver &&
               STREQ (conn->networkDriver->name, "remote")) {
        conn->storagePrivateData = conn->networkPrivateData;
        ((struct private_data *)conn->storagePrivateData)->localUses++;
        return VIR_DRV_OPEN_SUCCESS;
    } else {
        /* Using a non-remote driver, so we need to open a
         * new connection for network APIs, forcing it to
         * use the UNIX transport. This handles Xen driver
         * which doesn't have its own impl of the network APIs.
         */
        struct private_data *priv = calloc (1, sizeof(struct private_data));
        int ret, rflags = 0;
        if (!priv) {
            error (NULL, VIR_ERR_NO_MEMORY, _("struct private_data"));
            return VIR_DRV_OPEN_ERROR;
        }
        if (flags & VIR_CONNECT_RO)
            rflags |= VIR_DRV_OPEN_REMOTE_RO;
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;

        priv->magic = DEAD;
        priv->sock = -1;
        ret = doRemoteOpen(conn, priv, uri, auth, rflags);
        if (ret != VIR_DRV_OPEN_SUCCESS) {
            conn->storagePrivateData = NULL;
            free(priv);
        } else {
            priv->magic = MAGIC;
            priv->localUses = 1;
            conn->storagePrivateData = priv;
        }
        return ret;
    }
}

static int
remoteStorageClose (virConnectPtr conn)
{
    int ret = 0;
    GET_STORAGE_PRIVATE (conn, -1);
    if (priv->localUses) {
        priv->localUses--;
        if (!priv->localUses) {
            ret = doRemoteClose(conn, priv);
            free(priv);
            conn->storagePrivateData = NULL;
        }
    }
    return ret;
}

static int
remoteNumOfStoragePools (virConnectPtr conn)
{
    remote_num_of_storage_pools_ret ret;
    GET_STORAGE_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_STORAGE_POOLS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_storage_pools_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteListStoragePools (virConnectPtr conn, char **const names, int maxnames)
{
    int i;
    remote_list_storage_pools_args args;
    remote_list_storage_pools_ret ret;
    GET_STORAGE_PRIVATE (conn, -1);

    if (maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        error (conn, VIR_ERR_RPC, _("too many storage pools requested"));
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, _("too many storage pools received"));
        xdr_free ((xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_list_storage_pools_ret, (char *) &ret);

    return ret.names.names_len;
}

static int
remoteNumOfDefinedStoragePools (virConnectPtr conn)
{
    remote_num_of_defined_storage_pools_ret ret;
    GET_STORAGE_PRIVATE (conn, -1);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_NUM_OF_DEFINED_STORAGE_POOLS,
              (xdrproc_t) xdr_void, (char *) NULL,
              (xdrproc_t) xdr_remote_num_of_defined_storage_pools_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteListDefinedStoragePools (virConnectPtr conn,
                               char **const names, int maxnames)
{
    int i;
    remote_list_defined_storage_pools_args args;
    remote_list_defined_storage_pools_ret ret;
    GET_STORAGE_PRIVATE (conn, -1);

    if (maxnames > REMOTE_STORAGE_POOL_NAME_LIST_MAX) {
        error (conn, VIR_ERR_RPC, _("too many storage pools requested"));
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_STORAGE_POOLS,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, _("too many storage pools received"));
        xdr_free ((xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_list_defined_storage_pools_ret, (char *) &ret);

    return ret.names.names_len;
}

static virStoragePoolPtr
remoteStoragePoolLookupByUUID (virConnectPtr conn,
                               const unsigned char *uuid)
{
    virStoragePoolPtr pool;
    remote_storage_pool_lookup_by_uuid_args args;
    remote_storage_pool_lookup_by_uuid_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    memcpy (args.uuid, uuid, VIR_UUID_BUFLEN);

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_UUID,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_uuid_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_uuid_ret, (char *) &ret) == -1)
        return NULL;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_uuid_ret, (char *) &ret);

    return pool;
}

static virStoragePoolPtr
remoteStoragePoolLookupByName (virConnectPtr conn,
                               const char *name)
{
    virStoragePoolPtr pool;
    remote_storage_pool_lookup_by_name_args args;
    remote_storage_pool_lookup_by_name_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_name_ret, (char *) &ret) == -1)
        return NULL;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_name_ret, (char *) &ret);

    return pool;
}

static virStoragePoolPtr
remoteStoragePoolLookupByVolume (virStorageVolPtr vol)
{
    virStoragePoolPtr pool;
    remote_storage_pool_lookup_by_volume_args args;
    remote_storage_pool_lookup_by_volume_ret ret;
    GET_STORAGE_PRIVATE (vol->conn, NULL);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LOOKUP_BY_VOLUME,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_volume_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_lookup_by_volume_ret, (char *) &ret) == -1)
        return NULL;

    pool = get_nonnull_storage_pool (vol->conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_lookup_by_volume_ret, (char *) &ret);

    return pool;
}


static virStoragePoolPtr
remoteStoragePoolCreateXML (virConnectPtr conn, const char *xmlDesc, unsigned int flags)
{
    virStoragePoolPtr pool;
    remote_storage_pool_create_xml_args args;
    remote_storage_pool_create_xml_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_CREATE_XML,
              (xdrproc_t) xdr_remote_storage_pool_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_create_xml_ret, (char *) &ret) == -1)
        return NULL;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_create_xml_ret, (char *) &ret);

    return pool;
}

static virStoragePoolPtr
remoteStoragePoolDefineXML (virConnectPtr conn, const char *xml, unsigned int flags)
{
    virStoragePoolPtr pool;
    remote_storage_pool_define_xml_args args;
    remote_storage_pool_define_xml_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    args.xml = (char *) xml;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DEFINE_XML,
              (xdrproc_t) xdr_remote_storage_pool_define_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_define_xml_ret, (char *) &ret) == -1)
        return NULL;

    pool = get_nonnull_storage_pool (conn, ret.pool);
    xdr_free ((xdrproc_t) &xdr_remote_storage_pool_define_xml_ret, (char *) &ret);

    return pool;
}

static int
remoteStoragePoolUndefine (virStoragePoolPtr pool)
{
    remote_storage_pool_undefine_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_UNDEFINE,
              (xdrproc_t) xdr_remote_storage_pool_undefine_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolCreate (virStoragePoolPtr pool, unsigned int flags)
{
    remote_storage_pool_create_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_CREATE,
              (xdrproc_t) xdr_remote_storage_pool_create_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolBuild (virStoragePoolPtr pool,
                        unsigned int flags)
{
    remote_storage_pool_build_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_BUILD,
              (xdrproc_t) xdr_remote_storage_pool_build_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolDestroy (virStoragePoolPtr pool)
{
    remote_storage_pool_destroy_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DESTROY,
              (xdrproc_t) xdr_remote_storage_pool_destroy_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolDelete (virStoragePoolPtr pool,
                         unsigned int flags)
{
    remote_storage_pool_delete_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DELETE,
              (xdrproc_t) xdr_remote_storage_pool_delete_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolRefresh (virStoragePoolPtr pool,
                          unsigned int flags)
{
    remote_storage_pool_refresh_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_REFRESH,
              (xdrproc_t) xdr_remote_storage_pool_refresh_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStoragePoolGetInfo (virStoragePoolPtr pool, virStoragePoolInfoPtr info)
{
    remote_storage_pool_get_info_args args;
    remote_storage_pool_get_info_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_GET_INFO,
              (xdrproc_t) xdr_remote_storage_pool_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_get_info_ret, (char *) &ret) == -1)
        return -1;

    info->state = ret.state;
    info->capacity = ret.capacity;
    info->allocation = ret.allocation;
    info->available = ret.available;

    return 0;
}

static char *
remoteStoragePoolDumpXML (virStoragePoolPtr pool,
                          unsigned int flags)
{
    remote_storage_pool_dump_xml_args args;
    remote_storage_pool_dump_xml_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, NULL);

    make_nonnull_storage_pool (&args.pool, pool);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_DUMP_XML,
              (xdrproc_t) xdr_remote_storage_pool_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_dump_xml_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.xml;
}

static int
remoteStoragePoolGetAutostart (virStoragePoolPtr pool, int *autostart)
{
    remote_storage_pool_get_autostart_args args;
    remote_storage_pool_get_autostart_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_GET_AUTOSTART,
              (xdrproc_t) xdr_remote_storage_pool_get_autostart_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_get_autostart_ret, (char *) &ret) == -1)
        return -1;

    if (autostart) *autostart = ret.autostart;

    return 0;
}

static int
remoteStoragePoolSetAutostart (virStoragePoolPtr pool, int autostart)
{
    remote_storage_pool_set_autostart_args args;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool (&args.pool, pool);
    args.autostart = autostart;

    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_SET_AUTOSTART,
              (xdrproc_t) xdr_remote_storage_pool_set_autostart_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}


static int
remoteStoragePoolNumOfVolumes (virStoragePoolPtr pool)
{
    remote_storage_pool_num_of_volumes_args args;
    remote_storage_pool_num_of_volumes_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    make_nonnull_storage_pool(&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_NUM_OF_VOLUMES,
              (xdrproc_t) xdr_remote_storage_pool_num_of_volumes_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_num_of_volumes_ret, (char *) &ret) == -1)
        return -1;

    return ret.num;
}

static int
remoteStoragePoolListVolumes (virStoragePoolPtr pool, char **const names, int maxnames)
{
    int i;
    remote_storage_pool_list_volumes_args args;
    remote_storage_pool_list_volumes_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, -1);

    if (maxnames > REMOTE_STORAGE_VOL_NAME_LIST_MAX) {
        error (pool->conn, VIR_ERR_RPC, _("too many storage volumes requested"));
        return -1;
    }
    args.maxnames = maxnames;
    make_nonnull_storage_pool(&args.pool, pool);

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_POOL_LIST_VOLUMES,
              (xdrproc_t) xdr_remote_storage_pool_list_volumes_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_pool_list_volumes_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (pool->conn, VIR_ERR_RPC, _("too many storage volumes received"));
        xdr_free ((xdrproc_t) xdr_remote_storage_pool_list_volumes_ret, (char *) &ret);
        return -1;
    }

    /* This call is caller-frees (although that isn't clear from
     * the documentation).  However xdr_free will free up both the
     * names and the list of pointers, so we have to strdup the
     * names here.
     */
    for (i = 0; i < ret.names.names_len; ++i)
        names[i] = strdup (ret.names.names_val[i]);

    xdr_free ((xdrproc_t) xdr_remote_storage_pool_list_volumes_ret, (char *) &ret);

    return ret.names.names_len;
}



static virStorageVolPtr
remoteStorageVolLookupByName (virStoragePoolPtr pool,
                              const char *name)
{
    virStorageVolPtr vol;
    remote_storage_vol_lookup_by_name_args args;
    remote_storage_vol_lookup_by_name_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, NULL);

    make_nonnull_storage_pool(&args.pool, pool);
    args.name = (char *) name;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_NAME,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_name_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_name_ret, (char *) &ret) == -1)
        return NULL;

    vol = get_nonnull_storage_vol (pool->conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_name_ret, (char *) &ret);

    return vol;
}

static virStorageVolPtr
remoteStorageVolLookupByKey (virConnectPtr conn,
                             const char *key)
{
    virStorageVolPtr vol;
    remote_storage_vol_lookup_by_key_args args;
    remote_storage_vol_lookup_by_key_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    args.key = (char *) key;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_KEY,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_key_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_key_ret, (char *) &ret) == -1)
        return NULL;

    vol = get_nonnull_storage_vol (conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_key_ret, (char *) &ret);

    return vol;
}

static virStorageVolPtr
remoteStorageVolLookupByPath (virConnectPtr conn,
                              const char *path)
{
    virStorageVolPtr vol;
    remote_storage_vol_lookup_by_path_args args;
    remote_storage_vol_lookup_by_path_ret ret;
    GET_STORAGE_PRIVATE (conn, NULL);

    args.path = (char *) path;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_STORAGE_VOL_LOOKUP_BY_PATH,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_path_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_lookup_by_path_ret, (char *) &ret) == -1)
        return NULL;

    vol = get_nonnull_storage_vol (conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_lookup_by_path_ret, (char *) &ret);

    return vol;
}

static virStorageVolPtr
remoteStorageVolCreateXML (virStoragePoolPtr pool, const char *xmlDesc,
                           unsigned int flags)
{
    virStorageVolPtr vol;
    remote_storage_vol_create_xml_args args;
    remote_storage_vol_create_xml_ret ret;
    GET_STORAGE_PRIVATE (pool->conn, NULL);

    make_nonnull_storage_pool (&args.pool, pool);
    args.xml = (char *) xmlDesc;
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (pool->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_CREATE_XML,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_create_xml_ret, (char *) &ret) == -1)
        return NULL;

    vol = get_nonnull_storage_vol (pool->conn, ret.vol);
    xdr_free ((xdrproc_t) &xdr_remote_storage_vol_create_xml_ret, (char *) &ret);

    return vol;
}

static int
remoteStorageVolDelete (virStorageVolPtr vol,
                        unsigned int flags)
{
    remote_storage_vol_delete_args args;
    GET_STORAGE_PRIVATE (vol->conn, -1);

    make_nonnull_storage_vol (&args.vol, vol);
    args.flags = flags;

    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_DELETE,
              (xdrproc_t) xdr_remote_storage_vol_delete_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteStorageVolGetInfo (virStorageVolPtr vol, virStorageVolInfoPtr info)
{
    remote_storage_vol_get_info_args args;
    remote_storage_vol_get_info_ret ret;
    GET_STORAGE_PRIVATE (vol->conn, -1);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_GET_INFO,
              (xdrproc_t) xdr_remote_storage_vol_get_info_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_get_info_ret, (char *) &ret) == -1)
        return -1;

    info->type = ret.type;
    info->capacity = ret.capacity;
    info->allocation = ret.allocation;

    return 0;
}

static char *
remoteStorageVolDumpXML (virStorageVolPtr vol,
                         unsigned int flags)
{
    remote_storage_vol_dump_xml_args args;
    remote_storage_vol_dump_xml_ret ret;
    GET_STORAGE_PRIVATE (vol->conn, NULL);

    make_nonnull_storage_vol (&args.vol, vol);
    args.flags = flags;

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_DUMP_XML,
              (xdrproc_t) xdr_remote_storage_vol_dump_xml_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_dump_xml_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.xml;
}

static char *
remoteStorageVolGetPath (virStorageVolPtr vol)
{
    remote_storage_vol_get_path_args args;
    remote_storage_vol_get_path_ret ret;
    GET_NETWORK_PRIVATE (vol->conn, NULL);

    make_nonnull_storage_vol (&args.vol, vol);

    memset (&ret, 0, sizeof ret);
    if (call (vol->conn, priv, 0, REMOTE_PROC_STORAGE_VOL_GET_PATH,
              (xdrproc_t) xdr_remote_storage_vol_get_path_args, (char *) &args,
              (xdrproc_t) xdr_remote_storage_vol_get_path_ret, (char *) &ret) == -1)
        return NULL;

    /* Caller frees. */
    return ret.name;
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            free(ret.types.types_val);
            return -1;
        }
        break;
    }
#endif

#if HAVE_POLKIT
    case REMOTE_AUTH_POLKIT:
        if (remoteAuthPolkit(conn, priv, in_open, auth) < 0) {
            free(ret.types.types_val);
            return -1;
        }
        break;
#endif

    case REMOTE_AUTH_NONE:
        /* Nothing todo, hurrah ! */
        break;

    default:
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                         NULL, NULL, NULL, 0, 0,
                         _("unsupported authentication type %d"),
                         ret.types.types_val[0]);
        free(ret.types.types_val);
        return -1;
    }

    free(ret.types.types_val);

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
        __virRaiseError (NULL, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_NO_MEMORY, VIR_ERR_ERROR,
                         NULL, NULL, NULL, 0, 0,
                         _("Cannot resolve address %d: %s"),
                         err, gai_strerror(err));
        return NULL;
    }

    addr = malloc(strlen(host) + 1 + strlen(port) + 1);
    if (!addr) {
        __virRaiseError (NULL, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_NO_MEMORY, VIR_ERR_ERROR,
                         NULL, NULL, NULL, 0, 0,
                         "address");
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
    sasl_callback_t *cbs = calloc(ncredtype+1, sizeof (*cbs));
    int i, n;
    if (!cbs) {
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

    *cred = calloc(ninteract, sizeof(*cred));
    if (!*cred)
        return -1;

    for (ninteract = 0 ; interact[ninteract].id != 0 ; ninteract++) {
        (*cred)[ninteract].type = remoteAuthCredSASL2Vir(interact[ninteract].id);
        if (!(*cred)[ninteract].type) {
            free(*cred);
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
        free(cred[i].result);
    free(cred);
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
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("failed to initialize SASL library: %d (%s)"),
                         err, sasl_errstring(err, NULL, NULL));
        goto cleanup;
    }

    /* Get local address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getsockname(priv->sock, (struct sockaddr*)&sa, &salen) < 0) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("failed to get sock address %d (%s)"),
                         socket_errno (), strerror(socket_errno ()));
        goto cleanup;
    }
    if ((localAddr = addrToString(&sa, salen)) == NULL)
        goto cleanup;

    /* Get remote address in form  IPADDR:PORT */
    salen = sizeof(sa);
    if (getpeername(priv->sock, (struct sockaddr*)&sa, &salen) < 0) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("failed to get peer address %d (%s)"),
                         socket_errno (), strerror(socket_errno ()));
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
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_INTERNAL_ERROR, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             "%s", _("invalid cipher size for TLS session"));
            goto cleanup;
        }
        ssf *= 8; /* key size is bytes, sasl wants bits */

        DEBUG("Setting external SSF %d", ssf);
        err = sasl_setprop(saslconn, SASL_SSF_EXTERNAL, &ssf);
        if (err != SASL_OK) {
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                             NULL, NULL, NULL, 0, 0,
                             _("SASL mechanism %s not supported by server"),
                             wantmech);
            free(iret.mechlist);
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
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("Failed to start SASL negotiation: %d (%s)"),
                         err, sasl_errdetail(saslconn));
        free(iret.mechlist);
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR,
                             NULL, NULL, NULL, 0, 0,
                             "%s", _("Failed to make auth credentials"));
            free(iret.mechlist);
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
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL,
                         0, 0, "%s", msg);
        goto cleanup;
    }
    free(iret.mechlist);

    if (clientoutlen > REMOTE_AUTH_SASL_DATA_MAX) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
                __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
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
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL,
                             0, 0, "%s", msg);
            goto cleanup;
        }

        if (serverin) {
            free(serverin);
            serverin = NULL;
        }
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
            free(serverin);
            break;
        }
    }

    /* Check for suitable SSF if non-TLS */
    if (!priv->uses_tls) {
        err = sasl_getprop(saslconn, SASL_SSF, &val);
        if (err != SASL_OK) {
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("cannot query SASL ssf on connection %d (%s)"),
                             err, sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
        ssf = *(const int *)val;
        DEBUG("SASL SSF value %d", ssf);
        if (ssf < 56) { /* 56 == DES level, good for Kerberos */
            __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                             VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                             _("negotiation SSF %d was not strong enough"), ssf);
            goto cleanup;
        }
    }

    DEBUG0("SASL authentication complete");
    priv->saslconn = saslconn;
    ret = 0;

 cleanup:
    free(localAddr);
    free(remoteAddr);
    free(serverin);

    free(saslcb);
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
                __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                                 VIR_ERR_AUTH_FAILED, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
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

    DEBUG0("PolicyKit authentication complete");
    return 0;
}
#endif /* HAVE_POLKIT */

/*----------------------------------------------------------------------*/

static int really_write (virConnectPtr conn, struct private_data *priv,
                         int in_open, char *bytes, int len);
static int really_read (virConnectPtr conn, struct private_data *priv,
                        int in_open, char *bytes, int len);

/* This function performs a remote procedure call to procedure PROC_NR.
 *
 * NB. This does not free the args structure (not desirable, since you
 * often want this allocated on the stack or else it contains strings
 * which come from the user).  It does however free any intermediate
 * results, eg. the error structure if there is one.
 *
 * NB(2). Make sure to memset (&ret, 0, sizeof ret) before calling,
 * else Bad Things will happen in the XDR code.
 */
static int
call (virConnectPtr conn, struct private_data *priv,
      int flags /* if we are in virConnectOpen */,
      int proc_nr,
      xdrproc_t args_filter, char *args,
      xdrproc_t ret_filter, char *ret)
{
    char buffer[REMOTE_MESSAGE_MAX];
    char buffer2[4];
    struct remote_message_header hdr;
    XDR xdr;
    int len;
    struct remote_error rerror;

    /* Get a unique serial number for this message. */
    int serial = priv->counter++;

    hdr.prog = REMOTE_PROGRAM;
    hdr.vers = REMOTE_PROTOCOL_VERSION;
    hdr.proc = proc_nr;
    hdr.direction = REMOTE_CALL;
    hdr.serial = serial;
    hdr.status = REMOTE_OK;

    /* Serialise header followed by args. */
    xdrmem_create (&xdr, buffer, sizeof buffer, XDR_ENCODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_RPC, _("xdr_remote_message_header failed"));
        return -1;
    }

    if (!(*args_filter) (&xdr, args)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, VIR_ERR_RPC,
               _("marshalling args"));
        return -1;
    }

    /* Get the length stored in buffer. */
    len = xdr_getpos (&xdr);
    xdr_destroy (&xdr);

    /* Length must include the length word itself (always encoded in
     * 4 bytes as per RFC 4506).
     */
    len += 4;

    /* Encode the length word. */
    xdrmem_create (&xdr, buffer2, sizeof buffer2, XDR_ENCODE);
    if (!xdr_int (&xdr, &len)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, VIR_ERR_RPC,
               _("xdr_int (length word)"));
        return -1;
    }
    xdr_destroy (&xdr);

    /* Send length word followed by header+args. */
    if (really_write (conn, priv, flags & REMOTE_CALL_IN_OPEN, buffer2, sizeof buffer2) == -1 ||
        really_write (conn, priv, flags & REMOTE_CALL_IN_OPEN, buffer, len-4) == -1)
        return -1;

    /* Read and deserialise length word. */
    if (really_read (conn, priv, flags & REMOTE_CALL_IN_OPEN, buffer2, sizeof buffer2) == -1)
        return -1;

    xdrmem_create (&xdr, buffer2, sizeof buffer2, XDR_DECODE);
    if (!xdr_int (&xdr, &len)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_RPC, _("xdr_int (length word, reply)"));
        return -1;
    }
    xdr_destroy (&xdr);

    /* Length includes length word - adjust to real length to read. */
    len -= 4;

    if (len < 0 || len > REMOTE_MESSAGE_MAX) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_RPC, _("packet received from server too large"));
        return -1;
    }

    /* Read reply header and what follows (either a ret or an error). */
    if (really_read (conn, priv, flags & REMOTE_CALL_IN_OPEN, buffer, len) == -1)
        return -1;

    /* Deserialise reply header. */
    xdrmem_create (&xdr, buffer, len, XDR_DECODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
               VIR_ERR_RPC, _("invalid header in reply"));
        return -1;
    }

    /* Check program, version, etc. are what we expect. */
    if (hdr.prog != REMOTE_PROGRAM) {
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                         NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown program (received %x, expected %x)"),
                         hdr.prog, REMOTE_PROGRAM);
        return -1;
    }
    if (hdr.vers != REMOTE_PROTOCOL_VERSION) {
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                         NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown protocol version (received %x, expected %x)"),
                         hdr.vers, REMOTE_PROTOCOL_VERSION);
        return -1;
    }

    /* If we extend the server to actually send asynchronous messages, then
     * we'll need to change this so that it can recognise an asynch
     * message being received at this point.
     */
    if (hdr.proc != proc_nr) {
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                         NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown procedure (received %x, expected %x)"),
                         hdr.proc, proc_nr);
        return -1;
    }
    if (hdr.direction != REMOTE_REPLY) {
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                         NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown direction (received %x, expected %x)"),
                         hdr.direction, REMOTE_REPLY);
        return -1;
    }
    if (hdr.serial != serial) {
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown serial (received %x, expected %x)"),
                         hdr.serial, serial);
        return -1;
    }

    /* Status is either REMOTE_OK (meaning that what follows is a ret
     * structure), or REMOTE_ERROR (and what follows is a remote_error
     * structure).
     */
    switch (hdr.status) {
    case REMOTE_OK:
        if (!(*ret_filter) (&xdr, ret)) {
            error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, VIR_ERR_RPC,
                   _("unmarshalling ret"));
            return -1;
        }
        xdr_destroy (&xdr);
        return 0;

    case REMOTE_ERROR:
        memset (&rerror, 0, sizeof rerror);
        if (!xdr_remote_error (&xdr, &rerror)) {
            error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn,
                   VIR_ERR_RPC, _("unmarshalling remote_error"));
            return -1;
        }
        xdr_destroy (&xdr);
        /* See if caller asked us to keep quiet about missing RPCs
         * eg for interop with older servers */
        if (flags & REMOTE_CALL_QUIET_MISSING_RPC &&
            rerror.domain == VIR_FROM_REMOTE &&
            rerror.code == VIR_ERR_RPC &&
            rerror.level == VIR_ERR_ERROR &&
            STREQLEN(*rerror.message, "unknown procedure", 17)) {
            return -2;
        }
        server_error (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, &rerror);
        xdr_free ((xdrproc_t) xdr_remote_error, (char *) &rerror);
        return -1;

    default:
        __virRaiseError (flags & REMOTE_CALL_IN_OPEN ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         _("unknown status (received %x)"),
                         hdr.status);
        xdr_destroy (&xdr);
        return -1;
    }
}

static int
really_write_buf (virConnectPtr conn, struct private_data *priv,
                  int in_open /* if we are in virConnectOpen */,
                  const char *bytes, int len)
{
    const char *p;
    int err;

    p = bytes;
    if (priv->uses_tls) {
        do {
            err = gnutls_record_send (priv->session, p, len);
            if (err < 0) {
                if (err == GNUTLS_E_INTERRUPTED || err == GNUTLS_E_AGAIN)
                    continue;
                error (in_open ? NULL : conn,
                       VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
                return -1;
            }
            len -= err;
            p += err;
        }
        while (len > 0);
    } else {
        do {
            err = send (priv->sock, p, len, 0);
            if (err == -1) {
                int errno_ = socket_errno ();
                if (errno_ == EINTR || errno_ == EAGAIN)
                    continue;
                error (in_open ? NULL : conn,
                       VIR_ERR_SYSTEM_ERROR, strerror (errno_));
                return -1;
            }
            len -= err;
            p += err;
        }
        while (len > 0);
    }

    return 0;
}

static int
really_write_plain (virConnectPtr conn, struct private_data *priv,
                    int in_open /* if we are in virConnectOpen */,
                    char *bytes, int len)
{
    return really_write_buf(conn, priv, in_open, bytes, len);
}

#if HAVE_SASL
static int
really_write_sasl (virConnectPtr conn, struct private_data *priv,
              int in_open /* if we are in virConnectOpen */,
              char *bytes, int len)
{
    const char *output;
    unsigned int outputlen;
    int err;

    err = sasl_encode(priv->saslconn, bytes, len, &output, &outputlen);
    if (err != SASL_OK) {
        return -1;
    }

    return really_write_buf(conn, priv, in_open, output, outputlen);
}
#endif

static int
really_write (virConnectPtr conn, struct private_data *priv,
              int in_open /* if we are in virConnectOpen */,
              char *bytes, int len)
{
#if HAVE_SASL
    if (priv->saslconn)
        return really_write_sasl(conn, priv, in_open, bytes, len);
    else
#endif
        return really_write_plain(conn, priv, in_open, bytes, len);
}

static int
really_read_buf (virConnectPtr conn, struct private_data *priv,
                 int in_open /* if we are in virConnectOpen */,
                 char *bytes, int len)
{
    int err;

    if (priv->uses_tls) {
    tlsreread:
        err = gnutls_record_recv (priv->session, bytes, len);
        if (err < 0) {
            if (err == GNUTLS_E_INTERRUPTED)
                goto tlsreread;
            error (in_open ? NULL : conn,
                   VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
            return -1;
        }
        if (err == 0) {
            error (in_open ? NULL : conn,
                   VIR_ERR_RPC, _("socket closed unexpectedly"));
            return -1;
        }
        return err;
    } else {
    reread:
        err = recv (priv->sock, bytes, len, 0);
        if (err == -1) {
            int errno_ = socket_errno ();
            if (errno_ == EINTR)
                goto reread;
            error (in_open ? NULL : conn,
                   VIR_ERR_SYSTEM_ERROR, strerror (errno_));
            return -1;
        }
        if (err == 0) {
            error (in_open ? NULL : conn,
                   VIR_ERR_RPC, _("socket closed unexpectedly"));
            return -1;
        }
        return err;
    }

    return 0;
}

static int
really_read_plain (virConnectPtr conn, struct private_data *priv,
                   int in_open /* if we are in virConnectOpen */,
                   char *bytes, int len)
{
    do {
        int ret = really_read_buf (conn, priv, in_open, bytes, len);
        if (ret < 0)
            return -1;

        len -= ret;
        bytes += ret;
    } while (len > 0);

    return 0;
}

#if HAVE_SASL
static int
really_read_sasl (virConnectPtr conn, struct private_data *priv,
                  int in_open /* if we are in virConnectOpen */,
                  char *bytes, int len)
{
    do {
        int want, got;
        if (priv->saslDecoded == NULL) {
            char encoded[8192];
            int encodedLen = sizeof(encoded);
            int err, ret;
            ret = really_read_buf (conn, priv, in_open, encoded, encodedLen);
            if (ret < 0)
                return -1;

            err = sasl_decode(priv->saslconn, encoded, ret,
                              &priv->saslDecoded, &priv->saslDecodedLength);
        }

        got = priv->saslDecodedLength - priv->saslDecodedOffset;
        want = len;
        if (want > got)
            want = got;

        memcpy(bytes, priv->saslDecoded + priv->saslDecodedOffset, want);
        priv->saslDecodedOffset += want;
        if (priv->saslDecodedOffset == priv->saslDecodedLength) {
            priv->saslDecoded = NULL;
            priv->saslDecodedOffset = priv->saslDecodedLength = 0;
        }
        bytes += want;
        len -= want;
    } while (len > 0);

    return 0;
}
#endif

static int
really_read (virConnectPtr conn, struct private_data *priv,
             int in_open /* if we are in virConnectOpen */,
             char *bytes, int len)
{
#if HAVE_SASL
    if (priv->saslconn)
        return really_read_sasl (conn, priv, in_open, bytes, len);
    else
#endif
        return really_read_plain (conn, priv, in_open, bytes, len);
}

/* For errors internal to this library. */
static void
error (virConnectPtr conn, virErrorNumber code, const char *info)
{
    const char *errmsg;

    errmsg = __virErrorMsg (code, info);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
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

    errmsg = __virErrorMsg (code, errorMessage);
    __virRaiseError (conn, NULL, NULL, VIR_FROM_REMOTE,
                     code, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                     "%s", errmsg);
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

    __virRaiseError (conn, dom, net,
                     err->domain, err->code, err->level,
                     err->str1 ? *err->str1 : NULL,
                     err->str2 ? *err->str2 : NULL,
                     err->str3 ? *err->str3 : NULL,
                     err->int1, err->int2,
                     "%s", err->message ? *err->message : NULL);
}

/* get_nonnull_domain and get_nonnull_network turn an on-wire
 * (name, uuid) pair into virDomainPtr or virNetworkPtr object.
 * These can return NULL if underlying memory allocations fail,
 * but if they do then virterror has been set.
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

static virDriver driver = {
    .no = VIR_DRV_REMOTE,
    .name = "remote",
    .ver = REMOTE_PROTOCOL_VERSION,
    .probe = NULL,
    .open = remoteOpen,
    .close = remoteClose,
    .supports_feature = remoteSupportsFeature,
	.type = remoteType,
	.version = remoteVersion,
    .getHostname = remoteGetHostname,
	.getMaxVcpus = remoteGetMaxVcpus,
	.nodeGetInfo = remoteNodeGetInfo,
    .getCapabilities = remoteGetCapabilities,
    .listDomains = remoteListDomains,
    .numOfDomains = remoteNumOfDomains,
    .domainCreateLinux = remoteDomainCreateLinux,
    .domainLookupByID = remoteDomainLookupByID,
    .domainLookupByUUID = remoteDomainLookupByUUID,
    .domainLookupByName = remoteDomainLookupByName,
    .domainSuspend = remoteDomainSuspend,
    .domainResume = remoteDomainResume,
    .domainShutdown = remoteDomainShutdown,
    .domainReboot = remoteDomainReboot,
    .domainDestroy = remoteDomainDestroy,
    .domainGetOSType = remoteDomainGetOSType,
    .domainGetMaxMemory = remoteDomainGetMaxMemory,
    .domainSetMaxMemory = remoteDomainSetMaxMemory,
    .domainSetMemory = remoteDomainSetMemory,
    .domainGetInfo = remoteDomainGetInfo,
    .domainSave = remoteDomainSave,
    .domainRestore = remoteDomainRestore,
    .domainCoreDump = remoteDomainCoreDump,
    .domainSetVcpus = remoteDomainSetVcpus,
    .domainPinVcpu = remoteDomainPinVcpu,
    .domainGetVcpus = remoteDomainGetVcpus,
    .domainGetMaxVcpus = remoteDomainGetMaxVcpus,
    .domainDumpXML = remoteDomainDumpXML,
    .listDefinedDomains = remoteListDefinedDomains,
    .numOfDefinedDomains = remoteNumOfDefinedDomains,
    .domainCreate = remoteDomainCreate,
    .domainDefineXML = remoteDomainDefineXML,
    .domainUndefine = remoteDomainUndefine,
    .domainAttachDevice = remoteDomainAttachDevice,
    .domainDetachDevice = remoteDomainDetachDevice,
    .domainGetAutostart = remoteDomainGetAutostart,
    .domainSetAutostart = remoteDomainSetAutostart,
    .domainGetSchedulerType = remoteDomainGetSchedulerType,
    .domainGetSchedulerParameters = remoteDomainGetSchedulerParameters,
    .domainSetSchedulerParameters = remoteDomainSetSchedulerParameters,
    .domainMigratePrepare = remoteDomainMigratePrepare,
    .domainMigratePerform = remoteDomainMigratePerform,
    .domainMigrateFinish = remoteDomainMigrateFinish,
    .domainBlockStats = remoteDomainBlockStats,
    .domainInterfaceStats = remoteDomainInterfaceStats,
    .nodeGetCellsFreeMemory = NULL,
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
    .poolLookupByUUID = remoteStoragePoolLookupByUUID,
    .poolLookupByName = remoteStoragePoolLookupByName,
    .poolLookupByVolume = remoteStoragePoolLookupByVolume,
    .poolCreateXML = remoteStoragePoolCreateXML,
    .poolDefineXML = remoteStoragePoolDefineXML,
    .poolUndefine = remoteStoragePoolUndefine,
    .poolCreate = remoteStoragePoolCreate,
    .poolBuild = remoteStoragePoolBuild,
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

static virStateDriver state_driver = {
    remoteStartup,
    NULL,
    NULL,
    NULL,
};


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
    if (virRegisterStateDriver (&state_driver) == -1) return -1;

    return 0;
}

/*
 * vim: set tabstop=4:
 * vim: set shiftwidth=4:
 * vim: set expandtab:
 */
/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
