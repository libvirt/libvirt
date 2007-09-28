/*
 * remote_internal.c: driver to provide access to libvirtd running
 *   on a remote machine
 *
 * Copyright (C) 2007 Red Hat, Inc.
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

#define _GNU_SOURCE /* for asprintf */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <paths.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pwd.h>

#include <rpc/xdr.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "gnutls_1_0_compat.h"
#include <libxml/uri.h>

#include "internal.h"
#include "driver.h"
#include "remote_internal.h"
#include "remote_protocol.h"

#define DEBUG 0                 /* Enable verbose messages on stderr. */

/* Per-connection private data. */
#define MAGIC 999               /* private_data->magic if OK */
#define DEAD 998                /* private_data->magic if dead/closed */

struct private_data {
    int magic;                  /* Should be MAGIC or DEAD. */
    int sock;                   /* Socket. */
    pid_t pid;                  /* PID of tunnel process */
    int uses_tls;               /* TLS enabled on socket? */
    gnutls_session_t session;   /* GnuTLS session (if uses_tls != 0). */
    char *type;                 /* Cached return from remoteType. */
    int counter;                /* Generates serial numbers for RPC. */
    char *uri;                  /* Original (remote) URI. */
    int networkOnly;            /* Only used for network API */
};

#define GET_PRIVATE(conn,retcode)                                       \
    struct private_data *priv = (struct private_data *) (conn)->privateData; \
    if (!priv || priv->magic != MAGIC) {                                \
        error (conn, VIR_ERR_INVALID_ARG,                               \
               "tried to use a closed or uninitialised handle");        \
        return (retcode);                                               \
    }

#define GET_NETWORK_PRIVATE(conn,retcode)                               \
    struct private_data *priv = (struct private_data *) (conn)->networkPrivateData; \
    if (!priv || priv->magic != MAGIC) {                                \
        error (conn, VIR_ERR_INVALID_ARG,                               \
               "tried to use a closed or uninitialised handle");        \
        return (retcode);                                               \
    }

static int call (virConnectPtr conn, struct private_data *priv, int in_open, int proc_nr, xdrproc_t args_filter, char *args, xdrproc_t ret_filter, char *ret);
static void error (virConnectPtr conn, virErrorNumber code, const char *info);
static void server_error (virConnectPtr conn, remote_error *err);
static virDomainPtr get_nonnull_domain (virConnectPtr conn, remote_nonnull_domain domain);
static virNetworkPtr get_nonnull_network (virConnectPtr conn, remote_nonnull_network network);
static void make_nonnull_domain (remote_nonnull_domain *dom_dst, virDomainPtr dom_src);
static void make_nonnull_network (remote_nonnull_network *net_dst, virNetworkPtr net_src);

/*----------------------------------------------------------------------*/

/* Helper functions for remoteOpen. */
static char *get_transport_from_scheme (char *scheme);

/* Parse query string. */
struct query_fields {
    struct query_fields *next;	/* Linked list chain. */
    char *name;			/* Field name (unescaped). */
    char *value;		/* Field value (unescaped). */
    int ignore;			/* Ignore field in query_create. */
};

static int query_parse (const char *query,
                        const char *separator,
                        struct query_fields * *fields_out);
static int query_create (const struct query_fields *fields,
                         const char *separator,
                         char **query_out);
static void query_free (struct query_fields *fields);

/* GnuTLS functions used by remoteOpen. */
static int initialise_gnutls (virConnectPtr conn);
static gnutls_session_t negotiate_gnutls_on_connection (virConnectPtr conn, int sock, int no_verify, const char *hostname);

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
    int ret, pid, status;

    if (!daemonPath) {
        error(conn, VIR_ERR_INTERNAL_ERROR, "failed to find libvirtd binary");
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


/* Must not overlap with virDrvOpenFlags */
enum virDrvOpenRemoteFlags {
    VIR_DRV_OPEN_REMOTE_RO = (1 << 0),
    VIR_DRV_OPEN_REMOTE_UNIX = (1 << 1),
    VIR_DRV_OPEN_REMOTE_USER = (1 << 2),
    VIR_DRV_OPEN_REMOTE_AUTOSTART = (1 << 3),
};

static int
doRemoteOpen (virConnectPtr conn, struct private_data *priv, const char *uri_str, int flags)
{
    if (!uri_str) return VIR_DRV_OPEN_DECLINED;

    /* We have to parse the URL every time to discover whether
     * it contains a transport or remote server name.  There's no
     * way to get around this.
     */
    xmlURIPtr uri = xmlParseURI (uri_str);
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
        error (NULL, VIR_ERR_INVALID_ARG,
               "remote_open: transport in URL not recognised "
               "(should be tls|unix|ssh|ext|tcp)");
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
    char *server = 0, *port = 0;
    int no_verify = 0, no_tty = 0;
    char **cmd_argv = 0;

    /* Return code from this function, and the private data. */
    int retcode = VIR_DRV_OPEN_ERROR;

    /* Remote server defaults to "localhost" if not specified. */
    server = strdup (uri->server ? uri->server : "localhost");
    if (!server) {
    out_of_memory:
        error (NULL, VIR_ERR_NO_MEMORY, "duplicating server name");
        goto failed;
    }
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

    if (uri->user) {
        username = strdup (uri->user);
        if (!username) goto out_of_memory;
    }

    /* Get the variables from the query string.
     * Then we need to reconstruct the query string (because
     * feasibly it might contain variables needed by the real driver,
     * although that won't be the case for now).
     */
    struct query_fields *vars, *var;
    char *query;
#ifdef HAVE_XMLURI_QUERY_RAW
    query = uri->query_raw;
#else
    query = uri->query;
#endif
    if (query_parse (query, NULL, &vars) != 0) goto failed;

    for (var = vars; var; var = var->next) {
        if (strcasecmp (var->name, "name") == 0) {
            name = strdup (var->value);
            if (!name) goto out_of_memory;
            var->ignore = 1;
        } else if (strcasecmp (var->name, "command") == 0) {
            command = strdup (var->value);
            if (!command) goto out_of_memory;
            var->ignore = 1;
        } else if (strcasecmp (var->name, "socket") == 0) {
            sockname = strdup (var->value);
            if (!sockname) goto out_of_memory;
            var->ignore = 1;
        } else if (strcasecmp (var->name, "netcat") == 0) {
            netcat = strdup (var->value);
            if (!netcat) goto out_of_memory;
            var->ignore = 1;
        } else if (strcasecmp (var->name, "no_verify") == 0) {
            no_verify = atoi (var->value);
            var->ignore = 1;
        } else if (strcasecmp (var->name, "no_tty") == 0) {
            no_tty = atoi (var->value);
            var->ignore = 1;
        }
#if DEBUG
        else
            fprintf (stderr,
                     "remoteOpen: "
                     "passing through variable '%s' to remote end\n",
                     var->name);
#endif
    }

#ifdef HAVE_XMLURI_QUERY_RAW
    if (uri->query_raw) xmlFree (uri->query_raw);
#else
    if (uri->query) xmlFree (uri->query);
#endif

    if (query_create (vars, NULL,
#ifdef HAVE_XMLURI_QUERY_RAW
                      &uri->query_raw
#else
                      &uri->query
#endif
                      ) != 0) goto failed;
    query_free (vars);

    /* For ext transport, command is required. */
    if (transport == trans_ext && !command) {
        error (NULL, VIR_ERR_INVALID_ARG, "remote_open: for 'ext' transport, command is required");
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
#if DEBUG
    fprintf (stderr, "remoteOpen: proceeding with name = %s\n", name);
#endif

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
        int e = getaddrinfo (server, port, &hints, &res);
        if (e != 0) {
            error (NULL, VIR_ERR_INVALID_ARG, gai_strerror (e));
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
                error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                continue;
            }

            /* Disable Nagle - Dan Berrange. */
            setsockopt (priv->sock,
                        IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                        sizeof no_slow_start);

            if (connect (priv->sock, r->ai_addr, r->ai_addrlen) == -1) {
                error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                close (priv->sock);
                continue;
            }

            if (priv->uses_tls) {
                priv->session =
                    negotiate_gnutls_on_connection
                      (conn, priv->sock, no_verify, server);
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

    case trans_unix: {
        if (!sockname) {
            if (flags & VIR_DRV_OPEN_REMOTE_USER) {
                struct passwd *pw;
                uid_t uid = getuid();
 
                if (!(pw = getpwuid(uid))) {
                    error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }
 
                if (asprintf (&sockname, "@%s" LIBVIRTD_USER_UNIX_SOCKET, pw->pw_dir) < 0) {
                    error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
                    goto failed;
                }
            } else {
                if (flags & VIR_DRV_OPEN_REMOTE_RO)
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET_RO);
                else
                    sockname = strdup (LIBVIRTD_PRIV_UNIX_SOCKET);
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
            error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
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
            error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        break;
    }

    case trans_ssh: {
        int j, nr_args = 8;

        if (username) nr_args += 2; /* For -l username */
        if (no_tty) nr_args += 5;   /* For -T -o BatchMode=yes -e none */

        command = command ? : strdup ("ssh");

        // Generate the final command argv[] array.
        //   ssh -p $port [-l $username] $hostname $netcat -U $sockname [NULL]
        cmd_argv = malloc (nr_args * sizeof (char *));
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
        cmd_argv[j++] = strdup (server);
        cmd_argv[j++] = strdup (netcat ? netcat : "nc");
        cmd_argv[j++] = strdup ("-U");
        cmd_argv[j++] = strdup (sockname ? sockname : LIBVIRTD_PRIV_UNIX_SOCKET);
        cmd_argv[j++] = 0;
        assert (j == nr_args);
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
            error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
            goto failed;
        }

        pid = fork ();
        if (pid == -1) {
            error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
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
                cmd_argv = malloc (2 * sizeof (char *));
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
    } /* switch (transport) */

    /* Finally we can call the remote side's open function. */
    remote_open_args args = { &name, flags };

    if (call (conn, priv, 1, REMOTE_PROC_OPEN,
              (xdrproc_t) xdr_remote_open_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        goto failed;

    /* Duplicate and save the uri_str. */
    priv->uri = strdup (uri_str);
    if (!priv->uri) {
        error (NULL, VIR_ERR_NO_MEMORY, "allocating priv->uri");
        goto failed;
    }

    /* Successful. */
    retcode = VIR_DRV_OPEN_SUCCESS;

    /*FALLTHROUGH*/
 failed:
    /* Close the socket if we failed. */
    if (retcode != VIR_DRV_OPEN_SUCCESS && priv->sock >= 0) {
        if (priv->uses_tls && priv->session)
            gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
        close (priv->sock);
        if (priv->pid > 0) {
            pid_t reap;
            do {
                reap = waitpid(priv->pid, NULL, 0);
                if (reap == -1 && errno == EINTR)
                    continue;
            } while (reap != -1 && reap != priv->pid);
        }
    }

    /* Free up the URL and strings. */
    xmlFreeURI (uri);
    if (name) free (name);
    if (command) free (command);
    if (sockname) free (sockname);
    if (netcat) free (netcat);
    if (username) free (username);
    if (server) free (server);
    if (port) free (port);
    if (cmd_argv) {
        char **cmd_argv_ptr = cmd_argv;
        while (*cmd_argv_ptr) {
            free (*cmd_argv_ptr);
            cmd_argv_ptr++;
        }
        free (cmd_argv);
    }

    return retcode;
}

static int
remoteOpen (virConnectPtr conn, const char *uri_str, int flags)
{
    struct private_data *priv = malloc (sizeof(struct private_data));
    int ret, rflags = 0;

    if (!priv) {
        error (NULL, VIR_ERR_NO_MEMORY, "struct private_data");
        return VIR_DRV_OPEN_ERROR;
    }

    if (flags & VIR_DRV_OPEN_RO)
        rflags |= VIR_DRV_OPEN_REMOTE_RO;

    if (uri_str) {
        if (STREQ (uri_str, "qemu:///system")) {
            rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
        } else if (STREQ (uri_str, "qemu:///session")) {
            rflags |= VIR_DRV_OPEN_REMOTE_UNIX;
            if (getuid() > 0) {
                rflags |= VIR_DRV_OPEN_REMOTE_USER;
                rflags |= VIR_DRV_OPEN_REMOTE_AUTOSTART;
            }
        }
    }

    memset(priv, 0, sizeof(struct private_data));
    priv->magic = DEAD;
    priv->sock = -1;
    ret = doRemoteOpen(conn, priv, uri_str, rflags);
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

static int
query_create (const struct query_fields *fields,
              const char *separator,
              char **query_out)
{
    /* List of characters which are safe inside names or values,
     * apart from '@', IS_MARK and IS_ALPHANUM.  Best to escape
     * as much as possible.  Certainly '=', '&' and '#' must NEVER
     * be added to this list.
     */
    static const xmlChar *special_chars = BAD_CAST "";

    int append_sep = 0, sep_len;
    xmlBufferPtr buf;
    xmlChar *str;
    int rv;

    if (query_out) *query_out = NULL;
    if (!fields) return 0;

    if (separator == NULL) {
	separator = "&";
	sep_len = 1;
    } else
	sep_len = xmlStrlen (BAD_CAST separator);

    buf = xmlBufferCreate ();
    if (!buf) return -1;

    rv = 0;
    while (fields) {
	if (!fields->ignore) {
	    if (append_sep) {
		rv = xmlBufferAdd (buf, BAD_CAST separator, sep_len);
		if (rv != 0) goto error;
	    }
	    append_sep = 1;

	    str = xmlURIEscapeStr (BAD_CAST fields->name, special_chars);
	    if (!str) { rv = XML_ERR_NO_MEMORY; goto error; }
	    rv = xmlBufferAdd (buf, str, xmlStrlen (str));
	    xmlFree (str);
	    if (rv != 0) goto error;

	    rv = xmlBufferAdd (buf, BAD_CAST "=", 1);
	    if (rv != 0) goto error;
	    str = xmlURIEscapeStr (BAD_CAST fields->value, special_chars);
	    if (!str) { rv = XML_ERR_NO_MEMORY; goto error; }
	    rv = xmlBufferAdd (buf, str, xmlStrlen (str));
	    xmlFree (str);
	    if (rv != 0) goto error;
	}

	fields = fields->next;
    }

    if (query_out && buf->content) {
	*query_out = (char *) xmlStrdup (buf->content);
	if (!*query_out) {
	    rv = XML_ERR_NO_MEMORY;
	    goto error;
	}
    }

 error:
    if (buf)
	xmlBufferFree (buf);
    return rv;
}

static int
query_parse (const char *query_,
             const char *separator,
             struct query_fields * *fields_out)
{
    struct query_fields *fields, *field, **prev;
    int sep_len;
    const xmlChar *query = BAD_CAST query_, *end, *eq;
    char *name, *value;

    if (fields_out) *fields_out = NULL;
    if (!query || query[0] == '\0') return 0;

    if (separator == NULL) {
	separator = "&";
	sep_len = 1;
    } else
	sep_len = xmlStrlen (BAD_CAST separator);

    fields = NULL;
    prev = &fields;

    while (*query) {
	/* Find the next separator, or end of the string. */
	end = xmlStrstr (query, BAD_CAST separator);
	if (!end) end = query + xmlStrlen (query);

	/* Find the first '=' character between here and end. */
	eq = xmlStrchr (query, '=');
	if (eq && eq >= end) eq = NULL;

	/* Empty section (eg. "?&"). */
	if (end == query)
	    goto next;
	/* If there is no '=' character, then we have just "name"
	 * and consistent with CGI.pm we assume value is "".
	 */
	else if (!eq) {
	    name = xmlURIUnescapeString ((const char *) query,
					 end - query, NULL);
	    value = (char *) xmlStrdup (BAD_CAST "");
	    if (!name || !value) goto out_of_memory;
	}
	/* Or if we have "name=" here (works around annoying
	 * problem when calling xmlURIUnescapeString with len = 0).
	 */
	else if (eq+1 == end) {
	    name = xmlURIUnescapeString ((const char *) query,
					 eq - query, NULL);
	    value = (char *) xmlStrdup (BAD_CAST "");
	    if (!name || !value) goto out_of_memory;
	}
	/* If the '=' character is at the beginning then we have
	 * "=value" and consistent with CGI.pm we _ignore_ this.
	 */
	else if (query == eq)
	    goto next;
	/* Otherwise it's "name=value". */
	else {
	    name = xmlURIUnescapeString ((const char *) query,
					 eq - query, NULL);
	    value = xmlURIUnescapeString ((const char *) eq+1,
					  end - (eq+1), NULL);
	    if (!name || !value) goto out_of_memory;
	}

	/* Allocate this field and append to the list. */
	field = xmlMalloc (sizeof *field);
	if (!field) goto out_of_memory;
	field->next = NULL;
	field->name = name;
	field->value = value;
	field->ignore = 0;
	*prev = field;
	prev = &field->next;

    next:
	query = end;
	if (*query) query += sep_len; /* skip separator */
    }

    if (fields_out) *fields_out = fields;
    return 0;

 out_of_memory:
    query_free (fields);
    return XML_ERR_NO_MEMORY;
}

static void
query_free (struct query_fields *fields)
{
    struct query_fields *t;

    while (fields) {
        if (fields->name) xmlFree (fields->name);
        if (fields->value) xmlFree (fields->value);
        t = fields;
        fields = fields->next;
        xmlFree (t);
    }
}

/* GnuTLS functions used by remoteOpen. */
static gnutls_certificate_credentials_t x509_cred;


static int
check_cert_file (const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        __virRaiseError (NULL, NULL, NULL, VIR_FROM_REMOTE, VIR_ERR_RPC,
                         VIR_ERR_ERROR, LIBVIRT_CACERT, NULL, NULL, 0, 0,
                         "Cannot access %s '%s': %s (%d)",
                         type, file, strerror(errno), errno);
        return -1;
    }
    return 0;
}


static int
initialise_gnutls (virConnectPtr conn ATTRIBUTE_UNUSED)
{
    static int initialised = 0;
    int err;

    if (initialised) return 0;

    gnutls_global_init ();

    /* X509 stuff */
    err = gnutls_certificate_allocate_credentials (&x509_cred);
    if (err) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return -1;
    }


    if (check_cert_file("CA certificate", LIBVIRT_CACERT) < 0)
        return -1;
    if (check_cert_file("client key", LIBVIRT_CLIENTKEY) < 0)
        return -1;
    if (check_cert_file("client certificate", LIBVIRT_CLIENTCERT) < 0)
        return -1;

    /* Set the trusted CA cert. */
#if DEBUG
    fprintf (stderr, "loading CA file %s\n", LIBVIRT_CACERT);
#endif
    err =
        gnutls_certificate_set_x509_trust_file (x509_cred, LIBVIRT_CACERT,
                                                GNUTLS_X509_FMT_PEM);
    if (err < 0) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return -1;
    }

    /* Set the client certificate and private key. */
#if DEBUG
    fprintf (stderr, "loading client cert and key from files %s and %s\n",
             LIBVIRT_CLIENTCERT, LIBVIRT_CLIENTKEY);
#endif
    err =
        gnutls_certificate_set_x509_key_file (x509_cred,
                                              LIBVIRT_CLIENTCERT,
                                              LIBVIRT_CLIENTKEY,
                                              GNUTLS_X509_FMT_PEM);
    if (err < 0) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return -1;
    }

    initialised = 1;
    return 0;
}

static int verify_certificate (virConnectPtr conn, gnutls_session_t session, const char *hostname);

static gnutls_session_t
negotiate_gnutls_on_connection (virConnectPtr conn,
                                int sock, int no_verify, const char *hostname)
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
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    /* Use default priorities */
    err = gnutls_set_default_priority (session);
    if (err) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }
    err =
        gnutls_certificate_type_set_priority (session,
                                              cert_type_priority);
    if (err) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    /* put the x509 credentials to the current session
     */
    err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
    if (err) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    gnutls_transport_set_ptr (session,
                              (gnutls_transport_ptr_t) (long) sock);

    /* Perform the TLS handshake. */
 again:
    err = gnutls_handshake (session);
    if (err < 0) {
        if (err == GNUTLS_E_AGAIN || err == GNUTLS_E_INTERRUPTED)
            goto again;
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
        return NULL;
    }

    /* Verify certificate. */
    if (verify_certificate (conn, session, hostname) == -1) {
            fprintf (stderr,
                     "remote_internal: failed to verify peer's certificate\n");
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
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (len));
        return NULL;
    }
    if (len != 1 || buf[0] != '\1') {
        error (NULL, VIR_ERR_RPC,
               "server verification (of our certificate or IP address) failed\n");
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
                    gnutls_session_t session,
                    const char *hostname)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    time_t now;

    if ((ret = gnutls_certificate_verify_peers2 (session, &status)) < 0) {
        error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
        return -1;
    }
  
    if ((now = time(NULL)) == ((time_t)-1)) {
        error (NULL, VIR_ERR_SYSTEM_ERROR, strerror (errno));
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
    
        error (NULL, VIR_ERR_RPC, reason);
        return -1;
    }

    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
        error (NULL, VIR_ERR_RPC, "Certificate type is not X.509");
        return -1;
    }
  
    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        error (NULL, VIR_ERR_RPC, "gnutls_certificate_get_peers failed");
        return -1;
    }
  
    for (i = 0 ; i < nCerts ; i++) {
        gnutls_x509_crt_t cert;

        ret = gnutls_x509_crt_init (&cert);
        if (ret < 0) {
            error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
            return -1;
        }
        
        ret = gnutls_x509_crt_import (cert, &certs[i], GNUTLS_X509_FMT_DER);
        if (ret < 0) {
            error (NULL, VIR_ERR_GNUTLS_ERROR, gnutls_strerror (ret));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }
    
        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            error (NULL, VIR_ERR_RPC, "The certificate has expired");
            gnutls_x509_crt_deinit (cert);
            return -1;
        }
    
        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            error (NULL, VIR_ERR_RPC, "The certificate is not yet activated");
            gnutls_x509_crt_deinit (cert);
            return -1;
        }
    
        if (i == 0) {
            if (!gnutls_x509_crt_check_hostname (cert, hostname)) {
                __virRaiseError
                    (NULL, NULL, NULL,
                     VIR_FROM_REMOTE, VIR_ERR_RPC,
                     VIR_ERR_ERROR, hostname, NULL, NULL,
                     0, 0,
                     "Certificate's owner does not match the hostname (%s)",
                     hostname);
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
    if (priv->uses_tls && priv->session)
        gnutls_bye (priv->session, GNUTLS_SHUT_RDWR);
    close (priv->sock);

    if (priv->pid > 0) {
        pid_t reap;
        do {
            reap = waitpid(priv->pid, NULL, 0);
            if (reap == -1 && errno == EINTR)
                continue;
        } while (reap != -1 && reap != priv->pid);
    }

    /* See comment for remoteType. */
    if (priv->type) free (priv->type);

    /* Free URI copy. */
    if (priv->uri) free (priv->uri);

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

/* This call is unusual because it doesn't go over RPC.  The
 * full URI is known (only) at the client end of the connection.
 */
static char *
remoteGetURI (virConnectPtr conn)
{
    GET_PRIVATE (conn, NULL);
    char *str;

    str = strdup (priv->uri);
    if (str == NULL) {
        error (conn, VIR_ERR_SYSTEM_ERROR, strerror (errno));
        return NULL;
    }
    return str;
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
        error (conn, VIR_ERR_RPC, "maxids > REMOTE_DOMAIN_ID_LIST_MAX");
        return -1;
    }
    args.maxids = maxids;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DOMAINS,
              (xdrproc_t) xdr_remote_list_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_domains_ret, (char *) &ret) == -1)
        return -1;

    if (ret.ids.ids_len > maxids) {
        error (conn, VIR_ERR_RPC, "ret.ids.ids_len > maxids");
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
        error (domain->conn, VIR_ERR_RPC, "maplen > REMOTE_CPUMAP_MAX");
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
        error (domain->conn, VIR_ERR_RPC, "maxinfo > REMOTE_VCPUINFO_MAX");
        return -1;
    }
    if (maxinfo * maplen > REMOTE_CPUMAPS_MAX) {
        error (domain->conn, VIR_ERR_RPC, "maxinfo * maplen > REMOTE_CPUMAPS_MAX");
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
        error (domain->conn, VIR_ERR_RPC, "ret.info.info_len > maxinfo");
        xdr_free ((xdrproc_t) xdr_remote_domain_get_vcpus_ret, (char *) &ret);
        return -1;
    }
    if (ret.cpumaps.cpumaps_len > maxinfo * maplen) {
        error (domain->conn, VIR_ERR_RPC, "ret.cpumaps.cpumaps_len > maxinfo * maplen");
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
        error (conn, VIR_ERR_RPC, "maxnames > REMOTE_DOMAIN_NAME_LIST_MAX");
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_DOMAINS,
              (xdrproc_t) xdr_remote_list_defined_domains_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_domains_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, "ret.names.names_len > maxnames");
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
remoteDomainAttachDevice (virDomainPtr domain, char *xml)
{
    remote_domain_attach_device_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.xml = xml;

    if (call (domain->conn, priv, 0, REMOTE_PROC_DOMAIN_ATTACH_DEVICE,
              (xdrproc_t) xdr_remote_domain_attach_device_args, (char *) &args,
              (xdrproc_t) xdr_void, (char *) NULL) == -1)
        return -1;

    return 0;
}

static int
remoteDomainDetachDevice (virDomainPtr domain, char *xml)
{
    remote_domain_detach_device_args args;
    GET_PRIVATE (domain->conn, -1);

    make_nonnull_domain (&args.dom, domain);
    args.xml = xml;

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
        error (domain->conn, VIR_ERR_RPC, "remoteDomainGetSchedulerParameters: returned number of parameters exceeds limit");
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
            error (domain->conn, VIR_ERR_RPC, "remoteDomainGetSchedulerParameters: unknown parameter type");
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
    args.params.params_val = malloc (sizeof (struct remote_sched_param)
                                     * nparams);
    if (args.params.params_val == NULL) {
        error (domain->conn, VIR_ERR_RPC, "out of memory allocating array");
        return -1;
    }

    do_error = 0;
    for (i = 0; i < nparams; ++i) {
        // call() will free this:
        args.params.params_val[i].field = strdup (params[i].field);
        if (args.params.params_val[i].field == NULL) {
            error (domain->conn, VIR_ERR_NO_MEMORY, "out of memory");
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
            error (domain->conn, VIR_ERR_RPC, "unknown parameter type");
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
                   const char *uri_str,
                   int flags)
{
    if (conn &&
        conn->driver &&
        strcmp (conn->driver->name, "remote") == 0) {
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
        struct private_data *priv = malloc (sizeof(struct private_data));
        int ret, rflags = 0;
        if (!priv) {
            error (NULL, VIR_ERR_NO_MEMORY, "struct private_data");
            return VIR_DRV_OPEN_ERROR;
        }
        if (flags & VIR_DRV_OPEN_RO)
            rflags |= VIR_DRV_OPEN_REMOTE_RO;
        rflags |= VIR_DRV_OPEN_REMOTE_UNIX;

        memset(priv, 0, sizeof(struct private_data));
        priv->magic = DEAD;
        priv->sock = -1;
        ret = doRemoteOpen(conn, priv, uri_str, rflags);
        if (ret != VIR_DRV_OPEN_SUCCESS) {
            conn->networkPrivateData = NULL;
            free(priv);
        } else {
            priv->magic = MAGIC;
            priv->networkOnly = 1;
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
    if (priv->networkOnly) {
        ret = doRemoteClose(conn, priv);
        free(priv);
        conn->networkPrivateData = NULL;
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
        error (conn, VIR_ERR_RPC, "maxnames > REMOTE_NETWORK_NAME_LIST_MAX");
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_NETWORKS,
              (xdrproc_t) xdr_remote_list_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_networks_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, "ret.names.names_len > maxnames");
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
        error (conn, VIR_ERR_RPC, "maxnames > REMOTE_NETWORK_NAME_LIST_MAX");
        return -1;
    }
    args.maxnames = maxnames;

    memset (&ret, 0, sizeof ret);
    if (call (conn, priv, 0, REMOTE_PROC_LIST_DEFINED_NETWORKS,
              (xdrproc_t) xdr_remote_list_defined_networks_args, (char *) &args,
              (xdrproc_t) xdr_remote_list_defined_networks_ret, (char *) &ret) == -1)
        return -1;

    if (ret.names.names_len > maxnames) {
        error (conn, VIR_ERR_RPC, "ret.names.names_len > maxnames");
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
      int in_open /* if we are in virConnectOpen */,
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
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, "xdr_remote_message_header");
        return -1;
    }

    if (!(*args_filter) (&xdr, args)) {
        error (in_open ? NULL : conn, VIR_ERR_RPC, "marshalling args");
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
        error (in_open ? NULL : conn, VIR_ERR_RPC, "xdr_int (length word)");
        return -1;
    }
    xdr_destroy (&xdr);

    /* Send length word followed by header+args. */
    if (really_write (conn, priv, in_open, buffer2, sizeof buffer2) == -1 ||
        really_write (conn, priv, in_open, buffer, len-4) == -1)
        return -1;

    /* Read and deserialise length word. */
    if (really_read (conn, priv, in_open, buffer2, sizeof buffer2) == -1)
        return -1;

    xdrmem_create (&xdr, buffer2, sizeof buffer2, XDR_DECODE);
    if (!xdr_int (&xdr, &len)) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, "xdr_int (length word, reply)");
        return -1;
    }
    xdr_destroy (&xdr);

    /* Length includes length word - adjust to real length to read. */
    len -= 4;

    if (len < 0 || len > REMOTE_MESSAGE_MAX) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, "packet received from server too large");
        return -1;
    }

    /* Read reply header and what follows (either a ret or an error). */
    if (really_read (conn, priv, in_open, buffer, len) == -1)
        return -1;

    /* Deserialise reply header. */
    xdrmem_create (&xdr, buffer, len, XDR_DECODE);
    if (!xdr_remote_message_header (&xdr, &hdr)) {
        error (in_open ? NULL : conn,
               VIR_ERR_RPC, "xdr_remote_message_header (reply)");
        return -1;
    }

    /* Check program, version, etc. are what we expect. */
    if (hdr.prog != REMOTE_PROGRAM) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown program (received %x, expected %x)",
                         hdr.prog, REMOTE_PROGRAM);
        return -1;
    }
    if (hdr.vers != REMOTE_PROTOCOL_VERSION) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown protocol version (received %x, expected %x)",
                         hdr.vers, REMOTE_PROTOCOL_VERSION);
        return -1;
    }

    /* If we extend the server to actually send asynchronous messages, then
     * we'll need to change this so that it can recognise an asynch
     * message being received at this point.
     */
    if (hdr.proc != proc_nr) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown procedure (received %x, expected %x)",
                         hdr.proc, proc_nr);
        return -1;
    }
    if (hdr.direction != REMOTE_REPLY) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown direction (received %x, expected %x)",
                         hdr.direction, REMOTE_REPLY);
        return -1;
    }
    if (hdr.serial != serial) {
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown serial (received %x, expected %x)",
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
            error (in_open ? NULL : conn, VIR_ERR_RPC, "unmarshalling ret");
            return -1;
        }
        xdr_destroy (&xdr);
        return 0;

    case REMOTE_ERROR:
        memset (&rerror, 0, sizeof rerror);
        if (!xdr_remote_error (&xdr, &rerror)) {
            error (in_open ? NULL : conn,
                   VIR_ERR_RPC, "unmarshalling remote_error");
            return -1;
        }
        xdr_destroy (&xdr);
        server_error (in_open ? NULL : conn, &rerror);
        xdr_free ((xdrproc_t) xdr_remote_error, (char *) &rerror);
        return -1;

    default:
        __virRaiseError (in_open ? NULL : conn, NULL, NULL, VIR_FROM_REMOTE,
                         VIR_ERR_RPC, VIR_ERR_ERROR, NULL, NULL, NULL, 0, 0,
                         "unknown status (received %x)",
                         hdr.status);
        xdr_destroy (&xdr);
        return -1;
    }
}

static int
really_write (virConnectPtr conn, struct private_data *priv,
              int in_open /* if we are in virConnectOpen */,
              char *bytes, int len)
{
    char *p;
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
            err = write (priv->sock, p, len);
            if (err == -1) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                error (in_open ? NULL : conn,
                       VIR_ERR_SYSTEM_ERROR, strerror (errno));
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
really_read (virConnectPtr conn, struct private_data *priv,
             int in_open /* if we are in virConnectOpen */,
             char *bytes, int len)
{
    char *p;
    int err;

    p = bytes;
    if (priv->uses_tls) {
        do {
            err = gnutls_record_recv (priv->session, p, len);
            if (err < 0) {
                if (err == GNUTLS_E_INTERRUPTED || err == GNUTLS_E_AGAIN)
                    continue;
                error (in_open ? NULL : conn,
                       VIR_ERR_GNUTLS_ERROR, gnutls_strerror (err));
                return -1;
            }
            if (err == 0) {
                error (in_open ? NULL : conn,
                       VIR_ERR_RPC, "socket closed unexpectedly");
                return -1;
            }
            len -= err;
            p += err;
        }
        while (len > 0);
    } else {
        do {
            err = read (priv->sock, p, len);
            if (err == -1) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                error (in_open ? NULL : conn,
                       VIR_ERR_SYSTEM_ERROR, strerror (errno));
                return -1;
            }
            if (err == 0) {
                error (in_open ? NULL : conn,
                       VIR_ERR_RPC, "socket closed unexpectedly");
                return -1;
            }
            len -= err;
            p += err;
        }
        while (len > 0);
    }

    return 0;
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

/* For errors generated on the server side and sent back to us. */
static void
server_error (virConnectPtr conn, remote_error *err)
{
    virDomainPtr dom;
    virNetworkPtr net;

    /* Get the domain and network, if set. */
    dom = err->dom ? get_nonnull_domain (conn, *err->dom) : NULL;
    net = err->net ? get_nonnull_network (conn, *err->net) : NULL;

    /* These strings are nullable.  OK to ignore the return value
     * of strdup since these strings are informational.
     */
    char *str1 = err->str1 ? strdup (*err->str1) : NULL;
    char *str2 = err->str2 ? strdup (*err->str2) : NULL;
    char *str3 = err->str3 ? strdup (*err->str3) : NULL;

    char *message = err->message ? strdup (*err->message) : NULL;

    __virRaiseError (conn, dom, net,
                     err->domain, err->code, err->level,
                     str1, str2, str3,
                     err->int1, err->int2,
                     message);
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

/*----------------------------------------------------------------------*/

static virDriver driver = {
    .no = VIR_DRV_REMOTE,
    .name = "remote",
    .ver = REMOTE_PROTOCOL_VERSION,
    .open = remoteOpen,
    .close = remoteClose,
    .supports_feature = remoteSupportsFeature,
	.type = remoteType,
	.version = remoteVersion,
    .getHostname = remoteGetHostname,
    .getURI = remoteGetURI,
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
