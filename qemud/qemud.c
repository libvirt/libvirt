/*
 * qemud.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006, 2007 Red Hat, Inc.
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

#include <config.h>

#define _GNU_SOURCE /* for asprintf */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <stdlib.h>
#include <pwd.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <fnmatch.h>
#include <grp.h>

#include <libvirt/virterror.h>

#include "internal.h"
#include "../src/internal.h"
#include "../src/remote_internal.h"
#include "../src/conf.h"
#include "event.h"
#ifdef HAVE_AVAHI
#include "mdns.h"
#endif

static int godaemon = 0;        /* -d: Be a daemon */
static int verbose = 0;         /* -v: Verbose mode */
static int timeout = -1;        /* -t: Shutdown timeout */
static int sigwrite = -1;       /* Signal handler pipe */
static int ipsock = 0;          /* -l  Listen for TCP/IP */

/* Defaults for configuration file elements */
static int listen_tls = 1;
static int listen_tcp = 0;
static const char *tls_port = LIBVIRTD_TLS_PORT;
static const char *tcp_port = LIBVIRTD_TCP_PORT;

static gid_t unix_sock_gid = 0; /* Only root by default */
static int unix_sock_rw_perms = 0700; /* Allow user only */
static int unix_sock_ro_perms = 0777; /* Allow world */

#ifdef HAVE_AVAHI
static int mdns_adv = 1;
static const char *mdns_name = NULL;
#endif

static int tls_no_verify_certificate = 0;
static int tls_no_verify_address = 0;
static const char **tls_allowed_ip_list = 0;
static const char **tls_allowed_dn_list = 0;

static const char *key_file = LIBVIRT_SERVERKEY;
static const char *cert_file = LIBVIRT_SERVERCERT;
static const char *ca_file = LIBVIRT_CACERT;
static const char *crl_file = "";

static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;

#define DH_BITS 1024

static sig_atomic_t sig_errors = 0;
static int sig_lasterrno = 0;

static void sig_handler(int sig) {
    unsigned char sigc = sig;
    int origerrno;
    int r;

    if (sig == SIGCHLD) /* We explicitly waitpid the child later */
        return;

    origerrno = errno;
    r = write(sigwrite, &sigc, 1);
    if (r == -1) {
        sig_errors++;
        sig_lasterrno = errno;
    }
    errno = origerrno;
}

static void qemudDispatchClientEvent(int fd, int events, void *opaque);
static void qemudDispatchServerEvent(int fd, int events, void *opaque);
static int qemudRegisterClientEvent(struct qemud_server *server,
                                    struct qemud_client *client,
                                    int removeFirst);

static int
remoteCheckCertFile(const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        qemudLog (QEMUD_ERR, "Cannot access %s '%s': %s (%d)",
                  type, file, strerror(errno), errno);
        return -1;
    }
    return 0;
}

static int
remoteInitializeGnuTLS (void)
{
    int err;

    /* Initialise GnuTLS. */
    gnutls_global_init ();

    err = gnutls_certificate_allocate_credentials (&x509_cred);
    if (err) {
        qemudLog (QEMUD_ERR, "gnutls_certificate_allocate_credentials: %s",
                  gnutls_strerror (err));
        return -1;
    }

    if (ca_file && ca_file[0] != '\0') {
        if (remoteCheckCertFile("CA certificate", ca_file) < 0)
            return -1;

        qemudDebug ("loading CA cert from %s", ca_file);
        err = gnutls_certificate_set_x509_trust_file (x509_cred, ca_file,
                                                      GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            qemudLog (QEMUD_ERR, "gnutls_certificate_set_x509_trust_file: %s",
                      gnutls_strerror (err));
            return -1;
        }
    }

    if (crl_file && crl_file[0] != '\0') {
        if (remoteCheckCertFile("CA revocation list", ca_file) < 0)
            return -1;

        qemudDebug ("loading CRL from %s", crl_file);
        err = gnutls_certificate_set_x509_crl_file (x509_cred, crl_file,
                                                    GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            qemudLog (QEMUD_ERR, "gnutls_certificate_set_x509_crl_file: %s",
                      gnutls_strerror (err));
            return -1;
        }
    }

    if (cert_file && cert_file[0] != '\0' && key_file && key_file[0] != '\0') {
        if (remoteCheckCertFile("server certificate", cert_file) < 0)
            return -1;
        if (remoteCheckCertFile("server key", key_file) < 0)
            return -1;
        qemudDebug ("loading cert and key from %s and %s",
                    cert_file, key_file);
        err =
            gnutls_certificate_set_x509_key_file (x509_cred,
                                                  cert_file, key_file,
                                                  GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            qemudLog (QEMUD_ERR, "gnutls_certificate_set_x509_key_file: %s",
                      gnutls_strerror (err));
            return -1;
        }
    }

    /* Generate Diffie Hellman parameters - for use with DHE
     * kx algorithms. These should be discarded and regenerated
     * once a day, once a week or once a month. Depending on the
     * security requirements.
     */
    err = gnutls_dh_params_init (&dh_params);
    if (err < 0) {
        qemudLog (QEMUD_ERR, "gnutls_dh_params_init: %s",
                  gnutls_strerror (err));
        return -1;
    }
    err = gnutls_dh_params_generate2 (dh_params, DH_BITS);
    if (err < 0) {
        qemudLog (QEMUD_ERR, "gnutls_dh_params_generate2: %s",
                  gnutls_strerror (err));
        return -1;
    }

    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    return 0;
}

static void qemudDispatchSignalEvent(int fd ATTRIBUTE_UNUSED,
                                     int events ATTRIBUTE_UNUSED,
                                     void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    unsigned char sigc;
    int ret;

    if (read(server->sigread, &sigc, 1) != 1) {
        qemudLog(QEMUD_ERR, "Failed to read from signal pipe: %s",
                 strerror(errno));
        return;
    }

    ret = 0;

    switch (sigc) {
    case SIGHUP:
        qemudLog(QEMUD_INFO, "Reloading configuration on SIGHUP");
        if (virStateReload() < 0)
            qemudLog(QEMUD_WARN, "Error while reloading drivers");
        break;

    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
        qemudLog(QEMUD_WARN, "Shutting down on signal %d", sigc);
        server->shutdown = 1;
        break;

    default:
        break;
    }

    if (ret != 0)
        server->shutdown = 1;
}

static int qemudSetCloseExec(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFD)) < 0)
        goto error;
    flags |= FD_CLOEXEC;
    if ((fcntl(fd, F_SETFD, flags)) < 0)
        goto error;
    return 0;
 error:
    qemudLog(QEMUD_ERR, "Failed to set close-on-exec file descriptor flag");
    return -1;
}


static int qemudSetNonBlock(int fd) {
    int flags;
    if ((flags = fcntl(fd, F_GETFL)) < 0)
        goto error;
    flags |= O_NONBLOCK;
    if ((fcntl(fd, F_SETFL, flags)) < 0)
        goto error;
    return 0;
 error:
    qemudLog(QEMUD_ERR, "Failed to set non-blocking file descriptor flag");
    return -1;
}

void qemudLog(int priority, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);

    if (godaemon) {
        int sysprio = -1;

        switch(priority) {
        case QEMUD_ERR:
            sysprio = LOG_ERR;
            break;
        case QEMUD_WARN:
            sysprio = LOG_WARNING;
            break;
        case QEMUD_INFO:
            if (verbose)
                sysprio = LOG_INFO;
            break;
#ifdef ENABLE_DEBUG
        case QEMUD_DEBUG:
            if (verbose)
                sysprio = LOG_DEBUG;
            break;
#endif
        default:
            break;
        }

        if (sysprio != -1)
            vsyslog(sysprio, fmt, args);
    } else {
        switch(priority) {
        case QEMUD_ERR:
        case QEMUD_WARN:
            vfprintf(stderr, fmt, args);
            fputc('\n', stderr);
            break;

        case QEMUD_INFO:
            if (verbose) {
                vprintf(fmt, args);
                fputc('\n', stdout);
            }
            break;

#ifdef ENABLE_DEBUG
        case QEMUD_DEBUG:
            if (verbose) {
                vprintf(fmt, args);
                fputc('\n', stdout);
            }
            break;
#endif
        default:
            break;
        }
    }

    va_end(args);
}

static int qemudGoDaemon(void) {
    int pid = fork();
    switch (pid) {
    case 0:
        {
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;

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

            if (setsid() < 0)
                goto cleanup;

            nextpid = fork();
            switch (nextpid) {
            case 0:
                return 0;
            case -1:
                return -1;
            default:
                return nextpid;
            }

        cleanup:
            if (stdoutfd != -1)
                close(stdoutfd);
            if (stdinfd != -1)
                close(stdinfd);
            return -1;

        }

    case -1:
        return -1;

    default:
        {
            int got, status = 0;
            /* We wait to make sure the next child forked
               successfully */
            if ((got = waitpid(pid, &status, 0)) < 0 ||
                got != pid ||
                status != 0) {
                return -1;
            }
      
            return pid;
        }
    }
}

static int qemudWritePidFile(const char *pidFile) {
    int fd;
    FILE *fh;

    if (pidFile[0] == '\0')
        return 0;

    if ((fd = open(pidFile, O_WRONLY|O_CREAT|O_EXCL, 0644)) < 0) {
        qemudLog(QEMUD_ERR, "Failed to open pid file '%s' : %s",
                 pidFile, strerror(errno));
        return -1;
    }

    if (!(fh = fdopen(fd, "w"))) {
        qemudLog(QEMUD_ERR, "Failed to fdopen pid file '%s' : %s",
                 pidFile, strerror(errno));
        close(fd);
        return -1;
    }

    if (fprintf(fh, "%lu\n", (unsigned long)getpid()) < 0) {
        qemudLog(QEMUD_ERR, "Failed to write to pid file '%s' : %s",
                 pidFile, strerror(errno));
        close(fd);
        return -1;
    }

    if (fclose(fh) == EOF) {
        qemudLog(QEMUD_ERR, "Failed to close pid file '%s' : %s",
                 pidFile, strerror(errno));
        return -1;
    }

    return 0;
}

static int qemudListenUnix(struct qemud_server *server,
                           const char *path, int readonly) {
    struct qemud_socket *sock = calloc(1, sizeof(struct qemud_socket));
    struct sockaddr_un addr;
    mode_t oldmask;
    gid_t oldgrp;

    if (!sock) {
        qemudLog(QEMUD_ERR, "Failed to allocate memory for struct qemud_socket");
        return -1;
    }

    sock->readonly = readonly;
    sock->port = -1;

    if ((sock->fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        qemudLog(QEMUD_ERR, "Failed to create socket: %s",
                 strerror(errno));
        goto cleanup;
    }

    if (qemudSetCloseExec(sock->fd) < 0 ||
        qemudSetNonBlock(sock->fd) < 0)
        goto cleanup;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0';


    oldgrp = getgid();
    oldmask = umask(readonly ? ~unix_sock_ro_perms : ~unix_sock_rw_perms);
    if (getuid() == 0)
        setgid(unix_sock_gid);

    if (bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemudLog(QEMUD_ERR, "Failed to bind socket to '%s': %s",
                 path, strerror(errno));
        goto cleanup;
    }
    umask(oldmask);
    if (getuid() == 0)
        setgid(oldgrp);

    if (listen(sock->fd, 30) < 0) {
        qemudLog(QEMUD_ERR, "Failed to listen for connections on '%s': %s",
                 path, strerror(errno));
        goto cleanup;
    }

    if (virEventAddHandleImpl(sock->fd,
                              POLLIN| POLLERR | POLLHUP,
                              qemudDispatchServerEvent,
                              server) < 0) {
        qemudLog(QEMUD_ERR, "Failed to add server event callback");
        goto cleanup;
    }

    sock->next = server->sockets;
    server->sockets = sock;
    server->nsockets++;

    return 0;

 cleanup:
    if (sock->fd)
        close(sock->fd);
    free(sock);
    return -1;
}

// See: http://people.redhat.com/drepper/userapi-ipv6.html
static int
remoteMakeSockets (int *fds, int max_fds, int *nfds_r, const char *service)
{
    struct addrinfo *ai;
    struct addrinfo hints;
    memset (&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    int e = getaddrinfo (NULL, service, &hints, &ai);
    if (e != 0) {
        qemudLog (QEMUD_ERR, "getaddrinfo: %s\n", gai_strerror (e));
        return -1;
    }

    struct addrinfo *runp = ai;
    while (runp && *nfds_r < max_fds) {
        fds[*nfds_r] = socket (runp->ai_family, runp->ai_socktype,
                               runp->ai_protocol);
        if (fds[*nfds_r] == -1) {
            qemudLog (QEMUD_ERR, "socket: %s", strerror (errno));
            return -1;
        }

        int opt = 1;
        setsockopt (fds[*nfds_r], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

        if (bind (fds[*nfds_r], runp->ai_addr, runp->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                qemudLog (QEMUD_ERR, "bind: %s", strerror (errno));
                return -1;
            }
            close (fds[*nfds_r]);
        }
        else {
            if (listen (fds[*nfds_r], SOMAXCONN) == -1) {
                qemudLog (QEMUD_ERR, "listen: %s", strerror (errno));
                return -1;
            }
            ++*nfds_r;
        }
        runp = runp->ai_next;
    }

    freeaddrinfo (ai);
    return 0;
}

/* Listen on the named/numbered TCP port.  On a machine with IPv4 and
 * IPv6 interfaces this may generate several sockets.
 */
static int
remoteListenTCP (struct qemud_server *server,
                 const char *port,
                 int tls)
{
    int fds[2];
    int nfds = 0;
    int i;
    struct qemud_socket *sock;

    if (remoteMakeSockets (fds, 2, &nfds, port) == -1)
        return -1;

    for (i = 0; i < nfds; ++i) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);

        sock = calloc (1, sizeof *sock);

        if (!sock) {
            qemudLog (QEMUD_ERR,
                      "remoteListenTCP: calloc: %s", strerror (errno));
            return -1;
        }

        sock->readonly = 0;
        sock->next = server->sockets;
        server->sockets = sock;
        server->nsockets++;

        sock->fd = fds[i];
        sock->tls = tls;

        if (getsockname(sock->fd, (struct sockaddr *)(&sa), &salen) < 0)
            return -1;

        if (sa.ss_family == AF_INET)
            sock->port = htons(((struct sockaddr_in*)&sa)->sin_port);
        else if (sa.ss_family == AF_INET6)
            sock->port = htons(((struct sockaddr_in6*)&sa)->sin6_port);
        else
            sock->port = -1;

        if (qemudSetCloseExec(sock->fd) < 0 ||
            qemudSetNonBlock(sock->fd) < 0)
            return -1;

        if (listen (sock->fd, 30) < 0) {
            qemudLog (QEMUD_ERR,
                      "remoteListenTCP: listen: %s", strerror (errno));
            return -1;
        }

        if (virEventAddHandleImpl(sock->fd,
                                  POLLIN| POLLERR | POLLHUP,
                                  qemudDispatchServerEvent,
                                  server) < 0) {
            qemudLog(QEMUD_ERR, "Failed to add server event callback");
            return -1;
        }

    }

    return 0;
}

static int qemudInitPaths(struct qemud_server *server,
                          char *sockname,
                          char *roSockname,
                          int maxlen) {
    char *base = 0;
    uid_t uid = geteuid();

    
    if (!uid) {
        if (snprintf (sockname, maxlen, "%s/run/libvirt/libvirt-sock",
                      LOCAL_STATE_DIR) >= maxlen)
            goto snprintf_error;

        unlink(sockname);

        if (snprintf (roSockname, maxlen, "%s/run/libvirt/libvirt-sock-ro",
                      LOCAL_STATE_DIR) >= maxlen)
            goto snprintf_error;

        unlink(roSockname);

        if (snprintf(server->logDir, PATH_MAX, "%s/log/libvirt/", LOCAL_STATE_DIR) >= PATH_MAX)
            goto snprintf_error;
    } else {
        struct passwd *pw;

        if (!(pw = getpwuid(uid))) {
            qemudLog(QEMUD_ERR, "Failed to find user record for uid '%d': %s",
                     uid, strerror(errno));
            return -1;
        }

        if (snprintf(sockname, maxlen, "@%s/.libvirt/libvirt-sock", pw->pw_dir) >= maxlen)
            goto snprintf_error;

        if (snprintf(server->logDir, PATH_MAX, "%s/.libvirt/log", pw->pw_dir) >= PATH_MAX)
            goto snprintf_error;

        if (asprintf (&base, "%s/.libvirt", pw->pw_dir) == -1) {
            qemudLog (QEMUD_ERR, "out of memory in asprintf");
            return -1;
        }

    } /* !remote */

    if (base) free (base);

    return 0;

 snprintf_error:
    qemudLog(QEMUD_ERR, "Resulting path to long for buffer in qemudInitPaths()");
    return -1;
}

static struct qemud_server *qemudInitialize(int sigread) {
    struct qemud_server *server;
    struct qemud_socket *sock;
    char sockname[PATH_MAX];
    char roSockname[PATH_MAX];

    if (!(server = calloc(1, sizeof(struct qemud_server)))) {
        qemudLog(QEMUD_ERR, "Failed to allocate struct qemud_server");
        return NULL;
    }

    /* We don't have a dom-0, so start from 1 */
    server->sigread = sigread;

    roSockname[0] = '\0';

    if (qemudInitPaths(server, sockname, roSockname, PATH_MAX) < 0)
        goto cleanup;

    if (qemudListenUnix(server, sockname, 0) < 0)
        goto cleanup;

    if (roSockname[0] != '\0' && qemudListenUnix(server, roSockname, 1) < 0)
        goto cleanup;

    __virEventRegisterImpl(virEventAddHandleImpl,
                           virEventUpdateHandleImpl,
                           virEventRemoveHandleImpl,
                           virEventAddTimeoutImpl,
                           virEventUpdateTimeoutImpl,
                           virEventRemoveTimeoutImpl);

    virStateInitialize();

    if (ipsock) {
        if (listen_tcp && remoteListenTCP (server, tcp_port, 0) < 0)
            goto cleanup;

        if (listen_tls) {
            if (remoteInitializeGnuTLS () < 0)
                goto cleanup;

            if (remoteListenTCP (server, tls_port, 1) < 0)
                goto cleanup;
        }
    }

#ifdef HAVE_AVAHI
    if (getuid() == 0 && mdns_adv) {
        struct libvirtd_mdns_group *group;
        int port = 0;

        server->mdns = libvirtd_mdns_new();

        if (!mdns_name) {
            char groupname[64], localhost[HOST_NAME_MAX+1], *tmp;
            /* Extract the host part of the potentially FQDN */
            gethostname(localhost, HOST_NAME_MAX);
            localhost[HOST_NAME_MAX] = '\0';
            if ((tmp = strchr(localhost, '.')))
                *tmp = '\0';
            snprintf(groupname, sizeof(groupname)-1, "Virtualization Host %s", localhost);
            groupname[sizeof(groupname)-1] = '\0';
            group = libvirtd_mdns_add_group(server->mdns, groupname);
        } else {
            group = libvirtd_mdns_add_group(server->mdns, mdns_name);
        }

        /* 
         * See if there's a TLS enabled port we can advertise. Cowardly
         * don't bother to advertise TCP since we don't want people using
         * them for real world apps
         */
        sock = server->sockets;
        while (sock) {
            if (sock->port != -1 && sock->tls) {
                port = sock->port;
                break;
            }
            sock = sock->next;
        }
    
        /*
         * Add the primary entry - we choose SSH because its most likely to always
         * be available
         */
        libvirtd_mdns_add_entry(group, "_libvirt._tcp", port);
        libvirtd_mdns_start(server->mdns);
    }
#endif

    return server;

 cleanup:
    if (server) {
        sock = server->sockets;
        while (sock) {
            close(sock->fd);
            sock = sock->next;
        }

        free(server);
    }
    return NULL;
}

static gnutls_session_t
remoteInitializeTLSSession (void)
{
  gnutls_session_t session;
  int err;

  err = gnutls_init (&session, GNUTLS_SERVER);
  if (err != 0) goto failed;

  /* avoid calling all the priority functions, since the defaults
   * are adequate.
   */
  err = gnutls_set_default_priority (session);
  if (err != 0) goto failed;

  err = gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);
  if (err != 0) goto failed;

  /* request client certificate if any.
   */
  gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

  gnutls_dh_set_prime_bits (session, DH_BITS);

  return session;

 failed:
  qemudLog (QEMUD_ERR, "remoteInitializeTLSSession: %s",
            gnutls_strerror (err));
  return NULL;
}

/* Check DN is on tls_allowed_dn_list. */
static int
remoteCheckDN (gnutls_x509_crt_t cert)
{
    char name[256];
    size_t namesize = sizeof name;
    const char **wildcards;
    int err;

    err = gnutls_x509_crt_get_dn (cert, name, &namesize);
    if (err != 0) {
        qemudLog (QEMUD_ERR,
                  "remoteCheckDN: gnutls_x509_cert_get_dn: %s",
                  gnutls_strerror (err));
        return 0;
    }

    /* If the list is not set, allow any DN. */
    wildcards = tls_allowed_dn_list;
    if (!wildcards)
        return 1;

    while (*wildcards) {
        if (fnmatch (*wildcards, name, 0) == 0)
            return 1;
        wildcards++;
    }

#ifdef ENABLE_DEBUG
    /* Print the client's DN. */
    qemudLog (QEMUD_DEBUG,
              "remoteCheckDN: failed: client DN is %s", name);
#endif

    return 0; // Not found.
}

static int
remoteCheckCertificate (gnutls_session_t session)
{
    int ret;
    unsigned int status;
    const gnutls_datum_t *certs;
    unsigned int nCerts, i;
    time_t now;

    if ((ret = gnutls_certificate_verify_peers2 (session, &status)) < 0){
        qemudLog (QEMUD_ERR, "remoteCheckCertificate: verify failed: %s",
                  gnutls_strerror (ret));
        return -1;
    }

    if (status != 0) {
        if (status & GNUTLS_CERT_INVALID)
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate is not trusted.");

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate hasn't got a known issuer.");

        if (status & GNUTLS_CERT_REVOKED)
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate has been revoked.");

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate uses an insecure algorithm.");
#endif

        return -1;
    }

    if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509) {
        qemudLog (QEMUD_ERR, "remoteCheckCertificate: certificate is not X.509");
        return -1;
    }

    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        qemudLog (QEMUD_ERR, "remoteCheckCertificate: no peers");
        return -1;
    }

    now = time (NULL);

    for (i = 0; i < nCerts; i++) {
        gnutls_x509_crt_t cert;

        if (gnutls_x509_crt_init (&cert) < 0) {
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: gnutls_x509_crt_init failed");
            return -1;
        }

        if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
            gnutls_x509_crt_deinit (cert);
            return -1;
        }
    
        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate has expired");
            gnutls_x509_crt_deinit (cert);
            return -1;
        }
    
        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            qemudLog (QEMUD_ERR, "remoteCheckCertificate: the client certificate is not yet activated");
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (i == 0) {
            if (!remoteCheckDN (cert)) {
                /* This is the most common error: make it informative. */
                qemudLog (QEMUD_ERR, "remoteCheckCertificate: client's Distinguished Name is not on the list of allowed clients (tls_allowed_dn_list).  Use 'openssl x509 -in clientcert.pem -text' to view the Distinguished Name field in the client certificate, or run this daemon with --verbose option.");
                gnutls_x509_crt_deinit (cert);
                return -1;
            }
        }
    }

    return 0;
}

/* Check the client's access. */
static int
remoteCheckAccess (struct qemud_client *client)
{
    char addr[NI_MAXHOST];
    const char **wildcards;
    int found, err;

    /* Verify client certificate. */
    if (remoteCheckCertificate (client->session) == -1) {
        qemudLog (QEMUD_ERR, "remoteCheckCertificate: failed to verify client's certificate");
        if (!tls_no_verify_certificate) return -1;
        else qemudLog (QEMUD_INFO, "remoteCheckCertificate: tls_no_verify_certificate is set so the bad certificate is ignored");
    }

    /*----- IP address check, similar to tcp wrappers -----*/

    /* Convert IP address to printable string (eg. "127.0.0.1" or "::1"). */
    err = getnameinfo ((struct sockaddr *) &client->addr, client->addrlen,
                       addr, sizeof addr, NULL, 0,
                       NI_NUMERICHOST);
    if (err != 0) {
        qemudLog (QEMUD_ERR, "getnameinfo: %s", gai_strerror (err));
        return -1;
    }

    /* Verify the client is on the list of allowed clients.
     *
     * NB: No tls_allowed_ip_list in config file means anyone can access.
     * If tls_allowed_ip_list is in the config file but empty, means no
     * one can access (not particularly useful, but it's what the sysadmin
     * would expect).
     */
    wildcards = tls_allowed_ip_list;
    if (wildcards) {
        found = 0;

        while (*wildcards) {
            if (fnmatch (*wildcards, addr, 0) == 0) {
                found = 1;
                break;
            }
            wildcards++;
        }
    } else
        found = 1;

    if (!found) {
        qemudLog (QEMUD_ERR, "remoteCheckAccess: client's IP address (%s) is not on the list of allowed clients (tls_allowed_ip_list)", addr);
        if (!tls_no_verify_address) return -1;
        else qemudLog (QEMUD_INFO, "remoteCheckAccess: tls_no_verify_address is set so the client's IP address is ignored");
    }

    /* Checks have succeeded.  Write a '\1' byte back to the client to
     * indicate this (otherwise the socket is abruptly closed).
     * (NB. The '\1' byte is sent in an encrypted record).
     */
    client->bufferLength = 1;
    client->bufferOffset = 0;
    client->buffer[0] = '\1';
    client->mode = QEMUD_MODE_TX_PACKET;
    client->direction = QEMUD_TLS_DIRECTION_WRITE;
    return 0;
}

static int qemudDispatchServer(struct qemud_server *server, struct qemud_socket *sock) {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = (socklen_t) (sizeof addr);
    struct qemud_client *client;
    int no_slow_start = 1;

    if ((fd = accept(sock->fd, (struct sockaddr *)&addr, &addrlen)) < 0) {
        if (errno == EAGAIN)
            return 0;
        qemudLog(QEMUD_ERR, "Failed to accept connection: %s", strerror(errno));
        return -1;
    }

    /* Disable Nagle.  Unix sockets will ignore this. */
    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                sizeof no_slow_start);

    if (qemudSetCloseExec(fd) < 0 ||
        qemudSetNonBlock(fd) < 0) {
        close(fd);
        return -1;
    }

    client = calloc(1, sizeof(struct qemud_client));
    client->magic = QEMUD_CLIENT_MAGIC;
    client->fd = fd;
    client->readonly = sock->readonly;
    client->tls = sock->tls;
    memcpy (&client->addr, &addr, sizeof addr);
    client->addrlen = addrlen;

    if (!client->tls) {
        client->mode = QEMUD_MODE_RX_HEADER;
        client->bufferLength = QEMUD_PKT_HEADER_XDR_LEN;

        if (qemudRegisterClientEvent (server, client, 0) < 0)
            goto cleanup;
    } else {
        int ret;

        client->session = remoteInitializeTLSSession ();
        if (client->session == NULL)
            goto cleanup;

        gnutls_transport_set_ptr (client->session,
                                  (gnutls_transport_ptr_t) (long) fd);

        /* Begin the TLS handshake. */
        ret = gnutls_handshake (client->session);
        if (ret == 0) {
            /* Unlikely, but ...  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                goto cleanup;

            if (qemudRegisterClientEvent(server, client, 0) < 0)
                goto cleanup;
        } else if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
            /* Most likely. */
            client->mode = QEMUD_MODE_TLS_HANDSHAKE;
            client->bufferLength = -1;
            client->direction = gnutls_record_get_direction (client->session);

            if (qemudRegisterClientEvent (server, client, 0) < 0)
                goto cleanup;
        } else {
            qemudLog (QEMUD_ERR, "TLS handshake failed: %s",
                      gnutls_strerror (ret));
            goto cleanup;
        }
    }

    client->next = server->clients;
    server->clients = client;
    server->nclients++;

    return 0;

 cleanup:
    if (client->session) gnutls_deinit (client->session);
    close (fd);
    free (client);
    return -1;
}




static void qemudDispatchClientFailure(struct qemud_server *server, struct qemud_client *client) {
    struct qemud_client *tmp = server->clients;
    struct qemud_client *prev = NULL;
    while (tmp) {
        if (tmp == client) {
            if (prev == NULL)
                server->clients = client->next;
            else
                prev->next = client->next;
            server->nclients--;
            break;
        }
        prev = tmp;
        tmp = tmp->next;
    }

    virEventRemoveHandleImpl(client->fd);

    if (client->conn)
        virConnectClose(client->conn);

    if (client->tls && client->session) gnutls_deinit (client->session);
    close(client->fd);
    free(client);
}



static int qemudClientRead(struct qemud_server *server,
                           struct qemud_client *client) {
    int ret, len;
    char *data;

    data = client->buffer + client->bufferOffset;
    len = client->bufferLength - client->bufferOffset;

    /*qemudDebug ("qemudClientRead: len = %d", len);*/

    if (!client->tls) {
        if ((ret = read (client->fd, data, len)) <= 0) {
            if (ret == 0 || errno != EAGAIN) {
                if (ret != 0)
                    qemudLog (QEMUD_ERR, "read: %s", strerror (errno));
                qemudDispatchClientFailure(server, client);
            }
            return -1;
        }
    } else {
        ret = gnutls_record_recv (client->session, data, len);
        client->direction = gnutls_record_get_direction (client->session);
        if (qemudRegisterClientEvent (server, client, 1) < 0)
            qemudDispatchClientFailure (server, client);
        else if (ret <= 0) {
            if (ret == 0 || (ret != GNUTLS_E_AGAIN &&
                             ret != GNUTLS_E_INTERRUPTED)) {
                if (ret != 0)
                    qemudLog (QEMUD_ERR, "gnutls_record_recv: %s",
                              gnutls_strerror (ret));
                qemudDispatchClientFailure (server, client);
            }
            return -1;
        }
    }

    client->bufferOffset += ret;
    return 0;
}

static void qemudDispatchClientRead(struct qemud_server *server, struct qemud_client *client) {

    /*qemudDebug ("qemudDispatchClientRead: mode = %d", client->mode);*/

    switch (client->mode) {
    case QEMUD_MODE_RX_HEADER: {
        XDR x;
        qemud_packet_header h;

        if (qemudClientRead(server, client) < 0)
            return; /* Error, or blocking */

        if (client->bufferOffset < client->bufferLength)
            return; /* Not read enough */

        xdrmem_create(&x, client->buffer, client->bufferLength, XDR_DECODE);

        if (!xdr_qemud_packet_header(&x, &h)) {
            qemudDebug("Failed to decode packet header");
            qemudDispatchClientFailure(server, client);
            return;
        }

        if (h.prog != REMOTE_PROGRAM) {
            qemudDebug("Header magic %x mismatch", h.prog);
            qemudDispatchClientFailure(server, client);
            return;
        }

        /* NB: h.length is unsigned. */
        if (h.length > REMOTE_MESSAGE_MAX) {
            qemudDebug("Packet length %u too large", h.length);
            qemudDispatchClientFailure(server, client);
            return;
        }

        client->mode = QEMUD_MODE_RX_PAYLOAD;
        client->bufferLength = h.length;
        if (client->tls) client->direction = QEMUD_TLS_DIRECTION_READ;
        /* Note that we don't reset bufferOffset here because we want
         * to retain the whole message, including header.
         */

        xdr_destroy (&x);

        if (qemudRegisterClientEvent(server, client, 1) < 0) {
            qemudDispatchClientFailure(server, client);
            return;
        }

        /* Fall through */
    }

    case QEMUD_MODE_RX_PAYLOAD: {
        XDR x;
        qemud_packet_header h;

        if (qemudClientRead(server, client) < 0)
            return; /* Error, or blocking */

        if (client->bufferOffset < client->bufferLength)
            return; /* Not read enough */

        /* Reparse the header to decide if this is for qemud or remote. */
        xdrmem_create(&x, client->buffer, client->bufferLength, XDR_DECODE);

        if (!xdr_qemud_packet_header(&x, &h)) {
            qemudDebug("Failed to decode packet header");
            qemudDispatchClientFailure(server, client);
            return;
        }

        if (h.prog == REMOTE_PROGRAM) {
            remoteDispatchClientRequest (server, client);
            if (qemudRegisterClientEvent(server, client, 1) < 0)
                qemudDispatchClientFailure(server, client);
        } else {
            /* An internal error. */
            qemudDebug ("Not REMOTE_PROGRAM");
            qemudDispatchClientFailure(server, client);
        }

        xdr_destroy (&x);

        break;
    }

    case QEMUD_MODE_TLS_HANDSHAKE: {
        int ret;

        /* Continue the handshake. */
        ret = gnutls_handshake (client->session);
        if (ret == 0) {
            /* Finished.  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                qemudDispatchClientFailure (server, client);
            else if (qemudRegisterClientEvent (server, client, 1) < 0)
                qemudDispatchClientFailure (server, client);
        } else if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
            qemudLog (QEMUD_ERR, "TLS handshake failed: %s",
                      gnutls_strerror (ret));
            qemudDispatchClientFailure (server, client);
        } else {
            client->direction = gnutls_record_get_direction (client->session);
            if (qemudRegisterClientEvent (server ,client, 1) < 0)
                qemudDispatchClientFailure (server, client);
        }

        break;
    }

    default:
        qemudDebug("Got unexpected data read while in %d mode", client->mode);
        qemudDispatchClientFailure(server, client);
    }
}


static int qemudClientWrite(struct qemud_server *server,
                            struct qemud_client *client) {
    int ret, len;
    char *data;

    data = client->buffer + client->bufferOffset;
    len = client->bufferLength - client->bufferOffset;

    if (!client->tls) {
        if ((ret = write(client->fd, data, len)) == -1) {
            if (errno != EAGAIN) {
                qemudLog (QEMUD_ERR, "write: %s", strerror (errno));
                qemudDispatchClientFailure(server, client);
            }
            return -1;
        }
    } else {
        ret = gnutls_record_send (client->session, data, len);
        client->direction = gnutls_record_get_direction (client->session);
        if (qemudRegisterClientEvent (server, client, 1) < 0)
            qemudDispatchClientFailure (server, client);
        else if (ret < 0) {
            if (ret != GNUTLS_E_INTERRUPTED && ret != GNUTLS_E_AGAIN) {
                qemudLog (QEMUD_ERR, "gnutls_record_send: %s",
                          gnutls_strerror (ret));
                qemudDispatchClientFailure (server, client);
            }
            return -1;
        }
    }

    client->bufferOffset += ret;
    return 0;
}


static void qemudDispatchClientWrite(struct qemud_server *server, struct qemud_client *client) {
    switch (client->mode) {
    case QEMUD_MODE_TX_PACKET: {
        if (qemudClientWrite(server, client) < 0)
            return;

        if (client->bufferOffset == client->bufferLength) {
            /* Done writing, switch back to receive */
            client->mode = QEMUD_MODE_RX_HEADER;
            client->bufferLength = QEMUD_PKT_HEADER_XDR_LEN;
            client->bufferOffset = 0;
            if (client->tls) client->direction = QEMUD_TLS_DIRECTION_READ;

            if (qemudRegisterClientEvent (server, client, 1) < 0)
                qemudDispatchClientFailure (server, client);
        }
        /* Still writing */
        break;
    }

    case QEMUD_MODE_TLS_HANDSHAKE: {
        int ret;

        /* Continue the handshake. */
        ret = gnutls_handshake (client->session);
        if (ret == 0) {
            /* Finished.  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                qemudDispatchClientFailure (server, client);
            else if (qemudRegisterClientEvent (server, client, 1))
                qemudDispatchClientFailure (server, client);
        } else if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
            qemudLog (QEMUD_ERR, "TLS handshake failed: %s",
                      gnutls_strerror (ret));
            qemudDispatchClientFailure (server, client);
        } else {
            client->direction = gnutls_record_get_direction (client->session);
            if (qemudRegisterClientEvent (server, client, 1))
                qemudDispatchClientFailure (server, client);
        }

        break;
    }

    default:
        qemudDebug("Got unexpected data write while in %d mode", client->mode);
        qemudDispatchClientFailure(server, client);
    }
}


static void qemudDispatchClientEvent(int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_client *client = server->clients;

    while (client) {
        if (client->fd == fd)
            break;

        client = client->next;
    }

    if (!client)
        return;

    if (events == POLLOUT)
        qemudDispatchClientWrite(server, client);
    else if (events == POLLIN)
        qemudDispatchClientRead(server, client);
    else
        qemudDispatchClientFailure(server, client);
}

static int qemudRegisterClientEvent(struct qemud_server *server,
                                    struct qemud_client *client,
                                    int removeFirst) {
    if (removeFirst)
        if (virEventRemoveHandleImpl(client->fd) < 0)
            return -1;

    if (client->tls) {
        if (virEventAddHandleImpl(client->fd,
                                  (client->direction ?
                                   POLLOUT : POLLIN) | POLLERR | POLLHUP,
                                  qemudDispatchClientEvent,
                                  server) < 0)
            return -1;
    } else {
        if (virEventAddHandleImpl(client->fd,
                                  (client->mode == QEMUD_MODE_TX_PACKET ?
                                   POLLOUT : POLLIN) | POLLERR | POLLHUP,
                                  qemudDispatchClientEvent,
                                  server) < 0)
            return -1;
    }

    return 0;
}

static void qemudDispatchServerEvent(int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_socket *sock = server->sockets;

    while (sock) {
        if (sock->fd == fd)
            break;

        sock = sock->next;
    }

    if (!sock)
        return;

    if (events)
        qemudDispatchServer(server, sock);
}


static int qemudOneLoop(void) {
    sig_atomic_t errors;

    if (virEventRunOnce() < 0)
        return -1;

    /* Check for any signal handling errors and log them. */
    errors = sig_errors;
    if (errors) {
        sig_errors -= errors;
        qemudLog (QEMUD_ERR,
                  "Signal handler reported %d errors: last error: %s",
                  errors, strerror (sig_lasterrno));
        return -1;
    }

    return 0;
}

static void qemudInactiveTimer(int timer ATTRIBUTE_UNUSED, void *data) {
    struct qemud_server *server = (struct qemud_server *)data;
    qemudDebug("Got inactive timer expiry");
    if (!virStateActive()) {
        qemudDebug("No state active, shutting down");
        server->shutdown = 1;
    }
}

static int qemudRunLoop(struct qemud_server *server) {
    int timerid = -1;

    for (;;) {
        /* A shutdown timeout is specified, so check
         * if any drivers have active state, if not
         * shutdown after timeout seconds
         */
        if (timeout > 0 && !virStateActive() && !server->clients) {
            timerid = virEventAddTimeoutImpl(timeout*1000, qemudInactiveTimer, server);
            qemudDebug("Scheduling shutdown timer %d", timerid);
        }

        if (qemudOneLoop() < 0)
            break;

        /* Unregister any timeout that's active, since we
         * just had an event processed
         */
        if (timerid != -1) {
            qemudDebug("Removing shutdown timer %d", timerid);
            virEventRemoveTimeoutImpl(timerid);
            timerid = -1;
        }

        if (server->shutdown)
            return 0;
    }

    return -1;
}

static void qemudCleanup(struct qemud_server *server) {
    struct qemud_socket *sock;

    close(server->sigread);

    sock = server->sockets;
    while (sock) {
        struct qemud_socket *next = sock->next;
        close(sock->fd);
        free(sock);
        sock = next;
    }


    virStateCleanup();

    free(server);
}

/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
static int
remoteReadConfigFile (const char *filename)
{
    virConfPtr conf;

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access (filename, R_OK) == -1) return 0;

    conf = virConfReadFile (filename);
    if (!conf) return 0;

    virConfValuePtr p;

#define CHECK_TYPE(name,typ) if (p && p->type != (typ)) {               \
        qemudLog (QEMUD_ERR,                                            \
                  "remoteReadConfigFile: %s: %s: expected type " #typ "\n", \
                  filename, (name));                                    \
        return -1;                                                      \
    }

    p = virConfGetValue (conf, "listen_tls");
    CHECK_TYPE ("listen_tls", VIR_CONF_LONG);
    listen_tls = p ? p->l : listen_tls;

    p = virConfGetValue (conf, "listen_tcp");
    CHECK_TYPE ("listen_tcp", VIR_CONF_LONG);
    listen_tcp = p ? p->l : listen_tcp;

    p = virConfGetValue (conf, "tls_port");
    CHECK_TYPE ("tls_port", VIR_CONF_STRING);
    tls_port = p ? strdup (p->str) : tls_port;

    p = virConfGetValue (conf, "tcp_port");
    CHECK_TYPE ("tcp_port", VIR_CONF_STRING);
    tcp_port = p ? strdup (p->str) : tcp_port;

    p = virConfGetValue (conf, "unix_sock_group");
    CHECK_TYPE ("unix_sock_group", VIR_CONF_STRING);
    if (p && p->str) {
        if (getuid() != 0) {
            qemudLog (QEMUD_WARN, "Cannot set group when not running as root");
        } else {
            struct group *grp = getgrnam(p->str);
            if (!grp) {
                qemudLog (QEMUD_ERR, "Failed to lookup group '%s'", p->str);
                return -1;
            }
            unix_sock_gid = grp->gr_gid;
        }
    }

    p = virConfGetValue (conf, "unix_sock_ro_perms");
    CHECK_TYPE ("unix_sock_ro_perms", VIR_CONF_STRING);
    if (p && p->str) {
        char *tmp = NULL;
        unix_sock_ro_perms = strtol(p->str, &tmp, 8);
        if (*tmp) {
            qemudLog (QEMUD_ERR, "Failed to parse mode '%s'", p->str);
            return -1;
        }
    }

    p = virConfGetValue (conf, "unix_sock_rw_perms");
    CHECK_TYPE ("unix_sock_rw_perms", VIR_CONF_STRING);
    if (p && p->str) {
        char *tmp = NULL;
        unix_sock_rw_perms = strtol(p->str, &tmp, 8);
        if (*tmp) {
            qemudLog (QEMUD_ERR, "Failed to parse mode '%s'", p->str);
            return -1;
        }
    }

#ifdef HAVE_AVAHI
    p = virConfGetValue (conf, "mdns_adv");
    CHECK_TYPE ("mdns_adv", VIR_CONF_LONG);
    mdns_adv = p ? p->l : mdns_adv;

    p = virConfGetValue (conf, "mdns_name");
    CHECK_TYPE ("mdns_name", VIR_CONF_STRING);
    mdns_name = p ? strdup (p->str) : NULL;
#endif

    p = virConfGetValue (conf, "tls_no_verify_certificate");
    CHECK_TYPE ("tls_no_verify_certificate", VIR_CONF_LONG);
    tls_no_verify_certificate = p ? p->l : tls_no_verify_certificate;

    p = virConfGetValue (conf, "tls_no_verify_address");
    CHECK_TYPE ("tls_no_verify_address", VIR_CONF_LONG);
    tls_no_verify_address = p ? p->l : tls_no_verify_address;

    p = virConfGetValue (conf, "key_file");
    CHECK_TYPE ("key_file", VIR_CONF_STRING);
    key_file = p ? strdup (p->str) : key_file;

    p = virConfGetValue (conf, "cert_file");
    CHECK_TYPE ("cert_file", VIR_CONF_STRING);
    cert_file = p ? strdup (p->str) : cert_file;

    p = virConfGetValue (conf, "ca_file");
    CHECK_TYPE ("ca_file", VIR_CONF_STRING);
    ca_file = p ? strdup (p->str) : ca_file;

    p = virConfGetValue (conf, "crl_file");
    CHECK_TYPE ("crl_file", VIR_CONF_STRING);
    crl_file = p ? strdup (p->str) : crl_file;

    p = virConfGetValue (conf, "tls_allowed_dn_list");
    if (p) {
        switch (p->type) {
        case VIR_CONF_STRING:
            tls_allowed_dn_list = malloc (2 * sizeof (char *));
            tls_allowed_dn_list[0] = strdup (p->str);
            tls_allowed_dn_list[1] = 0;
            break;

        case VIR_CONF_LIST: {
            int i, len = 0;
            virConfValuePtr pp;
            for (pp = p->list; pp; pp = p->next)
                len++;
            tls_allowed_dn_list =
                malloc ((1+len) * sizeof (char *));
            for (i = 0, pp = p->list; pp; ++i, pp = p->next) {
                if (pp->type != VIR_CONF_STRING) {
                    qemudLog (QEMUD_ERR, "remoteReadConfigFile: %s: tls_allowed_dn_list: should be a string or list of strings\n", filename);
                    return -1;
                }
                tls_allowed_dn_list[i] = strdup (pp->str);
            }
            tls_allowed_dn_list[i] = 0;
            break;
        }

        default:
            qemudLog (QEMUD_ERR, "remoteReadConfigFile: %s: tls_allowed_dn_list: should be a string or list of strings\n", filename);
            return -1;
        }
    }

    p = virConfGetValue (conf, "tls_allowed_ip_list");
    if (p) {
        switch (p->type) {
        case VIR_CONF_STRING:
            tls_allowed_ip_list = malloc (2 * sizeof (char *));
            tls_allowed_ip_list[0] = strdup (p->str);
            tls_allowed_ip_list[1] = 0;
            break;

        case VIR_CONF_LIST: {
            int i, len = 0;
            virConfValuePtr pp;
            for (pp = p->list; pp; pp = p->next)
                len++;
            tls_allowed_ip_list =
                malloc ((1+len) * sizeof (char *));
            for (i = 0, pp = p->list; pp; ++i, pp = p->next) {
                if (pp->type != VIR_CONF_STRING) {
                    qemudLog (QEMUD_ERR, "remoteReadConfigFile: %s: tls_allowed_ip_list: should be a string or list of strings\n", filename);
                    return -1;
                }
                tls_allowed_ip_list[i] = strdup (pp->str);
            }
            tls_allowed_ip_list[i] = 0;
            break;
        }

        default:
            qemudLog (QEMUD_ERR, "remoteReadConfigFile: %s: tls_allowed_ip_list: should be a string or list of strings\n", filename);
            return -1;
        }
    }

    virConfFree (conf);
    return 0;
}

/* Print command-line usage. */
static void
usage (const char *argv0)
{
    fprintf (stderr,
             "\n\
Usage:\n\
  %s [options]\n\
\n\
Options:\n\
  -v | --verbose         Verbose messages.\n\
  -d | --daemon          Run as a daemon & write PID file.\n\
  -l | --listen          Listen for TCP/IP connections.\n\
  -t | --timeout <secs>  Exit after timeout period.\n\
  -f | --config <file>   Configuration file.\n\
  -p | --pid-file <file> Change name of PID file.\n\
\n\
libvirt management daemon:\n\
\n\
  Default paths:\n\
\n\
    Configuration file (unless overridden by -c):\n\
      " SYSCONF_DIR "/libvirt/libvirtd.conf\n\
\n\
    Sockets (as root):\n\
      " LOCAL_STATE_DIR "/run/libvirt/libvirt-sock\n\
      " LOCAL_STATE_DIR "/run/libvirt/libvirt-sock-ro\n\
\n\
    Sockets (as non-root):\n\
      $HOME/.libvirt/libvirt-sock (in UNIX abstract namespace)\n\
\n\
    TLS:\n\
      CA certificate:     " LIBVIRT_CACERT "\n\
      Server certificate: " LIBVIRT_SERVERCERT "\n\
      Server private key: " LIBVIRT_SERVERKEY "\n\
\n\
    PID file (unless overridden by --pid-file):\n\
      %s\n\
\n",
             argv0,
             REMOTE_PID_FILE[0] != '\0'
               ? REMOTE_PID_FILE
               : "(disabled in ./configure)");
}

#define MAX_LISTEN 5
int main(int argc, char **argv) {
    struct qemud_server *server;
    struct sigaction sig_action;
    int sigpipe[2];
    const char *pid_file = NULL;
    const char *remote_config_file = SYSCONF_DIR "/libvirt/libvirtd.conf";
    int ret = 1;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 1},
        { "daemon", no_argument, &godaemon, 1},
        { "listen", no_argument, &ipsock, 1},
        { "config", required_argument, NULL, 'f'},
        { "timeout", required_argument, NULL, 't'},
        { "pid-file", required_argument, NULL, 'p'},
        { "help", no_argument, NULL, '?' },
        {0, 0, 0, 0}
    };

    while (1) {
        int optidx = 0;
        int c;
        char *tmp;

        c = getopt_long(argc, argv, "ldf:p:t:v", opts, &optidx);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            /* Got one of the flags */
            break;
        case 'v':
            verbose = 1;
            break;
        case 'd':
            godaemon = 1;
            break;
        case 'l':
            ipsock = 1;
            break;

        case 't':
            timeout = strtol(optarg, &tmp, 10);
            if (!tmp)
                timeout = -1;
            if (timeout <= 0)
                timeout = -1;
            break;

        case 'p':
            pid_file = optarg;
            break;

        case 'f':
            remote_config_file = optarg;
            break;

        case '?':
            usage (argv[0]);
            return 2;

        default:
            fprintf (stderr, "libvirtd: internal error: unknown flag: %c\n",
                     c);
            exit (1);
        }
    }

    /* Read the config file (if it exists). */
    if (remoteReadConfigFile (remote_config_file) < 0)
        goto error1;

    if (godaemon)
        openlog("libvirtd", 0, 0);

    if (pipe(sigpipe) < 0 ||
        qemudSetNonBlock(sigpipe[0]) < 0 ||
        qemudSetNonBlock(sigpipe[1]) < 0) {
        qemudLog(QEMUD_ERR, "Failed to create pipe: %s",
                 strerror(errno));
        goto error1;
    }

    sigwrite = sigpipe[1];

    sig_action.sa_handler = sig_handler;
    sig_action.sa_flags = 0;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGHUP, &sig_action, NULL);
    sigaction(SIGINT, &sig_action, NULL);
    sigaction(SIGQUIT, &sig_action, NULL);
    sigaction(SIGTERM, &sig_action, NULL);
    sigaction(SIGCHLD, &sig_action, NULL);

    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);

    if (godaemon) {
        int pid = qemudGoDaemon();
        if (pid < 0) {
            qemudLog(QEMUD_ERR, "Failed to fork as daemon: %s",
                     strerror(errno));
            goto error1;
        }
        if (pid > 0)
            goto out;

        /* Choose the name of the PID file. */
        if (!pid_file) {
            if (REMOTE_PID_FILE[0] != '\0')
                pid_file = REMOTE_PID_FILE;
        }

        if (pid_file && qemudWritePidFile (pid_file) < 0)
            goto error1;
    }

    if (!(server = qemudInitialize(sigpipe[0]))) {
        ret = 2;
        goto error2;
    }

    if (virEventAddHandleImpl(sigpipe[0],
                              POLLIN,
                              qemudDispatchSignalEvent,
                              server) < 0) {
        qemudLog(QEMUD_ERR, "Failed to register callback for signal pipe");
        ret = 3;
        goto error2;
    }

    qemudRunLoop(server);

    qemudCleanup(server);

    close(sigwrite);

    if (godaemon)
        closelog();

 out:
    ret = 0;

 error2:
    if (godaemon && pid_file)
        unlink (pid_file);

 error1:
    return ret;
}

/*
 * Local variables:
 *  indent-tabs-mode: nil
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
