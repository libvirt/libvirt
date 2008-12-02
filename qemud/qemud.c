/*
 * qemud.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006, 2007, 2008 Red Hat, Inc.
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
#include <fnmatch.h>
#include <grp.h>
#include <signal.h>
#include <netdb.h>

#include "libvirt_internal.h"

#include "qemud.h"
#include "util.h"
#include "remote_internal.h"
#include "conf.h"
#include "event.h"
#include "memory.h"
#ifdef HAVE_AVAHI
#include "mdns.h"
#endif

#ifdef WITH_DRIVER_MODULES
#include "driver.h"
#else
#ifdef WITH_QEMU
#include "qemu_driver.h"
#endif
#ifdef WITH_LXC
#include "lxc_driver.h"
#endif
#ifdef WITH_UML
#include "uml_driver.h"
#endif
#ifdef WITH_NETWORK
#include "network_driver.h"
#endif
#ifdef WITH_STORAGE_DIR
#include "storage_driver.h"
#endif
#ifdef WITH_NODE_DEVICES
#include "node_device.h"
#endif
#endif


static int godaemon = 0;        /* -d: Be a daemon */
static int verbose = 0;         /* -v: Verbose mode */
static int timeout = -1;        /* -t: Shutdown timeout */
static int sigwrite = -1;       /* Signal handler pipe */
static int ipsock = 0;          /* -l  Listen for TCP/IP */

/* Defaults for configuration file elements */
static int listen_tls = 1;
static int listen_tcp = 0;
static char *listen_addr  = (char *) LIBVIRTD_LISTEN_ADDR;
static char *tls_port = (char *) LIBVIRTD_TLS_PORT;
static char *tcp_port = (char *) LIBVIRTD_TCP_PORT;

static gid_t unix_sock_gid = 0; /* Only root by default */
static int unix_sock_rw_mask = 0700; /* Allow user only */
static int unix_sock_ro_mask = 0777; /* Allow world */

#if HAVE_POLKIT
static int auth_unix_rw = REMOTE_AUTH_POLKIT;
static int auth_unix_ro = REMOTE_AUTH_POLKIT;
#else
static int auth_unix_rw = REMOTE_AUTH_NONE;
static int auth_unix_ro = REMOTE_AUTH_NONE;
#endif /* HAVE_POLKIT */
#if HAVE_SASL
static int auth_tcp = REMOTE_AUTH_SASL;
#else
static int auth_tcp = REMOTE_AUTH_NONE;
#endif
static int auth_tls = REMOTE_AUTH_NONE;

static int mdns_adv = 1;
static char *mdns_name = NULL;

static int tls_no_verify_certificate = 0;
static char **tls_allowed_dn_list = NULL;

static char *key_file = (char *) LIBVIRT_SERVERKEY;
static char *cert_file = (char *) LIBVIRT_SERVERCERT;
static char *ca_file = (char *) LIBVIRT_CACERT;
static char *crl_file = (char *) "";

static gnutls_certificate_credentials_t x509_cred;
static gnutls_dh_params_t dh_params;

#define DH_BITS 1024

static sig_atomic_t sig_errors = 0;
static int sig_lasterrno = 0;

static void sig_handler(int sig, siginfo_t * siginfo,
                        void* context ATTRIBUTE_UNUSED) {
    int origerrno;
    int r;

    /* set the sig num in the struct */
    siginfo->si_signo = sig;

    origerrno = errno;
    r = safewrite(sigwrite, siginfo, sizeof(*siginfo));
    if (r == -1) {
        sig_errors++;
        sig_lasterrno = errno;
    }
    errno = origerrno;
}

static void qemudDispatchClientEvent(int watch, int fd, int events, void *opaque);
static void qemudDispatchServerEvent(int watch, int fd, int events, void *opaque);
static int qemudRegisterClientEvent(struct qemud_server *server,
                                    struct qemud_client *client,
                                    int removeFirst);

static int
remoteCheckCertFile(const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        qemudLog (QEMUD_ERR, _("Cannot access %s '%s': %s (%d)"),
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
        qemudLog (QEMUD_ERR, _("gnutls_certificate_allocate_credentials: %s"),
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
            qemudLog (QEMUD_ERR, _("gnutls_certificate_set_x509_trust_file: %s"),
                      gnutls_strerror (err));
            return -1;
        }
    }

    if (crl_file && crl_file[0] != '\0') {
        if (remoteCheckCertFile("CA revocation list", crl_file) < 0)
            return -1;

        qemudDebug ("loading CRL from %s", crl_file);
        err = gnutls_certificate_set_x509_crl_file (x509_cred, crl_file,
                                                    GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            qemudLog (QEMUD_ERR, _("gnutls_certificate_set_x509_crl_file: %s"),
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
            qemudLog (QEMUD_ERR, _("gnutls_certificate_set_x509_key_file: %s"),
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
        qemudLog (QEMUD_ERR, _("gnutls_dh_params_init: %s"),
                  gnutls_strerror (err));
        return -1;
    }
    err = gnutls_dh_params_generate2 (dh_params, DH_BITS);
    if (err < 0) {
        qemudLog (QEMUD_ERR, _("gnutls_dh_params_generate2: %s"),
                  gnutls_strerror (err));
        return -1;
    }

    gnutls_certificate_set_dh_params (x509_cred, dh_params);

    return 0;
}

static void
qemudDispatchSignalEvent(int watch ATTRIBUTE_UNUSED,
                         int fd ATTRIBUTE_UNUSED,
                         int events ATTRIBUTE_UNUSED,
                         void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    siginfo_t siginfo;
    int ret;

    if (saferead(server->sigread, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        qemudLog(QEMUD_ERR, _("Failed to read from signal pipe: %s"),
                 strerror(errno));
        return;
    }

    ret = 0;

    switch (siginfo.si_signo) {
    case SIGHUP:
        qemudLog(QEMUD_INFO, "%s", _("Reloading configuration on SIGHUP"));
        if (virStateReload() < 0)
            qemudLog(QEMUD_WARN, "%s", _("Error while reloading drivers"));
        break;

    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
        qemudLog(QEMUD_WARN, _("Shutting down on signal %d"),
                 siginfo.si_signo);
        server->shutdown = 1;
        break;

    default:
        qemudLog(QEMUD_INFO, _("Received unexpected signal %d"),
                 siginfo.si_signo);
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
    qemudLog(QEMUD_ERR,
             "%s", _("Failed to set close-on-exec file descriptor flag"));
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
    qemudLog(QEMUD_ERR,
             "%s", _("Failed to set non-blocking file descriptor flag"));
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
                _exit(0);
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
            _exit(0);
        }
    }
}

static int qemudWritePidFile(const char *pidFile) {
    int fd;
    FILE *fh;

    if (pidFile[0] == '\0')
        return 0;

    if ((fd = open(pidFile, O_WRONLY|O_CREAT|O_EXCL, 0644)) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to open pid file '%s' : %s"),
                 pidFile, strerror(errno));
        return -1;
    }

    if (!(fh = fdopen(fd, "w"))) {
        qemudLog(QEMUD_ERR, _("Failed to fdopen pid file '%s' : %s"),
                 pidFile, strerror(errno));
        close(fd);
        return -1;
    }

    if (fprintf(fh, "%lu\n", (unsigned long)getpid()) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to write to pid file '%s' : %s"),
                 pidFile, strerror(errno));
        close(fd);
        return -1;
    }

    if (fclose(fh) == EOF) {
        qemudLog(QEMUD_ERR, _("Failed to close pid file '%s' : %s"),
                 pidFile, strerror(errno));
        return -1;
    }

    return 0;
}

static int qemudListenUnix(struct qemud_server *server,
                           const char *path, int readonly, int auth) {
    struct qemud_socket *sock;
    struct sockaddr_un addr;
    mode_t oldmask;
    gid_t oldgrp;

    if (VIR_ALLOC(sock) < 0) {
        qemudLog(QEMUD_ERR,
                 "%s", _("Failed to allocate memory for struct qemud_socket"));
        return -1;
    }

    sock->readonly = readonly;
    sock->port = -1;
    sock->type = QEMUD_SOCK_TYPE_UNIX;
    sock->auth = auth;

    if ((sock->fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to create socket: %s"),
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
    oldmask = umask(readonly ? ~unix_sock_ro_mask : ~unix_sock_rw_mask);
    if (getuid() == 0)
        setgid(unix_sock_gid);

    if (bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to bind socket to '%s': %s"),
                 path, strerror(errno));
        goto cleanup;
    }
    umask(oldmask);
    if (getuid() == 0)
        setgid(oldgrp);

    if (listen(sock->fd, 30) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to listen for connections on '%s': %s"),
                 path, strerror(errno));
        goto cleanup;
    }

    if ((sock->watch = virEventAddHandleImpl(sock->fd,
                                             VIR_EVENT_HANDLE_READABLE |
                                             VIR_EVENT_HANDLE_ERROR |
                                             VIR_EVENT_HANDLE_HANGUP,
                                             qemudDispatchServerEvent,
                                             server, NULL)) < 0) {
        qemudLog(QEMUD_ERR, "%s",
                 _("Failed to add server event callback"));
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
remoteMakeSockets (int *fds, int max_fds, int *nfds_r, const char *node, const char *service)
{
    struct addrinfo *ai;
    struct addrinfo hints;
    memset (&hints, 0, sizeof hints);
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    int e = getaddrinfo (node, service, &hints, &ai);
    if (e != 0) {
        qemudLog (QEMUD_ERR, _("getaddrinfo: %s\n"), gai_strerror (e));
        return -1;
    }

    struct addrinfo *runp = ai;
    while (runp && *nfds_r < max_fds) {
        fds[*nfds_r] = socket (runp->ai_family, runp->ai_socktype,
                               runp->ai_protocol);
        if (fds[*nfds_r] == -1) {
            qemudLog (QEMUD_ERR, _("socket: %s"), strerror (errno));
            return -1;
        }

        int opt = 1;
        setsockopt (fds[*nfds_r], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

        if (bind (fds[*nfds_r], runp->ai_addr, runp->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                qemudLog (QEMUD_ERR, _("bind: %s"), strerror (errno));
                return -1;
            }
            close (fds[*nfds_r]);
        }
        else {
            if (listen (fds[*nfds_r], SOMAXCONN) == -1) {
                qemudLog (QEMUD_ERR, _("listen: %s"), strerror (errno));
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
                 const char *addr,
                 const char *port,
                 int type,
                 int auth)
{
    int fds[2];
    int nfds = 0;
    int i;
    struct qemud_socket *sock;

    if (remoteMakeSockets (fds, 2, &nfds, addr, port) == -1)
        return -1;

    for (i = 0; i < nfds; ++i) {
        struct sockaddr_storage sa;
        socklen_t salen = sizeof(sa);

        if (VIR_ALLOC(sock) < 0) {
            qemudLog (QEMUD_ERR,
                      _("remoteListenTCP: calloc: %s"), strerror (errno));
            goto cleanup;
        }

        sock->readonly = 0;
        sock->next = server->sockets;
        server->sockets = sock;
        server->nsockets++;

        sock->fd = fds[i];
        sock->type = type;
        sock->auth = auth;

        if (getsockname(sock->fd, (struct sockaddr *)(&sa), &salen) < 0)
            goto cleanup;

        if (sa.ss_family == AF_INET)
            sock->port = htons(((struct sockaddr_in*)&sa)->sin_port);
#ifdef AF_INET6
        else if (sa.ss_family == AF_INET6)
            sock->port = htons(((struct sockaddr_in6*)&sa)->sin6_port);
#endif
        else
            sock->port = -1;

        if (qemudSetCloseExec(sock->fd) < 0 ||
            qemudSetNonBlock(sock->fd) < 0)
            goto cleanup;

        if (listen (sock->fd, 30) < 0) {
            qemudLog (QEMUD_ERR,
                      _("remoteListenTCP: listen: %s"), strerror (errno));
            goto cleanup;
        }

        if ((sock->watch = virEventAddHandleImpl(sock->fd,
                                                 VIR_EVENT_HANDLE_READABLE |
                                                 VIR_EVENT_HANDLE_ERROR |
                                                 VIR_EVENT_HANDLE_HANGUP,
                                                 qemudDispatchServerEvent,
                                                 server, NULL)) < 0) {
            qemudLog(QEMUD_ERR, "%s", _("Failed to add server event callback"));
            goto cleanup;
        }

    }

    return 0;

cleanup:
    for (i = 0; i < nfds; ++i)
        close(fds[0]);
    return -1;
}

static int qemudInitPaths(struct qemud_server *server,
                          char *sockname,
                          char *roSockname,
                          int maxlen) {
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
            qemudLog(QEMUD_ERR, _("Failed to find user record for uid '%d': %s"),
                     uid, strerror(errno));
            return -1;
        }

        if (snprintf(sockname, maxlen, "@%s/.libvirt/libvirt-sock", pw->pw_dir) >= maxlen)
            goto snprintf_error;

        if (snprintf(server->logDir, PATH_MAX, "%s/.libvirt/log", pw->pw_dir) >= PATH_MAX)
            goto snprintf_error;

    } /* !remote */

    return 0;

 snprintf_error:
    qemudLog(QEMUD_ERR,
             "%s", _("Resulting path too long for buffer in qemudInitPaths()"));
    return -1;
}

static struct qemud_server *qemudInitialize(int sigread) {
    struct qemud_server *server;

    if (VIR_ALLOC(server) < 0) {
        qemudLog(QEMUD_ERR, "%s", _("Failed to allocate struct qemud_server"));
        return NULL;
    }

    server->sigread = sigread;

    virInitialize();

    /*
     * Note that the order is important: the first ones have a higher
     * priority when calling virStateInitialize. We must register
     * the network, storage and nodedev drivers before any domain
     * drivers, since their resources must be auto-started before
     * any domains can be auto-started.
     */
#ifdef WITH_DRIVER_MODULES
    /* We don't care if any of these fail, because the whole point
     * is to allow users to only install modules they want to use.
     * If they try to use a open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
    virDriverLoadModule("network");
    virDriverLoadModule("storage");
    virDriverLoadModule("nodedev");
    virDriverLoadModule("qemu");
    virDriverLoadModule("lxc");
    virDriverLoadModule("uml");
#else
#ifdef WITH_NETWORK
    networkRegister();
#endif
#ifdef WITH_STORAGE_DIR
    storageRegister();
#endif
#if defined(HAVE_HAL) || defined(HAVE_DEVKIT)
    nodedevRegister();
#endif
#ifdef WITH_QEMU
    qemuRegister();
#endif
#ifdef WITH_LXC
    lxcRegister();
#endif
#ifdef WITH_UML
    umlRegister();
#endif
#endif

    virEventRegisterImpl(virEventAddHandleImpl,
                         virEventUpdateHandleImpl,
                         virEventRemoveHandleImpl,
                         virEventAddTimeoutImpl,
                         virEventUpdateTimeoutImpl,
                         virEventRemoveTimeoutImpl);

    virStateInitialize();

    return server;
}

static struct qemud_server *qemudNetworkInit(struct qemud_server *server) {
    struct qemud_socket *sock;
    char sockname[PATH_MAX];
    char roSockname[PATH_MAX];
#if HAVE_SASL
    int err;
#endif /* HAVE_SASL */

    roSockname[0] = '\0';

    if (qemudInitPaths(server, sockname, roSockname, PATH_MAX) < 0)
        goto cleanup;

    if (qemudListenUnix(server, sockname, 0, auth_unix_rw) < 0)
        goto cleanup;

    if (roSockname[0] != '\0' && qemudListenUnix(server, roSockname, 1, auth_unix_ro) < 0)
        goto cleanup;

#if HAVE_SASL
    if (auth_unix_rw == REMOTE_AUTH_SASL ||
        auth_unix_ro == REMOTE_AUTH_SASL ||
        auth_tcp == REMOTE_AUTH_SASL ||
        auth_tls == REMOTE_AUTH_SASL) {
        if ((err = sasl_server_init(NULL, "libvirt")) != SASL_OK) {
            qemudLog(QEMUD_ERR,
                     _("Failed to initialize SASL authentication %s"),
                     sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
    }
#endif

#ifdef HAVE_POLKIT
    if (auth_unix_rw == REMOTE_AUTH_POLKIT ||
        auth_unix_ro == REMOTE_AUTH_POLKIT) {
        DBusError derr;
        dbus_error_init(&derr);
        server->sysbus = dbus_bus_get(DBUS_BUS_SYSTEM, &derr);
        if (!(server->sysbus)) {
            qemudLog(QEMUD_ERR,
                     _("Failed to connect to system bus for PolicyKit auth: %s"),
                     derr.message);
            dbus_error_free(&derr);
            goto cleanup;
        }
    }
#endif

    if (ipsock) {
        if (listen_tcp && remoteListenTCP (server, listen_addr, tcp_port, QEMUD_SOCK_TYPE_TCP, auth_tcp) < 0)
            goto cleanup;

        if (listen_tls) {
            if (remoteInitializeGnuTLS () < 0)
                goto cleanup;

            if (remoteListenTCP (server, listen_addr, tls_port, QEMUD_SOCK_TYPE_TLS, auth_tls) < 0)
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
            if (sock->port != -1 && sock->type == QEMUD_SOCK_TYPE_TLS) {
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

#ifdef HAVE_POLKIT
        if (server->sysbus)
            dbus_connection_unref(server->sysbus);
#endif
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
  qemudLog (QEMUD_ERR, _("remoteInitializeTLSSession: %s"),
            gnutls_strerror (err));
  return NULL;
}

/* Check DN is on tls_allowed_dn_list. */
static int
remoteCheckDN (gnutls_x509_crt_t cert)
{
    char name[256];
    size_t namesize = sizeof name;
    char **wildcards;
    int err;

    err = gnutls_x509_crt_get_dn (cert, name, &namesize);
    if (err != 0) {
        qemudLog (QEMUD_ERR,
                  _("remoteCheckDN: gnutls_x509_cert_get_dn: %s"),
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
              _("remoteCheckDN: failed: client DN is %s"), name);
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
        qemudLog (QEMUD_ERR, _("remoteCheckCertificate: verify failed: %s"),
                  gnutls_strerror (ret));
        return -1;
    }

    if (status != 0) {
        if (status & GNUTLS_CERT_INVALID)
            qemudLog (QEMUD_ERR, "%s",
                      _("remoteCheckCertificate: "
                        "the client certificate is not trusted."));

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            qemudLog (QEMUD_ERR, "%s",
                      _("remoteCheckCertificate: the client "
                        "certificate has unknown issuer."));

        if (status & GNUTLS_CERT_REVOKED)
            qemudLog (QEMUD_ERR, "%s",
                      _("remoteCheckCertificate: "
                        "the client certificate has been revoked."));

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            qemudLog (QEMUD_ERR, "%s",
                      _("remoteCheckCertificate: the client certificate"
                        " uses an insecure algorithm."));
#endif

        return -1;
    }

    if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509) {
        qemudLog (QEMUD_ERR,
                  "%s", _("remoteCheckCertificate: certificate is not X.509"));
        return -1;
    }

    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        qemudLog (QEMUD_ERR, "%s", _("remoteCheckCertificate: no peers"));
        return -1;
    }

    now = time (NULL);

    for (i = 0; i < nCerts; i++) {
        gnutls_x509_crt_t cert;

        if (gnutls_x509_crt_init (&cert) < 0) {
            qemudLog (QEMUD_ERR, "%s",
                      _("remoteCheckCertificate: gnutls_x509_crt_init failed"));
            return -1;
        }

        if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            qemudLog (QEMUD_ERR, "%s", _("remoteCheckCertificate: "
                                         "the client certificate has expired"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            qemudLog (QEMUD_ERR, "%s", _("remoteCheckCertificate: the client "
                                         "certificate is not yet activated"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (i == 0) {
            if (!remoteCheckDN (cert)) {
                /* This is the most common error: make it informative. */
                qemudLog (QEMUD_ERR, "%s", _("remoteCheckCertificate: client's Distinguished Name is not on the list of allowed clients (tls_allowed_dn_list).  Use 'openssl x509 -in clientcert.pem -text' to view the Distinguished Name field in the client certificate, or run this daemon with --verbose option."));
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
    /* Verify client certificate. */
    if (remoteCheckCertificate (client->tlssession) == -1) {
        qemudLog (QEMUD_ERR, "%s",
                  _("remoteCheckCertificate: "
                    "failed to verify client's certificate"));
        if (!tls_no_verify_certificate) return -1;
        else qemudLog (QEMUD_INFO, "%s",
                       _("remoteCheckCertificate: tls_no_verify_certificate "
                         "is set so the bad certificate is ignored"));
    }

    /* Checks have succeeded.  Write a '\1' byte back to the client to
     * indicate this (otherwise the socket is abruptly closed).
     * (NB. The '\1' byte is sent in an encrypted record).
     */
    client->bufferLength = 1;
    client->bufferOffset = 0;
    client->buffer[0] = '\1';
    client->mode = QEMUD_MODE_TX_PACKET;
    return 0;
}

#if HAVE_POLKIT
int qemudGetSocketIdentity(int fd, uid_t *uid, pid_t *pid) {
#ifdef SO_PEERCRED
    struct ucred cr;
    unsigned int cr_len = sizeof (cr);

    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to verify client credentials: %s"),
                 strerror(errno));
        return -1;
    }

    *pid = cr.pid;
    *uid = cr.uid;
#else
    /* XXX Many more OS support UNIX socket credentials we could port to. See dbus ....*/
#error "UNIX socket credentials not supported/implemented on this platform yet..."
#endif
    return 0;
}
#endif

static int qemudDispatchServer(struct qemud_server *server, struct qemud_socket *sock) {
    int fd;
    struct sockaddr_storage addr;
    socklen_t addrlen = (socklen_t) (sizeof addr);
    struct qemud_client *client;
    int no_slow_start = 1;

    if ((fd = accept(sock->fd, (struct sockaddr *)&addr, &addrlen)) < 0) {
        if (errno == EAGAIN)
            return 0;
        qemudLog(QEMUD_ERR, _("Failed to accept connection: %s"), strerror(errno));
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

    if (VIR_ALLOC(client) < 0)
        goto cleanup;
    client->magic = QEMUD_CLIENT_MAGIC;
    client->fd = fd;
    client->readonly = sock->readonly;
    client->type = sock->type;
    client->auth = sock->auth;
    memcpy (&client->addr, &addr, sizeof addr);
    client->addrlen = addrlen;
    client->server = server;

#if HAVE_POLKIT
    /* Only do policy checks for non-root - allow root user
       through with no checks, as a fail-safe - root can easily
       change policykit policy anyway, so its pointless trying
       to restrict root */
    if (client->auth == REMOTE_AUTH_POLKIT) {
        uid_t uid;
        pid_t pid;

        if (qemudGetSocketIdentity(client->fd, &uid, &pid) < 0)
            goto cleanup;

        /* Client is running as root, so disable auth */
        if (uid == 0) {
            qemudLog(QEMUD_INFO, _("Turn off polkit auth for privileged client %d"), pid);
            client->auth = REMOTE_AUTH_NONE;
        }
    }
#endif

    if (client->type != QEMUD_SOCK_TYPE_TLS) {
        client->mode = QEMUD_MODE_RX_HEADER;
        client->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;

        if (qemudRegisterClientEvent (server, client, 0) < 0)
            goto cleanup;
    } else {
        int ret;

        client->tlssession = remoteInitializeTLSSession ();
        if (client->tlssession == NULL)
            goto cleanup;

        gnutls_transport_set_ptr (client->tlssession,
                                  (gnutls_transport_ptr_t) (long) fd);

        /* Begin the TLS handshake. */
        ret = gnutls_handshake (client->tlssession);
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

            if (qemudRegisterClientEvent (server, client, 0) < 0)
                goto cleanup;
        } else {
            qemudLog (QEMUD_ERR, _("TLS handshake failed: %s"),
                      gnutls_strerror (ret));
            goto cleanup;
        }
    }

    client->next = server->clients;
    server->clients = client;
    server->nclients++;

    return 0;

 cleanup:
    if (client->tlssession) gnutls_deinit (client->tlssession);
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

    virEventRemoveHandleImpl(client->watch);

    /* Deregister event delivery callback */
    if(client->conn) {
        qemudDebug("Deregistering to relay remote events");
        virConnectDomainEventDeregister(client->conn, remoteRelayDomainEvent);
    }

    if (client->conn)
        virConnectClose(client->conn);

#if HAVE_SASL
    if (client->saslconn) sasl_dispose(&client->saslconn);
    free(client->saslUsername);
#endif
    if (client->tlssession) gnutls_deinit (client->tlssession);
    close(client->fd);
    free(client);
}



static int qemudClientReadBuf(struct qemud_server *server,
                              struct qemud_client *client,
                              char *data, unsigned len) {
    int ret;

    /*qemudDebug ("qemudClientRead: len = %d", len);*/

    if (!client->tlssession) {
        if ((ret = read (client->fd, data, len)) <= 0) {
            if (ret == 0 || errno != EAGAIN) {
                if (ret != 0)
                    qemudLog (QEMUD_ERR, _("read: %s"), strerror (errno));
                qemudDispatchClientFailure(server, client);
            }
            return -1;
        }
    } else {
        ret = gnutls_record_recv (client->tlssession, data, len);
        if (qemudRegisterClientEvent (server, client, 1) < 0)
            qemudDispatchClientFailure (server, client);
        else if (ret <= 0) {
            if (ret == 0 || (ret != GNUTLS_E_AGAIN &&
                             ret != GNUTLS_E_INTERRUPTED)) {
                if (ret != 0)
                    qemudLog (QEMUD_ERR, _("gnutls_record_recv: %s"),
                              gnutls_strerror (ret));
                qemudDispatchClientFailure (server, client);
            }
            return -1;
        }
    }

    return ret;
}

static int qemudClientReadPlain(struct qemud_server *server,
                                struct qemud_client *client) {
    int ret;
    ret = qemudClientReadBuf(server, client,
                             client->buffer + client->bufferOffset,
                             client->bufferLength - client->bufferOffset);
    if (ret < 0)
        return ret;
    client->bufferOffset += ret;
    return 0;
}

#if HAVE_SASL
static int qemudClientReadSASL(struct qemud_server *server,
                               struct qemud_client *client) {
    int got, want;

    /* We're doing a SSF data read, so now its times to ensure
     * future writes are under SSF too.
     *
     * cf remoteSASLCheckSSF in remote.c
     */
    client->saslSSF |= QEMUD_SASL_SSF_WRITE;

    /* Need to read some more data off the wire */
    if (client->saslDecoded == NULL) {
        char encoded[8192];
        int encodedLen = sizeof(encoded);
        encodedLen = qemudClientReadBuf(server, client, encoded, encodedLen);

        if (encodedLen < 0)
            return -1;

        sasl_decode(client->saslconn, encoded, encodedLen,
                    &client->saslDecoded, &client->saslDecodedLength);

        client->saslDecodedOffset = 0;
    }

    /* Some buffered decoded data to return now */
    got = client->saslDecodedLength - client->saslDecodedOffset;
    want = client->bufferLength - client->bufferOffset;

    if (want > got)
        want = got;

    memcpy(client->buffer + client->bufferOffset,
           client->saslDecoded + client->saslDecodedOffset, want);
    client->saslDecodedOffset += want;
    client->bufferOffset += want;

    if (client->saslDecodedOffset == client->saslDecodedLength) {
        client->saslDecoded = NULL;
        client->saslDecodedOffset = client->saslDecodedLength = 0;
    }

    return 0;
}
#endif

static int qemudClientRead(struct qemud_server *server,
                           struct qemud_client *client) {
#if HAVE_SASL
    if (client->saslSSF & QEMUD_SASL_SSF_READ)
        return qemudClientReadSASL(server, client);
    else
#endif
        return qemudClientReadPlain(server, client);
}


static void qemudDispatchClientRead(struct qemud_server *server, struct qemud_client *client) {

    /*qemudDebug ("qemudDispatchClientRead: mode = %d", client->mode);*/

    switch (client->mode) {
    case QEMUD_MODE_RX_HEADER: {
        XDR x;
        unsigned int len;

        if (qemudClientRead(server, client) < 0)
            return; /* Error, or blocking */

        if (client->bufferOffset < client->bufferLength)
            return; /* Not read enough */

        xdrmem_create(&x, client->buffer, client->bufferLength, XDR_DECODE);

        if (!xdr_u_int(&x, &len)) {
            xdr_destroy (&x);
            qemudDebug("Failed to decode packet length");
            qemudDispatchClientFailure(server, client);
            return;
        }
        xdr_destroy (&x);

        if (len > REMOTE_MESSAGE_MAX) {
            qemudDebug("Packet length %u too large", len);
            qemudDispatchClientFailure(server, client);
            return;
        }

        /* Length include length of the length field itself, so
         * check minimum size requirements */
        if (len <= REMOTE_MESSAGE_HEADER_XDR_LEN) {
            qemudDebug("Packet length %u too small", len);
            qemudDispatchClientFailure(server, client);
            return;
        }

        client->mode = QEMUD_MODE_RX_PAYLOAD;
        client->bufferLength = len - REMOTE_MESSAGE_HEADER_XDR_LEN;
        client->bufferOffset = 0;

        if (qemudRegisterClientEvent(server, client, 1) < 0) {
            qemudDispatchClientFailure(server, client);
            return;
        }

        /* Fall through */
    }

    case QEMUD_MODE_RX_PAYLOAD: {
        if (qemudClientRead(server, client) < 0)
            return; /* Error, or blocking */

        if (client->bufferOffset < client->bufferLength)
            return; /* Not read enough */

        remoteDispatchClientRequest (server, client);
        if (qemudRegisterClientEvent(server, client, 1) < 0)
            qemudDispatchClientFailure(server, client);

        break;
    }

    case QEMUD_MODE_TLS_HANDSHAKE: {
        int ret;

        /* Continue the handshake. */
        ret = gnutls_handshake (client->tlssession);
        if (ret == 0) {
            /* Finished.  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                qemudDispatchClientFailure (server, client);
            else if (qemudRegisterClientEvent (server, client, 1) < 0)
                qemudDispatchClientFailure (server, client);
        } else if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
            qemudLog (QEMUD_ERR, _("TLS handshake failed: %s"),
                      gnutls_strerror (ret));
            qemudDispatchClientFailure (server, client);
        } else {
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


static int qemudClientWriteBuf(struct qemud_server *server,
                               struct qemud_client *client,
                               const char *data, int len) {
    int ret;
    if (!client->tlssession) {
        if ((ret = safewrite(client->fd, data, len)) == -1) {
            qemudLog (QEMUD_ERR, _("write: %s"), strerror (errno));
            qemudDispatchClientFailure(server, client);
            return -1;
        }
    } else {
        ret = gnutls_record_send (client->tlssession, data, len);
        if (qemudRegisterClientEvent (server, client, 1) < 0)
            qemudDispatchClientFailure (server, client);
        else if (ret < 0) {
            if (ret != GNUTLS_E_INTERRUPTED && ret != GNUTLS_E_AGAIN) {
                qemudLog (QEMUD_ERR, _("gnutls_record_send: %s"),
                          gnutls_strerror (ret));
                qemudDispatchClientFailure (server, client);
            }
            return -1;
        }
    }
    return ret;
}


static int qemudClientWritePlain(struct qemud_server *server,
                                 struct qemud_client *client) {
    int ret = qemudClientWriteBuf(server, client,
                                  client->buffer + client->bufferOffset,
                                  client->bufferLength - client->bufferOffset);
    if (ret < 0)
        return -1;
    client->bufferOffset += ret;
    return 0;
}


#if HAVE_SASL
static int qemudClientWriteSASL(struct qemud_server *server,
                                struct qemud_client *client) {
    int ret;

    /* Not got any pending encoded data, so we need to encode raw stuff */
    if (client->saslEncoded == NULL) {
        int err;
        err = sasl_encode(client->saslconn,
                          client->buffer + client->bufferOffset,
                          client->bufferLength - client->bufferOffset,
                          &client->saslEncoded,
                          &client->saslEncodedLength);

        client->saslEncodedOffset = 0;
    }

    /* Send some of the encoded stuff out on the wire */
    ret = qemudClientWriteBuf(server, client,
                              client->saslEncoded + client->saslEncodedOffset,
                              client->saslEncodedLength - client->saslEncodedOffset);

    if (ret < 0)
        return -1;

    /* Note how much we sent */
    client->saslEncodedOffset += ret;

    /* Sent all encoded, so update raw buffer to indicate completion */
    if (client->saslEncodedOffset == client->saslEncodedLength) {
        client->saslEncoded = NULL;
        client->saslEncodedOffset = client->saslEncodedLength = 0;
        client->bufferOffset = client->bufferLength;
    }

    return 0;
}
#endif

static int qemudClientWrite(struct qemud_server *server,
                            struct qemud_client *client) {
#if HAVE_SASL
    if (client->saslSSF & QEMUD_SASL_SSF_WRITE)
        return qemudClientWriteSASL(server, client);
    else
#endif
        return qemudClientWritePlain(server, client);
}


void
qemudDispatchClientWrite(struct qemud_server *server,
                         struct qemud_client *client) {
    switch (client->mode) {
    case QEMUD_MODE_TX_PACKET: {
        if (qemudClientWrite(server, client) < 0)
            return;

        if (client->bufferOffset == client->bufferLength) {
            /* Done writing, switch back to receive */
            client->mode = QEMUD_MODE_RX_HEADER;
            client->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;
            client->bufferOffset = 0;

            if (qemudRegisterClientEvent (server, client, 1) < 0)
                qemudDispatchClientFailure (server, client);
        }
        /* Still writing */
        break;
    }

    case QEMUD_MODE_TLS_HANDSHAKE: {
        int ret;

        /* Continue the handshake. */
        ret = gnutls_handshake (client->tlssession);
        if (ret == 0) {
            /* Finished.  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                qemudDispatchClientFailure (server, client);
            else if (qemudRegisterClientEvent (server, client, 1))
                qemudDispatchClientFailure (server, client);
        } else if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED) {
            qemudLog (QEMUD_ERR, _("TLS handshake failed: %s"),
                      gnutls_strerror (ret));
            qemudDispatchClientFailure (server, client);
        } else {
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


static void
qemudDispatchClientEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_client *client = server->clients;

    while (client) {
        if (client->watch == watch)
            break;

        client = client->next;
    }

    if (!client)
        return;

    if (client->fd != fd)
        return;

    if (events == VIR_EVENT_HANDLE_WRITABLE)
        qemudDispatchClientWrite(server, client);
    else if (events == VIR_EVENT_HANDLE_READABLE)
        qemudDispatchClientRead(server, client);
    else
        qemudDispatchClientFailure(server, client);
}

static int qemudRegisterClientEvent(struct qemud_server *server,
                                    struct qemud_client *client,
                                    int removeFirst) {
    int mode;
    switch (client->mode) {
    case QEMUD_MODE_TLS_HANDSHAKE:
        if (gnutls_record_get_direction (client->tlssession) == 0)
            mode = VIR_EVENT_HANDLE_READABLE;
        else
            mode = VIR_EVENT_HANDLE_WRITABLE;
        break;

    case QEMUD_MODE_RX_HEADER:
    case QEMUD_MODE_RX_PAYLOAD:
        mode = VIR_EVENT_HANDLE_READABLE;
        break;

    case QEMUD_MODE_TX_PACKET:
        mode = VIR_EVENT_HANDLE_WRITABLE;
        break;

    default:
        return -1;
    }

    if (removeFirst)
        if (virEventRemoveHandleImpl(client->watch) < 0)
            return -1;

    if ((client->watch = virEventAddHandleImpl(client->fd,
                                               mode | VIR_EVENT_HANDLE_ERROR |
                                               VIR_EVENT_HANDLE_HANGUP,
                                               qemudDispatchClientEvent,
                                               server, NULL)) < 0)
            return -1;

    return 0;
}

static void
qemudDispatchServerEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_socket *sock = server->sockets;

    while (sock) {
        if (sock->watch == watch)
            break;

        sock = sock->next;
    }

    if (!sock)
        return;

    if (sock->fd != fd)
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
                  _("Signal handler reported %d errors: last error: %s"),
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
            timerid = virEventAddTimeoutImpl(timeout*1000,
                                             qemudInactiveTimer,
                                             server, NULL);
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

#ifdef HAVE_SASL
    if (server->saslUsernameWhitelist) {
        char **list = server->saslUsernameWhitelist;
        while (*list) {
            free(*list);
            list++;
        }
        free(server->saslUsernameWhitelist);
    }
#endif

    virStateCleanup();

    free(server);
}

/* Allocate an array of malloc'd strings from the config file, filename
 * (used only in diagnostics), using handle "conf".  Upon error, return -1
 * and free any allocated memory.  Otherwise, save the array in *list_arg
 * and return 0.
 */
static int
remoteConfigGetStringList(virConfPtr conf, const char *key, char ***list_arg,
                          const char *filename)
{
    char **list;
    virConfValuePtr p = virConfGetValue (conf, key);
    if (!p)
        return 0;

    switch (p->type) {
    case VIR_CONF_STRING:
        if (VIR_ALLOC_N(list, 2) < 0) {
            qemudLog (QEMUD_ERR,
                      _("failed to allocate memory for %s config list"), key);
            return -1;
        }
        list[0] = strdup (p->str);
        list[1] = NULL;
        if (list[0] == NULL) {
            qemudLog (QEMUD_ERR,
                      _("failed to allocate memory for %s config list value"),
                      key);
            VIR_FREE(list);
            return -1;
        }
        break;

    case VIR_CONF_LIST: {
        int i, len = 0;
        virConfValuePtr pp;
        for (pp = p->list; pp; pp = pp->next)
            len++;
        if (VIR_ALLOC_N(list, 1+len) < 0) {
            qemudLog (QEMUD_ERR,
                      _("failed to allocate memory for %s config list"), key);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                qemudLog (QEMUD_ERR, _("remoteReadConfigFile: %s: %s:"
                          " must be a string or list of strings\n"),
                          filename, key);
                VIR_FREE(list);
                return -1;
            }
            list[i] = strdup (pp->str);
            if (list[i] == NULL) {
                int j;
                for (j = 0 ; j < i ; j++)
                    VIR_FREE(list[j]);
                VIR_FREE(list);
                qemudLog (QEMUD_ERR, _("failed to allocate memory"
                                       " for %s config list value"), key);
                return -1;
            }

        }
        list[i] = NULL;
        break;
    }

    default:
        qemudLog (QEMUD_ERR, _("remoteReadConfigFile: %s: %s:"
                               " must be a string or list of strings\n"),
                  filename, key);
        return -1;
    }

    *list_arg = list;
    return 0;
}

/* A helper function used by each of the following macros.  */
static int
checkType (virConfValuePtr p, const char *filename,
           const char *key, virConfType required_type)
{
    if (p->type != required_type) {
        qemudLog (QEMUD_ERR,
                  _("remoteReadConfigFile: %s: %s: invalid type:"
                    " got %s; expected %s\n"), filename, key,
                  virConfTypeName (p->type),
                  virConfTypeName (required_type));
        return -1;
    }
    return 0;
}

/* If there is no config data for the key, #var_name, then do nothing.
   If there is valid data of type VIR_CONF_STRING, and strdup succeeds,
   store the result in var_name.  Otherwise, (i.e. invalid type, or strdup
   failure), give a diagnostic and "goto" the cleanup-and-fail label.  */
#define GET_CONF_STR(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue (conf, #var_name);          \
        if (p) {                                                        \
            if (checkType (p, filename, #var_name, VIR_CONF_STRING) < 0) \
                goto free_and_fail;                                     \
            (var_name) = strdup (p->str);                               \
            if ((var_name) == NULL) {                                   \
                qemudLog (QEMUD_ERR, _("remoteReadConfigFile: %s\n"),   \
                          strerror (errno));                            \
                goto free_and_fail;                                     \
            }                                                           \
        }                                                               \
    } while (0)

/* Like GET_CONF_STR, but for integral values.  */
#define GET_CONF_INT(conf, filename, var_name)                          \
    do {                                                                \
        virConfValuePtr p = virConfGetValue (conf, #var_name);          \
        if (p) {                                                        \
            if (checkType (p, filename, #var_name, VIR_CONF_LONG) < 0)  \
                goto free_and_fail;                                     \
            (var_name) = p->l;                                          \
        }                                                               \
    } while (0)


static int remoteConfigGetAuth(virConfPtr conf, const char *key, int *auth, const char *filename) {
    virConfValuePtr p;

    p = virConfGetValue (conf, key);
    if (!p)
        return 0;

    if (checkType (p, filename, key, VIR_CONF_STRING) < 0)
        return -1;

    if (!p->str)
        return 0;

    if (STREQ(p->str, "none")) {
        *auth = REMOTE_AUTH_NONE;
#if HAVE_SASL
    } else if (STREQ(p->str, "sasl")) {
        *auth = REMOTE_AUTH_SASL;
#endif
#if HAVE_POLKIT
    } else if (STREQ(p->str, "polkit")) {
        *auth = REMOTE_AUTH_POLKIT;
#endif
    } else {
        qemudLog (QEMUD_ERR,
                  _("remoteReadConfigFile: %s: %s: unsupported auth %s\n"),
                  filename, key, p->str);
        return -1;
    }

    return 0;
}

#ifdef HAVE_SASL
static inline int
remoteReadSaslAllowedUsernameList (virConfPtr conf,
                                   struct qemud_server *server,
                                   const char *filename)
{
    return
        remoteConfigGetStringList (conf, "sasl_allowed_username_list",
                                   &server->saslUsernameWhitelist, filename);
}
#else
static inline int
remoteReadSaslAllowedUsernameList (virConfPtr conf ATTRIBUTE_UNUSED,
                                   struct qemud_server *server ATTRIBUTE_UNUSED,
                                   const char *filename ATTRIBUTE_UNUSED)
{
    return 0;
}
#endif


/* Read the config file if it exists.
 * Only used in the remote case, hence the name.
 */
static int
remoteReadConfigFile (struct qemud_server *server, const char *filename)
{
    virConfPtr conf;

    /* The following variable names must match the corresponding
       configuration strings.  */
    char *unix_sock_ro_perms = NULL;
    char *unix_sock_rw_perms = NULL;
    char *unix_sock_group = NULL;

#if HAVE_POLKIT
    /* Change the default back to no auth for non-root */
    if (getuid() != 0 && auth_unix_rw == REMOTE_AUTH_POLKIT)
        auth_unix_rw = REMOTE_AUTH_NONE;
    if (getuid() != 0 && auth_unix_ro == REMOTE_AUTH_POLKIT)
        auth_unix_ro = REMOTE_AUTH_NONE;
#endif

    /* Just check the file is readable before opening it, otherwise
     * libvirt emits an error.
     */
    if (access (filename, R_OK) == -1) return 0;

    conf = virConfReadFile (filename);
    if (!conf) return 0;

    GET_CONF_INT (conf, filename, listen_tcp);
    GET_CONF_INT (conf, filename, listen_tls);
    GET_CONF_STR (conf, filename, tls_port);
    GET_CONF_STR (conf, filename, tcp_port);
    GET_CONF_STR (conf, filename, listen_addr);

    if (remoteConfigGetAuth(conf, "auth_unix_rw", &auth_unix_rw, filename) < 0)
        goto free_and_fail;
#if HAVE_POLKIT
    /* Change default perms to be wide-open if PolicyKit is enabled.
     * Admin can always override in config file
     */
    if (auth_unix_rw == REMOTE_AUTH_POLKIT)
        unix_sock_rw_mask = 0777;
#endif
    if (remoteConfigGetAuth(conf, "auth_unix_ro", &auth_unix_ro, filename) < 0)
        goto free_and_fail;
    if (remoteConfigGetAuth(conf, "auth_tcp", &auth_tcp, filename) < 0)
        goto free_and_fail;
    if (remoteConfigGetAuth(conf, "auth_tls", &auth_tls, filename) < 0)
        goto free_and_fail;

    GET_CONF_STR (conf, filename, unix_sock_group);
    if (unix_sock_group) {
        if (getuid() != 0) {
            qemudLog (QEMUD_WARN,
                      "%s", _("Cannot set group when not running as root"));
        } else {
            struct group *grp = getgrnam(unix_sock_group);
            if (!grp) {
                qemudLog (QEMUD_ERR, _("Failed to lookup group '%s'"),
                          unix_sock_group);
                goto free_and_fail;
            }
            unix_sock_gid = grp->gr_gid;
        }
        free (unix_sock_group);
        unix_sock_group = NULL;
    }

    GET_CONF_STR (conf, filename, unix_sock_ro_perms);
    if (unix_sock_ro_perms) {
        if (virStrToLong_i (unix_sock_ro_perms, NULL, 8, &unix_sock_ro_mask) != 0) {
            qemudLog (QEMUD_ERR, _("Failed to parse mode '%s'"),
                      unix_sock_ro_perms);
            goto free_and_fail;
        }
        free (unix_sock_ro_perms);
        unix_sock_ro_perms = NULL;
    }

    GET_CONF_STR (conf, filename, unix_sock_rw_perms);
    if (unix_sock_rw_perms) {
        if (virStrToLong_i (unix_sock_rw_perms, NULL, 8, &unix_sock_rw_mask) != 0) {
            qemudLog (QEMUD_ERR, _("Failed to parse mode '%s'"),
                      unix_sock_rw_perms);
            goto free_and_fail;
        }
        free (unix_sock_rw_perms);
        unix_sock_rw_perms = NULL;
    }

    GET_CONF_INT (conf, filename, mdns_adv);
    GET_CONF_STR (conf, filename, mdns_name);

    GET_CONF_INT (conf, filename, tls_no_verify_certificate);

    GET_CONF_STR (conf, filename, key_file);
    GET_CONF_STR (conf, filename, cert_file);
    GET_CONF_STR (conf, filename, ca_file);
    GET_CONF_STR (conf, filename, crl_file);

    if (remoteConfigGetStringList (conf, "tls_allowed_dn_list",
                                   &tls_allowed_dn_list, filename) < 0)
        goto free_and_fail;

    if (remoteReadSaslAllowedUsernameList (conf, server, filename) < 0)
        goto free_and_fail;

    virConfFree (conf);
    return 0;

 free_and_fail:
    virConfFree (conf);
    free (mdns_name);
    mdns_name = NULL;
    free (unix_sock_ro_perms);
    free (unix_sock_rw_perms);
    free (unix_sock_group);

    /* Don't bother trying to free listen_addr, tcp_port, tls_port, key_file,
       cert_file, ca_file, or crl_file, since they are initialized to
       non-malloc'd strings.  Besides, these are static variables, and callers
       are unlikely to call this function more than once, so there wouldn't
       even be a real leak.  */

    if (tls_allowed_dn_list) {
        int i;
        for (i = 0; tls_allowed_dn_list[i]; i++)
            free (tls_allowed_dn_list[i]);
        free (tls_allowed_dn_list);
        tls_allowed_dn_list = NULL;
    }

    return -1;
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
    struct qemud_server *server = NULL;
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
            if (virStrToLong_i(optarg, &tmp, 10, &timeout) != 0
                || timeout <= 0
                /* Ensure that we can multiply by 1000 without overflowing.  */
                || timeout > INT_MAX / 1000)
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

    if (godaemon) {
        openlog("libvirtd", 0, 0);
        if (qemudGoDaemon() < 0) {
            qemudLog(QEMUD_ERR, _("Failed to fork as daemon: %s"),
                     strerror(errno));
            goto error1;
        }
    }

    /* If running as root and no PID file is set, use the default */
    if (pid_file == NULL &&
        getuid() == 0 &&
        REMOTE_PID_FILE[0] != '\0')
        pid_file = REMOTE_PID_FILE;

    /* If we have a pidfile set, claim it now, exiting if already taken */
    if (pid_file != NULL &&
        qemudWritePidFile (pid_file) < 0)
        goto error1;

    if (pipe(sigpipe) < 0 ||
        qemudSetNonBlock(sigpipe[0]) < 0 ||
        qemudSetNonBlock(sigpipe[1]) < 0 ||
        qemudSetCloseExec(sigpipe[0]) < 0 ||
        qemudSetCloseExec(sigpipe[1]) < 0) {
        qemudLog(QEMUD_ERR, _("Failed to create pipe: %s"),
                 strerror(errno));
        goto error2;
    }
    sigwrite = sigpipe[1];

    sig_action.sa_sigaction = sig_handler;
    sig_action.sa_flags = SA_SIGINFO;
    sigemptyset(&sig_action.sa_mask);

    sigaction(SIGHUP, &sig_action, NULL);
    sigaction(SIGINT, &sig_action, NULL);
    sigaction(SIGQUIT, &sig_action, NULL);
    sigaction(SIGTERM, &sig_action, NULL);
    sigaction(SIGCHLD, &sig_action, NULL);

    sig_action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig_action, NULL);

    if (!(server = qemudInitialize(sigpipe[0]))) {
        ret = 2;
        goto error2;
    }

    /* Read the config file (if it exists). */
    if (remoteReadConfigFile (server, remote_config_file) < 0)
        goto error2;

    /* Change the group ownership of /var/run/libvirt to unix_sock_gid */
    if (getuid() == 0) {
        const char *sockdirname = LOCAL_STATE_DIR "/run/libvirt";

        if (chown(sockdirname, -1, unix_sock_gid) < 0)
            qemudLog(QEMUD_ERR, _("Failed to change group ownership of %s"),
                     sockdirname);
    }

    if (virEventAddHandleImpl(sigpipe[0],
                              VIR_EVENT_HANDLE_READABLE,
                              qemudDispatchSignalEvent,
                              server, NULL) < 0) {
        qemudLog(QEMUD_ERR,
                 "%s", _("Failed to register callback for signal pipe"));
        ret = 3;
        goto error2;
    }

    if (!(server = qemudNetworkInit(server))) {
        ret = 2;
        goto error2;
    }

    qemudRunLoop(server);

    ret = 0;

error2:
    if (server)
        qemudCleanup(server);
    if (pid_file)
        unlink (pid_file);
    close(sigwrite);

error1:
    if (godaemon)
        closelog();
    return ret;
}
