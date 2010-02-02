/*
 * libvirtd.c: daemon start of day, guest process & i/o management
 *
 * Copyright (C) 2006-2010 Red Hat, Inc.
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
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_QEMU

#include "libvirtd.h"
#include "dispatch.h"

#include "util.h"
#include "remote_driver.h"
#include "conf.h"
#include "event.h"
#include "memory.h"
#include "stream.h"
#ifdef HAVE_AVAHI
#include "mdns.h"
#endif

#ifdef WITH_DRIVER_MODULES
#include "driver.h"
#else
#ifdef WITH_QEMU
#include "qemu/qemu_driver.h"
#endif
#ifdef WITH_LXC
#include "lxc/lxc_driver.h"
#endif
#ifdef WITH_UML
#include "uml/uml_driver.h"
#endif
#ifdef WITH_ONE
#include "opennebula/one_driver.h"
#endif
#ifdef WITH_NETWORK
#include "network/bridge_driver.h"
#endif
#ifdef WITH_NETCF
#include "interface/netcf_driver.h"
#endif
#ifdef WITH_STORAGE_DIR
#include "storage/storage_driver.h"
#endif
#ifdef WITH_NODE_DEVICES
#include "node_device/node_device_driver.h"
#endif
#ifdef WITH_SECRETS
#include "secret/secret_driver.h"
#endif
#endif


#ifdef __sun
#include <ucred.h>
#include <priv.h>

#ifndef PRIV_VIRT_MANAGE
#define PRIV_VIRT_MANAGE ((const char *)"virt_manage")
#endif

#ifndef PRIV_XVM_CONTROL
#define PRIV_XVM_CONTROL ((const char *)"xvm_control")
#endif

#define PU_RESETGROUPS          0x0001  /* Remove supplemental groups */
#define PU_CLEARLIMITSET        0x0008  /* L=0 */

extern int __init_daemon_priv(int, uid_t, gid_t, ...);

#define SYSTEM_UID 60

static gid_t unix_sock_gid = 60; /* Not used */
static int unix_sock_rw_mask = 0666;
static int unix_sock_ro_mask = 0666;

#else

static gid_t unix_sock_gid = 0; /* Only root by default */
static int unix_sock_rw_mask = 0700; /* Allow user only */
static int unix_sock_ro_mask = 0777; /* Allow world */

#endif /* __sun */

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

static char *unix_sock_dir = NULL;

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

static int min_workers = 5;
static int max_workers = 20;
static int max_clients = 20;

/* Total number of 'in-process' RPC calls allowed across all clients */
static int max_requests = 20;
/* Total number of 'in-process' RPC calls allowed by a single client*/
static int max_client_requests = 5;

#define DH_BITS 1024

static sig_atomic_t sig_errors = 0;
static int sig_lasterrno = 0;

enum {
    VIR_DAEMON_ERR_NONE = 0,
    VIR_DAEMON_ERR_PIDFILE,
    VIR_DAEMON_ERR_RUNDIR,
    VIR_DAEMON_ERR_INIT,
    VIR_DAEMON_ERR_SIGNAL,
    VIR_DAEMON_ERR_PRIVS,
    VIR_DAEMON_ERR_NETWORK,
    VIR_DAEMON_ERR_CONFIG,

    VIR_DAEMON_ERR_LAST
};

VIR_ENUM_DECL(virDaemonErr)
VIR_ENUM_IMPL(virDaemonErr, VIR_DAEMON_ERR_LAST,
              "Initialization successful",
              "Unable to obtain pidfile",
              "Unable to create rundir",
              "Unable to initialize libvirt",
              "Unable to setup signal handlers",
              "Unable to drop privileges",
              "Unable to initialize network sockets",
              "Unable to load configuration file")

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
static int qemudStartWorker(struct qemud_server *server, struct qemud_worker *worker);

void
qemudClientMessageQueuePush(struct qemud_client_message **queue,
                            struct qemud_client_message *msg)
{
    struct qemud_client_message *tmp = *queue;

    if (tmp) {
        while (tmp->next)
            tmp = tmp->next;
        tmp->next = msg;
    } else {
        *queue = msg;
    }
}

struct qemud_client_message *
qemudClientMessageQueueServe(struct qemud_client_message **queue)
{
    struct qemud_client_message *tmp = *queue;

    if (tmp) {
        *queue = tmp->next;
        tmp->next = NULL;
    }

    return tmp;
}

static int
remoteCheckCertFile(const char *type, const char *file)
{
    struct stat sb;
    if (stat(file, &sb) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Cannot access %s '%s': %s"),
                  type, file, virStrerror(errno, ebuf, sizeof ebuf));
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
        VIR_ERROR(_("gnutls_certificate_allocate_credentials: %s"),
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
            VIR_ERROR(_("gnutls_certificate_set_x509_trust_file: %s"),
                      gnutls_strerror (err));
            return -1;
        }
    }

    if (crl_file && crl_file[0] != '\0') {
        if (remoteCheckCertFile("CA revocation list", crl_file) < 0)
            return -1;

        DEBUG("loading CRL from %s", crl_file);
        err = gnutls_certificate_set_x509_crl_file (x509_cred, crl_file,
                                                    GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            VIR_ERROR(_("gnutls_certificate_set_x509_crl_file: %s"),
                      gnutls_strerror (err));
            return -1;
        }
    }

    if (cert_file && cert_file[0] != '\0' && key_file && key_file[0] != '\0') {
        if (remoteCheckCertFile("server certificate", cert_file) < 0)
            return -1;
        if (remoteCheckCertFile("server key", key_file) < 0)
            return -1;
        DEBUG("loading cert and key from %s and %s", cert_file, key_file);
        err =
            gnutls_certificate_set_x509_key_file (x509_cred,
                                                  cert_file, key_file,
                                                  GNUTLS_X509_FMT_PEM);
        if (err < 0) {
            VIR_ERROR(_("gnutls_certificate_set_x509_key_file: %s"),
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
        VIR_ERROR(_("gnutls_dh_params_init: %s"), gnutls_strerror (err));
        return -1;
    }
    err = gnutls_dh_params_generate2 (dh_params, DH_BITS);
    if (err < 0) {
        VIR_ERROR(_("gnutls_dh_params_generate2: %s"), gnutls_strerror (err));
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

    virMutexLock(&server->lock);

    if (saferead(server->sigread, &siginfo, sizeof(siginfo)) != sizeof(siginfo)) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to read from signal pipe: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        virMutexUnlock(&server->lock);
        return;
    }

    switch (siginfo.si_signo) {
    case SIGHUP:
        VIR_INFO0(_("Reloading configuration on SIGHUP"));
        if (virStateReload() < 0)
            VIR_WARN0(_("Error while reloading drivers"));
        break;

    case SIGINT:
    case SIGQUIT:
    case SIGTERM:
        VIR_WARN(_("Shutting down on signal %d"), siginfo.si_signo);
        server->quitEventThread = 1;
        break;

    default:
        VIR_INFO(_("Received unexpected signal %d"), siginfo.si_signo);
        break;
    }

    virMutexUnlock(&server->lock);
}


static int daemonForkIntoBackground(void) {
    int statuspipe[2];
    if (pipe(statuspipe) < 0)
        return -1;

    int pid = fork();
    switch (pid) {
    case 0:
        {
            int stdinfd = -1;
            int stdoutfd = -1;
            int nextpid;

            close(statuspipe[0]);

            if ((stdinfd = open("/dev/null", O_RDONLY)) < 0)
                goto cleanup;
            if ((stdoutfd = open("/dev/null", O_WRONLY)) < 0)
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
                return statuspipe[1];
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
            int got, exitstatus = 0;
            int ret;
            char status;

            close(statuspipe[1]);

            /* We wait to make sure the first child forked successfully */
            if ((got = waitpid(pid, &exitstatus, 0)) < 0 ||
                got != pid ||
                exitstatus != 0) {
                return -1;
            }

            /* Now block until the second child initializes successfully */
        again:
            ret = read(statuspipe[0], &status, 1);
            if (ret == -1 && errno == EINTR)
                goto again;

            if (ret == 1 && status != 0) {
                fprintf(stderr, "error: %s\n", virDaemonErrTypeToString(status));
            }
            _exit(ret == 1 && status == 0 ? 0 : 1);
        }
    }
}

static int qemudWritePidFile(const char *pidFile) {
    int fd;
    FILE *fh;
    char ebuf[1024];

    if (pidFile[0] == '\0')
        return 0;

    if ((fd = open(pidFile, O_WRONLY|O_CREAT|O_EXCL, 0644)) < 0) {
        VIR_ERROR(_("Failed to open pid file '%s' : %s"),
                  pidFile, virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    if (!(fh = fdopen(fd, "w"))) {
        VIR_ERROR(_("Failed to fdopen pid file '%s' : %s"),
                  pidFile, virStrerror(errno, ebuf, sizeof ebuf));
        close(fd);
        return -1;
    }

    if (fprintf(fh, "%lu\n", (unsigned long)getpid()) < 0) {
        VIR_ERROR(_("Failed to write to pid file '%s' : %s"),
                  pidFile, virStrerror(errno, ebuf, sizeof ebuf));
        fclose(fh);
        return -1;
    }

    if (fclose(fh) == EOF) {
        VIR_ERROR(_("Failed to close pid file '%s' : %s"),
                  pidFile, virStrerror(errno, ebuf, sizeof ebuf));
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
    char ebuf[1024];

    if (VIR_ALLOC(sock) < 0) {
        VIR_ERROR("%s", _("Failed to allocate memory for struct qemud_socket"));
        return -1;
    }

    sock->readonly = readonly;
    sock->port = -1;
    sock->type = QEMUD_SOCK_TYPE_UNIX;
    sock->auth = auth;

    if ((sock->fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        VIR_ERROR(_("Failed to create socket: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        goto cleanup;
    }

    if (virSetCloseExec(sock->fd) < 0 ||
        virSetNonBlock(sock->fd) < 0)
        goto cleanup;

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.sun_path, path) == NULL) {
        VIR_ERROR(_("Path %s too long for unix socket"), path);
        goto cleanup;
    }
    if (addr.sun_path[0] == '@')
        addr.sun_path[0] = '\0';

    oldgrp = getgid();
    oldmask = umask(readonly ? ~unix_sock_ro_mask : ~unix_sock_rw_mask);
    if (server->privileged)
        setgid(unix_sock_gid);

    if (bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        VIR_ERROR(_("Failed to bind socket to '%s': %s"),
                  path, virStrerror(errno, ebuf, sizeof ebuf));
        goto cleanup;
    }
    umask(oldmask);
    if (server->privileged)
        setgid(oldgrp);

    if (listen(sock->fd, 30) < 0) {
        VIR_ERROR(_("Failed to listen for connections on '%s': %s"),
                  path, virStrerror(errno, ebuf, sizeof ebuf));
        goto cleanup;
    }

    sock->next = server->sockets;
    server->sockets = sock;
    server->nsockets++;

    return 0;

 cleanup:
    if (sock->fd >= 0)
        close(sock->fd);
    VIR_FREE(sock);
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
        VIR_ERROR(_("getaddrinfo: %s"), gai_strerror (e));
        return -1;
    }

    struct addrinfo *runp = ai;
    while (runp && *nfds_r < max_fds) {
        char ebuf[1024];
        fds[*nfds_r] = socket (runp->ai_family, runp->ai_socktype,
                               runp->ai_protocol);
        if (fds[*nfds_r] == -1) {
            VIR_ERROR(_("socket: %s"), virStrerror (errno, ebuf, sizeof ebuf));
            return -1;
        }

        int opt = 1;
        setsockopt (fds[*nfds_r], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

#ifdef IPV6_V6ONLY
        if (runp->ai_family == PF_INET6) {
            int on = 1;
            /*
             * Normally on Linux an INET6 socket will bind to the INET4
             * address too. If getaddrinfo returns results with INET4
             * first though, this will result in INET6 binding failing.
             * We can trivially cope with multiple server sockets, so
             * we force it to only listen on IPv6
             */
            setsockopt(fds[*nfds_r], IPPROTO_IPV6,IPV6_V6ONLY,
                       (void*)&on, sizeof on);
        }
#endif

        if (bind (fds[*nfds_r], runp->ai_addr, runp->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                VIR_ERROR(_("bind: %s"), virStrerror (errno, ebuf, sizeof ebuf));
                return -1;
            }
            close (fds[*nfds_r]);
        } else {
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
        union {
            struct sockaddr_storage sa_stor;
            struct sockaddr sa;
            struct sockaddr_in sa_in;
#ifdef AF_INET6
            struct sockaddr_in6 sa_in6;
#endif
        } s;
        char ebuf[1024];
        socklen_t salen = sizeof(s);

        if (VIR_ALLOC(sock) < 0) {
            VIR_ERROR(_("remoteListenTCP: calloc: %s"),
                      virStrerror (errno, ebuf, sizeof ebuf));
            goto cleanup;
        }

        sock->readonly = 0;
        sock->next = server->sockets;
        server->sockets = sock;
        server->nsockets++;

        sock->fd = fds[i];
        sock->type = type;
        sock->auth = auth;

        if (getsockname(sock->fd, &s.sa, &salen) < 0)
            goto cleanup;

        if (s.sa.sa_family == AF_INET) {
            sock->port = htons(s.sa_in.sin_port);
#ifdef AF_INET6
        } else if (s.sa.sa_family == AF_INET6)
            sock->port = htons(s.sa_in6.sin6_port);
#endif
        else
            sock->port = -1;

        if (virSetCloseExec(sock->fd) < 0 ||
            virSetNonBlock(sock->fd) < 0)
            goto cleanup;

        if (listen (sock->fd, 30) < 0) {
            VIR_ERROR(_("remoteListenTCP: listen: %s"),
                      virStrerror (errno, ebuf, sizeof ebuf));
            goto cleanup;
        }
    }

    return 0;

cleanup:
    for (i = 0; i < nfds; ++i)
        close(fds[i]);
    return -1;
}

static int qemudInitPaths(struct qemud_server *server,
                          char *sockname,
                          char *roSockname,
                          int maxlen)
{
    char *sock_dir;
    char *dir_prefix = NULL;
    int ret = -1;
    char *sock_dir_prefix = NULL;

    if (unix_sock_dir) {
        sock_dir = unix_sock_dir;
        /* Change the group ownership of /var/run/libvirt to unix_sock_gid */
        if (server->privileged) {
            if (chown(unix_sock_dir, -1, unix_sock_gid) < 0)
                VIR_ERROR(_("Failed to change group ownership of %s"),
                          unix_sock_dir);
        }
    } else {
        sock_dir = sockname;
        if (server->privileged) {
            dir_prefix = strdup (LOCAL_STATE_DIR);
            if (dir_prefix == NULL) {
                virReportOOMError(NULL);
                goto cleanup;
            }
            if (snprintf (sock_dir, maxlen, "%s/run/libvirt",
                          dir_prefix) >= maxlen)
                goto snprintf_error;
        } else {
            uid_t uid = geteuid();
            dir_prefix = virGetUserDirectory(NULL, uid);
            if (dir_prefix == NULL) {
                /* Do not diagnose here; virGetUserDirectory does that.  */
                goto snprintf_error;
            }

            if (snprintf(sock_dir, maxlen, "%s/.libvirt", dir_prefix) >= maxlen)
                goto snprintf_error;
        }
    }

    sock_dir_prefix = strdup (sock_dir);
    if (!sock_dir_prefix) {
        virReportOOMError(NULL);
        goto cleanup;
    }

    if (server->privileged) {
        if (snprintf (sockname, maxlen, "%s/libvirt-sock",
                      sock_dir_prefix) >= maxlen
            || (snprintf (roSockname, maxlen, "%s/libvirt-sock-ro",
                          sock_dir_prefix) >= maxlen))
            goto snprintf_error;
        unlink(sockname);
        unlink(roSockname);
    } else {
        if (snprintf(sockname, maxlen, "@%s/libvirt-sock",
                     sock_dir_prefix) >= maxlen)
            goto snprintf_error;
    }

    if (server->privileged) {
        if (!(server->logDir = strdup (LOCAL_STATE_DIR "/log/libvirt")))
            virReportOOMError(NULL);
    } else {
        if (virAsprintf(&server->logDir, "%s/.libvirt/log", dir_prefix) < 0)
            virReportOOMError(NULL);
    }

    if (server->logDir == NULL)
        goto cleanup;

    ret = 0;

 snprintf_error:
    if (ret)
        VIR_ERROR("%s",
                  _("Resulting path too long for buffer in qemudInitPaths()"));

 cleanup:
    VIR_FREE(dir_prefix);
    VIR_FREE(sock_dir_prefix);
    return ret;
}

static void virshErrorHandler(void *opaque ATTRIBUTE_UNUSED, virErrorPtr err ATTRIBUTE_UNUSED)
{
    /* Don't do anything, since logging infrastructure already
     * took care of reporting the error */
}

static struct qemud_server *qemudInitialize(void) {
    struct qemud_server *server;

    if (VIR_ALLOC(server) < 0) {
        VIR_ERROR0(_("Failed to allocate struct qemud_server"));
        return NULL;
    }

    server->privileged = geteuid() == 0 ? 1 : 0;
    server->sigread = server->sigwrite = -1;

    if (virMutexInit(&server->lock) < 0) {
        VIR_ERROR("%s", _("cannot initialize mutex"));
        VIR_FREE(server);
        return NULL;
    }
    if (virCondInit(&server->job) < 0) {
        VIR_ERROR("%s", _("cannot initialize condition variable"));
        virMutexDestroy(&server->lock);
        VIR_FREE(server);
        return NULL;
    }

    if (virEventInit() < 0) {
        VIR_ERROR0(_("Failed to initialize event system"));
        virMutexDestroy(&server->lock);
        if (virCondDestroy(&server->job) < 0)
        {}
        VIR_FREE(server);
        return NULL;
    }

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
     * If they try to open a connection for a module that
     * is not loaded they'll get a suitable error at that point
     */
    virDriverLoadModule("network");
    virDriverLoadModule("storage");
    virDriverLoadModule("nodedev");
    virDriverLoadModule("secret");
    virDriverLoadModule("qemu");
    virDriverLoadModule("lxc");
    virDriverLoadModule("uml");
    virDriverLoadModule("one");
#else
#ifdef WITH_NETWORK
    networkRegister();
#endif
#ifdef WITH_NETCF
    interfaceRegister();
#endif
#ifdef WITH_STORAGE_DIR
    storageRegister();
#endif
#if defined(WITH_NODE_DEVICES)
    nodedevRegister();
#endif
#ifdef WITH_SECRETS
    secretRegister();
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
#ifdef WITH_ONE
    oneRegister();
#endif
#endif

    virEventRegisterImpl(virEventAddHandleImpl,
                         virEventUpdateHandleImpl,
                         virEventRemoveHandleImpl,
                         virEventAddTimeoutImpl,
                         virEventUpdateTimeoutImpl,
                         virEventRemoveTimeoutImpl);

    return server;
}

static int qemudNetworkInit(struct qemud_server *server) {
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
            VIR_ERROR(_("Failed to initialize SASL authentication %s"),
                      sasl_errstring(err, NULL, NULL));
            goto cleanup;
        }
    }
#endif

#if HAVE_POLKIT0
    if (auth_unix_rw == REMOTE_AUTH_POLKIT ||
        auth_unix_ro == REMOTE_AUTH_POLKIT) {
        DBusError derr;

        dbus_connection_set_change_sigpipe(FALSE);
        dbus_threads_init_default();

        dbus_error_init(&derr);
        server->sysbus = dbus_bus_get(DBUS_BUS_SYSTEM, &derr);
        if (!(server->sysbus)) {
            VIR_ERROR(_("Failed to connect to system bus for PolicyKit auth: %s"),
                      derr.message);
            dbus_error_free(&derr);
            goto cleanup;
        }
        dbus_connection_set_exit_on_disconnect(server->sysbus, FALSE);
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
    if (server->privileged && mdns_adv) {
        struct libvirtd_mdns_group *group;
        struct qemud_socket *sock;
        int port = 0;

        server->mdns = libvirtd_mdns_new();

        if (!mdns_name) {
            char groupname[64], *localhost, *tmp;
            /* Extract the host part of the potentially FQDN */
            localhost = virGetHostname(NULL);
            if (localhost == NULL)
                goto cleanup;

            if ((tmp = strchr(localhost, '.')))
                *tmp = '\0';
            snprintf(groupname, sizeof(groupname)-1, "Virtualization Host %s", localhost);
            groupname[sizeof(groupname)-1] = '\0';
            group = libvirtd_mdns_add_group(server->mdns, groupname);
            VIR_FREE(localhost);
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

    return 0;

 cleanup:
    return -1;
}

static int qemudNetworkEnable(struct qemud_server *server) {
    struct qemud_socket *sock;

    sock = server->sockets;
    while (sock) {
        if ((sock->watch = virEventAddHandleImpl(sock->fd,
                                                 VIR_EVENT_HANDLE_READABLE |
                                                 VIR_EVENT_HANDLE_ERROR |
                                                 VIR_EVENT_HANDLE_HANGUP,
                                                 qemudDispatchServerEvent,
                                                 server, NULL)) < 0) {
            VIR_ERROR0(_("Failed to add server event callback"));
            return -1;
        }

        sock = sock->next;
    }
    return 0;
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
  VIR_ERROR(_("remoteInitializeTLSSession: %s"),
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
        VIR_ERROR(_("remoteCheckDN: gnutls_x509_cert_get_dn: %s"),
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

    /* Print the client's DN. */
    DEBUG(_("remoteCheckDN: failed: client DN is %s"), name);

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
        VIR_ERROR(_("remoteCheckCertificate: verify failed: %s"),
                  gnutls_strerror (ret));
        return -1;
    }

    if (status != 0) {
        if (status & GNUTLS_CERT_INVALID)
            VIR_ERROR0(_("remoteCheckCertificate: "
                         "the client certificate is not trusted."));

        if (status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            VIR_ERROR0(_("remoteCheckCertificate: the client "
                         "certificate has unknown issuer."));

        if (status & GNUTLS_CERT_REVOKED)
            VIR_ERROR0(_("remoteCheckCertificate: "
                         "the client certificate has been revoked."));

#ifndef GNUTLS_1_0_COMPAT
        if (status & GNUTLS_CERT_INSECURE_ALGORITHM)
            VIR_ERROR0(_("remoteCheckCertificate: the client certificate"
                         " uses an insecure algorithm."));
#endif

        return -1;
    }

    if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509) {
        VIR_ERROR0(_("remoteCheckCertificate: certificate is not X.509"));
        return -1;
    }

    if (!(certs = gnutls_certificate_get_peers(session, &nCerts))) {
        VIR_ERROR0(_("remoteCheckCertificate: no peers"));
        return -1;
    }

    now = time (NULL);

    for (i = 0; i < nCerts; i++) {
        gnutls_x509_crt_t cert;

        if (gnutls_x509_crt_init (&cert) < 0) {
            VIR_ERROR0(_("remoteCheckCertificate: gnutls_x509_crt_init failed"));
            return -1;
        }

        if (gnutls_x509_crt_import(cert, &certs[i], GNUTLS_X509_FMT_DER) < 0) {
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_expiration_time (cert) < now) {
            VIR_ERROR0(_("remoteCheckCertificate: "
                         "the client certificate has expired"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (gnutls_x509_crt_get_activation_time (cert) > now) {
            VIR_ERROR0(_("remoteCheckCertificate: the client "
                         "certificate is not yet activated"));
            gnutls_x509_crt_deinit (cert);
            return -1;
        }

        if (i == 0) {
            if (!remoteCheckDN (cert)) {
                /* This is the most common error: make it informative. */
                VIR_ERROR0(_("remoteCheckCertificate: client's Distinguished Name is not on the list of allowed clients (tls_allowed_dn_list).  Use 'openssl x509 -in clientcert.pem -text' to view the Distinguished Name field in the client certificate, or run this daemon with --verbose option."));
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
    struct qemud_client_message *confirm;

    /* Verify client certificate. */
    if (remoteCheckCertificate (client->tlssession) == -1) {
        VIR_ERROR0(_("remoteCheckCertificate: "
                     "failed to verify client's certificate"));
        if (!tls_no_verify_certificate) return -1;
        else VIR_INFO0(_("remoteCheckCertificate: tls_no_verify_certificate "
                          "is set so the bad certificate is ignored"));
    }

    if (client->tx) {
        VIR_INFO("%s",
                 _("client had unexpected data pending tx after access check"));
        return -1;
    }

    if (VIR_ALLOC(confirm) < 0)
        return -1;

    /* Checks have succeeded.  Write a '\1' byte back to the client to
     * indicate this (otherwise the socket is abruptly closed).
     * (NB. The '\1' byte is sent in an encrypted record).
     */
    confirm->async = 1;
    confirm->bufferLength = 1;
    confirm->bufferOffset = 0;
    confirm->buffer[0] = '\1';

    client->tx = confirm;
    return 0;
}

#if HAVE_POLKIT
int qemudGetSocketIdentity(int fd, uid_t *uid, pid_t *pid) {
#ifdef SO_PEERCRED
    struct ucred cr;
    unsigned int cr_len = sizeof (cr);

    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to verify client credentials: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
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
        char ebuf[1024];
        if (errno == EAGAIN)
            return 0;
        VIR_ERROR(_("Failed to accept connection: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        return -1;
    }

    if (server->nclients >= max_clients) {
        VIR_ERROR(_("Too many active clients (%d), dropping connection"), max_clients);
        close(fd);
        return -1;
    }

    if (VIR_REALLOC_N(server->clients, server->nclients+1) < 0) {
        VIR_ERROR0(_("Out of memory allocating clients"));
        close(fd);
        return -1;
    }

#ifdef __sun
    {
        ucred_t *ucred = NULL;
        const priv_set_t *privs;

        if (getpeerucred (fd, &ucred) == -1 ||
            (privs = ucred_getprivset (ucred, PRIV_EFFECTIVE)) == NULL) {
            if (ucred != NULL)
                ucred_free (ucred);
            close (fd);
            return -1;
        }

        if (!priv_ismember (privs, PRIV_VIRT_MANAGE)) {
            ucred_free (ucred);
            close (fd);
            return -1;
        }

        ucred_free (ucred);
    }
#endif /* __sun */

    /* Disable Nagle.  Unix sockets will ignore this. */
    setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void *)&no_slow_start,
                sizeof no_slow_start);

    if (virSetCloseExec(fd) < 0 ||
        virSetNonBlock(fd) < 0) {
        close(fd);
        return -1;
    }

    if (VIR_ALLOC(client) < 0)
        goto cleanup;
    if (virMutexInit(&client->lock) < 0) {
        VIR_ERROR("%s", _("cannot initialize mutex"));
        VIR_FREE(client);
        goto cleanup;
    }

    client->magic = QEMUD_CLIENT_MAGIC;
    client->fd = fd;
    client->readonly = sock->readonly;
    client->type = sock->type;
    client->auth = sock->auth;
    memcpy (&client->addr, &addr, sizeof addr);
    client->addrlen = addrlen;

    /* Prepare one for packet receive */
    if (VIR_ALLOC(client->rx) < 0)
        goto cleanup;
    client->rx->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;


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
            VIR_INFO(_("Turn off polkit auth for privileged client %d"), pid);
            client->auth = REMOTE_AUTH_NONE;
        }
    }
#endif

    if (client->type != QEMUD_SOCK_TYPE_TLS) {
        /* Plain socket, so prepare to read first message */
        if (qemudRegisterClientEvent (server, client) < 0)
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
            client->handshake = 0;

            /* Unlikely, but ...  Next step is to check the certificate. */
            if (remoteCheckAccess (client) == -1)
                goto cleanup;

            /* Handshake & cert check OK,  so prepare to read first message */
            if (qemudRegisterClientEvent(server, client) < 0)
                goto cleanup;
        } else if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
            /* Most likely, need to do more handshake data */
            client->handshake = 1;

            if (qemudRegisterClientEvent (server, client) < 0)
                goto cleanup;
        } else {
            VIR_ERROR(_("TLS handshake failed: %s"),
                      gnutls_strerror (ret));
            goto cleanup;
        }
    }

    server->clients[server->nclients++] = client;

    if (server->nclients > server->nactiveworkers &&
        server->nactiveworkers < server->nworkers) {
        int i;
        for (i = 0 ; i < server->nworkers ; i++) {
            if (!server->workers[i].hasThread) {
                if (qemudStartWorker(server, &server->workers[i]) < 0)
                    return -1;
                server->nactiveworkers++;
                break;
            }
        }
    }


    return 0;

 cleanup:
    if (client &&
        client->tlssession) gnutls_deinit (client->tlssession);
    close (fd);
    if (client)
        VIR_FREE(client->rx);
    VIR_FREE(client);
    return -1;
}


/*
 * You must hold lock for at least the client
 * We don't free stuff here, merely disconnect the client's
 * network socket & resources.
 * We keep the libvirt connection open until any async
 * jobs have finished, then clean it up elsehwere
 */
void qemudDispatchClientFailure(struct qemud_client *client) {
    if (client->watch != -1) {
        virEventRemoveHandleImpl(client->watch);
        client->watch = -1;
    }

    /* Deregister event delivery callback */
    if (client->conn && client->domain_events_registered) {
        DEBUG0("Deregistering to relay remote events");
        virConnectDomainEventDeregister(client->conn, remoteRelayDomainEvent);
    }

#if HAVE_SASL
    if (client->saslconn) {
        sasl_dispose(&client->saslconn);
        client->saslconn = NULL;
    }
    VIR_FREE(client->saslUsername);
#endif
    if (client->tlssession) {
        gnutls_deinit (client->tlssession);
        client->tlssession = NULL;
    }
    if (client->fd != -1) {
        close(client->fd);
        client->fd = -1;
    }
}


/* Caller must hold server lock */
static struct qemud_client *qemudPendingJob(struct qemud_server *server)
{
    int i;
    for (i = 0 ; i < server->nclients ; i++) {
        virMutexLock(&server->clients[i]->lock);
        if (server->clients[i]->dx) {
            /* Delibrately don't unlock client - caller wants the lock */
            return server->clients[i];
        }
        virMutexUnlock(&server->clients[i]->lock);
    }
    return NULL;
}

static void *qemudWorker(void *data)
{
    struct qemud_worker *worker = data;
    struct qemud_server *server = worker->server;

    while (1) {
        struct qemud_client *client = NULL;
        struct qemud_client_message *msg;

        virMutexLock(&server->lock);
        while (((client = qemudPendingJob(server)) == NULL) &&
               !worker->quitRequest) {
            if (virCondWait(&server->job, &server->lock) < 0) {
                virMutexUnlock(&server->lock);
                return NULL;
            }
        }
        if (worker->quitRequest) {
            if (client)
                virMutexUnlock(&client->lock);
            virMutexUnlock(&server->lock);
            return NULL;
        }
        worker->processingCall = 1;
        virMutexUnlock(&server->lock);

        /* We own a locked client now... */
        client->refs++;

        /* Remove our message from dispatch queue while we use it */
        msg = qemudClientMessageQueueServe(&client->dx);

        /* This function drops the lock during dispatch,
         * and re-acquires it before returning */
        if (remoteDispatchClientRequest (server, client, msg) < 0) {
            VIR_FREE(msg);
            qemudDispatchClientFailure(client);
            client->refs--;
            virMutexUnlock(&client->lock);
            continue;
        }

        client->refs--;
        virMutexUnlock(&client->lock);

        virMutexLock(&server->lock);
        worker->processingCall = 0;
        virMutexUnlock(&server->lock);
    }
}

static int qemudStartWorker(struct qemud_server *server,
                            struct qemud_worker *worker) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    /* We want to join workers, so don't detach them */
    /*pthread_attr_setdetachstate(&attr, 1);*/

    if (worker->hasThread)
        return -1;

    worker->server = server;
    worker->hasThread = 1;
    worker->quitRequest = 0;
    worker->processingCall = 0;

    if (pthread_create(&worker->thread,
                       &attr,
                       qemudWorker,
                       worker) != 0) {
        worker->hasThread = 0;
        worker->server = NULL;
        return -1;
    }

    return 0;
}


/*
 * Read data into buffer using wire decoding (plain or TLS)
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t qemudClientReadBuf(struct qemud_client *client,
                                  char *data, ssize_t len) {
    ssize_t ret;

    if (len < 0) {
        VIR_ERROR(_("unexpected negative length request %lld"),
                  (long long int) len);
        qemudDispatchClientFailure(client);
        return -1;
    }

    /*qemudDebug ("qemudClientRead: len = %d", len);*/

    if (!client->tlssession) {
        char ebuf[1024];
        ret = read (client->fd, data, len);
        if (ret == -1 && (errno == EAGAIN ||
                          errno == EINTR))
            return 0;
        if (ret <= 0) {
            if (ret != 0)
                VIR_ERROR(_("read: %s"),
                          virStrerror (errno, ebuf, sizeof ebuf));
            qemudDispatchClientFailure(client);
            return -1;
        }
    } else {
        ret = gnutls_record_recv (client->tlssession, data, len);

        if (ret < 0 && (ret == GNUTLS_E_AGAIN ||
                        ret == GNUTLS_E_INTERRUPTED))
            return 0;
        if (ret <= 0) {
            if (ret != 0)
                VIR_ERROR(_("gnutls_record_recv: %s"),
                          gnutls_strerror (ret));
            qemudDispatchClientFailure(client);
            return -1;
        }
    }

    return ret;
}

/*
 * Read data into buffer without decoding
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t qemudClientReadPlain(struct qemud_client *client) {
    ssize_t ret;
    ret = qemudClientReadBuf(client,
                             client->rx->buffer + client->rx->bufferOffset,
                             client->rx->bufferLength - client->rx->bufferOffset);
    if (ret <= 0)
        return ret; /* -1 error, 0 eagain */

    client->rx->bufferOffset += ret;
    return ret;
}

#if HAVE_SASL
/*
 * Read data into buffer decoding with SASL
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t qemudClientReadSASL(struct qemud_client *client) {
    ssize_t got, want;

    /* We're doing a SSF data read, so now its times to ensure
     * future writes are under SSF too.
     *
     * cf remoteSASLCheckSSF in remote.c
     */
    client->saslSSF |= QEMUD_SASL_SSF_WRITE;

    /* Need to read some more data off the wire */
    if (client->saslDecoded == NULL) {
        int ret;
        char encoded[8192];
        ssize_t encodedLen = sizeof(encoded);
        encodedLen = qemudClientReadBuf(client, encoded, encodedLen);

        if (encodedLen <= 0)
            return encodedLen;

        ret = sasl_decode(client->saslconn, encoded, encodedLen,
                          &client->saslDecoded, &client->saslDecodedLength);
        if (ret != SASL_OK) {
            VIR_ERROR(_("failed to decode SASL data %s"),
                      sasl_errstring(ret, NULL, NULL));
            qemudDispatchClientFailure(client);
            return -1;
        }

        client->saslDecodedOffset = 0;
    }

    /* Some buffered decoded data to return now */
    got = client->saslDecodedLength - client->saslDecodedOffset;
    want = client->rx->bufferLength - client->rx->bufferOffset;

    if (want > got)
        want = got;

    memcpy(client->rx->buffer + client->rx->bufferOffset,
           client->saslDecoded + client->saslDecodedOffset, want);
    client->saslDecodedOffset += want;
    client->rx->bufferOffset += want;

    if (client->saslDecodedOffset == client->saslDecodedLength) {
        client->saslDecoded = NULL;
        client->saslDecodedOffset = client->saslDecodedLength = 0;
    }

    return want;
}
#endif

/*
 * Read as much data off wire as possible till we fill our
 * buffer, or would block on I/O
 */
static ssize_t qemudClientRead(struct qemud_client *client) {
#if HAVE_SASL
    if (client->saslSSF & QEMUD_SASL_SSF_READ)
        return qemudClientReadSASL(client);
    else
#endif
        return qemudClientReadPlain(client);
}


/*
 * Read data until we get a complete message to process
 */
static void qemudDispatchClientRead(struct qemud_server *server,
                                    struct qemud_client *client) {
    /*qemudDebug ("qemudDispatchClientRead: mode = %d", client->mode);*/

readmore:
    if (qemudClientRead(client) < 0)
        return; /* Error */

    if (client->rx->bufferOffset < client->rx->bufferLength)
        return; /* Still not read enough */

    /* Either done with length word header */
    if (client->rx->bufferLength == REMOTE_MESSAGE_HEADER_XDR_LEN) {
        unsigned int len;
        XDR x;

        xdrmem_create(&x, client->rx->buffer, client->rx->bufferLength, XDR_DECODE);

        if (!xdr_u_int(&x, &len)) {
            xdr_destroy (&x);
            DEBUG0("Failed to decode packet length");
            qemudDispatchClientFailure(client);
            return;
        }
        xdr_destroy (&x);

        if (len < REMOTE_MESSAGE_HEADER_XDR_LEN) {
            DEBUG("Packet length %u too small", len);
            qemudDispatchClientFailure(client);
            return;
        }

        /* Length includes the size of the length word itself */
        len -= REMOTE_MESSAGE_HEADER_XDR_LEN;

        if (len > REMOTE_MESSAGE_MAX) {
            DEBUG("Packet length %u too large", len);
            qemudDispatchClientFailure(client);
            return;
        }

        /* Prepare to read rest of message */
        client->rx->bufferLength += len;

        qemudUpdateClientEvent(client);

        /* Try and read payload immediately instead of going back
           into poll() because chances are the data is already
           waiting for us */
        goto readmore;
    } else {
        /* Grab the completed message */
        struct qemud_client_message *msg = qemudClientMessageQueueServe(&client->rx);
        struct qemud_client_filter *filter;

        /* Decode the header so we can use it for routing decisions */
        if (remoteDecodeClientMessageHeader(msg) < 0) {
            VIR_FREE(msg);
            qemudDispatchClientFailure(client);
        }

        /* Check if any filters match this message */
        filter = client->filters;
        while (filter) {
            int ret;
            ret = (filter->query)(client, msg, filter->opaque);
            if (ret == 1) {
                msg = NULL;
                break;
            } else if (ret == -1) {
                VIR_FREE(msg);
                qemudDispatchClientFailure(client);
                return;
            }
            filter = filter->next;
        }

        /* Move completed message to the end of the dispatch queue */
        if (msg)
            qemudClientMessageQueuePush(&client->dx, msg);
        client->nrequests++;

        /* Possibly need to create another receive buffer */
        if ((client->nrequests < max_client_requests &&
             VIR_ALLOC(client->rx) < 0)) {
            qemudDispatchClientFailure(client);
        } else {
            if (client->rx)
                client->rx->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;

            qemudUpdateClientEvent(client);

            /* Tell one of the workers to get on with it... */
            virCondSignal(&server->job);
        }
    }
}


/*
 * Send a chunk of data using wire encoding (plain or TLS)
 *
 * Returns:
 *   -1 on error
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t qemudClientWriteBuf(struct qemud_client *client,
                                   const char *data, ssize_t len) {
    ssize_t ret;

    if (len < 0) {
        VIR_ERROR(_("unexpected negative length request %lld"),
                  (long long int) len);
        qemudDispatchClientFailure(client);
        return -1;
    }

    if (!client->tlssession) {
        char ebuf[1024];
        if ((ret = write(client->fd, data, len)) == -1) {
            if (errno == EAGAIN || errno == EINTR)
                return 0;
            VIR_ERROR(_("write: %s"), virStrerror (errno, ebuf, sizeof ebuf));
            qemudDispatchClientFailure(client);
            return -1;
        }
    } else {
        ret = gnutls_record_send (client->tlssession, data, len);
        if (ret < 0) {
            if (ret == GNUTLS_E_INTERRUPTED ||
                ret == GNUTLS_E_AGAIN)
                return 0;

            VIR_ERROR(_("gnutls_record_send: %s"), gnutls_strerror (ret));
            qemudDispatchClientFailure(client);
            return -1;
        }
    }
    return ret;
}


/*
 * Send client->tx using no encoding
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static int qemudClientWritePlain(struct qemud_client *client) {
    int ret = qemudClientWriteBuf(client,
                                  client->tx->buffer + client->tx->bufferOffset,
                                  client->tx->bufferLength - client->tx->bufferOffset);
    if (ret <= 0)
        return ret; /* -1 error, 0 = egain */
    client->tx->bufferOffset += ret;
    return ret;
}


#if HAVE_SASL
/*
 * Send client->tx using SASL encoding
 *
 * Returns:
 *   -1 on error
 *    0 on EAGAIN
 *    n number of bytes
 */
static int qemudClientWriteSASL(struct qemud_client *client) {
    int ret;

    /* Not got any pending encoded data, so we need to encode raw stuff */
    if (client->saslEncoded == NULL) {
        ret = sasl_encode(client->saslconn,
                          client->tx->buffer + client->tx->bufferOffset,
                          client->tx->bufferLength - client->tx->bufferOffset,
                          &client->saslEncoded,
                          &client->saslEncodedLength);

        if (ret != SASL_OK) {
            VIR_ERROR(_("failed to encode SASL data %s"),
                      sasl_errstring(ret, NULL, NULL));
            qemudDispatchClientFailure(client);
            return -1;
        }

        client->saslEncodedOffset = 0;
    }

    /* Send some of the encoded stuff out on the wire */
    ret = qemudClientWriteBuf(client,
                              client->saslEncoded + client->saslEncodedOffset,
                              client->saslEncodedLength - client->saslEncodedOffset);

    if (ret <= 0)
        return ret; /* -1 error, 0 == egain */

    /* Note how much we sent */
    client->saslEncodedOffset += ret;

    /* Sent all encoded, so update raw buffer to indicate completion */
    if (client->saslEncodedOffset == client->saslEncodedLength) {
        client->saslEncoded = NULL;
        client->saslEncodedOffset = client->saslEncodedLength = 0;

        /* Mark as complete, so caller detects completion */
        client->tx->bufferOffset = client->tx->bufferLength;
    }

    return ret;
}
#endif

/*
 * Send as much data in the client->tx as possible
 *
 * Returns:
 *   -1 on error or EOF
 *    0 on EAGAIN
 *    n number of bytes
 */
static ssize_t qemudClientWrite(struct qemud_client *client) {
#if HAVE_SASL
    if (client->saslSSF & QEMUD_SASL_SSF_WRITE)
        return qemudClientWriteSASL(client);
    else
#endif
        return qemudClientWritePlain(client);
}


void
qemudClientMessageRelease(struct qemud_client *client,
                          struct qemud_client_message *msg)
{
    if (msg->streamTX) {
        remoteStreamMessageFinished(client, msg);
    } else if (!msg->async)
        client->nrequests--;

    /* See if the recv queue is currently throttled */
    if (!client->rx &&
        client->nrequests < max_client_requests) {
        /* Reset message record for next RX attempt */
        memset(msg, 0, sizeof(*msg));
        client->rx = msg;
        /* Get ready to receive next message */
        client->rx->bufferLength = REMOTE_MESSAGE_HEADER_XDR_LEN;
    } else {
        VIR_FREE(msg);
    }

    qemudUpdateClientEvent(client);
}


/*
 * Process all queued client->tx messages until
 * we would block on I/O
 */
static void
qemudDispatchClientWrite(struct qemud_client *client) {
    while (client->tx) {
        ssize_t ret;

        ret = qemudClientWrite(client);
        if (ret < 0) {
            qemudDispatchClientFailure(client);
            return;
        }
        if (ret == 0)
            return; /* Would block on write EAGAIN */

        if (client->tx->bufferOffset == client->tx->bufferLength) {
            struct qemud_client_message *reply;

            /* Get finished reply from head of tx queue */
            reply = qemudClientMessageQueueServe(&client->tx);

            qemudClientMessageRelease(client, reply);

            if (client->closing)
                qemudDispatchClientFailure(client);
         }
    }
}

static void
qemudDispatchClientHandshake(struct qemud_client *client) {
    int ret;
    /* Continue the handshake. */
    ret = gnutls_handshake (client->tlssession);
    if (ret == 0) {
        client->handshake = 0;

        /* Finished.  Next step is to check the certificate. */
        if (remoteCheckAccess (client) == -1)
            qemudDispatchClientFailure(client);
        else
            qemudUpdateClientEvent(client);
    } else if (ret == GNUTLS_E_AGAIN ||
               ret == GNUTLS_E_INTERRUPTED) {
        /* Carry on waiting for more handshake. Update
           the events just in case handshake data flow
           direction has changed */
        qemudUpdateClientEvent (client);
    } else {
        /* Fatal error in handshake */
        VIR_ERROR(_("TLS handshake failed: %s"),
                  gnutls_strerror (ret));
        qemudDispatchClientFailure(client);
    }
}

static void
qemudDispatchClientEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_client *client = NULL;
    int i;

    virMutexLock(&server->lock);

    for (i = 0 ; i < server->nclients ; i++) {
        virMutexLock(&server->clients[i]->lock);
        if (server->clients[i]->watch == watch) {
            client = server->clients[i];
            break;
        }
        virMutexUnlock(&server->clients[i]->lock);
    }

    virMutexUnlock(&server->lock);

    if (!client) {
        return;
    }

    if (client->fd != fd) {
        virMutexUnlock(&client->lock);
        return;
    }

    if (events & (VIR_EVENT_HANDLE_WRITABLE |
                  VIR_EVENT_HANDLE_READABLE)) {
        if (client->handshake) {
            qemudDispatchClientHandshake(client);
        } else {
            if (events & VIR_EVENT_HANDLE_WRITABLE)
                qemudDispatchClientWrite(client);
            if (events & VIR_EVENT_HANDLE_READABLE)
                qemudDispatchClientRead(server, client);
        }
    }

    /* NB, will get HANGUP + READABLE at same time upon
     * disconnect */
    if (events & (VIR_EVENT_HANDLE_ERROR |
                  VIR_EVENT_HANDLE_HANGUP))
        qemudDispatchClientFailure(client);

    virMutexUnlock(&client->lock);
}


/*
 * @client: a locked client object
 */
static int
qemudCalculateHandleMode(struct qemud_client *client) {
    int mode = 0;

    if (client->handshake) {
        if (gnutls_record_get_direction (client->tlssession) == 0)
            mode |= VIR_EVENT_HANDLE_READABLE;
        else
            mode |= VIR_EVENT_HANDLE_WRITABLE;
    } else {
        /* If there is a message on the rx queue then
         * we're wanting more input */
        if (client->rx)
            mode |= VIR_EVENT_HANDLE_READABLE;

        /* If there are one or more messages to send back to client,
           then monitor for writability on socket */
        if (client->tx)
            mode |= VIR_EVENT_HANDLE_WRITABLE;
    }

    return mode;
}

/*
 * @server: a locked or unlocked server object
 * @client: a locked client object
 */
int qemudRegisterClientEvent(struct qemud_server *server,
                             struct qemud_client *client) {
    int mode;

    mode = qemudCalculateHandleMode(client);

    if ((client->watch = virEventAddHandleImpl(client->fd,
                                               mode,
                                               qemudDispatchClientEvent,
                                               server, NULL)) < 0)
        return -1;

    return 0;
}

/*
 * @client: a locked client object
 */
void qemudUpdateClientEvent(struct qemud_client *client) {
    int mode;

    mode = qemudCalculateHandleMode(client);

    virEventUpdateHandleImpl(client->watch, mode);
}


static void
qemudDispatchServerEvent(int watch, int fd, int events, void *opaque) {
    struct qemud_server *server = (struct qemud_server *)opaque;
    struct qemud_socket *sock;

    virMutexLock(&server->lock);

    sock = server->sockets;

    while (sock) {
        if (sock->watch == watch)
            break;

        sock = sock->next;
    }

    if (sock && sock->fd == fd && events)
        qemudDispatchServer(server, sock);

    virMutexUnlock(&server->lock);
}


static int qemudOneLoop(void) {
    sig_atomic_t errors;

    if (virEventRunOnce() < 0)
        return -1;

    /* Check for any signal handling errors and log them. */
    errors = sig_errors;
    if (errors) {
        char ebuf[1024];
        sig_errors -= errors;
        VIR_ERROR(_("Signal handler reported %d errors: last error: %s"),
                  errors, virStrerror (sig_lasterrno, ebuf, sizeof ebuf));
        return -1;
    }

    return 0;
}

static void qemudInactiveTimer(int timerid, void *data) {
    struct qemud_server *server = (struct qemud_server *)data;

    if (virStateActive() ||
        server->clients) {
        DEBUG0("Timer expired but still active, not shutting down");
        virEventUpdateTimeoutImpl(timerid, -1);
    } else {
        DEBUG0("Timer expired and inactive, shutting down");
        server->quitEventThread = 1;
    }
}

static void qemudFreeClient(struct qemud_client *client) {
    while (client->rx) {
        struct qemud_client_message *msg
            = qemudClientMessageQueueServe(&client->rx);
        VIR_FREE(msg);
    }
    while (client->dx) {
        struct qemud_client_message *msg
            = qemudClientMessageQueueServe(&client->dx);
        VIR_FREE(msg);
    }
    while (client->tx) {
        struct qemud_client_message *msg
            = qemudClientMessageQueueServe(&client->tx);
        VIR_FREE(msg);
    }

    while (client->streams)
        remoteRemoveClientStream(client, client->streams);

    if (client->conn)
        virConnectClose(client->conn);
    virMutexDestroy(&client->lock);
    VIR_FREE(client);
}

static void *qemudRunLoop(void *opaque) {
    struct qemud_server *server = opaque;
    int timerid = -1;
    int i;
    int timerActive = 0;

    virMutexLock(&server->lock);

    if (timeout > 0 &&
        (timerid = virEventAddTimeoutImpl(-1,
                                          qemudInactiveTimer,
                                          server, NULL)) < 0) {
        VIR_ERROR0(_("Failed to register shutdown timeout"));
        return NULL;
    }

    if (min_workers > max_workers)
        max_workers = min_workers;

    server->nworkers = max_workers;
    if (VIR_ALLOC_N(server->workers, server->nworkers) < 0) {
        VIR_ERROR0(_("Failed to allocate workers"));
        return NULL;
    }

    for (i = 0 ; i < min_workers ; i++) {
        if (qemudStartWorker(server, &server->workers[i]) < 0)
            goto cleanup;
        server->nactiveworkers++;
    }

    for (;!server->quitEventThread;) {
        /* A shutdown timeout is specified, so check
         * if any drivers have active state, if not
         * shutdown after timeout seconds
         */
        if (timeout > 0) {
            if (timerActive) {
                if (server->clients) {
                    DEBUG("Deactivating shutdown timer %d", timerid);
                    virEventUpdateTimeoutImpl(timerid, -1);
                    timerActive = 0;
                }
            } else {
                if (!virStateActive() &&
                    !server->clients) {
                    DEBUG("Activating shutdown timer %d", timerid);
                    virEventUpdateTimeoutImpl(timerid, timeout * 1000);
                    timerActive = 1;
                }
            }
        }

        virMutexUnlock(&server->lock);
        if (qemudOneLoop() < 0) {
            virMutexLock(&server->lock);
            DEBUG0("Loop iteration error, exiting\n");
            break;
        }
        virMutexLock(&server->lock);

    reprocess:
        for (i = 0 ; i < server->nclients ; i++) {
            int inactive;
            virMutexLock(&server->clients[i]->lock);
            inactive = server->clients[i]->fd == -1
                && server->clients[i]->refs == 0;
            virMutexUnlock(&server->clients[i]->lock);
            if (inactive) {
                qemudFreeClient(server->clients[i]);
                server->nclients--;
                if (i < server->nclients)
                    memmove(server->clients + i,
                            server->clients + i + 1,
                            sizeof (*server->clients) * (server->nclients - i));

                if (VIR_REALLOC_N(server->clients,
                                  server->nclients) < 0) {
                    ; /* ignore */
                }
                goto reprocess;
            }
        }

        /* If number of active workers exceeds both the min_workers
         * threshold and the number of clients, then kill some
         * off */
        for (i = 0 ; (i < server->nworkers &&
                      server->nactiveworkers > server->nclients &&
                      server->nactiveworkers > min_workers) ; i++) {

            if (server->workers[i].hasThread &&
                !server->workers[i].processingCall) {
                server->workers[i].quitRequest = 1;

                virCondBroadcast(&server->job);
                virMutexUnlock(&server->lock);
                pthread_join(server->workers[i].thread, NULL);
                virMutexLock(&server->lock);
                server->workers[i].hasThread = 0;
                server->nactiveworkers--;
            }
        }
    }

cleanup:
    for (i = 0 ; i < server->nworkers ; i++) {
        if (!server->workers[i].hasThread)
            continue;

        server->workers[i].quitRequest = 1;
        virCondBroadcast(&server->job);

        virMutexUnlock(&server->lock);
        pthread_join(server->workers[i].thread, NULL);
        virMutexLock(&server->lock);
        server->workers[i].hasThread = 0;
    }
    VIR_FREE(server->workers);

    virMutexUnlock(&server->lock);
    return NULL;
}


static int qemudStartEventLoop(struct qemud_server *server) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    /* We want to join the eventloop, so don't detach it */
    /*pthread_attr_setdetachstate(&attr, 1);*/

    if (pthread_create(&server->eventThread,
                       &attr,
                       qemudRunLoop,
                       server) != 0)
        return -1;

    server->hasEventThread = 1;

    return 0;
}


static void qemudCleanup(struct qemud_server *server) {
    struct qemud_socket *sock;

    if (server->sigread != -1)
        close(server->sigread);
    if (server->sigwrite != -1)
        close(server->sigwrite);

    sock = server->sockets;
    while (sock) {
        struct qemud_socket *next = sock->next;
        if (sock->watch)
            virEventRemoveHandleImpl(sock->watch);
        close(sock->fd);
        VIR_FREE(sock);
        sock = next;
    }
    VIR_FREE(server->logDir);

#ifdef HAVE_SASL
    if (server->saslUsernameWhitelist) {
        char **list = server->saslUsernameWhitelist;
        while (*list) {
            VIR_FREE(*list);
            list++;
        }
        VIR_FREE(server->saslUsernameWhitelist);
    }
#endif

#if HAVE_POLKIT0
        if (server->sysbus)
            dbus_connection_unref(server->sysbus);
#endif

    virStateCleanup();

    if (virCondDestroy(&server->job) < 0) {
        ;
    }
    virMutexDestroy(&server->lock);

    VIR_FREE(server);
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
            VIR_ERROR(_("failed to allocate memory for %s config list"), key);
            return -1;
        }
        list[0] = strdup (p->str);
        list[1] = NULL;
        if (list[0] == NULL) {
            VIR_ERROR(_("failed to allocate memory for %s config list value"),
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
            VIR_ERROR(_("failed to allocate memory for %s config list"), key);
            return -1;
        }
        for (i = 0, pp = p->list; pp; ++i, pp = pp->next) {
            if (pp->type != VIR_CONF_STRING) {
                VIR_ERROR(_("remoteReadConfigFile: %s: %s:"
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
                VIR_ERROR(_("failed to allocate memory for %s config list value"),
                          key);
                return -1;
            }

        }
        list[i] = NULL;
        break;
    }

    default:
        VIR_ERROR(_("remoteReadConfigFile: %s: %s:"
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
        VIR_ERROR(_("remoteReadConfigFile: %s: %s: invalid type:"
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
                char ebuf[1024];                                        \
                VIR_ERROR(_("remoteReadConfigFile: %s"),		\
                          virStrerror(errno, ebuf, sizeof ebuf));       \
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
        VIR_ERROR(_("remoteReadConfigFile: %s: %s: unsupported auth %s"),
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

/*
 * Set up the logging environment
 * By default if daemonized all errors go to syslog and the logging
 * is also saved onto the logfile libvird.log, but if verbose or error
 * debugging is asked for then output informations or debug.
 */
static int
qemudSetLogging(virConfPtr conf, const char *filename)
{
    int log_level = 0;
    char *log_filters = NULL;
    char *log_outputs = NULL;
    int ret = -1;

    virLogReset();

    /*
     * Libvirtd's order of precedence is:
     * cmdline > environment > config
     *
     * In order to achieve this, we must process configuration in
     * different order for the log level versus the filters and
     * outputs. Because filters and outputs append, we have to look at
     * the environment first and then only check the config file if
     * there was no result from the environment. The default output is
     * then applied only if there was no setting from either of the
     * first two. Because we don't have a way to determine if the log
     * level has been set, we must process variables in the opposite
     * order, each one overriding the previous.
     */
    GET_CONF_INT (conf, filename, log_level);
    if (log_level != 0)
        virLogSetDefaultPriority(log_level);

    virLogSetFromEnv();

    if (virLogGetNbFilters() == 0) {
        GET_CONF_STR (conf, filename, log_filters);
        virLogParseFilters(log_filters);
    }

    if (virLogGetNbOutputs() == 0) {
        GET_CONF_STR (conf, filename, log_outputs);
        virLogParseOutputs(log_outputs);
    }

    /*
     * If no defined outputs, then direct to syslog when running
     * as daemon. Otherwise the default output is stderr.
     */
    if (virLogGetNbOutputs() == 0) {
        char *tmp = NULL;
        if (godaemon) {
            if (virAsprintf (&tmp, "%d:syslog:libvirtd",
                             virLogGetDefaultPriority()) < 0)
                goto free_and_fail;
        } else {
            if (virAsprintf (&tmp, "%d:stderr",
                             virLogGetDefaultPriority()) < 0)
                goto free_and_fail;
        }
        virLogParseOutputs(tmp);
        VIR_FREE(tmp);
    }

    /*
     * Command line override for --verbose
     */
    if ((verbose) && (virLogGetDefaultPriority() > VIR_LOG_INFO))
        virLogSetDefaultPriority(VIR_LOG_INFO);

    ret = 0;

free_and_fail:
    VIR_FREE(log_filters);
    VIR_FREE(log_outputs);
    return(ret);
}

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
    char *buf = NULL;

#if HAVE_POLKIT
    /* Change the default back to no auth for non-root */
    if (!server->privileged && auth_unix_rw == REMOTE_AUTH_POLKIT)
        auth_unix_rw = REMOTE_AUTH_NONE;
    if (!server->privileged && auth_unix_ro == REMOTE_AUTH_POLKIT)
        auth_unix_ro = REMOTE_AUTH_NONE;
#endif

    conf = virConfReadFile (filename, 0);
    if (!conf) return -1;

    /*
     * First get all the logging settings and activate them
     */
    if (qemudSetLogging(conf, filename) < 0)
        goto free_and_fail;

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
        if (!server->privileged) {
            VIR_WARN0(_("Cannot set group when not running as root"));
        } else {
            int ret;
            struct group grpdata, *grp;
            size_t maxbuf = sysconf(_SC_GETGR_R_SIZE_MAX);

            if (maxbuf == -1)
                maxbuf = 1024;

            if (VIR_ALLOC_N(buf, maxbuf) < 0) {
                VIR_ERROR("%s", _("Failed to allocate memory for buffer"));
                goto free_and_fail;
            }

            while ((ret = getgrnam_r(unix_sock_group, &grpdata,
                                     buf, maxbuf,
                                     &grp)) == ERANGE) {
                    maxbuf *= 2;
                    if (maxbuf > 65536 || VIR_REALLOC_N(buf, maxbuf) < 0) {
                        VIR_ERROR("%s", _("Failed to reallocate enough memory for buffer"));
                        goto free_and_fail;
                    }
            }

            if (ret != 0 || !grp) {
                VIR_ERROR(_("Failed to lookup group '%s'"), unix_sock_group);
                goto free_and_fail;
            }
            unix_sock_gid = grp->gr_gid;
            VIR_FREE(buf);
        }
        VIR_FREE(unix_sock_group);
    }

    GET_CONF_STR (conf, filename, unix_sock_ro_perms);
    if (unix_sock_ro_perms) {
        if (virStrToLong_i (unix_sock_ro_perms, NULL, 8, &unix_sock_ro_mask) != 0) {
            VIR_ERROR(_("Failed to parse mode '%s'"), unix_sock_ro_perms);
            goto free_and_fail;
        }
        VIR_FREE(unix_sock_ro_perms);
    }

    GET_CONF_STR (conf, filename, unix_sock_rw_perms);
    if (unix_sock_rw_perms) {
        if (virStrToLong_i (unix_sock_rw_perms, NULL, 8, &unix_sock_rw_mask) != 0) {
            VIR_ERROR(_("Failed to parse mode '%s'"), unix_sock_rw_perms);
            goto free_and_fail;
        }
        VIR_FREE(unix_sock_rw_perms);
    }

    GET_CONF_STR (conf, filename, unix_sock_dir);

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


    GET_CONF_INT (conf, filename, min_workers);
    GET_CONF_INT (conf, filename, max_workers);
    GET_CONF_INT (conf, filename, max_clients);

    GET_CONF_INT (conf, filename, max_requests);
    GET_CONF_INT (conf, filename, max_client_requests);

    virConfFree (conf);
    return 0;

 free_and_fail:
    virConfFree (conf);
    VIR_FREE(mdns_name);
    VIR_FREE(unix_sock_ro_perms);
    VIR_FREE(unix_sock_rw_perms);
    VIR_FREE(unix_sock_group);
    VIR_FREE(buf);

    /* Don't bother trying to free listen_addr, tcp_port, tls_port, key_file,
       cert_file, ca_file, or crl_file, since they are initialized to
       non-malloc'd strings.  Besides, these are static variables, and callers
       are unlikely to call this function more than once, so there wouldn't
       even be a real leak.  */

    if (tls_allowed_dn_list) {
        int i;
        for (i = 0; tls_allowed_dn_list[i]; i++)
            VIR_FREE(tls_allowed_dn_list[i]);
        VIR_FREE(tls_allowed_dn_list);
    }

    return -1;
}

/* Display version information. */
static void
version (const char *argv0)
{
    printf ("%s (%s) %s\n", argv0, PACKAGE_NAME, PACKAGE_VERSION);
}

#ifdef __sun
static int
qemudSetupPrivs (void)
{
    chown ("/var/run/libvirt", SYSTEM_UID, SYSTEM_UID);

    if (__init_daemon_priv (PU_RESETGROUPS | PU_CLEARLIMITSET,
        SYSTEM_UID, SYSTEM_UID, PRIV_XVM_CONTROL, NULL)) {
        VIR_ERROR0(_("additional privileges are required"));
        return -1;
    }

    if (priv_set (PRIV_OFF, PRIV_ALLSETS, PRIV_FILE_LINK_ANY, PRIV_PROC_INFO,
        PRIV_PROC_SESSION, PRIV_PROC_EXEC, PRIV_PROC_FORK, NULL)) {
        VIR_ERROR0(_("failed to set reduced privileges"));
        return -1;
    }

    return 0;
}
#else
#define qemudSetupPrivs() 0
#endif


/*
 * Doing anything non-trivial in signal handlers is pretty dangerous,
 * since there are very few async-signal safe POSIX funtions. To
 * deal with this we setup a very simple signal handler. It simply
 * writes the signal number to a pipe. The main event loop then sees
 * the signal on the pipe and can safely do the processing from
 * event loop context
 */
static int
daemonSetupSignals(struct qemud_server *server)
{
    struct sigaction sig_action;
    int sigpipe[2];

    if (pipe(sigpipe) < 0)
        return -1;

    if (virSetNonBlock(sigpipe[0]) < 0 ||
        virSetNonBlock(sigpipe[1]) < 0 ||
        virSetCloseExec(sigpipe[0]) < 0 ||
        virSetCloseExec(sigpipe[1]) < 0) {
        char ebuf[1024];
        VIR_ERROR(_("Failed to create pipe: %s"),
                  virStrerror(errno, ebuf, sizeof ebuf));
        goto error;
    }

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

    if (virEventAddHandleImpl(sigpipe[0],
                              VIR_EVENT_HANDLE_READABLE,
                              qemudDispatchSignalEvent,
                              server, NULL) < 0) {
        VIR_ERROR0(_("Failed to register callback for signal pipe"));
        goto error;
    }

    server->sigread = sigpipe[0];
    server->sigwrite = sigpipe[1];
    sigwrite = sigpipe[1];

    return 0;

error:
    close(sigpipe[0]);
    close(sigpipe[1]);
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
     | --version         Display version information.\n\
  -p | --pid-file <file> Change name of PID file.\n\
\n\
libvirt management daemon:\n\
\n\
  Default paths:\n\
\n\
    Configuration file (unless overridden by -f):\n\
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

enum {
    OPT_VERSION = 129
};

#define MAX_LISTEN 5
int main(int argc, char **argv) {
    struct qemud_server *server = NULL;
    const char *pid_file = NULL;
    const char *remote_config_file = NULL;
    int statuswrite = -1;
    int ret = 1;

    struct option opts[] = {
        { "verbose", no_argument, &verbose, 1},
        { "daemon", no_argument, &godaemon, 1},
        { "listen", no_argument, &ipsock, 1},
        { "config", required_argument, NULL, 'f'},
        { "timeout", required_argument, NULL, 't'},
        { "pid-file", required_argument, NULL, 'p'},
        { "version", no_argument, NULL, OPT_VERSION },
        { "help", no_argument, NULL, '?' },
        {0, 0, 0, 0}
    };

    virInitialize();

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

        case OPT_VERSION:
            version (argv[0]);
            return 0;

        case '?':
            usage (argv[0]);
            return 2;

        default:
            fprintf (stderr, "libvirtd: internal error: unknown flag: %c\n",
                     c);
            exit (EXIT_FAILURE);
        }
    }

    if (remote_config_file == NULL) {
        static const char *default_config_file
            = SYSCONF_DIR "/libvirt/libvirtd.conf";
        remote_config_file =
            (access(default_config_file, R_OK) == 0
             ? default_config_file
             : "/dev/null");
    }

    if (godaemon) {
        char ebuf[1024];
        if ((statuswrite = daemonForkIntoBackground()) < 0) {
            VIR_ERROR(_("Failed to fork as daemon: %s"),
                      virStrerror(errno, ebuf, sizeof ebuf));
            goto error;
        }
    }

    /* If running as root and no PID file is set, use the default */
    if (pid_file == NULL &&
        geteuid() == 0 &&
        REMOTE_PID_FILE[0] != '\0')
        pid_file = REMOTE_PID_FILE;

    /* If we have a pidfile set, claim it now, exiting if already taken */
    if (pid_file != NULL &&
        qemudWritePidFile (pid_file) < 0) {
        pid_file = NULL; /* Prevent unlinking of someone else's pid ! */
        ret = VIR_DAEMON_ERR_PIDFILE;
        goto error;
    }

    /* Ensure the rundir exists (on tmpfs on some systems) */
    if (geteuid() == 0) {
        const char *rundir = LOCAL_STATE_DIR "/run/libvirt";

        if (mkdir (rundir, 0755)) {
            if (errno != EEXIST) {
                char ebuf[1024];
                VIR_ERROR(_("unable to create rundir %s: %s"), rundir,
                          virStrerror(errno, ebuf, sizeof(ebuf)));
                ret = VIR_DAEMON_ERR_RUNDIR;
                goto error;
            }
        }
    }

    /* Beyond this point, nothing should rely on using
     * getuid/geteuid() == 0, for privilege level checks.
     * It must all use the flag 'server->privileged'
     * which is also passed into all libvirt stateful
     * drivers
     */
    if (qemudSetupPrivs() < 0) {
        ret = VIR_DAEMON_ERR_PRIVS;
        goto error;
    }

    if (!(server = qemudInitialize())) {
        ret = VIR_DAEMON_ERR_INIT;
        goto error;
    }

    if ((daemonSetupSignals(server)) < 0) {
        ret = VIR_DAEMON_ERR_SIGNAL;
        goto error;
    }

    /* Read the config file (if it exists). */
    if (remoteReadConfigFile (server, remote_config_file) < 0) {
        ret = VIR_DAEMON_ERR_CONFIG;
        goto error;
    }

    /* Disable error func, now logging is setup */
    virSetErrorFunc(NULL, virshErrorHandler);

    if (qemudNetworkInit(server) < 0) {
        ret = VIR_DAEMON_ERR_NETWORK;
        goto error;
    }

    /* Tell parent of daemon that basic initialization is complete
     * In particular we're ready to accept net connections & have
     * written the pidfile
     */
    if (statuswrite != -1) {
        char status = 0;
        while (write(statuswrite, &status, 1) == -1 &&
               errno == EINTR)
            ;
        close(statuswrite);
        statuswrite = -1;
    }

    /* Start the event loop in a background thread, since
     * state initialization needs events to be being processed */
    if (qemudStartEventLoop(server) < 0) {
        VIR_ERROR0("Event thread startup failed");
        goto error;
    }

    /* Start the stateful HV drivers
     * This is delibrately done after telling the parent process
     * we're ready, since it can take a long time and this will
     * seriously delay OS bootup process */
    if (virStateInitialize(server->privileged) < 0) {
        VIR_ERROR0("Driver state initialization failed");
        goto shutdown;
    }

    /* Start accepting new clients from network */
    virMutexLock(&server->lock);
    if (qemudNetworkEnable(server) < 0) {
        VIR_ERROR0("Network event loop enablement failed");
        goto shutdown;
    }
    virMutexUnlock(&server->lock);

    ret = 0;

shutdown:
    /* In a non-0 shutdown scenario we need to tell event loop
     * to quit immediately. Otherwise in normal case we just
     * sit in the thread join forever. Sure this means the
     * main thread doesn't do anything useful ever, but that's
     * not too much of drain on resources
     */
    if (ret != 0) {
        virMutexLock(&server->lock);
        if (server->hasEventThread)
            /* This SIGQUIT triggers the shutdown process */
            kill(getpid(), SIGQUIT);
        virMutexUnlock(&server->lock);
    }
    pthread_join(server->eventThread, NULL);

error:
    if (statuswrite != -1) {
        if (ret != 0) {
            /* Tell parent of daemon what failed */
            char status = ret;
            while (write(statuswrite, &status, 1) == -1 &&
                   errno == EINTR)
                ;
        }
        close(statuswrite);
    }
    if (server)
        qemudCleanup(server);
    if (pid_file)
        unlink (pid_file);
    virLogShutdown();
    return ret;
}
