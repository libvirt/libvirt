/*
 * virnetsocket.c: generic network socket handling
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_IFADDRS_H
# include <ifaddrs.h>
#endif
#include <netdb.h>

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#ifdef HAVE_SYS_UCRED_H
# include <sys/ucred.h>
#endif

#include "c-ctype.h"
#ifdef WITH_SELINUX
# include <selinux/selinux.h>
#endif

#include "virnetsocket.h"
#include "virutil.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virfile.h"
#include "virthread.h"
#include "virpidfile.h"
#include "virprobe.h"
#include "virprocess.h"
#include "virstring.h"
#include "dirname.h"
#include "passfd.h"

#if WITH_SSH2
# include "virnetsshsession.h"
#endif

#if WITH_LIBSSH
# include "virnetlibsshsession.h"
#endif

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netsocket");

struct _virNetSocket {
    virObjectLockable parent;

    int fd;
    int watch;
    pid_t pid;
    int errfd;
    bool isClient;
    bool ownsFd;
    bool quietEOF;
    bool unlinkUNIX;

    /* Event callback fields */
    virNetSocketIOFunc func;
    void *opaque;
    virFreeCallback ff;

    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    char *localAddrStrSASL;
    char *remoteAddrStrSASL;
    char *remoteAddrStrURI;

#if WITH_GNUTLS
    virNetTLSSessionPtr tlsSession;
#endif
#if WITH_SASL
    virNetSASLSessionPtr saslSession;

    const char *saslDecoded;
    size_t saslDecodedLength;
    size_t saslDecodedOffset;

    const char *saslEncoded;
    size_t saslEncodedLength;
    size_t saslEncodedRawLength;
    size_t saslEncodedOffset;
#endif
#if WITH_SSH2
    virNetSSHSessionPtr sshSession;
#endif
#if WITH_LIBSSH
    virNetLibsshSessionPtr libsshSession;
#endif
};


static virClassPtr virNetSocketClass;
static void virNetSocketDispose(void *obj);

static int virNetSocketOnceInit(void)
{
    if (!VIR_CLASS_NEW(virNetSocket, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virNetSocket);


#ifndef WIN32
static int virNetSocketForkDaemon(const char *binary)
{
    int ret;
    virCommandPtr cmd = virCommandNewArgList(binary,
                                             "--timeout=120",
                                             NULL);

    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvPass(cmd, "XDG_CACHE_HOME");
    virCommandAddEnvPass(cmd, "XDG_CONFIG_HOME");
    virCommandAddEnvPass(cmd, "XDG_RUNTIME_DIR");
    virCommandClearCaps(cmd);
    virCommandDaemonize(cmd);
    ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    return ret;
}
#endif

int virNetSocketCheckProtocols(bool *hasIPv4,
                               bool *hasIPv6)
{
#ifdef HAVE_IFADDRS_H
    struct ifaddrs *ifaddr = NULL, *ifa;
    struct addrinfo hints;
    struct addrinfo *ai = NULL;
    int ret = -1;
    int gaierr;

    memset(&hints, 0, sizeof(hints));

    *hasIPv4 = *hasIPv6 = false;

    if (getifaddrs(&ifaddr) < 0) {
        virReportSystemError(errno, "%s",
                             _("Cannot get host interface addresses"));
        goto cleanup;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET)
            *hasIPv4 = true;
        if (ifa->ifa_addr->sa_family == AF_INET6)
            *hasIPv6 = true;
    }

    freeifaddrs(ifaddr);

    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;

    if ((gaierr = getaddrinfo("::1", NULL, &hints, &ai)) != 0) {
        if (gaierr == EAI_ADDRFAMILY ||
            gaierr == EAI_FAMILY ||
            gaierr == EAI_NONAME) {
            *hasIPv6 = false;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot resolve ::1 address: %s"),
                           gai_strerror(gaierr));
            goto cleanup;
        }
    }

    freeaddrinfo(ai);

    VIR_DEBUG("Protocols: v4 %d v6 %d", *hasIPv4, *hasIPv6);

    ret = 0;
 cleanup:
    return ret;
#else
    *hasIPv4 = *hasIPv6 = false;
    virReportError(VIR_ERR_NO_SUPPORT, "%s",
                   _("Cannot check address family on this platform"));
    return -1;
#endif
}


static virNetSocketPtr
virNetSocketNew(virSocketAddrPtr localAddr,
                virSocketAddrPtr remoteAddr,
                bool isClient,
                int fd,
                int errfd,
                pid_t pid,
                bool unlinkUNIX)
{
    virNetSocketPtr sock;
    int no_slow_start = 1;

    if (virNetSocketInitialize() < 0)
        return NULL;

    VIR_DEBUG("localAddr=%p remoteAddr=%p fd=%d errfd=%d pid=%lld",
              localAddr, remoteAddr,
              fd, errfd, (long long)pid);

    if (virSetCloseExec(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to set close-on-exec flag"));
       return NULL;
    }
    if (virSetNonBlock(fd) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to enable non-blocking flag"));
        return NULL;
    }

    if (!(sock = virObjectLockableNew(virNetSocketClass)))
        return NULL;

    if (localAddr)
        sock->localAddr = *localAddr;
    if (remoteAddr)
        sock->remoteAddr = *remoteAddr;
    sock->fd = fd;
    sock->errfd = errfd;
    sock->pid = pid;
    sock->watch = -1;
    sock->ownsFd = true;
    sock->isClient = isClient;
    sock->unlinkUNIX = unlinkUNIX;

    /* Disable nagle for TCP sockets */
    if (sock->localAddr.data.sa.sa_family == AF_INET ||
        sock->localAddr.data.sa.sa_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
                       &no_slow_start,
                       sizeof(no_slow_start)) < 0) {
            virReportSystemError(errno, "%s",
                                 _("Unable to disable nagle algorithm"));
            goto error;
        }
    }


    if (localAddr &&
        !(sock->localAddrStrSASL = virSocketAddrFormatFull(localAddr, true, ";")))
        goto error;

    if (remoteAddr &&
        !(sock->remoteAddrStrSASL = virSocketAddrFormatFull(remoteAddr, true, ";")))
        goto error;

    if (remoteAddr &&
        !(sock->remoteAddrStrURI = virSocketAddrFormatFull(remoteAddr, true, NULL)))
        goto error;

    PROBE(RPC_SOCKET_NEW,
          "sock=%p fd=%d errfd=%d pid=%lld localAddr=%s, remoteAddr=%s",
          sock, fd, errfd, (long long)pid,
          NULLSTR(sock->localAddrStrSASL), NULLSTR(sock->remoteAddrStrSASL));

    return sock;

 error:
    sock->fd = sock->errfd = -1; /* Caller owns fd/errfd on failure */
    virObjectUnref(sock);
    return NULL;
}


int virNetSocketNewListenTCP(const char *nodename,
                             const char *service,
                             int family,
                             virNetSocketPtr **retsocks,
                             size_t *nretsocks)
{
    virNetSocketPtr *socks = NULL;
    size_t nsocks = 0;
    struct addrinfo *ai = NULL;
    struct addrinfo hints;
    int fd = -1;
    size_t i;
    int socketErrno = 0;
    int bindErrno = 0;
    virSocketAddr tmp_addr;
    int port = 0;

    *retsocks = NULL;
    *nretsocks = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;

    /* Don't use ADDRCONFIG for binding to the wildcard address.
     * Just catch the error returned by socket() if the system has
     * no IPv6 support.
     *
     * This allows libvirtd to be started in parallel with the network
     * startup in most cases.
     */
    if (nodename &&
        !(virSocketAddrParseAny(&tmp_addr, nodename, AF_UNSPEC, false) > 0 &&
          virSocketAddrIsWildcard(&tmp_addr)))
        hints.ai_flags |= AI_ADDRCONFIG;

    int e = getaddrinfo(nodename, service, &hints, &ai);
    if (e != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to resolve address '%s' service '%s': %s"),
                       nodename, service, gai_strerror(e));
        return -1;
    }

    struct addrinfo *runp = ai;
    while (runp) {
        virSocketAddr addr;

        memset(&addr, 0, sizeof(addr));

        if ((fd = socket(runp->ai_family, runp->ai_socktype,
                         runp->ai_protocol)) < 0) {
            if (errno == EAFNOSUPPORT) {
                socketErrno = errno;
                runp = runp->ai_next;
                continue;
            }
            virReportSystemError(errno, "%s", _("Unable to create socket"));
            goto error;
        }

        if (virSetSockReuseAddr(fd, true) < 0)
            goto error;

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
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                           (void*)&on, sizeof(on)) < 0) {
                virReportSystemError(errno, "%s",
                                     _("Unable to force bind to IPv6 only"));
                goto error;
            }
        }
#endif

        addr.len = runp->ai_addrlen;
        memcpy(&addr.data.sa, runp->ai_addr, runp->ai_addrlen);

        /* When service is NULL, we let the kernel auto-select the
         * port. Once we've selected a port for one IP protocol
         * though, we want to ensure we pick the same port for the
         * other IP protocol
         */
        if (port != 0 && service == NULL) {
            if (addr.data.sa.sa_family == AF_INET) {
                addr.data.inet4.sin_port = port;
            } else if (addr.data.sa.sa_family == AF_INET6) {
                addr.data.inet6.sin6_port = port;
            }
            VIR_DEBUG("Used saved port %d", port);
        }

        if (bind(fd, &addr.data.sa, addr.len) < 0) {
            if (errno != EADDRINUSE && errno != EADDRNOTAVAIL) {
                virReportSystemError(errno, "%s", _("Unable to bind to port"));
                goto error;
            }
            bindErrno = errno;
            VIR_FORCE_CLOSE(fd);
            runp = runp->ai_next;
            continue;
        }

        addr.len = sizeof(addr.data);
        if (getsockname(fd, &addr.data.sa, &addr.len) < 0) {
            virReportSystemError(errno, "%s", _("Unable to get local socket name"));
            goto error;
        }

        if (port == 0 && service == NULL) {
            if (addr.data.sa.sa_family == AF_INET)
                port = addr.data.inet4.sin_port;
            else if (addr.data.sa.sa_family == AF_INET6)
                port = addr.data.inet6.sin6_port;
            VIR_DEBUG("Saved port %d", port);
        }

        VIR_DEBUG("%p f=%d f=%d", &addr, runp->ai_family, addr.data.sa.sa_family);

        if (VIR_EXPAND_N(socks, nsocks, 1) < 0)
            goto error;

        if (!(socks[nsocks-1] = virNetSocketNew(&addr, NULL, false, fd, -1, 0, false)))
            goto error;
        runp = runp->ai_next;
        fd = -1;
    }

    if (nsocks == 0) {
        if (bindErrno)
            virReportSystemError(bindErrno, "%s", _("Unable to bind to port"));
        else if (socketErrno)
            virReportSystemError(socketErrno, "%s", _("Unable to create socket"));
        else
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _("No addresses to bind to"));
        goto error;
    }

    freeaddrinfo(ai);

    *retsocks = socks;
    *nretsocks = nsocks;
    return 0;

 error:
    for (i = 0; i < nsocks; i++)
        virObjectUnref(socks[i]);
    VIR_FREE(socks);
    freeaddrinfo(ai);
    VIR_FORCE_CLOSE(fd);
    return -1;
}


#if HAVE_SYS_UN_H
int virNetSocketNewListenUNIX(const char *path,
                              mode_t mask,
                              uid_t user,
                              gid_t grp,
                              virNetSocketPtr *retsock)
{
    virSocketAddr addr;
    mode_t oldmask;
    int fd;

    *retsock = NULL;

    memset(&addr, 0, sizeof(addr));

    addr.len = sizeof(addr.data.un);

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s", _("Failed to create socket"));
        goto error;
    }

    addr.data.un.sun_family = AF_UNIX;
    if (virStrcpyStatic(addr.data.un.sun_path, path) < 0) {
        virReportSystemError(ENAMETOOLONG,
                             _("Path %s too long for unix socket"), path);
        goto error;
    }
    if (addr.data.un.sun_path[0] == '@')
        addr.data.un.sun_path[0] = '\0';
    else
        unlink(addr.data.un.sun_path);

    oldmask = umask(~mask);

    if (bind(fd, &addr.data.sa, addr.len) < 0) {
        umask(oldmask);
        virReportSystemError(errno,
                             _("Failed to bind socket to '%s'"),
                             path);
        goto error;
    }
    umask(oldmask);

    /* chown() doesn't work for abstract sockets but we use them only
     * if libvirtd runs unprivileged
     */
    if (grp != 0 && chown(path, user, grp)) {
        virReportSystemError(errno,
                             _("Failed to change ownership of '%s' to %d:%d"),
                             path, (int)user, (int)grp);
        goto error;
    }

    if (!(*retsock = virNetSocketNew(&addr, NULL, false, fd, -1, 0, true)))
        goto error;

    return 0;

 error:
    if (path[0] != '@')
        unlink(path);
    VIR_FORCE_CLOSE(fd);
    return -1;
}
#else
int virNetSocketNewListenUNIX(const char *path ATTRIBUTE_UNUSED,
                              mode_t mask ATTRIBUTE_UNUSED,
                              uid_t user ATTRIBUTE_UNUSED,
                              gid_t grp ATTRIBUTE_UNUSED,
                              virNetSocketPtr *retsock ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("UNIX sockets are not supported on this platform"));
    return -1;
}
#endif

int virNetSocketNewListenFD(int fd,
                            bool unlinkUNIX,
                            virNetSocketPtr *retsock)
{
    virSocketAddr addr;
    *retsock = NULL;

    memset(&addr, 0, sizeof(addr));

    addr.len = sizeof(addr.data);
    if (getsockname(fd, &addr.data.sa, &addr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        return -1;
    }

    if (!(*retsock = virNetSocketNew(&addr, NULL, false, fd, -1, 0, unlinkUNIX)))
        return -1;

    return 0;
}


int virNetSocketNewConnectTCP(const char *nodename,
                              const char *service,
                              int family,
                              virNetSocketPtr *retsock)
{
    struct addrinfo *ai = NULL;
    struct addrinfo hints;
    int fd = -1;
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    struct addrinfo *runp;
    int savedErrno = ENOENT;

    *retsock = NULL;

    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    int e = getaddrinfo(nodename, service, &hints, &ai);
    if (e != 0) {
        virReportError(VIR_ERR_SYSTEM_ERROR,
                       _("Unable to resolve address '%s' service '%s': %s"),
                       nodename, service, gai_strerror(e));
        return -1;
    }

    runp = ai;
    while (runp) {
        if ((fd = socket(runp->ai_family, runp->ai_socktype,
                         runp->ai_protocol)) < 0) {
            virReportSystemError(errno, "%s", _("Unable to create socket"));
            goto error;
        }

        if (virSetSockReuseAddr(fd, false) < 0)
            VIR_WARN("Unable to enable port reuse");

        if (connect(fd, runp->ai_addr, runp->ai_addrlen) >= 0)
            break;

        savedErrno = errno;
        VIR_FORCE_CLOSE(fd);
        runp = runp->ai_next;
    }

    if (fd == -1) {
        virReportSystemError(savedErrno,
                             _("unable to connect to server at '%s:%s'"),
                             nodename, service);
        goto error;
    }

    localAddr.len = sizeof(localAddr.data);
    if (getsockname(fd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        goto error;
    }

    remoteAddr.len = sizeof(remoteAddr.data);
    if (getpeername(fd, &remoteAddr.data.sa, &remoteAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get remote socket name"));
        goto error;
    }

    if (!(*retsock = virNetSocketNew(&localAddr, &remoteAddr, true, fd, -1, 0, false)))
        goto error;

    freeaddrinfo(ai);

    return 0;

 error:
    freeaddrinfo(ai);
    VIR_FORCE_CLOSE(fd);
    return -1;
}


#ifdef HAVE_SYS_UN_H
int virNetSocketNewConnectUNIX(const char *path,
                               bool spawnDaemon,
                               const char *binary,
                               virNetSocketPtr *retsock)
{
    char *lockpath = NULL;
    int lockfd = -1;
    int fd = -1;
    int retries = 500;
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    char *rundir = NULL;
    int ret = -1;
    bool daemonLaunched = false;

    VIR_DEBUG("path=%s spawnDaemon=%d binary=%s", path, spawnDaemon,
        NULLSTR(binary));

    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));

    remoteAddr.len = sizeof(remoteAddr.data.un);

    if (spawnDaemon) {
        const char *binname;

        if (spawnDaemon && !binary) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Auto-spawn of daemon requested, "
                             "but no binary specified"));
            goto cleanup;
        }

        if (!(binname = last_component(binary)) || binname[0] == '\0') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Cannot determine basename for binary '%s'"),
                           binary);
            goto cleanup;
        }

        if (!(rundir = virGetUserRuntimeDirectory()))
            goto cleanup;

        if (virFileMakePathWithMode(rundir, 0700) < 0) {
            virReportSystemError(errno,
                                 _("Cannot create user runtime directory '%s'"),
                                 rundir);
            goto cleanup;
        }

        if (virAsprintf(&lockpath, "%s/%s.lock", rundir, binname) < 0)
            goto cleanup;

        if ((lockfd = open(lockpath, O_RDWR | O_CREAT, 0600)) < 0 ||
            virSetCloseExec(lockfd) < 0) {
            virReportSystemError(errno, _("Unable to create lock '%s'"), lockpath);
            goto cleanup;
        }

        if (virFileLock(lockfd, false, 0, 1, true) < 0) {
            virReportSystemError(errno, _("Unable to lock '%s'"), lockpath);
            goto cleanup;
        }
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s", _("Failed to create socket"));
        goto cleanup;
    }

    remoteAddr.data.un.sun_family = AF_UNIX;
    if (virStrcpyStatic(remoteAddr.data.un.sun_path, path) < 0) {
        virReportSystemError(ENOMEM, _("Path %s too long for unix socket"), path);
        goto cleanup;
    }
    if (remoteAddr.data.un.sun_path[0] == '@')
        remoteAddr.data.un.sun_path[0] = '\0';

    while (retries) {
        if (connect(fd, &remoteAddr.data.sa, remoteAddr.len) == 0) {
            VIR_DEBUG("connect() succeeded");
            break;
        }
        VIR_DEBUG("connect() failed: retries=%d errno=%d", retries, errno);

        retries--;
        if (!spawnDaemon ||
            retries == 0 ||
            (errno != ENOENT && errno != ECONNREFUSED)) {
            virReportSystemError(errno, _("Failed to connect socket to '%s'"),
                                 path);
            goto cleanup;
        }

        if (!daemonLaunched) {
            if (virNetSocketForkDaemon(binary) < 0)
                goto cleanup;

            daemonLaunched = true;
        }

        usleep(10000);
    }

    localAddr.len = sizeof(localAddr.data);
    if (getsockname(fd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        goto cleanup;
    }

    if (!(*retsock = virNetSocketNew(&localAddr, &remoteAddr, true, fd, -1, 0, false)))
        goto cleanup;

    ret = 0;

 cleanup:
    if (lockfd != -1) {
        unlink(lockpath);
        VIR_FORCE_CLOSE(lockfd);
    }
    VIR_FREE(lockpath);
    VIR_FREE(rundir);

    if (ret < 0)
        VIR_FORCE_CLOSE(fd);

    return ret;
}
#else
int virNetSocketNewConnectUNIX(const char *path ATTRIBUTE_UNUSED,
                               bool spawnDaemon ATTRIBUTE_UNUSED,
                               const char *binary ATTRIBUTE_UNUSED,
                               virNetSocketPtr *retsock ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("UNIX sockets are not supported on this platform"));
    return -1;
}
#endif


#ifndef WIN32
int virNetSocketNewConnectCommand(virCommandPtr cmd,
                                  virNetSocketPtr *retsock)
{
    pid_t pid = 0;
    int sv[2] = { -1, -1 };
    int errfd[2] = { -1, -1 };

    *retsock = NULL;

    /* Fork off the external process.  Use socketpair to create a private
     * (unnamed) Unix domain socket to the child process so we don't have
     * to faff around with two file descriptors (a la 'pipe(2)').
     */
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to create socket pair"));
        goto error;
    }

    if (pipe(errfd) < 0) {
        virReportSystemError(errno, "%s",
                             _("unable to create socket pair"));
        goto error;
    }

    virCommandSetInputFD(cmd, sv[1]);
    virCommandSetOutputFD(cmd, &sv[1]);
    virCommandSetErrorFD(cmd, &errfd[1]);

    if (virCommandRunAsync(cmd, &pid) < 0)
        goto error;

    /* Parent continues here. */
    VIR_FORCE_CLOSE(sv[1]);
    VIR_FORCE_CLOSE(errfd[1]);

    if (!(*retsock = virNetSocketNew(NULL, NULL, true, sv[0], errfd[0], pid, false)))
        goto error;

    virCommandFree(cmd);

    return 0;

 error:
    VIR_FORCE_CLOSE(sv[0]);
    VIR_FORCE_CLOSE(sv[1]);
    VIR_FORCE_CLOSE(errfd[0]);
    VIR_FORCE_CLOSE(errfd[1]);

    virCommandAbort(cmd);
    virCommandFree(cmd);

    return -1;
}
#else
int virNetSocketNewConnectCommand(virCommandPtr cmd ATTRIBUTE_UNUSED,
                                  virNetSocketPtr *retsock ATTRIBUTE_UNUSED)
{
    virReportSystemError(errno, "%s",
                         _("Tunnelling sockets not supported on this platform"));
    return -1;
}
#endif

int virNetSocketNewConnectSSH(const char *nodename,
                              const char *service,
                              const char *binary,
                              const char *username,
                              bool noTTY,
                              bool noVerify,
                              const char *netcat,
                              const char *keyfile,
                              const char *path,
                              virNetSocketPtr *retsock)
{
    char *quoted;
    virCommandPtr cmd;
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    *retsock = NULL;

    cmd = virCommandNew(binary ? binary : "ssh");
    virCommandAddEnvPassCommon(cmd);
    virCommandAddEnvPass(cmd, "KRB5CCNAME");
    virCommandAddEnvPass(cmd, "SSH_AUTH_SOCK");
    virCommandAddEnvPass(cmd, "SSH_ASKPASS");
    virCommandAddEnvPass(cmd, "DISPLAY");
    virCommandAddEnvPass(cmd, "XAUTHORITY");
    virCommandClearCaps(cmd);

    if (service)
        virCommandAddArgList(cmd, "-p", service, NULL);
    if (username)
        virCommandAddArgList(cmd, "-l", username, NULL);
    if (keyfile)
        virCommandAddArgList(cmd, "-i", keyfile, NULL);
    virCommandAddArgList(cmd, "-T", "-e", "none", NULL);
    if (noTTY)
        virCommandAddArgList(cmd, "-o", "BatchMode=yes", NULL);
    if (noVerify)
        virCommandAddArgList(cmd, "-o", "StrictHostKeyChecking=no", NULL);

    if (!netcat)
        netcat = "nc";

    virCommandAddArgList(cmd, "--", nodename, "sh", "-c", NULL);

    virBufferEscapeShell(&buf, netcat);
    if (virBufferCheckError(&buf) < 0) {
        virCommandFree(cmd);
        return -1;
    }
    quoted = virBufferContentAndReset(&buf);

    virBufferEscapeShell(&buf, quoted);
    VIR_FREE(quoted);
    if (virBufferCheckError(&buf) < 0) {
        virCommandFree(cmd);
        return -1;
    }
    quoted = virBufferContentAndReset(&buf);

    /*
     * This ugly thing is a shell script to detect availability of
     * the -q option for 'nc': debian and suse based distros need this
     * flag to ensure the remote nc will exit on EOF, so it will go away
     * when we close the connection tunnel. If it doesn't go away, subsequent
     * connection attempts will hang.
     *
     * Fedora's 'nc' doesn't have this option, and defaults to the desired
     * behavior.
     */
    virCommandAddArgFormat(cmd,
         "'if '%s' -q 2>&1 | grep \"requires an argument\" >/dev/null 2>&1; then "
             "ARG=-q0;"
         "else "
             "ARG=;"
         "fi;"
         "'%s' $ARG -U %s'",
         quoted, quoted, path);

    VIR_FREE(quoted);
    return virNetSocketNewConnectCommand(cmd, retsock);
}

#if WITH_SSH2
int
virNetSocketNewConnectLibSSH2(const char *host,
                              const char *port,
                              int family,
                              const char *username,
                              const char *privkey,
                              const char *knownHosts,
                              const char *knownHostsVerify,
                              const char *authMethods,
                              const char *command,
                              virConnectAuthPtr auth,
                              virURIPtr uri,
                              virNetSocketPtr *retsock)
{
    virNetSocketPtr sock = NULL;
    virNetSSHSessionPtr sess = NULL;
    unsigned int verify;
    int ret = -1;
    int portN;

    char *authMethodNext = NULL;
    char *authMethodsCopy = NULL;
    char *authMethod;

    /* port number will be verified while opening the socket */
    if (virStrToLong_i(port, NULL, 10, &portN) < 0) {
        virReportError(VIR_ERR_SSH, "%s",
                       _("Failed to parse port number"));
        goto error;
    }

    /* create ssh session context */
    if (!(sess = virNetSSHSessionNew()))
        goto error;

    /* set ssh session parameters */
    if (virNetSSHSessionAuthSetCallback(sess, auth) != 0)
        goto error;

    if (STRCASEEQ("auto", knownHostsVerify)) {
        verify = VIR_NET_SSH_HOSTKEY_VERIFY_AUTO_ADD;
    } else if (STRCASEEQ("ignore", knownHostsVerify)) {
        verify = VIR_NET_SSH_HOSTKEY_VERIFY_IGNORE;
    } else if (STRCASEEQ("normal", knownHostsVerify)) {
        verify = VIR_NET_SSH_HOSTKEY_VERIFY_NORMAL;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid host key verification method: '%s'"),
                       knownHostsVerify);
        goto error;
    }

    if (virNetSSHSessionSetHostKeyVerification(sess,
                                               host,
                                               portN,
                                               knownHosts,
                                               verify,
                                               VIR_NET_SSH_HOSTKEY_FILE_CREATE) != 0)
        goto error;

    if (virNetSSHSessionSetChannelCommand(sess, command) != 0)
        goto error;

    if (VIR_STRDUP(authMethodsCopy, authMethods) < 0)
        goto error;

    authMethodNext = authMethodsCopy;

    while ((authMethod = strsep(&authMethodNext, ","))) {
        if (STRCASEEQ(authMethod, "keyboard-interactive")) {
            ret = virNetSSHSessionAuthAddKeyboardAuth(sess, username, -1);
        } else if (STRCASEEQ(authMethod, "password")) {
            ret = virNetSSHSessionAuthAddPasswordAuth(sess,
                                                      uri,
                                                      username);
        } else if (STRCASEEQ(authMethod, "privkey")) {
            ret = virNetSSHSessionAuthAddPrivKeyAuth(sess,
                                                     username,
                                                     privkey,
                                                     NULL);
        } else if (STRCASEEQ(authMethod, "agent")) {
            ret = virNetSSHSessionAuthAddAgentAuth(sess, username);
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid authentication method: '%s'"),
                           authMethod);
            ret = -1;
            goto error;
        }

        if (ret != 0)
            goto error;
    }

    /* connect to remote server */
    if ((ret = virNetSocketNewConnectTCP(host, port, family, &sock)) < 0)
        goto error;

    /* connect to the host using ssh */
    if ((ret = virNetSSHSessionConnect(sess, virNetSocketGetFD(sock))) != 0)
        goto error;

    sock->sshSession = sess;
    *retsock = sock;

    VIR_FREE(authMethodsCopy);
    return 0;

 error:
    virObjectUnref(sock);
    virObjectUnref(sess);
    VIR_FREE(authMethodsCopy);
    return ret;
}
#else
int
virNetSocketNewConnectLibSSH2(const char *host ATTRIBUTE_UNUSED,
                              const char *port ATTRIBUTE_UNUSED,
                              int family ATTRIBUTE_UNUSED,
                              const char *username ATTRIBUTE_UNUSED,
                              const char *privkey ATTRIBUTE_UNUSED,
                              const char *knownHosts ATTRIBUTE_UNUSED,
                              const char *knownHostsVerify ATTRIBUTE_UNUSED,
                              const char *authMethods ATTRIBUTE_UNUSED,
                              const char *command ATTRIBUTE_UNUSED,
                              virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                              virURIPtr uri ATTRIBUTE_UNUSED,
                              virNetSocketPtr *retsock ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("libssh2 transport support was not enabled"));
    return -1;
}
#endif /* WITH_SSH2 */

#if WITH_LIBSSH
int
virNetSocketNewConnectLibssh(const char *host,
                             const char *port,
                             int family,
                             const char *username,
                             const char *privkey,
                             const char *knownHosts,
                             const char *knownHostsVerify,
                             const char *authMethods,
                             const char *command,
                             virConnectAuthPtr auth,
                             virURIPtr uri,
                             virNetSocketPtr *retsock)
{
    virNetSocketPtr sock = NULL;
    virNetLibsshSessionPtr sess = NULL;
    unsigned int verify;
    int ret = -1;
    int portN;

    char *authMethodNext = NULL;
    char *authMethodsCopy = NULL;
    char *authMethod;

    /* port number will be verified while opening the socket */
    if (virStrToLong_i(port, NULL, 10, &portN) < 0) {
        virReportError(VIR_ERR_LIBSSH, "%s",
                       _("Failed to parse port number"));
        goto error;
    }

    /* create ssh session context */
    if (!(sess = virNetLibsshSessionNew(username)))
        goto error;

    /* set ssh session parameters */
    if (virNetLibsshSessionAuthSetCallback(sess, auth) != 0)
        goto error;

    if (STRCASEEQ("auto", knownHostsVerify)) {
        verify = VIR_NET_LIBSSH_HOSTKEY_VERIFY_AUTO_ADD;
    } else if (STRCASEEQ("ignore", knownHostsVerify)) {
        verify = VIR_NET_LIBSSH_HOSTKEY_VERIFY_IGNORE;
    } else if (STRCASEEQ("normal", knownHostsVerify)) {
        verify = VIR_NET_LIBSSH_HOSTKEY_VERIFY_NORMAL;
    } else {
        virReportError(VIR_ERR_INVALID_ARG,
                       _("Invalid host key verification method: '%s'"),
                       knownHostsVerify);
        goto error;
    }

    if (virNetLibsshSessionSetHostKeyVerification(sess,
                                                  host,
                                                  portN,
                                                  knownHosts,
                                                  verify) != 0)
        goto error;

    if (virNetLibsshSessionSetChannelCommand(sess, command) != 0)
        goto error;

    if (VIR_STRDUP(authMethodsCopy, authMethods) < 0)
        goto error;

    authMethodNext = authMethodsCopy;

    while ((authMethod = strsep(&authMethodNext, ","))) {
        if (STRCASEEQ(authMethod, "keyboard-interactive")) {
            ret = virNetLibsshSessionAuthAddKeyboardAuth(sess, -1);
        } else if (STRCASEEQ(authMethod, "password")) {
            ret = virNetLibsshSessionAuthAddPasswordAuth(sess, uri);
        } else if (STRCASEEQ(authMethod, "privkey")) {
            ret = virNetLibsshSessionAuthAddPrivKeyAuth(sess,
                                                        privkey,
                                                        NULL);
        } else if (STRCASEEQ(authMethod, "agent")) {
            ret = virNetLibsshSessionAuthAddAgentAuth(sess);
        } else {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("Invalid authentication method: '%s'"),
                           authMethod);
            ret = -1;
            goto error;
        }

        if (ret != 0)
            goto error;
    }

    /* connect to remote server */
    if ((ret = virNetSocketNewConnectTCP(host, port, family, &sock)) < 0)
        goto error;

    /* connect to the host using ssh */
    if ((ret = virNetLibsshSessionConnect(sess, virNetSocketGetFD(sock))) != 0)
        goto error;

    sock->libsshSession = sess;
    /* libssh owns the FD and closes it on its own, and thus
     * we must not close it (otherwise there are warnings about
     * trying to close an invalid FD).
     */
    sock->ownsFd = false;
    *retsock = sock;

    VIR_FREE(authMethodsCopy);
    return 0;

 error:
    virObjectUnref(sock);
    virObjectUnref(sess);
    VIR_FREE(authMethodsCopy);
    return ret;
}
#else
int
virNetSocketNewConnectLibssh(const char *host ATTRIBUTE_UNUSED,
                             const char *port ATTRIBUTE_UNUSED,
                             int family ATTRIBUTE_UNUSED,
                             const char *username ATTRIBUTE_UNUSED,
                             const char *privkey ATTRIBUTE_UNUSED,
                             const char *knownHosts ATTRIBUTE_UNUSED,
                             const char *knownHostsVerify ATTRIBUTE_UNUSED,
                             const char *authMethods ATTRIBUTE_UNUSED,
                             const char *command ATTRIBUTE_UNUSED,
                             virConnectAuthPtr auth ATTRIBUTE_UNUSED,
                             virURIPtr uri ATTRIBUTE_UNUSED,
                             virNetSocketPtr *retsock ATTRIBUTE_UNUSED)
{
    virReportSystemError(ENOSYS, "%s",
                         _("libssh transport support was not enabled"));
    return -1;
}
#endif /* WITH_LIBSSH */

int virNetSocketNewConnectExternal(const char **cmdargv,
                                   virNetSocketPtr *retsock)
{
    virCommandPtr cmd;

    *retsock = NULL;

    cmd = virCommandNewArgs(cmdargv);
    virCommandAddEnvPassCommon(cmd);
    virCommandClearCaps(cmd);

    return virNetSocketNewConnectCommand(cmd, retsock);
}


int virNetSocketNewConnectSockFD(int sockfd,
                                 virNetSocketPtr *retsock)
{
    virSocketAddr localAddr;

    localAddr.len = sizeof(localAddr.data);
    if (getsockname(sockfd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        return -1;
    }

    if (!(*retsock = virNetSocketNew(&localAddr, NULL, true, sockfd, -1, -1, false)))
        return -1;

    return 0;
}


virNetSocketPtr virNetSocketNewPostExecRestart(virJSONValuePtr object)
{
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    int fd, thepid, errfd;
    bool isClient;
    bool unlinkUNIX;

    if (virJSONValueObjectGetNumberInt(object, "fd", &fd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing fd data in JSON document"));
        return NULL;
    }

    if (virJSONValueObjectGetNumberInt(object, "pid", &thepid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing pid data in JSON document"));
        return NULL;
    }

    if (virJSONValueObjectGetNumberInt(object, "errfd", &errfd) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing errfd data in JSON document"));
        return NULL;
    }

    if (virJSONValueObjectGetBoolean(object, "isClient", &isClient) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Missing isClient data in JSON document"));
        return NULL;
    }

    if (virJSONValueObjectGetBoolean(object, "unlinkUNIX", &unlinkUNIX) < 0)
        unlinkUNIX = !isClient;

    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));

    remoteAddr.len = sizeof(remoteAddr.data.stor);
    if (getsockname(fd, &remoteAddr.data.sa, &remoteAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get peer socket name"));
        return NULL;
    }

    localAddr.len = sizeof(localAddr.data.stor);
    if (getsockname(fd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        return NULL;
    }

    return virNetSocketNew(&localAddr, &remoteAddr, isClient,
                           fd, errfd, thepid, unlinkUNIX);
}


virJSONValuePtr virNetSocketPreExecRestart(virNetSocketPtr sock)
{
    virJSONValuePtr object = NULL;

    virObjectLock(sock);

#if WITH_SASL
    if (sock->saslSession) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Unable to save socket state when SASL session is active"));
        goto error;
    }
#endif
#if WITH_GNUTLS
    if (sock->tlsSession) {
        virReportError(VIR_ERR_OPERATION_INVALID, "%s",
                       _("Unable to save socket state when TLS session is active"));
        goto error;
    }
#endif

    if (!(object = virJSONValueNewObject()))
        goto error;

    if (virJSONValueObjectAppendNumberInt(object, "fd", sock->fd) < 0)
        goto error;

    if (virJSONValueObjectAppendNumberInt(object, "errfd", sock->errfd) < 0)
        goto error;

    if (virJSONValueObjectAppendNumberInt(object, "pid", sock->pid) < 0)
        goto error;

    if (virJSONValueObjectAppendBoolean(object, "isClient", sock->isClient) < 0)
        goto error;

    if (virJSONValueObjectAppendBoolean(object, "unlinkUNIX", sock->unlinkUNIX) < 0)
        goto error;

    if (virSetInherit(sock->fd, true) < 0) {
        virReportSystemError(errno,
                             _("Cannot disable close-on-exec flag on socket %d"),
                             sock->fd);
        goto error;
    }
    if (sock->errfd != -1 &&
        virSetInherit(sock->errfd, true) < 0) {
        virReportSystemError(errno,
                             _("Cannot disable close-on-exec flag on pipe %d"),
                             sock->errfd);
        goto error;
    }

    virObjectUnlock(sock);
    return object;

 error:
    virObjectUnlock(sock);
    virJSONValueFree(object);
    return NULL;
}


void virNetSocketDispose(void *obj)
{
    virNetSocketPtr sock = obj;

    PROBE(RPC_SOCKET_DISPOSE,
          "sock=%p", sock);

    if (sock->watch >= 0) {
        virEventRemoveHandle(sock->watch);
        sock->watch = -1;
    }

#ifdef HAVE_SYS_UN_H
    /* If a server socket, then unlink UNIX path */
    if (sock->unlinkUNIX &&
        sock->localAddr.data.sa.sa_family == AF_UNIX &&
        sock->localAddr.data.un.sun_path[0] != '\0')
        unlink(sock->localAddr.data.un.sun_path);
#endif

#if WITH_GNUTLS
    /* Make sure it can't send any more I/O during shutdown */
    if (sock->tlsSession)
        virNetTLSSessionSetIOCallbacks(sock->tlsSession, NULL, NULL, NULL);
    virObjectUnref(sock->tlsSession);
#endif
#if WITH_SASL
    virObjectUnref(sock->saslSession);
#endif

#if WITH_SSH2
    virObjectUnref(sock->sshSession);
#endif

#if WITH_LIBSSH
    virObjectUnref(sock->libsshSession);
#endif

    if (sock->ownsFd)
        VIR_FORCE_CLOSE(sock->fd);
    VIR_FORCE_CLOSE(sock->errfd);

    virProcessAbort(sock->pid);

    VIR_FREE(sock->localAddrStrSASL);
    VIR_FREE(sock->remoteAddrStrSASL);
    VIR_FREE(sock->remoteAddrStrURI);
}


int virNetSocketGetFD(virNetSocketPtr sock)
{
    int fd;
    virObjectLock(sock);
    fd = sock->fd;
    virObjectUnlock(sock);
    return fd;
}


int virNetSocketDupFD(virNetSocketPtr sock, bool cloexec)
{
    int fd;

    if (cloexec)
        fd = fcntl(sock->fd, F_DUPFD_CLOEXEC, 0);
    else
        fd = dup(sock->fd);
    if (fd < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to copy socket file handle"));
        return -1;
    }
    return fd;
}


bool virNetSocketIsLocal(virNetSocketPtr sock)
{
    bool isLocal = false;
    virObjectLock(sock);
    if (sock->localAddr.data.sa.sa_family == AF_UNIX)
        isLocal = true;
    virObjectUnlock(sock);
    return isLocal;
}


bool virNetSocketHasPassFD(virNetSocketPtr sock)
{
    bool hasPassFD = false;
    virObjectLock(sock);
    if (sock->localAddr.data.sa.sa_family == AF_UNIX)
        hasPassFD = true;
    virObjectUnlock(sock);
    return hasPassFD;
}

char *virNetSocketGetPath(virNetSocketPtr sock)
{
    char *path = NULL;
    virObjectLock(sock);
    path = virSocketAddrGetPath(&sock->localAddr);
    virObjectUnlock(sock);
    return path;
}

int virNetSocketGetPort(virNetSocketPtr sock)
{
    int port;
    virObjectLock(sock);
    port = virSocketAddrGetPort(&sock->localAddr);
    virObjectUnlock(sock);
    return port;
}


#if defined(SO_PEERCRED)
int virNetSocketGetUNIXIdentity(virNetSocketPtr sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid,
                                unsigned long long *timestamp)
{
# if defined(HAVE_STRUCT_SOCKPEERCRED)
    struct sockpeercred cr;
# else
    struct ucred cr;
# endif
    socklen_t cr_len = sizeof(cr);
    int ret = -1;

    virObjectLock(sock);

    if (getsockopt(sock->fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to get client socket identity"));
        goto cleanup;
    }

    *timestamp = -1;
    if (cr.pid && virProcessGetStartTime(cr.pid, timestamp) < 0)
        goto cleanup;

    if (cr.pid)
        *pid = cr.pid;
    else
        *pid = -1;
    *uid = cr.uid;
    *gid = cr.gid;

    ret = 0;

 cleanup:
    virObjectUnlock(sock);
    return ret;
}
#elif defined(LOCAL_PEERCRED)

/* VIR_SOL_PEERCRED - the value needed to let getsockopt() work with
 * LOCAL_PEERCRED
 */

/* Mac OS X 10.8 provides SOL_LOCAL for LOCAL_PEERCRED */
# ifdef SOL_LOCAL
#  define VIR_SOL_PEERCRED SOL_LOCAL
# else
/* FreeBSD and Mac OS X prior to 10.7, SOL_LOCAL is not defined and
 * users are expected to supply 0 as the second value for getsockopt()
 * when using LOCAL_PEERCRED. NB SOL_SOCKET cannot be used instead
 * of SOL_LOCAL
 */
#  define VIR_SOL_PEERCRED 0
# endif

int virNetSocketGetUNIXIdentity(virNetSocketPtr sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid,
                                unsigned long long *timestamp)
{
    struct xucred cr;
    socklen_t cr_len = sizeof(cr);
    int ret = -1;

    virObjectLock(sock);

    cr.cr_ngroups = -1;
    if (getsockopt(sock->fd, VIR_SOL_PEERCRED, LOCAL_PEERCRED, &cr, &cr_len) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to get client socket identity"));
        goto cleanup;
    }

    if (cr.cr_version != XUCRED_VERSION) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Failed to get valid client socket identity"));
        goto cleanup;
    }

    if (cr.cr_ngroups <= 0 || cr.cr_ngroups > NGROUPS) {
        virReportError(VIR_ERR_SYSTEM_ERROR, "%s",
                       _("Failed to get valid client socket identity groups"));
        goto cleanup;
    }

    /* PID and process creation time are not supported on BSDs by
     * LOCAL_PEERCRED.
     */
    *pid = -1;
    *timestamp = -1;
    *uid = cr.cr_uid;
    *gid = cr.cr_gid;

# ifdef LOCAL_PEERPID
    /* Exists on Mac OS X 10.8 for retrieving the peer's PID */
    cr_len = sizeof(*pid);

    if (getsockopt(sock->fd, VIR_SOL_PEERCRED, LOCAL_PEERPID, pid, &cr_len) < 0) {
        /* Ensure this is set to something sane as there are no guarantees
         * as to what its set to now.
         */
        *pid = -1;

        /* If this was built on a system with LOCAL_PEERPID defined but
         * the kernel doesn't support it we'll get back EOPNOTSUPP so
         * treat all errors but EOPNOTSUPP as fatal
         */
        if (errno != EOPNOTSUPP) {
            virReportSystemError(errno, "%s",
                    _("Failed to get client socket PID"));
            goto cleanup;
        }
    }
# endif

    ret = 0;

 cleanup:
    virObjectUnlock(sock);
    return ret;
}
#else
int virNetSocketGetUNIXIdentity(virNetSocketPtr sock ATTRIBUTE_UNUSED,
                                uid_t *uid ATTRIBUTE_UNUSED,
                                gid_t *gid ATTRIBUTE_UNUSED,
                                pid_t *pid ATTRIBUTE_UNUSED,
                                unsigned long long *timestamp ATTRIBUTE_UNUSED)
{
    /* XXX Many more OS support UNIX socket credentials we could port to. See dbus ....*/
    virReportSystemError(ENOSYS, "%s",
                         _("Client socket identity not available"));
    return -1;
}
#endif

#ifdef WITH_SELINUX
int virNetSocketGetSELinuxContext(virNetSocketPtr sock,
                                  char **context)
{
    security_context_t seccon = NULL;
    int ret = -1;

    *context = NULL;

    virObjectLock(sock);
    if (getpeercon(sock->fd, &seccon) < 0) {
        if (errno == ENOSYS || errno == ENOPROTOOPT) {
            ret = 0;
            goto cleanup;
        }
        virReportSystemError(errno, "%s",
                             _("Unable to query peer security context"));
        goto cleanup;
    }

    if (VIR_STRDUP(*context, seccon) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    freecon(seccon);
    virObjectUnlock(sock);
    return ret;
}
#else
int virNetSocketGetSELinuxContext(virNetSocketPtr sock ATTRIBUTE_UNUSED,
                                  char **context)
{
    *context = NULL;
    return 0;
}
#endif


int virNetSocketSetBlocking(virNetSocketPtr sock,
                            bool blocking)
{
    int ret;
    virObjectLock(sock);
    ret = virSetBlocking(sock->fd, blocking);
    virObjectUnlock(sock);
    return ret;
}


const char *virNetSocketLocalAddrStringSASL(virNetSocketPtr sock)
{
    return sock->localAddrStrSASL;
}

const char *virNetSocketRemoteAddrStringSASL(virNetSocketPtr sock)
{
    return sock->remoteAddrStrSASL;
}

const char *virNetSocketRemoteAddrStringURI(virNetSocketPtr sock)
{
    return sock->remoteAddrStrURI;
}

#if WITH_GNUTLS
static ssize_t virNetSocketTLSSessionWrite(const char *buf,
                                           size_t len,
                                           void *opaque)
{
    virNetSocketPtr sock = opaque;
    return write(sock->fd, buf, len);
}


static ssize_t virNetSocketTLSSessionRead(char *buf,
                                          size_t len,
                                          void *opaque)
{
    virNetSocketPtr sock = opaque;
    return read(sock->fd, buf, len);
}


void virNetSocketSetTLSSession(virNetSocketPtr sock,
                               virNetTLSSessionPtr sess)
{
    virObjectLock(sock);
    virObjectUnref(sock->tlsSession);
    sock->tlsSession = virObjectRef(sess);
    virNetTLSSessionSetIOCallbacks(sess,
                                   virNetSocketTLSSessionWrite,
                                   virNetSocketTLSSessionRead,
                                   sock);
    virObjectUnlock(sock);
}
#endif

#if WITH_SASL
void virNetSocketSetSASLSession(virNetSocketPtr sock,
                                virNetSASLSessionPtr sess)
{
    virObjectLock(sock);
    virObjectUnref(sock->saslSession);
    sock->saslSession = virObjectRef(sess);
    virObjectUnlock(sock);
}
#endif


bool virNetSocketHasCachedData(virNetSocketPtr sock ATTRIBUTE_UNUSED)
{
    bool hasCached = false;
    virObjectLock(sock);

#if WITH_SSH2
    if (virNetSSHSessionHasCachedData(sock->sshSession))
        hasCached = true;
#endif

#if WITH_LIBSSH
    if (virNetLibsshSessionHasCachedData(sock->libsshSession))
        hasCached = true;
#endif

#if WITH_SASL
    if (sock->saslDecoded)
        hasCached = true;
#endif
    virObjectUnlock(sock);
    return hasCached;
}

#if WITH_SSH2
static ssize_t virNetSocketLibSSH2Read(virNetSocketPtr sock,
                                       char *buf,
                                       size_t len)
{
    return virNetSSHChannelRead(sock->sshSession, buf, len);
}

static ssize_t virNetSocketLibSSH2Write(virNetSocketPtr sock,
                                        const char *buf,
                                        size_t len)
{
    return virNetSSHChannelWrite(sock->sshSession, buf, len);
}
#endif

#if WITH_LIBSSH
static ssize_t virNetSocketLibsshRead(virNetSocketPtr sock,
                                      char *buf,
                                      size_t len)
{
    return virNetLibsshChannelRead(sock->libsshSession, buf, len);
}

static ssize_t virNetSocketLibsshWrite(virNetSocketPtr sock,
                                       const char *buf,
                                       size_t len)
{
    return virNetLibsshChannelWrite(sock->libsshSession, buf, len);
}
#endif

bool virNetSocketHasPendingData(virNetSocketPtr sock ATTRIBUTE_UNUSED)
{
    bool hasPending = false;
    virObjectLock(sock);
#if WITH_SASL
    if (sock->saslEncoded)
        hasPending = true;
#endif
    virObjectUnlock(sock);
    return hasPending;
}


static ssize_t virNetSocketReadWire(virNetSocketPtr sock, char *buf, size_t len)
{
    char *errout = NULL;
    ssize_t ret;

#if WITH_SSH2
    if (sock->sshSession)
        return virNetSocketLibSSH2Read(sock, buf, len);
#endif

#if WITH_LIBSSH
    if (sock->libsshSession)
        return virNetSocketLibsshRead(sock, buf, len);
#endif

 reread:
#if WITH_GNUTLS
    if (sock->tlsSession &&
        virNetTLSSessionGetHandshakeStatus(sock->tlsSession) ==
        VIR_NET_TLS_HANDSHAKE_COMPLETE) {
        ret = virNetTLSSessionRead(sock->tlsSession, buf, len);
    } else {
#endif
        ret = read(sock->fd, buf, len);
#if WITH_GNUTLS
    }
#endif

    if ((ret < 0) && (errno == EINTR))
        goto reread;
    if ((ret < 0) && (errno == EAGAIN))
        return 0;

    if (ret <= 0 &&
        sock->errfd != -1 &&
        virFileReadLimFD(sock->errfd, 1024, &errout) >= 0 &&
        errout != NULL) {
        size_t elen = strlen(errout);
        /* remove trailing whitespace */
        while (elen && c_isspace(errout[elen - 1]))
            errout[--elen] = '\0';
    }

    if (ret < 0) {
        if (errout)
            virReportSystemError(errno,
                                 _("Cannot recv data: %s"), errout);
        else
            virReportSystemError(errno, "%s",
                                 _("Cannot recv data"));
        ret = -1;
    } else if (ret == 0) {
        if (sock->quietEOF) {
            VIR_DEBUG("socket='%p' EOF while reading: errout='%s'",
                      socket, NULLSTR(errout));

            ret = -2;
        } else {
            if (errout)
                virReportSystemError(EIO,
                                     _("End of file while reading data: %s"),
                                     errout);
            else
                virReportSystemError(EIO, "%s",
                                     _("End of file while reading data"));

            ret = -1;
        }
    }

    VIR_FREE(errout);
    return ret;
}

static ssize_t virNetSocketWriteWire(virNetSocketPtr sock, const char *buf, size_t len)
{
    ssize_t ret;

#if WITH_SSH2
    if (sock->sshSession)
        return virNetSocketLibSSH2Write(sock, buf, len);
#endif

#if WITH_LIBSSH
    if (sock->libsshSession)
        return virNetSocketLibsshWrite(sock, buf, len);
#endif

 rewrite:
#if WITH_GNUTLS
    if (sock->tlsSession &&
        virNetTLSSessionGetHandshakeStatus(sock->tlsSession) ==
        VIR_NET_TLS_HANDSHAKE_COMPLETE) {
        ret = virNetTLSSessionWrite(sock->tlsSession, buf, len);
    } else {
#endif
        ret = write(sock->fd, buf, len);
#if WITH_GNUTLS
    }
#endif

    if (ret < 0) {
        if (errno == EINTR)
            goto rewrite;
        if (errno == EAGAIN)
            return 0;

        virReportSystemError(errno, "%s",
                             _("Cannot write data"));
        return -1;
    }
    if (ret == 0) {
        virReportSystemError(EIO, "%s",
                             _("End of file while writing data"));
        return -1;
    }

    return ret;
}


#if WITH_SASL
static ssize_t virNetSocketReadSASL(virNetSocketPtr sock, char *buf, size_t len)
{
    ssize_t got;

    /* Need to read some more data off the wire */
    if (sock->saslDecoded == NULL) {
        ssize_t encodedLen = virNetSASLSessionGetMaxBufSize(sock->saslSession);
        char *encoded;
        if (VIR_ALLOC_N(encoded, encodedLen) < 0)
            return -1;
        encodedLen = virNetSocketReadWire(sock, encoded, encodedLen);

        if (encodedLen <= 0) {
            VIR_FREE(encoded);
            return encodedLen;
        }

        if (virNetSASLSessionDecode(sock->saslSession,
                                    encoded, encodedLen,
                                    &sock->saslDecoded, &sock->saslDecodedLength) < 0) {
            VIR_FREE(encoded);
            return -1;
        }
        VIR_FREE(encoded);

        sock->saslDecodedOffset = 0;
    }

    /* Some buffered decoded data to return now */
    got = sock->saslDecodedLength - sock->saslDecodedOffset;

    if (len > got)
        len = got;

    memcpy(buf, sock->saslDecoded + sock->saslDecodedOffset, len);
    sock->saslDecodedOffset += len;

    if (sock->saslDecodedOffset == sock->saslDecodedLength) {
        sock->saslDecoded = NULL;
        sock->saslDecodedOffset = sock->saslDecodedLength = 0;
    }

    return len;
}


static ssize_t virNetSocketWriteSASL(virNetSocketPtr sock, const char *buf, size_t len)
{
    int ret;
    size_t tosend = virNetSASLSessionGetMaxBufSize(sock->saslSession);

    /* SASL doesn't necessarily let us send the whole
       buffer at once */
    if (tosend > len)
        tosend = len;

    /* Not got any pending encoded data, so we need to encode raw stuff */
    if (sock->saslEncoded == NULL) {
        if (virNetSASLSessionEncode(sock->saslSession,
                                    buf, tosend,
                                    &sock->saslEncoded,
                                    &sock->saslEncodedLength) < 0)
            return -1;

        sock->saslEncodedRawLength = tosend;
        sock->saslEncodedOffset = 0;
    }

    /* Send some of the encoded stuff out on the wire */
    ret = virNetSocketWriteWire(sock,
                                sock->saslEncoded + sock->saslEncodedOffset,
                                sock->saslEncodedLength - sock->saslEncodedOffset);

    if (ret <= 0)
        return ret; /* -1 error, 0 == egain */

    /* Note how much we sent */
    sock->saslEncodedOffset += ret;

    /* Sent all encoded, so update raw buffer to indicate completion */
    if (sock->saslEncodedOffset == sock->saslEncodedLength) {
        ssize_t done = sock->saslEncodedRawLength;
        sock->saslEncoded = NULL;
        sock->saslEncodedOffset = sock->saslEncodedLength = sock->saslEncodedRawLength = 0;

        /* Mark as complete, so caller detects completion.
         *
         * Note that 'done' is possibly less than our current
         * 'tosend' value, since if virNetSocketWriteWire
         * only partially sent the data, we might have been
         * called a 2nd time to write remaining cached
         * encoded data. This means that the caller might
         * also have further raw data pending that's included
         * in 'tosend' */
        return done;
    } else {
        /* Still have stuff pending in saslEncoded buffer.
         * Pretend to caller that we didn't send any yet.
         * The caller will then retry with same buffer
         * shortly, which lets us finish saslEncoded.
         */
        return 0;
    }
}
#endif

ssize_t virNetSocketRead(virNetSocketPtr sock, char *buf, size_t len)
{
    ssize_t ret;
    virObjectLock(sock);
#if WITH_SASL
    if (sock->saslSession)
        ret = virNetSocketReadSASL(sock, buf, len);
    else
#endif
        ret = virNetSocketReadWire(sock, buf, len);
    virObjectUnlock(sock);
    return ret;
}

ssize_t virNetSocketWrite(virNetSocketPtr sock, const char *buf, size_t len)
{
    ssize_t ret;

    virObjectLock(sock);
#if WITH_SASL
    if (sock->saslSession)
        ret = virNetSocketWriteSASL(sock, buf, len);
    else
#endif
        ret = virNetSocketWriteWire(sock, buf, len);
    virObjectUnlock(sock);
    return ret;
}


/*
 * Returns 1 if an FD was sent, 0 if it would block, -1 on error
 */
int virNetSocketSendFD(virNetSocketPtr sock, int fd)
{
    int ret = -1;
    if (!virNetSocketHasPassFD(sock)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Sending file descriptors is not supported on this socket"));
        return -1;
    }
    virObjectLock(sock);
    PROBE(RPC_SOCKET_SEND_FD,
          "sock=%p fd=%d", sock, fd);
    if (sendfd(sock->fd, fd) < 0) {
        if (errno == EAGAIN)
            ret = 0;
        else
            virReportSystemError(errno,
                                 _("Failed to send file descriptor %d"),
                                 fd);
        goto cleanup;
    }
    ret = 1;

 cleanup:
    virObjectUnlock(sock);
    return ret;
}


/*
 * Returns 1 if an FD was read, 0 if it would block, -1 on error
 */
int virNetSocketRecvFD(virNetSocketPtr sock, int *fd)
{
    int ret = -1;

    *fd = -1;

    if (!virNetSocketHasPassFD(sock)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Receiving file descriptors is not supported on this socket"));
        return -1;
    }
    virObjectLock(sock);

    if ((*fd = recvfd(sock->fd, O_CLOEXEC)) < 0) {
        if (errno == EAGAIN)
            ret = 0;
        else
            virReportSystemError(errno, "%s",
                                 _("Failed to recv file descriptor"));
        goto cleanup;
    }
    PROBE(RPC_SOCKET_RECV_FD,
          "sock=%p fd=%d", sock, *fd);
    ret = 1;

 cleanup:
    virObjectUnlock(sock);
    return ret;
}


int virNetSocketListen(virNetSocketPtr sock, int backlog)
{
    virObjectLock(sock);
    if (listen(sock->fd, backlog > 0 ? backlog : 30) < 0) {
        virReportSystemError(errno, "%s", _("Unable to listen on socket"));
        virObjectUnlock(sock);
        return -1;
    }
    virObjectUnlock(sock);
    return 0;
}

int virNetSocketAccept(virNetSocketPtr sock, virNetSocketPtr *clientsock)
{
    int fd = -1;
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    int ret = -1;

    virObjectLock(sock);

    *clientsock = NULL;

    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));

    remoteAddr.len = sizeof(remoteAddr.data.stor);
    if ((fd = accept(sock->fd, &remoteAddr.data.sa, &remoteAddr.len)) < 0) {
        if (errno == ECONNABORTED ||
            errno == EAGAIN) {
            ret = 0;
            goto cleanup;
        }

        virReportSystemError(errno, "%s",
                             _("Unable to accept client"));
        goto cleanup;
    }

    localAddr.len = sizeof(localAddr.data);
    if (getsockname(fd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        goto cleanup;
    }

    if (!(*clientsock = virNetSocketNew(&localAddr,
                                        &remoteAddr,
                                        true,
                                        fd, -1, 0,
                                        false)))
        goto cleanup;

    fd = -1;
    ret = 0;

 cleanup:
    VIR_FORCE_CLOSE(fd);
    virObjectUnlock(sock);
    return ret;
}


static void virNetSocketEventHandle(int watch ATTRIBUTE_UNUSED,
                                    int fd ATTRIBUTE_UNUSED,
                                    int events,
                                    void *opaque)
{
    virNetSocketPtr sock = opaque;
    virNetSocketIOFunc func;
    void *eopaque;

    virObjectLock(sock);
    func = sock->func;
    eopaque = sock->opaque;
    virObjectUnlock(sock);

    if (func)
        func(sock, events, eopaque);
}


static void virNetSocketEventFree(void *opaque)
{
    virNetSocketPtr sock = opaque;
    virFreeCallback ff;
    void *eopaque;

    virObjectLock(sock);
    ff = sock->ff;
    eopaque = sock->opaque;
    sock->func = NULL;
    sock->ff = NULL;
    sock->opaque = NULL;
    virObjectUnlock(sock);

    if (ff)
        ff(eopaque);

    virObjectUnref(sock);
}

int virNetSocketAddIOCallback(virNetSocketPtr sock,
                              int events,
                              virNetSocketIOFunc func,
                              void *opaque,
                              virFreeCallback ff)
{
    int ret = -1;

    virObjectRef(sock);
    virObjectLock(sock);
    if (sock->watch >= 0) {
        VIR_DEBUG("Watch already registered on socket %p", sock);
        goto cleanup;
    }

    if ((sock->watch = virEventAddHandle(sock->fd,
                                         events,
                                         virNetSocketEventHandle,
                                         sock,
                                         virNetSocketEventFree)) < 0) {
        VIR_DEBUG("Failed to register watch on socket %p", sock);
        goto cleanup;
    }
    sock->func = func;
    sock->opaque = opaque;
    sock->ff = ff;

    ret = 0;

 cleanup:
    virObjectUnlock(sock);
    if (ret != 0)
        virObjectUnref(sock);
    return ret;
}

void virNetSocketUpdateIOCallback(virNetSocketPtr sock,
                                  int events)
{
    virObjectLock(sock);
    if (sock->watch < 0) {
        VIR_DEBUG("Watch not registered on socket %p", sock);
        virObjectUnlock(sock);
        return;
    }

    virEventUpdateHandle(sock->watch, events);

    virObjectUnlock(sock);
}

void virNetSocketRemoveIOCallback(virNetSocketPtr sock)
{
    virObjectLock(sock);

    if (sock->watch < 0) {
        VIR_DEBUG("Watch not registered on socket %p", sock);
        virObjectUnlock(sock);
        return;
    }

    virEventRemoveHandle(sock->watch);
    /* Don't unref @sock, it's done via eventloop callback. */
    sock->watch = -1;

    virObjectUnlock(sock);
}

void virNetSocketClose(virNetSocketPtr sock)
{
    if (!sock)
        return;

    virObjectLock(sock);

    VIR_FORCE_CLOSE(sock->fd);

#ifdef HAVE_SYS_UN_H
    /* If a server socket, then unlink UNIX path */
    if (sock->unlinkUNIX &&
        sock->localAddr.data.sa.sa_family == AF_UNIX &&
        sock->localAddr.data.un.sun_path[0] != '\0') {
        if (unlink(sock->localAddr.data.un.sun_path) == 0)
            sock->localAddr.data.un.sun_path[0] = '\0';
    }
#endif

    virObjectUnlock(sock);
}


/**
 * virNetSocketSetQuietEOF:
 * @sock: socket object pointer
 *
 * Disables reporting I/O errors as a virError when @socket is closed while
 * reading data.
 */
void
virNetSocketSetQuietEOF(virNetSocketPtr sock)
{
    sock->quietEOF = true;
}
