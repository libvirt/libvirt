/*
 * virnetsocket.c: generic network socket handling
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>

#ifdef HAVE_NETINET_TCP_H
# include <netinet/tcp.h>
#endif

#include "virnetsocket.h"
#include "util.h"
#include "memory.h"
#include "virterror_internal.h"
#include "logging.h"
#include "virfile.h"
#include "event.h"
#include "threads.h"

#include "passfd.h"

#define VIR_FROM_THIS VIR_FROM_RPC

#define virNetError(code, ...)                                    \
    virReportErrorHelper(VIR_FROM_THIS, code, __FILE__,           \
                         __FUNCTION__, __LINE__, __VA_ARGS__)


struct _virNetSocket {
    virMutex lock;
    int refs;

    int fd;
    int watch;
    pid_t pid;
    int errfd;
    bool client;

    /* Event callback fields */
    virNetSocketIOFunc func;
    void *opaque;
    virFreeCallback ff;

    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    char *localAddrStr;
    char *remoteAddrStr;

    virNetTLSSessionPtr tlsSession;
#if HAVE_SASL
    virNetSASLSessionPtr saslSession;

    const char *saslDecoded;
    size_t saslDecodedLength;
    size_t saslDecodedOffset;

    const char *saslEncoded;
    size_t saslEncodedLength;
    size_t saslEncodedOffset;
#endif
};


#ifndef WIN32
static int virNetSocketForkDaemon(const char *binary)
{
    int ret;
    virCommandPtr cmd = virCommandNewArgList(binary,
                                             "--timeout=30",
                                             NULL);

    virCommandAddEnvPassCommon(cmd);
    virCommandClearCaps(cmd);
    virCommandDaemonize(cmd);
    ret = virCommandRun(cmd, NULL);
    virCommandFree(cmd);
    return ret;
}
#endif


static virNetSocketPtr virNetSocketNew(virSocketAddrPtr localAddr,
                                       virSocketAddrPtr remoteAddr,
                                       bool isClient,
                                       int fd, int errfd, pid_t pid)
{
    virNetSocketPtr sock;
    int no_slow_start = 1;

    VIR_DEBUG("localAddr=%p remoteAddr=%p fd=%d errfd=%d pid=%lld",
              localAddr, remoteAddr,
              fd, errfd, (long long) pid);

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

    if (VIR_ALLOC(sock) < 0) {
        virReportOOMError();
        return NULL;
    }

    if (virMutexInit(&sock->lock) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to initialize mutex"));
        VIR_FREE(sock);
        return NULL;
    }
    sock->refs = 1;

    if (localAddr)
        sock->localAddr = *localAddr;
    if (remoteAddr)
        sock->remoteAddr = *remoteAddr;
    sock->fd = fd;
    sock->errfd = errfd;
    sock->pid = pid;

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
        !(sock->localAddrStr = virSocketAddrFormatFull(localAddr, true, ";")))
        goto error;

    if (remoteAddr &&
        !(sock->remoteAddrStr = virSocketAddrFormatFull(remoteAddr, true, ";")))
        goto error;

    sock->client = isClient;

    PROBE(RPC_SOCKET_NEW,
          "sock=%p refs=%d fd=%d errfd=%d pid=%lld localAddr=%s, remoteAddr=%s",
          sock, sock->refs, fd, errfd, (long long) pid,
          NULLSTR(sock->localAddrStr), NULLSTR(sock->remoteAddrStr));

    return sock;

error:
    sock->fd = sock->errfd = -1; /* Caller owns fd/errfd on failure */
    virNetSocketFree(sock);
    return NULL;
}


int virNetSocketNewListenTCP(const char *nodename,
                             const char *service,
                             virNetSocketPtr **retsocks,
                             size_t *nretsocks)
{
    virNetSocketPtr *socks = NULL;
    size_t nsocks = 0;
    struct addrinfo *ai = NULL;
    struct addrinfo hints;
    int fd = -1;
    int i;
    int addrInUse = false;

    *retsocks = NULL;
    *nretsocks = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    int e = getaddrinfo(nodename, service, &hints, &ai);
    if (e != 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
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
            virReportSystemError(errno, "%s", _("Unable to create socket"));
            goto error;
        }

        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            virReportSystemError(errno, "%s", _("Unable to enable port reuse"));
            goto error;
        }

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

        if (bind(fd, runp->ai_addr, runp->ai_addrlen) < 0) {
            if (errno != EADDRINUSE) {
                virReportSystemError(errno, "%s", _("Unable to bind to port"));
                goto error;
            }
            addrInUse = true;
            VIR_FORCE_CLOSE(fd);
            runp = runp->ai_next;
            continue;
        }

        addr.len = sizeof(addr.data);
        if (getsockname(fd, &addr.data.sa, &addr.len) < 0) {
            virReportSystemError(errno, "%s", _("Unable to get local socket name"));
            goto error;
        }

        VIR_DEBUG("%p f=%d f=%d", &addr, runp->ai_family, addr.data.sa.sa_family);

        if (VIR_EXPAND_N(socks, nsocks, 1) < 0) {
            virReportOOMError();
            goto error;
        }

        if (!(socks[nsocks-1] = virNetSocketNew(&addr, NULL, false, fd, -1, 0)))
            goto error;
        runp = runp->ai_next;
        fd = -1;
    }

    if (nsocks == 0 &&
        addrInUse) {
        virReportSystemError(EADDRINUSE, "%s", _("Unable to bind to port"));
        goto error;
    }

    freeaddrinfo(ai);

    *retsocks = socks;
    *nretsocks = nsocks;
    return 0;

error:
    for (i = 0 ; i < nsocks ; i++)
        virNetSocketFree(socks[i]);
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
    if (virStrcpyStatic(addr.data.un.sun_path, path) == NULL) {
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
                             path, (int) user, (int) grp);
        goto error;
    }

    if (!(*retsock = virNetSocketNew(&addr, NULL, false, fd, -1, 0)))
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


int virNetSocketNewConnectTCP(const char *nodename,
                              const char *service,
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
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_socktype = SOCK_STREAM;

    int e = getaddrinfo(nodename, service, &hints, &ai);
    if (e != 0) {
        virNetError(VIR_ERR_SYSTEM_ERROR,
                    _("Unable to resolve address '%s' service '%s': %s"),
                    nodename, service, gai_strerror (e));
        return -1;
    }

    runp = ai;
    while (runp) {
        int opt = 1;

        if ((fd = socket(runp->ai_family, runp->ai_socktype,
                         runp->ai_protocol)) < 0) {
            virReportSystemError(errno, "%s", _("Unable to create socket"));
            goto error;
        }

        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

    if (!(*retsock = virNetSocketNew(&localAddr, &remoteAddr, true, fd, -1, 0)))
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
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    int fd;
    int retries = 0;

    memset(&localAddr, 0, sizeof(localAddr));
    memset(&remoteAddr, 0, sizeof(remoteAddr));

    remoteAddr.len = sizeof(remoteAddr.data.un);

    if (spawnDaemon && !binary) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("Auto-spawn of daemon requested, but no binary specified"));
        return -1;
    }

    if ((fd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        virReportSystemError(errno, "%s", _("Failed to create socket"));
        goto error;
    }

    remoteAddr.data.un.sun_family = AF_UNIX;
    if (virStrcpyStatic(remoteAddr.data.un.sun_path, path) == NULL) {
        virReportSystemError(ENOMEM, _("Path %s too long for unix socket"), path);
        goto error;
    }
    if (remoteAddr.data.un.sun_path[0] == '@')
        remoteAddr.data.un.sun_path[0] = '\0';

retry:
    if (connect(fd, &remoteAddr.data.sa, remoteAddr.len) < 0) {
        if (errno == ECONNREFUSED && spawnDaemon && retries < 20) {
            if (retries == 0 &&
                virNetSocketForkDaemon(binary) < 0)
                goto error;

            retries++;
            usleep(1000 * 100 * retries);
            goto retry;
        }

        virReportSystemError(errno,
                             _("Failed to connect socket to '%s'"),
                             path);
        goto error;
    }

    localAddr.len = sizeof(localAddr.data);
    if (getsockname(fd, &localAddr.data.sa, &localAddr.len) < 0) {
        virReportSystemError(errno, "%s", _("Unable to get local socket name"));
        goto error;
    }

    if (!(*retsock = virNetSocketNew(&localAddr, &remoteAddr, true, fd, -1, 0)))
        goto error;

    return 0;

error:
    VIR_FORCE_CLOSE(fd);
    return -1;
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

    if (!(*retsock = virNetSocketNew(NULL, NULL, true, sv[0], errfd[0], pid)))
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
    if (noTTY)
        virCommandAddArgList(cmd, "-T", "-o", "BatchMode=yes",
                             "-e", "none", NULL);
    if (noVerify)
        virCommandAddArgList(cmd, "-o", "StrictHostKeyChecking=no", NULL);

    if (!netcat)
        netcat = "nc";

    virCommandAddArgList(cmd, nodename, "sh", "-c", NULL);

    virBufferEscapeShell(&buf, netcat);
    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
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


void virNetSocketRef(virNetSocketPtr sock)
{
    virMutexLock(&sock->lock);
    sock->refs++;
    PROBE(RPC_SOCKET_REF,
          "sock=%p refs=%d",
          sock, sock->refs);
    virMutexUnlock(&sock->lock);
}


void virNetSocketFree(virNetSocketPtr sock)
{
    if (!sock)
        return;

    virMutexLock(&sock->lock);
    PROBE(RPC_SOCKET_FREE,
          "sock=%p refs=%d",
          sock, sock->refs);

    sock->refs--;
    if (sock->refs > 0) {
        virMutexUnlock(&sock->lock);
        return;
    }

    VIR_DEBUG("sock=%p fd=%d", sock, sock->fd);
    if (sock->watch > 0) {
        virEventRemoveHandle(sock->watch);
        sock->watch = -1;
    }

#ifdef HAVE_SYS_UN_H
    /* If a server socket, then unlink UNIX path */
    if (!sock->client &&
        sock->localAddr.data.sa.sa_family == AF_UNIX &&
        sock->localAddr.data.un.sun_path[0] != '\0')
        unlink(sock->localAddr.data.un.sun_path);
#endif

    /* Make sure it can't send any more I/O during shutdown */
    if (sock->tlsSession)
        virNetTLSSessionSetIOCallbacks(sock->tlsSession, NULL, NULL, NULL);
    virNetTLSSessionFree(sock->tlsSession);
#if HAVE_SASL
    virNetSASLSessionFree(sock->saslSession);
#endif

    VIR_FORCE_CLOSE(sock->fd);
    VIR_FORCE_CLOSE(sock->errfd);

    virPidAbort(sock->pid);

    VIR_FREE(sock->localAddrStr);
    VIR_FREE(sock->remoteAddrStr);

    virMutexUnlock(&sock->lock);
    virMutexDestroy(&sock->lock);

    VIR_FREE(sock);
}


int virNetSocketGetFD(virNetSocketPtr sock)
{
    int fd;
    virMutexLock(&sock->lock);
    fd = sock->fd;
    virMutexUnlock(&sock->lock);
    return fd;
}


int virNetSocketDupFD(virNetSocketPtr sock, bool cloexec)
{
    int fd;

    if (cloexec)
        fd = fcntl(sock->fd, F_DUPFD_CLOEXEC);
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
    virMutexLock(&sock->lock);
    if (sock->localAddr.data.sa.sa_family == AF_UNIX)
        isLocal = true;
    virMutexUnlock(&sock->lock);
    return isLocal;
}


bool virNetSocketHasPassFD(virNetSocketPtr sock)
{
    bool hasPassFD = false;
    virMutexLock(&sock->lock);
    if (sock->localAddr.data.sa.sa_family == AF_UNIX)
        hasPassFD = true;
    virMutexUnlock(&sock->lock);
    return hasPassFD;
}


int virNetSocketGetPort(virNetSocketPtr sock)
{
    int port;
    virMutexLock(&sock->lock);
    port = virSocketAddrGetPort(&sock->localAddr);
    virMutexUnlock(&sock->lock);
    return port;
}


#ifdef SO_PEERCRED
int virNetSocketGetUNIXIdentity(virNetSocketPtr sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid)
{
    struct ucred cr;
    socklen_t cr_len = sizeof(cr);
    virMutexLock(&sock->lock);

    if (getsockopt(sock->fd, SOL_SOCKET, SO_PEERCRED, &cr, &cr_len) < 0) {
        virReportSystemError(errno, "%s",
                             _("Failed to get client socket identity"));
        virMutexUnlock(&sock->lock);
        return -1;
    }

    *pid = cr.pid;
    *uid = cr.uid;
    *gid = cr.gid;

    virMutexUnlock(&sock->lock);
    return 0;
}
#else
int virNetSocketGetUNIXIdentity(virNetSocketPtr sock ATTRIBUTE_UNUSED,
                                uid_t *uid ATTRIBUTE_UNUSED,
                                gid_t *gid ATTRIBUTE_UNUSED,
                                pid_t *pid ATTRIBUTE_UNUSED)
{
    /* XXX Many more OS support UNIX socket credentials we could port to. See dbus ....*/
    virReportSystemError(ENOSYS, "%s",
                         _("Client socket identity not available"));
    return -1;
}
#endif


int virNetSocketSetBlocking(virNetSocketPtr sock,
                            bool blocking)
{
    int ret;
    virMutexLock(&sock->lock);
    ret = virSetBlocking(sock->fd, blocking);
    virMutexUnlock(&sock->lock);
    return ret;
}


const char *virNetSocketLocalAddrString(virNetSocketPtr sock)
{
    return sock->localAddrStr;
}

const char *virNetSocketRemoteAddrString(virNetSocketPtr sock)
{
    return sock->remoteAddrStr;
}


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
    virMutexLock(&sock->lock);
    virNetTLSSessionFree(sock->tlsSession);
    sock->tlsSession = sess;
    virNetTLSSessionSetIOCallbacks(sess,
                                   virNetSocketTLSSessionWrite,
                                   virNetSocketTLSSessionRead,
                                   sock);
    virNetTLSSessionRef(sess);
    virMutexUnlock(&sock->lock);
}


#if HAVE_SASL
void virNetSocketSetSASLSession(virNetSocketPtr sock,
                                virNetSASLSessionPtr sess)
{
    virMutexLock(&sock->lock);
    virNetSASLSessionFree(sock->saslSession);
    sock->saslSession = sess;
    virNetSASLSessionRef(sess);
    virMutexUnlock(&sock->lock);
}
#endif


bool virNetSocketHasCachedData(virNetSocketPtr sock ATTRIBUTE_UNUSED)
{
    bool hasCached = false;
    virMutexLock(&sock->lock);
#if HAVE_SASL
    if (sock->saslDecoded)
        hasCached = true;
#endif
    virMutexUnlock(&sock->lock);
    return hasCached;
}


bool virNetSocketHasPendingData(virNetSocketPtr sock ATTRIBUTE_UNUSED)
{
    bool hasPending = false;
    virMutexLock(&sock->lock);
#if HAVE_SASL
    if (sock->saslEncoded)
        hasPending = true;
#endif
    virMutexUnlock(&sock->lock);
    return hasPending;
}


static ssize_t virNetSocketReadWire(virNetSocketPtr sock, char *buf, size_t len)
{
    char *errout = NULL;
    ssize_t ret;
reread:
    if (sock->tlsSession &&
        virNetTLSSessionGetHandshakeStatus(sock->tlsSession) ==
        VIR_NET_TLS_HANDSHAKE_COMPLETE) {
        ret = virNetTLSSessionRead(sock->tlsSession, buf, len);
    } else {
        ret = read(sock->fd, buf, len);
    }

    if ((ret < 0) && (errno == EINTR))
        goto reread;
    if ((ret < 0) && (errno == EAGAIN))
        return 0;

    if (ret <= 0 &&
        sock->errfd != -1 &&
        virFileReadLimFD(sock->errfd, 1024, &errout) >= 0 &&
        errout != NULL) {
        size_t elen = strlen(errout);
        if (elen && errout[elen-1] == '\n')
            errout[elen-1] = '\0';
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
        if (errout)
            virReportSystemError(EIO,
                                 _("End of file while reading data: %s"), errout);
        else
            virReportSystemError(EIO, "%s",
                                 _("End of file while reading data"));
        ret = -1;
    }

    VIR_FREE(errout);
    return ret;
}

static ssize_t virNetSocketWriteWire(virNetSocketPtr sock, const char *buf, size_t len)
{
    ssize_t ret;
rewrite:
    if (sock->tlsSession &&
        virNetTLSSessionGetHandshakeStatus(sock->tlsSession) ==
        VIR_NET_TLS_HANDSHAKE_COMPLETE) {
        ret = virNetTLSSessionWrite(sock->tlsSession, buf, len);
    } else {
        ret = write(sock->fd, buf, len);
    }

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


#if HAVE_SASL
static ssize_t virNetSocketReadSASL(virNetSocketPtr sock, char *buf, size_t len)
{
    ssize_t got;

    /* Need to read some more data off the wire */
    if (sock->saslDecoded == NULL) {
        ssize_t encodedLen = virNetSASLSessionGetMaxBufSize(sock->saslSession);
        char *encoded;
        if (VIR_ALLOC_N(encoded, encodedLen) < 0) {
            virReportOOMError();
            return -1;
        }
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
        sock->saslEncoded = NULL;
        sock->saslEncodedOffset = sock->saslEncodedLength = 0;

        /* Mark as complete, so caller detects completion */
        return tosend;
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
    virMutexLock(&sock->lock);
#if HAVE_SASL
    if (sock->saslSession)
        ret = virNetSocketReadSASL(sock, buf, len);
    else
#endif
        ret = virNetSocketReadWire(sock, buf, len);
    virMutexUnlock(&sock->lock);
    return ret;
}

ssize_t virNetSocketWrite(virNetSocketPtr sock, const char *buf, size_t len)
{
    ssize_t ret;

    virMutexLock(&sock->lock);
#if HAVE_SASL
    if (sock->saslSession)
        ret = virNetSocketWriteSASL(sock, buf, len);
    else
#endif
        ret = virNetSocketWriteWire(sock, buf, len);
    virMutexUnlock(&sock->lock);
    return ret;
}


/*
 * Returns 1 if an FD was sent, 0 if it would block, -1 on error
 */
int virNetSocketSendFD(virNetSocketPtr sock, int fd)
{
    int ret = -1;
    if (!virNetSocketHasPassFD(sock)) {
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("Sending file descriptors is not supported on this socket"));
        return -1;
    }
    virMutexLock(&sock->lock);
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
    virMutexUnlock(&sock->lock);
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
        virNetError(VIR_ERR_INTERNAL_ERROR,
                    _("Receiving file descriptors is not supported on this socket"));
        return -1;
    }
    virMutexLock(&sock->lock);

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
    virMutexUnlock(&sock->lock);
    return ret;
}


int virNetSocketListen(virNetSocketPtr sock, int backlog)
{
    virMutexLock(&sock->lock);
    if (listen(sock->fd, backlog > 0 ? backlog : 30) < 0) {
        virReportSystemError(errno, "%s", _("Unable to listen on socket"));
        virMutexUnlock(&sock->lock);
        return -1;
    }
    virMutexUnlock(&sock->lock);
    return 0;
}

int virNetSocketAccept(virNetSocketPtr sock, virNetSocketPtr *clientsock)
{
    int fd = -1;
    virSocketAddr localAddr;
    virSocketAddr remoteAddr;
    int ret = -1;

    virMutexLock(&sock->lock);

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
                                        fd, -1, 0)))
        goto cleanup;

    fd = -1;
    ret = 0;

cleanup:
    VIR_FORCE_CLOSE(fd);
    virMutexUnlock(&sock->lock);
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

    virMutexLock(&sock->lock);
    func = sock->func;
    eopaque = sock->opaque;
    virMutexUnlock(&sock->lock);

    if (func)
        func(sock, events, eopaque);
}


static void virNetSocketEventFree(void *opaque)
{
    virNetSocketPtr sock = opaque;
    virFreeCallback ff;
    void *eopaque;

    virMutexLock(&sock->lock);
    ff = sock->ff;
    eopaque = sock->opaque;
    sock->func = NULL;
    sock->ff = NULL;
    sock->opaque = NULL;
    virMutexUnlock(&sock->lock);

    if (ff)
        ff(eopaque);

    virNetSocketFree(sock);
}

int virNetSocketAddIOCallback(virNetSocketPtr sock,
                              int events,
                              virNetSocketIOFunc func,
                              void *opaque,
                              virFreeCallback ff)
{
    int ret = -1;

    virNetSocketRef(sock);
    virMutexLock(&sock->lock);
    if (sock->watch > 0) {
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
    virMutexUnlock(&sock->lock);
    if (ret != 0)
        virNetSocketFree(sock);
    return ret;
}

void virNetSocketUpdateIOCallback(virNetSocketPtr sock,
                                  int events)
{
    virMutexLock(&sock->lock);
    if (sock->watch <= 0) {
        VIR_DEBUG("Watch not registered on socket %p", sock);
        virMutexUnlock(&sock->lock);
        return;
    }

    virEventUpdateHandle(sock->watch, events);

    virMutexUnlock(&sock->lock);
}

void virNetSocketRemoveIOCallback(virNetSocketPtr sock)
{
    virMutexLock(&sock->lock);

    if (sock->watch <= 0) {
        VIR_DEBUG("Watch not registered on socket %p", sock);
        virMutexUnlock(&sock->lock);
        return;
    }

    virEventRemoveHandle(sock->watch);

    virMutexUnlock(&sock->lock);
}

void virNetSocketClose(virNetSocketPtr sock)
{
    if (!sock)
        return;

    virMutexLock(&sock->lock);

    VIR_FORCE_CLOSE(sock->fd);

#ifdef HAVE_SYS_UN_H
    /* If a server socket, then unlink UNIX path */
    if (!sock->client &&
        sock->localAddr.data.sa.sa_family == AF_UNIX &&
        sock->localAddr.data.un.sun_path[0] != '\0') {
        if (unlink(sock->localAddr.data.un.sun_path) == 0)
            sock->localAddr.data.un.sun_path[0] = '\0';
    }
#endif

    virMutexUnlock(&sock->lock);
}
