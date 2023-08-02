/*
 * Copyright (C) 2020 Red Hat, Inc.
 * Copyright (C) 2011-2021 Free Software Foundation, Inc.
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

#include "virsocket.h"
#include "virutil.h"
#include "virfile.h"

#include <fcntl.h>

#ifdef WIN32

# define FD2SK(fd) _get_osfhandle(fd)
# define SK2FD(sk) (_open_osfhandle((intptr_t) (sk), O_RDWR | O_BINARY))

# define GET_HANDLE(fd) \

# define RETURN_ERROR(call) \
    if ((call) < 0) { \
        set_errno(); \
        return -1; \
    }

# undef accept
# undef bind
# undef closesocket
# undef connect
# undef getpeername
# undef getsockname
# undef getsockopt
# undef ioctlsocket
# undef listen
# undef setsockopt
# undef socket

static void
set_errno(void)
{
    int err = WSAGetLastError();

    /* Map some WSAE* errors to the runtime library's error codes.  */
    switch (err) {
    case WSA_INVALID_HANDLE:
        errno = EBADF;
        break;
    case WSA_NOT_ENOUGH_MEMORY:
        errno = ENOMEM;
        break;
    case WSA_INVALID_PARAMETER:
        errno = EINVAL;
        break;
    case WSAENAMETOOLONG:
        errno = ENAMETOOLONG;
        break;
    case WSAENOTEMPTY:
        errno = ENOTEMPTY;
        break;
    case WSAEWOULDBLOCK:
        errno = EWOULDBLOCK;
        break;
    case WSAEINPROGRESS:
        errno = EINPROGRESS;
        break;
    case WSAEALREADY:
        errno = EALREADY;
        break;
    case WSAENOTSOCK:
        errno = ENOTSOCK;
        break;
    case WSAEDESTADDRREQ:
        errno = EDESTADDRREQ;
        break;
    case WSAEMSGSIZE:
        errno = EMSGSIZE;
        break;
    case WSAEPROTOTYPE:
        errno = EPROTOTYPE;
        break;
    case WSAENOPROTOOPT:
        errno = ENOPROTOOPT;
        break;
    case WSAEPROTONOSUPPORT:
        errno = EPROTONOSUPPORT;
        break;
    case WSAEOPNOTSUPP:
        errno = EOPNOTSUPP;
        break;
    case WSAEAFNOSUPPORT:
        errno = EAFNOSUPPORT;
        break;
    case WSAEADDRINUSE:
        errno = EADDRINUSE;
        break;
    case WSAEADDRNOTAVAIL:
        errno = EADDRNOTAVAIL;
        break;
    case WSAENETDOWN:
        errno = ENETDOWN;
        break;
    case WSAENETUNREACH:
        errno = ENETUNREACH;
        break;
    case WSAENETRESET:
        errno = ENETRESET;
        break;
    case WSAECONNABORTED:
        errno = ECONNABORTED;
        break;
    case WSAECONNRESET:
        errno = ECONNRESET;
        break;
    case WSAENOBUFS:
        errno = ENOBUFS;
        break;
    case WSAEISCONN:
        errno = EISCONN;
        break;
    case WSAENOTCONN:
        errno = ENOTCONN;
        break;
    case WSAETIMEDOUT:
        errno = ETIMEDOUT;
        break;
    case WSAECONNREFUSED:
        errno = ECONNREFUSED;
        break;
    case WSAELOOP:
        errno = ELOOP;
        break;
    case WSAEHOSTUNREACH:
        errno = EHOSTUNREACH;
        break;
    default:
        errno = (err > 10000 && err < 10025) ? err - 10000 : err;
        break;
    }
}


int
vir_accept(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);
    SOCKET csk;

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    csk = accept(sk, addr, addrlen);

    if (csk == INVALID_SOCKET) {
        set_errno();
        return -1;
    }

    return SK2FD(csk);
}


int
vir_bind(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (bind(sk, addr, addrlen) < 0)  {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_closesocket(int fd)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (closesocket(sk) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (connect(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getpeername(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getsockname(sk, addr, addrlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_listen(int fd, int backlog)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (listen(sk, backlog) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_ioctlsocket(int fd, int cmd, void *arg)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (ioctlsocket(sk, cmd, arg) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_getsockopt(int fd, int level, int optname,
               void *optval, socklen_t *optlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (getsockopt(sk, level, optname, optval, optlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    SOCKET sk = FD2SK(fd);

    if (sk == INVALID_SOCKET) {
        errno = EBADF;
        return -1;
    }

    if (setsockopt(sk, level, optname, optval, optlen) < 0) {
        set_errno();
        return -1;
    }

    return 0;
}


int
vir_socket(int domain, int type, int protocol)
{
    SOCKET sk;

    /* We have to use WSASocket() instead of socket(), to create
     * non-overlapped IO sockets. Overlapped IO sockets cannot
     * be used with read/write.
     */
    sk = WSASocket(domain, type, protocol, NULL, 0, 0);
    if (sk == INVALID_SOCKET) {
        set_errno();
        return -1;
    }

    return SK2FD(sk);
}

#endif /* WIN32 */


/* The following two methods are derived from GNULIB's
 * passfd code */

/* MSG_CMSG_CLOEXEC is defined only on Linux, as of 2011.  */
#ifndef MSG_CMSG_CLOEXEC
# define MSG_CMSG_CLOEXEC 0
#endif

#ifndef WIN32
/* virSocketSendFD sends the file descriptor fd along the socket
   to a process calling virSocketRecvFD on the other end.

   Return 0 on success, or -1 with errno set in case of error.
*/
int
virSocketSendFD(int sock, int fd)
{
    char byte = 0;
    struct iovec iov;
    struct msghdr msg = { 0 };
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];

    /* send at least one char */
    iov.iov_base = &byte;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    /* Initialize the payload: */
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = cmsg->cmsg_len;

    if (sendmsg(sock, &msg, 0) != iov.iov_len)
        return -1;
    return 0;
}


/* virSocketRecvFD receives a file descriptor through the socket.
   The flags are a bitmask, possibly including O_CLOEXEC (defined in <fcntl.h>).

   Return the fd on success, or -1 with errno set in case of error.
*/
int
virSocketRecvFD(int sock, int fdflags)
{
    char byte = 0;
    struct iovec iov;
    struct msghdr msg = { 0 };
    int fd = -1;
    ssize_t len;
    struct cmsghdr *cmsg;
    char buf[CMSG_SPACE(sizeof(fd))];
    int fdflags_recvmsg = fdflags & O_CLOEXEC ? MSG_CMSG_CLOEXEC : 0;

    if ((fdflags & ~O_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }

    /* send at least one char */
    iov.iov_base = &byte;
    iov.iov_len = 1;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
    /* Initialize the payload: */
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));
    msg.msg_controllen = CMSG_SPACE(sizeof(fd));

    len = recvmsg(sock, &msg, fdflags_recvmsg);
    if (len < 0)
        return -1;

    cmsg = CMSG_FIRSTHDR(&msg);
    /* be paranoiac */
    if (len == 0 || cmsg == NULL || cmsg->cmsg_len != CMSG_LEN(sizeof(fd))
        || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
        /* fake errno: at end the file is not available */
        errno = len ? EACCES : ENOTCONN;
        return -1;
    }

    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));

    /* set close-on-exec flag */
    if (!MSG_CMSG_CLOEXEC && (fdflags & O_CLOEXEC)) {
        if (virSetCloseExec(fd) < 0) {
            VIR_FORCE_CLOSE(fd);
            return -1;
        }
    }

    return fd;
}
#else /* WIN32 */
int
virSocketSendFD(int sock G_GNUC_UNUSED, int fd G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}

int
virSocketRecvFD(int sock G_GNUC_UNUSED, int fdflags G_GNUC_UNUSED)
{
    errno = ENOSYS;
    return -1;
}
#endif  /* WIN32 */
