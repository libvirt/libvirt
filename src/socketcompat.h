/*
 * socketcompat.h: Socket compatibility for Windows, making it slightly
 * less painful to use.
 *
 * Use this header under the following circumstances:
 * (a) Instead of including any of: <net/if.h>, <netinet/in.h>,
 *     <sys/socket.h>, <netdb.h>, <netinet/tcp.h>, AND
 * (b) The file will be part of what is built on Windows (basically
 *     just remote client stuff).
 *
 * You need to use socket_errno() instead of errno to get socket
 * errors.
 *
 * Copyright (C) 2008 Red Hat, Inc.
 *
 * See COPYING.LIB for the License of this software
 *
 * Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef __SOCKETCOMPAT_H__
#define __SOCKETCOMPAT_H__

#include <config.h>

#include <errno.h>
#include <sys/socket.h>

static inline int
socket_errno (void)
{
  return errno;
}

#ifndef HAVE_WINSOCK2_H		/* Unix & Cygwin. */
# include <sys/un.h>
# include <net/if.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
#endif /* HAVE_WINSOCK2_H */

#endif /* __WINSOCKWRAPPER_H__ */
