/*
 * Copyright (C) 2010-2013, 2015 Red Hat, Inc.
 * Copyright (C) 2010-2012 IBM Corporation
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

#ifndef __VIR_NETLINK_H__
# define __VIR_NETLINK_H__

# include "internal.h"
# include "virmacaddr.h"

# if defined(__linux__) && defined(HAVE_LIBNL)

/* Work around a bug where older libnl-1 headers expected older gcc
 * semantics of 'extern inline' that conflict with C99 semantics.  */
#  ifdef HAVE_LIBNL1
#   define inline
#  endif
#  include <netlink/msg.h>
#  ifdef HAVE_LIBNL1
#   undef inline
#  endif

# else

struct nl_msg;
struct sockaddr_nl;
struct nlattr;
struct nlmsghdr;

# endif /* __linux__ */

int virNetlinkStartup(void);
void virNetlinkShutdown(void);

int virNetlinkCommand(struct nl_msg *nl_msg,
                      struct nlmsghdr **resp, unsigned int *respbuflen,
                      uint32_t src_pid, uint32_t dst_pid,
                      unsigned int protocol, unsigned int groups);

typedef int (*virNetlinkDumpCallback)(const struct nlmsghdr *resp,
                                      void *data);

int virNetlinkDumpCommand(struct nl_msg *nl_msg,
                          virNetlinkDumpCallback callback,
                          uint32_t src_pid, uint32_t dst_pid,
                          unsigned int protocol, unsigned int groups,
                          void *opaque);

typedef int (*virNetlinkDelLinkFallback)(const char *ifname);

int virNetlinkDelLink(const char *ifname, virNetlinkDelLinkFallback fallback);

int virNetlinkGetErrorCode(struct nlmsghdr *resp, unsigned int recvbuflen);

int virNetlinkDumpLink(const char *ifname, int ifindex,
                       void **nlData, struct nlattr **tb,
                       uint32_t src_pid, uint32_t dst_pid)
    ATTRIBUTE_RETURN_CHECK;

typedef void (*virNetlinkEventHandleCallback)(struct nlmsghdr *,
                                              unsigned int length,
                                              struct sockaddr_nl *peer,
                                              bool *handled,
                                              void *opaque);

typedef void (*virNetlinkEventRemoveCallback)(int watch,
                                              const virMacAddr *macaddr,
                                              void *opaque);

/**
 * stopNetlinkEventServer: stop the monitor to receive netlink messages for libvirtd
 */
int virNetlinkEventServiceStop(unsigned int protocol);

/**
 * stopNetlinkEventServerAll: stop all the monitors to receive netlink messages for libvirtd
 */
int virNetlinkEventServiceStopAll(void);

/**
 * startNetlinkEventServer: start a monitor to receive netlink messages for libvirtd
 */
int virNetlinkEventServiceStart(unsigned int protocol, unsigned int groups);

/**
 * virNetlinkEventServiceIsRunning: returns if the netlink event service is running.
 */
bool virNetlinkEventServiceIsRunning(unsigned int protocol);

/**
 * virNetlinkEventServiceLocalPid: returns nl_pid used to bind() netlink socket
 */
int virNetlinkEventServiceLocalPid(unsigned int protocol);

/**
 * virNetlinkEventAddClient: register a callback for handling of netlink messages
 */
int virNetlinkEventAddClient(virNetlinkEventHandleCallback handleCB,
                             virNetlinkEventRemoveCallback removeCB,
                             void *opaque, const virMacAddr *macaddr,
                             unsigned int protocol);

/**
 * virNetlinkEventRemoveClient: unregister a callback from a netlink monitor
 */
int virNetlinkEventRemoveClient(int watch, const virMacAddr *macaddr,
                                unsigned int protocol);

#endif /* __VIR_NETLINK_H__ */
