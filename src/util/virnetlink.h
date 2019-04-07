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

#ifndef LIBVIRT_VIRNETLINK_H
# define LIBVIRT_VIRNETLINK_H

# include "internal.h"
# include "virmacaddr.h"
# include "viralloc.h"

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

typedef struct nl_msg virNetlinkMsg;
VIR_DEFINE_AUTOPTR_FUNC(virNetlinkMsg, nlmsg_free);

# else

struct nl_msg;
struct sockaddr_nl;
struct nlattr;
struct nlmsghdr;

# endif /* __linux__ */

# define NETLINK_MSG_NEST_START(msg, container, attrtype) \
do { \
    container = nla_nest_start(msg, attrtype); \
    if (!container) \
        goto buffer_too_small; \
} while(0)

# define NETLINK_MSG_NEST_END(msg, container) \
do { nla_nest_end(msg, container); } while(0)

/*
 * we need to use an intermediary pointer to @data as compilers may sometimes
 * complain about @data not being a pointer type:
 * error: the address of 'foo' will always evaluate as 'true' [-Werror=address]
 */
# define NETLINK_MSG_PUT(msg, attrtype, datalen, data) \
do { \
    const void *dataptr = data; \
    if (dataptr && nla_put(msg, attrtype, datalen, dataptr) < 0) \
        goto buffer_too_small; \
} while(0)


int virNetlinkStartup(void);
void virNetlinkShutdown(void);

int virNetlinkCommand(struct nl_msg *nl_msg,
                      struct nlmsghdr **resp, unsigned int *respbuflen,
                      uint32_t src_pid, uint32_t dst_pid,
                      unsigned int protocol, unsigned int groups);

typedef int (*virNetlinkDumpCallback)(struct nlmsghdr *resp,
                                      void *data);

int virNetlinkDumpCommand(struct nl_msg *nl_msg,
                          virNetlinkDumpCallback callback,
                          uint32_t src_pid, uint32_t dst_pid,
                          unsigned int protocol, unsigned int groups,
                          void *opaque);

typedef struct _virNetlinkNewLinkData virNetlinkNewLinkData;
typedef virNetlinkNewLinkData *virNetlinkNewLinkDataPtr;
struct _virNetlinkNewLinkData {
    const int *ifindex;             /* The index for the 'link' device */
    const virMacAddr *mac;          /* The MAC address of the device */
    const uint32_t *macvlan_mode;   /* The mode of macvlan */
};

int virNetlinkNewLink(const char *ifname,
                      const char *type,
                      virNetlinkNewLinkDataPtr data,
                      int *error);

typedef int (*virNetlinkDelLinkFallback)(const char *ifname);

int virNetlinkDelLink(const char *ifname, virNetlinkDelLinkFallback fallback);

int virNetlinkGetErrorCode(struct nlmsghdr *resp, unsigned int recvbuflen);

int virNetlinkDumpLink(const char *ifname, int ifindex,
                       void **nlData, struct nlattr **tb,
                       uint32_t src_pid, uint32_t dst_pid)
    ATTRIBUTE_RETURN_CHECK;
int
virNetlinkGetNeighbor(void **nlData, uint32_t src_pid, uint32_t dst_pid);

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

#endif /* LIBVIRT_VIRNETLINK_H */
