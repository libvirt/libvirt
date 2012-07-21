/*
 * Copyright (C) 2010-2012 Red Hat, Inc.
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
 * License along with this library;  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Authors:
 *     Stefan Berger <stefanb@us.ibm.com>
 *     Dirk Herrendoerfer <herrend[at]de[dot]ibm[dot]com>
 *
 * Notes:
 * netlink: http://lovezutto.googlepages.com/netlink.pdf
 *          iproute2 package
 *
 * 2012/02: Renamed from netlink.[ch] to virnetlink.[ch]
 *
 */

#include <config.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "virnetlink.h"
#include "logging.h"
#include "memory.h"
#include "threads.h"
#include "virmacaddr.h"
#include "virterror_internal.h"

#define VIR_FROM_THIS VIR_FROM_NET

#define NETLINK_ACK_TIMEOUT_S  2

#if defined(__linux__) && defined(HAVE_LIBNL)
/* State for a single netlink event handle */
struct virNetlinkEventHandle {
    int watch;
    virNetlinkEventHandleCallback handleCB;
    virNetlinkEventRemoveCallback removeCB;
    void *opaque;
    virMacAddr macaddr;
    int deleted;
};

# ifdef HAVE_LIBNL1
#  define virNetlinkAlloc nl_handle_alloc
#  define virNetlinkFree nl_handle_destroy
typedef struct nl_handle virNetlinkHandle;
# else
#  define virNetlinkAlloc nl_socket_alloc
#  define virNetlinkFree nl_socket_free
typedef struct nl_sock virNetlinkHandle;
# endif

typedef struct _virNetlinkEventSrvPrivate virNetlinkEventSrvPrivate;
typedef virNetlinkEventSrvPrivate *virNetlinkEventSrvPrivatePtr;
struct _virNetlinkEventSrvPrivate {
    /*Server*/
    virMutex lock;
    int eventwatch;
    int netlinkfd;
    virNetlinkHandle *netlinknh;
    /*Events*/
    int handled;
    size_t handlesCount;
    size_t handlesAlloc;
    struct virNetlinkEventHandle *handles;
};

enum virNetlinkDeleteMode {
    VIR_NETLINK_HANDLE_VALID,
    VIR_NETLINK_HANDLE_DELETED,
};

/* Unique ID for the next netlink watch to be registered */
static int nextWatch = 1;

/* Allocate extra slots for virEventPollHandle/virEventPollTimeout
 records in this multiple */
# define NETLINK_EVENT_ALLOC_EXTENT 10

static virNetlinkEventSrvPrivatePtr server = NULL;
static virNetlinkHandle *placeholder_nlhandle = NULL;

/* Function definitions */

/**
 * virNetlinkStartup:
 *
 * Perform any initialization that needs to take place before the
 * program starts up worker threads. This is currently used to assure
 * that an nl_handle is allocated prior to any attempts to bind a
 * netlink socket. For a discussion of why this is necessary, please
 * see the following email message:
 *
 *   https://www.redhat.com/archives/libvir-list/2012-May/msg00202.html
 *
 * The short version is that, without this placeholder allocation of
 * an nl_handle that is never used, it is possible for nl_connect() in
 * one thread to collide with a direct bind() of a netlink socket in
 * another thread, leading to failure of the operation (which could
 * lead to failure of libvirtd to start). Since getaddrinfo() (used by
 * libvirtd in virSocketAddrParse, which is called quite frequently
 * during startup) directly calls bind() on a netlink socket, this is
 * actually a very common occurrence (15-20% failure rate on some
 * hardware).
 *
 * Returns 0 on success, -1 on failure.
 */
int
virNetlinkStartup(void)
{
    if (placeholder_nlhandle)
        return 0;
    VIR_DEBUG("Running global netlink initialization");
    placeholder_nlhandle = virNetlinkAlloc();
    if (!placeholder_nlhandle) {
        virReportSystemError(errno, "%s",
                             _("cannot allocate placeholder nlhandle for netlink"));
        return -1;
    }
    return 0;
}

/**
 * virNetlinkShutdown:
 *
 * Undo any initialization done by virNetlinkStartup. This currently
 * destroys the placeholder nl_handle.
 */
void
virNetlinkShutdown(void)
{
    if (placeholder_nlhandle) {
        virNetlinkFree(placeholder_nlhandle);
        placeholder_nlhandle = NULL;
    }
}

/**
 * virNetlinkCommand:
 * @nlmsg: pointer to netlink message
 * @respbuf: pointer to pointer where response buffer will be allocated
 * @respbuflen: pointer to integer holding the size of the response buffer
 *      on return of the function.
 * @nl_pid: the pid of the process to talk to, i.e., pid = 0 for kernel
 *
 * Send the given message to the netlink layer and receive response.
 * Returns 0 on success, -1 on error. In case of error, no response
 * buffer will be returned.
 */
int virNetlinkCommand(struct nl_msg *nl_msg,
                      unsigned char **respbuf, unsigned int *respbuflen,
                      uint32_t src_pid, uint32_t dst_pid)
{
    int rc = 0;
    struct sockaddr_nl nladdr = {
            .nl_family = AF_NETLINK,
            .nl_pid    = dst_pid,
            .nl_groups = 0,
    };
    ssize_t nbytes;
    struct timeval tv = {
        .tv_sec = NETLINK_ACK_TIMEOUT_S,
    };
    fd_set readfds;
    int fd;
    int n;
    struct nlmsghdr *nlmsg = nlmsg_hdr(nl_msg);
    virNetlinkHandle *nlhandle = virNetlinkAlloc();

    if (!nlhandle) {
        virReportSystemError(errno,
                             "%s", _("cannot allocate nlhandle for netlink"));
        return -1;
    }

    if (nl_connect(nlhandle, NETLINK_ROUTE) < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot connect to netlink socket"));
        rc = -1;
        goto error;
    }

    nlmsg_set_dst(nl_msg, &nladdr);

    nlmsg->nlmsg_pid = src_pid ? src_pid : getpid();

    nbytes = nl_send_auto_complete(nlhandle, nl_msg);
    if (nbytes < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot send to netlink socket"));
        rc = -1;
        goto error;
    }

    fd = nl_socket_get_fd(nlhandle);

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    n = select(fd + 1, &readfds, NULL, NULL, &tv);
    if (n <= 0) {
        if (n < 0)
            virReportSystemError(errno, "%s",
                                 _("error in select call"));
        if (n == 0)
            virReportSystemError(ETIMEDOUT, "%s",
                                 _("no valid netlink response was received"));
        rc = -1;
        goto error;
    }

    *respbuflen = nl_recv(nlhandle, &nladdr, respbuf, NULL);
    if (*respbuflen <= 0) {
        virReportSystemError(errno,
                             "%s", _("nl_recv failed"));
        rc = -1;
    }
error:
    if (rc == -1) {
        VIR_FREE(*respbuf);
        *respbuf = NULL;
        *respbuflen = 0;
    }

    virNetlinkFree(nlhandle);
    return rc;
}

static void
virNetlinkEventServerLock(virNetlinkEventSrvPrivatePtr driver)
{
    virMutexLock(&driver->lock);
}

static void
virNetlinkEventServerUnlock(virNetlinkEventSrvPrivatePtr driver)
{
    virMutexUnlock(&driver->lock);
}

/**
 * virNetlinkEventRemoveClientPrimitive:
 *
 * @i: index of the client to remove from the table
 *
 * This static function does the low level removal of a client from
 * the table once its index is known, including calling the remove
 * callback (which usually will free resources required by the
 * handler). The event server lock *must* be locked before calling
 * this function.
 *
 * assumes success, returns nothing.
 */
static void
virNetlinkEventRemoveClientPrimitive(size_t i)
{
    virNetlinkEventRemoveCallback removeCB = server->handles[i].removeCB;

    if (removeCB) {
        (removeCB)(server->handles[i].watch,
                   &server->handles[i].macaddr,
                   server->handles[i].opaque);
    }
    server->handles[i].deleted = VIR_NETLINK_HANDLE_DELETED;
}

static void
virNetlinkEventCallback(int watch,
                        int fd ATTRIBUTE_UNUSED,
                        int events ATTRIBUTE_UNUSED,
                        void *opaque)
{
    virNetlinkEventSrvPrivatePtr srv = opaque;
    unsigned char *msg;
    struct sockaddr_nl peer;
    struct ucred *creds = NULL;
    int i, length;
    bool handled = false;

    length = nl_recv(srv->netlinknh, &peer, &msg, &creds);

    if (length == 0)
        return;
    if (length < 0) {
        virReportSystemError(errno,
                             "%s", _("nl_recv returned with error"));
        return;
    }

    virNetlinkEventServerLock(srv);

    VIR_DEBUG("dispatching to max %d clients, called from event watch %d",
            (int)srv->handlesCount, watch);

    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted != VIR_NETLINK_HANDLE_VALID)
            continue;

        VIR_DEBUG("dispatching client %d.", i);

        (srv->handles[i].handleCB)(msg, length, &peer, &handled,
                                   srv->handles[i].opaque);
    }

    if (!handled)
        VIR_DEBUG("event not handled.");
    VIR_FREE(msg);
    virNetlinkEventServerUnlock(srv);
}

/**
 * virNetlinkEventServiceStop:
 *
 * stop the monitor to receive netlink messages for libvirtd.
 * This removes the netlink socket fd from the event handler.
 *
 * Returns -1 if the monitor cannot be unregistered, 0 upon success
 */
int
virNetlinkEventServiceStop(void)
{
    virNetlinkEventSrvPrivatePtr srv = server;
    int i;

    VIR_INFO("stopping netlink event service");

    if (!server)
        return 0;

    virNetlinkEventServerLock(srv);
    nl_close(srv->netlinknh);
    virNetlinkFree(srv->netlinknh);
    virEventRemoveHandle(srv->eventwatch);

    /* free any remaining clients on the list */
    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted == VIR_NETLINK_HANDLE_VALID)
            virNetlinkEventRemoveClientPrimitive(i);
    }

    server = 0;
    virNetlinkEventServerUnlock(srv);

    virMutexDestroy(&srv->lock);
    VIR_FREE(srv);
    return 0;
}

/**
 * virNetlinkEventServiceIsRunning:
 *
 * Returns if the netlink event service is running.
 *
 * Returns 'true' if the service is running, 'false' if stopped.
 */
bool
virNetlinkEventServiceIsRunning(void)
{
    return server != NULL;
}

/**
 * virNetlinkEventServiceLocalPid:
 *
 * Returns the nl_pid value that was used to bind() the netlink socket
 * used by the netlink event service, or -1 on error (netlink
 * guarantees that this value will always be > 0).
 */
int virNetlinkEventServiceLocalPid(void)
{
    if (!(server && server->netlinknh)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("netlink event service not running"));
        return -1;
    }
    return (int)nl_socket_get_local_port(server->netlinknh);
}


/**
 * virNetlinkEventServiceStart:
 *
 * start a monitor to receive netlink messages for libvirtd.
 * This registers a netlink socket with the event interface.
 *
 * Returns -1 if the monitor cannot be registered, 0 upon success
 */
int
virNetlinkEventServiceStart(void)
{
    virNetlinkEventSrvPrivatePtr srv;
    int fd;
    int ret = -1;

    if (server)
        return 0;

    VIR_INFO("starting netlink event service");

    if (VIR_ALLOC(srv) < 0) {
        virReportOOMError();
        return -1;
    }

    if (virMutexInit(&srv->lock) < 0) {
        VIR_FREE(srv);
        return -1;
    }

    virNetlinkEventServerLock(srv);

    /* Allocate a new socket and get fd */
    srv->netlinknh = virNetlinkAlloc();

    if (!srv->netlinknh) {
        virReportSystemError(errno,
                             "%s", _("cannot allocate nlhandle for virNetlinkEvent server"));
        goto error_locked;
    }

    if (nl_connect(srv->netlinknh, NETLINK_ROUTE) < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot connect to netlink socket"));
        goto error_server;
    }

    fd = nl_socket_get_fd(srv->netlinknh);

    if (fd < 0) {
        virReportSystemError(errno,
                             "%s", _("cannot get netlink socket fd"));
        goto error_server;
    }

    if (nl_socket_set_nonblocking(srv->netlinknh)) {
        virReportSystemError(errno, "%s",
                             _("cannot set netlink socket nonblocking"));
        goto error_server;
    }

    if ((srv->eventwatch = virEventAddHandle(fd,
                                             VIR_EVENT_HANDLE_READABLE,
                                             virNetlinkEventCallback,
                                             srv, NULL)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Failed to add netlink event handle watch"));
        goto error_server;
    }

    srv->netlinkfd = fd;
    VIR_DEBUG("netlink event listener on fd: %i running", fd);

    ret = 0;
    server = srv;

error_server:
    if (ret < 0) {
        nl_close(srv->netlinknh);
        virNetlinkFree(srv->netlinknh);
    }
error_locked:
    virNetlinkEventServerUnlock(srv);
    if (ret < 0) {
        virMutexDestroy(&srv->lock);
        VIR_FREE(srv);
    }
    return ret;
}

/**
 * virNetlinkEventAddClient:
 *
 * @handleCB: callback to invoke when an event occurs
 * @removeCB: callback to invoke when removing a client
 * @opaque: user data to pass to callback
 * @macaddr: macaddr to store with the data. Used to identify callers.
 *           May be null.
 *
 * register a callback for handling of netlink messages. The
 * registered function receives the entire netlink message and
 * may choose to act upon it.
 *
 * Returns -1 if the file handle cannot be registered, number of
 * monitor upon success.
 */
int
virNetlinkEventAddClient(virNetlinkEventHandleCallback handleCB,
                         virNetlinkEventRemoveCallback removeCB,
                         void *opaque, const virMacAddrPtr macaddr)
{
    int i, r, ret = -1;
    virNetlinkEventSrvPrivatePtr srv = server;

    if (handleCB == NULL) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Invalid NULL callback provided"));
        return -1;
    }

    virNetlinkEventServerLock(srv);

    VIR_DEBUG("adding client: %d.", nextWatch);

    r = 0;
    /* first try to re-use deleted free slots */
    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted == VIR_NETLINK_HANDLE_DELETED) {
            r = i;
            goto addentry;
        }
    }
    /* Resize the eventLoop array if needed */
    if (srv->handlesCount == srv->handlesAlloc) {
        VIR_DEBUG("Used %zu handle slots, adding at least %d more",
                  srv->handlesAlloc, NETLINK_EVENT_ALLOC_EXTENT);
        if (VIR_RESIZE_N(srv->handles, srv->handlesAlloc,
                        srv->handlesCount, NETLINK_EVENT_ALLOC_EXTENT) < 0) {
            virReportOOMError();
            goto error;
        }
    }
    r = srv->handlesCount++;

addentry:
    srv->handles[r].watch    = nextWatch;
    srv->handles[r].handleCB = handleCB;
    srv->handles[r].removeCB = removeCB;
    srv->handles[r].opaque   = opaque;
    srv->handles[r].deleted  = VIR_NETLINK_HANDLE_VALID;
    if (macaddr)
        virMacAddrSet(&srv->handles[r].macaddr, macaddr);
    else
        virMacAddrSetRaw(&srv->handles[r].macaddr,
                         (unsigned char[VIR_MAC_BUFLEN]){0,0,0,0,0,0});

    VIR_DEBUG("added client to loop slot: %d. with macaddr ptr=%p", r, macaddr);

    ret = nextWatch++;
error:
    virNetlinkEventServerUnlock(srv);
    return ret;
}

/**
 * virNetlinkEventRemoveClient:
 *
 * @watch: watch whose handle to remove
 * @macaddr: macaddr whose handle to remove
 *
 * Unregister a callback from a netlink monitor.
 * The handler function referenced will no longer receive netlink messages.
 * Either watch or macaddr may be used, the other should be null.
 *
 * Returns -1 if the file handle was not registered, 0 upon success
 */
int
virNetlinkEventRemoveClient(int watch, const virMacAddrPtr macaddr)
{
    int i;
    int ret = -1;
    virNetlinkEventSrvPrivatePtr srv = server;

    VIR_DEBUG("removing client watch=%d, mac=%p.", watch, macaddr);

    if (watch <= 0 && !macaddr) {
        VIR_WARN("Ignoring invalid netlink client id: %d", watch);
        return -1;
    }

    virNetlinkEventServerLock(srv);

    for (i = 0; i < srv->handlesCount; i++) {
        if (srv->handles[i].deleted != VIR_NETLINK_HANDLE_VALID)
            continue;

        if ((watch && srv->handles[i].watch == watch) ||
            (!watch &&
             virMacAddrCmp(macaddr, &srv->handles[i].macaddr) == 0)) {

            VIR_DEBUG("removed client: %d by %s.",
                      srv->handles[i].watch, watch ? "index" : "mac");
            virNetlinkEventRemoveClientPrimitive(i);
            ret = 0;
            goto cleanup;
        }
    }
    VIR_DEBUG("no client found to remove.");

cleanup:
    virNetlinkEventServerUnlock(srv);
    return ret;
}

#else

# if defined(__linux)
static const char *unsupported = N_("libnl was not available at build time");
# else
static const char *unsupported = N_("not supported on non-linux platforms");
# endif

int
virNetlinkStartup(void)
{
    return 0;
}

void
virNetlinkShutdown(void)
{
    return;
}

int virNetlinkCommand(struct nl_msg *nl_msg ATTRIBUTE_UNUSED,
                      unsigned char **respbuf ATTRIBUTE_UNUSED,
                      unsigned int *respbuflen ATTRIBUTE_UNUSED,
                      uint32_t src_pid ATTRIBUTE_UNUSED,
                      uint32_t dst_pid ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * stopNetlinkEventServer: stop the monitor to receive netlink
 * messages for libvirtd
 */
int virNetlinkEventServiceStop(void)
{
    VIR_DEBUG("%s", _(unsupported));
    return 0;
}

/**
 * startNetlinkEventServer: start a monitor to receive netlink
 * messages for libvirtd
 */
int virNetlinkEventServiceStart(void)
{
    VIR_DEBUG("%s", _(unsupported));
    return 0;
}

/**
 * virNetlinkEventServiceIsRunning: returns if the netlink event
 * service is running.
 */
bool virNetlinkEventServiceIsRunning(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return 0;
}

int virNetlinkEventServiceLocalPid(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * virNetlinkEventAddClient: register a callback for handling of
 * netlink messages
 */
int virNetlinkEventAddClient(virNetlinkEventHandleCallback handleCB ATTRIBUTE_UNUSED,
                             virNetlinkEventRemoveCallback removeCB ATTRIBUTE_UNUSED,
                             void *opaque ATTRIBUTE_UNUSED,
                             const virMacAddrPtr macaddr ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

/**
 * virNetlinkEventRemoveClient: unregister a callback from a netlink monitor
 */
int virNetlinkEventRemoveClient(int watch ATTRIBUTE_UNUSED,
                                const virMacAddrPtr macaddr ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

#endif /* __linux__ */
