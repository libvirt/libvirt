/*
 * vireventglibwatch.c: GSource impl for sockets
 *
 * Copyright (C) 2015-2020 Red Hat, Inc.
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
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include "vireventglibwatch.h"

#ifndef WIN32
typedef struct virEventGLibFDSource virEventGLibFDSource;
struct virEventGLibFDSource {
    GSource parent;
    GPollFD pollfd;
    int fd;
    GIOCondition condition;
};


static gboolean
virEventGLibFDSourcePrepare(GSource *source G_GNUC_UNUSED,
                            gint *timeout)
{
    *timeout = -1;

    return FALSE;
}


static gboolean
virEventGLibFDSourceCheck(GSource *source)
{
    virEventGLibFDSource *ssource = (virEventGLibFDSource *)source;

    return ssource->pollfd.revents & ssource->condition;
}


static gboolean
virEventGLibFDSourceDispatch(GSource *source,
                             GSourceFunc callback,
                             gpointer user_data)
{
    virEventGLibSocketFunc func = (virEventGLibSocketFunc)callback;
    virEventGLibFDSource *ssource = (virEventGLibFDSource *)source;

    return (*func)(ssource->fd,
                   ssource->pollfd.revents & ssource->condition,
                   user_data);
}


static void
virEventGLibFDSourceFinalize(GSource *source G_GNUC_UNUSED)
{
}


GSourceFuncs virEventGLibFDSourceFuncs = {
    .prepare = virEventGLibFDSourcePrepare,
    .check = virEventGLibFDSourceCheck,
    .dispatch = virEventGLibFDSourceDispatch,
    .finalize = virEventGLibFDSourceFinalize
};


GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition)
{
    GSource *source;
    virEventGLibFDSource *ssource;

    source = g_source_new(&virEventGLibFDSourceFuncs,
                          sizeof(virEventGLibFDSource));
    ssource = (virEventGLibFDSource *)source;

    ssource->condition = condition | G_IO_HUP | G_IO_ERR;
    ssource->fd = fd;

    ssource->pollfd.fd = fd;
    ssource->pollfd.events = condition | G_IO_HUP | G_IO_ERR;

    g_source_add_poll(source, &ssource->pollfd);

    return source;
}

#else /* WIN32 */

# define WIN32_LEAN_AND_MEAN
# include <winsock2.h>

typedef struct virEventGLibSocketSource virEventGLibSocketSource;
struct virEventGLibSocketSource {
    GSource parent;
    GPollFD pollfd;
    int fd;
    SOCKET socket;
    HANDLE event;
    int revents;
    GIOCondition condition;
};


static gboolean
virEventGLibSocketSourcePrepare(GSource *source G_GNUC_UNUSED,
                                gint *timeout)
{
    *timeout = -1;

    return FALSE;
}


/*
 * NB, this impl only works when the socket is in non-blocking
 * mode on Win32
 */
static gboolean
virEventGLibSocketSourceCheck(GSource *source)
{
    static struct timeval tv0;

    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;
    WSANETWORKEVENTS ev;
    fd_set rfds, wfds, xfds;

    if (!ssource->condition)
        return 0;

    WSAEnumNetworkEvents(ssource->socket, ssource->event, &ev);

    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&xfds);
    if (ssource->condition & G_IO_IN)
        FD_SET(ssource->socket, &rfds);
    if (ssource->condition & G_IO_OUT)
        FD_SET(ssource->socket, &wfds);
    if (ssource->condition & G_IO_PRI)
        FD_SET(ssource->socket, &xfds);

    ssource->revents = 0;
    if (select(0, &rfds, &wfds, &xfds, &tv0) == 0)
        return 0;

    if (FD_ISSET(ssource->socket, &rfds))
        ssource->revents |= G_IO_IN;

    if (FD_ISSET(ssource->socket, &wfds))
        ssource->revents |= G_IO_OUT;

    if (FD_ISSET(ssource->socket, &xfds))
        ssource->revents |= G_IO_PRI;

    return ssource->revents;
}


static gboolean
virEventGLibSocketSourceDispatch(GSource *source,
                                 GSourceFunc callback,
                                 gpointer user_data)
{
    virEventGLibSocketFunc func = (virEventGLibSocketFunc)callback;
    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;

    return (*func)(ssource->fd, ssource->revents, user_data);
}


static void
virEventGLibSocketSourceFinalize(GSource *source)
{
    virEventGLibSocketSource *ssource = (virEventGLibSocketSource *)source;

    WSAEventSelect(ssource->socket, NULL, 0);
    CloseHandle(ssource->event);
}


GSourceFuncs virEventGLibSocketSourceFuncs = {
    .prepare = virEventGLibSocketSourcePrepare,
    .check = virEventGLibSocketSourceCheck,
    .dispatch = virEventGLibSocketSourceDispatch,
    .finalize = virEventGLibSocketSourceFinalize
};


GSource *virEventGLibCreateSocketWatch(int fd,
                                       GIOCondition condition)
{
    GSource *source;
    virEventGLibSocketSource *ssource;

    source = g_source_new(&virEventGLibSocketSourceFuncs,
                          sizeof(virEventGLibSocketSource));
    ssource = (virEventGLibSocketSource *)source;

    ssource->condition = condition;
    ssource->fd = fd;
    ssource->socket = _get_osfhandle(fd);
    ssource->event = CreateEvent(NULL, FALSE, FALSE, NULL);
    ssource->revents = 0;

    ssource->pollfd.fd = (gintptr)ssource->event;
    ssource->pollfd.events = G_IO_IN;

    WSAEventSelect(ssource->socket, ssource->event,
                   FD_READ | FD_ACCEPT | FD_CLOSE |
                   FD_CONNECT | FD_WRITE | FD_OOB);

    g_source_add_poll(source, &ssource->pollfd);

    return source;
}

#endif /* WIN32 */


GSource *
virEventGLibAddSocketWatch(int fd,
                           GIOCondition condition,
                           GMainContext *context,
                           virEventGLibSocketFunc func,
                           gpointer opaque,
                           GDestroyNotify notify)
{
    GSource *source = NULL;

    source = virEventGLibCreateSocketWatch(fd, condition);
    g_source_set_callback(source, (GSourceFunc)func, opaque, notify);

    g_source_attach(source, context);

    return source;
}
