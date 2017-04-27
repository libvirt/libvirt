/*
 * virnetservermdns.c: advertise server sockets
 *
 * Copyright (C) 2011-2012 Red Hat, Inc.
 * Copyright (C) 2007 Daniel P. Berrange
 *
 * Derived from Avahi example service provider code.
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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#if WITH_AVAHI
# include <avahi-client/client.h>
# include <avahi-client/publish.h>

# include <avahi-common/alternative.h>
# include <avahi-common/simple-watch.h>
# include <avahi-common/malloc.h>
# include <avahi-common/error.h>
# include <avahi-common/timeval.h>
#endif

#include "virnetservermdns.h"
#include "vireventpoll.h"
#include "viralloc.h"
#include "virerror.h"
#include "virlog.h"
#include "virstring.h"

#define VIR_FROM_THIS VIR_FROM_RPC

VIR_LOG_INIT("rpc.netservermdns");

struct _virNetServerMDNSEntry {
    char *type;
    int port;
    virNetServerMDNSEntryPtr next;
};

struct _virNetServerMDNSGroup {
    virNetServerMDNSPtr mdns;
#if WITH_AVAHI
    AvahiEntryGroup *handle;
#endif
    char *name;
    virNetServerMDNSEntryPtr entry;
    virNetServerMDNSGroupPtr next;
};

struct _virNetServerMDNS {
#if WITH_AVAHI
    AvahiClient *client;
    AvahiPoll *poller;
#endif
    virNetServerMDNSGroupPtr group;
};

#if WITH_AVAHI
/* Avahi API requires this struct name in the app :-( */
struct AvahiWatch {
    int watch;
    int fd;
    int revents;
    AvahiWatchCallback callback;
    void *userdata;
};

/* Avahi API requires this struct name in the app :-( */
struct AvahiTimeout {
    int timer;
    AvahiTimeoutCallback callback;
    void  *userdata;
};

static void virNetServerMDNSCreateServices(virNetServerMDNSGroupPtr group);

/* Called whenever the entry group state changes */
static void virNetServerMDNSGroupCallback(AvahiEntryGroup *g ATTRIBUTE_UNUSED,
                                          AvahiEntryGroupState state,
                                          void *data)
{
    virNetServerMDNSGroupPtr group = data;

    switch (state) {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        /* The entry group has been established successfully */
        VIR_DEBUG("Group '%s' established", group->name);
        break;

    case AVAHI_ENTRY_GROUP_COLLISION:
        {
            char *n;

            /* A service name collision happened. Let's pick a new name */
            n = avahi_alternative_service_name(group->name);
            VIR_FREE(group->name);
            group->name = n;

            VIR_DEBUG("Group name collision, renaming service to '%s'", group->name);

            /* And recreate the services */
            virNetServerMDNSCreateServices(group);
        }
        break;

    case AVAHI_ENTRY_GROUP_FAILURE :
        VIR_DEBUG("Group failure: %s",
                  avahi_strerror(avahi_client_errno(group->mdns->client)));

        /* Some kind of failure happened while we were registering our services */
        /* avahi_simple_poll_quit(simple_poll); */
        break;

    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:
        ;
    }
}

static void virNetServerMDNSCreateServices(virNetServerMDNSGroupPtr group)
{
    virNetServerMDNSPtr mdns = group->mdns;
    virNetServerMDNSEntryPtr entry;
    int ret;
    VIR_DEBUG("Adding services to '%s'", group->name);

    /* If we've no services to advertise, just reset the group to make
     * sure it is emptied of any previously advertised services */
    if (!group->entry) {
        if (group->handle)
            avahi_entry_group_reset(group->handle);
        return;
    }

    /* If this is the first time we're called, let's create a new entry group */
    if (!group->handle) {
        VIR_DEBUG("Creating initial group %s", group->name);
        if (!(group->handle =
              avahi_entry_group_new(mdns->client,
                                    virNetServerMDNSGroupCallback,
                                    group))) {
            VIR_DEBUG("avahi_entry_group_new() failed: %s",
                      avahi_strerror(avahi_client_errno(mdns->client)));
            return;
        }
    }

    entry = group->entry;
    while (entry) {
        if ((ret = avahi_entry_group_add_service(group->handle,
                                                 AVAHI_IF_UNSPEC,
                                                 AVAHI_PROTO_UNSPEC,
                                                 0,
                                                 group->name,
                                                 entry->type,
                                                 NULL,
                                                 NULL,
                                                 entry->port,
                                                 NULL)) < 0) {
            VIR_DEBUG("Failed to add %s service on port %d: %s",
                      entry->type, entry->port, avahi_strerror(ret));
            avahi_entry_group_reset(group->handle);
            return;
        }
        entry = entry->next;
    }

    /* Tell the server to register the service */
    if ((ret = avahi_entry_group_commit(group->handle)) < 0) {
        avahi_entry_group_reset(group->handle);
        VIR_DEBUG("Failed to commit entry_group: %s",
                  avahi_strerror(ret));
        return;
    }
}


static void virNetServerMDNSClientCallback(AvahiClient *c,
                                           AvahiClientState state,
                                           void *data)
{
    virNetServerMDNSPtr mdns = data;
    virNetServerMDNSGroupPtr group;
    if (!mdns->client)
        mdns->client = c;

    VIR_DEBUG("Callback state=%d", state);

    /* Called whenever the client or server state changes */
    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
            VIR_DEBUG("Client running %p", mdns->client);
            group = mdns->group;
            while (group) {
                virNetServerMDNSCreateServices(group);
                group = group->next;
            }
            break;

        case AVAHI_CLIENT_FAILURE:
            VIR_DEBUG("Client failure: %s",
                      avahi_strerror(avahi_client_errno(c)));
            virNetServerMDNSStop(mdns);
            virNetServerMDNSStart(mdns);
            break;

        case AVAHI_CLIENT_S_COLLISION:
            /* Let's drop our registered services. When the server is back
             * in AVAHI_SERVER_RUNNING state we will register them
             * again with the new host name. */

            /* Fallthrough */

        case AVAHI_CLIENT_S_REGISTERING:
            /* The server records are now being established. This
             * might be caused by a host name change. We need to wait
             * for our own records to register until the host name is
             * properly established. */
            VIR_DEBUG("Client collision/connecting %p", mdns->client);
            group = mdns->group;
            while (group) {
                if (group->handle)
                    avahi_entry_group_reset(group->handle);
                group = group->next;
            }
            break;

        case AVAHI_CLIENT_CONNECTING:
            VIR_DEBUG("Client connecting.... %p", mdns->client);
            ;
    }
}


static void virNetServerMDNSWatchDispatch(int watch, int fd, int events, void *opaque)
{
    AvahiWatch *w = opaque;
    int fd_events = virEventPollToNativeEvents(events);
    VIR_DEBUG("Dispatch watch %d FD %d Event %d", watch, fd, fd_events);
    w->revents = fd_events;
    w->callback(w, fd, fd_events, w->userdata);
}

static void virNetServerMDNSWatchDofree(void *w)
{
    VIR_FREE(w);
}


static AvahiWatch *virNetServerMDNSWatchNew(const AvahiPoll *api ATTRIBUTE_UNUSED,
                                            int fd, AvahiWatchEvent event,
                                            AvahiWatchCallback cb, void *userdata)
{
    AvahiWatch *w;
    virEventHandleType hEvents;
    if (VIR_ALLOC(w) < 0)
        return NULL;

    w->fd = fd;
    w->revents = 0;
    w->callback = cb;
    w->userdata = userdata;

    VIR_DEBUG("New handle %p FD %d Event %d", w, w->fd, event);
    hEvents = virEventPollFromNativeEvents(event);
    if ((w->watch = virEventAddHandle(fd, hEvents,
                                      virNetServerMDNSWatchDispatch,
                                      w,
                                      virNetServerMDNSWatchDofree)) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to add watch for fd %d events %d"), fd, hEvents);
        VIR_FREE(w);
        return NULL;
    }

    return w;
}

static void virNetServerMDNSWatchUpdate(AvahiWatch *w, AvahiWatchEvent event)
{
    VIR_DEBUG("Update handle %p FD %d Event %d", w, w->fd, event);
    virEventUpdateHandle(w->watch, event);
}

static AvahiWatchEvent virNetServerMDNSWatchGetEvents(AvahiWatch *w)
{
    VIR_DEBUG("Get handle events %p %d", w, w->fd);
    return w->revents;
}

static void virNetServerMDNSWatchFree(AvahiWatch *w)
{
    VIR_DEBUG("Free handle %p %d", w, w->fd);
    virEventRemoveHandle(w->watch);
}

static void virNetServerMDNSTimeoutDispatch(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    AvahiTimeout *t = (AvahiTimeout*)opaque;
    VIR_DEBUG("Dispatch timeout %p %d", t, timer);
    virEventUpdateTimeout(t->timer, -1);
    t->callback(t, t->userdata);
}

static void virNetServerMDNSTimeoutDofree(void *t)
{
    VIR_FREE(t);
}

static AvahiTimeout *virNetServerMDNSTimeoutNew(const AvahiPoll *api ATTRIBUTE_UNUSED,
                                                const struct timeval *tv,
                                                AvahiTimeoutCallback cb,
                                                void *userdata)
{
    AvahiTimeout *t;
    struct timeval now;
    long long nowms, thenms, timeout;
    VIR_DEBUG("Add timeout TV %p", tv);
    if (VIR_ALLOC(t) < 0)
        return NULL;

    if (gettimeofday(&now, NULL) < 0) {
        virReportSystemError(errno, "%s",
                             _("Unable to get current time"));
        VIR_FREE(t);
        return NULL;
    }

    VIR_DEBUG("Trigger timed for %d %d      %d %d",
               (int)now.tv_sec, (int)now.tv_usec,
               (int)(tv ? tv->tv_sec : 0), (int)(tv ? tv->tv_usec : 0));
    nowms = (now.tv_sec * 1000ll) + (now.tv_usec / 1000ll);
    if (tv) {
        thenms = (tv->tv_sec * 1000ll) + (tv->tv_usec/1000ll);
        timeout = thenms > nowms ? nowms - thenms : 0;
        if (timeout < 0)
            timeout = 0;
    } else {
        timeout = -1;
    }

    t->timer = virEventAddTimeout(timeout,
                                  virNetServerMDNSTimeoutDispatch,
                                  t,
                                  virNetServerMDNSTimeoutDofree);
    t->callback = cb;
    t->userdata = userdata;

    if (t->timer < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to add timer with timeout %lld"), timeout);
        VIR_FREE(t);
        return NULL;
    }

    return t;
}

static void virNetServerMDNSTimeoutUpdate(AvahiTimeout *t, const struct timeval *tv)
{
    struct timeval now;
    long long nowms, thenms, timeout;
    VIR_DEBUG("Update timeout %p TV %p", t, tv);
    if (gettimeofday(&now, NULL) < 0) {
        VIR_FREE(t);
        return;
    }

    nowms = (now.tv_sec * 1000ll) + (now.tv_usec / 1000ll);
    if (tv) {
        thenms = ((tv->tv_sec * 1000ll) + (tv->tv_usec/1000ll));
        timeout = thenms > nowms ? nowms - thenms : 0;
        if (timeout < 0)
            timeout = 0;
    } else {
        timeout = -1;
    }

    virEventUpdateTimeout(t->timer, timeout);
}

static void virNetServerMDNSTimeoutFree(AvahiTimeout *t)
{
    VIR_DEBUG("Free timeout %p", t);
    virEventRemoveTimeout(t->timer);
}


static AvahiPoll *virNetServerMDNSCreatePoll(void)
{
    AvahiPoll *p;
    if (VIR_ALLOC(p) < 0)
        return NULL;

    p->userdata = NULL;

    p->watch_new = virNetServerMDNSWatchNew;
    p->watch_update = virNetServerMDNSWatchUpdate;
    p->watch_get_events = virNetServerMDNSWatchGetEvents;
    p->watch_free = virNetServerMDNSWatchFree;

    p->timeout_new = virNetServerMDNSTimeoutNew;
    p->timeout_update = virNetServerMDNSTimeoutUpdate;
    p->timeout_free = virNetServerMDNSTimeoutFree;

    return p;
}


virNetServerMDNS *virNetServerMDNSNew(void)
{
    virNetServerMDNS *mdns;
    if (VIR_ALLOC(mdns) < 0)
        return NULL;

    /* Allocate main loop object */
    if (!(mdns->poller = virNetServerMDNSCreatePoll())) {
        VIR_FREE(mdns);
        return NULL;
    }

    return mdns;
}


int virNetServerMDNSStart(virNetServerMDNS *mdns)
{
    int error;
    VIR_DEBUG("Starting client %p", mdns);
    mdns->client = avahi_client_new(mdns->poller,
                                    AVAHI_CLIENT_NO_FAIL,
                                    virNetServerMDNSClientCallback,
                                    mdns, &error);

    if (!mdns->client) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to create mDNS client: %s"),
                       avahi_strerror(error));
        return -1;
    }

    return 0;
}


virNetServerMDNSGroupPtr virNetServerMDNSAddGroup(virNetServerMDNS *mdns,
                                                  const char *name)
{
    virNetServerMDNSGroupPtr group;

    VIR_DEBUG("Adding group '%s'", name);
    if (VIR_ALLOC(group) < 0)
        return NULL;

    if (VIR_STRDUP(group->name, name) < 0) {
        VIR_FREE(group);
        return NULL;
    }
    group->mdns = mdns;
    group->next = mdns->group;
    mdns->group = group;
    return group;
}


void virNetServerMDNSRemoveGroup(virNetServerMDNSPtr mdns,
                                 virNetServerMDNSGroupPtr group)
{
    virNetServerMDNSGroupPtr tmp = mdns->group, prev = NULL;

    while (tmp) {
        if (tmp == group) {
            VIR_FREE(group->name);
            if (prev)
                prev->next = group->next;
            else
                group->mdns->group = group->next;
            VIR_FREE(group);
            return;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}


virNetServerMDNSEntryPtr virNetServerMDNSAddEntry(virNetServerMDNSGroupPtr group,
                                                  const char *type,
                                                  int port)
{
    virNetServerMDNSEntryPtr entry;

    VIR_DEBUG("Adding entry %s %d to group %s", type, port, group->name);
    if (VIR_ALLOC(entry) < 0)
        return NULL;

    entry->port = port;
    if (VIR_STRDUP(entry->type, type) < 0) {
        VIR_FREE(entry);
        return NULL;
    }
    entry->next = group->entry;
    group->entry = entry;
    return entry;
}


void virNetServerMDNSRemoveEntry(virNetServerMDNSGroupPtr group,
                                 virNetServerMDNSEntryPtr entry)
{
    virNetServerMDNSEntryPtr tmp = group->entry, prev = NULL;

    while (tmp) {
        if (tmp == entry) {
            VIR_FREE(entry->type);
            if (prev)
                prev->next = entry->next;
            else
                group->entry = entry->next;
            return;
        }
        prev = tmp;
        tmp = tmp->next;
    }
}


void virNetServerMDNSStop(virNetServerMDNSPtr mdns)
{
    virNetServerMDNSGroupPtr group = mdns->group;
    while (group) {
        if (group->handle) {
            avahi_entry_group_free(group->handle);
            group->handle = NULL;
        }
        group = group->next;
    }
    if (mdns->client)
        avahi_client_free(mdns->client);
    mdns->client = NULL;
}


void virNetServerMDNSFree(virNetServerMDNSPtr mdns)
{
    virNetServerMDNSGroupPtr group, tmp;

    if (!mdns)
        return;

    group = mdns->group;
    while (group) {
        tmp = group->next;
        virNetServerMDNSGroupFree(group);
        group = tmp;
    }

    VIR_FREE(mdns->poller);
    VIR_FREE(mdns);
}


void virNetServerMDNSGroupFree(virNetServerMDNSGroupPtr grp)
{
    virNetServerMDNSEntryPtr entry, tmp;

    if (!grp)
        return;

    entry = grp->entry;
    while (entry) {
        tmp = entry->next;
        virNetServerMDNSEntryFree(entry);
        entry = tmp;
    }

    VIR_FREE(grp->name);
    VIR_FREE(grp);
}


void virNetServerMDNSEntryFree(virNetServerMDNSEntryPtr entry)
{
    if (!entry)
        return;

    VIR_FREE(entry->type);
    VIR_FREE(entry);
}

#else /* ! WITH_AVAHI */

static const char *unsupported = N_("avahi not available at build time");

virNetServerMDNS *
virNetServerMDNSNew(void)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}

int
virNetServerMDNSStart(virNetServerMDNS *mdns ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

virNetServerMDNSGroupPtr
virNetServerMDNSAddGroup(virNetServerMDNS *mdns ATTRIBUTE_UNUSED,
                         const char *name ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}

void
virNetServerMDNSRemoveGroup(virNetServerMDNSPtr mdns ATTRIBUTE_UNUSED,
                            virNetServerMDNSGroupPtr group ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

virNetServerMDNSEntryPtr
virNetServerMDNSAddEntry(virNetServerMDNSGroupPtr group ATTRIBUTE_UNUSED,
                         const char *type ATTRIBUTE_UNUSED,
                         int port ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}

void
virNetServerMDNSRemoveEntry(virNetServerMDNSGroupPtr group ATTRIBUTE_UNUSED,
                            virNetServerMDNSEntryPtr entry ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

void
virNetServerMDNSStop(virNetServerMDNSPtr mdns ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

void
virNetServerMDNSFree(virNetServerMDNSPtr mdns ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

void
virNetServerMDNSGroupFree(virNetServerMDNSGroupPtr grp ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

void
virNetServerMDNSEntryFree(virNetServerMDNSEntryPtr entry ATTRIBUTE_UNUSED)
{
    VIR_DEBUG("%s", _(unsupported));
}

#endif /* ! WITH_AVAHI */
