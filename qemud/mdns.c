/*
 * mdns.c: advertise libvirt hypervisor connections
 *
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

#include "internal.h"
#include "qemud.h"
#include "mdns.h"
#include "event.h"
#include "remote_internal.h"
#include "memory.h"

#define AVAHI_DEBUG(fmt, ...) DEBUG(fmt, __VA_ARGS__)

struct libvirtd_mdns_entry {
    char *type;
    int port;
    struct libvirtd_mdns_entry *next;
};

struct libvirtd_mdns_group {
    struct libvirtd_mdns *mdns;
    AvahiEntryGroup *handle;
    char *name;
    struct libvirtd_mdns_entry *entry;
    struct libvirtd_mdns_group *next;
};

struct libvirtd_mdns {
    AvahiClient *client;
    AvahiPoll *poller;
    struct libvirtd_mdns_group *group;
};

/* Avahi API requires this struct names in the app :-( */
struct AvahiWatch {
    int watch;
    int fd;
    int revents;
    AvahiWatchCallback callback;
    void *userdata;
};

/* Avahi API requires this struct names in the app :-( */
struct AvahiTimeout {
    int timer;
    AvahiTimeoutCallback callback;
    void  *userdata;
};


static void libvirtd_mdns_create_services(struct libvirtd_mdns_group *group);

/* Called whenever the entry group state changes */
static void libvirtd_mdns_group_callback(AvahiEntryGroup *g ATTRIBUTE_UNUSED, AvahiEntryGroupState state, void *userdata) {
    struct libvirtd_mdns_group *group = (struct libvirtd_mdns_group *)userdata;

    switch (state) {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        /* The entry group has been established successfully */
        AVAHI_DEBUG("Group '%s' established", group->name);
        break;

    case AVAHI_ENTRY_GROUP_COLLISION:
        {
            char *n;

            /* A service name collision happened. Let's pick a new name */
            n = avahi_alternative_service_name(group->name);
            VIR_FREE(group->name);
            group->name = n;

            AVAHI_DEBUG("Group name collision, renaming service to '%s'", group->name);

            /* And recreate the services */
            libvirtd_mdns_create_services(group);
        }
        break;

    case AVAHI_ENTRY_GROUP_FAILURE :
        AVAHI_DEBUG("Group failure: %s", avahi_strerror(avahi_client_errno(group->mdns->client)));

        /* Some kind of failure happened while we were registering our services */
        //avahi_simple_poll_quit(simple_poll);
        break;

    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:
        ;
    }
}

static void libvirtd_mdns_create_services(struct libvirtd_mdns_group *group) {
    struct libvirtd_mdns *mdns = group->mdns;
    struct libvirtd_mdns_entry *entry;
    int ret;
    AVAHI_DEBUG("Adding services to '%s'", group->name);

    /* If we've no services to advertise, just reset the group to make
     * sure it is emptied of any previously advertised services */
    if (!group->entry) {
        if (group->handle)
            avahi_entry_group_reset(group->handle);
        return;
    }

    /* If this is the first time we're called, let's create a new entry group */
    if (!group->handle) {
        AVAHI_DEBUG("Creating initial group %s", group->name);
        if (!(group->handle = avahi_entry_group_new(mdns->client, libvirtd_mdns_group_callback, group))) {
            AVAHI_DEBUG("avahi_entry_group_new() failed: %s", avahi_strerror(avahi_client_errno(mdns->client)));
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
            AVAHI_DEBUG("Failed to add %s service on port %d: %s",
                        entry->type, entry->port, avahi_strerror(ret));
            avahi_entry_group_reset(group->handle);
            return;
        }
        entry = entry->next;
    }

    /* Tell the server to register the service */
    if ((ret = avahi_entry_group_commit(group->handle)) < 0) {
        avahi_entry_group_reset(group->handle);
        AVAHI_DEBUG("Failed to commit entry_group: %s", avahi_strerror(ret));
        return;
    }
}


static void libvirtd_mdns_client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    struct libvirtd_mdns *mdns = (struct libvirtd_mdns *)userdata;
    struct libvirtd_mdns_group *group;
    if (!mdns->client)
        mdns->client = c;

    /* Called whenever the client or server state changes */
    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            /* The server has startup successfully and registered its host
             * name on the network, so it's time to create our services */
            AVAHI_DEBUG("Client running %p", mdns->client);
            group = mdns->group;
            while (group) {
                libvirtd_mdns_create_services(group);
                group = group->next;
            }
            break;

        case AVAHI_CLIENT_FAILURE:
            AVAHI_DEBUG("Client failure: %s", avahi_strerror(avahi_client_errno(c)));
            libvirtd_mdns_stop(mdns);
            libvirtd_mdns_start(mdns);
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
            AVAHI_DEBUG("Client collision/connecting %p", mdns->client);
            group = mdns->group;
            while (group) {
                if (group->handle)
                    avahi_entry_group_reset(group->handle);
                group = group->next;
            }
            break;

        case AVAHI_CLIENT_CONNECTING:
            AVAHI_DEBUG("Client connecting.... %p", mdns->client);
            ;
    }
}


static void libvirtd_mdns_watch_dispatch(int watch, int fd, int events, void *opaque)
{
    AvahiWatch *w = (AvahiWatch*)opaque;
    int fd_events = virEventHandleTypeToPollEvent(events);
    AVAHI_DEBUG("Dispatch watch %d FD %d Event %d", watch, fd, fd_events);
    w->revents = fd_events;
    w->callback(w, fd, fd_events, w->userdata);
}

static void libvirtd_mdns_watch_dofree(void *w)
{
    VIR_FREE(w);
}


static AvahiWatch *libvirtd_mdns_watch_new(const AvahiPoll *api ATTRIBUTE_UNUSED,
                                           int fd, AvahiWatchEvent event,
                                           AvahiWatchCallback cb, void *userdata) {
    AvahiWatch *w;
    virEventHandleType hEvents;
    if (VIR_ALLOC(w) < 0)
        return NULL;

    w->fd = fd;
    w->revents = 0;
    w->callback = cb;
    w->userdata = userdata;

    AVAHI_DEBUG("New handle %p FD %d Event %d", w, w->fd, event);
    hEvents = virPollEventToEventHandleType(event);
    if ((w->watch = virEventAddHandleImpl(fd, hEvents,
                                          libvirtd_mdns_watch_dispatch,
                                          w,
                                          libvirtd_mdns_watch_dofree)) < 0) {
        VIR_FREE(w);
        return NULL;
    }

    return w;
}

static void libvirtd_mdns_watch_update(AvahiWatch *w, AvahiWatchEvent event)
{
    AVAHI_DEBUG("Update handle %p FD %d Event %d", w, w->fd, event);
    virEventUpdateHandleImpl(w->watch, event);
}

static AvahiWatchEvent libvirtd_mdns_watch_get_events(AvahiWatch *w)
{
    AVAHI_DEBUG("Get handle events %p %d", w, w->fd);
    return w->revents;
}

static void libvirtd_mdns_watch_free(AvahiWatch *w)
{
    AVAHI_DEBUG("Free handle %p %d", w, w->fd);
    virEventRemoveHandleImpl(w->watch);
}

static void libvirtd_mdns_timeout_dispatch(int timer ATTRIBUTE_UNUSED, void *opaque)
{
    AvahiTimeout *t = (AvahiTimeout*)opaque;
    AVAHI_DEBUG("Dispatch timeout %p %d", t, timer);
    virEventUpdateTimeoutImpl(t->timer, -1);
    t->callback(t, t->userdata);
}

static void libvirtd_mdns_timeout_dofree(void *t)
{
    VIR_FREE(t);
}

static AvahiTimeout *libvirtd_mdns_timeout_new(const AvahiPoll *api ATTRIBUTE_UNUSED,
                                                const struct timeval *tv,
                                                AvahiTimeoutCallback cb,
                                                void *userdata)
{
    AvahiTimeout *t;
    struct timeval now;
    long long nowms, thenms, timeout;
    AVAHI_DEBUG("Add timeout TV %p", tv);
    if (VIR_ALLOC(t) < 0)
        return NULL;

    if (gettimeofday(&now, NULL) < 0) {
        VIR_FREE(t);
        return NULL;
    }

    AVAHI_DEBUG("Trigger timed for %d %d      %d %d",
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

    t->timer = virEventAddTimeoutImpl(timeout,
                                      libvirtd_mdns_timeout_dispatch,
                                      t,
                                      libvirtd_mdns_timeout_dofree);
    t->callback = cb;
    t->userdata = userdata;

    if (t->timer < 0) {
        VIR_FREE(t);
        return NULL;
    }

    return t;
}

static void libvirtd_mdns_timeout_update(AvahiTimeout *t, const struct timeval *tv)
{
    struct timeval now;
    long long nowms, thenms, timeout;
    AVAHI_DEBUG("Update timeout %p TV %p", t, tv);
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

    virEventUpdateTimeoutImpl(t->timer, timeout);
}

static void libvirtd_mdns_timeout_free(AvahiTimeout *t)
{
    AVAHI_DEBUG("Free timeout %p", t);
    virEventRemoveTimeoutImpl(t->timer);
}


static AvahiPoll *libvirtd_create_poll(void)
{
    AvahiPoll *p;
    if (VIR_ALLOC(p) < 0)
        return NULL;

    p->userdata = NULL;

    p->watch_new = libvirtd_mdns_watch_new;
    p->watch_update = libvirtd_mdns_watch_update;
    p->watch_get_events = libvirtd_mdns_watch_get_events;
    p->watch_free = libvirtd_mdns_watch_free;

    p->timeout_new = libvirtd_mdns_timeout_new;
    p->timeout_update = libvirtd_mdns_timeout_update;
    p->timeout_free = libvirtd_mdns_timeout_free;

    return p;
}

struct libvirtd_mdns *libvirtd_mdns_new(void)
{
    struct libvirtd_mdns *mdns;
    if (VIR_ALLOC(mdns) < 0)
        return NULL;

    /* Allocate main loop object */
    if (!(mdns->poller = libvirtd_create_poll())) {
        VIR_FREE(mdns);
        return NULL;
    }

    return mdns;
}

int libvirtd_mdns_start(struct libvirtd_mdns *mdns)
{
    int error;
    AVAHI_DEBUG("Starting client %p", mdns);
    mdns->client = avahi_client_new(mdns->poller, AVAHI_CLIENT_NO_FAIL, libvirtd_mdns_client_callback, mdns, &error);

    if (!mdns->client) {
        AVAHI_DEBUG("Failed to create mDNS client: %s", avahi_strerror(error));
        return -1;
    }

    return 0;
}

struct libvirtd_mdns_group *libvirtd_mdns_add_group(struct libvirtd_mdns *mdns, const char *name) {
    struct libvirtd_mdns_group *group;

    AVAHI_DEBUG("Adding group '%s'", name);
    if (VIR_ALLOC(group) < 0)
        return NULL;

    if (!(group->name = strdup(name))) {
        VIR_FREE(group);
        return NULL;
    }
    group->mdns = mdns;
    group->next = mdns->group;
    mdns->group = group;
    return group;
}

void libvirtd_mdns_remove_group(struct libvirtd_mdns *mdns, struct libvirtd_mdns_group *group) {
    struct libvirtd_mdns_group *tmp = mdns->group, *prev = NULL;

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

struct libvirtd_mdns_entry *libvirtd_mdns_add_entry(struct libvirtd_mdns_group *group, const char *type, int port) {
    struct libvirtd_mdns_entry *entry;

    AVAHI_DEBUG("Adding entry %s %d to group %s", type, port, group->name);
    if (VIR_ALLOC(entry) < 0)
        return NULL;

    entry->port = port;
    if (!(entry->type = strdup(type))) {
        VIR_FREE(entry);
        return NULL;
    }
    entry->next = group->entry;
    group->entry = entry;
    return entry;
}

void libvirtd_mdns_remove_entry(struct libvirtd_mdns_group *group, struct libvirtd_mdns_entry *entry) {
    struct libvirtd_mdns_entry *tmp = group->entry, *prev = NULL;

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

void libvirtd_mdns_stop(struct libvirtd_mdns *mdns)
{
    struct libvirtd_mdns_group *group = mdns->group;
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
