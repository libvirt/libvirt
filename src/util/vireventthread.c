/*
 * vireventthread.c: thread running a dedicated GMainLoop
 *
 * Copyright (C) 2020 Red Hat, Inc.
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

#include "vireventthread.h"
#include "virthread.h"
#include "virerror.h"

struct _virEventThread {
    GObject parent;

    GThread *thread;
    GMainContext *context;
    GMainLoop *loop;
};

G_DEFINE_TYPE(virEventThread, vir_event_thread, G_TYPE_OBJECT)

#define VIR_FROM_THIS VIR_FROM_EVENT

static void
vir_event_thread_finalize(GObject *object)
{
    virEventThread *evt = VIR_EVENT_THREAD(object);

    if (evt->thread) {
        g_main_loop_quit(evt->loop);
        g_thread_join(evt->thread);
    }

    g_main_loop_unref(evt->loop);
    g_main_context_unref(evt->context);

    G_OBJECT_CLASS(vir_event_thread_parent_class)->finalize(object);
}


static void
vir_event_thread_init(virEventThread *evt)
{
    evt->context = g_main_context_new();
    evt->loop = g_main_loop_new(evt->context, FALSE);
}


static void
vir_event_thread_class_init(virEventThreadClass *klass)
{
    GObjectClass *obj = G_OBJECT_CLASS(klass);

    obj->finalize = vir_event_thread_finalize;
}


typedef struct {
    GCond cond;
    GMutex lock;
    bool running;

    GMainContext *context;
    GMainLoop *loop;
} virEventThreadData;


static void
virEventThreadDataFree(virEventThreadData *data)
{
    g_main_loop_unref(data->loop);
    g_main_context_unref(data->context);

    g_mutex_clear(&data->lock);
    g_cond_clear(&data->cond);

    g_free(data);
}


static gboolean
virEventThreadNotify(void *opaque)
{
    virEventThreadData *data = opaque;

    g_mutex_lock(&data->lock);
    data->running = TRUE;
    g_mutex_unlock(&data->lock);
    g_cond_signal(&data->cond);

    return G_SOURCE_REMOVE;
}


static void *
virEventThreadWorker(void *opaque)
{
    virEventThreadData *data = opaque;
    /*
     * Do NOT use g_autoptr on this. We need to unref it
     * before the GMainContext is unrefed
     */
    GSource *running = g_idle_source_new();

    g_source_set_callback(running, virEventThreadNotify, data, NULL);

    g_source_attach(running, data->context);

    g_main_loop_run(data->loop);

    g_source_unref(running);
    virEventThreadDataFree(data);

    return NULL;
}


static int
virEventThreadStart(virEventThread *evt, const char *name)
{
    g_autoptr(GError) gerr = NULL;
    g_autofree char *thname = NULL;
    size_t maxname = virThreadMaxName();
    virEventThreadData *data;

    if (maxname)
        thname = g_strndup(name, maxname);
    else
        thname = g_strdup(name);

    if (evt->thread) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Event thread is already running"));
        return -1;
    }

    data = g_new0(virEventThreadData, 1);
    data->loop = g_main_loop_ref(evt->loop);
    data->context = g_main_context_ref(evt->context);
    g_mutex_init(&data->lock);
    g_cond_init(&data->cond);

    evt->thread = g_thread_try_new(thname,
                                   virEventThreadWorker,
                                   data,
                                   &gerr);
    if (!evt->thread) {
        virEventThreadDataFree(data);
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to start event thread: %1$s"),
                       gerr->message);
        return -1;
    }

    g_mutex_lock(&data->lock);
    while (!data->running)
        g_cond_wait(&data->cond, &data->lock);
    g_mutex_unlock(&data->lock);

    return 0;
}


virEventThread *
virEventThreadNew(const char *name)
{
    g_autoptr(virEventThread) evt = VIR_EVENT_THREAD(g_object_new(VIR_TYPE_EVENT_THREAD, NULL));

    if (virEventThreadStart(evt, name) < 0)
        return NULL;

    return g_steal_pointer(&evt);
}


GMainContext *
virEventThreadGetContext(virEventThread *evt)
{
    return evt->context;
}
