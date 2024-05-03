/*
 * Copyright (C) 2019 Red Hat, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "glibcompat.h"

/*
 * Note that because of the GLIB_VERSION_MAX_ALLOWED constant in
 * config-post.h, allowing use of functions from newer GLib via
 * this compat impl needs a little trickery to prevent warnings
 * being emitted.
 *
 * Consider a function from newer glib-X.Y that we want to use
 *
 *    int g_foo(const char *wibble)
 *
 * We must define a function with the same signature that does
 * what we need, but with a "vir_" prefix e.g.
 *
 * void vir_g_foo(const char *wibble)
 * {
 *     #if GLIB_CHECK_VERSION(X, Y, 0)
 *        g_foo(wibble)
 *     #else
 *        g_something_equivalent_in_older_glib(wibble);
 *     #endif
 * }
 *
 * The #pragma at the top of this file turns off -Wdeprecated-declarations,
 * ensuring this wrapper function impl doesn't trigger the compiler
 * warning about using too new glib APIs. Finally in glibcompat.h we can
 * add
 *
 *   #define g_foo(a) vir_g_foo(a)
 *
 * Thus all the code elsewhere in libvirt, which *does* have the
 * -Wdeprecated-declarations warning active, can call g_foo(...) as
 * normal, without generating warnings. The cost is an extra function
 * call when using new glib, but this compat code will go away over
 * time as we update the supported platforms target.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#undef g_fsync
#undef g_strdup_printf
#undef g_strdup_vprintf


/* Drop when min glib >= 2.63.0 */
gint
vir_g_fsync(gint fd)
{
#ifdef G_OS_WIN32
    return _commit(fd);
#else
    return fsync(fd);
#endif
}


/* Due to a bug in glib, g_strdup_printf() nor g_strdup_vprintf()
 * abort on OOM.  It's fixed in glib's upstream. Provide our own
 * implementation until the fix gets distributed. */
char *
vir_g_strdup_printf(const char *msg, ...)
{
    va_list args;
    char *ret;
    va_start(args, msg);
    ret = g_strdup_vprintf(msg, args);
    if (!ret)
        abort();
    va_end(args);
    return ret;
}


char *
vir_g_strdup_vprintf(const char *msg, va_list args)
{
    char *ret;
    ret = g_strdup_vprintf(msg, args);
    if (!ret)
        abort();
    return ret;
}


/*
 * If the last reference to a GSource is released in a non-main
 * thread we're exposed to a race condition that causes a
 * crash:
 *
 *    https://gitlab.gnome.org/GNOME/glib/-/merge_requests/1358
 *
 * Thus we're using an idle func to release our ref...
 *
 * ...but this imposes a significant performance penalty on
 * I/O intensive workloads which are sensitive to the iterations
 * of the event loop, so avoid the workaround if we know we have
 * new enough glib.
 *
 * The function below is used from a header file definition.
 *
 * Drop when min glib >= 2.64.0
 */
#if GLIB_CHECK_VERSION(2, 64, 0)
void vir_g_source_unref(GSource *src, GMainContext *ctx G_GNUC_UNUSED)
{
    g_source_unref(src);
}
#else

static gboolean
virEventGLibSourceUnrefIdle(gpointer data)
{
    GSource *src = data;

    g_source_unref(src);

    return FALSE;
}

void vir_g_source_unref(GSource *src, GMainContext *ctx)
{
    GSource *idle = g_idle_source_new();

    g_source_set_callback(idle, virEventGLibSourceUnrefIdle, src, NULL);

    g_source_attach(idle, ctx);

    g_source_unref(idle);
}

#endif
