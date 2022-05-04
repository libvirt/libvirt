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

#undef g_canonicalize_filename
#undef g_hash_table_steal_extended
#undef g_fsync
#undef g_strdup_printf
#undef g_strdup_vprintf


gchar *
vir_g_canonicalize_filename(const gchar *filename,
                            const gchar *relative_to)
{
#if GLIB_CHECK_VERSION(2, 58, 0)
    return g_canonicalize_filename(filename, relative_to);
#else /* ! GLIB_CHECK_VERSION(2, 58, 0) */
    gchar *canon, *start, *p, *q;
    guint i;

    g_return_val_if_fail(relative_to == NULL || g_path_is_absolute(relative_to), NULL);

    if (!g_path_is_absolute(filename)) {
        gchar *cwd_allocated = NULL;
        const gchar  *cwd;

        if (relative_to != NULL)
            cwd = relative_to;
        else
            cwd = cwd_allocated = g_get_current_dir();

        canon = g_build_filename(cwd, filename, NULL);
        g_free(cwd_allocated);
    } else {
        canon = g_strdup(filename);
    }

    start = (char *)g_path_skip_root(canon);

    if (start == NULL) {
        /* This shouldn't really happen, as g_get_current_dir() should
           return an absolute pathname, but bug 573843 shows this is
           not always happening */
        g_free(canon);
        return g_build_filename(G_DIR_SEPARATOR_S, filename, NULL);
    }

    /* POSIX allows double slashes at the start to
     * mean something special (as does windows too).
     * So, "//" != "/", but more than two slashes
     * is treated as "/".
     */
    i = 0;
    for (p = start - 1;
         (p >= canon) &&
             G_IS_DIR_SEPARATOR(*p);
         p--)
        i++;
    if (i > 2) {
        i -= 1;
        start -= i;
        memmove(start, start+i, strlen(start+i) + 1);
    }

    /* Make sure we're using the canonical dir separator */
    p++;
    while (p < start && G_IS_DIR_SEPARATOR(*p))
        *p++ = G_DIR_SEPARATOR;

    p = start;
    while (*p != 0) {
        if (p[0] == '.' && (p[1] == 0 || G_IS_DIR_SEPARATOR(p[1]))) {
            memmove(p, p+1, strlen(p+1)+1);
        } else if (p[0] == '.' && p[1] == '.' &&
                   (p[2] == 0 || G_IS_DIR_SEPARATOR(p[2]))) {
            q = p + 2;
            /* Skip previous separator */
            p = p - 2;
            if (p < start)
                p = start;
            while (p > start && !G_IS_DIR_SEPARATOR(*p))
                p--;
            if (G_IS_DIR_SEPARATOR(*p))
                *p++ = G_DIR_SEPARATOR;
            memmove(p, q, strlen(q)+1);
        } else {
            /* Skip until next separator */
            while (*p != 0 && !G_IS_DIR_SEPARATOR(*p))
                p++;

            if (*p != 0) {
                /* Canonicalize one separator */
                *p++ = G_DIR_SEPARATOR;
            }
        }

        /* Remove additional separators */
        q = p;
        while (*q && G_IS_DIR_SEPARATOR(*q))
            q++;

        if (p != q)
            memmove(p, q, strlen(q) + 1);
    }

    /* Remove trailing slashes */
    if (p > start && G_IS_DIR_SEPARATOR(*(p-1)))
        *(p-1) = 0;

    return canon;
#endif /* ! GLIB_CHECK_VERSION(2, 58, 0) */
}


gboolean
vir_g_hash_table_steal_extended(GHashTable *hash_table,
                                gconstpointer lookup_key,
                                gpointer *stolen_key,
                                gpointer *stolen_value)
{
#if GLIB_CHECK_VERSION(2, 58, 0)
    return g_hash_table_steal_extended(hash_table, lookup_key, stolen_key, stolen_value);
#else /* ! GLIB_CHECK_VERSION(2, 58, 0) */
    if (!(g_hash_table_lookup_extended(hash_table, lookup_key, stolen_key, stolen_value)))
        return FALSE;

    g_hash_table_steal(hash_table, lookup_key);

    return TRUE;
#endif /* ! GLIB_CHECK_VERSION(2, 58, 0) */
}


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
