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

/**
 * Adapted (to pass syntax check) from 'g_string_replace' from
 * glib-2.83.3. Drop once minimum glib is bumped to 2.68.
 *
 * g_string_replace:
 * @string: a #GString
 * @find: the string to find in @string
 * @replace: the string to insert in place of @find
 * @limit: the maximum instances of @find to replace with @replace, or `0` for
 * no limit
 *
 * Replaces the string @find with the string @replace in a #GString up to
 * @limit times. If the number of instances of @find in the #GString is
 * less than @limit, all instances are replaced. If @limit is `0`,
 * all instances of @find are replaced.
 *
 * If @find is the empty string, since versions 2.69.1 and 2.68.4 the
 * replacement will be inserted no more than once per possible position
 * (beginning of string, end of string and between characters). This did
 * not work correctly in earlier versions.
 *
 * Returns: the number of find and replace operations performed.
 *
 * Since: 2.68
 */
guint
vir_g_string_replace(GString *string,
                     const gchar *find,
                     const gchar *replace,
                     guint limit)
{
    GString *new_string = NULL;
    gsize f_len, r_len, new_len;
    gchar *cur, *next, *first, *dst;
    guint n;

    g_return_val_if_fail(string != NULL, 0);
    g_return_val_if_fail(find != NULL, 0);
    g_return_val_if_fail(replace != NULL, 0);

    first = strstr(string->str, find);

    if (first == NULL)
        return 0;

    new_len = string->len;
    f_len = strlen(find);
    r_len = strlen(replace);

    /* It removes a lot of branches and possibility for infinite loops if we
     * handle the case of an empty @find string separately. */
    if (G_UNLIKELY(f_len == 0)) {
        size_t i;
        if (limit == 0 || limit > string->len) {
            if (string->len > G_MAXSIZE - 1)
                g_error("inserting in every position in string would overflow");

            limit = string->len + 1;
        }

        if (r_len > 0 &&
            (limit > G_MAXSIZE / r_len ||
             limit * r_len > G_MAXSIZE - string->len))
            g_error("inserting in every position in string would overflow");

        new_len = string->len + limit * r_len;
        new_string = g_string_sized_new(new_len);
        for (i = 0; i < limit; i++) {
            g_string_append_len(new_string, replace, r_len);
            if (i < string->len)
                g_string_append_c(new_string, string->str[i]);
        }
        if (limit < string->len)
            g_string_append_len(new_string, string->str + limit, string->len - limit);

        g_free(string->str);
        string->allocated_len = new_string->allocated_len;
        string->len = new_string->len;
        string->str = g_string_free(g_steal_pointer(&new_string), FALSE);

        return limit;
    }
    /* Potentially do two passes: the first to calculate the length of the new string,
     * new_len, if it’s going to be longer than the original string; and the second to
     * do the replacements. The first pass is skipped if the new string is going to be
     * no longer than the original.
     *
     * The second pass calls various g_string_insert_len() (and similar) methods
     * which would normally potentially reallocate string->str, and hence
     * invalidate the cur/next/first/dst pointers. Because we’ve pre-calculated
     * the new_len and do all the string manipulations on new_string, that
     * shouldn’t happen. This means we scan `string` while modifying
     * `new_string`. */
    do {
        dst = first;
        cur = first;
        n = 0;
        while ((next = strstr(cur, find)) != NULL) {
            n++;

            if (r_len <= f_len) {
                memmove(dst, cur, next - cur);
                dst += next - cur;
                memcpy(dst, replace, r_len);
                dst += r_len;
            } else {
                if (new_string == NULL) {
                    new_len += r_len - f_len;
                } else {
                    g_string_append_len(new_string, cur, next - cur);
                    g_string_append_len(new_string, replace, r_len);
                }
            }
            cur = next + f_len;

            if (n == limit)
                break;
        }

        /* Append the trailing characters from after the final instance of @find
         * in the input string. */
        if (r_len <= f_len) {
            /* First pass skipped. */
            gchar *end = string->str + string->len;
            memmove(dst, cur, end - cur);
            end = dst + (end - cur);
            *end = 0;
            string->len = end - string->str;
            break;
        } else {
            if (new_string == NULL) {
                /* First pass. */
                new_string = g_string_sized_new(new_len);
                g_string_append_len(new_string, string->str, first - string->str);
            } else {
                /* Second pass. */
                g_string_append_len(new_string, cur, (string->str + string->len) - cur);
                g_free(string->str);
                string->allocated_len = new_string->allocated_len;
                string->len = new_string->len;
                string->str = g_string_free(g_steal_pointer(&new_string), FALSE);
                break;
            }
        }
    } while (1);

    return n;
}
