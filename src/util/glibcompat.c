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
