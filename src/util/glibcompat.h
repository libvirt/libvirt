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

#pragma once

#include <glib.h>
#include <glib/gstdio.h>
#include <glib-object.h>

#if !GLIB_CHECK_VERSION(2, 67, 0)

/*
 * ...meanwhile GCC >= 11 has started issuing warnings about volatile
 * from the old G_DEFINE_TYPE macro impl. IOW the new macros impls fixed
 * new GCC, but broke CLang
 */
# if !defined(__clang__) && __GNUC_PREREQ (11, 0)
#  undef _G_DEFINE_TYPE_EXTENDED_BEGIN

#  define _G_DEFINE_TYPE_EXTENDED_BEGIN(TypeName, type_name, TYPE_PARENT, flags) \
    _Pragma("GCC diagnostic push") \
    _Pragma("GCC diagnostic ignored \"-Wincompatible-pointer-types\"") \
    _G_DEFINE_TYPE_EXTENDED_BEGIN_PRE(TypeName, type_name, TYPE_PARENT) \
    _G_DEFINE_TYPE_EXTENDED_BEGIN_REGISTER(TypeName, type_name, TYPE_PARENT, flags) \
    _Pragma("GCC diagnostic pop")
# endif /* !clang && GCC >= 11.0 */

#endif /* GLib < 2.67.0 */

/* Drop once we require glib-2.68 at minimum */
guint
vir_g_string_replace(GString *string,
                     const gchar *find,
                     const gchar *replace,
                     guint limit);
#undef g_string_replace
#define g_string_replace vir_g_string_replace

#if !GLIB_CHECK_VERSION(2, 73, 2)
# if (defined(__has_attribute) && __has_attribute(__noinline__)) || G_GNUC_CHECK_VERSION (2, 96)
#  if defined (__cplusplus) && __cplusplus >= 201103L
    /* Use ISO C++11 syntax when the compiler supports it. */
#   define G_NO_INLINE [[gnu::noinline]]
#  else
#   define G_NO_INLINE __attribute__ ((__noinline__))
#  endif
# elif defined (_MSC_VER) && (1200 <= _MSC_VER)
   /* Use MSVC specific syntax.  */
#  if defined (__cplusplus) && __cplusplus >= 201103L
    /* Use ISO C++11 syntax when the compiler supports it. */
#   define G_NO_INLINE [[msvc::noinline]]
#  else
#   define G_NO_INLINE __declspec (noinline)
#  endif
# else
#  define G_NO_INLINE /* empty */
# endif
#endif /* GLIB_CHECK_VERSION(2, 73, 0) */
