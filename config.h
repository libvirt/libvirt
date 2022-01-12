/*
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

#include <meson-config.h>

/* Enable compile-time and run-time bounds-checking, and some warnings,
 * without upsetting newer glibc. */

#if !defined _FORTIFY_SOURCE && defined __OPTIMIZE__ && __OPTIMIZE__
# define _FORTIFY_SOURCE 2
#endif

/*
 * Define __GNUC_PREREQ to a sane default if it isn't yet defined.
 * This is done here so that it's included as early as possible;
 */
#ifndef __GNUC_PREREQ
# define __GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#endif

#if defined(__clang_major__) && defined(__clang_minor__)
# ifdef __apple_build_version__
#  if __clang_major__ < 10 || (__clang_major__ == 10 && __clang_minor__ < 0)
#   error You need at least XCode Clang v10.0 to compile libvirt
#  endif
# else
#  if __clang_major__ < 6 || (__clang_major__ == 6 && __clang_minor__ < 4)
#   error You need at least Clang v6.0 to compile libvirt
#  endif
# endif
#elif defined(__GNUC__) && defined(__GNUC_MINOR__)
# if __GNUC__ < 7 || (__GNUC__ == 7 && __GNUC_MINOR__ < 4)
#  error You need at least GCC v7.4.0 to compile libvirt
# endif
#else
# error You either need at least GCC 7.4.0 or Clang 6.0 or XCode Clang 10.0 to compile libvirt
#endif
