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

#ifndef __GNUC__
# error "Libvirt requires GCC >= 4.8, or CLang"
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
#  if __clang_major__ < 5 || (__clang_major__ == 5 && __clang_minor__ < 1)
#   error You need at least XCode Clang v5.1 to compile QEMU
#  endif
# else
#  if __clang_major__ < 3 || (__clang_major__ == 3 && __clang_minor__ < 4)
#   error You need at least Clang v3.4 to compile QEMU
#  endif
# endif
#elif defined(__GNUC__) && defined(__GNUC_MINOR__)
# if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 8)
#  error You need at least GCC v4.8 to compile QEMU
# endif
#else
# error You either need at least GCC 4.8 or Clang 3.4 or XCode Clang 5.1 to compile libvirt
#endif

/* Ask for warnings for anything that was marked deprecated in
 * the defined version, or before. It is a candidate for rewrite.
 */
#define GLIB_VERSION_MIN_REQUIRED GLIB_VERSION_2_48

/* Ask for warnings if code tries to use function that did not
 * exist in the defined version. These risk breaking builds
 */
#define GLIB_VERSION_MAX_ALLOWED GLIB_VERSION_2_48
