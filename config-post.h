/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifndef __GNUC__
# error "Libvirt requires GCC >= 4.8, or CLang"
#endif

/*
 * Define __GNUC_PREREQ to a sane default if it isn't yet defined.
 * This is done here so that it's included as early as possible; gnulib relies
 * on this to be defined in features.h, which should be included from ctype.h.
 * This doesn't happen on many non-glibc systems.
 * When __GNUC_PREREQ is not defined, gnulib defines it to 0, which breaks things.
 */
#ifndef __GNUC_PREREQ
# define __GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#endif

#if !(__GNUC_PREREQ(4, 8) || defined(__clang__))
# error "Libvirt requires GCC >= 4.8, or CLang"
#endif
