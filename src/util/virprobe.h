/*
 * virprobe.h: dynamic operation tracing
 *
 * Copyright (C) 2006-2014 Red Hat, Inc.
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
 *
 */

#pragma once

#include "internal.h"
#include "virlog.h"

#if WITH_DTRACE_PROBES
# ifndef LIBVIRT_PROBES_H
#  define LIBVIRT_PROBES_H
#  include "libvirt_probes.h"
# endif /* LIBVIRT_PROBES_H */

/* Systemtap 1.2 headers have a bug where they cannot handle a
 * variable declared with array type.  Work around this by casting all
 * arguments.  This is some gross use of the preprocessor because
 * PROBE is a var-arg macro, but it is better than the alternative of
 * making all callers to PROBE have to be aware of the issues.  And
 * hopefully, if we ever add a call to PROBE with other than 9
 * end arguments, you can figure out the pattern to extend this hack.
 */
# define VIR_COUNT_ARGS(...) VIR_ARG11(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
# define VIR_ARG11(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, ...) _11
# define VIR_ADD_CAST_EXPAND(a, b, ...) VIR_ADD_CAST_PASTE(a, b, __VA_ARGS__)
# define VIR_ADD_CAST_PASTE(a, b, ...) a##b(__VA_ARGS__)

/* The double cast is necessary to silence gcc warnings; any pointer
 * can safely go to intptr_t and back to void *, which collapses
 * arrays into pointers; while any integer can be widened to intptr_t
 * then cast to void *.  */
# define VIR_ADD_CAST(a) ((void *)(intptr_t)(a))
# define VIR_ADD_CAST1(a) \
    VIR_ADD_CAST(a)
# define VIR_ADD_CAST2(a, b) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b)
# define VIR_ADD_CAST3(a, b, c) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c)
# define VIR_ADD_CAST4(a, b, c, d) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d)
# define VIR_ADD_CAST5(a, b, c, d, e) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e)
# define VIR_ADD_CAST6(a, b, c, d, e, f) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f)
# define VIR_ADD_CAST7(a, b, c, d, e, f, g) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f), \
    VIR_ADD_CAST(g)
# define VIR_ADD_CAST8(a, b, c, d, e, f, g, h) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f), \
    VIR_ADD_CAST(g), VIR_ADD_CAST(h)
# define VIR_ADD_CAST9(a, b, c, d, e, f, g, h, i) \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c), \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f), \
    VIR_ADD_CAST(g), VIR_ADD_CAST(h), VIR_ADD_CAST(i)

# define VIR_ADD_CASTS(...) \
    VIR_ADD_CAST_EXPAND(VIR_ADD_CAST, VIR_COUNT_ARGS(__VA_ARGS__), \
                        __VA_ARGS__)

# define PROBE_EXPAND(NAME, ARGS) NAME(ARGS)
# define PROBE(NAME, FMT, ...) \
    VIR_INFO_INT(&virLogSelf, \
                  __FILE__, __LINE__, __func__, \
                  #NAME ": " FMT, __VA_ARGS__); \
    if (LIBVIRT_ ## NAME ## _ENABLED()) { \
        PROBE_EXPAND(LIBVIRT_ ## NAME, \
                     VIR_ADD_CASTS(__VA_ARGS__)); \
    }

# define PROBE_QUIET(NAME, FMT, ...) \
    if (LIBVIRT_ ## NAME ## _ENABLED()) { \
        PROBE_EXPAND(LIBVIRT_ ## NAME, \
                     VIR_ADD_CASTS(__VA_ARGS__)); \
    }
#else
# define PROBE(NAME, FMT, ...) \
    VIR_INFO_INT(&virLogSelf, \
                 __FILE__, __LINE__, __func__, \
                 #NAME ": " FMT, __VA_ARGS__);

# define PROBE_QUIET(NAME, FMT, ...)
#endif
