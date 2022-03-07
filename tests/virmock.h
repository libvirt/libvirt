/*
 * virmock.h: helper for mocking C functions
 *
 * Copyright (C) 2014 Red Hat, Inc.
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

#if WITH_DLFCN_H
# include <dlfcn.h>
#endif

#include "internal.h"

#define VIR_MOCK_COUNT_ARGS(...) VIR_MOCK_ARG27(__VA_ARGS__, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#define VIR_MOCK_ARG27(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, ...) _27
#define VIR_MOCK_ARG_PASTE(a, b, ...) a##b(__VA_ARGS__)

#define VIR_MOCK_ARGNAME(a, b) b
#define VIR_MOCK_ARGTYPE(a, b) a
#define VIR_MOCK_ARGTYPENAME(a, b) a b
#define VIR_MOCK_ARGTYPENAME_UNUSED(a, b) a b G_GNUC_UNUSED

#define VIR_MOCK_GET_ARG2(z, a, b) z(a, b)
#define VIR_MOCK_GET_ARG3(z, a, b, c) z(a, b)
#define VIR_MOCK_GET_ARG4(z, a, b, c, d) z(a, b),  z(c, d)
#define VIR_MOCK_GET_ARG5(z, a, b, c, d, e) z(a, b),  z(c, d)
#define VIR_MOCK_GET_ARG6(z, a, b, c, d, e, f) z(a, b),  z(c, d), z(e, f)
#define VIR_MOCK_GET_ARG7(z, a, b, c, d, e, f, g) z(a, b),  z(c, d), z(e, f)
#define VIR_MOCK_GET_ARG8(z, a, b, c, d, e, f, g, h) z(a, b),  z(c, d), z(e, f), z(g, h)
#define VIR_MOCK_GET_ARG9(z, a, b, c, d, e, f, g, h, i) z(a, b),  z(c, d), z(e, f), z(g, h)
#define VIR_MOCK_GET_ARG10(z, a, b, c, d, e, f, g, h, i, j) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j)
#define VIR_MOCK_GET_ARG11(z, a, b, c, d, e, f, g, h, i, j, k) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j)
#define VIR_MOCK_GET_ARG12(z, a, b, c, d, e, f, g, h, i, j, k, l) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l)
#define VIR_MOCK_GET_ARG13(z, a, b, c, d, e, f, g, h, i, j, k, l, m) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l)
#define VIR_MOCK_GET_ARG14(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n)
#define VIR_MOCK_GET_ARG15(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n)
#define VIR_MOCK_GET_ARG16(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p)
#define VIR_MOCK_GET_ARG17(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p)
#define VIR_MOCK_GET_ARG18(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r)
#define VIR_MOCK_GET_ARG19(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r)
#define VIR_MOCK_GET_ARG20(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t)
#define VIR_MOCK_GET_ARG21(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t)
#define VIR_MOCK_GET_ARG22(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v)
#define VIR_MOCK_GET_ARG23(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v)
#define VIR_MOCK_GET_ARG24(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v), z(w, x)
#define VIR_MOCK_GET_ARG25(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v), z(w, x)
#define VIR_MOCK_GET_ARG26(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, aa) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v), z(w, x), z(y, aa)
#define VIR_MOCK_GET_ARG27(z, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, aa, ab) z(a, b),  z(c, d), z(e, f), z(g, h), z(i, j), z(k, l), z(m, n), z(o, p), z(q, r), z(s, t), z(u, v), z(w, x), z(y, aa)


#define VIR_MOCK_ARGNAMES_EXPAND(a, b, ...) VIR_MOCK_ARG_PASTE(a, b, __VA_ARGS__)
#define VIR_MOCK_ARGNAMES(...) \
    VIR_MOCK_ARGNAMES_EXPAND(VIR_MOCK_GET_ARG, VIR_MOCK_COUNT_ARGS(__VA_ARGS__), VIR_MOCK_ARGNAME, __VA_ARGS__)

#define VIR_MOCK_ARGTYPES_EXPAND(a, b, ...) VIR_MOCK_ARG_PASTE(a, b, __VA_ARGS__)
#define VIR_MOCK_ARGTYPES(...) \
    VIR_MOCK_ARGTYPES_EXPAND(VIR_MOCK_GET_ARG, VIR_MOCK_COUNT_ARGS(__VA_ARGS__), VIR_MOCK_ARGTYPE, __VA_ARGS__)

#define VIR_MOCK_ARGTYPENAMES_EXPAND(a, b, ...) VIR_MOCK_ARG_PASTE(a, b, __VA_ARGS__)
#define VIR_MOCK_ARGTYPENAMES(...) \
    VIR_MOCK_ARGTYPENAMES_EXPAND(VIR_MOCK_GET_ARG, VIR_MOCK_COUNT_ARGS(__VA_ARGS__), VIR_MOCK_ARGTYPENAME, __VA_ARGS__)

#define VIR_MOCK_ARGTYPENAMES_UNUSED_EXPAND(a, b, ...) VIR_MOCK_ARG_PASTE(a, b, __VA_ARGS__)
#define VIR_MOCK_ARGTYPENAMES_UNUSED(...) \
    VIR_MOCK_ARGTYPENAMES_UNUSED_EXPAND(VIR_MOCK_GET_ARG, VIR_MOCK_COUNT_ARGS(__VA_ARGS__), VIR_MOCK_ARGTYPENAME_UNUSED, __VA_ARGS__)


/*
 * The VIR_MOCK_LINK_NNN_MMM() macros are intended for use in
 * LD_PRELOAD based wrappers. They provide a replacement for
 * for an existing shared library symbol export. They will
 * then lookup the same symbol name but with 'wrap_' prefixed
 * on it, and call that.
 *
 * The actual test suite should provide the implementation of
 * the wrap_XXXX symbol, using the VIR_MOCK_WRAP_NNN_MMM
 * macros.
 */


/**
 * VIR_MOCK_LINK_RET_ARGS:
 * @name: the symbol name to replace
 * @rettype: the return type
 * @...: pairs of parameter type and parameter name
 *
 * Define a replacement for @name which invokes wrap_@name
 * forwarding on all args, and passing back the return value.
 */
#define VIR_MOCK_LINK_RET_ARGS(name, rettype, ...) \
    rettype name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)) \
    { \
        static rettype (*wrap_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
        if (wrap_##name == NULL && \
            !(wrap_##name = dlsym(RTLD_DEFAULT, \
                                  "wrap_" #name))) { \
            fprintf(stderr, "Missing symbol 'wrap_" #name "'\n"); \
            abort(); \
        } \
 \
        return wrap_##name(VIR_MOCK_ARGNAMES(__VA_ARGS__)); \
    }

/**
 * VIR_MOCK_LINK_RET_VOID:
 * @name: the symbol name to replace
 * @rettype: the return type
 *
 * Define a replacement for @name which invokes wrap_@name
 * with no arguments, and passing back the return value.
 */
#define VIR_MOCK_LINK_RET_VOID(name, rettype) \
    rettype name(void) \
    { \
        static rettype (*wrap_##name)(void); \
        if (wrap_##name == NULL && \
            !(wrap_##name = dlsym(RTLD_DEFAULT, \
                                  "wrap_" #name))) { \
            fprintf(stderr, "Missing symbol 'wrap_" #name "'\n"); \
            abort(); \
        } \
 \
        return wrap_##name(); \
    }

/**
 * VIR_MOCK_LINK_VOID_ARGS:
 * @name: the symbol name to replace
 * @...: pairs of parameter type and parameter name
 *
 * Define a replacement for @name which invokes wrap_@name
 * forwarding on all args, but with no return value.
 */
#define VIR_MOCK_LINK_VOID_ARGS(name, ...) \
    void name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)) \
    { \
        static void (*wrap_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
        if (wrap_##name == NULL && \
            !(wrap_##name = dlsym(RTLD_DEFAULT, \
                                  "wrap_" #name))) { \
            fprintf(stderr, "Missing symbol 'wrap_" #name "'\n"); \
            abort(); \
        } \
 \
        wrap_##name(VIR_MOCK_ARGNAMES(__VA_ARGS__)); \
    }



/*
 * The VIR_MOCK_STUB_NNN_MMM() macros are intended for use in
 * LD_PRELOAD based wrappers. They provide a replacement for
 * for an existing shared library symbol export. They will
 * be a pure no-op, optionally returning a dummy value.
 */


/**
 * VIR_MOCK_STUB_RET_ARGS:
 * @name: the symbol name to replace
 * @rettype: the return type
 * @retval: the return value
 * @...: pairs of parameter type and parameter name
 *
 * Define a replacement for @name which doesn't invoke anything, just
 * returns @retval.
 */
#define VIR_MOCK_STUB_RET_ARGS(name, rettype, retval, ...) \
    rettype name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__)) \
    { \
        return retval; \
    }

/**
 * VIR_MOCK_STUB_RET_VOID:
 * @name: the symbol name to replace
 * @rettype: the return type
 * @retval: value to return
 *
 * Define a replacement for @name which doesn't invoke anything, just
 * returns @retval.
 */
#define VIR_MOCK_STUB_RET_VOID(name, rettype, retval) \
    rettype name(void) \
    { \
        return retval; \
    }

/**
 * VIR_MOCK_STUB_VOID_ARGS:
 * @name: the symbol name to replace
 * @...: pairs of parameter type and parameter name
 *
 * Define a replacement for @name which doesn't invoke or return
 * anything.
 */
#define VIR_MOCK_STUB_VOID_ARGS(name, ...) \
    void name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__)) \
    { \
    }



/**
 * VIR_MOCK_STUB_VOID_VOID:
 * @name: the symbol name to replace
 *
 * Define a replacement for @name which doesn't invoke or return
 * anything.
 */
#define VIR_MOCK_STUB_VOID_VOID(name) \
    void name(void) \
    { \
    }


/*
 * The VIR_MOCK_IMPL_NNN_MMM() macros are intended for use in the
 * individual test suites. The define a stub implementation of
 * the wrapped method and insert the caller provided code snippet
 * as the body of the method.
 */

#define VIR_MOCK_IMPL_RET_ARGS(name, rettype, ...) \
    rettype name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)); \
    static rettype (*real_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
    rettype name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__))

#define VIR_MOCK_IMPL_RET_VOID(name, rettype) \
    rettype name(void); \
    static rettype (*real_##name)(void); \
    rettype name(void)

#define VIR_MOCK_IMPL_VOID_ARGS(name, ...) \
    void name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)); \
    static void (*real_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
    void name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__))

#define VIR_MOCK_IMPL_VOID_VOID(name) \
    void name(void); \
    static void (*real_##name)(void); \
    void name(void)

/*
 * The VIR_MOCK_WRAP_NNN_MMM() macros are intended for use in the
 * individual test suites. The define a stub implementation of
 * the wrapped method and insert the caller provided code snippet
 * as the body of the method.
 */

#define VIR_MOCK_WRAP_RET_ARGS(name, rettype, ...) \
    rettype wrap_##name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)); \
    static rettype (*real_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
    rettype wrap_##name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__))

#define VIR_MOCK_WRAP_RET_VOID(name, rettype) \
    rettype wrap_##name(void); \
    static rettype (*real_##name)(void); \
    rettype wrap_##name(void)

#define VIR_MOCK_WRAP_VOID_ARGS(name, ...) \
    void wrap_##name(VIR_MOCK_ARGTYPENAMES(__VA_ARGS__)); \
    static void (*real_##name)(VIR_MOCK_ARGTYPES(__VA_ARGS__)); \
    void wrap_##name(VIR_MOCK_ARGTYPENAMES_UNUSED(__VA_ARGS__))

#define VIR_MOCK_WRAP_VOID_VOID(name) \
    void wrap_##name(void); \
    static void (*real_##name)(void); \
    void wrap_##name(void)

#if defined(VIR_MOCK_LOOKUP_MAIN) && defined(__APPLE__)
# define VIR_MOCK_REAL_INIT_MAIN(name, alias) \
    do { \
        if (real_##name == NULL) { \
            real_##name = dlsym(RTLD_MAIN_ONLY, alias); \
        } \
    } while (0)
#else
# define VIR_MOCK_REAL_INIT_MAIN(name, alias) \
    do {} while (0)
#endif

#define VIR_MOCK_STRINGIFY_SYMBOL(name) #name

#define VIR_MOCK_REAL_INIT(name) \
    do { \
        VIR_MOCK_REAL_INIT_MAIN(name, #name); \
        if (real_##name == NULL && \
            !(real_##name = dlsym(RTLD_NEXT, \
                                  VIR_MOCK_STRINGIFY_SYMBOL(name)))) { \
            fprintf(stderr, "Missing symbol '" #name "'\n"); \
            abort(); \
        } \
    } while (0)

#define VIR_MOCK_REAL_INIT_ALIASED(name, alias) \
    do { \
        VIR_MOCK_REAL_INIT_MAIN(name, alias); \
        if (real_##name == NULL && \
            !(real_##name = dlsym(RTLD_NEXT, \
                                  alias))) { \
            fprintf(stderr, "Missing symbol '" alias "'\n"); \
            abort(); \
        } \
    } while (0)
