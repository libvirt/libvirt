/*
 * internal.h: internal definitions just used by code from the library
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
 */

#pragma once

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "glibcompat.h"

#if defined __clang_analyzer__ || defined __COVERITY__
# define STATIC_ANALYSIS 1
#endif

#if STATIC_ANALYSIS
# undef NDEBUG /* Don't let a prior NDEBUG definition cause trouble.  */
# include <assert.h>
# define sa_assert(expr) assert (expr)
#else
# define sa_assert(expr) /* empty */
#endif

#define VIR_INT_MULTIPLY_OVERFLOW(a,b) (G_UNLIKELY ((b) > 0 && (a) > G_MAXINT / (b)))

/* The library itself is allowed to use deprecated functions /
 * variables, so effectively undefine the deprecated attribute
 * which would otherwise be defined in libvirt.h.
 */
#undef VIR_DEPRECATED
#define VIR_DEPRECATED /*empty*/

/* The library itself needs to know enum sizes.  */
#define VIR_ENUM_SENTINELS

#ifdef WITH_LIBINTL_H
# define DEFAULT_TEXT_DOMAIN PACKAGE
# include <libintl.h>
# define _(str) dgettext(PACKAGE, str)
#else /* WITH_LIBINTL_H */
# define _(str) str
#endif /* WITH_LIBINTL_H */
#define N_(str) str

#include "libvirt/libvirt.h"
#include "libvirt/libvirt-lxc.h"
#include "libvirt/libvirt-qemu.h"
#include "libvirt/libvirt-admin.h"
#include "libvirt/virterror.h"

/* Merely casting to (void) is not sufficient since the
 * introduction of the "warn_unused_result" attribute
 */
#define ignore_value(x) \
    (__extension__ ({ __typeof__ (x) __x = (x); (void) __x; }))


/* String equality tests, suggested by Jim Meyering. */
#define STREQ(a, b) (strcmp(a, b) == 0)
#define STRCASEEQ(a, b) (g_ascii_strcasecmp(a, b) == 0)
#define STRNEQ(a, b) (strcmp(a, b) != 0)
#define STRCASENEQ(a, b) (g_ascii_strcasecmp(a, b) != 0)
#define STREQLEN(a, b, n) (strncmp(a, b, n) == 0)
#define STRCASEEQLEN(a, b, n) (g_ascii_strncasecmp(a, b, n) == 0)
#define STRNEQLEN(a, b, n) (strncmp(a, b, n) != 0)
#define STRCASENEQLEN(a, b, n) (g_ascii_strncasecmp(a, b, n) != 0)
#define STRPREFIX(a, b) (strncmp(a, b, strlen(b)) == 0)
#define STRCASEPREFIX(a, b) (g_ascii_strncasecmp(a, b, strlen(b)) == 0)
#define STRSKIP(a, b) (STRPREFIX(a, b) ? (a) + strlen(b) : NULL)
#define STRCASESKIP(a, b) (STRCASEPREFIX(a, b) ? (a) + strlen(b) : NULL)

/**
 * STRLIM
 * @str: pointer to a string (evaluated once)
 * @lim: length limit (evaluated twice)
 *
 * Evaluates as true if length of @str doesn't exceed the limit @lim. Note
 * that @lim + 1 characters may be accessed.
 */
#define STRLIM(str, lim) (strnlen((str), (lim) + 1) <= (lim))

#define STREQ_NULLABLE(a, b) (g_strcmp0(a, b) == 0)
#define STRNEQ_NULLABLE(a, b) (g_strcmp0(a, b) != 0)

#define CONCAT_(a, b) a ## b
#define CONCAT(a, b) CONCAT_(a, b)

#ifdef WIN32
# ifndef O_CLOEXEC
#  define O_CLOEXEC _O_NOINHERIT
# endif
#endif

/**
 * ATTRIBUTE_PACKED
 *
 * force a structure to be packed, i.e. not following architecture and
 * compiler best alignments for its sub components. It's needed for example
 * for the network filetering code when defining the content of raw
 * ethernet packets.
 * Others compiler than gcc may use something different e.g. #pragma pack(1)
 */
#ifndef ATTRIBUTE_PACKED
# define ATTRIBUTE_PACKED __attribute__((packed))
#endif

/* gcc's handling of attribute nonnull is less than stellar - it does
 * NOT improve diagnostics, and merely allows gcc to optimize away
 * null code checks even when the caller manages to pass null in spite
 * of the attribute, leading to weird crashes.  Coverity, on the other
 * hand, knows how to do better static analysis based on knowing
 * whether a parameter is nonnull.  Make this attribute conditional
 * based on whether we are compiling for real or for analysis, while
 * still requiring correct gcc syntax when it is turned off.  See also
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308 */
#ifndef ATTRIBUTE_NONNULL
# if STATIC_ANALYSIS
#  define ATTRIBUTE_NONNULL(m) __attribute__((__nonnull__(m)))
# else
#  define ATTRIBUTE_NONNULL(m) __attribute__(())
# endif
#endif

/**
 *
 * G_GNUC_FALLTHROUGH
 *
 * silence the compiler warning when falling through a switch case
 *
 * Note: GLib 2.69.0 introduced version checks on the
 * macro usage. Thus an app setting GLIB_VERSION_MAX_ALLOWED
 * to less than 2.60 will trigger a warning using G_GNUC_FALLTHROUGH
 * Normally the warning is a good thing, but we want to use our
 * fallback impl, so we have to temporarily cull the GLib macro.
 *
 * All this should be removed once updating to min GLib >= 2.60
 */
#if GLIB_CHECK_VERSION(2, 69, 0)
# undef G_GNUC_FALLTHROUGH
#endif
#ifndef G_GNUC_FALLTHROUGH
# if __GNUC_PREREQ (7, 0)
#  define G_GNUC_FALLTHROUGH __attribute__((fallthrough))
# else
#  define G_GNUC_FALLTHROUGH do {} while(0)
# endif
#endif

#define VIR_WARNINGS_NO_CAST_ALIGN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wcast-align\"")

#define VIR_WARNINGS_NO_DEPRECATED \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#define VIR_WARNINGS_NO_POINTER_SIGN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wpointer-sign\"")

#if WITH_SUGGEST_ATTRIBUTE_FORMAT
# define VIR_WARNINGS_NO_PRINTF \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wsuggest-attribute=format\"")
#else
# define VIR_WARNINGS_NO_PRINTF \
    _Pragma ("GCC diagnostic push")
#endif

#define VIR_WARNINGS_NO_UNUSED_FUNCTION \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wunused-function\"")

/* Workaround bogus GCC 6.0 for logical 'or' equal expression warnings.
 * (GCC bz 69602) */
#if BROKEN_GCC_WLOGICALOP_EQUAL_EXPR
# define VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR \
     _Pragma ("GCC diagnostic push") \
     _Pragma ("GCC diagnostic ignored \"-Wlogical-op\"")
#else
# define VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR \
     _Pragma ("GCC diagnostic push")
#endif

/* Where ignore_value cannot be used because it's a statement */
#define VIR_WARNINGS_NO_UNUSED_VARIABLE \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wunused-variable\"")

#define VIR_WARNINGS_NO_DECLARATION_AFTER_STATEMENT \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wdeclaration-after-statement\"")

#define VIR_WARNINGS_RESET \
    _Pragma ("GCC diagnostic pop")

/*
 * Use this when passing possibly-NULL strings to printf-a-likes.
 */
#define NULLSTR(s) ((s) ? (s) : "<null>")

/*
 * Turn a NULL string into an empty string
 */
#define NULLSTR_EMPTY(s) ((s) ? (s) : "")

/*
 * Turn a NULL string into a star
 */
#define NULLSTR_STAR(s) ((s) ? (s) : "*")

/*
 * Turn a NULL string into a minus sign
 */
#define NULLSTR_MINUS(s) ((s) ? (s) : "-")

/**
 * SWAP:
 *
 * In place exchange of two values
 */
#define SWAP(a, b) \
    do { \
        (a) = (a) ^ (b); \
        (b) = (a) ^ (b); \
        (a) = (a) ^ (b); \
    } while (0)


/**
 * VIR_IS_POW2:
 *
 * Returns true if given number is a power of two
 */
#define VIR_IS_POW2(x) \
    ((x) && !((x) & ((x) - 1)))


/**
 * virCheckFlags:
 * @supported: an OR'ed set of supported flags
 * @retval: return value in case unsupported flags were passed
 *
 * To avoid memory leaks this macro has to be used before any non-trivial
 * code which could possibly allocate some memory.
 *
 * Returns nothing. Exits the caller function if unsupported flags were
 * passed to it.
 */
#define virCheckFlags(supported, retval) \
    do { \
        unsigned int __uiflags = flags; \
        unsigned int __unsuppflags = flags & ~(supported); \
        if (__uiflags != flags) { \
            virReportInvalidArg(flags, \
                                _("unsupported use of long flags in function %1$s"), \
                                __FUNCTION__); \
            return retval; \
        } \
        if (__unsuppflags) { \
            virReportInvalidArg(flags, \
                                _("unsupported flags (0x%1$x) in function %2$s"), \
                                __unsuppflags, __FUNCTION__); \
            return retval; \
        } \
    } while (0)

/**
 * virCheckFlagsGoto:
 * @supported: an OR'ed set of supported flags
 * @label: label to jump to on error
 *
 * To avoid memory leaks this macro has to be used before any non-trivial
 * code which could possibly allocate some memory.
 *
 * Returns nothing. Jumps to a label if unsupported flags were
 * passed to it.
 */
#define virCheckFlagsGoto(supported, label) \
    do { \
        unsigned int __uiflags = flags; \
        unsigned int __unsuppflags = flags & ~(supported); \
        if (__uiflags != flags) { \
            virReportInvalidArg(flags, \
                                _("unsupported use of long flags in function %1$s"), \
                                __FUNCTION__); \
            goto label; \
        } \
        if (__unsuppflags) { \
            virReportInvalidArg(flags, \
                                _("unsupported flags (0x%1$x) in function %2$s"), \
                                __unsuppflags, __FUNCTION__); \
            goto label; \
        } \
    } while (0)

/* Macros to help dealing with mutually exclusive flags. */

/**
 * VIR_EXCLUSIVE_FLAGS_RET:
 *
 * @FLAG1: First flag to be checked.
 * @FLAG2: Second flag to be checked.
 * @RET: Return value.
 *
 * Reject mutually exclusive API flags.  The checked flags are compared
 * with flags variable.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VIR_EXCLUSIVE_FLAGS_RET(FLAG1, FLAG2, RET) \
    do { \
        if ((flags & FLAG1) && (flags & FLAG2)) { \
            virReportInvalidArg(ctl, \
                                _("Flags '%1$s' and '%2$s' are mutually exclusive"), \
                                #FLAG1, #FLAG2); \
            return RET; \
        } \
    } while (0)

/**
 * VIR_EXCLUSIVE_FLAGS_GOTO:
 *
 * @FLAG1: First flag to be checked.
 * @FLAG2: Second flag to be checked.
 * @LABEL: Label to jump to.
 *
 * Reject mutually exclusive API flags.  The checked flags are compared
 * with flags variable.
 *
 * Returns nothing.  Jumps to a label if unsupported flags were
 * passed to it.
 */
#define VIR_EXCLUSIVE_FLAGS_GOTO(FLAG1, FLAG2, LABEL) \
    do { \
        if ((flags & FLAG1) && (flags & FLAG2)) { \
            virReportInvalidArg(ctl, \
                                _("Flags '%1$s' and '%2$s' are mutually exclusive"), \
                                #FLAG1, #FLAG2); \
            goto LABEL; \
        } \
    } while (0)

/* Macros to help dealing with flag requirements. */

/**
 * VIR_REQUIRE_FLAG_RET:
 *
 * @FLAG1: First flag to be checked.
 * @FLAG2: Second flag that is required by first flag.
 * @RET: Return value.
 *
 * Check whether required flag is set.  The checked flags are compared
 * with flags variable.
 *
 * This helper does an early return and therefore it has to be called
 * before anything that would require cleanup.
 */
#define VIR_REQUIRE_FLAG_RET(FLAG1, FLAG2, RET) \
    do { \
        if ((flags & (FLAG1)) && !(flags & (FLAG2))) { \
            virReportInvalidArg(ctl, \
                                _("Flag '%1$s' is required by flag '%2$s'"), \
                                #FLAG2, #FLAG1); \
            return RET; \
        } \
    } while (0)

/**
 * VIR_REQUIRE_FLAG_GOTO:
 *
 * @FLAG1: First flag to be checked.
 * @FLAG2: Second flag that is required by first flag.
 * @LABEL: Label to jump to.
 *
 * Check whether required flag is set.  The checked flags are compared
 * with flags variable.
 *
 * Returns nothing.  Jumps to a label if required flag is not set.
 */
#define VIR_REQUIRE_FLAG_GOTO(FLAG1, FLAG2, LABEL) \
    do { \
        if ((flags & (FLAG1)) && !(flags & (FLAG2))) { \
            virReportInvalidArg(ctl, \
                                _("Flag '%1$s' is required by flag '%2$s'"), \
                                #FLAG2, #FLAG1); \
            goto LABEL; \
        } \
    } while (0)

#define virCheckNonNullArgReturn(argname, retval) \
    do { \
        if (argname == NULL) { \
            virReportInvalidNonNullArg(argname); \
            return retval; \
        } \
    } while (0)
#define virCheckNullArgGoto(argname, label) \
    do { \
        if (argname != NULL) { \
            virReportInvalidNullArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckNonNullArgGoto(argname, label) \
    do { \
        if (argname == NULL) { \
            virReportInvalidNonNullArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckNonEmptyStringArgGoto(argname, label) \
    do { \
        if (argname == NULL) { \
            virReportInvalidNonNullArg(argname); \
            goto label; \
        } \
        if (*argname == '\0') { \
            virReportInvalidEmptyStringArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckPositiveArgGoto(argname, label) \
    do { \
        if (argname <= 0) { \
            virReportInvalidPositiveArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckPositiveArgReturn(argname, retval) \
    do { \
        if (argname <= 0) { \
            virReportInvalidPositiveArg(argname); \
            return retval; \
        } \
    } while (0)
#define virCheckNonZeroArgGoto(argname, label) \
    do { \
        if (argname == 0) { \
            virReportInvalidNonZeroArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckZeroArgGoto(argname, label) \
    do { \
        if (argname != 0) { \
            virReportInvalidNonZeroArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckNonNegativeArgGoto(argname, label) \
    do { \
        if (argname < 0) { \
            virReportInvalidNonNegativeArg(argname); \
            goto label; \
        } \
    } while (0)
#define virCheckReadOnlyGoto(flags, label) \
    do { \
        if ((flags) & VIR_CONNECT_RO) { \
            virReportRestrictedError(_("read only access prevents %1$s"), \
                                     __FUNCTION__); \
            goto label; \
        } \
    } while (0)

/* This check is intended to be used with legacy APIs only which expect the
 * caller to pre-allocate the target buffer.
 * We want to allow callers pass NULL arrays if the size is declared as 0 and
 * still succeed in calling the API.
 */
#define virCheckNonNullArrayArgGoto(argname, argsize, label) \
    do { \
        if (!argname && argsize > 0) { \
            virReportInvalidNonNullArg(argname); \
            goto label; \
        } \
    } while (0)


/* Count leading zeros in an unsigned int.
 *
 * Wrapper needed as __builtin_clz is undefined if value is zero
 */
#define VIR_CLZ(value) \
    (value ? __builtin_clz(value) : (8 * sizeof(unsigned)))

/* divide value by size, rounding up */
#define VIR_DIV_UP(value, size) (((value) + (size) - 1) / (size))

/* round up value to the closest multiple of size */
#define VIR_ROUND_UP(value, size) (VIR_DIV_UP(value, size) * (size))

/* Round up to the next closest power of 2. It will return rounded number or 0
 * for 0 or number more than 2^31 (for 32bit unsigned int). */
#define VIR_ROUND_UP_POWER_OF_TWO(value) \
    ((value) > 0 && (value) <= 1U << (sizeof(unsigned int) * 8 - 1) ? \
     1U << (sizeof(unsigned int) * 8 - VIR_CLZ((value) - 1)) : 0)


/* Specific error values for use in forwarding programs such as
 * virt-login-shell; these values match what GNU env does.  */
enum {
    EXIT_CANCELED = 125, /* Failed before attempting exec */
    EXIT_CANNOT_INVOKE = 126, /* Exists but couldn't exec */
    EXIT_ENOENT = 127, /* Could not find program to exec */
};

#ifndef ENODATA
# define ENODATA EIO
#endif

#ifdef WIN32
# ifndef ENOMSG
#  define ENOMSG 122
# endif
#endif

/* Ideally callers would use the g_*printf
 * functions directly but there are a lot to
 * convert, so until then...
 */
#ifndef VIR_NO_GLIB_STDIO

# undef printf
# define printf(...) g_printf(__VA_ARGS__)

# undef fprintf
# define fprintf(fh, ...) g_fprintf(fh, __VA_ARGS__)

#endif /* VIR_NO_GLIB_STDIO */
