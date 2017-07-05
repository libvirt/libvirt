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

#ifndef __VIR_INTERNAL_H__
# define __VIR_INTERNAL_H__

# include <errno.h>
# include <limits.h>
# include <verify.h>
# include <stdbool.h>
# include <stdint.h>

# if STATIC_ANALYSIS
#  undef NDEBUG /* Don't let a prior NDEBUG definition cause trouble.  */
#  include <assert.h>
#  define sa_assert(expr) assert (expr)
# else
#  define sa_assert(expr) /* empty */
# endif

/* The library itself is allowed to use deprecated functions /
 * variables, so effectively undefine the deprecated attribute
 * which would otherwise be defined in libvirt.h.
 */
# undef VIR_DEPRECATED
# define VIR_DEPRECATED /*empty*/

/* The library itself needs to know enum sizes.  */
# define VIR_ENUM_SENTINELS

/* All uses of _() within the library should pick up translations from
 * libvirt's message files, rather than from the package that is
 * linking in the library.  Setting this macro before including
 * "gettext.h" means that gettext() (and _()) will properly expand to
 * dgettext.  */
# define DEFAULT_TEXT_DOMAIN PACKAGE
# include "gettext.h"
# define _(str) gettext(str)
# define N_(str) str

# include "libvirt/libvirt.h"
# include "libvirt/libvirt-lxc.h"
# include "libvirt/libvirt-qemu.h"
# include "libvirt/libvirt-admin.h"
# include "libvirt/virterror.h"

# include "c-strcase.h"
# include "ignore-value.h"
# include "count-leading-zeros.h"

/* String equality tests, suggested by Jim Meyering. */
# define STREQ(a, b) (strcmp(a, b) == 0)
# define STRCASEEQ(a, b) (c_strcasecmp(a, b) == 0)
# define STRNEQ(a, b) (strcmp(a, b) != 0)
# define STRCASENEQ(a, b) (c_strcasecmp(a, b) != 0)
# define STREQLEN(a, b, n) (strncmp(a, b, n) == 0)
# define STRCASEEQLEN(a, b, n) (c_strncasecmp(a, b, n) == 0)
# define STRNEQLEN(a, b, n) (strncmp(a, b, n) != 0)
# define STRCASENEQLEN(a, b, n) (c_strncasecmp(a, b, n) != 0)
# define STRPREFIX(a, b) (strncmp(a, b, strlen(b)) == 0)
# define STRSKIP(a, b) (STRPREFIX(a, b) ? (a) + strlen(b) : NULL)

# define STREQ_NULLABLE(a, b)                           \
    ((a) ? (b) && STREQ((a), (b)) : !(b))
# define STRNEQ_NULLABLE(a, b)                          \
    ((a) ? !(b) || STRNEQ((a), (b)) : !!(b))

# define NUL_TERMINATE(buf) do { (buf)[sizeof(buf)-1] = '\0'; } while (0)
# define ARRAY_CARDINALITY(Array) (sizeof(Array) / sizeof(*(Array)))

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag consciously unused parameters to functions
 */
# ifndef ATTRIBUTE_UNUSED
#  define ATTRIBUTE_UNUSED __attribute__((__unused__))
# endif

/**
 * ATTRIBUTE_NORETURN:
 *
 * Macro to indicate that a function won't return to the caller
 */
# ifndef ATTRIBUTE_NORETURN
#  define ATTRIBUTE_NORETURN __attribute__((__noreturn__))
# endif

/**
 * ATTRIBUTE_SENTINEL:
 *
 * Macro to check for NULL-terminated varargs lists
 */
# ifndef ATTRIBUTE_SENTINEL
#  define ATTRIBUTE_SENTINEL __attribute__((__sentinel__))
# endif

/**
 * ATTRIBUTE_NOINLINE:
 *
 * Force compiler not to inline a method. Should be used if
 * the method need to be overridable by test mocks.
 */
# ifndef ATTRIBUTE_NOINLINE
#  define ATTRIBUTE_NOINLINE __attribute__((__noinline__))
# endif

/**
 * ATTRIBUTE_FMT_PRINTF
 *
 * Macro used to check printf like functions, if compiling
 * with gcc.
 *
 * We use gnulib which guarantees we always have GNU style
 * printf format specifiers even on broken Win32 platforms
 * hence we have to force 'gnu_printf' for new GCC
 */
# ifndef ATTRIBUTE_FMT_PRINTF
#  ifndef __clang__
#   define ATTRIBUTE_FMT_PRINTF(fmtpos, argpos) \
       __attribute__((__format__ (__gnu_printf__, fmtpos, argpos)))
#  else
#   define ATTRIBUTE_FMT_PRINTF(fmtpos, argpos) \
       __attribute__((__format__ (__printf__, fmtpos, argpos)))
#  endif
# endif

# ifndef ATTRIBUTE_RETURN_CHECK
#  define ATTRIBUTE_RETURN_CHECK __attribute__((__warn_unused_result__))
# endif

/**
 * ATTRIBUTE_PACKED
 *
 * force a structure to be packed, i.e. not following architecture and
 * compiler best alignments for its sub components. It's needed for example
 * for the network filetering code when defining the content of raw
 * ethernet packets.
 * Others compiler than gcc may use something different e.g. #pragma pack(1)
 */
# ifndef ATTRIBUTE_PACKED
#  define ATTRIBUTE_PACKED __attribute__((packed))
# endif

/* gcc's handling of attribute nonnull is less than stellar - it does
 * NOT improve diagnostics, and merely allows gcc to optimize away
 * null code checks even when the caller manages to pass null in spite
 * of the attribute, leading to weird crashes.  Coverity, on the other
 * hand, knows how to do better static analysis based on knowing
 * whether a parameter is nonnull.  Make this attribute conditional
 * based on whether we are compiling for real or for analysis, while
 * still requiring correct gcc syntax when it is turned off.  See also
 * http://gcc.gnu.org/bugzilla/show_bug.cgi?id=17308 */
# ifndef ATTRIBUTE_NONNULL
#  if STATIC_ANALYSIS
#   define ATTRIBUTE_NONNULL(m) __attribute__((__nonnull__(m)))
#  else
#   define ATTRIBUTE_NONNULL(m) __attribute__(())
#  endif
# endif

# ifndef ATTRIBUTE_FALLTHROUGH
#  if __GNUC_PREREQ (7, 0)
#   define ATTRIBUTE_FALLTHROUGH __attribute__((fallthrough))
#  else
#   define ATTRIBUTE_FALLTHROUGH do {} while(0)
#  endif
# endif

# if WORKING_PRAGMA_PUSH
#  define VIR_WARNINGS_NO_CAST_ALIGN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wcast-align\"")

#  define VIR_WARNINGS_NO_DEPRECATED \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wdeprecated-declarations\"")

#  if HAVE_SUGGEST_ATTRIBUTE_FORMAT
#   define VIR_WARNINGS_NO_PRINTF \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wsuggest-attribute=format\"")
#  else
#   define VIR_WARNINGS_NO_PRINTF \
    _Pragma ("GCC diagnostic push")
#  endif

/* Workaround bogus GCC 6.0 for logical 'or' equal expression warnings.
 * (GCC bz 69602) */
#  if BROKEN_GCC_WLOGICALOP_EQUAL_EXPR
#   define VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR            \
     _Pragma ("GCC diagnostic push")                        \
     _Pragma ("GCC diagnostic ignored \"-Wlogical-op\"")
#  else
#   define VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR            \
     _Pragma ("GCC diagnostic push")
#  endif

#  define VIR_WARNINGS_RESET \
    _Pragma ("GCC diagnostic pop")
# else
#  define VIR_WARNINGS_NO_CAST_ALIGN
#  define VIR_WARNINGS_NO_DEPRECATED
#  define VIR_WARNINGS_NO_PRINTF
#  define VIR_WARNINGS_NO_WLOGICALOP_EQUAL_EXPR
#  define VIR_WARNINGS_RESET
# endif

/* Workaround bogus GCC < 4.6 that produces false -Wlogical-op warnings for
 * strchr(). Those old GCCs don't support push/pop. */
# if BROKEN_GCC_WLOGICALOP_STRCHR
#  define VIR_WARNINGS_NO_WLOGICALOP_STRCHR                \
    _Pragma ("GCC diagnostic ignored \"-Wlogical-op\"")
# else
#  define VIR_WARNINGS_NO_WLOGICALOP_STRCHR
# endif


/*
 * Use this when passing possibly-NULL strings to printf-a-likes.
 */
# define NULLSTR(s) ((s) ? (s) : "<null>")

/*
 * Similar to NULLSTR, but print '-' to make it more user friendly.
 */
# define EMPTYSTR(s) ((s) ? (s) : "-")

/**
 * SWAP:
 *
 * In place exchange of two values
 */
# define SWAP(a, b)         \
    do {                    \
        (a) = (a) ^ (b);    \
        (b) = (a) ^ (b);    \
        (a) = (a) ^ (b);    \
    } while (0)

/**
 * VIR_STEAL_PTR:
 *
 * Steals pointer passed as second argument into the first argument. Second
 * argument must not have side effects.
 */
# define VIR_STEAL_PTR(a, b)  \
    do {                      \
        (a) = (b);            \
        (b) = NULL;           \
    } while (0)

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
# define virCheckFlags(supported, retval)                               \
    do {                                                                \
        unsigned long __unsuppflags = flags & ~(supported);             \
        if (__unsuppflags) {                                            \
            virReportInvalidArg(flags,                                  \
                                _("unsupported flags (0x%lx) in function %s"), \
                                __unsuppflags, __FUNCTION__);           \
            return retval;                                              \
        }                                                               \
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
# define virCheckFlagsGoto(supported, label)                            \
    do {                                                                \
        unsigned long __unsuppflags = flags & ~(supported);             \
        if (__unsuppflags) {                                            \
            virReportInvalidArg(flags,                                  \
                                _("unsupported flags (0x%lx) in function %s"), \
                                __unsuppflags, __FUNCTION__);           \
            goto label;                                                 \
        }                                                               \
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
# define VIR_EXCLUSIVE_FLAGS_RET(FLAG1, FLAG2, RET)                         \
    do {                                                                    \
        if ((flags & FLAG1) && (flags & FLAG2)) {                           \
            virReportInvalidArg(ctl,                                        \
                                _("Flags '%s' and '%s' are mutually "       \
                                  "exclusive"),                             \
                                #FLAG1, #FLAG2);                            \
            return RET;                                                     \
        }                                                                   \
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
# define VIR_EXCLUSIVE_FLAGS_GOTO(FLAG1, FLAG2, LABEL)                      \
    do {                                                                    \
        if ((flags & FLAG1) && (flags & FLAG2)) {                           \
            virReportInvalidArg(ctl,                                        \
                                _("Flags '%s' and '%s' are mutually "       \
                                  "exclusive"),                             \
                                #FLAG1, #FLAG2);                            \
            goto LABEL;                                                     \
        }                                                                   \
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
# define VIR_REQUIRE_FLAG_RET(FLAG1, FLAG2, RET)                            \
    do {                                                                    \
        if ((flags & FLAG1) && !(flags & FLAG2)) {                          \
            virReportInvalidArg(ctl,                                        \
                                _("Flag '%s' is required by flag '%s'"),    \
                                #FLAG2, #FLAG1);                            \
            return RET;                                                     \
        }                                                                   \
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
# define VIR_REQUIRE_FLAG_GOTO(FLAG1, FLAG2, LABEL)                         \
    do {                                                                    \
        if ((flags & FLAG1) && !(flags & FLAG2)) {                          \
            virReportInvalidArg(ctl,                                        \
                                _("Flag '%s' is required by flag '%s'"),    \
                                #FLAG2, #FLAG1);                            \
            goto LABEL;                                                     \
        }                                                                   \
    } while (0)

# define virCheckNonNullArgReturn(argname, retval)  \
    do {                                            \
        if (argname == NULL) {                      \
            virReportInvalidNonNullArg(argname);    \
            return retval;                          \
        }                                           \
    } while (0)
# define virCheckNullArgGoto(argname, label)        \
    do {                                            \
        if (argname != NULL) {                      \
            virReportInvalidNullArg(argname);       \
            goto label;                             \
        }                                           \
    } while (0)
# define virCheckNonNullArgGoto(argname, label)     \
    do {                                            \
        if (argname == NULL) {                      \
            virReportInvalidNonNullArg(argname);    \
            goto label;                             \
        }                                           \
    } while (0)
# define virCheckNonEmptyStringArgGoto(argname, label) \
    do {                                               \
        if (argname == NULL) {                         \
            virReportInvalidNonNullArg(argname);       \
            goto label;                                \
        }                                              \
        if (*argname == '\0') {                        \
            virReportInvalidEmptyStringArg(argname);   \
            goto label;                                \
        }                                              \
    } while (0)
# define virCheckPositiveArgGoto(argname, label)    \
    do {                                            \
        if (argname <= 0) {                         \
            virReportInvalidPositiveArg(argname);   \
            goto label;                             \
        }                                           \
    } while (0)
# define virCheckPositiveArgReturn(argname, retval)     \
    do {                                                \
        if (argname <= 0) {                             \
            virReportInvalidPositiveArg(argname);       \
            return retval;                              \
        }                                               \
    } while (0)
# define virCheckNonZeroArgGoto(argname, label)     \
    do {                                            \
        if (argname == 0) {                         \
            virReportInvalidNonZeroArg(argname);    \
            goto label;                             \
        }                                           \
    } while (0)
# define virCheckZeroArgGoto(argname, label)        \
    do {                                            \
        if (argname != 0) {                         \
            virReportInvalidNonZeroArg(argname);    \
            goto label;                             \
        }                                           \
    } while (0)
# define virCheckNonNegativeArgGoto(argname, label)     \
    do {                                                \
        if (argname < 0) {                              \
            virReportInvalidNonNegativeArg(argname);    \
            goto label;                                 \
        }                                               \
    } while (0)
# define virCheckReadOnlyGoto(flags, label)                             \
    do {                                                                \
        if ((flags) & VIR_CONNECT_RO) {                                 \
            virReportRestrictedError(_("read only access prevents %s"), \
                                     __FUNCTION__);                     \
            goto label;                                                 \
        }                                                               \
    } while (0)



/* divide value by size, rounding up */
# define VIR_DIV_UP(value, size) (((value) + (size) - 1) / (size))

/* round up value to the closest multiple of size */
# define VIR_ROUND_UP(value, size) (VIR_DIV_UP(value, size) * (size))

/* Round up to the next closest power of 2. It will return rounded number or 0
 * for 0 or number more than 2^31 (for 32bit unsigned int). */
# define VIR_ROUND_UP_POWER_OF_TWO(value)                                   \
    ((value) > 0 && (value) <= 1U << (sizeof(unsigned int) * 8 - 1) ?       \
     1U << (sizeof(unsigned int) * 8 - count_leading_zeros((value) - 1)) : 0)


/* Specific error values for use in forwarding programs such as
 * virt-login-shell; these values match what GNU env does.  */
enum {
    EXIT_CANCELED = 125, /* Failed before attempting exec */
    EXIT_CANNOT_INVOKE = 126, /* Exists but couldn't exec */
    EXIT_ENOENT = 127, /* Could not find program to exec */
};

# ifndef ENODATA
#  define ENODATA EIO
# endif

#endif                          /* __VIR_INTERNAL_H__ */
