/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_INTERNAL_H__
# define __VIR_INTERNAL_H__

# include <errno.h>
# include <limits.h>
# include <verify.h>
# include <stdbool.h>

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
# include "libvirt/libvirt-qemu.h"
# include "libvirt/virterror.h"

# include "libvirt_internal.h"

# include "c-strcase.h"

/* On architectures which lack these limits, define them (ie. Cygwin).
 * Note that the libvirt code should be robust enough to handle the
 * case where actual value is longer than these limits (eg. by setting
 * length correctly in second argument to gethostname and by always
 * using strncpy instead of strcpy).
 */
# ifndef HOST_NAME_MAX
#  define HOST_NAME_MAX 256
# endif

# ifndef IF_NAMESIZE
#  define IF_NAMESIZE 16
# endif

# ifndef INET_ADDRSTRLEN
#  define INET_ADDRSTRLEN 16
# endif

/* String equality tests, suggested by Jim Meyering. */
# define STREQ(a,b) (strcmp(a,b) == 0)
# define STRCASEEQ(a,b) (c_strcasecmp(a,b) == 0)
# define STRNEQ(a,b) (strcmp(a,b) != 0)
# define STRCASENEQ(a,b) (c_strcasecmp(a,b) != 0)
# define STREQLEN(a,b,n) (strncmp(a,b,n) == 0)
# define STRCASEEQLEN(a,b,n) (c_strncasecmp(a,b,n) == 0)
# define STRNEQLEN(a,b,n) (strncmp(a,b,n) != 0)
# define STRCASENEQLEN(a,b,n) (c_strncasecmp(a,b,n) != 0)
# define STRPREFIX(a,b) (strncmp(a,b,strlen(b)) == 0)
# define STRSKIP(a,b) (STRPREFIX(a,b) ? (a) + strlen(b) : NULL)

# define STREQ_NULLABLE(a, b)                           \
    ((!(a) && !(b)) || ((a) && (b) && STREQ((a), (b))))
# define STRNEQ_NULLABLE(a, b)                          \
    ((!(a) ^ !(b)) || ((a) && (b) && STRNEQ((a), (b))))


# define NUL_TERMINATE(buf) do { (buf)[sizeof(buf)-1] = '\0'; } while (0)
# define ARRAY_CARDINALITY(Array) (sizeof(Array) / sizeof(*(Array)))

/* C99 uses __func__.  __FUNCTION__ is legacy. */
# ifndef __GNUC__
#  define __FUNCTION__ __func__
# endif

# ifdef __GNUC__

#  ifndef __GNUC_PREREQ
#   if defined __GNUC__ && defined __GNUC_MINOR__
#    define __GNUC_PREREQ(maj, min)                                        \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#   else
#    define __GNUC_PREREQ(maj,min) 0
#   endif

/* Work around broken limits.h on debian etch */
#   if defined _GCC_LIMITS_H_ && ! defined ULLONG_MAX
#    define ULLONG_MAX   ULONG_LONG_MAX
#   endif

#  endif /* __GNUC__ */

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
#  ifndef ATTRIBUTE_UNUSED
#   define ATTRIBUTE_UNUSED __attribute__((__unused__))
#  endif

/**
 * ATTRIBUTE_NORETURN:
 *
 * Macro to indicate that a function won't return to the caller
 */
#  ifndef ATTRIBUTE_NORETURN
#   define ATTRIBUTE_NORETURN __attribute__((__noreturn__))
#  endif

/**
 * ATTRIBUTE_SENTINEL:
 *
 * Macro to check for NULL-terminated varargs lists
 */
#  ifndef ATTRIBUTE_SENTINEL
#   if __GNUC_PREREQ (4, 0)
#    define ATTRIBUTE_SENTINEL __attribute__((__sentinel__))
#   else
#    define ATTRIBUTE_SENTINEL
#   endif
#  endif

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
#  ifndef ATTRIBUTE_FMT_PRINTF
#   if __GNUC_PREREQ (4, 4)
#    define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (gnu_printf, fmtpos,argpos)))
#   else
#    define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (printf, fmtpos,argpos)))
#   endif
#  endif

#  ifndef ATTRIBUTE_RETURN_CHECK
#   if __GNUC_PREREQ (3, 4)
#    define ATTRIBUTE_RETURN_CHECK __attribute__((__warn_unused_result__))
#   else
#    define ATTRIBUTE_RETURN_CHECK
#   endif
#  endif

/**
 * ATTRIBUTE_PACKED
 *
 * force a structure to be packed, i.e. not following architecture and
 * compiler best alignments for its sub components. It's needed for example
 * for the network filetering code when defining the content of raw
 * ethernet packets.
 * Others compiler than gcc may use something different e.g. #pragma pack(1)
 */
#  ifndef ATTRIBUTE_PACKED
#   if __GNUC_PREREQ (3, 3)
#    define ATTRIBUTE_PACKED __attribute__((packed))
#   else
#    error "Need an __attribute__((packed)) equivalent"
#   endif
#  endif

#  ifndef ATTRIBUTE_NONNULL
#   if __GNUC_PREREQ (3, 3)
#    define ATTRIBUTE_NONNULL(m) __attribute__((__nonnull__(m)))
#   else
#    define ATTRIBUTE_NONNULL(m)
#   endif
#  endif

# else
#  ifndef ATTRIBUTE_UNUSED
#   define ATTRIBUTE_UNUSED
#  endif
#  ifndef ATTRIBUTE_FMT_PRINTF
#   define ATTRIBUTE_FMT_PRINTF(...)
#  endif
#  ifndef ATTRIBUTE_RETURN_CHECK
#   define ATTRIBUTE_RETURN_CHECK
#  endif
# endif				/* __GNUC__ */

/*
 * Use this when passing possibly-NULL strings to printf-a-likes.
 */
# define NULLSTR(s) \
    ((void)verify_true(sizeof(*(s)) == sizeof(char)),   \
     (s) ? (s) : "(null)")

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
# define TODO								\
    fprintf(stderr, "Unimplemented block at %s:%d\n",			\
            __FILE__, __LINE__);

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
            virReportErrorHelper(VIR_FROM_THIS,                         \
                                 VIR_ERR_INVALID_ARG,                   \
                                 __FILE__,                              \
                                 __FUNCTION__,                          \
                                 __LINE__,                              \
                                 _("%s: unsupported flags (0x%lx)"),    \
                                 __FUNCTION__, __unsuppflags);          \
            return retval;                                              \
        }                                                               \
    } while (0)

/* divide value by size, rounding up */
# define VIR_DIV_UP(value, size) (((value) + (size) - 1) / (size))


# if WITH_DTRACE_PROBES
#  ifndef LIBVIRT_PROBES_H
#   define LIBVIRT_PROBES_H
#   include "probes.h"
#  endif /* LIBVIRT_PROBES_H */

/* Systemtap 1.2 headers have a bug where they cannot handle a
 * variable declared with array type.  Work around this by casting all
 * arguments.  This is some gross use of the preprocessor because
 * PROBE is a var-arg macro, but it is better than the alternative of
 * making all callers to PROBE have to be aware of the issues.  And
 * hopefully, if we ever add a call to PROBE with other than 9
 * end arguments, you can figure out the pattern to extend this hack.
 */
#  define VIR_COUNT_ARGS(...) VIR_ARG11(__VA_ARGS__, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#  define VIR_ARG11(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, ...) _11
#  define VIR_ADD_CAST_EXPAND(a, b, ...) VIR_ADD_CAST_PASTE(a, b, __VA_ARGS__)
#  define VIR_ADD_CAST_PASTE(a, b, ...) a##b(__VA_ARGS__)

/* The double cast is necessary to silence gcc warnings; any pointer
 * can safely go to intptr_t and back to void *, which collapses
 * arrays into pointers; while any integer can be widened to intptr_t
 * then cast to void *.  */
#  define VIR_ADD_CAST(a) ((void *)(intptr_t)(a))
#  define VIR_ADD_CAST1(a)                                  \
    VIR_ADD_CAST(a)
#  define VIR_ADD_CAST2(a, b)                               \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b)
#  define VIR_ADD_CAST3(a, b, c)                            \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c)
#  define VIR_ADD_CAST4(a, b, c, d)                         \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d)
#  define VIR_ADD_CAST5(a, b, c, d, e)                      \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e)
#  define VIR_ADD_CAST6(a, b, c, d, e, f)                   \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f)
#  define VIR_ADD_CAST7(a, b, c, d, e, f, g)                \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f),      \
    VIR_ADD_CAST(g)
#  define VIR_ADD_CAST8(a, b, c, d, e, f, g, h)             \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f),      \
    VIR_ADD_CAST(g), VIR_ADD_CAST(h)
#  define VIR_ADD_CAST9(a, b, c, d, e, f, g, h, i)          \
    VIR_ADD_CAST(a), VIR_ADD_CAST(b), VIR_ADD_CAST(c),      \
    VIR_ADD_CAST(d), VIR_ADD_CAST(e), VIR_ADD_CAST(f),      \
    VIR_ADD_CAST(g), VIR_ADD_CAST(h), VIR_ADD_CAST(i)

#  define VIR_ADD_CASTS(...)                                            \
    VIR_ADD_CAST_EXPAND(VIR_ADD_CAST, VIR_COUNT_ARGS(__VA_ARGS__),      \
                        __VA_ARGS__)

#  define PROBE_EXPAND(NAME, ARGS) NAME(ARGS)
#  define PROBE(NAME, FMT, ...)                              \
    VIR_DEBUG_INT("trace." __FILE__ , __func__, __LINE__,    \
                  #NAME ": " FMT, __VA_ARGS__);              \
    if (LIBVIRT_ ## NAME ## _ENABLED()) {                   \
        PROBE_EXPAND(LIBVIRT_ ## NAME,                      \
                     VIR_ADD_CASTS(__VA_ARGS__));            \
    }
# else
#  define PROBE(NAME, FMT, ...)                              \
    VIR_DEBUG_INT("trace." __FILE__, __func__, __LINE__,     \
                  #NAME ": " FMT, __VA_ARGS__);
# endif


#endif                          /* __VIR_INTERNAL_H__ */
