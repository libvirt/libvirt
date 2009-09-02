/*
 * internal.h: internal definitions just used by code from the library
 */

#ifndef __VIR_INTERNAL_H__
#define __VIR_INTERNAL_H__

#include <errno.h>
#include <limits.h>
#include <verify.h>

#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

/* The library itself is allowed to use deprecated functions /
 * variables, so effectively undefine the deprecated attribute
 * which would otherwise be defined in libvirt.h.
 */
#define VIR_DEPRECATED /*empty*/

#include "gettext.h"

#include "libvirt/libvirt.h"
#include "libvirt/virterror.h"

/* On architectures which lack these limits, define them (ie. Cygwin).
 * Note that the libvirt code should be robust enough to handle the
 * case where actual value is longer than these limits (eg. by setting
 * length correctly in second argument to gethostname and by always
 * using strncpy instead of strcpy).
 */
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#ifndef IF_NAMESIZE
#define IF_NAMESIZE 16
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#define _(str) dgettext(GETTEXT_PACKAGE, (str))
#define N_(str) dgettext(GETTEXT_PACKAGE, (str))

/* String equality tests, suggested by Jim Meyering. */
#define STREQ(a,b) (strcmp((a),(b)) == 0)
#define STRCASEEQ(a,b) (strcasecmp((a),(b)) == 0)
#define STRNEQ(a,b) (strcmp((a),(b)) != 0)
#define STRCASENEQ(a,b) (strcasecmp((a),(b)) != 0)
#define STREQLEN(a,b,n) (strncmp((a),(b),(n)) == 0)
#define STRCASEEQLEN(a,b,n) (strncasecmp((a),(b),(n)) == 0)
#define STRNEQLEN(a,b,n) (strncmp((a),(b),(n)) != 0)
#define STRCASENEQLEN(a,b,n) (strncasecmp((a),(b),(n)) != 0)
#define STRPREFIX(a,b) (strncmp((a),(b),strlen((b))) == 0)

#define NUL_TERMINATE(buf) do { (buf)[sizeof(buf)-1] = '\0'; } while (0)
#define ARRAY_CARDINALITY(Array) (sizeof (Array) / sizeof *(Array))

/* C99 uses __func__.  __FUNCTION__ is legacy. */
#ifndef __GNUC__
#define __FUNCTION__ __func__
#endif

#ifdef __GNUC__

#ifndef __GNUC_PREREQ
#if defined __GNUC__ && defined __GNUC_MINOR__
# define __GNUC_PREREQ(maj, min)                                        \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#else
#define __GNUC_PREREQ(maj,min) 0
#endif

/* Work around broken limits.h on debian etch */
#if defined _GCC_LIMITS_H_ && ! defined ULLONG_MAX
#define ULLONG_MAX   ULONG_LONG_MAX
#endif

#endif /* __GNUC__ */

/**
 * ATTRIBUTE_UNUSED:
 *
 * Macro to flag conciously unused parameters to functions
 */
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED __attribute__((__unused__))
#endif

/**
 * ATTRIBUTE_FMT_PRINTF
 *
 * Macro used to check printf like functions, if compiling
 * with gcc.
 *
 * We use gnulib which guarentees we always have GNU style
 * printf format specifiers even on broken Win32 platforms
 * hence we have to force 'gnu_printf' for new GCC
 */
#ifndef ATTRIBUTE_FMT_PRINTF
#if __GNUC_PREREQ (4, 4)
#define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (gnu_printf, fmtpos,argpos)))
#else
#define ATTRIBUTE_FMT_PRINTF(fmtpos,argpos) __attribute__((__format__ (printf, fmtpos,argpos)))
#endif
#endif

#ifndef ATTRIBUTE_RETURN_CHECK
#if __GNUC_PREREQ (3, 4)
#define ATTRIBUTE_RETURN_CHECK __attribute__((__warn_unused_result__))
#else
#define ATTRIBUTE_RETURN_CHECK
#endif
#endif

#ifndef ATTRIBUTE_NONNULL
# if __GNUC_PREREQ (3, 3)
#  define ATTRIBUTE_NONNULL(m) __attribute__((__nonnull__(m)))
# else
#  define ATTRIBUTE_NONNULL(m)
# endif
#endif

#else
#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif
#ifndef ATTRIBUTE_FMT_PRINTF
#define ATTRIBUTE_FMT_PRINTF(...)
#endif
#ifndef ATTRIBUTE_RETURN_CHECK
#define ATTRIBUTE_RETURN_CHECK
#endif
#endif				/* __GNUC__ */

/*
 * Use this when passing possibly-NULL strings to printf-a-likes.
 */
#define NULLSTR(s) \
    ((void)verify_true(sizeof *(s) == sizeof (char)), \
     (s) ? (s) : "(null)")

/**
 * TODO:
 *
 * macro to flag unimplemented blocks
 */
#define TODO 								\
    fprintf(stderr, "Unimplemented block at %s:%d\n",			\
            __FILE__, __LINE__);

#endif                          /* __VIR_INTERNAL_H__ */
