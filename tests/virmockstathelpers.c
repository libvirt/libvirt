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
 *
 * Helpers for dealing with the many variants of stat(). This
 * C file should be included from any file that wants to mock
 * stat() correctly.
 */

#include "virmock.h"

#include <sys/stat.h>
#include <unistd.h>

/*
 * The POSIX stat() function might resolve to any number of different
 * symbols in the C library.
 *
 * The may be an additional stat64() function exposed by the headers
 * too.
 *
 * On 64-bit hosts the stat & stat64 functions are identical, always
 * referring to the 64-bit ABI.
 *
 * On 32-bit hosts they refer to the 32-bit & 64-bit ABIs respectively.
 *
 * With meson libvirt will have _FILE_OFFSET_BITS=64 always defined.
 * On 32-bit hosts it causes the C library to transparently rewrite
 * stat() calls to be stat64() calls. Libvirt will never see the 32-bit
 * ABI from the traditional stat() call. We cannot assume this rewriting
 * is done using a macro. It might be, but on GLibC it is done with a
 * magic __asm__ statement to apply the rewrite at link time instead of
 * at preprocessing.
 *
 * In GLibC there may be two additional functions exposed by the headers,
 * __xstat() and __xstat64(). When these exist, stat() and stat64() are
 * transparently rewritten to call __xstat() and __xstat64() respectively.
 * The former symbols will not actually exist in the library at all, only
 * the header. The leading "__" indicates the symbols are a private impl
 * detail of the C library that applications should not care about.
 * Unfortunately, because we are trying to mock replace the C library,
 * we need to know about this internal impl detail.
 *
 * Furthermore, support for 64-bit time can be enabled, which on 32-bit
 * systems with glibc overwrites stat64() to __stat64_time64() and lstat64()
 * to __lstat64_time64().
 *
 * On macOS stat() and lstat() are resolved to _stat$INODE64 and
 * _lstat$INODE64, respectively. stat(2) man page also declares that
 * stat64(), lstat64() and fstat64() are deprecated, and when
 * building on Apple Silicon (aarch64) those functions are missing
 * from the header altogether and should not be mocked.
 *
 * With all this in mind the list of functions we have to mock will depend
 * on several factors
 *
 *  - If the stat or __xstat but there is no 64-bit version.
 *
 *  - If __xstat & __xstat64 exist, then stat & stat64 will not exist
 *    as symbols in the library, so the latter should not be mocked.
 *
 *  - If __xstat exists in the library, but not the header than it
 *    it is just there for binary back compat and should not be
 *    mocked
 *
 * The same all applies to lstat()
 */

#if !defined(__APPLE__)
# if !defined(WITH___XSTAT_DECL)
#  if defined(WITH_STAT)
#   if !defined(WITH___XSTAT) && !defined(WITH_STAT64)
#    define MOCK_STAT
#   endif
#  endif
#  if defined(WITH_STAT64)
#   define MOCK_STAT64
#  endif
# else /* WITH___XSTAT_DECL */
#  if defined(WITH___XSTAT) && !defined(WITH___XSTAT64)
#   define MOCK___XSTAT
#  endif
#  if defined(WITH___XSTAT64)
#   define MOCK___XSTAT64
#  endif
# endif /* WITH___XSTAT_DECL */
# if !defined(WITH___LXSTAT_DECL)
#  if defined(WITH_LSTAT)
#   if !defined(WITH___LXSTAT) && !defined(WITH_LSTAT64)
#    define MOCK_LSTAT
#   endif
#  endif
#  if defined(WITH_LSTAT64)
#   define MOCK_LSTAT64
#  endif
# else /* WITH___LXSTAT_DECL */
#  if defined(WITH___LXSTAT) && !defined(WITH___LXSTAT64)
#   define MOCK___LXSTAT
#  endif
#  if defined(WITH___LXSTAT64)
#   define MOCK___LXSTAT64
#  endif
# endif /* WITH___LXSTAT_DECL */
#else /* __APPLE__ */
# define MOCK_STAT
# if defined(WITH_STAT64_DECL)
#  define MOCK_STAT64
# endif
# define MOCK_LSTAT
# if defined(WITH_LSTAT64_DECL)
#  define MOCK_LSTAT64
# endif
#endif

#if !defined(MOCK_STAT) && !defined(MOCK_STAT64) && \
    !defined(MOCK___XSTAT) && !defined(MOCK___XSTAT64)
# define MOCK_STAT
#endif

#if !defined(MOCK_LSTAT) && !defined(MOCK_LSTAT64) && \
    !defined(MOCK___LXSTAT) && !defined(MOCK___LXSTAT64)
# define MOCK_LSTAT
#endif

#ifdef MOCK_STAT
static int (*real_stat)(const char *path, struct stat *sb);
#endif
#ifdef MOCK_STAT64
static int (*real_stat64)(const char *path, struct stat64 *sb);
#endif
#ifdef MOCK___XSTAT
static int (*real___xstat)(int ver, const char *path, struct stat *sb);
#endif
#ifdef MOCK___XSTAT64
static int (*real___xstat64)(int ver, const char *path, struct stat64 *sb);
#endif
#ifdef MOCK_LSTAT
static int (*real_lstat)(const char *path, struct stat *sb);
#endif
#ifdef MOCK_LSTAT64
static int (*real_lstat64)(const char *path, struct stat64 *sb);
#endif
#ifdef MOCK___LXSTAT
static int (*real___lxstat)(int ver, const char *path, struct stat *sb);
#endif
#ifdef MOCK___LXSTAT64
static int (*real___lxstat64)(int ver, const char *path, struct stat64 *sb);
#endif

static bool init;
static bool debug;

#define fdebug(msg, ...) do { if (debug) fprintf(stderr, msg, __VA_ARGS__); } while (0)

static void virMockStatInit(void)
{
    if (init)
        return;

    init = true;
    debug = getenv("VIR_MOCK_STAT_DEBUG");

#ifdef MOCK_STAT
# if defined(__APPLE__) && defined(__x86_64__)
    VIR_MOCK_REAL_INIT_ALIASED(stat, "stat$INODE64");
# else
    VIR_MOCK_REAL_INIT(stat);
# endif
    fdebug("real stat %p\n", real_stat);
#endif
#ifdef MOCK_STAT64
# if defined(__GLIBC__) && defined(_TIME_BITS) && _TIME_BITS == 64
    VIR_MOCK_REAL_INIT_ALIASED(stat64, "__stat64_time64");
# else
    VIR_MOCK_REAL_INIT(stat64);
# endif
    fdebug("real stat64 %p\n", real_stat64);
#endif
#ifdef MOCK___XSTAT
    VIR_MOCK_REAL_INIT(__xstat);
    fdebug("real __xstat %p\n", real___xstat);
#endif
#ifdef MOCK___XSTAT64
    VIR_MOCK_REAL_INIT(__xstat64);
    fdebug("real __xstat64 %p\n", real___xstat64);
#endif
#ifdef MOCK_LSTAT
# if defined(__APPLE__) && defined(__x86_64__)
    VIR_MOCK_REAL_INIT_ALIASED(lstat, "lstat$INODE64");
# else
    VIR_MOCK_REAL_INIT(lstat);
# endif
    fdebug("real lstat %p\n", real_lstat);
#endif
#ifdef MOCK_LSTAT64
# if defined(__GLIBC__) && defined(_TIME_BITS) && _TIME_BITS == 64
    VIR_MOCK_REAL_INIT_ALIASED(lstat64, "__lstat64_time64");
# else
    VIR_MOCK_REAL_INIT(lstat64);
# endif
    fdebug("real lstat64 %p\n", real_lstat64);
#endif
#ifdef MOCK___LXSTAT
    VIR_MOCK_REAL_INIT(__lxstat);
    fdebug("real __lxstat %p\n", real___lxstat);
#endif
#ifdef MOCK___LXSTAT64
    VIR_MOCK_REAL_INIT(__lxstat64);
    fdebug("real __lxstat64 %p\n", real___lxstat64);
#endif
}

/*
 * @stat: the path being queried
 * @newpath: fill with redirected path, or leave NULL to use orig path
 *
 * Return 0 on success, -1 on allocation error
 */
static int virMockStatRedirect(const char *path, char **newpath);

#ifndef VIR_MOCK_STAT_HOOK
# define VIR_MOCK_STAT_HOOK do { } while (0)
#endif

#ifdef MOCK_STAT
int stat(const char *path, struct stat *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("stat redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real_stat(newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK_STAT64
int stat64(const char *path, struct stat64 *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("stat64 redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real_stat64(newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK___XSTAT
int
__xstat(int ver, const char *path, struct stat *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("__xstat redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real___xstat(ver, newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK___XSTAT64
int
__xstat64(int ver, const char *path, struct stat64 *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("__xstat64 redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real___xstat64(ver, newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK_LSTAT
int
lstat(const char *path, struct stat *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("lstat redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real_lstat(newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK_LSTAT64
int
lstat64(const char *path, struct stat64 *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("lstat64 redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real_lstat64(newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK___LXSTAT
int
__lxstat(int ver, const char *path, struct stat *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("__lxstat redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real___lxstat(ver, newpath ? newpath : path, sb);
}
#endif

#ifdef MOCK___LXSTAT64
int
__lxstat64(int ver, const char *path, struct stat64 *sb)
{
    g_autofree char *newpath = NULL;

    virMockStatInit();

    if (virMockStatRedirect(path, &newpath) < 0)
        abort();
    fdebug("__lxstat64 redirect %s to %s sb=%p\n", path, newpath ? newpath : path, sb);

    VIR_MOCK_STAT_HOOK;

    return real___lxstat64(ver, newpath ? newpath : path, sb);
}
#endif
