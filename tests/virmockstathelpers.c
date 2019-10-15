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
#include "viralloc.h"

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
 * refering to the 64-bit ABI.
 *
 * On 32-bit hosts they refer to the 32-bit & 64-bit ABIs respectively.
 *
 * Libvirt uses _FILE_OFFSET_BITS=64 on 32-bit hosts, which causes the
 * C library to transparently rewrite stat() calls to be stat64() calls.
 * Libvirt will never see the 32-bit ABI from the traditional stat()
 * call. We cannot assume this rewriting is done using a macro. It might
 * be, but on GLibC it is done with a magic __asm__ statement to apply
 * the rewrite at link time instead of at preprocessing.
 *
 * In GLibC there may be two additional functions exposed by the headers,
 * __xstat() and __xstat64(). When these exist, stat() and stat64() are
 * transparently rewritten to call __xstat() and __xstat64() respectively.
 * The former symbols will not actally exist in the library at all, only
 * the header. The leading "__" indicates the symbols are a private impl
 * detail of the C library that applications should not care about.
 * Unfortunately, because we are trying to mock replace the C library,
 * we need to know about this internal impl detail.
 *
 * With all this in mind the list of functions we have to mock will depend
 * on several factors
 *
 *  - If _FILE_OFFSET_BITS is set, then we are on a 32-bit host, and we
 *    only need to mock stat64 and __xstat64. The other stat / __xstat
 *    functions exist, but we'll never call them so they can be ignored
 *    for mocking.
 *
 *  - If _FILE_OFFSET_BITS is not set, then we are on a 64-bit host and
 *    we should mock stat, stat64, __xstat & __xstat64. Either may be
 *    called by app code.
 *
 *  - If __xstat & __xstat64 exist, then stat & stat64 will not exist
 *    as symbols in the library, so the latter should not be mocked.
 *
 * The same all applies to lstat()
 */



#if defined(HAVE_STAT) && !defined(HAVE___XSTAT) && !defined(_FILE_OFFSET_BITS)
# define MOCK_STAT
#endif
#if defined(HAVE_STAT64) && !defined(HAVE___XSTAT64)
# define MOCK_STAT64
#endif
#if defined(HAVE___XSTAT) && !defined(_FILE_OFFSET_BITS)
# define MOCK___XSTAT
#endif
#if defined(HAVE___XSTAT64)
# define MOCK___XSTAT64
#endif
#if defined(HAVE_LSTAT) && !defined(HAVE___LXSTAT) && !defined(_FILE_OFFSET_BITS)
# define MOCK_LSTAT
#endif
#if defined(HAVE_LSTAT64) && !defined(HAVE___LXSTAT64)
# define MOCK_LSTAT64
#endif
#if defined(HAVE___LXSTAT) && !defined(_FILE_OFFSET_BITS)
# define MOCK___LXSTAT
#endif
#if defined(HAVE___LXSTAT64)
# define MOCK___LXSTAT64
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
# ifdef __APPLE__
    VIR_MOCK_REAL_INIT_ALIASED(stat, "stat$INODE64");
# else
    VIR_MOCK_REAL_INIT(stat);
# endif
    fdebug("real stat %p\n", real_stat);
#endif
#ifdef MOCK_STAT64
    VIR_MOCK_REAL_INIT(stat64);
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
# ifdef __APPLE__
    VIR_MOCK_REAL_INIT_ALIASED(stat, "lstat$INODE64");
# else
    VIR_MOCK_REAL_INIT(lstat);
# endif
    fdebug("real lstat %p\n", real_lstat);
#endif
#ifdef MOCK_LSTAT64
    VIR_MOCK_REAL_INIT(lstat64);
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
# ifdef __APPLE__
int _stat(const char *path, struct stat *sb) __asm("_stat$INODE64");
int _stat(const char *path, struct stat *sb)
# else
int stat(const char *path, struct stat *sb)
# endif
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
# ifdef __APPLE__
int _lstat(const char *path, struct stat *sb) __asm("_lstat$INODE64");
int _lstat(const char *path, struct stat *sb)
# else
int
lstat(const char *path, struct stat *sb)
# endif
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
