/*
 * virfilewrapper.c: Wrapper for universal file access
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

#include <config.h>

#ifndef WIN32

# include <stdio.h>
# include <stdlib.h>
# include <fcntl.h>

# include "viralloc.h"
# include "virfile.h"
# include "virfilewrapper.h"
# include "virmock.h"
# include "virstring.h"


/* Mapping for prefix overrides */
static size_t noverrides;
static const char **overrides;

/* nprefixes == noverrides, but two variables make it easier to use
 * VIR_*_ELEMENT macros */
static size_t nprefixes;
static const char **prefixes;

/* TODO: callbacks */


static int (*real_open)(const char *path, int flags, ...);
static FILE *(*real_fopen)(const char *path, const char *mode);
static int (*real_access)(const char *path, int mode);
static int (*real_stat)(const char *path, struct stat *sb);
static int (*real___xstat)(int ver, const char *path, struct stat *sb);
static int (*real_lstat)(const char *path, struct stat *sb);
static int (*real___lxstat)(int ver, const char *path, struct stat *sb);
static int (*real_mkdir)(const char *path, mode_t mode);
static DIR *(*real_opendir)(const char *path);

static void init_syms(void)
{
    if (real_fopen)
        return;

    VIR_MOCK_REAL_INIT(fopen);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT_ALT(lstat, __lxstat);
    VIR_MOCK_REAL_INIT_ALT(stat, __xstat);
    VIR_MOCK_REAL_INIT(mkdir);
    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(opendir);
}


int
virFileWrapperAddPrefix(const char *prefix,
                     const char *override)
{
    /* Both parameters are mandatory */
    if (!prefix || !override)
        return -1;

    init_syms();

    if (VIR_APPEND_ELEMENT_QUIET(prefixes, nprefixes, prefix) < 0 ||
        VIR_APPEND_ELEMENT_QUIET(overrides, noverrides, override) < 0) {
        VIR_FREE(prefixes);
        VIR_FREE(overrides);
        return -1;
    }

    return 0;
}


void
virFileWrapperRemovePrefix(const char *prefix)
{
    size_t i = 0;

    for (i = 0; i < noverrides; i++) {
        if (STREQ(prefixes[i], prefix))
            break;
    }

    if (i == noverrides)
        return;

    VIR_DELETE_ELEMENT(overrides, i, noverrides);
    VIR_DELETE_ELEMENT(prefixes, i, nprefixes);
}

void
virFileWrapperClearPrefixes(void)
{
    nprefixes = 0;
    noverrides = 0;

    VIR_FREE(prefixes);
    VIR_FREE(overrides);
}

static char *
virFileWrapperOverridePrefix(const char *path)
{
    char *ret = NULL;
    size_t i = 0;

    for (i = 0; i < noverrides; i++) {
        const char *tmp = STRSKIP(path, prefixes[i]);

        if (!tmp)
            continue;

        if (virAsprintfQuiet(&ret, "%s%s", overrides[i], tmp) < 0)
            return NULL;

        break;
    }

    if (!ret)
        ignore_value(VIR_STRDUP_QUIET(ret, path));

    return ret;
}


# define PATH_OVERRIDE(newpath, path)                   \
    do {                                                \
        init_syms();                                    \
                                                        \
        newpath = virFileWrapperOverridePrefix(path);      \
        if (!newpath)                                   \
            abort();                                    \
    } while (0)


FILE *fopen(const char *path, const char *mode)
{
    FILE *ret = NULL;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_fopen(newpath, mode);

    VIR_FREE(newpath);

    return ret;
}

int access(const char *path, int mode)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_access(newpath, mode);

    VIR_FREE(newpath);

    return ret;
}

# ifdef HAVE___LXSTAT
int __lxstat(int ver, const char *path, struct stat *sb)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real___lxstat(ver, newpath, sb);

    VIR_FREE(newpath);

    return ret;
}
# endif /* HAVE___LXSTAT */

int lstat(const char *path, struct stat *sb)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_lstat(newpath, sb);

    VIR_FREE(newpath);

    return ret;
}

# ifdef HAVE___XSTAT
int __xstat(int ver, const char *path, struct stat *sb)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real___xstat(ver, newpath, sb);

    VIR_FREE(newpath);

    return ret;
}
# endif /* HAVE___XSTAT */

int stat(const char *path, struct stat *sb)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_stat(newpath, sb);

    VIR_FREE(newpath);

    return ret;
}

int mkdir(const char *path, mode_t mode)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_mkdir(newpath, mode);

    VIR_FREE(newpath);

    return ret;
}

int open(const char *path, int flags, ...)
{
    int ret = -1;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_open(newpath, flags);

    VIR_FREE(newpath);

    return ret;
}

DIR *opendir(const char *path)
{
    DIR *ret = NULL;
    char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    ret = real_opendir(newpath);

    VIR_FREE(newpath);

    return ret;
}
#endif
