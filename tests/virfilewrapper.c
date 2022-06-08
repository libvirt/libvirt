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

# include <fcntl.h>

# include "viralloc.h"
# include "virfilewrapper.h"
# include "virmock.h"


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
static int (*real_mkdir)(const char *path, mode_t mode);
static DIR *(*real_opendir)(const char *path);
static int (*real_execv)(const char *path, char *const argv[]);
static int (*real_execve)(const char *path, char *const argv[], char *const envp[]);

static void init_syms(void)
{
    if (real_fopen)
        return;

    VIR_MOCK_REAL_INIT(fopen);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT(mkdir);
    VIR_MOCK_REAL_INIT(open);
# if defined(__APPLE__) && defined(__x86_64__)
    VIR_MOCK_REAL_INIT_ALIASED(opendir, "opendir$INODE64");
# else
    VIR_MOCK_REAL_INIT(opendir);
# endif
    VIR_MOCK_REAL_INIT(execv);
    VIR_MOCK_REAL_INIT(execve);
}


void
virFileWrapperAddPrefix(const char *prefix,
                        const char *override)
{
    /* Both parameters are mandatory */
    if (!prefix || !override) {
        fprintf(stderr, "Attempt to add invalid path override\n");
        abort();
    }

    init_syms();

    VIR_APPEND_ELEMENT(prefixes, nprefixes, prefix);
    VIR_APPEND_ELEMENT(overrides, noverrides, override);
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

# include "virmockstathelpers.c"

int
virMockStatRedirect(const char *path, char **newpath)
{
    size_t i = 0;

    for (i = 0; i < noverrides; i++) {
        const char *tmp = STRSKIP(path, prefixes[i]);

        if (!tmp)
            continue;

        *newpath = g_strdup_printf("%s%s", overrides[i], tmp);
        break;
    }

    return 0;
}


# define PATH_OVERRIDE(newpath, path) \
    do { \
        init_syms(); \
 \
        if (virMockStatRedirect(path, &newpath) < 0) \
            abort(); \
    } while (0)


FILE *fopen(const char *path, const char *mode)
{
    g_autofree char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    return real_fopen(newpath ? newpath : path, mode);
}

int access(const char *path, int mode)
{
    g_autofree char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    return real_access(newpath ? newpath : path, mode);
}

int open(const char *path, int flags, ...)
{
    g_autofree char *newpath = NULL;
    va_list ap;
    mode_t mode = 0;

    PATH_OVERRIDE(newpath, path);

    /* The mode argument is mandatory when O_CREAT is set in flags,
     * otherwise the argument is ignored.
     */
    if (flags & O_CREAT) {
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }

    return real_open(newpath ? newpath : path, flags, mode);
}

DIR *opendir(const char *path)
{
    g_autofree char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    return real_opendir(newpath ? newpath : path);
}

int execv(const char *path, char *const argv[])
{
    g_autofree char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    return real_execv(newpath ? newpath : path, argv);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    g_autofree char *newpath = NULL;

    PATH_OVERRIDE(newpath, path);

    return real_execve(newpath ? newpath : path, argv, envp);
}

#endif
