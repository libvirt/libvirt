/*
 * Copyright (C) 2016 Red Hat, Inc.
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
 * Author: Michal Privoznik <mprivozn@redhat.com>
 */

#include <config.h>

#include "virmock.h"
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include "internal.h"
#include "configmake.h"

static int (*real_open)(const char *path, int flags, ...);
static FILE *(*real_fopen)(const char *path, const char *mode);
static int (*real_access)(const char *path, int mode);
static int (*real_stat)(const char *path, struct stat *sb);
static int (*real___xstat)(int ver, const char *path, struct stat *sb);
static int (*real_lstat)(const char *path, struct stat *sb);
static int (*real___lxstat)(int ver, const char *path, struct stat *sb);

static void init_syms(void)
{
    if (real_open)
        return;

    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(fopen);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT_ALT(stat, __xstat);
    VIR_MOCK_REAL_INIT_ALT(lstat, __lxstat);
}

static void
checkPath(const char *path ATTRIBUTE_UNUSED)
{
    /* Nada */
}


int open(const char *path, int flags, ...)
{
    int ret;

    init_syms();

    checkPath(path);

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = real_open(path, flags, mode);
    } else {
        ret = real_open(path, flags);
    }
    return ret;
}

FILE *fopen(const char *path, const char *mode)
{
    init_syms();

    checkPath(path);

    return real_fopen(path, mode);
}


int access(const char *path, int mode)
{
    init_syms();

    checkPath(path);

    return real_access(path, mode);
}

int stat(const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_STAT(_STAT_VER, path, sb);
}

int
__xstat(int ver, const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_STAT(ver, path, sb);
}

int
lstat(const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_LSTAT(_STAT_VER, path, sb);
}

int
__lxstat(int ver, const char *path, struct stat *sb)
{
    init_syms();

    checkPath(path);

    return VIR_MOCK_CALL_LSTAT(ver, path, sb);
}
