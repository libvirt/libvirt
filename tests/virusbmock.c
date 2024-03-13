/*
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
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>

#include "virmock.h"

#define USB_SYSFS "/sys/bus/usb"
#define FAKE_USB_SYSFS "virusbtestdata/sys_bus_usb"

static int (*real_open)(const char *pathname, int flags, ...);
#if WITH___OPEN_2
static int (*real___open_2)(const char *path, int flags);
#endif
static DIR *(*real_opendir)(const char *name);

static void init_syms(void)
{
    if (real_open)
        return;

    VIR_MOCK_REAL_INIT(open);
#if WITH___OPEN_2
    VIR_MOCK_REAL_INIT(__open_2);
#endif
    VIR_MOCK_REAL_INIT(opendir);
}

static char *get_fake_path(const char *real_path)
{
    const char *p = NULL;
    char *path = NULL;

    if ((p = STRSKIP(real_path, USB_SYSFS)))
        path = g_strdup_printf("%s/%s/%s", abs_srcdir, FAKE_USB_SYSFS, p);
    else if (!p)
        path = g_strdup(real_path);

    return path;
}

DIR *opendir(const char *name)
{
    g_autofree char *path = NULL;

    init_syms();

    path = get_fake_path(name);

    return real_opendir(path);
}

int open(const char *pathname, int flags, ...)
{
    g_autofree char *path = NULL;
    int ret;
    va_list ap;
    mode_t mode = 0;

    init_syms();

    path = get_fake_path(pathname);
    if (!path)
        return -1;

    /* The mode argument is mandatory when O_CREAT is set in flags,
     * otherwise the argument is ignored.
     */
    if (flags & O_CREAT) {
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }

    ret = real_open(path, flags, mode);
    return ret;
}

#if WITH___OPEN_2
int
__open_2(const char *pathname, int flags)
{
    g_autofree char *path = NULL;

    init_syms();

    path = get_fake_path(pathname);
    if (!path)
        return -1;

    return real_open(path, flags);
}
#endif
