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
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "virmock.h"
#include "virfile.h"

#define USB_SYSFS "/sys/bus/usb"
#define FAKE_USB_SYSFS "virusbtestdata/sys_bus_usb"
#define USB_DEVFS "/dev/bus/usb/"

/* Device node of the test device that is present in the fake sysfs but is
 * meant to be inaccessible in the current mount namespace (usb4, i.e. the
 * root hub 1d6b:0003 on bus 4).  See virusbtest.c. */
#define INACCESSIBLE_USB_NODE USB_DEVFS "004/001"

static int (*real_open)(const char *pathname, int flags, ...);
#if WITH___OPEN_2
static int (*real___open_2)(const char *path, int flags);
#endif
static DIR *(*real_opendir)(const char *name);
static int (*real_access)(const char *path, int mode);
static char *(*real_virFileCanonicalizePath)(const char *path);

static void init_syms(void)
{
    if (real_open)
        return;

#if defined(__GLIBC__) && defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
    VIR_MOCK_REAL_INIT_ALIASED(open, "open64");
#else
    VIR_MOCK_REAL_INIT(open);
#endif
#if WITH___OPEN_2
    VIR_MOCK_REAL_INIT(__open_2);
#endif
    VIR_MOCK_REAL_INIT(opendir);
    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT(virFileCanonicalizePath);
}

static char *get_fake_path(const char *real_path)
{
    const char *p = NULL;
    char *path = NULL;

    if ((p = STRSKIP(real_path, USB_SYSFS)))
        path = g_strdup_printf("%s/%s/%s", abs_srcdir, FAKE_USB_SYSFS, p);
    else
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

int access(const char *path, int mode)
{
    init_syms();

    /* virUSBDeviceSearch() checks whether the /dev/bus/usb node of a device
     * found in sysfs is accessible.  There are no such nodes in the test
     * environment, so pretend every USB device node exists, except the one
     * device that is meant to be inaccessible in the current mount namespace
     * (as happens inside a container).  This lets us exercise the code path
     * without shipping empty device-node files. */
    if (STRSKIP(path, USB_DEVFS)) {
        if (STREQ(path, INACCESSIBLE_USB_NODE)) {
            errno = ENOENT;
            return -1;
        }
        return 0;
    }

    return real_access(path, mode);
}

char *
virFileCanonicalizePath(const char *path)
{
    init_syms();

    /* Since we pretend any /dev/bus/usb node exists (see access() above) we
     * must also make sure to return an expected value here. */
    if (STRPREFIX(path, USB_DEVFS)) {
        return g_strdup(path);
    }

    return real_virFileCanonicalizePath(path);
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
