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
 *
 * Author: Jan Tomko <jtomko@redhat.com>
 */

#include <config.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>

#include "viralloc.h"
#include "virfile.h"
#include "virstring.h"
#include "virusb.h"

#define USB_SYSFS "/sys/bus/usb"
#define FAKE_USB_SYSFS "virusbtestdata/sys_bus_usb"

static int (*realopen)(const char *pathname, int flags, ...);
static DIR *(*realopendir)(const char *name);

static void init_syms(void)
{
    if (realopen)
        return;

    realopen = dlsym(RTLD_NEXT, "open");
    realopendir = dlsym(RTLD_NEXT, "opendir");
    if (!realopen || !realopendir) {
        fprintf(stderr, "Error getting symbols");
        abort();
    }
}

static char *get_fake_path(const char *real_path)
{
    const char *p = NULL;
    char *path = NULL;

    if ((p = STRSKIP(real_path, USB_SYSFS)) &&
        virAsprintfQuiet(&path, "%s/%s/%s", abs_srcdir, FAKE_USB_SYSFS, p) < 0)
        goto error;
    else if (!p && VIR_STRDUP_QUIET(path, real_path) < 0)
        goto error;

    return path;

 error:
    errno = ENOMEM;
    return NULL;
}

DIR *opendir(const char *name)
{
    char *path;
    DIR* ret;

    init_syms();

    path = get_fake_path(name);

    ret = realopendir(path);
    VIR_FREE(path);
    return ret;
}

int open(const char *pathname, int flags, ...)
{
    char *path;
    int ret;

    init_syms();

    path = get_fake_path(pathname);
    if (!path)
        return -1;
    ret = realopen(path, flags);
    VIR_FREE(path);
    return ret;
}
