/*
 * Copyright (C) 2013 Red Hat, Inc.
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

#ifdef __linux__
# include "internal.h"
# include <stdio.h>
# include <dlfcn.h>
# include <stdlib.h>
# include <unistd.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <stdarg.h>
# include "viralloc.h"
# include "virstring.h"
# include "virfile.h"

static int (*realaccess)(const char *path, int mode);
static int (*reallstat)(const char *path, struct stat *sb);
static int (*real__lxstat)(int ver, const char *path, struct stat *sb);
static int (*realopen)(const char *path, int flags, ...);

/* Don't make static, since it causes problems with clang
 * when passed as an arg to virAsprintf()
 * vircgroupmock.c:462:22: error: static variable 'fakesysfsdir' is used in an inline function with external linkage [-Werror,-Wstatic-in-inline]
 */
char *fakesysfsdir;

# define PCI_SYSFS_PREFIX "/sys/bus/pci/"

# define STDERR(...)                                                    \
    fprintf(stderr, "%s %zu: ", __FUNCTION__, (size_t) __LINE__);       \
    fprintf(stderr, __VA_ARGS__);                                       \
    fprintf(stderr, "\n");                                              \

# define ABORT(...)                                                     \
    do {                                                                \
        STDERR(__VA_ARGS__);                                            \
        abort();                                                        \
    } while (0)

# define ABORT_OOM()                                                    \
    ABORT("Out of memory")
/*
 * The plan:
 *
 * Mock some file handling functions. Redirect them into a stub tree passed via
 * LIBVIRT_FAKE_SYSFS_DIR env variable. All files and links within stub tree is
 * created by us.
 */

/*
 *
 * Functions to model kernel behavior
 *
 */

struct pciDevice {
    char *id;
    int vendor;
    int device;
};

struct pciDevice **pciDevices = NULL;
size_t nPciDevices = 0;

static void init_env(void);

static void pci_device_new_from_stub(const struct pciDevice *data);


/*
 * Helper functions
 */
static void
make_file(const char *path,
          const char *name,
          const char *value)
{
    int fd = -1;
    char *filepath = NULL;

    if (virAsprintfQuiet(&filepath, "%s/%s", path, name) < 0)
        ABORT_OOM();

    if ((fd = realopen(filepath, O_CREAT|O_WRONLY, 0666)) < 0)
        ABORT("Unable to open: %s", filepath);

    if (value && safewrite(fd, value, strlen(value)) != strlen(value))
        ABORT("Unable to write: %s", filepath);

    VIR_FORCE_CLOSE(fd);
    VIR_FREE(filepath);
}

static int
getrealpath(char **newpath,
            const char *path)
{
    if (!fakesysfsdir)
        init_env();

    if (STRPREFIX(path, PCI_SYSFS_PREFIX)) {
        if (virAsprintfQuiet(newpath, "%s/%s",
                             fakesysfsdir,
                             path + strlen(PCI_SYSFS_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
    } else {
        if (VIR_STRDUP_QUIET(*newpath, path) < 0)
            return -1;
    }

    return 0;
}


/*
 * PCI Device functions
 */
static void
pci_device_new_from_stub(const struct pciDevice *data)
{
    struct pciDevice *dev;
    char *devpath;
    char tmp[32];

    if (VIR_ALLOC_QUIET(dev) < 0 ||
        virAsprintfQuiet(&devpath, "%s/devices/%s", fakesysfsdir, data->id) < 0)
        ABORT_OOM();

    memcpy(dev, data, sizeof(*dev));

    if (virFileMakePath(devpath) < 0)
        ABORT("Unable to create: %s", devpath);

    make_file(devpath, "config", "some dummy config");

    if (snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->vendor) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "vendor", tmp);

    if (snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->device) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "device", tmp);

    if (VIR_APPEND_ELEMENT_QUIET(pciDevices, nPciDevices, dev) < 0)
        ABORT_OOM();

    VIR_FREE(devpath);
}


/*
 * Functions to load the symbols and init the environment
 */
static void
init_syms(void)
{
    if (realaccess)
        return;

# define LOAD_SYM(name)                                                 \
    do {                                                                \
        if (!(real ## name = dlsym(RTLD_NEXT, #name)))                  \
            ABORT("Cannot find real '%s' symbol\n", #name);             \
    } while (0)

# define LOAD_SYM_ALT(name1, name2)                                     \
    do {                                                                \
        if (!(real ## name1 = dlsym(RTLD_NEXT, #name1)) &&              \
            !(real ## name2 = dlsym(RTLD_NEXT, #name2)))                \
            ABORT("Cannot find real '%s' or '%s' symbol\n",             \
                  #name1, #name2);                                      \
    } while (0)

    LOAD_SYM(access);
    LOAD_SYM_ALT(lstat, __lxstat);
    LOAD_SYM(open);
}

static void
init_env(void)
{
    if (fakesysfsdir)
        return;

    if (!(fakesysfsdir = getenv("LIBVIRT_FAKE_SYSFS_DIR")))
        ABORT("Missing LIBVIRT_FAKE_SYSFS_DIR env variable\n");

# define MAKE_PCI_DEVICE(Id, Vendor, Device, ...)                       \
    do {                                                                \
        struct pciDevice dev = {.id = (char *)Id, .vendor = Vendor,     \
                                .device = Device, __VA_ARGS__};         \
        pci_device_new_from_stub(&dev);                                 \
    } while (0)

    MAKE_PCI_DEVICE("0000:00:00.0", 0x8086, 0x0044);
}


/*
 *
 * Mocked functions
 *
 */

int
access(const char *path, int mode)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, PCI_SYSFS_PREFIX)) {
        char *newpath;
        if (getrealpath(&newpath, path) < 0)
            return -1;
        ret = realaccess(newpath, mode);
        VIR_FREE(newpath);
    } else {
        ret = realaccess(path, mode);
    }
    return ret;
}

int
__lxstat(int ver, const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, PCI_SYSFS_PREFIX)) {
        char *newpath;
        if (getrealpath(&newpath, path) < 0)
            return -1;
        ret = real__lxstat(ver, newpath, sb);
        VIR_FREE(newpath);
    } else {
        ret = real__lxstat(ver, path, sb);
    }
    return ret;
}

int
lstat(const char *path, struct stat *sb)
{
    int ret;

    init_syms();

    if (STRPREFIX(path, PCI_SYSFS_PREFIX)) {
        char *newpath;
        if (getrealpath(&newpath, path) < 0)
            return -1;
        ret = reallstat(newpath, sb);
        VIR_FREE(newpath);
    } else {
        ret = reallstat(path, sb);
    }
    return ret;
}

int
open(const char *path, int flags, ...)
{
    int ret;
    char *newpath = NULL;

    init_syms();

    if (STRPREFIX(path, PCI_SYSFS_PREFIX) &&
        getrealpath(&newpath, path) < 0)
        return -1;

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = va_arg(ap, mode_t);
        va_end(ap);
        ret = realopen(newpath ? newpath : path, flags, mode);
    } else {
        ret = realopen(newpath ? newpath : path, flags);
    }
    VIR_FREE(newpath);
    return ret;
}

#else
/* Nothing to override on non-__linux__ platforms */
#endif
