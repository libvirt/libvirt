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
 */

#include <config.h>

#if defined(__linux__) || defined(__FreeBSD__)
# include "virmock.h"
# include <unistd.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <stdarg.h>
# include <dirent.h>
# include "viralloc.h"
# include "virstring.h"
# include "virfile.h"
# include "dirname.h"

static int (*real_access)(const char *path, int mode);
static int (*real_open)(const char *path, int flags, ...);
static int (*real_close)(int fd);
static DIR * (*real_opendir)(const char *name);
static char *(*real_virFileCanonicalizePath)(const char *path);

/* Don't make static, since it causes problems with clang
 * when passed as an arg to virAsprintf()
 * vircgroupmock.c:462:22: error: static variable 'fakesysfsdir' is used in an inline function with external linkage [-Werror,-Wstatic-in-inline]
 */
char *fakerootdir;
char *fakesysfspcidir;

# define SYSFS_PCI_PREFIX "/sys/bus/pci/"

# define STDERR(...) \
    fprintf(stderr, "%s %zu: ", __FUNCTION__, (size_t) __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \

# define ABORT(...) \
    do { \
        STDERR(__VA_ARGS__); \
        abort(); \
    } while (0)

# define ABORT_OOM() \
    ABORT("Out of memory")
/*
 * The plan:
 *
 * Mock some file handling functions. Redirect them into a stub tree passed via
 * LIBVIRT_FAKE_ROOT_DIR env variable. All files and links within stub tree is
 * created by us. There are some actions that we must take if some special
 * files are written to. Here's the list of files we watch:
 *
 * /sys/bus/pci/drivers/<driver>/new_id:
 *   Learn the driver new vendor and device combination.
 *   Data in format "VVVV DDDD".
 *
 * /sys/bus/pci/drivers/<driver>/remove_id
 *   Make the driver forget about vendor and device.
 *   Data in format "VVVV DDDD".
 *
 * /sys/bus/pci/drivers/<driver>/bind
 *   Check if driver supports the device and bind driver to it (create symlink
 *   called 'driver' pointing to the /sys/but/pci/drivers/<driver>).
 *   Data in format "DDDD:BB:DD.F" (Domain:Bus:Device.Function).
 *
 * /sys/bus/pci/drivers/<driver>/unbind
 *   Unbind driver from the device.
 *   Data in format "DDDD:BB:DD.F" (Domain:Bus:Device.Function).
 *
 * /sys/bus/pci/drivers_probe
 *   Probe for a driver that handles the specified device.
 *   Data in format "DDDD:BB:DD.F" (Domain:Bus:Device.Function).
 *
 * As a little hack, we are not mocking write to these files, but close()
 * instead. The advantage is we don't need any self growing array to hold the
 * partial writes and construct them back. We can let all the writes finish,
 * and then just read the file content back.
 */

/*
 *
 * Functions to model kernel behavior
 *
 */

enum driverActions {
    PCI_ACTION_BIND         = 1 << 0,
    PCI_ACTION_UNBIND       = 1 << 1,
    PCI_ACTION_NEW_ID       = 1 << 2,
    PCI_ACTION_REMOVE_ID    = 1 << 3,
};

struct pciDriver {
    char *name;
    int *vendor;        /* List of vendor:device IDs the driver can handle */
    int *device;
    size_t len;            /* @len is used for both @vendor and @device */
    unsigned int fail;  /* Bitwise-OR of driverActions that should fail */
};

struct pciDevice {
    char *id;
    int vendor;
    int device;
    int klass;
    int iommuGroup;
    struct pciDriver *driver;   /* Driver attached. NULL if attached to no driver */
};

struct fdCallback {
    int fd;
    char *path;
};

struct pciDevice **pciDevices = NULL;
size_t nPCIDevices = 0;

struct pciDriver **pciDrivers = NULL;
size_t nPCIDrivers = 0;

struct fdCallback *callbacks = NULL;
size_t nCallbacks = 0;

static void init_env(void);

static int pci_device_autobind(struct pciDevice *dev);
static void pci_device_new_from_stub(const struct pciDevice *data);
static struct pciDevice *pci_device_find_by_id(const char *id);
static struct pciDevice *pci_device_find_by_content(const char *path);

static void pci_driver_new(const char *name, int fail, ...);
static struct pciDriver *pci_driver_find_by_dev(struct pciDevice *dev);
static struct pciDriver *pci_driver_find_by_path(const char *path);
static int pci_driver_bind(struct pciDriver *driver, struct pciDevice *dev);
static int pci_driver_unbind(struct pciDriver *driver, struct pciDevice *dev);
static int pci_driver_handle_change(int fd, const char *path);
static int pci_driver_handle_bind(const char *path);
static int pci_driver_handle_unbind(const char *path);
static int pci_driver_handle_new_id(const char *path);
static int pci_driver_handle_remove_id(const char *path);


/*
 * Helper functions
 */
static void
make_file(const char *path,
          const char *name,
          const char *value,
          ssize_t len)
{
    int fd = -1;
    char *filepath = NULL;
    if (value && len == -1)
        len = strlen(value);

    if (virAsprintfQuiet(&filepath, "%s/%s", path, name) < 0)
        ABORT_OOM();

    if ((fd = real_open(filepath, O_CREAT|O_WRONLY, 0666)) < 0)
        ABORT("Unable to open: %s", filepath);

    if (value && safewrite(fd, value, len) != len)
        ABORT("Unable to write: %s", filepath);

    VIR_FORCE_CLOSE(fd);
    VIR_FREE(filepath);
}

static void
make_symlink(const char *path,
          const char *name,
          const char *target)
{
    char *filepath = NULL;

    if (virAsprintfQuiet(&filepath, "%s/%s", path, name) < 0)
        ABORT_OOM();

    if (symlink(target, filepath) < 0)
        ABORT("Unable to create symlink filepath -> target");

    VIR_FREE(filepath);
}

static int
pci_read_file(const char *path,
              char *buf,
              size_t buf_size)
{
    int ret = -1;
    int fd = -1;
    char *newpath;

    if (virAsprintfQuiet(&newpath, "%s/%s",
                         fakesysfspcidir,
                         path + strlen(SYSFS_PCI_PREFIX)) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    if ((fd = real_open(newpath, O_RDWR)) < 0)
        goto cleanup;

    bzero(buf, buf_size);
    if (saferead(fd, buf, buf_size - 1) < 0) {
        STDERR("Unable to read from %s", newpath);
        goto cleanup;
    }

    if (ftruncate(fd, 0) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(newpath);
    real_close(fd);
    return ret;
}

static int
getrealpath(char **newpath,
            const char *path)
{
    init_env();

    if (STRPREFIX(path, SYSFS_PCI_PREFIX)) {
        if (virAsprintfQuiet(newpath, "%s/%s",
                             fakesysfspcidir,
                             path + strlen(SYSFS_PCI_PREFIX)) < 0) {
            errno = ENOMEM;
            return -1;
        }
    } else {
        if (VIR_STRDUP_QUIET(*newpath, path) < 0)
            return -1;
    }

    return 0;
}

static bool
find_fd(int fd, size_t *indx)
{
    size_t i;

    for (i = 0; i < nCallbacks; i++) {
        if (callbacks[i].fd == fd) {
            if (indx)
                *indx = i;
            return true;
        }
    }

    return false;
}

static int
add_fd(int fd, const char *path)
{
    int ret = -1;
    size_t i;

    if (find_fd(fd, &i)) {
        struct fdCallback cb = callbacks[i];
        ABORT("FD %d %s already present in the array as %d %s",
              fd, path, cb.fd, cb.path);
    }

    if (VIR_REALLOC_N_QUIET(callbacks, nCallbacks + 1) < 0 ||
        VIR_STRDUP_QUIET(callbacks[nCallbacks].path, path) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    callbacks[nCallbacks++].fd = fd;
    ret = 0;
 cleanup:
    return ret;
}

static int
remove_fd(int fd)
{
    int ret = -1;
    size_t i;

    if (find_fd(fd, &i)) {
        struct fdCallback cb = callbacks[i];

        if (pci_driver_handle_change(cb.fd, cb.path) < 0)
            goto cleanup;

        VIR_FREE(cb.path);
        if (VIR_DELETE_ELEMENT(callbacks, i, nCallbacks) < 0) {
            errno = EINVAL;
            goto cleanup;
        }
    }

    ret = 0;
 cleanup:
    return ret;
}


/*
 * PCI Device functions
 */
static void
pci_device_new_from_stub(const struct pciDevice *data)
{
    struct pciDevice *dev;
    char *devpath;
    char *id;
    char *c;
    char *configSrc;
    char tmp[256];
    struct stat sb;
    bool configSrcExists = false;

    if (VIR_STRDUP_QUIET(id, data->id) < 0)
        ABORT_OOM();

    /* Replace ':' with '-' to create the config filename from the
     * device ID. The device ID cannot be used directly as filename
     * because it contains ':' and Windows does not allow ':' in
     * filenames. */
    c = strchr(id, ':');

    while (c) {
        *c = '-';
        c = strchr(c, ':');
    }

    if (VIR_ALLOC_QUIET(dev) < 0 ||
        virAsprintfQuiet(&configSrc, "%s/virpcitestdata/%s.config",
                         abs_srcdir, id) < 0 ||
        virAsprintfQuiet(&devpath, "%s/devices/%s", fakesysfspcidir, data->id) < 0)
        ABORT_OOM();

    VIR_FREE(id);
    memcpy(dev, data, sizeof(*dev));

    if (virFileMakePath(devpath) < 0)
        ABORT("Unable to create: %s", devpath);

    if (stat(configSrc, &sb) == 0)
        configSrcExists = true;

    /* If there is a config file for the device within virpcitestdata dir,
     * symlink it. Otherwise create a dummy config file. */
    if (configSrcExists) {
        /* On success, copy @configSrc into the destination (a copy,
         * rather than a symlink, is required since we write into the
         * file, and parallel VPATH builds must not stomp on the
         * original; besides, 'make distcheck' requires the original
         * to be read-only */
        char *buf;
        ssize_t len;

        if ((len = virFileReadAll(configSrc, 4096, &buf)) < 0)
            ABORT("Unable to read config file '%s'", configSrc);

        make_file(devpath, "config", buf, len);
        VIR_FREE(buf);
    } else {
        /* If there's no config data in the virpcitestdata dir, create a dummy
         * config file */
        make_file(devpath, "config", "some dummy config", -1);
    }

    if (snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->vendor) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "vendor", tmp, -1);

    if (snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->device) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "device", tmp, -1);

    if (snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->klass) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "class", tmp, -1);

    if (snprintf(tmp, sizeof(tmp),
                 "%s/../../../kernel/iommu_groups/%d",
                 devpath, dev->iommuGroup) < 0) {
        ABORT("@tmp overflow");
    }
    if (virFileMakePath(tmp) < 0)
        ABORT("Unable to create %s", tmp);

    if (snprintf(tmp, sizeof(tmp),
                 "../../../kernel/iommu_groups/%d", dev->iommuGroup) < 0) {
        ABORT("@tmp overflow");
    }
    make_symlink(devpath, "iommu_group", tmp);

    if (pci_device_autobind(dev) < 0)
        ABORT("Unable to bind: %s", data->id);

    if (VIR_APPEND_ELEMENT_QUIET(pciDevices, nPCIDevices, dev) < 0)
        ABORT_OOM();

    VIR_FREE(devpath);
    VIR_FREE(configSrc);
}

static struct pciDevice *
pci_device_find_by_id(const char *id)
{
    size_t i;
    for (i = 0; i < nPCIDevices; i++) {
        struct pciDevice *dev = pciDevices[i];

        if (STREQ(dev->id, id))
            return dev;
    }

    return NULL;
}

static struct pciDevice *
pci_device_find_by_content(const char *path)
{
    char tmp[32];

    if (pci_read_file(path, tmp, sizeof(tmp)) < 0)
        return NULL;

    return pci_device_find_by_id(tmp);
}

static int
pci_device_autobind(struct pciDevice *dev)
{
    struct pciDriver *driver = pci_driver_find_by_dev(dev);

    if (!driver) {
        /* No driver found. Nothing to do */
        return 0;
    }

    return pci_driver_bind(driver, dev);
}


/*
 * PCI Driver functions
 */
static void
pci_driver_new(const char *name, int fail, ...)
{
    struct pciDriver *driver;
    va_list args;
    int vendor, device;
    char *driverpath;

    if (VIR_ALLOC_QUIET(driver) < 0 ||
        VIR_STRDUP_QUIET(driver->name, name) < 0 ||
        virAsprintfQuiet(&driverpath, "%s/drivers/%s", fakesysfspcidir, name) < 0)
        ABORT_OOM();

    driver->fail = fail;

    if (virFileMakePath(driverpath) < 0)
        ABORT("Unable to create: %s", driverpath);

    va_start(args, fail);

    while ((vendor = va_arg(args, int)) != -1) {
        if ((device = va_arg(args, int)) == -1)
            ABORT("Invalid vendor device pair for driver %s", name);

        if (VIR_REALLOC_N_QUIET(driver->vendor, driver->len + 1) < 0 ||
            VIR_REALLOC_N_QUIET(driver->device, driver->len + 1) < 0)
            ABORT_OOM();

        driver->vendor[driver->len] = vendor;
        driver->device[driver->len] = device;
        driver->len++;
    }

    va_end(args);

    make_file(driverpath, "bind", NULL, -1);
    make_file(driverpath, "unbind", NULL, -1);
    make_file(driverpath, "new_id", NULL, -1);
    make_file(driverpath, "remove_id", NULL, -1);

    if (VIR_APPEND_ELEMENT_QUIET(pciDrivers, nPCIDrivers, driver) < 0)
        ABORT_OOM();

    VIR_FREE(driverpath);
}

static struct pciDriver *
pci_driver_find_by_dev(struct pciDevice *dev)
{
    size_t i;

    for (i = 0; i < nPCIDrivers; i++) {
        struct pciDriver *driver = pciDrivers[i];
        size_t j;

        for (j = 0; j < driver->len; j++) {
            if (driver->vendor[j] == dev->vendor &&
                driver->device[j] == dev->device)
                return driver;
        }
    }

    return NULL;
}

static struct pciDriver *
pci_driver_find_by_path(const char *path)
{
    size_t i;

    for (i = 0; i < nPCIDrivers; i++) {
        struct pciDriver *driver = pciDrivers[i];

        if (strstr(path, driver->name))
            return driver;
    }

    return NULL;
}

static int
pci_driver_bind(struct pciDriver *driver,
                struct pciDevice *dev)
{
    int ret = -1;
    char *devpath = NULL, *driverpath = NULL;

    if (dev->driver || PCI_ACTION_BIND & driver->fail) {
        /* Device already bound or failing driver requested */
        errno = ENODEV;
        return ret;
    }

    /* Make symlink under device tree */
    if (virAsprintfQuiet(&devpath, "%s/devices/%s/driver",
                         fakesysfspcidir, dev->id) < 0 ||
        virAsprintfQuiet(&driverpath, "%s/drivers/%s",
                         fakesysfspcidir, driver->name) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    if (symlink(driverpath, devpath) < 0)
        goto cleanup;

    /* Make symlink under driver tree */
    VIR_FREE(devpath);
    VIR_FREE(driverpath);
    if (virAsprintfQuiet(&devpath, "%s/devices/%s",
                         fakesysfspcidir, dev->id) < 0 ||
        virAsprintfQuiet(&driverpath, "%s/drivers/%s/%s",
                         fakesysfspcidir, driver->name, dev->id) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    if (symlink(devpath, driverpath) < 0)
        goto cleanup;

    dev->driver = driver;
    ret = 0;
 cleanup:
    VIR_FREE(devpath);
    VIR_FREE(driverpath);
    return ret;
}

static int
pci_driver_unbind(struct pciDriver *driver,
                  struct pciDevice *dev)
{
    int ret = -1;
    char *devpath = NULL, *driverpath = NULL;

    if (dev->driver != driver || PCI_ACTION_UNBIND & driver->fail) {
        /* Device not bound to the @driver or failing driver used */
        errno = ENODEV;
        return ret;
    }

    /* Make symlink under device tree */
    if (virAsprintfQuiet(&devpath, "%s/devices/%s/driver",
                         fakesysfspcidir, dev->id) < 0 ||
        virAsprintfQuiet(&driverpath, "%s/drivers/%s/%s",
                         fakesysfspcidir, driver->name, dev->id) < 0) {
        errno = ENOMEM;
        goto cleanup;
    }

    if (unlink(devpath) < 0 ||
        unlink(driverpath) < 0)
        goto cleanup;

    dev->driver = NULL;
    ret = 0;
 cleanup:
    VIR_FREE(devpath);
    VIR_FREE(driverpath);
    return ret;
}

static int
pci_driver_handle_drivers_probe(const char *path)
{
    struct pciDevice *dev;

    if (!(dev = pci_device_find_by_content(path))) {
        errno = ENODEV;
        return -1;
    }

    if (dev->driver)
        return 0;

    return pci_device_autobind(dev);
}

static int
pci_driver_handle_change(int fd ATTRIBUTE_UNUSED, const char *path)
{
    int ret;
    const char *file = last_component(path);

    if (STREQ(file, "bind"))
        ret = pci_driver_handle_bind(path);
    else if (STREQ(file, "unbind"))
        ret = pci_driver_handle_unbind(path);
    else if (STREQ(file, "new_id"))
        ret = pci_driver_handle_new_id(path);
    else if (STREQ(file, "remove_id"))
        ret = pci_driver_handle_remove_id(path);
    else if (STREQ(file, "drivers_probe"))
        ret = pci_driver_handle_drivers_probe(path);
    else
        ABORT("Not handled write to: %s", path);
    return ret;
}

static int
pci_driver_handle_bind(const char *path)
{
    int ret = -1;
    struct pciDevice *dev = pci_device_find_by_content(path);
    struct pciDriver *driver = pci_driver_find_by_path(path);

    if (!driver || !dev) {
        /* This should never happen (TM) */
        errno = ENODEV;
        goto cleanup;
    }

    ret = pci_driver_bind(driver, dev);
 cleanup:
    return ret;
}

static int
pci_driver_handle_unbind(const char *path)
{
    int ret = -1;
    struct pciDevice *dev = pci_device_find_by_content(path);

    if (!dev || !dev->driver) {
        /* This should never happen (TM) */
        errno = ENODEV;
        goto cleanup;
    }

    ret = pci_driver_unbind(dev->driver, dev);
 cleanup:
    return ret;
}
static int
pci_driver_handle_new_id(const char *path)
{
    int ret = -1;
    struct pciDriver *driver = pci_driver_find_by_path(path);
    size_t i;
    int vendor, device;
    char buf[32];

    if (!driver || PCI_ACTION_NEW_ID & driver->fail) {
        errno = ENODEV;
        goto cleanup;
    }

    if (pci_read_file(path, buf, sizeof(buf)) < 0)
        goto cleanup;

    if (sscanf(buf, "%x %x", &vendor, &device) < 2) {
        errno = EINVAL;
        goto cleanup;
    }

    for (i = 0; i < driver->len; i++) {
        if (driver->vendor[i] == vendor &&
            driver->device[i] == device)
            break;
    }

    if (i == driver->len) {
        if (VIR_REALLOC_N_QUIET(driver->vendor, driver->len + 1) < 0 ||
            VIR_REALLOC_N_QUIET(driver->device, driver->len + 1) < 0) {
            errno = ENOMEM;
            goto cleanup;
        }

        driver->vendor[driver->len] = vendor;
        driver->device[driver->len] = device;
        driver->len++;
    }

    for (i = 0; i < nPCIDevices; i++) {
        struct pciDevice *dev = pciDevices[i];

        if (!dev->driver &&
            dev->vendor == vendor &&
            dev->device == device &&
            pci_driver_bind(driver, dev) < 0)
                goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}

static int
pci_driver_handle_remove_id(const char *path)
{
    int ret = -1;
    struct pciDriver *driver = pci_driver_find_by_path(path);
    size_t i;
    int vendor, device;
    char buf[32];

    if (!driver || PCI_ACTION_REMOVE_ID & driver->fail) {
        errno = ENODEV;
        goto cleanup;
    }

    if (pci_read_file(path, buf, sizeof(buf)) < 0)
        goto cleanup;

    if (sscanf(buf, "%x %x", &vendor, &device) < 2) {
        errno = EINVAL;
        goto cleanup;
    }

    for (i = 0; i < driver->len; i++) {
        if (driver->vendor[i] == vendor &&
            driver->device[i] == device)
            continue;
    }

    if (i != driver->len) {
        if (VIR_DELETE_ELEMENT(driver->vendor, i, driver->len) < 0)
            goto cleanup;
        driver->len++;
        if (VIR_DELETE_ELEMENT(driver->device, i, driver->len) < 0)
            goto cleanup;
    }

    ret = 0;
 cleanup:
    return ret;
}


/*
 * Functions to load the symbols and init the environment
 */
static void
init_syms(void)
{
    if (real_access)
        return;

    VIR_MOCK_REAL_INIT(access);
    VIR_MOCK_REAL_INIT(open);
    VIR_MOCK_REAL_INIT(close);
    VIR_MOCK_REAL_INIT(opendir);
    VIR_MOCK_REAL_INIT(virFileCanonicalizePath);
}

static void
init_env(void)
{
    if (fakerootdir && fakesysfspcidir)
        return;

    if (!(fakerootdir = getenv("LIBVIRT_FAKE_ROOT_DIR")))
        ABORT("Missing LIBVIRT_FAKE_ROOT_DIR env variable\n");

    if (virAsprintfQuiet(&fakesysfspcidir, "%s%s",
                         fakerootdir, SYSFS_PCI_PREFIX) < 0)
        ABORT_OOM();

    if (virFileMakePath(fakesysfspcidir) < 0)
        ABORT("Unable to create: %s", fakesysfspcidir);

    make_file(fakesysfspcidir, "drivers_probe", NULL, -1);

# define MAKE_PCI_DRIVER(name, ...) \
    pci_driver_new(name, 0, __VA_ARGS__, -1, -1)

    MAKE_PCI_DRIVER("iwlwifi", 0x8086, 0x0044);
    MAKE_PCI_DRIVER("i915", 0x8086, 0x0046, 0x8086, 0x0047);
    MAKE_PCI_DRIVER("pci-stub", -1, -1);
    pci_driver_new("vfio-pci", PCI_ACTION_BIND, -1, -1);

# define MAKE_PCI_DEVICE(Id, Vendor, Device, ...) \
    do { \
        struct pciDevice dev = {.id = (char *)Id, .vendor = Vendor, \
                                .device = Device, __VA_ARGS__}; \
        pci_device_new_from_stub(&dev); \
    } while (0)

    MAKE_PCI_DEVICE("0000:00:00.0", 0x8086, 0x0044);
    MAKE_PCI_DEVICE("0000:00:01.0", 0x8086, 0x0044);
    MAKE_PCI_DEVICE("0000:00:02.0", 0x8086, 0x0046);
    MAKE_PCI_DEVICE("0000:00:03.0", 0x8086, 0x0048);
    MAKE_PCI_DEVICE("0001:00:00.0", 0x1014, 0x03b9, .klass = 0x060400);
    MAKE_PCI_DEVICE("0001:01:00.0", 0x8086, 0x105e, .iommuGroup = 0);
    MAKE_PCI_DEVICE("0001:01:00.1", 0x8086, 0x105e, .iommuGroup = 0);
    MAKE_PCI_DEVICE("0005:80:00.0", 0x10b5, 0x8112, .klass = 0x060400);
    MAKE_PCI_DEVICE("0005:90:01.0", 0x1033, 0x0035, .iommuGroup = 1);
    MAKE_PCI_DEVICE("0005:90:01.1", 0x1033, 0x0035, .iommuGroup = 1);
    MAKE_PCI_DEVICE("0005:90:01.2", 0x1033, 0x00e0, .iommuGroup = 1);
    MAKE_PCI_DEVICE("0000:0a:01.0", 0x8086, 0x0047);
    MAKE_PCI_DEVICE("0000:0a:02.0", 0x8286, 0x0048);
    MAKE_PCI_DEVICE("0000:0a:03.0", 0x8386, 0x0048);
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

    if (STRPREFIX(path, SYSFS_PCI_PREFIX)) {
        char *newpath;
        if (getrealpath(&newpath, path) < 0)
            return -1;
        ret = real_access(newpath, mode);
        VIR_FREE(newpath);
    } else {
        ret = real_access(path, mode);
    }
    return ret;
}


static int
virMockStatRedirect(const char *path, char **newpath)
{
    if (STRPREFIX(path, SYSFS_PCI_PREFIX)) {
        if (getrealpath(newpath, path) < 0)
            return -1;
    }
    return 0;
}


int
open(const char *path, int flags, ...)
{
    int ret;
    char *newpath = NULL;

    init_syms();

    if (STRPREFIX(path, SYSFS_PCI_PREFIX) &&
        getrealpath(&newpath, path) < 0)
        return -1;

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
        ret = real_open(newpath ? newpath : path, flags, mode);
    } else {
        ret = real_open(newpath ? newpath : path, flags);
    }

    /* Catch both: /sys/bus/pci/drivers/... and
     * /sys/bus/pci/device/.../driver/... */
    if (ret >= 0 && STRPREFIX(path, SYSFS_PCI_PREFIX) &&
        strstr(path, "driver") && add_fd(ret, path) < 0) {
        real_close(ret);
        ret = -1;
    }

    VIR_FREE(newpath);
    return ret;
}

DIR *
opendir(const char *path)
{
    DIR *ret;
    char *newpath = NULL;

    init_syms();

    if (STRPREFIX(path, SYSFS_PCI_PREFIX) &&
        getrealpath(&newpath, path) < 0)
        return NULL;

    ret = real_opendir(newpath ? newpath : path);

    VIR_FREE(newpath);
    return ret;
}

int
close(int fd)
{
    if (remove_fd(fd) < 0)
        return -1;
    return real_close(fd);
}

char *
virFileCanonicalizePath(const char *path)
{
    char *ret;

    init_syms();

    if (STRPREFIX(path, SYSFS_PCI_PREFIX)) {
        char *newpath;

        if (getrealpath(&newpath, path) < 0)
            return NULL;

        ret = real_virFileCanonicalizePath(newpath);
        VIR_FREE(newpath);
    } else {
        ret = real_virFileCanonicalizePath(path);
    }

    return ret;
}

# include "virmockstathelpers.c"

#else
/* Nothing to override on this platform */
#endif
