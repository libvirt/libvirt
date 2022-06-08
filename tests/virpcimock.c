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

#define LIBVIRT_VIRPCIVPDPRIV_H_ALLOW

#include "virpcivpdpriv.h"

#if defined(__linux__) || defined(__FreeBSD__) || defined(__APPLE__)
# define VIR_MOCK_LOOKUP_MAIN
# include "virmock.h"
# include <unistd.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <stdarg.h>
# include <dirent.h>
# include "viralloc.h"
# include "virfile.h"

static int (*real_access)(const char *path, int mode);
static int (*real_open)(const char *path, int flags, ...);
# ifdef __GLIBC__
static int (*real___open_2)(const char *path, int flags);
# endif /* ! __GLIBC__ */
static int (*real_close)(int fd);
static DIR * (*real_opendir)(const char *name);
static char *(*real_virFileCanonicalizePath)(const char *path);

static char *fakerootdir;

/* To add a new mocked prefix in virpcimock:
 * - add the prefix here as a define to make it easier to track what we
 * are mocking;
 * - add it to the 'pathPrefixIsMocked()' helper;
 * - (optional) edit 'getrealpath()' if you need the resulting mocked
 * path to be different than <fakerootdir>/path
 */
# define SYSFS_PCI_PREFIX "/sys/bus/pci/"
# define SYSFS_KERNEL_PREFIX "/sys/kernel/"
# define DEV_VFIO_PREFIX "/dev/vfio/"

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
 * /sys/bus/pci/devices/<device>/driver_override
 *   Name of a driver that overrides preferred driver can be written
 *   here. The device will be attached to it on drivers_probe event.
 *   Writing an empty string (or "\n") clears the override.
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

struct pciDriver {
    char *name;
    int *vendor;        /* List of vendor:device IDs the driver can handle */
    int *device;
    size_t len;            /* @len is used for both @vendor and @device */
};

struct pciIommuGroup {
    int iommu;
    size_t nDevicesBoundToVFIO; /* Indicates the devices in the group */
};

struct pciDeviceAddress {
    unsigned int domain;
    unsigned int bus;
    unsigned int device;
    unsigned int function;
};
# define ADDR_STR_FMT "%04x:%02x:%02x.%u"

struct pciVPD {
    /* PCI VPD contents (binary, may contain NULLs), NULL if not present. */
    const char *data;
    /* VPD length in bytes. */
    size_t vpd_len;
};

struct pciDevice {
    struct pciDeviceAddress addr;
    int vendor;
    int device;
    int klass;
    int iommuGroup;
    const char *physfn;
    struct pciDriver *driver;   /* Driver attached. NULL if attached to no driver */
    struct pciVPD vpd;
};

struct fdCallback {
    int fd;
    char *path;
};

struct pciDevice **pciDevices = NULL;
size_t nPCIDevices = 0;

struct pciDriver **pciDrivers = NULL;
size_t nPCIDrivers = 0;

struct pciIommuGroup **pciIommuGroups = NULL;
size_t npciIommuGroups = 0;

struct fdCallback *callbacks = NULL;
size_t nCallbacks = 0;

static void init_env(void);

static int pci_device_autobind(struct pciDevice *dev);
static void pci_device_new_from_stub(const struct pciDevice *data);
static struct pciDevice *pci_device_find_by_id(struct pciDeviceAddress const *addr);
static struct pciDevice *pci_device_find_by_content(const char *path);

static void pci_driver_new(const char *name, ...);
static struct pciDriver *pci_driver_find_by_dev(struct pciDevice *dev);
static struct pciDriver *pci_driver_find_by_path(const char *path);
static struct pciDriver *pci_driver_find_by_driver_override(struct pciDevice *dev);
static int pci_driver_bind(struct pciDriver *driver, struct pciDevice *dev);
static int pci_driver_unbind(struct pciDriver *driver, struct pciDevice *dev);
static int pci_driver_handle_change(int fd, const char *path);
static int pci_driver_handle_bind(const char *path);
static int pci_driver_handle_unbind(const char *path);


/*
 * Helper functions
 */
static void
make_file(const char *path,
          const char *name,
          const char *value,
          ssize_t len)
{
    VIR_AUTOCLOSE fd = -1;
    g_autofree char *filepath = NULL;
    if (value && len == -1)
        len = strlen(value);

    filepath = g_strdup_printf("%s/%s", path, name);

    if ((fd = real_open(filepath, O_CREAT|O_WRONLY, 0666)) < 0)
        ABORT("Unable to open: %s", filepath);

    if (value && safewrite(fd, value, len) != len)
        ABORT("Unable to write: %s", filepath);
}

static void
make_dir(const char *path,
         const char *name)
{
    g_autofree char *dirpath = NULL;

    dirpath = g_strdup_printf("%s/%s", path, name);

    if (g_mkdir_with_parents(dirpath, 0777) < 0)
        ABORT("Unable to create: %s", dirpath);
}

static void
make_symlink(const char *path,
          const char *name,
          const char *target)
{
    g_autofree char *filepath = NULL;

    filepath = g_strdup_printf("%s/%s", path, name);

    if (symlink(target, filepath) < 0)
        ABORT("Unable to create symlink filepath -> target");
}

static int
pci_read_file(const char *path,
              char *buf,
              size_t buf_size,
              bool truncate)
{
    int ret = -1;
    int fd = -1;
    g_autofree char *newpath = NULL;

    newpath = g_strdup_printf("%s/%s", fakerootdir, path);

    if ((fd = real_open(newpath, O_RDWR)) < 0)
        goto cleanup;

    memset(buf, 0, buf_size);
    if (saferead(fd, buf, buf_size - 1) < 0) {
        STDERR("Unable to read from %s", newpath);
        goto cleanup;
    }

    if (truncate &&
        ftruncate(fd, 0) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    real_close(fd);
    return ret;
}

static bool
pathPrefixIsMocked(const char *path)
{
    return STRPREFIX(path, SYSFS_PCI_PREFIX) ||
           STRPREFIX(path, SYSFS_KERNEL_PREFIX) ||
           STRPREFIX(path, DEV_VFIO_PREFIX);
}

static int
getrealpath(char **newpath,
            const char *path)
{
    if (!fakerootdir && pathPrefixIsMocked(path))
        init_env();

    if (STRPREFIX(path, SYSFS_PCI_PREFIX)) {
        *newpath = g_strdup_printf("%s/sys/bus/pci/%s",
                                   fakerootdir,
                                   path + strlen(SYSFS_PCI_PREFIX));
    } else if (pathPrefixIsMocked(path)) {
        *newpath = g_strdup_printf("%s/%s",
                                   fakerootdir,
                                   path);
    } else {
        *newpath = g_strdup(path);
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
    size_t i;

    if (find_fd(fd, &i)) {
        struct fdCallback cb = callbacks[i];
        ABORT("FD %d %s already present in the array as %d %s",
              fd, path, cb.fd, cb.path);
    }

    callbacks = g_renew(struct fdCallback, callbacks, nCallbacks + 1);
    callbacks[nCallbacks].path = g_strdup(path);
    callbacks[nCallbacks++].fd = fd;

    return 0;
}

static int
remove_fd(int fd)
{
    size_t i;

    if (find_fd(fd, &i)) {
        struct fdCallback cb = callbacks[i];

        if (pci_driver_handle_change(cb.fd, cb.path) < 0)
            return -1;

        VIR_FREE(cb.path);
        if (VIR_DELETE_ELEMENT(callbacks, i, nCallbacks) < 0) {
            errno = EINVAL;
            return -1;
        }
    }

    return 0;
}


/*
 * PCI Device functions
 */
static char *
pci_address_format(struct pciDeviceAddress const *addr)
{
    return g_strdup_printf(ADDR_STR_FMT, addr->domain, addr->bus,
                           addr->device, addr->function);
}

static int
pci_address_parse(struct pciDeviceAddress *addr,
                  const char *buf)
{
    if (sscanf(buf, ADDR_STR_FMT,
               &addr->domain, &addr->bus,
               &addr->device, &addr->function) != 4)
        return -1;
    return 0;
}


static char *
pci_device_get_path(const struct pciDevice *dev,
                    const char *file,
                    bool faked)
{
    char *ret = NULL;
    const char *prefix = "";
    g_autofree char *devid = NULL;

    if (faked)
        prefix = fakerootdir;

    if (!(devid = pci_address_format(&dev->addr)))
        return NULL;

    /* PCI devices really do live under /sys/devices/pciDDDD:BB
     * and then they are just symlinked to /sys/bus/pci/devices/
     */
    if (file) {
        ret = g_strdup_printf("%s/sys/devices/pci%04x:%02x/%s/%s",
                              prefix, dev->addr.domain, dev->addr.bus,
                              devid, file);
    } else {
        ret = g_strdup_printf("%s/sys/devices/pci%04x:%02x/%s",
                              prefix, dev->addr.domain, dev->addr.bus,
                              devid);
    }

    return ret;
}


static void
pci_device_create_iommu(const struct pciDevice *dev,
                        const char *devid)
{
    struct pciIommuGroup *iommuGroup;
    g_autofree char *iommuPath = NULL;
    char tmp[256];
    size_t i;

    iommuPath = g_strdup_printf("%s/sys/kernel/iommu_groups/%d/devices/",
                                fakerootdir, dev->iommuGroup);

    if (g_mkdir_with_parents(iommuPath, 0777) < 0)
        ABORT("Unable to create: %s", iommuPath);

    if (g_snprintf(tmp, sizeof(tmp),
                   "../../../../devices/pci%04x:%02x/%s",
                   dev->addr.domain, dev->addr.bus, devid) < 0) {
        ABORT("@tmp overflow");
    }

    make_symlink(iommuPath, devid, tmp);

    /* pci_device_create_iommu can be called more than one for the
     * same iommuGroup. Bail out here if the iommuGroup was already
     * created beforehand. */
    for (i = 0; i < npciIommuGroups; i++) {
        if (pciIommuGroups[i]->iommu == dev->iommuGroup)
            return;
    }

    iommuGroup = g_new0(struct pciIommuGroup, 1);
    iommuGroup->iommu = dev->iommuGroup;
    iommuGroup->nDevicesBoundToVFIO = 0; /* No device bound to VFIO by default */

    VIR_APPEND_ELEMENT(pciIommuGroups, npciIommuGroups, iommuGroup);
}


static void
pci_device_new_from_stub(const struct pciDevice *data)
{
    struct pciDevice *dev;
    g_autofree char *devpath = NULL;
    g_autofree char *devsympath = NULL;
    g_autofree char *id = NULL;
    g_autofree char *devid = NULL;
    char *c;
    g_autofree char *configSrc = NULL;
    char tmp[256];
    struct stat sb;
    bool configSrcExists = false;

    if (!(devid = pci_address_format(&data->addr)))
        ABORT_OOM();

    id = g_strdup(devid);

    /* Replace ':' with '-' to create the config filename from the
     * device ID. The device ID cannot be used directly as filename
     * because it contains ':' and Windows does not allow ':' in
     * filenames. */
    c = strchr(id, ':');

    while (c) {
        *c = '-';
        c = strchr(c, ':');
    }

    dev = g_new0(struct pciDevice, 1);

    configSrc = g_strdup_printf("%s/virpcitestdata/%s.config", abs_srcdir, id);

    memcpy(dev, data, sizeof(*dev));

    if (!(devpath = pci_device_get_path(dev, NULL, true)))
        ABORT_OOM();

    if (g_mkdir_with_parents(devpath, 0777) < 0)
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
        g_autofree char *buf = NULL;
        ssize_t len;

        if ((len = virFileReadAll(configSrc, 4096, &buf)) < 0)
            ABORT("Unable to read config file '%s'", configSrc);

        make_file(devpath, "config", buf, len);
    } else {
        /* If there's no config data in the virpcitestdata dir, create a dummy
         * config file */
        make_file(devpath, "config", "some dummy config", -1);
    }

    if (g_snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->vendor) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "vendor", tmp, -1);

    if (g_snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->device) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "device", tmp, -1);

    if (g_snprintf(tmp, sizeof(tmp),  "0x%.4x", dev->klass) < 0)
        ABORT("@tmp overflow");
    make_file(devpath, "class", tmp, -1);

    make_file(devpath, "driver_override", NULL, -1);

    pci_device_create_iommu(dev, devid);

    if (g_snprintf(tmp, sizeof(tmp),
                   "../../../kernel/iommu_groups/%d", dev->iommuGroup) < 0) {
        ABORT("@tmp overflow");
    }
    make_symlink(devpath, "iommu_group", tmp);

    if (g_snprintf(tmp, sizeof(tmp),
                   "../../../devices/pci%04x:%02x/%s",
                   dev->addr.domain, dev->addr.bus, devid) < 0) {
        ABORT("@tmp overflow");
    }

    devsympath = g_strdup_printf("%s" SYSFS_PCI_PREFIX "devices", fakerootdir);

    make_symlink(devsympath, devid, tmp);

    if (dev->physfn) {
        if (g_snprintf(tmp, sizeof(tmp),
                       "%s%s/devices/%s", fakerootdir,
                       SYSFS_PCI_PREFIX, dev->physfn) < 0) {
            ABORT("@tmp overflow");
        }
        make_symlink(devpath, "physfn", tmp);
    }

    if (dev->vpd.data && dev->vpd.vpd_len)
        make_file(devpath, "vpd", dev->vpd.data, dev->vpd.vpd_len);

    if (pci_device_autobind(dev) < 0)
        ABORT("Unable to bind: %s", devid);

    VIR_APPEND_ELEMENT(pciDevices, nPCIDevices, dev);
}

static struct pciDevice *
pci_device_find_by_id(struct pciDeviceAddress const *addr)
{
    size_t i;
    for (i = 0; i < nPCIDevices; i++) {
        struct pciDevice *dev = pciDevices[i];

        if (!memcmp(&dev->addr, addr, sizeof(*addr)))
            return dev;
    }

    return NULL;
}

static struct pciDevice *
pci_device_find_by_content(const char *path)
{
    char tmp[32];
    struct pciDeviceAddress addr;

    if (pci_read_file(path, tmp, sizeof(tmp), true) < 0 ||
        pci_address_parse(&addr, tmp) < 0)
        return NULL;

    return pci_device_find_by_id(&addr);
}

static int
pci_device_autobind(struct pciDevice *dev)
{
    struct pciDriver *driver = pci_driver_find_by_driver_override(dev);

    if (!driver)
        driver = pci_driver_find_by_dev(dev);

    if (!driver) {
        /* No driver found. Nothing to do */
        return 0;
    }

    return pci_driver_bind(driver, dev);
}

static int
pci_vfio_release_iommu(struct pciDevice *device)
{
    g_autofree char *vfiopath = NULL;
    size_t i = 0;

    for (i = 0; i < npciIommuGroups; i++) {
        if (device->iommuGroup != pciIommuGroups[i]->iommu)
            continue;

        if (pciIommuGroups[i]->nDevicesBoundToVFIO == 0) {
            errno = EXDEV;
            return -1;
        }

        pciIommuGroups[i]->nDevicesBoundToVFIO--;

        if (!pciIommuGroups[i]->nDevicesBoundToVFIO) {
            vfiopath = g_strdup_printf("%s/dev/vfio/%d",
                                       fakerootdir,
                                       device->iommuGroup);

            if (unlink(vfiopath) < 0)
                return -1;
        }
        break;
    }

    return 0;
}

static int
pci_vfio_lock_iommu(struct pciDevice *device)
{
    g_autofree char *vfiopath = NULL;
    int ret = -1;
    size_t i = 0;
    int fd = -1;

    for (i = 0; i < npciIommuGroups; i++) {
        if (device->iommuGroup != pciIommuGroups[i]->iommu)
            continue;

        if (pciIommuGroups[i]->nDevicesBoundToVFIO == 0) {
            vfiopath = g_strdup_printf("%s/dev/vfio/%d",
                                       fakerootdir,
                                       device->iommuGroup);
            if ((fd = real_open(vfiopath, O_CREAT)) < 0)
                goto cleanup;

        }

        pciIommuGroups[i]->nDevicesBoundToVFIO++;
        break;
    }

    ret = 0;
 cleanup:
    if (fd != -1)
        real_close(fd);
    return ret;
}

/*
 * PCI Driver functions
 */
static char *
pci_driver_get_path(const struct pciDriver *driver,
                    const char *file,
                    bool faked)
{
    char *ret = NULL;
    const char *prefix = "";

    if (faked)
        prefix = fakerootdir;

    if (file) {
        ret = g_strdup_printf("%s" SYSFS_PCI_PREFIX "drivers/%s/%s",
                              prefix, driver->name, file);
    } else {
        ret = g_strdup_printf("%s" SYSFS_PCI_PREFIX "drivers/%s",
                              prefix, driver->name);
    }

    return ret;
}


static void
pci_driver_new(const char *name, ...)
{
    struct pciDriver *driver;
    va_list args;
    int vendor, device;
    g_autofree char *driverpath = NULL;

    driver = g_new0(struct pciDriver, 1);
    driver->name = g_strdup(name);
    if (!(driverpath = pci_driver_get_path(driver, NULL, true)))
        ABORT_OOM();

    if (g_mkdir_with_parents(driverpath, 0777) < 0)
        ABORT("Unable to create: %s", driverpath);

    va_start(args, name);

    while ((vendor = va_arg(args, int)) != -1) {
        if ((device = va_arg(args, int)) == -1)
            ABORT("Invalid vendor device pair for driver %s", name);

        driver->vendor = g_renew(int, driver->vendor, driver->len + 1);
        driver->vendor[driver->len] = vendor;

        driver->device = g_renew(int, driver->device, driver->len + 1);
        driver->device[driver->len] = device;

        driver->len++;
    }

    va_end(args);

    make_file(driverpath, "bind", NULL, -1);
    make_file(driverpath, "unbind", NULL, -1);

    VIR_APPEND_ELEMENT(pciDrivers, nPCIDrivers, driver);
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

static struct pciDriver *
pci_driver_find_by_driver_override(struct pciDevice *dev)
{
    g_autofree char *path = NULL;
    char tmp[32];
    size_t i;

    if (!(path = pci_device_get_path(dev, "driver_override", false)))
        return NULL;

    if (pci_read_file(path, tmp, sizeof(tmp), false) < 0)
        return NULL;

    for (i = 0; i < nPCIDrivers; i++) {
        struct pciDriver *driver = pciDrivers[i];

        if (STREQ(tmp, driver->name))
            return driver;
    }

    return NULL;
}

static int
pci_driver_bind(struct pciDriver *driver,
                struct pciDevice *dev)
{
    g_autofree char *devid = NULL;
    g_autofree char *devpath = NULL;
    g_autofree char *driverpath = NULL;

    if (dev->driver) {
        /* Device already bound */
        errno = ENODEV;
        return -1;
    }

    /* Make symlink under device tree */
    if (!(devpath = pci_device_get_path(dev, "driver", true)) ||
        !(driverpath = pci_driver_get_path(driver, NULL, true))) {
        errno = ENOMEM;
        return -1;
    }

    if (symlink(driverpath, devpath) < 0)
        return -1;

    /* Make symlink under driver tree */
    VIR_FREE(devpath);
    VIR_FREE(driverpath);
    if (!(devid = pci_address_format(&dev->addr)) ||
        !(devpath = pci_device_get_path(dev, NULL, true)) ||
        !(driverpath = pci_driver_get_path(driver, devid, true))) {
        errno = ENOMEM;
        return -1;
    }

    if (symlink(devpath, driverpath) < 0)
        return -1;

    if (STREQ(driver->name, "vfio-pci") &&
        pci_vfio_lock_iommu(dev) < 0)
        return -1;

    dev->driver = driver;
    return 0;
}

static int
pci_driver_unbind(struct pciDriver *driver,
                  struct pciDevice *dev)
{
    g_autofree char *devid = NULL;
    g_autofree char *devpath = NULL;
    g_autofree char *driverpath = NULL;

    if (dev->driver != driver) {
        /* Device not bound to the @driver */
        errno = ENODEV;
        return -1;
    }

    /* Make symlink under device tree */
    if (!(devid = pci_address_format(&dev->addr)) ||
        !(devpath = pci_device_get_path(dev, "driver", true)) ||
        !(driverpath = pci_driver_get_path(driver, devid, true))) {
        errno = ENOMEM;
        return -1;
    }

    if (unlink(devpath) < 0 ||
        unlink(driverpath) < 0)
        return -1;

    if (STREQ(driver->name, "vfio-pci") &&
        pci_vfio_release_iommu(dev) < 0)
        return -1;

    dev->driver = NULL;
    return 0;
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
pci_driver_handle_change(int fd G_GNUC_UNUSED, const char *path)
{
    int ret;
    g_autofree char *file = g_path_get_basename(path);

    if (STREQ(file, "bind"))
        ret = pci_driver_handle_bind(path);
    else if (STREQ(file, "unbind"))
        ret = pci_driver_handle_unbind(path);
    else if (STREQ(file, "drivers_probe"))
        ret = pci_driver_handle_drivers_probe(path);
    else if (STREQ(file, "driver_override"))
        ret = 0; /* nada */
    else
        ABORT("Not handled write to: %s", path);
    return ret;
}

static int
pci_driver_handle_bind(const char *path)
{
    struct pciDevice *dev = pci_device_find_by_content(path);
    struct pciDriver *driver = pci_driver_find_by_path(path);

    if (!driver || !dev) {
        /* No driver, no device or failing driver requested */
        errno = ENODEV;
        return -1;
    }

    return pci_driver_bind(driver, dev);
}

static int
pci_driver_handle_unbind(const char *path)
{
    struct pciDevice *dev = pci_device_find_by_content(path);

    if (!dev || !dev->driver) {
        /* No device, device not binded or failing driver requested */
        errno = ENODEV;
        return -1;
    }

    return pci_driver_unbind(dev->driver, dev);
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
# ifdef __GLIBC__
    VIR_MOCK_REAL_INIT(__open_2);
# endif /* ! __GLIBC__ */
    VIR_MOCK_REAL_INIT(close);
# if defined(__APPLE__) && defined(__x86_64__)
    VIR_MOCK_REAL_INIT_ALIASED(opendir, "opendir$INODE64");
# else
    VIR_MOCK_REAL_INIT(opendir);
# endif
    VIR_MOCK_REAL_INIT(virFileCanonicalizePath);
}

static void
init_env(void)
{
    g_autofree char *tmp = NULL;
    const char fullVPDExampleData[] = {
        PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_STRING_RESOURCE_FLAG, 0x08, 0x00,
        't', 'e', 's', 't', 'n', 'a', 'm', 'e',
        PCI_VPD_LARGE_RESOURCE_FLAG | PCI_VPD_READ_ONLY_LARGE_RESOURCE_FLAG, 0x16, 0x00,
        'P', 'N', 0x02, '4', '2',
        'E', 'C', 0x04, '4', '2', '4', '2',
        'V', 'A', 0x02, 'E', 'X',
        'R', 'V', 0x02, 0x31, 0x00,
        PCI_VPD_RESOURCE_END_VAL
    };
    struct pciVPD exampleVPD = {
        .data = fullVPDExampleData,
        .vpd_len = G_N_ELEMENTS(fullVPDExampleData),
    };

    if (!(fakerootdir = getenv("LIBVIRT_FAKE_ROOT_DIR")))
        ABORT("Missing LIBVIRT_FAKE_ROOT_DIR env variable\n");

    tmp = g_strdup_printf("%s%s", fakerootdir, SYSFS_PCI_PREFIX);

    if (g_mkdir_with_parents(tmp, 0777) < 0)
        ABORT("Unable to create: %s", tmp);

    make_dir(tmp, "devices");
    make_dir(tmp, "drivers");
    make_file(tmp, "drivers_probe", NULL, -1);

    /* Create /dev/vfio/ dir and /dev/vfio/vfio file */
    VIR_FREE(tmp);
    tmp = g_strdup_printf("%s/dev/vfio", fakerootdir);

    if (g_mkdir_with_parents(tmp, 0777) < 0)
        ABORT("Unable to create: %s", tmp);

    make_file(tmp, "vfio", NULL, -1);

# define MAKE_PCI_DRIVER(name, ...) \
    pci_driver_new(name, __VA_ARGS__, -1, -1)

    MAKE_PCI_DRIVER("iwlwifi", 0x8086, 0x0044);
    MAKE_PCI_DRIVER("i915", 0x8086, 0x0046, 0x8086, 0x0047);
    MAKE_PCI_DRIVER("vfio-pci", -1, -1);
    MAKE_PCI_DRIVER("nvme", 0x1cc1, 0x8201);

# define MAKE_PCI_DEVICE(Id, Vendor, Device, IommuGroup, ...) \
    do { \
        struct pciDevice dev = {.vendor = Vendor, \
                                .device = Device, \
                                .iommuGroup = IommuGroup, __VA_ARGS__}; \
        if (pci_address_parse(&dev.addr, Id) < 0) \
            ABORT("Unable to parse PCI address " Id); \
        pci_device_new_from_stub(&dev); \
    } while (0)

    MAKE_PCI_DEVICE("0000:00:00.0", 0x8086, 0x0044, 0);
    MAKE_PCI_DEVICE("0000:00:01.0", 0x8086, 0x0044, 1);
    MAKE_PCI_DEVICE("0000:00:02.0", 0x8086, 0x0046, 2);
    MAKE_PCI_DEVICE("0000:00:03.0", 0x8086, 0x0048, 3);
    MAKE_PCI_DEVICE("0001:00:00.0", 0x1014, 0x03b9, 4, .klass = 0x060400);
    MAKE_PCI_DEVICE("0001:01:00.0", 0x8086, 0x105e, 5);
    MAKE_PCI_DEVICE("0001:01:00.1", 0x8086, 0x105e, 5);
    MAKE_PCI_DEVICE("0005:80:00.0", 0x10b5, 0x8112, 6, .klass = 0x060400);
    MAKE_PCI_DEVICE("0005:90:01.0", 0x1033, 0x0035, 7);
    MAKE_PCI_DEVICE("0005:90:01.1", 0x1033, 0x0035, 7);
    MAKE_PCI_DEVICE("0005:90:01.2", 0x1033, 0x00e0, 7);
    MAKE_PCI_DEVICE("0005:90:01.3", 0x1033, 0x00e0, 7);
    MAKE_PCI_DEVICE("0000:0a:01.0", 0x8086, 0x0047, 8);
    MAKE_PCI_DEVICE("0000:0a:02.0", 0x8286, 0x0048, 8);
    MAKE_PCI_DEVICE("0000:0a:03.0", 0x8386, 0x0048, 8);
    MAKE_PCI_DEVICE("0000:06:12.0", 0x8086, 0x0047, 9);
    MAKE_PCI_DEVICE("0000:06:12.1", 0x8086, 0x0047, 10,
                    .physfn = "0000:06:12.0"); /* Virtual Function */
    MAKE_PCI_DEVICE("0000:06:12.2", 0x8086, 0x0047, 11,
                    .physfn = "0000:06:12.0"); /* Virtual Function */
    MAKE_PCI_DEVICE("0021:de:1f.0", 0x8086, 0x0047, 12);
    MAKE_PCI_DEVICE("0021:de:1f.1", 0x8086, 0x0047, 13,
                    .physfn = "0021:de:1f.0"); /* Virtual Function */

    MAKE_PCI_DEVICE("0000:01:00.0", 0x1cc1, 0x8201, 14, .klass = 0x010802);
    MAKE_PCI_DEVICE("0000:02:00.0", 0x1cc1, 0x8201, 15, .klass = 0x010802);

    MAKE_PCI_DEVICE("0000:03:00.0", 0x15b3, 0xa2d6, 16, .vpd = exampleVPD);
}


/*
 *
 * Mocked functions
 *
 */

int
access(const char *path, int mode)
{
    g_autofree char *newpath = NULL;

    init_syms();

    if (getrealpath(&newpath, path) < 0)
        return -1;

    return real_access(newpath, mode);
}


static int
virMockStatRedirect(const char *path, char **newpath)
{
    if (getrealpath(newpath, path) < 0)
        return -1;

    return 0;
}


int
open(const char *path, int flags, ...)
{
    int ret;
    g_autofree char *newpath = NULL;

    init_syms();

    if (getrealpath(&newpath, path) < 0)
        return -1;

    if (flags & O_CREAT) {
        va_list ap;
        mode_t mode;
        va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
        ret = real_open(newpath, flags, mode);
    } else {
        ret = real_open(newpath, flags);
    }

    /* Catch both: /sys/bus/pci/drivers/... and
     * /sys/bus/pci/device/.../driver/... */
    if (ret >= 0 && STRPREFIX(path, SYSFS_PCI_PREFIX) &&
        strstr(path, "driver") && add_fd(ret, path) < 0) {
        real_close(ret);
        ret = -1;
    }

    return ret;
}


# ifdef __GLIBC__
/* in some cases this function may not be present in headers, so we need
 * a declaration to silence the compiler */
int
__open_2(const char *path, int flags);

int
__open_2(const char *path, int flags)
{
    g_autofree char *newpath = NULL;
    int ret;

    init_syms();

    if (getrealpath(&newpath, path) < 0)
        return -1;

    ret = real___open_2(newpath, flags);

    /* Catch both: /sys/bus/pci/drivers/... and
     * /sys/bus/pci/device/.../driver/... */
    if (ret >= 0 && STRPREFIX(path, SYSFS_PCI_PREFIX) &&
        strstr(path, "driver") && add_fd(ret, path) < 0) {
        real_close(ret);
        ret = -1;
    }

    return ret;
}
# endif /* ! __GLIBC__ */

DIR *
opendir(const char *path)
{
    g_autofree char *newpath = NULL;

    init_syms();

    if (getrealpath(&newpath, path) < 0)
        return NULL;

    return real_opendir(newpath);
}

int
close(int fd)
{
    init_syms();

    if (remove_fd(fd) < 0)
        return -1;
    return real_close(fd);
}

char *
virFileCanonicalizePath(const char *path)
{
    g_autofree char *newpath = NULL;

    init_syms();

    if (getrealpath(&newpath, path) < 0)
        return NULL;

    return real_virFileCanonicalizePath(newpath);
}

# include "virmockstathelpers.c"

#else
/* Nothing to override on this platform */
#endif
