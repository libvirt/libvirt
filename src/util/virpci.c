/*
 * virpci.c: helper APIs for managing host PCI devices
 *
 * Copyright (C) 2009-2015 Red Hat, Inc.
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

#include "virpci.h"
#include "virnetdev.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "virlog.h"
#include "virerror.h"
#include "virfile.h"
#include "virkmod.h"
#include "virstring.h"
#include "viralloc.h"
#include "virpcivpd.h"

VIR_LOG_INIT("util.pci");

#define PCI_SYSFS "/sys/bus/pci/"
#define PCI_ID_LEN 10   /* "XXXX XXXX" */

VIR_ENUM_IMPL(virPCIELinkSpeed,
              VIR_PCIE_LINK_SPEED_LAST,
              "", "2.5", "5", "8", "16", "32", "64"
);

VIR_ENUM_IMPL(virPCIStubDriver,
              VIR_PCI_STUB_DRIVER_LAST,
              "none",
              "pciback", /* XEN */
              "vfio-pci", /* VFIO */
);

VIR_ENUM_IMPL(virPCIHeader,
              VIR_PCI_HEADER_LAST,
              "endpoint",
              "pci-bridge",
              "cardbus-bridge",
);

struct _virPCIDevice {
    virPCIDeviceAddress address;

    char          *name;              /* domain:bus:slot.function */
    char          id[PCI_ID_LEN];     /* product vendor */
    char          *path;

    /* The driver:domain which uses the device */
    char          *used_by_drvname;
    char          *used_by_domname;

    /* The following 5 items are only valid after virPCIDeviceInit()
     * has been called for the virPCIDevice object. This is *not* done
     * in most cases (because it creates extra overhead, and parts of
     * it can fail if libvirtd is running unprivileged)
     */
    unsigned int  pcie_cap_pos;
    unsigned int  pci_pm_cap_pos;
    bool          has_flr;
    bool          has_pm_reset;
    bool          is_pcie;
    /**/

    bool          managed;

    virPCIStubDriver stubDriverType;
    char            *stubDriverName; /* if blank, use default for type */

    /* used by reattach function */
    bool          unbind_from_stub;
    bool          remove_slot;
    bool          reprobe;
};

struct _virPCIDeviceList {
    virObjectLockable parent;

    size_t count;
    virPCIDevice **devs;
};


#define VIR_FROM_THIS VIR_FROM_NONE

/* Specifications referenced in comments:
 *  PCI30  - PCI Local Bus Specification 3.0
 *  PCIe20 - PCI Express Base Specification 2.0
 *  BR12   - PCI-to-PCI Bridge Architecture Specification 1.2
 *  PM12   - PCI Bus Power Management Interface Specification 1.2
 *  ECN_AF - Advanced Capabilities for Conventional PCI ECN
 */

/* Type 0 config space header length; PCI30 Section 6.1 Configuration Space Organization */
#define PCI_CONF_LEN            0x100
#define PCI_CONF_HEADER_LEN     0x40

/* PCI30 6.2.1 */
#define PCI_HEADER_TYPE         0x0e    /* Header type */
#define PCI_HEADER_TYPE_BRIDGE 0x1
#define PCI_HEADER_TYPE_MASK   0x7f
#define PCI_HEADER_TYPE_MULTI  0x80

/* PCI30 6.2.1  Device Identification */
#define PCI_CLASS_DEVICE        0x0a    /* Device class */

/* Class Code for bridge; PCI30 D.7  Base Class 06h */
#define PCI_CLASS_BRIDGE_PCI    0x0604

/* PCI30 6.2.3  Device Status */
#define PCI_STATUS              0x06    /* 16 bits */
#define PCI_STATUS_CAP_LIST    0x10    /* Support Capability List */

/* PCI30 6.7  Capabilities List */
#define PCI_CAPABILITY_LIST     0x34    /* Offset of first capability list entry */
#define PCI_CAP_FLAGS           2       /* Capability defined flags (16 bits) */

/* PM12 3.2.1  Capability Identifier */
#define PCI_CAP_ID_PM           0x01    /* Power Management */
/* PCI30 H Capability IDs */
#define PCI_CAP_ID_EXP          0x10    /* PCI Express */
/* ECN_AF 6.x.1.1  Capability ID for AF */
#define PCI_CAP_ID_AF           0x13    /* Advanced Features */

/* PCIe20 7.8.3  Device Capabilities Register (Offset 04h) */
#define PCI_EXP_DEVCAP          0x4     /* Device capabilities */
#define PCI_EXP_DEVCAP_FLR     (1<<28)  /* Function Level Reset */
#define PCI_EXP_LNKCAP          0xc     /* Link Capabilities */
#define PCI_EXP_LNKCAP_SPEED    0x0000f /* Maximum Link Speed */
#define PCI_EXP_LNKCAP_WIDTH    0x003f0 /* Maximum Link Width */
#define PCI_EXP_LNKSTA          0x12    /* Link Status */
#define PCI_EXP_LNKSTA_SPEED    0x000f  /* Negotiated Link Speed */
#define PCI_EXP_LNKSTA_WIDTH    0x03f0  /* Negotiated Link Width */

/* Header type 1 BR12 3.2 PCI-to-PCI Bridge Configuration Space Header Format */
#define PCI_PRIMARY_BUS         0x18    /* BR12 3.2.5.2 Primary bus number */
#define PCI_SECONDARY_BUS       0x19    /* BR12 3.2.5.3 Secondary bus number */
#define PCI_SUBORDINATE_BUS     0x1a    /* BR12 3.2.5.4 Highest bus number behind the bridge */
#define PCI_BRIDGE_CONTROL      0x3e
/* BR12 3.2.5.18  Bridge Control Register */
#define PCI_BRIDGE_CTL_RESET   0x40    /* Secondary bus reset */

/* PM12 3.2.4  Power Management Control/Status (Offset = 4) */
#define PCI_PM_CTRL                4    /* PM control and status register */
#define PCI_PM_CTRL_STATE_MASK    0x3  /* Current power state (D0 to D3) */
#define PCI_PM_CTRL_STATE_D0      0x0  /* D0 state */
#define PCI_PM_CTRL_STATE_D3hot   0x3  /* D3 state */
#define PCI_PM_CTRL_NO_SOFT_RESET 0x8  /* No reset for D3hot->D0 */

/* ECN_AF 6.x.1  Advanced Features Capability Structure */
#define PCI_AF_CAP              0x3     /* Advanced features capabilities */
#define PCI_AF_CAP_FLR         0x2     /* Function Level Reset */

#define PCI_EXP_FLAGS           0x2
#define PCI_EXP_FLAGS_TYPE      0x00f0
#define PCI_EXP_TYPE_DOWNSTREAM 0x6

#define PCI_EXT_CAP_BASE          0x100
#define PCI_EXT_CAP_LIMIT         0x1000
#define PCI_EXT_CAP_ID_MASK       0x0000ffff
#define PCI_EXT_CAP_OFFSET_SHIFT  20
#define PCI_EXT_CAP_OFFSET_MASK   0x00000ffc

#define PCI_EXT_CAP_ID_ACS      0x000d
#define PCI_EXT_ACS_CTRL        0x06

#define PCI_EXT_CAP_ACS_SV      0x01
#define PCI_EXT_CAP_ACS_RR      0x04
#define PCI_EXT_CAP_ACS_CR      0x08
#define PCI_EXT_CAP_ACS_UF      0x10
#define PCI_EXT_CAP_ACS_ENABLED (PCI_EXT_CAP_ACS_SV | \
                                 PCI_EXT_CAP_ACS_RR | \
                                 PCI_EXT_CAP_ACS_CR | \
                                 PCI_EXT_CAP_ACS_UF)

#define PCI_EXP_TYPE_ROOT_INT_EP 0x9    /* Root Complex Integrated Endpoint */
#define PCI_EXP_TYPE_ROOT_EC 0xa        /* Root Complex Event Collector */

static virClass *virPCIDeviceListClass;

static void virPCIDeviceListDispose(void *obj);

static int virPCIOnceInit(void)
{
    if (!VIR_CLASS_NEW(virPCIDeviceList, virClassForObjectLockable()))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virPCI);


static char *
virPCIDriverDir(const char *driver)
{
    return g_strdup_printf(PCI_SYSFS "drivers/%s", driver);
}


static char *
virPCIFile(const char *device, const char *file)
{
    return g_strdup_printf(PCI_SYSFS "devices/%s/%s", device, file);
}


/* virPCIDeviceGetCurrentDriverPathAndName - put the path to the driver
 * directory of the driver in use for this device in @path and the
 * name of the driver in @name. Both could be NULL if it's not bound
 * to any driver.
 *
 * Return 0 for success, -1 for error.
 */
int
virPCIDeviceGetCurrentDriverPathAndName(virPCIDevice *dev,
                                        char **path,
                                        char **name)
{
    int ret = -1;
    g_autofree char *drvlink = NULL;

    *path = *name = NULL;

    /* drvlink = "/sys/bus/pci/dddd:bb:ss.ff/driver" */
    drvlink = virPCIFile(dev->name, "driver");

    if (!virFileExists(drvlink)) {
        ret = 0;
        goto cleanup;
    }

    if (virFileIsLink(drvlink) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device %1$s driver file %2$s is not a symlink"),
                       dev->name, drvlink);
        goto cleanup;
    }
    if (virFileResolveLink(drvlink, path) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %1$s driver symlink %2$s"),
                       dev->name, drvlink);
        goto cleanup;
    }
    /* path = "/sys/bus/pci/drivers/${drivername}" */

    *name = g_path_get_basename(*path);
    /* name = "${drivername}" */

    ret = 0;
 cleanup:
    if (ret < 0) {
        VIR_FREE(*path);
        VIR_FREE(*name);
    }
    return ret;
}


/**
 * virPCIDeviceGetCurrentDriverNameAndType:
 * @dev: virPCIDevice object to examine
 * @drvName: returns name of driver bound to this device (if any)
 * @drvType: returns type of driver if it is a known stub driver type
 *
 * Find the name of the driver bound to @dev (if any) and the type of
 * the driver if it is a known/recognized "stub" driver (based on the
 * driver name).
 *
 * There are vfio "variant" drivers that provide all the basic
 * functionality of the standard vfio-pci driver as well as additional
 * stuff. As of kernel 6.1, the vfio-pci driver and all vfio variant
 * drivers can be identified (once the driver has been bound to a
 * device) by looking for the subdirectory "vfio-dev" in the device's
 * sysfs directory; for example, if the directory
 * /sys/bus/pci/devices/0000:04:11.4/vfio-dev exists, then the driver
 * that is currently bound to PCI device 0000:04:11.4 is either
 * vfio-pci, or a vfio-pci variant driver.
 *
 * Return 0 on success, -1 on failure. If -1 is returned, then an error
 * message has been logged.
 */
int
virPCIDeviceGetCurrentDriverNameAndType(virPCIDevice *dev,
                                        char **drvName,
                                        virPCIStubDriver *drvType)
{
    g_autofree char *drvPath = NULL;
    g_autofree char *vfioDevDir = NULL;
    int tmpType;

    if (virPCIDeviceGetCurrentDriverPathAndName(dev, &drvPath, drvName) < 0)
        return -1;

    if (!*drvName) {
        *drvType = VIR_PCI_STUB_DRIVER_NONE;
        return 0;
    }

    tmpType = virPCIStubDriverTypeFromString(*drvName);

    if (tmpType > VIR_PCI_STUB_DRIVER_NONE) {
        *drvType = tmpType;
        return 0; /* exact match of a known driver name (or no name) */
    }

    /* If the sysfs directory of this device contains a directory
     * named "vfio-dev" then the currently-bound driver is a vfio
     * variant driver.
     */

    vfioDevDir = virPCIFile(dev->name, "vfio-dev");

    if (virFileIsDir(vfioDevDir)) {
        VIR_DEBUG("Driver %s is a vfio_pci driver", *drvName);
        *drvType = VIR_PCI_STUB_DRIVER_VFIO;
    } else {
        VIR_DEBUG("Driver %s is NOT a vfio_pci driver, or kernel is too old",
                  *drvName);
        *drvType = VIR_PCI_STUB_DRIVER_NONE;
    }

    return 0;
}


static int
virPCIDeviceConfigOpenInternal(virPCIDevice *dev, bool readonly, bool fatal)
{
    int fd;

    fd = open(dev->path, readonly ? O_RDONLY : O_RDWR);

    if (fd < 0) {
        if (fatal) {
            virReportSystemError(errno,
                                 _("Failed to open config space file '%1$s'"),
                                 dev->path);
        } else {
            VIR_WARN("Failed to open config space file '%s': %s",
                     dev->path, g_strerror(errno));
        }
        return -1;
    }

    VIR_DEBUG("%s %s: opened %s", dev->id, dev->name, dev->path);
    return fd;
}

static int
virPCIDeviceConfigOpen(virPCIDevice *dev)
{
    return virPCIDeviceConfigOpenInternal(dev, true, true);
}

static int
virPCIDeviceConfigOpenTry(virPCIDevice *dev)
{
    return virPCIDeviceConfigOpenInternal(dev, true, false);
}

static int
virPCIDeviceConfigOpenWrite(virPCIDevice *dev)
{
    return virPCIDeviceConfigOpenInternal(dev, false, true);
}

static void
virPCIDeviceConfigClose(virPCIDevice *dev, int cfgfd)
{
    if (VIR_CLOSE(cfgfd) < 0) {
        VIR_WARN("Failed to close config space file '%s': %s",
                 dev->path, g_strerror(errno));
    }
}


static int
virPCIDeviceRead(virPCIDevice *dev,
                 int cfgfd,
                 unsigned int pos,
                 uint8_t *buf,
                 unsigned int buflen)
{
    memset(buf, 0, buflen);
    errno = 0;

    if (lseek(cfgfd, pos, SEEK_SET) != pos ||
        saferead(cfgfd, buf, buflen) != buflen) {
        VIR_DEBUG("Failed to read %u bytes at %u from '%s' : %s",
                 buflen, pos, dev->path, g_strerror(errno));
        return -1;
    }
    return 0;
}


/**
 * virPCIDeviceReadN:
 * @dev: virPCIDevice object (used only to log name of config file)
 * @cfgfd: open file descriptor for device config file in sysfs
 * @pos: byte offset in the file to read from
 *
 * read "N" (where "N" is "8", "16", or "32", and appears at the end
 * of the function name) bytes from a PCI device's already-opened
 * sysfs config file and return them as the return value from the
 * function.
 *
 * Returns the value at @pos in the file, or 0 if there was an
 * error. NB: since 0 could be a valid value, occurrence of an error
 * must be determined by examining errno. errno is always reset to 0
 * before the seek/read is attempted (see virPCIDeviceRead()), so if
 * errno != 0 on return from one of these functions, then either the
 * seek or the read operation failed for some reason. If errno == 0
 * and the return value is 0, then the config file really does contain
 * the value 0 at @pos.
 */
static uint8_t
virPCIDeviceRead8(virPCIDevice *dev, int cfgfd, unsigned int pos)
{
    uint8_t buf;
    virPCIDeviceRead(dev, cfgfd, pos, &buf, sizeof(buf));
    return buf;
}

static uint16_t
virPCIDeviceRead16(virPCIDevice *dev, int cfgfd, unsigned int pos)
{
    uint8_t buf[2];
    virPCIDeviceRead(dev, cfgfd, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8);
}

static uint32_t
virPCIDeviceRead32(virPCIDevice *dev, int cfgfd, unsigned int pos)
{
    uint8_t buf[4];
    virPCIDeviceRead(dev, cfgfd, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static int
virPCIDeviceReadClass(virPCIDevice *dev, uint16_t *device_class)
{
    g_autofree char *path = NULL;
    g_autofree char *id_str = NULL;
    unsigned int value;

    path = virPCIFile(dev->name, "class");

    /* class string is '0xNNNNNN\n' ... i.e. 9 bytes */
    if (virFileReadAll(path, 9, &id_str) < 0)
        return -1;

    id_str[8] = '\0';
    if (virStrToLong_ui(id_str, NULL, 16, &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unusual value in %1$s/devices/%2$s/class: %3$s"),
                       PCI_SYSFS, dev->name, id_str);
        return -1;
    }

    *device_class = (value >> 8) & 0xFFFF;
    return 0;
}

static int
virPCIDeviceWrite(virPCIDevice *dev,
                  int cfgfd,
                  unsigned int pos,
                  uint8_t *buf,
                  unsigned int buflen)
{
    if (lseek(cfgfd, pos, SEEK_SET) != pos ||
        safewrite(cfgfd, buf, buflen) != buflen) {
        VIR_WARN("Failed to write to '%s' : %s", dev->path,
                 g_strerror(errno));
        return -1;
    }
    return 0;
}

static void
virPCIDeviceWrite16(virPCIDevice *dev, int cfgfd, unsigned int pos, uint16_t val)
{
    uint8_t buf[2] = { (val >> 0), (val >> 8) };
    virPCIDeviceWrite(dev, cfgfd, pos, &buf[0], sizeof(buf));
}

static void
virPCIDeviceWrite32(virPCIDevice *dev, int cfgfd, unsigned int pos, uint32_t val)
{
    uint8_t buf[4] = { (val >> 0), (val >> 8), (val >> 16), (val >> 24) };
    virPCIDeviceWrite(dev, cfgfd, pos, &buf[0], sizeof(buf));
}

typedef int (*virPCIDeviceIterPredicate)(virPCIDevice *, virPCIDevice *,
                                         void *);

/* Iterate over available PCI devices calling @predicate
 * to compare each one to @dev.
 * Return -1 on error since we don't want to assume it is
 * safe to reset if there is an error.
 */
static int
virPCIDeviceIterDevices(virPCIDeviceIterPredicate predicate,
                        virPCIDevice *dev,
                        virPCIDevice **matched,
                        void *data)
{
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry;
    int ret = 0;
    int rc;

    *matched = NULL;

    VIR_DEBUG("%s %s: iterating over " PCI_SYSFS "devices", dev->id, dev->name);

    if (virDirOpen(&dir, PCI_SYSFS "devices") < 0)
        return -1;

    while ((ret = virDirRead(dir, &entry, PCI_SYSFS "devices")) > 0) {
        g_autoptr(virPCIDevice) check = NULL;
        virPCIDeviceAddress devAddr;
        char *tmp;

        /* expected format: <domain>:<bus>:<slot>.<function> */
        if (/* domain */
            virStrToLong_ui(entry->d_name, &tmp, 16, &devAddr.domain) < 0 || *tmp != ':' ||
            /* bus */
            virStrToLong_ui(tmp + 1, &tmp, 16, &devAddr.bus) < 0 || *tmp != ':' ||
            /* slot */
            virStrToLong_ui(tmp + 1, &tmp, 16, &devAddr.slot) < 0 || *tmp != '.' ||
            /* function */
            virStrToLong_ui(tmp + 1, NULL, 16, &devAddr.function) < 0) {
            VIR_WARN("Unusual entry in " PCI_SYSFS "devices: %s", entry->d_name);
            continue;
        }

        check = virPCIDeviceNew(&devAddr);
        if (!check) {
            ret = -1;
            break;
        }

        rc = predicate(dev, check, data);
        if (rc < 0) {
            /* the predicate returned an error, bail */
            ret = -1;
            break;
        } else if (rc == 1) {
            VIR_DEBUG("%s %s: iter matched on %s", dev->id, dev->name, check->name);
            *matched = g_steal_pointer(&check);
            ret = 1;
            break;
        }
    }
    return ret;
}


/**
 * virPCIDeviceFindCapabilityOffset:
 * @dev: virPCIDevice object (used only to log name of config file)
 * @cfgfd: open file descriptor for device config file in sysfs
 * @capability: PCI_CAP_ID_* being requested
 * @offset: used to return the offset of @capability in the file
 *
 * Find the offset of @capability within the PCI config file @cfgfd of
 * the device @dev. if found, the offset is returned in @offset,
 * otherwise @offset is set to 0.
 *
 * Returns 0 on success, -1 on failure.
 */
static int
virPCIDeviceFindCapabilityOffset(virPCIDevice *dev,
                                 int cfgfd,
                                 unsigned int capability,
                                 unsigned int *offset)
{
    uint16_t status;
    uint8_t pos;

    *offset = 0; /* assume failure (*nothing* can be at offset 0) */

    status = virPCIDeviceRead16(dev, cfgfd, PCI_STATUS);
    if (errno != 0 || !(status & PCI_STATUS_CAP_LIST))
        goto error;

    pos = virPCIDeviceRead8(dev, cfgfd, PCI_CAPABILITY_LIST);
    if (errno != 0)
        goto error;

    /* Zero indicates last capability, capabilities can't
     * be in the config space header and 0xff is returned
     * by the kernel if we don't have access to this region
     *
     * Note: we're not handling loops or extended
     * capabilities here.
     */
    while (pos >= PCI_CONF_HEADER_LEN && pos != 0xff) {
        uint8_t capid = virPCIDeviceRead8(dev, cfgfd, pos);
        if (errno != 0)
            goto error;

        if (capid == capability) {
            VIR_DEBUG("%s %s: found cap 0x%.2x at 0x%.2x",
                      dev->id, dev->name, capability, pos);
            *offset = pos;
            return 0;
        }

        pos = virPCIDeviceRead8(dev, cfgfd, pos + 1);
        if (errno != 0)
            goto error;
    }

 error:
    VIR_DEBUG("%s %s: failed to find cap 0x%.2x (%s)",
              dev->id, dev->name, capability, g_strerror(errno));

    /* reset errno in case the failure was due to insufficient
     * privileges to read the entire PCI config file
     */
    errno = 0;

    return -1;
}

static unsigned int
virPCIDeviceFindExtendedCapabilityOffset(virPCIDevice *dev,
                                         int cfgfd,
                                         unsigned int capability)
{
    int ttl;
    unsigned int pos;
    uint32_t header;

    /* minimum 8 bytes per capability */
    ttl = (PCI_EXT_CAP_LIMIT - PCI_EXT_CAP_BASE) / 8;
    pos = PCI_EXT_CAP_BASE;

    while (ttl > 0 && pos >= PCI_EXT_CAP_BASE) {
        header = virPCIDeviceRead32(dev, cfgfd, pos);

        if ((header & PCI_EXT_CAP_ID_MASK) == capability)
            return pos;

        pos = (header >> PCI_EXT_CAP_OFFSET_SHIFT) & PCI_EXT_CAP_OFFSET_MASK;
        ttl--;
    }

    return 0;
}

/* detects whether this device has FLR.  Returns 0 if the device does
 * not have FLR, 1 if it does, and -1 on error
 */
static bool
virPCIDeviceDetectFunctionLevelReset(virPCIDevice *dev, int cfgfd)
{
    uint32_t caps;
    unsigned int pos;
    g_autofree char *path = NULL;
    int found;

    /* The PCIe Function Level Reset capability allows
     * individual device functions to be reset without
     * affecting any other functions on the device or
     * any other devices on the bus. This is only common
     * on SR-IOV NICs at the moment.
     */
    if (dev->pcie_cap_pos) {
        caps = virPCIDeviceRead32(dev, cfgfd, dev->pcie_cap_pos + PCI_EXP_DEVCAP);
        if (caps & PCI_EXP_DEVCAP_FLR) {
            VIR_DEBUG("%s %s: detected PCIe FLR capability", dev->id, dev->name);
            return true;
        }
    }

    /* The PCI AF Function Level Reset capability is
     * the same thing, except for conventional PCI
     * devices. This is not common yet.
     */
    if (virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_AF, &pos) < 0)
        goto error;

    if (pos) {
        caps = virPCIDeviceRead16(dev, cfgfd, pos + PCI_AF_CAP);
        if (caps & PCI_AF_CAP_FLR) {
            VIR_DEBUG("%s %s: detected PCI FLR capability", dev->id, dev->name);
            return true;
        }
    }

    /* there are some buggy devices that do support FLR, but forget to
     * advertise that fact in their capabilities.  However, FLR is *required*
     * to be present for virtual functions (VFs), so if we see that this
     * device is a VF, we just assume FLR works
     */

    path = g_strdup_printf(PCI_SYSFS "devices/%s/physfn", dev->name);

    found = virFileExists(path);
    if (found) {
        VIR_DEBUG("%s %s: buggy device didn't advertise FLR, but is a VF; forcing flr on",
                  dev->id, dev->name);
        return true;
    }

 error:
    VIR_DEBUG("%s %s: no FLR capability found", dev->id, dev->name);
    return false;
}

/* Require the device has the PCI Power Management capability
 * and that a D3hot->D0 transition will results in a full
 * internal reset, not just a soft reset.
 */
static bool
virPCIDeviceDetectPowerManagementReset(virPCIDevice *dev, int cfgfd)
{
    if (dev->pci_pm_cap_pos) {
        uint32_t ctl;

        /* require the NO_SOFT_RESET bit is clear */
        ctl = virPCIDeviceRead32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL);
        if (!(ctl & PCI_PM_CTRL_NO_SOFT_RESET)) {
            VIR_DEBUG("%s %s: detected PM reset capability", dev->id, dev->name);
            return true;
        }
    }

    VIR_DEBUG("%s %s: no PM reset capability found", dev->id, dev->name);

    return false;
}

/* Any active devices on the same domain/bus ? */
static int
virPCIDeviceSharesBusWithActive(virPCIDevice *dev, virPCIDevice *check, void *data)
{
    virPCIDeviceList *inactiveDevs = data;

    /* Different domain, different bus, or simply identical device */
    if (dev->address.domain != check->address.domain ||
        dev->address.bus != check->address.bus ||
        (dev->address.slot == check->address.slot &&
         dev->address.function == check->address.function))
        return 0;

    /* same bus, but inactive, i.e. about to be assigned to guest */
    if (inactiveDevs && virPCIDeviceListFind(inactiveDevs, &check->address))
        return 0;

    return 1;
}

static virPCIDevice *
virPCIDeviceBusContainsActiveDevices(virPCIDevice *dev,
                                     virPCIDeviceList *inactiveDevs)
{
    virPCIDevice *active = NULL;
    if (virPCIDeviceIterDevices(virPCIDeviceSharesBusWithActive,
                                dev, &active, inactiveDevs) < 0)
        return NULL;
    return active;
}

/* Is @check the parent of @dev ? */
static int
virPCIDeviceIsParent(virPCIDevice *dev, virPCIDevice *check, void *data)
{
    uint16_t device_class;
    uint8_t header_type, secondary, subordinate;
    virPCIDevice **best = data;
    int ret = 0;
    int fd;

    if (dev->address.domain != check->address.domain)
        return 0;

    if ((fd = virPCIDeviceConfigOpenTry(check)) < 0)
        return 0;

    /* Is it a bridge? */
    ret = virPCIDeviceReadClass(check, &device_class);
    if (ret < 0 || device_class != PCI_CLASS_BRIDGE_PCI)
        goto cleanup;

    /* Is it a plane? */
    header_type = virPCIDeviceRead8(check, fd, PCI_HEADER_TYPE);
    if ((header_type & PCI_HEADER_TYPE_MASK) != PCI_HEADER_TYPE_BRIDGE)
        goto cleanup;

    secondary   = virPCIDeviceRead8(check, fd, PCI_SECONDARY_BUS);
    subordinate = virPCIDeviceRead8(check, fd, PCI_SUBORDINATE_BUS);

    VIR_DEBUG("%s %s: found parent device %s", dev->id, dev->name, check->name);

    /* if the secondary bus exactly equals the device's bus, then we found
     * the direct parent.  No further work is necessary
     */
    if (dev->address.bus == secondary) {
        ret = 1;
        goto cleanup;
    }

    /* otherwise, SRIOV allows VFs to be on different buses than their PFs.
     * In this case, what we need to do is look for the "best" match; i.e.
     * the most restrictive match that still satisfies all of the conditions.
     */
    if (dev->address.bus > secondary && dev->address.bus <= subordinate) {
        if (*best == NULL) {
            *best = virPCIDeviceNew(&check->address);
            if (*best == NULL) {
                ret = -1;
                goto cleanup;
            }
        } else {
            /* OK, we had already recorded a previous "best" match for the
             * parent.  See if the current device is more restrictive than the
             * best, and if so, make it the new best
             */
            int bestfd;
            uint8_t best_secondary;

            if ((bestfd = virPCIDeviceConfigOpenTry(*best)) < 0)
                goto cleanup;
            best_secondary = virPCIDeviceRead8(*best, bestfd, PCI_SECONDARY_BUS);
            virPCIDeviceConfigClose(*best, bestfd);

            if (secondary > best_secondary) {
                virPCIDeviceFree(*best);
                *best = virPCIDeviceNew(&check->address);
                if (*best == NULL) {
                    ret = -1;
                    goto cleanup;
                }
            }
        }
    }

 cleanup:
    virPCIDeviceConfigClose(check, fd);
    return ret;
}

static int
virPCIDeviceGetParent(virPCIDevice *dev, virPCIDevice **parent)
{
    virPCIDevice *best = NULL;
    int ret;

    *parent = NULL;
    ret = virPCIDeviceIterDevices(virPCIDeviceIsParent, dev, parent, &best);
    if (ret == 1)
        virPCIDeviceFree(best);
    else if (ret == 0)
        *parent = best;
    return ret;
}

/* Secondary Bus Reset is our sledgehammer - it resets all
 * devices behind a bus.
 */
static int
virPCIDeviceTrySecondaryBusReset(virPCIDevice *dev,
                                 int cfgfd,
                                 virPCIDeviceList *inactiveDevs)
{
    g_autoptr(virPCIDevice) parent = NULL;
    g_autoptr(virPCIDevice) conflict = NULL;
    uint8_t config_space[PCI_CONF_LEN];
    uint16_t ctl;
    int ret = -1;
    int parentfd;

    /* Refuse to do a secondary bus reset if there are other
     * devices/functions behind the bus are used by the host
     * or other guests.
     */
    if ((conflict = virPCIDeviceBusContainsActiveDevices(dev, inactiveDevs))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Active %1$s devices on bus with %2$s, not doing bus reset"),
                       conflict->name, dev->name);
        return -1;
    }

    /* Find the parent bus */
    if (virPCIDeviceGetParent(dev, &parent) < 0)
        return -1;
    if (!parent) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find parent device for %1$s"),
                       dev->name);
        return -1;
    }
    if ((parentfd = virPCIDeviceConfigOpenWrite(parent)) < 0)
        goto out;

    VIR_DEBUG("%s %s: doing a secondary bus reset", dev->id, dev->name);

    /* Save and restore the device's config space; we only do this
     * for the supplied device since we refuse to do a reset if there
     * are multiple devices/functions
     */
    if (virPCIDeviceRead(dev, cfgfd, 0, config_space, PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read PCI config space for %1$s"),
                       dev->name);
        goto out;
    }

    /* Read the control register, set the reset flag, wait 200ms,
     * unset the reset flag and wait 200ms.
     */
    ctl = virPCIDeviceRead16(dev, parentfd, PCI_BRIDGE_CONTROL);

    virPCIDeviceWrite16(parent, parentfd, PCI_BRIDGE_CONTROL,
                        ctl | PCI_BRIDGE_CTL_RESET);

    g_usleep(200 * 1000); /* sleep 200ms */

    virPCIDeviceWrite16(parent, parentfd, PCI_BRIDGE_CONTROL, ctl);

    g_usleep(200 * 1000); /* sleep 200ms */

    if (virPCIDeviceWrite(dev, cfgfd, 0, config_space, PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to restore PCI config space for %1$s"),
                       dev->name);
        goto out;
    }
    ret = 0;

 out:
    virPCIDeviceConfigClose(parent, parentfd);
    return ret;
}

/* Power management reset attempts to reset a device using a
 * D-state transition from D3hot to D0. Note, in detect_pm_reset()
 * above we require the device supports a full internal reset.
 */
static int
virPCIDeviceTryPowerManagementReset(virPCIDevice *dev, int cfgfd)
{
    uint8_t config_space[PCI_CONF_LEN];
    uint32_t ctl;

    if (!dev->pci_pm_cap_pos)
        return -1;

    /* Save and restore the device's config space. */
    if (virPCIDeviceRead(dev, cfgfd, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read PCI config space for %1$s"),
                       dev->name);
        return -1;
    }

    VIR_DEBUG("%s %s: doing a power management reset", dev->id, dev->name);

    ctl = virPCIDeviceRead32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL);
    ctl &= ~PCI_PM_CTRL_STATE_MASK;

    virPCIDeviceWrite32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL,
                        ctl | PCI_PM_CTRL_STATE_D3hot);

    g_usleep(10 * 1000); /* sleep 10ms */

    virPCIDeviceWrite32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL,
                        ctl | PCI_PM_CTRL_STATE_D0);

    g_usleep(10 * 1000); /* sleep 10ms */

    if (virPCIDeviceWrite(dev, cfgfd, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to restore PCI config space for %1$s"),
                       dev->name);
        return -1;
    }

    return 0;
}

/**
 * virPCIDeviceInit:
 * @dev: virPCIDevice object needing its PCI capabilities info initialized
 * @cfgfd: open file descriptor for device config file in sysfs
 *
 * Initialize the PCI capabilities attributes of a virPCIDevice object
 * (i.e. pcie_cap_pos, pci_pm_cap_pos, has_flr, has_pm_reset, and
 * is_pcie). This is done by walking the info in the (already-opened)
 * device PCI config file in sysfs. This function can be called
 * regardless of whether a process has sufficient privilege to read
 * the entire file (unprivileged processes can only read the 1st 64
 * bytes, while the Express Capabilities are all located beyond that
 * boundary).
 *
 * In the case that we are unable to read a capability
 * directly, we will attempt to infer its value by other means. In
 * particular, we can determine that a device is (almost surely) PCIe
 * by checking that the length of the config file is != 256 (since all
 * conventional PCI config files are 256 bytes), and we know that any
 * device that is an SR-IOV VF will have FLR available (since that is
 * required by the SR-IOV spec.)
 *
 * Always returns success (0) (for now)
 */
static int
virPCIDeviceInit(virPCIDevice *dev, int cfgfd)
{
    dev->is_pcie = false;
    if (virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_EXP, &dev->pcie_cap_pos) < 0) {
        /* an unprivileged process is unable to read *all* of a
         * device's PCI config (it can only read the first 64
         * bytes, which isn't enough for see the Express
         * Capabilities data). If virPCIDeviceFindCapabilityOffset
         * returns failure (and not just a pcie_cap_pos == 0,
         * which is *success* at determining the device is *not*
         * PCIe) we make an educated guess based on the length of
         * the device's config file - if it is 256 bytes, then it
         * is definitely a legacy PCI device. If it's larger than
         * that, then it is *probably PCIe (although it could be
         * PCI-x, but those are extremely rare). If the config
         * file can't be found (in which case the "length" will be
         * -1), then we blindly assume the most likely outcome -
         * PCIe.
         */
        off_t configLen = virFileLength(virPCIDeviceGetConfigPath(dev), -1);

        if (configLen != 256)
            dev->is_pcie = true;

    } else {
        dev->is_pcie = (dev->pcie_cap_pos != 0);
    }

    virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_PM, &dev->pci_pm_cap_pos);
    dev->has_flr = virPCIDeviceDetectFunctionLevelReset(dev, cfgfd);
    dev->has_pm_reset = virPCIDeviceDetectPowerManagementReset(dev, cfgfd);

    return 0;
}

int
virPCIDeviceReset(virPCIDevice *dev,
                  virPCIDeviceList *activeDevs,
                  virPCIDeviceList *inactiveDevs)
{
    g_autofree char *drvName = NULL;
    virPCIStubDriver drvType;
    int ret = -1;
    int fd = -1;
    int hdrType = -1;

    if (virPCIGetHeaderType(dev, &hdrType) < 0)
        return -1;

    if (hdrType != VIR_PCI_HEADER_ENDPOINT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid attempt to reset PCI device %1$s. Only PCI endpoint devices can be reset"),
                       dev->name);
        return -1;
    }

    if (activeDevs && virPCIDeviceListFind(activeDevs, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not resetting active device %1$s"), dev->name);
        return -1;
    }

    /* If the device is currently bound to vfio-pci, ignore all
     * requests to reset it, since the vfio-pci driver will always
     * reset it whenever appropriate, so doing it ourselves would just
     * be redundant.
     */
    if (virPCIDeviceGetCurrentDriverNameAndType(dev, &drvName, &drvType) < 0)
        goto cleanup;

    if (drvType == VIR_PCI_STUB_DRIVER_VFIO) {

        VIR_DEBUG("Device %s is bound to %s - skip reset", dev->name, drvName);
        ret = 0;
        goto cleanup;
    }

    VIR_DEBUG("Resetting device %s", dev->name);

    if ((fd = virPCIDeviceConfigOpenWrite(dev)) < 0)
        goto cleanup;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    /* KVM will perform FLR when starting and stopping
     * a guest, so there is no need for us to do it here.
     */
    if (dev->has_flr) {
        ret = 0;
        goto cleanup;
    }

    /* If the device supports PCI power management reset,
     * that's the next best thing because it only resets
     * the function, not the whole device.
     */
    if (dev->has_pm_reset)
        ret = virPCIDeviceTryPowerManagementReset(dev, fd);

    /* Bus reset is not an option with the root bus */
    if (ret < 0 && dev->address.bus != 0)
        ret = virPCIDeviceTrySecondaryBusReset(dev, fd, inactiveDevs);

    if (ret < 0) {
        virErrorPtr err = virGetLastError();
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to reset PCI device %1$s: %2$s"),
                       dev->name,
                       err ? err->message :
                       _("no FLR, PM reset or bus reset available"));
    }

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}


static int
virPCIProbeDriver(const char *driverName)
{
    g_autofree char *drvpath = NULL;
    g_autofree char *errbuf = NULL;

    drvpath = virPCIDriverDir(driverName);

    /* driver previously loaded, return */
    if (virFileExists(drvpath))
        return 0;

    if ((errbuf = virKModLoad(driverName))) {
        VIR_WARN("failed to load driver %s: %s", driverName, errbuf);
        goto cleanup;
    }

    /* driver loaded after probing */
    if (virFileExists(drvpath))
        return 0;

 cleanup:
    /* If we know failure was because of admin config, let's report that;
     * otherwise, report a more generic failure message
     */
    if (virKModIsProhibited(driverName)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI driver module %1$s: administratively prohibited"),
                       driverName);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI driver module %1$s"),
                       driverName);
    }

    return -1;
}

int
virPCIDeviceUnbind(virPCIDevice *dev)
{
    g_autofree char *path = NULL;
    g_autofree char *drvpath = NULL;
    g_autofree char *driver = NULL;

    if (virPCIDeviceGetCurrentDriverPathAndName(dev, &drvpath, &driver) < 0)
        return -1;

    if (!driver)
        /* The device is not bound to any driver */
        return 0;

    path = virPCIFile(dev->name, "driver/unbind");

    if (virFileExists(path)) {
        if (virFileWriteStr(path, dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to unbind PCI device '%1$s' from %2$s"),
                                 dev->name, driver);
            return -1;
        }
    }

    return 0;
}


/**
 * virPCIDeviceRebind:
 *  @dev: virPCIDevice object describing the device to rebind
 *
 * unbind a device from its driver, then immediately rebind it.
 *
 * Returns 0 on success, -1 on failure
 */
int virPCIDeviceRebind(virPCIDevice *dev)
{
    if (virPCIDeviceUnbind(dev) < 0)
        return -1;

    if (virFileWriteStr(PCI_SYSFS "drivers_probe", dev->name, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to trigger a probe for PCI device '%1$s'"),
                             dev->name);
        return -1;
    }

    return 0;
}


/*
 * Bind a PCI device to a driver using driver_override sysfs interface.
 * E.g.
 *
 *  echo driver-name > /sys/bus/pci/devices/0000:03:00.0/driver_override
 *  echo 0000:03:00.0 > /sys/bus/pci/devices/0000:03:00.0/driver/unbind
 *  echo 0000:03:00.0 > /sys/bus/pci/drivers_probe
 *
 * An empty driverName will cause the device to be bound to its
 * preferred driver.
 */
static int
virPCIDeviceBindWithDriverOverride(virPCIDevice *dev,
                                   const char *driverName)
{
    g_autofree char *path = NULL;

    path = virPCIFile(dev->name, "driver_override");

    if (virFileWriteStr(path, driverName, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to add driver '%1$s' to driver_override interface of PCI device '%2$s'"),
                             driverName, dev->name);
        return -1;
    }

    if (virPCIDeviceRebind(dev) < 0)
        return -1;

    return 0;
}

static int
virPCIDeviceUnbindFromStub(virPCIDevice *dev)
{
    if (!dev->unbind_from_stub) {
        VIR_DEBUG("Unbind from stub skipped for PCI device %s", dev->name);
        return 0;
    }

    return virPCIDeviceBindWithDriverOverride(dev, "\n");
}

static int
virPCIDeviceBindToStub(virPCIDevice *dev)
{
    const char *stubDriverName = dev->stubDriverName;
    g_autofree char *stubDriverPath = NULL;
    g_autofree char *driverLink = NULL;


    if (dev->stubDriverType == VIR_PCI_STUB_DRIVER_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No stub driver configured for PCI device %1$s"),
                       dev->name);
        return -1;
    }

    if (!stubDriverName
        && !(stubDriverName = virPCIStubDriverTypeToString(dev->stubDriverType))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown stub driver configured for PCI device %1$s"),
                       dev->name);
        return -1;
    }

    if (virPCIProbeDriver(stubDriverName) < 0)
        return -1;

    stubDriverPath = virPCIDriverDir(stubDriverName);
    driverLink = virPCIFile(dev->name, "driver");

    if (virFileExists(driverLink)) {
        if (virFileLinkPointsTo(driverLink, stubDriverPath)) {
            /* The device is already bound to the correct driver */
            VIR_DEBUG("Device %s is already bound to %s",
                      dev->name, stubDriverName);
            return 0;
        }
    }

    if (virPCIDeviceBindWithDriverOverride(dev, stubDriverName) < 0)
        return -1;

    dev->unbind_from_stub = true;
    return 0;
}

/* virPCIDeviceDetach:
 *
 * Detach this device from the host driver, attach it to the stub
 * driver (previously set with virPCIDeviceSetStubDriverType(), and
 * add *a copy* of the object to the inactiveDevs list (if provided).
 * This function will *never* consume dev, so the caller should free
 * it.
 *
 * Returns 0 on success, -1 on failure (will fail if the device is
 * already in the activeDevs list, but will be a NOP if the device is
 * already bound to the stub).
 *
 * GENERAL NOTE: activeDevs should be a list of all PCI devices
 * currently in use by a domain. inactiveDevs is a list of all PCI
 * devices that libvirt has detached from the host driver + attached
 * to the stub driver, but hasn't yet assigned to a domain. Any device
 * that is still attached to its host driver should not be on either
 * list.
 */
int
virPCIDeviceDetach(virPCIDevice *dev,
                   virPCIDeviceList *activeDevs,
                   virPCIDeviceList *inactiveDevs)
{
    if (activeDevs && virPCIDeviceListFind(activeDevs, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not detaching active device %1$s"), dev->name);
        return -1;
    }

    if (virPCIDeviceBindToStub(dev) < 0)
        return -1;

    /* Add *a copy of* the dev into list inactiveDevs, if
     * it's not already there.
     */
    if (inactiveDevs && !virPCIDeviceListFind(inactiveDevs, &dev->address)) {
        VIR_DEBUG("Adding PCI device %s to inactive list", dev->name);
        if (virPCIDeviceListAddCopy(inactiveDevs, dev) < 0)
            return -1;
    }

    return 0;
}

/*
 * Pre-condition: inactivePCIHostdevs & activePCIHostdevs
 * are locked
 */
int
virPCIDeviceReattach(virPCIDevice *dev,
                     virPCIDeviceList *activeDevs,
                     virPCIDeviceList *inactiveDevs)
{
    if (activeDevs && virPCIDeviceListFind(activeDevs, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not reattaching active device %1$s"), dev->name);
        return -1;
    }

    if (virPCIDeviceUnbindFromStub(dev) < 0)
        return -1;

    /* Steal the dev from list inactiveDevs */
    if (inactiveDevs) {
        VIR_DEBUG("Removing PCI device %s from inactive list", dev->name);
        virPCIDeviceListDel(inactiveDevs, &dev->address);
    }

    return 0;
}

static char *
virPCIDeviceReadID(virPCIDevice *dev, const char *id_name)
{
    g_autofree char *path = NULL;
    g_autofree char *id_str = NULL;

    path = virPCIFile(dev->name, id_name);

    /* ID string is '0xNNNN\n' ... i.e. 7 bytes */
    if (virFileReadAll(path, 7, &id_str) < 0)
        return NULL;

    /* Check for 0x suffix */
    if (id_str[0] != '0' || id_str[1] != 'x')
        return NULL;

    /* Chop off the newline; we know the string is 7 bytes */
    id_str[6] = '\0';

    return g_steal_pointer(&id_str);
}

bool
virPCIDeviceAddressIsValid(virPCIDeviceAddress *addr,
                           bool report)
{
    if (addr->bus > 0xFF) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address bus='0x%1$x', must be <= 0xFF"),
                           addr->bus);
        return false;
    }
    if (addr->slot > 0x1F) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address slot='0x%1$x', must be <= 0x1F"),
                           addr->slot);
        return false;
    }
    if (addr->function > 7) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address function=0x%1$x, must be <= 7"),
                           addr->function);
        return false;
    }
    if (virPCIDeviceAddressIsEmpty(addr)) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid PCI address 0000:00:00, at least one of domain, bus, or slot must be > 0"));
        return false;
    }
    return true;
}

bool
virPCIDeviceAddressIsEmpty(const virPCIDeviceAddress *addr)
{
    return !(addr->domain || addr->bus || addr->slot);
}

bool
virPCIDeviceAddressEqual(const virPCIDeviceAddress *addr1,
                         const virPCIDeviceAddress *addr2)
{
    if (addr1->domain == addr2->domain &&
        addr1->bus == addr2->bus &&
        addr1->slot == addr2->slot &&
        addr1->function == addr2->function) {
        return true;
    }
    return false;
}

/**
 * virPCIDeviceAddressCopy:
 * @dst: where to store address
 * @src: source address to copy
 *
 * Creates a deep copy of given @src address and stores it into
 * @dst which has to be pre-allocated by caller.
 */
void virPCIDeviceAddressCopy(virPCIDeviceAddress *dst,
                             const virPCIDeviceAddress *src)
{
    memcpy(dst, src, sizeof(*src));
}

char *
virPCIDeviceAddressAsString(const virPCIDeviceAddress *addr)
{
    return g_strdup_printf(VIR_PCI_DEVICE_ADDRESS_FMT, addr->domain,
                           addr->bus, addr->slot, addr->function);
}

bool
virPCIDeviceExists(const virPCIDeviceAddress *addr)
{
    g_autofree char *devName = virPCIDeviceAddressAsString(addr);
    g_autofree char *devPath = g_strdup_printf(PCI_SYSFS "devices/%s/config",
                                               devName);

    return virFileExists(devPath);
}

virPCIDevice *
virPCIDeviceNew(const virPCIDeviceAddress *address)
{
    g_autoptr(virPCIDevice) dev = NULL;
    g_autofree char *vendor = NULL;
    g_autofree char *product = NULL;

    dev = g_new0(virPCIDevice, 1);

    virPCIDeviceAddressCopy(&dev->address, address);

    dev->name = virPCIDeviceAddressAsString(&dev->address);

    dev->path = g_strdup_printf(PCI_SYSFS "devices/%s/config", dev->name);

    if (!virFileExists(dev->path)) {
        virReportSystemError(errno,
                             _("Device %1$s not found: could not access %2$s"),
                             dev->name, dev->path);
        return NULL;
    }

    vendor  = virPCIDeviceReadID(dev, "vendor");
    product = virPCIDeviceReadID(dev, "device");

    if (!vendor || !product) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read product/vendor ID for %1$s"),
                       dev->name);
        return NULL;
    }

    /* strings contain '0x' prefix */
    if (g_snprintf(dev->id, sizeof(dev->id), "%s %s", &vendor[2],
                   &product[2]) >= sizeof(dev->id)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->id buffer overflow: %1$s %2$s"),
                       &vendor[2], &product[2]);
        return NULL;
    }

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

    return g_steal_pointer(&dev);
}


virPCIDevice *
virPCIDeviceCopy(virPCIDevice *dev)
{
    virPCIDevice *copy;

    copy = g_new0(virPCIDevice, 1);

    /* shallow copy to take care of most attributes */
    *copy = *dev;
    copy->path = NULL;
    copy->used_by_drvname = copy->used_by_domname = NULL;
    copy->name = g_strdup(dev->name);
    copy->path = g_strdup(dev->path);
    copy->used_by_drvname = g_strdup(dev->used_by_drvname);
    copy->used_by_domname = g_strdup(dev->used_by_domname);
    copy->stubDriverName = g_strdup(dev->stubDriverName);
    return copy;
}


void
virPCIDeviceFree(virPCIDevice *dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    g_free(dev->name);
    g_free(dev->path);
    g_free(dev->used_by_drvname);
    g_free(dev->used_by_domname);
    g_free(dev->stubDriverName);
    g_free(dev);
}

/**
 * virPCIDeviceGetAddress:
 * @dev: device to get address from
 *
 * Take a PCI device on input and return its PCI address. The
 * returned object is owned by the device and must not be freed.
 *
 * Returns: a pointer to the address, which can never be NULL.
 */
virPCIDeviceAddress *
virPCIDeviceGetAddress(virPCIDevice *dev)
{
    return &(dev->address);
}

const char *
virPCIDeviceGetName(virPCIDevice *dev)
{
    return dev->name;
}

/**
 * virPCIDeviceGetConfigPath:
 *
 * Returns a pointer to a string containing the path of @dev's PCI
 * config file.
 */
const char *
virPCIDeviceGetConfigPath(virPCIDevice *dev)
{
    return dev->path;
}

void virPCIDeviceSetManaged(virPCIDevice *dev, bool managed)
{
    dev->managed = managed;
}

bool
virPCIDeviceGetManaged(virPCIDevice *dev)
{
    return dev->managed;
}

void
virPCIDeviceSetStubDriverType(virPCIDevice *dev, virPCIStubDriver driverType)
{
    dev->stubDriverType = driverType;
}

virPCIStubDriver
virPCIDeviceGetStubDriverType(virPCIDevice *dev)
{
    return dev->stubDriverType;
}

void
virPCIDeviceSetStubDriverName(virPCIDevice *dev,
                                   const char *driverName)
{
    g_free(dev->stubDriverName);
    dev->stubDriverName = g_strdup(driverName);
}

const char *
virPCIDeviceGetStubDriverName(virPCIDevice *dev)
{
    return dev->stubDriverName;
}

bool
virPCIDeviceGetUnbindFromStub(virPCIDevice *dev)
{
    return dev->unbind_from_stub;
}

void
virPCIDeviceSetUnbindFromStub(virPCIDevice *dev, bool unbind)
{
    dev->unbind_from_stub = unbind;
}

bool
virPCIDeviceGetRemoveSlot(virPCIDevice *dev)
{
    return dev->remove_slot;
}

void
virPCIDeviceSetRemoveSlot(virPCIDevice *dev, bool remove_slot)
{
    dev->remove_slot = remove_slot;
}

bool
virPCIDeviceGetReprobe(virPCIDevice *dev)
{
    return dev->reprobe;
}

void
virPCIDeviceSetReprobe(virPCIDevice *dev, bool reprobe)
{
    dev->reprobe = reprobe;
}

int
virPCIDeviceSetUsedBy(virPCIDevice *dev,
                      const char *drv_name,
                      const char *dom_name)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    dev->used_by_drvname = g_strdup(drv_name);
    dev->used_by_domname = g_strdup(dom_name);

    return 0;
}

void
virPCIDeviceGetUsedBy(virPCIDevice *dev,
                      const char **drv_name,
                      const char **dom_name)
{
    *drv_name = dev->used_by_drvname;
    *dom_name = dev->used_by_domname;
}

virPCIDeviceList *
virPCIDeviceListNew(void)
{
    virPCIDeviceList *list;

    if (virPCIInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virPCIDeviceListClass)))
        return NULL;

    return list;
}

static void
virPCIDeviceListDispose(void *obj)
{
    virPCIDeviceList *list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        g_clear_pointer(&list->devs[i], virPCIDeviceFree);
    }

    list->count = 0;
    g_free(list->devs);
}

int
virPCIDeviceListAdd(virPCIDeviceList *list,
                    virPCIDevice *dev)
{
    if (virPCIDeviceListFind(list, &dev->address)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %1$s is already in use"), dev->name);
        return -1;
    }
    VIR_APPEND_ELEMENT(list->devs, list->count, dev);

    return 0;
}


/* virPCIDeviceListAddCopy - add a *copy* of the device to this list */
int
virPCIDeviceListAddCopy(virPCIDeviceList *list, virPCIDevice *dev)
{
    g_autoptr(virPCIDevice) copy = virPCIDeviceCopy(dev);

    if (!copy)
        return -1;
    if (virPCIDeviceListAdd(list, copy) < 0)
        return -1;

    copy = NULL;
    return 0;
}


virPCIDevice *
virPCIDeviceListGet(virPCIDeviceList *list,
                    int idx)
{
    if (idx >= list->count)
        return NULL;
    if (idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virPCIDeviceListCount(virPCIDeviceList *list)
{
    return list->count;
}

virPCIDevice *
virPCIDeviceListStealIndex(virPCIDeviceList *list,
                           int idx)
{
    virPCIDevice *ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}

virPCIDevice *
virPCIDeviceListSteal(virPCIDeviceList *list,
                      virPCIDeviceAddress *devAddr)
{
    return virPCIDeviceListStealIndex(list, virPCIDeviceListFindIndex(list, devAddr));
}

void
virPCIDeviceListDel(virPCIDeviceList *list,
                    virPCIDeviceAddress *devAddr)
{
    virPCIDeviceFree(virPCIDeviceListSteal(list, devAddr));
}

int
virPCIDeviceListFindIndex(virPCIDeviceList *list,
                          virPCIDeviceAddress *devAddr)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virPCIDevice *other = list->devs[i];
        if (other->address.domain   == devAddr->domain &&
            other->address.bus      == devAddr->bus    &&
            other->address.slot     == devAddr->slot   &&
            other->address.function == devAddr->function)
            return i;
    }
    return -1;
}


virPCIDevice *
virPCIDeviceListFindByIDs(virPCIDeviceList *list,
                          unsigned int domain,
                          unsigned int bus,
                          unsigned int slot,
                          unsigned int function)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virPCIDevice *other = list->devs[i];
        if (other->address.domain   == domain &&
            other->address.bus      == bus    &&
            other->address.slot     == slot   &&
            other->address.function == function)
            return list->devs[i];
    }
    return NULL;
}


virPCIDevice *
virPCIDeviceListFind(virPCIDeviceList *list, virPCIDeviceAddress *devAddr)
{
    int idx;

    if ((idx = virPCIDeviceListFindIndex(list, devAddr)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


int virPCIDeviceFileIterate(virPCIDevice *dev,
                            virPCIDeviceFileActor actor,
                            void *opaque)
{
    g_autofree char *pcidir = NULL;
    g_autoptr(DIR) dir = NULL;
    struct dirent *ent;
    int direrr;

    pcidir = g_strdup_printf("/sys/bus/pci/devices/" VIR_PCI_DEVICE_ADDRESS_FMT,
                             dev->address.domain, dev->address.bus, dev->address.slot,
                             dev->address.function);

    if (virDirOpen(&dir, pcidir) < 0)
        return -1;

    while ((direrr = virDirRead(dir, &ent, pcidir)) > 0) {
        g_autofree char *file = NULL;
        /* Device assignment requires:
         *   $PCIDIR/config, $PCIDIR/resource, $PCIDIR/resourceNNN,
         *   $PCIDIR/rom, $PCIDIR/reset, $PCIDIR/vendor, $PCIDIR/device
         */
        if (STREQ(ent->d_name, "config") ||
            STRPREFIX(ent->d_name, "resource") ||
            STREQ(ent->d_name, "rom") ||
            STREQ(ent->d_name, "vendor") ||
            STREQ(ent->d_name, "device") ||
            STREQ(ent->d_name, "reset")) {
            file = g_strdup_printf("%s/%s", pcidir, ent->d_name);
            if ((actor)(dev, file, opaque) < 0)
                return -1;
        }
    }
    if (direrr < 0)
        return -1;

    return 0;
}


/* virPCIDeviceAddressIOMMUGroupIterate:
 *   Call @actor for all devices in the same iommu_group as orig
 *   (including orig itself) Even if there is no iommu_group for the
 *   device, call @actor once for orig.
 */
int
virPCIDeviceAddressIOMMUGroupIterate(virPCIDeviceAddress *orig,
                                     virPCIDeviceAddressActor actor,
                                     void *opaque)
{
    g_autofree char *groupPath = NULL;
    g_autoptr(DIR) groupDir = NULL;
    struct dirent *ent;
    int direrr;

    groupPath = g_strdup_printf(PCI_SYSFS "devices/" VIR_PCI_DEVICE_ADDRESS_FMT "/iommu_group/devices",
                                orig->domain, orig->bus, orig->slot, orig->function);

    if (virDirOpenQuiet(&groupDir, groupPath) < 0) {
        /* just process the original device, nothing more */
        return (actor)(orig, opaque);
    }

    while ((direrr = virDirRead(groupDir, &ent, groupPath)) > 0) {
        virPCIDeviceAddress newDev = { 0 };

        if (virPCIDeviceAddressParse(ent->d_name, &newDev) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Found invalid device link '%1$s' in '%2$s'"),
                           ent->d_name, groupPath);
            return -1;
        }

        if ((actor)(&newDev, opaque) < 0)
            return -1;
    }
    if (direrr < 0)
        return -1;

    return 0;
}


static int
virPCIDeviceGetIOMMUGroupAddOne(virPCIDeviceAddress *newDevAddr, void *opaque)
{
    virPCIDeviceList *groupList = opaque;
    g_autoptr(virPCIDevice) newDev = NULL;

    if (!(newDev = virPCIDeviceNew(newDevAddr)))
        return -1;

    if (virPCIDeviceListAdd(groupList, newDev) < 0)
        return -1;

    newDev = NULL; /* it's now on the list */
    return 0;
}


/*
 * virPCIDeviceGetIOMMUGroupList - return a virPCIDeviceList containing
 * all of the devices in the same iommu_group as @dev.
 *
 * Return the new list, or NULL on failure
 */
virPCIDeviceList *
virPCIDeviceGetIOMMUGroupList(virPCIDevice *dev)
{
    virPCIDeviceList *groupList = virPCIDeviceListNew();

    if (!groupList)
        goto error;

    if (virPCIDeviceAddressIOMMUGroupIterate(&(dev->address),
                                             virPCIDeviceGetIOMMUGroupAddOne,
                                             groupList) < 0)
        goto error;

    return groupList;

 error:
    virObjectUnref(groupList);
    return NULL;
}


typedef struct {
    virPCIDeviceAddress ***iommuGroupDevices;
    size_t *nIommuGroupDevices;
} virPCIDeviceAddressList;

static int
virPCIGetIOMMUGroupAddressesAddOne(virPCIDeviceAddress *newDevAddr, void *opaque)
{
    virPCIDeviceAddressList *addrList = opaque;
    g_autofree virPCIDeviceAddress *copyAddr = NULL;

    /* make a copy to insert onto the list */
    copyAddr = g_new0(virPCIDeviceAddress, 1);

    *copyAddr = *newDevAddr;

    VIR_APPEND_ELEMENT(*addrList->iommuGroupDevices,
                       *addrList->nIommuGroupDevices, copyAddr);

    return 0;
}


/*
 * virPCIDeviceAddressGetIOMMUGroupAddresses - return a
 * virPCIDeviceList containing all of the devices in the same
 * iommu_group as @dev.
 *
 * Return the new list, or NULL on failure
 */
int
virPCIDeviceAddressGetIOMMUGroupAddresses(virPCIDeviceAddress *devAddr,
                                          virPCIDeviceAddress ***iommuGroupDevices,
                                          size_t *nIommuGroupDevices)
{
    virPCIDeviceAddressList addrList = { iommuGroupDevices,
                                         nIommuGroupDevices };

    if (virPCIDeviceAddressIOMMUGroupIterate(devAddr,
                                             virPCIGetIOMMUGroupAddressesAddOne,
                                             &addrList) < 0)
        return -1;

    return 0;
}


/* virPCIDeviceAddressGetIOMMUGroupNum - return the group number of
 * this PCI device's iommu_group, or -2 if there is no iommu_group for
 * the device (or -1 if there was any other error)
 */
int
virPCIDeviceAddressGetIOMMUGroupNum(virPCIDeviceAddress *addr)
{
    g_autofree char *devName = NULL;
    g_autofree char *devPath = NULL;
    g_autofree char *groupPath = NULL;
    g_autofree char *groupNumStr = NULL;
    unsigned int groupNum;

    devName = virPCIDeviceAddressAsString(addr);

    devPath = virPCIFile(devName, "iommu_group");

    if (virFileIsLink(devPath) != 1)
        return -2;
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %1$s iommu_group symlink %2$s"),
                       devName, devPath);
        return -1;
    }

    groupNumStr = g_path_get_basename(groupPath);
    if (virStrToLong_ui(groupNumStr, NULL, 10, &groupNum) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device %1$s iommu_group symlink %2$s has invalid group number %3$s"),
                       devName, groupPath, groupNumStr);
        return -1;
    }

    return groupNum;
}


char *
virPCIDeviceAddressGetIOMMUGroupDev(const virPCIDeviceAddress *devAddr)
{
    g_autoptr(virPCIDevice) pci = NULL;

    if (!(pci = virPCIDeviceNew(devAddr)))
        return NULL;

    return virPCIDeviceGetIOMMUGroupDev(pci);
}


/* virPCIDeviceGetIOMMUGroupDev - return the name of the device used
 * to control this PCI device's group (e.g. "/dev/vfio/15")
 */
char *
virPCIDeviceGetIOMMUGroupDev(virPCIDevice *dev)
{
    g_autofree char *devPath = NULL;
    g_autofree char *groupPath = NULL;
    g_autofree char *groupFile = NULL;

    devPath = virPCIFile(dev->name, "iommu_group");

    if (virFileIsLink(devPath) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device %1$s iommu_group file %2$s is not a symlink"),
                       dev->name, devPath);
        return NULL;
    }
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %1$s iommu_group symlink %2$s"),
                       dev->name, devPath);
        return NULL;
    }
    groupFile = g_path_get_basename(groupPath);

    return g_strdup_printf("/dev/vfio/%s", groupFile);
}

static int
virPCIDeviceDownstreamLacksACS(virPCIDevice *dev)
{
    uint16_t flags;
    uint16_t ctrl;
    unsigned int pos;
    int fd;
    int ret = 0;
    uint16_t device_class;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return -1;

    if (virPCIDeviceInit(dev, fd) < 0) {
        ret = -1;
        goto cleanup;
    }

    if (virPCIDeviceReadClass(dev, &device_class) < 0)
        goto cleanup;

    pos = dev->pcie_cap_pos;
    if (!pos || device_class != PCI_CLASS_BRIDGE_PCI)
        goto cleanup;

    flags = virPCIDeviceRead16(dev, fd, pos + PCI_EXP_FLAGS);
    if (((flags & PCI_EXP_FLAGS_TYPE) >> 4) != PCI_EXP_TYPE_DOWNSTREAM)
        goto cleanup;

    pos = virPCIDeviceFindExtendedCapabilityOffset(dev, fd, PCI_EXT_CAP_ID_ACS);
    if (!pos) {
        VIR_DEBUG("%s %s: downstream port lacks ACS", dev->id, dev->name);
        ret = 1;
        goto cleanup;
    }

    ctrl = virPCIDeviceRead16(dev, fd, pos + PCI_EXT_ACS_CTRL);
    if ((ctrl & PCI_EXT_CAP_ACS_ENABLED) != PCI_EXT_CAP_ACS_ENABLED) {
        VIR_DEBUG("%s %s: downstream port has ACS disabled",
                  dev->id, dev->name);
        ret = 1;
        goto cleanup;
    }

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}

static int
virPCIDeviceIsBehindSwitchLackingACS(virPCIDevice *dev)
{
    g_autoptr(virPCIDevice) parent = NULL;

    if (virPCIDeviceGetParent(dev, &parent) < 0)
        return -1;
    if (!parent) {
        /* if we have no parent, and this is the root bus, ACS doesn't come
         * into play since devices on the root bus can't P2P without going
         * through the root IOMMU.
         */
        if (dev->address.bus == 0) {
            return 0;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to find parent device for %1$s"),
                           dev->name);
            return -1;
        }
    }

    /* XXX we should rather fail when we can't find device's parent and
     * stop the loop when we get to root instead of just stopping when no
     * parent can be found
     */
    do {
        g_autoptr(virPCIDevice) tmp = NULL;
        int acs;
        int ret;

        acs = virPCIDeviceDownstreamLacksACS(parent);

        if (acs) {
            if (acs < 0)
                return -1;
            else
                return 1;
        }

        tmp = g_steal_pointer(&parent);
        ret = virPCIDeviceGetParent(tmp, &parent);
        if (ret < 0)
            return -1;
    } while (parent);

    return 0;
}

int virPCIDeviceIsAssignable(virPCIDevice *dev,
                             int strict_acs_check)
{
    int ret;

    /* XXX This could be a great place to actually check that a non-managed
     * device isn't in use, e.g. by checking that device is either un-bound
     * or bound to a stub driver.
     */

    ret = virPCIDeviceIsBehindSwitchLackingACS(dev);
    if (ret < 0)
        return 0;

    if (ret) {
        if (!strict_acs_check) {
            VIR_DEBUG("%s %s: strict ACS check disabled; device assignment allowed",
                      dev->id, dev->name);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Device %1$s is behind a switch lacking ACS and cannot be assigned"),
                           dev->name);
            return 0;
        }
    }

    return 1;
}

static int
logStrToLong_ui(char const *s,
                char **end_ptr,
                int base,
                unsigned int *result)
{
    int ret = 0;

    ret = virStrToLong_ui(s, end_ptr, base, result);
    if (ret != 0)
        VIR_ERROR(_("Failed to convert '%1$s' to unsigned int"), s);
    return ret;
}

int
virPCIDeviceAddressParse(char *address,
                         virPCIDeviceAddress *bdf)
{
    char *p = NULL;

    if ((address == NULL) || (logStrToLong_ui(address, &p, 16,
                                              &bdf->domain) == -1)) {
        return -1;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->bus) == -1)) {
        return -1;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->slot) == -1)) {
        return -1;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->function) == -1)) {
        return -1;
    }

    return 0;
}


bool
virZPCIDeviceAddressIsIncomplete(const virZPCIDeviceAddress *addr)
{
    return !addr->uid.isSet || !addr->fid.isSet;
}


bool
virZPCIDeviceAddressIsPresent(const virZPCIDeviceAddress *addr)
{
    return addr->uid.isSet || addr->fid.isSet;
}


void
virPCIVirtualFunctionListFree(virPCIVirtualFunctionList *list)
{
    size_t i;

    if (!list)
        return;

    for (i = 0; i < list->nfunctions; i++) {
        g_free(list->functions[i].addr);
        g_free(list->functions[i].ifname);
    }

    g_free(list->functions);
    g_free(list);
}


int
virPCIGetVirtualFunctions(const char *sysfs_path,
                          virPCIVirtualFunctionList **vfs)
{
    return virPCIGetVirtualFunctionsFull(sysfs_path, vfs, NULL);
}


#ifdef __linux__

virPCIDeviceAddress *
virPCIGetDeviceAddressFromSysfsLink(const char *device_link)
{
    g_autofree virPCIDeviceAddress *bdf = NULL;
    g_autofree char *config_address = NULL;
    g_autofree char *device_path = NULL;

    if (!virFileExists(device_link)) {
        VIR_DEBUG("'%s' does not exist", device_link);
        return NULL;
    }

    device_path = virFileCanonicalizePath(device_link);
    if (device_path == NULL) {
        virReportSystemError(errno,
                             _("Failed to resolve device link '%1$s'"),
                             device_link);
        return NULL;
    }

    config_address = g_path_get_basename(device_path);
    bdf = g_new0(virPCIDeviceAddress, 1);

    if (virPCIDeviceAddressParse(config_address, bdf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse PCI config address '%1$s'"),
                       config_address);
        return NULL;
    }

    return g_steal_pointer(&bdf);
}

/**
 * virPCIGetPhysicalFunction:
 * @vf_sysfs_path: sysfs path for the virtual function
 * @pf: where to store the physical function's address
 *
 * Given @vf_sysfs_path, this function will store the pointer
 * to a newly-allocated virPCIDeviceAddress in @pf.
 *
 * @pf might be NULL if @vf_sysfs_path does not point to a
 * virtual function. If it's not NULL, then it should be
 * freed by the caller when no longer needed.
 *
 * Returns: >=0 on success, <0 on failure
 */
int
virPCIGetPhysicalFunction(const char *vf_sysfs_path,
                          virPCIDeviceAddress **pf)
{
    g_autofree char *device_link = NULL;

    *pf = NULL;

    device_link = g_build_filename(vf_sysfs_path, "physfn", NULL);

    if ((*pf = virPCIGetDeviceAddressFromSysfsLink(device_link))) {
        VIR_DEBUG("PF for VF device '%s': " VIR_PCI_DEVICE_ADDRESS_FMT,
                  vf_sysfs_path,
                  (*pf)->domain, (*pf)->bus, (*pf)->slot, (*pf)->function);
    }

    return 0;
}


/**
 * virPCIGetVirtualFunctionsFull:
 * @sysfs_path: path to physical function sysfs entry
 * @vfs: filled with the virtual function data
 * @pfNetDevName: Optional netdev name of this PF. If provided, the netdev
 *                names of the VFs are queried too.
 *
 *
 * Returns virtual functions of a physical function.
 */
int
virPCIGetVirtualFunctionsFull(const char *sysfs_path,
                              virPCIVirtualFunctionList **vfs,
                              const char *pfNetDevName)
{
    g_autofree char *totalvfs_file = NULL;
    g_autofree char *totalvfs_str = NULL;
    g_autoptr(virPCIVirtualFunctionList) list = g_new0(virPCIVirtualFunctionList, 1);

    *vfs = NULL;

    totalvfs_file = g_strdup_printf("%s/sriov_totalvfs", sysfs_path);
    if (virFileExists(totalvfs_file)) {
        char *end = NULL; /* so that terminating \n doesn't create error */
        unsigned long long maxfunctions = 0;

        if (virFileReadAll(totalvfs_file, 16, &totalvfs_str) < 0)
            return -1;
        if (virStrToLong_ull(totalvfs_str, &end, 10, &maxfunctions) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unrecognized value in %1$s: %2$s"),
                           totalvfs_file, totalvfs_str);
            return -1;
        }
        list->maxfunctions = maxfunctions;
    }

    do {
        g_autofree char *device_link = NULL;
        struct virPCIVirtualFunction fnc = { NULL, NULL };

        /* look for virtfn%d links until one isn't found */
        device_link = g_strdup_printf("%s/virtfn%zu", sysfs_path, list->nfunctions);

        if (!virFileExists(device_link))
            break;

        if (!(fnc.addr = virPCIGetDeviceAddressFromSysfsLink(device_link))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get SRIOV function from device link '%1$s'"),
                           device_link);
            return -1;
        }

        if (pfNetDevName &&
            virPCIGetNetName(device_link, 0, pfNetDevName, &fnc.ifname) < 0) {
            g_free(fnc.addr);
            return -1;
        }

        VIR_APPEND_ELEMENT(list->functions, list->nfunctions, fnc);
    } while (1);

    VIR_DEBUG("Found %zu virtual functions for %s", list->nfunctions, sysfs_path);

    *vfs = g_steal_pointer(&list);
    return 0;
}


/*
 * Returns 1 if vf device is a virtual function, 0 if not, -1 on error
 */
int
virPCIIsVirtualFunction(const char *vf_sysfs_device_link)
{
    g_autofree char *vf_sysfs_physfn_link = NULL;

    vf_sysfs_physfn_link = g_strdup_printf("%s/physfn", vf_sysfs_device_link);

    return virFileExists(vf_sysfs_physfn_link);
}

/*
 * Returns the sriov virtual function index of vf given its pf
 */
int
virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link,
                              const char *vf_sysfs_device_link,
                              int *vf_index)
{
    size_t i;
    g_autofree virPCIDeviceAddress *vf_bdf = NULL;
    g_autoptr(virPCIVirtualFunctionList) virt_fns = NULL;

    if (!(vf_bdf = virPCIGetDeviceAddressFromSysfsLink(vf_sysfs_device_link)))
        return -1;

    if (virPCIGetVirtualFunctions(pf_sysfs_device_link, &virt_fns) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error getting physical function's '%1$s' virtual_functions"),
                       pf_sysfs_device_link);
        return -1;
    }

    for (i = 0; i < virt_fns->nfunctions; i++) {
        if (virPCIDeviceAddressEqual(vf_bdf, virt_fns->functions[i].addr)) {
            *vf_index = i;
            return 0;
        }
    }

    return -1;
}

/*
 * Returns a path to the PCI sysfs file given the BDF of the PCI function
 */

int
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddress *addr,
                                char **pci_sysfs_device_link)
{
    *pci_sysfs_device_link = g_strdup_printf(PCI_SYSFS "devices/" VIR_PCI_DEVICE_ADDRESS_FMT, addr->domain,
                                             addr->bus, addr->slot, addr->function);
    return 0;
}

/**
 * virPCIGetNetName:
 * @device_link_sysfs_path: sysfs path to the PCI device
 * @idx: used to choose which netdev when there are several
 *       (ignored if physPortID is set or physPortName is available)

 * @physPortNetDevName: if non-null, attempt to learn the phys_port_id
 *                      of the netdev interface named
 *                      @physPortNetDevName, and find a netdev for
 *                      this PCI device that has the same
 *                      phys_port_id. if @physPortNetDevName is NULL,
 *                      or has no phys_port_id, then use
 *                      phys_port_name or idx to determine which
 *                      netdev to return. (NB: as of today, only mlx
 *                      drivers/cards can have multiple phys_ports for
 *                      a single PCI device; on all other devices
 *                      there is only a single choice of netdev, and
 *                      phys_port_id, phys_port_name, and idx are
 *                      unavailable/unused)
 * @netname: used to return the name of the netdev
 *       (set to NULL (but returns success) if there is no netdev)
 *
 * Returns 0 on success, -1 on error (error has been logged)
 */
int
virPCIGetNetName(const char *device_link_sysfs_path,
                 size_t idx,
                 const char *physPortNetDevName,
                 char **netname)
{
    g_autofree char *physPortID = NULL;
    g_autofree char *pcidev_sysfs_net_path = NULL;
    g_autofree char *firstEntryName = NULL;
    g_autoptr(DIR) dir = NULL;
    struct dirent *entry = NULL;
    size_t i = 0;

    *netname = NULL;

    if (physPortNetDevName &&
        virNetDevGetPhysPortID(physPortNetDevName, &physPortID) < 0) {
        return -1;
    }

    pcidev_sysfs_net_path = g_build_filename(device_link_sysfs_path, "net", NULL);

    if (virDirOpenQuiet(&dir, pcidev_sysfs_net_path) < 0) {
        /* this *isn't* an error - caller needs to check for netname == NULL */
        return 0;
    }

    while (virDirRead(dir, &entry, pcidev_sysfs_net_path) > 0) {
        /* save the first entry we find to use as a failsafe
         * in case we don't match the phys_port_id. This is
         * needed because some NIC drivers (e.g. i40e)
         * implement phys_port_id for PFs, but not for VFs
         */
        if (!firstEntryName)
            firstEntryName = g_strdup(entry->d_name);

        /* if the caller sent a physPortID, compare it to the
         * physportID of this netdev. If not, look for entry[idx].
         */
        if (physPortID) {
            g_autofree char *thisPhysPortID = NULL;

            if (virNetDevGetPhysPortID(entry->d_name, &thisPhysPortID) < 0)
                return -1;

            /* if this one doesn't match, keep looking */
            if (STRNEQ_NULLABLE(physPortID, thisPhysPortID))
                continue;

        } else {
            /* Most switch devices use phys_port_name instead of
             * phys_port_id.
             * NOTE: VFs' representors net devices can be linked to PF's PCI
             * device, which mean that there'll be multiple net devices
             * instances and to get a proper net device need to match on
             * specific regex.
             * To get PF netdev, for ex., used following regex:
             * "(p[0-9]+$)|(p[0-9]+s[0-9]+$)"
             * or to get exact VF's netdev next regex is used:
             * "pf0vf1$"
             */
            g_autofree char *thisPhysPortName = NULL;

            if (virNetDevGetPhysPortName(entry->d_name, &thisPhysPortName) < 0)
                return -1;

            if (thisPhysPortName) {

                /* if this one doesn't match, keep looking */
                if (!virStringMatch(thisPhysPortName, VIR_PF_PHYS_PORT_NAME_REGEX))
                    continue;

            } else {

                if (i++ < idx)
                    continue;
            }
        }

        *netname = g_strdup(entry->d_name);
        return 0;
    }

    if (firstEntryName) {
        /* we didn't match the provided phys_port_id / find a
         * phys_port_name matching VIR_PF_PHYS_PORT_NAME_REGEX / find
         * as many net devices as the value of idx, but this is
         * probably because phys_port_id / phys_port_name isn't
         * implemented for this NIC driver, so just return the first
         * (probably only) netname we found.
         */
        *netname = g_steal_pointer(&firstEntryName);
        return 0;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("Could not find any network device under PCI device at %1$s"),
                   device_link_sysfs_path);
    return -1;
}

int
virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path,
                             int pfNetDevIdx,
                             char **pfname,
                             int *vf_index)
{
    g_autofree virPCIDeviceAddress *pf_config_address = NULL;
    g_autofree char *pf_sysfs_device_path = NULL;
    g_autofree char *vfname = NULL;

    if (virPCIGetPhysicalFunction(vf_sysfs_device_path, &pf_config_address) < 0)
        return -1;

    if (!pf_config_address)
        return -1;

    if (virPCIDeviceAddressGetSysfsFile(pf_config_address,
                                        &pf_sysfs_device_path) < 0) {
        return -1;
    }

    if (virPCIGetVirtualFunctionIndex(pf_sysfs_device_path,
                                      vf_sysfs_device_path, vf_index) < 0) {
        return -1;
    }

    /* If the caller hasn't asked for a specific pfNetDevIdx, and VF
     * is bound to a netdev, learn that netdev's phys_port_id (if
     * available). This can be used to disambiguate when the PF has
     * multiple netdevs. If the VF isn't bound to a netdev, then we
     * return netdev[pfNetDevIdx] on the PF, which may or may not be
     * correct.
     */
    if (pfNetDevIdx == -1) {
        if (virPCIGetNetName(vf_sysfs_device_path, 0, NULL, &vfname) < 0)
            return -1;

        pfNetDevIdx = 0;
    }

    if (virPCIGetNetName(pf_sysfs_device_path, pfNetDevIdx, vfname, pfname) < 0)
        return -1;

    if (!*pfname) {
        /* this shouldn't be possible. A VF can't exist unless its
         * PF device is bound to a network driver
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("The PF device for VF %1$s has no network device name"),
                       vf_sysfs_device_path);
        return -1;
    }

    return 0;
}


bool
virPCIDeviceHasVPD(virPCIDevice *dev)
{
    g_autofree char *vpdPath = NULL;

    vpdPath = virPCIFile(dev->name, "vpd");
    if (!virFileExists(vpdPath)) {
        VIR_INFO("Device VPD file does not exist %s", vpdPath);
        return false;
    } else if (!virFileIsRegular(vpdPath)) {
        VIR_WARN("VPD path does not point to a regular file %s", vpdPath);
        return false;
    }
    return true;
}

/**
 * virPCIDeviceGetVPD:
 * @dev: a PCI device to get a PCI VPD for.
 *
 * Obtain a PCI device's Vital Product Data (VPD). VPD is optional in
 * both PCI Local Bus and PCIe specifications so there is no guarantee it
 * will be there for a particular device.
 *
 * Returns: a pointer to virPCIVPDResource which needs to be freed by the caller
 * or NULL if getting it failed for some reason (e.g. invalid format, I/O error).
 */
virPCIVPDResource *
virPCIDeviceGetVPD(virPCIDevice *dev)
{
    g_autofree char *vpdPath = NULL;
    int fd;
    g_autoptr(virPCIVPDResource) res = NULL;

    vpdPath = virPCIFile(dev->name, "vpd");
    if (!virPCIDeviceHasVPD(dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR, _("Device %1$s does not have a VPD"),
                virPCIDeviceGetName(dev));
        return NULL;
    }
    if ((fd = open(vpdPath, O_RDONLY)) < 0) {
        virReportSystemError(-fd, _("Failed to open a VPD file '%1$s'"), vpdPath);
        return NULL;
    }
    res = virPCIVPDParse(fd);

    if (VIR_CLOSE(fd) < 0) {
        virReportSystemError(errno, _("Unable to close the VPD file, fd: %1$d"), fd);
        return NULL;
    }

    return g_steal_pointer(&res);
}

#else
static const char *unsupported = N_("not supported on non-linux platforms");

virPCIDeviceAddress *
virPCIGetDeviceAddressFromSysfsLink(const char *device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}


int
virPCIGetPhysicalFunction(const char *vf_sysfs_path G_GNUC_UNUSED,
                          virPCIDeviceAddress **pf G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctionsFull(const char *sysfs_path G_GNUC_UNUSED,
                              virPCIVirtualFunctionList **vfs G_GNUC_UNUSED,
                              const char *pfNetDevName G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIIsVirtualFunction(const char *vf_sysfs_device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link G_GNUC_UNUSED,
                              const char *vf_sysfs_device_link G_GNUC_UNUSED,
                              int *vf_index G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;

}


int
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddress *dev G_GNUC_UNUSED,
                                char **pci_sysfs_device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetNetName(const char *device_link_sysfs_path G_GNUC_UNUSED,
                 size_t idx G_GNUC_UNUSED,
                 const char *physPortNetDevName G_GNUC_UNUSED,
                 char **netname G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path G_GNUC_UNUSED,
                             int pfNetDevIdx G_GNUC_UNUSED,
                             char **pfname G_GNUC_UNUSED,
                             int *vf_index G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

bool
virPCIDeviceHasVPD(virPCIDevice *dev G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}

virPCIVPDResource *
virPCIDeviceGetVPD(virPCIDevice *dev G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}
#endif /* __linux__ */

int
virPCIDeviceIsPCIExpress(virPCIDevice *dev)
{
    int fd;
    int ret = -1;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return ret;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    ret = dev->is_pcie;

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}

int
virPCIDeviceHasPCIExpressLink(virPCIDevice *dev)
{
    int fd;
    int ret = -1;
    uint16_t cap, type;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return ret;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    if (dev->pcie_cap_pos == 0) {
        ret = 0;
        goto cleanup;
    }

    cap = virPCIDeviceRead16(dev, fd, dev->pcie_cap_pos + PCI_CAP_FLAGS);
    type = (cap & PCI_EXP_FLAGS_TYPE) >> 4;

    ret = type != PCI_EXP_TYPE_ROOT_INT_EP && type != PCI_EXP_TYPE_ROOT_EC;

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}

int
virPCIDeviceGetLinkCapSta(virPCIDevice *dev,
                          int *cap_port,
                          unsigned int *cap_speed,
                          unsigned int *cap_width,
                          unsigned int *sta_speed,
                          unsigned int *sta_width)
{
    uint32_t t;
    int fd;
    int ret = -1;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return ret;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    if (!dev->pcie_cap_pos) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("pci device %1$s is not a PCI-Express device"),
                       dev->name);
        goto cleanup;
    }

    t = virPCIDeviceRead32(dev, fd, dev->pcie_cap_pos + PCI_EXP_LNKCAP);

    *cap_port = t >> 24;
    *cap_speed = t & PCI_EXP_LNKCAP_SPEED;
    *cap_width = (t & PCI_EXP_LNKCAP_WIDTH) >> 4;

    t = virPCIDeviceRead16(dev, fd, dev->pcie_cap_pos + PCI_EXP_LNKSTA);

    *sta_speed = t & PCI_EXP_LNKSTA_SPEED;
    *sta_width = (t & PCI_EXP_LNKSTA_WIDTH) >> 4;
    ret = 0;

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}


int virPCIGetHeaderType(virPCIDevice *dev, int *hdrType)
{
    int fd;
    uint8_t type;

    *hdrType = -1;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return -1;

    type = virPCIDeviceRead8(dev, fd, PCI_HEADER_TYPE);

    virPCIDeviceConfigClose(dev, fd);

    type &= PCI_HEADER_TYPE_MASK;
    if (type >= VIR_PCI_HEADER_LAST) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown PCI header type '%1$d' for device '%2$s'"),
                       type, dev->name);
        return -1;
    }

    *hdrType = type;

    return 0;
}


void
virPCIEDeviceInfoFree(virPCIEDeviceInfo *dev)
{
    if (!dev)
        return;

    g_free(dev->link_cap);
    g_free(dev->link_sta);
    g_free(dev);
}

void
virPCIDeviceAddressFree(virPCIDeviceAddress *address)
{
    g_free(address);
}
