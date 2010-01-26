/*
 * Copyright (C) 2009-2010 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#include "pci.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logging.h"
#include "memory.h"
#include "util.h"
#include "virterror_internal.h"

/* avoid compilation breakage on some systems */
#ifndef MODPROBE
#define MODPROBE "modprobe"
#endif

#define PCI_SYSFS "/sys/bus/pci/"
#define PCI_ID_LEN 10   /* "XXXX XXXX" */
#define PCI_ADDR_LEN 13 /* "XXXX:XX:XX.X" */

struct _pciDevice {
    unsigned      domain;
    unsigned      bus;
    unsigned      slot;
    unsigned      function;

    char          name[PCI_ADDR_LEN]; /* domain:bus:slot.function */
    char          id[PCI_ID_LEN];     /* product vendor */
    char          path[PATH_MAX];
    int           fd;

    unsigned      initted;
    unsigned      pcie_cap_pos;
    unsigned      pci_pm_cap_pos;
    unsigned      has_flr : 1;
    unsigned      has_pm_reset : 1;
    unsigned      managed : 1;
};

struct _pciDeviceList {
    unsigned count;
    pciDevice **devs;
};


/* For virReportOOMError()  and virReportSystemError() */
#define VIR_FROM_THIS VIR_FROM_NONE

#define pciReportError(conn, code, fmt...)                     \
    virReportErrorHelper(conn, VIR_FROM_NONE, code, __FILE__,  \
                         __FUNCTION__, __LINE__, fmt)

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
#define  PCI_HEADER_TYPE_BRIDGE 0x1
#define  PCI_HEADER_TYPE_MASK   0x7f
#define  PCI_HEADER_TYPE_MULTI  0x80

/* PCI30 6.2.1  Device Identification */
#define PCI_CLASS_DEVICE        0x0a    /* Device class */

/* Class Code for bridge; PCI30 D.7  Base Class 06h */
#define PCI_CLASS_BRIDGE_PCI    0x0604

/* PCI30 6.2.3  Device Status */
#define PCI_STATUS              0x06    /* 16 bits */
#define  PCI_STATUS_CAP_LIST    0x10    /* Support Capability List */

/* PCI30 6.7  Capabilities List */
#define PCI_CAPABILITY_LIST     0x34    /* Offset of first capability list entry */

/* PM12 3.2.1  Capability Identifier */
#define PCI_CAP_ID_PM           0x01    /* Power Management */
/* PCI30 H Capability IDs */
#define PCI_CAP_ID_EXP          0x10    /* PCI Express */
/* ECN_AF 6.x.1.1  Capability ID for AF */
#define PCI_CAP_ID_AF           0x13    /* Advanced Features */

/* PCIe20 7.8.3  Device Capabilities Register (Offset 04h) */
#define PCI_EXP_DEVCAP          0x4     /* Device capabilities */
#define  PCI_EXP_DEVCAP_FLR     (1<<28) /* Function Level Reset */

/* Header type 1 BR12 3.2 PCI-to-PCI Bridge Configuration Space Header Format */
#define PCI_PRIMARY_BUS         0x18    /* BR12 3.2.5.2 Primary bus number */
#define PCI_SECONDARY_BUS       0x19    /* BR12 3.2.5.3 Secondary bus number */
#define PCI_SUBORDINATE_BUS     0x1a    /* BR12 3.2.5.4 Highest bus number behind the bridge */
#define PCI_BRIDGE_CONTROL      0x3e
/* BR12 3.2.5.18  Bridge Control Register */
#define  PCI_BRIDGE_CTL_RESET   0x40    /* Secondary bus reset */

/* PM12 3.2.4  Power Management Control/Status (Offset = 4) */
#define PCI_PM_CTRL                4    /* PM control and status register */
#define  PCI_PM_CTRL_STATE_MASK    0x3  /* Current power state (D0 to D3) */
#define  PCI_PM_CTRL_STATE_D0      0x0  /* D0 state */
#define  PCI_PM_CTRL_STATE_D3hot   0x3  /* D3 state */
#define  PCI_PM_CTRL_NO_SOFT_RESET 0x8  /* No reset for D3hot->D0 */

/* ECN_AF 6.x.1  Advanced Features Capability Structure */
#define PCI_AF_CAP              0x3     /* Advanced features capabilities */
#define  PCI_AF_CAP_FLR         0x2     /* Function Level Reset */

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

static int
pciOpenConfig(pciDevice *dev)
{
    int fd;

    if (dev->fd > 0)
        return 0;

    fd = open(dev->path, O_RDWR);
    if (fd < 0) {
        char ebuf[1024];
        VIR_WARN(_("Failed to open config space file '%s': %s"),
                 dev->path, virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    VIR_DEBUG("%s %s: opened %s", dev->id, dev->name, dev->path);
    dev->fd = fd;
    return 0;
}

static int
pciRead(pciDevice *dev, unsigned pos, uint8_t *buf, unsigned buflen)
{
    memset(buf, 0, buflen);

    if (pciOpenConfig(dev) < 0)
        return -1;

    if (lseek(dev->fd, pos, SEEK_SET) != pos ||
        saferead(dev->fd, buf, buflen) != buflen) {
        char ebuf[1024];
        VIR_WARN(_("Failed to read from '%s' : %s"), dev->path,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    return 0;
}

static uint8_t
pciRead8(pciDevice *dev, unsigned pos)
{
    uint8_t buf;
    pciRead(dev, pos, &buf, sizeof(buf));
    return buf;
}

static uint16_t
pciRead16(pciDevice *dev, unsigned pos)
{
    uint8_t buf[2];
    pciRead(dev, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8);
}

static uint32_t
pciRead32(pciDevice *dev, unsigned pos)
{
    uint8_t buf[4];
    pciRead(dev, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static int
pciWrite(pciDevice *dev, unsigned pos, uint8_t *buf, unsigned buflen)
{
    if (pciOpenConfig(dev) < 0)
        return -1;

    if (lseek(dev->fd, pos, SEEK_SET) != pos ||
        safewrite(dev->fd, buf, buflen) != buflen) {
        char ebuf[1024];
        VIR_WARN(_("Failed to write to '%s' : %s"), dev->path,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    return 0;
}

static void
pciWrite16(pciDevice *dev, unsigned pos, uint16_t val)
{
    uint8_t buf[2] = { (val >> 0), (val >> 8) };
    pciWrite(dev, pos, &buf[0], sizeof(buf));
}

static void
pciWrite32(pciDevice *dev, unsigned pos, uint32_t val)
{
    uint8_t buf[4] = { (val >> 0), (val >> 8), (val >> 16), (val >> 14) };
    pciWrite(dev, pos, &buf[0], sizeof(buf));
}

typedef int (*pciIterPredicate)(pciDevice *, pciDevice *, void *);

/* Iterate over available PCI devices calling @predicate
 * to compare each one to @dev.
 * Return -1 on error since we don't want to assume it is
 * safe to reset if there is an error.
 */
static int
pciIterDevices(virConnectPtr conn,
               pciIterPredicate predicate,
               pciDevice *dev,
               pciDevice **matched,
               void *data)
{
    DIR *dir;
    struct dirent *entry;
    int ret = 0;

    *matched = NULL;

    VIR_DEBUG("%s %s: iterating over " PCI_SYSFS "devices", dev->id, dev->name);

    dir = opendir(PCI_SYSFS "devices");
    if (!dir) {
        VIR_WARN0("Failed to open " PCI_SYSFS "devices");
        return -1;
    }

    while ((entry = readdir(dir))) {
        unsigned domain, bus, slot, function;
        pciDevice *check;

        /* Ignore '.' and '..' */
        if (entry->d_name[0] == '.')
            continue;

        if (sscanf(entry->d_name, "%x:%x:%x.%x",
                   &domain, &bus, &slot, &function) < 4) {
            VIR_WARN("Unusual entry in " PCI_SYSFS "devices: %s", entry->d_name);
            continue;
        }

        check = pciGetDevice(conn, domain, bus, slot, function);
        if (!check) {
            ret = -1;
            break;
        }

        if (predicate(dev, check, data)) {
            VIR_DEBUG("%s %s: iter matched on %s", dev->id, dev->name, check->name);
            *matched = check;
            break;
        }
        pciFreeDevice(conn, check);
    }
    closedir(dir);
    return ret;
}

static uint8_t
pciFindCapabilityOffset(pciDevice *dev, unsigned capability)
{
    uint16_t status;
    uint8_t pos;

    status = pciRead16(dev, PCI_STATUS);
    if (!(status & PCI_STATUS_CAP_LIST))
        return 0;

    pos = pciRead8(dev, PCI_CAPABILITY_LIST);

    /* Zero indicates last capability, capabilities can't
     * be in the config space header and 0xff is returned
     * by the kernel if we don't have access to this region
     *
     * Note: we're not handling loops or extended
     * capabilities here.
     */
    while (pos >= PCI_CONF_HEADER_LEN && pos != 0xff) {
        uint8_t capid = pciRead8(dev, pos);
        if (capid == capability) {
            VIR_DEBUG("%s %s: found cap 0x%.2x at 0x%.2x",
                      dev->id, dev->name, capability, pos);
            return pos;
        }

        pos = pciRead8(dev, pos + 1);
    }

    VIR_DEBUG("%s %s: failed to find cap 0x%.2x", dev->id, dev->name, capability);

    return 0;
}

static unsigned int
pciFindExtendedCapabilityOffset(pciDevice *dev, unsigned capability)
{
    int ttl;
    unsigned int pos;
    uint32_t header;

    /* minimum 8 bytes per capability */
    ttl = (PCI_EXT_CAP_LIMIT - PCI_EXT_CAP_BASE) / 8;
    pos = PCI_EXT_CAP_BASE;

    while (ttl > 0 && pos >= PCI_EXT_CAP_BASE) {
        header = pciRead32(dev, pos);

        if ((header & PCI_EXT_CAP_ID_MASK) == capability)
            return pos;

        pos = (header >> PCI_EXT_CAP_OFFSET_SHIFT) & PCI_EXT_CAP_OFFSET_MASK;
        ttl--;
    }

    return 0;
}

static unsigned
pciDetectFunctionLevelReset(pciDevice *dev)
{
    uint32_t caps;
    uint8_t pos;

    /* The PCIe Function Level Reset capability allows
     * individual device functions to be reset without
     * affecting any other functions on the device or
     * any other devices on the bus. This is only common
     * on SR-IOV NICs at the moment.
     */
    if (dev->pcie_cap_pos) {
        caps = pciRead32(dev, dev->pcie_cap_pos + PCI_EXP_DEVCAP);
        if (caps & PCI_EXP_DEVCAP_FLR) {
            VIR_DEBUG("%s %s: detected PCIe FLR capability", dev->id, dev->name);
            return 1;
        }
    }

    /* The PCI AF Function Level Reset capability is
     * the same thing, except for conventional PCI
     * devices. This is not common yet.
     */
    pos = pciFindCapabilityOffset(dev, PCI_CAP_ID_AF);
    if (pos) {
        caps = pciRead16(dev, pos + PCI_AF_CAP);
        if (caps & PCI_AF_CAP_FLR) {
            VIR_DEBUG("%s %s: detected PCI FLR capability", dev->id, dev->name);
            return 1;
        }
    }

    VIR_DEBUG("%s %s: no FLR capability found", dev->id, dev->name);

    return 0;
}

/* Require the device has the PCI Power Management capability
 * and that a D3hot->D0 transition will results in a full
 * internal reset, not just a soft reset.
 */
static unsigned
pciDetectPowerManagementReset(pciDevice *dev)
{
    if (dev->pci_pm_cap_pos) {
        uint32_t ctl;

        /* require the NO_SOFT_RESET bit is clear */
        ctl = pciRead32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL);
        if (!(ctl & PCI_PM_CTRL_NO_SOFT_RESET)) {
            VIR_DEBUG("%s %s: detected PM reset capability", dev->id, dev->name);
            return 1;
        }
    }

    VIR_DEBUG("%s %s: no PM reset capability found", dev->id, dev->name);

    return 0;
}

/* Any active devices other than the one supplied on the same domain/bus ? */
static int
pciSharesBusWithActive(pciDevice *dev, pciDevice *check, void *data)
{
    pciDeviceList *activeDevs = data;

    if (dev->domain != check->domain ||
        dev->bus != check->bus ||
        (check->slot == check->slot &&
         check->function == check->function))
        return 0;

    if (activeDevs && !pciDeviceListFind(activeDevs, check))
        return 0;

    return 1;
}

static pciDevice *
pciBusContainsActiveDevices(virConnectPtr conn,
                            pciDevice *dev,
                            pciDeviceList *activeDevs)
{
    pciDevice *active = NULL;
    if (pciIterDevices(conn, pciSharesBusWithActive,
                       dev, &active, activeDevs) < 0)
        return NULL;
    return active;
}

/* Is @check the parent of @dev ? */
static int
pciIsParent(pciDevice *dev, pciDevice *check, void *data ATTRIBUTE_UNUSED)
{
    uint16_t device_class;
    uint8_t header_type, secondary, subordinate;

    if (dev->domain != check->domain)
        return 0;

    /* Is it a bridge? */
    device_class = pciRead16(check, PCI_CLASS_DEVICE);
    if (device_class != PCI_CLASS_BRIDGE_PCI)
        return 0;

    /* Is it a plane? */
    header_type = pciRead8(check, PCI_HEADER_TYPE);
    if ((header_type & PCI_HEADER_TYPE_MASK) != PCI_HEADER_TYPE_BRIDGE)
        return 0;

    secondary   = pciRead8(check, PCI_SECONDARY_BUS);
    subordinate = pciRead8(check, PCI_SUBORDINATE_BUS);

    VIR_DEBUG("%s %s: found parent device %s", dev->id, dev->name, check->name);

    /* No, it's superman! */
    return (dev->bus >= secondary && dev->bus <= subordinate);
}

static pciDevice *
pciGetParentDevice(virConnectPtr conn, pciDevice *dev)
{
    pciDevice *parent = NULL;
    pciIterDevices(conn, pciIsParent, dev, &parent, NULL);
    return parent;
}

/* Secondary Bus Reset is our sledgehammer - it resets all
 * devices behind a bus.
 */
static int
pciTrySecondaryBusReset(virConnectPtr conn,
                        pciDevice *dev,
                        pciDeviceList *activeDevs)
{
    pciDevice *parent, *conflict;
    uint8_t config_space[PCI_CONF_LEN];
    uint16_t ctl;
    int ret = -1;

    /* For now, we just refuse to do a secondary bus reset
     * if there are other devices/functions behind the bus.
     * In future, we could allow it so long as those devices
     * are not in use by the host or other guests.
     */
    if ((conflict = pciBusContainsActiveDevices(conn, dev, activeDevs))) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Active %s devices on bus with %s, not doing bus reset"),
                       conflict->name, dev->name);
        return -1;
    }

    /* Find the parent bus */
    parent = pciGetParentDevice(conn, dev);
    if (!parent) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to find parent device for %s"),
                       dev->name);
        return -1;
    }

    VIR_DEBUG("%s %s: doing a secondary bus reset", dev->id, dev->name);

    /* Save and restore the device's config space; we only do this
     * for the supplied device since we refuse to do a reset if there
     * are multiple devices/functions
     */
    if (pciRead(dev, 0, config_space, PCI_CONF_LEN) < 0) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to save PCI config space for %s"),
                       dev->name);
        goto out;
    }

    /* Read the control register, set the reset flag, wait 200ms,
     * unset the reset flag and wait 200ms.
     */
    ctl = pciRead16(dev, PCI_BRIDGE_CONTROL);

    pciWrite16(parent, PCI_BRIDGE_CONTROL, ctl | PCI_BRIDGE_CTL_RESET);

    usleep(200 * 1000); /* sleep 200ms */

    pciWrite16(parent, PCI_BRIDGE_CONTROL, ctl);

    usleep(200 * 1000); /* sleep 200ms */

    if (pciWrite(dev, 0, config_space, PCI_CONF_LEN) < 0) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to restore PCI config space for %s"),
                       dev->name);
        goto out;
    }
    ret = 0;
out:
    pciFreeDevice(conn, parent);
    return ret;
}

/* Power management reset attempts to reset a device using a
 * D-state transition from D3hot to D0. Note, in detect_pm_reset()
 * above we require the device supports a full internal reset.
 */
static int
pciTryPowerManagementReset(virConnectPtr conn ATTRIBUTE_UNUSED, pciDevice *dev)
{
    uint8_t config_space[PCI_CONF_LEN];
    uint32_t ctl;

    if (!dev->pci_pm_cap_pos)
        return -1;

    /* Save and restore the device's config space. */
    if (pciRead(dev, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to save PCI config space for %s"),
                       dev->name);
        return -1;
    }

    VIR_DEBUG("%s %s: doing a power management reset", dev->id, dev->name);

    ctl = pciRead32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL);
    ctl &= ~PCI_PM_CTRL_STATE_MASK;

    pciWrite32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL, ctl|PCI_PM_CTRL_STATE_D3hot);

    usleep(10 * 1000); /* sleep 10ms */

    pciWrite32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL, ctl|PCI_PM_CTRL_STATE_D0);

    usleep(10 * 1000); /* sleep 10ms */

    if (pciWrite(dev, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to restore PCI config space for %s"),
                       dev->name);
        return -1;
    }

    return 0;
}

static int
pciInitDevice(virConnectPtr conn, pciDevice *dev)
{
    if (pciOpenConfig(dev) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to open config space file '%s'"),
                             dev->path);
        return -1;
    }

    dev->pcie_cap_pos   = pciFindCapabilityOffset(dev, PCI_CAP_ID_EXP);
    dev->pci_pm_cap_pos = pciFindCapabilityOffset(dev, PCI_CAP_ID_PM);
    dev->has_flr        = pciDetectFunctionLevelReset(dev);
    dev->has_pm_reset   = pciDetectPowerManagementReset(dev);
    dev->initted        = 1;
    return 0;
}

int
pciResetDevice(virConnectPtr conn,
               pciDevice *dev,
               pciDeviceList *activeDevs)
{
    int ret = -1;

    if (activeDevs && pciDeviceListFind(activeDevs, dev)) {
        pciReportError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("Not resetting active device %s"), dev->name);
        return -1;
    }

    if (!dev->initted && pciInitDevice(conn, dev) < 0)
        return -1;

    /* KVM will perform FLR when starting and stopping
     * a guest, so there is no need for us to do it here.
     */
    if (dev->has_flr)
        return 0;

    /* If the device supports PCI power management reset,
     * that's the next best thing because it only resets
     * the function, not the whole device.
     */
    if (dev->has_pm_reset)
        ret = pciTryPowerManagementReset(conn, dev);

    /* Bus reset is not an option with the root bus */
    if (ret < 0 && dev->bus != 0)
        ret = pciTrySecondaryBusReset(conn, dev, activeDevs);

    if (ret < 0) {
        virErrorPtr err = virGetLastError();
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Unable to reset PCI device %s: %s"),
                       dev->name,
                       err ? err->message : _("no FLR, PM reset or bus reset available"));
    }

    return ret;
}


static void
pciDriverDir(char *buf, size_t buflen, const char *driver)
{
    snprintf(buf, buflen, PCI_SYSFS "drivers/%s", driver);
}

static void
pciDriverFile(char *buf, size_t buflen, const char *driver, const char *file)
{
    snprintf(buf, buflen, PCI_SYSFS "drivers/%s/%s", driver, file);
}

static void
pciDeviceFile(char *buf, size_t buflen, const char *device, const char *file)
{
    snprintf(buf, buflen, PCI_SYSFS "devices/%s/%s", device, file);
}


static const char *
pciFindStubDriver(virConnectPtr conn)
{
    char drvpath[PATH_MAX];
    int probed = 0;

recheck:
    pciDriverDir(drvpath, sizeof(drvpath), "pci-stub");
    if (virFileExists(drvpath))
        return "pci-stub";
    pciDriverDir(drvpath, sizeof(drvpath), "pciback");
    if (virFileExists(drvpath))
        return "pciback";

    if (!probed) {
        const char *const stubprobe[] = { MODPROBE, "pci-stub", NULL };
        const char *const backprobe[] = { MODPROBE, "pciback", NULL };

        probed = 1;
        /*
         * Probing for pci-stub will succeed regardless of whether
         * on native or Xen kernels.
         * On Xen though, we want to prefer pciback, so probe
         * for that first, because that will only work on Xen
         */
        if (virRun(conn, backprobe, NULL) < 0 &&
            virRun(conn, stubprobe, NULL) < 0) {
            char ebuf[1024];
            VIR_WARN(_("failed to load pci-stub or pciback drivers: %s"),
                     virStrerror(errno, ebuf, sizeof ebuf));
            return 0;
        }

        goto recheck;
    }

    return NULL;
}


static int
pciBindDeviceToStub(virConnectPtr conn, pciDevice *dev, const char *driver)
{
    char drvdir[PATH_MAX];
    char path[PATH_MAX];

    /* Add the PCI device ID to the stub's dynamic ID table;
     * this is needed to allow us to bind the device to the stub.
     * Note: if the device is not currently bound to any driver,
     * stub will immediately be bound to the device. Also, note
     * that if a new device with this ID is hotplugged, or if a probe
     * is triggered for such a device, it will also be immediately
     * bound by the stub.
     */
    pciDriverFile(path, sizeof(path), driver, "new_id");
    if (virFileWriteStr(path, dev->id) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to add PCI device ID '%s' to %s"),
                             dev->id, driver);
        return -1;
    }

    /* If the device is already bound to a driver, unbind it.
     * Note, this will have rather unpleasant side effects if this
     * PCI device happens to be IDE controller for the disk hosting
     * your root filesystem.
     */
    pciDeviceFile(path, sizeof(path), dev->name, "driver/unbind");
    if (virFileExists(path) && virFileWriteStr(path, dev->name) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to unbind PCI device '%s'"), dev->name);
        return -1;
    }

    /* If the device isn't already bound to pci-stub, try binding it now.
     */
    pciDriverDir(drvdir, sizeof(drvdir), driver);
    pciDeviceFile(path, sizeof(path), dev->name, "driver");
    if (!virFileLinkPointsTo(path, drvdir)) {
        /* Xen's pciback.ko wants you to use new_slot first */
        pciDriverFile(path, sizeof(path), driver, "new_slot");
        if (virFileExists(path) && virFileWriteStr(path, dev->name) < 0) {
            virReportSystemError(conn, errno,
                                 _("Failed to add slot for PCI device '%s' to %s"),
                                 dev->name, driver);
            return -1;
        }

        pciDriverFile(path, sizeof(path), driver, "bind");
        if (virFileWriteStr(path, dev->name) < 0) {
            virReportSystemError(conn, errno,
                                 _("Failed to bind PCI device '%s' to %s"),
                                 dev->name, driver);
            return -1;
        }
    }

    /* If 'remove_id' exists, remove the device id from pci-stub's dynamic
     * ID table so that 'drivers_probe' works below.
     */
    pciDriverFile(path, sizeof(path), driver, "remove_id");
    if (virFileExists(path) && virFileWriteStr(path, dev->id) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to remove PCI ID '%s' from %s"),
                             dev->id, driver);
        return -1;
    }

    return 0;
}

int
pciDettachDevice(virConnectPtr conn, pciDevice *dev)
{
    const char *driver = pciFindStubDriver(conn);
    if (!driver) {
        pciReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find any PCI stub module"));
        return -1;
    }

    return pciBindDeviceToStub(conn, dev, driver);
}

static int
pciUnBindDeviceFromStub(virConnectPtr conn, pciDevice *dev, const char *driver)
{
    char drvdir[PATH_MAX];
    char path[PATH_MAX];

    /* If the device is bound to stub, unbind it.
     */
    pciDriverDir(drvdir, sizeof(drvdir), driver);
    pciDeviceFile(path, sizeof(path), dev->name, "driver");
    if (virFileExists(drvdir) && virFileLinkPointsTo(path, drvdir)) {
        pciDriverFile(path, sizeof(path), driver, "unbind");
        if (virFileWriteStr(path, dev->name) < 0) {
            virReportSystemError(conn, errno,
                                 _("Failed to bind PCI device '%s' to %s"),
                                 dev->name, driver);
            return -1;
        }
    }

    /* Xen's pciback.ko wants you to use remove_slot on the specific device */
    pciDriverFile(path, sizeof(path), driver, "remove_slot");
    if (virFileExists(path) && virFileWriteStr(path, dev->name) < 0) {
        virReportSystemError(conn, errno,
                             _("Failed to remove slot for PCI device '%s' to %s"),
                             dev->name, driver);
        return -1;
    }


    /* Trigger a re-probe of the device is not in the stub's dynamic
     * ID table. If the stub is available, but 'remove_id' isn't
     * available, then re-probing would just cause the device to be
     * re-bound to the stub.
     */
    pciDriverFile(path, sizeof(path), driver, "remove_id");
    if (!virFileExists(drvdir) || virFileExists(path)) {
        if (virFileWriteStr(PCI_SYSFS "drivers_probe", dev->name) < 0) {
            virReportSystemError(conn, errno,
                                 _("Failed to trigger a re-probe for PCI device '%s'"),
                                 dev->name);
            return -1;
        }
    }

    return 0;
}

int
pciReAttachDevice(virConnectPtr conn, pciDevice *dev)
{
    const char *driver = pciFindStubDriver(conn);
    if (!driver) {
        pciReportError(conn, VIR_ERR_INTERNAL_ERROR, "%s",
                       _("cannot find any PCI stub module"));
        return -1;
    }

    return pciUnBindDeviceFromStub(conn, dev, driver);
}

/* Certain hypervisors (like qemu/kvm) map the PCI bar(s) on
 * the host when doing device passthrough.  This can lead to a race
 * condition where the hypervisor is still cleaning up the device while
 * libvirt is trying to re-attach it to the host device driver.  To avoid
 * this situation, we look through /proc/iomem, and if the hypervisor is
 * still holding onto the bar (denoted by the string in the matcher variable),
 * then we can wait around a bit for that to clear up.
 *
 * A typical /proc/iomem looks like this (snipped for brevity):
 * 00010000-0008efff : System RAM
 * 0008f000-0008ffff : reserved
 * ...
 * 00100000-cc9fcfff : System RAM
 *   00200000-00483d3b : Kernel code
 *   00483d3c-005c88df : Kernel data
 * cc9fd000-ccc71fff : ACPI Non-volatile Storage
 * ...
 * d0200000-d02fffff : PCI Bus #05
 *   d0200000-d021ffff : 0000:05:00.0
 *     d0200000-d021ffff : e1000e
 *   d0220000-d023ffff : 0000:05:00.0
 *     d0220000-d023ffff : e1000e
 * ...
 * f0000000-f0003fff : 0000:00:1b.0
 *   f0000000-f0003fff : kvm_assigned_device
 *
 * Returns 0 if we are clear to continue, and 1 if the hypervisor is still
 * holding onto the resource.
 */
int
pciWaitForDeviceCleanup(pciDevice *dev, const char *matcher)
{
    FILE *fp;
    char line[160];
    unsigned long long start, end;
    int consumed;
    char *rest;
    unsigned long long domain;
    int bus, slot, function;
    int in_matching_device;
    int ret;
    size_t match_depth;

    fp = fopen("/proc/iomem", "r");
    if (!fp) {
        /* If we failed to open iomem, we just basically ignore the error.  The
         * unbind might succeed anyway, and besides, it's very likely we have
         * no way to report the error
         */
        VIR_DEBUG0("Failed to open /proc/iomem, trying to continue anyway");
        return 0;
    }

    ret = 0;
    in_matching_device = 0;
    match_depth = 0;
    while (fgets(line, sizeof(line), fp) != 0) {
        /* the logic here is a bit confusing.  For each line, we look to
         * see if it matches the domain:bus:slot.function we were given.
         * If this line matches the DBSF, then any subsequent lines indented
         * by 2 spaces are the PCI regions for this device.  It's also
         * possible that none of the PCI regions are currently mapped, in
         * which case we have no indented regions.  This code handles all
         * of these situations
         */
        if (in_matching_device && (strspn(line, " ") == (match_depth + 2))) {
            if (sscanf(line, "%Lx-%Lx : %n", &start, &end, &consumed) != 2)
                continue;

            rest = line + consumed;
            if (STRPREFIX(rest, matcher)) {
                ret = 1;
                break;
            }
        }
        else {
            in_matching_device = 0;
            if (sscanf(line, "%Lx-%Lx : %n", &start, &end, &consumed) != 2)
                continue;

            rest = line + consumed;
            if (sscanf(rest, "%Lx:%x:%x.%x", &domain, &bus, &slot, &function) != 4)
                continue;

            if (domain != dev->domain || bus != dev->bus || slot != dev->slot ||
                function != dev->function)
                continue;
            in_matching_device = 1;
            match_depth = strspn(line, " ");
        }
    }

    fclose(fp);

    return ret;
}

static char *
pciReadDeviceID(pciDevice *dev, const char *id_name)
{
    char path[PATH_MAX];
    char *id_str;

    snprintf(path, sizeof(path), PCI_SYSFS "devices/%s/%s",
             dev->name, id_name);

    /* ID string is '0xNNNN\n' ... i.e. 7 bytes */
    if (virFileReadAll(path, 7, &id_str) < 0)
        return NULL;

    /* Check for 0x suffix */
    if (id_str[0] != '0' || id_str[1] != 'x') {
        VIR_FREE(id_str);
        return NULL;
    }

    /* Chop off the newline; we know the string is 7 bytes */
    id_str[6] = '\0';

    return id_str;
}

pciDevice *
pciGetDevice(virConnectPtr conn,
             unsigned domain,
             unsigned bus,
             unsigned slot,
             unsigned function)
{
    pciDevice *dev;
    char *vendor, *product;

    if (VIR_ALLOC(dev) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    dev->fd       = -1;
    dev->domain   = domain;
    dev->bus      = bus;
    dev->slot     = slot;
    dev->function = function;

    snprintf(dev->name, sizeof(dev->name), "%.4x:%.2x:%.2x.%.1x",
             dev->domain, dev->bus, dev->slot, dev->function);
    snprintf(dev->path, sizeof(dev->path),
             PCI_SYSFS "devices/%s/config", dev->name);

    vendor  = pciReadDeviceID(dev, "vendor");
    product = pciReadDeviceID(dev, "device");

    if (!vendor || !product) {
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("Failed to read product/vendor ID for %s"),
                       dev->name);
        VIR_FREE(product);
        VIR_FREE(vendor);
        pciFreeDevice(conn, dev);
        return NULL;
    }

    /* strings contain '0x' prefix */
    snprintf(dev->id, sizeof(dev->id), "%s %s", &vendor[2], &product[2]);

    VIR_FREE(product);
    VIR_FREE(vendor);

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

    return dev;
}

void
pciFreeDevice(virConnectPtr conn ATTRIBUTE_UNUSED, pciDevice *dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    if (dev->fd >= 0)
        close(dev->fd);
    VIR_FREE(dev);
}

void pciDeviceSetManaged(pciDevice *dev, unsigned managed)
{
    dev->managed = !!managed;
}

unsigned pciDeviceGetManaged(pciDevice *dev)
{
    return dev->managed;
}

pciDeviceList *
pciDeviceListNew(virConnectPtr conn)
{
    pciDeviceList *list;

    if (VIR_ALLOC(list) < 0) {
        virReportOOMError(conn);
        return NULL;
    }

    return list;
}

void
pciDeviceListFree(virConnectPtr conn,
                  pciDeviceList *list)
{
    int i;

    if (!list)
        return;

    for (i = 0; i < list->count; i++) {
        pciFreeDevice(conn, list->devs[i]);
        list->devs[i] = NULL;
    }

    list->count = 0;
    VIR_FREE(list->devs);
    VIR_FREE(list);
}

int
pciDeviceListAdd(virConnectPtr conn,
                 pciDeviceList *list,
                 pciDevice *dev)
{
    if (pciDeviceListFind(list, dev)) {
        pciReportError(conn, VIR_ERR_INTERNAL_ERROR,
                       _("Device %s is already in use"), dev->name);
        return -1;
    }

    if (VIR_REALLOC_N(list->devs, list->count+1) < 0) {
        virReportOOMError(conn);
        return -1;
    }

    list->devs[list->count++] = dev;

    return 0;
}

pciDevice *
pciDeviceListGet(pciDeviceList *list,
                 int idx)
{
    if (idx >= list->count)
        return NULL;
    if (idx < 0)
        return NULL;

    return list->devs[idx];
}

int
pciDeviceListCount(pciDeviceList *list)
{
    return list->count;
}

pciDevice *
pciDeviceListSteal(virConnectPtr conn ATTRIBUTE_UNUSED,
                   pciDeviceList *list,
                   pciDevice *dev)
{
    pciDevice *ret = NULL;
    int i;

    for (i = 0; i < list->count; i++) {
        if (list->devs[i]->domain   != dev->domain ||
            list->devs[i]->bus      != dev->bus    ||
            list->devs[i]->slot     != dev->slot   ||
            list->devs[i]->function != dev->function)
            continue;

        ret = list->devs[i];

        if (i != --list->count)
            memmove(&list->devs[i],
                    &list->devs[i+1],
                    sizeof(*list->devs) * (list->count-i));

        if (VIR_REALLOC_N(list->devs, list->count) < 0) {
            ; /* not fatal */
        }

        break;
    }
    return ret;
}

void
pciDeviceListDel(virConnectPtr conn,
                 pciDeviceList *list,
                 pciDevice *dev)
{
    pciDevice *ret = pciDeviceListSteal(conn, list, dev);
    if (ret)
        pciFreeDevice(conn, ret);
}

pciDevice *
pciDeviceListFind(pciDeviceList *list, pciDevice *dev)
{
    int i;

    for (i = 0; i < list->count; i++)
        if (list->devs[i]->domain   == dev->domain &&
            list->devs[i]->bus      == dev->bus    &&
            list->devs[i]->slot     == dev->slot   &&
            list->devs[i]->function == dev->function)
            return list->devs[i];
    return NULL;
}


int pciDeviceFileIterate(virConnectPtr conn,
                         pciDevice *dev,
                         pciDeviceFileActor actor,
                         void *opaque)
{
    char *pcidir = NULL;
    char *file = NULL;
    DIR *dir = NULL;
    int ret = -1;
    struct dirent *ent;

    if (virAsprintf(&pcidir, "/sys/bus/pci/devices/%04x:%02x:%02x.%x",
                    dev->domain, dev->bus, dev->slot, dev->function) < 0) {
        virReportOOMError(conn);
        goto cleanup;
    }

    if (!(dir = opendir(pcidir))) {
        virReportSystemError(conn, errno,
                             _("cannot open %s"), pcidir);
        goto cleanup;
    }

    while ((ent = readdir(dir)) != NULL) {
        /* Device assignment requires:
         *   $PCIDIR/config, $PCIDIR/resource, $PCIDIR/resourceNNN, $PCIDIR/rom
         */
        if (STREQ(ent->d_name, "config") ||
            STRPREFIX(ent->d_name, "resource") ||
            STREQ(ent->d_name, "rom")) {
            if (virAsprintf(&file, "%s/%s", pcidir, ent->d_name) < 0) {
                virReportOOMError(conn);
                goto cleanup;
            }
            if ((actor)(conn, dev, file, opaque) < 0)
                goto cleanup;

            VIR_FREE(file);
        }
    }

    ret = 0;

cleanup:
    if (dir)
        closedir(dir);
    VIR_FREE(file);
    VIR_FREE(pcidir);
    return ret;
}

static int
pciDeviceDownstreamLacksACS(virConnectPtr conn,
                            pciDevice *dev)
{
    uint16_t flags;
    uint16_t ctrl;
    unsigned int pos;

    if (!dev->initted && pciInitDevice(conn, dev) < 0)
        return -1;

    pos = dev->pcie_cap_pos;
    if (!pos || pciRead16(dev, PCI_CLASS_DEVICE) != PCI_CLASS_BRIDGE_PCI)
        return 0;

    flags = pciRead16(dev, pos + PCI_EXP_FLAGS);
    if (((flags & PCI_EXP_FLAGS_TYPE) >> 4) != PCI_EXP_TYPE_DOWNSTREAM)
        return 0;

    pos = pciFindExtendedCapabilityOffset(dev, PCI_EXT_CAP_ID_ACS);
    if (!pos) {
        VIR_DEBUG("%s %s: downstream port lacks ACS", dev->id, dev->name);
        return 1;
    }

    ctrl = pciRead16(dev, pos + PCI_EXT_ACS_CTRL);
    if ((ctrl & PCI_EXT_CAP_ACS_ENABLED) != PCI_EXT_CAP_ACS_ENABLED) {
        VIR_DEBUG("%s %s: downstream port has ACS disabled",
                  dev->id, dev->name);
        return 1;
    }

    return 0;
}

static int
pciDeviceIsBehindSwitchLackingACS(virConnectPtr conn,
                                  pciDevice *dev)
{
    pciDevice *parent;

    parent = pciGetParentDevice(conn, dev);
    if (!parent) {
        /* if we have no parent, and this is the root bus, ACS doesn't come
         * into play since devices on the root bus can't P2P without going
         * through the root IOMMU.
         */
        if (dev->bus == 0)
            return 0;
        else {
            pciReportError(conn, VIR_ERR_NO_SUPPORT,
                           _("Failed to find parent device for %s"),
                           dev->name);
            return -1;
        }
    }

    /* XXX we should rather fail when we can't find device's parent and
     * stop the loop when we get to root instead of just stopping when no
     * parent can be found
     */
    do {
        pciDevice *tmp;
        int acs;

        acs = pciDeviceDownstreamLacksACS(conn, parent);

        if (acs) {
            pciFreeDevice(conn, parent);
            if (acs < 0)
                return -1;
            else
                return 1;
        }

        tmp = parent;
        parent = pciGetParentDevice(conn, parent);
        pciFreeDevice(conn, tmp);
    } while (parent);

    return 0;
}

int pciDeviceIsAssignable(virConnectPtr conn,
                          pciDevice *dev,
                          int strict_acs_check)
{
    int ret;

    /* XXX This could be a great place to actually check that a non-managed
     * device isn't in use, e.g. by checking that device is either un-bound
     * or bound to a stub driver.
     */

    ret = pciDeviceIsBehindSwitchLackingACS(conn, dev);
    if (ret < 0)
        return 0;

    if (ret) {
        if (!strict_acs_check) {
            VIR_DEBUG("%s %s: strict ACS check disabled; device assignment allowed",
                      dev->id, dev->name);
        } else {
            pciReportError(conn, VIR_ERR_NO_SUPPORT,
                           _("Device %s is behind a switch lacking ACS and "
                             "cannot be assigned"),
                           dev->name);
            return 0;
        }
    }

    return 1;
}
