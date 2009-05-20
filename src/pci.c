/*
 * Copyright (C) 2009 Red Hat, Inc.
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

typedef int (*pciIterPredicate)(pciDevice *, pciDevice *);

/* Iterate over available PCI devices calling @predicate
 * to compare each one to @dev.
 * Return -1 on error since we don't want to assume it is
 * safe to reset if there is an error.
 */
static int
pciIterDevices(virConnectPtr conn,
               pciIterPredicate predicate,
               pciDevice *dev,
               pciDevice **matched)
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
        pciDevice *try;

        /* Ignore '.' and '..' */
        if (entry->d_name[0] == '.')
            continue;

        if (sscanf(entry->d_name, "%x:%x:%x.%x",
                   &domain, &bus, &slot, &function) < 4) {
            VIR_WARN("Unusual entry in " PCI_SYSFS "devices: %s", entry->d_name);
            continue;
        }

        try = pciGetDevice(conn, domain, bus, slot, function);
        if (!try) {
            ret = -1;
            break;
        }

        if (predicate(try, dev)) {
            VIR_DEBUG("%s %s: iter matched on %s", dev->id, dev->name, try->name);
            *matched = try;
            break;
        }
        pciFreeDevice(conn, try);
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

static unsigned
pciDetectFunctionLevelReset(pciDevice *dev)
{
    uint16_t caps;
    uint8_t pos;

    /* The PCIe Function Level Reset capability allows
     * individual device functions to be reset without
     * affecting any other functions on the device or
     * any other devices on the bus. This is only common
     * on SR-IOV NICs at the moment.
     */
    if (dev->pcie_cap_pos) {
        caps = pciRead16(dev, dev->pcie_cap_pos + PCI_EXP_DEVCAP);
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

/* Any devices other than the one supplied on the same domain/bus ? */
static int
pciSharesBus(pciDevice *a, pciDevice *b)
{
    return
        a->domain == b->domain &&
        a->bus == b->bus &&
        (a->slot != b->slot ||
         a->function != b->function);
}

static int
pciBusContainsOtherDevices(virConnectPtr conn, pciDevice *dev)
{
    pciDevice *matched = NULL;
    if (pciIterDevices(conn, pciSharesBus, dev, &matched) < 0)
        return 1;
    if (!matched)
        return 0;
    pciFreeDevice(conn, matched);
    return 1;
}

/* Any other functions on this device ? */
static int
pciSharesDevice(pciDevice *a, pciDevice *b)
{
    return
        a->domain == b->domain &&
        a->bus == b->bus &&
        a->slot == b->slot &&
        a->function != b->function;
}

static int
pciDeviceContainsOtherFunctions(virConnectPtr conn, pciDevice *dev)
{
    pciDevice *matched = NULL;
    if (pciIterDevices(conn, pciSharesDevice, dev, &matched) < 0)
        return 1;
    if (!matched)
        return 0;
    pciFreeDevice(conn, matched);
    return 1;
}

/* Is @a the parent of @b ? */
static int
pciIsParent(pciDevice *a, pciDevice *b)
{
    uint16_t device_class;
    uint8_t header_type, secondary, subordinate;

    if (a->domain != b->domain)
        return 0;

    /* Is it a bridge? */
    device_class = pciRead16(a, PCI_CLASS_DEVICE);
    if (device_class != PCI_CLASS_BRIDGE_PCI)
        return 0;

    /* Is it a plane? */
    header_type = pciRead8(a, PCI_HEADER_TYPE);
    if ((header_type & PCI_HEADER_TYPE_MASK) != PCI_HEADER_TYPE_BRIDGE)
        return 0;

    secondary   = pciRead8(a, PCI_SECONDARY_BUS);
    subordinate = pciRead8(a, PCI_SUBORDINATE_BUS);

    VIR_DEBUG("%s %s: found parent device %s\n", b->id, b->name, a->name);

    /* No, it's superman! */
    return (b->bus >= secondary && b->bus <= subordinate);
}

static pciDevice *
pciGetParentDevice(virConnectPtr conn, pciDevice *dev)
{
    pciDevice *parent = NULL;
    pciIterDevices(conn, pciIsParent, dev, &parent);
    return parent;
}

/* Secondary Bus Reset is our sledgehammer - it resets all
 * devices behind a bus.
 */
static int
pciTrySecondaryBusReset(virConnectPtr conn, pciDevice *dev)
{
    pciDevice *parent;
    uint8_t config_space[PCI_CONF_LEN];
    uint16_t ctl;
    int ret = -1;

    /* For now, we just refuse to do a secondary bus reset
     * if there are other devices/functions behind the bus.
     * In future, we could allow it so long as those devices
     * are not in use by the host or other guests.
     */
    if (pciBusContainsOtherDevices(conn, dev)) {
        VIR_WARN("Other devices on bus with %s, not doing bus reset",
                 dev->name);
        return -1;
    }

    /* Find the parent bus */
    parent = pciGetParentDevice(conn, dev);
    if (!parent) {
        VIR_WARN("Failed to find parent device for %s", dev->name);
        return -1;
    }

    VIR_DEBUG("%s %s: doing a secondary bus reset", dev->id, dev->name);

    /* Save and restore the device's config space; we only do this
     * for the supplied device since we refuse to do a reset if there
     * are multiple devices/functions
     */
    if (pciRead(dev, 0, config_space, PCI_CONF_LEN) < 0) {
        VIR_WARN("Failed to save PCI config space for %s", dev->name);
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

    if (pciWrite(dev, 0, config_space, PCI_CONF_LEN) < 0)
        VIR_WARN("Failed to restore PCI config space for %s", dev->name);

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
pciTryPowerManagementReset(virConnectPtr conn, pciDevice *dev)
{
    uint8_t config_space[PCI_CONF_LEN];
    uint32_t ctl;

    if (!dev->pci_pm_cap_pos)
        return -1;

    /* For now, we just refuse to do a power management reset
     * if there are other functions on this device.
     * In future, we could allow it so long as those functions
     * are not in use by the host or other guests.
     */
    if (pciDeviceContainsOtherFunctions(conn, dev)) {
        VIR_WARN("%s contains other functions, not resetting", dev->name);
        return -1;
    }

    /* Save and restore the device's config space. */
    if (pciRead(dev, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        VIR_WARN("Failed to save PCI config space for %s", dev->name);
        return -1;
    }

    VIR_DEBUG("%s %s: doing a power management reset", dev->id, dev->name);

    ctl = pciRead32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL);
    ctl &= ~PCI_PM_CTRL_STATE_MASK;

    pciWrite32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL, ctl|PCI_PM_CTRL_STATE_D3hot);

    usleep(10 * 1000); /* sleep 10ms */

    pciWrite32(dev, dev->pci_pm_cap_pos + PCI_PM_CTRL, ctl|PCI_PM_CTRL_STATE_D0);

    usleep(10 * 1000); /* sleep 10ms */

    if (pciWrite(dev, 0, &config_space[0], PCI_CONF_LEN) < 0)
        VIR_WARN("Failed to restore PCI config space for %s", dev->name);

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
pciResetDevice(virConnectPtr conn, pciDevice *dev)
{
    int ret = -1;

    if (!dev->initted && pciInitDevice(conn, dev) < 0)
        return -1;

    /* KVM will perform FLR when starting and stopping
     * a guest, so there is no need for us to do it here.
     */
    if (dev->has_flr)
        return 0;

    /* Bus reset is not an option with the root bus */
    if (dev->bus != 0)
        ret = pciTrySecondaryBusReset(conn, dev);

    /* Next best option is a PCI power management reset */
    if (ret < 0 && dev->has_pm_reset)
        ret = pciTryPowerManagementReset(conn, dev);

    if (ret < 0)
        pciReportError(conn, VIR_ERR_NO_SUPPORT,
                       _("No PCI reset capability available for %s"),
                       dev->name);
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

static char *
pciReadDeviceID(pciDevice *dev, const char *id_name)
{
    char path[PATH_MAX];
    char *id_str;

    snprintf(path, sizeof(path), PCI_SYSFS "devices/%s/%s",
             dev->name, id_name);

    /* ID string is '0xNNNN\n' ... i.e. 7 bytes */
    if (virFileReadAll(path, 7, &id_str) < 7) {
        VIR_FREE(id_str);
        return NULL;
    }

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
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    if (dev->fd >= 0)
        close(dev->fd);
    VIR_FREE(dev);
}
