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

#include "dirname.h"
#include "virlog.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virkmod.h"
#include "virstring.h"
#include "virutil.h"
#include "viralloc.h"

VIR_LOG_INIT("util.pci");

#define PCI_SYSFS "/sys/bus/pci/"
#define PCI_ID_LEN 10   /* "XXXX XXXX" */

VIR_ENUM_IMPL(virPCIELinkSpeed,
              VIR_PCIE_LINK_SPEED_LAST,
              "", "2.5", "5", "8", "16",
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

    unsigned int  pcie_cap_pos;
    unsigned int  pci_pm_cap_pos;
    bool          has_flr;
    bool          has_pm_reset;
    bool          managed;

    virPCIStubDriver stubDriver;

    /* used by reattach function */
    bool          unbind_from_stub;
    bool          remove_slot;
    bool          reprobe;
};

struct _virPCIDeviceList {
    virObjectLockable parent;

    size_t count;
    virPCIDevicePtr *devs;
};


/* For virReportOOMError()  and virReportSystemError() */
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

static virClassPtr virPCIDeviceListClass;

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
    char *buffer;

    ignore_value(virAsprintf(&buffer, PCI_SYSFS "drivers/%s", driver));
    return buffer;
}


static char *
virPCIFile(const char *device, const char *file)
{
    char *buffer;

    ignore_value(virAsprintf(&buffer, PCI_SYSFS "devices/%s/%s", device, file));
    return buffer;
}


/* virPCIDeviceGetDriverPathAndName - put the path to the driver
 * directory of the driver in use for this device in @path and the
 * name of the driver in @name. Both could be NULL if it's not bound
 * to any driver.
 *
 * Return 0 for success, -1 for error.
 */
int
virPCIDeviceGetDriverPathAndName(virPCIDevicePtr dev, char **path, char **name)
{
    int ret = -1;
    VIR_AUTOFREE(char *) drvlink = NULL;

    *path = *name = NULL;
    /* drvlink = "/sys/bus/pci/dddd:bb:ss.ff/driver" */
    if (!(drvlink = virPCIFile(dev->name, "driver")))
        goto cleanup;

    if (!virFileExists(drvlink)) {
        ret = 0;
        goto cleanup;
    }

    if (virFileIsLink(drvlink) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device %s driver file %s is not a symlink"),
                       dev->name, drvlink);
        goto cleanup;
    }
    if (virFileResolveLink(drvlink, path) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %s driver symlink %s"),
                       dev->name, drvlink);
        goto cleanup;
    }
    /* path = "/sys/bus/pci/drivers/${drivername}" */

    if (VIR_STRDUP(*name, last_component(*path)) < 0)
        goto cleanup;
    /* name = "${drivername}" */

    ret = 0;
 cleanup:
    if (ret < 0) {
        VIR_FREE(*path);
        VIR_FREE(*name);
    }
    return ret;
}


static int
virPCIDeviceConfigOpenInternal(virPCIDevicePtr dev, bool readonly, bool fatal)
{
    int fd;

    fd = open(dev->path, readonly ? O_RDONLY : O_RDWR);

    if (fd < 0) {
        if (fatal) {
            virReportSystemError(errno,
                                 _("Failed to open config space file '%s'"),
                                 dev->path);
        } else {
            char ebuf[1024];
            VIR_WARN("Failed to open config space file '%s': %s",
                     dev->path, virStrerror(errno, ebuf, sizeof(ebuf)));
        }
        return -1;
    }

    VIR_DEBUG("%s %s: opened %s", dev->id, dev->name, dev->path);
    return fd;
}

static int
virPCIDeviceConfigOpen(virPCIDevicePtr dev)
{
    return virPCIDeviceConfigOpenInternal(dev, true, true);
}

static int
virPCIDeviceConfigOpenTry(virPCIDevicePtr dev)
{
    return virPCIDeviceConfigOpenInternal(dev, true, false);
}

static int
virPCIDeviceConfigOpenWrite(virPCIDevicePtr dev)
{
    return virPCIDeviceConfigOpenInternal(dev, false, true);
}

static void
virPCIDeviceConfigClose(virPCIDevicePtr dev, int cfgfd)
{
    if (VIR_CLOSE(cfgfd) < 0) {
        char ebuf[1024];
        VIR_WARN("Failed to close config space file '%s': %s",
                 dev->path, virStrerror(errno, ebuf, sizeof(ebuf)));
    }
}


static int
virPCIDeviceRead(virPCIDevicePtr dev,
                 int cfgfd,
                 unsigned int pos,
                 uint8_t *buf,
                 unsigned int buflen)
{
    memset(buf, 0, buflen);

    if (lseek(cfgfd, pos, SEEK_SET) != pos ||
        saferead(cfgfd, buf, buflen) != buflen) {
        char ebuf[1024];
        VIR_WARN("Failed to read from '%s' : %s", dev->path,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    return 0;
}

static uint8_t
virPCIDeviceRead8(virPCIDevicePtr dev, int cfgfd, unsigned int pos)
{
    uint8_t buf;
    virPCIDeviceRead(dev, cfgfd, pos, &buf, sizeof(buf));
    return buf;
}

static uint16_t
virPCIDeviceRead16(virPCIDevicePtr dev, int cfgfd, unsigned int pos)
{
    uint8_t buf[2];
    virPCIDeviceRead(dev, cfgfd, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8);
}

static uint32_t
virPCIDeviceRead32(virPCIDevicePtr dev, int cfgfd, unsigned int pos)
{
    uint8_t buf[4];
    virPCIDeviceRead(dev, cfgfd, pos, &buf[0], sizeof(buf));
    return (buf[0] << 0) | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24);
}

static int
virPCIDeviceReadClass(virPCIDevicePtr dev, uint16_t *device_class)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) id_str = NULL;
    unsigned int value;

    if (!(path = virPCIFile(dev->name, "class")))
        return -1;

    /* class string is '0xNNNNNN\n' ... i.e. 9 bytes */
    if (virFileReadAll(path, 9, &id_str) < 0)
        return -1;

    id_str[8] = '\0';
    if (virStrToLong_ui(id_str, NULL, 16, &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unusual value in %s/devices/%s/class: %s"),
                       PCI_SYSFS, dev->name, id_str);
        return -1;
    }

    *device_class = (value >> 8) & 0xFFFF;
    return 0;
}

static int
virPCIDeviceWrite(virPCIDevicePtr dev,
                  int cfgfd,
                  unsigned int pos,
                  uint8_t *buf,
                  unsigned int buflen)
{
    if (lseek(cfgfd, pos, SEEK_SET) != pos ||
        safewrite(cfgfd, buf, buflen) != buflen) {
        char ebuf[1024];
        VIR_WARN("Failed to write to '%s' : %s", dev->path,
                 virStrerror(errno, ebuf, sizeof(ebuf)));
        return -1;
    }
    return 0;
}

static void
virPCIDeviceWrite16(virPCIDevicePtr dev, int cfgfd, unsigned int pos, uint16_t val)
{
    uint8_t buf[2] = { (val >> 0), (val >> 8) };
    virPCIDeviceWrite(dev, cfgfd, pos, &buf[0], sizeof(buf));
}

static void
virPCIDeviceWrite32(virPCIDevicePtr dev, int cfgfd, unsigned int pos, uint32_t val)
{
    uint8_t buf[4] = { (val >> 0), (val >> 8), (val >> 16), (val >> 24) };
    virPCIDeviceWrite(dev, cfgfd, pos, &buf[0], sizeof(buf));
}

typedef int (*virPCIDeviceIterPredicate)(virPCIDevicePtr, virPCIDevicePtr,
                                         void *);

/* Iterate over available PCI devices calling @predicate
 * to compare each one to @dev.
 * Return -1 on error since we don't want to assume it is
 * safe to reset if there is an error.
 */
static int
virPCIDeviceIterDevices(virPCIDeviceIterPredicate predicate,
                        virPCIDevicePtr dev,
                        virPCIDevicePtr *matched,
                        void *data)
{
    DIR *dir;
    struct dirent *entry;
    int ret = 0;
    int rc;

    *matched = NULL;

    VIR_DEBUG("%s %s: iterating over " PCI_SYSFS "devices", dev->id, dev->name);

    if (virDirOpen(&dir, PCI_SYSFS "devices") < 0)
        return -1;

    while ((ret = virDirRead(dir, &entry, PCI_SYSFS "devices")) > 0) {
        unsigned int domain, bus, slot, function;
        VIR_AUTOPTR(virPCIDevice) check = NULL;
        char *tmp;

        /* expected format: <domain>:<bus>:<slot>.<function> */
        if (/* domain */
            virStrToLong_ui(entry->d_name, &tmp, 16, &domain) < 0 || *tmp != ':' ||
            /* bus */
            virStrToLong_ui(tmp + 1, &tmp, 16, &bus) < 0 || *tmp != ':' ||
            /* slot */
            virStrToLong_ui(tmp + 1, &tmp, 16, &slot) < 0 || *tmp != '.' ||
            /* function */
            virStrToLong_ui(tmp + 1, NULL, 16, &function) < 0) {
            VIR_WARN("Unusual entry in " PCI_SYSFS "devices: %s", entry->d_name);
            continue;
        }

        check = virPCIDeviceNew(domain, bus, slot, function);
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
            VIR_STEAL_PTR(*matched, check);
            ret = 1;
            break;
        }
    }
    VIR_DIR_CLOSE(dir);
    return ret;
}

static uint8_t
virPCIDeviceFindCapabilityOffset(virPCIDevicePtr dev,
                                 int cfgfd,
                                 unsigned int capability)
{
    uint16_t status;
    uint8_t pos;

    status = virPCIDeviceRead16(dev, cfgfd, PCI_STATUS);
    if (!(status & PCI_STATUS_CAP_LIST))
        return 0;

    pos = virPCIDeviceRead8(dev, cfgfd, PCI_CAPABILITY_LIST);

    /* Zero indicates last capability, capabilities can't
     * be in the config space header and 0xff is returned
     * by the kernel if we don't have access to this region
     *
     * Note: we're not handling loops or extended
     * capabilities here.
     */
    while (pos >= PCI_CONF_HEADER_LEN && pos != 0xff) {
        uint8_t capid = virPCIDeviceRead8(dev, cfgfd, pos);
        if (capid == capability) {
            VIR_DEBUG("%s %s: found cap 0x%.2x at 0x%.2x",
                      dev->id, dev->name, capability, pos);
            return pos;
        }

        pos = virPCIDeviceRead8(dev, cfgfd, pos + 1);
    }

    VIR_DEBUG("%s %s: failed to find cap 0x%.2x", dev->id, dev->name, capability);

    return 0;
}

static unsigned int
virPCIDeviceFindExtendedCapabilityOffset(virPCIDevicePtr dev,
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
static int
virPCIDeviceDetectFunctionLevelReset(virPCIDevicePtr dev, int cfgfd)
{
    uint32_t caps;
    uint8_t pos;
    VIR_AUTOFREE(char *) path = NULL;
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
            return 1;
        }
    }

    /* The PCI AF Function Level Reset capability is
     * the same thing, except for conventional PCI
     * devices. This is not common yet.
     */
    pos = virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_AF);
    if (pos) {
        caps = virPCIDeviceRead16(dev, cfgfd, pos + PCI_AF_CAP);
        if (caps & PCI_AF_CAP_FLR) {
            VIR_DEBUG("%s %s: detected PCI FLR capability", dev->id, dev->name);
            return 1;
        }
    }

    /* there are some buggy devices that do support FLR, but forget to
     * advertise that fact in their capabilities.  However, FLR is *required*
     * to be present for virtual functions (VFs), so if we see that this
     * device is a VF, we just assume FLR works
     */

    if (virAsprintf(&path, PCI_SYSFS "devices/%s/physfn", dev->name) < 0)
        return -1;

    found = virFileExists(path);
    if (found) {
        VIR_DEBUG("%s %s: buggy device didn't advertise FLR, but is a VF; forcing flr on",
                  dev->id, dev->name);
        return 1;
    }

    VIR_DEBUG("%s %s: no FLR capability found", dev->id, dev->name);

    return 0;
}

/* Require the device has the PCI Power Management capability
 * and that a D3hot->D0 transition will results in a full
 * internal reset, not just a soft reset.
 */
static unsigned int
virPCIDeviceDetectPowerManagementReset(virPCIDevicePtr dev, int cfgfd)
{
    if (dev->pci_pm_cap_pos) {
        uint32_t ctl;

        /* require the NO_SOFT_RESET bit is clear */
        ctl = virPCIDeviceRead32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL);
        if (!(ctl & PCI_PM_CTRL_NO_SOFT_RESET)) {
            VIR_DEBUG("%s %s: detected PM reset capability", dev->id, dev->name);
            return 1;
        }
    }

    VIR_DEBUG("%s %s: no PM reset capability found", dev->id, dev->name);

    return 0;
}

/* Any active devices on the same domain/bus ? */
static int
virPCIDeviceSharesBusWithActive(virPCIDevicePtr dev, virPCIDevicePtr check, void *data)
{
    virPCIDeviceList *inactiveDevs = data;

    /* Different domain, different bus, or simply identical device */
    if (dev->address.domain != check->address.domain ||
        dev->address.bus != check->address.bus ||
        (dev->address.slot == check->address.slot &&
         dev->address.function == check->address.function))
        return 0;

    /* same bus, but inactive, i.e. about to be assigned to guest */
    if (inactiveDevs && virPCIDeviceListFind(inactiveDevs, check))
        return 0;

    return 1;
}

static virPCIDevicePtr
virPCIDeviceBusContainsActiveDevices(virPCIDevicePtr dev,
                                     virPCIDeviceList *inactiveDevs)
{
    virPCIDevicePtr active = NULL;
    if (virPCIDeviceIterDevices(virPCIDeviceSharesBusWithActive,
                                dev, &active, inactiveDevs) < 0)
        return NULL;
    return active;
}

/* Is @check the parent of @dev ? */
static int
virPCIDeviceIsParent(virPCIDevicePtr dev, virPCIDevicePtr check, void *data)
{
    uint16_t device_class;
    uint8_t header_type, secondary, subordinate;
    virPCIDevicePtr *best = data;
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
            *best = virPCIDeviceNew(check->address.domain,
                                    check->address.bus,
                                    check->address.slot,
                                    check->address.function);
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
                *best = virPCIDeviceNew(check->address.domain,
                                        check->address.bus,
                                        check->address.slot,
                                        check->address.function);
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
virPCIDeviceGetParent(virPCIDevicePtr dev, virPCIDevicePtr *parent)
{
    virPCIDevicePtr best = NULL;
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
virPCIDeviceTrySecondaryBusReset(virPCIDevicePtr dev,
                                 int cfgfd,
                                 virPCIDeviceList *inactiveDevs)
{
    VIR_AUTOPTR(virPCIDevice) parent = NULL;
    VIR_AUTOPTR(virPCIDevice) conflict = NULL;
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
                       _("Active %s devices on bus with %s, not doing bus reset"),
                       conflict->name, dev->name);
        return -1;
    }

    /* Find the parent bus */
    if (virPCIDeviceGetParent(dev, &parent) < 0)
        return -1;
    if (!parent) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to find parent device for %s"),
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
                       _("Failed to read PCI config space for %s"),
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
                       _("Failed to restore PCI config space for %s"),
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
virPCIDeviceTryPowerManagementReset(virPCIDevicePtr dev, int cfgfd)
{
    uint8_t config_space[PCI_CONF_LEN];
    uint32_t ctl;

    if (!dev->pci_pm_cap_pos)
        return -1;

    /* Save and restore the device's config space. */
    if (virPCIDeviceRead(dev, cfgfd, 0, &config_space[0], PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read PCI config space for %s"),
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
                       _("Failed to restore PCI config space for %s"),
                       dev->name);
        return -1;
    }

    return 0;
}

static int
virPCIDeviceInit(virPCIDevicePtr dev, int cfgfd)
{
    int flr;

    dev->pcie_cap_pos   = virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_EXP);
    dev->pci_pm_cap_pos = virPCIDeviceFindCapabilityOffset(dev, cfgfd, PCI_CAP_ID_PM);
    flr = virPCIDeviceDetectFunctionLevelReset(dev, cfgfd);
    if (flr < 0)
        return flr;
    dev->has_flr        = !!flr;
    dev->has_pm_reset   = !!virPCIDeviceDetectPowerManagementReset(dev, cfgfd);

    return 0;
}

int
virPCIDeviceReset(virPCIDevicePtr dev,
                  virPCIDeviceList *activeDevs,
                  virPCIDeviceList *inactiveDevs)
{
    VIR_AUTOFREE(char *) drvPath = NULL;
    VIR_AUTOFREE(char *) drvName = NULL;
    int ret = -1;
    int fd = -1;
    int hdrType = -1;

    if (virPCIGetHeaderType(dev, &hdrType) < 0)
        return -1;

    if (hdrType != VIR_PCI_HEADER_ENDPOINT) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid attempt to reset PCI device %s. "
                         "Only PCI endpoint devices can be reset"),
                       dev->name);
        return -1;
    }

    if (activeDevs && virPCIDeviceListFind(activeDevs, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not resetting active device %s"), dev->name);
        return -1;
    }

    /* If the device is currently bound to vfio-pci, ignore all
     * requests to reset it, since the vfio-pci driver will always
     * reset it whenever appropriate, so doing it ourselves would just
     * be redundant.
     */
    if (virPCIDeviceGetDriverPathAndName(dev, &drvPath, &drvName) < 0)
        goto cleanup;

    if (virPCIStubDriverTypeFromString(drvName) == VIR_PCI_STUB_DRIVER_VFIO) {
        VIR_DEBUG("Device %s is bound to vfio-pci - skip reset",
                  dev->name);
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
                       _("Unable to reset PCI device %s: %s"),
                       dev->name,
                       err ? err->message :
                       _("no FLR, PM reset or bus reset available"));
    }

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}


static int
virPCIProbeStubDriver(virPCIStubDriver driver)
{
    const char *drvname = NULL;
    VIR_AUTOFREE(char *) drvpath = NULL;
    bool probed = false;

    if (driver == VIR_PCI_STUB_DRIVER_NONE ||
        !(drvname = virPCIStubDriverTypeToString(driver))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s",
                       _("Attempting to use unknown stub driver"));
        return -1;
    }

 recheck:
    if ((drvpath = virPCIDriverDir(drvname)) && virFileExists(drvpath))
        /* driver already loaded, return */
        return 0;

    if (!probed) {
        VIR_AUTOFREE(char *) errbuf = NULL;
        probed = true;
        if ((errbuf = virKModLoad(drvname, true))) {
            VIR_WARN("failed to load driver %s: %s", drvname, errbuf);
            goto cleanup;
        }

        goto recheck;
    }

 cleanup:
    /* If we know failure was because of blacklist, let's report that;
     * otherwise, report a more generic failure message
     */
    if (virKModIsBlacklisted(drvname)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI stub module %s: "
                         "administratively prohibited"),
                       drvname);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI stub module %s"),
                       drvname);
    }

    return -1;
}

int
virPCIDeviceUnbind(virPCIDevicePtr dev)
{
    VIR_AUTOFREE(char *) path = NULL;
    VIR_AUTOFREE(char *) drvpath = NULL;
    VIR_AUTOFREE(char *) driver = NULL;

    if (virPCIDeviceGetDriverPathAndName(dev, &drvpath, &driver) < 0)
        return -1;

    if (!driver)
        /* The device is not bound to any driver */
        return 0;

    if (!(path = virPCIFile(dev->name, "driver/unbind")))
        return -1;

    if (virFileExists(path)) {
        if (virFileWriteStr(path, dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to unbind PCI device '%s' from %s"),
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
int virPCIDeviceRebind(virPCIDevicePtr dev)
{
    if (virPCIDeviceUnbind(dev) < 0)
        return -1;

    if (virFileWriteStr(PCI_SYSFS "drivers_probe", dev->name, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to trigger a probe for PCI device '%s'"),
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
virPCIDeviceBindWithDriverOverride(virPCIDevicePtr dev,
                                   const char *driverName)
{
    VIR_AUTOFREE(char *) path = NULL;

    if (!(path = virPCIFile(dev->name, "driver_override")))
        return -1;

    if (virFileWriteStr(path, driverName, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to add driver '%s' to driver_override "
                               " interface of PCI device '%s'"),
                             driverName, dev->name);
        return -1;
    }

    if (virPCIDeviceRebind(dev) < 0)
        return -1;

    return 0;
}

static int
virPCIDeviceUnbindFromStub(virPCIDevicePtr dev)
{
    if (!dev->unbind_from_stub) {
        VIR_DEBUG("Unbind from stub skipped for PCI device %s", dev->name);
        return 0;
    }

    return virPCIDeviceBindWithDriverOverride(dev, "\n");
}

static int
virPCIDeviceBindToStub(virPCIDevicePtr dev)
{
    const char *stubDriverName;
    VIR_AUTOFREE(char *) stubDriverPath = NULL;
    VIR_AUTOFREE(char *) driverLink = NULL;

    /* Check the device is configured to use one of the known stub drivers */
    if (dev->stubDriver == VIR_PCI_STUB_DRIVER_NONE) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("No stub driver configured for PCI device %s"),
                       dev->name);
        return -1;
    } else if (!(stubDriverName = virPCIStubDriverTypeToString(dev->stubDriver))) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unknown stub driver configured for PCI device %s"),
                       dev->name);
        return -1;
    }

    if (!(stubDriverPath = virPCIDriverDir(stubDriverName))  ||
        !(driverLink = virPCIFile(dev->name, "driver")))
        return -1;

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
 * driver (previously set with virPCIDeviceSetStubDriver(), and add *a
 * copy* of the object to the inactiveDevs list (if provided). This
 * function will *never* consume dev, so the caller should free it.
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
virPCIDeviceDetach(virPCIDevicePtr dev,
                   virPCIDeviceList *activeDevs,
                   virPCIDeviceList *inactiveDevs)
{
    if (virPCIProbeStubDriver(dev->stubDriver) < 0)
        return -1;

    if (activeDevs && virPCIDeviceListFind(activeDevs, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not detaching active device %s"), dev->name);
        return -1;
    }

    if (virPCIDeviceBindToStub(dev) < 0)
        return -1;

    /* Add *a copy of* the dev into list inactiveDevs, if
     * it's not already there.
     */
    if (inactiveDevs && !virPCIDeviceListFind(inactiveDevs, dev)) {
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
virPCIDeviceReattach(virPCIDevicePtr dev,
                     virPCIDeviceListPtr activeDevs,
                     virPCIDeviceListPtr inactiveDevs)
{
    if (activeDevs && virPCIDeviceListFind(activeDevs, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not reattaching active device %s"), dev->name);
        return -1;
    }

    if (virPCIDeviceUnbindFromStub(dev) < 0)
        return -1;

    /* Steal the dev from list inactiveDevs */
    if (inactiveDevs) {
        VIR_DEBUG("Removing PCI device %s from inactive list", dev->name);
        virPCIDeviceListDel(inactiveDevs, dev);
    }

    return 0;
}

static char *
virPCIDeviceReadID(virPCIDevicePtr dev, const char *id_name)
{
    VIR_AUTOFREE(char *) path = NULL;
    char *id_str;

    if (!(path = virPCIFile(dev->name, id_name)))
        return NULL;

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

bool
virPCIDeviceAddressIsValid(virPCIDeviceAddressPtr addr,
                           bool report)
{
    if (addr->domain > 0xFFFFFFFF) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address domain='0x%x', "
                             "must be <= 0xFFFF"),
                           addr->domain);
        return false;
    }
    if (addr->bus > 0xFF) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address bus='0x%x', "
                             "must be <= 0xFF"),
                           addr->bus);
        return false;
    }
    if (addr->slot > 0x1F) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address slot='0x%x', "
                             "must be <= 0x1F"),
                           addr->slot);
        return false;
    }
    if (addr->function > 7) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR,
                           _("Invalid PCI address function=0x%x, "
                             "must be <= 7"),
                           addr->function);
        return false;
    }
    if (virPCIDeviceAddressIsEmpty(addr)) {
        if (report)
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Invalid PCI address 0000:00:00, at least "
                             "one of domain, bus, or slot must be > 0"));
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

char *
virPCIDeviceAddressAsString(const virPCIDeviceAddress *addr)
{
    char *str;

    ignore_value(virAsprintf(&str,
                             VIR_PCI_DEVICE_ADDRESS_FMT,
                             addr->domain,
                             addr->bus,
                             addr->slot,
                             addr->function));
    return str;
}

virPCIDevicePtr
virPCIDeviceNew(unsigned int domain,
                unsigned int bus,
                unsigned int slot,
                unsigned int function)
{
    VIR_AUTOPTR(virPCIDevice) dev = NULL;
    VIR_AUTOFREE(char *) vendor = NULL;
    VIR_AUTOFREE(char *) product = NULL;

    if (VIR_ALLOC(dev) < 0)
        return NULL;

    dev->address.domain = domain;
    dev->address.bus = bus;
    dev->address.slot = slot;
    dev->address.function = function;

    if (virAsprintf(&dev->name,
                    VIR_PCI_DEVICE_ADDRESS_FMT,
                    domain, bus, slot, function) < 0)
        return NULL;

    if (virAsprintf(&dev->path, PCI_SYSFS "devices/%s/config",
                    dev->name) < 0)
        return NULL;

    if (!virFileExists(dev->path)) {
        virReportSystemError(errno,
                             _("Device %s not found: could not access %s"),
                             dev->name, dev->path);
        return NULL;
    }

    vendor  = virPCIDeviceReadID(dev, "vendor");
    product = virPCIDeviceReadID(dev, "device");

    if (!vendor || !product) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read product/vendor ID for %s"),
                       dev->name);
        return NULL;
    }

    /* strings contain '0x' prefix */
    if (snprintf(dev->id, sizeof(dev->id), "%s %s", &vendor[2],
                 &product[2]) >= sizeof(dev->id)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->id buffer overflow: %s %s"),
                       &vendor[2], &product[2]);
        return NULL;
    }

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

    VIR_RETURN_PTR(dev);
}


virPCIDevicePtr
virPCIDeviceCopy(virPCIDevicePtr dev)
{
    virPCIDevicePtr copy;

    if (VIR_ALLOC(copy) < 0)
        return NULL;

    /* shallow copy to take care of most attributes */
    *copy = *dev;
    copy->path = NULL;
    copy->used_by_drvname = copy->used_by_domname = NULL;
    if (VIR_STRDUP(copy->name, dev->name) < 0 ||
        VIR_STRDUP(copy->path, dev->path) < 0 ||
        VIR_STRDUP(copy->used_by_drvname, dev->used_by_drvname) < 0 ||
        VIR_STRDUP(copy->used_by_domname, dev->used_by_domname) < 0) {
        goto error;
    }
    return copy;

 error:
    virPCIDeviceFree(copy);
    return NULL;
}


void
virPCIDeviceFree(virPCIDevicePtr dev)
{
    if (!dev)
        return;
    VIR_DEBUG("%s %s: freeing", dev->id, dev->name);
    VIR_FREE(dev->name);
    VIR_FREE(dev->path);
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    VIR_FREE(dev);
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
virPCIDeviceAddressPtr
virPCIDeviceGetAddress(virPCIDevicePtr dev)
{
    return &(dev->address);
}

const char *
virPCIDeviceGetName(virPCIDevicePtr dev)
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
virPCIDeviceGetConfigPath(virPCIDevicePtr dev)
{
    return dev->path;
}

void virPCIDeviceSetManaged(virPCIDevicePtr dev, bool managed)
{
    dev->managed = managed;
}

bool
virPCIDeviceGetManaged(virPCIDevicePtr dev)
{
    return dev->managed;
}

void
virPCIDeviceSetStubDriver(virPCIDevicePtr dev, virPCIStubDriver driver)
{
    dev->stubDriver = driver;
}

virPCIStubDriver
virPCIDeviceGetStubDriver(virPCIDevicePtr dev)
{
    return dev->stubDriver;
}

bool
virPCIDeviceGetUnbindFromStub(virPCIDevicePtr dev)
{
    return dev->unbind_from_stub;
}

void
virPCIDeviceSetUnbindFromStub(virPCIDevicePtr dev, bool unbind)
{
    dev->unbind_from_stub = unbind;
}

bool
virPCIDeviceGetRemoveSlot(virPCIDevicePtr dev)
{
    return dev->remove_slot;
}

void
virPCIDeviceSetRemoveSlot(virPCIDevicePtr dev, bool remove_slot)
{
    dev->remove_slot = remove_slot;
}

bool
virPCIDeviceGetReprobe(virPCIDevicePtr dev)
{
    return dev->reprobe;
}

void
virPCIDeviceSetReprobe(virPCIDevicePtr dev, bool reprobe)
{
    dev->reprobe = reprobe;
}

int
virPCIDeviceSetUsedBy(virPCIDevicePtr dev,
                      const char *drv_name,
                      const char *dom_name)
{
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    if (VIR_STRDUP(dev->used_by_drvname, drv_name) < 0)
        return -1;
    if (VIR_STRDUP(dev->used_by_domname, dom_name) < 0)
        return -1;

    return 0;
}

void
virPCIDeviceGetUsedBy(virPCIDevicePtr dev,
                      const char **drv_name,
                      const char **dom_name)
{
    *drv_name = dev->used_by_drvname;
    *dom_name = dev->used_by_domname;
}

virPCIDeviceListPtr
virPCIDeviceListNew(void)
{
    virPCIDeviceListPtr list;

    if (virPCIInitialize() < 0)
        return NULL;

    if (!(list = virObjectLockableNew(virPCIDeviceListClass)))
        return NULL;

    return list;
}

static void
virPCIDeviceListDispose(void *obj)
{
    virPCIDeviceListPtr list = obj;
    size_t i;

    for (i = 0; i < list->count; i++) {
        virPCIDeviceFree(list->devs[i]);
        list->devs[i] = NULL;
    }

    list->count = 0;
    VIR_FREE(list->devs);
}

int
virPCIDeviceListAdd(virPCIDeviceListPtr list,
                    virPCIDevicePtr dev)
{
    if (virPCIDeviceListFind(list, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Device %s is already in use"), dev->name);
        return -1;
    }
    return VIR_APPEND_ELEMENT(list->devs, list->count, dev);
}


/* virPCIDeviceListAddCopy - add a *copy* of the device to this list */
int
virPCIDeviceListAddCopy(virPCIDeviceListPtr list, virPCIDevicePtr dev)
{
    VIR_AUTOPTR(virPCIDevice) copy = virPCIDeviceCopy(dev);

    if (!copy)
        return -1;
    if (virPCIDeviceListAdd(list, copy) < 0)
        return -1;

    copy = NULL;
    return 0;
}


virPCIDevicePtr
virPCIDeviceListGet(virPCIDeviceListPtr list,
                    int idx)
{
    if (idx >= list->count)
        return NULL;
    if (idx < 0)
        return NULL;

    return list->devs[idx];
}

size_t
virPCIDeviceListCount(virPCIDeviceListPtr list)
{
    return list->count;
}

virPCIDevicePtr
virPCIDeviceListStealIndex(virPCIDeviceListPtr list,
                           int idx)
{
    virPCIDevicePtr ret;

    if (idx < 0 || idx >= list->count)
        return NULL;

    ret = list->devs[idx];
    VIR_DELETE_ELEMENT(list->devs, idx, list->count);
    return ret;
}

virPCIDevicePtr
virPCIDeviceListSteal(virPCIDeviceListPtr list,
                      virPCIDevicePtr dev)
{
    return virPCIDeviceListStealIndex(list, virPCIDeviceListFindIndex(list, dev));
}

void
virPCIDeviceListDel(virPCIDeviceListPtr list,
                    virPCIDevicePtr dev)
{
    virPCIDeviceFree(virPCIDeviceListSteal(list, dev));
}

int
virPCIDeviceListFindIndex(virPCIDeviceListPtr list, virPCIDevicePtr dev)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virPCIDevicePtr other = list->devs[i];
        if (other->address.domain   == dev->address.domain &&
            other->address.bus      == dev->address.bus    &&
            other->address.slot     == dev->address.slot   &&
            other->address.function == dev->address.function)
            return i;
    }
    return -1;
}


virPCIDevicePtr
virPCIDeviceListFindByIDs(virPCIDeviceListPtr list,
                          unsigned int domain,
                          unsigned int bus,
                          unsigned int slot,
                          unsigned int function)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        virPCIDevicePtr other = list->devs[i];
        if (other->address.domain   == domain &&
            other->address.bus      == bus    &&
            other->address.slot     == slot   &&
            other->address.function == function)
            return list->devs[i];
    }
    return NULL;
}


virPCIDevicePtr
virPCIDeviceListFind(virPCIDeviceListPtr list, virPCIDevicePtr dev)
{
    int idx;

    if ((idx = virPCIDeviceListFindIndex(list, dev)) >= 0)
        return list->devs[idx];
    else
        return NULL;
}


int virPCIDeviceFileIterate(virPCIDevicePtr dev,
                            virPCIDeviceFileActor actor,
                            void *opaque)
{
    VIR_AUTOFREE(char *) pcidir = NULL;
    DIR *dir = NULL;
    int ret = -1;
    struct dirent *ent;
    int direrr;

    if (virAsprintf(&pcidir, "/sys/bus/pci/devices/" VIR_PCI_DEVICE_ADDRESS_FMT,
                    dev->address.domain, dev->address.bus,
                    dev->address.slot, dev->address.function) < 0)
        goto cleanup;

    if (virDirOpen(&dir, pcidir) < 0)
        goto cleanup;

    while ((direrr = virDirRead(dir, &ent, pcidir)) > 0) {
        VIR_AUTOFREE(char *) file = NULL;
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
            if (virAsprintf(&file, "%s/%s", pcidir, ent->d_name) < 0)
                goto cleanup;
            if ((actor)(dev, file, opaque) < 0)
                goto cleanup;
        }
    }
    if (direrr < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_DIR_CLOSE(dir);
    return ret;
}


/* virPCIDeviceAddressIOMMUGroupIterate:
 *   Call @actor for all devices in the same iommu_group as orig
 *   (including orig itself) Even if there is no iommu_group for the
 *   device, call @actor once for orig.
 */
int
virPCIDeviceAddressIOMMUGroupIterate(virPCIDeviceAddressPtr orig,
                                     virPCIDeviceAddressActor actor,
                                     void *opaque)
{
    VIR_AUTOFREE(char *) groupPath = NULL;
    DIR *groupDir = NULL;
    int ret = -1;
    struct dirent *ent;
    int direrr;

    if (virAsprintf(&groupPath,
                    PCI_SYSFS "devices/" VIR_PCI_DEVICE_ADDRESS_FMT "/iommu_group/devices",
                    orig->domain, orig->bus, orig->slot, orig->function) < 0)
        goto cleanup;

    if (virDirOpenQuiet(&groupDir, groupPath) < 0) {
        /* just process the original device, nothing more */
        ret = (actor)(orig, opaque);
        goto cleanup;
    }

    while ((direrr = virDirRead(groupDir, &ent, groupPath)) > 0) {
        virPCIDeviceAddress newDev;

        if (virPCIDeviceAddressParse(ent->d_name, &newDev) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Found invalid device link '%s' in '%s'"),
                           ent->d_name, groupPath);
            goto cleanup;
        }

        if ((actor)(&newDev, opaque) < 0)
            goto cleanup;
    }
    if (direrr < 0)
        goto cleanup;

    ret = 0;

 cleanup:
    VIR_DIR_CLOSE(groupDir);
    return ret;
}


static int
virPCIDeviceGetIOMMUGroupAddOne(virPCIDeviceAddressPtr newDevAddr, void *opaque)
{
    virPCIDeviceListPtr groupList = opaque;
    VIR_AUTOPTR(virPCIDevice) newDev = NULL;

    if (!(newDev = virPCIDeviceNew(newDevAddr->domain, newDevAddr->bus,
                                   newDevAddr->slot, newDevAddr->function)))
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
virPCIDeviceListPtr
virPCIDeviceGetIOMMUGroupList(virPCIDevicePtr dev)
{
    virPCIDeviceListPtr groupList = virPCIDeviceListNew();

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
    virPCIDeviceAddressPtr **iommuGroupDevices;
    size_t *nIommuGroupDevices;
} virPCIDeviceAddressList;
typedef virPCIDeviceAddressList *virPCIDeviceAddressListPtr;

static int
virPCIGetIOMMUGroupAddressesAddOne(virPCIDeviceAddressPtr newDevAddr, void *opaque)
{
    int ret = -1;
    virPCIDeviceAddressListPtr addrList = opaque;
    virPCIDeviceAddressPtr copyAddr;

    /* make a copy to insert onto the list */
    if (VIR_ALLOC(copyAddr) < 0)
        goto cleanup;

    *copyAddr = *newDevAddr;

    if (VIR_APPEND_ELEMENT(*addrList->iommuGroupDevices,
                           *addrList->nIommuGroupDevices, copyAddr) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    VIR_FREE(copyAddr);
    return ret;
}


/*
 * virPCIDeviceAddressGetIOMMUGroupAddresses - return a
 * virPCIDeviceList containing all of the devices in the same
 * iommu_group as @dev.
 *
 * Return the new list, or NULL on failure
 */
int
virPCIDeviceAddressGetIOMMUGroupAddresses(virPCIDeviceAddressPtr devAddr,
                                          virPCIDeviceAddressPtr **iommuGroupDevices,
                                          size_t *nIommuGroupDevices)
{
    int ret = -1;
    virPCIDeviceAddressList addrList = { iommuGroupDevices,
                                         nIommuGroupDevices };

    if (virPCIDeviceAddressIOMMUGroupIterate(devAddr,
                                             virPCIGetIOMMUGroupAddressesAddOne,
                                             &addrList) < 0)
        goto cleanup;

    ret = 0;
 cleanup:
    return ret;
}


/* virPCIDeviceAddressGetIOMMUGroupNum - return the group number of
 * this PCI device's iommu_group, or -2 if there is no iommu_group for
 * the device (or -1 if there was any other error)
 */
int
virPCIDeviceAddressGetIOMMUGroupNum(virPCIDeviceAddressPtr addr)
{
    VIR_AUTOFREE(char *) devName = NULL;
    VIR_AUTOFREE(char *) devPath = NULL;
    VIR_AUTOFREE(char *) groupPath = NULL;
    const char *groupNumStr;
    unsigned int groupNum;

    if (virAsprintf(&devName,
                    VIR_PCI_DEVICE_ADDRESS_FMT,
                    addr->domain, addr->bus, addr->slot, addr->function) < 0)
        return -1;

    if (!(devPath = virPCIFile(devName, "iommu_group")))
        return -1;
    if (virFileIsLink(devPath) != 1)
        return -2;
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %s iommu_group symlink %s"),
                       devName, devPath);
        return -1;
    }

    groupNumStr = last_component(groupPath);
    if (virStrToLong_ui(groupNumStr, NULL, 10, &groupNum) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device %s iommu_group symlink %s has "
                         "invalid group number %s"),
                       devName, groupPath, groupNumStr);
        return -1;
    }

    return groupNum;
}


/* virPCIDeviceGetIOMMUGroupDev - return the name of the device used
 * to control this PCI device's group (e.g. "/dev/vfio/15")
 */
char *
virPCIDeviceGetIOMMUGroupDev(virPCIDevicePtr dev)
{
    VIR_AUTOFREE(char *) devPath = NULL;
    VIR_AUTOFREE(char *) groupPath = NULL;
    char *groupDev = NULL;

    if (!(devPath = virPCIFile(dev->name, "iommu_group")))
        return NULL;
    if (virFileIsLink(devPath) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device %s iommu_group file %s is not a symlink"),
                       dev->name, devPath);
        return NULL;
    }
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %s iommu_group symlink %s"),
                       dev->name, devPath);
        return NULL;
    }
    if (virAsprintf(&groupDev, "/dev/vfio/%s",
                    last_component(groupPath)) < 0)
        return NULL;

    return groupDev;
}

static int
virPCIDeviceDownstreamLacksACS(virPCIDevicePtr dev)
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
virPCIDeviceIsBehindSwitchLackingACS(virPCIDevicePtr dev)
{
    VIR_AUTOPTR(virPCIDevice) parent = NULL;

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
        VIR_AUTOPTR(virPCIDevice) tmp = NULL;
        int acs;
        int ret;

        acs = virPCIDeviceDownstreamLacksACS(parent);

        if (acs) {
            if (acs < 0)
                return -1;
            else
                return 1;
        }

        tmp = parent;
        ret = virPCIDeviceGetParent(parent, &parent);
        if (ret < 0)
            return -1;
    } while (parent);

    return 0;
}

int virPCIDeviceIsAssignable(virPCIDevicePtr dev,
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
                           _("Device %s is behind a switch lacking ACS and "
                             "cannot be assigned"),
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
        VIR_ERROR(_("Failed to convert '%s' to unsigned int"), s);
    return ret;
}

int
virPCIDeviceAddressParse(char *address,
                         virPCIDeviceAddressPtr bdf)
{
    char *p = NULL;
    int ret = -1;

    if ((address == NULL) || (logStrToLong_ui(address, &p, 16,
                                              &bdf->domain) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->bus) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->slot) == -1)) {
        goto out;
    }

    if ((p == NULL) || (logStrToLong_ui(p+1, &p, 16,
                                        &bdf->function) == -1)) {
        goto out;
    }

    ret = 0;

 out:
    return ret;
}


bool
virZPCIDeviceAddressIsValid(virZPCIDeviceAddressPtr zpci)
{
    /* We don't need to check fid because fid covers
     * all range of uint32 type.
     */
    if (zpci->uid > VIR_DOMAIN_DEVICE_ZPCI_MAX_UID ||
        zpci->uid == 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Invalid PCI address uid='0x%.4x', "
                         "must be > 0x0000 and <= 0x%.4x"),
                       zpci->uid,
                       VIR_DOMAIN_DEVICE_ZPCI_MAX_UID);
        return false;
    }

    return true;
}

bool
virZPCIDeviceAddressIsEmpty(const virZPCIDeviceAddress *addr)
{
    return !(addr->uid || addr->fid);
}

#ifdef __linux__

virPCIDeviceAddressPtr
virPCIGetDeviceAddressFromSysfsLink(const char *device_link)
{
    virPCIDeviceAddressPtr bdf = NULL;
    char *config_address = NULL;
    VIR_AUTOFREE(char *) device_path = NULL;

    if (!virFileExists(device_link)) {
        VIR_DEBUG("'%s' does not exist", device_link);
        return NULL;
    }

    device_path = virFileCanonicalizePath(device_link);
    if (device_path == NULL) {
        virReportSystemError(errno,
                             _("Failed to resolve device link '%s'"),
                             device_link);
        return NULL;
    }

    config_address = last_component(device_path);
    if (VIR_ALLOC(bdf) < 0)
        return NULL;

    if (virPCIDeviceAddressParse(config_address, bdf) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse PCI config address '%s'"),
                       config_address);
        VIR_FREE(bdf);
        return NULL;
    }

    return bdf;
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
                          virPCIDeviceAddressPtr *pf)
{
    VIR_AUTOFREE(char *) device_link = NULL;

    *pf = NULL;

    if (virBuildPath(&device_link, vf_sysfs_path, "physfn") == -1) {
        virReportOOMError();
        return -1;
    }

    if ((*pf = virPCIGetDeviceAddressFromSysfsLink(device_link))) {
        VIR_DEBUG("PF for VF device '%s': " VIR_PCI_DEVICE_ADDRESS_FMT,
                  vf_sysfs_path,
                  (*pf)->domain, (*pf)->bus, (*pf)->slot, (*pf)->function);
    }

    return 0;
}


/*
 * Returns virtual functions of a physical function
 */
int
virPCIGetVirtualFunctions(const char *sysfs_path,
                          virPCIDeviceAddressPtr **virtual_functions,
                          size_t *num_virtual_functions,
                          unsigned int *max_virtual_functions)
{
    int ret = -1;
    size_t i;
    VIR_AUTOFREE(char *) totalvfs_file = NULL;
    VIR_AUTOFREE(char *) totalvfs_str = NULL;
    virPCIDeviceAddressPtr config_addr = NULL;

    *virtual_functions = NULL;
    *num_virtual_functions = 0;
    *max_virtual_functions = 0;

    if (virAsprintf(&totalvfs_file, "%s/sriov_totalvfs", sysfs_path) < 0)
       goto error;
    if (virFileExists(totalvfs_file)) {
        char *end = NULL; /* so that terminating \n doesn't create error */

        if (virFileReadAll(totalvfs_file, 16, &totalvfs_str) < 0)
            goto error;
        if (virStrToLong_ui(totalvfs_str, &end, 10, max_virtual_functions) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unrecognized value in %s: %s"),
                           totalvfs_file, totalvfs_str);
            goto error;
        }
    }

    do {
        VIR_AUTOFREE(char *) device_link = NULL;
        /* look for virtfn%d links until one isn't found */
        if (virAsprintf(&device_link, "%s/virtfn%zu", sysfs_path, *num_virtual_functions) < 0)
            goto error;

        if (!virFileExists(device_link))
            break;

        if (!(config_addr = virPCIGetDeviceAddressFromSysfsLink(device_link))) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get SRIOV function from device link '%s'"),
                           device_link);
            goto error;
        }

        if (VIR_APPEND_ELEMENT(*virtual_functions, *num_virtual_functions,
                               config_addr) < 0)
            goto error;
    } while (1);

    VIR_DEBUG("Found %zu virtual functions for %s",
              *num_virtual_functions, sysfs_path);
    ret = 0;
 cleanup:
    VIR_FREE(config_addr);
    return ret;

 error:
    for (i = 0; i < *num_virtual_functions; i++)
        VIR_FREE((*virtual_functions)[i]);
    VIR_FREE(*virtual_functions);
    *num_virtual_functions = 0;
    goto cleanup;
}


/*
 * Returns 1 if vf device is a virtual function, 0 if not, -1 on error
 */
int
virPCIIsVirtualFunction(const char *vf_sysfs_device_link)
{
    VIR_AUTOFREE(char *) vf_sysfs_physfn_link = NULL;

    if (virAsprintf(&vf_sysfs_physfn_link, "%s/physfn",
                    vf_sysfs_device_link) < 0)
        return -1;

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
    int ret = -1;
    size_t i;
    size_t num_virt_fns = 0;
    unsigned int max_virt_fns = 0;
    virPCIDeviceAddressPtr vf_bdf = NULL;
    virPCIDeviceAddressPtr *virt_fns = NULL;

    if (!(vf_bdf = virPCIGetDeviceAddressFromSysfsLink(vf_sysfs_device_link)))
        return ret;

    if (virPCIGetVirtualFunctions(pf_sysfs_device_link, &virt_fns,
                                  &num_virt_fns, &max_virt_fns) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error getting physical function's '%s' "
                         "virtual_functions"), pf_sysfs_device_link);
        goto out;
    }

    for (i = 0; i < num_virt_fns; i++) {
        if (virPCIDeviceAddressEqual(vf_bdf, virt_fns[i])) {
            *vf_index = i;
            ret = 0;
            break;
        }
    }

 out:

    /* free virtual functions */
    for (i = 0; i < num_virt_fns; i++)
        VIR_FREE(virt_fns[i]);

    VIR_FREE(virt_fns);
    VIR_FREE(vf_bdf);

    return ret;
}

/*
 * Returns a path to the PCI sysfs file given the BDF of the PCI function
 */

int
virPCIGetSysfsFile(char *virPCIDeviceName, char **pci_sysfs_device_link)
{
    if (virAsprintf(pci_sysfs_device_link, PCI_SYSFS "devices/%s",
                    virPCIDeviceName) < 0)
        return -1;
    return 0;
}

int
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr addr,
                                char **pci_sysfs_device_link)
{
    if (virAsprintf(pci_sysfs_device_link,
                    PCI_SYSFS "devices/" VIR_PCI_DEVICE_ADDRESS_FMT,
                    addr->domain, addr->bus,
                    addr->slot, addr->function) < 0)
        return -1;
    return 0;
}

/**
 * virPCIGetNetName:
 * @device_link_sysfs_path: sysfs path to the PCI device
 * @idx: used to choose which netdev when there are several
 *       (ignored if physPortID is set)
 * @physPortID: match this string in the netdev's phys_port_id
 *       (or NULL to ignore and use idx instead)
 * @netname: used to return the name of the netdev
 *       (set to NULL (but returns success) if there is no netdev)
 *
 * Returns 0 on success, -1 on error (error has been logged)
 */
int
virPCIGetNetName(const char *device_link_sysfs_path,
                 size_t idx,
                 char *physPortID,
                 char **netname)
{
    VIR_AUTOFREE(char *) pcidev_sysfs_net_path = NULL;
    VIR_AUTOFREE(char *) firstEntryName = NULL;
    VIR_AUTOFREE(char *) thisPhysPortID = NULL;
    int ret = -1;
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    size_t i = 0;

    *netname = NULL;

    if (virBuildPath(&pcidev_sysfs_net_path, device_link_sysfs_path,
                     "net") == -1) {
        virReportOOMError();
        return -1;
    }

    if (virDirOpenQuiet(&dir, pcidev_sysfs_net_path) < 0) {
        /* this *isn't* an error - caller needs to check for netname == NULL */
        ret = 0;
        goto cleanup;
    }

    while (virDirRead(dir, &entry, pcidev_sysfs_net_path) > 0) {
        /* if the caller sent a physPortID, compare it to the
         * physportID of this netdev. If not, look for entry[idx].
         */
        if (physPortID) {
            if (virNetDevGetPhysPortID(entry->d_name, &thisPhysPortID) < 0)
                goto cleanup;

            /* if this one doesn't match, keep looking */
            if (STRNEQ_NULLABLE(physPortID, thisPhysPortID)) {
                VIR_FREE(thisPhysPortID);
                /* save the first entry we find to use as a failsafe
                 * in case we don't match the phys_port_id. This is
                 * needed because some NIC drivers (e.g. i40e)
                 * implement phys_port_id for PFs, but not for VFs
                 */
                if (!firstEntryName &&
                    VIR_STRDUP(firstEntryName, entry->d_name) < 0) {
                    goto cleanup;
                }

                continue;
            }
        } else {
            if (i++ < idx)
                continue;
        }

        if (VIR_STRDUP(*netname, entry->d_name) < 0)
            goto cleanup;

        ret = 0;
        break;
    }

    if (ret < 0) {
        if (physPortID) {
            if (firstEntryName) {
                /* we didn't match the provided phys_port_id, but this
                 * is probably because phys_port_id isn't implemented
                 * for this NIC driver, so just return the first
                 * (probably only) netname we found.
                 */
                *netname = firstEntryName;
                firstEntryName = NULL;
                ret = 0;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Could not find network device with "
                                 "phys_port_id '%s' under PCI device at %s"),
                               physPortID, device_link_sysfs_path);
            }
        } else {
            ret = 0; /* no netdev at the given index is *not* an error */
        }
    }
 cleanup:
    VIR_DIR_CLOSE(dir);
    return ret;
}

int
virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path,
                             int pfNetDevIdx,
                             char **pfname,
                             int *vf_index)
{
    virPCIDeviceAddressPtr pf_config_address = NULL;
    VIR_AUTOFREE(char *) pf_sysfs_device_path = NULL;
    VIR_AUTOFREE(char *) vfname = NULL;
    VIR_AUTOFREE(char *) vfPhysPortID = NULL;
    int ret = -1;

    if (virPCIGetPhysicalFunction(vf_sysfs_device_path, &pf_config_address) < 0)
        goto cleanup;

    if (!pf_config_address)
        goto cleanup;

    if (virPCIDeviceAddressGetSysfsFile(pf_config_address,
                                        &pf_sysfs_device_path) < 0) {
        goto cleanup;
    }

    if (virPCIGetVirtualFunctionIndex(pf_sysfs_device_path,
                                      vf_sysfs_device_path, vf_index) < 0) {
        goto cleanup;
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
            goto cleanup;

        if (vfname) {
            if (virNetDevGetPhysPortID(vfname, &vfPhysPortID) < 0)
                goto cleanup;
        }
        pfNetDevIdx = 0;
    }

    if (virPCIGetNetName(pf_sysfs_device_path,
                         pfNetDevIdx, vfPhysPortID, pfname) < 0) {
        goto cleanup;
    }

    if (!*pfname) {
        /* this shouldn't be possible. A VF can't exist unless its
         * PF device is bound to a network driver
         */
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("The PF device for VF %s has no network device name"),
                       vf_sysfs_device_path);
        goto cleanup;
    }

    ret = 0;
 cleanup:
    VIR_FREE(pf_config_address);

    return ret;
}


ssize_t
virPCIGetMdevTypes(const char *sysfspath,
                   virMediatedDeviceTypePtr **types)
{
    ssize_t ret = -1;
    int dirret = -1;
    DIR *dir = NULL;
    struct dirent *entry;
    VIR_AUTOFREE(char *) types_path = NULL;
    VIR_AUTOPTR(virMediatedDeviceType) mdev_type = NULL;
    virMediatedDeviceTypePtr *mdev_types = NULL;
    size_t ntypes = 0;
    size_t i;

    if (virAsprintf(&types_path, "%s/mdev_supported_types", sysfspath) < 0)
        return -1;

    if ((dirret = virDirOpenIfExists(&dir, types_path)) < 0)
        goto cleanup;

    if (dirret == 0) {
        ret = 0;
        goto cleanup;
    }

    while ((dirret = virDirRead(dir, &entry, types_path)) > 0) {
        VIR_AUTOFREE(char *) tmppath = NULL;
        /* append the type id to the path and read the attributes from there */
        if (virAsprintf(&tmppath, "%s/%s", types_path, entry->d_name) < 0)
            goto cleanup;

        if (virMediatedDeviceTypeReadAttrs(tmppath, &mdev_type) < 0)
            goto cleanup;

        if (VIR_APPEND_ELEMENT(mdev_types, ntypes, mdev_type) < 0)
            goto cleanup;
    }

    if (dirret < 0)
        goto cleanup;

    VIR_STEAL_PTR(*types, mdev_types);
    ret = ntypes;
    ntypes = 0;
 cleanup:
    for (i = 0; i < ntypes; i++)
        virMediatedDeviceTypeFree(mdev_types[i]);
    VIR_FREE(mdev_types);
    VIR_DIR_CLOSE(dir);
    return ret;
}

#else
static const char *unsupported = N_("not supported on non-linux platforms");

virPCIDeviceAddressPtr
virPCIGetDeviceAddressFromSysfsLink(const char *device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return NULL;
}


int
virPCIGetPhysicalFunction(const char *vf_sysfs_path G_GNUC_UNUSED,
                          virPCIDeviceAddressPtr *pf G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctions(const char *sysfs_path G_GNUC_UNUSED,
                          virPCIDeviceAddressPtr **virtual_functions G_GNUC_UNUSED,
                          size_t *num_virtual_functions G_GNUC_UNUSED,
                          unsigned int *max_virtual_functions G_GNUC_UNUSED)
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
virPCIGetSysfsFile(char *virPCIDeviceName G_GNUC_UNUSED,
                   char **pci_sysfs_device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr dev G_GNUC_UNUSED,
                                char **pci_sysfs_device_link G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetNetName(const char *device_link_sysfs_path G_GNUC_UNUSED,
                 size_t idx G_GNUC_UNUSED,
                 char *physPortID G_GNUC_UNUSED,
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


ssize_t
virPCIGetMdevTypes(const char *sysfspath G_GNUC_UNUSED,
                   virMediatedDeviceTypePtr **types G_GNUC_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}
#endif /* __linux__ */

int
virPCIDeviceIsPCIExpress(virPCIDevicePtr dev)
{
    int fd;
    int ret = -1;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return ret;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    ret = dev->pcie_cap_pos != 0;

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}

int
virPCIDeviceHasPCIExpressLink(virPCIDevicePtr dev)
{
    int fd;
    int ret = -1;
    uint16_t cap, type;

    if ((fd = virPCIDeviceConfigOpen(dev)) < 0)
        return ret;

    if (virPCIDeviceInit(dev, fd) < 0)
        goto cleanup;

    cap = virPCIDeviceRead16(dev, fd, dev->pcie_cap_pos + PCI_CAP_FLAGS);
    type = (cap & PCI_EXP_FLAGS_TYPE) >> 4;

    ret = type != PCI_EXP_TYPE_ROOT_INT_EP && type != PCI_EXP_TYPE_ROOT_EC;

 cleanup:
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}

int
virPCIDeviceGetLinkCapSta(virPCIDevicePtr dev,
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
                       _("pci device %s is not a PCI-Express device"),
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


int virPCIGetHeaderType(virPCIDevicePtr dev, int *hdrType)
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
                       _("Unknown PCI header type '%d' for device '%s'"),
                       type, dev->name);
        return -1;
    }

    *hdrType = type;

    return 0;
}


void
virPCIEDeviceInfoFree(virPCIEDeviceInfoPtr dev)
{
    if (!dev)
        return;

    VIR_FREE(dev->link_cap);
    VIR_FREE(dev->link_sta);
    VIR_FREE(dev);
}

void
virPCIDeviceAddressFree(virPCIDeviceAddressPtr address)
{
    VIR_FREE(address);
}
