/*
 * virpci.c: helper APIs for managing host PCI devices
 *
 * Copyright (C) 2009-2013 Red Hat, Inc.
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
 * Authors:
 *     Mark McLoughlin <markmc@redhat.com>
 */

#include <config.h>

#include "virpci.h"

#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include "dirname.h"
#include "virlog.h"
#include "viralloc.h"
#include "vircommand.h"
#include "virerror.h"
#include "virfile.h"
#include "virkmod.h"
#include "virstring.h"
#include "virutil.h"

VIR_LOG_INIT("util.pci");

#define PCI_SYSFS "/sys/bus/pci/"
#define PCI_ID_LEN 10   /* "XXXX XXXX" */
#define PCI_ADDR_LEN 13 /* "XXXX:XX:XX.X" */

struct _virPCIDevice {
    unsigned int  domain;
    unsigned int  bus;
    unsigned int  slot;
    unsigned int  function;

    char          name[PCI_ADDR_LEN]; /* domain:bus:slot.function */
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
    char          *stubDriver;

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

/* PM12 3.2.1  Capability Identifier */
#define PCI_CAP_ID_PM           0x01    /* Power Management */
/* PCI30 H Capability IDs */
#define PCI_CAP_ID_EXP          0x10    /* PCI Express */
/* ECN_AF 6.x.1.1  Capability ID for AF */
#define PCI_CAP_ID_AF           0x13    /* Advanced Features */

/* PCIe20 7.8.3  Device Capabilities Register (Offset 04h) */
#define PCI_EXP_DEVCAP          0x4     /* Device capabilities */
#define PCI_EXP_DEVCAP_FLR     (1<<28) /* Function Level Reset */

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
#define PCI_EXT_CAP_ACS_ENABLED (PCI_EXT_CAP_ACS_SV |   \
                                 PCI_EXT_CAP_ACS_RR |   \
                                 PCI_EXT_CAP_ACS_CR |   \
                                 PCI_EXT_CAP_ACS_UF)

static virClassPtr virPCIDeviceListClass;

static void virPCIDeviceListDispose(void *obj);

static int virPCIOnceInit(void)
{
    if (!(virPCIDeviceListClass = virClassNew(virClassForObjectLockable(),
                                              "virPCIDeviceList",
                                              sizeof(virPCIDeviceList),
                                              virPCIDeviceListDispose)))
        return -1;

    return 0;
}

VIR_ONCE_GLOBAL_INIT(virPCI)


static int
virPCIDriverDir(char **buffer, const char *driver)
{
    VIR_FREE(*buffer);

    if (virAsprintf(buffer, PCI_SYSFS "drivers/%s", driver) < 0)
        return -1;
    return 0;
}


static int
virPCIDriverFile(char **buffer, const char *driver, const char *file)
{
    VIR_FREE(*buffer);

    if (virAsprintf(buffer, PCI_SYSFS "drivers/%s/%s", driver, file) < 0)
        return -1;
    return 0;
}


static int
virPCIFile(char **buffer, const char *device, const char *file)
{
    VIR_FREE(*buffer);

    if (virAsprintf(buffer, PCI_SYSFS "devices/%s/%s", device, file) < 0)
        return -1;
    return 0;
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
    char *drvlink = NULL;

    *path = *name = NULL;
    /* drvlink = "/sys/bus/pci/dddd:bb:ss.ff/driver" */
    if (virPCIFile(&drvlink, dev->name, "driver") < 0)
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
    VIR_FREE(drvlink);
    if (ret < 0) {
        VIR_FREE(*path);
        VIR_FREE(*name);
    }
    return ret;
}


static int
virPCIDeviceConfigOpen(virPCIDevicePtr dev, bool fatal)
{
    int fd;

    fd = open(dev->path, O_RDWR);

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
    char *path = NULL;
    char *id_str = NULL;
    int ret = -1;
    unsigned int value;

    if (virPCIFile(&path, dev->name, "class") < 0)
        return ret;

    /* class string is '0xNNNNNN\n' ... i.e. 9 bytes */
    if (virFileReadAll(path, 9, &id_str) < 0)
        goto cleanup;

    id_str[8] = '\0';
    if (virStrToLong_ui(id_str, NULL, 16, &value) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unusual value in %s/devices/%s/class: %s"),
                       PCI_SYSFS, dev->name, id_str);
        goto cleanup;
    }

    *device_class = (value >> 8) & 0xFFFF;
    ret = 0;
 cleanup:
    VIR_FREE(id_str);
    VIR_FREE(path);
    return ret;
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

    dir = opendir(PCI_SYSFS "devices");
    if (!dir) {
        VIR_WARN("Failed to open " PCI_SYSFS "devices");
        return -1;
    }

    while ((entry = readdir(dir))) {
        unsigned int domain, bus, slot, function;
        virPCIDevicePtr check;
        char *tmp;

        /* Ignore '.' and '..' */
        if (entry->d_name[0] == '.')
            continue;

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
            virPCIDeviceFree(check);
            ret = -1;
            break;
        }
        else if (rc == 1) {
            VIR_DEBUG("%s %s: iter matched on %s", dev->id, dev->name, check->name);
            *matched = check;
            ret = 1;
            break;
        }

        virPCIDeviceFree(check);
    }
    closedir(dir);
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
    char *path;
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
    VIR_FREE(path);
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
    if (dev->domain != check->domain ||
        dev->bus != check->bus ||
        (dev->slot == check->slot &&
         dev->function == check->function))
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

    if (dev->domain != check->domain)
        return 0;

    if ((fd = virPCIDeviceConfigOpen(check, false)) < 0)
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
    if (dev->bus == secondary) {
        ret = 1;
        goto cleanup;
    }

    /* otherwise, SRIOV allows VFs to be on different buses than their PFs.
     * In this case, what we need to do is look for the "best" match; i.e.
     * the most restrictive match that still satisfies all of the conditions.
     */
    if (dev->bus > secondary && dev->bus <= subordinate) {
        if (*best == NULL) {
            *best = virPCIDeviceNew(check->domain, check->bus, check->slot,
                                    check->function);
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

            if ((bestfd = virPCIDeviceConfigOpen(*best, false)) < 0)
                goto cleanup;
            best_secondary = virPCIDeviceRead8(*best, bestfd, PCI_SECONDARY_BUS);
            virPCIDeviceConfigClose(*best, bestfd);

            if (secondary > best_secondary) {
                virPCIDeviceFree(*best);
                *best = virPCIDeviceNew(check->domain, check->bus, check->slot,
                                        check->function);
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
    virPCIDevicePtr parent, conflict;
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
    if ((parentfd = virPCIDeviceConfigOpen(parent, true)) < 0)
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
    ctl = virPCIDeviceRead16(dev, cfgfd, PCI_BRIDGE_CONTROL);

    virPCIDeviceWrite16(parent, parentfd, PCI_BRIDGE_CONTROL,
                        ctl | PCI_BRIDGE_CTL_RESET);

    usleep(200 * 1000); /* sleep 200ms */

    virPCIDeviceWrite16(parent, parentfd, PCI_BRIDGE_CONTROL, ctl);

    usleep(200 * 1000); /* sleep 200ms */

    if (virPCIDeviceWrite(dev, cfgfd, 0, config_space, PCI_CONF_LEN) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to restore PCI config space for %s"),
                       dev->name);
        goto out;
    }
    ret = 0;

 out:
    virPCIDeviceConfigClose(parent, parentfd);
    virPCIDeviceFree(parent);
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

    usleep(10 * 1000); /* sleep 10ms */

    virPCIDeviceWrite32(dev, cfgfd, dev->pci_pm_cap_pos + PCI_PM_CTRL,
                        ctl | PCI_PM_CTRL_STATE_D0);

    usleep(10 * 1000); /* sleep 10ms */

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
    char *drvPath = NULL;
    char *drvName = NULL;
    int ret = -1;
    int fd = -1;

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

    if (STREQ_NULLABLE(drvName, "vfio-pci")) {
        VIR_DEBUG("Device %s is bound to vfio-pci - skip reset",
                  dev->name);
        ret = 0;
        goto cleanup;
    }
    VIR_DEBUG("Resetting device %s", dev->name);

    if ((fd = virPCIDeviceConfigOpen(dev, true)) < 0)
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
    if (ret < 0 && dev->bus != 0)
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
    VIR_FREE(drvPath);
    VIR_FREE(drvName);
    virPCIDeviceConfigClose(dev, fd);
    return ret;
}


static int
virPCIProbeStubDriver(const char *driver)
{
    char *drvpath = NULL;
    bool probed = false;

 recheck:
    if (virPCIDriverDir(&drvpath, driver) == 0 && virFileExists(drvpath)) {
        /* driver already loaded, return */
        VIR_FREE(drvpath);
        return 0;
    }

    VIR_FREE(drvpath);

    if (!probed) {
        char *errbuf = NULL;
        probed = true;
        if ((errbuf = virKModLoad(driver, true))) {
            VIR_WARN("failed to load driver %s: %s", driver, errbuf);
            VIR_FREE(errbuf);
            goto cleanup;
        }

        goto recheck;
    }

 cleanup:
    /* If we know failure was because of blacklist, let's report that;
     * otherwise, report a more generic failure message
     */
    if (virKModIsBlacklisted(driver)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI stub module %s: "
                         "administratively prohibited"),
                       driver);
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to load PCI stub module %s"),
                       driver);
    }

    return -1;
}

int
virPCIDeviceUnbind(virPCIDevicePtr dev, bool reprobe)
{
    char *path = NULL;
    char *drvpath = NULL;
    char *driver = NULL;
    int ret = -1;

    if (virPCIDeviceGetDriverPathAndName(dev, &drvpath, &driver) < 0)
        goto cleanup;

    if (!driver) {
        /* The device is not bound to any driver */
        ret = 0;
        goto cleanup;
    }

    if (virPCIFile(&path, dev->name, "driver/unbind") < 0)
        goto cleanup;

    if (virFileExists(path)) {
        if (virFileWriteStr(path, dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to unbind PCI device '%s' from %s"),
                                 dev->name, driver);
            goto cleanup;
        }
        dev->reprobe = reprobe;
    }

    ret = 0;
 cleanup:
    VIR_FREE(path);
    VIR_FREE(drvpath);
    VIR_FREE(driver);
    return ret;
}

static const char *virPCIKnownStubs[] = {
    "pciback",  /* used by xen */
    "pci-stub", /* used by kvm legacy passthrough */
    "vfio-pci", /* used by VFIO device assignment */
    NULL
};

static int
virPCIDeviceUnbindFromStub(virPCIDevicePtr dev)
{
    int result = -1;
    char *drvdir = NULL;
    char *path = NULL;
    char *driver = NULL;
    const char **stubTest;
    bool isStub = false;

    /* If the device is currently bound to one of the "well known"
     * stub drivers, then unbind it, otherwise ignore it.
     */
    if (virPCIDeviceGetDriverPathAndName(dev, &drvdir, &driver) < 0)
        goto cleanup;

    if (!driver) {
        /* The device is not bound to any driver and we are almost done. */
        goto reprobe;
    }

    if (!dev->unbind_from_stub)
        goto remove_slot;

    /* If the device isn't bound to a known stub, skip the unbind. */
    for (stubTest = virPCIKnownStubs; *stubTest != NULL; stubTest++) {
        if (STREQ(driver, *stubTest)) {
            isStub = true;
            VIR_DEBUG("Found stub driver %s", *stubTest);
            break;
        }
    }
    if (!isStub)
        goto remove_slot;

    if (virPCIDeviceUnbind(dev, dev->reprobe) < 0)
        goto cleanup;
    dev->unbind_from_stub = false;

 remove_slot:
    if (!dev->remove_slot)
        goto reprobe;

    /* Xen's pciback.ko wants you to use remove_slot on the specific device */
    if (virPCIDriverFile(&path, driver, "remove_slot") < 0) {
        goto cleanup;
    }

    if (virFileExists(path) && virFileWriteStr(path, dev->name, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to remove slot for PCI device '%s' from %s"),
                             dev->name, driver);
        goto cleanup;
    }
    dev->remove_slot = false;

 reprobe:
    if (!dev->reprobe) {
        result = 0;
        goto cleanup;
    }

    /* Trigger a re-probe of the device is not in the stub's dynamic
     * ID table. If the stub is available, but 'remove_id' isn't
     * available, then re-probing would just cause the device to be
     * re-bound to the stub.
     */
    if (driver && virPCIDriverFile(&path, driver, "remove_id") < 0)
        goto cleanup;

    if (!driver || !virFileExists(drvdir) || virFileExists(path)) {
        if (virFileWriteStr(PCI_SYSFS "drivers_probe", dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to trigger a re-probe for PCI device '%s'"),
                                 dev->name);
            goto cleanup;
        }
    }

    result = 0;

 cleanup:
    /* do not do it again */
    dev->unbind_from_stub = false;
    dev->remove_slot = false;
    dev->reprobe = false;

    VIR_FREE(drvdir);
    VIR_FREE(path);
    VIR_FREE(driver);

    return result;
}


static int
virPCIDeviceBindToStub(virPCIDevicePtr dev,
                       const char *stubDriverName)
{
    int result = -1;
    int reprobe = false;
    char *stubDriverPath = NULL;
    char *driverLink = NULL;
    char *path = NULL; /* reused for different purposes */
    char *newDriverName = NULL;
    virErrorPtr err = NULL;

    if (virPCIDriverDir(&stubDriverPath, stubDriverName) < 0 ||
        virPCIFile(&driverLink, dev->name, "driver") < 0 ||
        VIR_STRDUP(newDriverName, stubDriverName) < 0)
        goto cleanup;

    if (virFileExists(driverLink)) {
        if (virFileLinkPointsTo(driverLink, stubDriverPath)) {
            /* The device is already bound to the correct driver */
            VIR_DEBUG("Device %s is already bound to %s",
                      dev->name, stubDriverName);
            result = 0;
            goto cleanup;
        }
        reprobe = true;
    }

    /* Add the PCI device ID to the stub's dynamic ID table;
     * this is needed to allow us to bind the device to the stub.
     * Note: if the device is not currently bound to any driver,
     * stub will immediately be bound to the device. Also, note
     * that if a new device with this ID is hotplugged, or if a probe
     * is triggered for such a device, it will also be immediately
     * bound by the stub.
     */
    if (virPCIDriverFile(&path, stubDriverName, "new_id") < 0) {
        goto cleanup;
    }

    if (virFileWriteStr(path, dev->id, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to add PCI device ID '%s' to %s"),
                             dev->id, stubDriverName);
        goto cleanup;
    }

    /* check whether the device is bound to pci-stub when we write dev->id to
     * ${stubDriver}/new_id.
     */
    if (virFileLinkPointsTo(driverLink, stubDriverPath)) {
        dev->unbind_from_stub = true;
        dev->remove_slot = true;
        result = 0;
        goto remove_id;
    }

    if (virPCIDeviceUnbind(dev, reprobe) < 0)
        goto remove_id;

    /* If the device isn't already bound to pci-stub, try binding it now.
     */
    if (!virFileLinkPointsTo(driverLink, stubDriverPath)) {
        /* Xen's pciback.ko wants you to use new_slot first */
        if (virPCIDriverFile(&path, stubDriverName, "new_slot") < 0) {
            goto remove_id;
        }

        if (virFileExists(path) && virFileWriteStr(path, dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to add slot for "
                                   "PCI device '%s' to %s"),
                                 dev->name, stubDriverName);
            goto remove_id;
        }
        dev->remove_slot = true;

        if (virPCIDriverFile(&path, stubDriverName, "bind") < 0) {
            goto remove_id;
        }

        if (virFileWriteStr(path, dev->name, 0) < 0) {
            virReportSystemError(errno,
                                 _("Failed to bind PCI device '%s' to %s"),
                                 dev->name, stubDriverName);
            goto remove_id;
        }
        dev->unbind_from_stub = true;
    }

    result = 0;

 remove_id:
    err = virSaveLastError();

    /* If 'remove_id' exists, remove the device id from pci-stub's dynamic
     * ID table so that 'drivers_probe' works below.
     */
    if (virPCIDriverFile(&path, stubDriverName, "remove_id") < 0) {
        /* We do not remove PCI ID from pci-stub, and we cannot reprobe it */
        if (dev->reprobe) {
            VIR_WARN("Could not remove PCI ID '%s' from %s, and the device "
                     "cannot be probed again.", dev->id, stubDriverName);
        }
        dev->reprobe = false;
        result = -1;
        goto cleanup;
    }

    if (virFileExists(path) && virFileWriteStr(path, dev->id, 0) < 0) {
        virReportSystemError(errno,
                             _("Failed to remove PCI ID '%s' from %s"),
                             dev->id, stubDriverName);

        /* remove PCI ID from pci-stub failed, and we cannot reprobe it */
        if (dev->reprobe) {
            VIR_WARN("Failed to remove PCI ID '%s' from %s, and the device "
                     "cannot be probed again.", dev->id, stubDriverName);
        }
        dev->reprobe = false;
        result = -1;
        goto cleanup;
    }

 cleanup:
    VIR_FREE(stubDriverPath);
    VIR_FREE(driverLink);
    VIR_FREE(path);

    if (result < 0) {
        VIR_FREE(newDriverName);
        virPCIDeviceUnbindFromStub(dev);
    } else {
        VIR_FREE(dev->stubDriver);
        dev->stubDriver = newDriverName;
    }

    if (err)
        virSetError(err);
    virFreeError(err);

    return result;
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
    sa_assert(dev->stubDriver);

    if (virPCIProbeStubDriver(dev->stubDriver) < 0)
        return -1;

    if (activeDevs && virPCIDeviceListFind(activeDevs, dev)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Not detaching active device %s"), dev->name);
        return -1;
    }

    if (virPCIDeviceBindToStub(dev, dev->stubDriver) < 0)
        return -1;

    /* Add *a copy of* the dev into list inactiveDevs, if
     * it's not already there.
     */
    if (inactiveDevs && !virPCIDeviceListFind(inactiveDevs, dev) &&
        virPCIDeviceListAddCopy(inactiveDevs, dev) < 0) {
        return -1;
    }

    return 0;
}

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
    if (inactiveDevs)
        virPCIDeviceListDel(inactiveDevs, dev);

    return 0;
}

/* Certain hypervisors (like qemu/kvm) map the PCI bar(s) on
 * the host when doing device passthrough.  This can lead to a race
 * condition where the hypervisor is still cleaning up the device while
 * libvirt is trying to re-attach it to the host device driver.  To avoid
 * this situation, we look through /proc/iomem, and if the hypervisor is
 * still holding on to the bar (denoted by the string in the matcher
 * variable), then we can wait around a bit for that to clear up.
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
 * holding on to the resource.
 */
int
virPCIDeviceWaitForCleanup(virPCIDevicePtr dev, const char *matcher)
{
    FILE *fp;
    char line[160];
    char *tmp;
    unsigned long long start, end;
    unsigned int domain, bus, slot, function;
    bool in_matching_device;
    int ret;
    size_t match_depth;

    fp = fopen("/proc/iomem", "r");
    if (!fp) {
        /* If we failed to open iomem, we just basically ignore the error.  The
         * unbind might succeed anyway, and besides, it's very likely we have
         * no way to report the error
         */
        VIR_DEBUG("Failed to open /proc/iomem, trying to continue anyway");
        return 0;
    }

    ret = 0;
    in_matching_device = false;
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
            /* expected format: <start>-<end> : <suffix> */
            if (/* start */
                virStrToLong_ull(line, &tmp, 16, &start) < 0 || *tmp != '-' ||
                /* end */
                virStrToLong_ull(tmp + 1, &tmp, 16, &end) < 0 ||
                (tmp = STRSKIP(tmp, " : ")) == NULL)
                continue;

            if (STRPREFIX(tmp, matcher)) {
                ret = 1;
                break;
            }
        }
        else {
            in_matching_device = false;

            /* expected format: <start>-<end> : <domain>:<bus>:<slot>.<function> */
            if (/* start */
                virStrToLong_ull(line, &tmp, 16, &start) < 0 || *tmp != '-' ||
                /* end */
                virStrToLong_ull(tmp + 1, &tmp, 16, &end) < 0 ||
                (tmp = STRSKIP(tmp, " : ")) == NULL ||
                /* domain */
                virStrToLong_ui(tmp, &tmp, 16, &domain) < 0 || *tmp != ':' ||
                /* bus */
                virStrToLong_ui(tmp + 1, &tmp, 16, &bus) < 0 || *tmp != ':' ||
                /* slot */
                virStrToLong_ui(tmp + 1, &tmp, 16, &slot) < 0 || *tmp != '.' ||
                /* function */
                virStrToLong_ui(tmp + 1, &tmp, 16, &function) < 0 || *tmp != '\n')
                continue;

            if (domain != dev->domain || bus != dev->bus || slot != dev->slot ||
                function != dev->function)
                continue;
            in_matching_device = true;
            match_depth = strspn(line, " ");
        }
    }

    VIR_FORCE_FCLOSE(fp);

    return ret;
}

static char *
virPCIDeviceReadID(virPCIDevicePtr dev, const char *id_name)
{
    char *path = NULL;
    char *id_str;

    if (virPCIFile(&path, dev->name, id_name) < 0) {
        return NULL;
    }

    /* ID string is '0xNNNN\n' ... i.e. 7 bytes */
    if (virFileReadAll(path, 7, &id_str) < 0) {
        VIR_FREE(path);
        return NULL;
    }

    VIR_FREE(path);

    /* Check for 0x suffix */
    if (id_str[0] != '0' || id_str[1] != 'x') {
        VIR_FREE(id_str);
        return NULL;
    }

    /* Chop off the newline; we know the string is 7 bytes */
    id_str[6] = '\0';

    return id_str;
}

int
virPCIGetAddrString(unsigned int domain,
                    unsigned int bus,
                    unsigned int slot,
                    unsigned int function,
                    char **pciConfigAddr)
{
    virPCIDevicePtr dev = NULL;
    int ret = -1;

    dev = virPCIDeviceNew(domain, bus, slot, function);
    if (dev != NULL) {
        if (VIR_STRDUP(*pciConfigAddr, dev->name) < 0)
            goto cleanup;
        ret = 0;
    }

 cleanup:
    virPCIDeviceFree(dev);
    return ret;
}

virPCIDevicePtr
virPCIDeviceNew(unsigned int domain,
                unsigned int bus,
                unsigned int slot,
                unsigned int function)
{
    virPCIDevicePtr dev;
    char *vendor = NULL;
    char *product = NULL;

    if (VIR_ALLOC(dev) < 0)
        return NULL;

    dev->domain   = domain;
    dev->bus      = bus;
    dev->slot     = slot;
    dev->function = function;

    if (snprintf(dev->name, sizeof(dev->name), "%.4x:%.2x:%.2x.%.1x",
                 dev->domain, dev->bus, dev->slot,
                 dev->function) >= sizeof(dev->name)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->name buffer overflow: %.4x:%.2x:%.2x.%.1x"),
                       dev->domain, dev->bus, dev->slot, dev->function);
        goto error;
    }
    if (virAsprintf(&dev->path, PCI_SYSFS "devices/%s/config",
                    dev->name) < 0)
        goto error;

    if (!virFileExists(dev->path)) {
        virReportSystemError(errno,
                             _("Device %s not found: could not access %s"),
                             dev->name, dev->path);
        goto error;
    }

    vendor  = virPCIDeviceReadID(dev, "vendor");
    product = virPCIDeviceReadID(dev, "device");

    if (!vendor || !product) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to read product/vendor ID for %s"),
                       dev->name);
        goto error;
    }

    /* strings contain '0x' prefix */
    if (snprintf(dev->id, sizeof(dev->id), "%s %s", &vendor[2],
                 &product[2]) >= sizeof(dev->id)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("dev->id buffer overflow: %s %s"),
                       &vendor[2], &product[2]);
        goto error;
    }

    VIR_DEBUG("%s %s: initialized", dev->id, dev->name);

 cleanup:
    VIR_FREE(product);
    VIR_FREE(vendor);
    return dev;

 error:
    virPCIDeviceFree(dev);
    dev = NULL;
    goto cleanup;
}


virPCIDevicePtr
virPCIDeviceCopy(virPCIDevicePtr dev)
{
    virPCIDevicePtr copy;

    if (VIR_ALLOC(copy) < 0)
        return NULL;

    /* shallow copy to take care of most attributes */
    *copy = *dev;
    copy->path = copy->stubDriver = NULL;
    copy->used_by_drvname = copy->used_by_domname = NULL;
    if (VIR_STRDUP(copy->path, dev->path) < 0 ||
        VIR_STRDUP(copy->stubDriver, dev->stubDriver) < 0 ||
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
    VIR_FREE(dev->path);
    VIR_FREE(dev->stubDriver);
    VIR_FREE(dev->used_by_drvname);
    VIR_FREE(dev->used_by_domname);
    VIR_FREE(dev);
}

const char *
virPCIDeviceGetName(virPCIDevicePtr dev)
{
    return dev->name;
}

void virPCIDeviceSetManaged(virPCIDevicePtr dev, bool managed)
{
    dev->managed = managed;
}

unsigned int
virPCIDeviceGetManaged(virPCIDevicePtr dev)
{
    return dev->managed;
}

int
virPCIDeviceSetStubDriver(virPCIDevicePtr dev, const char *driver)
{
    VIR_FREE(dev->stubDriver);
    return VIR_STRDUP(dev->stubDriver, driver);
}

const char *
virPCIDeviceGetStubDriver(virPCIDevicePtr dev)
{
    return dev->stubDriver;
}

unsigned int
virPCIDeviceGetUnbindFromStub(virPCIDevicePtr dev)
{
    return dev->unbind_from_stub;
}

void
virPCIDeviceSetUnbindFromStub(virPCIDevicePtr dev, bool unbind)
{
    dev->unbind_from_stub = unbind;
}

unsigned int
virPCIDeviceGetRemoveSlot(virPCIDevicePtr dev)
{
    return dev->remove_slot;
}

void
virPCIDeviceSetRemoveSlot(virPCIDevicePtr dev, bool remove_slot)
{
    dev->remove_slot = remove_slot;
}

unsigned int
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

void virPCIDeviceReattachInit(virPCIDevicePtr pci)
{
    pci->unbind_from_stub = true;
    pci->remove_slot = true;
    pci->reprobe = true;
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
    virPCIDevicePtr copy = virPCIDeviceCopy(dev);

    if (!copy)
        return -1;
    if (virPCIDeviceListAdd(list, copy) < 0) {
        virPCIDeviceFree(copy);
        return -1;
    }
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
    virPCIDevicePtr ret = virPCIDeviceListSteal(list, dev);
    virPCIDeviceFree(ret);
}

int
virPCIDeviceListFindIndex(virPCIDeviceListPtr list, virPCIDevicePtr dev)
{
    size_t i;

    for (i = 0; i < list->count; i++)
        if (list->devs[i]->domain   == dev->domain &&
            list->devs[i]->bus      == dev->bus    &&
            list->devs[i]->slot     == dev->slot   &&
            list->devs[i]->function == dev->function)
            return i;
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
        if (list->devs[i]->domain == domain &&
            list->devs[i]->bus == bus &&
            list->devs[i]->slot == slot &&
            list->devs[i]->function == function)
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
    char *pcidir = NULL;
    char *file = NULL;
    DIR *dir = NULL;
    int ret = -1;
    struct dirent *ent;

    if (virAsprintf(&pcidir, "/sys/bus/pci/devices/%04x:%02x:%02x.%x",
                    dev->domain, dev->bus, dev->slot, dev->function) < 0)
        goto cleanup;

    if (!(dir = opendir(pcidir))) {
        virReportSystemError(errno,
                             _("cannot open %s"), pcidir);
        goto cleanup;
    }

    while ((ent = readdir(dir)) != NULL) {
        /* Device assignment requires:
         *   $PCIDIR/config, $PCIDIR/resource, $PCIDIR/resourceNNN,
         *   $PCIDIR/rom, $PCIDIR/reset
         */
        if (STREQ(ent->d_name, "config") ||
            STRPREFIX(ent->d_name, "resource") ||
            STREQ(ent->d_name, "rom") ||
            STREQ(ent->d_name, "reset")) {
            if (virAsprintf(&file, "%s/%s", pcidir, ent->d_name) < 0)
                goto cleanup;
            if ((actor)(dev, file, opaque) < 0)
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
    char *groupPath = NULL;
    DIR *groupDir = NULL;
    int ret = -1;
    struct dirent *ent;

    if (virAsprintf(&groupPath,
                    PCI_SYSFS "devices/%04x:%02x:%02x.%x/iommu_group/devices",
                    orig->domain, orig->bus, orig->slot, orig->function) < 0)
        goto cleanup;

    if (!(groupDir = opendir(groupPath))) {
        /* just process the original device, nothing more */
        ret = (actor)(orig, opaque);
        goto cleanup;
    }

    while ((errno = 0, ent = readdir(groupDir)) != NULL) {
        virPCIDeviceAddress newDev;

        if (ent->d_name[0] == '.')
            continue;

        if (virPCIDeviceAddressParse(ent->d_name, &newDev) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Found invalid device link '%s' in '%s'"),
                           ent->d_name, groupPath);
            goto cleanup;
        }

        if ((actor)(&newDev, opaque) < 0)
            goto cleanup;
    }
    if (errno != 0) {
        virReportSystemError(errno,
                             _("Failed to read directory entry for %s"),
                             groupPath);
        goto cleanup;
    }

    ret = 0;

 cleanup:
    VIR_FREE(groupPath);
    if (groupDir)
        closedir(groupDir);
    return ret;
}


static int
virPCIDeviceGetIOMMUGroupAddOne(virPCIDeviceAddressPtr newDevAddr, void *opaque)
{
    int ret = -1;
    virPCIDeviceListPtr groupList = opaque;
    virPCIDevicePtr newDev;

    if (!(newDev = virPCIDeviceNew(newDevAddr->domain, newDevAddr->bus,
                                   newDevAddr->slot, newDevAddr->function)))
        goto cleanup;

    if (virPCIDeviceListAdd(groupList, newDev) < 0)
        goto cleanup;

    newDev = NULL; /* it's now on the list */
    ret = 0;
 cleanup:
    virPCIDeviceFree(newDev);
    return ret;
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
    virPCIDeviceAddress devAddr = { dev->domain, dev->bus,
                                    dev->slot, dev->function };

    if (!groupList)
        goto error;

    if (virPCIDeviceAddressIOMMUGroupIterate(&devAddr,
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
    char *devName = NULL;
    char *devPath = NULL;
    char *groupPath = NULL;
    const char *groupNumStr;
    unsigned int groupNum;
    int ret = -1;

    if (virAsprintf(&devName, "%.4x:%.2x:%.2x.%.1x", addr->domain,
                    addr->bus, addr->slot, addr->function) < 0)
        goto cleanup;

    if (virPCIFile(&devPath, devName, "iommu_group") < 0)
        goto cleanup;
    if (virFileIsLink(devPath) != 1) {
        ret = -2;
        goto cleanup;
    }
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %s iommu_group symlink %s"),
                       devName, devPath);
        goto cleanup;
    }

    groupNumStr = last_component(groupPath);
    if (virStrToLong_ui(groupNumStr, NULL, 10, &groupNum) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("device %s iommu_group symlink %s has "
                         "invalid group number %s"),
                       devName, groupPath, groupNumStr);
        ret = -1;
        goto cleanup;
    }

    ret = groupNum;
 cleanup:
    VIR_FREE(devName);
    VIR_FREE(devPath);
    VIR_FREE(groupPath);
    return ret;
}


/* virPCIDeviceGetIOMMUGroupDev - return the name of the device used
 * to control this PCI device's group (e.g. "/dev/vfio/15")
 */
char *
virPCIDeviceGetIOMMUGroupDev(virPCIDevicePtr dev)
{
    char *devPath = NULL;
    char *groupPath = NULL;
    char *groupDev = NULL;

    if (virPCIFile(&devPath, dev->name, "iommu_group") < 0)
        goto cleanup;
    if (virFileIsLink(devPath) != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid device %s iommu_group file %s is not a symlink"),
                       dev->name, devPath);
        goto cleanup;
    }
    if (virFileResolveLink(devPath, &groupPath) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Unable to resolve device %s iommu_group symlink %s"),
                       dev->name, devPath);
        goto cleanup;
    }
    if (virAsprintf(&groupDev, "/dev/vfio/%s",
                    last_component(groupPath)) < 0)
        goto cleanup;
 cleanup:
    VIR_FREE(devPath);
    VIR_FREE(groupPath);
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

    if ((fd = virPCIDeviceConfigOpen(dev, true)) < 0)
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
    virPCIDevicePtr parent;

    if (virPCIDeviceGetParent(dev, &parent) < 0)
        return -1;
    if (!parent) {
        /* if we have no parent, and this is the root bus, ACS doesn't come
         * into play since devices on the root bus can't P2P without going
         * through the root IOMMU.
         */
        if (dev->bus == 0)
            return 0;
        else {
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
        virPCIDevicePtr tmp;
        int acs;
        int ret;

        acs = virPCIDeviceDownstreamLacksACS(parent);

        if (acs) {
            virPCIDeviceFree(parent);
            if (acs < 0)
                return -1;
            else
                return 1;
        }

        tmp = parent;
        ret = virPCIDeviceGetParent(parent, &parent);
        virPCIDeviceFree(tmp);
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
    if (ret != 0) {
        VIR_ERROR(_("Failed to convert '%s' to unsigned int"), s);
    } else {
        VIR_DEBUG("Converted '%s' to unsigned int %u", s, *result);
    }

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

#ifdef __linux__

/*
 * returns true if equal
 */
static bool
virPCIDeviceAddressIsEqual(virPCIDeviceAddressPtr bdf1,
                           virPCIDeviceAddressPtr bdf2)
{
    return ((bdf1->domain == bdf2->domain) &&
            (bdf1->bus == bdf2->bus) &&
            (bdf1->slot == bdf2->slot) &&
            (bdf1->function == bdf2->function));
}

static int
virPCIGetDeviceAddressFromSysfsLink(const char *device_link,
                                    virPCIDeviceAddressPtr *bdf)
{
    char *config_address = NULL;
    char *device_path = NULL;
    char errbuf[64];
    int ret = -1;

    VIR_DEBUG("Attempting to resolve device path from device link '%s'",
              device_link);

    if (!virFileExists(device_link)) {
        VIR_DEBUG("sysfs_path '%s' does not exist", device_link);
        return ret;
    }

    device_path = canonicalize_file_name(device_link);
    if (device_path == NULL) {
        memset(errbuf, '\0', sizeof(errbuf));
        virReportSystemError(errno,
                             _("Failed to resolve device link '%s'"),
                             device_link);
        return ret;
    }

    config_address = last_component(device_path);
    if (VIR_ALLOC(*bdf) != 0)
        goto out;

    if (virPCIDeviceAddressParse(config_address, *bdf) != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Failed to parse PCI config address '%s'"),
                       config_address);
        VIR_FREE(*bdf);
        goto out;
    }

    VIR_DEBUG("virPCIDeviceAddress %.4x:%.2x:%.2x.%.1x",
              (*bdf)->domain,
              (*bdf)->bus,
              (*bdf)->slot,
              (*bdf)->function);

    ret = 0;

 out:
    VIR_FREE(device_path);

    return ret;
}

/*
 * Returns Physical function given a virtual function
 */
int
virPCIGetPhysicalFunction(const char *vf_sysfs_path,
                          virPCIDeviceAddressPtr *physical_function)
{
    int ret = -1;
    char *device_link = NULL;

    VIR_DEBUG("Attempting to get SR IOV physical function for device "
              "with sysfs path '%s'", vf_sysfs_path);

    if (virBuildPath(&device_link, vf_sysfs_path, "physfn") == -1) {
        virReportOOMError();
        return ret;
    } else {
        ret = virPCIGetDeviceAddressFromSysfsLink(device_link,
                                                  physical_function);
    }

    VIR_FREE(device_link);

    return ret;
}


/*
 * Returns virtual functions of a physical function
 */
int
virPCIGetVirtualFunctions(const char *sysfs_path,
                          virPCIDeviceAddressPtr **virtual_functions,
                          size_t *num_virtual_functions)
{
    int ret = -1;
    size_t i;
    char *device_link = NULL;
    virPCIDeviceAddress *config_addr = NULL;

    VIR_DEBUG("Attempting to get SR IOV virtual functions for device"
              "with sysfs path '%s'", sysfs_path);

    *virtual_functions = NULL;
    *num_virtual_functions = 0;

    do {
        /* look for virtfn%d links until one isn't found */
        if (virAsprintf(&device_link, "%s/virtfn%zu", sysfs_path, *num_virtual_functions) < 0)
            goto error;

        if (!virFileExists(device_link))
            break;

        if (virPCIGetDeviceAddressFromSysfsLink(device_link, &config_addr) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Failed to get SRIOV function from device link '%s'"),
                           device_link);
            goto error;
        }

        VIR_DEBUG("Found virtual function %zu", *num_virtual_functions);
        if (VIR_APPEND_ELEMENT(*virtual_functions, *num_virtual_functions, config_addr) < 0)
            goto error;
        VIR_FREE(device_link);

    } while (1);

    ret = 0;
 cleanup:
    VIR_FREE(device_link);
    VIR_FREE(config_addr);
    return ret;

 error:
    for (i = 0; i < *num_virtual_functions; i++)
        VIR_FREE((*virtual_functions)[i]);
    VIR_FREE(*virtual_functions);
    goto cleanup;
}


/*
 * Returns 1 if vf device is a virtual function, 0 if not, -1 on error
 */
int
virPCIIsVirtualFunction(const char *vf_sysfs_device_link)
{
    char *vf_sysfs_physfn_link = NULL;
    int ret = -1;

    if (virAsprintf(&vf_sysfs_physfn_link, "%s/physfn",
                    vf_sysfs_device_link) < 0)
        return ret;

    ret = virFileExists(vf_sysfs_physfn_link);

    VIR_FREE(vf_sysfs_physfn_link);

    return ret;
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
    virPCIDeviceAddressPtr vf_bdf = NULL;
    virPCIDeviceAddressPtr *virt_fns = NULL;

    if (virPCIGetDeviceAddressFromSysfsLink(vf_sysfs_device_link,
                                            &vf_bdf) < 0)
        return ret;

    if (virPCIGetVirtualFunctions(pf_sysfs_device_link, &virt_fns,
                                  &num_virt_fns) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Error getting physical function's '%s' "
                         "virtual_functions"), pf_sysfs_device_link);
        goto out;
    }

    for (i = 0; i < num_virt_fns; i++) {
        if (virPCIDeviceAddressIsEqual(vf_bdf, virt_fns[i])) {
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
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr dev,
                                char **pci_sysfs_device_link)
{
    if (virAsprintf(pci_sysfs_device_link,
                    PCI_SYSFS "devices/%04x:%02x:%02x.%x", dev->domain,
                    dev->bus, dev->slot, dev->function) < 0)
        return -1;
    return 0;
}

/*
 * Returns the network device name of a pci device
 */
int
virPCIGetNetName(char *device_link_sysfs_path, char **netname)
{
    char *pcidev_sysfs_net_path = NULL;
    int ret = -1;
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (virBuildPath(&pcidev_sysfs_net_path, device_link_sysfs_path,
                     "net") == -1) {
        virReportOOMError();
        return -1;
    }

    dir = opendir(pcidev_sysfs_net_path);
    if (dir == NULL)
        goto out;

    while ((entry = readdir(dir))) {
        if (STREQ(entry->d_name, ".") ||
            STREQ(entry->d_name, ".."))
            continue;

        /* Assume a single directory entry */
        if (VIR_STRDUP(*netname, entry->d_name) > 0)
            ret = 0;
        break;
    }

    closedir(dir);

 out:
    VIR_FREE(pcidev_sysfs_net_path);

    return ret;
}

int
virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path,
                             char **pfname, int *vf_index)
{
    virPCIDeviceAddressPtr pf_config_address = NULL;
    char *pf_sysfs_device_path = NULL;
    int ret = -1;

    if (virPCIGetPhysicalFunction(vf_sysfs_device_path, &pf_config_address) < 0)
        return ret;

    if (virPCIDeviceAddressGetSysfsFile(pf_config_address,
                                        &pf_sysfs_device_path) < 0) {

        VIR_FREE(pf_config_address);
        return ret;
    }

    if (virPCIGetVirtualFunctionIndex(pf_sysfs_device_path, vf_sysfs_device_path,
                                      vf_index) < 0)
        goto cleanup;

    ret = virPCIGetNetName(pf_sysfs_device_path, pfname);

 cleanup:
    VIR_FREE(pf_config_address);
    VIR_FREE(pf_sysfs_device_path);

    return ret;
}

#else
static const char *unsupported = N_("not supported on non-linux platforms");

int
virPCIGetPhysicalFunction(const char *vf_sysfs_path ATTRIBUTE_UNUSED,
                          virPCIDeviceAddressPtr *physical_function ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctions(const char *sysfs_path ATTRIBUTE_UNUSED,
                          virPCIDeviceAddressPtr **virtual_functions ATTRIBUTE_UNUSED,
                          size_t *num_virtual_functions ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIIsVirtualFunction(const char *vf_sysfs_device_link ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctionIndex(const char *pf_sysfs_device_link ATTRIBUTE_UNUSED,
                              const char *vf_sysfs_device_link ATTRIBUTE_UNUSED,
                              int *vf_index ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;

}

int
virPCIDeviceAddressGetSysfsFile(virPCIDeviceAddressPtr dev ATTRIBUTE_UNUSED,
                                char **pci_sysfs_device_link ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetNetName(char *device_link_sysfs_path ATTRIBUTE_UNUSED,
                 char **netname ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}

int
virPCIGetVirtualFunctionInfo(const char *vf_sysfs_device_path ATTRIBUTE_UNUSED,
                             char **pfname ATTRIBUTE_UNUSED,
                             int *vf_index ATTRIBUTE_UNUSED)
{
    virReportError(VIR_ERR_INTERNAL_ERROR, "%s", _(unsupported));
    return -1;
}
#endif /* __linux__ */
