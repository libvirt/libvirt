/*
 * qemu_command.c: QEMU command generation
 *
 * Copyright (C) 2006-2007, 2009-2010 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_command.h"
#include "qemu_capabilities.h"
#include "qemu_bridge_filter.h"
#include "cpu/cpu.h"
#include "memory.h"
#include "logging.h"
#include "virterror_internal.h"
#include "util.h"
#include "files.h"
#include "uuid.h"
#include "c-ctype.h"
#include "domain_nwfilter.h"

#include <sys/utsname.h>
#include <sys/stat.h>
#include <fcntl.h>

#define VIR_FROM_THIS VIR_FROM_QEMU


VIR_ENUM_DECL(virDomainDiskQEMUBus)
VIR_ENUM_IMPL(virDomainDiskQEMUBus, VIR_DOMAIN_DISK_BUS_LAST,
              "ide",
              "floppy",
              "scsi",
              "virtio",
              "xen",
              "usb",
              "uml",
              "sata")


VIR_ENUM_DECL(qemuDiskCacheV1)
VIR_ENUM_DECL(qemuDiskCacheV2)

VIR_ENUM_IMPL(qemuDiskCacheV1, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "off",
              "off", /* writethrough not supported, so for safety, disable */
              "on"); /* Old 'on' was equivalent to 'writeback' */

VIR_ENUM_IMPL(qemuDiskCacheV2, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback");

VIR_ENUM_DECL(qemuVideo)

VIR_ENUM_IMPL(qemuVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "std",
              "cirrus",
              "vmware",
              "", /* no arg needed for xen */
              "", /* don't support vbox */
              "qxl");

static void
uname_normalize (struct utsname *ut)
{
    uname(ut);

    /* Map i386, i486, i586 to i686.  */
    if (ut->machine[0] == 'i' &&
        ut->machine[1] != '\0' &&
        ut->machine[2] == '8' &&
        ut->machine[3] == '6' &&
        ut->machine[4] == '\0')
        ut->machine[1] = '6';
}


/**
 * qemuPhysIfaceConnect:
 * @conn: pointer to virConnect object
 * @driver: pointer to the qemud_driver
 * @net: pointer to he VM's interface description with direct device type
 * @qemuCmdFlags: flags for qemu
 * @vmuuid: The UUID of the VM (needed by 802.1Qbh)
 *
 * Returns a filedescriptor on success or -1 in case of error.
 */
int
qemuPhysIfaceConnect(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainNetDefPtr net,
                     unsigned long long qemuCmdFlags,
                     const unsigned char *vmuuid,
                     enum virVMOperationType vmop)
{
    int rc;
#if WITH_MACVTAP
    char *res_ifname = NULL;
    int vnet_hdr = 0;
    int err;

    if (qemuCmdFlags & QEMUD_CMD_FLAG_VNET_HDR &&
        net->model && STREQ(net->model, "virtio"))
        vnet_hdr = 1;

    rc = openMacvtapTap(net->ifname, net->mac, net->data.direct.linkdev,
                        net->data.direct.mode, vnet_hdr, vmuuid,
                        &net->data.direct.virtPortProfile, &res_ifname,
                        vmop);
    if (rc >= 0) {
        VIR_FREE(net->ifname);
        net->ifname = res_ifname;
    }

    if (rc >=0 && driver->macFilter) {
        if ((err = networkAllowMacOnPort(driver, net->ifname, net->mac))) {
            virReportSystemError(err,
                 _("failed to add ebtables rule to allow MAC address on  '%s'"),
                                 net->ifname);
        }
    }

    if (rc >= 0) {
        if ((net->filter) && (net->ifname)) {
            err = virDomainConfNWFilterInstantiate(conn, net);
            if (err) {
                VIR_FORCE_CLOSE(rc);
                delMacvtap(net->ifname, net->mac, net->data.direct.linkdev,
                           &net->data.direct.virtPortProfile);
                VIR_FREE(net->ifname);
            }
        }
    }
#else
    (void)conn;
    (void)net;
    (void)qemuCmdFlags;
    (void)driver;
    (void)vmuuid;
    (void)vmop;
    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("No support for macvtap device"));
    rc = -1;
#endif
    return rc;
}


int
qemuNetworkIfaceConnect(virConnectPtr conn,
                        struct qemud_driver *driver,
                        virDomainNetDefPtr net,
                        unsigned long long qemuCmdFlags)
{
    char *brname = NULL;
    int err;
    int tapfd = -1;
    int vnet_hdr = 0;
    int template_ifname = 0;
    unsigned char tapmac[VIR_MAC_BUFLEN];

    if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
        int active, fail = 0;
        virErrorPtr errobj;
        virNetworkPtr network = virNetworkLookupByName(conn,
                                                       net->data.network.name);
        if (!network)
            return -1;

        active = virNetworkIsActive(network);
        if (active != 1) {
            fail = 1;

            if (active == 0)
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("Network '%s' is not active."),
                                net->data.network.name);
        }

        if (!fail) {
            brname = virNetworkGetBridgeName(network);
            if (brname == NULL)
                fail = 1;
        }

        /* Make sure any above failure is preserved */
        errobj = virSaveLastError();
        virNetworkFree(network);
        virSetError(errobj);
        virFreeError(errobj);

        if (fail)
            return -1;

    } else if (net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        if (!(brname = strdup(net->data.bridge.brname))) {
            virReportOOMError();
            return -1;
        }
    } else {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("Network type %d is not supported"), net->type);
        return -1;
    }

    if (!driver->brctl && (err = brInit(&driver->brctl))) {
        virReportSystemError(err, "%s",
                             _("cannot initialize bridge support"));
        goto cleanup;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, "vnet") ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (!(net->ifname = strdup("vnet%d"))) {
            virReportOOMError();
            goto cleanup;
        }
        /* avoid exposing vnet%d in dumpxml or error outputs */
        template_ifname = 1;
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_VNET_HDR &&
        net->model && STREQ(net->model, "virtio"))
        vnet_hdr = 1;

    memcpy(tapmac, net->mac, VIR_MAC_BUFLEN);
    tapmac[0] = 0xFE; /* Discourage bridge from using TAP dev MAC */
    if ((err = brAddTap(driver->brctl,
                        brname,
                        &net->ifname,
                        tapmac,
                        vnet_hdr,
                        &tapfd))) {
        if (err == ENOTSUP) {
            /* In this particular case, give a better diagnostic. */
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Failed to add tap interface to bridge. "
                              "%s is not a bridge device"), brname);
        } else if (err == ENOENT) {
            /* When the tun drive is missing, give a better message. */
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Failed to add tap interface to bridge. "
                              "Your kernel is missing the 'tun' module or "
                              "CONFIG_TUN, or you need to add the "
                              "/dev/net/tun device node."));
        } else if (template_ifname) {
            virReportSystemError(err,
                                 _("Failed to add tap interface to bridge '%s'"),
                                 brname);
        } else {
            virReportSystemError(err,
                                 _("Failed to add tap interface '%s' to bridge '%s'"),
                                 net->ifname, brname);
        }
        if (template_ifname)
            VIR_FREE(net->ifname);
        tapfd = -1;
    }

    if (driver->macFilter) {
        if ((err = networkAllowMacOnPort(driver, net->ifname, net->mac))) {
            virReportSystemError(err,
                 _("failed to add ebtables rule to allow MAC address on  '%s'"),
                                 net->ifname);
        }
    }

    if (tapfd >= 0) {
        if ((net->filter) && (net->ifname)) {
            err = virDomainConfNWFilterInstantiate(conn, net);
            if (err)
                VIR_FORCE_CLOSE(tapfd);
        }
    }

cleanup:
    VIR_FREE(brname);

    return tapfd;
}


int
qemuOpenVhostNet(virDomainNetDefPtr net,
                 unsigned long long qemuCmdFlags)
{

    /* If qemu supports vhost-net mode (including the -netdev command
     * option), the nic model is virtio, and we can open
     * /dev/vhost_net, assume that vhost-net mode is available and
     * return the fd to /dev/vhost_net. Otherwise, return -1.
     */

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_VNET_HOST &&
          qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV &&
          qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE &&
          net->model && STREQ(net->model, "virtio")))
        return -1;

    return open("/dev/vhost-net", O_RDWR, 0);
}


static int qemuDomainDeviceAliasIndex(virDomainDeviceInfoPtr info,
                                      const char *prefix)
{
    int idx;

    if (!info->alias)
        return -1;
    if (!STRPREFIX(info->alias, prefix))
        return -1;

    if (virStrToLong_i(info->alias + strlen(prefix), NULL, 10, &idx) < 0)
        return -1;

    return idx;
}


int qemuDomainNetVLAN(virDomainNetDefPtr def)
{
    return qemuDomainDeviceAliasIndex(&def->info, "net");
}


/* Names used before -drive existed */
static int qemuAssignDeviceDiskAliasLegacy(virDomainDiskDefPtr disk)
{
    char *devname;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        STREQ(disk->dst, "hdc"))
        devname = strdup("cdrom");
    else
        devname = strdup(disk->dst);

    if (!devname) {
        virReportOOMError();
        return -1;
    }

    disk->info.alias = devname;
    return 0;
}


char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk,
                               unsigned long long qemudCmdFlags)
{
    char *ret;

    if (qemudCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (virAsprintf(&ret, "%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias) < 0) {
            virReportOOMError();
            return NULL;
        }
    } else {
        if (!(ret = strdup(disk->info.alias))) {
            virReportOOMError();
            return NULL;
        }
    }
    return ret;
}


/* Names used before -drive supported the id= option */
static int qemuAssignDeviceDiskAliasFixed(virDomainDiskDefPtr disk)
{
    int busid, devid;
    int ret;
    char *devname;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot convert disk '%s' to bus/device index"),
                        disk->dst);
        return -1;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->device== VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&devname, "ide%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&devname, "ide%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&devname, "scsi%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&devname, "scsi%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_FDC:
        ret = virAsprintf(&devname, "floppy%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        ret = virAsprintf(&devname, "virtio%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_XEN:
        ret = virAsprintf(&devname, "xenblk%d", devid);
        break;
    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("Unsupported disk name mapping for bus '%s'"),
                        virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (ret == -1) {
        virReportOOMError();
        return -1;
    }

    disk->info.alias = devname;

    return 0;
}


/* Our custom -drive naming scheme used with id= */
static int qemuAssignDeviceDiskAliasCustom(virDomainDiskDefPtr disk)
{
    const char *prefix = virDomainDiskBusTypeToString(disk->bus);
    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        if (virAsprintf(&disk->info.alias, "%s%d-%d-%d", prefix,
                        disk->info.addr.drive.controller,
                        disk->info.addr.drive.bus,
                        disk->info.addr.drive.unit) < 0)
            goto no_memory;
    } else {
        int idx = virDiskNameToIndex(disk->dst);
        if (virAsprintf(&disk->info.alias, "%s-disk%d", prefix, idx) < 0)
            goto no_memory;
    }

    return 0;

no_memory:
    virReportOOMError();
    return -1;
}


int
qemuAssignDeviceDiskAlias(virDomainDiskDefPtr def, unsigned long long qemuCmdFlags)
{
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)
            return qemuAssignDeviceDiskAliasCustom(def);
        else
            return qemuAssignDeviceDiskAliasFixed(def);
    } else {
        return qemuAssignDeviceDiskAliasLegacy(def);
    }
}


int
qemuAssignDeviceNetAlias(virDomainDefPtr def, virDomainNetDefPtr net, int idx)
{
    if (idx == -1) {
        int i;
        idx = 0;
        for (i = 0 ; i < def->nnets ; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "net")) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Unable to determine device index for network device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&net->info.alias, "net%d", idx) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


int
qemuAssignDeviceHostdevAlias(virDomainDefPtr def, virDomainHostdevDefPtr hostdev, int idx)
{
    if (idx == -1) {
        int i;
        idx = 0;
        for (i = 0 ; i < def->nhostdevs ; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->hostdevs[i]->info, "hostdev")) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Unable to determine device index for hostdevwork device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&hostdev->info.alias, "hostdev%d", idx) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


int
qemuAssignDeviceControllerAlias(virDomainControllerDefPtr controller)
{
    const char *prefix = virDomainControllerTypeToString(controller->type);

    if (virAsprintf(&controller->info.alias,  "%s%d", prefix,
                    controller->idx) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


static int
qemuAssignDeviceAliases(virDomainDefPtr def, unsigned long long qemuCmdFlags)
{
    int i;

    for (i = 0; i < def->ndisks ; i++) {
        if (qemuAssignDeviceDiskAlias(def->disks[i], qemuCmdFlags) < 0)
            return -1;
    }
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NET_NAME) ||
        (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
        for (i = 0; i < def->nnets ; i++) {
            if (qemuAssignDeviceNetAlias(def, def->nets[i], i) < 0)
                return -1;
        }
    }

    if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
        return 0;

    for (i = 0; i < def->nfss ; i++) {
        if (virAsprintf(&def->fss[i]->info.alias, "fs%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nsounds ; i++) {
        if (virAsprintf(&def->sounds[i]->info.alias, "sound%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nhostdevs ; i++) {
        if (qemuAssignDeviceHostdevAlias(def, def->hostdevs[i], i) < 0)
            return -1;
    }
    for (i = 0; i < def->nvideos ; i++) {
        if (virAsprintf(&def->videos[i]->info.alias, "video%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->ncontrollers ; i++) {
        if (qemuAssignDeviceControllerAlias(def->controllers[i]) < 0)
            return -1;
    }
    for (i = 0; i < def->ninputs ; i++) {
        if (virAsprintf(&def->inputs[i]->info.alias, "input%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nparallels ; i++) {
        if (virAsprintf(&def->parallels[i]->info.alias, "parallel%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nserials ; i++) {
        if (virAsprintf(&def->serials[i]->info.alias, "serial%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nchannels ; i++) {
        if (virAsprintf(&def->channels[i]->info.alias, "channel%d", i) < 0)
            goto no_memory;
    }
    if (def->console) {
        if (virAsprintf(&def->console->info.alias, "console%d", i) < 0)
            goto no_memory;
    }
    if (def->watchdog) {
        if (virAsprintf(&def->watchdog->info.alias, "watchdog%d", 0) < 0)
            goto no_memory;
    }
    if (def->memballoon) {
        if (virAsprintf(&def->memballoon->info.alias, "balloon%d", 0) < 0)
            goto no_memory;
    }

    return 0;

    no_memory:
    virReportOOMError();
    return -1;
}


#define QEMU_PCI_ADDRESS_LAST_SLOT 31
struct _qemuDomainPCIAddressSet {
    virHashTablePtr used;
    int nextslot;
};


static char *qemuPCIAddressAsString(virDomainDeviceInfoPtr dev)
{
    char *addr;

    if (dev->addr.pci.domain != 0 ||
        dev->addr.pci.bus != 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("Only PCI domain 0 and bus 0 are available"));
        return NULL;
    }

    if (virAsprintf(&addr, "%d:%d:%d",
                    dev->addr.pci.domain,
                    dev->addr.pci.bus,
                    dev->addr.pci.slot) < 0) {
        virReportOOMError();
        return NULL;
    }
    return addr;
}


static int qemuCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                 virDomainDeviceInfoPtr dev,
                                 void *opaque)
{
    qemuDomainPCIAddressSetPtr addrs = opaque;

    if (dev->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        char *addr = qemuPCIAddressAsString(dev);
        if (!addr)
            return -1;

        VIR_DEBUG("Remembering PCI addr %s", addr);

        if (virHashAddEntry(addrs->used, addr, addr) < 0) {
            VIR_FREE(addr);
            return -1;
        }
    }

    return 0;
}


qemuDomainPCIAddressSetPtr qemuDomainPCIAddressSetCreate(virDomainDefPtr def)
{
    qemuDomainPCIAddressSetPtr addrs;

    if (VIR_ALLOC(addrs) < 0)
        goto no_memory;

    if (!(addrs->used = virHashCreate(10)))
        goto no_memory;

    if (virDomainDeviceInfoIterate(def, qemuCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

no_memory:
    virReportOOMError();
error:
    qemuDomainPCIAddressSetFree(addrs);
    return NULL;
}

int qemuDomainPCIAddressReserveAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    char *addr;

    addr = qemuPCIAddressAsString(dev);
    if (!addr)
        return -1;

    VIR_DEBUG("Reserving PCI addr %s", addr);

    if (virHashLookup(addrs->used, addr)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unable to reserve PCI address %s"), addr);
        VIR_FREE(addr);
        return -1;
    }

    if (virHashAddEntry(addrs->used, addr, addr)) {
        VIR_FREE(addr);
        return -1;
    }

    if (dev->addr.pci.slot > addrs->nextslot) {
        addrs->nextslot = dev->addr.pci.slot + 1;
        if (QEMU_PCI_ADDRESS_LAST_SLOT < addrs->nextslot)
            addrs->nextslot = 0;
    }

    return 0;
}

int qemuDomainPCIAddressReserveSlot(qemuDomainPCIAddressSetPtr addrs,
                                    int slot)
{
    virDomainDeviceInfo dev;

    dev.addr.pci.domain = 0;
    dev.addr.pci.bus = 0;
    dev.addr.pci.slot = slot;

    return qemuDomainPCIAddressReserveAddr(addrs, &dev);
}


int qemuDomainPCIAddressEnsureAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    int ret = 0;
    if (dev->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        ret = qemuDomainPCIAddressReserveAddr(addrs, dev);
    else
        ret = qemuDomainPCIAddressSetNextAddr(addrs, dev);
    return ret;
}

static void qemuDomainPCIAddressSetFreeEntry(void *payload, const char *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}


int qemuDomainPCIAddressReleaseAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    char *addr;
    int ret;

    addr = qemuPCIAddressAsString(dev);
    if (!addr)
        return -1;

    ret = virHashRemoveEntry(addrs->used, addr, qemuDomainPCIAddressSetFreeEntry);

    VIR_FREE(addr);

    return ret;
}


void qemuDomainPCIAddressSetFree(qemuDomainPCIAddressSetPtr addrs)
{
    if (!addrs)
        return;

    virHashFree(addrs->used, qemuDomainPCIAddressSetFreeEntry);
    VIR_FREE(addrs);
}


int qemuDomainPCIAddressSetNextAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    int i;
    int iteration;

    for (i = addrs->nextslot, iteration = 0;
         iteration <= QEMU_PCI_ADDRESS_LAST_SLOT; i++, iteration++) {
        virDomainDeviceInfo maybe;
        char *addr;

        if (QEMU_PCI_ADDRESS_LAST_SLOT < i)
            i = 0;
        memset(&maybe, 0, sizeof(maybe));
        maybe.addr.pci.domain = 0;
        maybe.addr.pci.bus = 0;
        maybe.addr.pci.slot = i;

        if (!(addr = qemuPCIAddressAsString(&maybe)))
            return -1;

        if (virHashLookup(addrs->used, addr)) {
            VIR_DEBUG("PCI addr %s already in use", addr);
            VIR_FREE(addr);
            continue;
        }

        VIR_DEBUG("Allocating PCI addr %s", addr);

        if (virHashAddEntry(addrs->used, addr, addr) < 0) {
            VIR_FREE(addr);
            return -1;
        }

        dev->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
        dev->addr.pci = maybe.addr.pci;

        addrs->nextslot = i + 1;
        if (QEMU_PCI_ADDRESS_LAST_SLOT < addrs->nextslot)
            addrs->nextslot = 0;

        return 0;
    }

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    "%s", _("No more available PCI addresses"));
    return -1;
}

/*
 * This assigns static PCI slots to all configured devices.
 * The ordering here is chosen to match the ordering used
 * with old QEMU < 0.12, so that if a user updates a QEMU
 * host from old QEMU to QEMU >= 0.12, their guests should
 * get PCI addresses in the same order as before.
 *
 * NB, if they previously hotplugged devices then all bets
 * are off. Hotplug for old QEMU was unfixably broken wrt
 * to stable PCI addressing.
 *
 * Order is:
 *
 *  - Host bridge (slot 0)
 *  - PIIX3 ISA bridge, IDE controller, something else unknown, USB controller (slot 1)
 *  - Video (slot 2)
 *
 * Incrementally assign slots from 3 onwards:
 *
 *  - Net
 *  - Sound
 *  - SCSI controllers
 *  - VirtIO block
 *  - VirtIO balloon
 *  - Host device passthrough
 *  - Watchdog
 *
 * Prior to this function being invoked, qemuCollectPCIAddress() will have
 * added all existing PCI addresses from the 'def' to 'addrs'. Thus this
 * function must only try to reserve addresses if info.type == NONE and
 * skip over info.type == PCI
 */
int
qemuAssignDevicePCISlots(virDomainDefPtr def, qemuDomainPCIAddressSetPtr addrs)
{
    int i;
    bool reservedIDE = false;

    /* Host bridge */
    if (qemuDomainPCIAddressReserveSlot(addrs, 0) < 0)
        goto error;

    /* Verify that first IDE controller (if any) is on the PIIX3, fn 1 */
    for (i = 0; i < def->ncontrollers ; i++) {
        /* First IDE controller lives on the PIIX3 at slot=1, function=1 */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 1) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("Primary IDE controller must have PCI address 0:0:1.1"));
                    goto error;
                }
                /* If TYPE==PCI, then then qemuCollectPCIAddress() function
                 * has already reserved the address, so we must skip */
                reservedIDE = true;
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 1;
            }
        }
    }

    /* PIIX3 (ISA bridge, IDE controller, something else unknown, USB controller)
     * hardcoded slot=1, multifunction device
     */
    if (!reservedIDE &&
        qemuDomainPCIAddressReserveSlot(addrs, 1) < 0)
        goto error;

    /* First VGA is hardcoded slot=2 */
    if (def->nvideos > 0) {
        if (def->videos[0]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            if (def->videos[0]->info.addr.pci.domain != 0 ||
                def->videos[0]->info.addr.pci.bus != 0 ||
                def->videos[0]->info.addr.pci.slot != 2 ||
                def->videos[0]->info.addr.pci.function != 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("Primary video card must have PCI address 0:0:2.0"));
                goto error;
            }
        } else {
            def->videos[0]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            def->videos[0]->info.addr.pci.domain = 0;
            def->videos[0]->info.addr.pci.bus = 0;
            def->videos[0]->info.addr.pci.slot = 2;
            def->videos[0]->info.addr.pci.function = 0;
            if (qemuDomainPCIAddressReserveSlot(addrs, 2) < 0)
                goto error;
        }
    }
    for (i = 0; i < def->nfss ; i++) {
        if (def->fss[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* Only support VirtIO-9p-pci so far. If that changes,
         * we might need to skip devices here */
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->fss[i]->info) < 0)
            goto error;
    }

    /* Network interfaces */
    for (i = 0; i < def->nnets ; i++) {
        if (def->nets[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->nets[i]->info) < 0)
            goto error;
    }

    /* Sound cards */
    for (i = 0; i < def->nsounds ; i++) {
        if (def->sounds[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        /* Skip ISA sound card, and PCSPK */
        if (def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_SB16 ||
            def->sounds[i]->model == VIR_DOMAIN_SOUND_MODEL_PCSPK)
            continue;

        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->sounds[i]->info) < 0)
            goto error;
    }

    /* Disk controllers (SCSI only for now) */
    for (i = 0; i < def->ncontrollers ; i++) {
        /* FDC lives behind the ISA bridge */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC)
            continue;

        /* First IDE controller lives on the PIIX3 at slot=1, function=1,
           dealt with earlier on*/
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0)
            continue;

        if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->controllers[i]->info) < 0)
            goto error;
    }

    /* Disks (VirtIO only for now */
    for (i = 0; i < def->ndisks ; i++) {
        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* Only VirtIO disks use PCI addrs */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->disks[i]->info) < 0)
            goto error;
    }

    /* Host PCI devices */
    for (i = 0; i < def->nhostdevs ; i++) {
        if (def->hostdevs[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->hostdevs[i]->info) < 0)
            goto error;
    }

    /* VirtIO balloon */
    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->memballoon->info) < 0)
            goto error;
    }

    /* A watchdog */
    if (def->watchdog &&
        def->watchdog->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->watchdog->info) < 0)
            goto error;
    }

    /* Further non-primary video cards */
    for (i = 1; i < def->nvideos ; i++) {
        if (def->videos[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->videos[i]->info) < 0)
            goto error;
    }
    for (i = 0; i < def->ninputs ; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nparallels ; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nserials ; i++) {
        /* Nada - none are PCI based (yet) */
    }
    for (i = 0; i < def->nchannels ; i++) {
        /* Nada - none are PCI based (yet) */
    }

    return 0;

error:
    return -1;
}


static int
qemuBuildDeviceAddressStr(virBufferPtr buf,
                          virDomainDeviceInfoPtr info)
{
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        if (info->addr.pci.domain != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Only PCI device addresses with domain=0 are supported"));
            return -1;
        }
        if (info->addr.pci.bus != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Only PCI device addresses with bus=0 are supported"));
            return -1;
        }
        if (info->addr.pci.function != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("Only PCI device addresses with function=0 are supported"));
            return -1;
        }

        /* XXX
         * When QEMU grows support for > 1 PCI bus, then pci.0 changes
         * to pci.1, pci.2, etc
         * When QEMU grows support for > 1 PCI domain, then pci.0 change
         * to pciNN.0  where NN is the domain number
         */
        virBufferVSprintf(buf, ",bus=pci.0,addr=0x%x", info->addr.pci.slot);
    }
    return 0;
}


#define QEMU_SERIAL_PARAM_ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

static int
qemuSafeSerialParamValue(const char *value)
{
    if (strspn(value, QEMU_SERIAL_PARAM_ACCEPTED_CHARS) != strlen (value)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("driver serial '%s' contains unsafe characters"),
                        value);
        return -1;
    }

    return 0;
}


char *
qemuBuildDriveStr(virDomainDiskDefPtr disk,
                  int bootable,
                  unsigned long long qemuCmdFlags)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    int idx = virDiskNameToIndex(disk->dst);
    int busid = -1, unitid = -1;

    if (idx < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("unexpected address type for scsi disk"));
            goto error;
        }

        /* Setting bus= attr for SCSI drives, causes a controller
         * to be created. Yes this is slightly odd. It is not possible
         * to have > 1 bus on a SCSI controller (yet). */
        if (disk->info.addr.drive.bus != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("SCSI controller only supports 1 bus"));
            goto error;
        }
        busid = disk->info.addr.drive.controller;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("unexpected address type for ide disk"));
            goto error;
        }
        /* We can only have 1 IDE controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        busid = disk->info.addr.drive.bus;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                            _("unexpected address type for fdc disk"));
            goto error;
        }
        /* We can only have 1 FDC controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        /* We can only have 1 FDC bus (currently) */
        if (disk->info.addr.drive.bus != 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("Only 1 %s bus is supported"), bus);
            goto error;
        }
        unitid = disk->info.addr.drive.unit;

        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        /* Each virtio drive is a separate PCI device, no unit/busid or index */
        idx = -1;
        break;

    case VIR_DOMAIN_DISK_BUS_XEN:
        /* Xen has no address type currently, so assign based on index */
        break;
    }

    /* disk->src is NULL when we use nbd disks */
    if (disk->src || (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                      disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_NBD)) {
        if (disk->type == VIR_DOMAIN_DISK_TYPE_DIR) {
            /* QEMU only supports magic FAT format for now */
            if (disk->driverType &&
                STRNEQ(disk->driverType, "fat")) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("unsupported disk driver type for '%s'"),
                                disk->driverType);
                goto error;
            }
            if (!disk->readonly) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                _("cannot create virtual FAT disks in read-write mode"));
                goto error;
            }
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                virBufferVSprintf(&opt, "file=fat:floppy:%s,", disk->src);
            else
                virBufferVSprintf(&opt, "file=fat:%s,", disk->src);
        } else if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
            switch (disk->protocol) {
            case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                if (disk->nhosts != 1) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("NBD accepts only one host"));
                    goto error;
                }
                virBufferVSprintf(&opt, "file=nbd:%s:%s,",
                                  disk->hosts->name, disk->hosts->port);
                break;
            case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                /* TODO: set monitor hostnames */
                virBufferVSprintf(&opt, "file=rbd:%s,", disk->src);
                break;
            case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                if (disk->nhosts == 0)
                    virBufferVSprintf(&opt, "file=sheepdog:%s,", disk->src);
                else
                    /* only one host is supported now */
                    virBufferVSprintf(&opt, "file=sheepdog:%s:%s:%s,",
                                      disk->hosts->name, disk->hosts->port,
                                      disk->src);
                break;
            }
        } else {
            virBufferVSprintf(&opt, "file=%s,", disk->src);
        }
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)
        virBufferAddLit(&opt, "if=none");
    else
        virBufferVSprintf(&opt, "if=%s", bus);

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
        virBufferAddLit(&opt, ",media=cdrom");

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        virBufferVSprintf(&opt, ",id=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    } else {
        if (busid == -1 && unitid == -1) {
            if (idx != -1)
                virBufferVSprintf(&opt, ",index=%d", idx);
        } else {
            if (busid != -1)
                virBufferVSprintf(&opt, ",bus=%d", busid);
            if (unitid != -1)
                virBufferVSprintf(&opt, ",unit=%d", unitid);
        }
    }
    if (bootable &&
        disk->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        disk->bus != VIR_DOMAIN_DISK_BUS_IDE)
        virBufferAddLit(&opt, ",boot=on");
    if (disk->readonly &&
        qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_READONLY)
        virBufferAddLit(&opt, ",readonly=on");
    if (disk->driverType && *disk->driverType != '\0' &&
        disk->type != VIR_DOMAIN_DISK_TYPE_DIR &&
        qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_FORMAT)
        virBufferVSprintf(&opt, ",format=%s", disk->driverType);
    if (disk->serial &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_SERIAL)) {
        if (qemuSafeSerialParamValue(disk->serial) < 0)
            goto error;
        virBufferVSprintf(&opt, ",serial=%s", disk->serial);
    }

    if (disk->cachemode) {
        const char *mode =
            (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_CACHE_V2) ?
            qemuDiskCacheV2TypeToString(disk->cachemode) :
            qemuDiskCacheV1TypeToString(disk->cachemode);

        virBufferVSprintf(&opt, ",cache=%s", mode);
    } else if (disk->shared && !disk->readonly) {
        virBufferAddLit(&opt, ",cache=off");
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_MONITOR_JSON) {
        if (disk->error_policy) {
            virBufferVSprintf(&opt, ",werror=%s,rerror=%s",
                              virDomainDiskErrorPolicyTypeToString(disk->error_policy),
                              virDomainDiskErrorPolicyTypeToString(disk->error_policy));
        }
    }

    if (virBufferError(&opt)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&opt);

error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *
qemuBuildDriveDevStr(virDomainDiskDefPtr disk)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    int idx = virDiskNameToIndex(disk->dst);

    if (idx < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        virBufferAddLit(&opt, "ide-drive");
        virBufferVSprintf(&opt, ",bus=ide.%d,unit=%d",
                          disk->info.addr.drive.bus,
                          disk->info.addr.drive.unit);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        virBufferAddLit(&opt, "scsi-disk");
        virBufferVSprintf(&opt, ",bus=scsi%d.%d,scsi-id=%d",
                          disk->info.addr.drive.controller,
                          disk->info.addr.drive.bus,
                          disk->info.addr.drive.unit);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        virBufferAddLit(&opt, "virtio-blk-pci");
        qemuBuildDeviceAddressStr(&opt, &disk->info);
        break;
    case VIR_DOMAIN_DISK_BUS_USB:
        virBufferAddLit(&opt, "usb-storage");
        break;
    default:
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unsupported disk bus '%s' with device setup"), bus);
        goto error;
    }
    virBufferVSprintf(&opt, ",drive=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    virBufferVSprintf(&opt, ",id=%s", disk->info.alias);

    if (virBufferError(&opt)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&opt);

error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *qemuBuildFSStr(virDomainFSDefPtr fs,
                     unsigned long long qemuCmdFlags ATTRIBUTE_UNUSED)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("only supports mount filesystem type"));
        goto error;
    }

    virBufferAddLit(&opt, "local");
    if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_MAPPED) {
        virBufferAddLit(&opt, ",security_model=mapped");
    } else if(fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
        virBufferAddLit(&opt, ",security_model=passthrough");
    } else if(fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_SQUASH) {
        virBufferAddLit(&opt, ",security_model=none");
    }
    virBufferVSprintf(&opt, ",id=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferVSprintf(&opt, ",path=%s", fs->src);

    if (virBufferError(&opt)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&opt);

error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *
qemuBuildFSDevStr(virDomainFSDefPtr fs)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("can only passthrough directories"));
        goto error;
    }

    virBufferAddLit(&opt, "virtio-9p-pci");
    virBufferVSprintf(&opt, ",id=%s", fs->info.alias);
    virBufferVSprintf(&opt, ",fsdev=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferVSprintf(&opt, ",mount_tag=%s", fs->dst);
    qemuBuildDeviceAddressStr(&opt, &fs->info);

    if (virBufferError(&opt)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&opt);

error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


char *
qemuBuildControllerDevStr(virDomainControllerDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        virBufferAddLit(&buf, "lsi");
        virBufferVSprintf(&buf, ",id=scsi%d", def->idx);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virBufferAddLit(&buf, "virtio-serial-pci");
        } else {
            virBufferAddLit(&buf, "virtio-serial");
        }
        virBufferVSprintf(&buf, ",id=" QEMU_VIRTIO_SERIAL_PREFIX "%d",
                          def->idx);
        if (def->opts.vioserial.ports != -1) {
            virBufferVSprintf(&buf, ",max_ports=%d",
                              def->opts.vioserial.ports);
        }
        if (def->opts.vioserial.vectors != -1) {
            virBufferVSprintf(&buf, ",vectors=%d",
                              def->opts.vioserial.vectors);
        }
        break;

    /* We always get an IDE controller, whether we want it or not. */
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    default:
        goto error;
    }

    if (qemuBuildDeviceAddressStr(&buf, &def->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildNicStr(virDomainNetDefPtr net,
                const char *prefix,
                int vlan)
{
    char *str;
    if (virAsprintf(&str,
                    "%smacaddr=%02x:%02x:%02x:%02x:%02x:%02x,vlan=%d%s%s%s%s",
                    prefix ? prefix : "",
                    net->mac[0], net->mac[1],
                    net->mac[2], net->mac[3],
                    net->mac[4], net->mac[5],
                    vlan,
                    (net->model ? ",model=" : ""),
                    (net->model ? net->model : ""),
                    (net->info.alias ? ",name=" : ""),
                    (net->info.alias ? net->info.alias : "")) < 0) {
        virReportOOMError();
        return NULL;
    }

    return str;
}


char *
qemuBuildNicDevStr(virDomainNetDefPtr net, int vlan)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *nic;

    if (!net->model) {
        nic = "rtl8139";
    } else if (STREQ(net->model, "virtio")) {
        nic = "virtio-net-pci";
    } else {
        nic = net->model;
    }

    virBufferAdd(&buf, nic, strlen(nic));
    if (vlan == -1)
        virBufferVSprintf(&buf, ",netdev=host%s", net->info.alias);
    else
        virBufferVSprintf(&buf, ",vlan=%d", vlan);
    virBufferVSprintf(&buf, ",id=%s", net->info.alias);
    virBufferVSprintf(&buf, ",mac=%02x:%02x:%02x:%02x:%02x:%02x",
                      net->mac[0], net->mac[1],
                      net->mac[2], net->mac[3],
                      net->mac[4], net->mac[5]);
    if (qemuBuildDeviceAddressStr(&buf, &net->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildHostNetStr(virDomainNetDefPtr net,
                    char type_sep,
                    int vlan,
                    const char *tapfd,
                    const char *vhostfd)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (net->type) {
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        virBufferAddLit(&buf, "tap");
        virBufferVSprintf(&buf, "%cfd=%s", type_sep, tapfd);
        type_sep = ',';
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        virBufferAddLit(&buf, "tap");
        if (net->ifname) {
            virBufferVSprintf(&buf, "%cifname=%s", type_sep, net->ifname);
            type_sep = ',';
        }
        if (net->data.ethernet.script) {
            virBufferVSprintf(&buf, "%cscript=%s", type_sep,
                              net->data.ethernet.script);
            type_sep = ',';
        }
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
    case VIR_DOMAIN_NET_TYPE_SERVER:
    case VIR_DOMAIN_NET_TYPE_MCAST:
        virBufferAddLit(&buf, "socket");
        switch (net->type) {
        case VIR_DOMAIN_NET_TYPE_CLIENT:
            virBufferVSprintf(&buf, "%cconnect=%s:%d",
                              type_sep,
                              net->data.socket.address,
                              net->data.socket.port);
            break;
        case VIR_DOMAIN_NET_TYPE_SERVER:
            virBufferVSprintf(&buf, "%clisten=%s:%d",
                              type_sep,
                              net->data.socket.address,
                              net->data.socket.port);
            break;
        case VIR_DOMAIN_NET_TYPE_MCAST:
            virBufferVSprintf(&buf, "%cmcast=%s:%d",
                              type_sep,
                              net->data.socket.address,
                              net->data.socket.port);
            break;
        case VIR_DOMAIN_NET_TYPE_USER:
        case VIR_DOMAIN_NET_TYPE_ETHERNET:
        case VIR_DOMAIN_NET_TYPE_NETWORK:
        case VIR_DOMAIN_NET_TYPE_BRIDGE:
        case VIR_DOMAIN_NET_TYPE_INTERNAL:
        case VIR_DOMAIN_NET_TYPE_DIRECT:
        case VIR_DOMAIN_NET_TYPE_LAST:
            break;
        }
        type_sep = ',';
        break;

    case VIR_DOMAIN_NET_TYPE_USER:
    default:
        virBufferAddLit(&buf, "user");
        break;
    }

    if (vlan >= 0) {
        virBufferVSprintf(&buf, "%cvlan=%d", type_sep, vlan);
        if (net->info.alias)
            virBufferVSprintf(&buf, ",name=host%s",
                              net->info.alias);
    } else {
        virBufferVSprintf(&buf, "%cid=host%s",
                          type_sep, net->info.alias);
    }

    if (vhostfd && *vhostfd) {
        virBufferVSprintf(&buf, ",vhost=on,vhostfd=%s", vhostfd);
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


char *
qemuBuildWatchdogDevStr(virDomainWatchdogDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    const char *model = virDomainWatchdogModelTypeToString(dev->model);
    if (!model) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("missing watchdog model"));
        goto error;
    }

    virBufferVSprintf(&buf, "%s", model);
    virBufferVSprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildMemballoonDevStr(virDomainMemballoonDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "virtio-balloon-pci");
    virBufferVSprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildUSBInputDevStr(virDomainInputDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferVSprintf(&buf, "%s",
                      dev->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                      "usb-mouse" : "usb-tablet");
    virBufferVSprintf(&buf, ",id=%s", dev->info.alias);

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildSoundDevStr(virDomainSoundDefPtr sound)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model = virDomainSoundModelTypeToString(sound->model);

    if (!model) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("invalid sound model"));
        goto error;
    }

    /* Hack for 2 wierdly unusal devices name in QEMU */
    if (STREQ(model, "es1370"))
        model = "ES1370";
    else if (STREQ(model, "ac97"))
        model = "AC97";

    virBufferVSprintf(&buf, "%s", model);
    virBufferVSprintf(&buf, ",id=%s", sound->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &sound->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static char *
qemuBuildVideoDevStr(virDomainVideoDefPtr video)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model = qemuVideoTypeToString(video->type);

    if (!model) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("invalid video model"));
        goto error;
    }

    virBufferVSprintf(&buf, "%s", model);
    virBufferVSprintf(&buf, ",id=%s", video->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &video->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


int
qemuOpenPCIConfig(virDomainHostdevDefPtr dev)
{
    char *path = NULL;
    int configfd = -1;

    if (virAsprintf(&path, "/sys/bus/pci/devices/%04x:%02x:%02x.%01x/config",
                    dev->source.subsys.u.pci.domain,
                    dev->source.subsys.u.pci.bus,
                    dev->source.subsys.u.pci.slot,
                    dev->source.subsys.u.pci.function) < 0) {
        virReportOOMError();
        return -1;
    }

    configfd = open(path, O_RDWR, 0);

    if (configfd < 0)
        virReportSystemError(errno, _("Failed opening %s"), path);

    VIR_FREE(path);

    return configfd;
}

char *
qemuBuildPCIHostdevDevStr(virDomainHostdevDefPtr dev, const char *configfd)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "pci-assign");
    virBufferVSprintf(&buf, ",host=%.2x:%.2x.%.1x",
                      dev->source.subsys.u.pci.bus,
                      dev->source.subsys.u.pci.slot,
                      dev->source.subsys.u.pci.function);
    virBufferVSprintf(&buf, ",id=%s", dev->info.alias);
    if (configfd && *configfd)
        virBufferVSprintf(&buf, ",configfd=%s", configfd);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info) < 0)
        goto error;

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildPCIHostdevPCIDevStr(virDomainHostdevDefPtr dev)
{
    char *ret = NULL;

    if (virAsprintf(&ret, "host=%.2x:%.2x.%.1x",
                    dev->source.subsys.u.pci.bus,
                    dev->source.subsys.u.pci.slot,
                    dev->source.subsys.u.pci.function) < 0)
        virReportOOMError();

    return ret;
}


char *
qemuBuildUSBHostdevDevStr(virDomainHostdevDefPtr dev)
{
    char *ret = NULL;

    if (!dev->source.subsys.u.usb.bus &&
        !dev->source.subsys.u.usb.device) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("USB host device is missing bus/device information"));
        return NULL;
    }

    if (virAsprintf(&ret, "usb-host,hostbus=%d,hostaddr=%d,id=%s",
                    dev->source.subsys.u.usb.bus,
                    dev->source.subsys.u.usb.device,
                    dev->info.alias) < 0)
        virReportOOMError();

    return ret;
}


char *
qemuBuildUSBHostdevUsbDevStr(virDomainHostdevDefPtr dev)
{
    char *ret = NULL;

    if (!dev->source.subsys.u.usb.bus &&
        !dev->source.subsys.u.usb.device) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                        _("USB host device is missing bus/device information"));
        return NULL;
    }

    if (virAsprintf(&ret, "host:%d.%d",
                    dev->source.subsys.u.usb.bus,
                    dev->source.subsys.u.usb.device) < 0)
        virReportOOMError();

    return ret;
}



/* This function outputs a -chardev command line option which describes only the
 * host side of the character device */
char *
qemuBuildChrChardevStr(virDomainChrDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool telnet;

    switch(dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferVSprintf(&buf, "null,id=%s", dev->info.alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferVSprintf(&buf, "vc,id=%s", dev->info.alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferVSprintf(&buf, "pty,id=%s", dev->info.alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferVSprintf(&buf, "tty,id=%s,path=%s", dev->info.alias, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferVSprintf(&buf, "file,id=%s,path=%s", dev->info.alias, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferVSprintf(&buf, "pipe,id=%s,path=%s", dev->info.alias, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferVSprintf(&buf, "stdio,id=%s", dev->info.alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferVSprintf(&buf,
                          "udp,id=%s,host=%s,port=%s,localaddr=%s,localport=%s",
                          dev->info.alias,
                          dev->data.udp.connectHost,
                          dev->data.udp.connectService,
                          dev->data.udp.bindHost,
                          dev->data.udp.bindService);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        telnet = dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        virBufferVSprintf(&buf,
                          "socket,id=%s,host=%s,port=%s%s%s",
                          dev->info.alias,
                          dev->data.tcp.host,
                          dev->data.tcp.service,
                          telnet ? ",telnet" : "",
                          dev->data.tcp.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferVSprintf(&buf,
                          "socket,id=%s,path=%s%s",
                          dev->info.alias,
                          dev->data.nix.path,
                          dev->data.nix.listen ? ",server,nowait" : "");
        break;
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildChrArgStr(virDomainChrDefPtr dev, const char *prefix)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (prefix)
        virBufferAdd(&buf, prefix, strlen(prefix));

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferAddLit(&buf, "null");
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferAddLit(&buf, "vc");
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAddLit(&buf, "pty");
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferStrcat(&buf, dev->data.file.path, NULL);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferVSprintf(&buf, "file:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferVSprintf(&buf, "pipe:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAddLit(&buf, "stdio");
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        virBufferVSprintf(&buf, "udp:%s:%s@%s:%s",
                          dev->data.udp.connectHost,
                          dev->data.udp.connectService,
                          dev->data.udp.bindHost,
                          dev->data.udp.bindService);
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET) {
            virBufferVSprintf(&buf, "telnet:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        } else {
            virBufferVSprintf(&buf, "tcp:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferVSprintf(&buf, "unix:%s%s",
                          dev->data.nix.path,
                          dev->data.nix.listen ? ",server,nowait" : "");
        break;
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


char *
qemuBuildVirtioSerialPortDevStr(virDomainChrDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE)
        virBufferAddLit(&buf, "virtconsole");
    else
        virBufferAddLit(&buf, "virtserialport");

    if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        /* Check it's a virtio-serial address */
        if (dev->info.type !=
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL)
        {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("virtio serial device has invalid address type"));
            goto error;
        }

        virBufferVSprintf(&buf,
                          ",bus=" QEMU_VIRTIO_SERIAL_PREFIX "%d.%d",
                          dev->info.addr.vioserial.controller,
                          dev->info.addr.vioserial.bus);
        virBufferVSprintf(&buf,
                          ",nr=%d",
                          dev->info.addr.vioserial.port);
    }

    virBufferVSprintf(&buf, ",chardev=%s", dev->info.alias);
    if (dev->target.name) {
        virBufferVSprintf(&buf, ",name=%s", dev->target.name);
    }
    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *qemuBuildSmbiosBiosStr(virSysinfoDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if ((def->bios_vendor == NULL) && (def->bios_version == NULL) &&
        (def->bios_date == NULL) && (def->bios_release == NULL))
        return(NULL);

    virBufferAddLit(&buf, "type=0");

    /* 0:Vendor */
    if (def->bios_vendor)
        virBufferVSprintf(&buf, ",vendor=%s", def->bios_vendor);
    /* 0:BIOS Version */
    if (def->bios_version)
        virBufferVSprintf(&buf, ",version=%s", def->bios_version);
    /* 0:BIOS Release Date */
    if (def->bios_date)
        virBufferVSprintf(&buf, ",date=%s", def->bios_date);
    /* 0:System BIOS Major Release and 0:System BIOS Minor Release */
    if (def->bios_release)
        virBufferVSprintf(&buf, ",release=%s", def->bios_release);

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return(NULL);
}

static char *qemuBuildSmbiosSystemStr(virSysinfoDefPtr def, bool skip_uuid)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if ((def->system_manufacturer == NULL) && (def->system_sku == NULL) &&
        (def->system_product == NULL) && (def->system_version == NULL) &&
        (def->system_serial == NULL) && (def->system_family == NULL) &&
        (def->system_uuid == NULL || skip_uuid))
        return NULL;

    virBufferAddLit(&buf, "type=1");

    /* 1:Manufacturer */
    if (def->system_manufacturer)
        virBufferVSprintf(&buf, ",manufacturer=%s",
                          def->system_manufacturer);
     /* 1:Product Name */
    if (def->system_product)
        virBufferVSprintf(&buf, ",product=%s", def->system_product);
    /* 1:Version */
    if (def->system_version)
        virBufferVSprintf(&buf, ",version=%s", def->system_version);
    /* 1:Serial Number */
    if (def->system_serial)
        virBufferVSprintf(&buf, ",serial=%s", def->system_serial);
    /* 1:UUID */
    if (def->system_uuid && !skip_uuid)
        virBufferVSprintf(&buf, ",uuid=%s", def->system_uuid);
    /* 1:SKU Number */
    if (def->system_sku)
        virBufferVSprintf(&buf, ",sku=%s", def->system_sku);
    /* 1:Family */
    if (def->system_family)
        virBufferVSprintf(&buf, ",family=%s", def->system_family);

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return(NULL);
}

static char *
qemuBuildClockArgStr(virDomainClockDefPtr def)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    switch (def->offset) {
    case VIR_DOMAIN_CLOCK_OFFSET_UTC:
        virBufferAddLit(&buf, "base=utc");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
    case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
        virBufferAddLit(&buf, "base=localtime");
        break;

    case VIR_DOMAIN_CLOCK_OFFSET_VARIABLE: {
        time_t now = time(NULL);
        struct tm nowbits;

        now += def->data.adjustment;
        gmtime_r(&now, &nowbits);

        virBufferVSprintf(&buf, "base=%d-%02d-%02dT%02d:%02d:%02d",
                          nowbits.tm_year + 1900,
                          nowbits.tm_mon + 1,
                          nowbits.tm_mday,
                          nowbits.tm_hour,
                          nowbits.tm_min,
                          nowbits.tm_sec);
    }   break;

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("unsupported clock offset '%s'"),
                        virDomainClockOffsetTypeToString(def->offset));
        goto error;
    }

    /* Look for an 'rtc' timer element, and add in appropriate clock= and driftfix= */
    int i;
    for (i = 0; i < def->ntimers; i++) {
        if (def->timers[i]->name == VIR_DOMAIN_TIMER_NAME_RTC) {
            switch (def->timers[i]->track) {
            case -1: /* unspecified - use hypervisor default */
                break;
            case VIR_DOMAIN_TIMER_TRACK_BOOT:
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("unsupported rtc timer track '%s'"),
                                virDomainTimerTrackTypeToString(def->timers[i]->track));
                goto error;
            case VIR_DOMAIN_TIMER_TRACK_GUEST:
                virBufferAddLit(&buf, ",clock=vm");
                break;
            case VIR_DOMAIN_TIMER_TRACK_WALL:
                virBufferAddLit(&buf, ",clock=host");
                break;
            }

            switch (def->timers[i]->tickpolicy) {
            case -1:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* This is the default - missed ticks delivered when
                   next scheduled, at normal rate */
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                /* deliver ticks at a faster rate until caught up */
                virBufferAddLit(&buf, ",driftfix=slew");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("unsupported rtc timer tickpolicy '%s'"),
                                virDomainTimerTickpolicyTypeToString(def->timers[i]->tickpolicy));
                goto error;
            }
            break; /* no need to check other timers - there is only one rtc */
        }
    }

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}


static int
qemuBuildCpuArgStr(const struct qemud_driver *driver,
                   const virDomainDefPtr def,
                   const char *emulator,
                   unsigned long long qemuCmdFlags,
                   const struct utsname *ut,
                   char **opt,
                   bool *hasHwVirt)
{
    const virCPUDefPtr host = driver->caps->host.cpu;
    virCPUDefPtr guest = NULL;
    unsigned int ncpus = 0;
    const char **cpus = NULL;
    union cpuData *data = NULL;
    int ret = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int i;

    *hasHwVirt = false;

    if (def->cpu && def->cpu->model) {
        if (qemuCapsProbeCPUModels(emulator, qemuCmdFlags, ut->machine,
                                   &ncpus, &cpus) < 0)
            goto cleanup;

        if (!ncpus || !host) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("CPU specification not supported by hypervisor"));
            goto cleanup;
        }
    }

    if (ncpus > 0 && host) {
        virCPUCompareResult cmp;
        const char *preferred;
        int hasSVM;

        cmp = cpuGuestData(host, def->cpu, &data);
        switch (cmp) {
        case VIR_CPU_COMPARE_INCOMPATIBLE:
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("guest CPU is not compatible with host CPU"));
            /* fall through */
        case VIR_CPU_COMPARE_ERROR:
            goto cleanup;

        default:
            break;
        }

        if (VIR_ALLOC(guest) < 0 || !(guest->arch = strdup(ut->machine)))
            goto no_memory;

        if (def->cpu->match == VIR_CPU_MATCH_MINIMUM)
            preferred = host->model;
        else
            preferred = def->cpu->model;

        guest->type = VIR_CPU_TYPE_GUEST;
        if (cpuDecode(guest, data, cpus, ncpus, preferred) < 0)
            goto cleanup;

        /* Only 'svm' requires --enable-nesting. The nested
         * 'vmx' patches now simply hook off the CPU features
         */
        hasSVM = cpuHasFeature(guest->arch, data, "svm");
        if (hasSVM < 0)
            goto cleanup;
        *hasHwVirt = hasSVM > 0 ? true : false;

        virBufferVSprintf(&buf, "%s", guest->model);
        for (i = 0; i < guest->nfeatures; i++) {
            char sign;
            if (guest->features[i].policy == VIR_CPU_FEATURE_DISABLE)
                sign = '-';
            else
                sign = '+';

            virBufferVSprintf(&buf, ",%c%s", sign, guest->features[i].name);
        }
    }
    else {
        /*
         * Need to force a 32-bit guest CPU type if
         *
         *  1. guest OS is i686
         *  2. host OS is x86_64
         *  3. emulator is qemu-kvm or kvm
         *
         * Or
         *
         *  1. guest OS is i686
         *  2. emulator is qemu-system-x86_64
         */
        if (STREQ(def->os.arch, "i686") &&
            ((STREQ(ut->machine, "x86_64") &&
              strstr(emulator, "kvm")) ||
             strstr(emulator, "x86_64")))
            virBufferAddLit(&buf, "qemu32");
    }

    if (virBufferError(&buf))
        goto no_memory;

    *opt = virBufferContentAndReset(&buf);

    ret = 0;

cleanup:
    virCPUDefFree(guest);
    cpuDataFree(ut->machine, data);

    if (cpus) {
        for (i = 0; i < ncpus; i++)
            VIR_FREE(cpus[i]);
        VIR_FREE(cpus);
    }

    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static char *
qemuBuildSmpArgStr(const virDomainDefPtr def,
                   unsigned long long qemuCmdFlags)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferVSprintf(&buf, "%u", def->vcpus);

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_SMP_TOPOLOGY)) {
        if (def->vcpus != def->maxvcpus)
            virBufferVSprintf(&buf, ",maxcpus=%u", def->maxvcpus);
        /* sockets, cores, and threads are either all zero
         * or all non-zero, thus checking one of them is enough */
        if (def->cpu && def->cpu->sockets) {
            virBufferVSprintf(&buf, ",sockets=%u", def->cpu->sockets);
            virBufferVSprintf(&buf, ",cores=%u", def->cpu->cores);
            virBufferVSprintf(&buf, ",threads=%u", def->cpu->threads);
        }
        else {
            virBufferVSprintf(&buf, ",sockets=%u", def->maxvcpus);
            virBufferVSprintf(&buf, ",cores=%u", 1);
            virBufferVSprintf(&buf, ",threads=%u", 1);
        }
    } else if (def->vcpus != def->maxvcpus) {
        virBufferFreeAndReset(&buf);
        /* FIXME - consider hot-unplugging cpus after boot for older qemu */
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("setting current vcpu count less than maximum is "
                          "not supported with this QEMU binary"));
        return NULL;
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


/*
 * Constructs a argv suitable for launching qemu with config defined
 * for a given virtual machine.
 *
 * XXX 'conn' is only required to resolve network -> bridge name
 * figure out how to remove this requirement some day
 */
virCommandPtr
qemuBuildCommandLine(virConnectPtr conn,
                     struct qemud_driver *driver,
                     virDomainDefPtr def,
                     virDomainChrDefPtr monitor_chr,
                     bool monitor_json,
                     unsigned long long qemuCmdFlags,
                     const char *migrateFrom,
                     virDomainSnapshotObjPtr current_snapshot,
                     enum virVMOperationType vmop)
{
    int i;
    char boot[VIR_DOMAIN_BOOT_LAST+1];
    struct utsname ut;
    int disableKQEMU = 0;
    int enableKQEMU = 0;
    int disableKVM = 0;
    int enableKVM = 0;
    const char *emulator;
    char uuid[VIR_UUID_STRING_BUFLEN];
    char *cpu;
    char *smp;
    int last_good_net = -1;
    bool hasHwVirt = false;
    virCommandPtr cmd;
    bool has_rbd_hosts = false;
    virBuffer rbd_hosts = VIR_BUFFER_INITIALIZER;

    uname_normalize(&ut);

    if (qemuAssignDeviceAliases(def, qemuCmdFlags) < 0)
        return NULL;

    virUUIDFormat(def->uuid, uuid);

    /* Migration is very annoying due to wildly varying syntax & capabilities
     * over time of KVM / QEMU codebases
     */
    if (migrateFrom) {
        if (STRPREFIX(migrateFrom, "tcp")) {
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_TCP)) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("TCP migration is not supported with this QEMU binary"));
                return NULL;
            }
        } else if (STREQ(migrateFrom, "stdio")) {
            if (qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC) {
                migrateFrom = "exec:cat";
            } else if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_KVM_STDIO)) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("STDIO migration is not supported with this QEMU binary"));
                return NULL;
            }
        } else if (STRPREFIX(migrateFrom, "exec")) {
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MIGRATE_QEMU_EXEC)) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("STDIO migration is not supported with this QEMU binary"));
                return NULL;
            }
        }
    }

    emulator = def->emulator;

    /*
     * do not use boot=on for drives when not using KVM since this
     * is not supported at all in upstream QEmu.
     */
    if ((qemuCmdFlags & QEMUD_CMD_FLAG_KVM) &&
        (def->virtType == VIR_DOMAIN_VIRT_QEMU) &&
        (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_BOOT))
        qemuCmdFlags -= QEMUD_CMD_FLAG_DRIVE_BOOT;

    switch (def->virtType) {
    case VIR_DOMAIN_VIRT_QEMU:
        if (qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU)
            disableKQEMU = 1;
        if (qemuCmdFlags & QEMUD_CMD_FLAG_KVM)
            disableKVM = 1;
        break;

    case VIR_DOMAIN_VIRT_KQEMU:
        if (qemuCmdFlags & QEMUD_CMD_FLAG_KVM)
            disableKVM = 1;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_ENABLE_KQEMU) {
            enableKQEMU = 1;
        } else if (!(qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU)) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("the QEMU binary %s does not support kqemu"),
                            emulator);
        }
        break;

    case VIR_DOMAIN_VIRT_KVM:
        if (qemuCmdFlags & QEMUD_CMD_FLAG_KQEMU)
            disableKQEMU = 1;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_ENABLE_KVM) {
            enableKVM = 1;
        } else if (!(qemuCmdFlags & QEMUD_CMD_FLAG_KVM)) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("the QEMU binary %s does not support kvm"),
                            emulator);
        }
        break;

    case VIR_DOMAIN_VIRT_XEN:
        /* XXX better check for xenner */
        break;

    default:
        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                        _("the QEMU binary %s does not support %s"),
                        emulator, virDomainVirtTypeToString(def->virtType));
        break;
    }

    cmd = virCommandNewArgList(emulator, "-S", NULL);

    virCommandAddEnvPassCommon(cmd);

    /* This should *never* be NULL, since we always provide
     * a machine in the capabilities data for QEMU. So this
     * check is just here as a safety in case the unexpected
     * happens */
    if (def->os.machine)
        virCommandAddArgList(cmd, "-M", def->os.machine, NULL);

    if (qemuBuildCpuArgStr(driver, def, emulator, qemuCmdFlags,
                           &ut, &cpu, &hasHwVirt) < 0)
        goto error;

    if (cpu) {
        virCommandAddArgList(cmd, "-cpu", cpu, NULL);
        VIR_FREE(cpu);

        if ((qemuCmdFlags & QEMUD_CMD_FLAG_NESTING) &&
            hasHwVirt)
            virCommandAddArg(cmd, "-enable-nesting");
    }

    if (disableKQEMU)
        virCommandAddArg(cmd, "-no-kqemu");
    else if (enableKQEMU)
        virCommandAddArgList(cmd, "-enable-kqemu", "-kernel-kqemu", NULL);
    if (disableKVM)
        virCommandAddArg(cmd, "-no-kvm");
    if (enableKVM)
        virCommandAddArg(cmd, "-enable-kvm");

    /* Set '-m MB' based on maxmem, because the lower 'memory' limit
     * is set post-startup using the balloon driver. If balloon driver
     * is not supported, then they're out of luck anyway
     */
    virCommandAddArg(cmd, "-m");
    virCommandAddArgFormat(cmd, "%lu", def->mem.max_balloon / 1024);
    if (def->mem.hugepage_backed) {
        if (!driver->hugetlbfs_mount) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("hugetlbfs filesystem is not mounted"));
            goto error;
        }
        if (!driver->hugepage_path) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("hugepages are disabled by administrator config"));
            goto error;
        }
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_MEM_PATH)) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("hugepage backing not supported by '%s'"),
                            def->emulator);
            goto error;
        }
        virCommandAddArgList(cmd, "-mem-prealloc", "-mem-path",
                             driver->hugepage_path, NULL);
    }

    virCommandAddArg(cmd, "-smp");
    if (!(smp = qemuBuildSmpArgStr(def, qemuCmdFlags)))
        goto error;
    virCommandAddArg(cmd, smp);
    VIR_FREE(smp);

    if (qemuCmdFlags & QEMUD_CMD_FLAG_NAME) {
        virCommandAddArg(cmd, "-name");
        if (driver->setProcessName &&
            (qemuCmdFlags & QEMUD_CMD_FLAG_NAME_PROCESS)) {
            virCommandAddArgFormat(cmd, "%s,process=qemu:%s",
                                   def->name, def->name);
        } else {
            virCommandAddArg(cmd, def->name);
        }
    }
    if (qemuCmdFlags & QEMUD_CMD_FLAG_UUID)
        virCommandAddArgList(cmd, "-uuid", uuid, NULL);
    if (def->virtType == VIR_DOMAIN_VIRT_XEN ||
        STREQ(def->os.type, "xen") ||
        STREQ(def->os.type, "linux")) {
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DOMID) {
            virCommandAddArg(cmd, "-domid");
            virCommandAddArgFormat(cmd, "%d", def->id);
        } else if (qemuCmdFlags & QEMUD_CMD_FLAG_XEN_DOMID) {
            virCommandAddArg(cmd, "-xen-attach");
            virCommandAddArg(cmd, "-xen-domid");
            virCommandAddArgFormat(cmd, "%d", def->id);
        } else {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("qemu emulator '%s' does not support xen"),
                            def->emulator);
            goto error;
        }
    }

    if ((def->os.smbios_mode != VIR_DOMAIN_SMBIOS_NONE) &&
        (def->os.smbios_mode != VIR_DOMAIN_SMBIOS_EMULATE)) {
        virSysinfoDefPtr source = NULL;
        bool skip_uuid = false;

        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_SMBIOS_TYPE)) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                    _("the QEMU binary %s does not support smbios settings"),
                            emulator);
            goto error;
        }

        /* should we really error out or just warn in those cases ? */
        if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
            if (driver->hostsysinfo == NULL) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("Host SMBIOS information is not available"));
                goto error;
            }
            source = driver->hostsysinfo;
            /* Host and guest uuid must differ, by definition of UUID. */
            skip_uuid = true;
        } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_SYSINFO) {
            if (def->sysinfo == NULL) {
                qemuReportError(VIR_ERR_XML_ERROR,
                            _("Domain '%s' sysinfo are not available"),
                               def->name);
                goto error;
            }
            source = def->sysinfo;
            /* domain_conf guaranteed that system_uuid matches guest uuid. */
        }
        if (source != NULL) {
            char *smbioscmd;

            smbioscmd = qemuBuildSmbiosBiosStr(source);
            if (smbioscmd != NULL) {
                virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
                VIR_FREE(smbioscmd);
            }
            smbioscmd = qemuBuildSmbiosSystemStr(source, skip_uuid);
            if (smbioscmd != NULL) {
                virCommandAddArgList(cmd, "-smbios", smbioscmd, NULL);
                VIR_FREE(smbioscmd);
            }
        }
    }

    /*
     * NB, -nographic *MUST* come before any serial, or monitor
     * or parallel port flags due to QEMU craziness, where it
     * decides to change the serial port & monitor to be on stdout
     * if you ask for nographic. So we have to make sure we override
     * these defaults ourselves...
     */
    if (!def->graphics)
        virCommandAddArg(cmd, "-nographic");

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        if (qemuCmdFlags & QEMUD_CMD_FLAG_NODEFCONFIG)
            virCommandAddArg(cmd,
                             "-nodefconfig"); /* Disable global config files */
        virCommandAddArg(cmd,
                         "-nodefaults");  /* Disable default guest devices */
    }

    if (monitor_chr) {
        char *chrdev;
        /* Use -chardev if it's available */
        if (qemuCmdFlags & QEMUD_CMD_FLAG_CHARDEV) {

            virCommandAddArg(cmd, "-chardev");
            if (!(chrdev = qemuBuildChrChardevStr(monitor_chr)))
                goto error;
            virCommandAddArg(cmd, chrdev);
            VIR_FREE(chrdev);

            virCommandAddArg(cmd, "-mon");
            virCommandAddArgFormat(cmd, "chardev=monitor,mode=%s",
                                   monitor_json ? "control" : "readline");
        } else {
            const char *prefix = NULL;
            if (monitor_json)
                prefix = "control,";

            virCommandAddArg(cmd, "-monitor");
            if (!(chrdev = qemuBuildChrArgStr(monitor_chr, prefix)))
                goto error;
            virCommandAddArg(cmd, chrdev);
            VIR_FREE(chrdev);
        }
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_RTC) {
        const char *rtcopt;
        virCommandAddArg(cmd, "-rtc");
        if (!(rtcopt = qemuBuildClockArgStr(&def->clock)))
            goto error;
        virCommandAddArg(cmd, rtcopt);
        VIR_FREE(rtcopt);
    } else {
        switch (def->clock.offset) {
        case VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME:
        case VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE:
            virCommandAddArg(cmd, "-localtime");
            break;

        case VIR_DOMAIN_CLOCK_OFFSET_UTC:
            /* Nothing, its the default */
            break;

        default:
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("unsupported clock offset '%s'"),
                            virDomainClockOffsetTypeToString(def->clock.offset));
            goto error;
        }
    }
    if (def->clock.offset == VIR_DOMAIN_CLOCK_OFFSET_TIMEZONE &&
        def->clock.data.timezone) {
        virCommandAddEnvPair(cmd, "TZ", def->clock.data.timezone);
    }

    for (i = 0; i < def->clock.ntimers; i++) {
        switch (def->clock.timers[i]->name) {
        default:
        case VIR_DOMAIN_TIMER_NAME_PLATFORM:
        case VIR_DOMAIN_TIMER_NAME_TSC:
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("unsupported timer type (name) '%s'"),
                            virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            goto error;

        case VIR_DOMAIN_TIMER_NAME_RTC:
            /* This has already been taken care of (in qemuBuildClockArgStr)
               if QEMUD_CMD_FLAG_RTC is set (mutually exclusive with
               QEMUD_FLAG_RTC_TD_HACK) */
            if (qemuCmdFlags & QEMUD_CMD_FLAG_RTC_TD_HACK) {
                switch (def->clock.timers[i]->tickpolicy) {
                case -1:
                case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                    /* the default - do nothing */
                    break;
                case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                    virCommandAddArg(cmd, "-rtc-td-hack");
                    break;
                case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
                case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                    qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                    _("unsupported rtc tickpolicy '%s'"),
                                    virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
                }
            } else if (!(qemuCmdFlags & QEMUD_CMD_FLAG_RTC)
                       && (def->clock.timers[i]->tickpolicy
                           != VIR_DOMAIN_TIMER_TICKPOLICY_DELAY)
                       && (def->clock.timers[i]->tickpolicy != -1)) {
                /* a non-default rtc policy was given, but there is no
                   way to implement it in this version of qemu */
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("unsupported rtc tickpolicy '%s'"),
                                virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_PIT:
            switch (def->clock.timers[i]->tickpolicy) {
            case -1:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DELAY:
                /* delay is the default if we don't have kernel
                   (-no-kvm-pit), otherwise, the default is catchup. */
                if (qemuCmdFlags & QEMUD_CMD_FLAG_NO_KVM_PIT)
                    virCommandAddArg(cmd, "-no-kvm-pit-reinjection");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                if (qemuCmdFlags & QEMUD_CMD_FLAG_NO_KVM_PIT) {
                    /* do nothing - this is default for kvm-pit */
                } else if (qemuCmdFlags & QEMUD_CMD_FLAG_TDF) {
                    /* -tdf switches to 'catchup' with userspace pit. */
                    virCommandAddArg(cmd, "-tdf");
                } else {
                    /* can't catchup if we have neither pit mode */
                    qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                    _("unsupported pit tickpolicy '%s'"),
                                    virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                    goto error;
                }
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                /* no way to support these modes for pit in qemu */
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("unsupported pit tickpolicy '%s'"),
                                virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
            }
            break;

        case VIR_DOMAIN_TIMER_NAME_HPET:
            /* the only meaningful attribute for hpet is "present". If
             * present is -1, that means it wasn't specified, and
             * should be left at the default for the
             * hypervisor. "default" when -no-hpet exists is "yes",
             * and when -no-hpet doesn't exist is "no". "confusing"?
             * "yes"! */

            if (qemuCmdFlags & QEMUD_CMD_FLAG_NO_HPET) {
                if (def->clock.timers[i]->present == 0)
                    virCommandAddArg(cmd, "-no-hpet");
            } else {
                /* no hpet timer available. The only possible action
                   is to raise an error if present="yes" */
                if (def->clock.timers[i]->present == 1) {
                    qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                    "%s", _("pit timer is not supported"));
                }
            }
            break;
        }
    }

    if ((qemuCmdFlags & QEMUD_CMD_FLAG_NO_REBOOT) &&
        def->onReboot != VIR_DOMAIN_LIFECYCLE_RESTART)
        virCommandAddArg(cmd, "-no-reboot");

    if (!(def->features & (1 << VIR_DOMAIN_FEATURE_ACPI)))
        virCommandAddArg(cmd, "-no-acpi");

    if (!def->os.bootloader) {
        for (i = 0 ; i < def->os.nBootDevs ; i++) {
            switch (def->os.bootDevs[i]) {
            case VIR_DOMAIN_BOOT_CDROM:
                boot[i] = 'd';
                break;
            case VIR_DOMAIN_BOOT_FLOPPY:
                boot[i] = 'a';
                break;
            case VIR_DOMAIN_BOOT_DISK:
                boot[i] = 'c';
                break;
            case VIR_DOMAIN_BOOT_NET:
                boot[i] = 'n';
                break;
            default:
                boot[i] = 'c';
                break;
            }
        }
        if (def->os.nBootDevs) {
            virBuffer boot_buf = VIR_BUFFER_INITIALIZER;
            virCommandAddArg(cmd, "-boot");

            boot[def->os.nBootDevs] = '\0';

            if (qemuCmdFlags & QEMUD_CMD_FLAG_BOOT_MENU &&
                def->os.bootmenu != VIR_DOMAIN_BOOT_MENU_DEFAULT) {
                if (def->os.bootmenu == VIR_DOMAIN_BOOT_MENU_ENABLED)
                    virBufferVSprintf(&boot_buf, "order=%s,menu=on", boot);
                else if (def->os.bootmenu == VIR_DOMAIN_BOOT_MENU_DISABLED)
                    virBufferVSprintf(&boot_buf, "order=%s,menu=off", boot);
            } else {
                virBufferVSprintf(&boot_buf, "%s", boot);
            }

            virCommandAddArgBuffer(cmd, &boot_buf);
        }

        if (def->os.kernel)
            virCommandAddArgList(cmd, "-kernel", def->os.kernel, NULL);
        if (def->os.initrd)
            virCommandAddArgList(cmd, "-initrd", def->os.initrd, NULL);
        if (def->os.cmdline)
            virCommandAddArgList(cmd, "-append", def->os.cmdline, NULL);
    } else {
        virCommandAddArgList(cmd, "-bootloader", def->os.bootloader, NULL);
    }

    for (i = 0 ; i < def->ndisks ; i++) {
        virDomainDiskDefPtr disk = def->disks[i];

        if (disk->driverName != NULL &&
            !STREQ(disk->driverName, "qemu")) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("unsupported driver name '%s' for disk '%s'"),
                            disk->driverName, disk->src);
            goto error;
        }
    }

    if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
        for (i = 0 ; i < def->ncontrollers ; i++) {
            virDomainControllerDefPtr cont = def->controllers[i];

            /* We don't add an explicit IDE or FD controller because the
             * provided PIIX4 device already includes one. It isn't possible to
             * remove the PIIX4. */
            if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE ||
                cont->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC)
                continue;

            /* QEMU doesn't implement a SATA driver */
            if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("SATA is not supported with this QEMU binary"));
                goto error;
            }

            virCommandAddArg(cmd, "-device");

            char *devstr;
            if (!(devstr = qemuBuildControllerDevStr(def->controllers[i])))
                goto no_memory;

            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
        }
    }

    /* If QEMU supports -drive param instead of old -hda, -hdb, -cdrom .. */
    if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE) {
        int bootCD = 0, bootFloppy = 0, bootDisk = 0;

        /* If QEMU supports boot=on for -drive param... */
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DRIVE_BOOT) {
            for (i = 0 ; i < def->os.nBootDevs ; i++) {
                switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_CDROM:
                    bootCD = 1;
                    break;
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootFloppy = 1;
                    break;
                case VIR_DOMAIN_BOOT_DISK:
                    bootDisk = 1;
                    break;
                }
            }
        }

        for (i = 0 ; i < def->ndisks ; i++) {
            char *optstr;
            int bootable = 0;
            virDomainDiskDefPtr disk = def->disks[i];
            int withDeviceArg = 0;
            int j;

            /* Unless we have -device, then USB disks need special
               handling */
            if ((disk->bus == VIR_DOMAIN_DISK_BUS_USB) &&
                !(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    virCommandAddArg(cmd, "-usbdevice");
                    virCommandAddArgFormat(cmd, "disk:%s", disk->src);
                } else {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("unsupported usb disk type for '%s'"),
                                    disk->src);
                    goto error;
                }
                continue;
            }

            switch (disk->device) {
            case VIR_DOMAIN_DISK_DEVICE_CDROM:
                bootable = bootCD;
                bootCD = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                bootable = bootFloppy;
                bootFloppy = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_DISK:
                bootable = bootDisk;
                bootDisk = 0;
                break;
            }

            virCommandAddArg(cmd, "-drive");

            /* Unfortunately it is not possible to use
               -device for floppies, or Xen paravirt
               devices. Fortunately, those don't need
               static PCI addresses, so we don't really
               care that we can't use -device */
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
                (disk->bus != VIR_DOMAIN_DISK_BUS_XEN))
                withDeviceArg = 1;
            if (!(optstr = qemuBuildDriveStr(disk, bootable,
                                             (withDeviceArg ? qemuCmdFlags :
                                              (qemuCmdFlags & ~QEMUD_CMD_FLAG_DEVICE)))))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);

            if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_RBD) {
                for (j = 0 ; j < disk->nhosts ; j++) {
                    if (!has_rbd_hosts) {
                        virBufferAddLit(&rbd_hosts, "CEPH_ARGS=-m ");
                        has_rbd_hosts = true;
                    } else {
                        virBufferAddLit(&rbd_hosts, ",");
                    }
                    virDomainDiskHostDefPtr host = &disk->hosts[j];
                    if (host->port) {
                        virBufferVSprintf(&rbd_hosts, "%s:%s",
                                          host->name,
                                          host->port);
                    } else {
                        virBufferVSprintf(&rbd_hosts, "%s",
                                          host->name);
                    }
                }
            }

            if (withDeviceArg) {
                if (disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
                    virCommandAddArg(cmd, "-global");
                    virCommandAddArgFormat(cmd, "isa-fdc.drive%c=drive-%s",
                                           disk->info.addr.drive.unit
                                           ? 'B' : 'A',
                                           disk->info.alias);
                } else {
                    virCommandAddArg(cmd, "-device");

                    if (!(optstr = qemuBuildDriveDevStr(disk)))
                        goto error;
                    virCommandAddArg(cmd, optstr);
                    VIR_FREE(optstr);
                }
            }
        }
    } else {
        for (i = 0 ; i < def->ndisks ; i++) {
            char dev[NAME_MAX];
            char file[PATH_MAX];
            virDomainDiskDefPtr disk = def->disks[i];
            int j;

            if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    virCommandAddArg(cmd, "-usbdevice");
                    virCommandAddArgFormat(cmd, "disk:%s", disk->src);
                } else {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("unsupported usb disk type for '%s'"),
                                    disk->src);
                    goto error;
                }
                continue;
            }

            if (STREQ(disk->dst, "hdc") &&
                disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
                if (disk->src) {
                    snprintf(dev, NAME_MAX, "-%s", "cdrom");
                } else {
                    continue;
                }
            } else {
                if (STRPREFIX(disk->dst, "hd") ||
                    STRPREFIX(disk->dst, "fd")) {
                    snprintf(dev, NAME_MAX, "-%s", disk->dst);
                } else {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("unsupported disk type '%s'"), disk->dst);
                    goto error;
                }
            }

            if (disk->type == VIR_DOMAIN_DISK_TYPE_DIR) {
                /* QEMU only supports magic FAT format for now */
                if (disk->driverType &&
                    STRNEQ(disk->driverType, "fat")) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("unsupported disk driver type for '%s'"),
                                    disk->driverType);
                    goto error;
                }
                if (!disk->readonly) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                    _("cannot create virtual FAT disks in read-write mode"));
                    goto error;
                }
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                    snprintf(file, PATH_MAX, "fat:floppy:%s", disk->src);
                else
                    snprintf(file, PATH_MAX, "fat:%s", disk->src);
            } else if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
                switch (disk->protocol) {
                case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                    if (disk->nhosts != 1) {
                        qemuReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                        _("NBD accepts only one host"));
                        goto error;
                    }
                    snprintf(file, PATH_MAX, "nbd:%s:%s,",
                             disk->hosts->name, disk->hosts->port);
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                    snprintf(file, PATH_MAX, "rbd:%s,", disk->src);
                    for (j = 0 ; j < disk->nhosts ; j++) {
                        if (!has_rbd_hosts) {
                            virBufferAddLit(&rbd_hosts, "CEPH_ARGS=-m ");
                            has_rbd_hosts = true;
                        } else {
                            virBufferAddLit(&rbd_hosts, ",");
                        }
                        virDomainDiskHostDefPtr host = &disk->hosts[j];
                        if (host->port) {
                            virBufferVSprintf(&rbd_hosts, "%s:%s",
                                              host->name,
                                              host->port);
                        } else {
                            virBufferVSprintf(&rbd_hosts, "%s",
                                              host->name);
                        }
                    }
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                    if (disk->nhosts == 0)
                        snprintf(file, PATH_MAX, "sheepdog:%s,", disk->src);
                    else
                        /* only one host is supported now */
                        snprintf(file, PATH_MAX, "sheepdog:%s:%s:%s,",
                                 disk->hosts->name, disk->hosts->port,
                                 disk->src);
                    break;
                }
            } else {
                snprintf(file, PATH_MAX, "%s", disk->src);
            }

            virCommandAddArgList(cmd, dev, file, NULL);
        }
    }

    if (has_rbd_hosts)
        virCommandAddEnvBuffer(cmd, &rbd_hosts);

    if (qemuCmdFlags & QEMUD_CMD_FLAG_FSDEV) {
        for (i = 0 ; i < def->nfss ; i++) {
            char *optstr;
            virDomainFSDefPtr fs = def->fss[i];

            virCommandAddArg(cmd, "-fsdev");
            if (!(optstr = qemuBuildFSStr(fs, qemuCmdFlags)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);

            virCommandAddArg(cmd, "-device");
            if (!(optstr = qemuBuildFSDevStr(fs)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        }
    } else {
        if (def->nfss) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("filesystem passthrough not supported by this QEMU"));
            goto error;
        }
    }

    if (!def->nnets) {
        /* If we have -device, then we set -nodefault already */
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
            virCommandAddArgList(cmd, "-net", "none", NULL);
    } else {
        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr net = def->nets[i];
            char *nic, *host;
            char tapfd_name[50];
            char vhostfd_name[50] = "";
            int vlan;

            /* VLANs are not used with -netdev, so don't record them */
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
                (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
                vlan = -1;
            else
                vlan = i;

            if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK ||
                net->type == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                int tapfd = qemuNetworkIfaceConnect(conn, driver, net,
                                                    qemuCmdFlags);
                if (tapfd < 0)
                    goto error;

                last_good_net = i;
                virCommandTransferFD(cmd, tapfd);

                if (snprintf(tapfd_name, sizeof(tapfd_name), "%d",
                             tapfd) >= sizeof(tapfd_name))
                    goto no_memory;
            } else if (net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
                int tapfd = qemuPhysIfaceConnect(conn, driver, net,
                                                 qemuCmdFlags,
                                                 def->uuid,
                                                 vmop);
                if (tapfd < 0)
                    goto error;

                last_good_net = i;
                virCommandTransferFD(cmd, tapfd);

                if (snprintf(tapfd_name, sizeof(tapfd_name), "%d",
                             tapfd) >= sizeof(tapfd_name))
                    goto no_memory;
            }

            if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK ||
                net->type == VIR_DOMAIN_NET_TYPE_BRIDGE ||
                net->type == VIR_DOMAIN_NET_TYPE_DIRECT) {
                /* Attempt to use vhost-net mode for these types of
                   network device */
                int vhostfd = qemuOpenVhostNet(net, qemuCmdFlags);
                if (vhostfd >= 0) {
                    virCommandTransferFD(cmd, vhostfd);

                    if (snprintf(vhostfd_name, sizeof(vhostfd_name), "%d",
                                 vhostfd) >= sizeof(vhostfd_name))
                        goto no_memory;
                }
            }
            /* Possible combinations:
             *
             *  1. Old way:   -net nic,model=e1000,vlan=1 -net tap,vlan=1
             *  2. Semi-new:  -device e1000,vlan=1        -net tap,vlan=1
             *  3. Best way:  -netdev type=tap,id=netdev1 -device e1000,id=netdev1
             *
             * NB, no support for -netdev without use of -device
             */
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
                (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                virCommandAddArg(cmd, "-netdev");
                if (!(host = qemuBuildHostNetStr(net, ',', vlan,
                                                 tapfd_name, vhostfd_name)))
                    goto error;
                virCommandAddArg(cmd, host);
                VIR_FREE(host);
            }
            if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
                virCommandAddArg(cmd, "-device");
                if (!(nic = qemuBuildNicDevStr(net, vlan)))
                    goto error;
                virCommandAddArg(cmd, nic);
                VIR_FREE(nic);
            } else {
                virCommandAddArg(cmd, "-net");
                if (!(nic = qemuBuildNicStr(net, "nic,", vlan)))
                    goto error;
                virCommandAddArg(cmd, nic);
                VIR_FREE(nic);
            }
            if (!((qemuCmdFlags & QEMUD_CMD_FLAG_NETDEV) &&
                  (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))) {
                virCommandAddArg(cmd, "-net");
                if (!(host = qemuBuildHostNetStr(net, ',', vlan,
                                                 tapfd_name, vhostfd_name)))
                    goto error;
                virCommandAddArg(cmd, host);
                VIR_FREE(host);
            }
        }
    }

    if (!def->nserials) {
        /* If we have -device, then we set -nodefault already */
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
            virCommandAddArgList(cmd, "-serial", "none", NULL);
    } else {
        for (i = 0 ; i < def->nserials ; i++) {
            virDomainChrDefPtr serial = def->serials[i];
            char *devstr;

            /* Use -chardev with -device if they are available */
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_CHARDEV) &&
                (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(serial)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);

                virCommandAddArg(cmd, "-device");
                virCommandAddArgFormat(cmd, "isa-serial,chardev=%s",
                                       serial->info.alias);
            } else {
                virCommandAddArg(cmd, "-serial");
                if (!(devstr = qemuBuildChrArgStr(serial, NULL)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    if (!def->nparallels) {
        /* If we have -device, then we set -nodefault already */
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE))
            virCommandAddArgList(cmd, "-parallel", "none", NULL);
    } else {
        for (i = 0 ; i < def->nparallels ; i++) {
            virDomainChrDefPtr parallel = def->parallels[i];
            char *devstr;

            /* Use -chardev with -device if they are available */
            if ((qemuCmdFlags & QEMUD_CMD_FLAG_CHARDEV) &&
                (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(parallel)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);

                virCommandAddArg(cmd, "-device");
                virCommandAddArgFormat(cmd, "isa-parallel,chardev=%s",
                                       parallel->info.alias);
            } else {
                virCommandAddArg(cmd, "-parallel");
                if (!(devstr = qemuBuildChrArgStr(parallel, NULL)))
                      goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    for (i = 0 ; i < def->nchannels ; i++) {
        virDomainChrDefPtr channel = def->channels[i];
        char *devstr;

        switch(channel->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_CHARDEV) ||
                !(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("guestfwd requires QEMU to support -chardev & -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(channel)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            char *addr = virSocketFormatAddr(channel->target.addr);
            if (!addr)
                goto error;
            int port = virSocketGetPort(channel->target.addr);

            virCommandAddArg(cmd, "-netdev");
            virCommandAddArgFormat(cmd,
                                   "user,guestfwd=tcp:%s:%i,chardev=%s,id=user-%s",
                                   addr, port, channel->info.alias,
                                   channel->info.alias);
            VIR_FREE(addr);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                    _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(channel)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virCommandAddArg(cmd, "-device");
            if (!(devstr = qemuBuildVirtioSerialPortDevStr(channel)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
            break;
        }
    }

    /* Explicit console devices */
    if (def->console) {
        virDomainChrDefPtr console = def->console;
        char *devstr;

        switch(console->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
            if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE)) {
                qemuReportError(VIR_ERR_NO_SUPPORT, "%s",
                    _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(console)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virCommandAddArg(cmd, "-device");
            if (!(devstr = qemuBuildVirtioSerialPortDevStr(console)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            break;

        default:
            qemuReportError(VIR_ERR_NO_SUPPORT,
                            _("unsupported console target type %s"),
                            NULLSTR(virDomainChrConsoleTargetTypeToString(console->targetType)));
            goto error;
        }
    }

    virCommandAddArg(cmd, "-usb");
    for (i = 0 ; i < def->ninputs ; i++) {
        virDomainInputDefPtr input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
                char *optstr;
                virCommandAddArg(cmd, "-device");
                if (!(optstr = qemuBuildUSBInputDevStr(input)))
                    goto error;
                virCommandAddArg(cmd, optstr);
                VIR_FREE(optstr);
            } else {
                virCommandAddArgList(cmd, "-usbdevice",
                                     input->type == VIR_DOMAIN_INPUT_TYPE_MOUSE
                                     ? "mouse" : "tablet", NULL);
            }
        }
    }

    if (def->ngraphics > 1) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("only 1 graphics device is supported"));
        goto error;
    }

    if ((def->ngraphics == 1) &&
        def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_VNC_COLON) {
            if (def->graphics[0]->data.vnc.listenAddr)
                virBufferAdd(&opt, def->graphics[0]->data.vnc.listenAddr, -1);
            else if (driver->vncListen)
                virBufferAdd(&opt, driver->vncListen, -1);

            virBufferVSprintf(&opt, ":%d",
                              def->graphics[0]->data.vnc.port - 5900);

            if (def->graphics[0]->data.vnc.auth.passwd ||
                driver->vncPassword)
                virBufferAddLit(&opt, ",password");

            if (driver->vncTLS) {
                virBufferAddLit(&opt, ",tls");
                if (driver->vncTLSx509verify) {
                    virBufferVSprintf(&opt, ",x509verify=%s",
                                      driver->vncTLSx509certdir);
                } else {
                    virBufferVSprintf(&opt, ",x509=%s",
                                      driver->vncTLSx509certdir);
                }
            }

            if (driver->vncSASL) {
                virBufferAddLit(&opt, ",sasl");

                if (driver->vncSASLdir)
                    virCommandAddEnvPair(cmd, "SASL_CONF_DIR",
                                         driver->vncSASLdir);

                /* TODO: Support ACLs later */
            }
        } else {
            virBufferVSprintf(&opt, "%d",
                              def->graphics[0]->data.vnc.port - 5900);
        }

        virCommandAddArg(cmd, "-vnc");
        virCommandAddArgBuffer(cmd, &opt);
        if (def->graphics[0]->data.vnc.keymap) {
            virCommandAddArgList(cmd, "-k", def->graphics[0]->data.vnc.keymap,
                                 NULL);
        }

        /* Unless user requested it, set the audio backend to none, to
         * prevent it opening the host OS audio devices, since that causes
         * security issues and might not work when using VNC.
         */
        if (driver->vncAllowHostAudio) {
            virCommandAddEnvPass(cmd, "QEMU_AUDIO_DRV");
        } else {
            virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=none");
        }
    } else if ((def->ngraphics == 1) &&
               def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        if (def->graphics[0]->data.sdl.xauth)
            virCommandAddEnvPair(cmd, "XAUTHORITY",
                                 def->graphics[0]->data.sdl.xauth);
        if (def->graphics[0]->data.sdl.display)
            virCommandAddEnvPair(cmd, "DISPLAY",
                                 def->graphics[0]->data.sdl.display);
        if (def->graphics[0]->data.sdl.fullscreen)
            virCommandAddArg(cmd, "-full-screen");

        /* If using SDL for video, then we should just let it
         * use QEMU's host audio drivers, possibly SDL too
         * User can set these two before starting libvirtd
         */
        virCommandAddEnvPass(cmd, "QEMU_AUDIO_DRV");
        virCommandAddEnvPass(cmd, "SDL_AUDIODRIVER");

        /* New QEMU has this flag to let us explicitly ask for
         * SDL graphics. This is better than relying on the
         * default, since the default changes :-( */
        if (qemuCmdFlags & QEMUD_CMD_FLAG_SDL)
            virCommandAddArg(cmd, "-sdl");

    } else if ((def->ngraphics == 1) &&
               def->graphics[0]->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;

        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_SPICE)) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                            _("spice graphics are not supported with this QEMU"));
            goto error;
        }

        virBufferVSprintf(&opt, "port=%u", def->graphics[0]->data.spice.port);

        if (driver->spiceTLS && def->graphics[0]->data.spice.tlsPort != -1)
            virBufferVSprintf(&opt, ",tls-port=%u", def->graphics[0]->data.spice.tlsPort);

        if (def->graphics[0]->data.spice.listenAddr)
            virBufferVSprintf(&opt, ",addr=%s", def->graphics[0]->data.spice.listenAddr);
        else if (driver->spiceListen)
            virBufferVSprintf(&opt, ",addr=%s", driver->spiceListen);

        /* In the password case we set it via monitor command, to avoid
         * making it visible on CLI, so there's no use of password=XXX
         * in this bit of the code */
        if (!def->graphics[0]->data.spice.auth.passwd &&
            !driver->spicePassword)
            virBufferAddLit(&opt, ",disable-ticketing");

        if (driver->spiceTLS)
            virBufferVSprintf(&opt, ",x509-dir=%s",
                              driver->spiceTLSx509certdir);

        for (i = 0 ; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST ; i++) {
            int mode = def->graphics[0]->data.spice.channels[i];
            switch (mode) {
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                virBufferVSprintf(&opt, ",tls-channel=%s",
                                  virDomainGraphicsSpiceChannelNameTypeToString(i));
                break;
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                virBufferVSprintf(&opt, ",plaintext-channel=%s",
                                  virDomainGraphicsSpiceChannelNameTypeToString(i));
                break;
            }
        }

        virCommandAddArg(cmd, "-spice");
        virCommandAddArgBuffer(cmd, &opt);
        if (def->graphics[0]->data.spice.keymap)
            virCommandAddArgList(cmd, "-k",
                                 def->graphics[0]->data.spice.keymap, NULL);
        /* SPICE includes native support for tunnelling audio, so we
         * set the audio backend to point at SPICE's own driver
         */
        virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=spice");

    } else if ((def->ngraphics == 1)) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("unsupported graphics type '%s'"),
                    virDomainGraphicsTypeToString(def->graphics[0]->type));
        goto error;
    }

    if (def->nvideos > 0) {
        if (qemuCmdFlags & QEMUD_CMD_FLAG_VGA) {
            if (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_XEN) {
                /* nothing - vga has no effect on Xen pvfb */
            } else {
                if ((def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_QXL) &&
                    !(qemuCmdFlags & QEMUD_CMD_FLAG_VGA_QXL)) {
                    qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                    _("This QEMU does not support QXL graphics adapters"));
                    goto error;
                }

                const char *vgastr = qemuVideoTypeToString(def->videos[0]->type);
                if (!vgastr || STREQ(vgastr, "")) {
                    qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                    _("video type %s is not supported with QEMU"),
                                    virDomainVideoTypeToString(def->videos[0]->type));
                    goto error;
                }

                virCommandAddArgList(cmd, "-vga", vgastr, NULL);
            }
        } else {

            switch (def->videos[0]->type) {
            case VIR_DOMAIN_VIDEO_TYPE_VGA:
                virCommandAddArg(cmd, "-std-vga");
                break;

            case VIR_DOMAIN_VIDEO_TYPE_VMVGA:
                virCommandAddArg(cmd, "-vmwarevga");
                break;

            case VIR_DOMAIN_VIDEO_TYPE_XEN:
            case VIR_DOMAIN_VIDEO_TYPE_CIRRUS:
                /* No special args - this is the default */
                break;

            default:
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                _("video type %s is not supported with this QEMU"),
                                virDomainVideoTypeToString(def->videos[0]->type));
                goto error;
            }
        }

        if (def->nvideos > 1) {
            if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
                for (i = 1 ; i < def->nvideos ; i++) {
                    char *str;
                    if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
                        qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                        _("video type %s is only valid as primary video card"),
                                        virDomainVideoTypeToString(def->videos[0]->type));
                        goto error;
                    }

                    virCommandAddArg(cmd, "-device");

                    if (!(str = qemuBuildVideoDevStr(def->videos[i])))
                        goto error;

                    virCommandAddArg(cmd, str);
                    VIR_FREE(str);
                }
            } else {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                "%s", _("only one video card is currently supported"));
                goto error;
            }
        }

    } else {
        /* If we have -device, then we set -nodefault already */
        if (!(qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) &&
            (qemuCmdFlags & QEMUD_CMD_FLAG_VGA) &&
            (qemuCmdFlags & QEMUD_CMD_FLAG_VGA_NONE))
            virCommandAddArgList(cmd, "-vga", "none", NULL);
    }

    /* Add sound hardware */
    if (def->nsounds) {
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
            for (i = 0 ; i < def->nsounds ; i++) {
                virDomainSoundDefPtr sound = def->sounds[i];
                char *str = NULL;

                /* Sadly pcspk device doesn't use -device syntax. Fortunately
                 * we don't need to set any PCI address on it, so we don't
                 * mind too much */
                if (sound->model == VIR_DOMAIN_SOUND_MODEL_PCSPK) {
                    virCommandAddArgList(cmd, "-soundhw", "pcspk", NULL);
                } else {
                    virCommandAddArg(cmd, "-device");

                    if (!(str = qemuBuildSoundDevStr(sound)))
                        goto error;

                    virCommandAddArg(cmd, str);
                    VIR_FREE(str);
                }
            }
        } else {
            int size = 100;
            char *modstr;
            if (VIR_ALLOC_N(modstr, size+1) < 0)
                goto no_memory;

            for (i = 0 ; i < def->nsounds && size > 0 ; i++) {
                virDomainSoundDefPtr sound = def->sounds[i];
                const char *model = virDomainSoundModelTypeToString(sound->model);
                if (!model) {
                    VIR_FREE(modstr);
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    "%s", _("invalid sound model"));
                    goto error;
                }
                strncat(modstr, model, size);
                size -= strlen(model);
                if (i < (def->nsounds - 1))
                    strncat(modstr, ",", size--);
            }
            virCommandAddArgList(cmd, "-soundhw", modstr, NULL);
            VIR_FREE(modstr);
        }
    }

    /* Add watchdog hardware */
    if (def->watchdog) {
        virDomainWatchdogDefPtr watchdog = def->watchdog;
        char *optstr;

        if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildWatchdogDevStr(watchdog);
            if (!optstr)
                goto error;
        } else {
            virCommandAddArg(cmd, "-watchdog");

            const char *model = virDomainWatchdogModelTypeToString(watchdog->model);
            if (!model) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                "%s", _("missing watchdog model"));
                goto error;
            }

            if (!(optstr = strdup(model)))
                goto no_memory;
        }
        virCommandAddArg(cmd, optstr);
        VIR_FREE(optstr);

        int act = watchdog->action;
        if (act == VIR_DOMAIN_WATCHDOG_ACTION_DUMP)
            act = VIR_DOMAIN_WATCHDOG_ACTION_PAUSE;
        const char *action = virDomainWatchdogActionTypeToString(act);
        if (!action) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            "%s", _("invalid watchdog action"));
            goto error;
        }
        virCommandAddArgList(cmd, "-watchdog-action", action, NULL);
    }

    /* Add host passthrough hardware */
    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        char *devstr;

        /* USB */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {

            if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildUSBHostdevDevStr(hostdev)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virCommandAddArg(cmd, "-usbdevice");
                if (!(devstr = qemuBuildUSBHostdevUsbDevStr(hostdev)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }

        /* PCI */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
                char *configfd_name = NULL;
                if (qemuCmdFlags & QEMUD_CMD_FLAG_PCI_CONFIGFD) {
                    int configfd = qemuOpenPCIConfig(hostdev);

                    if (configfd >= 0) {
                        if (virAsprintf(&configfd_name, "%d", configfd) < 0) {
                            VIR_FORCE_CLOSE(configfd);
                            virReportOOMError();
                            goto no_memory;
                        }

                        virCommandTransferFD(cmd, configfd);
                    }
                }
                virCommandAddArg(cmd, "-device");
                devstr = qemuBuildPCIHostdevDevStr(hostdev, configfd_name);
                VIR_FREE(configfd_name);
                if (!devstr)
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else if (qemuCmdFlags & QEMUD_CMD_FLAG_PCIDEVICE) {
                virCommandAddArg(cmd, "-pcidevice");
                if (!(devstr = qemuBuildPCIHostdevPCIDevStr(hostdev)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                _("PCI device assignment is not supported by this version of qemu"));
                goto error;
            }
        }
    }

    if (migrateFrom)
        virCommandAddArgList(cmd, "-incoming", migrateFrom, NULL);

    /* QEMU changed its default behavior to not include the virtio balloon
     * device.  Explicitly request it to ensure it will be present.
     *
     * NB: Earlier we declared that VirtIO balloon will always be in
     * slot 0x3 on bus 0x0
     */
    if ((def->memballoon) &&
        (def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE)) {
        if (def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            qemuReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                            _("Memory balloon device type '%s' is not supported by this version of qemu"),
                            virDomainMemballoonModelTypeToString(def->memballoon->model));
            goto error;
        }
        if (qemuCmdFlags & QEMUD_CMD_FLAG_DEVICE) {
            char *optstr;
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildMemballoonDevStr(def->memballoon);
            if (!optstr)
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        } else if (qemuCmdFlags & QEMUD_CMD_FLAG_BALLOON) {
            virCommandAddArgList(cmd, "-balloon", "virtio", NULL);
        }
    }

    if (current_snapshot && current_snapshot->def->active)
        virCommandAddArgList(cmd, "-loadvm", current_snapshot->def->name,
                             NULL);

    if (def->namespaceData) {
        qemuDomainCmdlineDefPtr qemucmd;

        qemucmd = def->namespaceData;
        for (i = 0; i < qemucmd->num_args; i++)
            virCommandAddArg(cmd, qemucmd->args[i]);
        for (i = 0; i < qemucmd->num_env; i++)
            virCommandAddEnvPair(cmd, qemucmd->env_name[i],
                                 qemucmd->env_value[i]
                                 ? qemucmd->env_value[i] : "");
    }

    return cmd;

 no_memory:
    virReportOOMError();
 error:
    for (i = 0; i <= last_good_net; i++)
        virDomainConfNWFilterTeardown(def->nets[i]);
    virBufferFreeAndReset(&rbd_hosts);
    virCommandFree(cmd);
    return NULL;
}


/*
 * This method takes a string representing a QEMU command line ARGV set
 * optionally prefixed by a list of environment variables. It then tries
 * to split it up into a NULL terminated list of env & argv, splitting
 * on space
 */
static int qemuStringToArgvEnv(const char *args,
                               const char ***retenv,
                               const char ***retargv)
{
    char **arglist = NULL;
    int argcount = 0;
    int argalloc = 0;
    int envend;
    int i;
    const char *curr = args;
    const char *start;
    const char **progenv = NULL;
    const char **progargv = NULL;

    /* Iterate over string, splitting on sequences of ' ' */
    while (curr && *curr != '\0') {
        char *arg;
        const char *next;

        start = curr;
        /* accept a space in CEPH_ARGS */
        if (STRPREFIX(curr, "CEPH_ARGS=-m ")) {
            start += strlen("CEPH_ARGS=-m ");
        }
        if (*start == '\'') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '\'');
        } else if (*start == '"') {
            if (start == curr)
                curr++;
            next = strchr(start + 1, '"');
        } else {
            next = strchr(start, ' ');
        }
        if (!next)
            next = strchr(curr, '\n');

        if (next) {
            arg = strndup(curr, next-curr);
            if (*next == '\'' ||
                *next == '"')
                next++;
        } else {
            arg = strdup(curr);
        }

        if (!arg)
            goto no_memory;

        if (argalloc == argcount) {
            if (VIR_REALLOC_N(arglist, argalloc+10) < 0) {
                VIR_FREE(arg);
                goto no_memory;
            }
            argalloc+=10;
        }

        arglist[argcount++] = arg;

        while (next && c_isspace(*next))
            next++;

        curr = next;
    }

    /* Iterate over list of args, finding first arg not containing
     * the '=' character (eg, skip over env vars FOO=bar) */
    for (envend = 0 ; ((envend < argcount) &&
                       (strchr(arglist[envend], '=') != NULL));
         envend++)
        ; /* nada */

    /* Copy the list of env vars */
    if (envend > 0) {
        if (VIR_REALLOC_N(progenv, envend+1) < 0)
            goto no_memory;
        for (i = 0 ; i < envend ; i++) {
            progenv[i] = arglist[i];
            arglist[i] = NULL;
        }
        progenv[i] = NULL;
    }

    /* Copy the list of argv */
    if (VIR_REALLOC_N(progargv, argcount-envend + 1) < 0)
        goto no_memory;
    for (i = envend ; i < argcount ; i++)
        progargv[i-envend] = arglist[i];
    progargv[i-envend] = NULL;

    VIR_FREE(arglist);

    *retenv = progenv;
    *retargv = progargv;

    return 0;

no_memory:
    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);
    for (i = 0 ; i < argcount ; i++)
        VIR_FREE(arglist[i]);
    VIR_FREE(arglist);
    virReportOOMError();
    return -1;
}


/*
 * Search for a named env variable, and return the value part
 */
static const char *qemuFindEnv(const char **progenv,
                               const char *name)
{
    int i;
    int len = strlen(name);

    for (i = 0 ; progenv && progenv[i] ; i++) {
        if (STREQLEN(progenv[i], name, len) &&
            progenv[i][len] == '=')
            return progenv[i] + len + 1;
    }
    return NULL;
}

/*
 * Takes a string containing a set of key=value,key=value,key...
 * parameters and splits them up, returning two arrays with
 * the individual keys and values. If allowEmptyValue is nonzero,
 * the "=value" part is optional and if a key with no value is found,
 * NULL is be placed into corresponding place in retvalues.
 */
int
qemuParseKeywords(const char *str,
                  char ***retkeywords,
                  char ***retvalues,
                  int allowEmptyValue)
{
    int keywordCount = 0;
    int keywordAlloc = 0;
    char **keywords = NULL;
    char **values = NULL;
    const char *start = str;
    const char *end;
    int i;

    *retkeywords = NULL;
    *retvalues = NULL;
    end = start + strlen(str);

    while (start) {
        const char *separator;
        const char *endmark;
        char *keyword;
        char *value = NULL;

        if (!(endmark = strchr(start, ',')))
            endmark = end;
        if (!(separator = strchr(start, '=')))
            separator = end;

        if (separator >= endmark) {
            if (!allowEmptyValue) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("malformed keyword arguments in '%s'"), str);
                goto error;
            }
            separator = endmark;
        }

        if (!(keyword = strndup(start, separator - start)))
            goto no_memory;

        if (separator < endmark) {
            separator++;
            if (!(value = strndup(separator, endmark - separator))) {
                VIR_FREE(keyword);
                goto no_memory;
            }
        }

        if (keywordAlloc == keywordCount) {
            if (VIR_REALLOC_N(keywords, keywordAlloc + 10) < 0 ||
                VIR_REALLOC_N(values, keywordAlloc + 10) < 0) {
                VIR_FREE(keyword);
                VIR_FREE(value);
                goto no_memory;
            }
            keywordAlloc += 10;
        }

        keywords[keywordCount] = keyword;
        values[keywordCount] = value;
        keywordCount++;

        start = endmark < end ? endmark + 1 : NULL;
    }

    *retkeywords = keywords;
    *retvalues = values;

    return keywordCount;

no_memory:
    virReportOOMError();
error:
    for (i = 0 ; i < keywordCount ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return -1;
}

/*
 * Tries to parse new style QEMU -drive  args.
 *
 * eg -drive file=/dev/HostVG/VirtData1,if=ide,index=1
 *
 * Will fail if not using the 'index' keyword
 */
static virDomainDiskDefPtr
qemuParseCommandLineDisk(virCapsPtr caps,
                         const char *val,
                         int nvirtiodisk)
{
    virDomainDiskDefPtr def = NULL;
    char **keywords;
    char **values;
    int nkeywords;
    int i;
    int idx = -1;
    int busid = -1;
    int unitid = -1;

    if ((nkeywords = qemuParseKeywords(val,
                                       &keywords,
                                       &values, 0)) < 0)
        return NULL;

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    def->bus = VIR_DOMAIN_DISK_BUS_IDE;
    def->device = VIR_DOMAIN_DISK_DEVICE_DISK;
    def->type = VIR_DOMAIN_DISK_TYPE_FILE;

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "file")) {
            if (values[i] && STRNEQ(values[i], "")) {
                def->src = values[i];
                values[i] = NULL;
                if (STRPREFIX(def->src, "/dev/"))
                    def->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                else if (STRPREFIX(def->src, "nbd:")) {
                    char *host, *port;

                    def->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                    def->protocol = VIR_DOMAIN_DISK_PROTOCOL_NBD;
                    host = def->src + strlen("nbd:");
                    port = strchr(host, ':');
                    if (!port) {
                        def = NULL;
                        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                        _("cannot parse nbd filename '%s'"), def->src);
                        goto cleanup;
                    }
                    *port++ = '\0';
                    if (VIR_ALLOC(def->hosts) < 0) {
                        virReportOOMError();
                        goto cleanup;
                    }
                    def->nhosts = 1;
                    def->hosts->name = strdup(host);
                    if (!def->hosts->name) {
                        virReportOOMError();
                        goto cleanup;
                    }
                    def->hosts->port = strdup(port);
                    if (!def->hosts->port) {
                        virReportOOMError();
                        goto cleanup;
                    }

                    VIR_FREE(def->src);
                    def->src = NULL;
                } else if (STRPREFIX(def->src, "rbd:")) {
                    char *p = def->src;

                    def->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                    def->protocol = VIR_DOMAIN_DISK_PROTOCOL_RBD;
                    def->src = strdup(p + strlen("rbd:"));
                    if (!def->src) {
                        virReportOOMError();
                        goto cleanup;
                    }

                    VIR_FREE(p);
                } else if (STRPREFIX(def->src, "sheepdog:")) {
                    char *p = def->src;
                    char *port, *vdi;

                    def->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                    def->protocol = VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG;
                    def->src = strdup(p + strlen("sheepdog:"));
                    if (!def->src) {
                        virReportOOMError();
                        goto cleanup;
                    }

                    /* def->src must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(def->src, ':');
                    if (port) {
                        *port++ = '\0';
                        vdi = strchr(port, ':');
                        if (!vdi) {
                            def = NULL;
                            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                            _("cannot parse sheepdog filename '%s'"), p);
                            goto cleanup;
                        }
                        *vdi++ = '\0';
                        if (VIR_ALLOC(def->hosts) < 0) {
                            virReportOOMError();
                            goto cleanup;
                        }
                        def->nhosts = 1;
                        def->hosts->name = def->src;
                        def->hosts->port = strdup(port);
                        if (!def->hosts->port) {
                            virReportOOMError();
                            goto cleanup;
                        }
                        def->src = strdup(vdi);
                        if (!def->src) {
                            virReportOOMError();
                            goto cleanup;
                        }
                    }

                    VIR_FREE(p);
                } else
                    def->type = VIR_DOMAIN_DISK_TYPE_FILE;
            } else {
                def->type = VIR_DOMAIN_DISK_TYPE_FILE;
            }
        } else if (STREQ(keywords[i], "if")) {
            if (STREQ(values[i], "ide"))
                def->bus = VIR_DOMAIN_DISK_BUS_IDE;
            else if (STREQ(values[i], "scsi"))
                def->bus = VIR_DOMAIN_DISK_BUS_SCSI;
            else if (STREQ(values[i], "virtio"))
                def->bus = VIR_DOMAIN_DISK_BUS_VIRTIO;
            else if (STREQ(values[i], "xen"))
                def->bus = VIR_DOMAIN_DISK_BUS_XEN;
        } else if (STREQ(keywords[i], "media")) {
            if (STREQ(values[i], "cdrom")) {
                def->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                def->readonly = 1;
            } else if (STREQ(values[i], "floppy"))
                def->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
        } else if (STREQ(keywords[i], "format")) {
            def->driverName = strdup("qemu");
            if (!def->driverName) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportOOMError();
                goto cleanup;
            }
            def->driverType = values[i];
            values[i] = NULL;
        } else if (STREQ(keywords[i], "cache")) {
            if (STREQ(values[i], "off") ||
                STREQ(values[i], "none"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DISABLE;
            else if (STREQ(values[i], "writeback") ||
                     STREQ(values[i], "on"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITEBACK;
            else if (STREQ(values[i], "writethrough"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_WRITETHRU;
        } else if (STREQ(keywords[i], "werror") ||
                   STREQ(keywords[i], "rerror")) {
            if (STREQ(values[i], "stop"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "ignore"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
            else if (STREQ(values[i], "enospace"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE;
        } else if (STREQ(keywords[i], "index")) {
            if (virStrToLong_i(values[i], NULL, 10, &idx) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("cannot parse drive index '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "bus")) {
            if (virStrToLong_i(values[i], NULL, 10, &busid) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("cannot parse drive bus '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "unit")) {
            if (virStrToLong_i(values[i], NULL, 10, &unitid) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("cannot parse drive unit '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "readonly")) {
            if ((values[i] == NULL) || STREQ(values[i], "on"))
                def->readonly = 1;
        }
    }

    if (!def->src &&
        def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        def->type != VIR_DOMAIN_DISK_TYPE_NETWORK) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing file parameter in drive '%s'"), val);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }
    if (idx == -1 &&
        def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
        idx = nvirtiodisk;

    if (idx == -1 &&
        unitid == -1 &&
        busid == -1) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("missing index/unit/bus parameter in drive '%s'"), val);
        virDomainDiskDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (idx == -1) {
        if (unitid == -1)
            unitid = 0;
        if (busid == -1)
            busid = 0;
        switch (def->bus) {
        case VIR_DOMAIN_DISK_BUS_IDE:
            idx = (busid * 2) + unitid;
            break;
        case VIR_DOMAIN_DISK_BUS_SCSI:
            idx = (busid * 7) + unitid;
            break;
        default:
            idx = unitid;
            break;
        }
    }

    if (def->bus == VIR_DOMAIN_DISK_BUS_IDE) {
        def->dst = strdup("hda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
        def->dst = strdup("sda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_VIRTIO) {
        def->dst = strdup("vda");
    } else if (def->bus == VIR_DOMAIN_DISK_BUS_XEN) {
        def->dst = strdup("xvda");
    } else {
        def->dst = strdup("hda");
    }

    if (!def->dst) {
        virDomainDiskDefFree(def);
        def = NULL;
        virReportOOMError();
        goto cleanup;
    }
    if (STREQ(def->dst, "xvda"))
        def->dst[3] = 'a' + idx;
    else
        def->dst[2] = 'a' + idx;

    if (virDomainDiskDefAssignAddress(caps, def) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("invalid device name '%s'"), def->dst);
        virDomainDiskDefFree(def);
        def = NULL;
        /* fall through to "cleanup" */
    }

cleanup:
    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}

/*
 * Tries to find a NIC definition matching a vlan we want
 */
static const char *
qemuFindNICForVLAN(int nnics,
                   const char **nics,
                   int wantvlan)
{
    int i;
    for (i = 0 ; i < nnics ; i++) {
        int gotvlan;
        const char *tmp = strstr(nics[i], "vlan=");
        char *end;
        if (!tmp)
            continue;

        tmp += strlen("vlan=");

        if (virStrToLong_i(tmp, &end, 10, &gotvlan) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot parse NIC vlan in '%s'"), nics[i]);
            return NULL;
        }

        if (gotvlan == wantvlan)
            return nics[i];
    }

    if (wantvlan == 0 && nnics > 0)
        return nics[0];

    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot find NIC definition for vlan %d"), wantvlan);
    return NULL;
}


/*
 * Tries to parse a QEMU -net backend argument. Gets given
 * a list of all known -net frontend arguments to try and
 * match up against. Horribly complicated stuff
 */
static virDomainNetDefPtr
qemuParseCommandLineNet(virCapsPtr caps,
                        const char *val,
                        int nnics,
                        const char **nics)
{
    virDomainNetDefPtr def = NULL;
    char **keywords = NULL;
    char **values = NULL;
    int nkeywords;
    const char *nic;
    int wantvlan = 0;
    const char *tmp;
    int genmac = 1;
    int i;

    tmp = strchr(val, ',');

    if (tmp) {
        if ((nkeywords = qemuParseKeywords(tmp+1,
                                           &keywords,
                                           &values, 0)) < 0)
            return NULL;
    } else {
        nkeywords = 0;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    /* 'tap' could turn into libvirt type=ethernet, type=bridge or
     * type=network, but we can't tell, so use the generic config */
    if (STRPREFIX(val, "tap,"))
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;
    else if (STRPREFIX(val, "socket"))
        def->type = VIR_DOMAIN_NET_TYPE_CLIENT;
    else if (STRPREFIX(val, "user"))
        def->type = VIR_DOMAIN_NET_TYPE_USER;
    else
        def->type = VIR_DOMAIN_NET_TYPE_ETHERNET;

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "vlan")) {
            if (virStrToLong_i(values[i], NULL, 10, &wantvlan) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("cannot parse vlan in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "script") && STRNEQ(values[i], "")) {
            def->data.ethernet.script = values[i];
            values[i] = NULL;
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "ifname")) {
            def->ifname = values[i];
            values[i] = NULL;
        }
    }


    /* Done parsing the nic backend. Now to try and find corresponding
     * frontend, based off vlan number. NB this assumes a 1-1 mapping
     */

    nic = qemuFindNICForVLAN(nnics, nics, wantvlan);
    if (!nic) {
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    if (!STRPREFIX(nic, "nic")) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot parse NIC definition '%s'"), nic);
        virDomainNetDefFree(def);
        def = NULL;
        goto cleanup;
    }

    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);

    if (STRPREFIX(nic, "nic,")) {
        if ((nkeywords = qemuParseKeywords(nic + strlen("nic,"),
                                           &keywords,
                                           &values, 0)) < 0) {
            virDomainNetDefFree(def);
            def = NULL;
            goto cleanup;
        }
    } else {
        nkeywords = 0;
    }

    for (i = 0 ; i < nkeywords ; i++) {
        if (STREQ(keywords[i], "macaddr")) {
            genmac = 0;
            if (virParseMacAddr(values[i], def->mac) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("unable to parse mac address '%s'"),
                                values[i]);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "model")) {
            def->model = values[i];
            values[i] = NULL;
        }
    }

    if (genmac)
        virCapabilitiesGenerateMac(caps, def->mac);

cleanup:
    for (i = 0 ; i < nkeywords ; i++) {
        VIR_FREE(keywords[i]);
        VIR_FREE(values[i]);
    }
    VIR_FREE(keywords);
    VIR_FREE(values);
    return def;
}


/*
 * Tries to parse a QEMU PCI device
 */
static virDomainHostdevDefPtr
qemuParseCommandLinePCI(const char *val)
{
    virDomainHostdevDefPtr def = NULL;
    int bus = 0, slot = 0, func = 0;
    const char *start;
    char *end;

    if (!STRPREFIX(val, "host=")) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unknown PCI device syntax '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    start = val + strlen("host=");
    if (virStrToLong_i(start, &end, 16, &bus) < 0 || *end != ':') {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot extract PCI device bus '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }
    start = end + 1;
    if (virStrToLong_i(start, &end, 16, &slot) < 0 || *end != '.') {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot extract PCI device slot '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }
    start = end + 1;
    if (virStrToLong_i(start, NULL, 16, &func) < 0) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("cannot extract PCI device function '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = 1;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    def->source.subsys.u.pci.bus = bus;
    def->source.subsys.u.pci.slot = slot;
    def->source.subsys.u.pci.function = func;

cleanup:
    return def;
}


/*
 * Tries to parse a QEMU USB device
 */
static virDomainHostdevDefPtr
qemuParseCommandLineUSB(const char *val)
{
    virDomainHostdevDefPtr def = NULL;
    int first = 0, second = 0;
    const char *start;
    char *end;

    if (!STRPREFIX(val, "host:")) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unknown USB device syntax '%s'"), val);
        VIR_FREE(def);
        goto cleanup;
    }

    start = val + strlen("host:");
    if (strchr(start, ':')) {
        if (virStrToLong_i(start, &end, 16, &first) < 0 || *end != ':') {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot extract USB device vendor '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 16, &second) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot extract USB device product '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
    } else {
        if (virStrToLong_i(start, &end, 10, &first) < 0 || *end != '.') {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                             _("cannot extract USB device bus '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 10, &second) < 0) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot extract USB device address '%s'"), val);
            VIR_FREE(def);
            goto cleanup;
        }
    }

    if (VIR_ALLOC(def) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = 0;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB;
    if (*end == '.') {
        def->source.subsys.u.usb.bus = first;
        def->source.subsys.u.usb.device = second;
    } else {
        def->source.subsys.u.usb.vendor = first;
        def->source.subsys.u.usb.product = second;
    }

cleanup:
    return def;
}


/*
 * Tries to parse a QEMU serial/parallel device
 */
static virDomainChrDefPtr
qemuParseCommandLineChr(const char *val)
{
    virDomainChrDefPtr def;

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    if (STREQ(val, "null")) {
        def->type = VIR_DOMAIN_CHR_TYPE_NULL;
    } else if (STREQ(val, "vc")) {
        def->type = VIR_DOMAIN_CHR_TYPE_VC;
    } else if (STREQ(val, "pty")) {
        def->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if (STRPREFIX(val, "file:")) {
        def->type = VIR_DOMAIN_CHR_TYPE_FILE;
        def->data.file.path = strdup(val+strlen("file:"));
        if (!def->data.file.path)
            goto no_memory;
    } else if (STRPREFIX(val, "pipe:")) {
        def->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        def->data.file.path = strdup(val+strlen("pipe:"));
        if (!def->data.file.path)
            goto no_memory;
    } else if (STREQ(val, "stdio")) {
        def->type = VIR_DOMAIN_CHR_TYPE_STDIO;
    } else if (STRPREFIX(val, "udp:")) {
        const char *svc1, *host2, *svc2;
        def->type = VIR_DOMAIN_CHR_TYPE_UDP;
        val += strlen("udp:");
        svc1 = strchr(val, ':');
        host2 = svc1 ? strchr(svc1, '@') : NULL;
        svc2 = host2 ? strchr(host2, ':') : NULL;

        if (svc1)
            def->data.udp.connectHost = strndup(val, svc1-val);
        else
            def->data.udp.connectHost = strdup(val);

        if (!def->data.udp.connectHost)
            goto no_memory;

        if (svc1) {
            svc1++;
            if (host2)
                def->data.udp.connectService = strndup(svc1, host2-svc1);
            else
                def->data.udp.connectService = strdup(svc1);

            if (!def->data.udp.connectService)
                goto no_memory;
        }

        if (host2) {
            host2++;
            if (svc2)
                def->data.udp.bindHost = strndup(host2, svc2-host2);
            else
                def->data.udp.bindHost = strdup(host2);

            if (!def->data.udp.bindHost)
                goto no_memory;
        }
        if (svc2) {
            svc2++;
            def->data.udp.bindService = strdup(svc2);
            if (!def->data.udp.bindService)
                goto no_memory;
        }
    } else if (STRPREFIX(val, "tcp:") ||
               STRPREFIX(val, "telnet:")) {
        const char *opt, *svc;
        def->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (STRPREFIX(val, "tcp:")) {
            val += strlen("tcp:");
        } else {
            val += strlen("telnet:");
            def->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        }
        svc = strchr(val, ':');
        if (!svc) {
            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                            _("cannot find port number in character device %s"), val);
            goto error;
        }
        opt = strchr(svc, ',');
        if (opt && strstr(opt, "server"))
            def->data.tcp.listen = 1;

        def->data.tcp.host = strndup(val, svc-val);
        if (!def->data.tcp.host)
            goto no_memory;
        svc++;
        if (opt) {
            def->data.tcp.service = strndup(svc, opt-svc);
        } else {
            def->data.tcp.service = strdup(svc);
        }
        if (!def->data.tcp.service)
            goto no_memory;
    } else if (STRPREFIX(val, "unix:")) {
        const char *opt;
        val += strlen("unix:");
        opt = strchr(val, ',');
        def->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        if (opt) {
            if (strstr(opt, "listen"))
                def->data.nix.listen = 1;
            def->data.nix.path = strndup(val, opt-val);
        } else {
            def->data.nix.path = strdup(val);
        }
        if (!def->data.nix.path)
            goto no_memory;

    } else if (STRPREFIX(val, "/dev")) {
        def->type = VIR_DOMAIN_CHR_TYPE_DEV;
        def->data.file.path = strdup(val);
        if (!def->data.file.path)
            goto no_memory;
    } else {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        _("unknown character device syntax %s"), val);
        goto error;
    }

    return def;

no_memory:
    virReportOOMError();
error:
    virDomainChrDefFree(def);
    return NULL;
}


static virCPUDefPtr
qemuInitGuestCPU(virDomainDefPtr dom)
{
    if (!dom->cpu) {
        virCPUDefPtr cpu;

        if (VIR_ALLOC(cpu) < 0) {
            virReportOOMError();
            return NULL;
        }

        cpu->type = VIR_CPU_TYPE_GUEST;
        cpu->match = VIR_CPU_MATCH_EXACT;
        dom->cpu = cpu;
    }

    return dom->cpu;
}


static int
qemuParseCommandLineCPU(virDomainDefPtr dom,
                        const char *val)
{
    virCPUDefPtr cpu;
    const char *p = val;
    const char *next;

    if (!(cpu = qemuInitGuestCPU(dom)))
        goto error;

    do {
        if (*p == '\0' || *p == ',')
            goto syntax;

        if ((next = strchr(p, ',')))
            next++;

        if (!cpu->model) {
            if (next)
                cpu->model = strndup(p, next - p - 1);
            else
                cpu->model = strdup(p);

            if (!cpu->model)
                goto no_memory;
        }
        else if (*p == '+' || *p == '-') {
            char *feature;
            int policy;
            int ret;

            if (*p == '+')
                policy = VIR_CPU_FEATURE_REQUIRE;
            else
                policy = VIR_CPU_FEATURE_DISABLE;

            p++;
            if (*p == '\0' || *p == ',')
                goto syntax;

            if (next)
                feature = strndup(p, next - p - 1);
            else
                feature = strdup(p);

            ret = virCPUDefAddFeature(cpu, feature, policy);
            VIR_FREE(feature);
            if (ret < 0)
                goto error;
        }
    } while ((p = next));

    return 0;

syntax:
    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("unknown CPU syntax '%s'"), val);
    goto error;

no_memory:
    virReportOOMError();
error:
    return -1;
}


static int
qemuParseCommandLineSmp(virDomainDefPtr dom,
                        const char *val)
{
    unsigned int sockets = 0;
    unsigned int cores = 0;
    unsigned int threads = 0;
    unsigned int maxcpus = 0;
    int i;
    int nkws;
    char **kws;
    char **vals;
    int n;
    char *end;
    int ret;

    nkws = qemuParseKeywords(val, &kws, &vals, 1);
    if (nkws < 0)
        return -1;

    for (i = 0; i < nkws; i++) {
        if (vals[i] == NULL) {
            if (i > 0 ||
                virStrToLong_i(kws[i], &end, 10, &n) < 0 || *end != '\0')
                goto syntax;
            dom->vcpus = n;
        } else {
            if (virStrToLong_i(vals[i], &end, 10, &n) < 0 || *end != '\0')
                goto syntax;
            if (STREQ(kws[i], "sockets"))
                sockets = n;
            else if (STREQ(kws[i], "cores"))
                cores = n;
            else if (STREQ(kws[i], "threads"))
                threads = n;
            else if (STREQ(kws[i], "maxcpus"))
                maxcpus = n;
            else
                goto syntax;
        }
    }

    dom->maxvcpus = maxcpus ? maxcpus : dom->vcpus;

    if (sockets && cores && threads) {
        virCPUDefPtr cpu;

        if (!(cpu = qemuInitGuestCPU(dom)))
            goto error;
        cpu->sockets = sockets;
        cpu->cores = cores;
        cpu->threads = threads;
    } else if (sockets || cores || threads)
        goto syntax;

    ret = 0;

cleanup:
    for (i = 0; i < nkws; i++) {
        VIR_FREE(kws[i]);
        VIR_FREE(vals[i]);
    }
    VIR_FREE(kws);
    VIR_FREE(vals);

    return ret;

syntax:
    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                    _("cannot parse CPU topology '%s'"), val);
error:
    ret = -1;
    goto cleanup;
}


/*
 * Analyse the env and argv settings and reconstruct a
 * virDomainDefPtr representing these settings as closely
 * as is practical. This is not an exact science....
 */
virDomainDefPtr qemuParseCommandLine(virCapsPtr caps,
                                     const char **progenv,
                                     const char **progargv)
{
    virDomainDefPtr def;
    int i;
    int nographics = 0;
    int fullscreen = 0;
    char *path;
    int nnics = 0;
    const char **nics = NULL;
    int video = VIR_DOMAIN_VIDEO_TYPE_CIRRUS;
    int nvirtiodisk = 0;
    qemuDomainCmdlineDefPtr cmd;

    if (!progargv[0]) {
        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                        "%s", _("no emulator path found"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    /* allocate the cmdlinedef up-front; if it's unused, we'll free it later */
    if (VIR_ALLOC(cmd) < 0)
        goto no_memory;

    virUUIDGenerate(def->uuid);

    def->id = -1;
    def->mem.cur_balloon = def->mem.max_balloon = 64 * 1024;
    def->maxvcpus = 1;
    def->vcpus = 1;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;
    def->features = (1 << VIR_DOMAIN_FEATURE_ACPI)
        /*| (1 << VIR_DOMAIN_FEATURE_APIC)*/;
    def->onReboot = VIR_DOMAIN_LIFECYCLE_RESTART;
    def->onCrash = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->onPoweroff = VIR_DOMAIN_LIFECYCLE_DESTROY;
    def->virtType = VIR_DOMAIN_VIRT_QEMU;
    if (!(def->emulator = strdup(progargv[0])))
        goto no_memory;

    if (strstr(def->emulator, "kvm")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->features |= (1 << VIR_DOMAIN_FEATURE_PAE);
    }


    if (strstr(def->emulator, "xenner")) {
        def->virtType = VIR_DOMAIN_VIRT_KVM;
        def->os.type = strdup("xen");
    } else {
        def->os.type = strdup("hvm");
    }
    if (!def->os.type)
        goto no_memory;

    if (STRPREFIX(def->emulator, "qemu"))
        path = def->emulator;
    else
        path = strstr(def->emulator, "qemu");
    if (path &&
        STRPREFIX(path, "qemu-system-"))
        def->os.arch = strdup(path + strlen("qemu-system-"));
    else
        def->os.arch = strdup("i686");
    if (!def->os.arch)
        goto no_memory;

#define WANT_VALUE()                                                   \
    const char *val = progargv[++i];                                   \
    if (!val) {                                                        \
        qemuReportError(VIR_ERR_INTERNAL_ERROR,                        \
                        _("missing value for %s argument"), arg);      \
        goto error;                                                    \
    }

    /* One initial loop to get list of NICs, so we
     * can correlate them later */
    for (i = 1 ; progargv[i] ; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (STRPREFIX(val, "nic")) {
                if (VIR_REALLOC_N(nics, nnics+1) < 0)
                    goto no_memory;
                nics[nnics++] = val;
            }
        }
    }

    /* Now the real processing loop */
    for (i = 1 ; progargv[i] ; i++) {
        const char *arg = progargv[i];
        /* Make sure we have a single - for all options to
           simplify next logic */
        if (STRPREFIX(arg, "--"))
            arg++;

        if (STREQ(arg, "-vnc")) {
            virDomainGraphicsDefPtr vnc;
            char *tmp;
            WANT_VALUE();
            if (VIR_ALLOC(vnc) < 0)
                goto no_memory;
            vnc->type = VIR_DOMAIN_GRAPHICS_TYPE_VNC;

            tmp = strchr(val, ':');
            if (tmp) {
                char *opts;
                if (virStrToLong_i(tmp+1, &opts, 10, &vnc->data.vnc.port) < 0) {
                    VIR_FREE(vnc);
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,             \
                                    _("cannot parse VNC port '%s'"), tmp+1);
                    goto error;
                }
                vnc->data.vnc.listenAddr = strndup(val, tmp-val);
                if (!vnc->data.vnc.listenAddr) {
                    VIR_FREE(vnc);
                    goto no_memory;
                }
                vnc->data.vnc.port += 5900;
                vnc->data.vnc.autoport = 0;
            } else {
                vnc->data.vnc.autoport = 1;
            }

            if (VIR_REALLOC_N(def->graphics, def->ngraphics+1) < 0) {
                virDomainGraphicsDefFree(vnc);
                goto no_memory;
            }
            def->graphics[def->ngraphics++] = vnc;
        } else if (STREQ(arg, "-m")) {
            int mem;
            WANT_VALUE();
            if (virStrToLong_i(val, NULL, 10, &mem) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, \
                                _("cannot parse memory level '%s'"), val);
                goto error;
            }
            def->mem.cur_balloon = def->mem.max_balloon = mem * 1024;
        } else if (STREQ(arg, "-smp")) {
            WANT_VALUE();
            if (qemuParseCommandLineSmp(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-uuid")) {
            WANT_VALUE();
            if (virUUIDParse(val, def->uuid) < 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR, \
                                _("cannot parse UUID '%s'"), val);
                goto error;
            }
        } else if (STRPREFIX(arg, "-hd") ||
                   STRPREFIX(arg, "-sd") ||
                   STRPREFIX(arg, "-fd") ||
                   STREQ(arg, "-cdrom")) {
            WANT_VALUE();
            virDomainDiskDefPtr disk;
            if (VIR_ALLOC(disk) < 0)
                goto no_memory;

            if (STRPREFIX(val, "/dev/"))
                disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
            else if (STRPREFIX(val, "nbd:")) {
                disk->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                disk->protocol = VIR_DOMAIN_DISK_PROTOCOL_NBD;
                val += strlen("nbd:");
            } else if (STRPREFIX(val, "rbd:")) {
                disk->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                disk->protocol = VIR_DOMAIN_DISK_PROTOCOL_RBD;
                val += strlen("rbd:");
            } else if (STRPREFIX(val, "sheepdog:")) {
                disk->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                disk->protocol = VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG;
                val += strlen("sheepdog:");
            } else
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            if (STREQ(arg, "-cdrom")) {
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                disk->dst = strdup("hdc");
                disk->readonly = 1;
            } else {
                if (STRPREFIX(arg, "-fd")) {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_FLOPPY;
                    disk->bus = VIR_DOMAIN_DISK_BUS_FDC;
                } else {
                    disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                    if (STRPREFIX(arg, "-hd"))
                        disk->bus = VIR_DOMAIN_DISK_BUS_IDE;
                    else
                        disk->bus = VIR_DOMAIN_DISK_BUS_SCSI;
                }
                disk->dst = strdup(arg + 1);
            }
            disk->src = strdup(val);

            if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
                char *host, *port;

                switch (disk->protocol) {
                case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                    host = disk->src;
                    port = strchr(host, ':');
                    if (!port) {
                        def = NULL;
                        qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                        _("cannot parse nbd filename '%s'"), disk->src);
                        goto error;
                    }
                    *port++ = '\0';
                    if (VIR_ALLOC(disk->hosts) < 0) {
                        virReportOOMError();
                        goto error;
                    }
                    disk->nhosts = 1;
                    disk->hosts->name = host;
                    disk->hosts->port = strdup(port);
                    if (!disk->hosts->port) {
                        virReportOOMError();
                        goto error;
                    }
                    disk->src = NULL;
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                    /* handled later since the hosts for all disks are in CEPH_ARGS */
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                    /* disk->src must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(disk->src, ':');
                    if (port) {
                        char *vdi;

                        *port++ = '\0';
                        vdi = strchr(port, ':');
                        if (!vdi) {
                            qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                            _("cannot parse sheepdog filename '%s'"), val);
                            goto error;
                        }
                        *vdi++ = '\0';
                        if (VIR_ALLOC(disk->hosts) < 0) {
                            virReportOOMError();
                            goto error;
                        }
                        disk->nhosts = 1;
                        disk->hosts->name = disk->src;
                        disk->hosts->port = strdup(port);
                        if (!disk->hosts->port) {
                            virReportOOMError();
                            goto error;
                        }
                        disk->src = strdup(vdi);
                        if (!disk->src) {
                            virReportOOMError();
                            goto error;
                        }
                    }
                    break;
                }
            }

            if (!(disk->src || disk->nhosts > 0) ||
                !disk->dst) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }

            if (virDomainDiskDefAssignAddress(caps, disk) < 0)
                goto error;

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;
        } else if (STREQ(arg, "-no-acpi")) {
            def->features &= ~(1 << VIR_DOMAIN_FEATURE_ACPI);
        } else if (STREQ(arg, "-no-reboot")) {
            def->onReboot = VIR_DOMAIN_LIFECYCLE_DESTROY;
        } else if (STREQ(arg, "-no-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_QEMU;
        } else if (STREQ(arg, "-nographic")) {
            nographics = 1;
        } else if (STREQ(arg, "-full-screen")) {
            fullscreen = 1;
        } else if (STREQ(arg, "-localtime")) {
            def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_LOCALTIME;
        } else if (STREQ(arg, "-kernel")) {
            WANT_VALUE();
            if (!(def->os.kernel = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-initrd")) {
            WANT_VALUE();
            if (!(def->os.initrd = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-append")) {
            WANT_VALUE();
            if (!(def->os.cmdline = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-boot")) {
            int n, b = 0;
            WANT_VALUE();
            for (n = 0 ; val[n] && b < VIR_DOMAIN_BOOT_LAST ; n++) {
                if (val[n] == 'a')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_FLOPPY;
                else if (val[n] == 'c')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_DISK;
                else if (val[n] == 'd')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_CDROM;
                else if (val[n] == 'n')
                    def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_NET;
                else if (val[n] == ',')
                    break;
            }
            def->os.nBootDevs = b;

            if (strstr(val, "menu=on"))
                def->os.bootmenu = 1;
        } else if (STREQ(arg, "-name")) {
            char *process;
            WANT_VALUE();
            process = strstr(val, ",process=");
            if (process == NULL) {
                if (!(def->name = strdup(val)))
                    goto no_memory;
            } else {
                if (!(def->name = strndup(val, process - val)))
                    goto no_memory;
            }
        } else if (STREQ(arg, "-M")) {
            WANT_VALUE();
            if (!(def->os.machine = strdup(val)))
                goto no_memory;
        } else if (STREQ(arg, "-serial")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;
                if (!(chr = qemuParseCommandLineChr(val)))
                    goto error;
                if (VIR_REALLOC_N(def->serials, def->nserials+1) < 0) {
                    virDomainChrDefFree(chr);
                    goto no_memory;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL;
                chr->target.port = def->nserials;
                def->serials[def->nserials++] = chr;
            }
        } else if (STREQ(arg, "-parallel")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;
                if (!(chr = qemuParseCommandLineChr(val)))
                    goto error;
                if (VIR_REALLOC_N(def->parallels, def->nparallels+1) < 0) {
                    virDomainChrDefFree(chr);
                    goto no_memory;
                }
                chr->deviceType = VIR_DOMAIN_CHR_DEVICE_TYPE_PARALLEL;
                chr->target.port = def->nparallels;
                def->parallels[def->nparallels++] = chr;
            }
        } else if (STREQ(arg, "-usbdevice")) {
            WANT_VALUE();
            if (STREQ(val, "tablet") ||
                STREQ(val, "mouse")) {
                virDomainInputDefPtr input;
                if (VIR_ALLOC(input) < 0)
                    goto no_memory;
                input->bus = VIR_DOMAIN_INPUT_BUS_USB;
                if (STREQ(val, "tablet"))
                    input->type = VIR_DOMAIN_INPUT_TYPE_TABLET;
                else
                    input->type = VIR_DOMAIN_INPUT_TYPE_MOUSE;
                if (VIR_REALLOC_N(def->inputs, def->ninputs+1) < 0) {
                    virDomainInputDefFree(input);
                    goto no_memory;
                }
                def->inputs[def->ninputs++] = input;
            } else if (STRPREFIX(val, "disk:")) {
                virDomainDiskDefPtr disk;
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                disk->src = strdup(val + strlen("disk:"));
                if (!disk->src) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (STRPREFIX(disk->src, "/dev/"))
                    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                else
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                disk->bus = VIR_DOMAIN_DISK_BUS_USB;
                if (!(disk->dst = strdup("sda"))) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                    virDomainDiskDefFree(disk);
                    goto no_memory;
                }
                def->disks[def->ndisks++] = disk;
            } else {
                virDomainHostdevDefPtr hostdev;
                if (!(hostdev = qemuParseCommandLineUSB(val)))
                    goto error;
                if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
                    virDomainHostdevDefFree(hostdev);
                    goto no_memory;
                }
                def->hostdevs[def->nhostdevs++] = hostdev;
            }
        } else if (STREQ(arg, "-net")) {
            WANT_VALUE();
            if (!STRPREFIX(val, "nic") && STRNEQ(val, "none")) {
                virDomainNetDefPtr net;
                if (!(net = qemuParseCommandLineNet(caps, val, nnics, nics)))
                    goto error;
                if (VIR_REALLOC_N(def->nets, def->nnets+1) < 0) {
                    virDomainNetDefFree(net);
                    goto no_memory;
                }
                def->nets[def->nnets++] = net;
            }
        } else if (STREQ(arg, "-drive")) {
            virDomainDiskDefPtr disk;
            WANT_VALUE();
            if (!(disk = qemuParseCommandLineDisk(caps, val, nvirtiodisk)))
                goto error;
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0) {
                virDomainDiskDefFree(disk);
                goto no_memory;
            }
            def->disks[def->ndisks++] = disk;

            if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
                nvirtiodisk++;
        } else if (STREQ(arg, "-pcidevice")) {
            virDomainHostdevDefPtr hostdev;
            WANT_VALUE();
            if (!(hostdev = qemuParseCommandLinePCI(val)))
                goto error;
            if (VIR_REALLOC_N(def->hostdevs, def->nhostdevs+1) < 0) {
                virDomainHostdevDefFree(hostdev);
                goto no_memory;
            }
            def->hostdevs[def->nhostdevs++] = hostdev;
        } else if (STREQ(arg, "-soundhw")) {
            const char *start;
            WANT_VALUE();
            start = val;
            while (start) {
                const char *tmp = strchr(start, ',');
                int type = -1;
                if (STRPREFIX(start, "pcspk")) {
                    type = VIR_DOMAIN_SOUND_MODEL_PCSPK;
                } else if (STRPREFIX(start, "sb16")) {
                    type = VIR_DOMAIN_SOUND_MODEL_SB16;
                } else if (STRPREFIX(start, "es1370")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ES1370;
                } else if (STRPREFIX(start, "ac97")) {
                    type = VIR_DOMAIN_SOUND_MODEL_AC97;
                }

                if (type != -1) {
                    virDomainSoundDefPtr snd;
                    if (VIR_ALLOC(snd) < 0)
                        goto no_memory;
                    snd->model = type;
                    if (VIR_REALLOC_N(def->sounds, def->nsounds+1) < 0) {
                        VIR_FREE(snd);
                        goto no_memory;
                    }
                    def->sounds[def->nsounds++] = snd;
                }

                start = tmp ? tmp + 1 : NULL;
            }
        } else if (STREQ(arg, "-watchdog")) {
            WANT_VALUE();
            int model = virDomainWatchdogModelTypeFromString (val);

            if (model != -1) {
                virDomainWatchdogDefPtr wd;
                if (VIR_ALLOC(wd) < 0)
                    goto no_memory;
                wd->model = model;
                wd->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;
                def->watchdog = wd;
            }
        } else if (STREQ(arg, "-watchdog-action") && def->watchdog) {
            WANT_VALUE();
            int action = virDomainWatchdogActionTypeFromString (val);

            if (action != -1)
                def->watchdog->action = action;
        } else if (STREQ(arg, "-bootloader")) {
            WANT_VALUE();
            def->os.bootloader = strdup(val);
            if (!def->os.bootloader)
                goto no_memory;
        } else if (STREQ(arg, "-vmwarevga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VMVGA;
        } else if (STREQ(arg, "-std-vga")) {
            video = VIR_DOMAIN_VIDEO_TYPE_VGA;
        } else if (STREQ(arg, "-vga")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                video = qemuVideoTypeFromString(val);
                if (video < 0) {
                    qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                    _("unknown video adapter type '%s'"), val);
                    goto error;
                }
            }
        } else if (STREQ(arg, "-cpu")) {
            WANT_VALUE();
            if (qemuParseCommandLineCPU(def, val) < 0)
                goto error;
        } else if (STREQ(arg, "-domid")) {
            WANT_VALUE();
            /* ignore, generted on the fly */
        } else if (STREQ(arg, "-usb")) {
            /* ignore, always added by libvirt */
        } else if (STREQ(arg, "-pidfile")) {
            WANT_VALUE();
            /* ignore, used by libvirt as needed */
        } else if (STREQ(arg, "-incoming")) {
            WANT_VALUE();
            /* ignore, used via restore/migrate APIs */
        } else if (STREQ(arg, "-monitor")) {
            WANT_VALUE();
            /* ignore, used internally by libvirt */
        } else if (STREQ(arg, "-S")) {
            /* ignore, always added by libvirt */
        } else {
            /* something we can't yet parse.  Add it to the qemu namespace
             * cmdline/environment advanced options and hope for the best
             */
            VIR_WARN("unknown QEMU argument '%s', adding to the qemu namespace",
                     arg);
            if (VIR_REALLOC_N(cmd->args, cmd->num_args+1) < 0)
                goto no_memory;
            cmd->args[cmd->num_args] = strdup(arg);
            if (cmd->args[cmd->num_args] == NULL)
                goto no_memory;
            cmd->num_args++;
        }
    }

#undef WANT_VALUE
    if (def->ndisks > 0) {
        const char *ceph_args = qemuFindEnv(progenv, "CEPH_ARGS");
        if (ceph_args) {
            char *hosts, *port, *saveptr, *token;
            virDomainDiskDefPtr first_rbd_disk = NULL;
            for (i = 0 ; i < def->ndisks ; i++) {
                virDomainDiskDefPtr disk = def->disks[i];
                if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                    disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_RBD) {
                    first_rbd_disk = disk;
                    break;
                }
            }

            if (!first_rbd_disk) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("CEPH_ARGS was set without an rbd disk"));
                goto error;
            }

            /* CEPH_ARGS should be: -m host1[:port1][,host2[:port2]]... */
            if (!STRPREFIX(ceph_args, "-m ")) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("could not parse CEPH_ARGS '%s'"), ceph_args);
                goto error;
            }
            hosts = strdup(strchr(ceph_args, ' ') + 1);
            if (!hosts)
                goto no_memory;
            first_rbd_disk->nhosts = 0;
            token = strtok_r(hosts, ",", &saveptr);
            while (token != NULL) {
                if (VIR_REALLOC_N(first_rbd_disk->hosts, first_rbd_disk->nhosts + 1) < 0) {
                    VIR_FREE(hosts);
                    goto no_memory;
                }
                port = strchr(token, ':');
                if (port) {
                    *port++ = '\0';
                    port = strdup(port);
                    if (!port) {
                        VIR_FREE(hosts);
                        goto no_memory;
                    }
                }
                first_rbd_disk->hosts[first_rbd_disk->nhosts].port = port;
                first_rbd_disk->hosts[first_rbd_disk->nhosts].name = strdup(token);
                if (!first_rbd_disk->hosts[first_rbd_disk->nhosts].name) {
                    VIR_FREE(hosts);
                    goto no_memory;
                }
                first_rbd_disk->nhosts++;
                token = strtok_r(NULL, ",", &saveptr);
            }
            VIR_FREE(hosts);

            if (first_rbd_disk->nhosts == 0) {
                qemuReportError(VIR_ERR_INTERNAL_ERROR,
                                _("found no rbd hosts in CEPH_ARGS '%s'"), ceph_args);
                goto error;
            }
        }
    }

    if (!nographics && def->ngraphics == 0) {
        virDomainGraphicsDefPtr sdl;
        const char *display = qemuFindEnv(progenv, "DISPLAY");
        const char *xauth = qemuFindEnv(progenv, "XAUTHORITY");
        if (VIR_ALLOC(sdl) < 0)
            goto no_memory;
        sdl->type = VIR_DOMAIN_GRAPHICS_TYPE_SDL;
        sdl->data.sdl.fullscreen = fullscreen;
        if (display &&
            !(sdl->data.sdl.display = strdup(display))) {
            VIR_FREE(sdl);
            goto no_memory;
        }
        if (xauth &&
            !(sdl->data.sdl.xauth = strdup(xauth))) {
            VIR_FREE(sdl);
            goto no_memory;
        }

        if (VIR_REALLOC_N(def->graphics, def->ngraphics+1) < 0) {
            virDomainGraphicsDefFree(sdl);
            goto no_memory;
        }
        def->graphics[def->ngraphics++] = sdl;
    }

    if (def->ngraphics) {
        virDomainVideoDefPtr vid;
        if (VIR_ALLOC(vid) < 0)
            goto no_memory;
        if (def->virtType == VIR_DOMAIN_VIRT_XEN)
            vid->type = VIR_DOMAIN_VIDEO_TYPE_XEN;
        else
            vid->type = video;
        vid->vram = virDomainVideoDefaultRAM(def, vid->type);
        vid->heads = 1;

        if (VIR_REALLOC_N(def->videos, def->nvideos+1) < 0) {
            virDomainVideoDefFree(vid);
            goto no_memory;
        }
        def->videos[def->nvideos++] = vid;
    }

    /*
     * having a balloon is the default, define one with type="none" to avoid it
     */
    if (!def->memballoon) {
        virDomainMemballoonDefPtr memballoon;
        if (VIR_ALLOC(memballoon) < 0)
            goto no_memory;
        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO;

        def->memballoon = memballoon;
    }

    VIR_FREE(nics);

    if (!def->name) {
        if (!(def->name = strdup("unnamed")))
            goto no_memory;
    }

    if (virDomainDefAddImplicitControllers(def) < 0)
        goto error;

    if (cmd->num_args || cmd->num_env) {
        def->ns = caps->ns;
        def->namespaceData = cmd;
    }
    else
        VIR_FREE(cmd);

    return def;

no_memory:
    virReportOOMError();
error:
    VIR_FREE(cmd);
    virDomainDefFree(def);
    VIR_FREE(nics);
    return NULL;
}


virDomainDefPtr qemuParseCommandLineString(virCapsPtr caps,
                                           const char *args)
{
    const char **progenv = NULL;
    const char **progargv = NULL;
    virDomainDefPtr def = NULL;
    int i;

    if (qemuStringToArgvEnv(args, &progenv, &progargv) < 0)
        goto cleanup;

    def = qemuParseCommandLine(caps, progenv, progargv);

cleanup:
    for (i = 0 ; progargv && progargv[i] ; i++)
        VIR_FREE(progargv[i]);
    VIR_FREE(progargv);

    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    return def;
}
