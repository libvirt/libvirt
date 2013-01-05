/*
 * qemu_command.c: QEMU command generation
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#include <config.h>

#include "qemu_command.h"
#include "qemu_hostdev.h"
#include "qemu_capabilities.h"
#include "qemu_bridge_filter.h"
#include "cpu/cpu.h"
#include "viralloc.h"
#include "virlog.h"
#include "virarch.h"
#include "virerror.h"
#include "virutil.h"
#include "virfile.h"
#include "viruuid.h"
#include "c-ctype.h"
#include "domain_nwfilter.h"
#include "domain_audit.h"
#include "domain_conf.h"
#include "snapshot_conf.h"
#include "network/bridge_driver.h"
#include "virnetdevtap.h"
#include "base64.h"
#include "device_conf.h"
#include "virstoragefile.h"

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
              "off",  /* writethrough not supported, so for safety, disable */
              "on",   /* Old 'on' was equivalent to 'writeback' */
              "off",  /* directsync not supported, for safety, disable */
              "off"); /* unsafe not supported, for safety, disable */

VIR_ENUM_IMPL(qemuDiskCacheV2, VIR_DOMAIN_DISK_CACHE_LAST,
              "default",
              "none",
              "writethrough",
              "writeback",
              "directsync",
              "unsafe");

VIR_ENUM_DECL(qemuVideo)

VIR_ENUM_IMPL(qemuVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "std",
              "cirrus",
              "vmware",
              "", /* no arg needed for xen */
              "", /* don't support vbox */
              "qxl");

VIR_ENUM_DECL(qemuDeviceVideo)

VIR_ENUM_IMPL(qemuDeviceVideo, VIR_DOMAIN_VIDEO_TYPE_LAST,
              "VGA",
              "cirrus-vga",
              "vmware-svga",
              "", /* no device for xen */
              "", /* don't support vbox */
              "qxl-vga");

VIR_ENUM_DECL(qemuSoundCodec)

VIR_ENUM_IMPL(qemuSoundCodec, VIR_DOMAIN_SOUND_CODEC_TYPE_LAST,
              "hda-duplex",
              "hda-micro");

VIR_ENUM_DECL(qemuControllerModelUSB)

VIR_ENUM_IMPL(qemuControllerModelUSB, VIR_DOMAIN_CONTROLLER_MODEL_USB_LAST,
              "piix3-usb-uhci",
              "piix4-usb-uhci",
              "usb-ehci",
              "ich9-usb-ehci1",
              "ich9-usb-uhci1",
              "ich9-usb-uhci2",
              "ich9-usb-uhci3",
              "vt82c686b-usb-uhci",
              "pci-ohci",
              "nec-usb-xhci",
              "none");

VIR_ENUM_DECL(qemuDomainFSDriver)
VIR_ENUM_IMPL(qemuDomainFSDriver, VIR_DOMAIN_FS_DRIVER_TYPE_LAST,
              "local",
              "local",
              "handle");


/**
 * qemuPhysIfaceConnect:
 * @def: the definition of the VM (needed by 802.1Qbh and audit)
 * @driver: pointer to the driver instance
 * @net: pointer to he VM's interface description with direct device type
 * @qemuCaps: flags for qemu
 * @vmop: VM operation type
 *
 * Returns a filedescriptor on success or -1 in case of error.
 */
int
qemuPhysIfaceConnect(virDomainDefPtr def,
                     virQEMUDriverPtr driver,
                     virDomainNetDefPtr net,
                     qemuCapsPtr caps,
                     enum virNetDevVPortProfileOp vmop)
{
    int rc;
    char *res_ifname = NULL;
    int vnet_hdr = 0;

    if (qemuCapsGet(caps, QEMU_CAPS_VNET_HDR) &&
        net->model && STREQ(net->model, "virtio"))
        vnet_hdr = 1;

    rc = virNetDevMacVLanCreateWithVPortProfile(
        net->ifname, &net->mac,
        virDomainNetGetActualDirectDev(net),
        virDomainNetGetActualDirectMode(net),
        true, vnet_hdr, def->uuid,
        virDomainNetGetActualVirtPortProfile(net),
        &res_ifname,
        vmop, driver->stateDir,
        virDomainNetGetActualBandwidth(net));
    if (rc >= 0) {
        if (virSecurityManagerSetTapFDLabel(driver->securityManager,
                                            def, rc) < 0)
            goto error;

        virDomainAuditNetDevice(def, net, res_ifname, true);
        VIR_FREE(net->ifname);
        net->ifname = res_ifname;
    }

    return rc;

error:
    ignore_value(virNetDevMacVLanDeleteWithVPortProfile(
                     res_ifname, &net->mac,
                     virDomainNetGetActualDirectDev(net),
                     virDomainNetGetActualDirectMode(net),
                     virDomainNetGetActualVirtPortProfile(net),
                     driver->stateDir));
    VIR_FREE(res_ifname);
    return -1;
}


int
qemuNetworkIfaceConnect(virDomainDefPtr def,
                        virConnectPtr conn,
                        virQEMUDriverPtr driver,
                        virDomainNetDefPtr net,
                        qemuCapsPtr caps)
{
    char *brname = NULL;
    int err;
    int tapfd = -1;
    unsigned int tap_create_flags = VIR_NETDEV_TAP_CREATE_IFUP;
    bool template_ifname = false;
    int actualType = virDomainNetGetActualType(net);

    if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK) {
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
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

    } else if (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
        if (!(brname = strdup(virDomainNetGetActualBridgeName(net)))) {
            virReportOOMError();
            return -1;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Network type %d is not supported"),
                       virDomainNetGetActualType(net));
        return -1;
    }

    if (!net->ifname ||
        STRPREFIX(net->ifname, VIR_NET_GENERATED_PREFIX) ||
        strchr(net->ifname, '%')) {
        VIR_FREE(net->ifname);
        if (!(net->ifname = strdup(VIR_NET_GENERATED_PREFIX "%d"))) {
            virReportOOMError();
            goto cleanup;
        }
        /* avoid exposing vnet%d in getXMLDesc or error outputs */
        template_ifname = true;
    }

    if (qemuCapsGet(caps, QEMU_CAPS_VNET_HDR) &&
        net->model && STREQ(net->model, "virtio")) {
        tap_create_flags |= VIR_NETDEV_TAP_CREATE_VNET_HDR;
    }

    err = virNetDevTapCreateInBridgePort(brname, &net->ifname, &net->mac,
                                         def->uuid, &tapfd,
                                         virDomainNetGetActualVirtPortProfile(net),
                                         virDomainNetGetActualVlan(net),
                                         tap_create_flags);
    virDomainAuditNetDevice(def, net, "/dev/net/tun", tapfd >= 0);
    if (err < 0) {
        if (template_ifname)
            VIR_FREE(net->ifname);
        tapfd = -1;
    }

    if (driver->macFilter) {
        if ((err = networkAllowMacOnPort(driver, net->ifname, &net->mac))) {
            virReportSystemError(err,
                 _("failed to add ebtables rule to allow MAC address on '%s'"),
                                 net->ifname);
        }
    }

    if (tapfd >= 0 &&
        virNetDevBandwidthSet(net->ifname,
                              virDomainNetGetActualBandwidth(net),
                              false) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot set bandwidth limits on %s"),
                       net->ifname);
        VIR_FORCE_CLOSE(tapfd);
        goto cleanup;
    }

    if (tapfd >= 0) {
        if ((net->filter) && (net->ifname)) {
            if (virDomainConfNWFilterInstantiate(conn, def->uuid, net) < 0)
                VIR_FORCE_CLOSE(tapfd);
        }
    }

cleanup:
    VIR_FREE(brname);

    return tapfd;
}


int
qemuOpenVhostNet(virDomainDefPtr def,
                 virDomainNetDefPtr net,
                 qemuCapsPtr caps,
                 int *vhostfd)
{
    *vhostfd = -1;   /* assume we won't use vhost */

    /* If the config says explicitly to not use vhost, return now */
    if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_QEMU) {
       return 0;
    }

    /* If qemu doesn't support vhost-net mode (including the -netdev command
     * option), don't try to open the device.
     */
    if (!(qemuCapsGet(caps, QEMU_CAPS_VHOST_NET) &&
          qemuCapsGet(caps, QEMU_CAPS_NETDEV) &&
          qemuCapsGet(caps, QEMU_CAPS_DEVICE))) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("vhost-net is not supported with "
                                   "this QEMU binary"));
            return -1;
        }
        return 0;
    }

    /* If the nic model isn't virtio, don't try to open. */
    if (!(net->model && STREQ(net->model, "virtio"))) {
        if (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("vhost-net is only supported for "
                                   "virtio network interfaces"));
            return -1;
        }
        return 0;
    }

    *vhostfd = open("/dev/vhost-net", O_RDWR);
    virDomainAuditNetDevice(def, net, "/dev/vhost-net", *vhostfd >= 0);

    /* If the config says explicitly to use vhost and we couldn't open it,
     * report an error.
     */
    if ((*vhostfd < 0) &&
        (net->driver.virtio.name == VIR_DOMAIN_NET_BACKEND_TYPE_VHOST)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s", _("vhost-net was requested for an interface, "
                               "but is unavailable"));
        return -1;
    }
    return 0;
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
    char *dev_name;

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
        STREQ(disk->dst, "hdc"))
        dev_name = strdup("cdrom");
    else
        dev_name = strdup(disk->dst);

    if (!dev_name) {
        virReportOOMError();
        return -1;
    }

    disk->info.alias = dev_name;
    return 0;
}


char *qemuDeviceDriveHostAlias(virDomainDiskDefPtr disk,
                               qemuCapsPtr caps)
{
    char *ret;

    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
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
    char *dev_name;

    if (virDiskNameToBusDeviceIndex(disk, &busid, &devid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot convert disk '%s' to bus/device index"),
                       disk->dst);
        return -1;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->device== VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "ide%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "ide%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK)
            ret = virAsprintf(&dev_name, "scsi%d-hd%d", busid, devid);
        else
            ret = virAsprintf(&dev_name, "scsi%d-cd%d", busid, devid);
        break;
    case VIR_DOMAIN_DISK_BUS_FDC:
        ret = virAsprintf(&dev_name, "floppy%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        ret = virAsprintf(&dev_name, "virtio%d", devid);
        break;
    case VIR_DOMAIN_DISK_BUS_XEN:
        ret = virAsprintf(&dev_name, "xenblk%d", devid);
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported disk name mapping for bus '%s'"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (ret == -1) {
        virReportOOMError();
        return -1;
    }

    disk->info.alias = dev_name;

    return 0;
}

static int
qemuSetScsiControllerModel(virDomainDefPtr def,
                           qemuCapsPtr caps,
                           int *model)
{
    if (*model > 0) {
        switch (*model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            if (!qemuCapsGet(caps, QEMU_CAPS_SCSI_LSI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "lsi scsi controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            if (!qemuCapsGet(caps, QEMU_CAPS_VIRTIO_SCSI_PCI)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support "
                                 "virtio scsi controller"));
                return -1;
            }
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            /*TODO: need checking work here if necessary */
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller model: %s"),
                           virDomainControllerModelSCSITypeToString(*model));
            return -1;
        }
    } else {
        if ((def->os.arch == VIR_ARCH_PPC64) &&
            STREQ(def->os.machine, "pseries")) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI;
        } else if (qemuCapsGet(caps, QEMU_CAPS_SCSI_LSI)) {
            *model = VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC;
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Unable to determine model for scsi controller"));
            return -1;
        }
    }

    return 0;
}

/* Our custom -drive naming scheme used with id= */
static int
qemuAssignDeviceDiskAliasCustom(virDomainDefPtr def,
                                virDomainDiskDefPtr disk,
                                qemuCapsPtr caps)
{
    const char *prefix = virDomainDiskBusTypeToString(disk->bus);
    int controllerModel = -1;

    if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
        if (disk->bus == VIR_DOMAIN_DISK_BUS_SCSI) {
            controllerModel =
                virDomainDiskFindControllerModel(def, disk,
                                                 VIR_DOMAIN_CONTROLLER_TYPE_SCSI);

            if ((qemuSetScsiControllerModel(def, caps, &controllerModel)) < 0)
                return -1;
        }

        if (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI ||
            controllerModel == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.unit) < 0)
                goto no_memory;
        } else {
            if (virAsprintf(&disk->info.alias, "%s%d-%d-%d-%d", prefix,
                            disk->info.addr.drive.controller,
                            disk->info.addr.drive.bus,
                            disk->info.addr.drive.target,
                            disk->info.addr.drive.unit) < 0)
                goto no_memory;
        }
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
qemuAssignDeviceDiskAlias(virDomainDefPtr vmdef,
                          virDomainDiskDefPtr def,
                          qemuCapsPtr caps)
{
    if (qemuCapsGet(caps, QEMU_CAPS_DRIVE)) {
        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE))
            return qemuAssignDeviceDiskAliasCustom(vmdef, def, caps);
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

            if (def->nets[i]->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
                /* type='hostdev' interfaces have a hostdev%d alias */
               continue;
            }
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->nets[i]->info, "net")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
            if ((thisidx = qemuDomainDeviceAliasIndex(def->hostdevs[i]->info, "hostdev")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for hostdev device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&hostdev->info->alias, "hostdev%d", idx) < 0) {
        virReportOOMError();
        return -1;
    }

    return 0;
}


int
qemuAssignDeviceRedirdevAlias(virDomainDefPtr def, virDomainRedirdevDefPtr redirdev, int idx)
{
    if (idx == -1) {
        int i;
        idx = 0;
        for (i = 0 ; i < def->nredirdevs ; i++) {
            int thisidx;
            if ((thisidx = qemuDomainDeviceAliasIndex(&def->redirdevs[i]->info, "redir")) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Unable to determine device index for redirected device"));
                return -1;
            }
            if (thisidx >= idx)
                idx = thisidx + 1;
        }
    }

    if (virAsprintf(&redirdev->info.alias, "redir%d", idx) < 0) {
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


int
qemuAssignDeviceAliases(virDomainDefPtr def, qemuCapsPtr caps)
{
    int i;

    for (i = 0; i < def->ndisks ; i++) {
        if (qemuAssignDeviceDiskAlias(def, def->disks[i], caps) < 0)
            return -1;
    }
    if (qemuCapsGet(caps, QEMU_CAPS_NET_NAME) ||
        qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
        for (i = 0; i < def->nnets ; i++) {
            /* type='hostdev' interfaces are also on the hostdevs list,
             * and will have their alias assigned with other hostdevs.
             */
            if ((def->nets[i]->type != VIR_DOMAIN_NET_TYPE_HOSTDEV) &&
                (qemuAssignDeviceNetAlias(def, def->nets[i], i) < 0)) {
                return -1;
            }
        }
    }

    if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE))
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
    for (i = 0; i < def->nredirdevs ; i++) {
        if (qemuAssignDeviceRedirdevAlias(def, def->redirdevs[i], i) < 0)
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
    for (i = 0; i < def->nconsoles ; i++) {
        if (virAsprintf(&def->consoles[i]->info.alias, "console%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nhubs ; i++) {
        if (virAsprintf(&def->hubs[i]->info.alias, "hub%d", i) < 0)
            goto no_memory;
    }
    for (i = 0; i < def->nsmartcards ; i++) {
        if (virAsprintf(&def->smartcards[i]->info.alias, "smartcard%d", i) < 0)
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

static void
qemuDomainPrimeS390VirtioDevices(virDomainDefPtr def,
                                 enum virDomainDeviceAddressType type)
{
    /*
       declare address-less virtio devices to be of address type 'type'
       only disks, networks, consoles and controllers for now
    */
    int i;

    for (i = 0; i < def->ndisks ; i++) {
        if (def->disks[i]->bus == VIR_DOMAIN_DISK_BUS_VIRTIO &&
            def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->disks[i]->info.type = type;
    }

    for (i = 0; i < def->nnets ; i++) {
        if ((def->os.arch == VIR_ARCH_S390 ||
             def->os.arch == VIR_ARCH_S390X) &&
            def->nets[i]->model == NULL) {
            def->nets[i]->model = strdup("virtio");
        }
        if (STREQ(def->nets[i]->model,"virtio") &&
            def->nets[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            def->nets[i]->info.type = type;
        }
    }

    for (i = 0; i < def->ncontrollers ; i++) {
        if (def->controllers[i]->type ==
            VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL &&
            def->controllers[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            def->controllers[i]->info.type = type;
    }

}

static void
qemuDomainAssignS390Addresses(virDomainDefPtr def, qemuCapsPtr caps)
{
    /* deal with legacy virtio-s390 */
    if (qemuCapsGet(caps, QEMU_CAPS_VIRTIO_S390))
        qemuDomainPrimeS390VirtioDevices(
            def, VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390);
}

static int
qemuSpaprVIOFindByReg(virDomainDefPtr def ATTRIBUTE_UNUSED,
                      virDomainDeviceDefPtr device ATTRIBUTE_UNUSED,
                      virDomainDeviceInfoPtr info, void *opaque)
{
    virDomainDeviceInfoPtr target = opaque;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Match a dev that has a reg, is not us, and has a matching reg */
    if (info->addr.spaprvio.has_reg && info != target &&
        info->addr.spaprvio.reg == target->addr.spaprvio.reg)
        /* Has to be < 0 so virDomainDeviceInfoIterate() will exit */
        return -1;

    return 0;
}

static int
qemuAssignSpaprVIOAddress(virDomainDefPtr def, virDomainDeviceInfoPtr info,
                          unsigned long long default_reg)
{
    bool user_reg;
    int ret;

    if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
        return 0;

    /* Check if the user has assigned the reg already, if so use it */
    user_reg = info->addr.spaprvio.has_reg;
    if (!user_reg) {
        info->addr.spaprvio.reg = default_reg;
        info->addr.spaprvio.has_reg = true;
    }

    ret = virDomainDeviceInfoIterate(def, qemuSpaprVIOFindByReg, info);
    while (ret != 0) {
        if (user_reg) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("spapr-vio address %#llx already in use"),
                           info->addr.spaprvio.reg);
            return -EEXIST;
        }

        /* We assigned the reg, so try a new value */
        info->addr.spaprvio.reg += 0x1000;
        ret = virDomainDeviceInfoIterate(def, qemuSpaprVIOFindByReg, info);
    }

    return 0;
}

int qemuDomainAssignSpaprVIOAddresses(virDomainDefPtr def,
                                      qemuCapsPtr caps)
{
    int i, ret = -1;
    int model;

    /* Default values match QEMU. See spapr_(llan|vscsi|vty).c */

    for (i = 0 ; i < def->nnets; i++) {
        if (def->nets[i]->model &&
            STREQ(def->nets[i]->model, "spapr-vlan"))
            def->nets[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->nets[i]->info,
                                      0x1000ul) < 0)
            goto cleanup;
    }

    for (i = 0 ; i < def->ncontrollers; i++) {
        model = def->controllers[i]->model;
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI) {
            if (qemuSetScsiControllerModel(def, caps, &model) < 0)
                goto cleanup;
        }

        if (model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI &&
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_SCSI)
            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->controllers[i]->info,
                                      0x2000ul) < 0)
            goto cleanup;
    }

    for (i = 0 ; i < def->nserials; i++) {
        if (def->serials[i]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            (def->os.arch == VIR_ARCH_PPC64) &&
            STREQ(def->os.machine, "pseries"))
            def->serials[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO;
        if (qemuAssignSpaprVIOAddress(def, &def->serials[i]->info,
                                      0x30000000ul) < 0)
            goto cleanup;
    }

    /* No other devices are currently supported on spapr-vio */

    ret = 0;

cleanup:
    return ret;
}

#define QEMU_PCI_ADDRESS_LAST_SLOT 31
#define QEMU_PCI_ADDRESS_LAST_FUNCTION 8
struct _qemuDomainPCIAddressSet {
    virHashTablePtr used;
    int nextslot;
};


static char *qemuPCIAddressAsString(virDomainDeviceInfoPtr dev)
{
    char *addr;

    if (dev->addr.pci.domain != 0 ||
        dev->addr.pci.bus != 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Only PCI domain 0 and bus 0 are available"));
        return NULL;
    }

    if (virAsprintf(&addr, "%d:%d:%d.%d",
                    dev->addr.pci.domain,
                    dev->addr.pci.bus,
                    dev->addr.pci.slot,
                    dev->addr.pci.function) < 0) {
        virReportOOMError();
        return NULL;
    }
    return addr;
}


static int qemuCollectPCIAddress(virDomainDefPtr def ATTRIBUTE_UNUSED,
                                 virDomainDeviceDefPtr device,
                                 virDomainDeviceInfoPtr info,
                                 void *opaque)
{
    int ret = -1;
    char *addr = NULL;
    qemuDomainPCIAddressSetPtr addrs = opaque;

    if ((info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI)
        || ((device->type == VIR_DOMAIN_DEVICE_HOSTDEV) &&
            (device->data.hostdev->parent.type != VIR_DOMAIN_DEVICE_NONE))) {
        /* If a hostdev has a parent, its info will be a part of the
         * parent, and will have its address collected during the scan
         * of the parent's device type.
        */
        return 0;
    }

    addr = qemuPCIAddressAsString(info);
    if (!addr)
        goto cleanup;

    if (virHashLookup(addrs->used, addr)) {
        if (info->addr.pci.function != 0) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Attempted double use of PCI Address '%s' "
                             "(may need \"multifunction='on'\" for device on function 0)"),
                           addr);
        } else {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Attempted double use of PCI Address '%s'"), addr);
        }
        goto cleanup;
    }

    VIR_DEBUG("Remembering PCI addr %s", addr);
    if (virHashAddEntry(addrs->used, addr, addr) < 0)
        goto cleanup;
    addr = NULL;

    if ((info->addr.pci.function == 0) &&
        (info->addr.pci.multi != VIR_DEVICE_ADDRESS_PCI_MULTI_ON)) {
        /* a function 0 w/o multifunction=on must reserve the entire slot */
        int function;
        virDomainDeviceInfo temp_info = *info;

        for (function = 1; function < QEMU_PCI_ADDRESS_LAST_FUNCTION; function++) {
            temp_info.addr.pci.function = function;
            addr = qemuPCIAddressAsString(&temp_info);
            if (!addr)
                goto cleanup;

            if (virHashLookup(addrs->used, addr)) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Attempted double use of PCI Address '%s' "
                                 "(need \"multifunction='off'\" for device "
                                 "on function 0)"),
                               addr);
                goto cleanup;
            }

            VIR_DEBUG("Remembering PCI addr %s (multifunction=off for function 0)", addr);
            if (virHashAddEntry(addrs->used, addr, addr))
                goto cleanup;
            addr = NULL;
        }
    }
    ret = 0;
cleanup:
    VIR_FREE(addr);
    return ret;
}


int
qemuDomainAssignPCIAddresses(virDomainDefPtr def,
                             qemuCapsPtr caps,
                             virDomainObjPtr obj)
{
    int ret = -1;
    qemuDomainPCIAddressSetPtr addrs = NULL;
    qemuDomainObjPrivatePtr priv = NULL;

    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
        if (!(addrs = qemuDomainPCIAddressSetCreate(def)))
            goto cleanup;

        if (qemuAssignDevicePCISlots(def, caps, addrs) < 0)
            goto cleanup;
    }

    if (obj && obj->privateData) {
        priv = obj->privateData;
        if (addrs) {
            /* if this is the live domain object, we persist the PCI addresses*/
            qemuDomainPCIAddressSetFree(priv->pciaddrs);
            priv->persistentAddrs = 1;
            priv->pciaddrs = addrs;
            addrs = NULL;
        } else {
            priv->persistentAddrs = 0;
        }
    }

    ret = 0;

cleanup:
    qemuDomainPCIAddressSetFree(addrs);

    return ret;
}

int qemuDomainAssignAddresses(virDomainDefPtr def,
                              qemuCapsPtr caps,
                              virDomainObjPtr obj)
{
    int rc;

    rc = qemuDomainAssignSpaprVIOAddresses(def, caps);
    if (rc)
        return rc;

    qemuDomainAssignS390Addresses(def, caps);

    return qemuDomainAssignPCIAddresses(def, caps, obj);
}

static void
qemuDomainPCIAddressSetFreeEntry(void *payload,
                                 const void *name ATTRIBUTE_UNUSED)
{
    VIR_FREE(payload);
}

qemuDomainPCIAddressSetPtr qemuDomainPCIAddressSetCreate(virDomainDefPtr def)
{
    qemuDomainPCIAddressSetPtr addrs;

    if (VIR_ALLOC(addrs) < 0)
        goto no_memory;

    if (!(addrs->used = virHashCreate(10, qemuDomainPCIAddressSetFreeEntry)))
        goto error;

    if (virDomainDeviceInfoIterate(def, qemuCollectPCIAddress, addrs) < 0)
        goto error;

    return addrs;

no_memory:
    virReportOOMError();
error:
    qemuDomainPCIAddressSetFree(addrs);
    return NULL;
}

/* check whether the slot is used by the other device
 * Return 0 if the slot is not used by the other device, or -1 if the slot
 * is used by the other device.
 */
static int qemuDomainPCIAddressCheckSlot(qemuDomainPCIAddressSetPtr addrs,
                                         virDomainDeviceInfoPtr dev)
{
    char *addr;
    virDomainDeviceInfo temp_dev;
    int function;

    temp_dev = *dev;
    for (function = 0; function < QEMU_PCI_ADDRESS_LAST_FUNCTION; function++) {
        temp_dev.addr.pci.function = function;
        addr = qemuPCIAddressAsString(&temp_dev);
        if (!addr)
            return -1;

        if (virHashLookup(addrs->used, addr)) {
            VIR_FREE(addr);
            return -1;
        }

        VIR_FREE(addr);
    }

    return 0;
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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

int qemuDomainPCIAddressReserveFunction(qemuDomainPCIAddressSetPtr addrs,
                                        int slot, int function)
{
    virDomainDeviceInfo dev;

    dev.addr.pci.domain = 0;
    dev.addr.pci.bus = 0;
    dev.addr.pci.slot = slot;
    dev.addr.pci.function = function;

    return qemuDomainPCIAddressReserveAddr(addrs, &dev);
}

int qemuDomainPCIAddressReserveSlot(qemuDomainPCIAddressSetPtr addrs,
                                    int slot)
{
    int function;

    for (function = 0; function < QEMU_PCI_ADDRESS_LAST_FUNCTION; function++) {
        if (qemuDomainPCIAddressReserveFunction(addrs, slot, function) < 0)
            goto cleanup;
    }

    return 0;

cleanup:
    for (function--; function >= 0; function--) {
        qemuDomainPCIAddressReleaseFunction(addrs, slot, function);
    }
    return -1;
}

int qemuDomainPCIAddressEnsureAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    int ret = 0;
    if (dev->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        /* We do not support hotplug multi-function PCI device now, so we should
         * reserve the whole slot. The function of the PCI device must be 0.
         */
        if (dev->addr.pci.function != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only PCI device addresses with function=0"
                             " are supported"));
            return -1;
        }

        ret = qemuDomainPCIAddressReserveSlot(addrs, dev->addr.pci.slot);
    } else {
        ret = qemuDomainPCIAddressSetNextAddr(addrs, dev);
    }
    return ret;
}


int qemuDomainPCIAddressReleaseAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    char *addr;
    int ret;

    addr = qemuPCIAddressAsString(dev);
    if (!addr)
        return -1;

    ret = virHashRemoveEntry(addrs->used, addr);

    VIR_FREE(addr);

    return ret;
}

int qemuDomainPCIAddressReleaseFunction(qemuDomainPCIAddressSetPtr addrs,
                                        int slot, int function)
{
    virDomainDeviceInfo dev;

    dev.addr.pci.domain = 0;
    dev.addr.pci.bus = 0;
    dev.addr.pci.slot = slot;
    dev.addr.pci.function = function;

    return qemuDomainPCIAddressReleaseAddr(addrs, &dev);
}

int qemuDomainPCIAddressReleaseSlot(qemuDomainPCIAddressSetPtr addrs, int slot)
{
    virDomainDeviceInfo dev;
    char *addr;
    int ret = 0;
    unsigned int *function = &dev.addr.pci.function;

    dev.addr.pci.domain = 0;
    dev.addr.pci.bus = 0;
    dev.addr.pci.slot = slot;

    for (*function = 0; *function < QEMU_PCI_ADDRESS_LAST_FUNCTION; (*function)++) {
        addr = qemuPCIAddressAsString(&dev);
        if (!addr)
            return -1;

        if (!virHashLookup(addrs->used, addr)) {
            VIR_FREE(addr);
            continue;
        }

        VIR_FREE(addr);

        if (qemuDomainPCIAddressReleaseFunction(addrs, slot, *function) < 0)
            ret = -1;
    }

    return ret;
}

void qemuDomainPCIAddressSetFree(qemuDomainPCIAddressSetPtr addrs)
{
    if (!addrs)
        return;

    virHashFree(addrs->used);
    VIR_FREE(addrs);
}


static int qemuDomainPCIAddressGetNextSlot(qemuDomainPCIAddressSetPtr addrs)
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
        maybe.addr.pci.function = 0;

        if (!(addr = qemuPCIAddressAsString(&maybe)))
            return -1;

        if (qemuDomainPCIAddressCheckSlot(addrs, &maybe) < 0) {
            VIR_DEBUG("PCI addr %s already in use", addr);
            VIR_FREE(addr);
            continue;
        }

        VIR_DEBUG("Found free PCI addr %s", addr);
        VIR_FREE(addr);

        return i;
    }

    virReportError(VIR_ERR_INTERNAL_ERROR,
                   "%s", _("No more available PCI addresses"));
    return -1;
}

int qemuDomainPCIAddressSetNextAddr(qemuDomainPCIAddressSetPtr addrs,
                                    virDomainDeviceInfoPtr dev)
{
    int slot = qemuDomainPCIAddressGetNextSlot(addrs);

    if (slot < 0)
        return -1;

    if (qemuDomainPCIAddressReserveSlot(addrs, slot) < 0)
        return -1;

    dev->type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
    dev->addr.pci.bus = 0;
    dev->addr.pci.domain = 0;
    dev->addr.pci.slot = slot;
    dev->addr.pci.function = 0;

    addrs->nextslot = slot + 1;
    if (QEMU_PCI_ADDRESS_LAST_SLOT < addrs->nextslot)
        addrs->nextslot = 0;

    return 0;
}


#define IS_USB2_CONTROLLER(ctrl) \
    (((ctrl)->type == VIR_DOMAIN_CONTROLLER_TYPE_USB) && \
     ((ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2 || \
      (ctrl)->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3))

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
 *  - Watchdog (not IB700)
 *
 * Prior to this function being invoked, qemuCollectPCIAddress() will have
 * added all existing PCI addresses from the 'def' to 'addrs'. Thus this
 * function must only try to reserve addresses if info.type == NONE and
 * skip over info.type == PCI
 */
int
qemuAssignDevicePCISlots(virDomainDefPtr def,
                         qemuCapsPtr caps,
                         qemuDomainPCIAddressSetPtr addrs)
{
    size_t i, j;
    bool reservedIDE = false;
    bool reservedUSB = false;
    int function;
    bool qemuDeviceVideoUsable = qemuCapsGet(caps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY);

    /* Host bridge */
    if (qemuDomainPCIAddressReserveSlot(addrs, 0) < 0)
        goto error;

    /* Verify that first IDE and USB controllers (if any) is on the PIIX3, fn 1 */
    for (i = 0; i < def->ncontrollers ; i++) {
        /* First IDE controller lives on the PIIX3 at slot=1, function=1 */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("Primary IDE controller must have PCI address 0:0:1.1"));
                    goto error;
                }
                /* If TYPE==PCI, then qemuCollectPCIAddress() function
                 * has already reserved the address, so we must skip */
                reservedIDE = true;
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 1;
            }
        } else if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                   def->controllers[i]->idx == 0 &&
                   (def->controllers[i]->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI ||
                    def->controllers[i]->model == -1)) {
            if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                if (def->controllers[i]->info.addr.pci.domain != 0 ||
                    def->controllers[i]->info.addr.pci.bus != 0 ||
                    def->controllers[i]->info.addr.pci.slot != 1 ||
                    def->controllers[i]->info.addr.pci.function != 2) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PIIX3 USB controller must have PCI address 0:0:1.2"));
                    goto error;
                }
                reservedUSB = true;
            } else {
                def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
                def->controllers[i]->info.addr.pci.domain = 0;
                def->controllers[i]->info.addr.pci.bus = 0;
                def->controllers[i]->info.addr.pci.slot = 1;
                def->controllers[i]->info.addr.pci.function = 2;
            }
        }
    }

    /* PIIX3 (ISA bridge, IDE controller, something else unknown, USB controller)
     * hardcoded slot=1, multifunction device
     */
    for (function = 0; function < QEMU_PCI_ADDRESS_LAST_FUNCTION; function++) {
        if ((function == 1 && reservedIDE) ||
            (function == 2 && reservedUSB))
            /* we have reserved this pci address */
            continue;

        if (qemuDomainPCIAddressReserveFunction(addrs, 1, function) < 0)
            goto error;
    }

    if (def->nvideos > 0) {
        virDomainVideoDefPtr primaryVideo = def->videos[0];
        if (primaryVideo->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            primaryVideo->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            primaryVideo->info.addr.pci.domain = 0;
            primaryVideo->info.addr.pci.bus = 0;
            primaryVideo->info.addr.pci.slot = 2;
            primaryVideo->info.addr.pci.function = 0;

            if (qemuDomainPCIAddressCheckSlot(addrs, &primaryVideo->info) < 0) {
                if (qemuDeviceVideoUsable) {
                    virResetLastError();
                    if (qemuDomainPCIAddressSetNextAddr(addrs, &primaryVideo->info) < 0)
                        goto error;
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("PCI address 0:0:2.0 is in use, "
                                     "QEMU needs it for primary video"));
                    goto error;
                }
            } else if (qemuDomainPCIAddressReserveSlot(addrs, 2) < 0) {
                goto error;
            }
        } else if (!qemuDeviceVideoUsable) {
            if (primaryVideo->info.addr.pci.domain != 0 ||
                primaryVideo->info.addr.pci.bus != 0 ||
                primaryVideo->info.addr.pci.slot != 2 ||
                primaryVideo->info.addr.pci.function != 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Primary video card must have PCI address 0:0:2.0"));
                goto error;
            }
            /* If TYPE==PCI, then qemuCollectPCIAddress() function
             * has already reserved the address, so we must skip */
        }
    } else if (!qemuDeviceVideoUsable) {
        virDomainDeviceInfo dev;
        memset(&dev, 0, sizeof(dev));
        dev.addr.pci.slot = 2;

        if (qemuDomainPCIAddressCheckSlot(addrs, &dev) < 0) {
            VIR_DEBUG("PCI address 0:0:2.0 in use, future addition of a video"
                      " device will not be possible without manual"
                      " intervention");
            virResetLastError();
        } else if (qemuDomainPCIAddressReserveSlot(addrs, 2) < 0) {
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
        /* type='hostdev' network devices might be USB, and are also
         * in hostdevs list anyway, so handle them with other hostdevs
         * instead of here.
         */
        if ((def->nets[i]->type == VIR_DOMAIN_NET_TYPE_HOSTDEV) ||
            (def->nets[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)) {
            continue;
        }
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

    /* Device controllers (SCSI, USB, but not IDE, FDC or CCID) */
    for (i = 0; i < def->ncontrollers ; i++) {
        /* FDC lives behind the ISA bridge; CCID is a usb device */
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_FDC ||
            def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_CCID)
            continue;

        /* First IDE controller lives on the PIIX3 at slot=1, function=1,
           dealt with earlier on*/
        if (def->controllers[i]->type == VIR_DOMAIN_CONTROLLER_TYPE_IDE &&
            def->controllers[i]->idx == 0)
            continue;

        if (def->controllers[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO)
            continue;
        if (def->controllers[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;

        /* USB2 needs special handling to put all companions in the same slot */
        if (IS_USB2_CONTROLLER(def->controllers[i])) {
            virDevicePCIAddress addr = { 0, 0, 0, 0, false };
            for (j = 0 ; j < i ; j++) {
                if (IS_USB2_CONTROLLER(def->controllers[j]) &&
                    def->controllers[j]->idx == def->controllers[i]->idx) {
                    addr = def->controllers[j]->info.addr.pci;
                    break;
                }
            }

            switch (def->controllers[i]->model) {
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
                addr.function = 7;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
                addr.function = 0;
                addr.multi = VIR_DEVICE_ADDRESS_PCI_MULTI_ON;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
                addr.function = 1;
                break;
            case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
                addr.function = 2;
                break;
            }

            if (addr.slot == 0) {
                /* This is the first part of the controller, so need
                 * to find a free slot & then reserve a function */
                int slot = qemuDomainPCIAddressGetNextSlot(addrs);
                if (slot < 0)
                    goto error;

                addr.slot = slot;
                addrs->nextslot = addr.slot + 1;
                if (QEMU_PCI_ADDRESS_LAST_SLOT < addrs->nextslot)
                    addrs->nextslot = 0;
            }
            /* Finally we can reserve the slot+function */
            if (qemuDomainPCIAddressReserveFunction(addrs,
                                                    addr.slot,
                                                    addr.function) < 0)
                goto error;

            def->controllers[i]->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI;
            def->controllers[i]->info.addr.pci = addr;
        } else {
            if (qemuDomainPCIAddressSetNextAddr(addrs, &def->controllers[i]->info) < 0)
                goto error;
        }
    }

    /* Disks (VirtIO only for now) */
    for (i = 0; i < def->ndisks ; i++) {
        /* Only VirtIO disks use PCI addrs */
        if (def->disks[i]->bus != VIR_DOMAIN_DISK_BUS_VIRTIO)
            continue;

        /* don't touch s390 devices */
        if (def->disks[i]->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI ||
            def->disks[i]->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)
            continue;

        if (def->disks[i]->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio only support device address type 'PCI'"));
            goto error;
        }

        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->disks[i]->info) < 0)
            goto error;
    }

    /* Host PCI devices */
    for (i = 0; i < def->nhostdevs ; i++) {
        if (def->hostdevs[i]->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
            continue;
        if (def->hostdevs[i]->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            def->hostdevs[i]->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI)
            continue;

        if (qemuDomainPCIAddressSetNextAddr(addrs, def->hostdevs[i]->info) < 0)
            goto error;
    }

    /* VirtIO balloon */
    if (def->memballoon &&
        def->memballoon->model == VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO &&
        def->memballoon->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->memballoon->info) < 0)
            goto error;
    }

    /* A watchdog - skip IB700, it is not a PCI device */
    if (def->watchdog &&
        def->watchdog->model != VIR_DOMAIN_WATCHDOG_MODEL_IB700 &&
        def->watchdog->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
        if (qemuDomainPCIAddressSetNextAddr(addrs, &def->watchdog->info) < 0)
            goto error;
    }

    /* Further non-primary video cards which have to be qxl type */
    for (i = 1; i < def->nvideos ; i++) {
        if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("non-primary video device must be type of 'qxl'"));
            goto error;
        }
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
    for (i = 0; i < def->nhubs ; i++) {
        /* Nada - none are PCI based (yet) */
    }

    return 0;

error:
    return -1;
}

static void
qemuUsbId(virBufferPtr buf, int idx)
{
    if (idx == 0)
        virBufferAsprintf(buf, "usb");
    else
        virBufferAsprintf(buf, "usb%d", idx);
}

static int
qemuBuildDeviceAddressStr(virBufferPtr buf,
                          virDomainDeviceInfoPtr info,
                          qemuCapsPtr caps)
{
    if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
        if (info->addr.pci.domain != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only PCI device addresses with domain=0 are supported"));
            return -1;
        }
        if (info->addr.pci.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Only PCI device addresses with bus=0 are supported"));
            return -1;
        }
        if (qemuCapsGet(caps, QEMU_CAPS_PCI_MULTIFUNCTION)) {
            if (info->addr.pci.function > 7) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("The function of PCI device addresses must "
                                 "less than 8"));
                return -1;
            }
        } else {
            if (info->addr.pci.function != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only PCI device addresses with function=0 "
                                 "are supported with this QEMU binary"));
                return -1;
            }
            if (info->addr.pci.multi == VIR_DEVICE_ADDRESS_PCI_MULTI_ON) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("'multifunction=on' is not supported with "
                                 "this QEMU binary"));
                return -1;
            }
        }

        /* XXX
         * When QEMU grows support for > 1 PCI bus, then pci.0 changes
         * to pci.1, pci.2, etc
         * When QEMU grows support for > 1 PCI domain, then pci.0 change
         * to pciNN.0  where NN is the domain number
         */
        if (qemuCapsGet(caps, QEMU_CAPS_PCI_MULTIBUS))
            virBufferAsprintf(buf, ",bus=pci.0");
        else
            virBufferAsprintf(buf, ",bus=pci");
        if (info->addr.pci.multi == VIR_DEVICE_ADDRESS_PCI_MULTI_ON)
            virBufferAddLit(buf, ",multifunction=on");
        else if (info->addr.pci.multi == VIR_DEVICE_ADDRESS_PCI_MULTI_OFF)
            virBufferAddLit(buf, ",multifunction=off");
        virBufferAsprintf(buf, ",addr=0x%x", info->addr.pci.slot);
        if (info->addr.pci.function != 0)
           virBufferAsprintf(buf, ".0x%x", info->addr.pci.function);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
        virBufferAsprintf(buf, ",bus=");
        qemuUsbId(buf, info->addr.usb.bus);
        virBufferAsprintf(buf, ".0,port=%s", info->addr.usb.port);
    } else if (info->type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO) {
        if (info->addr.spaprvio.has_reg)
            virBufferAsprintf(buf, ",reg=0x%llx", info->addr.spaprvio.reg);
    }

    return 0;
}

static int
qemuBuildRomStr(virBufferPtr buf,
                virDomainDeviceInfoPtr info,
                qemuCapsPtr caps)
{
    if (info->rombar || info->romfile) {
        if (info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("rombar and romfile are supported only for PCI devices"));
            return -1;
        }
        if (!qemuCapsGet(caps, QEMU_CAPS_PCI_ROMBAR)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("rombar and romfile not supported in this QEMU binary"));
            return -1;
        }

        switch (info->rombar) {
        case VIR_DOMAIN_PCI_ROMBAR_OFF:
            virBufferAddLit(buf, ",rombar=0");
            break;
        case VIR_DOMAIN_PCI_ROMBAR_ON:
            virBufferAddLit(buf, ",rombar=1");
            break;
        default:
            break;
        }
        if (info->romfile)
           virBufferAsprintf(buf, ",romfile=%s", info->romfile);
    }
    return 0;
}

static int
qemuBuildIoEventFdStr(virBufferPtr buf,
                      enum virDomainIoEventFd use,
                      qemuCapsPtr caps)
{
    if (use && qemuCapsGet(caps, QEMU_CAPS_VIRTIO_IOEVENTFD))
        virBufferAsprintf(buf, ",ioeventfd=%s",
                          virDomainIoEventFdTypeToString(use));
    return 0;
}

#define QEMU_SERIAL_PARAM_ACCEPTED_CHARS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"

static int
qemuSafeSerialParamValue(const char *value)
{
    if (strspn(value, QEMU_SERIAL_PARAM_ACCEPTED_CHARS) != strlen(value)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("driver serial '%s' contains unsafe characters"),
                       value);
        return -1;
    }

    return 0;
}


static int
qemuBuildRBDString(virConnectPtr conn,
                   virDomainDiskDefPtr disk,
                   virBufferPtr opt)
{
    int i, ret = 0;
    virSecretPtr sec = NULL;
    char *secret = NULL;
    size_t secret_size;

    virBufferEscape(opt, ',', ",", "rbd:%s", disk->src);
    if (disk->auth.username) {
        virBufferEscape(opt, '\\', ":", ":id=%s", disk->auth.username);
        /* look up secret */
        switch (disk->auth.secretType) {
        case VIR_DOMAIN_DISK_SECRET_TYPE_UUID:
            sec = virSecretLookupByUUID(conn,
                                        disk->auth.secret.uuid);
            break;
        case VIR_DOMAIN_DISK_SECRET_TYPE_USAGE:
            sec = virSecretLookupByUsage(conn,
                                         VIR_SECRET_USAGE_TYPE_CEPH,
                                         disk->auth.secret.usage);
            break;
        }

        if (sec) {
            char *base64 = NULL;

            secret = (char *)conn->secretDriver->getValue(sec, &secret_size, 0,
                                                          VIR_SECRET_GET_VALUE_INTERNAL_CALL);
            if (secret == NULL) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("could not get the value of the secret for username %s"),
                               disk->auth.username);
                goto error;
            }
            /* qemu/librbd wants it base64 encoded */
            base64_encode_alloc(secret, secret_size, &base64);
            if (!base64) {
                virReportOOMError();
                goto error;
            }
            virBufferEscape(opt, '\\', ":",
                            ":key=%s:auth_supported=cephx\\;none",
                            base64);
            VIR_FREE(base64);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("rbd username '%s' specified but secret not found"),
                           disk->auth.username);
            goto error;
        }
    } else {
        virBufferAddLit(opt, ":auth_supported=none");
    }

    if (disk->nhosts > 0) {
        virBufferAddLit(opt, ":mon_host=");
        for (i = 0; i < disk->nhosts; ++i) {
            if (i) {
                virBufferAddLit(opt, "\\;");
            }
            if (disk->hosts[i].port) {
                virBufferAsprintf(opt, "%s\\:%s",
                                  disk->hosts[i].name,
                                  disk->hosts[i].port);
            } else {
                virBufferAsprintf(opt, "%s", disk->hosts[i].name);
            }
        }
    }

cleanup:
    VIR_FREE(secret);
    virObjectUnref(sec);

    return ret;

error:
    ret = -1;
    goto cleanup;
}

static int qemuAddRBDHost(virDomainDiskDefPtr disk, char *hostport)
{
    char *port;

    disk->nhosts++;
    if (VIR_REALLOC_N(disk->hosts, disk->nhosts) < 0)
        goto no_memory;

    port = strstr(hostport, "\\:");
    if (port) {
        *port = '\0';
        port += 2;
        disk->hosts[disk->nhosts-1].port = strdup(port);
        if (!disk->hosts[disk->nhosts-1].port)
            goto no_memory;
    } else {
        disk->hosts[disk->nhosts-1].port = strdup("6789");
        if (!disk->hosts[disk->nhosts-1].port)
            goto no_memory;
    }
    disk->hosts[disk->nhosts-1].name = strdup(hostport);
    if (!disk->hosts[disk->nhosts-1].name)
        goto no_memory;

    disk->hosts[disk->nhosts-1].transport = VIR_DOMAIN_DISK_PROTO_TRANS_TCP;
    disk->hosts[disk->nhosts-1].socket = NULL;

    return 0;

no_memory:
    virReportOOMError();
    VIR_FREE(disk->hosts[disk->nhosts-1].port);
    VIR_FREE(disk->hosts[disk->nhosts-1].name);
    return -1;
}

/* disk->src initially has everything after the rbd: prefix */
static int qemuParseRBDString(virDomainDiskDefPtr disk)
{
    char *options = NULL;
    char *p, *e, *next;

    p = strchr(disk->src, ':');
    if (p) {
        options = strdup(p + 1);
        if (!options)
            goto no_memory;
        *p = '\0';
    }

    /* options */
    if (!options)
        return 0; /* all done */

    p = options;
    while (*p) {
        /* find : delimiter or end of string */
        for (e = p; *e && *e != ':'; ++e) {
            if (*e == '\\') {
                e++;
                if (*e == '\0')
                    break;
            }
        }
        if (*e == '\0') {
            next = e;    /* last kv pair */
        } else {
            next = e + 1;
            *e = '\0';
        }

        if (STRPREFIX(p, "id=")) {
            disk->auth.username = strdup(p + strlen("id="));
            if (!disk->auth.username)
                goto no_memory;
        }
        if (STRPREFIX(p, "mon_host=")) {
            char *h, *sep;

            h = p + strlen("mon_host=");
            while (h < e) {
                for (sep = h; sep < e; ++sep) {
                    if (*sep == '\\' && (sep[1] == ',' ||
                                         sep[1] == ';' ||
                                         sep[1] == ' ')) {
                        *sep = '\0';
                        sep += 2;
                        break;
                    }
                }
                if (qemuAddRBDHost(disk, h) < 0) {
                    return -1;
                }
                h = sep;
            }
        }

        p = next;
    }
    VIR_FREE(options);
    return 0;

no_memory:
    VIR_FREE(options);
    virReportOOMError();
    return -1;
}

static int
qemuParseGlusterString(virDomainDiskDefPtr def)
{
    int ret = -1;
    char *transp = NULL;
    char *sock = NULL;
    char *volimg = NULL;
    virURIPtr uri = NULL;

    if (!(uri = virURIParse(def->src))) {
        return -1;
    }

    if (VIR_ALLOC(def->hosts) < 0)
        goto no_memory;

    if (STREQ(uri->scheme, "gluster")) {
        def->hosts->transport = VIR_DOMAIN_DISK_PROTO_TRANS_TCP;
    } else if (STRPREFIX(uri->scheme, "gluster+")) {
        transp = strchr(uri->scheme, '+') + 1;
        def->hosts->transport = virDomainDiskProtocolTransportTypeFromString(transp);
        if (def->hosts->transport < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Invalid gluster transport type '%s'"), transp);
            goto error;
        }
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid transport/scheme '%s'"), uri->scheme);
        goto error;
    }
    def->nhosts = 0; /* set to 1 once everything succeeds */

    if (def->hosts->transport != VIR_DOMAIN_DISK_PROTO_TRANS_UNIX) {
        def->hosts->name = strdup(uri->server);
        if (!def->hosts->name)
            goto no_memory;

        if (virAsprintf(&def->hosts->port, "%d", uri->port) < 0)
            goto no_memory;
    } else {
        def->hosts->name = NULL;
        def->hosts->port = 0;
        if (uri->query) {
            if (STRPREFIX(uri->query, "socket=")) {
                sock = strchr(uri->query, '=') + 1;
                def->hosts->socket = strdup(sock);
                if (!def->hosts->socket)
                    goto no_memory;
            } else {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Invalid query parameter '%s'"), uri->query);
                goto error;
            }
        }
    }
    volimg = uri->path + 1; /* skip the prefix slash */
    def->src = strdup(volimg);
    if (!def->src)
        goto no_memory;

    def->nhosts = 1;
    ret = 0;

cleanup:
    virURIFree(uri);

    return ret;

no_memory:
    virReportOOMError();
error:
    virDomainDiskHostDefFree(def->hosts);
    VIR_FREE(def->hosts);
    goto cleanup;
}

static int
qemuBuildGlusterString(virDomainDiskDefPtr disk, virBufferPtr opt)
{
    int ret = -1;
    int port = 0;
    char *tmpscheme = NULL;
    char *volimg = NULL;
    char *sock = NULL;
    char *builturi = NULL;
    const char *transp = NULL;
    virURI uri = {
        .port = port /* just to clear rest of bits */
    };

    if (disk->nhosts != 1) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("gluster accepts only one host"));
        return -1;
    }

    virBufferAddLit(opt, "file=");
    transp = virDomainDiskProtocolTransportTypeToString(disk->hosts->transport);

    if (virAsprintf(&tmpscheme, "gluster+%s", transp) < 0)
        goto no_memory;

    if (virAsprintf(&volimg, "/%s", disk->src) < 0)
        goto no_memory;

    if (disk->hosts->port) {
        port = atoi(disk->hosts->port);
    }

    if (disk->hosts->socket &&
        virAsprintf(&sock, "socket=%s", disk->hosts->socket) < 0)
        goto no_memory;

    uri.scheme = tmpscheme; /* gluster+<transport> */
    uri.server = disk->hosts->name;
    uri.port = port;
    uri.path = volimg;
    uri.query = sock;

    builturi = virURIFormat(&uri);
    virBufferEscape(opt, ',', ",", "%s", builturi);

    ret = 0;

cleanup:
    VIR_FREE(builturi);
    VIR_FREE(tmpscheme);
    VIR_FREE(volimg);
    VIR_FREE(sock);

    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}

char *
qemuBuildDriveStr(virConnectPtr conn ATTRIBUTE_UNUSED,
                  virDomainDiskDefPtr disk,
                  bool bootable,
                  qemuCapsPtr caps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    const char *trans =
        virDomainDiskGeometryTransTypeToString(disk->geometry.trans);
    int idx = virDiskNameToIndex(disk->dst);
    int busid = -1, unitid = -1;

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for scsi disk"));
            goto error;
        }

        /* Setting bus= attr for SCSI drives, causes a controller
         * to be created. Yes this is slightly odd. It is not possible
         * to have > 1 bus on a SCSI controller (yet). */
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("SCSI controller only supports 1 bus"));
            goto error;
        }
        busid = disk->info.addr.drive.controller;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for ide disk"));
            goto error;
        }
        /* We can only have 1 IDE controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        busid = disk->info.addr.drive.bus;
        unitid = disk->info.addr.drive.unit;
        break;

    case VIR_DOMAIN_DISK_BUS_FDC:
        if (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for fdc disk"));
            goto error;
        }
        /* We can only have 1 FDC controller (currently) */
        if (disk->info.addr.drive.controller != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s controller is supported"), bus);
            goto error;
        }
        /* We can only have 1 FDC bus (currently) */
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Only 1 %s bus is supported"), bus);
            goto error;
        }
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for controller fdc"));
            goto error;
        }
        unitid = disk->info.addr.drive.unit;

        break;

    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (qemuCapsGet(caps, QEMU_CAPS_VIRTIO_S390) &&
            (disk->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390)) {
            /* Paranoia - leave in here for now */
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("unexpected address type for s390-virtio disk"));
            goto error;
        }
        idx = -1;
        break;

    case VIR_DOMAIN_DISK_BUS_XEN:
        /* Xen has no address type currently, so assign based on index */
        break;
    }

    /* disk->src is NULL when we use nbd disks */
    if ((disk->src ||
        (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
         disk->protocol == VIR_DOMAIN_DISK_PROTOCOL_NBD)) &&
        !((disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY ||
           disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
          disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN)) {
        if (disk->type == VIR_DOMAIN_DISK_TYPE_DIR) {
            /* QEMU only supports magic FAT format for now */
            if (disk->format > 0 && disk->format != VIR_STORAGE_FILE_FAT) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unsupported disk driver type for '%s'"),
                               virStorageFileFormatTypeToString(disk->format));
                goto error;
            }
            if (!disk->readonly) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("cannot create virtual FAT disks in read-write mode"));
                goto error;
            }
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                virBufferEscape(&opt, ',', ",", "file=fat:floppy:%s,",
                                disk->src);
            else
                virBufferEscape(&opt, ',', ",", "file=fat:%s,", disk->src);
        } else if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
            switch (disk->protocol) {
            case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                if (disk->nhosts != 1) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("NBD accepts only one host"));
                    goto error;
                }
                virBufferAsprintf(&opt, "file=nbd:%s:%s,",
                                  disk->hosts->name, disk->hosts->port);
                break;
            case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                virBufferAddLit(&opt, "file=");
                if (qemuBuildRBDString(conn, disk, &opt) < 0)
                    goto error;
                virBufferAddChar(&opt, ',');
                break;
            case VIR_DOMAIN_DISK_PROTOCOL_GLUSTER:
                if (qemuBuildGlusterString(disk, &opt) < 0)
                    goto error;
                virBufferAddChar(&opt, ',');
                break;

            case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                if (disk->nhosts == 0) {
                    virBufferEscape(&opt, ',', ",", "file=sheepdog:%s,",
                                    disk->src);
                } else {
                    /* only one host is supported now */
                    virBufferAsprintf(&opt, "file=sheepdog:%s:%s:",
                                      disk->hosts->name, disk->hosts->port);
                    virBufferEscape(&opt, ',', ",", "%s,", disk->src);
                }
                break;
            }
        } else {
            if ((disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) &&
                (disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("tray status 'open' is invalid for "
                                 "block type disk"));
                goto error;
            }
            virBufferEscape(&opt, ',', ",", "file=%s,", disk->src);
        }
    }
    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE))
        virBufferAddLit(&opt, "if=none");
    else
        virBufferAsprintf(&opt, "if=%s", bus);

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) {
        if ((disk->bus == VIR_DOMAIN_DISK_BUS_SCSI)) {
            if (!qemuCapsGet(caps, QEMU_CAPS_SCSI_CD))
                virBufferAddLit(&opt, ",media=cdrom");
        } else if (disk->bus == VIR_DOMAIN_DISK_BUS_IDE) {
            if (!qemuCapsGet(caps, QEMU_CAPS_IDE_CD))
                virBufferAddLit(&opt, ",media=cdrom");
        } else {
            virBufferAddLit(&opt, ",media=cdrom");
        }
    }

    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
        virBufferAsprintf(&opt, ",id=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    } else {
        if (busid == -1 && unitid == -1) {
            if (idx != -1)
                virBufferAsprintf(&opt, ",index=%d", idx);
        } else {
            if (busid != -1)
                virBufferAsprintf(&opt, ",bus=%d", busid);
            if (unitid != -1)
                virBufferAsprintf(&opt, ",unit=%d", unitid);
        }
    }
    if (bootable &&
        qemuCapsGet(caps, QEMU_CAPS_DRIVE_BOOT) &&
        (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
         disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) &&
        disk->bus != VIR_DOMAIN_DISK_BUS_IDE)
        virBufferAddLit(&opt, ",boot=on");
    if (disk->readonly &&
        qemuCapsGet(caps, QEMU_CAPS_DRIVE_READONLY))
        virBufferAddLit(&opt, ",readonly=on");
    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient disks not supported yet"));
        goto error;
    }
    if (disk->format > 0 &&
        disk->type != VIR_DOMAIN_DISK_TYPE_DIR &&
        qemuCapsGet(caps, QEMU_CAPS_DRIVE_FORMAT))
        virBufferAsprintf(&opt, ",format=%s",
                          virStorageFileFormatTypeToString(disk->format));

    /* generate geometry command string */
    if (disk->geometry.cylinders > 0 &&
        disk->geometry.heads > 0 &&
        disk->geometry.sectors > 0) {

        virBufferAsprintf(&opt, ",cyls=%u,heads=%u,secs=%u",
                          disk->geometry.cylinders,
                          disk->geometry.heads,
                          disk->geometry.sectors);

        if (disk->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT)
            virBufferEscapeString(&opt, ",trans=%s", trans);
    }

    if (disk->serial &&
        qemuCapsGet(caps, QEMU_CAPS_DRIVE_SERIAL)) {
        if (qemuSafeSerialParamValue(disk->serial) < 0)
            goto error;
        virBufferAsprintf(&opt, ",serial=%s", disk->serial);
    }

    if (disk->cachemode) {
        const char *mode = NULL;

        if (qemuCapsGet(caps, QEMU_CAPS_DRIVE_CACHE_V2)) {
            mode = qemuDiskCacheV2TypeToString(disk->cachemode);

            if (disk->cachemode == VIR_DOMAIN_DISK_CACHE_DIRECTSYNC &&
                !qemuCapsGet(caps, QEMU_CAPS_DRIVE_CACHE_DIRECTSYNC)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("disk cache mode 'directsync' is not "
                                 "supported by this QEMU"));
                goto error;
            } else if (disk->cachemode == VIR_DOMAIN_DISK_CACHE_UNSAFE &&
                !qemuCapsGet(caps, QEMU_CAPS_DRIVE_CACHE_UNSAFE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("disk cache mode 'unsafe' is not "
                                 "supported by this QEMU"));
                goto error;
            }
        } else {
            mode = qemuDiskCacheV1TypeToString(disk->cachemode);
        }

        virBufferAsprintf(&opt, ",cache=%s", mode);
    } else if (disk->shared && !disk->readonly) {
        virBufferAddLit(&opt, ",cache=off");
    }

    if (disk->copy_on_read) {
        if (qemuCapsGet(caps, QEMU_CAPS_DRIVE_COPY_ON_READ)) {
            virBufferAsprintf(&opt, ",copy-on-read=%s",
                              virDomainDiskCopyOnReadTypeToString(disk->copy_on_read));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("copy_on_read is not supported by this QEMU binary"));
            goto error;
        }
    }

    if (qemuCapsGet(caps, QEMU_CAPS_MONITOR_JSON)) {
        const char *wpolicy = NULL, *rpolicy = NULL;

        if (disk->error_policy)
            wpolicy = virDomainDiskErrorPolicyTypeToString(disk->error_policy);
        if (disk->rerror_policy)
            rpolicy = virDomainDiskErrorPolicyTypeToString(disk->rerror_policy);

        if (disk->error_policy == VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE) {
            /* in the case of enospace, the option is spelled
             * differently in qemu, and it's only valid for werror,
             * not for rerror, so leave leave rerror NULL.
             */
            wpolicy = "enospc";
        } else if (!rpolicy) {
            /* for other policies, rpolicy can match wpolicy */
            rpolicy = wpolicy;
        }

        if (wpolicy)
            virBufferAsprintf(&opt, ",werror=%s", wpolicy);
        if (rpolicy)
            virBufferAsprintf(&opt, ",rerror=%s", rpolicy);
    }

    if (disk->iomode) {
        if (qemuCapsGet(caps, QEMU_CAPS_DRIVE_AIO)) {
            virBufferAsprintf(&opt, ",aio=%s",
                              virDomainDiskIoTypeToString(disk->iomode));
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk aio mode not supported with this "
                             "QEMU binary"));
            goto error;
        }
    }

    /* block I/O throttling */
    if ((disk->blkdeviotune.total_bytes_sec ||
         disk->blkdeviotune.read_bytes_sec ||
         disk->blkdeviotune.write_bytes_sec ||
         disk->blkdeviotune.total_iops_sec ||
         disk->blkdeviotune.read_iops_sec ||
         disk->blkdeviotune.write_iops_sec) &&
        !qemuCapsGet(caps, QEMU_CAPS_DRIVE_IOTUNE)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("block I/O throttling not supported with this "
                         "QEMU binary"));
        goto error;
    }

    if (disk->blkdeviotune.total_bytes_sec) {
        virBufferAsprintf(&opt, ",bps=%llu",
                          disk->blkdeviotune.total_bytes_sec);
    }

    if (disk->blkdeviotune.read_bytes_sec) {
        virBufferAsprintf(&opt, ",bps_rd=%llu",
                          disk->blkdeviotune.read_bytes_sec);
    }

    if (disk->blkdeviotune.write_bytes_sec) {
        virBufferAsprintf(&opt, ",bps_wr=%llu",
                          disk->blkdeviotune.write_bytes_sec);
    }

    if (disk->blkdeviotune.total_iops_sec) {
        virBufferAsprintf(&opt, ",iops=%llu",
                          disk->blkdeviotune.total_iops_sec);
    }

    if (disk->blkdeviotune.read_iops_sec) {
        virBufferAsprintf(&opt, ",iops_rd=%llu",
                          disk->blkdeviotune.read_iops_sec);
    }

    if (disk->blkdeviotune.write_iops_sec) {
        virBufferAsprintf(&opt, ",iops_wr=%llu",
                          disk->blkdeviotune.write_iops_sec);
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
qemuBuildDriveDevStr(virDomainDefPtr def,
                     virDomainDiskDefPtr disk,
                     int bootindex,
                     qemuCapsPtr caps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *bus = virDomainDiskQEMUBusTypeToString(disk->bus);
    int idx = virDiskNameToIndex(disk->dst);
    int controllerModel;

    if (idx < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk type '%s'"), disk->dst);
        goto error;
    }

    if (disk->wwn) {
        if ((disk->bus != VIR_DOMAIN_DISK_BUS_IDE) &&
            (disk->bus != VIR_DOMAIN_DISK_BUS_SCSI)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only ide and scsi disk support wwn"));
            goto error;
        }
    }

    if ((disk->vendor || disk->product) &&
        disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only scsi disk supports vendor and product"));
            goto error;
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* make sure that both the bus and the qemu binary support
         *  type='lun' (SG_IO).
         */
        if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO &&
            disk->bus != VIR_DOMAIN_DISK_BUS_SCSI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device='lun' is not supported for bus='%s'"),
                           bus);
            goto error;
        }
        if (disk->type != VIR_DOMAIN_DISK_TYPE_BLOCK) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk device='lun' is not supported for type='%s'"),
                           virDomainDiskTypeToString(disk->type));
            goto error;
        }
        if (!qemuCapsGet(caps, QEMU_CAPS_VIRTIO_BLK_SG_IO)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk device='lun' is not supported by this QEMU"));
            goto error;
        }
        if (disk->wwn) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn is not supported for lun device"));
            goto error;
        }
        if (disk->vendor || disk->product) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting vendor or product is not supported "
                             "for lun device"));
            goto error;
        }
    }

    switch (disk->bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for ide controller"));
            goto error;
        }

        if (disk->wwn &&
            !qemuCapsGet(caps, QEMU_CAPS_IDE_DRIVE_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn for ide disk is not supported "
                             "by this QEMU"));
            goto error;
        }

        if (qemuCapsGet(caps, QEMU_CAPS_IDE_CD)) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                virBufferAddLit(&opt, "ide-cd");
            else
                virBufferAddLit(&opt, "ide-hd");
        } else {
            virBufferAddLit(&opt, "ide-drive");
        }

        virBufferAsprintf(&opt, ",bus=ide.%d,unit=%d",
                          disk->info.addr.drive.bus,
                          disk->info.addr.drive.unit);
        break;
    case VIR_DOMAIN_DISK_BUS_SCSI:
        if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
            if (!qemuCapsGet(caps, QEMU_CAPS_SCSI_BLOCK)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("This QEMU doesn't support scsi-block for "
                                 "lun passthrough"));
                goto error;
            }
        }

        if (disk->wwn &&
            !qemuCapsGet(caps, QEMU_CAPS_SCSI_DISK_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting wwn for scsi disk is not supported "
                             "by this QEMU"));
            goto error;
        }

        /* Properties wwn, vendor and product were introduced in the
         * same QEMU release (1.2.0).
         */
        if ((disk->vendor || disk->product) &&
            !qemuCapsGet(caps, QEMU_CAPS_SCSI_DISK_WWN)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Setting vendor or product for scsi disk is not "
                             "supported by this QEMU"));
            goto error;
        }

        controllerModel =
            virDomainDiskFindControllerModel(def, disk,
                                             VIR_DOMAIN_CONTROLLER_TYPE_SCSI);
        if ((qemuSetScsiControllerModel(def, caps, &controllerModel)) < 0)
            goto error;

        if (controllerModel == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC) {
            if (disk->info.addr.drive.target != 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("target must be 0 for controller "
                                 "model 'lsilogic'"));
                goto error;
            }

            if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
                virBufferAddLit(&opt, "scsi-block");
            } else {
                if (qemuCapsGet(caps, QEMU_CAPS_SCSI_CD)) {
                    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                        virBufferAddLit(&opt, "scsi-cd");
                    else
                        virBufferAddLit(&opt, "scsi-hd");
                } else {
                    virBufferAddLit(&opt, "scsi-disk");
                }
            }

            virBufferAsprintf(&opt, ",bus=scsi%d.%d,scsi-id=%d",
                              disk->info.addr.drive.controller,
                              disk->info.addr.drive.bus,
                              disk->info.addr.drive.unit);
        } else {
            if (!qemuCapsGet(caps, QEMU_CAPS_SCSI_DISK_CHANNEL)) {
                if (disk->info.addr.drive.target > 7) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU doesn't support target "
                                     "greater than 7"));
                    goto error;
                }

                if ((disk->info.addr.drive.bus != disk->info.addr.drive.unit) &&
                    (disk->info.addr.drive.bus != 0)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU only supports both bus and "
                                     "unit equal to 0"));
                    goto error;
                }
            }

            if (disk->device != VIR_DOMAIN_DISK_DEVICE_LUN) {
                if (qemuCapsGet(caps, QEMU_CAPS_SCSI_CD)) {
                    if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                        virBufferAddLit(&opt, "scsi-cd");
                    else
                        virBufferAddLit(&opt, "scsi-hd");
                } else {
                    virBufferAddLit(&opt, "scsi-disk");
                }
            } else {
                virBufferAddLit(&opt, "scsi-block");
            }

            virBufferAsprintf(&opt, ",bus=scsi%d.0,channel=%d,scsi-id=%d,lun=%d",
                              disk->info.addr.drive.controller,
                              disk->info.addr.drive.bus,
                              disk->info.addr.drive.target,
                              disk->info.addr.drive.unit);
        }
        break;
    case VIR_DOMAIN_DISK_BUS_SATA:
        if (disk->info.addr.drive.bus != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("bus must be 0 for ide controller"));
            goto error;
        }
        if (disk->info.addr.drive.target != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("target must be 0 for ide controller"));
            goto error;
        }

        if (qemuCapsGet(caps, QEMU_CAPS_IDE_CD)) {
            if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM)
                virBufferAddLit(&opt, "ide-cd");
            else
                virBufferAddLit(&opt, "ide-hd");
        } else {
            virBufferAddLit(&opt, "ide-drive");
        }

        virBufferAsprintf(&opt, ",bus=ahci%d.%d",
                          disk->info.addr.drive.controller,
                          disk->info.addr.drive.unit);
        break;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
        if (disk->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
            virBufferAddLit(&opt, "virtio-blk-s390");
        } else {
            virBufferAddLit(&opt, "virtio-blk-pci");
        }
        qemuBuildIoEventFdStr(&opt, disk->ioeventfd, caps);
        if (disk->event_idx &&
            qemuCapsGet(caps, QEMU_CAPS_VIRTIO_BLK_EVENT_IDX)) {
            virBufferAsprintf(&opt, ",event_idx=%s",
                              virDomainVirtioEventIdxTypeToString(disk->event_idx));
        }
        if (qemuCapsGet(caps, QEMU_CAPS_VIRTIO_BLK_SCSI)) {
            /* if sg_io is true but the scsi option isn't supported,
             * that means it's just always on in this version of qemu.
             */
            virBufferAsprintf(&opt, ",scsi=%s",
                              (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN)
                              ? "on" : "off");
        }
        if (qemuBuildDeviceAddressStr(&opt, &disk->info, caps) < 0)
            goto error;
        break;
    case VIR_DOMAIN_DISK_BUS_USB:
        virBufferAddLit(&opt, "usb-storage");

        if (qemuBuildDeviceAddressStr(&opt, &disk->info, caps) < 0)
            goto error;
        break;
    default:
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unsupported disk bus '%s' with device setup"), bus);
        goto error;
    }
    virBufferAsprintf(&opt, ",drive=%s%s", QEMU_DRIVE_HOST_PREFIX, disk->info.alias);
    virBufferAsprintf(&opt, ",id=%s", disk->info.alias);
    if (bootindex && qemuCapsGet(caps, QEMU_CAPS_BOOTINDEX))
        virBufferAsprintf(&opt, ",bootindex=%d", bootindex);
    if (qemuCapsGet(caps, QEMU_CAPS_BLOCKIO)) {
        if (disk->blockio.logical_block_size > 0)
            virBufferAsprintf(&opt, ",logical_block_size=%u",
                              disk->blockio.logical_block_size);
        if (disk->blockio.physical_block_size > 0)
            virBufferAsprintf(&opt, ",physical_block_size=%u",
                              disk->blockio.physical_block_size);
    }

    if (disk->wwn)
        virBufferAsprintf(&opt, ",wwn=%s", disk->wwn);

    if (disk->vendor)
        virBufferAsprintf(&opt, ",vendor=%s", disk->vendor);

    if (disk->product)
        virBufferAsprintf(&opt, ",product=%s", disk->product);

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
                     qemuCapsPtr caps ATTRIBUTE_UNUSED)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;
    const char *driver = qemuDomainFSDriverTypeToString(fs->fsdriver);
    const char *wrpolicy = virDomainFSWrpolicyTypeToString(fs->wrpolicy);

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only supports mount filesystem type"));
        goto error;
    }

    if (!driver) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Filesystem driver type not supported"));
        goto error;
    }
    virBufferAdd(&opt, driver, -1);

    if (fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_PATH ||
        fs->fsdriver == VIR_DOMAIN_FS_DRIVER_TYPE_DEFAULT) {
        if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_MAPPED) {
            virBufferAddLit(&opt, ",security_model=mapped");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virBufferAddLit(&opt, ",security_model=passthrough");
        } else if (fs->accessmode == VIR_DOMAIN_FS_ACCESSMODE_SQUASH) {
            virBufferAddLit(&opt, ",security_model=none");
        }
    } else {
        /* For other fs drivers, default(passthru) should always
         * be supported */
        if (fs->accessmode != VIR_DOMAIN_FS_ACCESSMODE_PASSTHROUGH) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("only supports passthrough accessmode"));
            goto error;
        }
    }

    if (fs->wrpolicy) {
       if (qemuCapsGet(caps, QEMU_CAPS_FSDEV_WRITEOUT)) {
           virBufferAsprintf(&opt, ",writeout=%s", wrpolicy);
       } else {
           virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                          _("filesystem writeout not supported"));
           goto error;
       }
    }

    virBufferAsprintf(&opt, ",id=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferAsprintf(&opt, ",path=%s", fs->src);

    if (fs->readonly) {
        if (qemuCapsGet(caps, QEMU_CAPS_FSDEV_READONLY)) {
            virBufferAddLit(&opt, ",readonly");
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("readonly filesystem is not supported by this "
                             "QEMU binary"));
            goto error;
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
qemuBuildFSDevStr(virDomainFSDefPtr fs,
                  qemuCapsPtr caps)
{
    virBuffer opt = VIR_BUFFER_INITIALIZER;

    if (fs->type != VIR_DOMAIN_FS_TYPE_MOUNT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("can only passthrough directories"));
        goto error;
    }

    virBufferAddLit(&opt, "virtio-9p-pci");
    virBufferAsprintf(&opt, ",id=%s", fs->info.alias);
    virBufferAsprintf(&opt, ",fsdev=%s%s", QEMU_FSDEV_HOST_PREFIX, fs->info.alias);
    virBufferAsprintf(&opt, ",mount_tag=%s", fs->dst);

    if (qemuBuildDeviceAddressStr(&opt, &fs->info, caps) < 0)
        goto error;

    if (virBufferError(&opt)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&opt);

error:
    virBufferFreeAndReset(&opt);
    return NULL;
}


static int
qemuControllerModelUSBToCaps(int model)
{
    switch (model) {
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI:
        return QEMU_CAPS_PIIX3_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX4_UHCI:
        return QEMU_CAPS_PIIX4_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_EHCI:
        return QEMU_CAPS_USB_EHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_EHCI1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI1:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI2:
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_ICH9_UHCI3:
        return QEMU_CAPS_ICH9_USB_EHCI1;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_VT82C686B_UHCI:
        return QEMU_CAPS_VT82C686B_USB_UHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI:
        return QEMU_CAPS_PCI_OHCI;
    case VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI:
        return QEMU_CAPS_NEC_USB_XHCI;
    default:
        return -1;
    }
}


static int
qemuBuildUSBControllerDevStr(virDomainDefPtr domainDef,
                             virDomainControllerDefPtr def,
                             qemuCapsPtr caps,
                             virBuffer *buf)
{
    const char *smodel;
    int model, flags;

    model = def->model;

    if (model == -1) {
        if (domainDef->os.arch == VIR_ARCH_PPC64)
            model = VIR_DOMAIN_CONTROLLER_MODEL_USB_PCI_OHCI;
        else
            model = VIR_DOMAIN_CONTROLLER_MODEL_USB_PIIX3_UHCI;
    }

    smodel = qemuControllerModelUSBTypeToString(model);
    flags = qemuControllerModelUSBToCaps(model);

    if (flags == -1 || !qemuCapsGet(caps, flags)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s not supported in this QEMU binary"), smodel);
        return -1;
    }

    virBufferAsprintf(buf, "%s", smodel);

    if (def->info.mastertype == VIR_DOMAIN_CONTROLLER_MASTER_USB) {
        virBufferAsprintf(buf, ",masterbus=");
        qemuUsbId(buf, def->idx);
        virBufferAsprintf(buf, ".0,firstport=%d", def->info.master.usb.startport);
    } else {
        virBufferAsprintf(buf, ",id=");
        qemuUsbId(buf, def->idx);
    }

    return 0;
}

char *
qemuBuildControllerDevStr(virDomainDefPtr domainDef,
                          virDomainControllerDefPtr def,
                          qemuCapsPtr caps,
                          int *nusbcontroller)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int model;

    switch (def->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        model = def->model;
        if ((qemuSetScsiControllerModel(domainDef, caps, &model)) < 0)
            return NULL;

        switch (model) {
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_VIRTIO_SCSI:
            virBufferAddLit(&buf, "virtio-scsi-pci");
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_LSILOGIC:
            virBufferAddLit(&buf, "lsi");
            break;
        case VIR_DOMAIN_CONTROLLER_MODEL_SCSI_IBMVSCSI:
            virBufferAddLit(&buf, "spapr-vscsi");
            break;
        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Unsupported controller model: %s"),
                           virDomainControllerModelSCSITypeToString(def->model));
        }
        virBufferAsprintf(&buf, ",id=scsi%d", def->idx);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
        if (def->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
            virBufferAddLit(&buf, "virtio-serial-pci");
        } else if (def->info.type ==
                   VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
            virBufferAddLit(&buf, "virtio-serial-s390");
        } else {
            virBufferAddLit(&buf, "virtio-serial");
        }
        virBufferAsprintf(&buf, ",id=" QEMU_VIRTIO_SERIAL_PREFIX "%d",
                          def->idx);
        if (def->opts.vioserial.ports != -1) {
            virBufferAsprintf(&buf, ",max_ports=%d",
                              def->opts.vioserial.ports);
        }
        if (def->opts.vioserial.vectors != -1) {
            virBufferAsprintf(&buf, ",vectors=%d",
                              def->opts.vioserial.vectors);
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
        virBufferAsprintf(&buf, "usb-ccid,id=ccid%d", def->idx);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
        virBufferAsprintf(&buf, "ahci,id=ahci%d", def->idx);
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (qemuBuildUSBControllerDevStr(domainDef, def, caps, &buf) == -1)
            goto error;

        if (nusbcontroller)
            *nusbcontroller += 1;

        break;

    /* We always get an IDE controller, whether we want it or not. */
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unknown controller type: %s"),
                       virDomainControllerTypeToString(def->type));
        goto error;
    }

    if (qemuBuildDeviceAddressStr(&buf, &def->info, caps) < 0)
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
                    net->mac.addr[0], net->mac.addr[1],
                    net->mac.addr[2], net->mac.addr[3],
                    net->mac.addr[4], net->mac.addr[5],
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
qemuBuildNicDevStr(virDomainNetDefPtr net,
                   int vlan,
                   int bootindex,
                   qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *nic;
    bool usingVirtio = false;

    if (!net->model) {
        nic = "rtl8139";
    } else if (STREQ(net->model, "virtio")) {
        if (net->info.type ==
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
            nic = "virtio-net-s390";
        } else  {
            nic = "virtio-net-pci";
        }
        usingVirtio = true;
    } else {
        nic = net->model;
    }

    virBufferAdd(&buf, nic, strlen(nic));
    if (usingVirtio && net->driver.virtio.txmode) {
        if (qemuCapsGet(caps, QEMU_CAPS_VIRTIO_TX_ALG)) {
            virBufferAddLit(&buf, ",tx=");
            switch (net->driver.virtio.txmode) {
                case VIR_DOMAIN_NET_VIRTIO_TX_MODE_IOTHREAD:
                    virBufferAddLit(&buf, "bh");
                    break;

                case VIR_DOMAIN_NET_VIRTIO_TX_MODE_TIMER:
                    virBufferAddLit(&buf, "timer");
                    break;
                default:
                    /* this should never happen, if it does, we need
                     * to add another case to this switch.
                     */
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("unrecognized virtio-net-pci 'tx' option"));
                    goto error;
            }
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-net-pci 'tx' option not supported in this QEMU binary"));
            goto error;
        }
    }
    if (usingVirtio) {
        qemuBuildIoEventFdStr(&buf, net->driver.virtio.ioeventfd, caps);
        if (net->driver.virtio.event_idx &&
            qemuCapsGet(caps, QEMU_CAPS_VIRTIO_NET_EVENT_IDX)) {
            virBufferAsprintf(&buf, ",event_idx=%s",
                              virDomainVirtioEventIdxTypeToString(net->driver.virtio.event_idx));
        }
    }
    if (vlan == -1)
        virBufferAsprintf(&buf, ",netdev=host%s", net->info.alias);
    else
        virBufferAsprintf(&buf, ",vlan=%d", vlan);
    virBufferAsprintf(&buf, ",id=%s", net->info.alias);
    virBufferAsprintf(&buf, ",mac=%02x:%02x:%02x:%02x:%02x:%02x",
                      net->mac.addr[0], net->mac.addr[1],
                      net->mac.addr[2], net->mac.addr[3],
                      net->mac.addr[4], net->mac.addr[5]);
    if (qemuBuildDeviceAddressStr(&buf, &net->info, caps) < 0)
        goto error;
    if (qemuBuildRomStr(&buf, &net->info, caps) < 0)
       goto error;
    if (bootindex && qemuCapsGet(caps, QEMU_CAPS_BOOTINDEX))
        virBufferAsprintf(&buf, ",bootindex=%d", bootindex);

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
                    virQEMUDriverPtr driver,
                    qemuCapsPtr caps,
                    char type_sep,
                    int vlan,
                    const char *tapfd,
                    const char *vhostfd)
{
    bool is_tap = false;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    enum virDomainNetType netType = virDomainNetGetActualType(net);
    const char *brname = NULL;

    if (net->script && netType != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("scripts are not supported on interfaces of type %s"),
                       virDomainNetTypeToString(netType));
        return NULL;
    }

    switch (netType) {
    /*
     * If type='bridge', and we're running as privileged user
     * or -netdev bridge is not supported then it will fall
     * through, -net tap,fd
     */
    case VIR_DOMAIN_NET_TYPE_BRIDGE:
        if (!driver->privileged &&
            qemuCapsGet(caps, QEMU_CAPS_NETDEV_BRIDGE)) {
            brname = virDomainNetGetActualBridgeName(net);
            virBufferAsprintf(&buf, "bridge%cbr=%s", type_sep, brname);
            type_sep = ',';
            is_tap = true;
            break;
        }
    case VIR_DOMAIN_NET_TYPE_NETWORK:
    case VIR_DOMAIN_NET_TYPE_DIRECT:
        virBufferAsprintf(&buf, "tap%cfd=%s", type_sep, tapfd);
        type_sep = ',';
        is_tap = true;
        break;

    case VIR_DOMAIN_NET_TYPE_ETHERNET:
        virBufferAddLit(&buf, "tap");
        if (net->ifname) {
            virBufferAsprintf(&buf, "%cifname=%s", type_sep, net->ifname);
            type_sep = ',';
        }
        if (net->script) {
            virBufferAsprintf(&buf, "%cscript=%s", type_sep,
                              net->script);
            type_sep = ',';
        }
        is_tap = true;
        break;

    case VIR_DOMAIN_NET_TYPE_CLIENT:
       virBufferAsprintf(&buf, "socket%cconnect=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_SERVER:
       virBufferAsprintf(&buf, "socket%clisten=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_MCAST:
       virBufferAsprintf(&buf, "socket%cmcast=%s:%d",
                         type_sep,
                         net->data.socket.address,
                         net->data.socket.port);
       type_sep = ',';
       break;

    case VIR_DOMAIN_NET_TYPE_USER:
    default:
        virBufferAddLit(&buf, "user");
        break;
    }

    if (vlan >= 0) {
        virBufferAsprintf(&buf, "%cvlan=%d", type_sep, vlan);
        if (net->info.alias)
            virBufferAsprintf(&buf, ",name=host%s",
                              net->info.alias);
    } else {
        virBufferAsprintf(&buf, "%cid=host%s",
                          type_sep, net->info.alias);
    }

    if (is_tap) {
        if (vhostfd && *vhostfd)
            virBufferAsprintf(&buf, ",vhost=on,vhostfd=%s", vhostfd);
        if (net->tune.sndbuf_specified)
            virBufferAsprintf(&buf, ",sndbuf=%lu", net->tune.sndbuf);
    }

    if (virBufferError(&buf)) {
        virBufferFreeAndReset(&buf);
        virReportOOMError();
        return NULL;
    }

    return virBufferContentAndReset(&buf);
}


char *
qemuBuildWatchdogDevStr(virDomainWatchdogDefPtr dev,
                        qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    const char *model = virDomainWatchdogModelTypeToString(dev->model);
    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("missing watchdog model"));
        goto error;
    }

    virBufferAsprintf(&buf, "%s,id=%s", model, dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info, caps) < 0)
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
qemuBuildMemballoonDevStr(virDomainMemballoonDefPtr dev,
                          qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "virtio-balloon-pci");
    virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info, caps) < 0)
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
qemuBuildUSBInputDevStr(virDomainInputDefPtr dev,
                        qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%s,id=%s",
                      dev->type == VIR_DOMAIN_INPUT_TYPE_MOUSE ?
                      "usb-mouse" : "usb-tablet", dev->info.alias);

    if (qemuBuildDeviceAddressStr(&buf, &dev->info, caps) < 0)
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
qemuBuildSoundDevStr(virDomainSoundDefPtr sound,
                     qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model = virDomainSoundModelTypeToString(sound->model);

    if (!model) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("invalid sound model"));
        goto error;
    }

    /* Hack for weirdly unusual devices name in QEMU */
    if (STREQ(model, "es1370"))
        model = "ES1370";
    else if (STREQ(model, "ac97"))
        model = "AC97";
    else if (STREQ(model, "ich6"))
        model = "intel-hda";

    virBufferAsprintf(&buf, "%s,id=%s", model, sound->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &sound->info, caps) < 0)
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


static int
qemuSoundCodecTypeToCaps(int type)
{
    switch (type) {
    case VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX:
        return QEMU_CAPS_HDA_DUPLEX;
    case VIR_DOMAIN_SOUND_CODEC_TYPE_MICRO:
        return QEMU_CAPS_HDA_MICRO;
    default:
        return -1;
    }
}


static char *
qemuBuildSoundCodecStr(virDomainSoundDefPtr sound,
                       virDomainSoundCodecDefPtr codec,
                       qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *stype;
    int type, flags;

    type = codec->type;
    stype = qemuSoundCodecTypeToString(type);
    flags = qemuSoundCodecTypeToCaps(type);

    if (flags == -1 || !qemuCapsGet(caps, flags)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("%s not supported in this QEMU binary"), stype);
        goto error;
    }

    virBufferAsprintf(&buf, "%s,id=%s-codec%d,bus=%s.0,cad=%d",
                      stype, sound->info.alias, codec->cad, sound->info.alias, codec->cad);

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
}

static char *
qemuBuildDeviceVideoStr(virDomainVideoDefPtr video,
                        qemuCapsPtr caps,
                        bool primary)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    const char *model;

    if (primary) {
        model = qemuDeviceVideoTypeToString(video->type);
        if (!model || STREQ(model, "")) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("video type %s is not supported with QEMU"),
                           virDomainVideoTypeToString(video->type));
            goto error;
        }
    } else {
        if (video->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("non-primary video device must be type of 'qxl'"));
            goto error;
        }

        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE_QXL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("only one video card is currently supported"));
            goto error;
        }

        model = "qxl";
    }

    virBufferAsprintf(&buf, "%s,id=%s", model, video->info.alias);

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (video->vram > (UINT_MAX / 1024)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("value for 'vram' must be less than '%u'"),
                           UINT_MAX / 1024);
            goto error;
        }

        /* QEMU accepts bytes for vram_size. */
        virBufferAsprintf(&buf, ",vram_size=%u", video->vram * 1024);
    }

    if (qemuBuildDeviceAddressStr(&buf, &video->info, caps) < 0)
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
qemuBuildPCIHostdevDevStr(virDomainHostdevDefPtr dev, const char *configfd,
                          qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAddLit(&buf, "pci-assign");
    virBufferAsprintf(&buf, ",host=%.2x:%.2x.%.1x",
                      dev->source.subsys.u.pci.bus,
                      dev->source.subsys.u.pci.slot,
                      dev->source.subsys.u.pci.function);
    virBufferAsprintf(&buf, ",id=%s", dev->info->alias);
    if (configfd && *configfd)
        virBufferAsprintf(&buf, ",configfd=%s", configfd);
    if (dev->info->bootIndex)
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info->bootIndex);
    if (qemuBuildDeviceAddressStr(&buf, dev->info, caps) < 0)
        goto error;
    if (qemuBuildRomStr(&buf, dev->info, caps) < 0)
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
qemuBuildRedirdevDevStr(virDomainDefPtr def,
                        virDomainRedirdevDefPtr dev,
                        qemuCapsPtr caps)
{
    size_t i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    virDomainRedirFilterDefPtr redirfilter = def->redirfilter;

    if (dev->bus != VIR_DOMAIN_REDIRDEV_BUS_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Redirection bus %s is not supported by QEMU"),
                       virDomainRedirdevBusTypeToString(dev->bus));
        goto error;
    }

    if (!qemuCapsGet(caps, QEMU_CAPS_USB_REDIR)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("USB redirection is not supported "
                         "by this version of QEMU"));
        goto error;
    }

    virBufferAsprintf(&buf, "usb-redir,chardev=char%s,id=%s",
                      dev->info.alias,
                      dev->info.alias);

    if (redirfilter && redirfilter->nusbdevs) {
        if (!qemuCapsGet(caps, QEMU_CAPS_USB_REDIR_FILTER)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("USB redirection filter is not "
                             "supported by this version of QEMU"));
            goto error;
        }

        virBufferAsprintf(&buf, ",filter=");

        for (i = 0; i < redirfilter->nusbdevs; i++) {
            virDomainRedirFilterUsbDevDefPtr usbdev = redirfilter->usbdevs[i];
            if (usbdev->usbClass >= 0)
                virBufferAsprintf(&buf, "0x%02X:", usbdev->usbClass);
            else
                virBufferAsprintf(&buf, "-1:");

            if (usbdev->vendor >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->vendor);
            else
                virBufferAsprintf(&buf, "-1:");

            if (usbdev->product >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->product);
            else
                virBufferAsprintf(&buf, "-1:");

            if (usbdev->version >= 0)
                virBufferAsprintf(&buf, "0x%04X:", usbdev->version);
            else
                virBufferAsprintf(&buf, "-1:");

            virBufferAsprintf(&buf, "%u", usbdev->allow);
            if (i < redirfilter->nusbdevs -1)
                virBufferAsprintf(&buf, "|");
        }
    }

    if (dev->info.bootIndex) {
        if (!qemuCapsGet(caps, QEMU_CAPS_USB_REDIR_BOOTINDEX)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("USB redirection booting is not "
                             "supported by this version of QEMU"));
            goto error;
        }
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info.bootIndex);
    }

    if (qemuBuildDeviceAddressStr(&buf, &dev->info, caps) < 0)
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
qemuBuildUSBHostdevDevStr(virDomainHostdevDefPtr dev,
                          qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (!dev->missing &&
        !dev->source.subsys.u.usb.bus &&
        !dev->source.subsys.u.usb.device) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("USB host device is missing bus/device information"));
        return NULL;
    }

    virBufferAddLit(&buf, "usb-host");
    if (!dev->missing) {
        virBufferAsprintf(&buf, ",hostbus=%d,hostaddr=%d",
                          dev->source.subsys.u.usb.bus,
                          dev->source.subsys.u.usb.device);
    }
    virBufferAsprintf(&buf, ",id=%s", dev->info->alias);
    if (dev->info->bootIndex)
        virBufferAsprintf(&buf, ",bootindex=%d", dev->info->bootIndex);

    if (qemuBuildDeviceAddressStr(&buf, dev->info, caps) < 0)
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
qemuBuildHubDevStr(virDomainHubDefPtr dev,
                   qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    if (dev->type != VIR_DOMAIN_HUB_TYPE_USB) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("hub type %s not supported"),
                       virDomainHubTypeToString(dev->type));
        goto error;
    }

    if (!qemuCapsGet(caps, QEMU_CAPS_USB_HUB)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("usb-hub not supported by QEMU binary"));
        goto error;
    }

    virBufferAddLit(&buf, "usb-hub");
    virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
    if (qemuBuildDeviceAddressStr(&buf, &dev->info, caps) < 0)
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
qemuBuildUSBHostdevUsbDevStr(virDomainHostdevDefPtr dev)
{
    char *ret = NULL;

    if (dev->missing) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("This QEMU doesn't not support missing USB devices"));
        return NULL;
    }

    if (!dev->source.subsys.u.usb.bus &&
        !dev->source.subsys.u.usb.device) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
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
static char *
qemuBuildChrChardevStr(virDomainChrSourceDefPtr dev, const char *alias,
                       qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    bool telnet;

    switch (dev->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
        virBufferAsprintf(&buf, "null,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_VC:
        virBufferAsprintf(&buf, "vc,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_PTY:
        virBufferAsprintf(&buf, "pty,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_DEV:
        virBufferAsprintf(&buf, "%s,id=char%s,path=%s",
                          STRPREFIX(alias, "parallel") ? "parport" : "tty",
                          alias, dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
        virBufferAsprintf(&buf, "file,id=char%s,path=%s", alias,
                          dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(&buf, "pipe,id=char%s,path=%s", alias,
                          dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAsprintf(&buf, "stdio,id=char%s", alias);
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = dev->data.udp.connectHost;
        const char *bindHost = dev->data.udp.bindHost;
        const char *bindService = dev->data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        virBufferAsprintf(&buf,
                          "udp,id=char%s,host=%s,port=%s,localaddr=%s,"
                          "localport=%s",
                          alias,
                          connectHost,
                          dev->data.udp.connectService,
                          bindHost, bindService);
        break;
    }
    case VIR_DOMAIN_CHR_TYPE_TCP:
        telnet = dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        virBufferAsprintf(&buf,
                          "socket,id=char%s,host=%s,port=%s%s%s",
                          alias,
                          dev->data.tcp.host,
                          dev->data.tcp.service,
                          telnet ? ",telnet" : "",
                          dev->data.tcp.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&buf,
                          "socket,id=char%s,path=%s%s",
                          alias,
                          dev->data.nix.path,
                          dev->data.nix.listen ? ",server,nowait" : "");
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
        if (!qemuCapsGet(caps, QEMU_CAPS_CHARDEV_SPICEVMC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spicevmc not supported in this QEMU binary"));
            goto error;
        }
        virBufferAsprintf(&buf, "spicevmc,id=char%s,name=%s", alias,
                          virDomainChrSpicevmcTypeToString(dev->data.spicevmc));
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported chardev '%s'"),
                       virDomainChrTypeToString(dev->type));
        goto error;
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


static char *
qemuBuildChrArgStr(virDomainChrSourceDefPtr dev, const char *prefix)
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
        virBufferAsprintf(&buf, "file:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_PIPE:
        virBufferAsprintf(&buf, "pipe:%s", dev->data.file.path);
        break;

    case VIR_DOMAIN_CHR_TYPE_STDIO:
        virBufferAddLit(&buf, "stdio");
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP: {
        const char *connectHost = dev->data.udp.connectHost;
        const char *bindHost = dev->data.udp.bindHost;
        const char *bindService  = dev->data.udp.bindService;

        if (connectHost == NULL)
            connectHost = "";
        if (bindHost == NULL)
            bindHost = "";
        if (bindService == NULL)
            bindService = "0";

        virBufferAsprintf(&buf, "udp:%s:%s@%s:%s",
                          connectHost,
                          dev->data.udp.connectService,
                          bindHost,
                          bindService);
        break;
    }
    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (dev->data.tcp.protocol == VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET) {
            virBufferAsprintf(&buf, "telnet:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        } else {
            virBufferAsprintf(&buf, "tcp:%s:%s%s",
                              dev->data.tcp.host,
                              dev->data.tcp.service,
                              dev->data.tcp.listen ? ",server,nowait" : "");
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        virBufferAsprintf(&buf, "unix:%s%s",
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


static char *
qemuBuildVirtioSerialPortDevStr(virDomainChrDefPtr dev,
                                qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    switch (dev->deviceType) {
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE:
        virBufferAddLit(&buf, "virtconsole");
        break;
    case VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL:
        /* Legacy syntax  '-device spicevmc' */
        if (dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
            qemuCapsGet(caps, QEMU_CAPS_DEVICE_SPICEVMC)) {
            virBufferAddLit(&buf, "spicevmc");
        } else {
            virBufferAddLit(&buf, "virtserialport");
        }
        break;
    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use virtio serial for parallel/serial devices"));
        return NULL;
    }

    if (dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        dev->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_S390) {
        /* Check it's a virtio-serial address */
        if (dev->info.type !=
            VIR_DOMAIN_DEVICE_ADDRESS_TYPE_VIRTIO_SERIAL)
        {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("virtio serial device has invalid address type"));
            goto error;
        }

        virBufferAsprintf(&buf,
                          ",bus=" QEMU_VIRTIO_SERIAL_PREFIX "%d.%d",
                          dev->info.addr.vioserial.controller,
                          dev->info.addr.vioserial.bus);
        virBufferAsprintf(&buf,
                          ",nr=%d",
                          dev->info.addr.vioserial.port);
    }

    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
        dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
        STRNEQ_NULLABLE(dev->target.name, "com.redhat.spice.0")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Unsupported spicevmc target name '%s'"),
                       dev->target.name);
        goto error;
    }

    if (!(dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
          dev->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC &&
          qemuCapsGet(caps, QEMU_CAPS_DEVICE_SPICEVMC))) {
        virBufferAsprintf(&buf, ",chardev=char%s,id=%s",
                          dev->info.alias, dev->info.alias);
        if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL) {
            virBufferAsprintf(&buf, ",name=%s", dev->target.name
                              ? dev->target.name : "com.redhat.spice.0");
        }
    } else {
        virBufferAsprintf(&buf, ",id=%s", dev->info.alias);
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

static char *
qemuBuildSclpDevStr(virDomainChrDefPtr dev)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    if (dev->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE) {
        switch (dev->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
            virBufferAddLit(&buf, "sclpconsole");
            break;
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            virBufferAddLit(&buf, "sclplmconsole");
            break;
        }
    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Cannot use slcp with devices other than console"));
        goto error;
    }
    virBufferAsprintf(&buf, ",chardev=char%s,id=%s",
                      dev->info.alias, dev->info.alias);
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
        return NULL;

    virBufferAddLit(&buf, "type=0");

    /* 0:Vendor */
    if (def->bios_vendor)
        virBufferAsprintf(&buf, ",vendor=%s", def->bios_vendor);
    /* 0:BIOS Version */
    if (def->bios_version)
        virBufferAsprintf(&buf, ",version=%s", def->bios_version);
    /* 0:BIOS Release Date */
    if (def->bios_date)
        virBufferAsprintf(&buf, ",date=%s", def->bios_date);
    /* 0:System BIOS Major Release and 0:System BIOS Minor Release */
    if (def->bios_release)
        virBufferAsprintf(&buf, ",release=%s", def->bios_release);

    if (virBufferError(&buf)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&buf);

error:
    virBufferFreeAndReset(&buf);
    return NULL;
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
        virBufferAsprintf(&buf, ",manufacturer=%s",
                          def->system_manufacturer);
     /* 1:Product Name */
    if (def->system_product)
        virBufferAsprintf(&buf, ",product=%s", def->system_product);
    /* 1:Version */
    if (def->system_version)
        virBufferAsprintf(&buf, ",version=%s", def->system_version);
    /* 1:Serial Number */
    if (def->system_serial)
        virBufferAsprintf(&buf, ",serial=%s", def->system_serial);
    /* 1:UUID */
    if (def->system_uuid && !skip_uuid)
        virBufferAsprintf(&buf, ",uuid=%s", def->system_uuid);
    /* 1:SKU Number */
    if (def->system_sku)
        virBufferAsprintf(&buf, ",sku=%s", def->system_sku);
    /* 1:Family */
    if (def->system_family)
        virBufferAsprintf(&buf, ",family=%s", def->system_family);

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

        if (def->data.variable.basis != VIR_DOMAIN_CLOCK_BASIS_UTC) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported clock basis '%s'"),
                           virDomainClockBasisTypeToString(def->data.variable.basis));
            goto error;
        }
        now += def->data.variable.adjustment;
        gmtime_r(&now, &nowbits);

        virBufferAsprintf(&buf, "base=%d-%02d-%02dT%02d:%02d:%02d",
                          nowbits.tm_year + 1900,
                          nowbits.tm_mon + 1,
                          nowbits.tm_mday,
                          nowbits.tm_hour,
                          nowbits.tm_min,
                          nowbits.tm_sec);
    }   break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
qemuBuildCpuArgStr(const virQEMUDriverPtr driver,
                   const virDomainDefPtr def,
                   const char *emulator,
                   qemuCapsPtr caps,
                   virArch hostarch,
                   char **opt,
                   bool *hasHwVirt,
                   bool migrating)
{
    const virCPUDefPtr host = driver->caps->host.cpu;
    virCPUDefPtr guest = NULL;
    virCPUDefPtr cpu = NULL;
    size_t ncpus = 0;
    char **cpus = NULL;
    const char *default_model;
    union cpuData *data = NULL;
    bool have_cpu = false;
    char *compare_msg = NULL;
    int ret = -1;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    int i;

    *hasHwVirt = false;

    if (def->os.arch == VIR_ARCH_I686)
        default_model = "qemu32";
    else
        default_model = "qemu64";

    if (def->cpu &&
        (def->cpu->mode != VIR_CPU_MODE_CUSTOM || def->cpu->model)) {
        virCPUCompareResult cmp;
        const char *preferred;
        int hasSVM;

        if (!host ||
            !host->model ||
            (ncpus = qemuCapsGetCPUDefinitions(caps, &cpus)) == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("CPU specification not supported by hypervisor"));
            goto cleanup;
        }

        if (!(cpu = virCPUDefCopy(def->cpu)))
            goto cleanup;

        if (cpu->mode != VIR_CPU_MODE_CUSTOM &&
            !migrating &&
            cpuUpdate(cpu, host) < 0)
            goto cleanup;

        cmp = cpuGuestData(host, cpu, &data, &compare_msg);
        switch (cmp) {
        case VIR_CPU_COMPARE_INCOMPATIBLE:
            if (compare_msg) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("guest and host CPU are not compatible: %s"),
                               compare_msg);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("guest CPU is not compatible with host CPU"));
            }
            /* fall through */
        case VIR_CPU_COMPARE_ERROR:
            goto cleanup;

        default:
            break;
        }

        /* Only 'svm' requires --enable-nesting. The nested
         * 'vmx' patches now simply hook off the CPU features
         */
        hasSVM = cpuHasFeature(host->arch, data, "svm");
        if (hasSVM < 0)
            goto cleanup;
        *hasHwVirt = hasSVM > 0 ? true : false;

        if (cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH) {
            const char *mode = virCPUModeTypeToString(cpu->mode);
            if (!qemuCapsGet(caps, QEMU_CAPS_CPU_HOST)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("CPU mode '%s' is not supported by QEMU"
                                 " binary"), mode);
                goto cleanup;
            }
            if (def->virtType != VIR_DOMAIN_VIRT_KVM) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("CPU mode '%s' is only supported with kvm"),
                               mode);
                goto cleanup;
            }
            virBufferAddLit(&buf, "host");
        } else {
            if (VIR_ALLOC(guest) < 0 ||
                (cpu->vendor_id && !(guest->vendor_id = strdup(cpu->vendor_id))))
                goto no_memory;

            guest->arch = host->arch;
            if (cpu->match == VIR_CPU_MATCH_MINIMUM)
                preferred = host->model;
            else
                preferred = cpu->model;

            guest->type = VIR_CPU_TYPE_GUEST;
            guest->fallback = cpu->fallback;
            if (cpuDecode(guest, data, (const char **)cpus, ncpus, preferred) < 0)
                goto cleanup;

            virBufferAdd(&buf, guest->model, -1);
            if (guest->vendor_id)
                virBufferAsprintf(&buf, ",vendor=%s", guest->vendor_id);
            for (i = 0; i < guest->nfeatures; i++) {
                char sign;
                if (guest->features[i].policy == VIR_CPU_FEATURE_DISABLE)
                    sign = '-';
                else
                    sign = '+';

                virBufferAsprintf(&buf, ",%c%s", sign, guest->features[i].name);
            }
        }
        have_cpu = true;
    } else {
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
        if (def->os.arch == VIR_ARCH_I686 &&
            ((hostarch == VIR_ARCH_X86_64 &&
              strstr(emulator, "kvm")) ||
             strstr(emulator, "x86_64"))) {
            virBufferAdd(&buf, default_model, -1);
            have_cpu = true;
        }
    }

    /* Now force kvmclock on/off based on the corresponding <timer> element.  */
    for (i = 0; i < def->clock.ntimers; i++) {
        if (def->clock.timers[i]->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK &&
            def->clock.timers[i]->present != -1) {
            char sign;
            if (def->clock.timers[i]->present)
                sign = '+';
            else
                sign = '-';
            virBufferAsprintf(&buf, "%s,%ckvmclock",
                              have_cpu ? "" : default_model,
                              sign);
            have_cpu = true;
            break;
        }
    }

    if (def->apic_eoi) {
        char sign;
        if (def->apic_eoi == VIR_DOMAIN_FEATURE_STATE_ON)
            sign = '+';
        else
            sign = '-';

        virBufferAsprintf(&buf, "%s,%ckvm_pv_eoi",
                          have_cpu ? "" : default_model,
                          sign);
        have_cpu = true;
    }

    if (def->features & (1 << VIR_DOMAIN_FEATURE_HYPERV)) {
        if (!have_cpu) {
            virBufferAdd(&buf, default_model, -1);
            have_cpu = true;
        }

        for (i = 0; i < VIR_DOMAIN_HYPERV_LAST; i++) {
            switch ((enum virDomainHyperv) i) {
            case VIR_DOMAIN_HYPERV_RELAXED:
                if (def->hyperv_features[i] == VIR_DOMAIN_FEATURE_STATE_ON)
                    virBufferAsprintf(&buf, ",hv_%s",
                                      virDomainHypervTypeToString(i));
                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }
        }
    }

    if (virBufferError(&buf))
        goto no_memory;

    *opt = virBufferContentAndReset(&buf);

    ret = 0;

cleanup:
    VIR_FREE(compare_msg);
    if (host)
        cpuDataFree(host->arch, data);
    virCPUDefFree(guest);
    virCPUDefFree(cpu);

    return ret;

no_memory:
    virReportOOMError();
    goto cleanup;
}

static int
qemuBuildMachineArgStr(virCommandPtr cmd,
                       const virDomainDefPtr def,
                       qemuCapsPtr caps)
{
    /* This should *never* be NULL, since we always provide
     * a machine in the capabilities data for QEMU. So this
     * check is just here as a safety in case the unexpected
     * happens */
    if (!def->os.machine)
        return 0;

    if (!def->mem.dump_core) {
        /* if no parameter to the machine type is needed, we still use
         * '-M' to keep the most of the compatibility with older versions.
         */
        virCommandAddArgList(cmd, "-M", def->os.machine, NULL);
    } else {
        if (!qemuCapsGet(caps, QEMU_CAPS_DUMP_GUEST_CORE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("dump-guest-core is not available "
                                   " with this QEMU binary"));
            return -1;
        }

        /* However, in case there is a parameter to be added, we need to
         * use the "-machine" parameter because qemu is not parsing the
         * "-M" correctly */
        virCommandAddArg(cmd, "-machine");
        virCommandAddArgFormat(cmd,
                               "%s,dump-guest-core=%s",
                               def->os.machine,
                               virDomainMemDumpTypeToString(def->mem.dump_core));
    }

    return 0;
}

static char *
qemuBuildSmpArgStr(const virDomainDefPtr def,
                   qemuCapsPtr caps)
{
    virBuffer buf = VIR_BUFFER_INITIALIZER;

    virBufferAsprintf(&buf, "%u", def->vcpus);

    if (qemuCapsGet(caps, QEMU_CAPS_SMP_TOPOLOGY)) {
        if (def->vcpus != def->maxvcpus)
            virBufferAsprintf(&buf, ",maxcpus=%u", def->maxvcpus);
        /* sockets, cores, and threads are either all zero
         * or all non-zero, thus checking one of them is enough */
        if (def->cpu && def->cpu->sockets) {
            virBufferAsprintf(&buf, ",sockets=%u", def->cpu->sockets);
            virBufferAsprintf(&buf, ",cores=%u", def->cpu->cores);
            virBufferAsprintf(&buf, ",threads=%u", def->cpu->threads);
        }
        else {
            virBufferAsprintf(&buf, ",sockets=%u", def->maxvcpus);
            virBufferAsprintf(&buf, ",cores=%u", 1);
            virBufferAsprintf(&buf, ",threads=%u", 1);
        }
    } else if (def->vcpus != def->maxvcpus) {
        virBufferFreeAndReset(&buf);
        /* FIXME - consider hot-unplugging cpus after boot for older qemu */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
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

static int
qemuBuildNumaArgStr(const virDomainDefPtr def, virCommandPtr cmd)
{
    int i;
    virBuffer buf = VIR_BUFFER_INITIALIZER;
    char *cpumask;

    for (i = 0; i < def->cpu->ncells; i++) {
        virCommandAddArg(cmd, "-numa");
        virBufferAsprintf(&buf, "node,nodeid=%d", def->cpu->cells[i].cellid);
        virBufferAddLit(&buf, ",cpus=");
        cpumask = virBitmapFormat(def->cpu->cells[i].cpumask);
        if (cpumask) {
            virBufferAsprintf(&buf, "%s", cpumask);
            VIR_FREE(cpumask);
        }
        def->cpu->cells[i].mem = VIR_DIV_UP(def->cpu->cells[i].mem,
                                            1024) * 1024;
        virBufferAsprintf(&buf, ",mem=%d", def->cpu->cells[i].mem / 1024);

        if (virBufferError(&buf))
            goto error;

        virCommandAddArgBuffer(cmd, &buf);
    }
    return 0;

error:
    virBufferFreeAndReset(&buf);
    virReportOOMError();
    return -1;
}

static int
qemuBuildGraphicsCommandLine(virQEMUDriverPtr driver,
                             virCommandPtr cmd,
                             virDomainDefPtr def,
                             qemuCapsPtr caps,
                             virDomainGraphicsDefPtr graphics)
{
    int i;

    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;

        if (!qemuCapsGet(caps, QEMU_CAPS_VNC)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vnc graphics are not supported with this QEMU"));
            goto error;
        }

        if (graphics->data.vnc.socket ||
            driver->vncAutoUnixSocket) {

            if (!graphics->data.vnc.socket &&
                virAsprintf(&graphics->data.vnc.socket,
                            "%s/%s.vnc", driver->libDir, def->name) == -1) {
                goto no_memory;
            }

            virBufferAsprintf(&opt, "unix:%s",
                              graphics->data.vnc.socket);

        } else if (qemuCapsGet(caps, QEMU_CAPS_VNC_COLON)) {
            const char *listenNetwork;
            const char *listenAddr = NULL;
            char *netAddr = NULL;
            bool escapeAddr;
            int ret;

            switch (virDomainGraphicsListenGetType(graphics, 0)) {
            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
                listenAddr = virDomainGraphicsListenGetAddress(graphics, 0);
                break;

            case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
                listenNetwork = virDomainGraphicsListenGetNetwork(graphics, 0);
                if (!listenNetwork)
                    break;
                ret = networkGetNetworkAddress(listenNetwork, &netAddr);
                if (ret <= -2) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   "%s", _("network-based listen not possible, "
                                           "network driver not present"));
                    goto error;
                }
                if (ret < 0) {
                    virReportError(VIR_ERR_XML_ERROR,
                                   _("listen network '%s' had no usable address"),
                                   listenNetwork);
                    goto error;
                }
                listenAddr = netAddr;
                /* store the address we found in the <graphics> element so it will
                 * show up in status. */
                if (virDomainGraphicsListenSetAddress(graphics, 0,
                                                      listenAddr, -1, false) < 0)
                   goto error;
                break;
            }

            if (!listenAddr)
                listenAddr = driver->vncListen;

            escapeAddr = strchr(listenAddr, ':') != NULL;
            if (escapeAddr)
                virBufferAsprintf(&opt, "[%s]", listenAddr);
            else
                virBufferAdd(&opt, listenAddr, -1);
            virBufferAsprintf(&opt, ":%d",
                              graphics->data.vnc.port - 5900);

            VIR_FREE(netAddr);
        } else {
            virBufferAsprintf(&opt, "%d",
                              graphics->data.vnc.port - 5900);
        }

        if (qemuCapsGet(caps, QEMU_CAPS_VNC_COLON)) {
            if (graphics->data.vnc.auth.passwd ||
                driver->vncPassword)
                virBufferAddLit(&opt, ",password");

            if (driver->vncTLS) {
                virBufferAddLit(&opt, ",tls");
                if (driver->vncTLSx509verify) {
                    virBufferAsprintf(&opt, ",x509verify=%s",
                                      driver->vncTLSx509certdir);
                } else {
                    virBufferAsprintf(&opt, ",x509=%s",
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
        }

        virCommandAddArg(cmd, "-vnc");
        virCommandAddArgBuffer(cmd, &opt);
        if (graphics->data.vnc.keymap) {
            virCommandAddArgList(cmd, "-k", graphics->data.vnc.keymap,
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
    } else if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SDL) {
        if (qemuCapsGet(caps, QEMU_CAPS_0_10) &&
            !qemuCapsGet(caps, QEMU_CAPS_SDL)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("sdl not supported by '%s'"),
                           def->emulator);
            goto error;
        }

        if (graphics->data.sdl.xauth)
            virCommandAddEnvPair(cmd, "XAUTHORITY",
                                 graphics->data.sdl.xauth);
        if (graphics->data.sdl.display)
            virCommandAddEnvPair(cmd, "DISPLAY",
                                 graphics->data.sdl.display);
        if (graphics->data.sdl.fullscreen)
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
        if (qemuCapsGet(caps, QEMU_CAPS_SDL))
            virCommandAddArg(cmd, "-sdl");

    } else if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_SPICE) {
        virBuffer opt = VIR_BUFFER_INITIALIZER;
        const char *listenNetwork;
        const char *listenAddr = NULL;
        char *netAddr = NULL;
        int ret;
        int defaultMode = graphics->data.spice.defaultMode;
        int port = graphics->data.spice.port;
        int tlsPort = graphics->data.spice.tlsPort;

        if (!qemuCapsGet(caps, QEMU_CAPS_SPICE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("spice graphics are not supported with this QEMU"));
            goto error;
        }

        if (port > 0 || tlsPort <= 0)
            virBufferAsprintf(&opt, "port=%u", port);

        if (tlsPort > 0) {
            if (!driver->spiceTLS) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("spice TLS port set in XML configuration,"
                                 " but TLS is disabled in qemu.conf"));
                goto error;
            }
            if (port > 0)
                virBufferAddChar(&opt, ',');
            virBufferAsprintf(&opt, "tls-port=%u", tlsPort);
        }

        switch (virDomainGraphicsListenGetType(graphics, 0)) {
        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS:
            listenAddr = virDomainGraphicsListenGetAddress(graphics, 0);
            break;

        case VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_NETWORK:
            listenNetwork = virDomainGraphicsListenGetNetwork(graphics, 0);
            if (!listenNetwork)
                break;
            ret = networkGetNetworkAddress(listenNetwork, &netAddr);
            if (ret <= -2) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("network-based listen not possible, "
                                       "network driver not present"));
                goto error;
            }
            if (ret < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("listen network '%s' had no usable address"),
                               listenNetwork);
                goto error;
            }
            listenAddr = netAddr;
            /* store the address we found in the <graphics> element so it will
             * show up in status. */
            if (virDomainGraphicsListenSetAddress(graphics, 0,
                                                  listenAddr, -1, false) < 0)
               goto error;
            break;
        }

        if (!listenAddr)
            listenAddr = driver->spiceListen;
        if (listenAddr)
            virBufferAsprintf(&opt, ",addr=%s", listenAddr);

        VIR_FREE(netAddr);

        int mm = graphics->data.spice.mousemode;
        if (mm) {
            switch (mm) {
            case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_SERVER:
                virBufferAsprintf(&opt, ",agent-mouse=off");
                break;
            case VIR_DOMAIN_GRAPHICS_SPICE_MOUSE_MODE_CLIENT:
                virBufferAsprintf(&opt, ",agent-mouse=on");
                break;
            default:
                break;
            }
        }

        /* In the password case we set it via monitor command, to avoid
         * making it visible on CLI, so there's no use of password=XXX
         * in this bit of the code */
        if (!graphics->data.spice.auth.passwd &&
            !driver->spicePassword)
            virBufferAddLit(&opt, ",disable-ticketing");

        if (driver->spiceTLS)
            virBufferAsprintf(&opt, ",x509-dir=%s",
                              driver->spiceTLSx509certdir);

        switch (defaultMode) {
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
            virBufferAsprintf(&opt, ",tls-channel=default");
            break;
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
            virBufferAsprintf(&opt, ",plaintext-channel=default");
            break;
        case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_ANY:
            /* nothing */
            break;
        }

        for (i = 0 ; i < VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_LAST ; i++) {
            int mode = graphics->data.spice.channels[i];
            switch (mode) {
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_SECURE:
                if (!driver->spiceTLS) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("spice secure channels set in XML configuration, but TLS is disabled in qemu.conf"));
                    goto error;
                }
                virBufferAsprintf(&opt, ",tls-channel=%s",
                                  virDomainGraphicsSpiceChannelNameTypeToString(i));
                break;
            case VIR_DOMAIN_GRAPHICS_SPICE_CHANNEL_MODE_INSECURE:
                virBufferAsprintf(&opt, ",plaintext-channel=%s",
                                  virDomainGraphicsSpiceChannelNameTypeToString(i));
                break;
            }
        }
        if (graphics->data.spice.image)
            virBufferAsprintf(&opt, ",image-compression=%s",
                              virDomainGraphicsSpiceImageCompressionTypeToString(graphics->data.spice.image));
        if (graphics->data.spice.jpeg)
            virBufferAsprintf(&opt, ",jpeg-wan-compression=%s",
                              virDomainGraphicsSpiceJpegCompressionTypeToString(graphics->data.spice.jpeg));
        if (graphics->data.spice.zlib)
            virBufferAsprintf(&opt, ",zlib-glz-wan-compression=%s",
                              virDomainGraphicsSpiceZlibCompressionTypeToString(graphics->data.spice.zlib));
        if (graphics->data.spice.playback)
            virBufferAsprintf(&opt, ",playback-compression=%s",
                              virDomainGraphicsSpicePlaybackCompressionTypeToString(graphics->data.spice.playback));
        if (graphics->data.spice.streaming)
            virBufferAsprintf(&opt, ",streaming-video=%s",
                              virDomainGraphicsSpiceStreamingModeTypeToString(graphics->data.spice.streaming));
        if (graphics->data.spice.copypaste == VIR_DOMAIN_GRAPHICS_SPICE_CLIPBOARD_COPYPASTE_NO)
            virBufferAddLit(&opt, ",disable-copy-paste");

        if (qemuCapsGet(caps, QEMU_CAPS_SEAMLESS_MIGRATION)) {
            /* If qemu supports seamless migration turn it
             * unconditionally on. If migration destination
             * doesn't support it, it fallbacks to previous
             * migration algorithm silently. */
            virBufferAddLit(&opt, ",seamless-migration=on");
        }

        virCommandAddArg(cmd, "-spice");
        virCommandAddArgBuffer(cmd, &opt);
        if (graphics->data.spice.keymap)
            virCommandAddArgList(cmd, "-k",
                                 graphics->data.spice.keymap, NULL);
        /* SPICE includes native support for tunnelling audio, so we
         * set the audio backend to point at SPICE's own driver
         */
        virCommandAddEnvString(cmd, "QEMU_AUDIO_DRV=spice");

    } else {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unsupported graphics type '%s'"),
                       virDomainGraphicsTypeToString(graphics->type));
        goto error;
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
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
                     virQEMUDriverPtr driver,
                     virDomainDefPtr def,
                     virDomainChrSourceDefPtr monitor_chr,
                     bool monitor_json,
                     qemuCapsPtr caps,
                     const char *migrateFrom,
                     int migrateFd,
                     virDomainSnapshotObjPtr snapshot,
                     enum virNetDevVPortProfileOp vmop)
{
    int i, j;
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
    virCommandPtr cmd = NULL;
    bool emitBootindex = false;
    int sdl = 0;
    int vnc = 0;
    int spice = 0;
    int usbcontroller = 0;
    bool usblegacy = false;
    int contOrder[] = {
        /* We don't add an explicit IDE or FD controller because the
         * provided PIIX4 device already includes one. It isn't possible to
         * remove the PIIX4. */
        VIR_DOMAIN_CONTROLLER_TYPE_USB,
        VIR_DOMAIN_CONTROLLER_TYPE_SCSI,
        VIR_DOMAIN_CONTROLLER_TYPE_SATA,
        VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL,
        VIR_DOMAIN_CONTROLLER_TYPE_CCID,
    };
    virArch hostarch = virArchFromHost();

    VIR_DEBUG("conn=%p driver=%p def=%p mon=%p json=%d "
              "caps=%p migrateFrom=%s migrateFD=%d "
              "snapshot=%p vmop=%d",
              conn, driver, def, monitor_chr, monitor_json,
              caps, migrateFrom, migrateFd, snapshot, vmop);

    virUUIDFormat(def->uuid, uuid);

    emulator = def->emulator;

    /*
     * do not use boot=on for drives when not using KVM since this
     * is not supported at all in upstream QEmu.
     */
    if (qemuCapsGet(caps, QEMU_CAPS_KVM) &&
        (def->virtType == VIR_DOMAIN_VIRT_QEMU))
        qemuCapsClear(caps, QEMU_CAPS_DRIVE_BOOT);

    switch (def->virtType) {
    case VIR_DOMAIN_VIRT_QEMU:
        if (qemuCapsGet(caps, QEMU_CAPS_KQEMU))
            disableKQEMU = 1;
        if (qemuCapsGet(caps, QEMU_CAPS_KVM))
            disableKVM = 1;
        break;

    case VIR_DOMAIN_VIRT_KQEMU:
        if (qemuCapsGet(caps, QEMU_CAPS_KVM))
            disableKVM = 1;

        if (qemuCapsGet(caps, QEMU_CAPS_ENABLE_KQEMU)) {
            enableKQEMU = 1;
        } else if (!qemuCapsGet(caps, QEMU_CAPS_KQEMU)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("the QEMU binary %s does not support kqemu"),
                           emulator);
            goto error;
        }
        break;

    case VIR_DOMAIN_VIRT_KVM:
        if (qemuCapsGet(caps, QEMU_CAPS_KQEMU))
            disableKQEMU = 1;

        if (qemuCapsGet(caps, QEMU_CAPS_ENABLE_KVM)) {
            enableKVM = 1;
        } else if (!qemuCapsGet(caps, QEMU_CAPS_KVM)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("the QEMU binary %s does not support kvm"),
                           emulator);
            goto error;
        }
        break;

    case VIR_DOMAIN_VIRT_XEN:
        /* XXX better check for xenner */
        break;

    default:
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("the QEMU binary %s does not support %s"),
                       emulator, virDomainVirtTypeToString(def->virtType));
        break;
    }

    cmd = virCommandNew(emulator);

    virCommandAddEnvPassCommon(cmd);

    if (qemuCapsGet(caps, QEMU_CAPS_NAME)) {
        virCommandAddArg(cmd, "-name");
        if (driver->setProcessName &&
            qemuCapsGet(caps, QEMU_CAPS_NAME_PROCESS)) {
            virCommandAddArgFormat(cmd, "%s,process=qemu:%s",
                                   def->name, def->name);
        } else {
            virCommandAddArg(cmd, def->name);
        }
    }
    virCommandAddArg(cmd, "-S"); /* freeze CPU */

    if (qemuBuildMachineArgStr(cmd, def, caps) < 0)
        goto error;

    if (qemuBuildCpuArgStr(driver, def, emulator, caps,
                           hostarch, &cpu, &hasHwVirt, !!migrateFrom) < 0)
        goto error;

    if (cpu) {
        virCommandAddArgList(cmd, "-cpu", cpu, NULL);
        VIR_FREE(cpu);

        if (qemuCapsGet(caps, QEMU_CAPS_NESTING) &&
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

    if (def->os.loader) {
        virCommandAddArg(cmd, "-bios");
        virCommandAddArg(cmd, def->os.loader);
    }

    /* Set '-m MB' based on maxmem, because the lower 'memory' limit
     * is set post-startup using the balloon driver. If balloon driver
     * is not supported, then they're out of luck anyway.  Update the
     * XML to reflect our rounding.
     */
    virCommandAddArg(cmd, "-m");
    def->mem.max_balloon = VIR_DIV_UP(def->mem.max_balloon, 1024) * 1024;
    virCommandAddArgFormat(cmd, "%llu", def->mem.max_balloon / 1024);
    if (def->mem.hugepage_backed) {
        if (!driver->hugetlbfs_mount) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("hugetlbfs filesystem is not mounted"));
            goto error;
        }
        if (!driver->hugepage_path) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("hugepages are disabled by administrator config"));
            goto error;
        }
        if (!qemuCapsGet(caps, QEMU_CAPS_MEM_PATH)) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("hugepage backing not supported by '%s'"),
                           def->emulator);
            goto error;
        }
        virCommandAddArgList(cmd, "-mem-prealloc", "-mem-path",
                             driver->hugepage_path, NULL);
    }

    virCommandAddArg(cmd, "-smp");
    if (!(smp = qemuBuildSmpArgStr(def, caps)))
        goto error;
    virCommandAddArg(cmd, smp);
    VIR_FREE(smp);

    if (def->cpu && def->cpu->ncells)
        if (qemuBuildNumaArgStr(def, cmd) < 0)
            goto error;

    if (qemuCapsGet(caps, QEMU_CAPS_UUID))
        virCommandAddArgList(cmd, "-uuid", uuid, NULL);
    if (def->virtType == VIR_DOMAIN_VIRT_XEN ||
        STREQ(def->os.type, "xen") ||
        STREQ(def->os.type, "linux")) {
        if (qemuCapsGet(caps, QEMU_CAPS_DOMID)) {
            virCommandAddArg(cmd, "-domid");
            virCommandAddArgFormat(cmd, "%d", def->id);
        } else if (qemuCapsGet(caps, QEMU_CAPS_XEN_DOMID)) {
            virCommandAddArg(cmd, "-xen-attach");
            virCommandAddArg(cmd, "-xen-domid");
            virCommandAddArgFormat(cmd, "%d", def->id);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("qemu emulator '%s' does not support xen"),
                           def->emulator);
            goto error;
        }
    }

    if ((def->os.smbios_mode != VIR_DOMAIN_SMBIOS_NONE) &&
        (def->os.smbios_mode != VIR_DOMAIN_SMBIOS_EMULATE)) {
        virSysinfoDefPtr source = NULL;
        bool skip_uuid = false;

        if (!qemuCapsGet(caps, QEMU_CAPS_SMBIOS_TYPE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("the QEMU binary %s does not support smbios settings"),
                           emulator);
            goto error;
        }

        /* should we really error out or just warn in those cases ? */
        if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_HOST) {
            if (driver->hostsysinfo == NULL) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Host SMBIOS information is not available"));
                goto error;
            }
            source = driver->hostsysinfo;
            /* Host and guest uuid must differ, by definition of UUID. */
            skip_uuid = true;
        } else if (def->os.smbios_mode == VIR_DOMAIN_SMBIOS_SYSINFO) {
            if (def->sysinfo == NULL) {
                virReportError(VIR_ERR_XML_ERROR,
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

    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
        /* Disable global config files and default devices */
        if (qemuCapsGet(caps, QEMU_CAPS_NO_USER_CONFIG))
            virCommandAddArg(cmd, "-no-user-config");
        else if (qemuCapsGet(caps, QEMU_CAPS_NODEFCONFIG))
            virCommandAddArg(cmd, "-nodefconfig");
        virCommandAddArg(cmd, "-nodefaults");
    }

    /* Serial graphics adapter */
    if (def->os.bios.useserial == VIR_DOMAIN_BIOS_USESERIAL_YES) {
        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support -device"));
            goto error;
        }
        if (!qemuCapsGet(caps, QEMU_CAPS_SGA)) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("qemu does not support SGA"));
            goto error;
        }
        if (!def->nserials) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("need at least one serial port to use SGA"));
            goto error;
        }
        virCommandAddArgList(cmd, "-device", "sga", NULL);
    }

    if (monitor_chr) {
        char *chrdev;
        /* Use -chardev if it's available */
        if (qemuCapsGet(caps, QEMU_CAPS_CHARDEV)) {

            virCommandAddArg(cmd, "-chardev");
            if (!(chrdev = qemuBuildChrChardevStr(monitor_chr, "monitor",
                                                  caps)))
                goto error;
            virCommandAddArg(cmd, chrdev);
            VIR_FREE(chrdev);

            virCommandAddArg(cmd, "-mon");
            virCommandAddArgFormat(cmd,
                                   "chardev=charmonitor,id=monitor,mode=%s",
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

    if (qemuCapsGet(caps, QEMU_CAPS_RTC)) {
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
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported timer type (name) '%s'"),
                           virDomainTimerNameTypeToString(def->clock.timers[i]->name));
            goto error;

        case VIR_DOMAIN_TIMER_NAME_KVMCLOCK:
            /* This is handled when building -cpu.  */
            break;

        case VIR_DOMAIN_TIMER_NAME_RTC:
            /* This has already been taken care of (in qemuBuildClockArgStr)
               if QEMU_CAPS_RTC is set (mutually exclusive with
               QEMUD_FLAG_RTC_TD_HACK) */
            if (qemuCapsGet(caps, QEMU_CAPS_RTC_TD_HACK)) {
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
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported rtc tickpolicy '%s'"),
                                   virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                goto error;
                }
            } else if (!qemuCapsGet(caps, QEMU_CAPS_RTC)
                       && (def->clock.timers[i]->tickpolicy
                           != VIR_DOMAIN_TIMER_TICKPOLICY_DELAY)
                       && (def->clock.timers[i]->tickpolicy != -1)) {
                /* a non-default rtc policy was given, but there is no
                   way to implement it in this version of qemu */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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
                if (qemuCapsGet(caps, QEMU_CAPS_NO_KVM_PIT))
                    virCommandAddArg(cmd, "-no-kvm-pit-reinjection");
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_CATCHUP:
                if (qemuCapsGet(caps, QEMU_CAPS_NO_KVM_PIT)) {
                    /* do nothing - this is default for kvm-pit */
                } else if (qemuCapsGet(caps, QEMU_CAPS_TDF)) {
                    /* -tdf switches to 'catchup' with userspace pit. */
                    virCommandAddArg(cmd, "-tdf");
                } else {
                    /* can't catchup if we have neither pit mode */
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("unsupported pit tickpolicy '%s'"),
                                   virDomainTimerTickpolicyTypeToString(def->clock.timers[i]->tickpolicy));
                    goto error;
                }
                break;
            case VIR_DOMAIN_TIMER_TICKPOLICY_MERGE:
            case VIR_DOMAIN_TIMER_TICKPOLICY_DISCARD:
                /* no way to support these modes for pit in qemu */
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
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

            if (qemuCapsGet(caps, QEMU_CAPS_NO_HPET)) {
                if (def->clock.timers[i]->present == 0)
                    virCommandAddArg(cmd, "-no-hpet");
            } else {
                /* no hpet timer available. The only possible action
                   is to raise an error if present="yes" */
                if (def->clock.timers[i]->present == 1) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   "%s", _("pit timer is not supported"));
                }
            }
            break;
        }
    }

    if (qemuCapsGet(caps, QEMU_CAPS_NO_REBOOT) &&
        def->onReboot != VIR_DOMAIN_LIFECYCLE_RESTART)
        virCommandAddArg(cmd, "-no-reboot");

    /* If JSON monitor is enabled, we can receive an event
     * when QEMU stops. If we use no-shutdown, then we can
     * watch for this event and do a soft/warm reboot.
     */
    if (monitor_json && qemuCapsGet(caps, QEMU_CAPS_NO_SHUTDOWN))
        virCommandAddArg(cmd, "-no-shutdown");

    if (qemuCapsGet(caps, QEMU_CAPS_NO_ACPI)) {
        if (!(def->features & (1 << VIR_DOMAIN_FEATURE_ACPI)))
            virCommandAddArg(cmd, "-no-acpi");
    }

    if (def->pm.s3) {
        if (!qemuCapsGet(caps, QEMU_CAPS_DISABLE_S3)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("setting ACPI S3 not supported"));
            goto error;
        }
        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "PIIX4_PM.disable_s3=%d",
                               def->pm.s3 == VIR_DOMAIN_PM_STATE_DISABLED);
    }

    if (def->pm.s4) {
        if (!qemuCapsGet(caps, QEMU_CAPS_DISABLE_S4)) {
         virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           "%s", _("setting ACPI S4 not supported"));
            goto error;
        }
        virCommandAddArg(cmd, "-global");
        virCommandAddArgFormat(cmd, "PIIX4_PM.disable_s4=%d",
                               def->pm.s4 == VIR_DOMAIN_PM_STATE_DISABLED);
    }

    if (!def->os.bootloader) {
        int boot_nparams = 0;
        virBuffer boot_buf = VIR_BUFFER_INITIALIZER;
        /*
         * We prefer using explicit bootindex=N parameters for predictable
         * results even though domain XML doesn't use per device boot elements.
         * However, we can't use bootindex if boot menu was requested.
         */
        if (!def->os.nBootDevs) {
            /* def->os.nBootDevs is guaranteed to be > 0 unless per-device boot
             * configuration is used
             */
            if (!qemuCapsGet(caps, QEMU_CAPS_BOOTINDEX)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("hypervisor lacks deviceboot feature"));
                goto error;
            }
            emitBootindex = true;
        } else if (qemuCapsGet(caps, QEMU_CAPS_BOOTINDEX) &&
                   (def->os.bootmenu != VIR_DOMAIN_BOOT_MENU_ENABLED ||
                    !qemuCapsGet(caps, QEMU_CAPS_BOOT_MENU))) {
            emitBootindex = true;
        }

        if (!emitBootindex) {
            char boot[VIR_DOMAIN_BOOT_LAST+1];

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
            boot[def->os.nBootDevs] = '\0';

            virBufferAsprintf(&boot_buf, "%s", boot);
            boot_nparams++;
        }

        if (def->os.bootmenu) {
            if (qemuCapsGet(caps, QEMU_CAPS_BOOT_MENU)) {
                if (boot_nparams++)
                    virBufferAddChar(&boot_buf, ',');

                if (def->os.bootmenu == VIR_DOMAIN_BOOT_MENU_ENABLED)
                    virBufferAsprintf(&boot_buf, "menu=on");
                else
                    virBufferAsprintf(&boot_buf, "menu=off");
            } else {
                /* We cannot emit an error when bootmenu is enabled but
                 * unsupported because of backward compatibility */
                VIR_WARN("bootmenu is enabled but not "
                         "supported by this QEMU binary");
            }
        }

        if (def->os.bios.rt_set) {
            if (!qemuCapsGet(caps, QEMU_CAPS_REBOOT_TIMEOUT)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("reboot timeout is not supported "
                                 "by this QEMU binary"));
                goto error;
            }

            if (boot_nparams++)
                virBufferAddChar(&boot_buf, ',');

            virBufferAsprintf(&boot_buf,
                              "reboot-timeout=%d",
                              def->os.bios.rt_delay);
        }

        if (boot_nparams > 0) {
            virCommandAddArg(cmd, "-boot");

            if (boot_nparams < 2 || emitBootindex) {
                virCommandAddArgBuffer(cmd, &boot_buf);
            } else {
                virCommandAddArgFormat(cmd,
                                       "order=%s",
                                       virBufferContentAndReset(&boot_buf));
            }
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
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported driver name '%s' for disk '%s'"),
                           disk->driverName, disk->src);
            goto error;
        }
    }

    if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
        for (j = 0; j < ARRAY_CARDINALITY(contOrder); j++) {
            for (i = 0; i < def->ncontrollers; i++) {
                virDomainControllerDefPtr cont = def->controllers[i];

                if (cont->type != contOrder[j])
                    continue;

                /* Also, skip USB controllers with type none.*/
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                    cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE) {
                    usbcontroller = -1; /* mark we don't want a controller */
                    continue;
                }

                /* Only recent QEMU implements a SATA (AHCI) controller */
                if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_SATA) {
                    if (!qemuCapsGet(caps, QEMU_CAPS_ICH9_AHCI)) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("SATA is not supported with this "
                                         "QEMU binary"));
                        goto error;
                    } else {
                        char *devstr;

                        virCommandAddArg(cmd, "-device");
                        if (!(devstr = qemuBuildControllerDevStr(def, cont,
                                                                 caps, NULL)))
                            goto error;

                        virCommandAddArg(cmd, devstr);
                        VIR_FREE(devstr);
                    }
                } else if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_USB &&
                           cont->model == -1 &&
                           !qemuCapsGet(caps, QEMU_CAPS_PIIX3_USB_UHCI)) {
                    if (usblegacy) {
                        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                       _("Multiple legacy USB controllers are "
                                         "not supported"));
                        goto error;
                    }
                    usblegacy = true;
                } else {
                    virCommandAddArg(cmd, "-device");

                    char *devstr;
                    if (!(devstr = qemuBuildControllerDevStr(def, cont, caps,
                                                             &usbcontroller)))
                        goto error;

                    virCommandAddArg(cmd, devstr);
                    VIR_FREE(devstr);
                }
            }
        }
    }

    if (usbcontroller == 0)
        virCommandAddArg(cmd, "-usb");

    for (i = 0 ; i < def->nhubs ; i++) {
        virDomainHubDefPtr hub = def->hubs[i];
        char *optstr;

        virCommandAddArg(cmd, "-device");
        if (!(optstr = qemuBuildHubDevStr(hub, caps)))
            goto error;
        virCommandAddArg(cmd, optstr);
        VIR_FREE(optstr);
    }

    /* If QEMU supports -drive param instead of old -hda, -hdb, -cdrom .. */
    if (qemuCapsGet(caps, QEMU_CAPS_DRIVE)) {
        int bootCD = 0, bootFloppy = 0, bootDisk = 0;

        if ((qemuCapsGet(caps, QEMU_CAPS_DRIVE_BOOT) || emitBootindex)) {
            /* bootDevs will get translated into either bootindex=N or boot=on
             * depending on what qemu supports */
            for (i = 0 ; i < def->os.nBootDevs ; i++) {
                switch (def->os.bootDevs[i]) {
                case VIR_DOMAIN_BOOT_CDROM:
                    bootCD = i + 1;
                    break;
                case VIR_DOMAIN_BOOT_FLOPPY:
                    bootFloppy = i + 1;
                    break;
                case VIR_DOMAIN_BOOT_DISK:
                    bootDisk = i + 1;
                    break;
                }
            }
        }

        for (i = 0 ; i < def->ndisks ; i++) {
            char *optstr;
            int bootindex = 0;
            virDomainDiskDefPtr disk = def->disks[i];
            int withDeviceArg = 0;
            bool deviceFlagMasked = false;

            /* Unless we have -device, then USB disks need special
               handling */
            if ((disk->bus == VIR_DOMAIN_DISK_BUS_USB) &&
                !qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    virCommandAddArg(cmd, "-usbdevice");
                    virCommandAddArgFormat(cmd, "disk:%s", disk->src);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unsupported usb disk type for '%s'"),
                                   disk->src);
                    goto error;
                }
                continue;
            }

            switch (disk->device) {
            case VIR_DOMAIN_DISK_DEVICE_CDROM:
                bootindex = bootCD;
                bootCD = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_FLOPPY:
                bootindex = bootFloppy;
                bootFloppy = 0;
                break;
            case VIR_DOMAIN_DISK_DEVICE_DISK:
            case VIR_DOMAIN_DISK_DEVICE_LUN:
                bootindex = bootDisk;
                bootDisk = 0;
                break;
            }

            virCommandAddArg(cmd, "-drive");

            /* Unfortunately it is not possible to use
               -device for floppies, or Xen paravirt
               devices. Fortunately, those don't need
               static PCI addresses, so we don't really
               care that we can't use -device */
            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                if (disk->bus != VIR_DOMAIN_DISK_BUS_XEN) {
                    withDeviceArg = 1;
                } else {
                    qemuCapsClear(caps, QEMU_CAPS_DEVICE);
                    deviceFlagMasked = true;
                }
            }
            optstr = qemuBuildDriveStr(conn, disk,
                                       emitBootindex ? false : !!bootindex,
                                       caps);
            if (deviceFlagMasked)
                qemuCapsSet(caps, QEMU_CAPS_DEVICE);
            if (!optstr)
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);

            if (!emitBootindex)
                bootindex = 0;
            else if (disk->info.bootIndex)
                bootindex = disk->info.bootIndex;

            if (withDeviceArg) {
                if (disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
                    virCommandAddArg(cmd, "-global");
                    virCommandAddArgFormat(cmd, "isa-fdc.drive%c=drive-%s",
                                           disk->info.addr.drive.unit
                                           ? 'B' : 'A',
                                           disk->info.alias);

                    if (bootindex) {
                        virCommandAddArg(cmd, "-global");
                        virCommandAddArgFormat(cmd, "isa-fdc.bootindex%c=%d",
                                               disk->info.addr.drive.unit
                                               ? 'B' : 'A',
                                               bootindex);
                    }
                } else {
                    virCommandAddArg(cmd, "-device");

                    if (!(optstr = qemuBuildDriveDevStr(def, disk, bootindex,
                                                        caps)))
                        goto error;
                    virCommandAddArg(cmd, optstr);
                    VIR_FREE(optstr);
                }
            }
        }
    } else {
        for (i = 0 ; i < def->ndisks ; i++) {
            char dev[NAME_MAX];
            char *file;
            const char *fmt;
            virDomainDiskDefPtr disk = def->disks[i];

            if ((disk->type == VIR_DOMAIN_DISK_TYPE_BLOCK) &&
                (disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("tray status 'open' is invalid for "
                                 "block type disk"));
                goto error;
            }

            if (disk->bus == VIR_DOMAIN_DISK_BUS_USB) {
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
                    virCommandAddArg(cmd, "-usbdevice");
                    virCommandAddArgFormat(cmd, "disk:%s", disk->src);
                } else {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
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
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unsupported disk type '%s'"), disk->dst);
                    goto error;
                }
            }

            if (disk->type == VIR_DOMAIN_DISK_TYPE_DIR) {
                /* QEMU only supports magic FAT format for now */
                if (disk->format > 0 && disk->format != VIR_STORAGE_FILE_FAT) {
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("unsupported disk driver type for '%s'"),
                                   virStorageFileFormatTypeToString(disk->format));
                    goto error;
                }
                if (!disk->readonly) {
                    virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                   _("cannot create virtual FAT disks in read-write mode"));
                    goto error;
                }
                if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY)
                    fmt = "fat:floppy:%s";
                else
                    fmt = "fat:%s";

                if (virAsprintf(&file, fmt, disk->src) < 0) {
                    goto no_memory;
                }
            } else if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
                switch (disk->protocol) {
                case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                    if (disk->nhosts != 1) {
                        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                       _("NBD accepts only one host"));
                        goto error;
                    }
                    if (virAsprintf(&file, "nbd:%s:%s,", disk->hosts->name,
                                    disk->hosts->port) < 0) {
                        goto no_memory;
                    }
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                    {
                        virBuffer opt = VIR_BUFFER_INITIALIZER;
                        if (qemuBuildRBDString(conn, disk, &opt) < 0)
                            goto error;
                        if (virBufferError(&opt)) {
                            virReportOOMError();
                            goto error;
                        }
                        file = virBufferContentAndReset(&opt);
                    }
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_GLUSTER:
                    {
                        virBuffer opt = VIR_BUFFER_INITIALIZER;
                        if (qemuBuildGlusterString(disk, &opt) < 0)
                            goto error;
                        if (virBufferError(&opt)) {
                            virReportOOMError();
                            goto error;
                        }
                        file = virBufferContentAndReset(&opt);
                    }
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                    if (disk->nhosts == 0) {
                        if (virAsprintf(&file, "sheepdog:%s,", disk->src) < 0) {
                            goto no_memory;
                        }
                    } else {
                        /* only one host is supported now */
                        if (virAsprintf(&file, "sheepdog:%s:%s:%s,",
                                        disk->hosts->name, disk->hosts->port,
                                        disk->src) < 0) {
                            goto no_memory;
                        }
                    }
                    break;
                }
            } else {
                if (!(file = strdup(disk->src))) {
                    goto no_memory;
                }
            }

            /* Don't start with source if the tray is open for
             * CDROM and Floppy device.
             */
            if (!((disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY ||
                   disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM) &&
                  disk->tray_status == VIR_DOMAIN_DISK_TRAY_OPEN))
                virCommandAddArgList(cmd, dev, file, NULL);
            VIR_FREE(file);
        }
    }

    if (qemuCapsGet(caps, QEMU_CAPS_FSDEV)) {
        for (i = 0 ; i < def->nfss ; i++) {
            char *optstr;
            virDomainFSDefPtr fs = def->fss[i];

            virCommandAddArg(cmd, "-fsdev");
            if (!(optstr = qemuBuildFSStr(fs, caps)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);

            virCommandAddArg(cmd, "-device");
            if (!(optstr = qemuBuildFSDevStr(fs, caps)))
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        }
    } else {
        if (def->nfss) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("filesystem passthrough not supported by this QEMU"));
            goto error;
        }
    }

    if (!def->nnets) {
        /* If we have -device, then we set -nodefault already */
        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-net", "none", NULL);
    } else {
        int bootNet = 0;

        if (emitBootindex) {
            /* convert <boot dev='network'/> to bootindex since we didn't emit
             * -boot n
             */
            for (i = 0 ; i < def->os.nBootDevs ; i++) {
                if (def->os.bootDevs[i] == VIR_DOMAIN_BOOT_NET) {
                    bootNet = i + 1;
                    break;
                }
            }
        }

        for (i = 0 ; i < def->nnets ; i++) {
            virDomainNetDefPtr net = def->nets[i];
            char *nic, *host;
            char tapfd_name[50] = "";
            char vhostfd_name[50] = "";
            int vlan;
            int bootindex = bootNet;
            int actualType;

            bootNet = 0;
            if (!bootindex)
                bootindex = net->info.bootIndex;

            /* VLANs are not used with -netdev, so don't record them */
            if (qemuCapsGet(caps, QEMU_CAPS_NETDEV) &&
                qemuCapsGet(caps, QEMU_CAPS_DEVICE))
                vlan = -1;
            else
                vlan = i;

            /* If appropriate, grab a physical device from the configured
             * network's pool of devices, or resolve bridge device name
             * to the one defined in the network definition.
             */
            if (networkAllocateActualDevice(net) < 0)
               goto error;

            actualType = virDomainNetGetActualType(net);
            if (actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
                if (net->type == VIR_DOMAIN_NET_TYPE_NETWORK) {
                    virDomainHostdevDefPtr hostdev = virDomainNetGetActualHostdev(net);
                    virDomainHostdevDefPtr found;
                    /* For a network with <forward mode='hostdev'>, there is a need to
                     * add the newly minted hostdev to the hostdevs array.
                     */
                    if (qemuAssignDeviceHostdevAlias(def, hostdev,
                                                     (def->nhostdevs-1)) < 0) {
                        goto error;
                    }

                    if (virDomainHostdevFind(def, hostdev, &found) < 0) {
                        if (virDomainHostdevInsert(def, hostdev) < 0) {
                            virReportOOMError();
                            goto error;
                        }
                        if (qemuPrepareHostdevPCIDevices(driver, def->name, def->uuid,
                                                         &hostdev, 1) < 0) {
                            goto error;
                        }
                    }
                    else {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("PCI device %04x:%02x:%02x.%x "
                                         "allocated from network %s is already "
                                         "in use by domain %s"),
                                       hostdev->source.subsys.u.pci.domain,
                                       hostdev->source.subsys.u.pci.bus,
                                       hostdev->source.subsys.u.pci.slot,
                                       hostdev->source.subsys.u.pci.function,
                                       net->data.network.name,
                                       def->name);
                        goto error;
                    }
                }
                continue;
            }

            if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
                actualType == VIR_DOMAIN_NET_TYPE_BRIDGE) {
                /*
                 * If type='bridge' then we attempt to allocate the tap fd here only if
                 * running under a privilged user or -netdev bridge option is not
                 * supported.
                 */
                if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
                    driver->privileged ||
                    (!qemuCapsGet(caps, QEMU_CAPS_NETDEV_BRIDGE))) {
                    int tapfd = qemuNetworkIfaceConnect(def, conn, driver, net,
                                                        caps);
                    if (tapfd < 0)
                        goto error;

                    last_good_net = i;
                    virCommandTransferFD(cmd, tapfd);

                    if (snprintf(tapfd_name, sizeof(tapfd_name), "%d",
                                 tapfd) >= sizeof(tapfd_name))
                        goto no_memory;
                }
            } else if (actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
                int tapfd = qemuPhysIfaceConnect(def, driver, net,
                                                 caps, vmop);
                if (tapfd < 0)
                    goto error;

                last_good_net = i;
                virCommandTransferFD(cmd, tapfd);

                if (snprintf(tapfd_name, sizeof(tapfd_name), "%d",
                             tapfd) >= sizeof(tapfd_name))
                    goto no_memory;
            }

            if (actualType == VIR_DOMAIN_NET_TYPE_NETWORK ||
                actualType == VIR_DOMAIN_NET_TYPE_BRIDGE ||
                actualType == VIR_DOMAIN_NET_TYPE_DIRECT) {
                /* Attempt to use vhost-net mode for these types of
                   network device */
                int vhostfd;

                if (qemuOpenVhostNet(def, net, caps, &vhostfd) < 0)
                    goto error;
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
            if (qemuCapsGet(caps, QEMU_CAPS_NETDEV) &&
                qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-netdev");
                if (!(host = qemuBuildHostNetStr(net, driver, caps,
                                                 ',', vlan, tapfd_name,
                                                 vhostfd_name)))
                    goto error;
                virCommandAddArg(cmd, host);
                VIR_FREE(host);
            }
            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-device");
                nic = qemuBuildNicDevStr(net, vlan, bootindex, caps);
                if (!nic)
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
            if (!(qemuCapsGet(caps, QEMU_CAPS_NETDEV) &&
                  qemuCapsGet(caps, QEMU_CAPS_DEVICE))) {
                virCommandAddArg(cmd, "-net");
                if (!(host = qemuBuildHostNetStr(net, driver, caps,
                                                 ',', vlan, tapfd_name,
                                                 vhostfd_name)))
                    goto error;
                virCommandAddArg(cmd, host);
                VIR_FREE(host);
            }
        }
    }

    if (def->nsmartcards) {
        /* -device usb-ccid was already emitted along with other
         * controllers.  For now, qemu handles only one smartcard.  */
        virDomainSmartcardDefPtr smartcard = def->smartcards[0];
        char *devstr;
        virBuffer opt = VIR_BUFFER_INITIALIZER;
        const char *database;

        if (def->nsmartcards > 1 ||
            smartcard->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID ||
            smartcard->info.addr.ccid.controller != 0 ||
            smartcard->info.addr.ccid.slot != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("this QEMU binary lacks multiple smartcard "
                             "support"));
            virBufferFreeAndReset(&opt);
            goto error;
        }

        switch (smartcard->type) {
        case VIR_DOMAIN_SMARTCARD_TYPE_HOST:
            if (!qemuCapsGet(caps, QEMU_CAPS_CHARDEV) ||
                !qemuCapsGet(caps, QEMU_CAPS_CCID_EMULATED)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard host "
                                 "mode support"));
                goto error;
            }

            virBufferAddLit(&opt, "ccid-card-emulated,backend=nss-emulated");
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_HOST_CERTIFICATES:
            if (!qemuCapsGet(caps, QEMU_CAPS_CHARDEV) ||
                !qemuCapsGet(caps, QEMU_CAPS_CCID_EMULATED)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard host "
                                 "mode support"));
                goto error;
            }

            virBufferAddLit(&opt, "ccid-card-emulated,backend=certificates");
            for (j = 0; j < VIR_DOMAIN_SMARTCARD_NUM_CERTIFICATES; j++) {
                if (strchr(smartcard->data.cert.file[j], ',')) {
                    virBufferFreeAndReset(&opt);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("invalid certificate name: %s"),
                                   smartcard->data.cert.file[j]);
                    goto error;
                }
                virBufferAsprintf(&opt, ",cert%d=%s", j + 1,
                                  smartcard->data.cert.file[j]);
            }
            if (smartcard->data.cert.database) {
                if (strchr(smartcard->data.cert.database, ',')) {
                    virBufferFreeAndReset(&opt);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("invalid database name: %s"),
                                   smartcard->data.cert.database);
                    goto error;
                }
                database = smartcard->data.cert.database;
            } else {
                database = VIR_DOMAIN_SMARTCARD_DEFAULT_DATABASE;
            }
            virBufferAsprintf(&opt, ",database=%s", database);
            break;

        case VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH:
            if (!qemuCapsGet(caps, QEMU_CAPS_CHARDEV) ||
                !qemuCapsGet(caps, QEMU_CAPS_CCID_PASSTHRU)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("this QEMU binary lacks smartcard "
                                 "passthrough mode support"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&smartcard->data.passthru,
                                                  smartcard->info.alias,
                                                  caps))) {
                virBufferFreeAndReset(&opt);
                goto error;
            }
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virBufferAsprintf(&opt, "ccid-card-passthru,chardev=char%s",
                              smartcard->info.alias);
            break;

        default:
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("unexpected smartcard type %d"),
                           smartcard->type);
            virBufferFreeAndReset(&opt);
            goto error;
        }
        virCommandAddArg(cmd, "-device");
        virBufferAsprintf(&opt, ",id=%s,bus=ccid0.0", smartcard->info.alias);
        virCommandAddArgBuffer(cmd, &opt);
    }

    if (!def->nserials) {
        /* If we have -device, then we set -nodefault already */
        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-serial", "none", NULL);
    } else {
        for (i = 0 ; i < def->nserials ; i++) {
            virDomainChrDefPtr serial = def->serials[i];
            char *devstr;

            /* Use -chardev with -device if they are available */
            if (qemuCapsGet(caps, QEMU_CAPS_CHARDEV) &&
                qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(&serial->source,
                                                      serial->info.alias,
                                                      caps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);

                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildChrDeviceStr(serial, caps,
                                                     def->os.arch,
                                                     def->os.machine)))
                   goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virCommandAddArg(cmd, "-serial");
                if (!(devstr = qemuBuildChrArgStr(&serial->source, NULL)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    if (!def->nparallels) {
        /* If we have -device, then we set -nodefault already */
        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE))
            virCommandAddArgList(cmd, "-parallel", "none", NULL);
    } else {
        for (i = 0 ; i < def->nparallels ; i++) {
            virDomainChrDefPtr parallel = def->parallels[i];
            char *devstr;

            /* Use -chardev with -device if they are available */
            if (qemuCapsGet(caps, QEMU_CAPS_CHARDEV) &&
                qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(&parallel->source,
                                                      parallel->info.alias,
                                                      caps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);

                virCommandAddArg(cmd, "-device");
                virCommandAddArgFormat(cmd, "isa-parallel,chardev=char%s,id=%s",
                                       parallel->info.alias,
                                       parallel->info.alias);
            } else {
                virCommandAddArg(cmd, "-parallel");
                if (!(devstr = qemuBuildChrArgStr(&parallel->source, NULL)))
                      goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }
        }
    }

    for (i = 0 ; i < def->nchannels ; i++) {
        virDomainChrDefPtr channel = def->channels[i];
        char *devstr;
        char *addr;
        int port;

        switch (channel->targetType) {
        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_GUESTFWD:
            if (!qemuCapsGet(caps, QEMU_CAPS_CHARDEV) ||
                !qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("guestfwd requires QEMU to support -chardev & -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&channel->source,
                                                  channel->info.alias,
                                                  caps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            addr = virSocketAddrFormat(channel->target.addr);
            if (!addr)
                goto error;
            port = virSocketAddrGetPort(channel->target.addr);

            virCommandAddArg(cmd, "-netdev");
            virCommandAddArgFormat(cmd,
                                   "user,guestfwd=tcp:%s:%i,chardev=char%s,id=user-%s",
                                   addr, port, channel->info.alias,
                                   channel->info.alias);
            VIR_FREE(addr);
            break;

        case VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO:
            if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE_SPICEVMC) &&
                channel->source.type == VIR_DOMAIN_CHR_TYPE_SPICEVMC) {
                /* spicevmc was originally introduced via a -device
                 * with a backend internal to qemu; although we prefer
                 * the newer -chardev interface.  */
                ;
            } else {
                virCommandAddArg(cmd, "-chardev");
                if (!(devstr = qemuBuildChrChardevStr(&channel->source,
                                                      channel->info.alias,
                                                      caps)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            }

            virCommandAddArg(cmd, "-device");
            if (!(devstr = qemuBuildVirtioSerialPortDevStr(channel,
                                                           caps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
            break;
        }
    }

    /* Explicit console devices */
    for (i = 0 ; i < def->nconsoles ; i++) {
        virDomainChrDefPtr console = def->consoles[i];
        char *devstr;

        switch (console->targetType) {
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLP:
        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SCLPLM:
            if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclp console requires QEMU to support -device"));
                goto error;
            }
            if (!qemuCapsGet(caps, QEMU_CAPS_SCLP_S390)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("sclp console requires QEMU to support s390-sclp"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&console->source,
                                                  console->info.alias,
                                                  caps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virCommandAddArg(cmd, "-device");
            if (!(devstr = qemuBuildSclpDevStr(console)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_VIRTIO:
            if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("virtio channel requires QEMU to support -device"));
                goto error;
            }

            virCommandAddArg(cmd, "-chardev");
            if (!(devstr = qemuBuildChrChardevStr(&console->source,
                                                  console->info.alias,
                                                  caps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);

            virCommandAddArg(cmd, "-device");
            if (!(devstr = qemuBuildVirtioSerialPortDevStr(console,
                                                           caps)))
                goto error;
            virCommandAddArg(cmd, devstr);
            VIR_FREE(devstr);
            break;

        case VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL:
            break;

        default:
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unsupported console target type %s"),
                           NULLSTR(virDomainChrConsoleTargetTypeToString(console->targetType)));
            goto error;
        }
    }

    for (i = 0 ; i < def->ninputs ; i++) {
        virDomainInputDefPtr input = def->inputs[i];

        if (input->bus == VIR_DOMAIN_INPUT_BUS_USB) {
            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                char *optstr;
                virCommandAddArg(cmd, "-device");
                if (!(optstr = qemuBuildUSBInputDevStr(input, caps)))
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

    for (i = 0 ; i < def->ngraphics ; ++i) {
        switch (def->graphics[i]->type) {
        case VIR_DOMAIN_GRAPHICS_TYPE_SDL:
            ++sdl;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_VNC:
            ++vnc;
            break;
        case VIR_DOMAIN_GRAPHICS_TYPE_SPICE:
            ++spice;
            break;
        }
    }
    if (!qemuCapsGet(caps, QEMU_CAPS_0_10) && sdl + vnc + spice > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 1 graphics device is supported"));
        goto error;
    }
    if (sdl > 1 || vnc > 1 || spice > 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only 1 graphics device of each type "
                         "(sdl, vnc, spice) is supported"));
        goto error;
    }

    for (i = 0 ; i < def->ngraphics ; ++i) {
        if (qemuBuildGraphicsCommandLine(driver, cmd, def, caps,
                                         def->graphics[i]) < 0)
            goto error;
    }
    if (def->nvideos > 0) {
        int primaryVideoType = def->videos[0]->type;
        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE_VIDEO_PRIMARY) &&
             ((primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VGA &&
                 qemuCapsGet(caps, QEMU_CAPS_DEVICE_VGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_CIRRUS &&
                 qemuCapsGet(caps, QEMU_CAPS_DEVICE_CIRRUS_VGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_VMVGA &&
                 qemuCapsGet(caps, QEMU_CAPS_DEVICE_VMWARE_SVGA)) ||
             (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_QXL &&
                 qemuCapsGet(caps, QEMU_CAPS_DEVICE_QXL_VGA)))
           ) {
            for (i = 0 ; i < def->nvideos ; i++) {
                char *str;
                virCommandAddArg(cmd, "-device");
                if (!(str = qemuBuildDeviceVideoStr(def->videos[i], caps, !i)))
                    goto error;

                virCommandAddArg(cmd, str);
                VIR_FREE(str);
            }
        } else if (qemuCapsGet(caps, QEMU_CAPS_VGA)) {
            if (primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_XEN) {
                /* nothing - vga has no effect on Xen pvfb */
            } else {
                if ((primaryVideoType == VIR_DOMAIN_VIDEO_TYPE_QXL) &&
                    !qemuCapsGet(caps, QEMU_CAPS_VGA_QXL)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("This QEMU does not support QXL graphics adapters"));
                    goto error;
                }

                const char *vgastr = qemuVideoTypeToString(primaryVideoType);
                if (!vgastr || STREQ(vgastr, "")) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   _("video type %s is not supported with QEMU"),
                                   virDomainVideoTypeToString(primaryVideoType));
                    goto error;
                }

                virCommandAddArgList(cmd, "-vga", vgastr, NULL);

                if (def->videos[0]->type == VIR_DOMAIN_VIDEO_TYPE_QXL) {
                    if (def->videos[0]->vram &&
                        qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                        if (def->videos[0]->vram > (UINT_MAX / 1024)) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                           _("value for 'vram' must be less than '%u'"),
                                           UINT_MAX / 1024);
                            goto error;
                        }

                        virCommandAddArg(cmd, "-global");

                        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE_QXL_VGA))
                            virCommandAddArgFormat(cmd, "qxl-vga.vram_size=%u",
                                                   def->videos[0]->vram * 1024);
                        else
                            virCommandAddArgFormat(cmd, "qxl.vram_size=%u",
                                                   def->videos[0]->vram * 1024);
                    }
                }
            }

            if (def->nvideos > 1) {
                if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                    for (i = 1 ; i < def->nvideos ; i++) {
                        char *str;
                        if (def->videos[i]->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
                            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                           _("video type %s is only valid as primary video card"),
                                           virDomainVideoTypeToString(def->videos[0]->type));
                            goto error;
                        }

                        virCommandAddArg(cmd, "-device");

                        if (!(str = qemuBuildDeviceVideoStr(def->videos[i], caps, false)))
                            goto error;

                        virCommandAddArg(cmd, str);
                        VIR_FREE(str);
                    }
                } else {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                                   "%s", _("only one video card is currently supported"));
                    goto error;
                }
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
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("video type %s is not supported with this QEMU"),
                               virDomainVideoTypeToString(def->videos[0]->type));
                goto error;
            }

            if (def->nvideos > 1) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("only one video card is currently supported"));
                goto error;
            }
        }

    } else {
        /* If we have -device, then we set -nodefault already */
        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE) &&
            qemuCapsGet(caps, QEMU_CAPS_VGA) &&
            qemuCapsGet(caps, QEMU_CAPS_VGA_NONE))
            virCommandAddArgList(cmd, "-vga", "none", NULL);
    }

    /* Add sound hardware */
    if (def->nsounds) {
        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
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
                    if (!(str = qemuBuildSoundDevStr(sound, caps)))
                        goto error;

                    virCommandAddArg(cmd, str);

                    if (sound->model == VIR_DOMAIN_SOUND_MODEL_ICH6) {
                        char *codecstr = NULL;
                        int ii;

                        for (ii = 0 ; ii < sound->ncodecs ; ii++) {
                            virCommandAddArg(cmd, "-device");
                            if (!(codecstr = qemuBuildSoundCodecStr(sound, sound->codecs[ii], caps))) {
                                goto error;

                            }
                            virCommandAddArg(cmd, codecstr);
                            VIR_FREE(codecstr);
                        }
                        if (ii == 0) {
                            virDomainSoundCodecDef codec = {
                                VIR_DOMAIN_SOUND_CODEC_TYPE_DUPLEX,
                                0
                            };
                            virCommandAddArg(cmd, "-device");
                            if (!(codecstr = qemuBuildSoundCodecStr(sound, &codec, caps))) {
                                goto error;

                            }
                            virCommandAddArg(cmd, codecstr);
                            VIR_FREE(codecstr);
                        }
                    }

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
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   "%s", _("invalid sound model"));
                    goto error;
                }

                if (sound->model == VIR_DOMAIN_SOUND_MODEL_ICH6) {
                    VIR_FREE(modstr);
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("this QEMU binary lacks hda support"));
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

        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildWatchdogDevStr(watchdog, caps);
            if (!optstr)
                goto error;
        } else {
            virCommandAddArg(cmd, "-watchdog");

            const char *model = virDomainWatchdogModelTypeToString(watchdog->model);
            if (!model) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("invalid watchdog action"));
            goto error;
        }
        virCommandAddArgList(cmd, "-watchdog-action", action, NULL);
    }

    /* Add redirected devices */
    for (i = 0 ; i < def->nredirdevs ; i++) {
        virDomainRedirdevDefPtr redirdev = def->redirdevs[i];
        char *devstr;

        virCommandAddArg(cmd, "-chardev");
        if (!(devstr = qemuBuildChrChardevStr(&redirdev->source.chr,
                                              redirdev->info.alias,
                                              caps))) {
            goto error;
        }

        virCommandAddArg(cmd, devstr);
        VIR_FREE(devstr);

        if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE))
            goto error;

        virCommandAddArg(cmd, "-device");
        if (!(devstr = qemuBuildRedirdevDevStr(def, redirdev, caps)))
            goto error;
        virCommandAddArg(cmd, devstr);
        VIR_FREE(devstr);
    }


    /* Add host passthrough hardware */
    for (i = 0 ; i < def->nhostdevs ; i++) {
        virDomainHostdevDefPtr hostdev = def->hostdevs[i];
        char *devstr;

        if (hostdev->info->bootIndex) {
            if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
                (hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
                 hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("booting from assigned devices is only"
                                 " supported for PCI and USB devices"));
                goto error;
            } else {
                if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI &&
                    !qemuCapsGet(caps, QEMU_CAPS_PCI_BOOTINDEX)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("booting from assigned PCI devices is not"
                                     " supported with this version of qemu"));
                    goto error;
                }
                if (hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB &&
                    !qemuCapsGet(caps, QEMU_CAPS_USB_HOST_BOOTINDEX)) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("booting from assigned USB devices is not"
                                     " supported with this version of qemu"));
                    goto error;
                }
            }
        }

        /* USB */
        if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
            hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB) {

            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                virCommandAddArg(cmd, "-device");
                if (!(devstr = qemuBuildUSBHostdevDevStr(hostdev, caps)))
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
            if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
                char *configfd_name = NULL;
                if (qemuCapsGet(caps, QEMU_CAPS_PCI_CONFIGFD)) {
                    int configfd = qemuOpenPCIConfig(hostdev);

                    if (configfd >= 0) {
                        if (virAsprintf(&configfd_name, "%d", configfd) < 0) {
                            VIR_FORCE_CLOSE(configfd);
                            goto no_memory;
                        }

                        virCommandTransferFD(cmd, configfd);
                    }
                }
                virCommandAddArg(cmd, "-device");
                devstr = qemuBuildPCIHostdevDevStr(hostdev, configfd_name, caps);
                VIR_FREE(configfd_name);
                if (!devstr)
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else if (qemuCapsGet(caps, QEMU_CAPS_PCIDEVICE)) {
                virCommandAddArg(cmd, "-pcidevice");
                if (!(devstr = qemuBuildPCIHostdevPCIDevStr(hostdev)))
                    goto error;
                virCommandAddArg(cmd, devstr);
                VIR_FREE(devstr);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("PCI device assignment is not supported by this version of qemu"));
                goto error;
            }
        }
    }

    /* Migration is very annoying due to wildly varying syntax &
     * capabilities over time of KVM / QEMU codebases.
     */
    if (migrateFrom) {
        virCommandAddArg(cmd, "-incoming");
        if (STRPREFIX(migrateFrom, "tcp")) {
            if (!qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_TCP)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("TCP migration is not supported with "
                                       "this QEMU binary"));
                goto error;
            }
            virCommandAddArg(cmd, migrateFrom);
        } else if (STREQ(migrateFrom, "stdio")) {
            if (qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_FD)) {
                virCommandAddArgFormat(cmd, "fd:%d", migrateFd);
                virCommandPreserveFD(cmd, migrateFd);
            } else if (qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_EXEC)) {
                virCommandAddArg(cmd, "exec:cat");
                virCommandSetInputFD(cmd, migrateFd);
            } else if (qemuCapsGet(caps, QEMU_CAPS_MIGRATE_KVM_STDIO)) {
                virCommandAddArg(cmd, migrateFrom);
                virCommandSetInputFD(cmd, migrateFd);
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("STDIO migration is not supported "
                                       "with this QEMU binary"));
                goto error;
            }
        } else if (STRPREFIX(migrateFrom, "exec")) {
            if (!qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_EXEC)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("EXEC migration is not supported "
                                       "with this QEMU binary"));
                goto error;
            }
            virCommandAddArg(cmd, migrateFrom);
        } else if (STRPREFIX(migrateFrom, "fd")) {
            if (!qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_FD)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("FD migration is not supported "
                                       "with this QEMU binary"));
                goto error;
            }
            virCommandAddArg(cmd, migrateFrom);
            virCommandPreserveFD(cmd, migrateFd);
        } else if (STRPREFIX(migrateFrom, "unix")) {
            if (!qemuCapsGet(caps, QEMU_CAPS_MIGRATE_QEMU_UNIX)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s", _("UNIX migration is not supported "
                                       "with this QEMU binary"));
                goto error;
            }
            virCommandAddArg(cmd, migrateFrom);
        } else {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("unknown migration protocol"));
            goto error;
        }
    }

    /* QEMU changed its default behavior to not include the virtio balloon
     * device.  Explicitly request it to ensure it will be present.
     *
     * NB: Earlier we declared that VirtIO balloon will always be in
     * slot 0x3 on bus 0x0
     */
    if ((def->memballoon) &&
        (def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_NONE)) {
        if (def->memballoon->model != VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("Memory balloon device type '%s' is not supported by this version of qemu"),
                           virDomainMemballoonModelTypeToString(def->memballoon->model));
            goto error;
        }
        if (qemuCapsGet(caps, QEMU_CAPS_DEVICE)) {
            char *optstr;
            virCommandAddArg(cmd, "-device");

            optstr = qemuBuildMemballoonDevStr(def->memballoon, caps);
            if (!optstr)
                goto error;
            virCommandAddArg(cmd, optstr);
            VIR_FREE(optstr);
        } else if (qemuCapsGet(caps, QEMU_CAPS_BALLOON)) {
            virCommandAddArgList(cmd, "-balloon", "virtio", NULL);
        }
    }

    if (snapshot)
        virCommandAddArgList(cmd, "-loadvm", snapshot->def->name, NULL);

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

    if (qemuCapsGet(caps, QEMU_CAPS_SECCOMP_SANDBOX)) {
        if (driver->seccompSandbox == 0)
            virCommandAddArgList(cmd, "-sandbox", "off", NULL);
        else if (driver->seccompSandbox > 0)
            virCommandAddArgList(cmd, "-sandbox", "on", NULL);
    } else if (driver->seccompSandbox > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("QEMU does not support seccomp sandboxes"));
        goto error;
    }

    return cmd;

 no_memory:
    virReportOOMError();
 error:
    /* free up any resources in the network driver */
    for (i = 0; i <= last_good_net; i++)
        virDomainConfNWFilterTeardown(def->nets[i]);
    virCommandFree(cmd);
    return NULL;
}

/* This function generates the correct '-device' string for character
 * devices of each architecture.
 */
char *
qemuBuildChrDeviceStr(virDomainChrDefPtr serial,
                      qemuCapsPtr caps,
                      virArch arch,
                      char *machine)
{
    virBuffer cmd = VIR_BUFFER_INITIALIZER;

    if ((arch == VIR_ARCH_PPC64) && STREQ(machine, "pseries")) {
        if (serial->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
            serial->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_SPAPRVIO) {
            virBufferAsprintf(&cmd, "spapr-vty,chardev=char%s",
                              serial->info.alias);
            if (qemuBuildDeviceAddressStr(&cmd, &serial->info, caps) < 0)
                goto error;
        }
    } else {
        virBufferAsprintf(&cmd, "%s,chardev=char%s,id=%s",
                          virDomainChrSerialTargetTypeToString(serial->targetType),
                          serial->info.alias, serial->info.alias);

        if (serial->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB) {
            if (!qemuCapsGet(caps, QEMU_CAPS_DEVICE_USB_SERIAL)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("usb-serial is not supported in this QEMU binary"));
                goto error;
            }

            if (serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                serial->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("usb-serial requires address of usb type"));
                goto error;
            }

            if (qemuBuildDeviceAddressStr(&cmd, &serial->info, caps) < 0)
               goto error;
        }
    }

    if (virBufferError(&cmd)) {
        virReportOOMError();
        goto error;
    }

    return virBufferContentAndReset(&cmd);

 error:
    virBufferFreeAndReset(&cmd);
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

        endmark = start;
        do {
            /* Qemu accepts ',,' as an escape for a literal comma;
             * skip past those here while searching for the end of the
             * value, then strip them down below */
            endmark = strchr(endmark, ',');
        } while (endmark && endmark[1] == ',' && (endmark += 2));
        if (!endmark)
            endmark = end;
        if (!(separator = strchr(start, '=')))
            separator = end;

        if (separator >= endmark) {
            if (!allowEmptyValue) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
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
            if (strchr(value, ',')) {
                char *p = strchr(value, ',') + 1;
                char *q = p + 1;
                while (*q) {
                    if (*q == ',')
                        q++;
                    *p++ = *q++;
                }
                *p = '\0';
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
                         int nvirtiodisk,
                         bool old_style_ceph_args)
{
    virDomainDiskDefPtr def = NULL;
    char **keywords;
    char **values;
    int nkeywords;
    int i;
    int idx = -1;
    int busid = -1;
    int unitid = -1;
    int trans = VIR_DOMAIN_DISK_TRANS_DEFAULT;

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
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse nbd filename '%s'"),
                                       def->src);
                        def = NULL;
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
                    def->hosts->transport = VIR_DOMAIN_DISK_PROTO_TRANS_TCP;
                    def->hosts->socket = NULL;

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
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!old_style_ceph_args && qemuParseRBDString(def) < 0)
                        goto cleanup;

                    VIR_FREE(p);
                } else if (STRPREFIX(def->src, "gluster")) {
                    def->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                    def->protocol = VIR_DOMAIN_DISK_PROTOCOL_GLUSTER;

                    if (qemuParseGlusterString(def) < 0)
                        goto cleanup;
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
                            virReportError(VIR_ERR_INTERNAL_ERROR,
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
                        def->hosts->transport = VIR_DOMAIN_DISK_PROTO_TRANS_TCP;
                        def->hosts->socket = NULL;
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
            def->format = virStorageFileFormatTypeFromString(values[i]);
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
            else if (STREQ(values[i], "directsync"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_DIRECTSYNC;
            else if (STREQ(values[i], "unsafe"))
                def->cachemode = VIR_DOMAIN_DISK_CACHE_UNSAFE;
        } else if (STREQ(keywords[i], "werror")) {
            if (STREQ(values[i], "stop"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
            else if (STREQ(values[i], "enospc"))
                def->error_policy = VIR_DOMAIN_DISK_ERROR_POLICY_ENOSPACE;
        } else if (STREQ(keywords[i], "rerror")) {
            if (STREQ(values[i], "stop"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_STOP;
            else if (STREQ(values[i], "report"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_REPORT;
            else if (STREQ(values[i], "ignore"))
                def->rerror_policy = VIR_DOMAIN_DISK_ERROR_POLICY_IGNORE;
        } else if (STREQ(keywords[i], "index")) {
            if (virStrToLong_i(values[i], NULL, 10, &idx) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive index '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "bus")) {
            if (virStrToLong_i(values[i], NULL, 10, &busid) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive bus '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "unit")) {
            if (virStrToLong_i(values[i], NULL, 10, &unitid) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse drive unit '%s'"), val);
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "readonly")) {
            if ((values[i] == NULL) || STREQ(values[i], "on"))
                def->readonly = 1;
        } else if (STREQ(keywords[i], "aio")) {
            if ((def->iomode = virDomainDiskIoTypeFromString(values[i])) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse io mode '%s'"), values[i]);
            }
        } else if (STREQ(keywords[i], "cyls")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.cylinders)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse cylinders value'%s'"),
                               values[i]);
            }
        } else if (STREQ(keywords[i], "heads")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.heads)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse heads value'%s'"),
                               values[i]);
            }
        } else if (STREQ(keywords[i], "secs")) {
            if (virStrToLong_ui(values[i], NULL, 10,
                                &(def->geometry.sectors)) < 0) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sectors value'%s'"),
                               values[i]);
            }
        } else if (STREQ(keywords[i], "trans")) {
            def->geometry.trans =
                virDomainDiskGeometryTransTypeFromString(values[i]);
            if ((trans < VIR_DOMAIN_DISK_TRANS_DEFAULT) ||
                (trans >= VIR_DOMAIN_DISK_TRANS_LAST)) {
                virDomainDiskDefFree(def);
                def = NULL;
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse translation value'%s'"),
                               values[i]);
            }
        }
    }

    if (def->rerror_policy == def->error_policy)
        def->rerror_policy = 0;

    if (!def->src &&
        def->device == VIR_DOMAIN_DISK_DEVICE_DISK &&
        def->type != VIR_DOMAIN_DISK_TYPE_NETWORK) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot parse NIC vlan in '%s'"), nics[i]);
            return NULL;
        }

        if (gotvlan == wantvlan)
            return nics[i];
    }

    if (wantvlan == 0 && nnics > 0)
        return nics[0];

    virReportError(VIR_ERR_INTERNAL_ERROR,
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
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse vlan in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (def->type == VIR_DOMAIN_NET_TYPE_ETHERNET &&
                   STREQ(keywords[i], "script") && STRNEQ(values[i], "")) {
            def->script = values[i];
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
        virReportError(VIR_ERR_INTERNAL_ERROR,
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
            if (virMacAddrParse(values[i], &def->mac) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("unable to parse mac address '%s'"),
                               values[i]);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
        } else if (STREQ(keywords[i], "model")) {
            def->model = values[i];
            values[i] = NULL;
        } else if (STREQ(keywords[i], "vhost")) {
            if ((values[i] == NULL) || STREQ(values[i], "on")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_VHOST;
            } else if (STREQ(keywords[i], "off")) {
                def->driver.virtio.name = VIR_DOMAIN_NET_BACKEND_TYPE_QEMU;
            }
        } else if (STREQ(keywords[i], "sndbuf") && values[i]) {
            if (virStrToLong_ul(values[i], NULL, 10, &def->tune.sndbuf) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("cannot parse sndbuf size in '%s'"), val);
                virDomainNetDefFree(def);
                def = NULL;
                goto cleanup;
            }
            def->tune.sndbuf_specified = true;
        }
    }

    if (genmac)
        virCapabilitiesGenerateMac(caps, &def->mac);

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
    int bus = 0, slot = 0, func = 0;
    const char *start;
    char *end;
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc();

    if (!def)
       goto error;

    if (!STRPREFIX(val, "host=")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown PCI device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host=");
    if (virStrToLong_i(start, &end, 16, &bus) < 0 || *end != ':') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device bus '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, &end, 16, &slot) < 0 || *end != '.') {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device slot '%s'"), val);
        goto error;
    }
    start = end + 1;
    if (virStrToLong_i(start, NULL, 16, &func) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("cannot extract PCI device function '%s'"), val);
        goto error;
    }

    def->mode = VIR_DOMAIN_HOSTDEV_MODE_SUBSYS;
    def->managed = 1;
    def->source.subsys.type = VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI;
    def->source.subsys.u.pci.bus = bus;
    def->source.subsys.u.pci.slot = slot;
    def->source.subsys.u.pci.function = func;
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU USB device
 */
static virDomainHostdevDefPtr
qemuParseCommandLineUSB(const char *val)
{
    virDomainHostdevDefPtr def = virDomainHostdevDefAlloc();
    int first = 0, second = 0;
    const char *start;
    char *end;

    if (!def)
       goto error;

    if (!STRPREFIX(val, "host:")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown USB device syntax '%s'"), val);
        goto error;
    }

    start = val + strlen("host:");
    if (strchr(start, ':')) {
        if (virStrToLong_i(start, &end, 16, &first) < 0 || *end != ':') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device vendor '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 16, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device product '%s'"), val);
            goto error;
        }
    } else {
        if (virStrToLong_i(start, &end, 10, &first) < 0 || *end != '.') {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device bus '%s'"), val);
            goto error;
        }
        start = end + 1;
        if (virStrToLong_i(start, NULL, 10, &second) < 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot extract USB device address '%s'"), val);
            goto error;
        }
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
    return def;

 error:
    virDomainHostdevDefFree(def);
    return NULL;
}


/*
 * Tries to parse a QEMU serial/parallel device
 */
static int
qemuParseCommandLineChr(virDomainChrSourceDefPtr source,
                        const char *val)
{
    if (STREQ(val, "null")) {
        source->type = VIR_DOMAIN_CHR_TYPE_NULL;
    } else if (STREQ(val, "vc")) {
        source->type = VIR_DOMAIN_CHR_TYPE_VC;
    } else if (STREQ(val, "pty")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PTY;
    } else if (STRPREFIX(val, "file:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_FILE;
        source->data.file.path = strdup(val+strlen("file:"));
        if (!source->data.file.path)
            goto no_memory;
    } else if (STRPREFIX(val, "pipe:")) {
        source->type = VIR_DOMAIN_CHR_TYPE_PIPE;
        source->data.file.path = strdup(val+strlen("pipe:"));
        if (!source->data.file.path)
            goto no_memory;
    } else if (STREQ(val, "stdio")) {
        source->type = VIR_DOMAIN_CHR_TYPE_STDIO;
    } else if (STRPREFIX(val, "udp:")) {
        const char *svc1, *host2, *svc2;
        source->type = VIR_DOMAIN_CHR_TYPE_UDP;
        val += strlen("udp:");
        svc1 = strchr(val, ':');
        host2 = svc1 ? strchr(svc1, '@') : NULL;
        svc2 = host2 ? strchr(host2, ':') : NULL;

        if (svc1 && (svc1 != val)) {
            source->data.udp.connectHost = strndup(val, svc1-val);

            if (!source->data.udp.connectHost)
                goto no_memory;
        }

        if (svc1) {
            svc1++;
            if (host2)
                source->data.udp.connectService = strndup(svc1, host2-svc1);
            else
                source->data.udp.connectService = strdup(svc1);

            if (!source->data.udp.connectService)
                goto no_memory;
        }

        if (host2) {
            host2++;
            if (svc2 && (svc2 != host2)) {
                source->data.udp.bindHost = strndup(host2, svc2-host2);

                if (!source->data.udp.bindHost)
                    goto no_memory;
            }
        }

        if (svc2) {
            svc2++;
            if (STRNEQ(svc2, "0")) {
                source->data.udp.bindService = strdup(svc2);
                if (!source->data.udp.bindService)
                    goto no_memory;
            }
        }
    } else if (STRPREFIX(val, "tcp:") ||
               STRPREFIX(val, "telnet:")) {
        const char *opt, *svc;
        source->type = VIR_DOMAIN_CHR_TYPE_TCP;
        if (STRPREFIX(val, "tcp:")) {
            val += strlen("tcp:");
        } else {
            val += strlen("telnet:");
            source->data.tcp.protocol = VIR_DOMAIN_CHR_TCP_PROTOCOL_TELNET;
        }
        svc = strchr(val, ':');
        if (!svc) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("cannot find port number in character device %s"), val);
            goto error;
        }
        opt = strchr(svc, ',');
        if (opt && strstr(opt, "server"))
            source->data.tcp.listen = true;

        source->data.tcp.host = strndup(val, svc-val);
        if (!source->data.tcp.host)
            goto no_memory;
        svc++;
        if (opt) {
            source->data.tcp.service = strndup(svc, opt-svc);
        } else {
            source->data.tcp.service = strdup(svc);
        }
        if (!source->data.tcp.service)
            goto no_memory;
    } else if (STRPREFIX(val, "unix:")) {
        const char *opt;
        val += strlen("unix:");
        opt = strchr(val, ',');
        source->type = VIR_DOMAIN_CHR_TYPE_UNIX;
        if (opt) {
            if (strstr(opt, "listen"))
                source->data.nix.listen = true;
            source->data.nix.path = strndup(val, opt-val);
        } else {
            source->data.nix.path = strdup(val);
        }
        if (!source->data.nix.path)
            goto no_memory;

    } else if (STRPREFIX(val, "/dev")) {
        source->type = VIR_DOMAIN_CHR_TYPE_DEV;
        source->data.file.path = strdup(val);
        if (!source->data.file.path)
            goto no_memory;
    } else {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("unknown character device syntax %s"), val);
        goto error;
    }

    return 0;

no_memory:
    virReportOOMError();
error:
    return -1;
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
    virCPUDefPtr cpu = NULL;
    const char *p = val;
    const char *next;
    char *model = NULL;

    do {
        if (*p == '\0' || *p == ',')
            goto syntax;

        if ((next = strchr(p, ',')))
            next++;

        if (p == val) {
            if (next)
                model = strndup(p, next - p - 1);
            else
                model = strdup(p);

            if (!model)
                goto no_memory;

            if (!STREQ(model, "qemu32") && !STREQ(model, "qemu64")) {
                if (!(cpu = qemuInitGuestCPU(dom)))
                    goto error;

                cpu->model = model;
                model = NULL;
            }
        } else if (*p == '+' || *p == '-') {
            char *feature;
            int policy;
            int ret = 0;

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

            if (!feature)
                goto no_memory;

            if (STREQ(feature, "kvmclock")) {
                bool present = (policy == VIR_CPU_FEATURE_REQUIRE);
                int i;

                for (i = 0; i < dom->clock.ntimers; i++) {
                    if (dom->clock.timers[i]->name == VIR_DOMAIN_TIMER_NAME_KVMCLOCK) {
                        break;
                    }
                }

                if (i == dom->clock.ntimers) {
                    if (VIR_REALLOC_N(dom->clock.timers, i+1) < 0 ||
                        VIR_ALLOC(dom->clock.timers[i]) < 0)
                        goto no_memory;
                    dom->clock.timers[i]->name = VIR_DOMAIN_TIMER_NAME_KVMCLOCK;
                    dom->clock.timers[i]->present = -1;
                    dom->clock.timers[i]->tickpolicy = -1;
                    dom->clock.timers[i]->track = -1;
                    dom->clock.ntimers++;
                }

                if (dom->clock.timers[i]->present != -1 &&
                    dom->clock.timers[i]->present != present) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("conflicting occurrences of kvmclock feature"));
                    goto error;
                }
                dom->clock.timers[i]->present = present;
            } else if (STREQ(feature, "kvm_pv_eoi")) {
                if (policy == VIR_CPU_FEATURE_REQUIRE)
                    dom->apic_eoi = VIR_DOMAIN_FEATURE_STATE_ON;
                else
                    dom->apic_eoi = VIR_DOMAIN_FEATURE_STATE_OFF;
            } else {
                if (!cpu) {
                    if (!(cpu = qemuInitGuestCPU(dom)))
                        goto error;

                    cpu->model = model;
                    model = NULL;
                }

                ret = virCPUDefAddFeature(cpu, feature, policy);
            }

            VIR_FREE(feature);
            if (ret < 0)
                goto error;
        } else if (STRPREFIX(p, "hv_")) {
            char *feature;
            int f;
            p += 3; /* "hv_" */

            if (*p == '\0' || *p == ',')
                goto syntax;

            if (next)
                feature = strndup(p, next - p - 1);
            else
                feature = strdup(p);

            if (!feature)
                goto no_memory;

            dom->features |= (1 << VIR_DOMAIN_FEATURE_HYPERV);

            if ((f = virDomainHypervTypeFromString(feature)) < 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("unsupported HyperV Enlightenment feature "
                                 "'%s'"), feature);
                goto error;
            }

            switch ((enum virDomainHyperv) f) {
            case VIR_DOMAIN_HYPERV_RELAXED:
                dom->hyperv_features[f] = VIR_DOMAIN_FEATURE_STATE_ON;
                break;

            case VIR_DOMAIN_HYPERV_LAST:
                break;
            }

            VIR_FREE(feature);
        }
    } while ((p = next));

    if (dom->os.arch == VIR_ARCH_X86_64) {
        bool is_32bit = false;
        if (cpu) {
            union cpuData *cpuData = NULL;
            int ret;

            ret = cpuEncode(VIR_ARCH_X86_64, cpu, NULL, &cpuData,
                            NULL, NULL, NULL, NULL);
            if (ret < 0)
                goto error;

            is_32bit = (cpuHasFeature(VIR_ARCH_X86_64, cpuData, "lm") != 1);
            cpuDataFree(VIR_ARCH_X86_64, cpuData);
        } else if (model) {
            is_32bit = STREQ(model, "qemu32");
        }

        if (is_32bit) {
            dom->os.arch = VIR_ARCH_I686;
        }
    }
    VIR_FREE(model);
    return 0;

syntax:
    virReportError(VIR_ERR_INTERNAL_ERROR,
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
    virReportError(VIR_ERR_INTERNAL_ERROR,
                   _("cannot parse CPU topology '%s'"), val);
error:
    ret = -1;
    goto cleanup;
}


static void
qemuParseCommandLineBootDevs(virDomainDefPtr def, const char *str) {
    int n, b = 0;

    for (n = 0 ; str[n] && b < VIR_DOMAIN_BOOT_LAST ; n++) {
        if (str[n] == 'a')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_FLOPPY;
        else if (str[n] == 'c')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_DISK;
        else if (str[n] == 'd')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_CDROM;
        else if (str[n] == 'n')
            def->os.bootDevs[b++] = VIR_DOMAIN_BOOT_NET;
        else if (str[n] == ',')
            break;
    }
    def->os.nBootDevs = b;
}


/*
 * Analyse the env and argv settings and reconstruct a
 * virDomainDefPtr representing these settings as closely
 * as is practical. This is not an exact science....
 */
virDomainDefPtr qemuParseCommandLine(virCapsPtr caps,
                                     const char **progenv,
                                     const char **progargv,
                                     char **pidfile,
                                     virDomainChrSourceDefPtr *monConfig,
                                     bool *monJSON)
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
    qemuDomainCmdlineDefPtr cmd = NULL;
    virDomainDiskDefPtr disk = NULL;
    const char *ceph_args = qemuFindEnv(progenv, "CEPH_ARGS");

    if (pidfile)
        *pidfile = NULL;
    if (monConfig)
        *monConfig = NULL;
    if (monJSON)
        *monJSON = false;

    if (!progargv[0]) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       "%s", _("no emulator path found"));
        return NULL;
    }

    if (VIR_ALLOC(def) < 0)
        goto no_memory;

    /* allocate the cmdlinedef up-front; if it's unused, we'll free it later */
    if (VIR_ALLOC(cmd) < 0)
        goto no_memory;

    if (virUUIDGenerate(def->uuid) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("failed to generate uuid"));
        goto error;
    }

    def->id = -1;
    def->mem.cur_balloon = def->mem.max_balloon = 64 * 1024;
    def->maxvcpus = 1;
    def->vcpus = 1;
    def->clock.offset = VIR_DOMAIN_CLOCK_OFFSET_UTC;

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
    if (def->virtType == VIR_DOMAIN_VIRT_KVM)
        def->os.arch = caps->host.arch;
    else if (path &&
             STRPREFIX(path, "qemu-system-"))
        def->os.arch = virArchFromString(path + strlen("qemu-system-"));
    else
        def->os.arch = VIR_ARCH_I686;

    if ((def->os.arch == VIR_ARCH_I686) ||
        (def->os.arch == VIR_ARCH_X86_64))
        def->features |= (1 << VIR_DOMAIN_FEATURE_ACPI)
        /*| (1 << VIR_DOMAIN_FEATURE_APIC)*/;
#define WANT_VALUE()                                                   \
    const char *val = progargv[++i];                                   \
    if (!val) {                                                        \
        virReportError(VIR_ERR_INTERNAL_ERROR,                        \
                       _("missing value for %s argument"), arg);       \
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

            if (STRPREFIX(val, "unix:")) {
                /* -vnc unix:/some/big/path */
                vnc->data.vnc.socket = strdup(val + 5);
                if (!vnc->data.vnc.socket) {
                    virDomainGraphicsDefFree(vnc);
                    goto no_memory;
                }
            } else {
                /*
                 * -vnc 127.0.0.1:4
                 * -vnc [2001:1:2:3:4:5:1234:1234]:4
                 * -vnc some.host.name:4
                 */
                char *opts;
                const char *sep = ":";
                if (val[0] == '[')
                    sep = "]:";
                tmp = strstr(val, sep);
                if (!tmp) {
                    virDomainGraphicsDefFree(vnc);
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("missing VNC port number in '%s'"), val);
                    goto error;
                }
                if (virStrToLong_i(tmp+strlen(sep), &opts, 10,
                                   &vnc->data.vnc.port) < 0) {
                    virDomainGraphicsDefFree(vnc);
                    virReportError(VIR_ERR_INTERNAL_ERROR,
                                   _("cannot parse VNC port '%s'"), tmp+1);
                    goto error;
                }
                if (val[0] == '[')
                    virDomainGraphicsListenSetAddress(vnc, 0,
                                                      val+1, tmp-(val+1), true);
                else
                    virDomainGraphicsListenSetAddress(vnc, 0,
                                                      val, tmp-val, true);
                if (!virDomainGraphicsListenGetAddress(vnc, 0)) {
                    virDomainGraphicsDefFree(vnc);
                    goto no_memory;
                }
                vnc->data.vnc.port += 5900;
                vnc->data.vnc.autoport = 0;
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
                virReportError(VIR_ERR_INTERNAL_ERROR, \
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
                virReportError(VIR_ERR_INTERNAL_ERROR, \
                               _("cannot parse UUID '%s'"), val);
                goto error;
            }
        } else if (STRPREFIX(arg, "-hd") ||
                   STRPREFIX(arg, "-sd") ||
                   STRPREFIX(arg, "-fd") ||
                   STREQ(arg, "-cdrom")) {
            WANT_VALUE();
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
            } else if (STRPREFIX(val, "gluster")) {
                disk->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                disk->protocol = VIR_DOMAIN_DISK_PROTOCOL_GLUSTER;
            } else if (STRPREFIX(val, "sheepdog:")) {
                disk->type = VIR_DOMAIN_DISK_TYPE_NETWORK;
                disk->protocol = VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG;
                val += strlen("sheepdog:");
            } else
                disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
            if (STREQ(arg, "-cdrom")) {
                disk->device = VIR_DOMAIN_DISK_DEVICE_CDROM;
                disk->dst = strdup("hdc");
                if (!disk->dst)
                    goto no_memory;
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
                if (!disk->dst)
                    goto no_memory;
            }
            disk->src = strdup(val);
            if (!disk->src)
                goto no_memory;

            if (disk->type == VIR_DOMAIN_DISK_TYPE_NETWORK) {
                char *host, *port;

                switch (disk->protocol) {
                case VIR_DOMAIN_DISK_PROTOCOL_NBD:
                    host = disk->src;
                    port = strchr(host, ':');
                    if (!port) {
                        virReportError(VIR_ERR_INTERNAL_ERROR,
                                       _("cannot parse nbd filename '%s'"), disk->src);
                        goto error;
                    }
                    *port++ = '\0';
                    if (VIR_ALLOC(disk->hosts) < 0)
                        goto no_memory;
                    disk->nhosts = 1;
                    disk->hosts->name = host;
                    disk->hosts->port = strdup(port);
                    if (!disk->hosts->port)
                        goto no_memory;
                    VIR_FREE(disk->src);
                    disk->src = NULL;
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_RBD:
                    /* old-style CEPH_ARGS env variable is parsed later */
                    if (!ceph_args && qemuParseRBDString(disk) < 0)
                        goto error;
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_SHEEPDOG:
                    /* disk->src must be [vdiname] or [host]:[port]:[vdiname] */
                    port = strchr(disk->src, ':');
                    if (port) {
                        char *vdi;

                        *port++ = '\0';
                        vdi = strchr(port, ':');
                        if (!vdi) {
                            virReportError(VIR_ERR_INTERNAL_ERROR,
                                           _("cannot parse sheepdog filename '%s'"), val);
                            goto error;
                        }
                        *vdi++ = '\0';
                        if (VIR_ALLOC(disk->hosts) < 0)
                            goto no_memory;
                        disk->nhosts = 1;
                        disk->hosts->name = disk->src;
                        disk->hosts->port = strdup(port);
                        if (!disk->hosts->port)
                            goto no_memory;
                        disk->src = strdup(vdi);
                        if (!disk->src)
                            goto no_memory;
                    }
                    break;
                case VIR_DOMAIN_DISK_PROTOCOL_GLUSTER:
                    if (qemuParseGlusterString(disk) < 0)
                        goto error;

                    break;
                }
            }

            if (!(disk->src || disk->nhosts > 0) ||
                !disk->dst)
                goto no_memory;

            if (virDomainDiskDefAssignAddress(caps, disk) < 0) {
                virReportError(VIR_ERR_INTERNAL_ERROR,
                               _("Cannot assign address for device name '%s'"),
                               disk->dst);
                goto error;
            }

            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            def->disks[def->ndisks++] = disk;
            disk = NULL;
        } else if (STREQ(arg, "-no-acpi")) {
            def->features &= ~(1 << VIR_DOMAIN_FEATURE_ACPI);
        } else if (STREQ(arg, "-no-reboot")) {
            def->onReboot = VIR_DOMAIN_LIFECYCLE_DESTROY;
        } else if (STREQ(arg, "-no-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_QEMU;
        } else if (STREQ(arg, "-enable-kvm")) {
            def->virtType = VIR_DOMAIN_VIRT_KVM;
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
        } else if (STREQ(arg, "-bios")) {
            WANT_VALUE();
            if (!(def->os.loader = strdup(val)))
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
            const char *token = NULL;
            WANT_VALUE();

            if (!strchr(val, ','))
                qemuParseCommandLineBootDevs(def, val);
            else {
                token = val;
                while (token && *token) {
                    if (STRPREFIX(token, "order=")) {
                        token += strlen("order=");
                        qemuParseCommandLineBootDevs(def, token);
                    } else if (STRPREFIX(token, "menu=on")) {
                        def->os.bootmenu = 1;
                    } else if (STRPREFIX(token, "reboot-timeout=")) {
                        int num;
                        char *endptr;
                        if (virStrToLong_i(token + strlen("reboot-timeout="),
                                           &endptr, 10, &num) < 0 ||
                            (*endptr != '\0' && endptr != strchr(token, ','))) {
                            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                                           _("cannot parse reboot-timeout value"));
                            goto error;
                        }
                        if (num > 65535)
                            num = 65535;
                        else if (num < -1)
                            num = -1;
                        def->os.bios.rt_delay = num;
                        def->os.bios.rt_set = true;
                    }
                    token = strchr(token, ',');
                    /* This incrementation has to be done here in order to make it
                     * possible to pass the token pointer properly into the loop */
                    if (token)
                        token++;
                }
            }
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
            if (STREQ(def->name, ""))
                VIR_FREE(def->name);
        } else if (STREQ(arg, "-M") ||
                   STREQ(arg, "-machine")) {
            char *params;
            WANT_VALUE();
            params = strchr(val, ',');
            if (params == NULL) {
                if (!(def->os.machine = strdup(val)))
                    goto no_memory;
            } else {
                if (!(def->os.machine = strndup(val, params - val)))
                    goto no_memory;

                while (params++) {
                    /* prepared for more "-machine" parameters */
                    char *tmp = params;
                    params = strchr(params, ',');

                    if (STRPREFIX(tmp, "dump-guest-core=")) {
                        tmp += strlen("dump-guest-core=");
                        if (params) {
                            tmp = strndup(tmp, params - tmp);
                            if (tmp == NULL)
                                goto no_memory;
                        }
                        def->mem.dump_core = virDomainMemDumpTypeFromString(tmp);
                        if (def->mem.dump_core <= 0)
                            def->mem.dump_core = VIR_DOMAIN_MEM_DUMP_DEFAULT;
                        if (params)
                            VIR_FREE(tmp);
                    }
                }
            }
        } else if (STREQ(arg, "-serial")) {
            WANT_VALUE();
            if (STRNEQ(val, "none")) {
                virDomainChrDefPtr chr;

                if (!(chr = virDomainChrDefNew()))
                    goto error;

                if (qemuParseCommandLineChr(&chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
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

                if (!(chr = virDomainChrDefNew()))
                    goto error;

                if (qemuParseCommandLineChr(&chr->source, val) < 0) {
                    virDomainChrDefFree(chr);
                    goto error;
                }
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
                if (VIR_ALLOC(disk) < 0)
                    goto no_memory;
                disk->src = strdup(val + strlen("disk:"));
                if (!disk->src)
                    goto no_memory;
                if (STRPREFIX(disk->src, "/dev/"))
                    disk->type = VIR_DOMAIN_DISK_TYPE_BLOCK;
                else
                    disk->type = VIR_DOMAIN_DISK_TYPE_FILE;
                disk->device = VIR_DOMAIN_DISK_DEVICE_DISK;
                disk->bus = VIR_DOMAIN_DISK_BUS_USB;
                if (!(disk->dst = strdup("sda")) ||
                    VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                    goto no_memory;
                def->disks[def->ndisks++] = disk;
                disk = NULL;
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
            WANT_VALUE();
            if (!(disk = qemuParseCommandLineDisk(caps, val, nvirtiodisk,
                                                  ceph_args != NULL)))
                goto error;
            if (VIR_REALLOC_N(def->disks, def->ndisks+1) < 0)
                goto no_memory;
            if (disk->bus == VIR_DOMAIN_DISK_BUS_VIRTIO)
                nvirtiodisk++;

            def->disks[def->ndisks++] = disk;
            disk = NULL;
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
                } else if (STRPREFIX(start, "hda")) {
                    type = VIR_DOMAIN_SOUND_MODEL_ICH6;
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
            int model = virDomainWatchdogModelTypeFromString(val);

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
            int action = virDomainWatchdogActionTypeFromString(val);

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
                    virReportError(VIR_ERR_INTERNAL_ERROR,
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
            virDomainControllerDefPtr ctldef;
            if (VIR_ALLOC(ctldef) < 0)
                goto no_memory;
            ctldef->type = VIR_DOMAIN_CONTROLLER_TYPE_USB;
            ctldef->idx = 0;
            ctldef->model = -1;
            virDomainControllerInsert(def, ctldef);
        } else if (STREQ(arg, "-pidfile")) {
            WANT_VALUE();
            if (pidfile)
                if (!(*pidfile = strdup(val)))
                    goto no_memory;
        } else if (STREQ(arg, "-incoming")) {
            WANT_VALUE();
            /* ignore, used via restore/migrate APIs */
        } else if (STREQ(arg, "-monitor")) {
            WANT_VALUE();
            if (monConfig) {
                virDomainChrSourceDefPtr chr;

                if (VIR_ALLOC(chr) < 0)
                    goto no_memory;

                if (qemuParseCommandLineChr(chr, val) < 0) {
                    virDomainChrSourceDefFree(chr);
                    goto error;
                }

                *monConfig = chr;
            }
        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s3=")) {
            /* We want to parse only the known "-global" parameters,
             * so the ones that we don't know are still added to the
             * namespace */
            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s3=");
            if (STREQ(val, "0"))
                def->pm.s3 = VIR_DOMAIN_PM_STATE_ENABLED;
            else if (STREQ(val, "1"))
                def->pm.s3 = VIR_DOMAIN_PM_STATE_DISABLED;
            else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s3 parameter: "
                                 "'%s'"), val);
                goto error;
            }

        } else if (STREQ(arg, "-global") &&
                   STRPREFIX(progargv[i + 1], "PIIX4_PM.disable_s4=")) {

            WANT_VALUE();

            val += strlen("PIIX4_PM.disable_s4=");
            if (STREQ(val, "0"))
                def->pm.s4 = VIR_DOMAIN_PM_STATE_ENABLED;
            else if (STREQ(val, "1"))
                def->pm.s4 = VIR_DOMAIN_PM_STATE_DISABLED;
            else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("invalid value for disable_s4 parameter: "
                                 "'%s'"), val);
                goto error;
            }

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
    if (def->ndisks > 0 && ceph_args) {
        char *hosts, *port, *saveptr = NULL, *token;
        virDomainDiskDefPtr first_rbd_disk = NULL;
        for (i = 0 ; i < def->ndisks ; i++) {
            if (def->disks[i]->type == VIR_DOMAIN_DISK_TYPE_NETWORK &&
                def->disks[i]->protocol == VIR_DOMAIN_DISK_PROTOCOL_RBD) {
                first_rbd_disk = def->disks[i];
                break;
            }
        }

        if (!first_rbd_disk) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("CEPH_ARGS was set without an rbd disk"));
            goto error;
        }

        /* CEPH_ARGS should be: -m host1[:port1][,host2[:port2]]... */
        if (!STRPREFIX(ceph_args, "-m ")) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
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
            first_rbd_disk->hosts[first_rbd_disk->nhosts].transport = VIR_DOMAIN_DISK_PROTO_TRANS_TCP;
            first_rbd_disk->hosts[first_rbd_disk->nhosts].socket = NULL;

            first_rbd_disk->nhosts++;
            token = strtok_r(NULL, ",", &saveptr);
        }
        VIR_FREE(hosts);

        if (first_rbd_disk->nhosts == 0) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("found no rbd hosts in CEPH_ARGS '%s'"), ceph_args);
            goto error;
        }
    }

    if (!def->os.machine) {
        const char *defaultMachine =
                        virCapabilitiesDefaultGuestMachine(caps,
                                                           def->os.type,
                                                           def->os.arch,
                                                           virDomainVirtTypeToString(def->virtType));
        if (defaultMachine != NULL)
            if (!(def->os.machine = strdup(defaultMachine)))
                goto no_memory;
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
    virDomainDiskDefFree(disk);
    VIR_FREE(cmd);
    virDomainDefFree(def);
    VIR_FREE(nics);
    if (monConfig) {
        virDomainChrSourceDefFree(*monConfig);
        *monConfig = NULL;
    }
    if (pidfile)
        VIR_FREE(*pidfile);
    return NULL;
}


virDomainDefPtr qemuParseCommandLineString(virCapsPtr caps,
                                           const char *args,
                                           char **pidfile,
                                           virDomainChrSourceDefPtr *monConfig,
                                           bool *monJSON)
{
    const char **progenv = NULL;
    const char **progargv = NULL;
    virDomainDefPtr def = NULL;
    int i;

    if (qemuStringToArgvEnv(args, &progenv, &progargv) < 0)
        goto cleanup;

    def = qemuParseCommandLine(caps, progenv, progargv,
                               pidfile, monConfig, monJSON);

cleanup:
    for (i = 0 ; progargv && progargv[i] ; i++)
        VIR_FREE(progargv[i]);
    VIR_FREE(progargv);

    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);

    return def;
}


static int qemuParseProcFileStrings(int pid_value,
                                    const char *name,
                                    const char ***list)
{
    char *path = NULL;
    int ret = -1;
    char *data = NULL;
    ssize_t len;
    char *tmp;
    size_t nstr = 0;
    const char **str = NULL;
    int i;

    if (virAsprintf(&path, "/proc/%d/%s", pid_value, name) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if ((len = virFileReadAll(path, 1024*128, &data)) < 0)
        goto cleanup;

    tmp = data;
    while (tmp < (data + len)) {
        if (VIR_EXPAND_N(str, nstr, 1) < 0) {
            virReportOOMError();
            goto cleanup;
        }

        if (!(str[nstr-1] = strdup(tmp))) {
            virReportOOMError();
            goto cleanup;
        }
        /* Skip arg */
        tmp += strlen(tmp);
        /* Skip \0 separator */
        tmp++;
    }

    if (VIR_EXPAND_N(str, nstr, 1) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    str[nstr-1] = NULL;

    ret = nstr-1;
    *list = str;

cleanup:
    if (ret < 0) {
        for (i = 0 ; str && str[i] ; i++)
            VIR_FREE(str[i]);
        VIR_FREE(str);
    }
    VIR_FREE(data);
    VIR_FREE(path);
    return ret;
}

virDomainDefPtr qemuParseCommandLinePid(virCapsPtr caps,
                                        pid_t pid,
                                        char **pidfile,
                                        virDomainChrSourceDefPtr *monConfig,
                                        bool *monJSON)
{
    virDomainDefPtr def = NULL;
    const char **progargv = NULL;
    const char **progenv = NULL;
    char *exepath = NULL;
    char *emulator;
    int i;

    /* The parser requires /proc/pid, which only exists on platforms
     * like Linux where pid_t fits in int.  */
    if ((int) pid != pid ||
        qemuParseProcFileStrings(pid, "cmdline", &progargv) < 0 ||
        qemuParseProcFileStrings(pid, "environ", &progenv) < 0)
        goto cleanup;

    if (!(def = qemuParseCommandLine(caps, progenv, progargv,
                                     pidfile, monConfig, monJSON)))
        goto cleanup;

    if (virAsprintf(&exepath, "/proc/%d/exe", (int) pid) < 0) {
        virReportOOMError();
        goto cleanup;
    }

    if (virFileResolveLink(exepath, &emulator) < 0) {
        virReportSystemError(errno,
                             _("Unable to resolve %s for pid %u"),
                             exepath, (int) pid);
        goto cleanup;
    }
    VIR_FREE(def->emulator);
    def->emulator = emulator;

cleanup:
    VIR_FREE(exepath);
    for (i = 0 ; progargv && progargv[i] ; i++)
        VIR_FREE(progargv[i]);
    VIR_FREE(progargv);
    for (i = 0 ; progenv && progenv[i] ; i++)
        VIR_FREE(progenv[i]);
    VIR_FREE(progenv);
    return def;
}
