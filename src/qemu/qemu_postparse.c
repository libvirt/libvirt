/*
 * qemu_postparse.c: QEMU domain PostParse functions
 *
 * Copyright (C) 2006-2024 Red Hat, Inc.
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
 */

#include <config.h>

#include "qemu_postparse.h"
#include "qemu_alias.h"
#include "qemu_block.h"
#include "qemu_domain.h"
#include "qemu_firmware.h"
#include "qemu_security.h"
#include "qemu_validate.h"
#include "domain_conf.h"
#include "viralloc.h"
#include "virlog.h"

#define QEMU_QXL_VGAMEM_DEFAULT 16 * 1024

#define VIR_FROM_THIS VIR_FROM_QEMU

VIR_LOG_INIT("qemu.qemu_postparse");


/**
 * qemuDomainDefaultNetModel:
 * @def: domain definition
 * @qemuCaps: qemu capabilities
 *
 * Returns the default network model for a given domain. Note that if @qemuCaps
 * is NULL this function may return NULL if the default model depends on the
 * capabilities.
 */
static int
qemuDomainDefaultNetModel(const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    /* When there are no backwards compatibility concerns getting in
     * the way, virtio is a good default */
    if (ARCH_IS_S390(def->os.arch) ||
        qemuDomainIsLoongArchVirt(def) ||
        qemuDomainIsRISCVVirt(def)) {
        return VIR_DOMAIN_NET_MODEL_VIRTIO;
    }

    if (ARCH_IS_ARM(def->os.arch)) {
        if (STREQ(def->os.machine, "versatilepb"))
            return VIR_DOMAIN_NET_MODEL_SMC91C111;

        if (qemuDomainIsARMVirt(def))
            return VIR_DOMAIN_NET_MODEL_VIRTIO;

        /* Incomplete. vexpress (and a few others) use this, but not all
         * arm boards */
        return VIR_DOMAIN_NET_MODEL_LAN9118;
    }

    /* In all other cases the model depends on the capabilities. If they were
     * not provided don't report any default. */
    if (!qemuCaps)
        return VIR_DOMAIN_NET_MODEL_UNKNOWN;

    /* Try several network devices in turn; each of these devices is
     * less likely be supported out-of-the-box by the guest operating
     * system than the previous one */
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_RTL8139))
        return VIR_DOMAIN_NET_MODEL_RTL8139;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_E1000))
        return VIR_DOMAIN_NET_MODEL_E1000;

    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VIRTIO_NET))
        return VIR_DOMAIN_NET_MODEL_VIRTIO;

    /* We've had no luck detecting support for any network device,
     * but we have to return something: might as well be rtl8139 */
    return VIR_DOMAIN_NET_MODEL_RTL8139;
}


static int
qemuDomainDeviceNetDefPostParse(virDomainNetDef *net,
                                const virDomainDef *def,
                                virQEMUCaps *qemuCaps)
{
    if ((net->type == VIR_DOMAIN_NET_TYPE_VDPA ||
         net->type == VIR_DOMAIN_NET_TYPE_VHOSTUSER) &&
        !virDomainNetGetModelString(net)) {
        net->model = VIR_DOMAIN_NET_MODEL_VIRTIO;
    } else if (net->type != VIR_DOMAIN_NET_TYPE_HOSTDEV &&
        !virDomainNetGetModelString(net) &&
        virDomainNetResolveActualType(net) != VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        net->model = qemuDomainDefaultNetModel(def, qemuCaps);
    }

    if (net->type == VIR_DOMAIN_NET_TYPE_USER &&
        net->backend.type == VIR_DOMAIN_NET_BACKEND_DEFAULT) {
        virDomainCapsDeviceNet netCaps = { };

        virQEMUCapsFillDomainDeviceNetCaps(qemuCaps, &netCaps);

        if (!VIR_DOMAIN_CAPS_ENUM_IS_SET(netCaps.backendType, VIR_DOMAIN_NET_BACKEND_DEFAULT) &&
            VIR_DOMAIN_CAPS_ENUM_IS_SET(netCaps.backendType, VIR_DOMAIN_NET_BACKEND_PASST)) {
            net->backend.type = VIR_DOMAIN_NET_BACKEND_PASST;
        }
    }

    return 0;
}


/**
 * qemuDomainDeviceDiskDefPostParseRestoreSecAlias:
 *
 * Re-generate aliases for objects related to the storage source if they
 * were not stored in the status XML by an older libvirt.
 *
 * Note that qemuCaps should be always present for a status XML.
 */
static int
qemuDomainDeviceDiskDefPostParseRestoreSecAlias(virDomainDiskDef *disk,
                                                unsigned int parseFlags)
{
    qemuDomainStorageSourcePrivate *priv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(disk->src);
    bool restoreAuthSecret = false;
    bool restoreEncSecret = false;
    g_autofree char *authalias = NULL;
    g_autofree char *encalias = NULL;

    if (!(parseFlags & VIR_DOMAIN_DEF_PARSE_STATUS) ||
        virStorageSourceIsEmpty(disk->src))
        return 0;

    /* network storage authentication secret */
    if (disk->src->auth &&
        (!priv || !priv->secinfo)) {

        /* only RBD and iSCSI (with capability) were supporting authentication
         * using secret object at the time we did not format the alias into the
         * status XML */
        if (virStorageSourceGetActualType(disk->src) == VIR_STORAGE_TYPE_NETWORK &&
            (disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD ||
             disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI))
            restoreAuthSecret = true;
    }

    /* disk encryption secret */
    if (disk->src->encryption &&
        disk->src->encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
        (!priv || !priv->encinfo))
        restoreEncSecret = true;

    if (!restoreAuthSecret && !restoreEncSecret)
        return 0;

    if (!priv) {
        if (!(disk->src->privateData = qemuDomainStorageSourcePrivateNew()))
            return -1;

        priv = QEMU_DOMAIN_STORAGE_SOURCE_PRIVATE(disk->src);
    }

    if (restoreAuthSecret) {
        authalias = g_strdup_printf("%s-secret0", disk->info.alias);

        if (qemuStorageSourcePrivateDataAssignSecinfo(&priv->secinfo, &authalias) < 0)
            return -1;
    }

    if (restoreEncSecret) {
        if (!priv->encinfo) {
            priv->enccount = 1;
            priv->encinfo = g_new0(qemuDomainSecretInfo *, 1);
        }

        encalias = g_strdup_printf("%s-luks-secret0", disk->info.alias);

        if (qemuStorageSourcePrivateDataAssignSecinfo(&priv->encinfo[0], &encalias) < 0)
            return -1;
    }

    return 0;
}


int
qemuDomainDeviceDiskDefPostParse(virDomainDiskDef *disk,
                                 unsigned int parseFlags,
                                 virQEMUCaps *qemuCaps)
{
    virStorageSource *n;

    /* set default disk types and drivers */
    if (!virDomainDiskGetDriver(disk))
        virDomainDiskSetDriver(disk, "qemu");

    /* default disk format for drives */
    if (virDomainDiskGetFormat(disk) == VIR_STORAGE_FILE_NONE &&
        virDomainDiskGetType(disk) != VIR_STORAGE_TYPE_VOLUME)
        virDomainDiskSetFormat(disk, VIR_STORAGE_FILE_RAW);

    /* default disk format for mirrored drive */
    if (disk->mirror &&
        disk->mirror->format == VIR_STORAGE_FILE_NONE)
        disk->mirror->format = VIR_STORAGE_FILE_RAW;

    /* default USB disk model:
     *
     * Historically we didn't use model for USB disks. It became necessary once
     * it turned out that 'usb-storage' doesn't properly expose CDROM devices
     * with -blockdev. Additionally 'usb-bot' which does properly handle them,
     * while having identical implementation in qemu and driver in guest, are
     * not in fact ABI compatible. Thus the logic is as follows:
     *
     * If ABI update is not allowed:
     *  - use 'usb-storage' for either (unless only 'usb-bot' is supported)
     *
     * If ABI update is possible
     * - for VIR_DOMAIN_DISK_DEVICE_DISK use 'usb-storage' as it doesn't matter
     *    (it is identical with 'usb-bot' ABI wise)
     * - for VIR_DOMAIN_DISK_DEVICE_CDROM use 'usb-bot' if available
     *    (as it properly exposes cdrom)
     *
     * When formatting migratable XML the code strips 'usb-storage' to preserve
     * migration to older daemons. If a new definition with 'usb-bot' cdrom is
     * created via new start or hotplug it will fail migrating. Users must
     * explicitly set the broken config in XML or unplug the device.
     */
    if (qemuCaps &&
        disk->bus == VIR_DOMAIN_DISK_BUS_USB &&
        disk->model == VIR_DOMAIN_DISK_MODEL_DEFAULT) {

        if (disk->device == VIR_DOMAIN_DISK_DEVICE_CDROM &&
            parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE) {

            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_BOT)) {
                disk->model = VIR_DOMAIN_DISK_MODEL_USB_BOT;
            } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE)) {
                disk->model = VIR_DOMAIN_DISK_MODEL_USB_STORAGE;
            }

        } else {
            if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_STORAGE)) {
                disk->model = VIR_DOMAIN_DISK_MODEL_USB_STORAGE;
            } else if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_USB_BOT)) {
                disk->model = VIR_DOMAIN_DISK_MODEL_USB_BOT;
            }
        }
    }

    /* default disk encryption engine */
    for (n = disk->src; virStorageSourceIsBacking(n); n = n->backingStore) {
        if (n->encryption && n->encryption->engine == VIR_STORAGE_ENCRYPTION_ENGINE_DEFAULT)
            n->encryption->engine = VIR_STORAGE_ENCRYPTION_ENGINE_QEMU;
    }

    if (qemuDomainDeviceDiskDefPostParseRestoreSecAlias(disk, parseFlags) < 0)
        return -1;

    /* regenerate TLS alias for old status XMLs */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_STATUS &&
        disk->src->haveTLS == VIR_TRISTATE_BOOL_YES &&
        !disk->src->tlsAlias &&
        !(disk->src->tlsAlias = qemuAliasTLSObjFromSrcAlias(disk->info.alias)))
        return -1;

    return 0;
}


static int
qemuDomainDefaultVideoDevice(const virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    if (ARCH_IS_PPC64(def->os.arch))
        return VIR_DOMAIN_VIDEO_TYPE_VGA;
    if (qemuDomainIsARMVirt(def) ||
        qemuDomainIsLoongArchVirt(def) ||
        qemuDomainIsRISCVVirt(def) ||
        ARCH_IS_S390(def->os.arch)) {
        return VIR_DOMAIN_VIDEO_TYPE_VIRTIO;
    }
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_CIRRUS_VGA))
        return VIR_DOMAIN_VIDEO_TYPE_CIRRUS;
    if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_VGA))
        return VIR_DOMAIN_VIDEO_TYPE_VGA;
    return VIR_DOMAIN_VIDEO_TYPE_DEFAULT;
}


static int
qemuDomainDeviceVideoDefPostParse(virDomainVideoDef *video,
                                  const virDomainDef *def,
                                  virQEMUCaps *qemuCaps)
{
    if (video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT)
        video->type = qemuDomainDefaultVideoDevice(def, qemuCaps);

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_QXL &&
        !video->vgamem) {
        video->vgamem = QEMU_QXL_VGAMEM_DEFAULT;
    }

    return 0;
}


static int
qemuDomainDevicePanicDefPostParse(virDomainPanicDef *panic,
                                  const virDomainDef *def)
{
    if (panic->model == VIR_DOMAIN_PANIC_MODEL_DEFAULT)
        panic->model = qemuDomainDefaultPanicModel(def);

    return 0;
}


#define QEMU_USB_XHCI_MAXPORTS 15

static int
qemuDomainControllerDefPostParse(virDomainControllerDef *cont,
                                 const virDomainDef *def,
                                 virQEMUCaps *qemuCaps,
                                 unsigned int parseFlags)
{
    switch (cont->type) {
    case VIR_DOMAIN_CONTROLLER_TYPE_SCSI:
        /* If no model is set, try to come up with a reasonable
         * default. If one cannot be determined, error out */
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT ||
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_AUTO) {
            cont->model = qemuDomainDefaultSCSIControllerModel(def, qemuCaps);
        }
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_SCSI_DEFAULT) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           _("Unable to determine model for SCSI controller idx=%1$d"),
                           cont->idx);
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_USB:
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT && qemuCaps) {
            cont->model = qemuDomainDefaultUSBControllerModel(def, qemuCaps, parseFlags);
        }

        /* Make sure the 'none' USB controller doesn't have an address
         * associated with it, as that would trip up later checks and
         * it doesn't make sense anyway */
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            cont->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE;

        /* forbid usb model 'qusb1' and 'qusb2' in this kind of hyperviosr */
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB1 ||
            cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_QUSB2) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("USB controller model type 'qusb1' or 'qusb2' is not supported in %1$s"),
                           virDomainVirtTypeToString(def->virtType));
            return -1;
        }
        if ((cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_NEC_XHCI ||
             cont->model == VIR_DOMAIN_CONTROLLER_MODEL_USB_QEMU_XHCI) &&
            cont->opts.usbopts.ports > QEMU_USB_XHCI_MAXPORTS) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("'%1$s' controller only supports up to '%2$u' ports"),
                           virDomainControllerModelUSBTypeToString(cont->model),
                           QEMU_USB_XHCI_MAXPORTS);
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_PCI:

        /* pSeries guests can have multiple pci-root controllers,
         * but other machine types only support a single one */
        if (!qemuDomainIsPSeries(def) &&
            (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
             cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) &&
            cont->idx != 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("pci-root and pcie-root controllers should have index 0"));
            return -1;
        }

        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_EXPANDER_BUS &&
            !qemuDomainIsI440FX(def)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("pci-expander-bus controllers are only supported on 440fx-based machinetypes"));
            return -1;
        }
        if (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_EXPANDER_BUS &&
            !(qemuDomainIsQ35(def) || qemuDomainIsARMVirt(def))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("pcie-expander-bus controllers are not supported with this machine type"));
            return -1;
        }

        /* if a PCI expander bus or pci-root on Pseries has a NUMA node
         * set, make sure that NUMA node is configured in the guest
         * <cpu><numa> array. NUMA cell id's in this array are numbered
         * from 0 .. size-1.
         */
        if (cont->opts.pciopts.numaNode >= 0 &&
            cont->opts.pciopts.numaNode >=
            (int)virDomainNumaGetNodeCount(def->numa)) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("%1$s with index %2$d is configured for a NUMA node (%3$d) not present in the domain's <cpu><numa> array (%4$zu)"),
                           virDomainControllerModelPCITypeToString(cont->model),
                           cont->idx, cont->opts.pciopts.numaNode,
                           virDomainNumaGetNodeCount(def->numa));
            return -1;
        }
        break;

    case VIR_DOMAIN_CONTROLLER_TYPE_SATA:
    case VIR_DOMAIN_CONTROLLER_TYPE_VIRTIO_SERIAL:
    case VIR_DOMAIN_CONTROLLER_TYPE_CCID:
    case VIR_DOMAIN_CONTROLLER_TYPE_IDE:
    case VIR_DOMAIN_CONTROLLER_TYPE_FDC:
    case VIR_DOMAIN_CONTROLLER_TYPE_XENBUS:
    case VIR_DOMAIN_CONTROLLER_TYPE_ISA:
    case VIR_DOMAIN_CONTROLLER_TYPE_NVME:
    case VIR_DOMAIN_CONTROLLER_TYPE_LAST:
        break;
    }

    return 0;
}


static int
qemuDomainShmemDefPostParse(virDomainShmemDef *shm)
{
    /* This was the default since the introduction of this device. */
    if (shm->model != VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL && !shm->size)
        shm->size = 4 << 20;

    /* Nothing more to check/change for IVSHMEM */
    if (shm->model == VIR_DOMAIN_SHMEM_MODEL_IVSHMEM)
        return 0;

    if (!shm->server.enabled) {
        if (shm->model == VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_DOORBELL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' is supported only with server option enabled"),
                           virDomainShmemModelTypeToString(shm->model));
            return -1;
        }

        if (shm->msi.enabled) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' doesn't support msi"),
                           virDomainShmemModelTypeToString(shm->model));
        }
    } else {
        if (shm->model == VIR_DOMAIN_SHMEM_MODEL_IVSHMEM_PLAIN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' is supported only with server option disabled"),
                           virDomainShmemModelTypeToString(shm->model));
            return -1;
        }

        if (shm->size) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("shmem model '%1$s' does not support size setting"),
                           virDomainShmemModelTypeToString(shm->model));
            return -1;
        }
        shm->msi.enabled = true;
        if (!shm->msi.ioeventfd)
            shm->msi.ioeventfd = VIR_TRISTATE_SWITCH_ON;
    }

    return 0;
}


static int
qemuDomainChrDefPostParse(virDomainChrDef *chr,
                          const virDomainDef *def,
                          virQEMUDriver *driver,
                          unsigned int parseFlags)
{
    /* Historically, isa-serial and the default matched, so in order to
     * maintain backwards compatibility we map them here. The actual default
     * will be picked below based on the architecture and machine type. */
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA) {
        chr->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE;
    }

    /* Set the default serial type */
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        chr->targetType == VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE) {
        if (ARCH_IS_X86(def->os.arch)) {
            chr->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA;
        } else if (qemuDomainIsPSeries(def)) {
            chr->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO;
        } else if (qemuDomainIsARMVirt(def) ||
                   qemuDomainIsLoongArchVirt(def) ||
                   qemuDomainIsRISCVVirt(def)) {
            chr->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM;
        } else if (ARCH_IS_S390(def->os.arch)) {
            chr->targetType = VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP;
        }
    }

    /* Set the default target model */
    if (chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL &&
        chr->targetModel == VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_NONE) {
        switch ((virDomainChrSerialTargetType)chr->targetType) {
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_SERIAL;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_USB:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_USB_SERIAL;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_PCI:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PCI_SERIAL;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SPAPR_VIO:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SPAPR_VTY;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SYSTEM:
            if (qemuDomainIsARMVirt(def)) {
                chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_PL011;
            } else if (qemuDomainIsLoongArchVirt(def) ||
                       qemuDomainIsRISCVVirt(def)) {
                chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_16550A;
            }
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_SCLP:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_SCLPCONSOLE;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_ISA_DEBUG:
            chr->targetModel = VIR_DOMAIN_CHR_SERIAL_TARGET_MODEL_ISA_DEBUGCON;
            break;
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_NONE:
        case VIR_DOMAIN_CHR_SERIAL_TARGET_TYPE_LAST:
            /* Nothing to do */
            break;
        }
    }

    /* clear auto generated unix socket path for inactive definitions */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_INACTIVE) {
        qemuDomainChrDefDropDefaultPath(chr, driver);

        /* For UNIX chardev if no path is provided we generate one.
         * This also implies that the mode is 'bind'. */
        if (chr->source &&
            chr->source->type == VIR_DOMAIN_CHR_TYPE_UNIX &&
            !chr->source->data.nix.path) {
            chr->source->data.nix.listen = true;
        }
    }

    return 0;
}


static int
qemuDomainVsockDefPostParse(virDomainVsockDef *vsock)
{
    if (vsock->model == VIR_DOMAIN_VSOCK_MODEL_DEFAULT)
        vsock->model = VIR_DOMAIN_VSOCK_MODEL_VIRTIO;

    return 0;
}


/**
 * qemuDomainDeviceHostdevDefPostParseRestoreSecAlias:
 *
 * Re-generate aliases for objects related to the storage source if they
 * were not stored in the status XML by an older libvirt.
 *
 * Note that qemuCaps should be always present for a status XML.
 */
static int
qemuDomainDeviceHostdevDefPostParseRestoreSecAlias(virDomainHostdevDef *hostdev,
                                                   unsigned int parseFlags)
{
    qemuDomainStorageSourcePrivate *priv;
    virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;
    virDomainHostdevSubsysSCSIiSCSI *iscsisrc = &scsisrc->u.iscsi;
    g_autofree char *authalias = NULL;

    if (!(parseFlags & VIR_DOMAIN_DEF_PARSE_STATUS))
        return 0;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
        hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI ||
        scsisrc->protocol != VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI ||
        !iscsisrc->src->auth)
        return 0;

    if (!(priv = qemuDomainStorageSourcePrivateFetch(iscsisrc->src)))
        return -1;

    if (priv->secinfo)
        return 0;

    authalias = g_strdup_printf("%s-secret0", hostdev->info->alias);

    if (qemuStorageSourcePrivateDataAssignSecinfo(&priv->secinfo, &authalias) < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainDeviceHostdevDefPostParseRestoreBackendAlias:
 *
 * Re-generate backend alias if it wasn't stored in the status XML by an older
 * libvirtd.
 *
 * Note that qemuCaps should be always present for a status XML.
 */
static int
qemuDomainDeviceHostdevDefPostParseRestoreBackendAlias(virDomainHostdevDef *hostdev,
                                                       unsigned int parseFlags)
{
    virDomainHostdevSubsysSCSI *scsisrc = &hostdev->source.subsys.u.scsi;
    virStorageSource *src;

    if (!(parseFlags & VIR_DOMAIN_DEF_PARSE_STATUS))
        return 0;

    if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
        hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI)
        return 0;

    switch (scsisrc->protocol) {
    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_NONE:
        if (!scsisrc->u.host.src)
            scsisrc->u.host.src = virStorageSourceNew();

        src = scsisrc->u.host.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_ISCSI:
        src = scsisrc->u.iscsi.src;
        break;

    case VIR_DOMAIN_HOSTDEV_SCSI_PROTOCOL_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainHostdevSCSIProtocolType, scsisrc->protocol);
        return -1;
    }

    if (!qemuBlockStorageSourceGetStorageNodename(src))
        qemuBlockStorageSourceSetStorageNodename(src, g_strdup_printf("libvirt-%s-backend", hostdev->info->alias));

    return 0;
}


static int
qemuDomainHostdevDefMdevPostParse(virDomainHostdevSubsysMediatedDev *mdevsrc)
{
    /* QEMU 2.12 added support for vfio-pci display type, we default to
     * 'display=off' to stay safe from future changes */
    if (mdevsrc->model == VIR_MDEV_MODEL_TYPE_VFIO_PCI &&
        mdevsrc->display == VIR_TRISTATE_SWITCH_ABSENT)
        mdevsrc->display = VIR_TRISTATE_SWITCH_OFF;

    return 0;
}


static int
qemuDomainHostdevDefPostParse(virDomainHostdevDef *hostdev,
                              unsigned int parseFlags)
{
    virDomainHostdevSubsys *subsys = &hostdev->source.subsys;

    if (qemuDomainDeviceHostdevDefPostParseRestoreSecAlias(hostdev, parseFlags) < 0)
        return -1;

    if (qemuDomainDeviceHostdevDefPostParseRestoreBackendAlias(hostdev, parseFlags) < 0)
        return -1;

    if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS &&
        hostdev->source.subsys.type == VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV &&
        qemuDomainHostdevDefMdevPostParse(&subsys->u.mdev) < 0)
        return -1;

    return 0;
}


static int
qemuDomainTPMDefPostParse(virDomainTPMDef *tpm,
                          const virDomainDef *def)
{
    if (tpm->model == VIR_DOMAIN_TPM_MODEL_DEFAULT) {
        if (ARCH_IS_PPC64(def->os.arch))
            tpm->model = VIR_DOMAIN_TPM_MODEL_SPAPR;
        else
            tpm->model = VIR_DOMAIN_TPM_MODEL_TIS;
    }

    /* TPM 1.2 and 2 are not compatible, so we choose a specific version here */
    if (tpm->type == VIR_DOMAIN_TPM_TYPE_EMULATOR &&
        tpm->data.emulator.version == VIR_DOMAIN_TPM_VERSION_DEFAULT) {
        /* tpm-tis on x86 defaults to TPM 1.2 to preserve the
         * historical behavior, but in all other scenarios we want
         * TPM 2.0 instead */
        if (tpm->model == VIR_DOMAIN_TPM_MODEL_TIS &&
            ARCH_IS_X86(def->os.arch)) {
            tpm->data.emulator.version = VIR_DOMAIN_TPM_VERSION_1_2;
        } else {
            tpm->data.emulator.version = VIR_DOMAIN_TPM_VERSION_2_0;
        }
    }

    return 0;
}


static int
qemuDomainMemoryDefPostParse(virDomainMemoryDef *mem, virArch arch,
                             unsigned int parseFlags)
{
    /* Memory alignment can't be done for migration or snapshot
     * scenarios. This logic was defined by commit c7d7ba85a624.
     *
     * There is no easy way to replicate at this point the same conditions
     * used to call qemuDomainAlignMemorySizes(), which means checking if
     * we're not migrating and not in a snapshot.
     *
     * We can use the PARSE_ABI_UPDATE flag, which is more strict -
     * existing guests will not activate the flag to avoid breaking
     * boot ABI. This means that any alignment done here will be replicated
     * later on by qemuDomainAlignMemorySizes() to contemplate existing
     * guests as well. */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE) {
        if (ARCH_IS_PPC64(arch)) {
            unsigned long long ppc64MemModuleAlign = 256 * 1024;

            if (mem->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM) {
                if (qemuDomainNVDimmAlignSizePseries(mem) < 0)
                    return -1;
            } else {
                mem->size = VIR_ROUND_UP(mem->size, ppc64MemModuleAlign);
            }
        }
    }

    return 0;
}


static int
qemuDomainPstoreDefPostParse(virDomainPstoreDef *pstore,
                             const virDomainDef *def,
                             virQEMUDriver *driver)
{
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);

    switch (pstore->backend) {
    case VIR_DOMAIN_PSTORE_BACKEND_ACPI_ERST:
        if (!pstore->path)
            pstore->path = g_strdup_printf("%s/%s_PSTORE.raw",
                                           cfg->nvramDir, def->name);
        break;

    case VIR_DOMAIN_PSTORE_BACKEND_LAST:
        break;
    }

    return 0;
}


static bool
qemuDomainNeedsIOMMUWithEIM(const virDomainDef *def)
{
    return ARCH_IS_X86(def->os.arch) &&
           virDomainDefGetVcpusMax(def) > QEMU_MAX_VCPUS_WITHOUT_EIM &&
           qemuDomainIsQ35(def);
}


static int
qemuDomainIOMMUDefPostParse(virDomainIOMMUDef *iommu,
                            const virDomainDef *def,
                            virQEMUCaps *qemuCaps,
                            unsigned int parseFlags)
{
    /* In case domain has huge number of vCPUS and Extended Interrupt Mode
     * (EIM) is not explicitly turned off, let's enable it. If we didn't then
     * guest will have troubles with interrupts. */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE &&
        qemuDomainNeedsIOMMUWithEIM(def) &&
        iommu && iommu->model == VIR_DOMAIN_IOMMU_MODEL_INTEL) {

        /* eim requires intremap. */
        if (iommu->intremap == VIR_TRISTATE_SWITCH_ABSENT &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_INTREMAP)) {
            iommu->intremap = VIR_TRISTATE_SWITCH_ON;
        }

        if (iommu->eim == VIR_TRISTATE_SWITCH_ABSENT &&
            virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_EIM)) {
            iommu->eim = VIR_TRISTATE_SWITCH_ON;
        }
    }

    return 0;
}


int
qemuDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                             const virDomainDef *def,
                             unsigned int parseFlags,
                             void *opaque,
                             void *parseOpaque)
{
    virQEMUDriver *driver = opaque;
    /* Note that qemuCaps may be NULL when this function is called. This
     * function shall not fail in that case. It will be re-run on VM startup
     * with the capabilities populated. */
    virQEMUCaps *qemuCaps = parseOpaque;
    int ret = -1;

    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_NET:
        ret = qemuDomainDeviceNetDefPostParse(dev->data.net, def, qemuCaps);
        break;

    case VIR_DOMAIN_DEVICE_DISK:
        ret = qemuDomainDeviceDiskDefPostParse(dev->data.disk, parseFlags, qemuCaps);
        break;

    case VIR_DOMAIN_DEVICE_VIDEO:
        ret = qemuDomainDeviceVideoDefPostParse(dev->data.video, def, qemuCaps);
        break;

    case VIR_DOMAIN_DEVICE_PANIC:
        ret = qemuDomainDevicePanicDefPostParse(dev->data.panic, def);
        break;

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        ret = qemuDomainControllerDefPostParse(dev->data.controller, def,
                                               qemuCaps, parseFlags);
        break;

    case VIR_DOMAIN_DEVICE_SHMEM:
        ret = qemuDomainShmemDefPostParse(dev->data.shmem);
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        ret = qemuDomainChrDefPostParse(dev->data.chr, def, driver, parseFlags);
        break;

    case VIR_DOMAIN_DEVICE_VSOCK:
        ret = qemuDomainVsockDefPostParse(dev->data.vsock);
        break;

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        ret = qemuDomainHostdevDefPostParse(dev->data.hostdev, parseFlags);
        break;

    case VIR_DOMAIN_DEVICE_TPM:
        ret = qemuDomainTPMDefPostParse(dev->data.tpm, def);
        break;

    case VIR_DOMAIN_DEVICE_MEMORY:
        ret = qemuDomainMemoryDefPostParse(dev->data.memory, def->os.arch,
                                           parseFlags);
        break;

    case VIR_DOMAIN_DEVICE_PSTORE:
        ret = qemuDomainPstoreDefPostParse(dev->data.pstore, def, driver);
        break;

    case VIR_DOMAIN_DEVICE_IOMMU:
        ret = qemuDomainIOMMUDefPostParse(dev->data.iommu, def,
                                          qemuCaps, parseFlags);
        break;

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_RNG:
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
        ret = 0;
        break;

    case VIR_DOMAIN_DEVICE_NONE:
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("unexpected VIR_DOMAIN_DEVICE_NONE"));
        break;

    case VIR_DOMAIN_DEVICE_LAST:
    default:
        virReportEnumRangeError(virDomainDeviceType, dev->type);
        break;
    }

    return ret;
}


int
qemuDomainDefPostParseBasic(virDomainDef *def,
                            void *opaque G_GNUC_UNUSED)
{
    virQEMUDriver *driver = opaque;

    /* check for emulator and create a default one if needed */
    if (!def->emulator) {
        if (!(def->emulator = virQEMUCapsGetDefaultEmulator(
                  driver->hostarch, def->os.arch))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("No emulator found for arch '%1$s'"),
                           virArchToString(def->os.arch));
            return 1;
        }
    }

    return 0;
}


static int
qemuCanonicalizeMachine(virDomainDef *def, virQEMUCaps *qemuCaps)
{
    const char *canon;

    if (!(canon = virQEMUCapsGetCanonicalMachine(qemuCaps, def->virtType,
                                                 def->os.machine)))
        return 0;

    if (STRNEQ(canon, def->os.machine)) {
        VIR_FREE(def->os.machine);
        def->os.machine = g_strdup(canon);
    }

    return 0;
}


static int
qemuDomainDefMachinePostParse(virDomainDef *def,
                              virQEMUCaps *qemuCaps)
{
    if (!def->os.machine) {
        const char *machine = virQEMUCapsGetPreferredMachine(qemuCaps,
                                                             def->virtType);
        if (!machine) {
            virReportError(VIR_ERR_INVALID_ARG,
                           _("could not get preferred machine for %1$s type=%2$s"),
                           def->emulator,
                           virDomainVirtTypeToString(def->virtType));
            return -1;
        }

        def->os.machine = g_strdup(machine);
    }

    if (qemuCanonicalizeMachine(def, qemuCaps) < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainDefACPIPostParse:
 * @def: domain definition
 * @qemuCaps: qemu capabilities object
 *
 * Fixup the use of ACPI flag on certain architectures that never supported it
 * and users for some reason used it, which would break migration to newer
 * libvirt versions which check whether given machine type supports ACPI.
 *
 * The fixup is done in post-parse as it's hard to update the ABI stability
 * check on source of the migration.
 */
static void
qemuDomainDefACPIPostParse(virDomainDef *def,
                           virQEMUCaps *qemuCaps,
                           unsigned int parseFlags)
{
    /* Only cases when ACPI is enabled need to be fixed up */
    if (def->features[VIR_DOMAIN_FEATURE_ACPI] != VIR_TRISTATE_SWITCH_ON)
        return;

    /* Strip the <acpi/> feature only for non-fresh configs, in order to still
     * produce an error if the feature is present in a newly defined one.
     *
     * The use of the VIR_DOMAIN_DEF_PARSE_ABI_UPDATE looks counter-intuitive,
     * but it's used only in qemuDomainCreateXML/qemuDomainDefineXMLFlags APIs
     * */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE)
        return;

    /* This fixup is applicable _only_ on architectures which were present as of
     * libvirt-9.2 and *never* supported ACPI. The fixup is currently done only
     * for existing users of s390(x) to fix migration for configs which had
     * <acpi/> despite being ignored.
     */
    if (def->os.arch != VIR_ARCH_S390 &&
        def->os.arch != VIR_ARCH_S390X)
        return;

    /* To be sure, we only strip ACPI if given machine type doesn't support it */
    if (virQEMUCapsMachineSupportsACPI(qemuCaps, def->virtType, def->os.machine) != VIR_TRISTATE_BOOL_NO)
        return;

    def->features[VIR_DOMAIN_FEATURE_ACPI] = VIR_TRISTATE_SWITCH_ABSENT;
}


static int
qemuDomainDefBootPostParse(virDomainDef *def,
                           virQEMUDriver *driver,
                           unsigned int parseFlags)
{
    bool abiUpdate = !!(parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE);

    /* If we're loading an existing configuration from disk, we
     * should try as hard as possible to preserve historical
     * behavior. In particular, firmware autoselection being enabled
     * could never have resulted, before libvirt 9.2.0, in anything
     * but a raw firmware image being selected.
     *
     * In order to ensure that existing domains keep working even if
     * a firmware descriptor for a build with a different format is
     * given higher priority, explicitly add this requirement to the
     * definition before performing firmware selection */
    if (!abiUpdate && def->os.firmware) {
        if (!def->os.loader)
            def->os.loader = virDomainLoaderDefNew();
        if (!def->os.loader->format)
            def->os.loader->format = VIR_STORAGE_FILE_RAW;
    }

    /* Firmware selection can fail for a number of reasons, but the
     * most likely one is that the requested configuration contains
     * mistakes or includes constraints that are impossible to
     * satisfy on the current system.
     *
     * If that happens, we have to react differently based on the
     * situation: if we're defining a new domain or updating its ABI,
     * we should let the user know immediately so that they can
     * change the requested configuration, hopefully into one that we
     * can work with; if we're loading the configuration of an
     * existing domain from disk, however, we absolutely cannot error
     * out here, or the domain will disappear.
     *
     * To handle the second case gracefully, we clear any reported
     * errors and continue as if nothing had happened. When it's time
     * to start the domain, qemuFirmwareFillDomain() will be run
     * again, fail in the same way, and at that point we'll have a
     * chance to inform the user of any issues */
    if (qemuFirmwareFillDomain(driver, def, abiUpdate) < 0) {
        if (abiUpdate) {
            return -1;
        } else {
            virResetLastError();
            return 0;
        }
    }

    return 0;
}


static void
qemuDomainDefAddImplicitInputDevice(virDomainDef *def,
                                    virQEMUCaps *qemuCaps)
{
    if (virQEMUCapsSupportsI8042(qemuCaps, def) &&
        def->features[VIR_DOMAIN_FEATURE_PS2] != VIR_TRISTATE_SWITCH_OFF) {
        virDomainDefMaybeAddInput(def, VIR_DOMAIN_INPUT_TYPE_MOUSE, VIR_DOMAIN_INPUT_BUS_PS2);
        virDomainDefMaybeAddInput(def, VIR_DOMAIN_INPUT_TYPE_KBD, VIR_DOMAIN_INPUT_BUS_PS2);
    }
}


static int
qemuDomainDefSetDefaultCPU(virDomainDef *def,
                           virArch hostarch,
                           virQEMUCaps *qemuCaps)
{
    const char *model;

    if (def->cpu &&
        (def->cpu->mode != VIR_CPU_MODE_CUSTOM ||
         def->cpu->model))
        return 0;

    if (!virCPUArchIsSupported(def->os.arch))
        return 0;

    /* Default CPU model info from QEMU is usable for TCG only except for
     * x86, s390, and ppc64. */
    if (!ARCH_IS_X86(def->os.arch) &&
        !ARCH_IS_S390(def->os.arch) &&
        !ARCH_IS_PPC64(def->os.arch) &&
        def->virtType != VIR_DOMAIN_VIRT_QEMU)
        return 0;

    model = virQEMUCapsGetMachineDefaultCPU(qemuCaps, def->os.machine, def->virtType);
    if (!model) {
        VIR_DEBUG("Unknown default CPU model for domain '%s'", def->name);
        return 0;
    }

    if (STREQ(model, "host") && def->virtType != VIR_DOMAIN_VIRT_KVM) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("QEMU reports invalid default CPU model \"host\" for non-kvm domain virt type"));
        return -1;
    }

    if (!def->cpu)
        def->cpu = virCPUDefNew();

    def->cpu->type = VIR_CPU_TYPE_GUEST;

    if (STREQ(model, "host")) {
        if (ARCH_IS_S390(def->os.arch) &&
            virQEMUCapsIsCPUModeSupported(qemuCaps, hostarch, def->virtType,
                                          VIR_CPU_MODE_HOST_MODEL,
                                          def->os.machine)) {
            def->cpu->mode = VIR_CPU_MODE_HOST_MODEL;
        } else {
            def->cpu->mode = VIR_CPU_MODE_HOST_PASSTHROUGH;
        }

        VIR_DEBUG("Setting default CPU mode for domain '%s' to %s",
                  def->name, virCPUModeTypeToString(def->cpu->mode));
    } else {
        /* We need to turn off all CPU checks when the domain is started
         * because the default CPU (e.g., qemu64) may not be runnable on any
         * host. QEMU will just disable the unavailable features and we will
         * update the CPU definition accordingly and set check to FULL when
         * starting the domain. */
        def->cpu->check = VIR_CPU_CHECK_NONE;
        def->cpu->mode = VIR_CPU_MODE_CUSTOM;
        def->cpu->match = VIR_CPU_MATCH_EXACT;
        def->cpu->fallback = VIR_CPU_FALLBACK_FORBID;
        def->cpu->model = g_strdup(model);

        VIR_DEBUG("Setting default CPU model for domain '%s' to %s",
                  def->name, model);
    }

    return 0;
}


static int
qemuDomainDefAddDefaultDevices(virQEMUDriver *driver,
                               virDomainDef *def,
                               virQEMUCaps *qemuCaps)
{
    bool addDefaultUSB = false;
    virDomainControllerModelUSB usbModel = VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT;
    int pciRoot;       /* index within def->controllers */
    bool addImplicitSATA = false;
    bool addPCIRoot = false;
    bool addPCIeRoot = false;
    bool addDefaultMemballoon = false;
    bool addDefaultUSBKBD = false;
    bool addDefaultUSBMouse = false;
    bool addPanicDevice = false;
    bool addITCOWatchdog = false;
    bool addIOMMU = false;

    /* add implicit input devices */
    qemuDomainDefAddImplicitInputDevice(def, qemuCaps);

    /* Add implicit PCI root controller if the machine has one */
    switch (def->os.arch) {
    case VIR_ARCH_I686:
    case VIR_ARCH_X86_64:
        if (STREQ(def->os.machine, "isapc") ||
            STREQ(def->os.machine, "microvm")) {
            break;
        }

        addDefaultMemballoon = true;
        addDefaultUSB = true;

        if (qemuDomainIsQ35(def)) {
            addPCIeRoot = true;
            addImplicitSATA = true;
            addITCOWatchdog = true;

            if (virDomainDefGetVcpusMax(def) > QEMU_MAX_VCPUS_WITHOUT_EIM) {
                addIOMMU = true;
            }
        }
        if (qemuDomainIsI440FX(def))
            addPCIRoot = true;
        break;

    case VIR_ARCH_ARMV6L:
    case VIR_ARCH_ARMV7L:
    case VIR_ARCH_ARMV7B:
    case VIR_ARCH_AARCH64:
        /* Add default PCI and USB for the two machine types which
         * historically supported -usb */
        if (STREQ(def->os.machine, "versatilepb") ||
            STRPREFIX(def->os.machine, "realview-eb")) {
            addPCIRoot = true;
            addDefaultUSB = true;
        }

        if (qemuDomainIsARMVirt(def))
            addPCIeRoot = true;

        break;

    case VIR_ARCH_PPC64:
    case VIR_ARCH_PPC64LE:
        addPCIRoot = true;
        addDefaultUSB = true;
        addDefaultUSBKBD = true;
        addDefaultUSBMouse = true;
        addDefaultMemballoon = true;
        /* For pSeries guests, the firmware provides the same
         * functionality as the pvpanic device, so automatically
         * add the definition if not already present */
        if (qemuDomainIsPSeries(def))
            addPanicDevice = true;
        break;

    case VIR_ARCH_ALPHA:
    case VIR_ARCH_PPC:
    case VIR_ARCH_PPCEMB:
    case VIR_ARCH_SH4:
    case VIR_ARCH_SH4EB:
        addDefaultUSB = true;
        addDefaultMemballoon = true;
        addPCIRoot = true;
        break;

    case VIR_ARCH_RISCV32:
    case VIR_ARCH_RISCV64:
        if (qemuDomainIsRISCVVirt(def))
            addPCIeRoot = true;
        break;

    case VIR_ARCH_S390:
    case VIR_ARCH_S390X:
        addDefaultMemballoon = true;
        addPanicDevice = true;
        addPCIRoot = virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_ZPCI);
        break;

    case VIR_ARCH_SPARC64:
        addDefaultUSB = true;
        addDefaultMemballoon = true;
        addPCIRoot = true;
        break;

    case VIR_ARCH_MIPS:
    case VIR_ARCH_MIPSEL:
    case VIR_ARCH_MIPS64:
    case VIR_ARCH_MIPS64EL:
        addDefaultUSB = true;
        addDefaultMemballoon = true;
        if (qemuDomainIsMipsMalta(def))
            addPCIRoot = true;
        break;

    case VIR_ARCH_LOONGARCH64:
        addPCIeRoot = true;
        break;

    case VIR_ARCH_CRIS:
    case VIR_ARCH_ITANIUM:
    case VIR_ARCH_LM32:
    case VIR_ARCH_M68K:
    case VIR_ARCH_MICROBLAZE:
    case VIR_ARCH_MICROBLAZEEL:
    case VIR_ARCH_OR32:
    case VIR_ARCH_PARISC:
    case VIR_ARCH_PARISC64:
    case VIR_ARCH_PPCLE:
    case VIR_ARCH_SPARC:
    case VIR_ARCH_UNICORE32:
    case VIR_ARCH_XTENSA:
    case VIR_ARCH_XTENSAEB:
    case VIR_ARCH_NONE:
    case VIR_ARCH_LAST:
    default:
        break;
    }

    /* Sanity check. If the machine type does not support PCI, asking
     * for PCI(e) root to be added is an obvious mistake */
    if ((addPCIRoot ||
         addPCIeRoot) &&
        !qemuDomainSupportsPCI(def)) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Machine type '%1$s' wants PCI but PCI is not supported"),
                       def->os.machine);
        return -1;
    }

    /* Sanity check. If the machine type supports PCI, we need to reflect
     * that fact in the XML or other parts of the machine handling code
     * might misbehave */
    if (qemuDomainSupportsPCI(def) &&
        !addPCIRoot &&
        !addPCIeRoot) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Machine type '%1$s' supports PCI but no PCI controller added"),
                       def->os.machine);
        return -1;
    }

    if (addDefaultUSB && usbModel == VIR_DOMAIN_CONTROLLER_MODEL_USB_DEFAULT) {
        usbModel = qemuDomainDefaultUSBControllerModelAutoAdded(def, qemuCaps);

        /* If no reasonable model can be figured out, we should
         * simply not add the default USB controller */
        if (usbModel == VIR_DOMAIN_CONTROLLER_MODEL_USB_NONE)
            addDefaultUSB = false;
    }

    if (addDefaultUSB && virDomainControllerFind(def, VIR_DOMAIN_CONTROLLER_TYPE_USB, 0) < 0)
        virDomainDefAddUSBController(def, 0, usbModel);

    if (addImplicitSATA)
        virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_SATA, 0, -1);

    pciRoot = virDomainControllerFind(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0);

    if (addPCIRoot) {
        if (pciRoot >= 0) {
            if (def->controllers[pciRoot]->model != VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("The PCI controller with index='0' must be model='pci-root' for this machine type, but model='%1$s' was found instead"),
                               virDomainControllerModelPCITypeToString(def->controllers[pciRoot]->model));
                return -1;
            }
        } else {
            virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                      VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT);
        }
    }

    /* When a machine has a pcie-root, make sure that there is always
     * a dmi-to-pci-bridge controller added as bus 1, and a pci-bridge
     * as bus 2, so that standard PCI devices can be connected
     *
     * NB: any machine that sets addPCIeRoot to true must also return
     * true from the function qemuDomainSupportsPCI().
     */
    if (addPCIeRoot) {
        if (pciRoot >= 0) {
            if (def->controllers[pciRoot]->model != VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("The PCI controller with index='0' must be model='pcie-root' for this machine type, but model='%1$s' was found instead"),
                               virDomainControllerModelPCITypeToString(def->controllers[pciRoot]->model));
                return -1;
            }
        } else {
            virDomainDefAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                      VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT);
        }
    }

    if (addDefaultMemballoon && !def->memballoon) {
        virDomainMemballoonDef *memballoon;
        memballoon = g_new0(virDomainMemballoonDef, 1);

        memballoon->model = VIR_DOMAIN_MEMBALLOON_MODEL_VIRTIO;
        def->memballoon = memballoon;
    }

    if (addDefaultUSBMouse) {
        bool hasUSBTablet = false;
        size_t j;

        for (j = 0; j < def->ninputs; j++) {
            if (def->inputs[j]->type == VIR_DOMAIN_INPUT_TYPE_TABLET &&
                def->inputs[j]->bus == VIR_DOMAIN_INPUT_BUS_USB) {
                hasUSBTablet = true;
                break;
            }
        }

        /* Historically, we have automatically added USB keyboard and
         * mouse to some guests. While the former device is generally
         * safe to have, adding the latter is undesiderable if a USB
         * tablet is already present in the guest */
        if (hasUSBTablet)
            addDefaultUSBMouse = false;
    }

    if (addDefaultUSBKBD && def->ngraphics > 0)
        virDomainDefMaybeAddInput(def, VIR_DOMAIN_INPUT_TYPE_KBD, VIR_DOMAIN_INPUT_BUS_USB);

    if (addDefaultUSBMouse && def->ngraphics > 0)
        virDomainDefMaybeAddInput(def, VIR_DOMAIN_INPUT_TYPE_MOUSE, VIR_DOMAIN_INPUT_BUS_USB);

    if (addPanicDevice) {
        virDomainPanicModel defaultModel = qemuDomainDefaultPanicModel(def);
        size_t j;

        for (j = 0; j < def->npanics; j++) {
            if (def->panics[j]->model == VIR_DOMAIN_PANIC_MODEL_DEFAULT ||
                def->panics[j]->model == defaultModel)
                break;
        }

        if (j == def->npanics) {
            virDomainPanicDef *panic = g_new0(virDomainPanicDef, 1);

            VIR_APPEND_ELEMENT_COPY(def->panics, def->npanics, panic);
        }
    }

    if (addITCOWatchdog) {
        size_t i = 0;

        for (i = 0; i < def->nwatchdogs; i++) {
            if (def->watchdogs[i]->model == VIR_DOMAIN_WATCHDOG_MODEL_ITCO)
                break;
        }

        if (i == def->nwatchdogs) {
            virDomainWatchdogDef *watchdog = g_new0(virDomainWatchdogDef, 1);

            watchdog->model = VIR_DOMAIN_WATCHDOG_MODEL_ITCO;
            if (def->nwatchdogs)
                watchdog->action = def->watchdogs[0]->action;
            else
                watchdog->action = VIR_DOMAIN_WATCHDOG_ACTION_RESET;

            VIR_APPEND_ELEMENT(def->watchdogs, def->nwatchdogs, watchdog);
        }
    }

    if (addIOMMU && !def->iommus && def->niommus == 0 &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_DEVICE_INTEL_IOMMU) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_INTREMAP) &&
        virQEMUCapsGet(qemuCaps, QEMU_CAPS_INTEL_IOMMU_EIM)) {
        g_autoptr(virDomainIOMMUDef) iommu = NULL;

        iommu = virDomainIOMMUDefNew();
        iommu->model = VIR_DOMAIN_IOMMU_MODEL_INTEL;
        /* eim requires intremap. */
        iommu->intremap = VIR_TRISTATE_SWITCH_ON;
        iommu->eim = VIR_TRISTATE_SWITCH_ON;

        def->iommus = g_new0(virDomainIOMMUDef *, 1);
        def->iommus[def->niommus++] = g_steal_pointer(&iommu);
    }

    if (qemuDomainDefAddDefaultAudioBackend(driver, def) < 0)
        return -1;

    return 0;
}


/**
 * qemuDomainDefEnableDefaultFeatures:
 * @def: domain definition
 * @qemuCaps: QEMU capabilities
 *
 * Make sure that features that should be enabled by default are actually
 * enabled and configure default values related to those features.
 */
static void
qemuDomainDefEnableDefaultFeatures(virDomainDef *def,
                                   virQEMUCaps *qemuCaps)
{
    /* The virt machine type always uses GIC: if the relevant information
     * was not included in the domain XML, we need to choose a suitable
     * GIC version ourselves */
    if ((def->features[VIR_DOMAIN_FEATURE_GIC] == VIR_TRISTATE_SWITCH_ABSENT &&
         qemuDomainIsARMVirt(def)) ||
        (def->features[VIR_DOMAIN_FEATURE_GIC] == VIR_TRISTATE_SWITCH_ON &&
         def->gic_version == VIR_GIC_VERSION_NONE)) {
        virGICVersion version;

        VIR_DEBUG("Looking for usable GIC version in domain capabilities");
        for (version = VIR_GIC_VERSION_LAST - 1;
             version > VIR_GIC_VERSION_NONE;
             version--) {

            /* We want to use the highest available GIC version for guests;
             * however, the emulated GICv3 is currently lacking a MSI controller,
             * making it unsuitable for the pure PCIe topology we aim for.
             *
             * For that reason, we skip this step entirely for TCG guests,
             * and rely on the code below to pick the default version, GICv2,
             * which supports all the features we need.
             *
             * See https://bugzilla.redhat.com/show_bug.cgi?id=1414081 */
            if (version == VIR_GIC_VERSION_3 &&
                def->virtType == VIR_DOMAIN_VIRT_QEMU) {
                continue;
            }

            if (virQEMUCapsSupportsGICVersion(qemuCaps,
                                              def->virtType,
                                              version)) {
                VIR_DEBUG("Using GIC version %s",
                          virGICVersionTypeToString(version));
                def->gic_version = version;
                break;
            }
        }

        /* Use the default GIC version (GICv2) as a last-ditch attempt
         * if no match could be found above */
        if (def->gic_version == VIR_GIC_VERSION_NONE) {
            VIR_DEBUG("Using GIC version 2 (default)");
            def->gic_version = VIR_GIC_VERSION_2;
        }

        /* Even if we haven't found a usable GIC version in the domain
         * capabilities, we still want to enable this */
        def->features[VIR_DOMAIN_FEATURE_GIC] = VIR_TRISTATE_SWITCH_ON;
    }

    /* IOMMU with intremap requires split I/O APIC. But it may happen that
     * domain already has IOMMU without inremap. This will be fixed in
     * qemuDomainIOMMUDefPostParse() but there domain definition can't be
     * modified so change it now. */
    if (def->iommus && def->niommus == 1 &&
        (def->iommus[0]->intremap == VIR_TRISTATE_SWITCH_ON ||
         qemuDomainNeedsIOMMUWithEIM(def)) &&
        def->features[VIR_DOMAIN_FEATURE_IOAPIC] == VIR_DOMAIN_IOAPIC_NONE) {
        def->features[VIR_DOMAIN_FEATURE_IOAPIC] = VIR_DOMAIN_IOAPIC_QEMU;
    }
}


static int
qemuDomainRecheckInternalPaths(virDomainDef *def,
                               virQEMUDriverConfig *cfg,
                               unsigned int flags)
{
    size_t i = 0;
    size_t j = 0;

    for (i = 0; i < def->ngraphics; ++i) {
        virDomainGraphicsDef *graphics = def->graphics[i];

        for (j = 0; j < graphics->nListens; ++j) {
            virDomainGraphicsListenDef *glisten =  &graphics->listens[j];

            /* This will happen only if we parse XML from old libvirts where
             * unix socket was available only for VNC graphics.  In this
             * particular case we should follow the behavior and if we remove
             * the auto-generated socket based on config option from qemu.conf
             * we need to change the listen type to address. */
            if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC &&
                glisten->type == VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_SOCKET &&
                glisten->socket &&
                !glisten->autoGenerated &&
                STRPREFIX(glisten->socket, cfg->libDir)) {
                if (flags & VIR_DOMAIN_DEF_PARSE_INACTIVE) {
                    VIR_FREE(glisten->socket);
                    glisten->type = VIR_DOMAIN_GRAPHICS_LISTEN_TYPE_ADDRESS;
                } else {
                    glisten->fromConfig = true;
                }
            }
        }
    }

    return 0;
}


static int
qemuDomainDefVcpusPostParse(virDomainDef *def)
{
    unsigned int maxvcpus = virDomainDefGetVcpusMax(def);
    virDomainVcpuDef *vcpu;
    virDomainVcpuDef *prevvcpu;
    size_t i;
    bool has_order = false;

    /* vcpu 0 needs to be present, first, and non-hotpluggable */
    vcpu = virDomainDefGetVcpu(def, 0);
    if (!vcpu->online) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vcpu 0 can't be offline"));
        return -1;
    }
    if (vcpu->hotpluggable == VIR_TRISTATE_BOOL_YES) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vcpu0 can't be hotpluggable"));
        return -1;
    }
    if (vcpu->order != 0 && vcpu->order != 1) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vcpu0 must be enabled first"));
        return -1;
    }

    if (vcpu->order != 0)
        has_order = true;

    prevvcpu = vcpu;

    /* all online vcpus or non online vcpu need to have order set */
    for (i = 1; i < maxvcpus; i++) {
        vcpu = virDomainDefGetVcpu(def, i);

        if (vcpu->online &&
            (vcpu->order != 0) != has_order) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("all vcpus must have either set or unset order"));
            return -1;
        }

        /* few conditions for non-hotpluggable (thus online) vcpus */
        if (vcpu->hotpluggable == VIR_TRISTATE_BOOL_NO) {
            /* they can be ordered only at the beginning */
            if (prevvcpu->hotpluggable == VIR_TRISTATE_BOOL_YES) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("online non-hotpluggable vcpus need to be ordered prior to hotpluggable vcpus"));
                return -1;
            }

            /* they need to be in order (qemu doesn't support any order yet).
             * Also note that multiple vcpus may share order on some platforms */
            if (prevvcpu->order > vcpu->order) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("online non-hotpluggable vcpus must be ordered in ascending order"));
                return -1;
            }
        }

        prevvcpu = vcpu;
    }

    return 0;
}


static int
qemuDomainDefCPUPostParse(virDomainDef *def,
                          virQEMUCaps *qemuCaps)
{
    virCPUFeatureDef *sveFeature = NULL;
    bool sveVectorLengthsProvided = false;
    size_t i;

    if (!def->cpu)
        return 0;

    for (i = 0; i < def->cpu->nfeatures; i++) {
        virCPUFeatureDef *feature = &def->cpu->features[i];

        if (STREQ(feature->name, "sve")) {
            sveFeature = feature;
        } else if (STRPREFIX(feature->name, "sve")) {
            sveVectorLengthsProvided = true;
        }
    }

    if (sveVectorLengthsProvided) {
        if (sveFeature) {
            if (sveFeature->policy == VIR_CPU_FEATURE_DISABLE ||
                sveFeature->policy == VIR_CPU_FEATURE_FORBID) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SVE disabled, but SVE vector lengths provided"));
                return -1;
            } else {
                sveFeature->policy = VIR_CPU_FEATURE_REQUIRE;
            }
        } else {
            VIR_RESIZE_N(def->cpu->features, def->cpu->nfeatures_max,
                         def->cpu->nfeatures, 1);

            def->cpu->features[def->cpu->nfeatures].name = g_strdup("sve");
            def->cpu->features[def->cpu->nfeatures].policy = VIR_CPU_FEATURE_REQUIRE;

            def->cpu->nfeatures++;
        }
    }

    /* Running domains were either started before QEMU_CAPS_CPU_MIGRATABLE was
     * introduced and thus we can't rely on it or they already have the
     * migratable default set. */
    if (def->id == -1 &&
        qemuCaps &&
        def->cpu->mode == VIR_CPU_MODE_HOST_PASSTHROUGH &&
        def->cpu->migratable == VIR_TRISTATE_SWITCH_ABSENT) {
        if (virQEMUCapsGet(qemuCaps, QEMU_CAPS_CPU_MIGRATABLE))
            def->cpu->migratable = VIR_TRISTATE_SWITCH_ON;
        else if (ARCH_IS_X86(def->os.arch))
            def->cpu->migratable = VIR_TRISTATE_SWITCH_OFF;
    }

    /* Nothing to be done if only CPU topology is specified. */
    if (def->cpu->mode == VIR_CPU_MODE_CUSTOM &&
        !def->cpu->model)
        return 0;

    if (def->cpu->check != VIR_CPU_CHECK_DEFAULT)
        return 0;

    switch ((virCPUMode) def->cpu->mode) {
    case VIR_CPU_MODE_HOST_PASSTHROUGH:
    case VIR_CPU_MODE_MAXIMUM:
        def->cpu->check = VIR_CPU_CHECK_NONE;
        break;

    case VIR_CPU_MODE_HOST_MODEL:
        def->cpu->check = VIR_CPU_CHECK_PARTIAL;
        break;

    case VIR_CPU_MODE_CUSTOM:
        /* Custom CPUs in TCG mode are not compared to host CPU by default. */
        if (def->virtType == VIR_DOMAIN_VIRT_QEMU)
            def->cpu->check = VIR_CPU_CHECK_NONE;
        else
            def->cpu->check = VIR_CPU_CHECK_PARTIAL;
        break;

    case VIR_CPU_MODE_LAST:
        break;
    }

    return 0;
}


static int
qemuDomainDefTsegPostParse(virDomainDef *def,
                           virQEMUCaps *qemuCaps)
{
    if (def->features[VIR_DOMAIN_FEATURE_SMM] != VIR_TRISTATE_SWITCH_ON)
        return 0;

    if (!def->tseg_specified)
        return 0;

    if (!qemuDomainIsQ35(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("SMM TSEG is only supported with q35 machine type"));
        return -1;
    }

    if (!virQEMUCapsGet(qemuCaps, QEMU_CAPS_MCH_EXTENDED_TSEG_MBYTES)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Setting TSEG size is not supported with this QEMU binary"));
        return -1;
    }

    if (def->tseg_size & ((1 << 20) - 1)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("SMM TSEG size must be divisible by 1 MiB"));
        return -1;
    }

    return 0;
}


static int
qemuDomainDefNumaAutoAdd(virDomainDef *def,
                         unsigned int parseFlags)
{
    bool abiUpdate = !!(parseFlags & VIR_DOMAIN_DEF_PARSE_ABI_UPDATE);
    unsigned long long nodeMem;
    size_t i;

    if (!abiUpdate ||
        !virDomainDefHasMemoryHotplug(def) ||
        qemuDomainIsS390CCW(def) ||
        virDomainNumaGetNodeCount(def->numa) > 0) {
        return 0;
    }

    nodeMem = virDomainDefGetMemoryTotal(def);

    if (!def->numa)
        def->numa = virDomainNumaNew();

    virDomainNumaSetNodeCount(def->numa, 1);

    for (i = 0; i < def->nmems; i++) {
        virDomainMemoryDef *mem = def->mems[i];

        if (mem->size > nodeMem) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Total size of memory devices exceeds the total memory size"));
            return -1;
        }

        nodeMem -= mem->size;

        switch (mem->model) {
        case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_MEM:
            if (mem->targetNode == -1)
                mem->targetNode = 0;
            break;

        case VIR_DOMAIN_MEMORY_MODEL_NONE:
        case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        case VIR_DOMAIN_MEMORY_MODEL_SGX_EPC:
        case VIR_DOMAIN_MEMORY_MODEL_LAST:
            break;
        }
    }

    virDomainNumaSetNodeMemorySize(def->numa, 0, nodeMem);

    return 0;
}


static int
qemuDomainDefNumaCPUsPostParse(virDomainDef *def,
                               virQEMUCaps *qemuCaps,
                               unsigned int parseFlags)
{
    if (qemuDomainDefNumaAutoAdd(def, parseFlags) < 0)
        return -1;

    return qemuDomainDefNumaCPUsRectify(def, qemuCaps);
}


int
qemuDomainDefPostParse(virDomainDef *def,
                       unsigned int parseFlags,
                       void *opaque,
                       void *parseOpaque)
{
    virQEMUDriver *driver = opaque;
    g_autoptr(virQEMUDriverConfig) cfg = virQEMUDriverGetConfig(driver);
    virQEMUCaps *qemuCaps = parseOpaque;

    /* Note that qemuCaps may be NULL when this function is called. This
     * function shall not fail in that case. It will be re-run on VM startup
     * with the capabilities populated.
     */
    if (!qemuCaps)
        return 1;

    if (qemuDomainDefMachinePostParse(def, qemuCaps) < 0)
        return -1;

    qemuDomainDefACPIPostParse(def, qemuCaps, parseFlags);

    if (qemuDomainDefBootPostParse(def, driver, parseFlags) < 0)
        return -1;

    if (qemuDomainDefAddDefaultDevices(driver, def, qemuCaps) < 0)
        return -1;

    if (qemuDomainDefSetDefaultCPU(def, driver->hostarch, qemuCaps) < 0)
        return -1;

    qemuDomainDefEnableDefaultFeatures(def, qemuCaps);

    if (qemuDomainRecheckInternalPaths(def, cfg, parseFlags) < 0)
        return -1;

    if (qemuSecurityVerify(driver->securityManager, def) < 0)
        return -1;

    if (qemuDomainDefVcpusPostParse(def) < 0)
        return -1;

    if (qemuDomainDefCPUPostParse(def, qemuCaps) < 0)
        return -1;

    if (qemuDomainDefTsegPostParse(def, qemuCaps) < 0)
        return -1;

    if (qemuDomainDefNumaCPUsPostParse(def, qemuCaps, parseFlags) < 0)
        return -1;

    return 0;
}


int
qemuDomainPostParseDataAlloc(const virDomainDef *def,
                             unsigned int parseFlags G_GNUC_UNUSED,
                             void *opaque,
                             void **parseOpaque)
{
    virQEMUDriver *driver = opaque;

    if (!(*parseOpaque = virQEMUCapsCacheLookup(driver->qemuCapsCache,
                                                def->emulator)))
        return 1;

    return 0;
}


void
qemuDomainPostParseDataFree(void *parseOpaque)
{
    virQEMUCaps *qemuCaps = parseOpaque;

    virObjectUnref(qemuCaps);
}
