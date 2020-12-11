/*
 * domain_validate.c: domain general validation functions
 *
 * Copyright IBM Corp, 2020
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

#include "domain_validate.h"
#include "domain_conf.h"
#include "virconftypes.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_validate");

static int
virDomainDefBootValidate(const virDomainDef *def)
{
    if (def->os.bm_timeout_set && def->os.bm_timeout > 65535) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("invalid value for boot menu timeout, "
                         "must be in range [0,65535]"));
        return -1;
    }

    if (def->os.bios.rt_set &&
        (def->os.bios.rt_delay < -1 || def->os.bios.rt_delay > 65535)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("invalid value for rebootTimeout, "
                         "must be in range [-1,65535]"));
        return -1;
    }

    return 0;
}


static int
virDomainDefVideoValidate(const virDomainDef *def)
{
    size_t i;

    if (def->nvideos == 0)
        return 0;

    /* Any video marked as primary will be put in index 0 by the
     * parser. Ensure that we have only one primary set by the user. */
    if (def->videos[0]->primary) {
        for (i = 1; i < def->nvideos; i++) {
            if (def->videos[i]->primary) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only one primary video device is supported"));
                return -1;
            }
        }
    }

    return 0;
}


static int
virDomainVideoDefValidate(const virDomainVideoDef *video,
                          const virDomainDef *def)
{
    size_t i;

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("missing video model and cannot determine default"));
        return -1;
    }

    /* it doesn't make sense to pair video device type 'none' with any other
     * types, there can be only a single video device in such case
     */
    for (i = 0; i < def->nvideos; i++) {
        if (def->videos[i]->type == VIR_DOMAIN_VIDEO_TYPE_NONE &&
            def->nvideos > 1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("a 'none' video type must be the only video device "
                             "defined for the domain"));
            return -1;
        }
    }

    switch (video->backend) {
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_VHOSTUSER:
        if (video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("'vhostuser' driver is only supported with 'virtio' device"));
            return -1;
        }
        break;
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_DEFAULT:
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_QEMU:
        if (video->accel && video->accel->rendernode) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("unsupported rendernode accel attribute without 'vhostuser'"));
            return -1;
        }
        break;
    case VIR_DOMAIN_VIDEO_BACKEND_TYPE_LAST:
    default:
        virReportEnumRangeError(virDomainInputType, video->backend);
        return -1;
    }

    if (video->res && (video->res->x == 0 || video->res->y == 0)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("video resolution values must be greater than 0"));
        return -1;
    }

    if (video->type != VIR_DOMAIN_VIDEO_TYPE_QXL) {
        if (video->ram != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("ram attribute only supported for video type qxl"));
            return -1;
        }

        if (video->vram64 != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vram64 attribute only supported for video type qxl"));
            return -1;
        }

        if (video->vgamem != 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("vgamem attribute only supported for video type qxl"));
            return -1;
        }
    }

    return 0;
}


/**
 * virDomainDiskAddressDiskBusCompatibility:
 * @bus: disk bus type
 * @addressType: disk address type
 *
 * Check if the specified disk address type @addressType is compatible
 * with the specified disk bus type @bus. This function checks
 * compatibility with the bus types SATA, SCSI, FDC, and IDE only,
 * because only these are handled in common code.
 *
 * Returns true if compatible or can't be decided in common code,
 *         false if known to be not compatible.
 */
static bool
virDomainDiskAddressDiskBusCompatibility(virDomainDiskBus bus,
                                         virDomainDeviceAddressType addressType)
{
    if (addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE)
        return true;

    switch (bus) {
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_SATA:
        return addressType == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
        return true;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("unexpected bus type '%d'"),
                   bus);
    return true;
}


static int
virSecurityDeviceLabelDefValidate(virSecurityDeviceLabelDefPtr *seclabels,
                                  size_t nseclabels,
                                  virSecurityLabelDefPtr *vmSeclabels,
                                  size_t nvmSeclabels)
{
    virSecurityDeviceLabelDefPtr seclabel;
    size_t i;
    size_t j;

    for (i = 0; i < nseclabels; i++) {
        seclabel = seclabels[i];

        /* find the security label that it's being overridden */
        for (j = 0; j < nvmSeclabels; j++) {
            if (STRNEQ_NULLABLE(vmSeclabels[j]->model, seclabel->model))
                continue;

            if (!vmSeclabels[j]->relabel) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("label overrides require relabeling to be "
                                 "enabled at the domain level"));
                return -1;
            }
        }
    }

    return 0;
}


#define VENDOR_LEN  8
#define PRODUCT_LEN 16

static int
virDomainDiskDefValidate(const virDomainDef *def,
                         const virDomainDiskDef *disk)
{
    virStorageSourcePtr next;

    /* Validate LUN configuration */
    if (disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) {
        /* volumes haven't been translated at this point, so accept them */
        if (!(disk->src->type == VIR_STORAGE_TYPE_BLOCK ||
              disk->src->type == VIR_STORAGE_TYPE_VOLUME ||
              (disk->src->type == VIR_STORAGE_TYPE_NETWORK &&
               disk->src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk '%s' improperly configured for a "
                             "device='lun'"), disk->dst);
            return -1;
        }
    }

    if (disk->src->pr &&
        disk->device != VIR_DOMAIN_DISK_DEVICE_LUN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("<reservations/> allowed only for lun devices"));
        return -1;
    }

    /* Reject disks with a bus type that is not compatible with the
     * given address type. The function considers only buses that are
     * handled in common code. For other bus types it's not possible
     * to decide compatibility in common code.
     */
    if (!virDomainDiskAddressDiskBusCompatibility(disk->bus, disk->info.type)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid address type '%s' for the disk '%s' with the bus type '%s'"),
                       virDomainDeviceAddressTypeToString(disk->info.type),
                       disk->dst,
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->queues && disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("queues attribute in disk driver element is only "
                         "supported by virtio-blk"));
        return -1;
    }

    if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO &&
        (disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO ||
         disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL ||
         disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk model '%s' not supported for bus '%s'"),
                       virDomainDiskModelTypeToString(disk->model),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->src->type == VIR_STORAGE_TYPE_NVME) {
        /* NVMe namespaces start from 1 */
        if (disk->src->nvme->namespc == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("NVMe namespace can't be zero"));
            return -1;
        }
    }

    for (next = disk->src; next; next = next->backingStore) {
        if (virSecurityDeviceLabelDefValidate(next->seclabels,
                                              next->nseclabels,
                                              def->seclabels,
                                              def->nseclabels) < 0)
            return -1;
    }

    if (disk->tray_status &&
        disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("tray is only valid for cdrom and floppy"));
        return -1;
    }

    if (disk->vendor && strlen(disk->vendor) > VENDOR_LEN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk vendor is more than %d characters"),
                       VENDOR_LEN);
        return -1;
    }

    if (disk->product && strlen(disk->product) > PRODUCT_LEN) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("disk product is more than %d characters"),
                       PRODUCT_LEN);
        return -1;
    }

    return 0;
}


#define SERIAL_CHANNEL_NAME_CHARS \
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."

static int
virDomainChrSourceDefValidate(const virDomainChrSourceDef *src_def,
                              const virDomainChrDef *chr_def,
                              const virDomainDef *def)
{
    switch ((virDomainChrType) src_def->type) {
    case VIR_DOMAIN_CHR_TYPE_NULL:
    case VIR_DOMAIN_CHR_TYPE_PTY:
    case VIR_DOMAIN_CHR_TYPE_VC:
    case VIR_DOMAIN_CHR_TYPE_STDIO:
    case VIR_DOMAIN_CHR_TYPE_SPICEVMC:
    case VIR_DOMAIN_CHR_TYPE_LAST:
        break;

    case VIR_DOMAIN_CHR_TYPE_FILE:
    case VIR_DOMAIN_CHR_TYPE_DEV:
    case VIR_DOMAIN_CHR_TYPE_PIPE:
        if (!src_def->data.file.path) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source path attribute for char device"));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_NMDM:
        if (!src_def->data.nmdm.master) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing master path attribute for nmdm device"));
            return -1;
        }

        if (!src_def->data.nmdm.slave) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing slave path attribute for nmdm device"));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_TCP:
        if (!src_def->data.tcp.host) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source host attribute for char device"));
            return -1;
        }

        if (!src_def->data.tcp.service) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source service attribute for char device"));
            return -1;
        }

        if (src_def->data.tcp.listen && src_def->data.tcp.reconnect.enabled) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("chardev reconnect is possible only for connect mode"));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UDP:
        if (!src_def->data.udp.connectService) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source service attribute for char device"));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_UNIX:
        /* The source path can be auto generated for certain specific
         * types of channels, but in most cases we should report an
         * error if the user didn't provide it */
        if (!src_def->data.nix.path &&
            !(chr_def &&
              chr_def->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CHANNEL &&
              (chr_def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_XEN ||
               chr_def->targetType == VIR_DOMAIN_CHR_CHANNEL_TARGET_TYPE_VIRTIO))) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("Missing source path attribute for char device"));
            return -1;
        }

        if (src_def->data.nix.listen && src_def->data.nix.reconnect.enabled) {
            virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                           _("chardev reconnect is possible only for connect mode"));
            return -1;
        }
        break;

    case VIR_DOMAIN_CHR_TYPE_SPICEPORT:
        if (!src_def->data.spiceport.channel) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Missing source channel attribute for char device"));
            return -1;
        }
        if (strspn(src_def->data.spiceport.channel,
                   SERIAL_CHANNEL_NAME_CHARS) < strlen(src_def->data.spiceport.channel)) {
            virReportError(VIR_ERR_INVALID_ARG, "%s",
                           _("Invalid character in source channel for char device"));
            return -1;
        }
        break;
    }

    if (virSecurityDeviceLabelDefValidate(src_def->seclabels,
                                          src_def->nseclabels,
                                          def->seclabels,
                                          def->nseclabels) < 0)
        return -1;

    return 0;
}


static int
virDomainRedirdevDefValidate(const virDomainDef *def,
                             const virDomainRedirdevDef *redirdev)
{
    if (redirdev->bus == VIR_DOMAIN_REDIRDEV_BUS_USB &&
        !virDomainDefHasUSB(def)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cannot add redirected USB device: "
                         "USB is disabled for this domain"));
        return -1;
    }

    return virDomainChrSourceDefValidate(redirdev->source, NULL, def);
}


static int
virDomainChrDefValidate(const virDomainChrDef *chr,
                        const virDomainDef *def)
{
    return virDomainChrSourceDefValidate(chr->source, chr, def);
}


static int
virDomainRNGDefValidate(const virDomainRNGDef *rng,
                        const virDomainDef *def)
{
    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD)
        return virDomainChrSourceDefValidate(rng->source.chardev, NULL, def);

    return 0;
}


static int
virDomainSmartcardDefValidate(const virDomainSmartcardDef *smartcard,
                              const virDomainDef *def)
{
    if (smartcard->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
        smartcard->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCID) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("Controllers must use the 'ccid' address type"));
        return -1;
    }

    if (smartcard->type == VIR_DOMAIN_SMARTCARD_TYPE_PASSTHROUGH)
        return virDomainChrSourceDefValidate(smartcard->data.passthru, NULL, def);

    return 0;
}


static int
virDomainDefTunablesValidate(const virDomainDef *def)
{
    size_t i, j;

    for (i = 0; i < def->blkio.ndevices; i++) {
        for (j = 0; j < i; j++) {
            if (STREQ(def->blkio.devices[j].path,
                      def->blkio.devices[i].path)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("duplicate blkio device path '%s'"),
                               def->blkio.devices[i].path);
                return -1;
            }
        }
    }

    return 0;
}


static int
virDomainControllerDefValidate(const virDomainControllerDef *controller)
{
    if (controller->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI) {
        const virDomainPCIControllerOpts *opts = &controller->opts.pciopts;

        if (controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
            controller->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) {
            if (controller->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("pci-root and pcie-root controllers "
                                 "should not have an address"));
                return -1;
            }
        }

        if (controller->idx > 255) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("PCI controller index %d too high, maximum is 255"),
                           controller->idx);
            return -1;
        }

        /* Only validate the target index if it's been set */
        if (opts->targetIndex != -1) {

            if (opts->targetIndex < 0 || opts->targetIndex > 30) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller target index '%d' out of "
                                 "range - must be 0-30"),
                               opts->targetIndex);
                return -1;
            }

            if ((controller->idx == 0 && opts->targetIndex != 0) ||
                (controller->idx != 0 && opts->targetIndex == 0)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only the PCI controller with index 0 can "
                                 "have target index 0, and vice versa"));
                return -1;
            }
        }

        if (opts->chassisNr != -1) {
            if (opts->chassisNr < 1 || opts->chassisNr > 255) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller chassisNr '%d' out of range "
                                 "- must be 1-255"),
                               opts->chassisNr);
                return -1;
            }
        }

        if (opts->chassis != -1) {
            if (opts->chassis < 0 || opts->chassis > 255) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller chassis '%d' out of range "
                                 "- must be 0-255"),
                               opts->chassis);
                return -1;
            }
        }

        if (opts->port != -1) {
            if (opts->port < 0 || opts->port > 255) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller port '%d' out of range "
                                 "- must be 0-255"),
                               opts->port);
                return -1;
            }
        }

        if (opts->busNr != -1) {
            if (opts->busNr < 1 || opts->busNr > 254) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("PCI controller busNr '%d' out of range "
                                 "- must be 1-254"),
                               opts->busNr);
                return -1;
            }
        }

        if (opts->numaNode >= 0 && controller->idx == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("The PCI controller with index=0 can't "
                             "be associated with a NUMA node"));
            return -1;
        }
    }

    return 0;
}


static int
virDomainDefIdMapValidate(const virDomainDef *def)
{
    if ((def->idmap.uidmap && !def->idmap.gidmap) ||
        (!def->idmap.uidmap && def->idmap.gidmap)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("uid and gid should be mapped both"));
        return -1;
    }

    if ((def->idmap.uidmap && def->idmap.uidmap[0].start != 0) ||
        (def->idmap.gidmap && def->idmap.gidmap[0].start != 0)) {
        /* Root user of container hasn't been mapped to any user of host,
         * return error. */
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("You must map the root user of container"));
        return -1;
    }

    return 0;
}


static int
virDomainDefDuplicateDiskInfoValidate(const virDomainDef *def)
{
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        for (j = i + 1; j < def->ndisks; j++) {
            if (virDomainDiskDefCheckDuplicateInfo(def->disks[i],
                                                   def->disks[j]) < 0)
                return -1;
        }
    }

    return 0;
}



/**
 * virDomainDefDuplicateDriveAddressesValidate:
 * @def: domain definition to check against
 *
 * This function checks @def for duplicate drive addresses. Drive
 * addresses are only in use for disks and hostdevs at the moment.
 *
 * Returns 0 in case of there are no duplicate drive addresses, -1
 * otherwise.
 */
static int
virDomainDefDuplicateDriveAddressesValidate(const virDomainDef *def)
{
    size_t i;
    size_t j;

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDefPtr disk_i = def->disks[i];
        virDomainDeviceInfoPtr disk_info_i = &disk_i->info;

        if (disk_info_i->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        for (j = i + 1; j < def->ndisks; j++) {
            virDomainDiskDefPtr disk_j = def->disks[j];
            virDomainDeviceInfoPtr disk_info_j = &disk_j->info;

            if (disk_i->bus != disk_j->bus)
                continue;

            if (disk_info_j->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
                continue;

            if (virDomainDeviceInfoAddressIsEqual(disk_info_i, disk_info_j)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("Found duplicate drive address for disk with "
                                 "target name '%s' controller='%u' bus='%u' "
                                 "target='%u' unit='%u'"),
                               disk_i->dst,
                               disk_info_i->addr.drive.controller,
                               disk_info_i->addr.drive.bus,
                               disk_info_i->addr.drive.target,
                               disk_info_i->addr.drive.unit);
                return -1;
            }
        }

        /* Note: There is no need to check for conflicts with SCSI
         * hostdevs above, because conflicts with hostdevs are checked
         * in the next loop.
         */
    }

    for (i = 0; i < def->nhostdevs; i++) {
        virDomainHostdevDefPtr hdev_i = def->hostdevs[i];
        virDomainDeviceInfoPtr hdev_info_i = hdev_i->info;
        virDomainDeviceDriveAddressPtr hdev_addr_i;

        if (!virHostdevIsSCSIDevice(hdev_i))
            continue;

        if (hdev_i->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        hdev_addr_i = &hdev_info_i->addr.drive;
        for (j = i + 1; j < def->nhostdevs; j++) {
            virDomainHostdevDefPtr hdev_j = def->hostdevs[j];
            virDomainDeviceInfoPtr hdev_info_j = hdev_j->info;

            if (!virHostdevIsSCSIDevice(hdev_j))
                continue;

            /* Address type check for hdev_j will be done implicitly
             * in virDomainDeviceInfoAddressIsEqual() */

            if (virDomainDeviceInfoAddressIsEqual(hdev_info_i, hdev_info_j)) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("SCSI host address controller='%u' "
                                 "bus='%u' target='%u' unit='%u' in "
                                 "use by another SCSI host device"),
                               hdev_addr_i->bus,
                               hdev_addr_i->controller,
                               hdev_addr_i->target,
                               hdev_addr_i->unit);
                return -1;
            }
        }

        if (virDomainDriveAddressIsUsedByDisk(def, VIR_DOMAIN_DISK_BUS_SCSI,
                                              hdev_addr_i)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("SCSI host address controller='%u' "
                             "bus='%u' target='%u' unit='%u' in "
                             "use by another SCSI disk"),
                           hdev_addr_i->bus,
                           hdev_addr_i->controller,
                           hdev_addr_i->target,
                           hdev_addr_i->unit);
            return -1;
        }
    }

    return 0;
}



struct virDomainDefValidateAliasesData {
    GHashTable *aliases;
};


static int
virDomainDeviceDefValidateAliasesIterator(virDomainDefPtr def,
                                          virDomainDeviceDefPtr dev,
                                          virDomainDeviceInfoPtr info,
                                          void *opaque)
{
    struct virDomainDefValidateAliasesData *data = opaque;
    const char *alias = info->alias;

    if (!virDomainDeviceAliasIsUserAlias(alias))
        return 0;

    /* Some crazy backcompat for consoles. */
    if (def->nserials && def->nconsoles &&
        def->consoles[0]->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_CONSOLE &&
        def->consoles[0]->targetType == VIR_DOMAIN_CHR_CONSOLE_TARGET_TYPE_SERIAL &&
        dev->type == VIR_DOMAIN_DEVICE_CHR &&
        virDomainChrEquals(def->serials[0], dev->data.chr))
        return 0;

    if (dev->type == VIR_DOMAIN_DEVICE_HOSTDEV &&
        dev->data.hostdev->parentnet) {
        /* This hostdev is a copy of some previous interface.
         * Aliases are duplicated. */
        return 0;
    }

    if (virHashLookup(data->aliases, alias)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("non unique alias detected: %s"),
                       alias);
        return -1;
    }

    if (virHashAddEntry(data->aliases, alias, (void *) 1) < 0) {
        virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                       _("Unable to construct table of device aliases"));
        return -1;
    }

    return 0;
}


/**
 * virDomainDefValidateAliases:
 *
 * Check for uniqueness of device aliases. If @aliases is not
 * NULL return hash table of all the aliases in it.
 *
 * Returns 0 on success,
 *        -1 otherwise (with error reported).
 */
static int
virDomainDefValidateAliases(const virDomainDef *def,
                            GHashTable **aliases)
{
    struct virDomainDefValidateAliasesData data;
    int ret = -1;

    /* We are not storing copies of aliases. Don't free them. */
    if (!(data.aliases = virHashNew(NULL)))
        goto cleanup;

    if (virDomainDeviceInfoIterateFlags((virDomainDefPtr) def,
                                        virDomainDeviceDefValidateAliasesIterator,
                                        DOMAIN_DEVICE_ITERATE_ALL_CONSOLES,
                                        &data) < 0)
        goto cleanup;

    if (aliases)
        *aliases = g_steal_pointer(&data.aliases);

    ret = 0;
 cleanup:
    virHashFree(data.aliases);
    return ret;
}


static int
virDomainDeviceValidateAliasImpl(const virDomainDef *def,
                                 virDomainDeviceDefPtr dev)
{
    GHashTable *aliases = NULL;
    virDomainDeviceInfoPtr info = virDomainDeviceGetInfo(dev);
    int ret = -1;

    if (!info || !info->alias)
        return 0;

    if (virDomainDefValidateAliases(def, &aliases) < 0)
        goto cleanup;

    if (virHashLookup(aliases, info->alias)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("non unique alias detected: %s"),
                       info->alias);
        goto cleanup;
    }

    ret = 0;
 cleanup:

    virHashFree(aliases);
    return ret;
}


int
virDomainDeviceValidateAliasForHotplug(virDomainObjPtr vm,
                                       virDomainDeviceDefPtr dev,
                                       unsigned int flags)
{
    virDomainDefPtr persDef = NULL;
    virDomainDefPtr liveDef = NULL;

    if (virDomainObjGetDefs(vm, flags, &liveDef, &persDef) < 0)
        return -1;

    if (persDef &&
        virDomainDeviceValidateAliasImpl(persDef, dev) < 0)
        return -1;

    if (liveDef &&
        virDomainDeviceValidateAliasImpl(liveDef, dev) < 0)
        return -1;

    return 0;
}


static int
virDomainDefLifecycleActionValidate(const virDomainDef *def)
{
    if (!virDomainDefLifecycleActionAllowed(VIR_DOMAIN_LIFECYCLE_POWEROFF,
                                            def->onPoweroff)) {
        return -1;
    }

    if (!virDomainDefLifecycleActionAllowed(VIR_DOMAIN_LIFECYCLE_REBOOT,
                                            def->onReboot)) {
        return -1;
    }

    if (!virDomainDefLifecycleActionAllowed(VIR_DOMAIN_LIFECYCLE_CRASH,
                                            def->onCrash)) {
        return -1;
    }

    return 0;
}


static int
virDomainDefMemtuneValidate(const virDomainDef *def)
{
    const virDomainMemtune *mem = &(def->mem);
    size_t i;
    ssize_t pos = virDomainNumaGetNodeCount(def->numa) - 1;

    for (i = 0; i < mem->nhugepages; i++) {
        size_t j;
        ssize_t nextBit;

        for (j = 0; j < i; j++) {
            if (mem->hugepages[i].nodemask &&
                mem->hugepages[j].nodemask &&
                virBitmapOverlaps(mem->hugepages[i].nodemask,
                                  mem->hugepages[j].nodemask)) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("nodeset attribute of hugepages "
                                 "of sizes %llu and %llu intersect"),
                               mem->hugepages[i].size,
                               mem->hugepages[j].size);
                return -1;
            } else if (!mem->hugepages[i].nodemask &&
                       !mem->hugepages[j].nodemask) {
                virReportError(VIR_ERR_XML_DETAIL,
                               _("two master hugepages detected: "
                                 "%llu and %llu"),
                               mem->hugepages[i].size,
                               mem->hugepages[j].size);
                return -1;
            }
        }

        if (!mem->hugepages[i].nodemask) {
            /* This is the master hugepage to use. Skip it as it has no
             * nodemask anyway. */
            continue;
        }

        nextBit = virBitmapNextSetBit(mem->hugepages[i].nodemask, pos);
        if (nextBit >= 0) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("hugepages: node %zd not found"),
                           nextBit);
            return -1;
        }
    }

    return 0;
}


static int
virDomainDefOSValidate(const virDomainDef *def,
                       virDomainXMLOptionPtr xmlopt)
{
    if (!def->os.loader)
        return 0;

    if (def->os.firmware &&
        !(xmlopt->config.features & VIR_DOMAIN_DEF_FEATURE_FW_AUTOSELECT)) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("firmware auto selection not implemented for this driver"));
        return -1;
    }

    if (!def->os.loader->path &&
        def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_NONE) {
        virReportError(VIR_ERR_XML_DETAIL, "%s",
                       _("no loader path specified and firmware auto selection disabled"));
        return -1;
    }

    return 0;
}


#define CPUTUNE_VALIDATE_PERIOD(name) \
    do { \
        if (def->cputune.name > 0 && \
            (def->cputune.name < 1000 || def->cputune.name > 1000000)) { \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                           _("Value of cputune '%s' must be in range " \
                           "[1000, 1000000]"), #name); \
            return -1; \
        } \
    } while (0)

#define CPUTUNE_VALIDATE_QUOTA(name) \
    do { \
        if (def->cputune.name > 0 && \
            (def->cputune.name < 1000 || \
            def->cputune.name > 18446744073709551LL)) { \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                           _("Value of cputune '%s' must be in range " \
                           "[1000, 18446744073709551]"), #name); \
            return -1; \
        } \
    } while (0)

static int
virDomainDefCputuneValidate(const virDomainDef *def)
{
    CPUTUNE_VALIDATE_PERIOD(period);
    CPUTUNE_VALIDATE_PERIOD(global_period);
    CPUTUNE_VALIDATE_PERIOD(emulator_period);
    CPUTUNE_VALIDATE_PERIOD(iothread_period);

    CPUTUNE_VALIDATE_QUOTA(quota);
    CPUTUNE_VALIDATE_QUOTA(global_quota);
    CPUTUNE_VALIDATE_QUOTA(emulator_quota);
    CPUTUNE_VALIDATE_QUOTA(iothread_quota);

    return 0;
}
#undef CPUTUNE_VALIDATE_PERIOD
#undef CPUTUNE_VALIDATE_QUOTA


static int
virDomainDefIOMMUValidate(const virDomainDef *def)
{
    if (!def->iommu)
        return 0;

    if (def->iommu->intremap == VIR_TRISTATE_SWITCH_ON &&
        def->features[VIR_DOMAIN_FEATURE_IOAPIC] != VIR_DOMAIN_IOAPIC_QEMU) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOMMU interrupt remapping requires split I/O APIC "
                         "(ioapic driver='qemu')"));
        return -1;
    }

    if (def->iommu->eim == VIR_TRISTATE_SWITCH_ON &&
        def->iommu->intremap != VIR_TRISTATE_SWITCH_ON) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("IOMMU eim requires interrupt remapping to be enabled"));
        return -1;
    }

    return 0;
}


static int
virDomainDefValidateInternal(const virDomainDef *def,
                             virDomainXMLOptionPtr xmlopt)
{
    if (virDomainDefDuplicateDiskInfoValidate(def) < 0)
        return -1;

    if (virDomainDefDuplicateDriveAddressesValidate(def) < 0)
        return -1;

    if (virDomainDefGetVcpusTopology(def, NULL) < 0)
        return -1;

    if (virDomainDefValidateAliases(def, NULL) < 0)
        return -1;

    if (virDomainDefIOMMUValidate(def) < 0)
        return -1;

    if (virDomainDefLifecycleActionValidate(def) < 0)
        return -1;

    if (virDomainDefMemtuneValidate(def) < 0)
        return -1;

    if (virDomainDefOSValidate(def, xmlopt) < 0)
        return -1;

    if (virDomainDefCputuneValidate(def) < 0)
        return -1;

    if (virDomainDefBootValidate(def) < 0)
        return -1;

    if (virDomainDefVideoValidate(def) < 0)
        return -1;

    if (virDomainDefTunablesValidate(def) < 0)
        return -1;

    if (virDomainDefIdMapValidate(def) < 0)
        return -1;

    if (virDomainNumaDefValidate(def->numa) < 0)
        return -1;

    return 0;
}


static int
virDomainDefValidateDeviceIterator(virDomainDefPtr def,
                                   virDomainDeviceDefPtr dev,
                                   virDomainDeviceInfoPtr info G_GNUC_UNUSED,
                                   void *opaque)
{
    struct virDomainDefPostParseDeviceIteratorData *data = opaque;
    return virDomainDeviceDefValidate(dev, def,
                                      data->parseFlags, data->xmlopt,
                                      data->parseOpaque);
}


/**
 * virDomainDefValidate:
 * @def: domain definition
 * @caps: driver capabilities object
 * @parseFlags: virDomainDefParseFlags
 * @xmlopt: XML parser option object
 * @parseOpaque: hypervisor driver specific data for this validation run
 *
 * This validation function is designed to take checks of globally invalid
 * configurations that the parser needs to accept so that VMs don't vanish upon
 * daemon restart. Such definition can be rejected upon startup or define, where
 * this function shall be called.
 *
 * Returns 0 if domain definition is valid, -1 on error and reports an
 * appropriate message.
 */
int
virDomainDefValidate(virDomainDefPtr def,
                     unsigned int parseFlags,
                     virDomainXMLOptionPtr xmlopt,
                     void *parseOpaque)
{
    struct virDomainDefPostParseDeviceIteratorData data = {
        .xmlopt = xmlopt,
        .parseFlags = parseFlags,
        .parseOpaque = parseOpaque,
    };

    /* validate configuration only in certain places */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)
        return 0;

    /* call the domain config callback */
    if (xmlopt->config.domainValidateCallback &&
        xmlopt->config.domainValidateCallback(def, xmlopt->config.priv, parseOpaque) < 0)
        return -1;

    /* iterate the devices */
    if (virDomainDeviceInfoIterateFlags(def,
                                        virDomainDefValidateDeviceIterator,
                                        (DOMAIN_DEVICE_ITERATE_ALL_CONSOLES |
                                         DOMAIN_DEVICE_ITERATE_MISSING_INFO),
                                        &data) < 0)
        return -1;

    if (virDomainDefValidateInternal(def, xmlopt) < 0)
        return -1;

    return 0;
}


static int
virDomainNetDefValidatePortOptions(const char *macstr,
                                   virDomainNetType type,
                                   const virNetDevVPortProfile *vport,
                                   virTristateBool isolatedPort)
{
    /*
     * This function can be called for either a config interface
     * object (NetDef) or a runtime interface object (ActualNetDef),
     * by calling it with either, e.g., the "type" (what is in the
     * config) or the "actualType" (what is determined at runtime by
     * acquiring a port from the network).
     */
    /*
     * port isolation can only be set for an interface that is
     * connected to a Linux host bridge (either a libvirt-managed
     * network, or plain type='bridge')
     */
    if (isolatedPort == VIR_TRISTATE_BOOL_YES) {
        if (!(type == VIR_DOMAIN_NET_TYPE_NETWORK ||
              type == VIR_DOMAIN_NET_TYPE_BRIDGE)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("interface %s - <port isolated='yes'/> is not supported for network interfaces with type='%s'"),
                           macstr, virDomainNetTypeToString(type));
            return -1;
        }
        /*
         * also not allowed for anything with <virtualport> setting
         * (openvswitch or 802.11Qb[gh])
         */
        if (vport && vport->virtPortType != VIR_NETDEV_VPORT_PROFILE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("interface %s - <port isolated='yes'/> is not supported for network interfaces with virtualport type='%s'"),
                           macstr, virNetDevVPortTypeToString(vport->virtPortType));
            return -1;
        }
    }
    return 0;
}


int
virDomainActualNetDefValidate(const virDomainNetDef *net)
{
    /* Unlike virDomainNetDefValidate(), which is a static function
     * called internally to this file, virDomainActualNetDefValidate()
     * is a public function that can be called from a hypervisor after
     * it has completely setup the NetDef for use by a domain,
     * including possibly allocating a port from the network driver
     * (which could change the effective/"actual" type of the NetDef,
     * thus changing what should/shouldn't be allowed by validation).
     *
     * This function should contain validations not specific to a
     * particular hypervisor (e.g. whether or not specifying bandwidth
     * is allowed for a type of interface), but *not*
     * hypervisor-specific things.
     */
    char macstr[VIR_MAC_STRING_BUFLEN];
    virDomainNetType actualType = virDomainNetGetActualType(net);
    const virNetDevVPortProfile *vport = virDomainNetGetActualVirtPortProfile(net);
    const virNetDevBandwidth *bandwidth = virDomainNetGetActualBandwidth(net);

    virMacAddrFormat(&net->mac, macstr);

    if (virDomainNetGetActualVlan(net)) {
        /* vlan configuration via libvirt is only supported for PCI
         * Passthrough SR-IOV devices (hostdev or macvtap passthru
         * mode) and openvswitch bridges. Otherwise log an error and
         * fail
         */
        if (!(actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV ||
              (actualType == VIR_DOMAIN_NET_TYPE_DIRECT &&
               virDomainNetGetActualDirectMode(net) == VIR_NETDEV_MACVLAN_MODE_PASSTHRU) ||
              (actualType == VIR_DOMAIN_NET_TYPE_BRIDGE &&
               vport  && vport->virtPortType == VIR_NETDEV_VPORT_PROFILE_OPENVSWITCH))) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("interface %s - vlan tag not supported for this connection type"),
                           macstr);
            return -1;
        }
    }

    /* bandwidth configuration via libvirt is not supported for
     * hostdev network devices
     */
    if (bandwidth && actualType == VIR_DOMAIN_NET_TYPE_HOSTDEV) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("interface %s - bandwidth settings are not supported "
                         "for hostdev interfaces"),
                       macstr);
        return -1;
    }

    if (virDomainNetDefValidatePortOptions(macstr, actualType, vport,
                                           virDomainNetGetActualPortOptionsIsolated(net)) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainNetDefValidate(const virDomainNetDef *net)
{
    char macstr[VIR_MAC_STRING_BUFLEN];

    virMacAddrFormat(&net->mac, macstr);

    if ((net->hostIP.nroutes || net->hostIP.nips) &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Invalid attempt to set network interface "
                         "host-side IP route and/or address info on "
                         "interface of type '%s'. This is only supported "
                         "on interfaces of type 'ethernet'"),
                       virDomainNetTypeToString(net->type));
        return -1;
    }
    if (net->managed_tap == VIR_TRISTATE_BOOL_NO &&
        net->type != VIR_DOMAIN_NET_TYPE_ETHERNET) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("unmanaged target dev is not supported on "
                         "interfaces of type '%s'"),
                       virDomainNetTypeToString(net->type));
        return -1;
    }

    if (net->teaming.type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT) {
        if (!net->teaming.persistent) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("teaming persistent attribute must be set if teaming type is 'transient'"));
            return -1;
        }
    } else {
        if (net->teaming.persistent) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("teaming persistent attribute not allowed if teaming type is '%s'"),
                           virDomainNetTeamingTypeToString(net->teaming.type));
            return -1;
        }
    }

    if (virDomainNetDefValidatePortOptions(macstr, net->type, net->virtPortProfile,
                                           net->isolatedPort) < 0) {
        return -1;
    }

    return 0;
}


static int
virDomainHostdevDefValidate(const virDomainHostdevDef *hostdev)
{
    if (hostdev->mode == VIR_DOMAIN_HOSTDEV_MODE_SUBSYS) {
        switch ((virDomainHostdevSubsysType) hostdev->source.subsys.type) {
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI:
            if (hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_UNASSIGNED &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("PCI host devices must use 'pci' or "
                                 "'unassigned' address type"));
                return -1;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI:
            if (hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SCSI host device must use 'drive' "
                                 "address type"));
                return -1;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_SCSI_HOST:
            if (hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_PCI &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_CCW) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("SCSI_host host device must use 'pci' "
                                 "or 'ccw' address type"));
                return -1;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_USB:
            if (hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
                hostdev->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_USB) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("USB host device must use 'usb' address type"));
                return -1;
            }
            break;
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_MDEV:
        case VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_LAST:
            break;
        }
    }
    return 0;
}


static int
virDomainMemoryDefValidate(const virDomainMemoryDef *mem,
                           const virDomainDef *def)
{
    if (mem->model == VIR_DOMAIN_MEMORY_MODEL_NVDIMM) {
        if (!mem->nvdimmPath) {
            virReportError(VIR_ERR_XML_DETAIL, "%s",
                           _("path is required for model 'nvdimm'"));
            return -1;
        }

        if (mem->discard == VIR_TRISTATE_BOOL_YES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("discard is not supported for nvdimms"));
            return -1;
        }

        if (ARCH_IS_PPC64(def->os.arch) && mem->labelsize == 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("label size is required for NVDIMM device"));
            return -1;
        }
    }

    return 0;
}


static int
virDomainVsockDefValidate(const virDomainVsockDef *vsock)
{
    if (vsock->guest_cid > 0 && vsock->guest_cid <= 2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("guest CIDs must be >= 3"));
        return -1;
    }

    return 0;
}


static int
virDomainInputDefValidate(const virDomainInputDef *input)
{
    switch ((virDomainInputType) input->type) {
        case VIR_DOMAIN_INPUT_TYPE_MOUSE:
        case VIR_DOMAIN_INPUT_TYPE_TABLET:
        case VIR_DOMAIN_INPUT_TYPE_KBD:
            if (input->source.evdev) {
                 virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                _("setting source evdev path only supported for "
                                  "passthrough input devices"));
                 return -1;
            }
            break;

        case VIR_DOMAIN_INPUT_TYPE_PASSTHROUGH:
            if (input->bus != VIR_DOMAIN_INPUT_BUS_VIRTIO) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("only bus 'virtio' is supported for 'passthrough' "
                                 "input devices"));
                return -1;
            }
            break;

        case VIR_DOMAIN_INPUT_TYPE_LAST:
        default:
            virReportEnumRangeError(virDomainInputType, input->type);
            return -1;
    }

    return 0;
}


static int
virDomainShmemDefValidate(const virDomainShmemDef *shmem)
{
    if (strchr(shmem->name, '/')) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("shmem name cannot include '/' character"));
        return -1;
    }

    if (STREQ(shmem->name, ".")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("shmem name cannot be equal to '.'"));
        return -1;
    }

    if (STREQ(shmem->name, "..")) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("shmem name cannot be equal to '..'"));
        return -1;
    }

    return 0;
}


static int
virDomainDeviceDefValidateInternal(const virDomainDeviceDef *dev,
                                   const virDomainDef *def)
{
    switch ((virDomainDeviceType) dev->type) {
    case VIR_DOMAIN_DEVICE_DISK:
        return virDomainDiskDefValidate(def, dev->data.disk);

    case VIR_DOMAIN_DEVICE_REDIRDEV:
        return virDomainRedirdevDefValidate(def, dev->data.redirdev);

    case VIR_DOMAIN_DEVICE_NET:
        return virDomainNetDefValidate(dev->data.net);

    case VIR_DOMAIN_DEVICE_CONTROLLER:
        return virDomainControllerDefValidate(dev->data.controller);

    case VIR_DOMAIN_DEVICE_CHR:
        return virDomainChrDefValidate(dev->data.chr, def);

    case VIR_DOMAIN_DEVICE_SMARTCARD:
        return virDomainSmartcardDefValidate(dev->data.smartcard, def);

    case VIR_DOMAIN_DEVICE_RNG:
        return virDomainRNGDefValidate(dev->data.rng, def);

    case VIR_DOMAIN_DEVICE_HOSTDEV:
        return virDomainHostdevDefValidate(dev->data.hostdev);

    case VIR_DOMAIN_DEVICE_VIDEO:
        return virDomainVideoDefValidate(dev->data.video, def);

    case VIR_DOMAIN_DEVICE_MEMORY:
        return virDomainMemoryDefValidate(dev->data.memory, def);

    case VIR_DOMAIN_DEVICE_VSOCK:
        return virDomainVsockDefValidate(dev->data.vsock);

    case VIR_DOMAIN_DEVICE_INPUT:
        return virDomainInputDefValidate(dev->data.input);

    case VIR_DOMAIN_DEVICE_SHMEM:
        return virDomainShmemDefValidate(dev->data.shmem);

    case VIR_DOMAIN_DEVICE_AUDIO:
        /* TODO: validate? */
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_LAST:
        break;
    }

    return 0;
}


int
virDomainDeviceDefValidate(const virDomainDeviceDef *dev,
                           const virDomainDef *def,
                           unsigned int parseFlags,
                           virDomainXMLOptionPtr xmlopt,
                           void *parseOpaque)
{
    /* validate configuration only in certain places */
    if (parseFlags & VIR_DOMAIN_DEF_PARSE_SKIP_VALIDATE)
        return 0;

    if (xmlopt->config.deviceValidateCallback &&
        xmlopt->config.deviceValidateCallback(dev, def, xmlopt->config.priv, parseOpaque))
        return -1;

    if (virDomainDeviceDefValidateInternal(dev, def) < 0)
        return -1;

    return 0;
}
