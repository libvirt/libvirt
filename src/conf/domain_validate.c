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
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_DOMAIN

VIR_LOG_INIT("conf.domain_validate");

int
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


int
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


int
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


int
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

int
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
            virReportError(VIR_ERR_XML_ERROR, "%s",
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
            virReportError(VIR_ERR_XML_ERROR, "%s",
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


int
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


int
virDomainChrDefValidate(const virDomainChrDef *chr,
                        const virDomainDef *def)
{
    return virDomainChrSourceDefValidate(chr->source, chr, def);
}


int
virDomainRNGDefValidate(const virDomainRNGDef *rng,
                        const virDomainDef *def)
{
    if (rng->backend == VIR_DOMAIN_RNG_BACKEND_EGD)
        return virDomainChrSourceDefValidate(rng->source.chardev, NULL, def);

    return 0;
}


int
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
