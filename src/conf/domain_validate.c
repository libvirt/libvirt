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
#include "snapshot_conf.h"
#include "vircgroup.h"
#include "virconftypes.h"
#include "virlog.h"
#include "virutil.h"
#include "virstring.h"

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
virDomainCheckVirtioOptionsAreAbsent(virDomainVirtioOptions *virtio)
{
    if (!virtio)
        return 0;

    if (virtio->iommu != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iommu driver option is only supported "
                         "for virtio devices"));
        return -1;
    }
    if (virtio->ats != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ats driver option is only supported "
                         "for virtio devices"));
        return -1;
    }
    if (virtio->packed != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("packed driver option is only supported "
                         "for virtio devices"));
        return -1;
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

    if (video->type == VIR_DOMAIN_VIDEO_TYPE_RAMFB) {
        if (video->info.type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("address not supported for video type ramfb"));
            return -1;
        }
    }

    if (video->type != VIR_DOMAIN_VIDEO_TYPE_VIRTIO &&
        (virDomainCheckVirtioOptionsAreAbsent(video->virtio) < 0))
        return -1;

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
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_LAST:
        return true;
    }

    virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                   _("unexpected bus type '%d'"),
                   bus);
    return true;
}


static int
virSecurityDeviceLabelDefValidate(virSecurityDeviceLabelDef **seclabels,
                                  size_t nseclabels,
                                  virSecurityLabelDef **vmSeclabels,
                                  size_t nvmSeclabels)
{
    virSecurityDeviceLabelDef *seclabel;
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


static int
virDomainDiskVhostUserValidate(const virDomainDiskDef *disk)
{
    if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vhostuser disk supports only virtio bus"));
        return -1;
    }

    if (disk->snapshot != VIR_DOMAIN_SNAPSHOT_LOCATION_NONE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("only snapshot=no is supported with vhostuser disk"));
        return -1;
    }

    /* Unsupported driver attributes */

    if (disk->cachemode != VIR_DOMAIN_DISK_CACHE_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("cache is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->error_policy || disk->rerror_policy) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("error_policy is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->iomode) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("io is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->ioeventfd != VIR_TRISTATE_SWITCH_ABSENT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("ioeventfd is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->copy_on_read) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("copy_on_read is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->discard) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("discard is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->iothread) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iothread is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->detect_zeroes) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("detect_zeroes is not supported with vhostuser disk"));
        return -1;
    }

    /* Unsupported driver elements */

    if (disk->src->metadataCacheMaxSize > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("metadata_cache is not supported with vhostuser disk"));
        return -1;
    }

    /* Unsupported disk elements */

    if (disk->blkdeviotune.group_name ||
        virDomainBlockIoTuneInfoHasAny(&disk->blkdeviotune)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("iotune is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->src->backingStore) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("backingStore is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->src->encryption) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("encryption is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->src->readonly) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("readonly is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->src->shared) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("shareable is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->transient) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("transient is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->serial) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("serial is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->wwn) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("wwn is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->vendor) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("vendor is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->product) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("product is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->src->auth) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("auth is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->geometry.cylinders > 0 ||
        disk->geometry.heads > 0 ||
        disk->geometry.sectors > 0 ||
        disk->geometry.trans != VIR_DOMAIN_DISK_TRANS_DEFAULT) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("geometry is not supported with vhostuser disk"));
        return -1;
    }

    if (disk->blockio.logical_block_size > 0 ||
        disk->blockio.physical_block_size > 0) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("blockio is not supported with vhostuser disk"));
        return -1;
    }

    return 0;
}


static int
virDomainDiskDefValidateSourceChainOne(const virStorageSource *src)
{
    if (src->type == VIR_STORAGE_TYPE_NETWORK && src->auth) {
        virStorageAuthDef *authdef = src->auth;
        int actUsage;

        if ((actUsage = virSecretUsageTypeFromString(authdef->secrettype)) < 0) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("unknown secret type '%s'"),
                           NULLSTR(authdef->secrettype));
            return -1;
        }

        if ((src->protocol == VIR_STORAGE_NET_PROTOCOL_ISCSI &&
             actUsage != VIR_SECRET_USAGE_TYPE_ISCSI) ||
            (src->protocol == VIR_STORAGE_NET_PROTOCOL_RBD &&
             actUsage != VIR_SECRET_USAGE_TYPE_CEPH)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("invalid secret type '%s'"),
                           virSecretUsageTypeToString(actUsage));
            return -1;
        }
    }

    if (src->encryption) {
        virStorageEncryption *encryption = src->encryption;

        if (encryption->format == VIR_STORAGE_ENCRYPTION_FORMAT_LUKS &&
            encryption->encinfo.cipher_name) {

            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("supplying <cipher> for domain disk definition "
                             "is unnecessary"));
            return -1;
        }
    }

    /* internal snapshots and config files are currently supported only with rbd: */
    if (virStorageSourceGetActualType(src) != VIR_STORAGE_TYPE_NETWORK &&
        src->protocol != VIR_STORAGE_NET_PROTOCOL_RBD) {
        if (src->snapshot) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("<snapshot> element is currently supported "
                             "only with 'rbd' disks"));
            return -1;
        }

        if (src->configFile) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("<config> element is currently supported "
                             "only with 'rbd' disks"));
            return -1;
        }
    }

    return 0;
}


int
virDomainDiskDefValidateSource(const virStorageSource *src)
{
    const virStorageSource *next;

    for (next = src; next; next = next->backingStore) {
        if (virDomainDiskDefValidateSourceChainOne(next) < 0)
            return -1;
    }

    return 0;
}


#define VENDOR_LEN  8
#define PRODUCT_LEN 16

static int
virDomainDiskDefValidate(const virDomainDef *def,
                         const virDomainDiskDef *disk)
{
    virStorageSource *next;

    if (virDomainDiskDefValidateSource(disk->src) < 0)
        return -1;

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
    } else {
        if (disk->src->pr) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("<reservations/> allowed only for lun devices"));
            return -1;
        }

        if (disk->rawio != VIR_TRISTATE_BOOL_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("rawio can be used only with device='lun'"));
            return -1;
        }

        if (disk->sgio != VIR_DOMAIN_DEVICE_SGIO_DEFAULT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("sgio can be used only with device='lun'"));
            return -1;
        }
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

    if (disk->bus != VIR_DOMAIN_DISK_BUS_VIRTIO) {
        if (disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO ||
            disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_TRANSITIONAL ||
            disk->model == VIR_DOMAIN_DISK_MODEL_VIRTIO_NON_TRANSITIONAL) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk model '%s' not supported for bus '%s'"),
                           virDomainDiskModelTypeToString(disk->model),
                           virDomainDiskBusTypeToString(disk->bus));
            return -1;
        }

        if (disk->queues) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("queues attribute in disk driver element is only supported by virtio-blk"));
            return -1;
        }

        if (disk->event_idx != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk event_idx mode supported only for virtio bus"));
            return -1;
        }

        if (disk->ioeventfd != VIR_TRISTATE_SWITCH_ABSENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("disk ioeventfd mode supported only for virtio bus"));
            return -1;
        }

        if (virDomainCheckVirtioOptionsAreAbsent(disk->virtio) < 0)
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

    if (disk->src->type == VIR_STORAGE_TYPE_VHOST_USER &&
        virDomainDiskVhostUserValidate(disk) < 0) {
        return -1;
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

    if (disk->vendor) {
        if (!virStringIsPrintable(disk->vendor)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("disk vendor is not printable string"));
            return -1;
        }

        if (strlen(disk->vendor) > VENDOR_LEN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk vendor is more than %d characters"),
                           VENDOR_LEN);
            return -1;
        }
    }

    if (disk->product) {
        if (!virStringIsPrintable(disk->product)) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("disk product is not printable string"));
            return -1;
        }

        if (strlen(disk->product) > PRODUCT_LEN) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("disk product is more than %d characters"),
                           PRODUCT_LEN);
            return -1;
        }
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->bus != VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for floppy disk"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        disk->bus == VIR_DOMAIN_DISK_BUS_FDC) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid bus type '%s' for disk"),
                       virDomainDiskBusTypeToString(disk->bus));
        return -1;
    }

    if (disk->removable != VIR_TRISTATE_SWITCH_ABSENT &&
        disk->bus != VIR_DOMAIN_DISK_BUS_USB) {
        virReportError(VIR_ERR_XML_ERROR, "%s",
                       _("removable is only valid for usb disks"));
        return -1;
    }

    if (disk->startupPolicy != VIR_DOMAIN_STARTUP_POLICY_DEFAULT) {
        if (disk->src->type == VIR_STORAGE_TYPE_NETWORK) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("Setting disk %s is not allowed for "
                             "disk of network type"),
                           virDomainStartupPolicyTypeToString(disk->startupPolicy));
            return -1;
        }

        if (disk->device != VIR_DOMAIN_DISK_DEVICE_CDROM &&
            disk->device != VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
            disk->startupPolicy == VIR_DOMAIN_STARTUP_POLICY_REQUISITE) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("Setting disk 'requisite' is allowed only for "
                             "cdrom or floppy"));
            return -1;
        }
    }

    if (disk->wwn && !virValidateWWN(disk->wwn))
        return -1;

    if (!disk->dst) {
        if (disk->src->srcpool) {
            virReportError(VIR_ERR_NO_TARGET, _("pool = '%s', volume = '%s'"),
                           disk->src->srcpool->pool,
                           disk->src->srcpool->volume);
        } else {
            virReportError(VIR_ERR_NO_TARGET,
                           disk->src->path ? "%s" : NULL, disk->src->path);
        }

        return -1;
    }

    if ((disk->device == VIR_DOMAIN_DISK_DEVICE_DISK ||
         disk->device == VIR_DOMAIN_DISK_DEVICE_LUN) &&
        !STRPREFIX(disk->dst, "hd") &&
        !STRPREFIX(disk->dst, "sd") &&
        !STRPREFIX(disk->dst, "vd") &&
        !STRPREFIX(disk->dst, "xvd") &&
        !STRPREFIX(disk->dst, "ubd")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid harddisk device name: %s"), disk->dst);
        return -1;
    }

    if (disk->device == VIR_DOMAIN_DISK_DEVICE_FLOPPY &&
        !STRPREFIX(disk->dst, "fd")) {
        virReportError(VIR_ERR_INTERNAL_ERROR,
                       _("Invalid floppy device name: %s"), disk->dst);
        return -1;
    }

    /* Only CDROM and Floppy devices are allowed missing source path to
     * indicate no media present. LUN is for raw access CD-ROMs that are not
     * attached to a physical device presently */
    if (virStorageSourceIsEmpty(disk->src) &&
        disk->device == VIR_DOMAIN_DISK_DEVICE_DISK) {
        virReportError(VIR_ERR_NO_SOURCE, "%s", disk->dst);
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
        if ((src_def->data.nmdm.master && !src_def->data.nmdm.slave) ||
            (!src_def->data.nmdm.master && src_def->data.nmdm.slave)) {
                virReportError(VIR_ERR_INTERNAL_ERROR, "%s",
                               _("Should define both master and slave "
                                 "path attributes for nmdm device"));
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
        virDomainDiskDef *disk_i = def->disks[i];
        virDomainDeviceInfo *disk_info_i = &disk_i->info;

        if (disk_info_i->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        for (j = i + 1; j < def->ndisks; j++) {
            virDomainDiskDef *disk_j = def->disks[j];
            virDomainDeviceInfo *disk_info_j = &disk_j->info;

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
        virDomainHostdevDef *hdev_i = def->hostdevs[i];
        virDomainDeviceInfo *hdev_info_i = hdev_i->info;
        virDomainDeviceDriveAddress *hdev_addr_i;

        if (!virHostdevIsSCSIDevice(hdev_i))
            continue;

        if (hdev_i->info->type != VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE)
            continue;

        hdev_addr_i = &hdev_info_i->addr.drive;
        for (j = i + 1; j < def->nhostdevs; j++) {
            virDomainHostdevDef *hdev_j = def->hostdevs[j];
            virDomainDeviceInfo *hdev_info_j = hdev_j->info;

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
virDomainDeviceDefValidateAliasesIterator(virDomainDef *def,
                                          virDomainDeviceDef *dev,
                                          virDomainDeviceInfo *info,
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

    if (virDomainDeviceInfoIterateFlags((virDomainDef *) def,
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
                                 virDomainDeviceDef *dev)
{
    GHashTable *aliases = NULL;
    virDomainDeviceInfo *info = virDomainDeviceGetInfo(dev);
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
virDomainDeviceValidateAliasForHotplug(virDomainObj *vm,
                                       virDomainDeviceDef *dev,
                                       unsigned int flags)
{
    virDomainDef *persDef = NULL;
    virDomainDef *liveDef = NULL;

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
                       virDomainXMLOption *xmlopt)
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
            (def->cputune.name < VIR_CGROUP_CPU_PERIOD_MIN || \
             def->cputune.name > VIR_CGROUP_CPU_PERIOD_MAX)) { \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                           _("Value of cputune '%s' must be in range [%llu, %llu]"), \
                           #name, \
                           VIR_CGROUP_CPU_PERIOD_MIN, \
                           VIR_CGROUP_CPU_PERIOD_MAX); \
            return -1; \
        } \
    } while (0)

#define CPUTUNE_VALIDATE_QUOTA(name) \
    do { \
        if (def->cputune.name > 0 && \
            (def->cputune.name < VIR_CGROUP_CPU_QUOTA_MIN || \
             def->cputune.name > VIR_CGROUP_CPU_QUOTA_MAX)) { \
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, \
                           _("Value of cputune '%s' must be in range [%llu, %llu]"), \
                           #name, \
                           VIR_CGROUP_CPU_QUOTA_MIN, \
                           VIR_CGROUP_CPU_QUOTA_MAX); \
            return -1; \
        } \
    } while (0)

static int
virDomainDefCputuneValidate(const virDomainDef *def)
{
    if (def->cputune.shares > 0 &&
        (def->cputune.shares < VIR_CGROUP_CPU_SHARES_MIN ||
         def->cputune.shares > VIR_CGROUP_CPU_SHARES_MAX)) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       _("Value of cputune 'shares' must be in range [%llu, %llu]"),
                         VIR_CGROUP_CPU_SHARES_MIN,
                         VIR_CGROUP_CPU_SHARES_MAX);
        return -1;
    }

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
virDomainDefFSValidate(const virDomainDef *def)
{
    size_t i;
    g_autoptr(GHashTable) dsts = virHashNew(NULL);

    for (i = 0; i < def->nfss; i++) {
        const virDomainFSDef *fs = def->fss[i];

        if (fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS)
            continue;

        if (virHashHasEntry(dsts, fs->dst)) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("filesystem target '%s' specified twice"),
                           fs->dst);
            return -1;
        }

        if (virHashAddEntry(dsts, fs->dst, (void *) 0x1) < 0)
            return -1;
    }

    return 0;
}


static int
virDomainDefValidateInternal(const virDomainDef *def,
                             virDomainXMLOption *xmlopt)
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

    if (virDomainDefFSValidate(def) < 0)
        return -1;

    return 0;
}


static int
virDomainDefValidateDeviceIterator(virDomainDef *def,
                                   virDomainDeviceDef *dev,
                                   virDomainDeviceInfo *info G_GNUC_UNUSED,
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
virDomainDefValidate(virDomainDef *def,
                     unsigned int parseFlags,
                     virDomainXMLOption *xmlopt,
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

    if (net->teaming) {
        if (net->teaming->type == VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT) {
            if (!net->teaming->persistent) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("teaming persistent attribute must be set if teaming type is 'transient'"));
                return -1;
            }
        } else {
            if (net->teaming->persistent) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               _("teaming persistent attribute not allowed if teaming type is '%s'"),
                               virDomainNetTeamingTypeToString(net->teaming->type));
                return -1;
            }
        }
    }

    if (virDomainNetDefValidatePortOptions(macstr, net->type, net->virtPortProfile,
                                           net->isolatedPort) < 0) {
        return -1;
    }

    if (!virDomainNetIsVirtioModel(net) &&
        virDomainCheckVirtioOptionsAreAbsent(net->virtio) < 0) {
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

    if (hostdev->teaming) {
        if (hostdev->teaming->type != VIR_DOMAIN_NET_TEAMING_TYPE_TRANSIENT) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("teaming hostdev devices must have type='transient'"));
            return -1;
        }
        if (!hostdev->teaming->persistent) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("missing required persistent attribute in hostdev teaming element"));
            return -1;
        }
        if (hostdev->mode != VIR_DOMAIN_HOSTDEV_MODE_SUBSYS ||
            hostdev->source.subsys.type != VIR_DOMAIN_HOSTDEV_SUBSYS_TYPE_PCI) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("teaming is only supported for pci hostdev devices"));
            return -1;
        }
    }
    return 0;
}


static int
virDomainMemoryDefValidate(const virDomainMemoryDef *mem,
                           const virDomainDef *def)
{
    switch (mem->model) {
    case VIR_DOMAIN_MEMORY_MODEL_NVDIMM:
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

        if (ARCH_IS_PPC64(def->os.arch)) {
            if (mem->labelsize == 0) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("label size is required for NVDIMM device"));
                return -1;
            }
        } else if (mem->uuid) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("UUID is not supported for NVDIMM device"));
            return -1;
        }
        break;

    case VIR_DOMAIN_MEMORY_MODEL_VIRTIO_PMEM:
        if (!mem->nvdimmPath) {
            virReportError(VIR_ERR_XML_DETAIL,
                           _("path is required for model '%s'"),
                           virDomainMemoryModelTypeToString(mem->model));
            return -1;
        }

        if (mem->discard == VIR_TRISTATE_BOOL_YES) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                           _("discard is not supported for model '%s'"),
                           virDomainMemoryModelTypeToString(mem->model));
            return -1;
        }

        if (mem->access != VIR_DOMAIN_MEMORY_ACCESS_SHARED) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("shared access mode required for virtio-pmem device"));
            return -1;
        }

        if (mem->targetNode != -1) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("virtio-pmem does not support NUMA nodes"));
            return -1;
        }

    case VIR_DOMAIN_MEMORY_MODEL_DIMM:
        break;

    case VIR_DOMAIN_MEMORY_MODEL_NONE:
    case VIR_DOMAIN_MEMORY_MODEL_LAST:
    default:
        virReportEnumRangeError(virDomainMemoryModel, mem->model);
        return -1;
    }

    return 0;
}


static bool
virDomainVsockIsVirtioModel(const virDomainVsockDef *vsock)
{
    return (vsock->model == VIR_DOMAIN_VSOCK_MODEL_VIRTIO ||
            vsock->model == VIR_DOMAIN_VSOCK_MODEL_VIRTIO_TRANSITIONAL ||
            vsock->model == VIR_DOMAIN_VSOCK_MODEL_VIRTIO_NON_TRANSITIONAL);
}


static int
virDomainVsockDefValidate(const virDomainVsockDef *vsock)
{
    if (vsock->guest_cid > 0 && vsock->guest_cid <= 2) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("guest CIDs must be >= 3"));
        return -1;
    }

    if (!virDomainVsockIsVirtioModel(vsock) &&
        virDomainCheckVirtioOptionsAreAbsent(vsock->virtio) < 0)
        return -1;

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

        case VIR_DOMAIN_INPUT_TYPE_EVDEV:
            if (input->bus != VIR_DOMAIN_INPUT_BUS_NONE) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("input evdev doesn't support bus element"));
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
virDomainFSDefValidate(const virDomainFSDef *fs)
{
    if (fs->dst == NULL) {
        const char *source = fs->src->path;
        if (!source)
            source = fs->sock;

        virReportError(VIR_ERR_NO_TARGET,
                       source ? "%s" : NULL, source);
        return -1;
    }

    if (fs->info.bootIndex &&
        fs->fsdriver != VIR_DOMAIN_FS_DRIVER_TYPE_VIRTIOFS) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("boot order is only supported for virtiofs"));
        return -1;
    }

    return 0;
}

static int
virDomainEnsureAudioID(const virDomainDef *def,
                       unsigned int id)
{
    size_t i;

    if (id == 0)
        return 0;

    for (i = 0; i < def->naudios; i++) {
        if (def->audios[i]->id == id)
            return 0;
    }

    virReportError(VIR_ERR_XML_ERROR,
                   _("no audio device with ID %u"),
                   id);
    return -1;
}

static int
virDomainSoundDefValidate(const virDomainDef *def,
                          const virDomainSoundDef *sound)
{
    return virDomainEnsureAudioID(def, sound->audioId);
}

static int
virDomainAudioDefValidate(const virDomainDef *def,
                          const virDomainAudioDef *audio)
{
    size_t i;

    for (i = 0; i < def->naudios; i++) {
        if (def->audios[i] == audio)
            continue;
        if (def->audios[i]->id == audio->id) {
            virReportError(VIR_ERR_XML_ERROR,
                           _("audio ID %u is used multiple times"),
                           audio->id);
            return -1;
        }
    }

    return 0;
}

static int
virDomainGraphicsDefValidate(const virDomainDef *def,
                             const virDomainGraphicsDef *graphics)
{
    if (graphics->type == VIR_DOMAIN_GRAPHICS_TYPE_VNC)
        return virDomainEnsureAudioID(def, graphics->data.vnc.audioId);

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

    case VIR_DOMAIN_DEVICE_FS:
        return virDomainFSDefValidate(dev->data.fs);

    case VIR_DOMAIN_DEVICE_AUDIO:
        return virDomainAudioDefValidate(def, dev->data.audio);

    case VIR_DOMAIN_DEVICE_SOUND:
        return virDomainSoundDefValidate(def, dev->data.sound);

    case VIR_DOMAIN_DEVICE_GRAPHICS:
        return virDomainGraphicsDefValidate(def, dev->data.graphics);

    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
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
                           virDomainXMLOption *xmlopt,
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
