/*
 * bhyve_domain.c: bhyve domain private state
 *
 * Copyright (C) 2014 Roman Bogorodskiy
 * Copyright (C) 2025 The FreeBSD Foundation
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

#include "bhyve_driver.h"
#include "bhyve_conf.h"
#include "bhyve_device.h"
#include "bhyve_domain.h"
#include "bhyve_capabilities.h"
#include "viralloc.h"
#include "virlog.h"
#include "virutil.h"

#define VIR_FROM_THIS VIR_FROM_BHYVE

VIR_LOG_INIT("bhyve.bhyve_domain");

static void *
bhyveDomainObjPrivateAlloc(void *opaque)
{
    bhyveDomainObjPrivate *priv = g_new0(bhyveDomainObjPrivate, 1);

    priv->driver = opaque;

    return priv;
}

static void
bhyveDomainObjPrivateFree(void *data)
{
    bhyveDomainObjPrivate *priv = data;

    virDomainPCIAddressSetFree(priv->pciaddrs);

    g_free(priv);
}

virDomainXMLPrivateDataCallbacks virBhyveDriverPrivateDataCallbacks = {
    .alloc = bhyveDomainObjPrivateAlloc,
    .free = bhyveDomainObjPrivateFree,
};

static bool
bhyveDomainDefNeedsISAController(virDomainDef *def)
{
    if (def->os.bootloader == NULL && def->os.loader)
        return true;

    if (def->os.firmware == VIR_DOMAIN_OS_DEF_FIRMWARE_EFI)
        return true;

    if (def->nserials || def->nconsoles)
        return true;

    if (def->ngraphics && def->nvideos)
        return true;

    return false;
}

static int
bhyveDomainDefPostParse(virDomainDef *def,
                        unsigned int parseFlags G_GNUC_UNUSED,
                        void *opaque,
                        void *parseOpaque G_GNUC_UNUSED)
{
    struct _bhyveConn *driver = opaque;
    g_autoptr(virCaps) caps = bhyveDriverGetCapabilities(driver);
    if (!caps)
        return -1;

    if (!virCapabilitiesDomainSupported(caps, def->os.type,
                                        def->os.arch,
                                        def->virtType,
                                        true))
        return -1;

    /* Add an implicit PCI root controller */
    virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_PCI, 0,
                                   VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT);

    if (bhyveDomainDefNeedsISAController(def)) {
        virDomainDefMaybeAddController(def, VIR_DOMAIN_CONTROLLER_TYPE_ISA, 0,
                                       VIR_DOMAIN_CONTROLLER_MODEL_ISA_DEFAULT);
    }

    return 0;
}

static int
bhyveDomainDiskDefAssignAddress(struct _bhyveConn *driver,
                                virDomainDiskDef *def,
                                const virDomainDef *vmdef G_GNUC_UNUSED)
{
    int idx = -1;
    int nvme_ctrl = 0;

    if (virDiskNameParse(def->dst, &nvme_ctrl, &idx, NULL) < 0) {
        virReportError(VIR_ERR_XML_ERROR,
                       _("Unknown disk name '%1$s' and no address specified"),
                       def->dst);
        return -1;
    }

    switch (def->bus) {
    case VIR_DOMAIN_DISK_BUS_SATA:
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        if ((driver->bhyvecaps & BHYVE_CAP_AHCI32SLOT) != 0) {
            def->info.addr.drive.controller = idx / 32;
            def->info.addr.drive.unit = idx % 32;
        } else {
            def->info.addr.drive.controller = idx;
            def->info.addr.drive.unit = 0;
        }

        def->info.addr.drive.bus = 0;
        break;

    case VIR_DOMAIN_DISK_BUS_NVME:
        def->info.type = VIR_DOMAIN_DEVICE_ADDRESS_TYPE_DRIVE;

        def->info.addr.drive.controller = nvme_ctrl;
        def->info.addr.drive.unit = 0;
        def->info.addr.drive.bus = idx;
        break;

    case VIR_DOMAIN_DISK_BUS_SCSI:
    case VIR_DOMAIN_DISK_BUS_IDE:
    case VIR_DOMAIN_DISK_BUS_FDC:
    case VIR_DOMAIN_DISK_BUS_NONE:
    case VIR_DOMAIN_DISK_BUS_VIRTIO:
    case VIR_DOMAIN_DISK_BUS_XEN:
    case VIR_DOMAIN_DISK_BUS_USB:
    case VIR_DOMAIN_DISK_BUS_UML:
    case VIR_DOMAIN_DISK_BUS_SD:
    case VIR_DOMAIN_DISK_BUS_LAST:
    default:
        break;
    }
    return 0;
}

static int
bhyveDomainDeviceDefPostParse(virDomainDeviceDef *dev,
                              const virDomainDef *def,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque,
                              void *parseOpaque G_GNUC_UNUSED)
{
    struct _bhyveConn *driver = opaque;

    if (dev->type == VIR_DOMAIN_DEVICE_DISK) {
        virDomainDiskDef *disk = dev->data.disk;

        if (disk->info.type == VIR_DOMAIN_DEVICE_ADDRESS_TYPE_NONE &&
            bhyveDomainDiskDefAssignAddress(driver, disk, def) < 0)
            return -1;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_CONTROLLER) {
        virDomainControllerDef *cont = dev->data.controller;

        if (cont->type == VIR_DOMAIN_CONTROLLER_TYPE_PCI &&
            (cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCI_ROOT ||
             cont->model == VIR_DOMAIN_CONTROLLER_MODEL_PCIE_ROOT) &&
            cont->idx != 0) {
            virReportError(VIR_ERR_XML_ERROR, "%s",
                           _("pci-root and pcie-root controllers should have index 0"));
            return -1;
        }
    }

    if (dev->type == VIR_DOMAIN_DEVICE_VIDEO &&
        dev->data.video->type == VIR_DOMAIN_VIDEO_TYPE_DEFAULT) {
        dev->data.video->type = VIR_DOMAIN_VIDEO_TYPE_GOP;
    }

    if (dev->type == VIR_DOMAIN_DEVICE_CHR &&
        dev->data.chr->source->type == VIR_DOMAIN_CHR_TYPE_NMDM) {
        virDomainChrDef *chr = dev->data.chr;

        if (!chr->source->data.nmdm.master) {
            char uuidstr[VIR_UUID_STRING_BUFLEN];

            virUUIDFormat(def->uuid, uuidstr);

            chr->source->data.nmdm.master = g_strdup_printf("/dev/nmdm%sA", uuidstr);
            chr->source->data.nmdm.slave = g_strdup_printf("/dev/nmdm%sB", uuidstr);
        }
    }

    return 0;
}

static int
bhyveDomainDefAssignAddresses(virDomainDef *def,
                              unsigned int parseFlags G_GNUC_UNUSED,
                              void *opaque G_GNUC_UNUSED,
                              void *parseOpaque G_GNUC_UNUSED)
{
    if (bhyveDomainAssignAddresses(def, NULL) < 0)
        return -1;

    return 0;
}

virDomainXMLOption *
virBhyveDriverCreateXMLConf(struct _bhyveConn *driver)
{
    virDomainXMLOption *ret = NULL;

    virBhyveDriverDomainDefParserConfig.priv = driver;

    ret = virDomainXMLOptionNew(&virBhyveDriverDomainDefParserConfig,
                                &virBhyveDriverPrivateDataCallbacks,
                                &virBhyveDriverDomainXMLNamespace,
                                NULL, NULL, NULL);

    virDomainXMLOptionSetCloseCallbackAlloc(ret, virCloseCallbacksDomainAlloc);

    return ret;
}


static int
bhyveDomainDeviceDefValidate(const virDomainDeviceDef *dev,
                             const virDomainDef *def G_GNUC_UNUSED,
                             void *opaque G_GNUC_UNUSED,
                             void *parseOpaque G_GNUC_UNUSED)
{
    switch (dev->type) {
    case VIR_DOMAIN_DEVICE_CONTROLLER:
        if (dev->data.controller->type == VIR_DOMAIN_CONTROLLER_TYPE_ISA &&
            dev->data.controller->idx != 0) {
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_RNG:
        if (dev->data.rng->model == VIR_DOMAIN_RNG_MODEL_VIRTIO) {
            if (dev->data.rng->backend == VIR_DOMAIN_RNG_BACKEND_RANDOM) {
                if (STRNEQ(dev->data.rng->source.file, "/dev/random")) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only /dev/random source is supported"));
                    return -1;
                }
            } else {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only 'random' backend model is supported"));
                return -1;
            }
        } else {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("Only 'virio' RNG device model is supported"));
            return -1;
        }
        break;

    case VIR_DOMAIN_DEVICE_CHR:
        if (dev->data.chr->deviceType == VIR_DOMAIN_CHR_DEVICE_TYPE_SERIAL) {
            virDomainChrDef *chr = dev->data.chr;
            if (chr->source->type != VIR_DOMAIN_CHR_TYPE_NMDM &&
                chr->source->type != VIR_DOMAIN_CHR_TYPE_TCP) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only 'nmdm' and 'tcp' console types are supported"));
                return -1;
            }
            if (chr->target.port > 3) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                               _("Only four serial ports are supported"));
                return -1;
            }
            if (chr->source->type == VIR_DOMAIN_CHR_TYPE_TCP) {
                if (chr->source->data.tcp.listen == false) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only listening TCP sockets are supported"));
                    return -1;
                }

                if (chr->source->data.tcp.protocol != VIR_DOMAIN_CHR_TCP_PROTOCOL_RAW) {
                    virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                                   _("Only 'raw' protocol is supported for TCP sockets"));
                    return -1;
                }
            }
        }
        break;

    case VIR_DOMAIN_DEVICE_DISK: {
        virDomainDiskDef *disk = dev->data.disk;

        if (disk->rotation_rate &&
            disk->bus != VIR_DOMAIN_DISK_BUS_SATA) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("rotation rate is only valid for SATA bus"));
            return -1;
        }

        if ((disk->queues || disk->queue_size) &&
            disk->bus != VIR_DOMAIN_DISK_BUS_NVME) {
            virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                           _("queue configuration is only valid for NVMe bus"));
            return -1;
        }

        break;
    }
    case VIR_DOMAIN_DEVICE_AUDIO:
    case VIR_DOMAIN_DEVICE_CRYPTO:
    case VIR_DOMAIN_DEVICE_FS:
    case VIR_DOMAIN_DEVICE_GRAPHICS:
    case VIR_DOMAIN_DEVICE_HOSTDEV:
    case VIR_DOMAIN_DEVICE_HUB:
    case VIR_DOMAIN_DEVICE_INPUT:
    case VIR_DOMAIN_DEVICE_IOMMU:
    case VIR_DOMAIN_DEVICE_LAST:
    case VIR_DOMAIN_DEVICE_LEASE:
    case VIR_DOMAIN_DEVICE_MEMBALLOON:
    case VIR_DOMAIN_DEVICE_MEMORY:
    case VIR_DOMAIN_DEVICE_NET:
    case VIR_DOMAIN_DEVICE_NONE:
    case VIR_DOMAIN_DEVICE_NVRAM:
    case VIR_DOMAIN_DEVICE_PANIC:
    case VIR_DOMAIN_DEVICE_PSTORE:
    case VIR_DOMAIN_DEVICE_REDIRDEV:
    case VIR_DOMAIN_DEVICE_SHMEM:
    case VIR_DOMAIN_DEVICE_SMARTCARD:
    case VIR_DOMAIN_DEVICE_SOUND:
    case VIR_DOMAIN_DEVICE_TPM:
    case VIR_DOMAIN_DEVICE_VIDEO:
    case VIR_DOMAIN_DEVICE_VSOCK:
    case VIR_DOMAIN_DEVICE_WATCHDOG:
        break;
    }

    return 0;
}


static int
bhyveDomainDefValidate(const virDomainDef *def,
                       void *opaque G_GNUC_UNUSED,
                       void *parseOpaque G_GNUC_UNUSED)
{
    size_t i;
    virStorageSource *src = NULL;
    g_autoptr(GHashTable) nvme_controllers = g_hash_table_new(g_direct_hash,
                                                              g_direct_equal);

    for (i = 0; i < def->ndisks; i++) {
        virDomainDiskDef *disk = def->disks[i];
        int nvme_ctrl = 0;
        int idx = -1;

        if (disk->bus == VIR_DOMAIN_DISK_BUS_NVME) {
            if (virDiskNameParse(disk->dst, &nvme_ctrl, &idx, NULL) < 0) {
                virReportError(VIR_ERR_XML_ERROR,
                               _("Unknown disk name '%1$s' and no address specified"),
                               disk->dst);
                return -1;
            }

            if (g_hash_table_contains(nvme_controllers, GINT_TO_POINTER(nvme_ctrl))) {
                virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                               "%s",
                               _("Cannot have more than one disk per NVMe controller"));
                return -1;
            }

            g_hash_table_add(nvme_controllers, GINT_TO_POINTER(nvme_ctrl));
        }
    }

    if (def->nhostdevs && !def->mem.locked) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                       _("using passthrough devices requires locking guest memory"));
        return -1;
    }

    if (!def->os.loader)
        return 0;

    if (!(src = def->os.loader->nvram))
        return 0;

    if (src->type != VIR_STORAGE_TYPE_FILE) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED,
                       "%s",
                       _("only 'file' type is supported with NVRAM"));
        return -1;
    }

    if (src->sliceStorage) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("slices are not supported with NVRAM"));
        return -1;
    }

    if (src->pr) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("persistent reservations are not supported with NVRAM"));
        return -1;
    }

    if (src->backingStore) {
        virReportError(VIR_ERR_CONFIG_UNSUPPORTED, "%s",
                        _("backingStore is not supported with NVRAM"));
        return -1;
    }

    return 0;
}

virDomainDefParserConfig virBhyveDriverDomainDefParserConfig = {
    .devicesPostParseCallback = bhyveDomainDeviceDefPostParse,
    .domainPostParseCallback = bhyveDomainDefPostParse,
    .assignAddressesCallback = bhyveDomainDefAssignAddresses,
    .deviceValidateCallback = bhyveDomainDeviceDefValidate,
    .domainValidateCallback = bhyveDomainDefValidate,

    .features = VIR_DOMAIN_DEF_FEATURE_FW_AUTOSELECT,
};

static void
bhyveDomainDefNamespaceFree(void *nsdata)
{
    bhyveDomainCmdlineDef *cmd = nsdata;

    bhyveDomainCmdlineDefFree(cmd);
}

static int
bhyveDomainDefNamespaceParse(xmlXPathContextPtr ctxt,
                             void **data)
{
    bhyveDomainCmdlineDef *cmd = NULL;
    xmlNodePtr *nodes = NULL;
    int n;
    size_t i;
    int ret = -1;

    cmd = g_new0(bhyveDomainCmdlineDef, 1);

    n = virXPathNodeSet("./bhyve:commandline/bhyve:arg", ctxt, &nodes);
    if (n == 0)
        ret = 0;
    if (n <= 0)
        goto cleanup;

    cmd->args = g_new0(char *, n);

    for (i = 0; i < n; i++) {
        cmd->args[cmd->num_args] = virXMLPropString(nodes[i], "value");
        if (cmd->args[cmd->num_args] == NULL) {
            virReportError(VIR_ERR_INTERNAL_ERROR,
                           "%s", _("No bhyve command-line argument specified"));
            goto cleanup;
        }
        cmd->num_args++;
    }

    *data = g_steal_pointer(&cmd);
    ret = 0;

 cleanup:
    VIR_FREE(nodes);
    bhyveDomainDefNamespaceFree(cmd);

    return ret;
}

static int
bhyveDomainDefNamespaceFormatXML(virBuffer *buf,
                                 void *nsdata)
{
    bhyveDomainCmdlineDef *cmd = nsdata;
    size_t i;

    if (!cmd->num_args)
        return 0;

    virBufferAddLit(buf, "<bhyve:commandline>\n");
    virBufferAdjustIndent(buf, 2);

    for (i = 0; i < cmd->num_args; i++)
        virBufferEscapeString(buf, "<bhyve:arg value='%s'/>\n",
                              cmd->args[i]);

    virBufferAdjustIndent(buf, -2);
    virBufferAddLit(buf, "</bhyve:commandline>\n");

    return 0;
}

virXMLNamespace virBhyveDriverDomainXMLNamespace = {
    .parse = bhyveDomainDefNamespaceParse,
    .free = bhyveDomainDefNamespaceFree,
    .format = bhyveDomainDefNamespaceFormatXML,
    .prefix = "bhyve",
    .uri = "http://libvirt.org/schemas/domain/bhyve/1.0",

};
